package lib

import (
	"fmt"
	"github.com/pkg/errors"
	"time"
)

type VersionManager struct {
}

func (pp *Peer) NewVersionMessage(params *DeSoParams) *MsgDeSoVersion {
	ver := NewMessage(MsgTypeVersion).(*MsgDeSoVersion)

	ver.Version = params.ProtocolVersion
	ver.TstampSecs = time.Now().Unix()
	// We use an int64 instead of a uint64 for convenience but
	// this should be fine since we're just looking to generate a
	// unique value.
	ver.Nonce = uint64(RandInt64(math.MaxInt64))
	ver.UserAgent = params.UserAgent
	// TODO: Right now all peers are full nodes. Later on we'll want to change this,
	// at which point we'll need to do a little refactoring.
	ver.Services = SFFullNodeDeprecated
	if pp.cmgr != nil && pp.cmgr.HyperSync {
		ver.Services |= SFHyperSync
	}
	if pp.srv.blockchain.archivalMode {
		ver.Services |= SFArchivalNode
	}

	// When a node asks you for what height you have, you should reply with
	// the height of the latest actual block you have. This makes it so that
	// peers who have up-to-date headers but missing blocks won't be considered
	// for initial block download.
	//
	// TODO: This is ugly. It would be nice if the Peer required zero knowledge of the
	// Server and the Blockchain.
	if pp.srv != nil {
		ver.StartBlockHeight = uint32(pp.srv.blockchain.blockTip().Header.Height)
	} else {
		ver.StartBlockHeight = uint32(0)
	}

	// Set the minimum fee rate the peer will accept.
	ver.MinFeeRateNanosPerKB = pp.minTxFeeRateNanosPerKB

	return ver
}

func (pp *Peer) sendVerack() error {
	verackMsg := NewMessage(MsgTypeVerack)
	// Include the nonce we received in the peer's version message so
	// we can validate that we actually control our IP address.
	verackMsg.(*MsgDeSoVerack).Nonce = pp.VersionNonceReceived
	if err := pp.WriteDeSoMessage(verackMsg); err != nil {
		return errors.Wrap(err, "sendVerack: ")
	}

	return nil
}

func (pp *Peer) readVerack() error {
	msg, err := pp.ReadDeSoMessage()
	if err != nil {
		return errors.Wrap(err, "readVerack: ")
	}
	if msg.GetMsgType() != MsgTypeVerack {
		return fmt.Errorf(
			"readVerack: Received message with type %s but expected type VERACK. ",
			msg.GetMsgType().String())
	}
	verackMsg := msg.(*MsgDeSoVerack)
	if verackMsg.Nonce != pp.VersionNonceSent {
		return fmt.Errorf(
			"readVerack: Received VERACK message with nonce %d but expected nonce %d",
			verackMsg.Nonce, pp.VersionNonceSent)
	}

	return nil
}

func (pp *Peer) sendVersion() error {
	// For an outbound peer, we send a version message and then wait to
	// hear back for one.
	verMsg := pp.NewVersionMessage(pp.Params)

	// Record the nonce of this version message before we send it so we can
	// detect self connections and so we can validate that the peer actually
	// controls the IP she's supposedly communicating to us from.
	pp.VersionNonceSent = verMsg.Nonce
	if pp.cmgr != nil {
		pp.cmgr.sentNonces.Add(pp.VersionNonceSent)
	}

	if err := pp.WriteDeSoMessage(verMsg); err != nil {
		return errors.Wrap(err, "sendVersion: ")
	}

	return nil
}

func (pp *Peer) readVersion() error {
	msg, err := pp.ReadDeSoMessage()
	if err != nil {
		return errors.Wrap(err, "readVersion: ")
	}

	verMsg, ok := msg.(*MsgDeSoVersion)
	if !ok {
		return fmt.Errorf(
			"readVersion: Received message with type %s but expected type VERSION. "+
				"The VERSION message must preceed all others", msg.GetMsgType().String())
	}
	if verMsg.Version < pp.Params.MinProtocolVersion {
		return fmt.Errorf("readVersion: Peer's protocol version too low: %d (min: %v)",
			verMsg.Version, pp.Params.MinProtocolVersion)
	}

	// If we've sent this nonce before then return an error since this is
	// a connection from ourselves.
	msgNonce := verMsg.Nonce
	if pp.cmgr != nil {
		if pp.cmgr.sentNonces.Contains(msgNonce) {
			pp.cmgr.sentNonces.Delete(msgNonce)
			return fmt.Errorf("readVersion: Rejecting connection to self")
		}
	}
	// Save the version nonce so we can include it in our verack message.
	pp.VersionNonceReceived = msgNonce

	// Set the peer info-related fields.
	pp.PeerInfoMtx.Lock()
	pp.userAgent = verMsg.UserAgent
	pp.serviceFlags = verMsg.Services
	pp.advertisedProtocolVersion = verMsg.Version
	negotiatedVersion := pp.Params.ProtocolVersion
	if pp.advertisedProtocolVersion < pp.Params.ProtocolVersion {
		negotiatedVersion = pp.advertisedProtocolVersion
	}
	pp.negotiatedProtocolVersion = negotiatedVersion
	pp.PeerInfoMtx.Unlock()

	// Set the stats-related fields.
	pp.StatsMtx.Lock()
	pp.startingHeight = verMsg.StartBlockHeight
	pp.minTxFeeRateNanosPerKB = verMsg.MinFeeRateNanosPerKB
	pp.TimeConnected = time.Unix(verMsg.TstampSecs, 0)
	pp.TimeOffsetSecs = verMsg.TstampSecs - time.Now().Unix()
	pp.StatsMtx.Unlock()

	// Update the timeSource now that we've gotten a version message from the
	// peer.
	if pp.cmgr != nil {
		pp.cmgr.timeSource.AddTimeSample(pp.addrStr, pp.TimeConnected)
	}

	return nil
}

func (pp *Peer) ReadWithTimeout(readFunc func() error, readTimeout time.Duration) error {
	errChan := make(chan error)
	go func() {
		errChan <- readFunc()
	}()
	select {
	case err := <-errChan:
		{
			return err
		}
	case <-time.After(readTimeout):
		{
			return fmt.Errorf("ReadWithTimeout: Timed out reading message from peer: (%v)", pp)
		}
	}
}

func (pp *Peer) NegotiateVersion(versionNegotiationTimeout time.Duration) error {
	if pp.isOutbound {
		// Write a version message.
		if err := pp.sendVersion(); err != nil {
			return errors.Wrapf(err, "negotiateVersion: Problem sending version to Peer %v", pp)
		}
		// Read the peer's version.
		if err := pp.ReadWithTimeout(
			pp.readVersion,
			versionNegotiationTimeout); err != nil {

			return errors.Wrapf(err, "negotiateVersion: Problem reading OUTBOUND peer version for Peer %v", pp)
		}
	} else {
		// Read the version first since this is an inbound peer.
		if err := pp.ReadWithTimeout(
			pp.readVersion,
			versionNegotiationTimeout); err != nil {

			return errors.Wrapf(err, "negotiateVersion: Problem reading INBOUND peer version for Peer %v", pp)
		}
		if err := pp.sendVersion(); err != nil {
			return errors.Wrapf(err, "negotiateVersion: Problem sending version to Peer %v", pp)
		}
	}

	// After sending and receiving a compatible version, complete the
	// negotiation by sending and receiving a verack message.
	if err := pp.sendVerack(); err != nil {
		return errors.Wrapf(err, "negotiateVersion: Problem sending verack to Peer %v", pp)
	}
	if err := pp.ReadWithTimeout(
		pp.readVerack,
		versionNegotiationTimeout); err != nil {

		return errors.Wrapf(err, "negotiateVersion: Problem reading VERACK message from Peer %v", pp)
	}
	pp.VersionNegotiated = true

	// At this point we have sent a version and validated our peer's
	// version. So the negotiation should be complete.
	return nil
}
