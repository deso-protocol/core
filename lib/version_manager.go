package lib

import (
	"fmt"
	"github.com/decred/dcrd/lru"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"math"
	"time"
)

type VersionManager struct {
	bc *Blockchain
	srv *Server

	params *DeSoParams

	minTxFeeRateNanosPerKB uint64

	// When --hypersync is set to true we will attempt fast block synchronization
	hyperSync    bool
	archivalMode bool

	userAgent                 string
	advertisedProtocolVersion uint64
	negotiatedProtocolVersion uint64
	VersionNegotiated         bool

	peerVersionNoncesSent     map[uint64]uint64
	peerVersionNoncesReceived map[uint64]uint64
	peerVersionNegotiated map[uint64]struct{}

	usedNonces lru.Cache
}

func (vm *VersionManager) _logVersionSuccess(peer *Peer) {
	inboundStr := "INBOUND"
	if peer.isOutbound {
		inboundStr = "OUTBOUND"
	}
	persistentStr := "PERSISTENT"
	if !peer.isPersistent {
		persistentStr = "NON-PERSISTENT"
	}
	logStr := fmt.Sprintf("SUCCESS version negotiation for (%s) (%s) peer (%v).", inboundStr, persistentStr, peer)
	glog.V(1).Info(logStr)
}

func (vm *VersionManager) sendVersion(peerId uint64) error {
	// For an outbound peer, we send a version message and then wait to
	// hear back for one.
	verMsg := vm.newVersionMessage(vm.params)

	// Record the nonce of this version message before we send it so we can
	// detect self connections and so we can validate that the peer actually
	// controls the IP she's supposedly communicating to us from.
	vm.peerVersionNoncesSent[peerId] = verMsg.Nonce
	vm.usedNonces.Add(verMsg.Nonce)

	if err := vm.srv.SendMessage(verMsg, peerId, nil); err != nil {
		return errors.Wrap(err, "sendVersion: ")
	}

	return nil
}

func (vm *VersionManager) newVersionMessage(params *DeSoParams) *MsgDeSoVersion {
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
	if vm.hyperSync {
		ver.Services |= SFHyperSync
	}
	if vm.archivalMode {
		ver.Services |= SFArchivalNode
	}

	// When a node asks you for what height you have, you should reply with
	// the height of the latest actual block you have. This makes it so that
	// peers who have up-to-date headers but missing blocks won't be considered
	// for initial block download.
	//
	// TODO: This is ugly. It would be nice if the Peer required zero knowledge of the
	// Server and the Blockchain. Update (Piotr): Agreed!
	ver.StartBlockHeight = uint32(vm.bc.BlockTip().Header.Height)

	// Set the minimum fee rate the peer will accept.
	ver.MinFeeRateNanosPerKB = vm.minTxFeeRateNanosPerKB

	return ver
}

func (vm *VersionManager) _handleVersionMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	var verMsg *MsgDeSoVersion
	var ok bool
	if verMsg, ok = desoMsg.(*MsgDeSoVersion); !ok {
		return MessageHandlerResponseCodeSkip
	}

	if verMsg.Version < vm.params.MinProtocolVersion {
		glog.V(1).Infof("VersionManager._handleVersionMessage: Requesting PeerDisconnect for id: (%v) protocol version " +
			"too low: %d (min: %v)", origin.ID, verMsg.Version, vm.params.MinProtocolVersion)
		return MessageHandlerResponseCodePeerDisconnect
	}

	// If we've sent this nonce before then return an error since this is
	// a connection from ourselves.
	msgNonce := verMsg.Nonce
	if vm.usedNonces.Contains(msgNonce) {
		vm.usedNonces.Delete(msgNonce)
		glog.V(1).Infof("VersionManager._handleVersionMessage: Requesting PeerDisconnect for id: (%v) "+
			"nonce collision", origin.ID)
		return MessageHandlerResponseCodePeerDisconnect
	}
	// Save the version nonce so we can include it in our verack message.
	vm.peerVersionNoncesReceived[origin.ID] = msgNonce

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

func (vm *VersionManager) sendVerack(peerId uint64) error {
	verackMsg := NewMessage(MsgTypeVerack).(*MsgDeSoVerack)
	// Include the nonce we received in the peer's version message so
	// we can validate that we actually control our IP address.
	nonce, ok := vm.peerVersionNoncesReceived[peerId]
	if !ok {
		return fmt.Errorf("sendVerack: No nonce found for peer %d", peerId)
	}
	verackMsg.Nonce = nonce
	if err := vm.srv.SendMessage(verackMsg, peerId, nil); err != nil {
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

// TODO: Factor out of ConnectionManager to VersionManager
if err := peer.NegotiateVersion(cmgr.params.VersionNegotiationTimeout); err != nil {
/*
   TODO: Perhaps the caller will decide whether to disconnect or not.
   		// If we have an error in the version negotiation we disconnect
   		// from this peer.
   		peer.Conn.Close()
*/
return errors.Wrapf(err, "ConnectPeer: Problem negotiating version with peer with addr: (%s)", conn.RemoteAddr().String())
}
peer._logVersionSuccess()

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
