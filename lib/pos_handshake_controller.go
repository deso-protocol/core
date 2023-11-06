package lib

import (
	"encoding/binary"
	"fmt"
	"github.com/decred/dcrd/lru"
	"github.com/deso-protocol/core/bls"
	"github.com/golang/glog"
	"golang.org/x/crypto/sha3"
	"math"
	"time"
)

type HandshakeMetadata struct {
	versionNoncesSent         uint64
	versionNoncesReceived     uint64
	userAgent                 string
	versionNegotiated         bool
	ServiceFlag               ServiceFlag
	advertisedProtocolVersion ProtocolVersionType
	negotiatedProtocolVersion ProtocolVersionType
	minTxFeeRateNanosPerKB    uint64
	timeConnected             *time.Time
	timeOffsetSecs            int64
	versionTimeExpected       *time.Time
	verackTimeExpected        *time.Time
	StartingBlockHeight       uint32
	validatorPublicKey        bls.PublicKey
}

func (hm *HandshakeMetadata) NegotiatedProtocolVersion() ProtocolVersionType {
	return hm.negotiatedProtocolVersion
}

func (hm *HandshakeMetadata) GetValidatorPublicKey() bls.PublicKey {
	return hm.validatorPublicKey
}

type HandshakeController struct {
	bc  *Blockchain
	srv *Server

	params                 *DeSoParams
	minTxFeeRateNanosPerKB uint64
	hyperSync              bool
	posValidator           bool
	keystore               *BLSKeystore

	handshakeMetadataMap map[uint64]*HandshakeMetadata
	usedNonces           lru.Cache
}

func NewHandshakeController(bc *Blockchain, srv *Server, params *DeSoParams, minTxFeeRateNanosPerKB uint64,
	hyperSync bool, signer *BLSKeystore) *HandshakeController {

	vm := &HandshakeController{
		bc:                     bc,
		srv:                    srv,
		params:                 params,
		minTxFeeRateNanosPerKB: minTxFeeRateNanosPerKB,
		hyperSync:              hyperSync,
		keystore:               signer,
		handshakeMetadataMap:   make(map[uint64]*HandshakeMetadata),
		usedNonces:             lru.NewCache(1000),
	}

	if signer != nil {
		vm.posValidator = true
	}

	return vm
}

func (hc *HandshakeController) GetHandshakeMetadata(peerId uint64) *HandshakeMetadata {
	return hc.getHandshakeMetadata(peerId)
}

func (hc *HandshakeController) getHandshakeMetadata(peerId uint64) *HandshakeMetadata {
	if _, exists := hc.handshakeMetadataMap[peerId]; !exists {
		hc.handshakeMetadataMap[peerId] = &HandshakeMetadata{}
	}
	return hc.handshakeMetadataMap[peerId]
}

func (hc *HandshakeController) _handleNewPeerMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeNewPeer {
		return
	}

	// TODO: Do we want to reject peers outright if their BLS key is not in the validator set? Or is it okay to reject
	// 	them in consensus upon handshake completion.
	if origin.IsOutbound() {
		vMeta := hc.getHandshakeMetadata(origin.ID)
		versionTimeExpected := time.Now().Add(hc.params.VersionNegotiationTimeout)
		vMeta.versionTimeExpected = &versionTimeExpected
		hc.sendVersion(origin.ID)
	}
}

func (hc *HandshakeController) _handleDonePeerMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeDonePeer {
		return
	}

	delete(hc.handshakeMetadataMap, origin.ID)
}

func (hc *HandshakeController) sendVersion(peerId uint64) {
	// For an outbound peer, we send a version message and then wait to
	// hear back for one.
	verMsg := hc.newVersionMessage()

	// Record the nonce of this version message before we send it so we can
	// detect self connections and so we can validate that the peer actually
	// controls the IP she's supposedly communicating to us from.
	vMeta := hc.getHandshakeMetadata(peerId)
	vMeta.versionNoncesSent = verMsg.Nonce
	hc.usedNonces.Add(verMsg.Nonce)

	if err := hc.srv.SendMessage(verMsg, peerId); err != nil {
		glog.Errorf("sendVersion: Problem sending version message to peer (id= %d): %v", peerId, err)
	}
}

func (hc *HandshakeController) newVersionMessage() *MsgDeSoVersion {
	ver := NewMessage(MsgTypeVersion).(*MsgDeSoVersion)

	ver.Version = hc.params.ProtocolVersion.ToUint64()
	ver.TstampSecs = time.Now().Unix()
	// We use an int64 instead of a uint64 for convenience but
	// this should be fine since we're just looking to generate a
	// unique value.
	ver.Nonce = uint64(RandInt64(math.MaxInt64))
	ver.UserAgent = hc.params.UserAgent
	// TODO: Right now all peers are full nodes. Later on we'll want to change this,
	// at which point we'll need to do a little refactoring.
	ver.Services = SFFullNodeDeprecated
	if hc.hyperSync {
		ver.Services |= SFHyperSync
	}
	if hc.bc.archivalMode {
		ver.Services |= SFArchivalNode
	}
	if hc.posValidator {
		ver.Services |= SFPosValidator
	}

	// When a node asks you for what height you have, you should reply with
	// the height of the latest actual block you have. This makes it so that
	// peers who have up-to-date headers but missing blocks won't be considered
	// for initial block download.
	ver.StartBlockHeight = uint32(hc.bc.BlockTip().Header.Height)

	// Set the minimum fee rate the peer will accept.
	ver.MinFeeRateNanosPerKB = hc.minTxFeeRateNanosPerKB

	return ver
}

func (hc *HandshakeController) _handleVersionMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeVersion {
		return
	}

	var verMsg *MsgDeSoVersion
	var ok bool
	if verMsg, ok = desoMsg.(*MsgDeSoVersion); !ok {
		hc.srv.CloseConnection(origin.ID)
		return
	}

	if verMsg.Version < hc.params.MinProtocolVersion {
		glog.V(1).Infof("HandshakeController._handleVersionMessage: Requesting PeerDisconnect for id: (%v) protocol version "+
			"too low: %d (min: %v)", origin.ID, verMsg.Version, hc.params.MinProtocolVersion)
		hc.srv.CloseConnection(origin.ID)
		return
	}

	vMeta := hc.getHandshakeMetadata(origin.ID)
	if vMeta.versionTimeExpected != nil && vMeta.versionTimeExpected.Before(time.Now()) {
		glog.V(1).Infof("HandshakeController._handleVersionMessage: Requesting PeerDisconnect for id: (%v) "+
			"version timeout. Time expected: %v, now: %v", origin.ID, vMeta.versionTimeExpected.UnixMicro(), time.Now().UnixMicro())
		hc.srv.CloseConnection(origin.ID)
		return
	}

	// If we've sent this nonce before then return an error since this is
	// a connection from ourselves.
	msgNonce := verMsg.Nonce
	if hc.usedNonces.Contains(msgNonce) {
		hc.usedNonces.Delete(msgNonce)
		glog.V(1).Infof("HandshakeController._handleVersionMessage: Requesting PeerDisconnect for id: (%v) "+
			"nonce collision", origin.ID)
		hc.srv.CloseConnection(origin.ID)
		return
	}
	// Save the version nonce so we can include it in our verack message.
	vMeta.versionNoncesReceived = msgNonce

	// Set the peer info-related fields.
	vMeta.userAgent = verMsg.UserAgent
	vMeta.ServiceFlag = verMsg.Services
	vMeta.advertisedProtocolVersion = NewProtocolVersionType(verMsg.Version)
	negotiatedVersion := hc.params.ProtocolVersion
	if verMsg.Version < hc.params.ProtocolVersion.ToUint64() {
		negotiatedVersion = NewProtocolVersionType(verMsg.Version)
	}
	vMeta.negotiatedProtocolVersion = negotiatedVersion
	vMeta.minTxFeeRateNanosPerKB = verMsg.MinFeeRateNanosPerKB
	timeConnected := time.Unix(verMsg.TstampSecs, 0)
	vMeta.timeConnected = &timeConnected
	vMeta.timeOffsetSecs = verMsg.TstampSecs - time.Now().Unix()
	vMeta.StartingBlockHeight = verMsg.StartBlockHeight

	// Update the timeSource now that we've gotten a version message from the peer.
	hc.srv.AddTimeSample(origin.Address(), timeConnected)

	if !origin.IsOutbound() {
		// Respond to the version message if this is an inbound peer.
		hc.sendVersion(origin.ID)
	}
	// After sending and receiving a compatible version, complete the
	// negotiation by sending and receiving a verack message.
	verackTimeExpected := time.Now().Add(hc.params.VersionNegotiationTimeout)
	vMeta.verackTimeExpected = &verackTimeExpected
	if err := hc.sendVerack(origin.ID); err != nil {
		glog.Errorf("HandshakeController._handleVersionMessage: Problem sending verack message to peer (id= %d): %v", origin.ID, err)
		hc.srv.CloseConnection(origin.ID)
		return
	}
}

func (hc *HandshakeController) newVerackMessage(peerId uint64) (*MsgDeSoVerack, error) {
	verack := NewMessage(MsgTypeVerack).(*MsgDeSoVerack)
	vMeta := hc.getHandshakeMetadata(peerId)

	// Include the nonce we received in the peer's version message
	verack.NonceReceived = vMeta.versionNoncesReceived
	if vMeta.negotiatedProtocolVersion == ProtocolVersion2 {
		var err error
		verack.Version = VerackVersion1
		verack.NonceSent = vMeta.versionNoncesSent
		verack.PublicKey = hc.keystore.GetSigner().GetPublicKey()
		tstampMicro := uint64(time.Now().UnixMicro())
		verack.Signature, err = hc.keystore.GetSigner().SignPoSValidatorHandshake(verack.NonceSent, verack.NonceReceived, tstampMicro)
		if err != nil {
			return nil, fmt.Errorf("HandshakeController.newVerackMessage: Problem signing verack message: %v", err)
		}
	}
	return verack, nil
}

func (hc *HandshakeController) sendVerack(peerId uint64) error {
	verackMsg, err := hc.newVerackMessage(peerId)
	if err != nil {
		return err
	}

	if err := hc.srv.SendMessage(verackMsg, peerId); err != nil {
		glog.Errorf("HandshakeController.sendVerack: Problem sending verack message to peer (id= %d): %v", peerId, err)
	}
	return nil
}

func (hc *HandshakeController) _handleVerackMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeVerack {
		return
	}

	var vrkMsg *MsgDeSoVerack
	var ok bool
	if vrkMsg, ok = desoMsg.(*MsgDeSoVerack); !ok {
		hc.srv.CloseConnection(origin.ID)
		return
	}

	vMeta := hc.getHandshakeMetadata(origin.ID)
	nonceReceived := vMeta.versionNoncesReceived
	nonceSent := vMeta.versionNoncesSent
	if !ok {
		glog.V(1).Infof("HandshakeController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
			"nonce not found for peer", origin.ID)
		hc.srv.CloseConnection(origin.ID)
		return
	}
	if vMeta.verackTimeExpected != nil && vMeta.verackTimeExpected.Before(time.Now()) {
		glog.V(1).Infof("HandshakeController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
			"verack timeout. Time expected: %v, now: %v", origin.ID, vMeta.verackTimeExpected.UnixMicro(), time.Now().UnixMicro())
		hc.srv.CloseConnection(origin.ID)
		return
	}
	// If the verack message has a nonce unseen for us, then request peer disconnect.
	// In legacy code we compared the msg nonce to both the sent nonce and the received nonce.
	if vrkMsg.NonceReceived != nonceSent && vrkMsg.NonceReceived != nonceReceived {
		glog.V(1).Infof("HandshakeController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
			"nonce mismatch; message: %v; nonceSent: %v; nonceReceived: %v", origin.ID, vrkMsg.NonceReceived, nonceSent, nonceReceived)
		hc.srv.CloseConnection(origin.ID)
		return
	}
	if vMeta.negotiatedProtocolVersion == ProtocolVersion2 {
		// Verify that the verack message is formatted correctly.
		if vrkMsg.Version != VerackVersion1 {
			glog.V(1).Infof("HandshakeController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
				"verack version mismatch; message: %v; expected: %v", origin.ID, vrkMsg.Version, VerackVersion1)
			hc.srv.CloseConnection(origin.ID)
			return
		}
		// Verify that the counterparty's verack message's NonceSent matches the NonceReceived we sent.
		if vrkMsg.NonceSent != nonceReceived {
			glog.V(1).Infof("HandshakeController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
				"verack nonce mismatch; message: %v; expected: %v", origin.ID, vrkMsg.NonceSent, nonceReceived)
			hc.srv.CloseConnection(origin.ID)
			return
		}
		// Verify that the counterparty's verack message's NonceReceived matches the NonceSent we sent.
		if vrkMsg.NonceReceived != nonceSent {
			glog.V(1).Infof("HandshakeController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
				"verack nonce mismatch; message: %v; expected: %v", origin.ID, vrkMsg.NonceReceived, nonceSent)
			hc.srv.CloseConnection(origin.ID)
			return
		}
		if vrkMsg.PublicKey == nil || vrkMsg.Signature == nil {
			glog.V(1).Infof("HandshakeController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
				"verack public key or signature is nil", origin.ID)
			hc.srv.CloseConnection(origin.ID)
			return
		}

		// Get a verifier with the other node's public key.
		verifier, err := hc.keystore.GetVerifier(vrkMsg.PublicKey)
		if err != nil {
			glog.V(1).Infof("HandshakeController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
				"verack public key not found", origin.ID)
			hc.srv.CloseConnection(origin.ID)
			return
		}

		// Get the current time in microseconds and make sure the verack message's timestamp is within 15 minutes of it.
		timeNowMicro := uint64(time.Now().UnixMicro())
		if vrkMsg.TstampMicro > timeNowMicro-hc.params.HandshakeTimeoutMicroSeconds {
			glog.V(1).Infof("HandshakeController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
				"verack timestamp too far in the past. Time now: %v, verack timestamp: %v", origin.ID, timeNowMicro, vrkMsg.TstampMicro)
			hc.srv.CloseConnection(origin.ID)
			return
		}

		ok, err = verifier.VerifyPoSValidatorHandshake(vrkMsg.NonceSent, vrkMsg.NonceReceived, vrkMsg.TstampMicro, vrkMsg.Signature)
		if err != nil || !ok {
			glog.V(1).Infof("HandshakeController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
				"verack signature verification failed: %v", origin.ID, err)
			hc.srv.CloseConnection(origin.ID)
			return
		}
		vMeta.validatorPublicKey = *vrkMsg.PublicKey
	}

	// If we get here then the peer has successfully completed the handshakeController.
	vMeta.versionNegotiated = true
	go hc.srv.SendHandshakePeerMessage(origin)

	hc._logVersionSuccess(origin)
	return
}

func (hc *HandshakeController) _logVersionSuccess(peer *Peer) {
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

func GetVerackHandshakePayload(nonceReceived uint64, nonceSent uint64, tstampMicro uint64) [32]byte {
	// The payload for the verack message is the two nonces concatenated together.
	// We do this so that we can sign the nonces and verify the signature on the other side.
	nonceReceivedBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceReceivedBytes, nonceReceived)

	nonceSentBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceSentBytes, nonceSent)

	tstampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tstampBytes, tstampMicro)

	payload := append(nonceReceivedBytes, nonceSentBytes...)
	payload = append(payload, tstampBytes...)

	return sha3.Sum256(payload)
}
