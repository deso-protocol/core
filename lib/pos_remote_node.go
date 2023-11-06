package lib

import (
	"encoding/binary"
	"fmt"
	"github.com/btcsuite/btcd/wire"
	"github.com/deso-protocol/core/bls"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	"math"
	"net"
	"time"
)

type RNConnectionType int

const (
	RNConnectionType_Unknown  RNConnectionType = 0
	RNConnectionType_Outbound RNConnectionType = 1
	RNConnectionType_Inboound RNConnectionType = 2
)

type RNConnectionStatus int

const (
	RNConnectionStatus_NotConnected RNConnectionStatus = 0
	RNConnectionStatus_Connected    RNConnectionStatus = 1
	RNConnectionStatus_Attempted    RNConnectionStatus = 2
	RNConnectionStatus_Terminated   RNConnectionStatus = 3
)

//type RemoteNodeId struct {
//	PeerId    uint64
//	AttemptId uint64
//}

type RemoteNode struct {
	// Should we have ID here?
	peer             *Peer
	id               RemoteNodeId
	connectionType   RNConnectionType
	connectionStatus RNConnectionStatus

	params *DeSoParams

	bc  *Blockchain
	srv *Server

	minTxFeeRateNanosPerKB uint64
	hyperSync              bool
	posValidator           bool

	handshakeMetadata *HandshakeMetadata
	keystore          *BLSKeystore
}

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

func NewRemoteNode() *RemoteNode {
	return &RemoteNode{
		id:                NewRemoteNodeNoId(),
		connectionType:    RNConnectionType_Unknown,
		connectionStatus:  RNConnectionStatus_NotConnected,
		handshakeMetadata: nil,
	}
}

func (rn *RemoteNode) SetConnectedPeer(peer *Peer) {
	rn.peer = peer
	if rn.peer == nil {
		return
	}

	// Set connectionType
	if rn.peer.IsOutbound() {
		rn.connectionType = RNConnectionType_Outbound
		rn.SetId(NewRemoteNodeOutboundId(peer.ID, peer.AttemptId()))
	} else {
		rn.connectionType = RNConnectionType_Inboound
		rn.SetId(NewRemoteNodeInboundId(peer.ID))
	}

	// Set connectionStatus
	rn.connectionStatus = RNConnectionStatus_Connected
}

func (rn *RemoteNode) GetPeer() *Peer {
	return rn.peer
}

func (rn *RemoteNode) IsInbound() bool {
	return rn.connectionType == RNConnectionType_Inboound
}

func (rn *RemoteNode) IsOutbound() bool {
	return rn.connectionType == RNConnectionType_Outbound
}

func (rn *RemoteNode) SetId(id RemoteNodeId) {
	rn.id = id
}

func (rn *RemoteNode) GetId() RemoteNodeId {
	return rn.id
}

func (rn *RemoteNode) GetPeerId() uint64 {
	peerId, _ := rn.id.GetIds()
	return peerId
}

func (rn *RemoteNode) CreateOutboundConnection(netAddr *wire.NetAddress) {
	if rn.connectionStatus != RNConnectionStatus_NotConnected {
		return
	}

	attemptId := rn.srv.CreateOutboundConnection(netAddr)
	id := NewRemoteNodeAttemptedId(attemptId)
	rn.SetId(id)
	rn.connectionStatus = RNConnectionStatus_Attempted
}

func (rn *RemoteNode) CreatePersistentOutboundConnection(netAddr *wire.NetAddress) {
	if rn.connectionStatus != RNConnectionStatus_NotConnected {
		return
	}

	attemptId := rn.srv.CreatePersistentOutboundConnection(netAddr)
	id := NewRemoteNodeAttemptedId(attemptId)
	rn.SetId(id)
	rn.connectionStatus = RNConnectionStatus_Attempted
}

func (rn *RemoteNode) ConnectInboundPeer(conn net.Conn, na *wire.NetAddress) error {
	peer := rn.srv.ConnectPeer(conn, na, RemoteNodeIdNoAttempt, false, false)
	if peer == nil {
		return errors.Errorf("ConnectInboundPeer: Problem connecting peer (%s)", conn.RemoteAddr().String())
	}
	rn.SetConnectedPeer(peer)
	return nil
}

func (rn *RemoteNode) ConnectOutboundPeer(conn net.Conn, na *wire.NetAddress, attemptId uint64, isOutbound bool, isPersistent bool) error {
	peer := rn.srv.ConnectPeer(conn, na, attemptId, isOutbound, isPersistent)
	if peer == nil {
		return errors.Errorf("ConnectInboundPeer: Problem connecting peer (%s)", conn.RemoteAddr().String())
	}
	rn.SetConnectedPeer(peer)
	return nil
}

func (rn *RemoteNode) Disconnect() {
	peerId, attemptId := rn.id.GetIds()
	switch rn.connectionStatus {
	case RNConnectionStatus_Attempted:
		rn.srv.CloseAttemptedConnection(attemptId)
	case RNConnectionStatus_Connected:
		rn.srv.CloseConnection(peerId)
	}
	rn.connectionStatus = RNConnectionStatus_Terminated
}

func (rn *RemoteNode) SendMessage(desoMsg DeSoMessage) {
	if rn.connectionStatus != RNConnectionStatus_Connected {
		return
	}

	if err := rn.srv.SendMessage(desoMsg, rn.GetPeerId()); err != nil {
		glog.Errorf("sendMessage: Problem sending message to peer (id= %d): %v", rn.peer.ID, err)
	}
}

func (rn *RemoteNode) InitiateHandshake(reserveNonce func(versionNonce uint64)) error {
	if rn.GetPeer() == nil {
		return errors.Errorf("Remote node has no peer")
	}

	if rn.GetPeer().IsOutbound() {
		vMeta := rn.GetHandshakeMetadata()
		versionTimeExpected := time.Now().Add(rn.params.VersionNegotiationTimeout)
		vMeta.versionTimeExpected = &versionTimeExpected
		rn.sendVersion(reserveNonce)
	}
	return nil
}

func (rn *RemoteNode) GetHandshakeMetadata() *HandshakeMetadata {
	if rn.handshakeMetadata == nil {
		rn.handshakeMetadata = &HandshakeMetadata{}
	}
	return rn.handshakeMetadata
}

func (rn *RemoteNode) sendVersion(reserveNonce func(versionNonce uint64)) {
	verMsg := rn.newVersionMessage()

	// Record the nonce of this version message before we send it so we can
	// detect self connections and so we can validate that the peer actually
	// controls the IP she's supposedly communicating to us from.
	vMeta := rn.GetHandshakeMetadata()
	vMeta.versionNoncesSent = verMsg.Nonce
	reserveNonce(verMsg.Nonce)

	if err := rn.srv.SendMessage(verMsg, rn.peer.ID); err != nil {
		glog.Errorf("sendVersion: Problem sending version message to peer (id= %d): %v", rn.peer.ID, err)
	}
}

// Assume that newVersionMessage is a method of RemoteNode and updates accordingly
func (rn *RemoteNode) newVersionMessage() *MsgDeSoVersion {
	ver := NewMessage(MsgTypeVersion).(*MsgDeSoVersion)

	ver.Version = rn.params.ProtocolVersion.ToUint64()
	ver.TstampSecs = time.Now().Unix()
	// We use an int64 instead of a uint64 for convenience but
	// this should be fine since we're just looking to generate a
	// unique value.
	ver.Nonce = uint64(RandInt64(math.MaxInt64))
	ver.UserAgent = rn.params.UserAgent
	// TODO: Right now all peers are full nodes. Later on we'll want to change this,
	// at which point we'll need to do a little refactoring.
	ver.Services = SFFullNodeDeprecated
	if rn.hyperSync {
		ver.Services |= SFHyperSync
	}
	if rn.bc.archivalMode {
		ver.Services |= SFArchivalNode
	}
	if rn.posValidator {
		ver.Services |= SFPosValidator
	}

	// When a node asks you for what height you have, you should reply with
	// the height of the latest actual block you have. This makes it so that
	// peers who have up-to-date headers but missing blocks won't be considered
	// for initial block download.
	ver.StartBlockHeight = uint32(rn.bc.BlockTip().Header.Height)

	// Set the minimum fee rate the peer will accept.
	ver.MinFeeRateNanosPerKB = rn.minTxFeeRateNanosPerKB

	return ver
}

func (rn *RemoteNode) HandleVersionMessage(verMsg *MsgDeSoVersion, reserveNonce func(versionNonce uint64)) {
	if verMsg.Version < rn.params.MinProtocolVersion {
		glog.V(1).Infof("RemoteNode.HandleVersionMessage: Requesting PeerDisconnect for id: (%v) "+
			"protocol version too low. Peer version: %v, min version: %v", rn.peer.ID, verMsg.Version, rn.params.MinProtocolVersion)
		rn.Disconnect()
		return
	}

	vMeta := rn.GetHandshakeMetadata()
	if vMeta.versionTimeExpected != nil && vMeta.versionTimeExpected.Before(time.Now()) {
		glog.V(1).Infof("RemoteNode.HandleVersionMessage: Requesting PeerDisconnect for id: (%v) "+
			"version timeout. Time expected: %v, now: %v", rn.peer.ID, vMeta.versionTimeExpected.UnixMicro(), time.Now().UnixMicro())
		rn.Disconnect()
		return
	}

	// Save the version nonce so we can include it in our verack message.
	vMeta.versionNoncesReceived = verMsg.Nonce

	// Set the peer info-related fields.
	vMeta.userAgent = verMsg.UserAgent
	vMeta.ServiceFlag = verMsg.Services
	vMeta.advertisedProtocolVersion = NewProtocolVersionType(verMsg.Version)
	negotiatedVersion := rn.params.ProtocolVersion
	if verMsg.Version < rn.params.ProtocolVersion.ToUint64() {
		negotiatedVersion = NewProtocolVersionType(verMsg.Version)
	}
	vMeta.negotiatedProtocolVersion = negotiatedVersion
	vMeta.minTxFeeRateNanosPerKB = verMsg.MinFeeRateNanosPerKB
	timeConnected := time.Unix(verMsg.TstampSecs, 0)
	vMeta.timeConnected = &timeConnected
	vMeta.timeOffsetSecs = verMsg.TstampSecs - time.Now().Unix()
	vMeta.StartingBlockHeight = verMsg.StartBlockHeight

	// Update the timeSource now that we've gotten a version message from the peer.
	rn.srv.AddTimeSample(rn.peer.Address(), timeConnected)

	if !rn.peer.IsOutbound() {
		// Respond to the version message if this is an inbound peer.
		rn.sendVersion(reserveNonce)
	}
	// After sending and receiving a compatible version, complete the
	// negotiation by sending and receiving a verack message.
	verackTimeExpected := time.Now().Add(rn.params.VersionNegotiationTimeout)
	vMeta.verackTimeExpected = &verackTimeExpected
	if err := rn.sendVerack(); err != nil {
		glog.Errorf("RemoteNode.HandleVersionMessage: Problem sending verack message to peer (id= %d): %v", rn.peer.ID, err)
		rn.Disconnect()
		return
	}
}

func (rn *RemoteNode) sendVerack() error {
	verackMsg, err := rn.newVerackMessage()
	if err != nil {
		return err
	}

	if err := rn.srv.SendMessage(verackMsg, rn.peer.ID); err != nil {
		glog.Errorf("RemoteNode.SendVerack: Problem sending verack message to peer (id= %d): %v", rn.peer.ID, err)
		return err
	}
	return nil
}

func (rn *RemoteNode) newVerackMessage() (*MsgDeSoVerack, error) {
	verack := NewMessage(MsgTypeVerack).(*MsgDeSoVerack)
	vMeta := rn.GetHandshakeMetadata()

	// Include the nonce we received in the peer's version message
	verack.NonceReceived = vMeta.versionNoncesReceived
	if vMeta.negotiatedProtocolVersion == ProtocolVersion2 {
		var err error
		verack.Version = VerackVersion1
		verack.NonceSent = vMeta.versionNoncesSent
		verack.PublicKey = rn.keystore.GetSigner().GetPublicKey()
		tstampMicro := uint64(time.Now().UnixMicro())
		verack.Signature, err = rn.keystore.GetSigner().SignPoSValidatorHandshake(verack.NonceSent, verack.NonceReceived, tstampMicro)
		if err != nil {
			return nil, fmt.Errorf("RemoteNode.newVerackMessage: Problem signing verack message: %v", err)
		}
	}
	return verack, nil
}

func (rn *RemoteNode) HandleVerackMessage(vrkMsg *MsgDeSoVerack) {
	vMeta := rn.GetHandshakeMetadata()
	nonceReceived := vMeta.versionNoncesReceived
	nonceSent := vMeta.versionNoncesSent

	if vMeta.verackTimeExpected != nil && vMeta.verackTimeExpected.Before(time.Now()) {
		glog.V(1).Infof("RemoteNode.HandleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
			"verack timeout. Time expected: %v, now: %v", rn.peer.ID, vMeta.verackTimeExpected.UnixMicro(), time.Now().UnixMicro())
		rn.srv.CloseConnection(rn.peer.ID)
		return
	}
	// If the verack message has a nonce unseen for us, then request peer disconnect.
	if vrkMsg.NonceReceived != nonceSent && vrkMsg.NonceReceived != nonceReceived {
		glog.V(1).Infof("RemoteNode.HandleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
			"nonce mismatch; message: %v; nonceSent: %v; nonceReceived: %v", rn.peer.ID, vrkMsg.NonceReceived, nonceSent, nonceReceived)
		rn.srv.CloseConnection(rn.peer.ID)
		return
	}
	if vMeta.negotiatedProtocolVersion == ProtocolVersion2 {
		// Verify that the verack message is formatted correctly.
		if vrkMsg.Version != VerackVersion1 {
			glog.V(1).Infof("RemoteNode.HandleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
				"verack version mismatch; message: %v; expected: %v", rn.peer.ID, vrkMsg.Version, VerackVersion1)
			rn.srv.CloseConnection(rn.peer.ID)
			return
		}
		// Verify that the counterparty's verack message's NonceSent matches the NonceReceived we sent.
		if vrkMsg.NonceSent != nonceReceived {
			glog.V(1).Infof("RemoteNode.HandleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
				"verack nonce mismatch; message: %v; expected: %v", rn.peer.ID, vrkMsg.NonceSent, nonceReceived)
			rn.srv.CloseConnection(rn.peer.ID)
			return
		}
		// Verify that the counterparty's verack message's NonceReceived matches the NonceSent we sent.
		if vrkMsg.NonceReceived != nonceSent {
			glog.V(1).Infof("RemoteNode.HandleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
				"verack nonce mismatch; message: %v; expected: %v", rn.peer.ID, vrkMsg.NonceReceived, nonceSent)
			rn.srv.CloseConnection(rn.peer.ID)
			return
		}
		if vrkMsg.PublicKey == nil || vrkMsg.Signature == nil {
			glog.V(1).Infof("RemoteNode.HandleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
				"verack public key or signature is nil", rn.peer.ID)
			rn.srv.CloseConnection(rn.peer.ID)
			return
		}

		// Get the current time in microseconds and make sure the verack message's timestamp is within 15 minutes of it.
		timeNowMicro := uint64(time.Now().UnixMicro())
		if vrkMsg.TstampMicro > timeNowMicro-rn.params.HandshakeTimeoutMicroSeconds {
			glog.V(1).Infof("RemoteNode.HandleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
				"verack timestamp too far in the past. Time now: %v, verack timestamp: %v", rn.peer.ID, timeNowMicro, vrkMsg.TstampMicro)
			rn.srv.CloseConnection(rn.peer.ID)
			return
		}

		ok, err := BLSVerifyPoSValidatorHandshake(vrkMsg.NonceSent, vrkMsg.NonceReceived, vrkMsg.TstampMicro,
			vrkMsg.Signature, vrkMsg.PublicKey)
		if err != nil || !ok {
			glog.V(1).Infof("RemoteNode.HandleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
				"verack signature verification failed: %v", rn.peer.ID, err)
			rn.srv.CloseConnection(rn.peer.ID)
			return
		}
		vMeta.validatorPublicKey = *vrkMsg.PublicKey
	}

	// If we get here then the peer has successfully completed the handshake.
	vMeta.versionNegotiated = true
	rn._logVersionSuccess(rn.peer)
	rn.srv.SendHandshakePeerMessage(rn.peer)
}

func (rn *RemoteNode) _logVersionSuccess(peer *Peer) {
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

func (hm *HandshakeMetadata) NegotiatedProtocolVersion() ProtocolVersionType {
	return hm.negotiatedProtocolVersion
}

func (hm *HandshakeMetadata) GetValidatorPublicKey() bls.PublicKey {
	return hm.validatorPublicKey
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
