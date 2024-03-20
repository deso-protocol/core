package lib

import (
	"encoding/binary"
	"fmt"
	"github.com/btcsuite/btcd/wire"
	"github.com/deso-protocol/core/bls"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	"net"
	"sync"
	"time"
)

type RemoteNodeStatus int

const (
	RemoteNodeStatus_NotConnected       RemoteNodeStatus = 0
	RemoteNodeStatus_Connected          RemoteNodeStatus = 1
	RemoteNodeStatus_VersionSent        RemoteNodeStatus = 2
	RemoteNodeStatus_VerackSent         RemoteNodeStatus = 3
	RemoteNodeStatus_HandshakeCompleted RemoteNodeStatus = 4
	RemoteNodeStatus_Attempted          RemoteNodeStatus = 5
	RemoteNodeStatus_Terminated         RemoteNodeStatus = 6
)

type RemoteNodeId uint64

func NewRemoteNodeId(id uint64) RemoteNodeId {
	return RemoteNodeId(id)
}

func (id RemoteNodeId) ToUint64() uint64 {
	return uint64(id)
}

// RemoteNode is a chain-aware wrapper around the network Peer object. It is used to manage the lifecycle of a peer
// and to store blockchain-related metadata about the peer. The RemoteNode can wrap around either an inbound or outbound
// peer connection. For outbound peers, the RemoteNode is created prior to the connection being established. In this case,
// the RemoteNode will be first used to initiate an OutboundConnectionAttempt, and then store the resulting connected peer.
// For inbound peers, the RemoteNode is created after the connection is established in ConnectionManager.
//
// Once the RemoteNode's peer is set, the RemoteNode is used to manage the handshake with the peer. The handshake involves
// rounds of Version and Verack messages being sent between our node and the peer. The handshake is complete when both
// nodes have sent and received a Version and Verack message. Once the handshake is successful, the RemoteNode will
// emit a MsgDeSoPeerHandshakeComplete control message via the Server.
//
// In steady state, i.e. after the handshake is complete, the RemoteNode can be used to send a message to the peer,
// retrieve the peer's handshake metadata, and close the connection with the peer. The RemoteNode has a single-use
// lifecycle. Once the RemoteNode is terminated, it will be disposed of, and a new RemoteNode must be created if we
// wish to reconnect to the peer in the future.
type RemoteNode struct {
	mtx sync.RWMutex

	peer *Peer
	// The id is the unique identifier of this RemoteNode. For outbound connections, the id will be the same as the
	// attemptId of the OutboundConnectionAttempt, and the subsequent id of the outbound peer. For inbound connections,
	// the id will be the same as the inbound peer's id.
	id RemoteNodeId
	// validatorPublicKey is the BLS public key of the validator node. This is only set for validator nodes. For
	// non-validator nodes, this will be nil. For outbound validators nodes, the validatorPublicKey will be set when
	// the RemoteNode is instantiated. And for inbound validator nodes, the validatorPublicKey will be set when the
	// handshake is completed.
	validatorPublicKey *bls.PublicKey
	// isPersistent identifies whether the RemoteNode is persistent or not. Persistent RemoteNodes is a sub-category of
	// outbound RemoteNodes. They are different from non-persistent RemoteNodes from the very moment they are created.
	// Initially, an outbound RemoteNode is in an "attempted" state, meaning we dial the connection to the peer. The
	// non-persistent RemoteNode is terminated after the first failed dial, while a persistent RemoteNode will keep
	// trying to dial the peer indefinitely until the connection is established, or the node stops.
	isPersistent bool

	connectionStatus RemoteNodeStatus

	params *DeSoParams
	srv    *Server
	cmgr   *ConnectionManager

	// minTxFeeRateNanosPerKB is the minimum transaction fee rate in nanos per KB that our node will accept.
	minTxFeeRateNanosPerKB uint64
	// latestBlockHeight is the block height of our node's block tip.
	latestBlockHeight uint64
	// nodeServices is a bitfield that indicates the services supported by our node.
	nodeServices ServiceFlag

	// handshakeMetadata is used to store the information received from the peer during the handshake.
	handshakeMetadata *HandshakeMetadata
	// keystore is a reference to the node's BLS private key storage. In the context of a RemoteNode, the keystore is
	// used in the Verack message for validator nodes to prove ownership of the validator BLS public key.
	keystore *BLSKeystore

	// versionTimeExpected is the latest time by which we expect to receive a Version message from the peer.
	// If the Version message is not received by this time, the connection will be terminated.
	versionTimeExpected *time.Time
	// verackTimeExpected is the latest time by which we expect to receive a Verack message from the peer.
	// If the Verack message is not received by this time, the connection will be terminated.
	verackTimeExpected *time.Time
}

// HandshakeMetadata stores the information received from the peer during the Version and Verack exchange.
type HandshakeMetadata struct {
	// ### The following fields are populated during the MsgDeSoVersion exchange.
	// versionNonceSent is the nonce sent in the Version message to the peer.
	versionNonceSent uint64
	// versionNonceReceived is the nonce received in the Version message from the peer.
	versionNonceReceived uint64
	// userAgent is a meta level label that can be used to analyze the network.
	userAgent string
	// serviceFlag is a bitfield that indicates the services supported by the peer.
	serviceFlag ServiceFlag
	// latestBlockHeight is the block height of the peer's block tip during the Version exchange.
	latestBlockHeight uint64
	// minTxFeeRateNanosPerKB is the minimum transaction fee rate in nanos per KB that the peer will accept.
	minTxFeeRateNanosPerKB uint64
	// advertisedProtocolVersion is the protocol version advertised by the peer.
	advertisedProtocolVersion ProtocolVersionType
	// negotiatedProtocolVersion is the protocol version negotiated between the peer and our node. This is the minimum
	// of the advertised protocol version and our node's protocol version.
	negotiatedProtocolVersion ProtocolVersionType
	// versionNegotiated is true if the peer passed the version negotiation step.
	versionNegotiated bool

	// ### The following fields are populated during the MsgDeSoVerack exchange.
	// validatorPublicKey is the BLS public key of the peer, if the peer is a validator node.
	validatorPublicKey *bls.PublicKey
}

func NewHandshakeMetadata() *HandshakeMetadata {
	return &HandshakeMetadata{}
}

func NewRemoteNode(id RemoteNodeId, validatorPublicKey *bls.PublicKey, isPersistent bool, srv *Server,
	cmgr *ConnectionManager, keystore *BLSKeystore, params *DeSoParams, minTxFeeRateNanosPerKB uint64,
	latestBlockHeight uint64, nodeServices ServiceFlag) *RemoteNode {
	return &RemoteNode{
		id:                     id,
		validatorPublicKey:     validatorPublicKey,
		isPersistent:           isPersistent,
		connectionStatus:       RemoteNodeStatus_NotConnected,
		handshakeMetadata:      NewHandshakeMetadata(),
		srv:                    srv,
		cmgr:                   cmgr,
		keystore:               keystore,
		params:                 params,
		minTxFeeRateNanosPerKB: minTxFeeRateNanosPerKB,
		latestBlockHeight:      latestBlockHeight,
		nodeServices:           nodeServices,
	}
}

// setStatusHandshakeCompleted sets the connection status of the remote node to HandshakeCompleted.
func (rn *RemoteNode) setStatusHandshakeCompleted() {
	rn.connectionStatus = RemoteNodeStatus_HandshakeCompleted
}

// setStatusConnected sets the connection status of the remote node to connected.
func (rn *RemoteNode) setStatusConnected() {
	rn.connectionStatus = RemoteNodeStatus_Connected
}

// setStatusVersionSent sets the connection status of the remote node to version sent.
func (rn *RemoteNode) setStatusVersionSent() {
	rn.connectionStatus = RemoteNodeStatus_VersionSent
}

// setStatusVerackSent sets the connection status of the remote node to verack sent.
func (rn *RemoteNode) setStatusVerackSent() {
	rn.connectionStatus = RemoteNodeStatus_VerackSent
}

// setStatusTerminated sets the connection status of the remote node to terminated.
func (rn *RemoteNode) setStatusTerminated() {
	rn.connectionStatus = RemoteNodeStatus_Terminated
}

// setStatusAttempted sets the connection status of the remote node to attempted.
func (rn *RemoteNode) setStatusAttempted() {
	rn.connectionStatus = RemoteNodeStatus_Attempted
}

func (rn *RemoteNode) GetId() RemoteNodeId {
	return rn.id
}

func (rn *RemoteNode) GetPeer() *Peer {
	return rn.peer
}

func (rn *RemoteNode) GetNegotiatedProtocolVersion() ProtocolVersionType {
	return rn.handshakeMetadata.negotiatedProtocolVersion
}

func (rn *RemoteNode) GetValidatorPublicKey() *bls.PublicKey {
	return rn.validatorPublicKey
}

func (rn *RemoteNode) GetServiceFlag() ServiceFlag {
	return rn.handshakeMetadata.serviceFlag
}

func (rn *RemoteNode) GetLatestBlockHeight() uint64 {
	return rn.handshakeMetadata.latestBlockHeight
}

func (rn *RemoteNode) GetUserAgent() string {
	return rn.handshakeMetadata.userAgent
}

func (rn *RemoteNode) GetNetAddress() *wire.NetAddress {
	if !rn.IsHandshakeCompleted() || rn.GetPeer() == nil {
		return nil
	}
	return rn.GetPeer().NetAddress()
}

func (rn *RemoteNode) IsInbound() bool {
	return rn.peer != nil && !rn.peer.IsOutbound()
}

func (rn *RemoteNode) IsOutbound() bool {
	return rn.peer != nil && rn.peer.IsOutbound()
}

func (rn *RemoteNode) IsPersistent() bool {
	return rn.isPersistent
}

func (rn *RemoteNode) IsNotConnected() bool {
	return rn.connectionStatus == RemoteNodeStatus_NotConnected
}

func (rn *RemoteNode) IsConnected() bool {
	return rn.connectionStatus == RemoteNodeStatus_Connected
}

func (rn *RemoteNode) IsVersionSent() bool {
	return rn.connectionStatus == RemoteNodeStatus_VersionSent
}

func (rn *RemoteNode) IsVerackSent() bool {
	return rn.connectionStatus == RemoteNodeStatus_VerackSent
}

func (rn *RemoteNode) IsHandshakeCompleted() bool {
	return rn.connectionStatus == RemoteNodeStatus_HandshakeCompleted
}

func (rn *RemoteNode) IsTerminated() bool {
	return rn.connectionStatus == RemoteNodeStatus_Terminated
}

func (rn *RemoteNode) IsValidator() bool {
	if !rn.IsHandshakeCompleted() {
		return false
	}
	return rn.hasValidatorServiceFlag()
}

func (rn *RemoteNode) IsExpectedValidator() bool {
	return rn.GetValidatorPublicKey() != nil
}

func (rn *RemoteNode) hasValidatorServiceFlag() bool {
	return rn.GetServiceFlag().HasService(SFPosValidator)
}

// DialOutboundConnection dials an outbound connection to the provided netAddr.
func (rn *RemoteNode) DialOutboundConnection(netAddr *wire.NetAddress) error {
	rn.mtx.Lock()
	defer rn.mtx.Unlock()

	if !rn.IsNotConnected() {
		return fmt.Errorf("RemoteNode.DialOutboundConnection: RemoteNode is not in the NotConnected state")
	}

	rn.cmgr.DialOutboundConnection(netAddr, rn.GetId().ToUint64())
	rn.setStatusAttempted()
	return nil
}

// DialPersistentOutboundConnection dials a persistent outbound connection to the provided netAddr.
func (rn *RemoteNode) DialPersistentOutboundConnection(netAddr *wire.NetAddress) error {
	rn.mtx.Lock()
	defer rn.mtx.Unlock()

	if !rn.IsNotConnected() {
		return fmt.Errorf("RemoteNode.DialPersistentOutboundConnection: RemoteNode is not in the NotConnected state")
	}

	rn.cmgr.DialPersistentOutboundConnection(netAddr, rn.GetId().ToUint64())
	rn.setStatusAttempted()
	return nil
}

// AttachInboundConnection creates an inbound peer once a successful inbound connection has been established.
func (rn *RemoteNode) AttachInboundConnection(conn net.Conn, na *wire.NetAddress) error {
	rn.mtx.Lock()
	defer rn.mtx.Unlock()

	// At this point, the RemoteNode must be in the NotConnected state. If the RemoteNode already progressed to
	// another state, we return an error.
	if !rn.IsNotConnected() {
		return fmt.Errorf("RemoteNode.AttachInboundConnection: RemoteNode is not in the NotConnected state")
	}

	id := rn.GetId().ToUint64()
	rn.peer = rn.cmgr.ConnectPeer(id, conn, na, false, false)
	versionTimeExpected := time.Now().Add(rn.params.VersionNegotiationTimeout)
	rn.versionTimeExpected = &versionTimeExpected
	rn.setStatusConnected()
	return nil
}

// AttachOutboundConnection creates an outbound peer once a successful outbound connection has been established.
func (rn *RemoteNode) AttachOutboundConnection(conn net.Conn, na *wire.NetAddress, isPersistent bool) error {
	rn.mtx.Lock()
	defer rn.mtx.Unlock()

	if rn.connectionStatus != RemoteNodeStatus_Attempted {
		return fmt.Errorf("RemoteNode.AttachOutboundConnection: RemoteNode is not in the Attempted state")
	}

	id := rn.GetId().ToUint64()
	rn.peer = rn.cmgr.ConnectPeer(id, conn, na, true, isPersistent)
	versionTimeExpected := time.Now().Add(rn.params.VersionNegotiationTimeout)
	rn.versionTimeExpected = &versionTimeExpected
	rn.setStatusConnected()
	return nil
}

// Disconnect disconnects the remote node, closing the attempted connection or the established connection.
func (rn *RemoteNode) Disconnect() {
	rn.mtx.Lock()
	defer rn.mtx.Unlock()

	if rn.connectionStatus == RemoteNodeStatus_Terminated {
		return
	}
	glog.V(2).Infof("RemoteNode.Disconnect: Disconnecting from peer (id= %d, status= %v)",
		rn.id, rn.connectionStatus)

	id := rn.GetId().ToUint64()
	switch rn.connectionStatus {
	case RemoteNodeStatus_Attempted:
		rn.cmgr.CloseAttemptedConnection(id)
	case RemoteNodeStatus_Connected, RemoteNodeStatus_VersionSent, RemoteNodeStatus_VerackSent,
		RemoteNodeStatus_HandshakeCompleted:
		rn.cmgr.CloseConnection(id)
	}
	rn.setStatusTerminated()
}

func (rn *RemoteNode) SendMessage(desoMsg DeSoMessage) error {
	rn.mtx.RLock()
	rn.mtx.RUnlock()

	if rn.connectionStatus != RemoteNodeStatus_HandshakeCompleted {
		return fmt.Errorf("SendMessage: Remote node is not connected")
	}

	return rn.sendMessage(desoMsg)
}

func (rn *RemoteNode) sendMessage(desoMsg DeSoMessage) error {
	if err := rn.cmgr.SendMessage(desoMsg, rn.GetId().ToUint64()); err != nil {
		return fmt.Errorf("SendMessage: Problem sending message to peer (id= %d): %v", rn.id, err)
	}
	return nil
}

// InitiateHandshake is a starting point for a peer handshake. If the peer is outbound, a version message is sent
// to the peer. If the peer is inbound, the peer is expected to send a version message to us first.
func (rn *RemoteNode) InitiateHandshake(nonce uint64) error {
	rn.mtx.Lock()
	defer rn.mtx.Unlock()

	if rn.connectionStatus != RemoteNodeStatus_Connected {
		return fmt.Errorf("InitiateHandshake: Remote node is not connected")
	}

	if rn.GetPeer().IsOutbound() {
		if err := rn.sendVersionMessage(nonce); err != nil {
			return fmt.Errorf("InitiateHandshake: Problem sending version message to peer (id= %d): %v", rn.id, err)
		}
		rn.setStatusVersionSent()
	}
	return nil
}

// sendVersionMessage generates and sends a version message to a RemoteNode peer. The message will contain the nonce
// that is passed in as an argument.
func (rn *RemoteNode) sendVersionMessage(nonce uint64) error {
	verMsg := rn.newVersionMessage(nonce)

	// Record the nonce of this version message before we send it so we can
	// detect self connections and so we can validate that the peer actually
	// controls the IP she's supposedly communicating to us from.
	rn.handshakeMetadata.versionNonceSent = nonce

	if err := rn.sendMessage(verMsg); err != nil {
		return fmt.Errorf("sendVersionMessage: Problem sending version message to peer (id= %d): %v", rn.id, err)
	}
	return nil
}

// newVersionMessage returns a new version message that can be sent to a RemoteNode. The message will contain the
// nonce that is passed in as an argument.
func (rn *RemoteNode) newVersionMessage(nonce uint64) *MsgDeSoVersion {
	ver := NewMessage(MsgTypeVersion).(*MsgDeSoVersion)

	ver.Version = rn.params.ProtocolVersion.ToUint64()
	// Set the services bitfield to indicate what services this node supports.
	ver.Services = rn.nodeServices

	// We use an int64 instead of a uint64 for convenience.
	ver.TstampSecs = time.Now().Unix()

	ver.Nonce = nonce
	ver.UserAgent = rn.params.UserAgent

	// When a node asks you for what height you have, you should reply with the height of the latest actual block you
	// have. This makes it so that peers who have up-to-date headers but missing blocks won't be considered for initial
	// block download.
	ver.LatestBlockHeight = rn.latestBlockHeight

	// Set the minimum fee rate the peer will accept.
	ver.MinFeeRateNanosPerKB = rn.minTxFeeRateNanosPerKB

	return ver
}

func (rn *RemoteNode) IsTimedOut() bool {
	if rn.IsTerminated() {
		return true
	}
	if rn.IsConnected() || rn.IsVersionSent() {
		return rn.versionTimeExpected.Before(time.Now())
	}
	if rn.IsVerackSent() {
		return rn.verackTimeExpected.Before(time.Now())
	}
	return false
}

// HandleVersionMessage is called upon receiving a version message from the RemoteNode's peer. The peer may be the one
// initiating the handshake, in which case, we should respond with our own version message. To do this, we pass the
// responseNonce to this function, which we will use in our response version message.
func (rn *RemoteNode) HandleVersionMessage(verMsg *MsgDeSoVersion, responseNonce uint64) error {
	rn.mtx.Lock()
	defer rn.mtx.Unlock()

	if !rn.IsConnected() && !rn.IsVersionSent() {
		return fmt.Errorf("HandleVersionMessage: RemoteNode is not connected or version exchange has already "+
			"been completed, connectionStatus: %v", rn.connectionStatus)
	}

	// Verify that the peer's version matches our minimal supported version.
	if verMsg.Version < rn.params.MinProtocolVersion {
		return fmt.Errorf("RemoteNode.HandleVersionMessage: Requesting disconnect for id: (%v) "+
			"protocol version too low. Peer version: %v, min version: %v", rn.id, verMsg.Version, rn.params.MinProtocolVersion)
	}

	// Verify that the peer's version message is sent within the version negotiation timeout.
	if rn.versionTimeExpected.Before(time.Now()) {
		return fmt.Errorf("RemoteNode.HandleVersionMessage: Requesting disconnect for id: (%v) "+
			"version timeout. Time expected: %v, now: %v", rn.id, rn.versionTimeExpected.UnixMicro(), time.Now().UnixMicro())
	}

	vMeta := rn.handshakeMetadata
	// Record the version the peer is using.
	vMeta.advertisedProtocolVersion = NewProtocolVersionType(verMsg.Version)
	// Make sure the latest supported protocol version is ProtocolVersion2.
	if vMeta.advertisedProtocolVersion.After(ProtocolVersion2) {
		return fmt.Errorf("RemoteNode.HandleVersionMessage: Requesting disconnect for id: (%v) "+
			"protocol version too high. Peer version: %v, max version: %v", rn.id, verMsg.Version, ProtocolVersion2)
	}

	// Decide on the protocol version to use for this connection.
	negotiatedVersion := rn.params.ProtocolVersion
	if verMsg.Version < rn.params.ProtocolVersion.ToUint64() {
		// In order to smoothly transition to the PoS fork, we prevent establishing new outbound connections with
		// outdated nodes that run on ProtocolVersion1. This is because ProtocolVersion1 nodes will not be able to
		// validate the PoS blocks and will be stuck on the PoW chain, unless they upgrade to ProtocolVersion2.
		if rn.params.ProtocolVersion == ProtocolVersion2 && rn.IsOutbound() {
			return fmt.Errorf("RemoteNode.HandleVersionMessage: Requesting disconnect for id: (%v). Version too low. "+
				"Outbound RemoteNodes must use at least ProtocolVersion2, instead received version: %v", rn.id, verMsg.Version)
		}

		negotiatedVersion = NewProtocolVersionType(verMsg.Version)
	}

	vMeta.negotiatedProtocolVersion = negotiatedVersion

	// Record the services the peer is advertising.
	vMeta.serviceFlag = verMsg.Services
	// If the RemoteNode was connected with an expectation of being a validator, make sure that its advertised ServiceFlag
	// indicates that it is a validator.
	if !rn.hasValidatorServiceFlag() && rn.validatorPublicKey != nil {
		return fmt.Errorf("RemoteNode.HandleVersionMessage: Requesting disconnect for id: (%v). "+
			"Expected validator, but received invalid ServiceFlag: %v", rn.id, verMsg.Services)
	}
	// If the RemoteNode is on ProtocolVersion1, then it must not have the validator service flag set.
	if rn.hasValidatorServiceFlag() && vMeta.advertisedProtocolVersion.Before(ProtocolVersion2) {
		return fmt.Errorf("RemoteNode.HandleVersionMessage: Requesting disconnect for id: (%v). "+
			"RemoteNode has SFValidator service flag, but doesn't have ProtocolVersion2 or later", rn.id)
	}

	// Save the received version nonce so we can include it in our verack message.
	vMeta.versionNonceReceived = verMsg.Nonce

	// Set the peer info-related fields.
	vMeta.userAgent = verMsg.UserAgent
	vMeta.latestBlockHeight = verMsg.LatestBlockHeight
	vMeta.minTxFeeRateNanosPerKB = verMsg.MinFeeRateNanosPerKB

	// Respond to the version message if this is an inbound peer.
	if rn.IsInbound() {
		if err := rn.sendVersionMessage(responseNonce); err != nil {
			return errors.Wrapf(err, "RemoteNode.HandleVersionMessage: Problem sending version message to peer (id= %d)", rn.id)
		}
	}

	// After sending and receiving a compatible version, send the verack message. Notice that we don't wait for the
	// peer's verack message even if it is an inbound peer. Instead, we just send the verack message right away.

	// Set the latest time by which we should receive a verack message from the peer.
	verackTimeExpected := time.Now().Add(rn.params.VerackNegotiationTimeout)
	rn.verackTimeExpected = &verackTimeExpected
	if err := rn.sendVerack(); err != nil {
		return errors.Wrapf(err, "RemoteNode.HandleVersionMessage: Problem sending verack message to peer (id= %d)", rn.id)
	}

	// Update the timeSource now that we've gotten a version message from the peer.
	rn.setStatusVerackSent()
	return nil
}

// sendVerack constructs and sends a verack message to the peer.
func (rn *RemoteNode) sendVerack() error {
	verackMsg, err := rn.newVerackMessage()
	if err != nil {
		return err
	}

	if err := rn.sendMessage(verackMsg); err != nil {
		return errors.Wrapf(err, "RemoteNode.SendVerack: Problem sending verack message to peer (id= %d): %v", rn.id, err)
	}
	return nil
}

// newVerackMessage constructs a verack message to be sent to the peer.
func (rn *RemoteNode) newVerackMessage() (*MsgDeSoVerack, error) {
	verack := NewMessage(MsgTypeVerack).(*MsgDeSoVerack)
	vMeta := rn.handshakeMetadata

	switch vMeta.negotiatedProtocolVersion {
	case ProtocolVersion0, ProtocolVersion1:
		// For protocol versions 0 and 1, we just send back the nonce we received from the peer in the version message.
		verack.Version = VerackVersion0
		verack.NonceReceived = vMeta.versionNonceReceived
	case ProtocolVersion2:
		// For protocol version 2, we need to send the nonce we received from the peer in their version message.
		// We also need to send our own nonce, which we generate for our version message. In addition, we need to
		// send a current timestamp (in microseconds). We then sign the tuple of (nonceReceived, nonceSent, tstampMicro)
		// using our validator BLS key, and send the signature along with our public key.
		var err error
		verack.Version = VerackVersion1
		verack.NonceReceived = vMeta.versionNonceReceived
		verack.NonceSent = vMeta.versionNonceSent
		tstampMicro := uint64(time.Now().UnixMicro())
		verack.TstampMicro = tstampMicro
		// If the RemoteNode is not a validator, then we don't need to sign the verack message.
		if !rn.nodeServices.HasService(SFPosValidator) {
			break
		}
		verack.PublicKey = rn.keystore.GetSigner().GetPublicKey()
		verack.Signature, err = rn.keystore.GetSigner().SignPoSValidatorHandshake(verack.NonceSent, verack.NonceReceived, tstampMicro)
		if err != nil {
			return nil, fmt.Errorf("RemoteNode.newVerackMessage: Problem signing verack message: %v", err)
		}
	}
	return verack, nil
}

// HandleVerackMessage handles a verack message received from the peer.
func (rn *RemoteNode) HandleVerackMessage(vrkMsg *MsgDeSoVerack) error {
	rn.mtx.Lock()
	defer rn.mtx.Unlock()

	if rn.connectionStatus != RemoteNodeStatus_VerackSent {
		return fmt.Errorf("RemoteNode.HandleVerackMessage: Requesting disconnect for id: (%v) "+
			"verack received while in state: %v", rn.id, rn.connectionStatus)
	}

	if rn.verackTimeExpected != nil && rn.verackTimeExpected.Before(time.Now()) {
		return fmt.Errorf("RemoteNode.HandleVerackMessage: Requesting disconnect for id: (%v) "+
			"verack timeout. Time expected: %v, now: %v", rn.id, rn.verackTimeExpected.UnixMicro(), time.Now().UnixMicro())
	}

	var err error
	vMeta := rn.handshakeMetadata
	switch vMeta.negotiatedProtocolVersion {
	case ProtocolVersion0, ProtocolVersion1:
		err = rn.validateVerackPoW(vrkMsg)
	case ProtocolVersion2:
		err = rn.validateVerackPoS(vrkMsg)
	}

	if err != nil {
		return errors.Wrapf(err, "RemoteNode.HandleVerackMessage: Problem validating verack message from peer (id= %d)", rn.id)
	}

	// If we get here then the peer has successfully completed the handshake.
	vMeta.versionNegotiated = true
	rn._logVersionSuccess()
	rn.setStatusHandshakeCompleted()

	return nil
}

func (rn *RemoteNode) validateVerackPoW(vrkMsg *MsgDeSoVerack) error {
	vMeta := rn.handshakeMetadata

	// Verify that the verack message is formatted correctly according to the PoW standard.
	if vrkMsg.Version != VerackVersion0 {
		return fmt.Errorf("RemoteNode.validateVerackPoW: Requesting disconnect for id: (%v) "+
			"verack version mismatch; message: %v; expected: %v", rn.id, vrkMsg.Version, VerackVersion0)
	}

	// If the verack message has a nonce that wasn't previously sent to us in the version message, return an error.
	if vrkMsg.NonceReceived != vMeta.versionNonceSent {
		return fmt.Errorf("RemoteNode.validateVerackPoW: Requesting disconnect for id: (%v) nonce mismatch; "+
			"message: %v; nonceSent: %v", rn.id, vrkMsg.NonceReceived, vMeta.versionNonceSent)
	}

	return nil
}

func (rn *RemoteNode) validateVerackPoS(vrkMsg *MsgDeSoVerack) error {
	vMeta := rn.handshakeMetadata

	// Verify that the verack message is formatted correctly according to the PoS standard.
	if vrkMsg.Version != VerackVersion1 {
		return fmt.Errorf("RemoteNode.validateVerackPoS: Requesting disconnect for id: (%v) "+
			"verack version mismatch; message: %v; expected: %v", rn.id, vrkMsg.Version, VerackVersion1)
	}

	// Verify that the counterparty's verack message's NonceReceived matches the NonceSent we sent.
	if vrkMsg.NonceReceived != vMeta.versionNonceSent {
		return fmt.Errorf("RemoteNode.validateVerackPoS: Requesting disconnect for id: (%v) nonce mismatch; "+
			"message: %v; nonceSent: %v", rn.id, vrkMsg.NonceReceived, vMeta.versionNonceSent)
	}

	// Verify that the counterparty's verack message's NonceSent matches the NonceReceived we sent.
	if vrkMsg.NonceSent != vMeta.versionNonceReceived {
		return fmt.Errorf("RemoteNode.validateVerackPoS: Requesting disconnect for id: (%v) "+
			"verack nonce mismatch; message: %v; expected: %v", rn.id, vrkMsg.NonceSent, vMeta.versionNonceReceived)
	}

	// Get the current time in microseconds and make sure the verack message's timestamp is within 15 minutes of it.
	timeNowMicro := uint64(time.Now().UnixMicro())
	if vrkMsg.TstampMicro < timeNowMicro-rn.params.HandshakeTimeoutMicroSeconds {
		return fmt.Errorf("RemoteNode.validateVerackPoS: Requesting disconnect for id: (%v) "+
			"verack timestamp too far in the past. Time now: %v, verack timestamp: %v", rn.id, timeNowMicro, vrkMsg.TstampMicro)
	}

	// If the RemoteNode is not a validator, then we don't need to verify the verack message's signature.
	if !rn.hasValidatorServiceFlag() {
		return nil
	}

	// Make sure the verack message's public key and signature are not nil.
	if vrkMsg.PublicKey == nil || vrkMsg.Signature == nil {
		return fmt.Errorf("RemoteNode.validateVerackPoS: Requesting disconnect for id: (%v) "+
			"verack public key or signature is nil", rn.id)
	}

	// Verify the verack message's signature.
	ok, err := BLSVerifyPoSValidatorHandshake(vrkMsg.NonceSent, vrkMsg.NonceReceived, vrkMsg.TstampMicro,
		vrkMsg.Signature, vrkMsg.PublicKey)
	if err != nil {
		return errors.Wrapf(err, "RemoteNode.validateVerackPoS: Requesting disconnect for id: (%v) "+
			"verack signature verification failed with error", rn.id)
	}
	if !ok {
		return fmt.Errorf("RemoteNode.validateVerackPoS: Requesting disconnect for id: (%v) "+
			"verack signature verification failed", rn.id)
	}

	if rn.validatorPublicKey != nil && rn.validatorPublicKey.Serialize() != vrkMsg.PublicKey.Serialize() {
		return fmt.Errorf("RemoteNode.validateVerackPoS: Requesting disconnect for id: (%v) "+
			"verack public key mismatch; message: %v; expected: %v", rn.id, vrkMsg.PublicKey, rn.validatorPublicKey)
	}

	// If we get here then the verack message is valid. Set the validator public key on the peer.
	vMeta.validatorPublicKey = vrkMsg.PublicKey
	rn.validatorPublicKey = vrkMsg.PublicKey
	return nil
}

func (rn *RemoteNode) _logVersionSuccess() {
	inboundStr := "INBOUND"
	if rn.IsOutbound() {
		inboundStr = "OUTBOUND"
	}
	persistentStr := "PERSISTENT"
	if !rn.IsPersistent() {
		persistentStr = "NON-PERSISTENT"
	}
	logStr := fmt.Sprintf("SUCCESS version negotiation for (%s) (%s) id=(%v).", inboundStr, persistentStr, rn.id.ToUint64())
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
