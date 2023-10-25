package lib

import (
	"fmt"
	"github.com/decred/dcrd/lru"
	"github.com/golang/glog"
	"math"
	"time"
)

type ValidatorVersionMetadata struct {
	versionNoncesSent         uint64
	versionNoncesReceived     uint64
	userAgent                 string
	versionNegotiated         bool
	ServiceFlag               ServiceFlag
	advertisedProtocolVersion uint64
	negotiatedProtocolVersion uint64
	minTxFeeRateNanosPerKB    uint64
	timeConnected             *time.Time
	timeOffsetSecs            int64
	versionTimeExpected       *time.Time
	verackTimeExpected        *time.Time
	StartingBlockHeight       uint32
}

type VersionController struct {
	bc  *Blockchain
	srv *Server

	params                 *DeSoParams
	minTxFeeRateNanosPerKB uint64
	hyperSync              bool

	versionMetadataMap map[uint64]*ValidatorVersionMetadata
	usedNonces         lru.Cache
}

func NewVersionController(bc *Blockchain, srv *Server, params *DeSoParams, minTxFeeRateNanosPerKB uint64,
	hyperSync bool) *VersionController {

	vm := &VersionController{
		bc:                     bc,
		srv:                    srv,
		params:
		minTxFeeRateNanosPerKB: minTxFeeRateNanosPerKB,
		hyperSync:              hyperSync,
		versionMetadataMap:     make(map[uint64]*ValidatorVersionMetadata),
		usedNonces:             lru.NewCache(1000),
	}

	return vm
}

func (vm *VersionController) Init(controllers []Controller) {
	vm.srv.RegisterIncomingMessagesHandler(MsgTypeNewPeer, vm._handleNewPeerMessage)
	vm.srv.RegisterIncomingMessagesHandler(MsgTypeVersion, vm._handleVersionMessage)
	vm.srv.RegisterIncomingMessagesHandler(MsgTypeVerack, vm._handleVerackMessage)
}

func (vm *VersionController) Start() {
}

func (vm *VersionController) Stop() {
}

func (vm *VersionController) GetType() ControllerType {
	return ControllerTypeVersion
}

func (vm *VersionController) GetValidatorVersionMetadata(peerId uint64) *ValidatorVersionMetadata {
	return vm.getValidatorVersionMetadata(peerId)
}

func (vm *VersionController) getValidatorVersionMetadata(peerId uint64) *ValidatorVersionMetadata {
	if _, exists := vm.versionMetadataMap[peerId]; !exists {
		vm.versionMetadataMap[peerId] = &ValidatorVersionMetadata{}
	}
	return vm.versionMetadataMap[peerId]
}

func (vm *VersionController) _handleNewPeerMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeNewPeer {
		return MessageHandlerResponseCodeSkip
	}

	if origin.IsOutbound() {
		vMeta := vm.getValidatorVersionMetadata(origin.ID)
		versionTimeExpected := time.Now().Add(vm.params.VersionNegotiationTimeout)
		vMeta.versionTimeExpected = &versionTimeExpected
		return vm.sendVersion(origin.ID)
	}
	return MessageHandlerResponseCodeOK
}

func (vm *VersionController) sendVersion(peerId uint64) MessageHandlerResponseCode {
	// For an outbound peer, we send a version message and then wait to
	// hear back for one.
	verMsg := vm.newVersionMessage(vm.params)

	// Record the nonce of this version message before we send it so we can
	// detect self connections and so we can validate that the peer actually
	// controls the IP she's supposedly communicating to us from.
	vMeta := vm.getValidatorVersionMetadata(peerId)
	vMeta.versionNoncesSent = verMsg.Nonce
	vm.usedNonces.Add(verMsg.Nonce)

	if err := vm.srv.SendMessage(verMsg, peerId, nil); err != nil {
		return MessageHandlerResponseCodePeerUnavailable
	}

	return MessageHandlerResponseCodeOK
}

func (vm *VersionController) newVersionMessage(params *DeSoParams) *MsgDeSoVersion {
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
	if vm.bc.archivalMode {
		ver.Services |= SFArchivalNode
	}

	// When a node asks you for what height you have, you should reply with
	// the height of the latest actual block you have. This makes it so that
	// peers who have up-to-date headers but missing blocks won't be considered
	// for initial block download.
	ver.StartBlockHeight = uint32(vm.bc.BlockTip().Header.Height)

	// Set the minimum fee rate the peer will accept.
	ver.MinFeeRateNanosPerKB = vm.minTxFeeRateNanosPerKB

	return ver
}

func (vm *VersionController) _handleVersionMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeVersion {
		return MessageHandlerResponseCodeSkip
	}

	var verMsg *MsgDeSoVersion
	var ok bool
	if verMsg, ok = desoMsg.(*MsgDeSoVersion); !ok {
		return MessageHandlerResponseCodePeerDisconnect
	}

	if verMsg.Version < vm.params.MinProtocolVersion {
		glog.V(1).Infof("VersionController._handleVersionMessage: Requesting PeerDisconnect for id: (%v) protocol version "+
			"too low: %d (min: %v)", origin.ID, verMsg.Version, vm.params.MinProtocolVersion)
		return MessageHandlerResponseCodePeerDisconnect
	}

	vMeta := vm.getValidatorVersionMetadata(origin.ID)
	if vMeta.versionTimeExpected != nil && vMeta.versionTimeExpected.Before(time.Now()) {
		glog.V(1).Infof("VersionController._handleVersionMessage: Requesting PeerDisconnect for id: (%v) "+
			"version timeout. Time expected: %v, now: %v", origin.ID, vMeta.versionTimeExpected.UnixMicro(), time.Now().UnixMicro())
		return MessageHandlerResponseCodePeerDisconnect
	}

	// If we've sent this nonce before then return an error since this is
	// a connection from ourselves.
	msgNonce := verMsg.Nonce
	if vm.usedNonces.Contains(msgNonce) {
		vm.usedNonces.Delete(msgNonce)
		glog.V(1).Infof("VersionController._handleVersionMessage: Requesting PeerDisconnect for id: (%v) "+
			"nonce collision", origin.ID)
		return MessageHandlerResponseCodePeerDisconnect
	}
	// Save the version nonce so we can include it in our verack message.
	vMeta.versionNoncesReceived = msgNonce

	// Set the peer info-related fields.
	vMeta.userAgent = verMsg.UserAgent
	vMeta.ServiceFlag = verMsg.Services
	vMeta.advertisedProtocolVersion = verMsg.Version
	negotiatedVersion := vm.params.ProtocolVersion
	if verMsg.Version < vm.params.ProtocolVersion {
		negotiatedVersion = verMsg.Version
	}
	vMeta.negotiatedProtocolVersion = negotiatedVersion
	vMeta.minTxFeeRateNanosPerKB = verMsg.MinFeeRateNanosPerKB
	timeConnected := time.Unix(verMsg.TstampSecs, 0)
	vMeta.timeConnected = &timeConnected
	vMeta.timeOffsetSecs = verMsg.TstampSecs - time.Now().Unix()
	vMeta.StartingBlockHeight = verMsg.StartBlockHeight

	// Update the timeSource now that we've gotten a version message from the peer.
	vm.srv.AddTimeSample(origin.Address(), timeConnected)

	if !origin.IsOutbound() {
		// Respond to the version message if this is an inbound peer.
		if code := vm.sendVersion(origin.ID); code != MessageHandlerResponseCodeOK {
			return code
		}
	}
	// After sending and receiving a compatible version, complete the
	// negotiation by sending and receiving a verack message.
	verackTimeExpected := time.Now().Add(vm.params.VersionNegotiationTimeout)
	vMeta.verackTimeExpected = &verackTimeExpected
	return vm.sendVerack(origin.ID, msgNonce)
}

func (vm *VersionController) sendVerack(peerId uint64, nonce uint64) MessageHandlerResponseCode {
	verackMsg := NewMessage(MsgTypeVerack).(*MsgDeSoVerack)
	// Include the nonce we received in the peer's version message so
	// we can validate that we actually control our IP address.
	verackMsg.Nonce = nonce
	if err := vm.srv.SendMessage(verackMsg, peerId, nil); err != nil {
		return MessageHandlerResponseCodePeerUnavailable
	}

	return MessageHandlerResponseCodeOK
}

func (vm *VersionController) _handleVerackMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeVerack {
		return MessageHandlerResponseCodeSkip
	}

	var vrkMsg *MsgDeSoVerack
	var ok bool
	if vrkMsg, ok = desoMsg.(*MsgDeSoVerack); !ok {
		return MessageHandlerResponseCodePeerDisconnect
	}

	vMeta := vm.getValidatorVersionMetadata(origin.ID)
	nonceReceived := vMeta.versionNoncesReceived
	nonceSent := vMeta.versionNoncesSent
	if !ok {
		glog.V(1).Infof("VersionController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
			"nonce not found for peer", origin.ID)
		return MessageHandlerResponseCodePeerDisconnect
	}
	if vMeta.verackTimeExpected != nil && vMeta.verackTimeExpected.Before(time.Now()) {
		glog.V(1).Infof("VersionController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
			"verack timeout. Time expected: %v, now: %v", origin.ID, vMeta.verackTimeExpected.UnixMicro(), time.Now().UnixMicro())
		return MessageHandlerResponseCodePeerDisconnect
	}
	// If the verack message has a nonce unseen for us, then request peer disconnect.
	if vrkMsg.Nonce != nonceSent && vrkMsg.Nonce != nonceReceived {
		glog.V(1).Infof("VersionController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
			"nonce mismatch; message: %v; nonceSent: %v; nonceReceived: %v", origin.ID, vrkMsg.Nonce, nonceSent, nonceReceived)
		return MessageHandlerResponseCodePeerDisconnect
	}

	// If we get here then the peer has successfully completed the handshake.
	vMeta.versionNegotiated = true
	go vm.srv.SendHandshakePeerMessage(origin)

	vm._logVersionSuccess(origin)
	return MessageHandlerResponseCodeOK
}

func (vm *VersionController) _logVersionSuccess(peer *Peer) {
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
