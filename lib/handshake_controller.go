package lib

import (
	"fmt"
	"github.com/decred/dcrd/lru"
	"github.com/golang/glog"
	"math"
	"sync"
)

// HandshakeController is a structure that handles the handshake process with remote nodes. It is the entry point for
// initiating a handshake with a remote node. It is also responsible for handling version/verack messages from remote
// nodes. And for handling the handshake complete control message.
type HandshakeController struct {
	mtxHandshakeComplete sync.Mutex

	rnManager  *RemoteNodeManager
	usedNonces lru.Cache
}

func NewHandshakeController(rnManager *RemoteNodeManager) *HandshakeController {

	vm := &HandshakeController{
		rnManager:  rnManager,
		usedNonces: lru.NewCache(1000),
	}

	return vm
}

// InitiateHandshake kicks off handshake with a remote node.
func (hc *HandshakeController) InitiateHandshake(rn *RemoteNode) {
	nonce := uint64(RandInt64(math.MaxInt64))
	if err := rn.InitiateHandshake(nonce); err != nil {
		glog.Errorf("RemoteNode.InitiateHandshake: Error initiating handshake: %v", err)
		hc.rnManager.Disconnect(rn)
	}
	hc.usedNonces.Add(nonce)
}

// _handleHandshakeCompleteMessage handles HandshakeComplete control messages, sent by RemoteNodes.
func (hc *HandshakeController) _handleHandshakeCompleteMessage(origin *Peer, desoMsg DeSoMessage) {
	// Prevent race conditions while handling handshake complete messages.
	hc.mtxHandshakeComplete.Lock()
	defer hc.mtxHandshakeComplete.Unlock()

	if desoMsg.GetMsgType() != MsgTypePeerHandshakeComplete {
		return
	}

	// Get the handshake information of this peer.
	remoteNode := hc.rnManager.GetRemoteNodeFromPeer(origin)
	if remoteNode == nil {
		return
	}

	if remoteNode.GetNegotiatedProtocolVersion().Before(ProtocolVersion2) {
		hc.rnManager.ProcessCompletedHandshake(remoteNode)
		return
	}

	if err := hc.handleHandshakeCompletePoSMessage(remoteNode); err != nil {
		glog.Errorf("HandshakeController._handleHandshakeCompleteMessage: Error handling PoS handshake peer message: %v", err)
		hc.rnManager.Disconnect(remoteNode)
		return
	}
	hc.rnManager.ProcessCompletedHandshake(remoteNode)
}

func (hc *HandshakeController) handleHandshakeCompletePoSMessage(remoteNode *RemoteNode) error {

	validatorPk := remoteNode.GetValidatorPublicKey()
	// If the remote node is not a potential validator, we don't need to do anything.
	if validatorPk == nil {
		return nil
	}

	// Lookup the validator in the ValidatorIndex with the same public key.
	existingValidator, ok := hc.rnManager.GetValidatorIndex().Get(validatorPk.Serialize())
	// For inbound RemoteNodes, we should ensure that there isn't an existing validator connected with the same public key.
	// Inbound nodes are not initiated by us, so we shouldn't have added the RemoteNode to the ValidatorIndex yet.
	if remoteNode.IsInbound() && ok {
		return fmt.Errorf("HandshakeController.handleHandshakeCompletePoSMessage: Inbound RemoteNode with duplicate validator public key")
	}
	// For outbound RemoteNodes, we have two possible scenarios. Either the RemoteNode has been initiated as a validator,
	// in which case it should already be in the ValidatorIndex. Or the RemoteNode has been initiated as a regular node,
	// in which case it should not be in the ValidatorIndex, but in the NonValidatorOutboundIndex. So to ensure there is
	// no duplicate connection with the same public key, we only check whether there is a validator in the ValidatorIndex
	// with the RemoteNode's public key. If there is one, we want to ensure that these two RemoteNodes have identical ids.
	if remoteNode.IsOutbound() && ok {
		if remoteNode.GetId() != existingValidator.GetId() {
			return fmt.Errorf("HandshakeController.handleHandshakeCompletePoSMessage: Outbound RemoteNode with duplicate validator public key. "+
				"Existing validator id: %v, new validator id: %v", existingValidator.GetId().ToUint64(), remoteNode.GetId().ToUint64())
		}
	}
	return nil
}

// _handleVersionMessage handles version messages, sent by RemoteNodes.
func (hc *HandshakeController) _handleVersionMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeVersion {
		return
	}

	rn := hc.rnManager.GetRemoteNodeFromPeer(origin)
	if rn == nil {
		// This should never happen.
		return
	}

	var verMsg *MsgDeSoVersion
	var ok bool
	if verMsg, ok = desoMsg.(*MsgDeSoVersion); !ok {
		glog.Errorf("HandshakeController._handleVersionMessage: Disconnecting RemoteNode with id: (%v) "+
			"error casting version message", origin.ID)
		hc.rnManager.Disconnect(rn)
		return
	}

	// If we've seen this nonce before then return an error since this is a connection from ourselves.
	msgNonce := verMsg.Nonce
	if hc.usedNonces.Contains(msgNonce) {
		hc.usedNonces.Delete(msgNonce)
		glog.Errorf("HandshakeController._handleVersionMessage: Disconnecting RemoteNode with id: (%v) "+
			"nonce collision", origin.ID)
		hc.rnManager.Disconnect(rn)
		return
	}

	// Call HandleVersionMessage on the RemoteNode.
	responseNonce := uint64(RandInt64(math.MaxInt64))
	if err := rn.HandleVersionMessage(verMsg, responseNonce); err != nil {
		glog.Errorf("HandshakeController._handleVersionMessage: Requesting PeerDisconnect for id: (%v) "+
			"error handling version message: %v", origin.ID, err)
		hc.rnManager.Disconnect(rn)
		return

	}
	hc.usedNonces.Add(responseNonce)
}

// _handleVerackMessage handles verack messages, sent by RemoteNodes.
func (hc *HandshakeController) _handleVerackMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeVerack {
		return
	}

	rn := hc.rnManager.GetRemoteNodeFromPeer(origin)
	if rn == nil {
		// This should never happen.
		return
	}

	var vrkMsg *MsgDeSoVerack
	var ok bool
	if vrkMsg, ok = desoMsg.(*MsgDeSoVerack); !ok {
		glog.Errorf("HandshakeController._handleVerackMessage: Disconnecting RemoteNode with id: (%v) "+
			"error casting verack message", origin.ID)
		hc.rnManager.Disconnect(rn)
		return
	}

	// Call HandleVerackMessage on the RemoteNode.
	if err := rn.HandleVerackMessage(vrkMsg); err != nil {
		glog.Errorf("HandshakeController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
			"error handling verack message: %v", origin.ID, err)
		hc.rnManager.Disconnect(rn)
	}
	return
}
