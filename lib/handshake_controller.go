package lib

import (
	"fmt"
	"github.com/decred/dcrd/lru"
	"github.com/golang/glog"
	"math"
	"sync"
)

// HandshakeManager is a structure that handles the handshake process with remote nodes. It is the entry point for
// initiating a handshake with a remote node. It is also responsible for handling version/verack messages from remote
// nodes. And for handling the handshake complete control message.
type HandshakeManager struct {
	mtxHandshakeComplete sync.Mutex

	rnManager  *RemoteNodeManager
	usedNonces lru.Cache
}

func NewHandshakeController(rnManager *RemoteNodeManager) *HandshakeManager {

	vm := &HandshakeManager{
		rnManager:  rnManager,
		usedNonces: lru.NewCache(1000),
	}

	return vm
}

// InitiateHandshake kicks off handshake with a remote node.
func (hm *HandshakeManager) InitiateHandshake(rn *RemoteNode) {
	nonce := uint64(RandInt64(math.MaxInt64))
	if err := rn.InitiateHandshake(nonce); err != nil {
		glog.Errorf("RemoteNode.InitiateHandshake: Error initiating handshake: %v", err)
		hm.rnManager.Disconnect(rn)
	}
	hm.usedNonces.Add(nonce)
}

// handleHandshakeComplete handles HandshakeComplete control messages, sent by RemoteNodes.
func (hm *HandshakeManager) handleHandshakeComplete(remoteNode *RemoteNode) {
	// Prevent race conditions while handling handshake complete messages.
	hm.mtxHandshakeComplete.Lock()
	defer hm.mtxHandshakeComplete.Unlock()

	// Get the handshake information of this peer.
	if remoteNode == nil {
		return
	}

	if remoteNode.GetNegotiatedProtocolVersion().Before(ProtocolVersion2) {
		hm.rnManager.ProcessCompletedHandshake(remoteNode)
		return
	}

	if err := hm.handleHandshakeCompletePoSMessage(remoteNode); err != nil {
		glog.Errorf("HandshakeManager.handleHandshakeComplete: Error handling PoS handshake peer message: %v, "+
			"remoteNodePk (%s)", err, remoteNode.GetValidatorPublicKey().Serialize())
		hm.rnManager.Disconnect(remoteNode)
		return
	}
	hm.rnManager.ProcessCompletedHandshake(remoteNode)
}

func (hm *HandshakeManager) handleHandshakeCompletePoSMessage(remoteNode *RemoteNode) error {

	validatorPk := remoteNode.GetValidatorPublicKey()
	// If the remote node is not a potential validator, we don't need to do anything.
	if validatorPk == nil {
		return nil
	}

	// Lookup the validator in the ValidatorIndex with the same public key.
	existingValidator, ok := hm.rnManager.GetValidatorIndex().Get(validatorPk.Serialize())
	// For inbound RemoteNodes, we should ensure that there isn't an existing validator connected with the same public key.
	// Inbound nodes are not initiated by us, so we shouldn't have added the RemoteNode to the ValidatorIndex yet.
	if remoteNode.IsInbound() && ok {
		return fmt.Errorf("HandshakeManager.handleHandshakeCompletePoSMessage: Inbound RemoteNode with duplicate validator public key")
	}
	// For outbound RemoteNodes, we have two possible scenarios. Either the RemoteNode has been initiated as a validator,
	// in which case it should already be in the ValidatorIndex. Or the RemoteNode has been initiated as a regular node,
	// in which case it should not be in the ValidatorIndex, but in the NonValidatorOutboundIndex. So to ensure there is
	// no duplicate connection with the same public key, we only check whether there is a validator in the ValidatorIndex
	// with the RemoteNode's public key. If there is one, we want to ensure that these two RemoteNodes have identical ids.
	if remoteNode.IsOutbound() && ok {
		if remoteNode.GetId() != existingValidator.GetId() {
			return fmt.Errorf("HandshakeManager.handleHandshakeCompletePoSMessage: Outbound RemoteNode with duplicate validator public key. "+
				"Existing validator id: %v, new validator id: %v", existingValidator.GetId().ToUint64(), remoteNode.GetId().ToUint64())
		}
	}
	return nil
}

// handleVersionMessage handles version messages, sent by RemoteNodes.
func (hm *HandshakeManager) handleVersionMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeVersion {
		return
	}

	rn := hm.rnManager.GetRemoteNodeFromPeer(origin)
	if rn == nil {
		// This should never happen.
		return
	}

	var verMsg *MsgDeSoVersion
	var ok bool
	if verMsg, ok = desoMsg.(*MsgDeSoVersion); !ok {
		glog.Errorf("HandshakeManager.handleVersionMessage: Disconnecting RemoteNode with id: (%v) "+
			"error casting version message", origin.ID)
		hm.rnManager.Disconnect(rn)
		return
	}

	// If we've seen this nonce before then return an error since this is a connection from ourselves.
	msgNonce := verMsg.Nonce
	if hm.usedNonces.Contains(msgNonce) {
		hm.usedNonces.Delete(msgNonce)
		glog.Errorf("HandshakeManager.handleVersionMessage: Disconnecting RemoteNode with id: (%v) "+
			"nonce collision, nonce (%v)", origin.ID, msgNonce)
		hm.rnManager.Disconnect(rn)
		return
	}

	// Call HandleVersionMessage on the RemoteNode.
	responseNonce := uint64(RandInt64(math.MaxInt64))
	if err := rn.HandleVersionMessage(verMsg, responseNonce); err != nil {
		glog.Errorf("HandshakeManager.handleVersionMessage: Requesting PeerDisconnect for id: (%v) "+
			"error handling version message: %v", origin.ID, err)
		hm.rnManager.Disconnect(rn)
		return

	}
	hm.usedNonces.Add(responseNonce)
}

// handleVerackMessage handles verack messages, sent by RemoteNodes.
func (hm *HandshakeManager) handleVerackMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeVerack {
		return
	}

	rn := hm.rnManager.GetRemoteNodeFromPeer(origin)
	if rn == nil {
		// This should never happen.
		return
	}

	var vrkMsg *MsgDeSoVerack
	var ok bool
	if vrkMsg, ok = desoMsg.(*MsgDeSoVerack); !ok {
		glog.Errorf("HandshakeManager.handleVerackMessage: Disconnecting RemoteNode with id: (%v) "+
			"error casting verack message", origin.ID)
		hm.rnManager.Disconnect(rn)
		return
	}

	// Call HandleVerackMessage on the RemoteNode.
	if err := rn.HandleVerackMessage(vrkMsg); err != nil {
		glog.Errorf("HandshakeManager.handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
			"error handling verack message: %v", origin.ID, err)
		hm.rnManager.Disconnect(rn)
		return
	}

	hm.handleHandshakeComplete(rn)
}
