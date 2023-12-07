package lib

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/deso-protocol/core/bls"
)

type RemoteNodeIndexerManager struct {
	remoteNodeIndexer *RemoteNodeIndexer
}

func NewRemoteNodeIndexerManager() *RemoteNodeIndexerManager {
	return &RemoteNodeIndexerManager{
		remoteNodeIndexer: NewRemoteNodeIndexer(),
	}
}

func (manager *RemoteNodeIndexerManager) GetRemoteNodeIndexer() *RemoteNodeIndexer {
	return manager.remoteNodeIndexer
}

func (manager *RemoteNodeIndexerManager) GetRemoteNodeFromPeer(peer *Peer) *RemoteNode {
	return manager.GetRemoteNodeIndexer().GetRemoteNodeFromPeer(peer)
}

func (manager *RemoteNodeIndexerManager) DisconnectPeer(peer *Peer) {
	rn := manager.GetRemoteNodeFromPeer(peer)
	if rn == nil {
		return
	}

	manager.Disconnect(rn)
}

func (manager *RemoteNodeIndexerManager) Disconnect(rn *RemoteNode) {
	rn.Disconnect()
	manager.GetRemoteNodeIndexer().RemoveRemoteNode(rn)
}

func (manager *RemoteNodeIndexerManager) RemovePeer(peer *Peer) {
	rn := manager.GetRemoteNodeFromPeer(peer)
	manager.GetRemoteNodeIndexer().RemoveRemoteNode(rn)
}

func (manager *RemoteNodeIndexerManager) SendMessageToPeer(peer *Peer, desoMessage DeSoMessage) {
	rn := manager.GetRemoteNodeFromPeer(peer)
	if rn == nil {
		return
	}

	rn.SendMessage(desoMessage)
}

func (manager *RemoteNodeIndexerManager) CreateValidatorConnection(netAddr *wire.NetAddress, publicKey bls.PublicKey) {
	if netAddr == nil {
		return
	}

	remoteNode := NewRemoteNode()
	remoteNode.CreatePersistentOutboundConnection(netAddr)
	manager.GetRemoteNodeIndexer().SetRemoteNode(remoteNode)
	manager.GetRemoteNodeIndexer().GetValidatorAttemptedIndex().Add(publicKey, remoteNode)
}

func (manager *RemoteNodeIndexerManager) CreatePersistentOutboundConnectionNetAddress(netAddr *wire.NetAddress) {
	if netAddr == nil {
		return
	}

	remoteNode := NewRemoteNode()
	remoteNode.CreatePersistentOutboundConnection(netAddr)
	manager.GetRemoteNodeIndexer().SetRemoteNode(remoteNode)
	manager.GetRemoteNodeIndexer().GetNonValidatorAttemptedIndex().Add(remoteNode.GetId(), remoteNode)
}

func (manager *RemoteNodeIndexerManager) CreateOutboundConnectionNetAddress(netAddr *wire.NetAddress) {
	if netAddr == nil {
		return
	}

	remoteNode := NewRemoteNode()
	remoteNode.CreateOutboundConnection(netAddr)
	manager.GetRemoteNodeIndexer().SetRemoteNode(remoteNode)
	manager.GetRemoteNodeIndexer().GetNonValidatorAttemptedIndex().Add(remoteNode.GetId(), remoteNode)
}

func (manager *RemoteNodeIndexerManager) AddRemoteNode(remoteNode *RemoteNode) {
	manager.GetRemoteNodeIndexer().SetRemoteNode(remoteNode)
}

func (manager *RemoteNodeIndexerManager) SetValidator(pk bls.PublicKey, rn *RemoteNode) {
	if rn == nil {
		return
	}
	manager.GetRemoteNodeIndexer().GetValidatorIndex().Add(pk, rn)

	if rn.IsOutbound() {
		manager.GetRemoteNodeIndexer().GetNonValidatorOutboundIndex().Remove(rn.GetId())
	} else if rn.IsInbound() {
		manager.GetRemoteNodeIndexer().GetNonValidatorInboundIndex().Remove(rn.GetId())
	} else {
		manager.Disconnect(rn)
	}
}

func (manager *RemoteNodeIndexerManager) UnsetValidator(pk bls.PublicKey, rn *RemoteNode) {
	if rn == nil {
		return
	}
	manager.GetRemoteNodeIndexer().GetValidatorIndex().Remove(pk)

	if rn.IsOutbound() {
		manager.SetNonValidatorOutbound(rn)
	} else if rn.IsInbound() {
		manager.SetNonValidatorInbound(rn)
	} else {
		manager.Disconnect(rn)
	}
}

func (manager *RemoteNodeIndexerManager) SetNonValidatorOutbound(rn *RemoteNode) {
	if rn == nil || !rn.IsOutbound() {
		return
	}

	manager.RemoveNonValidatorAttempted(rn.GetId())
	manager.GetRemoteNodeIndexer().GetNonValidatorOutboundIndex().Add(rn.GetId(), rn)
}

func (manager *RemoteNodeIndexerManager) SetNonValidatorInbound(rn *RemoteNode) {
	if rn == nil || !rn.IsInbound() {
		return
	}

	manager.GetRemoteNodeIndexer().GetNonValidatorInboundIndex().Add(rn.GetId(), rn)
}

func (manager *RemoteNodeIndexerManager) RemoveNonValidatorAttempted(id RemoteNodeId) {
	rn, ok := manager.GetRemoteNodeIndexer().GetNonValidatorAttemptedIndex().Get(id)
	if !ok {
		return
	}
	manager.GetRemoteNodeIndexer().RemoveRemoteNode(rn)
}

func (manager *RemoteNodeIndexerManager) GetAllNonValidators() []*RemoteNode {
	outboundRemoteNodes := manager.GetRemoteNodeIndexer().GetNonValidatorOutboundIndex().GetAll()
	inboundRemoteNodes := manager.GetRemoteNodeIndexer().GetNonValidatorInboundIndex().GetAll()
	return append(outboundRemoteNodes, inboundRemoteNodes...)
}

func (manager *RemoteNodeIndexerManager) GetNumConnectedOutboundPeers() uint32 {
	outboundPeers := manager.GetRemoteNodeIndexer().GetNonValidatorOutboundIndex().GetAll()
	return uint32(len(outboundPeers))
}

func (manager *RemoteNodeIndexerManager) GetNumConnectedInboundPeers() uint32 {
	inboundPeers := manager.GetRemoteNodeIndexer().GetNonValidatorInboundIndex().GetAll()
	return uint32(len(inboundPeers))
}

func (manager *RemoteNodeIndexerManager) GetNumAttemptedNonValidators() uint32 {
	attemptedNonValidators := manager.GetRemoteNodeIndexer().GetNonValidatorAttemptedIndex().GetAll()
	return uint32(len(attemptedNonValidators))
}
