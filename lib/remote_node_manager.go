package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/wire"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/pkg/errors"
	"net"
	"sync/atomic"
)

// RemoteNodeManager manages all the RemoteNode that the node is connected to. It is responsible for starting, maintaining,
// and stopping remote node connections. It is also responsible for organizing the remote nodes into indices for easy
// access, through the RemoteNodeIndexer.
type RemoteNodeManager struct {
	// remoteNodeIndexer is a structure that stores and indexes all created remote nodes.
	remoteNodeIndexer *RemoteNodeIndexer

	params *DeSoParams
	srv    *Server
	bc     *Blockchain
	cmgr   *ConnectionManager

	// keystore is a reference to the node's BLS private key storage.
	keystore *BLSKeystore

	// configs
	minTxFeeRateNanosPerKB uint64
	nodeServices           ServiceFlag

	// Used to set remote node ids. Must be incremented atomically.
	remoteNodeIndex uint64
}

func NewRemoteNodeManager(srv *Server, bc *Blockchain, cmgr *ConnectionManager, keystore *BLSKeystore, params *DeSoParams,
	minTxFeeRateNanosPerKB uint64, nodeServices ServiceFlag) *RemoteNodeManager {
	return &RemoteNodeManager{
		remoteNodeIndexer:      NewRemoteNodeIndexer(),
		params:                 params,
		srv:                    srv,
		bc:                     bc,
		cmgr:                   cmgr,
		keystore:               keystore,
		minTxFeeRateNanosPerKB: minTxFeeRateNanosPerKB,
		nodeServices:           nodeServices,
	}
}

func (manager *RemoteNodeManager) newRemoteNode(validatorPublicKey *bls.PublicKey) *RemoteNode {
	id := atomic.AddUint64(&manager.remoteNodeIndex, 1)
	remoteNodeId := NewRemoteNodeId(id)
	latestBlockHeight := uint64(manager.bc.BlockTip().Height)
	return NewRemoteNode(remoteNodeId, validatorPublicKey, manager.srv, manager.cmgr, manager.keystore, manager.params,
		manager.minTxFeeRateNanosPerKB, latestBlockHeight, manager.nodeServices)
}

func (manager *RemoteNodeManager) ProcessCompletedHandshake(remoteNode *RemoteNode) {
	if remoteNode == nil {
		return
	}

	if remoteNode.IsValidator() {
		manager.SetValidator(remoteNode)
	} else {
		manager.SetNonValidator(remoteNode)
	}
	manager.srv.HandleAcceptedPeer(remoteNode.GetPeer())
}

func (manager *RemoteNodeManager) Disconnect(rn *RemoteNode) {
	rn.Disconnect()
	manager.removeRemoteNodeFromIndexer(rn)
}

func (manager *RemoteNodeManager) DisconnectById(id RemoteNodeId) {
	rn := manager.GetRemoteNodeById(id)
	if rn == nil {
		return
	}

	manager.Disconnect(rn)
}

func (manager *RemoteNodeManager) removeRemoteNodeFromIndexer(rn *RemoteNode) {
	if rn == nil {
		return
	}

	indexer := manager.remoteNodeIndexer
	indexer.GetAllRemoteNodes().Remove(rn.GetId())
	if rn.validatorPublicKey != nil {
		indexer.GetValidatorIndex().Remove(rn.validatorPublicKey.Serialize())
	}
	indexer.GetNonValidatorOutboundIndex().Remove(rn.GetId())
	indexer.GetNonValidatorInboundIndex().Remove(rn.GetId())
}

func (manager *RemoteNodeManager) SendMessage(rn *RemoteNode, desoMessage DeSoMessage) error {
	if rn == nil {
		return fmt.Errorf("RemoteNodeManager.SendMessage: RemoteNode is nil")
	}

	return rn.SendMessage(desoMessage)
}

// ###########################
// ## Create RemoteNode
// ###########################

func (manager *RemoteNodeManager) CreateValidatorConnection(netAddr *wire.NetAddress, publicKey *bls.PublicKey) error {
	if netAddr == nil || publicKey == nil {
		return fmt.Errorf("RemoteNodeManager.CreateValidatorConnection: netAddr or public key is nil")
	}

	remoteNode := manager.newRemoteNode(publicKey)
	if err := remoteNode.DialPersistentOutboundConnection(netAddr); err != nil {
		return errors.Wrapf(err, "RemoteNodeManager.CreateValidatorConnection: Problem calling DialPersistentOutboundConnection "+
			"for addr: (%s:%v)", netAddr.IP.String(), netAddr.Port)
	}
	manager.setRemoteNode(remoteNode)
	manager.GetValidatorIndex().Set(publicKey.Serialize(), remoteNode)
	return nil
}

func (manager *RemoteNodeManager) CreateNonValidatorPersistentOutboundConnection(netAddr *wire.NetAddress) error {
	if netAddr == nil {
		return fmt.Errorf("RemoteNodeManager.CreateNonValidatorPersistentOutboundConnection: netAddr is nil")
	}

	remoteNode := manager.newRemoteNode(nil)
	if err := remoteNode.DialPersistentOutboundConnection(netAddr); err != nil {
		return errors.Wrapf(err, "RemoteNodeManager.CreateNonValidatorPersistentOutboundConnection: Problem calling DialPersistentOutboundConnection "+
			"for addr: (%s:%v)", netAddr.IP.String(), netAddr.Port)
	}
	manager.setRemoteNode(remoteNode)
	manager.GetNonValidatorOutboundIndex().Set(remoteNode.GetId(), remoteNode)
	return nil
}

func (manager *RemoteNodeManager) CreateNonValidatorOutboundConnection(netAddr *wire.NetAddress) error {
	if netAddr == nil {
		return fmt.Errorf("RemoteNodeManager.CreateNonValidatorOutboundConnection: netAddr is nil")
	}

	remoteNode := manager.newRemoteNode(nil)
	if err := remoteNode.DialOutboundConnection(netAddr); err != nil {
		return errors.Wrapf(err, "RemoteNodeManager.CreateNonValidatorOutboundConnection: Problem calling DialOutboundConnection "+
			"for addr: (%s:%v)", netAddr.IP.String(), netAddr.Port)
	}
	manager.setRemoteNode(remoteNode)
	manager.GetNonValidatorOutboundIndex().Set(remoteNode.GetId(), remoteNode)
	return nil
}

func (manager *RemoteNodeManager) AttachInboundConnection(conn net.Conn,
	na *wire.NetAddress) (*RemoteNode, error) {

	remoteNode := manager.newRemoteNode(nil)
	if err := remoteNode.AttachInboundConnection(conn, na); err != nil {
		return nil, errors.Wrapf(err, "RemoteNodeManager.AttachInboundConnection: Problem calling AttachInboundConnection "+
			"for addr: (%s)", conn.RemoteAddr().String())
	}

	manager.setRemoteNode(remoteNode)
	return remoteNode, nil
}

func (manager *RemoteNodeManager) AttachOutboundConnection(conn net.Conn, na *wire.NetAddress,
	remoteNodeId uint64, isPersistent bool) (*RemoteNode, error) {

	id := NewRemoteNodeId(remoteNodeId)
	remoteNode := manager.GetRemoteNodeById(id)
	if remoteNode == nil {
		return nil, fmt.Errorf("RemoteNodeManager.AttachOutboundConnection: Problem getting remote node by id (%d)",
			id.ToUint64())
	}

	if err := remoteNode.AttachOutboundConnection(conn, na, isPersistent); err != nil {
		manager.Disconnect(remoteNode)
		return nil, errors.Wrapf(err, "RemoteNodeManager.AttachOutboundConnection: Problem calling AttachOutboundConnection "+
			"for addr: (%s)", conn.RemoteAddr().String())
	}

	return remoteNode, nil
}

// ###########################
// ## Setters
// ###########################

func (manager *RemoteNodeManager) setRemoteNode(rn *RemoteNode) {
	if rn == nil {
		return
	}

	manager.GetAllRemoteNodes().Set(rn.GetId(), rn)
}

func (manager *RemoteNodeManager) SetNonValidator(rn *RemoteNode) {
	if rn == nil {
		return
	}

	if rn.IsOutbound() {
		manager.GetNonValidatorOutboundIndex().Set(rn.GetId(), rn)
	} else if rn.IsInbound() {
		manager.GetNonValidatorInboundIndex().Set(rn.GetId(), rn)
	} else {
		manager.Disconnect(rn)
		return
	}

	manager.UnsetValidator(rn)
}

func (manager *RemoteNodeManager) SetValidator(remoteNode *RemoteNode) {
	if remoteNode == nil {
		return
	}

	pk := remoteNode.GetValidatorPublicKey()
	if pk == nil {
		manager.Disconnect(remoteNode)
		return
	}
	manager.GetValidatorIndex().Set(pk.Serialize(), remoteNode)
}

func (manager *RemoteNodeManager) UnsetValidator(remoteNode *RemoteNode) {
	if remoteNode == nil {
		return
	}

	pk := remoteNode.GetValidatorPublicKey()
	if pk == nil {
		return
	}
	manager.GetValidatorIndex().Remove(pk.Serialize())
}

func (manager *RemoteNodeManager) UnsetNonValidator(rn *RemoteNode) {
	if rn == nil {
		return
	}

	if rn.IsOutbound() {
		manager.GetNonValidatorOutboundIndex().Remove(rn.GetId())
	} else if rn.IsInbound() {
		manager.GetNonValidatorInboundIndex().Remove(rn.GetId())
	} else {
		manager.Disconnect(rn)
	}
}

// ###########################
// ## Getters
// ###########################

func (manager *RemoteNodeManager) GetAllRemoteNodes() *collections.ConcurrentMap[RemoteNodeId, *RemoteNode] {
	return manager.remoteNodeIndexer.GetAllRemoteNodes()
}

func (manager *RemoteNodeManager) GetValidatorIndex() *collections.ConcurrentMap[bls.SerializedPublicKey, *RemoteNode] {
	return manager.remoteNodeIndexer.GetValidatorIndex()
}

func (manager *RemoteNodeManager) GetNonValidatorOutboundIndex() *collections.ConcurrentMap[RemoteNodeId, *RemoteNode] {
	return manager.remoteNodeIndexer.GetNonValidatorOutboundIndex()
}

func (manager *RemoteNodeManager) GetNonValidatorInboundIndex() *collections.ConcurrentMap[RemoteNodeId, *RemoteNode] {
	return manager.remoteNodeIndexer.GetNonValidatorInboundIndex()
}

func (manager *RemoteNodeManager) GetRemoteNodeFromPeer(peer *Peer) *RemoteNode {
	if peer == nil {
		return nil
	}
	id := NewRemoteNodeId(peer.GetId())
	rn, _ := manager.GetAllRemoteNodes().Get(id)
	return rn
}

func (manager *RemoteNodeManager) GetRemoteNodeById(id RemoteNodeId) *RemoteNode {
	rn, ok := manager.GetAllRemoteNodes().Get(id)
	if !ok {
		return nil
	}
	return rn
}

func (manager *RemoteNodeManager) GetAllNonValidators() []*RemoteNode {
	outboundRemoteNodes := manager.GetNonValidatorOutboundIndex().GetAll()
	inboundRemoteNodes := manager.GetNonValidatorInboundIndex().GetAll()
	return append(outboundRemoteNodes, inboundRemoteNodes...)
}
