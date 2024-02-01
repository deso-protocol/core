package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/wire"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"net"
	"sync"
	"sync/atomic"
)

// RemoteNodeManager manages all the RemoteNode that the node is connected to. It is responsible for starting, maintaining,
// and stopping remote node connections. It is also responsible for organizing the remote nodes into indices for easy
// access, through the RemoteNodeIndexer.
type RemoteNodeManager struct {
	mtx sync.Mutex

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

func (manager *RemoteNodeManager) DisconnectAll() {
	allRemoteNodes := manager.GetAllRemoteNodes().GetAll()
	for _, rn := range allRemoteNodes {
		glog.V(2).Infof("RemoteNodeManager.DisconnectAll: Disconnecting from remote node (id=%v)", rn.GetId())
		manager.Disconnect(rn)
	}
}

func (manager *RemoteNodeManager) newRemoteNode(validatorPublicKey *bls.PublicKey, isPersistent bool) *RemoteNode {
	id := atomic.AddUint64(&manager.remoteNodeIndex, 1)
	remoteNodeId := NewRemoteNodeId(id)
	latestBlockHeight := uint64(manager.bc.BlockTip().Height)
	return NewRemoteNode(remoteNodeId, validatorPublicKey, isPersistent, manager.srv, manager.cmgr, manager.keystore,
		manager.params, manager.minTxFeeRateNanosPerKB, latestBlockHeight, manager.nodeServices)
}

func (manager *RemoteNodeManager) ProcessCompletedHandshake(remoteNode *RemoteNode) {
	if remoteNode == nil {
		return
	}

	if remoteNode.IsValidator() {
		manager.SetValidator(remoteNode)
		manager.UnsetNonValidator(remoteNode)
	} else {
		manager.UnsetValidator(remoteNode)
		manager.SetNonValidator(remoteNode)
	}
	manager.srv.HandleAcceptedPeer(remoteNode)
	manager.srv.maybeRequestAddresses(remoteNode)
}

func (manager *RemoteNodeManager) Disconnect(rn *RemoteNode) {
	if rn == nil {
		return
	}
	glog.V(2).Infof("RemoteNodeManager.Disconnect: Disconnecting from remote node id=%v", rn.GetId())
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
	manager.mtx.Lock()
	defer manager.mtx.Unlock()

	if rn == nil {
		return
	}

	indexer := manager.remoteNodeIndexer
	indexer.GetAllRemoteNodes().Remove(rn.GetId())
	indexer.GetNonValidatorOutboundIndex().Remove(rn.GetId())
	indexer.GetNonValidatorInboundIndex().Remove(rn.GetId())

	// Try to evict the remote node from the validator index. If the remote node is not a validator, then there is nothing to do.
	if rn.GetValidatorPublicKey() == nil {
		return
	}
	// Only remove from the validator index if the fetched remote node is the same as the one we are trying to remove.
	// Otherwise, we could have a fun edge-case where a duplicated validator connection ends up removing an
	// existing validator connection from the index.
	fetchedRn, ok := indexer.GetValidatorIndex().Get(rn.GetValidatorPublicKey().Serialize())
	if ok && fetchedRn.GetId() == rn.GetId() {
		indexer.GetValidatorIndex().Remove(rn.GetValidatorPublicKey().Serialize())
	}
}

func (manager *RemoteNodeManager) SendMessage(rn *RemoteNode, desoMessage DeSoMessage) error {
	if rn == nil {
		return fmt.Errorf("RemoteNodeManager.SendMessage: RemoteNode is nil")
	}

	return rn.SendMessage(desoMessage)
}

func (manager *RemoteNodeManager) Cleanup() {
	allRemoteNodes := manager.GetAllRemoteNodes().GetAll()
	for _, rn := range allRemoteNodes {
		if rn.IsTimedOut() {
			glog.V(2).Infof("RemoteNodeManager.Cleanup: Disconnecting from remote node (id=%v)", rn.GetId())
			manager.Disconnect(rn)
		}
	}
}

// ###########################
// ## Create RemoteNode
// ###########################

func (manager *RemoteNodeManager) CreateValidatorConnection(netAddr *wire.NetAddress, publicKey *bls.PublicKey) error {
	if netAddr == nil || publicKey == nil {
		return fmt.Errorf("RemoteNodeManager.CreateValidatorConnection: netAddr or public key is nil")
	}

	if _, ok := manager.GetValidatorIndex().Get(publicKey.Serialize()); ok {
		return fmt.Errorf("RemoteNodeManager.CreateValidatorConnection: RemoteNode already exists for public key: %v", publicKey)
	}

	remoteNode := manager.newRemoteNode(publicKey, false)
	if err := remoteNode.DialOutboundConnection(netAddr); err != nil {
		return errors.Wrapf(err, "RemoteNodeManager.CreateValidatorConnection: Problem calling DialPersistentOutboundConnection "+
			"for addr: (%s:%v)", netAddr.IP.String(), netAddr.Port)
	}
	manager.setRemoteNode(remoteNode)
	manager.GetValidatorIndex().Set(publicKey.Serialize(), remoteNode)
	return nil
}

func (manager *RemoteNodeManager) CreateNonValidatorPersistentOutboundConnection(netAddr *wire.NetAddress) (RemoteNodeId, error) {
	if netAddr == nil {
		return 0, fmt.Errorf("RemoteNodeManager.CreateNonValidatorPersistentOutboundConnection: netAddr is nil")
	}

	remoteNode := manager.newRemoteNode(nil, true)
	if err := remoteNode.DialPersistentOutboundConnection(netAddr); err != nil {
		return 0, errors.Wrapf(err, "RemoteNodeManager.CreateNonValidatorPersistentOutboundConnection: Problem calling DialPersistentOutboundConnection "+
			"for addr: (%s:%v)", netAddr.IP.String(), netAddr.Port)
	}
	manager.setRemoteNode(remoteNode)
	manager.GetNonValidatorOutboundIndex().Set(remoteNode.GetId(), remoteNode)
	return remoteNode.GetId(), nil
}

func (manager *RemoteNodeManager) CreateNonValidatorOutboundConnection(netAddr *wire.NetAddress) error {
	if netAddr == nil {
		return fmt.Errorf("RemoteNodeManager.CreateNonValidatorOutboundConnection: netAddr is nil")
	}

	remoteNode := manager.newRemoteNode(nil, false)
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

	remoteNode := manager.newRemoteNode(nil, false)
	if err := remoteNode.AttachInboundConnection(conn, na); err != nil {
		return remoteNode, errors.Wrapf(err, "RemoteNodeManager.AttachInboundConnection: Problem calling AttachInboundConnection "+
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
			"for addr: (%s). Disconnecting remote node (id=%v)", conn.RemoteAddr().String(), remoteNode.GetId())
	}

	return remoteNode, nil
}

// ###########################
// ## Setters
// ###########################

func (manager *RemoteNodeManager) setRemoteNode(rn *RemoteNode) {
	manager.mtx.Lock()
	defer manager.mtx.Unlock()

	if rn == nil || rn.IsTerminated() {
		return
	}

	manager.GetAllRemoteNodes().Set(rn.GetId(), rn)
}

func (manager *RemoteNodeManager) SetNonValidator(rn *RemoteNode) {
	manager.mtx.Lock()
	defer manager.mtx.Unlock()

	if rn == nil || rn.IsTerminated() {
		return
	}

	if rn.IsOutbound() {
		manager.GetNonValidatorOutboundIndex().Set(rn.GetId(), rn)
	} else {
		manager.GetNonValidatorInboundIndex().Set(rn.GetId(), rn)
	}
}

func (manager *RemoteNodeManager) SetValidator(remoteNode *RemoteNode) {
	manager.mtx.Lock()
	defer manager.mtx.Unlock()

	if remoteNode == nil || remoteNode.IsTerminated() {
		return
	}

	pk := remoteNode.GetValidatorPublicKey()
	if pk == nil {
		return
	}
	manager.GetValidatorIndex().Set(pk.Serialize(), remoteNode)
}

func (manager *RemoteNodeManager) UnsetValidator(remoteNode *RemoteNode) {
	manager.mtx.Lock()
	defer manager.mtx.Unlock()

	if remoteNode == nil || remoteNode.IsTerminated() {
		return
	}

	pk := remoteNode.GetValidatorPublicKey()
	if pk == nil {
		return
	}
	manager.GetValidatorIndex().Remove(pk.Serialize())
}

func (manager *RemoteNodeManager) UnsetNonValidator(rn *RemoteNode) {
	manager.mtx.Lock()
	defer manager.mtx.Unlock()

	if rn == nil || rn.IsTerminated() {
		return
	}

	if rn.IsOutbound() {
		manager.GetNonValidatorOutboundIndex().Remove(rn.GetId())
	} else {
		manager.GetNonValidatorInboundIndex().Remove(rn.GetId())
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
