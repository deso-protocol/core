package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/wire"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/consensus"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"net"
	"strconv"
	"sync"
	"time"
)

// ConnectionController is a structure that oversees all connections to remote nodes. It is responsible for kicking off
// the initial connections a node makes to the network. It is also responsible for creating RemoteNodes from all
// successful outbound and inbound connections. The ConnectionController also ensures that the node is connected to
// the active validators, once the node reaches Proof of Stake.
// TODO: Document more in later PRs
type ConnectionController struct {
	// The parameters we are initialized with.
	params *DeSoParams

	cmgr        *ConnectionManager
	blsKeystore *BLSKeystore

	handshake *HandshakeController

	rnManager *RemoteNodeManager

	// The address manager keeps track of peer addresses we're aware of. When
	// we need to connect to a new outbound peer, it chooses one of the addresses
	// it's aware of at random and provides it to us.
	AddrMgr *addrmgr.AddrManager

	// When --connect-ips is set, we don't connect to anything from the addrmgr.
	connectIps []string
	// persistentIpToRemoteNodeIdsMap maps persistent IP addresses, like the --connect-ips, to the RemoteNodeIds of the
	// corresponding RemoteNodes. This is used to ensure that we don't connect to the same persistent IP address twice.
	// And that we can reconnect to the same persistent IP address if we disconnect from it.
	persistentIpToRemoteNodeIdsMap *collections.ConcurrentMap[string, RemoteNodeId]

	validatorMapLock sync.RWMutex
	// validatorMap is a list of all validators that we are connected to. It will be updated periodically by the
	// owner of the ConnectionController.
	validatorMap *collections.ConcurrentMap[bls.SerializedPublicKey, consensus.Validator]

	// The target number of non-validator outbound remote nodes we want to have. We will disconnect remote nodes once
	// we've exceeded this number of outbound connections.
	targetNonValidatorOutboundRemoteNodes uint32
	// The target number of non-validator inbound remote nodes we want to have. We will disconnect remote nodes once
	// we've exceeded this number of inbound connections.
	targetNonValidatorInboundRemoteNodes uint32
	// When true, only one connection per IP is allowed. Prevents eclipse attacks
	// among other things.
	limitOneInboundRemoteNodePerIP bool

	startGroup sync.WaitGroup
	exitChan   chan struct{}
	exitGroup  sync.WaitGroup
}

func NewConnectionController(params *DeSoParams, cmgr *ConnectionManager, handshakeController *HandshakeController,
	rnManager *RemoteNodeManager, blsKeystore *BLSKeystore, addrMgr *addrmgr.AddrManager, connectIps []string,
	targetNonValidatorOutboundRemoteNodes uint32, targetNonValidatorInboundRemoteNodes uint32,
	limitOneInboundConnectionPerIP bool) *ConnectionController {

	return &ConnectionController{
		params:                                params,
		cmgr:                                  cmgr,
		blsKeystore:                           blsKeystore,
		handshake:                             handshakeController,
		rnManager:                             rnManager,
		AddrMgr:                               addrMgr,
		connectIps:                            connectIps,
		persistentIpToRemoteNodeIdsMap:        collections.NewConcurrentMap[string, RemoteNodeId](),
		validatorMap:                          collections.NewConcurrentMap[bls.SerializedPublicKey, consensus.Validator](),
		targetNonValidatorOutboundRemoteNodes: targetNonValidatorOutboundRemoteNodes,
		targetNonValidatorInboundRemoteNodes:  targetNonValidatorInboundRemoteNodes,
		limitOneInboundRemoteNodePerIP:        limitOneInboundConnectionPerIP,
		exitChan:                              make(chan struct{}),
	}
}

func (cc *ConnectionController) Start() {
	if cc.params.DisableNetworkManagerRoutines {
		return
	}

	cc.startGroup.Add(4)
	go cc.startPersistentConnector()
	go cc.startValidatorConnector()
	go cc.startNonValidatorConnector()
	go cc.startRemoteNodeCleanup()

	cc.startGroup.Wait()
	cc.exitGroup.Add(4)
}

func (cc *ConnectionController) Stop() {
	if !cc.params.DisableNetworkManagerRoutines {
		close(cc.exitChan)
		cc.exitGroup.Wait()
	}
	cc.rnManager.DisconnectAll()
}

func (cc *ConnectionController) GetRemoteNodeManager() *RemoteNodeManager {
	return cc.rnManager
}

func (cc *ConnectionController) startPersistentConnector() {
	cc.startGroup.Done()
	for {
		select {
		case <-cc.exitChan:
			cc.exitGroup.Done()
			return
		case <-time.After(1 * time.Second):
			cc.refreshConnectIps()
		}
	}
}

// startValidatorConnector is responsible for ensuring that the node is connected to all active validators. It does
// this in two steps. First, it looks through the already established connections and checks if any of these connections
// are validators. If they are, it adds them to the validator index. It also checks if any of the existing validators
// are no longer active and removes them from the validator index. Second, it checks if any of the active validators
// are missing from the validator index. If they are, it attempts to connect to them.
func (cc *ConnectionController) startValidatorConnector() {
	cc.startGroup.Done()
	for {
		select {
		case <-cc.exitChan:
			cc.exitGroup.Done()
			return
		case <-time.After(1 * time.Second):
			activeValidatorsMap := cc.getValidatorMap()
			cc.refreshValidatorIndex(activeValidatorsMap)
			cc.connectValidators(activeValidatorsMap)
		}
	}
}

// startNonValidatorConnector is responsible for ensuring that the node is connected to the target number of outbound
// and inbound remote nodes. To do this, it periodically checks the number of outbound and inbound remote nodes, and
// if the number is above the target number, it disconnects the excess remote nodes. If the number is below the target
// number, it attempts to connect to new remote nodes.
func (cc *ConnectionController) startNonValidatorConnector() {
	cc.startGroup.Done()

	for {
		select {
		case <-cc.exitChan:
			cc.exitGroup.Done()
			return
		case <-time.After(1 * time.Second):
			cc.refreshNonValidatorOutboundIndex()
			cc.refreshNonValidatorInboundIndex()
			cc.connectNonValidators()
		}
	}
}

func (cc *ConnectionController) startRemoteNodeCleanup() {
	cc.startGroup.Done()

	for {
		select {
		case <-cc.exitChan:
			cc.exitGroup.Done()
			return
		case <-time.After(1 * time.Second):
			cc.rnManager.Cleanup()
		}
	}

}

// ###########################
// ## Handlers (Peer, DeSoMessage)
// ###########################

func (cc *ConnectionController) _handleDonePeerMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeDisconnectedPeer {
		return
	}

	glog.V(2).Infof("ConnectionController.handleDonePeerMessage: Handling disconnected peer message for "+
		"id=%v", origin.ID)
	cc.rnManager.DisconnectById(NewRemoteNodeId(origin.ID))
	// Update the persistentIpToRemoteNodeIdsMap.
	ipRemoteNodeIdMap := cc.persistentIpToRemoteNodeIdsMap.ToMap()
	for ip, id := range ipRemoteNodeIdMap {
		if id.ToUint64() == origin.ID {
			cc.persistentIpToRemoteNodeIdsMap.Remove(ip)
		}
	}
}

func (cc *ConnectionController) _handleAddrMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeAddr {
		return
	}

	// TODO
}

func (cc *ConnectionController) _handleGetAddrMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeGetAddr {
		return
	}

	// TODO
}

// _handleNewConnectionMessage is called when a new outbound or inbound connection is established. It is responsible
// for creating a RemoteNode from the connection and initiating the handshake. The incoming DeSoMessage is a control message.
func (cc *ConnectionController) _handleNewConnectionMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeNewConnection {
		return
	}

	msg, ok := desoMsg.(*MsgDeSoNewConnection)
	if !ok {
		return
	}

	var remoteNode *RemoteNode
	var err error
	switch msg.Connection.GetConnectionType() {
	case ConnectionTypeInbound:
		remoteNode, err = cc.processInboundConnection(msg.Connection)
		if err != nil {
			glog.Errorf("ConnectionController.handleNewConnectionMessage: Problem handling inbound connection: %v", err)
			cc.cleanupFailedInboundConnection(remoteNode, msg.Connection)
			return
		}
	case ConnectionTypeOutbound:
		remoteNode, err = cc.processOutboundConnection(msg.Connection)
		if err != nil {
			glog.Errorf("ConnectionController.handleNewConnectionMessage: Problem handling outbound connection: %v", err)
			cc.cleanupFailedOutboundConnection(msg.Connection)
			return
		}
	}

	// If we made it here, we have a valid remote node. We will now initiate the handshake.
	cc.handshake.InitiateHandshake(remoteNode)
}

func (cc *ConnectionController) cleanupFailedInboundConnection(remoteNode *RemoteNode, connection Connection) {
	glog.V(2).Infof("ConnectionController.cleanupFailedInboundConnection: Cleaning up failed inbound connection")
	if remoteNode != nil {
		cc.rnManager.Disconnect(remoteNode)
	}
	connection.Close()
}

func (cc *ConnectionController) cleanupFailedOutboundConnection(connection Connection) {
	oc, ok := connection.(*outboundConnection)
	if !ok {
		return
	}
	glog.V(2).Infof("ConnectionController.cleanupFailedOutboundConnection: Cleaning up failed outbound connection")

	id := NewRemoteNodeId(oc.attemptId)
	rn := cc.rnManager.GetRemoteNodeById(id)
	if rn != nil {
		cc.rnManager.Disconnect(rn)
	}
	oc.Close()
	cc.cmgr.RemoveAttemptedOutboundAddrs(oc.address)
}

// ###########################
// ## Persistent Connections
// ###########################

func (cc *ConnectionController) refreshConnectIps() {
	// Connect to addresses passed via the --connect-ips flag. These addresses are persistent in the sense that if we
	// disconnect from one, we will try to reconnect to the same one.
	for _, connectIp := range cc.connectIps {
		if _, ok := cc.persistentIpToRemoteNodeIdsMap.Get(connectIp); ok {
			continue
		}

		glog.Infof("ConnectionController.initiatePersistentConnections: Connecting to connectIp: %v", connectIp)
		id, err := cc.CreateNonValidatorPersistentOutboundConnection(connectIp)
		if err != nil {
			glog.Errorf("ConnectionController.initiatePersistentConnections: Problem connecting "+
				"to connectIp %v: %v", connectIp, err)
			continue
		}

		cc.persistentIpToRemoteNodeIdsMap.Set(connectIp, id)
	}
}

// ###########################
// ## Validator Connections
// ###########################

func (cc *ConnectionController) SetValidatorMap(validatorMap *collections.ConcurrentMap[bls.SerializedPublicKey, consensus.Validator]) {
	cc.validatorMapLock.Lock()
	defer cc.validatorMapLock.Unlock()
	cc.validatorMap = validatorMap.Clone()

}

func (cc *ConnectionController) getValidatorMap() *collections.ConcurrentMap[bls.SerializedPublicKey, consensus.Validator] {
	cc.validatorMapLock.RLock()
	defer cc.validatorMapLock.RUnlock()
	return cc.validatorMap.Clone()
}

// refreshValidatorIndex re-indexes validators based on the activeValidatorsMap. It is called periodically by the
// validator connector.
func (cc *ConnectionController) refreshValidatorIndex(activeValidatorsMap *collections.ConcurrentMap[bls.SerializedPublicKey, consensus.Validator]) {
	// De-index inactive validators. We skip any checks regarding RemoteNodes connection status, nor do we verify whether
	// de-indexing the validator would result in an excess number of outbound/inbound connections. Any excess connections
	// will be cleaned up by the peer connector.
	validatorRemoteNodeMap := cc.rnManager.GetValidatorIndex().ToMap()
	for pk, rn := range validatorRemoteNodeMap {
		// If the validator is no longer active, de-index it.
		if _, ok := activeValidatorsMap.Get(pk); !ok {
			cc.rnManager.SetNonValidator(rn)
			cc.rnManager.UnsetValidator(rn)
		}
	}

	// Look for validators in our existing outbound / inbound connections.
	allNonValidators := cc.rnManager.GetAllNonValidators()
	for _, rn := range allNonValidators {
		// It is possible for a RemoteNode to be in the non-validator indices, and still have a public key. This can happen
		// if the RemoteNode advertised support for the SFValidator service flag during handshake, and provided us
		// with a public key, and a corresponding proof of possession signature.
		pk := rn.GetValidatorPublicKey()
		if pk == nil {
			continue
		}
		// It is possible that through unlikely concurrence, and malevolence, two non-validators happen to have the same
		// public key, which goes undetected during handshake. To prevent this from affecting the indexing of the validator
		// set, we check that the non-validator's public key is not already present in the validator index.
		if _, ok := cc.rnManager.GetValidatorIndex().Get(pk.Serialize()); ok {
			glog.V(2).Infof("ConnectionController.refreshValidatorIndex: Disconnecting Validator RemoteNode "+
				"(%v) has validator public key (%v) that is already present in validator index", rn, pk)
			cc.rnManager.Disconnect(rn)
			continue
		}

		// If the RemoteNode turns out to be in the validator set, index it.
		if _, ok := activeValidatorsMap.Get(pk.Serialize()); ok {
			cc.rnManager.SetValidator(rn)
			cc.rnManager.UnsetNonValidator(rn)
		}
	}
}

// connectValidators attempts to connect to all active validators that are not already connected. It is called
// periodically by the validator connector.
func (cc *ConnectionController) connectValidators(activeValidatorsMap *collections.ConcurrentMap[bls.SerializedPublicKey, consensus.Validator]) {
	// Look through the active validators and connect to any that we're not already connected to.
	if cc.blsKeystore == nil {
		return
	}

	validators := activeValidatorsMap.ToMap()
	for pk, validator := range validators {
		_, exists := cc.rnManager.GetValidatorIndex().Get(pk)
		// If we're already connected to the validator, continue.
		if exists {
			continue
		}
		if cc.blsKeystore.GetSigner().GetPublicKey().Serialize() == pk {
			continue
		}

		publicKey, err := pk.Deserialize()
		if err != nil {
			continue
		}

		// For now, we only dial the first domain in the validator's domain list.
		if len(validator.GetDomains()) == 0 {
			continue
		}
		address := string(validator.GetDomains()[0])
		if err := cc.CreateValidatorConnection(address, publicKey); err != nil {
			glog.V(2).Infof("ConnectionController.connectValidators: Problem connecting to validator %v: %v", address, err)
			continue
		}
	}
}

// ###########################
// ## NonValidator Connections
// ###########################

// refreshNonValidatorOutboundIndex is called periodically by the peer connector. It is responsible for disconnecting excess
// outbound remote nodes.
func (cc *ConnectionController) refreshNonValidatorOutboundIndex() {
	// There are three categories of outbound remote nodes: attempted, connected, and persistent. All of these
	// remote nodes are stored in the same non-validator outbound index. We want to disconnect excess remote nodes that
	// are not persistent, starting with the attempted nodes first.

	// First let's run a quick check to see if the number of our non-validator remote nodes exceeds our target. Note that
	// this number will include the persistent nodes.
	numOutboundRemoteNodes := uint32(cc.rnManager.GetNonValidatorOutboundIndex().Count())
	if numOutboundRemoteNodes <= cc.targetNonValidatorOutboundRemoteNodes {
		return
	}

	// If we get here, it means that we should potentially disconnect some remote nodes. Let's first separate the
	// attempted and connected remote nodes, ignoring the persistent ones.
	allOutboundRemoteNodes := cc.rnManager.GetNonValidatorOutboundIndex().GetAll()
	var attemptedOutboundRemoteNodes, connectedOutboundRemoteNodes []*RemoteNode
	for _, rn := range allOutboundRemoteNodes {
		if rn.IsPersistent() || rn.IsExpectedValidator() {
			// We do nothing for persistent remote nodes or expected validators.
			continue
		} else if rn.IsHandshakeCompleted() {
			connectedOutboundRemoteNodes = append(connectedOutboundRemoteNodes, rn)
		} else {
			attemptedOutboundRemoteNodes = append(attemptedOutboundRemoteNodes, rn)
		}
	}

	// Having separated the attempted and connected remote nodes, we can now find the actual number of attempted and
	// connected remote nodes. We can then find out how many remote nodes we need to disconnect.
	numOutboundRemoteNodes = uint32(len(attemptedOutboundRemoteNodes) + len(connectedOutboundRemoteNodes))
	excessiveOutboundRemoteNodes := uint32(0)
	if numOutboundRemoteNodes > cc.targetNonValidatorOutboundRemoteNodes {
		excessiveOutboundRemoteNodes = numOutboundRemoteNodes - cc.targetNonValidatorOutboundRemoteNodes
	}

	// First disconnect the attempted remote nodes.
	for _, rn := range attemptedOutboundRemoteNodes {
		if excessiveOutboundRemoteNodes == 0 {
			break
		}
		glog.V(2).Infof("ConnectionController.refreshNonValidatorOutboundIndex: Disconnecting attempted remote "+
			"node (id=%v) due to excess outbound peers", rn.GetId())
		cc.rnManager.Disconnect(rn)
		excessiveOutboundRemoteNodes--
	}
	// Now disconnect the connected remote nodes, if we still have too many remote nodes.
	for _, rn := range connectedOutboundRemoteNodes {
		if excessiveOutboundRemoteNodes == 0 {
			break
		}
		glog.V(2).Infof("ConnectionController.refreshNonValidatorOutboundIndex: Disconnecting connected remote "+
			"node (id=%v) due to excess outbound peers", rn.GetId())
		cc.rnManager.Disconnect(rn)
		excessiveOutboundRemoteNodes--
	}
}

// refreshNonValidatorInboundIndex is called periodically by the non-validator connector. It is responsible for
// disconnecting excess inbound remote nodes.
func (cc *ConnectionController) refreshNonValidatorInboundIndex() {
	// First let's check if we have an excess number of inbound remote nodes. If we do, we'll disconnect some of them.
	numConnectedInboundRemoteNodes := uint32(cc.rnManager.GetNonValidatorInboundIndex().Count())
	if numConnectedInboundRemoteNodes <= cc.targetNonValidatorInboundRemoteNodes {
		return
	}

	// Disconnect random inbound non-validators if we have too many of them.
	inboundRemoteNodes := cc.rnManager.GetNonValidatorInboundIndex().GetAll()
	var connectedInboundRemoteNodes []*RemoteNode
	for _, rn := range inboundRemoteNodes {
		// We only want to disconnect remote nodes that have completed handshake.
		if rn.IsHandshakeCompleted() {
			connectedInboundRemoteNodes = append(connectedInboundRemoteNodes, rn)
		}
	}

	excessiveInboundRemoteNodes := uint32(0)
	if numConnectedInboundRemoteNodes > cc.targetNonValidatorInboundRemoteNodes {
		excessiveInboundRemoteNodes = numConnectedInboundRemoteNodes - cc.targetNonValidatorInboundRemoteNodes
	}
	for _, rn := range connectedInboundRemoteNodes {
		if excessiveInboundRemoteNodes == 0 {
			break
		}
		glog.V(2).Infof("ConnectionController.refreshNonValidatorInboundIndex: Disconnecting inbound remote "+
			"node (id=%v) due to excess inbound peers", rn.GetId())
		cc.rnManager.Disconnect(rn)
		excessiveInboundRemoteNodes--
	}
}

func (cc *ConnectionController) connectNonValidators() {
	numOutboundPeers := uint32(cc.rnManager.GetNonValidatorOutboundIndex().Count())

	remainingOutboundPeers := uint32(0)
	if numOutboundPeers < cc.targetNonValidatorOutboundRemoteNodes {
		remainingOutboundPeers = cc.targetNonValidatorOutboundRemoteNodes - numOutboundPeers
	}
	for ii := uint32(0); ii < remainingOutboundPeers; ii++ {
		addr := cc.getRandomUnconnectedAddress()
		if addr == nil {
			break
		}
		cc.AddrMgr.Attempt(addr)
		if err := cc.rnManager.CreateNonValidatorOutboundConnection(addr); err != nil {
			glog.V(2).Infof("ConnectionController.connectNonValidators: Problem creating non-validator outbound "+
				"connection to addr: %v; err: %v", addr, err)
		}
	}
}

func (cc *ConnectionController) getRandomUnconnectedAddress() *wire.NetAddress {
	for tries := 0; tries < 100; tries++ {
		addr := cc.AddrMgr.GetAddress()
		if addr == nil {
			break
		}

		if cc.cmgr.IsConnectedOutboundIpAddress(addr.NetAddress()) {
			continue
		}

		if cc.cmgr.IsAttemptedOutboundIpAddress(addr.NetAddress()) {
			continue
		}

		// We can only have one outbound address per /16. This is similar to
		// Bitcoin and we do it to prevent Sybil attacks.
		if cc.cmgr.IsFromRedundantOutboundIPAddress(addr.NetAddress()) {
			continue
		}

		return addr.NetAddress()
	}

	return nil
}

func (cc *ConnectionController) CreateValidatorConnection(ipStr string, publicKey *bls.PublicKey) error {
	netAddr, err := cc.ConvertIPStringToNetAddress(ipStr)
	if err != nil {
		return err
	}
	return cc.rnManager.CreateValidatorConnection(netAddr, publicKey)
}

func (cc *ConnectionController) CreateNonValidatorPersistentOutboundConnection(ipStr string) (RemoteNodeId, error) {
	netAddr, err := cc.ConvertIPStringToNetAddress(ipStr)
	if err != nil {
		return 0, err
	}
	return cc.rnManager.CreateNonValidatorPersistentOutboundConnection(netAddr)
}

func (cc *ConnectionController) CreateNonValidatorOutboundConnection(ipStr string) error {
	netAddr, err := cc.ConvertIPStringToNetAddress(ipStr)
	if err != nil {
		return err
	}
	return cc.rnManager.CreateNonValidatorOutboundConnection(netAddr)
}

func (cc *ConnectionController) SetTargetOutboundPeers(numPeers uint32) {
	cc.targetNonValidatorOutboundRemoteNodes = numPeers
}

// processInboundConnection is called when a new inbound connection is established. At this point, the connection is not validated,
// nor is it assigned to a RemoteNode. This function is responsible for validating the connection and creating a RemoteNode from it.
// Once the RemoteNode is created, we will initiate handshake.
func (cc *ConnectionController) processInboundConnection(conn Connection) (*RemoteNode, error) {
	var ic *inboundConnection
	var ok bool
	if ic, ok = conn.(*inboundConnection); !ok {
		return nil, fmt.Errorf("ConnectionController.handleInboundConnection: Connection is not an inboundConnection")
	}

	// If we want to limit inbound connections to one per IP address, check to make sure this address isn't already connected.
	if cc.limitOneInboundRemoteNodePerIP &&
		cc.isDuplicateInboundIPAddress(ic.connection.RemoteAddr()) {

		return nil, fmt.Errorf("ConnectionController.handleInboundConnection: Rejecting INBOUND peer (%s) due to "+
			"already having an inbound connection from the same IP with limit_one_inbound_connection_per_ip set",
			ic.connection.RemoteAddr().String())
	}

	na, err := cc.ConvertIPStringToNetAddress(ic.connection.RemoteAddr().String())
	if err != nil {
		return nil, errors.Wrapf(err, "ConnectionController.handleInboundConnection: Problem calling "+
			"ConvertIPStringToNetAddress for addr: (%s)", ic.connection.RemoteAddr().String())
	}

	remoteNode, err := cc.rnManager.AttachInboundConnection(ic.connection, na)
	if remoteNode == nil || err != nil {
		return nil, errors.Wrapf(err, "ConnectionController.handleInboundConnection: Problem calling "+
			"AttachInboundConnection for addr: (%s)", ic.connection.RemoteAddr().String())
	}

	return remoteNode, nil
}

// processOutboundConnection is called when a new outbound connection is established. At this point, the connection is not validated,
// nor is it assigned to a RemoteNode. This function is responsible for validating the connection and creating a RemoteNode from it.
// Once the RemoteNode is created, we will initiate handshake.
func (cc *ConnectionController) processOutboundConnection(conn Connection) (*RemoteNode, error) {
	var oc *outboundConnection
	var ok bool
	if oc, ok = conn.(*outboundConnection); !ok {
		return nil, fmt.Errorf("ConnectionController.handleOutboundConnection: Connection is not an outboundConnection")
	}

	if oc.failed {
		return nil, fmt.Errorf("ConnectionController.handleOutboundConnection: Failed to connect to peer (%s:%v)",
			oc.address.IP.String(), oc.address.Port)
	}

	if !oc.isPersistent {
		cc.AddrMgr.Connected(oc.address)
		cc.AddrMgr.Good(oc.address)
	}

	// If this is a non-persistent outbound peer and the group key overlaps with another peer we're already connected to then
	// abort mission. We only connect to one peer per IP group in order to prevent Sybil attacks.
	if !oc.isPersistent && cc.cmgr.IsFromRedundantOutboundIPAddress(oc.address) {
		return nil, fmt.Errorf("ConnectionController.handleOutboundConnection: Rejecting OUTBOUND NON-PERSISTENT "+
			"connection with redundant group key (%s).", addrmgr.GroupKey(oc.address))
	}

	na, err := cc.ConvertIPStringToNetAddress(oc.connection.RemoteAddr().String())
	if err != nil {
		return nil, errors.Wrapf(err, "ConnectionController.handleOutboundConnection: Problem calling ipToNetAddr "+
			"for addr: (%s)", oc.connection.RemoteAddr().String())
	}

	// Attach the connection before additional validation steps because it is already established.
	remoteNode, err := cc.rnManager.AttachOutboundConnection(oc.connection, na, oc.attemptId, oc.isPersistent)
	if remoteNode == nil || err != nil {
		return nil, errors.Wrapf(err, "ConnectionController.handleOutboundConnection: Problem calling rnManager.AttachOutboundConnection "+
			"for addr: (%s)", oc.connection.RemoteAddr().String())
	}

	// If this is a persistent remote node or a validator, we don't need to do any extra connection validation.
	if remoteNode.IsPersistent() || remoteNode.IsExpectedValidator() {
		return remoteNode, nil
	}

	// If we get here, it means we're dealing with a non-persistent or non-validator remote node. We perform additional
	// connection validation.

	// If the group key overlaps with another peer we're already connected to then abort mission. We only connect to
	// one peer per IP group in order to prevent Sybil attacks.
	if cc.cmgr.IsFromRedundantOutboundIPAddress(oc.address) {
		return nil, fmt.Errorf("ConnectionController.handleOutboundConnection: Rejecting OUTBOUND NON-PERSISTENT "+
			"connection with redundant group key (%s).", addrmgr.GroupKey(oc.address))
	}
	cc.cmgr.AddToGroupKey(na)

	return remoteNode, nil
}

func (cc *ConnectionController) ConvertIPStringToNetAddress(ipStr string) (*wire.NetAddress, error) {
	netAddr, err := IPToNetAddr(ipStr, cc.AddrMgr, cc.params)
	if err != nil {
		return nil, errors.Wrapf(err,
			"ConnectionController.ConvertIPStringToNetAddress: Problem parsing "+
				"ipString to wire.NetAddress")
	}
	if netAddr == nil {
		return nil, fmt.Errorf("ConnectionController.ConvertIPStringToNetAddress: " +
			"address was nil after parsing")
	}
	return netAddr, nil
}

func IPToNetAddr(ipStr string, addrMgr *addrmgr.AddrManager, params *DeSoParams) (*wire.NetAddress, error) {
	port := params.DefaultSocketPort
	host, portstr, err := net.SplitHostPort(ipStr)
	if err != nil {
		// No port specified so leave port=default and set
		// host to the ipStr.
		host = ipStr
	} else {
		pp, err := strconv.ParseUint(portstr, 10, 16)
		if err != nil {
			return nil, errors.Wrapf(err, "IPToNetAddr: Can not parse port from %s for ip", ipStr)
		}
		port = uint16(pp)
	}
	netAddr, err := addrMgr.HostToNetAddress(host, port, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "IPToNetAddr: Can not parse port from %s for ip", ipStr)
	}
	return netAddr, nil
}

func (cc *ConnectionController) isDuplicateInboundIPAddress(addr net.Addr) bool {
	netAddr, err := IPToNetAddr(addr.String(), cc.AddrMgr, cc.params)
	if err != nil {
		// Return true in case we have an error. We do this because it
		// will result in the peer connection not being accepted, which
		// is desired in this case.
		glog.Warningf(errors.Wrapf(err,
			"ConnectionController.isDuplicateInboundIPAddress: Problem parsing "+
				"net.Addr to wire.NetAddress so marking as redundant and not "+
				"making connection").Error())
		return true
	}
	if netAddr == nil {
		glog.Warningf("ConnectionController.isDuplicateInboundIPAddress: " +
			"address was nil after parsing so marking as redundant and not " +
			"making connection")
		return true
	}

	return cc.cmgr.IsDuplicateInboundIPAddress(netAddr)
}
