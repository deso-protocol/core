package lib

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/wire"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/consensus"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

// NetworkManager is a structure that oversees all connections to RemoteNodes. NetworkManager has the following
// responsibilities in regard to the lifecycle of RemoteNodes:
//   - Maintain a list of all RemoteNodes that the node is connected to through the RemoteNodeManager.
//   - Initialize RemoteNodes from established outbound and inbound peer connections.
//   - Initiate and handle the communication of the handshake process with RemoteNodes.
//
// The NetworkManager is also responsible for opening and closing connections. It does this by running a set of
// goroutines that periodically check the state of different categories of RemoteNodes, and disconnects or connects
// RemoteNodes as needed. These categories of RemoteNodes include:
//   - Persistent RemoteNodes: These are RemoteNodes that we want to maintain a persistent (constant) connection to.
//     These are specified by the --connect-ips flag.
//   - Validators: These are RemoteNodes that are in the active validators set. We want to maintain a connection to
//     all active validators. We also want to disconnect from any validators that are no longer active.
//   - Non-Validators: These are RemoteNodes that are not in the active validators set. We want to maintain a connection
//     to at most a target number of outbound and inbound non-validators. If we have more than the target number of
//     outbound or inbound non-validators, we will disconnect the excess RemoteNodes.
//
// The NetworkManager also runs an auxiliary goroutine that periodically cleans up RemoteNodes that may have timed out
// the handshake process, or became invalid for some other reason.
type NetworkManager struct {
	// The parameters we are initialized with.
	params *DeSoParams

	cmgr        *ConnectionManager
	blsKeystore *BLSKeystore

	handshake *HandshakeManager
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

	activeValidatorsMapLock sync.RWMutex
	// activeValidatorsMap is a map of all currently active validators registered in consensus. It will be updated
	// periodically by the owner of the NetworkManager.
	activeValidatorsMap *collections.ConcurrentMap[bls.SerializedPublicKey, consensus.Validator]

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

func NewNetworkManager(params *DeSoParams, cmgr *ConnectionManager, rnManager *RemoteNodeManager,
	blsKeystore *BLSKeystore, addrMgr *addrmgr.AddrManager, connectIps []string,
	targetNonValidatorOutboundRemoteNodes uint32, targetNonValidatorInboundRemoteNodes uint32,
	limitOneInboundConnectionPerIP bool) *NetworkManager {

	return &NetworkManager{
		params:                                params,
		cmgr:                                  cmgr,
		blsKeystore:                           blsKeystore,
		handshake:                             NewHandshakeController(rnManager),
		rnManager:                             rnManager,
		AddrMgr:                               addrMgr,
		connectIps:                            connectIps,
		persistentIpToRemoteNodeIdsMap:        collections.NewConcurrentMap[string, RemoteNodeId](),
		activeValidatorsMap:                   collections.NewConcurrentMap[bls.SerializedPublicKey, consensus.Validator](),
		targetNonValidatorOutboundRemoteNodes: targetNonValidatorOutboundRemoteNodes,
		targetNonValidatorInboundRemoteNodes:  targetNonValidatorInboundRemoteNodes,
		limitOneInboundRemoteNodePerIP:        limitOneInboundConnectionPerIP,
		exitChan:                              make(chan struct{}),
	}
}

func (nm *NetworkManager) Start() {
	// If the NetworkManager routines are disabled, we do nothing.
	if nm.params.DisableNetworkManagerRoutines {
		return
	}

	// Start the NetworkManager goroutines. The startGroup is used to ensure that all goroutines have started before
	// exiting the context of this function.
	nm.startGroup.Add(4)
	go nm.startPersistentConnector()
	go nm.startValidatorConnector()
	go nm.startNonValidatorConnector()
	go nm.startRemoteNodeCleanup()

	nm.startGroup.Wait()
}

func (nm *NetworkManager) Stop() {
	if !nm.params.DisableNetworkManagerRoutines {
		nm.exitGroup.Add(4)
		close(nm.exitChan)
		nm.exitGroup.Wait()
	}
	nm.rnManager.DisconnectAll()
}

func (nm *NetworkManager) GetRemoteNodeManager() *RemoteNodeManager {
	return nm.rnManager
}

func (nm *NetworkManager) SetTargetOutboundPeers(numPeers uint32) {
	nm.targetNonValidatorOutboundRemoteNodes = numPeers
}

// ###########################
// ## NetworkManager Routines
// ###########################

// startPersistentConnector is responsible for ensuring that the node is connected to all persistent IP addresses. It
// does this by periodically checking the persistentIpToRemoteNodeIdsMap, and connecting to any persistent IP addresses
// that are not already connected.
func (nm *NetworkManager) startPersistentConnector() {
	nm.startGroup.Done()
	for {
		select {
		case <-nm.exitChan:
			nm.exitGroup.Done()
			return
		case <-time.After(1 * time.Second):
			nm.refreshConnectIps()
		}
	}
}

// startValidatorConnector is responsible for ensuring that the node is connected to all active validators. It does
// this in two steps. First, it looks through the already established connections and checks if any of these connections
// are validators. If they are, it adds them to the validator index. It also checks if any of the existing validators
// are no longer active and removes them from the validator index. Second, it checks if any of the active validators
// are missing from the validator index. If they are, it attempts to connect to them.
func (nm *NetworkManager) startValidatorConnector() {
	nm.startGroup.Done()
	for {
		select {
		case <-nm.exitChan:
			nm.exitGroup.Done()
			return
		case <-time.After(1 * time.Second):
			activeValidatorsMap := nm.getActiveValidatorsMap()
			nm.refreshValidatorIndex(activeValidatorsMap)
			nm.connectValidators(activeValidatorsMap)
		}
	}
}

// startNonValidatorConnector is responsible for ensuring that the node is connected to the target number of outbound
// and inbound remote nodes. To do this, it periodically checks the number of outbound and inbound remote nodes, and
// if the number is above the target number, it disconnects the excess remote nodes. If the number is below the target
// number, it attempts to connect to new remote nodes.
func (nm *NetworkManager) startNonValidatorConnector() {
	nm.startGroup.Done()

	for {
		select {
		case <-nm.exitChan:
			nm.exitGroup.Done()
			return
		case <-time.After(1 * time.Second):
			nm.refreshNonValidatorOutboundIndex()
			nm.refreshNonValidatorInboundIndex()
			nm.connectNonValidators()
		}
	}
}

// startRemoteNodeCleanup is responsible for cleaning up RemoteNodes that may have timed out the handshake process,
// or became invalid for some other reason.
func (nm *NetworkManager) startRemoteNodeCleanup() {
	nm.startGroup.Done()

	for {
		select {
		case <-nm.exitChan:
			nm.exitGroup.Done()
			return
		case <-time.After(1 * time.Second):
			nm.rnManager.Cleanup()
		}
	}

}

// ###########################
// ## Handlers (Peer, DeSoMessage)
// ###########################

// _handleVersionMessage is called when a new version message is received. It is a wrapper around the handshake's
// handleVersionMessage function.
func (nm *NetworkManager) _handleVersionMessage(origin *Peer, desoMsg DeSoMessage) {
	nm.handshake.handleVersionMessage(origin, desoMsg)
}

// _handleVerackMessage is called when a new verack message is received. It is a wrapper around the handshake's
// handleVerackMessage function.
func (nm *NetworkManager) _handleVerackMessage(origin *Peer, desoMsg DeSoMessage) {
	nm.handshake.handleVerackMessage(origin, desoMsg)
}

// _handleDisconnectedPeerMessage is called when a peer is disconnected. It is responsible for cleaning up the
// RemoteNode associated with the peer.
func (nm *NetworkManager) _handleDisconnectedPeerMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeDisconnectedPeer {
		return
	}

	glog.V(2).Infof("NetworkManager._handleDisconnectedPeerMessage: Handling disconnected peer message for "+
		"id=%v", origin.ID)
	nm.rnManager.DisconnectById(NewRemoteNodeId(origin.ID))
	// Update the persistentIpToRemoteNodeIdsMap, in case the disconnected peer was a persistent peer.
	ipRemoteNodeIdMap := nm.persistentIpToRemoteNodeIdsMap.ToMap()
	for ip, id := range ipRemoteNodeIdMap {
		if id.ToUint64() == origin.ID {
			nm.persistentIpToRemoteNodeIdsMap.Remove(ip)
		}
	}
}

// _handleNewConnectionMessage is called when a new outbound or inbound connection is established. It is responsible
// for creating a RemoteNode from the connection and initiating the handshake. The incoming DeSoMessage is a control message.
func (nm *NetworkManager) _handleNewConnectionMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeNewConnection {
		return
	}

	msg, ok := desoMsg.(*MsgDeSoNewConnection)
	if !ok {
		return
	}

	var remoteNode *RemoteNode
	var err error
	// We create the RemoteNode differently depending on whether the connection is inbound or outbound.
	switch msg.Connection.GetConnectionType() {
	case ConnectionTypeInbound:
		remoteNode, err = nm.processInboundConnection(msg.Connection)
		if err != nil {
			glog.Errorf("NetworkManager.handleNewConnectionMessage: Problem handling inbound connection: %v", err)
			nm.cleanupFailedInboundConnection(remoteNode, msg.Connection)
			return
		}
	case ConnectionTypeOutbound:
		remoteNode, err = nm.processOutboundConnection(msg.Connection)
		if err != nil {
			glog.Errorf("NetworkManager.handleNewConnectionMessage: Problem handling outbound connection: %v", err)
			nm.cleanupFailedOutboundConnection(msg.Connection)
			return
		}
	}

	// If we made it here, we have a valid remote node. We will now initiate the handshake.
	nm.handshake.InitiateHandshake(remoteNode)
}

// processInboundConnection is called when a new inbound connection is established. At this point, the connection is not validated,
// nor is it assigned to a RemoteNode. This function is responsible for validating the connection and creating a RemoteNode from it.
// Once the RemoteNode is created, we will initiate handshake.
func (nm *NetworkManager) processInboundConnection(conn Connection) (*RemoteNode, error) {
	var ic *inboundConnection
	var ok bool
	if ic, ok = conn.(*inboundConnection); !ok {
		return nil, fmt.Errorf("NetworkManager.handleInboundConnection: Connection is not an inboundConnection")
	}

	// If we want to limit inbound connections to one per IP address, check to make sure this address isn't already connected.
	if nm.limitOneInboundRemoteNodePerIP &&
		nm.isDuplicateInboundIPAddress(ic.connection.RemoteAddr()) {

		return nil, fmt.Errorf("NetworkManager.handleInboundConnection: Rejecting INBOUND peer (%s) due to "+
			"already having an inbound connection from the same IP with limit_one_inbound_connection_per_ip set",
			ic.connection.RemoteAddr().String())
	}

	na, err := nm.ConvertIPStringToNetAddress(ic.connection.RemoteAddr().String())
	if err != nil {
		return nil, errors.Wrapf(err, "NetworkManager.handleInboundConnection: Problem calling "+
			"ConvertIPStringToNetAddress for addr: (%s)", ic.connection.RemoteAddr().String())
	}

	remoteNode, err := nm.rnManager.AttachInboundConnection(ic.connection, na)
	if remoteNode == nil || err != nil {
		return nil, errors.Wrapf(err, "NetworkManager.handleInboundConnection: Problem calling "+
			"AttachInboundConnection for addr: (%s)", ic.connection.RemoteAddr().String())
	}

	return remoteNode, nil
}

// processOutboundConnection is called when a new outbound connection is established. At this point, the connection is not validated,
// nor is it assigned to a RemoteNode. This function is responsible for validating the connection and creating a RemoteNode from it.
// Once the RemoteNode is created, we will initiate handshake.
func (nm *NetworkManager) processOutboundConnection(conn Connection) (*RemoteNode, error) {
	var oc *outboundConnection
	var ok bool
	if oc, ok = conn.(*outboundConnection); !ok {
		return nil, fmt.Errorf("NetworkManager.handleOutboundConnection: Connection is not an outboundConnection")
	}

	if oc.failed {
		return nil, fmt.Errorf("NetworkManager.handleOutboundConnection: Failed to connect to peer (%s:%v)",
			oc.address.IP.String(), oc.address.Port)
	}

	if !oc.isPersistent {
		nm.AddrMgr.Connected(oc.address)
		nm.AddrMgr.Good(oc.address)
	}

	// If this is a non-persistent outbound peer and the group key overlaps with another peer we're already connected to then
	// abort mission. We only connect to one peer per IP group in order to prevent Sybil attacks.
	if !oc.isPersistent && nm.cmgr.IsFromRedundantOutboundIPAddress(oc.address) {
		return nil, fmt.Errorf("NetworkManager.handleOutboundConnection: Rejecting OUTBOUND NON-PERSISTENT "+
			"connection with redundant group key (%s).", addrmgr.GroupKey(oc.address))
	}

	na, err := nm.ConvertIPStringToNetAddress(oc.connection.RemoteAddr().String())
	if err != nil {
		return nil, errors.Wrapf(err, "NetworkManager.handleOutboundConnection: Problem calling ipToNetAddr "+
			"for addr: (%s)", oc.connection.RemoteAddr().String())
	}

	// Attach the connection before additional validation steps because it is already established.
	remoteNode, err := nm.rnManager.AttachOutboundConnection(oc.connection, na, oc.attemptId, oc.isPersistent)
	if remoteNode == nil || err != nil {
		return nil, errors.Wrapf(err, "NetworkManager.handleOutboundConnection: Problem calling rnManager.AttachOutboundConnection "+
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
	if nm.cmgr.IsFromRedundantOutboundIPAddress(oc.address) {
		return nil, fmt.Errorf("NetworkManager.handleOutboundConnection: Rejecting OUTBOUND NON-PERSISTENT "+
			"connection with redundant group key (%s).", addrmgr.GroupKey(oc.address))
	}
	nm.cmgr.AddToGroupKey(na)

	return remoteNode, nil
}

// cleanupFailedInboundConnection is called when an inbound connection fails to be processed. It is responsible for
// cleaning up the RemoteNode and the connection. Most of the time, the RemoteNode will be nil, but if the RemoteNode
// was successfully created, we will disconnect it.
func (nm *NetworkManager) cleanupFailedInboundConnection(remoteNode *RemoteNode, connection Connection) {
	glog.V(2).Infof("NetworkManager.cleanupFailedInboundConnection: Cleaning up failed inbound connection")
	if remoteNode != nil {
		nm.rnManager.Disconnect(remoteNode)
	}
	connection.Close()
}

// cleanupFailedOutboundConnection is called when an outbound connection fails to be processed. It is responsible for
// cleaning up the RemoteNode and the connection.
func (nm *NetworkManager) cleanupFailedOutboundConnection(connection Connection) {
	oc, ok := connection.(*outboundConnection)
	if !ok {
		return
	}
	glog.V(2).Infof("NetworkManager.cleanupFailedOutboundConnection: Cleaning up failed outbound connection")

	// Find the RemoteNode associated with the connection. It should almost always exist, since we create the RemoteNode
	// as we're attempting to connect to the address.
	id := NewRemoteNodeId(oc.attemptId)
	rn := nm.rnManager.GetRemoteNodeById(id)
	if rn != nil {
		nm.rnManager.Disconnect(rn)
	}
	oc.Close()
	nm.cmgr.RemoveAttemptedOutboundAddrs(oc.address)
}

// ###########################
// ## Persistent Connections
// ###########################

// refreshConnectIps is called periodically by the persistent connector. It is responsible for connecting to all
// persistent IP addresses that we are not already connected to.
func (nm *NetworkManager) refreshConnectIps() {
	// Connect to addresses passed via the --connect-ips flag. These addresses are persistent in the sense that if we
	// disconnect from one, we will try to reconnect to the same one.
	for _, connectIp := range nm.connectIps {
		if _, ok := nm.persistentIpToRemoteNodeIdsMap.Get(connectIp); ok {
			continue
		}

		glog.Infof("NetworkManager.initiatePersistentConnections: Connecting to connectIp: %v", connectIp)
		id, err := nm.CreateNonValidatorPersistentOutboundConnection(connectIp)
		if err != nil {
			glog.Errorf("NetworkManager.initiatePersistentConnections: Problem connecting "+
				"to connectIp %v: %v", connectIp, err)
			continue
		}

		nm.persistentIpToRemoteNodeIdsMap.Set(connectIp, id)
	}
}

// ###########################
// ## Validator Connections
// ###########################

// SetActiveValidatorsMap is called by the owner of the NetworkManager to update the activeValidatorsMap. This should
// generally be done whenever the active validators set changes.
func (nm *NetworkManager) SetActiveValidatorsMap(activeValidatorsMap *collections.ConcurrentMap[bls.SerializedPublicKey, consensus.Validator]) {
	nm.activeValidatorsMapLock.Lock()
	defer nm.activeValidatorsMapLock.Unlock()
	nm.activeValidatorsMap = activeValidatorsMap.Clone()

}

func (nm *NetworkManager) getActiveValidatorsMap() *collections.ConcurrentMap[bls.SerializedPublicKey, consensus.Validator] {
	nm.activeValidatorsMapLock.RLock()
	defer nm.activeValidatorsMapLock.RUnlock()
	return nm.activeValidatorsMap.Clone()
}

// refreshValidatorIndex re-indexes validators based on the activeValidatorsMap. It is called periodically by the
// validator connector.
func (nm *NetworkManager) refreshValidatorIndex(activeValidatorsMap *collections.ConcurrentMap[bls.SerializedPublicKey, consensus.Validator]) {
	// De-index inactive validators. We skip any checks regarding RemoteNodes connection status, nor do we verify whether
	// de-indexing the validator would result in an excess number of outbound/inbound connections. Any excess connections
	// will be cleaned up by the NonValidator connector.
	validatorRemoteNodeMap := nm.rnManager.GetValidatorIndex().ToMap()
	for pk, rn := range validatorRemoteNodeMap {
		// If the validator is no longer active, de-index it.
		if _, ok := activeValidatorsMap.Get(pk); !ok {
			nm.rnManager.SetNonValidator(rn)
			nm.rnManager.UnsetValidator(rn)
		}
	}

	// Look for validators in our existing outbound / inbound connections.
	allNonValidators := nm.rnManager.GetAllNonValidators()
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
		if _, ok := nm.rnManager.GetValidatorIndex().Get(pk.Serialize()); ok {
			glog.V(2).Infof("NetworkManager.refreshValidatorIndex: Disconnecting Validator RemoteNode "+
				"(%v) has validator public key (%v) that is already present in validator index", rn, pk)
			nm.rnManager.Disconnect(rn)
			continue
		}

		// If the RemoteNode turns out to be in the validator set, index it.
		if _, ok := activeValidatorsMap.Get(pk.Serialize()); ok {
			nm.rnManager.SetValidator(rn)
			nm.rnManager.UnsetNonValidator(rn)
		}
	}
}

// connectValidators attempts to connect to all active validators that are not already connected. It is called
// periodically by the validator connector.
func (nm *NetworkManager) connectValidators(activeValidatorsMap *collections.ConcurrentMap[bls.SerializedPublicKey, consensus.Validator]) {
	// Look through the active validators and connect to any that we're not already connected to.
	if nm.blsKeystore == nil {
		return
	}

	validators := activeValidatorsMap.ToMap()
	for pk, validator := range validators {
		_, exists := nm.rnManager.GetValidatorIndex().Get(pk)
		// If we're already connected to the validator, continue.
		if exists {
			continue
		}
		// If the validator is our node, continue.
		if nm.blsKeystore.GetSigner().GetPublicKey().Serialize() == pk {
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
		if err := nm.CreateValidatorConnection(address, publicKey); err != nil {
			glog.V(2).Infof("NetworkManager.connectValidators: Problem connecting to validator %v: %v", address, err)
			continue
		}
	}
}

// ###########################
// ## NonValidator Connections
// ###########################

// refreshNonValidatorOutboundIndex is called periodically by the NonValidator connector. It is responsible for
// disconnecting excess outbound remote nodes.
func (nm *NetworkManager) refreshNonValidatorOutboundIndex() {
	// There are three categories of outbound remote nodes: attempted, connected, and persistent. All of these
	// remote nodes are stored in the same non-validator outbound index. We want to disconnect excess remote nodes that
	// are not persistent, starting with the attempted nodes first.

	// First let's run a quick check to see if the number of our non-validator remote nodes exceeds our target. Note that
	// this number will include the persistent nodes.
	numOutboundRemoteNodes := uint32(nm.rnManager.GetNonValidatorOutboundIndex().Count())
	if numOutboundRemoteNodes <= nm.targetNonValidatorOutboundRemoteNodes {
		return
	}

	// If we get here, it means that we should potentially disconnect some remote nodes. Let's first separate the
	// attempted and connected remote nodes, ignoring the persistent ones.
	allOutboundRemoteNodes := nm.rnManager.GetNonValidatorOutboundIndex().GetAll()
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
	if numOutboundRemoteNodes > nm.targetNonValidatorOutboundRemoteNodes {
		excessiveOutboundRemoteNodes = numOutboundRemoteNodes - nm.targetNonValidatorOutboundRemoteNodes
	}

	// First disconnect the attempted remote nodes.
	for _, rn := range attemptedOutboundRemoteNodes {
		if excessiveOutboundRemoteNodes == 0 {
			break
		}
		glog.V(2).Infof("NetworkManager.refreshNonValidatorOutboundIndex: Disconnecting attempted remote "+
			"node (id=%v) due to excess outbound RemoteNodes", rn.GetId())
		nm.rnManager.Disconnect(rn)
		excessiveOutboundRemoteNodes--
	}
	// Now disconnect the connected remote nodes, if we still have too many remote nodes.
	for _, rn := range connectedOutboundRemoteNodes {
		if excessiveOutboundRemoteNodes == 0 {
			break
		}
		glog.V(2).Infof("NetworkManager.refreshNonValidatorOutboundIndex: Disconnecting connected remote "+
			"node (id=%v) due to excess outbound RemoteNodes", rn.GetId())
		nm.rnManager.Disconnect(rn)
		excessiveOutboundRemoteNodes--
	}
}

// refreshNonValidatorInboundIndex is called periodically by the non-validator connector. It is responsible for
// disconnecting excess inbound remote nodes.
func (nm *NetworkManager) refreshNonValidatorInboundIndex() {
	// First let's check if we have an excess number of inbound remote nodes. If we do, we'll disconnect some of them.
	numConnectedInboundRemoteNodes := uint32(nm.rnManager.GetNonValidatorInboundIndex().Count())
	if numConnectedInboundRemoteNodes <= nm.targetNonValidatorInboundRemoteNodes {
		return
	}

	// Disconnect random inbound non-validators if we have too many of them.
	inboundRemoteNodes := nm.rnManager.GetNonValidatorInboundIndex().GetAll()
	var connectedInboundRemoteNodes []*RemoteNode
	for _, rn := range inboundRemoteNodes {
		// We only want to disconnect remote nodes that have completed handshake. RemoteNodes that don't have the
		// handshake completed status could be validators, in which case we don't want to disconnect them. It is also
		// possible that the RemoteNodes without completed handshake will end up never finishing it, in which case
		// they will be removed by the cleanup goroutine, once the handshake timeout is reached.
		if rn.IsHandshakeCompleted() {
			connectedInboundRemoteNodes = append(connectedInboundRemoteNodes, rn)
		}
	}

	// Having separated the connected remote nodes, we can now find the actual number of connected inbound remote nodes
	// that have completed handshake. We can then find out how many remote nodes we need to disconnect.
	numConnectedInboundRemoteNodes = uint32(len(connectedInboundRemoteNodes))
	excessiveInboundRemoteNodes := uint32(0)
	if numConnectedInboundRemoteNodes > nm.targetNonValidatorInboundRemoteNodes {
		excessiveInboundRemoteNodes = numConnectedInboundRemoteNodes - nm.targetNonValidatorInboundRemoteNodes
	}
	for _, rn := range connectedInboundRemoteNodes {
		if excessiveInboundRemoteNodes == 0 {
			break
		}
		glog.V(2).Infof("NetworkManager.refreshNonValidatorInboundIndex: Disconnecting inbound remote "+
			"node (id=%v) due to excess inbound RemoteNodes", rn.GetId())
		nm.rnManager.Disconnect(rn)
		excessiveInboundRemoteNodes--
	}
}

// connectNonValidators attempts to connect to new outbound nonValidator remote nodes. It is called periodically by the
// nonValidator connector.
func (nm *NetworkManager) connectNonValidators() {
	// First, find all nonValidator outbound remote nodes that are not persistent.
	allOutboundRemoteNodes := nm.rnManager.GetNonValidatorOutboundIndex().GetAll()
	var nonValidatorOutboundRemoteNodes []*RemoteNode
	for _, rn := range allOutboundRemoteNodes {
		if rn.IsPersistent() || rn.IsExpectedValidator() {
			// We do nothing for persistent remote nodes or expected validators.
			continue
		} else {
			nonValidatorOutboundRemoteNodes = append(nonValidatorOutboundRemoteNodes, rn)
		}
	}
	// Now find the number of nonValidator, non-persistent outbound remote nodes.
	numOutboundRemoteNodes := uint32(len(nonValidatorOutboundRemoteNodes))
	remainingOutboundRemoteNodes := uint32(0)
	// Check if we need to connect to more nonValidator outbound remote nodes.
	if numOutboundRemoteNodes < nm.targetNonValidatorOutboundRemoteNodes {
		remainingOutboundRemoteNodes = nm.targetNonValidatorOutboundRemoteNodes - numOutboundRemoteNodes
	}
	for ii := uint32(0); ii < remainingOutboundRemoteNodes; ii++ {
		// Get a random unconnected address from the address manager. If we can't find one, we break out of the loop.
		addr := nm.getRandomUnconnectedAddress()
		if addr == nil {
			break
		}
		// Attempt to connect to the address.
		nm.AddrMgr.Attempt(addr)
		if err := nm.rnManager.CreateNonValidatorOutboundConnection(addr); err != nil {
			glog.V(2).Infof("NetworkManager.connectNonValidators: Problem creating non-validator outbound "+
				"connection to addr: %v; err: %v", addr, err)
		}
	}
}

// getRandomUnconnectedAddress returns a random address from the address manager that we are not already connected to.
func (nm *NetworkManager) getRandomUnconnectedAddress() *wire.NetAddress {
	for tries := 0; tries < 100; tries++ {
		addr := nm.AddrMgr.GetAddress()
		if addr == nil {
			break
		}

		if nm.cmgr.IsConnectedOutboundIpAddress(addr.NetAddress()) {
			continue
		}

		if nm.cmgr.IsAttemptedOutboundIpAddress(addr.NetAddress()) {
			continue
		}

		// We can only have one outbound address per /16. This is similar to
		// Bitcoin and we do it to prevent Sybil attacks.
		if nm.cmgr.IsFromRedundantOutboundIPAddress(addr.NetAddress()) {
			continue
		}

		return addr.NetAddress()
	}

	return nil
}

// ###########################
// ## RemoteNode Dial Functions
// ###########################

func (nm *NetworkManager) CreateValidatorConnection(ipStr string, publicKey *bls.PublicKey) error {
	netAddr, err := nm.ConvertIPStringToNetAddress(ipStr)
	if err != nil {
		return err
	}
	return nm.rnManager.CreateValidatorConnection(netAddr, publicKey)
}

func (nm *NetworkManager) CreateNonValidatorPersistentOutboundConnection(ipStr string) (RemoteNodeId, error) {
	netAddr, err := nm.ConvertIPStringToNetAddress(ipStr)
	if err != nil {
		return 0, err
	}
	return nm.rnManager.CreateNonValidatorPersistentOutboundConnection(netAddr)
}

func (nm *NetworkManager) CreateNonValidatorOutboundConnection(ipStr string) error {
	netAddr, err := nm.ConvertIPStringToNetAddress(ipStr)
	if err != nil {
		return err
	}
	return nm.rnManager.CreateNonValidatorOutboundConnection(netAddr)
}

// ###########################
// ## Helper Functions
// ###########################

func (nm *NetworkManager) ConvertIPStringToNetAddress(ipStr string) (*wire.NetAddress, error) {
	netAddr, err := IPToNetAddr(ipStr, nm.AddrMgr, nm.params)
	if err != nil {
		return nil, errors.Wrapf(err,
			"NetworkManager.ConvertIPStringToNetAddress: Problem parsing "+
				"ipString to wire.NetAddress")
	}
	if netAddr == nil {
		return nil, fmt.Errorf("NetworkManager.ConvertIPStringToNetAddress: " +
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

func (nm *NetworkManager) isDuplicateInboundIPAddress(addr net.Addr) bool {
	netAddr, err := IPToNetAddr(addr.String(), nm.AddrMgr, nm.params)
	if err != nil {
		// Return true in case we have an error. We do this because it
		// will result in the peer connection not being accepted, which
		// is desired in this case.
		glog.Warningf(errors.Wrapf(err,
			"NetworkManager.isDuplicateInboundIPAddress: Problem parsing "+
				"net.Addr to wire.NetAddress so marking as redundant and not "+
				"making connection").Error())
		return true
	}
	if netAddr == nil {
		glog.Warningf("NetworkManager.isDuplicateInboundIPAddress: " +
			"address was nil after parsing so marking as redundant and not " +
			"making connection")
		return true
	}

	return nm.cmgr.IsDuplicateInboundIPAddress(netAddr)
}
