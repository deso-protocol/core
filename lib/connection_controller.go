package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/wire"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"net"
	"strconv"
	"sync"
	"time"
)

type GetActiveValidatorsFunc func() *collections.ConcurrentMap[bls.SerializedPublicKey, *ValidatorEntry]

var GetActiveValidatorImpl GetActiveValidatorsFunc = BasicGetActiveValidators

func BasicGetActiveValidators() *collections.ConcurrentMap[bls.SerializedPublicKey, *ValidatorEntry] {
	return collections.NewConcurrentMap[bls.SerializedPublicKey, *ValidatorEntry]()
}

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

	// When --connectips is set, we don't connect to anything from the addrmgr.
	connectIps []string

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
		targetNonValidatorOutboundRemoteNodes: targetNonValidatorOutboundRemoteNodes,
		targetNonValidatorInboundRemoteNodes:  targetNonValidatorInboundRemoteNodes,
		limitOneInboundRemoteNodePerIP:        limitOneInboundConnectionPerIP,
		exitChan:                              make(chan struct{}),
	}
}

func (cc *ConnectionController) Start() {
	cc.startGroup.Add(3)
	cc.initiatePersistentConnections()
	// Start the validator connector
	go cc.startValidatorConnector()
	go cc.startNonValidatorConnector()
	go cc.startRemoteNodeCleanup()

	cc.startGroup.Wait()
	cc.exitGroup.Add(3)
}

func (cc *ConnectionController) Stop() {
	close(cc.exitChan)
	cc.exitGroup.Wait()
}

func (cc *ConnectionController) GetRemoteNodeManager() *RemoteNodeManager {
	return cc.rnManager
}

func (cc *ConnectionController) initiatePersistentConnections() {
	// Connect to addresses passed via the --connect-ips flag. These addresses are persistent in the sense that if we
	// disconnect from one, we will try to reconnect to the same one.
	if len(cc.connectIps) > 0 {
		for _, connectIp := range cc.connectIps {
			glog.Infof("ConnectionController.initiatePersistentConnections: Connecting to connectIp: %v", connectIp)
			if err := cc.CreateNonValidatorPersistentOutboundConnection(connectIp); err != nil {
				glog.Errorf("ConnectionController.initiatePersistentConnections: Problem connecting "+
					"to connectIp %v: %v", connectIp, err)
			}
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
			activeValidatorsMap := GetActiveValidatorImpl()
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
			//cc.rnManager.Cleanup()
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

	cc.rnManager.DisconnectById(NewRemoteNodeId(origin.ID))
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

	id := NewRemoteNodeId(oc.attemptId)
	rn := cc.rnManager.GetRemoteNodeById(id)
	if rn != nil {
		cc.rnManager.Disconnect(rn)
	}
	oc.Close()
	cc.cmgr.RemoveAttemptedOutboundAddrs(oc.address)
}

// ###########################
// ## Validator Connections
// ###########################

// refreshValidatorIndex re-indexes validators based on the activeValidatorsMap. It is called periodically by the
// validator connector.
func (cc *ConnectionController) refreshValidatorIndex(activeValidatorsMap *collections.ConcurrentMap[bls.SerializedPublicKey, *ValidatorEntry]) {
	// De-index inactive validators. We skip any checks regarding RemoteNodes connection status, nor do we verify whether
	// de-indexing the validator would result in an excess number of outbound/inbound connections. Any excess connections
	// will be cleaned up by the peer connector.
	validatorRemoteNodeMap := cc.rnManager.GetValidatorIndex().Copy()
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
func (cc *ConnectionController) connectValidators(activeValidatorsMap *collections.ConcurrentMap[bls.SerializedPublicKey, *ValidatorEntry]) {
	// Look through the active validators and connect to any that we're not already connected to.
	if cc.blsKeystore == nil {
		return
	}

	validators := activeValidatorsMap.Copy()
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
		address := string(validator.Domains[0])
		if err := cc.CreateValidatorConnection(address, publicKey); err != nil {
			// TODO: Do we want to log an error here?
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
	// First let's check if we have an excess number of outbound remote nodes. If we do, we'll disconnect some of them.
	numOutboundRemoteNodes := uint32(cc.rnManager.GetNonValidatorOutboundIndex().Count())
	excessiveOutboundRemoteNodes := uint32(0)
	if numOutboundRemoteNodes > cc.targetNonValidatorOutboundRemoteNodes {
		excessiveOutboundRemoteNodes = numOutboundRemoteNodes - cc.targetNonValidatorOutboundRemoteNodes
	}
	// We group the outbound remote nodes into two categories: attempted and connected. We disconnect the attempted
	// remote nodes first, and then the connected remote nodes.
	allOutboundRemoteNodes := cc.rnManager.GetNonValidatorOutboundIndex().GetAll()
	var attemptedOutboundRemoteNodes, connectedOutboundRemoteNodes []*RemoteNode
	for _, rn := range allOutboundRemoteNodes {
		if rn.IsHandshakeCompleted() {
			connectedOutboundRemoteNodes = append(connectedOutboundRemoteNodes, rn)
		} else {
			attemptedOutboundRemoteNodes = append(attemptedOutboundRemoteNodes, rn)
		}
	}
	// First disconnect the attempted remote nodes.
	for _, rn := range attemptedOutboundRemoteNodes {
		if excessiveOutboundRemoteNodes == 0 {
			break
		}
		cc.rnManager.Disconnect(rn)
		excessiveOutboundRemoteNodes--
	}
	// Now disconnect the connected remote nodes, if we still have too many remote nodes.
	for _, rn := range connectedOutboundRemoteNodes {
		if excessiveOutboundRemoteNodes == 0 {
			break
		}
		cc.rnManager.Disconnect(rn)
		excessiveOutboundRemoteNodes--
	}
}

// refreshNonValidatorInboundIndex is called periodically by the non-validator connector. It is responsible for
// disconnecting excess inbound remote nodes.
func (cc *ConnectionController) refreshNonValidatorInboundIndex() {
	// First let's check if we have an excess number of inbound remote nodes. If we do, we'll disconnect some of them.
	numConnectedInboundRemoteNodes := uint32(cc.rnManager.GetNonValidatorInboundIndex().Count())
	excessiveInboundRemoteNodes := uint32(0)
	if numConnectedInboundRemoteNodes > cc.targetNonValidatorInboundRemoteNodes {
		excessiveInboundRemoteNodes = numConnectedInboundRemoteNodes - cc.targetNonValidatorInboundRemoteNodes
	}
	// Disconnect random inbound non-validators if we have too many of them.
	inboundRemoteNodes := cc.rnManager.GetNonValidatorInboundIndex().GetAll()
	for _, rn := range inboundRemoteNodes {
		if excessiveInboundRemoteNodes == 0 {
			break
		}
		cc.rnManager.Disconnect(rn)
		excessiveInboundRemoteNodes--
	}
}

func (cc *ConnectionController) connectNonValidators() {
	// Only connect to addresses from the addrmgr if we don't specify --connect-ips. These addresses are *not* persistent,
	// meaning if we disconnect from one we'll try a different one.
	// TODO: We used this condition in the old code to prevent the node from connecting to non-connect-ips nodes.
	// 	I'm not sure whether this is still necessary. I suppose the concern here was that the connect-ips nodes
	//	should be prioritized over the addrmgr nodes, especially during syncing. However, I think we can achieve the
	// 	same result by defining another flag, like a boolean --sync-from-persistent-peers-only, which could indicate that
	//	we disregard non-persistent non-connect-ips nodes during syncing, if the flag is set to true.
	// FIXME: This about uncommenting the below condition.
	//if len(cc.connectIps) == 0 {
	//	return
	//}

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
		// FIXME: error handle
		cc.rnManager.CreateNonValidatorOutboundConnection(addr)
	}
}

func (cc *ConnectionController) getRandomUnconnectedAddress() *wire.NetAddress {
	for tries := 0; tries < 100; tries++ {
		addr := cc.AddrMgr.GetAddress()
		if addr == nil {
			//glog.V(2).Infof("ConnectionManager.getRandomUnconnectedAddress: addr from GetAddressWithExclusions was nil")
			break
		}

		if cc.cmgr.IsConnectedOutboundIpAddress(addr.NetAddress()) {
			//glog.V(2).Infof("ConnectionManager.getRandomUnconnectedAddress: Not choosing address due to redundancy %v:%v", addr.NetAddress().IP, addr.NetAddress().Port)
			continue
		}

		if cc.cmgr.IsAttemptedOutboundIpAddress(addr.NetAddress()) {
			continue
		}

		// We can only have one outbound address per /16. This is similar to
		// Bitcoin and we do it to prevent Sybil attacks.
		if cc.cmgr.IsFromRedundantOutboundIPAddress(addr.NetAddress()) {
			//glog.V(2).Infof("ConnectionManager.getRandomUnconnectedAddress: Not choosing address due to redundant group key %v:%v", addr.NetAddress().IP, addr.NetAddress().Port)
			continue
		}

		return addr.NetAddress()
	}

	//glog.V(2).Infof("ConnectionManager.getRandomAddr: Returning nil")
	return nil
}

func (cc *ConnectionController) CreateValidatorConnection(ipStr string, publicKey *bls.PublicKey) error {
	netAddr, err := cc.ConvertIPStringToNetAddress(ipStr)
	if err != nil {
		return err
	}
	return cc.rnManager.CreateValidatorConnection(netAddr, publicKey)
}

func (cc *ConnectionController) CreateNonValidatorPersistentOutboundConnection(ipStr string) error {
	netAddr, err := cc.ConvertIPStringToNetAddress(ipStr)
	if err != nil {
		return err
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

func (cc *ConnectionController) enoughNonValidatorInboundConnections() bool {
	return uint32(cc.rnManager.GetNonValidatorInboundIndex().Count()) >= cc.targetNonValidatorInboundRemoteNodes
}

func (cc *ConnectionController) enoughNonValidatorOutboundConnections() bool {
	return uint32(cc.rnManager.GetNonValidatorOutboundIndex().Count()) >= cc.targetNonValidatorOutboundRemoteNodes
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

	// Reject the peer if we have too many inbound connections already.
	if cc.enoughNonValidatorInboundConnections() {
		return nil, fmt.Errorf("ConnectionController.handleInboundConnection: Rejecting INBOUND peer (%s) due to max "+
			"inbound peers (%d) hit", ic.connection.RemoteAddr().String(), cc.targetNonValidatorInboundRemoteNodes)
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

	// if this is a non-persistent outbound peer, and we already have enough outbound peers, then don't bother adding this one.
	if !oc.isPersistent && cc.enoughNonValidatorOutboundConnections() {
		return nil, fmt.Errorf("ConnectionController.handleOutboundConnection: Connected to maximum number of outbound "+
			"peers (%d)", cc.targetNonValidatorOutboundRemoteNodes)
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
	if remoteNode.IsPersistent() || remoteNode.GetValidatorPublicKey() != nil {
		return remoteNode, nil
	}

	// If we get here, it means we're dealing with a non-persistent or non-validator remote node. We perform additional
	// connection validation.

	// If we already have enough outbound peers, then don't bother adding this one.
	if cc.enoughNonValidatorOutboundConnections() {
		return nil, fmt.Errorf("ConnectionController.handleOutboundConnection: Connected to maximum number of outbound "+
			"peers (%d)", cc.targetNonValidatorOutboundRemoteNodes)
	}

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
