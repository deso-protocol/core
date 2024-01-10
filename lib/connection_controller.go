package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/wire"
	"github.com/deso-protocol/core/bls"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"net"
	"strconv"
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
}

func NewConnectionController(params *DeSoParams, cmgr *ConnectionManager, handshakeController *HandshakeController,
	rnManager *RemoteNodeManager, blsKeystore *BLSKeystore, addrMgr *addrmgr.AddrManager, targetNonValidatorOutboundRemoteNodes uint32,
	targetNonValidatorInboundRemoteNodes uint32, limitOneInboundConnectionPerIP bool) *ConnectionController {

	return &ConnectionController{
		params:                                params,
		cmgr:                                  cmgr,
		blsKeystore:                           blsKeystore,
		handshake:                             handshakeController,
		rnManager:                             rnManager,
		AddrMgr:                               addrMgr,
		targetNonValidatorOutboundRemoteNodes: targetNonValidatorOutboundRemoteNodes,
		targetNonValidatorInboundRemoteNodes:  targetNonValidatorInboundRemoteNodes,
		limitOneInboundRemoteNodePerIP:        limitOneInboundConnectionPerIP,
	}
}

func (cc *ConnectionController) GetRemoteNodeManager() *RemoteNodeManager {
	return cc.rnManager
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
			msg.Connection.Close()
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
	cc.cmgr.RemoveAttemptedOutboundAddrs(oc.address)
}

// ###########################
// ## Connections
// ###########################

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
		return nil, fmt.Errorf("ConnectionController.handleOutboundConnection: Failed to connect to peer (%s)",
			oc.address.IP.String())
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

	remoteNode, err := cc.rnManager.AttachOutboundConnection(oc.connection, na, oc.attemptId, oc.isPersistent)
	if remoteNode == nil || err != nil {
		return nil, errors.Wrapf(err, "ConnectionController.handleOutboundConnection: Problem calling rnManager.AttachOutboundConnection "+
			"for addr: (%s)", oc.connection.RemoteAddr().String())
	}
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
