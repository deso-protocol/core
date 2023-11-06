package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/go-deadlock"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"net"
	"strconv"
	"sync"
	"time"
)

type ConnectionController struct {
	// The parameters we are initialized with.
	params *DeSoParams

	server *Server
	signer *BLSSigner

	handshake *HandshakeController

	rniManager *RemoteNodeIndexerManager

	validatorMapLock    sync.Mutex
	getActiveValidators func() map[bls.PublicKey]*ValidatorEntry

	// The address manager keeps track of peer addresses we're aware of. When
	// we need to connect to a new outbound peer, it chooses one of the addresses
	// it's aware of at random and provides it to us.
	AddrMgr *addrmgr.AddrManager

	// addrsToBroadcast is a list of all the addresses we've received from valid addr
	// messages that we intend to broadcast to our peers. It is organized as:
	// <recipient address> -> <list of addresses we received from that recipient>.
	//
	// It is organized in this way so that we can limit the number of addresses we
	// are distributing for a single peer to avoid a DOS attack.
	addrsToBroadcastLock deadlock.RWMutex
	addrsToBroadcast     map[string][]*SingleAddr

	// When --connectips is set, we don't connect to anything from the addrmgr.
	connectIps []string

	// The target number of outbound peers we want to have.
	targetOutboundPeers uint32
	// The maximum number of inbound peers we allow.
	maxInboundPeers uint32
	// When true, only one connection per IP is allowed. Prevents eclipse attacks
	// among other things.
	limitOneInboundConnectionPerIP bool

	startGroup sync.WaitGroup
	exitChan   chan struct{}
	exitGroup  sync.WaitGroup
}

func NewConnectionController(params *DeSoParams, server *Server, rniManager *RemoteNodeIndexerManager, signer *BLSSigner,
	addrMgr *addrmgr.AddrManager, targetOutboundPeers uint32, maxInboundPeers uint32,
	limitOneInboundConnectionPerIP bool) *ConnectionController {

	return &ConnectionController{
		params:                         params,
		server:                         server,
		signer:                         signer,
		rniManager:                     rniManager,
		AddrMgr:                        addrMgr,
		addrsToBroadcast:               make(map[string][]*SingleAddr),
		targetOutboundPeers:            targetOutboundPeers,
		maxInboundPeers:                maxInboundPeers,
		limitOneInboundConnectionPerIP: limitOneInboundConnectionPerIP,
		exitChan:                       make(chan struct{}),
	}
}

func (cc *ConnectionController) Start() {
	cc.startGroup.Add(3)
	// Start the validator connector
	go cc.startValidatorConnector()

	cc.startGroup.Wait()
	cc.exitGroup.Add(3)
}

func (cc *ConnectionController) Stop() {
	close(cc.exitChan)
	cc.exitGroup.Wait()
}

func (cc *ConnectionController) initiatePersistentConnections() {
	// This is a hack to make outbound connections go away.
	if cc.targetOutboundPeers == 0 {
		return
	}
	if len(cc.connectIps) > 0 {
		// Connect to addresses passed via the --connect-ips flag. These addresses
		// are persistent in the sense that if we disconnect from one, we will
		// try to reconnect to the same one.
		for _, connectIp := range cc.connectIps {
			if err := cc.createPersistentOutboundConnection(connectIp); err != nil {
				glog.Errorf("ConnectionController.initiatePersistentConnections: Problem connecting "+
					"to connectIp %v: %v", connectIp, err)
			}
		}
	}
}

func (cc *ConnectionController) startValidatorConnector() {
	cc.startGroup.Done()
	for {
		select {
		case <-cc.exitChan:
			cc.exitGroup.Done()
			return
		case <-time.After(1 * time.Minute):
			cc.validatorMapLock.Lock()
			activeValidatorsMap := cc.getActiveValidators()
			cc.refreshValidatorIndex(activeValidatorsMap)
			cc.refreshValidatorAttemptedIndex(activeValidatorsMap)
			cc.connectValidators(activeValidatorsMap)
			cc.validatorMapLock.Unlock()
		}
	}
}

func (cc *ConnectionController) startPeerConnector() {
	cc.startGroup.Done()

	for {
		select {
		case <-cc.exitChan:
			cc.exitGroup.Done()
			return
		case <-time.After(1 * time.Second):
			// Only connect to addresses from the addrmgr if we don't specify --connect-ips.
			// These addresses are *not* persistent, meaning if we disconnect from one we'll
			// try a different one.
			// TODO: Do we still want this?
			if len(cc.connectIps) == 0 {
				continue
			}

			cc.refreshOutboundIndex()
			cc.refreshInboundIndex()
			cc.connectPeers()
		}
	}
}

// Must be run inside a goroutine. Relays addresses to peers at regular intervals
// and relays our own address to peers once every 24 hours.
func (cc *ConnectionController) startAddressRelayer() {
	cc.startGroup.Done()
	numMinutesPassed := 0
	for {
		select {
		case <-cc.exitChan:
			cc.exitGroup.Done()
			return
		case <-time.After(AddrRelayIntervalSeconds * time.Second):
			// For the first ten minutes after the connection controller starts, relay our address to all
			// peers. After the first ten minutes, do it once every 24 hours.
			glog.V(1).Infof("ConnectionController.startAddressRelayer: Relaying our own addr to peers")
			if numMinutesPassed < 10 || numMinutesPassed%(RebroadcastNodeAddrIntervalMinutes) == 0 {
				// TODO: Change to retrieve all RemoteNodes from the indexer.
				for _, pp := range cc.server.GetAllPeers() {
					bestAddress := cc.AddrMgr.GetBestLocalAddress(pp.netAddr)
					if bestAddress != nil {
						glog.V(2).Infof("ConnectionController.startAddressRelayer: Relaying address %v to "+
							"peer %v", bestAddress.IP.String(), pp)
						if err := cc.server.SendMessage(&MsgDeSoAddr{
							AddrList: []*SingleAddr{
								{
									Timestamp: time.Now(),
									IP:        bestAddress.IP,
									Port:      bestAddress.Port,
									Services:  (ServiceFlag)(bestAddress.Services),
								},
							},
						}, pp.ID); err != nil {
							glog.Errorf("ConnectionController.startAddressRelayer: Problem sending "+
								"MsgDeSoAddr to peer %v: %v", pp, err)
						}
					}
				}
			}

			glog.V(2).Infof("ConnectionController.startAddressRelayer: Seeing if there are addrs to relay...")
			// Broadcast the addrs we have to all of our peers.
			addrsToBroadcast := cc.getAddrsToBroadcast()
			if len(addrsToBroadcast) == 0 {
				glog.V(2).Infof("ConnectionController.startAddressRelayer: No addrs to relay.")
				time.Sleep(AddrRelayIntervalSeconds * time.Second)
				continue
			}

			glog.V(2).Infof("ConnectionController.startAddressRelayer: Found %d addrs to "+
				"relay: %v", len(addrsToBroadcast), spew.Sdump(addrsToBroadcast))
			// Iterate over all our peers and broadcast the addrs to all of them.
			for _, pp := range cc.server.GetAllPeers() {
				pp.AddDeSoMessage(&MsgDeSoAddr{
					AddrList: addrsToBroadcast,
				}, false)
			}
			time.Sleep(AddrRelayIntervalSeconds * time.Second)
			numMinutesPassed++
		}
	}
}

// ###########################
// ## Handlers (Peer, DeSoMessage)
// ###########################

func (cc *ConnectionController) _handleDonePeerMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeDonePeer {
		return
	}

	cc.rniManager.RemovePeer(origin)
}

func (cc *ConnectionController) _handleAddrMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeAddr {
		return
	}

	var msg *MsgDeSoAddr
	var ok bool
	if msg, ok = desoMsg.(*MsgDeSoAddr); !ok {
		glog.Errorf("ConnectionController._handleAddrMessage: Problem decoding "+
			"MsgDeSoAddr: %v", spew.Sdump(desoMsg))
		cc.rniManager.DisconnectPeer(origin)
		return
	}

	cc.addrsToBroadcastLock.Lock()
	defer cc.addrsToBroadcastLock.Unlock()

	glog.V(1).Infof("ConnectionController._handleAddrMessage: Received Addr from peer %v with addrs %v", origin, spew.Sdump(msg.AddrList))

	// If this addr message contains more than the maximum allowed number of addresses
	// then disconnect this peer.
	if len(msg.AddrList) > MaxAddrsPerAddrMsg {
		glog.Errorf(fmt.Sprintf("ConnectionController._handleAddrMessage: Disconnecting "+
			"Peer %v for sending us an addr message with %d transactions, which exceeds "+
			"the max allowed %d",
			origin, len(msg.AddrList), MaxAddrsPerAddrMsg))

		cc.rniManager.DisconnectPeer(origin)
		return
	}

	// Add all the addresses we received to the addrmgr.
	netAddrsReceived := []*wire.NetAddress{}
	for _, addr := range msg.AddrList {
		addrAsNetAddr := wire.NewNetAddressIPPort(addr.IP, addr.Port, (wire.ServiceFlag)(addr.Services))
		if !addrmgr.IsRoutable(addrAsNetAddr) {
			glog.V(1).Infof("Dropping address %v from peer %v because it is not routable", addr, origin)
			continue
		}

		netAddrsReceived = append(
			netAddrsReceived, addrAsNetAddr)
	}
	cc.AddrMgr.AddAddresses(netAddrsReceived, origin.netAddr)

	// If the message had <= 10 addrs in it, then queue all the addresses for relaying
	// on the next cycle.
	if len(msg.AddrList) <= 10 {
		glog.V(1).Infof("ConnectionController._handleAddrMessage: Queueing %d addrs for forwarding from "+
			"peer %v", len(msg.AddrList), origin)
		sourceAddr := &SingleAddr{
			Timestamp: time.Now(),
			IP:        origin.netAddr.IP,
			Port:      origin.netAddr.Port,
			Services:  origin.serviceFlags,
		}
		listToAddTo, hasSeenSource := cc.addrsToBroadcast[sourceAddr.StringWithPort(false /*includePort*/)]
		if !hasSeenSource {
			listToAddTo = []*SingleAddr{}
		}
		// If this peer has been sending us a lot of little crap, evict a lot of their
		// stuff but don't disconnect.
		if len(listToAddTo) > MaxAddrsPerAddrMsg {
			listToAddTo = listToAddTo[:MaxAddrsPerAddrMsg/2]
		}
		listToAddTo = append(listToAddTo, msg.AddrList...)
		cc.addrsToBroadcast[sourceAddr.StringWithPort(false /*includePort*/)] = listToAddTo
	}
}

func (cc *ConnectionController) _handleGetAddrMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeGetAddr {
		return
	}

	if _, ok := desoMsg.(*MsgDeSoGetAddr); !ok {
		glog.Errorf("ConnectionController._handleAddrMessage: Problem decoding "+
			"MsgDeSoAddr: %v", spew.Sdump(desoMsg))
		cc.rniManager.DisconnectPeer(origin)
		return
	}

	glog.V(1).Infof("Server._handleGetAddrMessage: Received GetAddr from peer %v", origin)
	// When we get a GetAddr message, choose MaxAddrsPerMsg from the AddrMgr
	// and send them back to the peer.
	netAddrsFound := cc.AddrMgr.AddressCache()
	if len(netAddrsFound) > MaxAddrsPerAddrMsg {
		netAddrsFound = netAddrsFound[:MaxAddrsPerAddrMsg]
	}

	// Convert the list to a SingleAddr list.
	res := &MsgDeSoAddr{}
	for _, netAddr := range netAddrsFound {
		singleAddr := &SingleAddr{
			Timestamp: time.Now(),
			IP:        netAddr.IP,
			Port:      netAddr.Port,
			Services:  (ServiceFlag)(netAddr.Services),
		}
		res.AddrList = append(res.AddrList, singleAddr)
	}
	cc.rniManager.SendMessageToPeer(origin, res)
}

func (cc *ConnectionController) _handleNewConnectionMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeNewConnection {
		return
	}

	var msg *MsgDeSoNewConnection
	var ok bool
	if msg, ok = desoMsg.(*MsgDeSoNewConnection); !ok {
		return
	}

	switch msg.Connection.GetConnectionType() {
	case ConnectionTypeInbound:
		if err := cc.processInboundConnection(msg.Connection); err != nil {
			glog.Errorf("ConnectionController.handleNewConnectionMessage: Problem handling inbound connection: %v", err)
			msg.Connection.Close()
			return
		}
	case ConnectionTypeOutbound:
		if err := cc.processOutboundConnection(msg.Connection); err != nil {
			glog.Errorf("ConnectionController.handleNewConnectionMessage: Problem handling outbound connection: %v", err)
			var oc *outboundConnection
			if oc, ok = msg.Connection.(*outboundConnection); !ok {
				return
			}
			id := NewRemoteNodeAttemptedId(oc.attemptId)
			cc.rniManager.RemoveNonValidatorAttempted(id)
			cc.server.RemoveAttemptedOutboundAddrs(oc.address)
			msg.Connection.Close()
			return
		}
	}
}

// ###########################
// ## Validator Connections
// ###########################

func (cc *ConnectionController) refreshValidatorIndex(activeValidatorsMap map[bls.PublicKey]*ValidatorEntry) {
	// De-index inactive validators.
	validatorRemoteNodeMap := cc.rniManager.GetRemoteNodeIndexer().GetValidatorIndex().GetIndex()
	for pk, rn := range validatorRemoteNodeMap {
		if _, ok := activeValidatorsMap[pk]; !ok {
			cc.rniManager.UnsetValidator(pk, rn)
		}
	}

	// Look for validators in our existing outbound / inbound connections.
	allNonValidators := cc.rniManager.GetAllNonValidators()
	for _, rn := range allNonValidators {
		meta := rn.GetHandshakeMetadata()
		if meta == nil {
			continue
		}
		pk := meta.GetValidatorPublicKey()
		if _, ok := activeValidatorsMap[pk]; ok {
			cc.rniManager.SetValidator(pk, rn)
		}
	}
}

func (cc *ConnectionController) refreshValidatorAttemptedIndex(activeValidatorsMap map[bls.PublicKey]*ValidatorEntry) {
	// Disconnect inactive attempted validators.
	validatorRemoteNodeMap := cc.rniManager.GetRemoteNodeIndexer().GetValidatorAttemptedIndex().GetIndex()
	for pk, rn := range validatorRemoteNodeMap {
		if _, ok := activeValidatorsMap[pk]; !ok {
			cc.rniManager.Disconnect(rn)
		}
	}
}

func (cc *ConnectionController) connectValidators(activeValidatorsMap map[bls.PublicKey]*ValidatorEntry) {
	for pk, validator := range activeValidatorsMap {
		_, connected := cc.rniManager.GetRemoteNodeIndexer().GetValidatorIndex().Get(pk)
		_, attempted := cc.rniManager.GetRemoteNodeIndexer().GetValidatorAttemptedIndex().Get(pk)
		if !connected && !attempted {
			// FIXME: for now we'll only use the first address in the ValidatorEntry
			address := string(validator.Domains[0])
			if err := cc.createValidatorConnection(address, pk); err != nil {
				// TODO: Do we want to log an error here?
				continue
			}
		}
	}
}

// ###########################
// ## Peer Connections
// ###########################

func (cc *ConnectionController) connectPeers() {
	numConnectedOutboundPeers := cc.rniManager.GetNumConnectedOutboundPeers()
	numAttemptedPeers := cc.rniManager.GetNumAttemptedNonValidators()

	remainingOutboundPeers := uint32(0)
	if numConnectedOutboundPeers+numAttemptedPeers < cc.targetOutboundPeers {
		remainingOutboundPeers = cc.targetOutboundPeers - (numConnectedOutboundPeers + numAttemptedPeers)
	}
	for ii := uint32(0); ii < remainingOutboundPeers; ii++ {
		addr := cc.getRandomUnconnectedAddress()
		cc.AddrMgr.Attempt(addr)
		cc.rniManager.CreateOutboundConnectionNetAddress(addr)
	}
}

func (cc *ConnectionController) refreshOutboundIndex() {
	numConnectedOutboundPeers := cc.rniManager.GetNumConnectedOutboundPeers()
	numAttemptedPeers := cc.rniManager.GetNumAttemptedNonValidators()

	excessiveOutboundPeers := uint32(0)
	if numConnectedOutboundPeers+numAttemptedPeers > cc.targetOutboundPeers {
		excessiveOutboundPeers = numConnectedOutboundPeers + numAttemptedPeers - cc.targetOutboundPeers
	}
	// Disconnect random outbound peers if we have too many peers.
	for ii := uint32(0); ii < excessiveOutboundPeers; ii++ {
		rn, ok := cc.rniManager.GetRemoteNodeIndexer().GetNonValidatorOutboundIndex().GetRandom()
		if !ok {
			break
		}
		cc.rniManager.Disconnect(rn)
	}
}

func (cc *ConnectionController) refreshInboundIndex() {
	numConnectedInboundPeers := cc.rniManager.GetNumConnectedInboundPeers()

	excessiveInboundPeers := uint32(0)
	if numConnectedInboundPeers > cc.maxInboundPeers {
		excessiveInboundPeers = numConnectedInboundPeers - cc.maxInboundPeers
	}
	// Disconnect random inbound peers if we have too many peers.
	for ii := uint32(0); ii < excessiveInboundPeers; ii++ {
		rn, ok := cc.rniManager.GetRemoteNodeIndexer().GetNonValidatorInboundIndex().GetRandom()
		if !ok {
			break
		}
		cc.rniManager.Disconnect(rn)
	}
}

func (cc *ConnectionController) getRandomUnconnectedAddress() *wire.NetAddress {
	for tries := 0; tries < 100; tries++ {
		addr := cc.AddrMgr.GetAddress()
		if addr == nil {
			//glog.V(2).Infof("ConnectionManager.getRandomUnconnectedAddress: addr from GetAddressWithExclusions was nil")
			break
		}

		if cc.server.IsConnectedOutboundIpAddress(addr.NetAddress()) {
			//glog.V(2).Infof("ConnectionManager.getRandomUnconnectedAddress: Not choosing address due to redundancy %v:%v", addr.NetAddress().IP, addr.NetAddress().Port)
			continue
		}

		if cc.server.IsAttemptedOutboundIpAddress(addr.NetAddress()) {
			continue
		}

		// We can only have one outbound address per /16. This is similar to
		// Bitcoin and we do it to prevent Sybil attacks.
		if cc.server.IsFromRedundantOutboundIPAddress(addr.NetAddress()) {
			//glog.V(2).Infof("ConnectionManager.getRandomUnconnectedAddress: Not choosing address due to redundant group key %v:%v", addr.NetAddress().IP, addr.NetAddress().Port)
			continue
		}

		return addr.NetAddress()
	}

	//glog.V(2).Infof("ConnectionManager.getRandomAddr: Returning nil")
	return nil
}

func (cc *ConnectionController) SetTargetOutboundPeers(numPeers uint32) {
	cc.targetOutboundPeers = numPeers
}

func (cc *ConnectionController) enoughInboundPeers() bool {
	return cc.rniManager.GetNumConnectedInboundPeers() >= cc.maxInboundPeers
}

func (cc *ConnectionController) enoughOutboundPeers() bool {
	return cc.rniManager.GetNumConnectedOutboundPeers() >= cc.targetOutboundPeers
}

func (cc *ConnectionController) processInboundConnection(conn Connection) error {
	var ic *inboundConnection
	var ok bool
	if ic, ok = conn.(*inboundConnection); !ok {
		return fmt.Errorf("ConnectionController.handleInboundConnection: Connection is not an inboundConnection")
	}

	// As a quick check, reject the peer if we have too many already. Note that
	// this check isn't perfect but we have a later check at the end after doing
	// a version negotiation that will properly reject the peer if this check
	// messes up e.g. due to a concurrency issue.
	//
	// TODO: We should instead have eviction logic here to prevent
	// someone from monopolizing a node's inbound connections.
	if cc.enoughInboundPeers() {
		return fmt.Errorf("ConnectionController.handleInboundConnection: Rejecting INBOUND peer (%s) due to max "+
			"inbound peers (%d) hit", ic.connection.RemoteAddr().String(), cc.maxInboundPeers)
	}

	// If we want to limit inbound connections to one per IP address, check to
	// make sure this address isn't already connected.
	if cc.limitOneInboundConnectionPerIP &&
		cc.isFromRedundantInboundIPAddress(ic.connection.RemoteAddr()) {

		return fmt.Errorf("ConnectionController.handleInboundConnection: Rejecting INBOUND peer (%s) due to already having an "+
			"inbound connection from the same IP with limit_one_inbound_connection_per_ip set",
			ic.connection.RemoteAddr().String())
	}

	na, err := cc.ConvertIPStringToNetAddress(ic.connection.RemoteAddr().String())
	if err != nil {
		return errors.Wrapf(err, "ConnectionController.handleInboundConnection: Problem calling ipToNetAddr "+
			"for addr: (%s)", ic.connection.RemoteAddr().String())
	}

	remoteNode := NewRemoteNode()
	if err := remoteNode.ConnectInboundPeer(ic.connection, na); err != nil {
		return errors.Wrapf(err, "ConnectionController.handleInboundConnection: Problem calling ConnectInboundPeer "+
			"for addr: (%s)", ic.connection.RemoteAddr().String())
	}
	cc.rniManager.AddRemoteNode(remoteNode)
	cc.rniManager.SetNonValidatorInbound(remoteNode)

	return nil
}

func (cc *ConnectionController) processOutboundConnection(conn Connection) error {
	var oc *outboundConnection
	var ok bool
	if oc, ok = conn.(*outboundConnection); !ok {
		return fmt.Errorf("ConnectionController.handleOutboundConnection: Connection is not an outboundConnection")
	}

	if oc.failed {
		return fmt.Errorf("ConnectionController.handleOutboundConnection: Failed to connect to peer (%s)", oc.address.IP.String())
	}

	if !oc.isPersistent {
		cc.AddrMgr.Connected(oc.address)
		cc.AddrMgr.Good(oc.address)
	}

	// if this is a non-persistent outbound peer and we already have enough
	// outbound peers, then don't bother adding this one.
	if !oc.isPersistent && cc.enoughOutboundPeers() {
		return fmt.Errorf("ConnectionController.handleOutboundConnection: Connected to maximum number of outbound "+
			"peers (%d)", cc.targetOutboundPeers)
	}

	// If this is a non-persistent outbound peer and the group key
	// overlaps with another peer we're already connected to then
	// abort mission. We only connect to one peer per IP group in
	// order to prevent Sybil attacks.
	if !oc.isPersistent && cc.server.IsFromRedundantOutboundIPAddress(oc.address) {

		// TODO: Make this less verbose
		return fmt.Errorf("ConnectionController.handleOutboundConnection: Rejecting OUTBOUND NON-PERSISTENT connection with "+
			"redundant group key (%s).", addrmgr.GroupKey(oc.address))
	}

	na, err := cc.ConvertIPStringToNetAddress(oc.connection.RemoteAddr().String())
	if err != nil {
		return errors.Wrapf(err, "ConnectionController.handleOutboundConnection: Problem calling ipToNetAddr "+
			"for addr: (%s)", oc.connection.RemoteAddr().String())
	}

	remoteNode := NewRemoteNode()
	if err := remoteNode.ConnectOutboundPeer(oc.connection, na, 0, false, false); err != nil {
		return errors.Wrapf(err, "ConnectionController.handleOutboundConnection: Problem calling ConnectOutboundPeer "+
			"for addr: (%s)", oc.connection.RemoteAddr().String())
	}
	cc.rniManager.AddRemoteNode(remoteNode)
	cc.rniManager.SetNonValidatorOutbound(remoteNode)

	return nil
}

func (cc *ConnectionController) createValidatorConnection(ipStr string, pk bls.PublicKey) (_err error) {
	netAddr, err := cc.ConvertIPStringToNetAddress(ipStr)
	if err != nil {
		return err
	}
	cc.rniManager.CreateValidatorConnection(netAddr, pk)
	return nil
}

func (cc *ConnectionController) createPersistentOutboundConnection(ipStr string) (_err error) {
	netAddr, err := cc.ConvertIPStringToNetAddress(ipStr)
	if err != nil {
		return err
	}
	cc.rniManager.CreatePersistentOutboundConnectionNetAddress(netAddr)
	return nil
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

func (cc *ConnectionController) isFromRedundantInboundIPAddress(addr net.Addr) bool {
	netAddr, err := IPToNetAddr(addr.String(), cc.AddrMgr, cc.params)
	if err != nil {
		// Return true in case we have an error. We do this because it
		// will result in the peer connection not being accepted, which
		// is desired in this case.
		glog.Warningf(errors.Wrapf(err,
			"ConnectionController._isFromRedundantInboundIPAddress: Problem parsing "+
				"net.Addr to wire.NetAddress so marking as redundant and not "+
				"making connection").Error())
		return true
	}
	if netAddr == nil {
		glog.Warningf("ConnectionController._isFromRedundantInboundIPAddress: " +
			"address was nil after parsing so marking as redundant and not " +
			"making connection")
		return true
	}

	return cc.server.IsFromRedundantInboundIPAddress(netAddr)
}

func (cc *ConnectionController) getAddrsToBroadcast() []*SingleAddr {
	cc.addrsToBroadcastLock.Lock()
	defer cc.addrsToBroadcastLock.Unlock()

	// If there's nothing in the map, return.
	if len(cc.addrsToBroadcast) == 0 {
		return []*SingleAddr{}
	}

	// If we get here then we have some addresses to broadcast.
	addrsToBroadcast := []*SingleAddr{}
	for uint32(len(addrsToBroadcast)) < cc.params.MaxAddressesToBroadcast &&
		len(cc.addrsToBroadcast) > 0 {
		// Choose a key at random. This works because map iteration is random in golang.
		bucket := ""
		for kk := range cc.addrsToBroadcast {
			bucket = kk
			break
		}

		// Remove the last element from the slice for the given bucket.
		currentAddrList := cc.addrsToBroadcast[bucket]
		if len(currentAddrList) > 0 {
			lastIndex := len(currentAddrList) - 1
			currentAddr := currentAddrList[lastIndex]
			currentAddrList = currentAddrList[:lastIndex]
			if len(currentAddrList) == 0 {
				delete(cc.addrsToBroadcast, bucket)
			} else {
				cc.addrsToBroadcast[bucket] = currentAddrList
			}

			addrsToBroadcast = append(addrsToBroadcast, currentAddr)
		}
	}

	return addrsToBroadcast
}
