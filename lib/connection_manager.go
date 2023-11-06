package lib

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/addrmgr"
	chainlib "github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/lru"
	"github.com/deso-protocol/go-deadlock"
	"github.com/golang/glog"
)

// connection_manager.go contains most of the logic for creating and managing
// connections with peers. A good place to start is the Start() function.

const (
	// These values behave as -1 when added to a uint. To decrement a uint
	// atomically you need to do use these values.

	// Uint64Dec decrements a uint64 by one.
	Uint64Dec = ^uint64(0)
	// Uint32Dec decrements a uint32 by one.
	Uint32Dec = ^uint32(0)
)

type ConnectionManager struct {
	// Keep a reference to the Server.
	// TODO: I'm pretty sure we can make it so that the ConnectionManager and the Peer
	// doesn't need a reference to the Server object. But for now we keep things lazy.
	srv *Server

	// The interfaces we listen on for new incoming connections.
	listeners []net.Listener
	// The parameters we are initialized with.
	params *DeSoParams

	// When --hypersync is set to true we will attempt fast block synchronization
	HyperSync bool
	// We have the following options for SyncType:
	// - any: Will sync with a node no matter what kind of syncing it supports.
	// - blocksync: Will sync by connecting blocks from the beginning of time.
	// - hypersync-archival: Will sync by hypersyncing state, but then it will
	//   still download historical blocks at the end. Can only be set if HyperSync
	//   is true.
	// - hypersync: Will sync by downloading historical state, and will NOT
	//   download historical blocks. Can only be set if HyperSync is true.
	SyncType NodeSyncType

	// Keep track of the nonces we've sent in our version messages so
	// we can prevent connections to ourselves.
	sentNonces lru.Cache

	// This section defines the data structures for storing all the
	// peers we're aware of.
	//
	// A count of the number active connections we have for each IP group.
	// We use this to ensure we don't connect to more than one outbound
	// peer from the same IP group. We need a mutex on it because it's used
	// concurrently by many goroutines to figure out if outbound connections
	// should be made to particular addresses.

	mtxOutboundConnIPGroups deadlock.Mutex
	outboundConnIPGroups    map[string]int
	// The peer maps map peer ID to peers for various types of peer connections.
	//
	// A persistent peer is typically one we got through a commandline argument.
	// The reason it's called persistent is because we maintain a connection to
	// it, and retry the connection if it fails.
	mtxPeerMaps     deadlock.RWMutex
	persistentPeers map[uint64]*Peer
	outboundPeers   map[uint64]*Peer
	inboundPeers    map[uint64]*Peer
	connectedPeers  map[uint64]*Peer

	outboundConnectionAttempts map[uint64]*OutboundConnectionAttempt
	outboundConnectionChan     chan *outboundConnection
	inboundConnectionChan      chan *inboundConnection
	// Track the number of outbound peers we have so that this value can
	// be accessed concurrently when deciding whether or not to add more
	// outbound peers.
	numOutboundPeers   uint32
	numInboundPeers    uint32
	numPersistentPeers uint32

	// We keep track of the addresses for the outbound peers so that we can
	// avoid choosing them in the address manager. We need a mutex on this
	// guy because many goroutines will be querying the address manager
	// at once.
	mtxConnectedOutboundAddrs deadlock.RWMutex
	connectedOutboundAddrs    map[string]bool
	attemptedOutboundAddrs    map[string]bool

	// Used to set peer ids. Must be incremented atomically.
	peerIndex    uint64
	attemptIndex uint64

	serverMessageQueue chan *ServerMessage

	// Keeps track of the network time, which is the median of all of our
	// peers' time.
	timeSource chainlib.MedianTimeSource

	// Events that can happen to a peer.
	newPeerChan  chan *Peer
	donePeerChan chan *Peer

	// stallTimeoutSeconds is how long we wait to receive responses from Peers
	// for certain types of messages.
	stallTimeoutSeconds uint64

	minFeeRateNanosPerKB uint64

	// More chans we might want.	modifyRebroadcastInv chan interface{}
	shutdown int32
}

func NewConnectionManager(
	_params *DeSoParams, _listeners []net.Listener,
	_connectIps []string, _timeSource chainlib.MedianTimeSource,
	_hyperSync bool,
	_syncType NodeSyncType,
	_stallTimeoutSeconds uint64,
	_minFeeRateNanosPerKB uint64,
	_serverMessageQueue chan *ServerMessage,
	_srv *Server) *ConnectionManager {

	ValidateHyperSyncFlags(_hyperSync, _syncType)

	return &ConnectionManager{
		srv:       _srv,
		params:    _params,
		listeners: _listeners,
		// We keep track of the last N nonces we've sent in order to detect
		// self connections.
		sentNonces: lru.NewCache(1000),
		timeSource: _timeSource,
		//newestBlock: _newestBlock,

		// Initialize the peer data structures.
		outboundConnIPGroups:       make(map[string]int),
		persistentPeers:            make(map[uint64]*Peer),
		outboundPeers:              make(map[uint64]*Peer),
		inboundPeers:               make(map[uint64]*Peer),
		connectedPeers:             make(map[uint64]*Peer),
		outboundConnectionAttempts: make(map[uint64]*OutboundConnectionAttempt),
		connectedOutboundAddrs:     make(map[string]bool),
		attemptedOutboundAddrs:     make(map[string]bool),

		// Initialize the channels.
		newPeerChan:            make(chan *Peer, 100),
		donePeerChan:           make(chan *Peer, 100),
		outboundConnectionChan: make(chan *outboundConnection, 100),

		HyperSync:            _hyperSync,
		SyncType:             _syncType,
		serverMessageQueue:   _serverMessageQueue,
		stallTimeoutSeconds:  _stallTimeoutSeconds,
		minFeeRateNanosPerKB: _minFeeRateNanosPerKB,
	}
}

// Check if the address passed shares a group with any addresses already in our
// data structures.
func (cmgr *ConnectionManager) isRedundantGroupKey(na *wire.NetAddress) bool {
	groupKey := addrmgr.GroupKey(na)

	cmgr.mtxOutboundConnIPGroups.Lock()
	numGroupsForKey := cmgr.outboundConnIPGroups[groupKey]
	cmgr.mtxOutboundConnIPGroups.Unlock()

	if numGroupsForKey != 0 && numGroupsForKey != 1 {
		glog.V(2).Infof("isRedundantGroupKey: Found numGroupsForKey != (0 or 1). Is (%d) "+
			"instead for addr (%s) and group key (%s). This "+
			"should never happen.", numGroupsForKey, na.IP.String(), groupKey)
	}

	if numGroupsForKey == 0 {
		return false
	}
	return true
}

func (cmgr *ConnectionManager) addToGroupKey(na *wire.NetAddress) {
	groupKey := addrmgr.GroupKey(na)

	cmgr.mtxOutboundConnIPGroups.Lock()
	cmgr.outboundConnIPGroups[groupKey]++
	cmgr.mtxOutboundConnIPGroups.Unlock()
}

func (cmgr *ConnectionManager) subFromGroupKey(na *wire.NetAddress) {
	groupKey := addrmgr.GroupKey(na)

	cmgr.mtxOutboundConnIPGroups.Lock()
	cmgr.outboundConnIPGroups[groupKey]--
	cmgr.mtxOutboundConnIPGroups.Unlock()
}

func (cmgr *ConnectionManager) IsConnectedOutboundIpAddress(netAddr *wire.NetAddress) bool {
	// Lock the address map since multiple threads will be trying to read
	// and modify it at the same time.
	cmgr.mtxConnectedOutboundAddrs.RLock()
	defer cmgr.mtxConnectedOutboundAddrs.RUnlock()
	return cmgr.connectedOutboundAddrs[addrmgr.NetAddressKey(netAddr)]
}

func (cmgr *ConnectionManager) IsAttemptedOutboundIpAddress(netAddr *wire.NetAddress) bool {
	return cmgr.attemptedOutboundAddrs[addrmgr.NetAddressKey(netAddr)]
}

func (cmgr *ConnectionManager) AddAttemptedOutboundAddrs(netAddr *wire.NetAddress) {
	cmgr.attemptedOutboundAddrs[addrmgr.NetAddressKey(netAddr)] = true
}

func (cmgr *ConnectionManager) RemoveAttemptedOutboundAddrs(netAddr *wire.NetAddress) {
	delete(cmgr.attemptedOutboundAddrs, addrmgr.NetAddressKey(netAddr))
}

func (cmgr *ConnectionManager) CreatePersistentOutboundConnection(persistentAddr *wire.NetAddress) (_attemptId uint64) {
	return cmgr._createOutboundConnection(persistentAddr, true)
}

func (cmgr *ConnectionManager) CreateOutboundConnection(addr *wire.NetAddress) (_attemptId uint64) {
	return cmgr._createOutboundConnection(addr, false)
}

func (cmgr *ConnectionManager) CloseAttemptedConnection(attemptId uint64) {
	if attempt, exists := cmgr.outboundConnectionAttempts[attemptId]; exists {
		attempt.Stop()
	}
}

func (cmgr *ConnectionManager) _createOutboundConnection(addr *wire.NetAddress, isPersistent bool) (_attemptId uint64) {
	attemptId := atomic.AddUint64(&cmgr.attemptIndex, 1)
	connectionAttempt := NewOutboundConnectionAttempt(attemptId, addr, isPersistent,
		cmgr.params.DialTimeout, cmgr.outboundConnectionChan)
	cmgr.outboundConnectionAttempts[connectionAttempt.attemptId] = connectionAttempt
	cmgr.AddAttemptedOutboundAddrs(addr)

	connectionAttempt.Start()
	return attemptId
}

// ConnectPeer connects either an INBOUND or OUTBOUND peer. If Conn == nil,
// then we will set up an OUTBOUND peer. Otherwise we will use the Conn to
// create an INBOUND peer. If the connection is OUTBOUND and the persistentAddr
// is set, then we will connect only to that addr. Otherwise, we will use
// the addrmgr to randomly select addrs and create OUTBOUND connections
// with them until we find a worthy peer.
func (cmgr *ConnectionManager) ConnectPeer(conn net.Conn, na *wire.NetAddress, attemptId uint64, isOutbound bool, isPersistent bool) *Peer {
	// At this point Conn is set so create a peer object to do a version negotiation.
	id := atomic.AddUint64(&cmgr.peerIndex, 1)
	peer := NewPeer(id, attemptId, conn, isOutbound, na, isPersistent,
		cmgr.stallTimeoutSeconds,
		cmgr.minFeeRateNanosPerKB,
		cmgr.params,
		cmgr.srv.incomingMessages, cmgr, cmgr.srv, cmgr.SyncType,
		cmgr.newPeerChan, cmgr.donePeerChan)

	// Now we can add the peer to our data structures.
	peer._logAddPeer()
	cmgr.addPeer(peer)

	// Start the peer's message loop.
	peer.Start()

	// FIXME: Move this earlier
	// Signal the server about the new Peer in case it wants to do something with it.
	go func() {
		cmgr.serverMessageQueue <- &ServerMessage{
			Peer: peer,
			Msg:  &MsgDeSoNewPeer{},
		}
	}()

	return peer
}

func (cmgr *ConnectionManager) _isFromRedundantInboundIPAddress(netAddr *wire.NetAddress) bool {
	cmgr.mtxPeerMaps.RLock()
	defer cmgr.mtxPeerMaps.RUnlock()

	// Loop through all the peers to see if any have the same IP
	// address. This map is normally pretty small so doing this
	// every time a Peer connects should be fine.

	// If the IP is a localhost IP let it slide. This is useful for testing fake
	// nodes on a local machine.
	// TODO: Should this be a flag?
	if net.IP([]byte{127, 0, 0, 1}).Equal(netAddr.IP) {
		glog.V(1).Infof("ConnectionManager._isFromRedundantInboundIPAddress: Allowing " +
			"localhost IP address to connect")
		return false
	}
	for _, peer := range cmgr.inboundPeers {
		// If the peer's IP is equal to the passed IP then we have found a duplicate
		// inbound connection
		if peer.netAddr.IP.Equal(netAddr.IP) {
			return true
		}
	}

	// If we get here then no duplicate inbound IPs were found.
	return false
}

func (cmgr *ConnectionManager) _handleInboundConnections() {
	for _, outerListener := range cmgr.listeners {
		go func(ll net.Listener) {
			for {
				conn, err := ll.Accept()
				if conn == nil {
					return
				}
				glog.V(2).Infof("_handleInboundConnections: received connection from: local %v, remote %v",
					conn.LocalAddr().String(), conn.RemoteAddr().String())
				if atomic.LoadInt32(&cmgr.shutdown) != 0 {
					glog.Info("_handleInboundConnections: Ignoring connection due to shutdown")
					return
				}
				if err != nil {
					glog.Errorf("_handleInboundConnections: Can't accept connection: %v", err)
					continue
				}

				cmgr.inboundConnectionChan <- &inboundConnection{
					connection: conn,
				}
			}
		}(outerListener)
	}
}

// GetAllPeers holds the mtxPeerMaps lock for reading and returns a list containing
// pointers to all the active peers.
func (cmgr *ConnectionManager) GetAllPeers() []*Peer {
	cmgr.mtxPeerMaps.RLock()
	defer cmgr.mtxPeerMaps.RUnlock()

	allPeers := []*Peer{}
	for _, pp := range cmgr.persistentPeers {
		allPeers = append(allPeers, pp)
	}
	for _, pp := range cmgr.outboundPeers {
		allPeers = append(allPeers, pp)
	}
	for _, pp := range cmgr.inboundPeers {
		allPeers = append(allPeers, pp)
	}

	return allPeers
}

func (cmgr *ConnectionManager) RandomPeer() *Peer {
	cmgr.mtxPeerMaps.RLock()
	defer cmgr.mtxPeerMaps.RUnlock()

	// Prefer persistent peers over all other peers.
	if len(cmgr.persistentPeers) > 0 {
		// Maps iterate randomly so this should be sufficient.
		for _, pp := range cmgr.persistentPeers {
			return pp
		}
	}

	// Prefer outbound peers over inbound peers.
	if len(cmgr.outboundPeers) > 0 {
		// Maps iterate randomly so this should be sufficient.
		for _, pp := range cmgr.outboundPeers {
			return pp
		}
	}

	// If we don't have any other type of peer, use an inbound peer.
	if len(cmgr.inboundPeers) > 0 {
		// Maps iterate randomly so this should be sufficient.
		for _, pp := range cmgr.inboundPeers {
			return pp
		}
	}

	return nil
}

// Update our data structures to add this peer.
func (cmgr *ConnectionManager) addPeer(pp *Peer) {
	// Acquire the mtxPeerMaps lock for writing.
	cmgr.mtxPeerMaps.Lock()
	defer cmgr.mtxPeerMaps.Unlock()

	// Figure out what list this peer belongs to.
	var peerList map[uint64]*Peer
	if pp.isPersistent {
		peerList = cmgr.persistentPeers
		atomic.AddUint32(&cmgr.numPersistentPeers, 1)
	} else if pp.isOutbound {
		peerList = cmgr.outboundPeers

		// If this is a non-persistent outbound peer and if
		// the peer was not previously in our data structures then
		// increment the count for this IP group and increment the
		// number of outbound peers. Also add the peer's address to
		// our map.
		if _, ok := peerList[pp.ID]; !ok {
			cmgr.addToGroupKey(pp.netAddr)
			atomic.AddUint32(&cmgr.numOutboundPeers, 1)

			cmgr.mtxConnectedOutboundAddrs.Lock()
			cmgr.connectedOutboundAddrs[addrmgr.NetAddressKey(pp.netAddr)] = true
			cmgr.mtxConnectedOutboundAddrs.Unlock()
		}
	} else {
		// This is an inbound peer.
		atomic.AddUint32(&cmgr.numInboundPeers, 1)
		peerList = cmgr.inboundPeers
	}

	peerList[pp.ID] = pp
	cmgr.connectedPeers[pp.ID] = pp
}

func (cmgr *ConnectionManager) SendMessage(msg DeSoMessage, peerId uint64) error {
	if peer, ok := cmgr.connectedPeers[peerId]; ok {
		glog.V(1).Infof("SendMessage: Sending message %v to peer %d", msg.GetMsgType().String(), peerId)
		peer.AddDeSoMessage(msg, false)
	} else {
		return fmt.Errorf("SendMessage: Peer with ID %d not found", peerId)
	}
	return nil
}

func (cmgr *ConnectionManager) DisconnectPeer(peerId uint64) {
	var peer *Peer
	var ok bool
	cmgr.mtxPeerMaps.Lock()
	peer, ok = cmgr.connectedPeers[peerId]
	cmgr.mtxPeerMaps.Unlock()
	if !ok {
		return
	}
	peer.Disconnect()
}

// Update our data structures to remove this peer.
func (cmgr *ConnectionManager) removePeer(pp *Peer) {
	// Acquire the mtxPeerMaps lock for writing.
	cmgr.mtxPeerMaps.Lock()
	defer cmgr.mtxPeerMaps.Unlock()

	// Figure out what list this peer belongs to.
	var peerList map[uint64]*Peer
	if pp.isPersistent {
		peerList = cmgr.persistentPeers
		atomic.AddUint32(&cmgr.numPersistentPeers, Uint32Dec)
	} else if pp.isOutbound {
		peerList = cmgr.outboundPeers

		// If this is a non-persistent outbound peer and if
		// the peer was previously in our data structures then
		// decrement the outbound group count and the number of
		// outbound peers.
		if _, ok := peerList[pp.ID]; ok {
			cmgr.subFromGroupKey(pp.netAddr)
			atomic.AddUint32(&cmgr.numOutboundPeers, Uint32Dec)

			cmgr.mtxConnectedOutboundAddrs.Lock()
			delete(cmgr.connectedOutboundAddrs, addrmgr.NetAddressKey(pp.netAddr))
			cmgr.mtxConnectedOutboundAddrs.Unlock()
		}
	} else {
		// This is an inbound peer.
		atomic.AddUint32(&cmgr.numInboundPeers, Uint32Dec)
		peerList = cmgr.inboundPeers
	}

	// Update the last seen time before we finish removing the peer.
	// TODO: Really, we call 'Connected()' on removing a peer?
	// I can't find a Disconnected() but seems odd.
	// FIXME: Move this to Done Peer
	//cmgr.AddrMgr.Connected(pp.netAddr)

	// Remove the peer from our data structure.
	delete(peerList, pp.ID)
	delete(cmgr.connectedPeers, pp.ID)
}

func (cmgr *ConnectionManager) _logOutboundPeerData() {
	numOutboundPeers := int(atomic.LoadUint32(&cmgr.numOutboundPeers))
	numInboundPeers := int(atomic.LoadUint32(&cmgr.numInboundPeers))
	numPersistentPeers := int(atomic.LoadUint32(&cmgr.numPersistentPeers))
	glog.V(1).Infof("Num peers: OUTBOUND(%d) INBOUND(%d) PERSISTENT(%d)", numOutboundPeers, numInboundPeers, numPersistentPeers)

	cmgr.mtxOutboundConnIPGroups.Lock()
	for _, vv := range cmgr.outboundConnIPGroups {
		if vv != 0 && vv != 1 {
			glog.V(1).Infof("_logOutboundPeerData: Peer group count != (0 or 1). "+
				"Is (%d) instead. This "+
				"should never happen.", vv)
		}
	}
	cmgr.mtxOutboundConnIPGroups.Unlock()
}

func (cmgr *ConnectionManager) AddTimeSample(addrStr string, timeSample time.Time) {
	cmgr.timeSource.AddTimeSample(addrStr, timeSample)
}

func (cmgr *ConnectionManager) GetNumInboundPeers() uint32 {
	return atomic.LoadUint32(&cmgr.numInboundPeers)
}

func (cmgr *ConnectionManager) GetNumOutboundPeers() uint32 {
	return atomic.LoadUint32(&cmgr.numOutboundPeers)
}

func (cmgr *ConnectionManager) Start() {
	// Below is a basic description of the ConnectionManager's main loop:
	//
	// We have listeners (for inbound connections) and we have an addrmgr (for outbound connections).
	// Specify TargetOutbound connections we want to have.
	// Create TargetOutbound connection objects each with their own id.
	// Add these connection objects to a map of some sort.
	// Initiate TargetOutbound connections to peers using the addrmgr.
	// When a connection fails, remove that connection from the map and try another connection in its place. Wait for that connection to return. Repeat.
	// - If a connection has failed a few times then add a retryduration (since we're probably out of addresses).
	// - If you can't connect to a node because the addrmgr returned nil, wait some amount of time and then try again.
	// When a connection succeeds:
	// - Send the peer a version message.
	// - Read a version message from the peer.
	// - Wait for the above two steps to return.
	// - If the above steps don't return, then disconnect from the peer as above. Try to reconnect to another peer.
	// If the steps above succeed
	// - Have the peer enter a switch statement listening for all kinds of messages.
	// - Send addr and getaddr messages as appropriate.

	// Accept inbound connections from peers on our listeners.
	cmgr._handleInboundConnections()

	glog.Infof("Full node socket initialized")

	for {
		// Log some data for each event.
		cmgr._logOutboundPeerData()

		select {
		case oc := <-cmgr.outboundConnectionChan:
			glog.V(2).Infof("ConnectionManager.Start: Successfully established an outbound connection with "+
				"(addr= %v)", oc.connection.RemoteAddr())
			cmgr.serverMessageQueue <- &ServerMessage{
				Peer: nil,
				Msg: &MsgDeSoNewConnection{
					Connection: oc,
				},
			}
		case ic := <-cmgr.inboundConnectionChan:
			glog.V(2).Infof("ConnectionManager.Start: Successfully received an inbound connection from "+
				"(addr= %v)", ic.connection.RemoteAddr())
			cmgr.serverMessageQueue <- &ServerMessage{
				Peer: nil,
				Msg: &MsgDeSoNewConnection{
					Connection: ic,
				},
			}
		case pp := <-cmgr.donePeerChan:
			{
				// By the time we get here, it can be assumed that the Peer's Disconnect function
				// has already been called, since that is what's responsible for adding the peer
				// to this queue in the first place.

				glog.V(1).Infof("Done with peer (%v).", pp)

				// Remove the peer from our data structures.
				cmgr.removePeer(pp)

				// Potentially replace the peer. For example, if the Peer was an outbound Peer
				// then we want to find a new peer in order to maintain our TargetOutboundPeers.

				// Signal the server about the Peer being done in case it wants to do something
				// with it.
				cmgr.serverMessageQueue <- &ServerMessage{
					Peer: pp,
					Msg:  &MsgDeSoDonePeer{},
				}
			}
		}
	}
}

func (cmgr *ConnectionManager) Stop() {
	if atomic.AddInt32(&cmgr.shutdown, 1) != 1 {
		glog.Warningf("ConnectionManager.Stop is already in the process of " +
			"shutting down")
		return
	}

	for _, ca := range cmgr.outboundConnectionAttempts {
		ca.Stop()
	}

	glog.Infof("ConnectionManager: Stopping, number of inbound peers (%v), number of outbound "+
		"peers (%v), number of persistent peers (%v).", len(cmgr.inboundPeers), len(cmgr.outboundPeers),
		len(cmgr.persistentPeers))
	for _, peer := range cmgr.inboundPeers {
		glog.V(1).Infof(CLog(Red, fmt.Sprintf("ConnectionManager.Stop: Inbound peer (%v)", peer)))
		peer.Disconnect()
	}
	for _, peer := range cmgr.outboundPeers {
		glog.V(1).Infof("ConnectionManager.Stop: Outbound peer (%v)", peer)
		peer.Disconnect()
	}
	for _, peer := range cmgr.persistentPeers {
		glog.V(1).Infof("ConnectionManager.Stop: Persistent peer (%v)", peer)
		peer.Disconnect()
	}

	// Close all of the listeners.
	for _, listener := range cmgr.listeners {
		_ = listener.Close()
	}
}
