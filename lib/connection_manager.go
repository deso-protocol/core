package lib

import (
	"math"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/addrmgr"
	chainlib "github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/lru"
	"github.com/deso-protocol/go-deadlock"
	"github.com/golang/glog"
	"github.com/pkg/errors"
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

	// When --connectips is set, we don't connect to anything from the addrmgr.
	connectIps []string

	// The address manager keeps track of peer addresses we're aware of. When
	// we need to connect to a new outbound peer, it chooses one of the addresses
	// it's aware of at random and provides it to us.
	addrMgr *addrmgr.AddrManager
	// The interfaces we listen on for new incoming connections.
	listeners []net.Listener
	// The parameters we are initialized with.
	params *DeSoParams
	// The target number of outbound peers we want to have.
	targetOutboundPeers uint32
	// The maximum number of inbound peers we allow.
	maxInboundPeers uint32
	// When true, only one connection per IP is allowed. Prevents eclipse attacks
	// among other things.
	limitOneInboundConnectionPerIP bool

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

	// Used to set peer ids. Must be incremented atomically.
	peerIndex uint64

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
	_params *DeSoParams, _addrMgr *addrmgr.AddrManager, _listeners []net.Listener,
	_connectIps []string, _timeSource chainlib.MedianTimeSource,
	_targetOutboundPeers uint32, _maxInboundPeers uint32,
	_limitOneInboundConnectionPerIP bool,
	_stallTimeoutSeconds uint64,
	_minFeeRateNanosPerKB uint64,
	_serverMessageQueue chan *ServerMessage,
	_srv *Server) *ConnectionManager {

	return &ConnectionManager{
		srv:        _srv,
		params:     _params,
		addrMgr:    _addrMgr,
		listeners:  _listeners,
		connectIps: _connectIps,
		// We keep track of the last N nonces we've sent in order to detect
		// self connections.
		sentNonces: lru.NewCache(1000),
		timeSource: _timeSource,

		//newestBlock: _newestBlock,

		// Initialize the peer data structures.
		outboundConnIPGroups:   make(map[string]int),
		persistentPeers:        make(map[uint64]*Peer),
		outboundPeers:          make(map[uint64]*Peer),
		inboundPeers:           make(map[uint64]*Peer),
		connectedOutboundAddrs: make(map[string]bool),

		// Initialize the channels.
		newPeerChan:  make(chan *Peer),
		donePeerChan: make(chan *Peer),

		targetOutboundPeers:            _targetOutboundPeers,
		maxInboundPeers:                _maxInboundPeers,
		limitOneInboundConnectionPerIP: _limitOneInboundConnectionPerIP,
		serverMessageQueue:             _serverMessageQueue,
		stallTimeoutSeconds:            _stallTimeoutSeconds,
		minFeeRateNanosPerKB:           _minFeeRateNanosPerKB,
	}
}

func (cmgr *ConnectionManager) GetAddrManager() *addrmgr.AddrManager {
	return cmgr.addrMgr
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

func (cmgr *ConnectionManager) getRandomAddr() *wire.NetAddress {
	for tries := 0; tries < 100; tries++ {
		// Lock the address map since multiple threads will be trying to read
		// and modify it at the same time.
		cmgr.mtxConnectedOutboundAddrs.RLock()
		addr := cmgr.addrMgr.GetAddress()
		cmgr.mtxConnectedOutboundAddrs.RUnlock()

		if addr == nil {
			glog.V(2).Infof("ConnectionManager.getRandomAddr: addr from GetAddressWithExclusions was nil")
			break
		}

		if cmgr.connectedOutboundAddrs[addrmgr.NetAddressKey(addr.NetAddress())] {
			glog.V(2).Infof("ConnectionManager.getRandomAddr: Not choosing already connected address %v:%v", addr.NetAddress().IP, addr.NetAddress().Port)
			continue
		}

		// We can only have one outbound address per /16. This is similar to
		// Bitcoin and we do it to prevent Sybil attacks.
		if cmgr.isRedundantGroupKey(addr.NetAddress()) {
			glog.V(2).Infof("ConnectionManager.getRandomAddr: Not choosing address due to redundant group key %v:%v", addr.NetAddress().IP, addr.NetAddress().Port)
			continue
		}

		glog.V(2).Infof("ConnectionManager.getRandomAddr: Returning %v:%v at %d iterations",
			addr.NetAddress().IP, addr.NetAddress().Port, tries)
		return addr.NetAddress()
	}

	glog.V(2).Infof("ConnectionManager.getRandomAddr: Returning nil")
	return nil
}

func _delayRetry(retryCount int, persistentAddrForLogging *wire.NetAddress) {
	// No delay if we haven't tried yet or if the number of retries isn't positive.
	if retryCount <= 0 {
		time.Sleep(time.Second)
		return
	}
	numSecs := int(math.Pow(2.0, float64(retryCount)))
	retryDelay := time.Duration(numSecs) * time.Second

	if persistentAddrForLogging != nil {
		glog.V(1).Infof("Retrying connection to outbound persistent peer: "+
			"(%s:%d) in (%d) seconds.", persistentAddrForLogging.IP.String(),
			persistentAddrForLogging.Port, numSecs)
	} else {
		glog.V(2).Infof("Retrying connection to outbound non-persistent peer in (%d) seconds.", numSecs)
	}
	time.Sleep(retryDelay)
}

func (cmgr *ConnectionManager) enoughOutboundPeers() bool {
	val := atomic.LoadUint32(&cmgr.numOutboundPeers)
	if val > cmgr.targetOutboundPeers {
		glog.Errorf("enoughOutboundPeers: Connected to too many outbound "+
			"peers: (%d). Should be "+
			"no more than (%d).", val, cmgr.targetOutboundPeers)
		return true
	}

	if val == cmgr.targetOutboundPeers {
		return true
	}
	return false
}

// Chooses a random address and tries to connect to it. Repeats this proocess until
// it finds a peer that can pass version negotiation.
func (cmgr *ConnectionManager) _getOutboundConn(persistentAddr *wire.NetAddress) net.Conn {
	// If a persistentAddr was provided then the connection is a persistent
	// one.
	isPersistent := (persistentAddr != nil)
	retryCount := 0
	for {
		// We want to start backing off exponentially once we've gone through enough
		// unsuccessful retries. However, we want to give more slack to non-persistent
		// peers before we start backing off, which is why it's not as cut and dry as
		// just delaying based on the raw number of retries.
		adjustedRetryCount := retryCount
		if !isPersistent {
			// If the address is not persistent, only start backing off once there
			// has been a large number of failed attempts in a row as this likely indicates
			// that there's a connection issue we need to wait out.
			adjustedRetryCount = retryCount - 5
		}
		_delayRetry(adjustedRetryCount, persistentAddr)
		retryCount++

		// If the connection manager is saturated with non-persistent
		// outbound peers, no need to keep trying non-persistent outbound
		// connections.
		if !isPersistent && cmgr.enoughOutboundPeers() {
			glog.V(1).Infof("Dropping connection request to non-persistent outbound " +
				"peer because we have enough of them.")
			return nil
		}

		// If we don't have a persistentAddr, pick one from our addrmgr.
		ipNetAddr := persistentAddr
		if ipNetAddr == nil {
			ipNetAddr = cmgr.getRandomAddr()
		}
		if ipNetAddr == nil {
			// This should never happen but if it does, sleep a bit and try again.
			glog.V(1).Infof("_getOutboundConn: No valid addresses to connect to.")
			time.Sleep(time.Second)
			continue
		}

		netAddr := net.TCPAddr{
			IP:   ipNetAddr.IP,
			Port: int(ipNetAddr.Port),
		}

		// If the peer is not persistent, update the addrmgr.
		glog.V(1).Infof("Attempting to connect to addr: %v", netAddr)
		if !isPersistent {
			cmgr.addrMgr.Attempt(ipNetAddr)
		}
		var err error
		conn, err := net.DialTimeout(netAddr.Network(), netAddr.String(), cmgr.params.DialTimeout)
		if err != nil {
			// If we failed to connect to this peer, get a new address and try again.
			glog.V(1).Infof("Connection to addr (%v) failed: %v", netAddr, err)
			continue
		}

		// We were able to dial successfully so we'll break out now.
		glog.V(1).Infof("Connected to addr: %v", netAddr)

		// If this was a non-persistent outbound connection, mark the address as
		// connected in the addrmgr.
		if !isPersistent {
			cmgr.addrMgr.Connected(ipNetAddr)
		}

		// We made a successful outbound connection so return.
		return conn
	}
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

// Connect either an INBOUND or OUTBOUND peer. If conn == nil, then we will set up
// an OUTBOUND peer. Otherwise we will use the conn to create an INBOUND
// peer. If the connectoin is OUTBOUND and the persistentAddr is set, then
// we will connect only to that addr. Otherwise, we will use the addrmgr to
// randomly select addrs and create OUTBOUND connections with them until
// we find a worthy peer.
func (cmgr *ConnectionManager) ConnectPeer(conn net.Conn, persistentAddr *wire.NetAddress) {
	// If we don't have a connection object then we will try and make an
	// outbound connection to a peer to get one.
	isOutbound := false
	if conn == nil {
		isOutbound = true
	}
	isPersistent := (persistentAddr != nil)
	retryCount := 0
	for {
		if isPersistent {
			_delayRetry(retryCount, persistentAddr)
		}
		retryCount++

		// If this is an outbound peer, create an outbound connection.
		if isOutbound {
			conn = cmgr._getOutboundConn(persistentAddr)
		}

		if conn == nil {
			// Conn should only be nil if this is a non-persistent outbound peer.
			if isPersistent {
				glog.Errorf("ConnectPeer: Got a nil connection for a persistent peer. This should never happen: (%s)", persistentAddr.IP.String())
			}

			// If we end up without a connection object, it implies we had enough
			// outbound peers so just return.
			return
		}

		// At this point conn is set so create a peer object to do
		// a version negotiation.
		na, err := IPToNetAddr(conn.RemoteAddr().String(), cmgr.addrMgr, cmgr.params)
		if err != nil {
			glog.Errorf("ConnectPeer: Problem calling ipToNetAddr for addr: (%s) err: (%v)", conn.RemoteAddr().String(), err)

			// If we get an error in the conversion and this is an
			// outbound connection, keep trying it. Otherwise, just return.
			if isOutbound {
				continue
			}
			return
		}
		peer := NewPeer(conn, isOutbound, na, isPersistent,
			cmgr.stallTimeoutSeconds,
			cmgr.minFeeRateNanosPerKB,
			cmgr.params,
			cmgr.srv.incomingMessages, cmgr, cmgr.srv)

		if err := peer.NegotiateVersion(cmgr.params.VersionNegotiationTimeout); err != nil {
			glog.Errorf("ConnectPeer: Problem negotiating version with peer with addr: (%s) err: (%v)", conn.RemoteAddr().String(), err)

			// If we have an error in the version negotiation we disconnect
			// from this peer.
			peer.conn.Close()

			// If the connection is outbound, then
			// we try a new connection until we get one that works. Otherwise
			// we break.
			if isOutbound {
				continue
			}
			return
		}
		peer._logVersionSuccess()

		// If the version negotiation worked and we have an outbound non-persistent
		// connection, mark the address as good in the addrmgr.
		if isOutbound && !isPersistent {
			cmgr.addrMgr.Good(na)
		}

		// We connected to the peer and it passed its version negotiation.
		// Handle the next steps in the main loop.
		cmgr.newPeerChan <- peer

		// Once we've successfully connected to a valid peer we're done. The connection
		// manager will handle starting the peer and, if this is an outbound peer and
		// the peer later disconnects,
		// it will potentially try and reconnect the peer or replace the peer with
		// a new one so that we always maintain a fixed number of outbound peers.
		return
	}
}

func (cmgr *ConnectionManager) _initiateOutboundConnections() {
	// This is a hack to make outbound connections go away.
	if cmgr.targetOutboundPeers == 0 {
		return
	}
	if len(cmgr.connectIps) > 0 {
		// Connect to addresses passed via the --connectips flag. These addresses
		// are persistent in the sense that if we disconnect from one, we will
		// try to reconnect to the same one.
		for _, connectIp := range cmgr.connectIps {
			ipNetAddr, err := IPToNetAddr(connectIp, cmgr.addrMgr, cmgr.params)
			if err != nil {
				glog.Error(errors.Errorf("Couldn't connect to IP %v: %v", connectIp, err))
				continue
			}

			go func(na *wire.NetAddress) {
				cmgr.ConnectPeer(nil, na)
			}(ipNetAddr)
		}
		return
	}
	// Only connect to addresses from the addrmgr if we don't specify --connectips.
	// These addresses are *not* persistent, meaning if we disconnect from one we'll
	// try a different one.
	//
	// TODO: We should try more addresses than we need initially to increase the
	// speed at which we saturate our outbound connections. The ConnectionManager
	// will handle the disconnection from peers once we have enough outbound
	// connections. I had this as the logic before but removed it because it caused
	// contention of the addrMgr's lock.
	for ii := 0; ii < int(cmgr.targetOutboundPeers); ii++ {
		go cmgr.ConnectPeer(nil, nil)
	}
}

func (cmgr *ConnectionManager) _isFromRedundantInboundIPAddress(addrToCheck net.Addr) bool {
	cmgr.mtxPeerMaps.RLock()
	defer cmgr.mtxPeerMaps.RUnlock()

	// Loop through all the peers to see if any have the same IP
	// address. This map is normally pretty small so doing this
	// every time a Peer connects should be fine.
	netAddr, err := IPToNetAddr(addrToCheck.String(), cmgr.addrMgr, cmgr.params)
	if err != nil {
		// Return true in case we have an error. We do this because it
		// will result in the peer connection not being accepted, which
		// is desired in this case.
		glog.Warningf(errors.Wrapf(err,
			"ConnectionManager._isFromRedundantInboundIPAddress: Problem parsing "+
				"net.Addr to wire.NetAddress so marking as redundant and not "+
				"making connection").Error())
		return true
	}
	if netAddr == nil {
		glog.Warningf("ConnectionManager._isFromRedundantInboundIPAddress: " +
			"address was nil after parsing so marking as redundant and not " +
			"making connection")
		return true
	}
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
				if atomic.LoadInt32(&cmgr.shutdown) != 0 {
					glog.Info("_handleInboundConnections: Ignoring connection due to shutdown")
					return
				}
				if err != nil {
					glog.Errorf("_handleInboundConnections: Can't accept connection: %v", err)
					continue
				}

				// As a quick check, reject the peer if we have too many already. Note that
				// this check isn't perfect but we have a later check at the end after doing
				// a version negotiation that will properly reject the peer if this check
				// messes up e.g. due to a concurrency issue.
				//
				// TODO: We should instead have eviction logic here to prevent
				// someone from monopolizing a node's inbound connections.
				numInboundPeers := atomic.LoadUint32(&cmgr.numInboundPeers)
				if numInboundPeers > cmgr.maxInboundPeers {

					glog.Infof("Rejecting INBOUND peer (%s) due to max inbound peers (%d) hit.",
						conn.RemoteAddr().String(), cmgr.maxInboundPeers)
					conn.Close()

					continue
				}

				// If we want to limit inbound connections to one per IP address, check to
				// make sure this address isn't already connected.
				if cmgr.limitOneInboundConnectionPerIP &&
					cmgr._isFromRedundantInboundIPAddress(conn.RemoteAddr()) {

					glog.Infof("Rejecting INBOUND peer (%s) due to already having an "+
						"inbound connection from the same IP with "+
						"limit_one_inbound_connection_per_ip set.",
						conn.RemoteAddr().String())
					conn.Close()

					continue
				}

				go cmgr.ConnectPeer(conn, nil)
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
}

// Update our data structures to remove this peer.
func (cmgr *ConnectionManager) RemovePeer(pp *Peer) {
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
	cmgr.addrMgr.Connected(pp.netAddr)

	// Remove the peer from our data structure.
	delete(peerList, pp.ID)
}

func (cmgr *ConnectionManager) _maybeReplacePeer(pp *Peer) {
	// If the peer was outbound, replace her with a
	// new peer to maintain a fixed number of outbound connections.
	if pp.isOutbound {
		// If the peer is not persistent then we don't want to pass an
		// address to connectPeer. The lack of an address will cause it
		// to choose random addresses from the addrmgr until one works.
		na := pp.netAddr
		if !pp.isPersistent {
			na = nil
		}
		go cmgr.ConnectPeer(nil, na)
	}
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

func (cmgr *ConnectionManager) Stop() {
	if atomic.AddInt32(&cmgr.shutdown, 1) != 1 {
		glog.Warningf("ConnectionManager.Stop is already in the process of " +
			"shutting down")
		return
	}
	glog.Info("ConnectionManager.Stop: Gracefully shutting down ConnectionManager")

	// Close all of the listeners.
	for _, listener := range cmgr.listeners {
		_ = listener.Close()
	}
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

	// Initiate outbound connections with peers either using the --connectips passed
	// in or using the addrmgr.
	cmgr._initiateOutboundConnections()

	// Accept inbound connections from peers on our listeners.
	cmgr._handleInboundConnections()

	glog.Infof("Full node socket initialized")

	for {
		// Log some data for each event.
		cmgr._logOutboundPeerData()

		select {
		case pp := <-cmgr.newPeerChan:
			{
				// We have successfully connected to a peer and it passed its version
				// negotiation.

				// if this is a non-persistent outbound peer and we already have enough
				// outbound peers, then don't bother adding this one.
				if !pp.isPersistent && pp.isOutbound && cmgr.enoughOutboundPeers() {
					// TODO: Make this less verbose
					glog.V(1).Infof("Dropping peer because we already have enough outbound peer connections.")
					pp.conn.Close()
					continue
				}

				// If this is a non-persistent outbound peer and the group key
				// overlaps with another peer we're already connected to then
				// abort mission. We only connect to one peer per IP group in
				// order to prevent Sybil attacks.
				if pp.isOutbound &&
					!pp.isPersistent &&
					cmgr.isRedundantGroupKey(pp.netAddr) {

					// TODO: Make this less verbose
					glog.Infof("Rejecting OUTBOUND NON-PERSISTENT peer (%v) with "+
						"redundant group key (%s).",
						pp, addrmgr.GroupKey(pp.netAddr))

					pp.conn.Close()
					cmgr._maybeReplacePeer(pp)
					continue
				}

				// Check that we have not exceeded the maximum number of inbound
				// peers allowed.
				//
				// TODO: We should instead have eviction logic to prevent
				// someone from monopolizing a node's inbound connections.
				numInboundPeers := atomic.LoadUint32(&cmgr.numInboundPeers)
				if !pp.isOutbound && numInboundPeers > cmgr.maxInboundPeers {

					// TODO: Make this less verbose
					glog.Infof("Rejecting INBOUND peer (%v) due to max inbound peers (%d) hit.",
						pp, cmgr.maxInboundPeers)

					pp.conn.Close()
					continue
				}

				// Now we can add the peer to our data structures.
				pp._logAddPeer()
				cmgr.addPeer(pp)

				// Start the peer's message loop.
				pp.Start()

				// Signal the server about the new Peer in case it wants to do something with it.
				cmgr.serverMessageQueue <- &ServerMessage{
					Peer: pp,
					Msg:  &MsgDeSoNewPeer{},
				}

			}
		case pp := <-cmgr.donePeerChan:
			{
				// By the time we get here, it can be assumed that the Peer's Disconnect function
				// has already been called, since that is what's responsible for adding the peer
				// to this queue in the first place.

				glog.V(1).Infof("Done with peer (%v).", pp)

				if !pp.PeerManuallyRemovedFromConnectionManager {
					// Remove the peer from our data structures.
					cmgr.RemovePeer(pp)

					// Potentially replace the peer. For example, if the Peer was an outbound Peer
					// then we want to find a new peer in order to maintain our TargetOutboundPeers.
					cmgr._maybeReplacePeer(pp)
				}

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
