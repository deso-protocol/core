package lib

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/DataDog/datadog-go/statsd"

	"github.com/btcsuite/btcd/addrmgr"
	chainlib "github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/deso-protocol/go-deadlock"
	"github.com/golang/glog"
)

type ServerStatus int

const (
	ServerStatusNotStarted ServerStatus = iota
	ServerStatusStarted
	ServerStatusStopped
)

// TODO: change originId to some validator identifier
type MessageHandler func(msg DeSoMessage, origin *Peer) MessageHandlerResponseCode
type MessageHandlerResponseCode int

const (
	MessageHandlerResponseCodeOK MessageHandlerResponseCode = iota
	MessageHandlerResponseCodeSkip
	MessageHandlerResponseCodePeerUnavailable
	MessageHandlerResponseCodePeerDisconnect
)

func NewMessageHandler(fun func(msg DeSoMessage, origin *Peer) MessageHandlerResponseCode) MessageHandler {
	return fun
}

// ServerMessage is the core data structure processed by the Server in its main
// loop.
type ServerMessage struct {
	Peer      *Peer
	Msg       DeSoMessage
	ReplyChan chan *ServerReply
}

func (sm *ServerMessage) GetPeer() *Peer {
	return sm.Peer
}

func (sm *ServerMessage) GetMessage() DeSoMessage {
	return sm.Msg
}

// GetDataRequestInfo is a data structure used to keep track of which transactions
// we've requested from a Peer.
type GetDataRequestInfo struct {
	PeerWhoSentInv *Peer
	TimeRequested  time.Time
}

// ServerReply is used to signal to outside programs that a particular ServerMessage
// they may have been waiting on has been processed.
type ServerReply struct {
}

// Server is the core of the DeSo node. It effectively runs a single-threaded
// main loop that processes transactions from other peers and responds to them
// accordingly. Probably the best place to start looking is the messageHandler
// function.
type Server struct {
	status ServerStatus

	cmgr         *ConnectionManager
	eventManager *EventManager

	// All messages received from peers get sent from the ConnectionManager to the
	// Server through this channel.
	//
	// Generally, the
	// ConnectionManager is responsible for managing the connections to all the peers,
	// but when it receives a message from one of them, it forwards it to the Server
	// on this channel to actually process (acting as a router in that way).
	//
	// In addition to messages from peers, the ConnectionManager will also send control
	// messages to notify the Server e.g. when a Peer connects or disconnects so that
	// the Server can take action appropriately.
	incomingMessages chan *ServerMessage

	incomingMessagesHandlers map[MsgType][]MessageHandler

	// hasRequestedSync indicates whether we've bootstrapped our mempool
	// by requesting all mempool transactions from a
	// peer. It's initially false
	// when the server boots up but gets set to true after we make a Mempool
	// request once we're fully synced.
	// The waitGroup is used to manage the cleanup of the Server.
	waitGroup deadlock.WaitGroup

	// How long we wait on a transaction we're fetching before giving
	// up on it. Note this doesn't apply to blocks because they have their own
	// process for retrying that differs from transactions, which are
	// more best-effort than blocks.
	requestTimeoutSeconds uint32

	// addrsToBroadcast is a list of all the addresses we've received from valid addr
	// messages that we intend to broadcast to our peers. It is organized as:
	// <recipient address> -> <list of addresses we received from that recipient>.
	//
	// It is organized in this way so that we can limit the number of addresses we
	// are distributing for a single peer to avoid a DOS attack.
	addrsToBroadcastLock deadlock.RWMutex
	addrsToBroadcastt    map[string][]*SingleAddr

	// When set to true, we disable the ConnectionManager
	DisableNetworking bool

	// When set to true, transactions created on this node will be ignored.
	ReadOnlyMode bool

	// dataLock protects requestedTxns and requestedBlocks
	dataLock deadlock.Mutex

	statsdClient *statsd.Client

	Notifier *Notifier

	// nodeMessageChannel is used to restart the node that's currently running this server.
	// It is basically a backlink to the node that calls Stop() and Start().
	nodeMessageChannel chan NodeMessage

	shutdown int32
	// timer is a helper variable that allows timing events for development purposes.
	// It can be used to find computational bottlenecks.
	timer *Timer
}

// NewServer initializes all of the internal data structures. Right now this basically
// looks as follows:
//   - ConnectionManager starts and keeps track of peers.
//   - When messages are received from peers, they get forwarded on a channel to
//     the Server to handle them. In that sense the ConnectionManager is basically
//     just acting as a router.
//   - When the Server receives a message from a peer, it can do any of the following:
//   - Take no action.
//   - Use the Blockchain data structure to validate the transaction or update the
//     Blockchain data structure.
//   - Send a new message. This can be a message directed back to that actually sent this
//     message or it can be a message to another peer for whatever reason. When a message
//     is sent in this way it can also have a deadline on it that the peer needs to
//     respond by or else it will be disconnected.
//   - Disconnect the peer. In this case the ConnectionManager gets notified about the
//     disconnection and may opt to replace the now-disconnected peer with a new peer.
//     This happens for example when an outbound peer is disconnected in order to
//     maintain TargetOutboundPeers.
//   - The server could also receive a control message that a peer has been disconnected.
//     This can be useful to the server if, for example, it was expecting a response from
//     a particular peer, which could be the case in initial block download where a single
//     sync peer is used.
//
// TODO: Refactor all these arguments into a config object or something.
func NewServer(
	_params *DeSoParams,
	_listeners []net.Listener,
	_desoAddrMgr *addrmgr.AddrManager,
	_connectIps []string,
	_targetOutboundPeers uint32,
	_maxInboundPeers uint32,
	_limitOneInboundConnectionPerIP bool,
	_stallTimeoutSeconds uint64,
	_disableNetworking bool,
	_readOnlyMode bool,
	statsd *statsd.Client,
	eventManager *EventManager,
	_nodeMessageChan chan NodeMessage) (
	_srv *Server, _err error) {

	// Create an empty Server object here so we can pass a reference to it to the ConnectionManager.
	srv := &Server{
		status:                   ServerStatusNotStarted,
		DisableNetworking:        _disableNetworking,
		ReadOnlyMode:             _readOnlyMode,
		nodeMessageChannel:       _nodeMessageChan,
		incomingMessagesHandlers: make(map[MsgType][]MessageHandler),
	}

	srv.RegisterIncomingMessagesHandler(MsgTypeAddr, NewMessageHandler(srv._handleAddrMessage))
	srv.RegisterIncomingMessagesHandler(MsgTypeGetAddr, NewMessageHandler(srv._handleGetAddrMessage))

	// The same timesource is used in the chain data structure and in the connection
	// manager. It just takes and keeps track of the median time among our peers so
	// we can keep a consistent clock.
	timesource := chainlib.NewMedianTime()

	// Create a new connection manager but note that it won't be initialized until Start().
	_incomingMessages := make(chan *ServerMessage, (_targetOutboundPeers+_maxInboundPeers)*3)
	_cmgr := NewConnectionManager(
		_params, _desoAddrMgr, _listeners, _connectIps, timesource,
		_targetOutboundPeers, _maxInboundPeers, _limitOneInboundConnectionPerIP,
		_stallTimeoutSeconds, _incomingMessages, srv)

	// Set up the blockchain data structure. This is responsible for accepting new
	// blocks, keeping track of the best chain, and keeping all of that state up
	// to date on disk.
	//
	// If this is the first time this data structure is being initialized, it will
	// contain only the genesis block. Otherwise it loads all of the block headers
	// (actually BlockNode's) from the db into memory, which is a somewhat heavy-weight
	// operation.
	//
	// TODO: Would be nice if this heavier-weight operation were moved to Start() to
	// keep this constructor fast.
	srv.eventManager = eventManager

	// Set all the fields on the Server object.
	srv.cmgr = _cmgr
	srv.incomingMessages = _incomingMessages

	srv.statsdClient = statsd

	// TODO: Make this configurable
	//srv.Notifier = NewNotifier(_chain, postgres)
	//srv.Notifier.Start()

	// Initialize the addrs to broadcast map.
	srv.addrsToBroadcastt = make(map[string][]*SingleAddr)

	// Initialize the timer struct.
	timer := &Timer{}
	timer.Initialize()
	srv.timer = timer

	return srv, nil
}

// Start actually kicks off all of the management processes. Among other things, it causes
// the ConnectionManager to actually start connecting to peers and receiving messages. If
// requested, it also starts the miner.
func (srv *Server) Start() {
	// Start the Server so that it will be ready to process messages once the ConnectionManager
	// finds some Peers.
	glog.Info("Server.Start: Starting Server")
	srv.waitGroup.Add(1)

	// Once the ConnectionManager is started, peers will be found and connected to and
	// messages will begin to flow in to be processed.
	if srv.DisableNetworking {
		return
	}

	go srv.cmgr.Start()
	go srv._startMessageProcessor()
	go srv._startAddressRelayer()
}

func (srv *Server) _startMessageProcessor() {
	for {
		msg, open := <-srv.incomingMessages
		if !open {
			glog.Info("Server.Start: Incoming messages channel closed. Exiting.")
			break
		}

		msgType := msg.GetMessage().GetMsgType()
		// TODO: Maybe pass through to controllers?
		if msgType == MsgTypeQuit {
			break
		}
		handlers := srv.incomingMessagesHandlers[msgType]

		for _, handler := range handlers {
			code := handler(msg.GetMessage(), msg.GetPeer())
			switch code {
			case MessageHandlerResponseCodePeerDisconnect:
				// TODO: Make a sub-view of Peer (Validator) that exposes ID.
				srv.DisconnectPeer(msg.GetPeer().ID)
			}
		}
	}
	srv.waitGroup.Done()
}

// Must be run inside a goroutine. Relays addresses to peers at regular intervals
// and relays our own address to peers once every 24 hours.
func (srv *Server) _startAddressRelayer() {
	for numMinutesPassed := 0; ; numMinutesPassed++ {
		if atomic.LoadInt32(&srv.shutdown) > 0 {
			break
		}
		// For the first ten minutes after the server starts, relay our address to all
		// peers. After the first ten minutes, do it once every 24 hours.
		glog.V(1).Infof("Server.Start._startAddressRelayer: Relaying our own addr to peers")
		if numMinutesPassed < 10 || numMinutesPassed%(RebroadcastNodeAddrIntervalMinutes) == 0 {
			for _, pp := range srv.cmgr.GetAllPeers() {
				bestAddress := srv.cmgr.GetAddrManager().GetBestLocalAddress(pp.NetAddr())
				if bestAddress != nil {
					glog.V(2).Infof("Server.Start._startAddressRelayer: Relaying address %v to "+
						"peer %v", bestAddress.IP.String(), pp)
					// Send the message and do nothing if the peer is unavailable.
					_ = srv.cmgr.SendMessage(&MsgDeSoAddr{
						AddrList: []*SingleAddr{
							{
								Timestamp: time.Now(),
								IP:        bestAddress.IP,
								Port:      bestAddress.Port,
								Services:  (ServiceFlag)(bestAddress.Services),
							},
						},
					}, pp.ID, nil)
				}
			}
		}

		glog.V(2).Infof("Server.Start._startAddressRelayer: Seeing if there are addrs to relay...")
		// Broadcast the addrs we have to all of our peers.
		addrsToBroadcast := srv._getAddrsToBroadcast()
		if len(addrsToBroadcast) == 0 {
			glog.V(2).Infof("Server.Start._startAddressRelayer: No addrs to relay.")
			time.Sleep(AddrRelayIntervalSeconds * time.Second)
			continue
		}

		glog.V(2).Infof("Server.Start._startAddressRelayer: Found %d addrs to "+
			"relay: %v", len(addrsToBroadcast), spew.Sdump(addrsToBroadcast))
		// Iterate over all our peers and broadcast the addrs to all of them.
		for _, pp := range srv.cmgr.GetAllPeers() {
			// Send the message and do nothing if the peer is unavailable.
			_ = srv.cmgr.SendMessage(&MsgDeSoAddr{
				AddrList: addrsToBroadcast,
			}, pp.ID, nil)
		}
		time.Sleep(AddrRelayIntervalSeconds * time.Second)
		continue
	}
}

func (srv *Server) Stop() {
	glog.Info("Server.Stop: Gracefully shutting down Server")

	// Iterate through all the peers and flush their logs before we quit.
	glog.Info("Server.Stop: Flushing logs for all peers")
	atomic.AddInt32(&srv.shutdown, 1)

	// Stop the ConnectionManager
	srv.cmgr.Stop()
	glog.Infof(CLog(Yellow, "Server.Stop: Closed the ConnectionManger"))

	// This will signal any goroutines to quit. Note that enqueing this after stopping
	// the ConnectionManager seems like it should cause the Server to process any remaining
	// messages before calling waitGroup.Done(), which seems like a good thing.
	go func() {
		srv.incomingMessages <- &ServerMessage{
			// Peer is ignored for MsgDeSoQuit.
			Peer: nil,
			Msg:  &MsgDeSoQuit{},
		}
	}()

	// Wait for the server to fully shut down.
	srv.waitGroup.Wait()
	glog.Info("Server.Stop: Successfully shut down Server")
}

func (srv *Server) RegisterIncomingMessagesHandler(msgType MsgType, handler MessageHandler) {
	if srv.status != ServerStatusNotStarted {
		glog.Fatal("Server.RegisterIncomingMessagesHandler: Cannot add message handler after server has started")
	}
	srv.incomingMessagesHandlers[msgType] = append(srv.incomingMessagesHandlers[msgType], handler)
}

func (srv *Server) SendMessage(msg DeSoMessage, peerId uint64, expectedResponse *ExpectedResponse) error {
	return srv.cmgr.SendMessage(msg, peerId, expectedResponse)
}

func (srv *Server) DisconnectPeer(peerId uint64) {
	srv.cmgr.DisconnectPeer(peerId)
}

func (srv *Server) _handleAddrMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeAddr {
		return MessageHandlerResponseCodeSkip
	}

	var msg *MsgDeSoAddr
	var ok bool
	if msg, ok = desoMsg.(*MsgDeSoAddr); !ok {
		return MessageHandlerResponseCodeSkip
	}

	srv.addrsToBroadcastLock.Lock()
	defer srv.addrsToBroadcastLock.Unlock()

	glog.V(1).Infof("Server._handleAddrMessage: Received Addr from peer %v with addrs %v", origin, spew.Sdump(msg.AddrList))

	// If this addr message contains more than the maximum allowed number of addresses
	// then disconnect this peer.
	if len(msg.AddrList) > MaxAddrsPerAddrMsg {
		glog.Errorf(fmt.Sprintf("Server._handleAddrMessage: Disconnecting "+
			"Peer %v for sending us an addr message with %d transactions, which exceeds "+
			"the max allowed %d",
			origin, len(msg.AddrList), MaxAddrsPerAddrMsg))
		return MessageHandlerResponseCodePeerDisconnect
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
	srv.cmgr.AddAddresses(netAddrsReceived, origin.NetAddr())

	// If the message had <= 10 addrs in it, then queue all the addresses for relaying
	// on the next cycle.
	if len(msg.AddrList) <= 10 {
		glog.V(1).Infof("Server._handleAddrMessage: Queueing %d addrs for forwarding from "+
			"peer %v", len(msg.AddrList), origin)
		sourceAddr := &SingleAddr{
			Timestamp: time.Now(),
			IP:        origin.NetAddr().IP,
			Port:      origin.Port(),
			Services:  origin.serviceFlags,
		}
		listToAddTo, hasSeenSource := srv.addrsToBroadcastt[sourceAddr.StringWithPort(false /*includePort*/)]
		if !hasSeenSource {
			listToAddTo = []*SingleAddr{}
		}
		// If this peer has been sending us a lot of little crap, evict a lot of their
		// stuff but don't disconnect.
		if len(listToAddTo) > MaxAddrsPerAddrMsg {
			listToAddTo = listToAddTo[:MaxAddrsPerAddrMsg/2]
		}
		listToAddTo = append(listToAddTo, msg.AddrList...)
		srv.addrsToBroadcastt[sourceAddr.StringWithPort(false /*includePort*/)] = listToAddTo
	}

	return MessageHandlerResponseCodeOK
}

func (srv *Server) _handleGetAddrMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeGetAddr {
		return MessageHandlerResponseCodeSkip
	}

	if _, ok := desoMsg.(*MsgDeSoGetAddr); !ok {
		return MessageHandlerResponseCodeSkip
	}

	glog.V(1).Infof("Server._handleGetAddrMessage: Received GetAddr from peer %v", origin)
	// When we get a GetAddr message, choose MaxAddrsPerMsg from the AddrMgr
	// and send them back to the peer.
	netAddrsFound := srv.cmgr.AddrMgr.AddressCache()
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
	if err := srv.SendMessage(res, origin.ID, nil); err != nil {
		glog.Errorf("Server._handleGetAddrMessage: Problem sending "+
			"addr message to peer %v: %v", origin, err)
		return MessageHandlerResponseCodePeerUnavailable
	}

	return MessageHandlerResponseCodeOK
}

func (srv *Server) _getAddrsToBroadcast() []*SingleAddr {
	srv.addrsToBroadcastLock.Lock()
	defer srv.addrsToBroadcastLock.Unlock()

	// If there's nothing in the map, return.
	if len(srv.addrsToBroadcastt) == 0 {
		return []*SingleAddr{}
	}

	// If we get here then we have some addresses to broadcast.
	addrsToBroadcast := []*SingleAddr{}
	for len(addrsToBroadcast) < 10 && len(srv.addrsToBroadcastt) > 0 {
		// Choose a key at random. This works because map iteration is random in golang.
		bucket := ""
		for kk := range srv.addrsToBroadcastt {
			bucket = kk
			break
		}

		// Remove the last element from the slice for the given bucket.
		currentAddrList := srv.addrsToBroadcastt[bucket]
		if len(currentAddrList) > 0 {
			lastIndex := len(currentAddrList) - 1
			currentAddr := currentAddrList[lastIndex]
			currentAddrList = currentAddrList[:lastIndex]
			if len(currentAddrList) == 0 {
				delete(srv.addrsToBroadcastt, bucket)
			} else {
				srv.addrsToBroadcastt[bucket] = currentAddrList
			}

			addrsToBroadcast = append(addrsToBroadcast, currentAddr)
		}
	}

	return addrsToBroadcast
}

func (srv *Server) GetStatsdClient() *statsd.Client {
	return srv.statsdClient
}

func (srv *Server) AddTimeSample(addrStr string, timeSample time.Time) {
	srv.cmgr.AddTimeSample(addrStr, timeSample)
}

func (srv *Server) SignalPeerReady(peerId uint64) {
	// TODO: This is called when peer passes handshake.
}
