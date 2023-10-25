package lib

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/deso-protocol/go-deadlock"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

// peer.go defines an interface for connecting to and managing an DeSo
// peer. Each peer a node is connected to is represented by a Peer object,
// and the Peer object is how messages are sent and received to/from the
// peer. A good place to start is inHandler and outHandler in this file.

// ExpectedResponse is a struct used to enforce timeouts on peers. For example,
// if we send a GetBlocks message, we would expect a response within a given
// window and disconnect from the Peer if we don't get that response.
type ExpectedResponse struct {
	TimeExpected time.Time
	MessageType  MsgType
}

type outgoingMessage struct {
	message           DeSoMessage
	expectedResponses []*ExpectedResponse
}

// Peer is an object that holds all of the state for a connection to another node.
// Any communication with other nodes happens via this object, which maintains a
// queue of messages to send to the other node.
type Peer struct {
	// These stats should be accessed atomically.
	bytesReceived uint64
	bytesSent     uint64
	totalMessages uint64
	lastRecv      int64
	lastSend      int64

	// Stats that should be accessed using the mutex below.
	StatsMtx       deadlock.RWMutex
	TimeOffsetSecs int64
	TimeConnected  time.Time
	startingHeight uint32
	ID             uint64
	// Ping-related fields.
	LastPingNonce  uint64
	LastPingTime   time.Time
	LastPingMicros int64

	// Connection info.
	Conn         net.Conn
	isOutbound   bool
	isPersistent bool
	Params       *DeSoParams

	IncomingMessageChan chan DeSoMessage
	// Output queue for messages that need to be sent to the peer.
	outgoingMessageChan chan *outgoingMessage
	// Messages for which we are expecting a reply within a fixed
	// amount of time. This list is always sorted by ExpectedTime,
	// with the item having the earliest time at the front.
	// FIXME: This should be a treeset.Set
	expectedResponses []*ExpectedResponse
	msgMtx            sync.Mutex

	// A hack to make it so that we can allow an API endpoint to manually
	// delete a peer.
	PeerManuallyRemovedFromConnectionManager bool

	// In order to complete a version negotiation successfully, the peer must
	// reply to the initial version message we send them with a verack message
	// containing the nonce from that initial version message. This ensures that
	// the peer's IP isn't being spoofed since the only way to actually produce
	// a verack with the appropriate response is to actually own the IP that
	// the peer claims it has. As such, we maintain the version nonce we sent
	// the peer and the version nonce they sent us here.
	//
	// TODO: The way we synchronize the version nonce is currently a bit
	// messy; ideally we could do it without keeping global state.
	VersionNonceSent     uint64
	VersionNonceReceived uint64

	// Basic state.
	PeerInfoMtx  deadlock.Mutex
	serviceFlags ServiceFlag
	addrStr      string
	netAddr      *wire.NetAddress

	// The addresses this peer is aware of.
	knownAddressesMapLock deadlock.RWMutex
	knownAddressesMap     map[string]bool

	// Set to zero until Disconnect has been called on the Peer. Used to make it
	// so that the logic in Disconnect will only be executed once.
	disconnected int32
	// Signals that the peer is now in the stopped state.
	quit chan interface{}

	// We process GetTransaction requests in a separate loop. This allows us
	// to ensure that the responses are ordered.
	mtxMessageQueue deadlock.RWMutex
}

// NewPeer creates a new Peer object.
func NewPeer(_id uint64, _conn net.Conn, _isOutbound bool, _netAddr *wire.NetAddress,
	_isPersistent bool, params *DeSoParams) *Peer {

	pp := Peer{
		ID:                  _id,
		Conn:                _conn,
		addrStr:             _conn.RemoteAddr().String(),
		netAddr:             _netAddr,
		isOutbound:          _isOutbound,
		isPersistent:        _isPersistent,
		outgoingMessageChan: make(chan *outgoingMessage, 100),
		quit:                make(chan interface{}, 1),
		knownAddressesMap:   make(map[string]bool),
		Params:              params,
		IncomingMessageChan: make(chan DeSoMessage, 100),
	}

	// TODO: Before, we would give each Peer its own Logger object. Now we
	// have a much better way of debugging which is that we include a nonce
	// in all messages related to a Peer (i.e. PeerID=%d) that allows us to
	// pipe the output to a file and inspect it (and if we choose to filter on
	// a PeerID= then we can see exclusively that Peer's related messages).
	// Still, we're going to leave this logic here for a little while longer in
	// case a situation arises where commenting it in seems like it would be
	// useful.
	//
	// Each peer gets its own log directory. Name the directory with
	// IP:PORT_ID to ensure it's identifiable but also unique. The higher
	// the ID the more recently the peer connection was established.
	/*
		logDir := fmt.Sprintf("%s.%05d_%d.log", addrmgr.NetAddressKey(_netAddr), pp.ID, time.Now().UnixNano())
		resetLogDir := false
		pp.Logger = glog.NewLogger(logDir, resetLogDir)
		// Don't log peer information to stderr.
		pp.Logger.AlsoToStderr = false
	*/
	return &pp
}

func (pp *Peer) AddDeSoMessage(desoMessage DeSoMessage, expectedResponse []*ExpectedResponse) {
	// Don't add any more messages if the peer is disconnected
	if !pp.Connected() {
		return
	}

	pp.outgoingMessageChan <- &outgoingMessage{desoMessage, expectedResponse}
}

func (pp *Peer) GetIncomingMessageChan() chan DeSoMessage {
	return pp.IncomingMessageChan
}

const (
	// pingInterval is the interval of time to wait in between sending ping
	// messages.
	pingInterval = 2 * time.Minute

	// idleTimeout is the duration of inactivity before we time out a peer.
	idleTimeout = 5 * time.Minute
)

// HandlePingMsg is invoked when a peer receives a ping message. It replies with a pong
// message.
func (pp *Peer) HandlePingMsg(msg *MsgDeSoPing) {
	// Include nonce from ping so pong can be identified.
	glog.V(2).Infof("Peer.HandlePingMsg: Received ping from peer %v: %v", pp, msg)
	// Queue up a pong message.
	pp.AddDeSoMessage(&MsgDeSoPong{Nonce: msg.Nonce}, nil)
}

// HandlePongMsg is invoked when a peer receives a pong message.  It
// updates the ping statistics.
func (pp *Peer) HandlePongMsg(msg *MsgDeSoPong) {
	// Arguably we could use a buffered channel here sending data
	// in a fifo manner whenever we send a ping, or a list keeping track of
	// the times of each ping. For now we just make a best effort and
	// only record stats if it was for the last ping sent. Any preceding
	// and overlapping pings will be ignored. It is unlikely to occur
	// without large usage of the ping call since we ping infrequently
	// enough that if they overlap we would have timed out the peer.
	glog.V(2).Infof("Peer.HandlePongMsg: Received pong from peer %v: %v", msg, pp)
	pp.StatsMtx.Lock()
	defer pp.StatsMtx.Unlock()
	if pp.LastPingNonce != 0 && msg.Nonce == pp.LastPingNonce {
		pp.LastPingMicros = time.Since(pp.LastPingTime).Nanoseconds()
		pp.LastPingMicros /= 1000 // convert to usec.
		pp.LastPingNonce = 0
		glog.V(2).Infof("Peer.HandlePongMsg: LastPingMicros(%d) from Peer %v", pp.LastPingMicros, pp)
	}
}

func (pp *Peer) PingHandler() {
	glog.V(1).Infof("Peer.PingHandler: Starting ping handler for Peer %v", pp)
	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

out:
	for {
		select {
		case <-pingTicker.C:
			glog.V(2).Infof("Peer.PingHandler: Initiating ping for Peer %v", pp)
			nonce, err := wire.RandomUint64()
			if err != nil {
				glog.Errorf("Not sending ping to Peer %v: %v", pp, err)
				continue
			}
			// Update the ping stats when we initiate a ping.
			//
			// TODO: Setting LastPingTime here means that we're technically measuring the time
			// between *queueing* the ping and when we receive a pong vs the time between when
			// a ping is actually sent and when the pong is received. To fix it we'd have to
			// detect a ping message in the outHandler and set the stats there instead.
			pp.StatsMtx.Lock()
			pp.LastPingNonce = nonce
			pp.LastPingTime = time.Now()
			pp.StatsMtx.Unlock()
			// Queue the ping message to be sent.
			pp.AddDeSoMessage(&MsgDeSoPing{Nonce: nonce}, nil)

		case <-pp.quit:
			break out
		}
	}
}

func (pp *Peer) String() string {
	isDisconnected := ""
	if pp.disconnected != 0 {
		isDisconnected = ", DISCONNECTED"
	}
	return fmt.Sprintf("[ Remote Address: %v%s PeerID=%d ]", pp.addrStr, isDisconnected, pp.ID)
}

func (pp *Peer) Connected() bool {
	return atomic.LoadInt32(&pp.disconnected) == 0
}

func (pp *Peer) Address() string {
	return pp.addrStr
}

func (pp *Peer) IP() string {
	return pp.netAddr.IP.String()
}

func (pp *Peer) NetAddr() *wire.NetAddress {
	return pp.netAddr
}

func (pp *Peer) Port() uint16 {
	return pp.netAddr.Port
}

func (pp *Peer) IsOutbound() bool {
	return pp.isOutbound
}

func (pp *Peer) _filterAddrMsg(addrMsg *MsgDeSoAddr) *MsgDeSoAddr {
	pp.knownAddressesMapLock.Lock()
	defer pp.knownAddressesMapLock.Unlock()

	filteredAddrMsg := &MsgDeSoAddr{}
	for _, addr := range addrMsg.AddrList {
		if _, hasAddr := pp.knownAddressesMap[addr.StringWithPort(false /*includePort*/)]; hasAddr {
			continue
		}

		// If we get here this is an address the peer hasn't seen before so
		// don't filter it out. Also add it to the known address map.
		filteredAddrMsg.AddrList = append(filteredAddrMsg.AddrList, addr)
		pp.knownAddressesMap[addr.StringWithPort(false /*includePort*/)] = true
	}

	return filteredAddrMsg
}

func (pp *Peer) _setKnownAddressesMap(key string, val bool) {
	pp.knownAddressesMapLock.Lock()
	defer pp.knownAddressesMapLock.Unlock()

	pp.knownAddressesMap[key] = val
}

func (pp *Peer) outHandler() {
	glog.V(1).Infof("Peer.outHandler: Starting outHandler for Peer %v", pp)
	stallTicker := time.NewTicker(time.Second)
out:
	for {
		select {
		case oMsg := <-pp.outgoingMessageChan:
			pp.addExpectedResponses(oMsg.expectedResponses)
			// TODO: ============================
			//		Move this to Server maybe?
			// Before we send an addr message to the peer, filter out the addresses
			// the peer is already aware of.
			msg := oMsg.message
			if msg.GetMsgType() == MsgTypeAddr {
				msg = pp._filterAddrMsg(msg.(*MsgDeSoAddr))

				// Don't send anything if we managed to filter out all the addresses.
				if len(msg.(*MsgDeSoAddr).AddrList) == 0 {
					continue
				}
			}

			// If we have a problem sending a message to a peer then disconnect them.
			glog.V(3).Infof("Writing Message: (%v)", msg)
			if err := pp.WriteDeSoMessage(msg); err != nil {
				glog.Errorf("Peer.outHandler: Problem sending message to peer: %v: %v", pp, err)
				pp.Disconnect()
			}
		case <-stallTicker.C:
			// Every second take a look to see if there's something that the peer should
			// have responded to that they're delinquent on. If there is then error and
			// disconnect the Peer.
			if len(pp.expectedResponses) == 0 {
				// If there are no expected responses, nothing to do.
				continue
			}
			// The expected responses are sorted by when the corresponding requests were
			// made. As such, if the first entry is not past the deadline then nothing is.
			firstEntry := pp.expectedResponses[0]
			nowTime := time.Now()
			if nowTime.After(firstEntry.TimeExpected) {
				glog.Errorf("Peer.outHandler: Peer %v took too long to response to "+
					"reqest. Expected MsgType=%v at time %v but it is now time %v",
					pp, firstEntry.MessageType, firstEntry.TimeExpected, nowTime)
				pp.Disconnect()
			}

		case <-pp.quit:
			break out
		}
	}

	glog.V(1).Infof("Peer.outHandler: Quitting outHandler for Peer %v", pp)
}

func (pp *Peer) _removeEarliestExpectedResponse(msgType MsgType) {
	pp.msgMtx.Lock()
	defer pp.msgMtx.Unlock()

	// Just remove the first instance we find of the passed-in message
	// type and return.
	for ii, res := range pp.expectedResponses {
		if res.MessageType == msgType {
			// We found the first occurrence of the message type so remove
			// that message since we're no longer waiting on it.
			left := append([]*ExpectedResponse{}, pp.expectedResponses[:ii]...)
			pp.expectedResponses = append(left, pp.expectedResponses[ii+1:]...)
			return
		}
	}
}

func (pp *Peer) addExpectedResponses(responses []*ExpectedResponse) {
	for _, res := range responses {
		pp._addExpectedResponse(res)
	}
}

func (pp *Peer) _addExpectedResponse(item *ExpectedResponse) {
	pp.msgMtx.Lock()
	defer pp.msgMtx.Unlock()

	if len(pp.expectedResponses) == 0 {
		pp.expectedResponses = []*ExpectedResponse{item}
		return
	}

	// Usually the item will need to be added at the end so start
	// from there.
	index := len(pp.expectedResponses)
	for index > 0 &&
		pp.expectedResponses[index-1].TimeExpected.After(item.TimeExpected) {

		index--
	}

	left := append([]*ExpectedResponse{}, pp.expectedResponses[:index]...)
	right := pp.expectedResponses[index:]
	pp.expectedResponses = append(append(left, item), right...)
}

// inHandler handles all incoming messages for the peer. It must be run as a
// goroutine.
func (pp *Peer) inHandler() {
	glog.V(1).Infof("Peer.inHandler: Starting inHandler for Peer %v", pp)

	// The timer is stopped when a new message is received and reset after it
	// is processed.
	idleTimer := time.AfterFunc(idleTimeout, func() {
		glog.V(1).Infof("Peer.inHandler: Peer %v no answer for %v -- disconnecting", pp, idleTimeout)
		pp.Disconnect()
	})

	for {
		// Read a message and stop the idle timer as soon as the read
		// is done. The timer is reset below for the next iteration if
		// needed.
		rmsg, err := pp.ReadDeSoMessage()
		idleTimer.Stop()
		if err != nil {
			glog.Errorf("Peer.inHandler: Can't read message from peer %v: %v", pp, err)

			break
		}
		if !pp.Connected() {
			break
		}

		// Adjust what we expect our Peer to send us based on what we're now
		// receiving with this message.
		pp._removeEarliestExpectedResponse(rmsg.GetMsgType())

		// TODO: ============================
		//		Maybe move this to server as one of its components.. eeh maybe not.
		// If we get an addr message, add all of the addresses to the known addresses
		// for the peer.
		if rmsg.GetMsgType() == MsgTypeAddr {
			addrMsg := rmsg.(*MsgDeSoAddr)
			for _, addr := range addrMsg.AddrList {
				pp._setKnownAddressesMap(addr.StringWithPort(false /*includePort*/), true)
			}
		}

		// If we receive a control message from a Peer then that Peer is misbehaving
		// and we should disconnect. Control messages should never originate from Peers.
		if IsControlMessage(rmsg.GetMsgType()) {
			glog.Errorf("Peer.inHandler: Received control message of type %v from "+
				"Peer %v; this should never happen. Disconnecting the Peer", rmsg.GetMsgType(), pp)
			break
		}

		// This switch actually processes the message. For most messages, we just
		// pass them onto the Server.
		switch msg := rmsg.(type) {
		case *MsgDeSoPing:
			// Respond to a ping with a pong.
			pp.HandlePingMsg(msg)

		case *MsgDeSoPong:
			// Measure the ping time when we receive a pong.
			pp.HandlePongMsg(msg)

		default:
			// All other messages just forward back to the Connection Manager to handle them.
			//glog.V(2).Infof("Peer.inHandler: Received message of type %v from %v", rmsg.GetMsgType(), pp)
			pp.IncomingMessageChan <- msg
		}

		// A message was received so reset the idle timer.
		idleTimer.Reset(idleTimeout)
	}

	// Ensure the idle timer is stopped to avoid leaking the resource.
	idleTimer.Stop()

	// Disconnect the Peer if it isn't already.
	pp.Disconnect()

	glog.V(1).Infof("Peer.inHandler: done for peer: %v", pp)
}

func (pp *Peer) Start() {
	glog.Infof("Peer.Start: Starting peer %v", pp)
	// The protocol has been negotiated successfully so start processing input
	// and output messages.
	go pp.PingHandler()
	go pp.outHandler()
	go pp.inHandler()
}

func (pp *Peer) WriteDeSoMessage(msg DeSoMessage) error {
	payload, err := WriteMessage(pp.Conn, msg, pp.Params.NetworkType)
	if err != nil {
		return errors.Wrapf(err, "WriteDeSoMessage: ")
	}

	// Only track the payload sent in the statistics we track.
	atomic.AddUint64(&pp.bytesSent, uint64(len(payload)))
	atomic.StoreInt64(&pp.lastSend, time.Now().Unix())

	// Useful for debugging.
	// TODO: This may be too verbose
	messageSeq := atomic.AddUint64(&pp.totalMessages, 1)
	glog.V(3).Infof("SENDING( seq=%d ) message of type: %v to peer %v: %v",
		messageSeq, msg.GetMsgType(), pp, msg)

	return nil
}

func (pp *Peer) ReadDeSoMessage() (DeSoMessage, error) {
	msg, payload, err := ReadMessage(pp.Conn, pp.Params.NetworkType)
	if err != nil {
		err := errors.Wrapf(err, "ReadDeSoMessage: ")
		glog.Error(err)
		return nil, err
	}

	// Only track the payload received in the statistics we track.
	msgLen := uint64(len(payload))
	atomic.AddUint64(&pp.bytesReceived, msgLen)
	atomic.StoreInt64(&pp.lastRecv, time.Now().Unix())

	// Useful for debugging.
	messageSeq := atomic.AddUint64(&pp.totalMessages, 1)
	glog.V(3).Infof("RECEIVED( seq=%d ) message of type: %v from peer %v: %v",
		messageSeq, msg.GetMsgType(), pp, msg)

	return msg, nil
}

// Disconnect closes a peer's network connection.
func (pp *Peer) Disconnect() {
	if !pp.Connected() {
		return
	}
	atomic.StoreInt32(&pp.disconnected, 1)
	// Close the connection object.
	pp.Conn.Close()

	// Signaling the quit channel allows all the other goroutines to stop running.
	close(pp.quit)

	pp.IncomingMessageChan <- &MsgDeSoDonePeer{}
}

func (pp *Peer) _logAddPeer() {
	inboundStr := "INBOUND"
	if pp.isOutbound {
		inboundStr = "OUTBOUND"
	}
	persistentStr := "PERSISTENT"
	if !pp.isPersistent {
		persistentStr = "NON-PERSISTENT"
	}
	logStr := fmt.Sprintf("ADDING (%s) (%s) peer (%v)", inboundStr, persistentStr, pp)
	glog.V(1).Info(logStr)
}
