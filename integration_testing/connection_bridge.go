package integration_testing

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/btcsuite/btcd/addrmgr"
	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
)

// TODO: DEPRECATE
// ConnectionBridge is a bidirectional communication channel between two nodes. A bridge creates a pair of inbound and
// outbound peers for each of the nodes to handle communication. In total, it creates four peers.
//
// An inbound Peer represents incoming communication to a node, and an outbound Peer represents outgoing communication.
// To disambiguate, a "Peer" in this context is basically a wrapper around inter-node communication that allows
// receiving and sending messages between the two nodes.
//
// As mentioned, our bridge creates an inbound and outbound Peers for both nodes A and B. Now, you might be perplexed
// as to why we would need both of these peers, as opposed to just one. The reason is that inbound and outbound peers
// differ in a crucial aspect, which is, who creates them. Inbound Peers are created whenever any node on the network
// initiates a communication with our node - meaning a node has no control over the communication partner. On the other
// hand, outbound peers are created by the node itself, so they can be considered more trusted than inbound peers.
// As a result, certain communication is only sent to outbound peers. For instance, we never ask an inbound Peer
// for headers or blocks, but we can ask an outbound Peer. At the same time, a node will respond with headers/blocks
// if asked by an inbound Peer.
//
// Let's say we have two nodes, nodeA and nodeB, that we want to bridge together. The connection bridge will then
// simulate the creation of two outbound and two inbound node connections:
//
//	nodeA : connectionOutboundA -> connectionInboundB : nodeB
//	nodeB : connectionOutboundB -> connectionInboundA : nodeA
//
// For example, let's say nodeA wants to send a GET_HEADERS message to nodeB, the traffic will look like this:
//
//		GET_HEADERS: nodeA -> connectionOutboundA -> connectionInboundB -> nodeB
//	 HEADER_BUNDLE: nodeB -> connectionInboundB -> connectionOutboundA -> nodeA
//
// This middleware design of the ConnectionBridge allows us to have much higher control over the communication
// between the two nodes. In particular, we have full control over the `connectionOutboundA -> connectionInboundB`
// steps, which allows us to make sure nodes act predictably and deterministically in our tests. Moreover, we can
// simulate real-world network links by doing things like faking delays, dropping messages, partitioning networks, etc.
type ConnectionBridge struct {
	// nodeA is one end of the bridge.
	nodeA *cmd.Node
	// connectionInboundA is a peer representing an incoming connection from nodeB.
	// Any traffic sent to connectionInboundA by nodeA will be routed to connectionOutboundB.
	connectionInboundA *lib.Peer
	// connectionOutboundA is a peer representing an outgoing connection to nodeB.
	// Any traffic sent to connectionOutboundA by nodeA will be routed to connectionInboundB.
	connectionOutboundA *lib.Peer
	// outboundListenerA is a listener that waits for outgoing connections from nodeA.
	outboundListenerA net.Listener

	// nodeB is the other end of the bridge.
	nodeB *cmd.Node
	// connectionInboundB is a peer representing an incoming connection from nodeA.
	// Any traffic sent to connectionInboundB by nodeB will be routed to connectionOutboundA.
	connectionInboundB *lib.Peer
	// connectionOutboundB is a peer representing an outgoing connection to nodeA.
	// Any traffic sent to connectionOutboundB by nodeB will be routed to connectionInboundA.
	connectionOutboundB *lib.Peer
	// outboundListenerB is a listener that waits for outgoing connections from nodeB.
	outboundListenerB net.Listener

	paused   bool
	disabled bool

	waitGroup   sync.WaitGroup
	newPeerChan chan *lib.Peer

	connectionAttempt int
}

// NewConnectionBridge creates an instance of ConnectionBridge that's ready to be connected.
// This function is usually followed by ConnectionBridge.Start()
func NewConnectionBridge(nodeA *cmd.Node, nodeB *cmd.Node) *ConnectionBridge {

	bridge := &ConnectionBridge{
		nodeA:             nodeA,
		nodeB:             nodeB,
		disabled:          false,
		newPeerChan:       make(chan *lib.Peer),
		connectionAttempt: 0,
	}
	return bridge
}

// createInboundConnection will initialize the inbound connection (inbound peer) to the provided node.
// It doesn't initiate a version/verack exchange yet, just creates the connection object.
func (bridge *ConnectionBridge) createInboundConnection(node *cmd.Node) *lib.Peer {
	// Get the localhost network address of to the provided node.
	port := node.Config.ProtocolPort
	addr := "127.0.0.1:" + strconv.Itoa(int(port))
	netAddress, err := lib.IPToNetAddr(addr, addrmgr.New("", net.LookupIP), &lib.DeSoMainnetParams)
	if err != nil {
		panic(err)
	}

	ip, _, err := net.ParseCIDR(netAddress.IP.String())
	if err != nil {
		panic(err)
	}

	netAddress2 := net.TCPAddr{
		IP:   ip,
		Port: int(netAddress.Port),
	}
	// Dial/connect to the node.
	conn, err := net.DialTimeout(netAddress2.Network(), netAddress2.String(), 4*lib.DeSoMainnetParams.DialTimeout)
	if err != nil {
		panic(err)
	}

	// This channel is redundant in our setting.
	messagesFromPeer := make(chan *lib.ServerMessage, 100)
	donePeerChan := make(chan *lib.Peer, 100)
	// Because it is an inbound Peer of the node, it is simultaneously a "fake" outbound Peer of the bridge.
	// Hence, we will mark the _isOutbound parameter as "true" in NewPeer.
	peer := lib.NewPeer(uint64(lib.RandInt64(math.MaxInt64)), conn, true,
		netAddress, true, 10000, 0, &lib.DeSoMainnetParams,
		messagesFromPeer, nil, nil, lib.NodeSyncTypeAny, donePeerChan)
	return peer
}

// createOutboundConnection will initialize an outbound connection from the provided node.
// To do this, we setup an auxiliary listener and make the provided node connect to that listener.
// We will then wrap this connection in a Peer object and return it in the newPeerChan channel.
// The peer is returned through the channel due to the concurrency. This function doesn't initiate
// the version exchange, this should be handled through ConnectionBridge.startConnection()
func (bridge *ConnectionBridge) createOutboundConnection(node *cmd.Node, otherNode *cmd.Node, ll net.Listener) {

	// Setup a listener to intercept the traffic from the node.
	go func(ll net.Listener) {
		//for {
		conn, err := ll.Accept()
		if err != nil {
			glog.Infof(lib.CLog(lib.Red, fmt.Sprintf("Problem in createOutboundConnection: Error: (%v)", err)))
			return
		}
		fmt.Println("createOutboundConnection: Got a connection from remote:", conn.RemoteAddr().String(),
			"on listener:", ll.Addr().String())

		addrMgr := addrmgr.New("", net.LookupIP)
		na, err := lib.IPToNetAddr(conn.RemoteAddr().String(), addrMgr, otherNode.Params)
		messagesFromPeer := make(chan *lib.ServerMessage, 100)
		donePeerChan := make(chan *lib.Peer, 100)
		peer := lib.NewPeer(uint64(lib.RandInt64(math.MaxInt64)), conn,
			false, na, false, 10000, 0, bridge.nodeB.Params,
			messagesFromPeer, nil, nil, lib.NodeSyncTypeAny, donePeerChan)
		bridge.newPeerChan <- peer
		//}
	}(ll)

	// Make the provided node to make an outbound connection to our listener.
	addrMgr := addrmgr.New("", net.LookupIP)
	addr, _ := lib.IPToNetAddr(ll.Addr().String(), addrMgr, node.Params)
	go node.Server.GetConnectionManager().DialOutboundConnection(addr, uint64(lib.RandInt64(math.MaxInt64)))
}

// getVersionMessage simulates a version message that the provided node would have sent.
func (bridge *ConnectionBridge) getVersionMessage(node *cmd.Node) *lib.MsgDeSoVersion {
	ver := lib.NewMessage(lib.MsgTypeVersion).(*lib.MsgDeSoVersion)
	ver.Version = node.Params.ProtocolVersion.ToUint64()
	ver.TstampSecs = time.Now().Unix()
	ver.Nonce = uint64(lib.RandInt64(math.MaxInt64))
	ver.UserAgent = node.Params.UserAgent
	ver.Services = lib.SFFullNodeDeprecated
	if node.Config.HyperSync {
		ver.Services |= lib.SFHyperSync
	}
	if lib.IsNodeArchival(node.Config.SyncType) {
		ver.Services |= lib.SFArchivalNode
	}

	if node.Server != nil {
		ver.LatestBlockHeight = node.Server.GetBlockchain().BlockTip().Header.Height
	}
	ver.MinFeeRateNanosPerKB = node.Config.MinFeerate
	return ver
}

func ReadWithTimeout(readFunc func() error, readTimeout time.Duration) error {
	errChan := make(chan error)
	go func() {
		errChan <- readFunc()
	}()
	select {
	case err := <-errChan:
		{
			return err
		}
	case <-time.After(readTimeout):
		{
			return fmt.Errorf("ReadWithTimeout: Timed out reading message")
		}
	}
}

// startConnection starts the connection by performing version and verack exchange with
// the provided connection, pretending to be the otherNode.
func (bridge *ConnectionBridge) startConnection(connection *lib.Peer, otherNode *cmd.Node) error {
	// Prepare the version message.
	versionMessage := bridge.getVersionMessage(otherNode)

	// Send the version message.
	fmt.Println("Sending version message:", versionMessage, versionMessage.LatestBlockHeight)
	if err := connection.WriteDeSoMessage(versionMessage); err != nil {
		return err
	}

	// Wait for a response to the version message.
	if err := ReadWithTimeout(
		func() error {
			msg, err := connection.ReadDeSoMessage()
			if err != nil {
				return err
			}

			verMsg, ok := msg.(*lib.MsgDeSoVersion)
			if !ok {
				return err
			}

			connection.TimeConnected = time.Unix(verMsg.TstampSecs, 0)
			connection.TimeOffsetSecs = verMsg.TstampSecs - time.Now().Unix()
			return nil
		}, lib.DeSoMainnetParams.VersionNegotiationTimeout); err != nil {

		return err
	}

	// Now prepare the verack message.
	verackMsg := lib.NewMessage(lib.MsgTypeVerack)

	// And send it to the connection.
	if err := connection.WriteDeSoMessage(verackMsg); err != nil {
		return err
	}

	// And finally wait for connection's response to the verack message.
	if err := ReadWithTimeout(
		func() error {
			msg, err := connection.ReadDeSoMessage()
			if err != nil {
				return err
			}

			if msg.GetMsgType() != lib.MsgTypeVerack {
				return fmt.Errorf("message is not verack! Type: %v", msg.GetMsgType())
			}
			return nil
		}, lib.DeSoMainnetParams.VersionNegotiationTimeout); err != nil {

		return err
	}

	return nil
}

// routeTraffic routes all messages sent to the source connection and redirects it to the destination connection.
// This communication tunnel is one-directional, so normally we would also call routeTraffic(destination, source)
// to make it bidirectional.
func (bridge *ConnectionBridge) routeTraffic(source *lib.Peer, destination *lib.Peer) {
	bridge.waitGroup.Add(1)
	for {
		if bridge.disabled {
			break
		}
		if bridge.paused {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Retrieve a message from the source connection.
		inMsg, err := source.ReadDeSoMessage()
		if bridge.disabled {
			break
		}
		if err != nil {
			fmt.Printf("routeTraffic: Peer disconnected with source: (%v), destination: (%v)",
				source.Conn.LocalAddr().String(), destination.Conn.LocalAddr().String())
			bridge.Restart()
			return
		}
		//fmt.Printf("Reading message: type: (%v) at source with local addr: (%v) and remote addr: (%v)\n",
		//	/*inMsg, */ inMsg.GetMsgType(), source.Conn.LocalAddr().String(), source.Conn.RemoteAddr().String())
		switch inMsg.(type) {
		case *lib.MsgDeSoAddr:
		case *lib.MsgDeSoGetAddr:
			continue
		default:
			// Send the message to the destination connection.
			//fmt.Printf("Redirecting the message: type: (%v) to destination with local addr: (%v) and remote addr: (%v)\n",
			//	/*inMsg, */ inMsg.GetMsgType(), destination.Conn.LocalAddr().String(), destination.Conn.RemoteAddr().String())
			if err := destination.WriteDeSoMessage(inMsg); err != nil {
				fmt.Printf("routeTraffic: Problem writing message to peer with source: (%v), destination: (%v), "+
					"error: (%v), msg: (%v)", source.Conn.LocalAddr().String(), destination.Conn.LocalAddr().String(),
					err, inMsg)
				bridge.Restart()
				return
			}
		}
	}
	bridge.waitGroup.Done()
}

// waitForConnection will wait for 30 seconds to get a new connection, otherwise it will return an error.
func (bridge *ConnectionBridge) waitForConnection() (*lib.Peer, error) {
	timeoutTicker := time.NewTicker(30 * time.Second)
	select {
	case <-timeoutTicker.C:
		return nil, fmt.Errorf("Timed out")
	case peer := <-bridge.newPeerChan:
		return peer, nil
	}
}

func (bridge *ConnectionBridge) Start() error {
	var err error
	bridge.disabled = false

	// Start the outbound listener for A. The 127.0.0.1:0 pattern selects a random port.
	listenerA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	// Start the outbound listener for B. The 127.0.0.1:0 pattern selects a random port.
	listenerB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	bridge.outboundListenerA = listenerA
	bridge.outboundListenerB = listenerB

	// Initialize inbound connections to nodes.
	bridge.connectionInboundA = bridge.createInboundConnection(bridge.nodeA)
	bridge.connectionInboundB = bridge.createInboundConnection(bridge.nodeB)

	// Start the inbound connections.
	if err := bridge.startConnection(bridge.connectionInboundA, bridge.nodeB); err != nil {
		return err
	}
	if err := bridge.startConnection(bridge.connectionInboundB, bridge.nodeA); err != nil {
		return err
	}

	// Initialize outbound connections from nodes.
	bridge.createOutboundConnection(bridge.nodeA, bridge.nodeB, bridge.outboundListenerA)
	if bridge.connectionOutboundA, err = bridge.waitForConnection(); err != nil {
		return err
	}
	bridge.createOutboundConnection(bridge.nodeB, bridge.nodeA, bridge.outboundListenerB)
	if bridge.connectionOutboundB, err = bridge.waitForConnection(); err != nil {
		return err
	}

	// Start the outbound connections from nodes.
	if err := bridge.startConnection(bridge.connectionOutboundA, bridge.nodeB); err != nil {
		return err
	}
	if err := bridge.startConnection(bridge.connectionOutboundB, bridge.nodeB); err != nil {
		return err
	}

	// Get information about the connections
	fmt.Println("ConnectionOutBoundA, local address:", bridge.connectionOutboundA.Conn.LocalAddr().String())
	fmt.Println("ConnectionOutBoundA, remote address:", bridge.connectionOutboundA.Conn.RemoteAddr().String())
	fmt.Println("ConnectionOutBoundB, local address:", bridge.connectionOutboundB.Conn.LocalAddr().String())
	fmt.Println("ConnectionOutBoundB, remote address:", bridge.connectionOutboundB.Conn.RemoteAddr().String())
	fmt.Println("ConnectionInboundA, local address:", bridge.connectionInboundA.Conn.LocalAddr().String())
	fmt.Println("ConnectionInboundA, remote address:", bridge.connectionInboundA.Conn.RemoteAddr().String())
	fmt.Println("ConnectionInboundB, local address:", bridge.connectionInboundB.Conn.LocalAddr().String())
	fmt.Println("ConnectionInboundB, remote address:", bridge.connectionInboundB.Conn.RemoteAddr().String())

	// Start the communication routing between the two nodes. Basically we tunnel all the
	// node communication to happen through the bridge.
	go bridge.routeTraffic(bridge.connectionOutboundA, bridge.connectionInboundB)
	go bridge.routeTraffic(bridge.connectionInboundB, bridge.connectionOutboundA)
	go bridge.routeTraffic(bridge.connectionOutboundB, bridge.connectionInboundA)
	go bridge.routeTraffic(bridge.connectionInboundA, bridge.connectionOutboundB)

	return nil
}

// Stop and start the connection bridge.
func (bridge *ConnectionBridge) Restart() {
	bridge.Disconnect()
	bridge.Start()
}

// Disconnect stops the connection bridge.
func (bridge *ConnectionBridge) Disconnect() {
	if bridge.disabled {
		fmt.Println("ConnectionBridge.Disconnect: Doing nothing, bridge is already disconnected.")
		return
	}

	bridge.disabled = true
	bridge.connectionInboundA.Disconnect("ConnectionBridge.Disconnect")
	bridge.connectionInboundB.Disconnect("ConnectionBridge.Disconnect")
	bridge.connectionOutboundA.Disconnect("ConnectionBridge.Disconnect")
	bridge.connectionOutboundB.Disconnect("ConnectionBridge.Disconnect")
	bridge.outboundListenerA.Close()
	bridge.outboundListenerB.Close()

	bridge.waitGroup.Wait()
}
