package cmd

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/wire"
	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"math"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"
)

// ConnectionBridge is a bidirectional communication channel between two nodes.
// A bridge creates a pair of inbound and outbound peers for each of the nodes to handle communication.
// An inbound Peer represents incoming communication to a node, and an outbound Peer represents outgoing communication.
// To disambiguate, a "Peer" in this context is basically a wrapper around inter-node communication that allows
// receiving and sending messages between the two nodes. Importantly, a Peer supports bidirectional communication.
// As mentioned, our bridge creates an inbound and outbound Peers for both nodes A and B. Now, you might be perplexed
// as to why we would need both of these Peers, as opposed to just one. The reason is that inbound and outbound peers
// differ in a crucial aspect, which is, who creates them. Inbound Peers are created whenever any node on the network
// initiates a communication with our node - meaning a node has no control over the communication partner. On the other
// hand, outbound Peers are created by the node itself, so they can be considered more trusted than inbound peers.
// As a result, certain communication is only sent to outbound peers. To give a more concrete example, a node will,
// for instance, never ask an inbound Peer for headers or blocks, it can ask an outbound Peer though. At the same time,
// a node will respond with headers/blocks if asked by an inbound Peer. Finally, whenever node 1 creates an outbound
// peer and communicates with another node 2, the node 2 will add node 1 as an inbound peer.
//
// A bridge then will simulate the creation of two outbound node connections:
//	nodeA : connectionOutboundA -> connectionInboundB : nodeB
//	nodeB : connectionOutboundB -> connectionInboundA : nodeA
// For example, let's say nodeA wants to send a GET_HEADERS message to nodeB, the traffic will look like this:
// 	GET_HEADERS: nodeA -> connectionOutboundA -> connectionInboundB -> nodeB
//  HEADER_BUNDLE: nodeB -> connectionInboundB -> connectionOutboundA -> nodeA
//
// This middleware design of our the ConnectionBridge allows us to have much higher control over the communication
// between the two nodes. In particular, we have full control over the `connectionOutboundA -> connectionInboundB`
// steps, which allows us to make sure nodes act predictably and deterministically in our tests. Moreover, we can
// simulate real-world network links by doing things like faking delays, dropping messages, partitioning networks, etc.
// Nodes will be disallowed from connecting to other nodes outside of bridges.
type ConnectionBridge struct {
	// nodeA is one end of the bridge.
	nodeA *Node
	// connectionInboundA is a peer representing an incoming connection from nodeB.
	// Any traffic sent to connectionInboundA by nodeA will be routed to connectionOutboundB.
	connectionInboundA *lib.Peer
	// connectionOutboundA is a peer representing an outgoing connection to nodeB.
	// Any traffic sent to connectionOutboundA by nodeA will be routed to connectionInboundB.
	connectionOutboundA *lib.Peer
	// outboundListenerA is a listener that waits for outgoing connections from nodeA.
	outboundListenerA net.Listener

	// nodeB is the other end of the bridge.
	nodeB *Node
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
}

// NewConnectionBridge creates an instance of ConnectionBridge that's ready to be connected.
// This function is usually followed by ConnectionBridge.Connect()
func NewConnectionBridge(nodeA *Node, nodeB *Node) *ConnectionBridge {

	// Start the outbound listener for A.
	listenerA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	// Start the outbound listener for B.
	listenerB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}

	bridge := &ConnectionBridge{
		nodeA:             nodeA,
		outboundListenerA: listenerA,
		nodeB:             nodeB,
		outboundListenerB: listenerB,
		disabled:          false,
		newPeerChan:       make(chan *lib.Peer),
	}
	return bridge
}

// createInboundConnection will initialize the inbound connection (inbound peer) to the provided node.
// It doesn't initiate a version/verack exchange yet, just creates the connection object.
func (bridge *ConnectionBridge) createInboundConnection(node *Node) *lib.Peer {
	// Get the localhost network address of to the provided node.
	port := node.Config.ProtocolPort
	addr := "127.0.0.1:" + strconv.Itoa(int(port))
	netAddress, err := lib.IPToNetAddr(addr, addrmgr.New("", net.LookupIP), &lib.DeSoMainnetParams)
	if err != nil {
		panic(err)
	}
	netAddress2 := net.TCPAddr{
		IP:   netAddress.IP,
		Port: int(netAddress.Port),
	}
	// Dial/connect to the node.
	conn, err := net.DialTimeout(netAddress2.Network(), netAddress2.String(), lib.DeSoMainnetParams.DialTimeout)
	if err != nil {
		panic(err)
	}

	// This channel is redundant in our setting.
	messagesFromPeer := make(chan *lib.ServerMessage)
	// Because it is an inbound Peer of the node, it is simultaneously a "fake" outbound Peer of the bridge.
	// Hence, we will mark the _isOutbound parameter as "true" in NewPeer.
	peer := lib.NewPeer(conn, true, netAddress, true,
		10000, 0, &lib.DeSoMainnetParams,
		messagesFromPeer, nil, nil)
	peer.ID = uint64(lib.RandInt64(math.MaxInt64))
	return peer
}

// createOutboundConnection will initialize an outbound connection from the provided node.
// To do this, we setup an auxiliary listener and make the provided node connect to that listener.
// We will then wrap this connection in a Peer object and return it in the newPeerChan channel.
// The peer is returned through the channel due to the concurrency. This function doesn't initiate
// the version exchange, this should be handled through ConnectionBridge.StartConnection()
func (bridge *ConnectionBridge) createOutboundConnection(node *Node, otherNode *Node, ll net.Listener) {

	// Setup a listener to intercept the traffic from the node.
	go func(ll net.Listener) {
		//for {
		conn, err := ll.Accept()
		if err != nil {
			panic(err)
		}
		fmt.Println("createOutboundConnection: Got a connection from remote:", conn.RemoteAddr().String(),
			"on listener:", ll.Addr().String())

		na, err := lib.IPToNetAddr(conn.RemoteAddr().String(), otherNode.Server.GetConnectionManager().AddrMgr,
			otherNode.Params)
		messagesFromPeer := make(chan *lib.ServerMessage)
		peer := lib.NewPeer(conn, false, na, false,
			10000, 0, bridge.nodeB.Params,
			messagesFromPeer, nil, nil)
		peer.ID = uint64(lib.RandInt64(math.MaxInt64))
		bridge.newPeerChan <- peer
		//}
	}(ll)

	// Make the provided node to make an outbound connection to our listener.
	netAddress, _ := lib.IPToNetAddr(ll.Addr().String(), addrmgr.New("", net.LookupIP), &lib.DeSoMainnetParams)
	fmt.Println("createOutboundConnection: IP:", netAddress.IP, "Port:", netAddress.Port)
	go node.Server.GetConnectionManager().ConnectPeer(nil, netAddress)
}

// getVersionMessage simulates a version message that the provided node would have sent.
func (bridge *ConnectionBridge) getVersionMessage(node *Node) *lib.MsgDeSoVersion {
	ver := lib.NewMessage(lib.MsgTypeVersion).(*lib.MsgDeSoVersion)
	ver.Version = node.Params.ProtocolVersion
	ver.TstampSecs = time.Now().Unix()
	ver.Nonce = uint64(lib.RandInt64(math.MaxInt64))
	ver.UserAgent = node.Params.UserAgent
	ver.Services = lib.SFFullNode
	if node.Config.HyperSync {
		ver.Services |= lib.SFHyperSync
	}
	if node.Server != nil {
		ver.StartBlockHeight = uint32(node.Server.GetBlockchain().BlockTip().Header.Height)
	}
	ver.MinFeeRateNanosPerKB = node.Config.MinFeerate
	return ver
}

// StartConnection starts the connection by performing version and verack exchange with
// the provided connection, pretending to be the otherNode.
func (bridge *ConnectionBridge) StartConnection(connection *lib.Peer, otherNode *Node) error {
	// Prepare the version message.
	versionMessage := bridge.getVersionMessage(otherNode)
	connection.VersionNonceSent = versionMessage.Nonce

	// Send the version message.
	fmt.Println("Sending version message:", versionMessage, versionMessage.StartBlockHeight)
	if err := connection.WriteDeSoMessage(versionMessage); err != nil {
		return err
	}

	// Wait for a response to the version message.
	if err := connection.ReadWithTimeout(
		func() error {
			msg, err := connection.ReadDeSoMessage()
			if err != nil {
				return err
			}

			verMsg, ok := msg.(*lib.MsgDeSoVersion)
			if !ok {
				return err
			}

			connection.VersionNonceReceived = verMsg.Nonce
			connection.TimeConnected = time.Unix(verMsg.TstampSecs, 0)
			connection.TimeOffsetSecs = verMsg.TstampSecs - time.Now().Unix()
			return nil
		}, lib.DeSoMainnetParams.VersionNegotiationTimeout); err != nil {

		return err
	}

	// Now prepare the verack message.
	verackMsg := lib.NewMessage(lib.MsgTypeVerack)
	verackMsg.(*lib.MsgDeSoVerack).Nonce = connection.VersionNonceReceived

	// And send it to the connection.
	if err := connection.WriteDeSoMessage(verackMsg); err != nil {
		return err
	}

	// And finally wait for connection's response to the verack message.
	if err := connection.ReadWithTimeout(
		func() error {
			msg, err := connection.ReadDeSoMessage()
			if err != nil {
				return err
			}

			if msg.GetMsgType() != lib.MsgTypeVerack {
				return fmt.Errorf("message is not verack! Type: %v", msg.GetMsgType())
			}
			verackMsg := msg.(*lib.MsgDeSoVerack)
			if verackMsg.Nonce != connection.VersionNonceSent {
				return fmt.Errorf("verack message nonce doesn't match (received: %v, sent: %v)",
					verackMsg.Nonce, connection.VersionNonceSent)
			}
			return nil
		}, lib.DeSoMainnetParams.VersionNegotiationTimeout); err != nil {

		return err
	}
	connection.VersionNegotiated = true

	return nil
}

// RouteTraffic routes all messages sent to the source connection and redirects it to the destination connection.
// This communication tunnel is one-directional, so normally we would also call RouteTraffic(destination, source)
// to make it bidirectional.
func (bridge *ConnectionBridge) RouteTraffic(source *lib.Peer, destination *lib.Peer) {
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
			fmt.Printf("Peer disconencted with source: (%v), destination: (%v)",
				source.Conn.LocalAddr().String(), destination.Conn.LocalAddr().String())
			panic(err)
		}
		fmt.Printf("Reading message: type: (%v) at source with local addr: (%v) and remote addr: (%v)\n",
			/*inMsg, */ inMsg.GetMsgType(), source.Conn.LocalAddr().String(), source.Conn.RemoteAddr().String())
		switch inMsg.(type) {
		case *lib.MsgDeSoAddr:
		case *lib.MsgDeSoGetAddr:
			continue
		default:
			// Send the message to the destination connection.
			fmt.Printf("Redirecting the message: type: (%v) to destination with local addr: (%v) and remote addr: (%v)\n",
				/*inMsg, */ inMsg.GetMsgType(), destination.Conn.LocalAddr().String(), destination.Conn.RemoteAddr().String())
			if err := destination.WriteDeSoMessage(inMsg); err != nil {
				panic(err)
			}
		}
	}
	bridge.waitGroup.Done()
}

func (bridge *ConnectionBridge) waitForConnection() (*lib.Peer, error) {
	timeoutTicker := time.NewTicker(30 * time.Second)
	select {
	case <-timeoutTicker.C:
		return nil, fmt.Errorf("Timed out")
	case peer := <-bridge.newPeerChan:
		return peer, nil
	}
}

func (bridge *ConnectionBridge) Connect() error {
	var err error

	// Initialize inbound connections to nodes.
	bridge.connectionInboundA = bridge.createInboundConnection(bridge.nodeA)
	bridge.connectionInboundB = bridge.createInboundConnection(bridge.nodeB)

	// Start the inbound connections.
	if err := bridge.StartConnection(bridge.connectionInboundA, bridge.nodeB); err != nil {
		return err
	}
	if err := bridge.StartConnection(bridge.connectionInboundB, bridge.nodeA); err != nil {
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
	if err := bridge.StartConnection(bridge.connectionOutboundA, bridge.nodeB); err != nil {
		return err
	}
	if err := bridge.StartConnection(bridge.connectionOutboundB, bridge.nodeB); err != nil {
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
	go bridge.RouteTraffic(bridge.connectionOutboundA, bridge.connectionInboundB)
	go bridge.RouteTraffic(bridge.connectionInboundB, bridge.connectionOutboundA)
	go bridge.RouteTraffic(bridge.connectionOutboundB, bridge.connectionInboundA)
	go bridge.RouteTraffic(bridge.connectionInboundA, bridge.connectionOutboundB)

	return nil
}

func (bridge *ConnectionBridge) Disconnect() {
	bridge.disabled = true
	bridge.connectionInboundA.Disconnect()
	bridge.connectionInboundB.Disconnect()
	bridge.connectionOutboundA.Disconnect()
	bridge.connectionOutboundB.Disconnect()

	bridge.waitGroup.Wait()
}

type ConnectionRouter struct {
	nodes []*Node
}

// get a random temporary directory.
func getDirectory(t *testing.T) string {
	require := require.New(t)
	dbDir, err := ioutil.TempDir("", "badgerdb")
	if err != nil {
		require.NoError(err)
	}
	return dbDir
}

// generateConfig creates a default config for a node, with provided port, db directory, and number of max peers.
// It's usually the first step to starting a node.
func generateConfig(t *testing.T, port uint32, dataDir string, maxPeers uint32) *Config {
	config := &Config{}
	params := lib.DeSoMainnetParams

	params.DNSSeeds = []string{}
	config.Params = &params
	config.ProtocolPort = uint16(port)
	// "/Users/piotr/data_dirs/n98_1"
	config.DataDirectory = dataDir
	if err := os.MkdirAll(config.DataDirectory, os.ModePerm); err != nil {
		t.Fatalf("Could not create data directories (%s): %v", config.DataDirectory, err)
	}
	config.TXIndex = false
	config.HyperSync = false
	config.MaxSyncBlockHeight = 0
	config.ConnectIPs = []string{}
	config.PrivateMode = true
	config.GlogV = 1
	config.GlogVmodule = "*bitcoin_manager*=0,*balance*=0,*view*=0,*frontend*=0,*peer*=0,*addr*=0,*network*=0,*utils*=0,*connection*=0,*main*=0,*server*=0,*mempool*=0,*miner*=0,*blockchain*=0"
	config.MaxInboundPeers = maxPeers
	config.TargetOutboundPeers = maxPeers
	config.StallTimeoutSeconds = 900
	config.MinFeerate = 1000
	config.OneInboundPerIp = false
	config.MaxBlockTemplatesCache = 100
	config.MaxSyncBlockHeight = 100
	config.MinBlockUpdateInterval = 10

	return config
}

// waitForNodeToFullySync will busy-wait until provided node is fully current.
func waitForNodeToFullySync(node *Node) {
	ticker := time.NewTicker(100 * time.Millisecond)
	for {
		<-ticker.C

		if node.Server.GetBlockchain().ChainState() == lib.SyncStateFullyCurrent {
			return
		}
	}
}

// compareNodesByChecksum checks if the two provided nodes have identical checksums.
func compareNodesByChecksum(t *testing.T, nodeA *Node, nodeB *Node) {
	require := require.New(t)
	checksumA, err := nodeA.Server.GetBlockchain().Snapshot().Checksum.ToBytes()
	require.NoError(err)
	checksumB, err := nodeB.Server.GetBlockchain().Snapshot().Checksum.ToBytes()
	require.NoError(err)

	if !reflect.DeepEqual(checksumA, checksumB) {
		t.Fatalf("compareNodesByChecksum: error checksums not equal checksumA (%v), "+
			"checksumB (%v)", checksumA, checksumB)
	}
	fmt.Printf("Identical checksums: nodeA (%v)\n nodeB (%v)\n", checksumA, checksumB)
}

// compareNodesByState will look through all state records in nodeA and nodeB databases and will compare them.
// The nodes pass this comparison iff they have identical states.
func compareNodesByState(t *testing.T, nodeA *Node, nodeB *Node) {
	maxBytes := uint32(8 << 20)
	var allPrefixes [][]byte
	for _, prefix := range lib.StatePrefixes.StatePrefixesList {
		allPrefixes = append(allPrefixes, prefix)
		lastPrefix := prefix
		for {
			existingValuesA := make(map[string]string)
			existingValuesB := make(map[string]string)

			// Fetch a state chunk from nodeA database.
			dbEntriesA, isChunkFullA, err := lib.DBIteratePrefixKeys(nodeA.chainDB, prefix, lastPrefix, maxBytes)
			if err != nil {
				t.Fatal(errors.Wrapf(err, "problem reading nodeA database for prefix (%v) last prefix (%v)",
					prefix, lastPrefix))
			}
			for _, entry := range dbEntriesA {
				keyHex := hex.EncodeToString(entry.Key)
				valueHex := hex.EncodeToString(entry.Value)
				existingValuesA[keyHex] = valueHex
			}

			// Fetch a state chunk from nodeB database.
			dbEntriesB, isChunkFullB, err := lib.DBIteratePrefixKeys(nodeB.chainDB, prefix, lastPrefix, maxBytes)
			if err != nil {
				t.Fatal(errors.Wrapf(err, "problem reading nodeB database for prefix (%v) last prefix (%v",
					prefix, lastPrefix))
			}
			for _, entry := range dbEntriesB {
				keyHex := hex.EncodeToString(entry.Key)
				valueHex := hex.EncodeToString(entry.Value)
				existingValuesB[keyHex] = valueHex
			}

			// Make sure we've fetched the same number of entries for nodeA and nodeB.
			if len(dbEntriesA) != len(dbEntriesB) {
				t.Fatal(fmt.Errorf("Databases not equal on prefix: %v, and lastPrefix: %v;"+
					"varying lengths (nodeA, nodeB) : (%v, %v)\n", prefix, lastPrefix, len(dbEntriesA), len(dbEntriesB)))
			}

			// It doesn't matter which map we iterate through, since if we got here it means they have
			// an identical number of unique keys. So we will choose dbEntriesA for convenience.
			for ii, entry := range dbEntriesA {
				if !reflect.DeepEqual(entry.Key, dbEntriesB[ii].Key) {
					t.Fatal(fmt.Errorf("Databases not equal on prefix: %v, and lastPrefix: %v; unequal keys "+
						"(nodeA, nodeB) : (%v, %v)\n", prefix, lastPrefix, entry.Key, dbEntriesB[ii].Key))
				}
			}
			for ii, entry := range dbEntriesA {
				if !reflect.DeepEqual(entry.Value, dbEntriesB[ii].Value) {
					t.Fatal(fmt.Errorf("Databases not equal on prefix: %v, and lastPrefix: %v; unequal values "+
						"(nodeA, nodeB) : (%v, %v)\n", prefix, lastPrefix, entry.Value, dbEntriesB[ii].Value))
				}
			}

			// Make sure the isChunkFull match for both chunks.
			if isChunkFullA != isChunkFullB {
				t.Fatal(fmt.Errorf("Databases not equal on prefix: %v, and lastPrefix: %v;"+
					"unequal fulls (nodeA, nodeB) : (%v, %v)\n", prefix, lastPrefix, isChunkFullA, isChunkFullB))
			}

			if len(dbEntriesA) > 0 {
				lastPrefix = dbEntriesA[len(dbEntriesA)-1].Key
			} else {
				break
			}

			if !isChunkFullA {
				break
			}
		}
		fmt.Printf("MATCH: Prefix (%v)\n", allPrefixes)
	}
}

func shutdownNode(t *testing.T, node *Node) *Node {
	if !node.isRunning {
		t.Fatalf("shutdownNode: can't shutdown, node is already down")
	}

	node.Stop()
	config := node.Config
	return NewNode(config)
}

func startNode(t *testing.T, node *Node) *Node {
	if node.isRunning {
		t.Fatalf("startNode: node is already running")
	}
	// Start the node.
	node.Start()
	return node
}

func restartNode(t *testing.T, node *Node) *Node {
	if !node.isRunning {
		t.Fatalf("shutdownNode: can't restart, node already down")
	}

	newNode := shutdownNode(t, node)
	return startNode(t, newNode)
}

func listenForBlockHeight(t *testing.T, node *Node, height uint32, signal chan<- bool) {
	ticker := time.NewTicker(1 * time.Millisecond)
	go func() {
		for {
			<-ticker.C
			if node.Server.GetBlockchain().BlockTip().Height >= height {
				signal <- true
				break
			}
		}
	}()
}

func listenForSyncPrefix(t *testing.T, node *Node, syncPrefix []byte, signal chan<- bool) {
	ticker := time.NewTicker(1 * time.Millisecond)
	go func() {
		for {
			<-ticker.C
			for _, prefix := range node.Server.HyperSyncProgress.PrefixProgress {
				if reflect.DeepEqual(prefix.Prefix, syncPrefix) {
					signal <- true
					return
				}
			}
		}
	}()
}

func restartAtHeightAndReconnectNode(t *testing.T, node *Node, source *Node, currentBridge *ConnectionBridge,
	height uint32) (_node *Node, _bridge *ConnectionBridge) {

	require := require.New(t)
	listener := make(chan bool)
	listenForBlockHeight(t, node, height, listener)
	<-listener
	currentBridge.Disconnect()
	newNode := restartNode(t, node)
	// Wait after the restart.
	time.Sleep(1 * time.Second)

	// bridge the nodes together.
	bridge := NewConnectionBridge(newNode, source)
	require.NoError(bridge.Connect())
	return newNode, bridge
}

func restartAtSyncPrefixAndReconnectNode(t *testing.T, node *Node, source *Node, currentBridge *ConnectionBridge,
	syncPrefix []byte) (_node *Node, _bridge *ConnectionBridge) {

	require := require.New(t)
	listener := make(chan bool)
	listenForSyncPrefix(t, node, syncPrefix, listener)
	<-listener
	currentBridge.Disconnect()
	newNode := restartNode(t, node)

	// bridge the nodes together.
	bridge := NewConnectionBridge(newNode, source)
	require.NoError(bridge.Connect())
	return newNode, bridge
}

func randomUint32Between(t *testing.T, min, max uint32) uint32 {
	require := require.New(t)
	randomNumber, err := wire.RandomUint64()
	require.NoError(err)
	randomHeight := uint32(randomNumber) % (max - min)
	return randomHeight + min
}

// TestSimpleBlockSync test if a node can successfully sync from another node:
//	1. Spawn two nodes node1, node2 with max block height of 50 blocks.
//	2. node1 syncs 50 blocks from the "deso-seed-2.io" generator.
//	3. bridge node1 and node2
//	4. node2 syncs 50 blocks from node1.
//	5. compare node1 state matches node2 state.
func TestSimpleBlockSync(t *testing.T) {
	require := require.New(t)
	_ = require

	router := &ConnectionRouter{}
	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config2 := generateConfig(t, 18001, dbDir2, 10)

	config1.MaxSyncBlockHeight = 50
	config2.MaxSyncBlockHeight = 50
	config1.ConnectIPs = []string{"deso-seed-2.io:17000"}

	node1 := NewNode(config1)
	node2 := NewNode(config2)
	router.nodes = append(router.nodes, node1)
	router.nodes = append(router.nodes, node2)

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	// bridge the nodes together.
	bridge := NewConnectionBridge(node1, node2)
	require.NoError(bridge.Connect())

	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)

	compareNodesByState(t, node1, node2)
	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
}

// TestSimpleSyncRestart tests if a node can successfully restart while syncing blocks.
//	1. Spawn two nodes node1, node2 with max block height of 50 blocks.
//	2. node1 syncs 50 blocks from the "deso-seed-2.io" generator.
//	3. bridge node1 and node2
//	4. node2 syncs between 10 and 50 blocks from node1.
//  5. node2 disconnects from node1 and reboots.
//  6. node2 reconnects with node1 and syncs remaining blocks.
//	5. compare node1 state matches node2 state.
func TestSimpleSyncRestart(t *testing.T) {
	require := require.New(t)
	_ = require

	router := &ConnectionRouter{}
	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config2 := generateConfig(t, 18001, dbDir2, 10)

	config1.MaxSyncBlockHeight = 50
	config2.MaxSyncBlockHeight = 50
	config1.ConnectIPs = []string{"deso-seed-2.io:17000"}

	node1 := NewNode(config1)
	node2 := NewNode(config2)
	router.nodes = append(router.nodes, node1)
	router.nodes = append(router.nodes, node2)

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	// bridge the nodes together.
	bridge := NewConnectionBridge(node1, node2)
	require.NoError(bridge.Connect())

	randomHeight := randomUint32Between(t, 10, config2.MaxSyncBlockHeight)
	fmt.Println("Random height for a restart (re-use if test failed):", randomHeight)
	// Reboot node2 at a specific height and reconnect it with node1
	node2, bridge = restartAtHeightAndReconnectNode(t, node2, node1, bridge, randomHeight)
	waitForNodeToFullySync(node2)

	compareNodesByState(t, node1, node2)
	fmt.Println("Random restart successful! Random height was", randomHeight)
	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
}

// TestSimpleHyperSync test if a node can successfully hyper sync from another node:
//	1. Spawn two nodes node1, node2 with max block height of 50 blocks.
//	2. node1 syncs 50 blocks from the "deso-seed-2.io" generator and builds ancestral records.
//	3. bridge node1 and node2.
//	4. node2 hyper syncs [0,40] blocks from node1, and block syncs [41, 50] remaining blocks.
//	5. compare node1 state matches node2 state.
func TestSimpleHyperSync(t *testing.T) {
	require := require.New(t)
	_ = require

	router := &ConnectionRouter{}
	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config2 := generateConfig(t, 18001, dbDir2, 10)

	config1.MaxSyncBlockHeight = 50
	config2.MaxSyncBlockHeight = 50
	config1.HyperSync = true
	config2.HyperSync = true
	config1.SnapshotBlockHeightPeriod = 40
	config2.SnapshotBlockHeightPeriod = 40
	config1.ConnectIPs = []string{"deso-seed-2.io:17000"}

	node1 := NewNode(config1)
	node2 := NewNode(config2)
	router.nodes = append(router.nodes, node1)
	router.nodes = append(router.nodes, node2)

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	// bridge the nodes together.
	bridge := NewConnectionBridge(node1, node2)
	require.NoError(bridge.Connect())

	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)

	compareNodesByState(t, node1, node2)
	compareNodesByChecksum(t, node1, node2)
	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
}

// TestSimpleHyperSyncRestart tests if a node can successfully restart while syncing blocks.
//	1. Spawn two nodes node1, node2 with max block height of 50 blocks, hyper sync on, with snapshot period 40 blocks.
//	2. node1 syncs 50 blocks from the "deso-seed-2.io" generator, it will also be building ancestral records.
//	3. bridge node1 and node2.
//	4. node2 syncs state from node1, until it reaches a certain random sync prefix.
//  5. node2 disconnects from node1 and reboots.
//  6. node2 reconnects with node1 and syncs remaining state & blocks.
//	5. compare node1 state matches node2 state.
func TestSimpleHyperSyncRestart(t *testing.T) {
	require := require.New(t)
	_ = require

	router := &ConnectionRouter{}
	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config2 := generateConfig(t, 18001, dbDir2, 10)

	config1.MaxSyncBlockHeight = 50
	config2.MaxSyncBlockHeight = 50
	config1.HyperSync = true
	config2.HyperSync = true
	config1.SnapshotBlockHeightPeriod = 40
	config2.SnapshotBlockHeightPeriod = 40
	config1.ConnectIPs = []string{"deso-seed-2.io:17000"}

	node1 := NewNode(config1)
	node2 := NewNode(config2)
	router.nodes = append(router.nodes, node1)
	router.nodes = append(router.nodes, node2)

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	// bridge the nodes together.
	bridge := NewConnectionBridge(node1, node2)
	require.NoError(bridge.Connect())

	syncIndex := randomUint32Between(t, 0, uint32(len(lib.StatePrefixes.StatePrefixesList)))
	syncPrefix := lib.StatePrefixes.StatePrefixesList[syncIndex]
	fmt.Println("Random sync prefix for a restart (re-use if test failed):", syncPrefix)
	// Reboot node2 at a specific sync prefix and reconnect it with node1
	node2, bridge = restartAtSyncPrefixAndReconnectNode(t, node2, node1, bridge, syncPrefix)
	waitForNodeToFullySync(node2)

	compareNodesByState(t, node1, node2)
	compareNodesByChecksum(t, node1, node2)
	fmt.Println("Random restart successful! Random sync prefix was", syncPrefix)
	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
}
