package cmd

import (

"fmt"
"github.com/btcsuite/btcd/addrmgr"
"github.com/deso-protocol/core/lib"
"github.com/golang/glog"
"github.com/stretchr/testify/require"
"io/ioutil"
"math"
"net"
"os"
"os/signal"
"strconv"
"syscall"
"testing"
"time"
)

func generateConfig(t *testing.T, port uint32, dataDir string, maxPeers uint32) *Config{
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

type ConnectionRouter struct {
	nodes []*Node
}

type ConnectionBridge struct {
	nodeA *Node
	connectionInboundA *lib.Peer
	connectionOutboundA *lib.Peer
	outboundListenerA net.Listener

	nodeB *Node
	connectionInboundB *lib.Peer
	connectionOutboundB *lib.Peer
	outboundListenerB net.Listener

	disabled bool
}

func connectInboundToNode(node *Node) *lib.Peer {
	port := node.Config.ProtocolPort
	addr := "127.0.0.1:"+strconv.Itoa(int(port))
	netAddress, err := lib.IPToNetAddr(addr, addrmgr.New("", net.LookupIP), &lib.DeSoMainnetParams)
	if err != nil {
		panic(err)
	}
	netAddress2 := net.TCPAddr{
		IP:   netAddress.IP,
		Port: int(netAddress.Port),
	}
	conn, err := net.DialTimeout(netAddress2.Network(), netAddress2.String(), lib.DeSoMainnetParams.DialTimeout)
	if err != nil {
		panic(err)
	}
	messagesFromPeer := make(chan *lib.ServerMessage)
	peer := lib.NewPeer(conn, true, netAddress, true,
		10000, 0, &lib.DeSoMainnetParams,
		messagesFromPeer, nil, nil)
	peer.ID = uint64(lib.RandInt64(math.MaxInt64))
	return peer
}

func (bridge *ConnectionBridge) connectOutboundToNode(node *Node, connectionOutBound *lib.Peer,
	otherNode *Node, otherNodeInboundConnection *lib.Peer, ll net.Listener) {

	go func(ll net.Listener) {
		for {
			conn, err := ll.Accept()
			if err != nil {
				panic(err)
			}
			fmt.Println("connectOutboundToNode: Got a connection from remote:", conn.RemoteAddr().String(),
				"on listener:", ll.Addr().String())

			na, err := lib.IPToNetAddr(conn.RemoteAddr().String(), otherNode.Server.GetConnectionManager().AddrMgr,
				otherNode.Params)
			messagesFromPeer := make(chan *lib.ServerMessage)
			peer := lib.NewPeer(conn, false, na, false,
				10000, 0, bridge.nodeB.Params,
				messagesFromPeer, nil, nil)
			peer.ID = uint64(lib.RandInt64(math.MaxInt64))
			err = bridge.InitSide(peer, otherNode)
			if err != nil {
				panic(err)
			}
			connectionOutBound = peer
			fmt.Println("ConnectionOutBoundA, local address:", peer.Conn.LocalAddr().String())
			fmt.Println("ConnectionOutBoundA, remote address:", peer.Conn.RemoteAddr().String())
			fmt.Println("otherNodeInboundConnection, local address:", otherNodeInboundConnection.Conn.LocalAddr().String())
			fmt.Println("otherNodeInboundConnection, remote address:", otherNodeInboundConnection.Conn.RemoteAddr().String())
			go bridge.SetupOneWayLink(connectionOutBound, otherNodeInboundConnection)
			go bridge.SetupOneWayLink(otherNodeInboundConnection, connectionOutBound)
		}
	}(ll)

	netAddress, _ := lib.IPToNetAddr(ll.Addr().String(), addrmgr.New("", net.LookupIP), &lib.DeSoMainnetParams)
	fmt.Println("IP:", netAddress.IP, "Port:", netAddress.Port)
	go node.Server.GetConnectionManager().ConnectPeer(nil, netAddress)
}

func NewConnectionBridge(nodeA *Node, nodeB *Node) *ConnectionBridge {

	//addresses, listeners := GetAddrsToListenOn(19000)
	listenerA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	listenerB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}

	bridge := &ConnectionBridge{
		nodeA:       nodeA,
		connectionInboundA: connectInboundToNode(nodeA),
		outboundListenerA: listenerA,
		nodeB:       nodeB,
		connectionInboundB: connectInboundToNode(nodeB),
		outboundListenerB: listenerB,
		disabled:    false,
	}
	return bridge
}

func (bridge *ConnectionBridge) GetVersionMessage(node *Node) *lib.MsgDeSoVersion {
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

func (bridge *ConnectionBridge) InitSide(connection *lib.Peer, otherNode *Node) error {
	versionMessage := bridge.GetVersionMessage(otherNode)
	connection.VersionNonceSent = versionMessage.Nonce
	fmt.Println("Sending version message:", versionMessage, versionMessage.StartBlockHeight)
	if err := connection.WriteDeSoMessage(versionMessage); err != nil {
		return err
	}

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

	verackMsg := lib.NewMessage(lib.MsgTypeVerack)
	verackMsg.(*lib.MsgDeSoVerack).Nonce = connection.VersionNonceReceived
	if err := connection.WriteDeSoMessage(verackMsg); err != nil {
		return err
	}

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

func (bridge *ConnectionBridge) SetupOneWayLink(source *lib.Peer, destination *lib.Peer) {
	for {
		if bridge.disabled {
			time.Sleep(1 * time.Second)
			continue
		}

		inMsg, err := source.ReadDeSoMessage()
		if err != nil {
			panic(err)
		}
		outMsg := inMsg
		fmt.Printf("Reading message: (%v) type: (%v) at source with local addr: (%v) and remote addr: (%v)\n",
			inMsg, inMsg.GetMsgType(), source.Conn.LocalAddr().String(), source.Conn.RemoteAddr().String())
		switch inMsg.(type) {
			case *lib.MsgDeSoAddr:
				continue
			case *lib.MsgDeSoGetAddr:
				outMsg = lib.NewMessage(lib.MsgTypeAddr).(*lib.MsgDeSoAddr)
				//addr := "127.0.0.1:"+strconv.Itoa(19000)
				//netAddress, _ := lib.IPToNetAddr(addr, addrmgr.New("", net.LookupIP), &lib.DeSoMainnetParams)
				//outMsg.(*lib.MsgDeSoAddr).AddrList = append(outMsg.(*lib.MsgDeSoAddr).AddrList,
				//	&lib.SingleAddr{
				//		Timestamp: time.Now(),
				//		IP: netAddress.IP,
				//		Port: netAddress.Port,
				//		Services: lib.SFFullNode,
				//	})
		}
		fmt.Printf("Redirecting the message: (%v) type: (%v) to destination with local addr: (%v) and remote addr: (%v)\n",
			 outMsg, outMsg.GetMsgType(), destination.Conn.LocalAddr().String(), destination.Conn.RemoteAddr().String())
		 if err := destination.WriteDeSoMessage(outMsg); err != nil {
			panic(err)
		 }
	}
}

func (bridge *ConnectionBridge) Connect() error {
	fmt.Println("ConnectionInboundA, local address:", bridge.connectionInboundA.Conn.LocalAddr().String())
	fmt.Println("ConnectionInboundA, remote address:", bridge.connectionInboundA.Conn.RemoteAddr().String())
	fmt.Println("ConnectionInboundB, local address:", bridge.connectionInboundB.Conn.LocalAddr().String())
	fmt.Println("ConnectionInboundB, remote address:", bridge.connectionInboundB.Conn.RemoteAddr().String())
	if err := bridge.InitSide(bridge.connectionInboundA, bridge.nodeB); err != nil {
		return err
	}
	if err := bridge.InitSide(bridge.connectionInboundB, bridge.nodeA); err != nil {
		return err
	}

	bridge.connectOutboundToNode(bridge.nodeA, bridge.connectionOutboundA,
		bridge.nodeB, bridge.connectionInboundB, bridge.outboundListenerA)
	bridge.connectOutboundToNode(bridge.nodeB, bridge.connectionOutboundB,
		bridge.nodeA, bridge.connectionInboundA, bridge.outboundListenerB)

	//go bridge.SetupOneWayLink(bridge.connectionInboundA, bridge.connectionInboundB)
	//go bridge.SetupOneWayLink(bridge.connectionInboundB, bridge.connectionInboundA)

	return nil
}

func getDirectory(t *testing.T) string {
	require := require.New(t)
	dbDir, err := ioutil.TempDir("", "badgerdb")
	if err != nil {
		require.NoError(err)
	}
	return dbDir
}

func TestRouter(t *testing.T) {
	require := require.New(t)
	_ = require

	// Instead of having nodes exchange network messages, RPC trigger node's message handlers according to
	// manager's internal queues. This ensures tests are deterministic.
	//targetOutboundPeers := 10
	//maxInboundPeers := 5
	//incomingMessages := make(chan *lib.ServerMessage, (targetOutboundPeers + maxInboundPeers) * 3)

	router := &ConnectionRouter{}
	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)
	dbDir3 := getDirectory(t)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config2 := generateConfig(t, 18001, dbDir2, 10)
	config3 := generateConfig(t, 18003, dbDir3, 10)

	config2.MaxSyncBlockHeight = 50
	config3.MaxSyncBlockHeight = 50
	config3.ConnectIPs = []string{"deso-seed-2.io:17000"}

	node1 := NewNode(config1)
	node2 := NewNode(config2)
	node3 := NewNode(config3)
	_ = node1

	router.nodes = append(router.nodes, node2)
	router.nodes = append(router.nodes, node3)
	go node2.Start()
	go node3.Start()


	time.Sleep(10 * time.Second)
	fmt.Println("Waited 15 seconds")

	shutdownListener := make(chan os.Signal)
	signal.Notify(shutdownListener, syscall.SIGINT, syscall.SIGTERM)
	defer func() {
		node2.Stop()
		node3.Stop()
		glog.Info("Shutdown complete")
	}()

	bridge := NewConnectionBridge(node2, node3)
	require.NoError(bridge.Connect())

	time.Sleep(5 * time.Second)
	//netAddrss, err := lib.IPToNetAddr("127.0.0.1:18000", addrmgr.New("", net.LookupIP), &lib.DeSoMainnetParams)
	//if err != nil {
	//	panic(err)
	//}
	//
	//netAddr2 := net.TCPAddr{
	//	IP:   netAddrss.IP,
	//	Port: int(netAddrss.Port),
	//}
	//conn, err := net.DialTimeout(netAddr2.Network(), netAddr2.String(), lib.DeSoMainnetParams.DialTimeout)
	//if err != nil {
	//	panic(err)
	//}
	//
	//messagesFromPeer := make(chan *lib.ServerMessage)
	//peer := lib.NewPeer(conn, true, netAddrss, true,
	//	10000, 0, &lib.DeSoMainnetParams,
	//	messagesFromPeer, nil, nil)
	//time.Sleep(1 * time.Second)
	//if err := peer.NegotiateVersion(lib.DeSoMainnetParams.VersionNegotiationTimeout); err != nil {
	//	panic(err)
	//}
	////go peer.PingHandler()
	//// outHandler - this should handle all messages received from the other end of the bridge
	//bridgeDone := false
	//pingTicker := time.NewTicker(30 * time.Second)
	//go func(done *bool) {
	//	for {
	//		if *done {
	//			break
	//		}
	//
	//		select {
	//		case <-pingTicker.C:
	//			nonce, err := wire.RandomUint64()
	//			require.NoError(err)
	//			fmt.Println("Sending a ping to peer nonce:", nonce)
	//			peer.StatsMtx.Lock()
	//			peer.LastPingNonce = nonce
	//			peer.LastPingTime = time.Now()
	//			peer.StatsMtx.Unlock()
	//			ping := &lib.MsgDeSoPing{Nonce: nonce}
	//			require.NoError(peer.WriteDeSoMessage(ping))
	//		}
	//	}
	//}(&bridgeDone)
	//
	//go func(done *bool) {
	//	for {
	//		if *done {
	//			break
	//		}
	//		rmsg, err := peer.ReadDeSoMessage()
	//		require.NoError(err)
	//
	//		fmt.Println("rmsg:", rmsg)
	//		switch msg := rmsg.(type) {
	//		case *lib.MsgDeSoPing:
	//			fmt.Println("ping happening:")
	//			pong := &lib.MsgDeSoPong{Nonce: msg.Nonce}
	//			require.NoError(peer.WriteDeSoMessage(pong))
	//		case *lib.MsgDeSoPong:
	//			fmt.Println("Got pong nonce:", msg.Nonce)
	//			peer.HandlePongMsg(msg)
	//		}
	//	}
	//}(&bridgeDone)

	//dbDirAddr, err := ioutil.TempDir("", "badgerdb")
	//if err != nil {
	//	t.Fatal(err)
	//}
	//addrMgr := addrmgr.New(dbDirAddr, net.LookupIP)
	//addrMgr.Start()
	//
	//protocolPort := uint16(18011)
	//listeningAddrs, listeners := GetAddrsToListenOn(protocolPort)
	//_ = listeningAddrs
	////for _, addr := range listeningAddrs {
	////	err := addrMgr.AddLocalAddress(wire.NewNetAddress(&addr, 0), addrmgr.BoundPrio)
	////	require.NoError(err)
	////}
	//
	//srv := &lib.Server{
	//	DisableNetworking:            false,
	//	ReadOnlyMode:                 true,
	//	IgnoreInboundPeerInvMessages: false,
	//}
	//
	//incomingMessages := make(chan *lib.ServerMessage)
	//cmgr := lib.NewConnectionManager(
	//	config1.Params,
	//	addrMgr,
	//	listeners,
	//	[]string{"127.0.0.1:18000"} /*_connectIps*/,
	//	chainlib.NewMedianTime(),
	//	10 /*_targetOutboundPeers*/,
	//	10 /*_maxInboundPeers*/,
	//	true /*_limitOneInboundConnectionPerIP*/,
	//	false /*_hyperSync*/,
	//	config1.StallTimeoutSeconds,
	//	config1.MinFeerate,
	//	incomingMessages,
	//	srv)
	//cmgr.Start()
	//srv.

	<-shutdownListener
}