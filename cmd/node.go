package cmd

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/DataDog/datadog-go/statsd"
	"github.com/bitclout/core/lib"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/sasha-s/go-deadlock"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
	"gopkg.in/DataDog/dd-trace-go.v1/profiler"
)

type Node struct {
	Server     *lib.Server
	chainDB    *badger.DB
	TXIndex    *lib.TXIndex
	Params     *lib.BitCloutParams
	Config     *Config
}

func NewNode(config *Config) *Node {
	result := Node{}
	result.Config = config
	result.Params = config.Params

	return &result
}

func (node *Node) Start() {
	// TODO: Replace glog with logrus so we can also get rid of flag library
	flag.Parse()
	flag.Set("log_dir", node.Config.LogDirectory)
	flag.Set("v", fmt.Sprintf("%d", node.Config.GlogV))
	flag.Set("vmodule", node.Config.GlogVmodule)
	glog.Init()
	glog.CopyStandardLogTo("INFO")

	// Print config
	node.Config.Print()

	// Validate params
	validateParams(node.Params)

	// Setup Datadog span tracer and profiler
	if node.Config.DatadogProfiler {
		tracer.Start()
		err := profiler.Start(profiler.WithProfileTypes(profiler.CPUProfile, profiler.BlockProfile, profiler.MutexProfile, profiler.GoroutineProfile, profiler.HeapProfile))
		if err != nil {
			glog.Fatal(err)
		}
	}

	// Setup statsd
	statsdClient, err := statsd.New(fmt.Sprintf("%s:%d", os.Getenv("DD_AGENT_HOST"), 8125))
	if err != nil {
		glog.Fatal(err)
	}

	// Setup listeners and peers
	bitcloutAddrMgr := addrmgr.New(node.Config.DataDirectory, net.LookupIP)
	bitcloutAddrMgr.Start()

	listeningAddrs, listeners := getAddrsToListenOn(node.Config.ProtocolPort)

	for _, addr := range listeningAddrs {
		netAddr := wire.NewNetAddress(&addr, 0)
		_ = bitcloutAddrMgr.AddLocalAddress(netAddr, addrmgr.BoundPrio)
	}

	if len(node.Config.ConnectIPs) == 0 {
		for _, host := range node.Config.AddIPs {
			addIPsForHost(bitcloutAddrMgr, host, node.Params)
		}

		for _, host := range node.Params.DNSSeeds {
			addIPsForHost(bitcloutAddrMgr, host, node.Params)
		}

		if !node.Config.PrivateMode {
			go addSeedAddrsFromPrefixes(bitcloutAddrMgr, node.Params)
		}
	}

	bitcoinDataDir := filepath.Join(node.Config.DataDirectory, "bitcoin_manager")
	if err := os.MkdirAll(bitcoinDataDir, os.ModePerm); err != nil {
		fmt.Errorf("Could not create Bitcoin datadir (%s): %v", node.Config.DataDirectory, err)
		panic(err)
	}

	// Setup chain database
	dbDir := lib.GetBadgerDbPath(node.Config.DataDirectory)
	opts := badger.DefaultOptions(dbDir)
	opts.ValueDir = dbDir
	opts.MemTableSize = 1024 << 20
	node.chainDB, err = badger.Open(opts)
	if err != nil {
		panic(err)
	}

	// Setup snapshot logger
	if node.Config.LogDBSummarySnapshots {
		lib.StartDBSummarySnapshots(node.chainDB)
	}

	// Setup the server
	node.Server, err = lib.NewServer(
		node.Params,
		listeners,
		bitcloutAddrMgr,
		node.Config.ConnectIPs,
		node.chainDB,
		node.Config.TargetOutboundPeers,
		node.Config.MaxInboundPeers,
		node.Config.MinerPublicKeys,
		node.Config.NumMiningThreads,
		node.Config.OneInboundPerIp,
		node.Config.RateLimitFeerate,
		node.Config.MinFeerate,
		node.Config.StallTimeoutSeconds,
		bitcoinDataDir,
		node.Config.MaxBlockTemplatesCache,
		node.Config.MinBlockUpdateInterval,
		node.Config.BlockCypherAPIKey,
		true,
		node.Config.DataDirectory,
		node.Config.MempoolDumpDirectory,
		node.Config.DisableNetworking,
		node.Config.ReadOnlyMode,
		node.Config.IgnoreInboundInvs,
		node.Config.BitcoinConnectPeer,
		node.Config.IgnoreUnminedBitcoin,
		statsdClient,
		node.Config.BlockProducerSeed,
		node.Config.TrustedBlockProducerPublicKeys,
		node.Config.TrustedBlockProducerStartHeight,
	)
	if err != nil {
		panic(err)
	}

	node.Server.Start()

	// Setup TXIndex
	if node.Config.TXIndex {
		node.TXIndex, err = lib.NewTXIndex(node.Server, node.Params, node.Config.DataDirectory)
		if err != nil {
			glog.Fatal(err)
		}

		node.TXIndex.Start()
	}
}

func (node* Node) Stop() {
	node.Server.Stop()
	node.chainDB.Close()
	node.TXIndex.Stop()
}

func validateParams(params *lib.BitCloutParams) {
	if params.BitcoinBurnAddress == "" {
		glog.Fatalf("The BitCloutParams being used are missing the BitcoinBurnAddress field.")
	}

	// Check that TimeBetweenDifficultyRetargets is evenly divisible
	// by TimeBetweenBlocks.
	if params.TimeBetweenBlocks == 0 {
		glog.Fatalf("The BitCloutParams being used have TimeBetweenBlocks=0")
	}
	numBlocks := params.TimeBetweenDifficultyRetargets / params.TimeBetweenBlocks
	truncatedTime := params.TimeBetweenBlocks * numBlocks
	if truncatedTime != params.TimeBetweenDifficultyRetargets {
		glog.Fatalf("TimeBetweenDifficultyRetargets (%v) should be evenly divisible by "+
			"TimeBetweenBlocks (%v)", params.TimeBetweenDifficultyRetargets,
			params.TimeBetweenBlocks)
	}

	if params.GenesisBlock == nil || params.GenesisBlockHashHex == "" {
		glog.Fatalf("The BitCloutParams are missing genesis block info.")
	}

	// Compute the merkle root for the genesis block and make sure it matches.
	merkle, _, err := lib.ComputeMerkleRoot(params.GenesisBlock.Txns)
	if err != nil {
		glog.Fatalf("Could not compute a merkle root for the genesis block: %v", err)
	}
	if *merkle != *params.GenesisBlock.Header.TransactionMerkleRoot {
		glog.Fatalf("Genesis block merkle root (%s) not equal to computed merkle root (%s)",
			hex.EncodeToString(params.GenesisBlock.Header.TransactionMerkleRoot[:]),
			hex.EncodeToString(merkle[:]))
	}

	genesisHash, err := params.GenesisBlock.Header.Hash()
	if err != nil {
		glog.Fatalf("Problem hashing header for the GenesisBlock in "+
			"the BitCloutParams (%+v): %v", params.GenesisBlock.Header, err)
	}
	genesisHashHex := hex.EncodeToString(genesisHash[:])
	if genesisHashHex != params.GenesisBlockHashHex {
		glog.Fatalf("GenesisBlockHash in BitCloutParams (%s) does not match the block "+
			"hash computed (%s) %d %d", params.GenesisBlockHashHex, genesisHashHex, len(params.GenesisBlockHashHex), len(genesisHashHex))
	}

	if params.MinDifficultyTargetHex == "" {
		glog.Fatalf("The BitCloutParams MinDifficultyTargetHex (%s) should be non-empty",
			params.MinDifficultyTargetHex)
	}

	// Check to ensure the genesis block hash meets the initial difficulty target.
	hexBytes, err := hex.DecodeString(params.MinDifficultyTargetHex)
	if err != nil || len(hexBytes) != 32 {
		glog.Fatalf("The BitCloutParams MinDifficultyTargetHex (%s) with length (%d) is "+
			"invalid: %v", params.MinDifficultyTargetHex, len(params.MinDifficultyTargetHex), err)
	}

	if params.MaxDifficultyRetargetFactor == 0 {
		glog.Fatalf("The BitCloutParams MaxDifficultyRetargetFactor is unset")
	}
}

func getAddrsToListenOn(protocolPort uint16) ([]net.TCPAddr, []net.Listener) {
	listeningAddrs := []net.TCPAddr{}
	listeners := []net.Listener{}
	ifaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, nil
	}

	for _, iAddr := range ifaceAddrs {
		ifaceIP, _, err := net.ParseCIDR(iAddr.String())
		if err != nil {
			continue
		}

		if ifaceIP.IsLinkLocalUnicast() {
			continue
		}

		netAddr := net.TCPAddr{
			IP:   ifaceIP,
			Port: int(protocolPort),
		}

		listener, err := net.Listen(netAddr.Network(), netAddr.String())
		if err != nil {
			continue
		}

		listeners = append(listeners, listener)
		listeningAddrs = append(listeningAddrs, netAddr)
	}

	return listeningAddrs, listeners
}

func addIPsForHost(bitcloutAddrMgr *addrmgr.AddrManager, host string, params *lib.BitCloutParams) {
	ipAddrs, err := net.LookupIP(host)
	if err != nil {
		glog.Tracef("_addSeedAddrs: DNS discovery failed on seed host (continuing on): %s %v\n", host, err)
		return
	}
	if len(ipAddrs) == 0 {
		glog.Tracef("_addSeedAddrs: No IPs found for host: %s\n", host)
		return
	}

	// Don't take more than 5 IPs per host.
	ipsPerHost := 5
	if len(ipAddrs) > ipsPerHost {
		glog.Debugf("_addSeedAddrs: Truncating IPs found from %d to %d\n", len(ipAddrs), ipsPerHost)
		ipAddrs = ipAddrs[:ipsPerHost]
	}

	glog.Debugf("_addSeedAddrs: Adding seed IPs from seed %s: %v\n", host, ipAddrs)

	// Convert addresses to NetAddress'es.
	netAddrs := make([]*wire.NetAddress, len(ipAddrs))
	for ii, ip := range ipAddrs {
		netAddrs[ii] = wire.NewNetAddressTimestamp(
			// We initialize addresses with a
			// randomly selected "last seen time" between 3
			// and 7 days ago similar to what bitcoind does.
			time.Now().Add(-1*time.Second*time.Duration(lib.SecondsIn3Days+
				lib.RandInt32(lib.SecondsIn4Days))),
			0,
			ip,
			params.DefaultSocketPort)
	}
	glog.Debugf("_addSeedAddrs: Computed the following wire.NetAddress'es: %s", spew.Sdump(netAddrs))

	// Normally the second argument is the source who told us about the
	// addresses we're adding. In this case since the source is a DNS seed
	// just use the first address in the fetch as the source.
	bitcloutAddrMgr.AddAddresses(netAddrs, netAddrs[0])
}

// Must be run in a goroutine. This function continuously adds IPs from a DNS seed
// prefix+suffix by iterating up through all of the possible numeric values, which are typically
// [0, 10]
func addSeedAddrsFromPrefixes(bitcloutAddrMgr *addrmgr.AddrManager, params *lib.BitCloutParams) {
	MaxIterations := 20

	go func() {
		for dnsNumber := 0; dnsNumber < MaxIterations; dnsNumber++ {
			var wg deadlock.WaitGroup
			for _, dnsGeneratorOuter := range params.DNSSeedGenerators {
				wg.Add(1)
				go func(dnsGenerator []string) {
					dnsString := fmt.Sprintf("%s%d%s", dnsGenerator[0], dnsNumber, dnsGenerator[1])
					glog.Tracef("_addSeedAddrsFromPrefixes: Querying DNS seed: %s", dnsString)
					addIPsForHost(bitcloutAddrMgr, dnsString, params)
					wg.Done()
				}(dnsGeneratorOuter)
			}
			wg.Wait()
		}
	}()
}
