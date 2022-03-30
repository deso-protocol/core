package cmd

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/deso-protocol/core/lib"
	"github.com/deso-protocol/core/migrate"
	"github.com/deso-protocol/go-deadlock"
	"github.com/dgraph-io/badger/v3"
	"github.com/go-pg/pg/v10"
	"github.com/golang/glog"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
	"gopkg.in/DataDog/dd-trace-go.v1/profiler"
)

const (
	NodeRestart = iota
	NodeErase
)

type Node struct {
	Server   *lib.Server
	chainDB  *badger.DB
	TXIndex  *lib.TXIndex
	Params   *lib.DeSoParams
	Config   *Config
	Postgres *lib.Postgres

	// False when a NewNode is created, set to true on Start(), set to false
	// after Stop() is called. Mainly used in testing.
	isRunning bool

	exitChan    chan struct{}
	restartChan chan int
}

func NewNode(config *Config) *Node {
	result := Node{}
	result.Config = config
	result.Params = config.Params
	result.exitChan = make(chan struct{})
	result.restartChan = make(chan int)

	return &result
}

func (node *Node) Start() {
	// TODO: Replace glog with logrus so we can also get rid of flag library
	flag.Set("log_dir", node.Config.LogDirectory)
	flag.Set("v", fmt.Sprintf("%d", node.Config.GlogV))
	flag.Set("vmodule", node.Config.GlogVmodule)
	flag.Set("alsologtostderr", "true")
	flag.Parse()
	glog.CopyStandardLogTo("INFO")

	node.restartChan = make(chan int)
	go node.listenToRestart()

	// Print config
	node.Config.Print()
	glog.Infof("Start() | After node config")

	// Check for regtest mode
	if node.Config.Regtest {
		node.Params.EnableRegtest()
	}

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

	if node.Config.TimeEvents {
		lib.Mode = lib.EnableTimer
	}

	// Setup statsd
	statsdClient, err := statsd.New(fmt.Sprintf("%s:%d", os.Getenv("DD_AGENT_HOST"), 8125))
	if err != nil {
		glog.Fatal(err)
	}

	// Setup listeners and peers
	desoAddrMgr := addrmgr.New(node.Config.DataDirectory, net.LookupIP)
	desoAddrMgr.Start()

	// This just gets localhost listening addresses on the protocol port.
	// Such as [{127.0.0.1 18000 } {::1 18000 }], and associated listener structs.
	listeningAddrs, listeners := GetAddrsToListenOn(node.Config.ProtocolPort)
	_ = listeningAddrs

	// If --connect-ips is not passed, we will connect the addresses from
	// --add-ips, DNSSeeds, and DNSSeedGenerators.
	if len(node.Config.ConnectIPs) == 0 {
		glog.Infof("Looking for AddIPs: %v", len(node.Config.AddIPs))
		for _, host := range node.Config.AddIPs {
			addIPsForHost(desoAddrMgr, host, node.Params)
		}

		glog.Infof("Looking for DNSSeeds: %v", len(node.Params.DNSSeeds))
		for _, host := range node.Params.DNSSeeds {
			addIPsForHost(desoAddrMgr, host, node.Params)
		}

		// This is where we connect to addresses from DNSSeeds.
		if !node.Config.PrivateMode {
			go addSeedAddrsFromPrefixes(desoAddrMgr, node.Params)
		}
	}

	// Setup chain database
	dbDir := lib.GetBadgerDbPath(node.Config.DataDirectory)
	opts := lib.PerformanceBadgerOptions(dbDir)
	opts.ValueDir = dbDir
	node.chainDB, err = badger.Open(opts)
	if err != nil {
		panic(err)
	}

	// Setup snapshot logger
	if node.Config.LogDBSummarySnapshots {
		lib.StartDBSummarySnapshots(node.chainDB)
	}

	// Setup postgres using a remote URI. Postgres is not currently supported
	// when we're in hypersync mode.
	if node.Config.HyperSync && node.Config.PostgresURI != "" {
		glog.Fatal("--postgres-uri is not supported when --hypersync=true. We're " +
			"working on Hypersync support for Postgres though!")
	}
	if !node.Config.HyperSync && node.Config.DisableSlowSync {
		glog.Fatal("Cannot set --disable-slow-sync=true without also setting --hypersync=true")
	}
	var db *pg.DB
	if node.Config.PostgresURI != "" {
		options, err := pg.ParseURL(node.Config.PostgresURI)
		if err != nil {
			panic(err)
		}

		db = pg.Connect(options)
		node.Postgres = lib.NewPostgres(db)

		// LoadMigrations registers all the migration files in the migrate package.
		// See LoadMigrations for more info.
		migrate.LoadMigrations()

		// Migrate the database after loading all the migrations. This is equivalent
		// to running "go run migrate.go migrate". See migrate.go for a migrations CLI tool
		err = migrations.Run(db, "migrate", []string{"", "migrate"})
		if err != nil {
			panic(err)
		}
	}

	// Setup eventManager
	eventManager := lib.NewEventManager()

	// Setup the server
	shouldRestart := false
	node.Server, err, shouldRestart = lib.NewServer(
		node.Params,
		listeners,
		desoAddrMgr,
		node.Config.ConnectIPs,
		node.chainDB,
		node.Postgres,
		node.Config.TargetOutboundPeers,
		node.Config.MaxInboundPeers,
		node.Config.MinerPublicKeys,
		node.Config.NumMiningThreads,
		node.Config.OneInboundPerIp,
		node.Config.HyperSync,
		node.Config.DisableSlowSync,
		node.Config.MaxSyncBlockHeight,
		node.Config.RateLimitFeerate,
		node.Config.MinFeerate,
		node.Config.StallTimeoutSeconds,
		node.Config.MaxBlockTemplatesCache,
		node.Config.MinBlockUpdateInterval,
		node.Config.BlockCypherAPIKey,
		true,
		node.Config.SnapshotBlockHeightPeriod,
		node.Config.DataDirectory,
		node.Config.MempoolDumpDirectory,
		node.Config.DisableNetworking,
		node.Config.ReadOnlyMode,
		node.Config.IgnoreInboundInvs,
		statsdClient,
		node.Config.BlockProducerSeed,
		node.Config.TrustedBlockProducerPublicKeys,
		node.Config.TrustedBlockProducerStartHeight,
		eventManager,
		node.restartChan,
	)
	if err != nil {
		panic(err)
	}

	if !shouldRestart {
		node.Server.Start()

		// Setup TXIndex - not compatible with postgres
		if node.Config.TXIndex && node.Postgres == nil {
			node.TXIndex, err, shouldRestart = lib.NewTXIndex(node.Server.GetBlockchain(), node.Params, node.Config.DataDirectory)
			if err != nil {
				glog.Fatal(err)
			}
			node.Server.TxIndex = node.TXIndex
			if !shouldRestart {
				node.TXIndex.Start()
			}
		}
	}
	node.isRunning = true

	if shouldRestart {
		node.restartChan <- NodeRestart
	}
}

func (node *Node) Stop() {
	node.Server.Stop()

	if node.Server.GetBlockchain().Snapshot() != nil {
		node.Server.GetBlockchain().Snapshot().Stop()
	}

	if node.TXIndex != nil {
		node.TXIndex.Stop()
	}

	node.chainDB.Close()
	node.isRunning = false
	close(node.exitChan)
}

func (node *Node) listenToRestart() {
	select {
	case <-node.exitChan:
		break
	case operation := <-node.restartChan:
		if !node.isRunning {
			panic("Node.listenToRestart: Node is currently not running, restartChan should've not been called!")
		}
		glog.Infof("Node.listenToRestart: Stopping node")
		node.Stop()
		glog.Infof("Node.listenToRestart: Finished stopping node")
		switch operation {
		case NodeErase:
			if err := os.RemoveAll(node.Config.DataDirectory); err != nil {
				glog.Fatal(lib.CLog(lib.Red, fmt.Sprintf("IMPORTANT: Problem removing the directory (%v), you "+
					"should run `rm -rf %v` to delete it manually. Error: (%v)", node.Config.DataDirectory,
					node.Config.DataDirectory, err)))
				return
			}
		}

		glog.Infof("Node.listenToRestart: Restarting node")
		node.exitChan = make(chan struct{})
		node.restartChan = make(chan int)
		go node.Start()
	}
}

func validateParams(params *lib.DeSoParams) {
	if params.BitcoinBurnAddress == "" {
		glog.Fatalf("The DeSoParams being used are missing the BitcoinBurnAddress field.")
	}

	// Check that TimeBetweenDifficultyRetargets is evenly divisible
	// by TimeBetweenBlocks.
	if params.TimeBetweenBlocks == 0 {
		glog.Fatalf("The DeSoParams being used have TimeBetweenBlocks=0")
	}
	numBlocks := params.TimeBetweenDifficultyRetargets / params.TimeBetweenBlocks
	truncatedTime := params.TimeBetweenBlocks * numBlocks
	if truncatedTime != params.TimeBetweenDifficultyRetargets {
		glog.Fatalf("TimeBetweenDifficultyRetargets (%v) should be evenly divisible by "+
			"TimeBetweenBlocks (%v)", params.TimeBetweenDifficultyRetargets,
			params.TimeBetweenBlocks)
	}

	if params.GenesisBlock == nil || params.GenesisBlockHashHex == "" {
		glog.Fatalf("The DeSoParams are missing genesis block info.")
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
			"the DeSoParams (%+v): %v", params.GenesisBlock.Header, err)
	}
	genesisHashHex := hex.EncodeToString(genesisHash[:])
	if genesisHashHex != params.GenesisBlockHashHex {
		glog.Fatalf("GenesisBlockHash in DeSoParams (%s) does not match the block "+
			"hash computed (%s) %d %d", params.GenesisBlockHashHex, genesisHashHex, len(params.GenesisBlockHashHex), len(genesisHashHex))
	}

	if params.MinDifficultyTargetHex == "" {
		glog.Fatalf("The DeSoParams MinDifficultyTargetHex (%s) should be non-empty",
			params.MinDifficultyTargetHex)
	}

	// Check to ensure the genesis block hash meets the initial difficulty target.
	hexBytes, err := hex.DecodeString(params.MinDifficultyTargetHex)
	if err != nil || len(hexBytes) != 32 {
		glog.Fatalf("The DeSoParams MinDifficultyTargetHex (%s) with length (%d) is "+
			"invalid: %v", params.MinDifficultyTargetHex, len(params.MinDifficultyTargetHex), err)
	}

	if params.MaxDifficultyRetargetFactor == 0 {
		glog.Fatalf("The DeSoParams MaxDifficultyRetargetFactor is unset")
	}
}

func GetAddrsToListenOn(protocolPort uint16) ([]net.TCPAddr, []net.Listener) {
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

func addIPsForHost(desoAddrMgr *addrmgr.AddrManager, host string, params *lib.DeSoParams) {
	ipAddrs, err := net.LookupIP(host)
	if err != nil {
		glog.V(2).Infof("_addSeedAddrs: DNS discovery failed on seed host (continuing on): %s %v\n", host, err)
		return
	}
	if len(ipAddrs) == 0 {
		glog.V(2).Infof("_addSeedAddrs: No IPs found for host: %s\n", host)
		return
	}

	// Don't take more than 5 IPs per host.
	ipsPerHost := 5
	if len(ipAddrs) > ipsPerHost {
		glog.V(1).Infof("_addSeedAddrs: Truncating IPs found from %d to %d\n", len(ipAddrs), ipsPerHost)
		ipAddrs = ipAddrs[:ipsPerHost]
	}

	glog.V(1).Infof("_addSeedAddrs: Adding seed IPs from seed %s: %v\n", host, ipAddrs)

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
	glog.V(1).Infof("_addSeedAddrs: Computed the following wire.NetAddress'es: %s", spew.Sdump(netAddrs))

	// Normally the second argument is the source who told us about the
	// addresses we're adding. In this case since the source is a DNS seed
	// just use the first address in the fetch as the source.
	desoAddrMgr.AddAddresses(netAddrs, netAddrs[0])
}

// Must be run in a goroutine. This function continuously adds IPs from a DNS seed
// prefix+suffix by iterating up through all of the possible numeric values, which are typically
// [0, 10]
func addSeedAddrsFromPrefixes(desoAddrMgr *addrmgr.AddrManager, params *lib.DeSoParams) {
	MaxIterations := 20

	go func() {
		for dnsNumber := 0; dnsNumber < MaxIterations; dnsNumber++ {
			var wg deadlock.WaitGroup
			for _, dnsGeneratorOuter := range params.DNSSeedGenerators {
				wg.Add(1)
				go func(dnsGenerator []string) {
					dnsString := fmt.Sprintf("%s%d%s", dnsGenerator[0], dnsNumber, dnsGenerator[1])
					glog.V(2).Infof("_addSeedAddrsFromPrefixes: Querying DNS seed: %s", dnsString)
					addIPsForHost(desoAddrMgr, dnsString, params)
					wg.Done()
				}(dnsGeneratorOuter)
			}
			wg.Wait()
		}
	}()
}
