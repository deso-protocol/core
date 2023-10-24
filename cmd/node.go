package cmd

import (
	"encoding/hex"
	"flag"
	"fmt"
	chainlib "github.com/btcsuite/btcd/blockchain"
	"github.com/deso-protocol/core/consensus"
	"github.com/pkg/errors"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
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

type Node struct {
	// Components
	FastHotStuffConsensus *consensus.FastHotStuffConsensus
	Blockchain            *lib.Blockchain
	ChainDB               *badger.DB
	Snapshot              *lib.Snapshot
	Mempool               *lib.DeSoMempool
	BlockProducer         *lib.DeSoBlockProducer
	Miner                 *lib.DeSoMiner
	TXIndex               *lib.TXIndex
	Postgres              *lib.Postgres
	EventManager          *lib.EventManager

	// Server
	Server *lib.Server

	// Managers
	ConsensusManager *lib.ConsensusManager
	SteadyManager    *lib.SteadyManager
	SnapshotManager  *lib.SnapshotManager
	SyncManager      *lib.SyncManager
	StatsManager     *lib.StatsManager
	VersionManager   *lib.VersionManager
	// TODO: In the future we could avoid storing all components/managers individually.
	Managers []lib.Manager

	Params       *lib.DeSoParams
	Config       *Config
	timesource   chainlib.MedianTimeSource
	statsdClient *statsd.Client
	// IsRunning is false when a NewNode is created, set to true on Start(), set to false
	// after Stop() is called. Mainly used in testing.
	IsRunning bool
	// runningMutex is held whenever we call Start() or Stop() on the node.
	runningMutex sync.Mutex

	// internalExitChan is used internally to signal that a node should close.
	internalExitChan chan struct{}
	// nodeMessageChan is passed to the core engine and used to trigger node actions such as a restart or database reset.
	nodeMessageChan chan lib.NodeMessage
	// stopWaitGroup allows us to wait for the node to fully close.
	stopWaitGroup sync.WaitGroup
}

func NewNode(config *Config) *Node {
	result := Node{}
	result.Config = config
	result.Params = config.Params
	result.internalExitChan = make(chan struct{})
	result.nodeMessageChan = make(chan lib.NodeMessage)

	return &result
}

// Start is the main function used to kick off the node. The exitChannels are optionally passed by the caller to receive
// signals from the node. In particular, exitChannels will be closed by the node when the node is shutting down for good.
func (node *Node) Start(exitChannels ...*chan struct{}) {
	// TODO: Replace glog with logrus so we can also get rid of flag library
	flag.Set("log_dir", node.Config.LogDirectory)
	flag.Set("v", fmt.Sprintf("%d", node.Config.GlogV))
	flag.Set("vmodule", node.Config.GlogVmodule)
	flag.Set("alsologtostderr", "true")
	flag.Parse()
	glog.CopyStandardLogTo("INFO")
	node.runningMutex.Lock()
	defer node.runningMutex.Unlock()

	node.internalExitChan = make(chan struct{})
	node.nodeMessageChan = make(chan lib.NodeMessage)

	// listenToNodeMessages handles the messages received from the engine through the nodeMessageChan.
	go node.listenToNodeMessages()

	// Print config
	node.Config.Print()

	// Check for regtest mode
	if node.Config.Regtest {
		node.Params.EnableRegtest()
	}

	// Set the frequency of mempool's database backup.
	node.Params.MempoolBackupTimeMilliseconds = node.Config.MempoolBackupTimeMilliseconds

	// Validate params
	validateParams(node.Params)
	// This is a bit of a hack, and we should deprecate this. We rely on GlobalDeSoParams static variable in only one
	// place in the core code, namely in encoder migrations. Encoder migrations allow us to update the core database
	// schema without requiring a resync. GlobalDeSoParams is used so that encoders know if we're on mainnet or testnet.
	lib.GlobalDeSoParams = *node.Params

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
	node.statsdClient = statsdClient

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

	err, shouldRestart := node.initializeComponents()
	// If shouldRestart is true, it means that the state checksum is likely corrupted, and we need to enter a recovery mode.
	// This can happen if the node was terminated mid-operation last time it was running. The recovery process rolls back
	// blocks to the beginning of the current snapshot epoch and resets to the state checksum to the epoch checksum.
	if shouldRestart {
		glog.Errorf(lib.CLog(lib.Red, "Node.Start: Forcing a rollback to the last snapshot epoch because node was not closed "+
			"properly last time"))
		if err := node.Snapshot.ForceResetToLastSnapshot(node.Blockchain); err != nil {
			// shouldRestart can be true if, on the previous run, we did not finish flushing all ancestral
			// records to the DB. In this case, the snapshot is corrupted and needs to be recomputed entirely. See the
			// comment at the top of snapshot.go for more information on how this works.
			if shouldRestart {
				glog.Infof(lib.CLog(lib.Red, fmt.Sprintf("Node.Start: Got en error while starting server and shouldRestart "+
					"is true. Node will be erased and resynced. Error: (%v)", err)))
				node.nodeMessageChan <- lib.NodeErase
				return
			}
			panic(err)
		}
		node.nodeMessageChan <- lib.NodeRestart
		return
	}

	node.Server, err = lib.NewServer(node.Config.Params, listeners, desoAddrMgr, node.Config.ConnectIPs, node.Config.TargetOutboundPeers,
		node.Config.MaxInboundPeers, node.Config.OneInboundPerIp, node.Config.DisableNetworking, node.statsdClient,
		node.EventManager, node.nodeMessageChan)
	if err != nil {
		panic(errors.Wrapf(err, "Node.Start: Problem initializing server"))
	}

	node.initializeManagers()

	node.Server.Start()
	if node.Miner != nil && len(node.Miner.PublicKeys) > 0 {
		go node.Miner.Start()
	}

	node.startManagers()

	// Setup TXIndex - not compatible with postgres
	if node.Config.TXIndex && node.Postgres == nil {
		node.TXIndex, err = lib.NewTXIndex(node.Blockchain, node.Params, node.Config.DataDirectory)
		if err != nil {
			glog.Fatal(err)
		}
		node.TXIndex = node.TXIndex
		node.TXIndex.Start()
	}
	node.IsRunning = true

	// Detect whenever an interrupt (Ctrl-c) or termination signals are sent.
	syscallChannel := make(chan os.Signal)
	signal.Notify(syscallChannel, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		// If an internalExitChan is triggered then we won't immediately signal a shutdown to the parent context through
		// the exitChannels. When internal exit is called, we will just restart the node in the background.
		select {
		case _, open := <-node.internalExitChan:
			if !open {
				return
			}
		case <-syscallChannel:
		}

		node.Stop()
		for _, channel := range exitChannels {
			if *channel != nil {
				close(*channel)
				*channel = nil
			}
		}
		glog.Info(lib.CLog(lib.Yellow, "Core node shutdown complete"))
	}()
}

func (node *Node) Stop() {
	node.runningMutex.Lock()
	defer node.runningMutex.Unlock()

	if !node.IsRunning {
		return
	}
	node.IsRunning = false
	glog.Infof(lib.CLog(lib.Yellow, "Node is shutting down. This might take a minute. Please don't "+
		"close the node now or else you might corrupt the state."))

	// Stop the miner if we have one running.
	if node.Miner != nil {
		node.Miner.Stop()
		glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: Closed the Miner"))
	}

	node.stopManagers()

	// Stop the PoS block proposer if we have one running.
	if node.FastHotStuffConsensus != nil {
		node.FastHotStuffConsensus.Stop()
		glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: Closed the FastHotStuffConsensus"))
	}

	// TODO: Stop the PoS mempool if we have one running.

	if node.Mempool != nil {
		// Before the node shuts down, write all the mempool txns to disk
		// if the flag is set.
		if node.Mempool.MempoolDir != "" {
			glog.Info("Doing final mempool dump...")
			node.Mempool.DumpTxnsToDB()
			glog.Info("Final mempool dump complete!")
		}

		if !node.Mempool.IsStopped() {
			node.Mempool.Stop()
		}
		glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: Closed Mempool"))
	}

	// Stop the block producer
	if node.BlockProducer != nil {
		if node.Blockchain.MaxSyncBlockHeight == 0 {
			node.BlockProducer.Stop()
		}
		glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: Closed BlockProducer"))
	}

	// Server
	glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: Stopping server..."))
	if node.Server != nil {
		node.Server.Stop()
	}
	glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: Server successfully stopped."))

	// Snapshot
	if node.Snapshot != nil {
		glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: Stopping snapshot..."))
		node.Snapshot.Stop()
		node.closeDb(node.Snapshot.SnapshotDb, "snapshot")
		glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: Snapshot successfully stopped."))
	}

	// TXIndex
	if node.TXIndex != nil {
		glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: Stopping TXIndex..."))
		node.TXIndex.Stop()
		node.closeDb(node.TXIndex.TXIndexChain.DB(), "txindex")
		glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: TXIndex successfully stopped."))
	}

	// Databases
	glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: Closing all databases..."))
	node.closeDb(node.ChainDB, "chain")
	node.stopWaitGroup.Wait()
	glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: Databases successfully closed."))

	if node.internalExitChan != nil {
		close(node.internalExitChan)
		node.internalExitChan = nil
	}
}

func (node *Node) initializeComponents() (_err error, _shouldRestart bool) {
	var err error

	// Setup chain database
	dbDir := lib.GetBadgerDbPath(node.Config.DataDirectory)
	var opts badger.Options

	// If we're in hypersync mode, we use the default badger options. Otherwise, we use performance options.
	// This is because hypersync mode is very I/O intensive, so we want to use the default options to reduce
	// the amount of memory consumed by the database.
	// Blocksync requires performance options because certain indexes tracked by blocksync have extremely large
	// records (e.g. PrefixBlockHashToUtxoOperations). These large records will overflow the default badger mem table
	// size.
	//
	// FIXME: We should rewrite the code so that PrefixBlockHashToUtxoOperations is either removed or written
	// to badger in such a way as to not require the use of PerformanceBadgerOptions. Seet he comment on
	// dirtyHackUpdateDbOpts.
	if node.Config.HyperSync {
		opts = lib.DefaultBadgerOptions(dbDir)
	} else {
		opts = lib.PerformanceBadgerOptions(dbDir)
	}
	opts.ValueDir = dbDir
	node.ChainDB, err = badger.Open(opts)
	if err != nil {
		panic(err)
	}

	// Setup snapshot logger
	if node.Config.LogDBSummarySnapshots {
		lib.StartDBSummarySnapshots(node.ChainDB)
	}

	// Validate that we weren't passed incompatible Hypersync flags
	lib.ValidateHyperSyncFlags(node.Config.HyperSync, node.Config.SyncType)

	// Setup postgres using a remote URI. Postgres is not currently supported when we're in hypersync mode.
	if node.Config.HyperSync && node.Config.PostgresURI != "" {
		glog.Fatal("initializeComponents: --postgres-uri is not supported when --hypersync=true. We're " +
			"working on Hypersync support for Postgres though!")
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
	node.EventManager = lib.NewEventManager()

	// Setup snapshot
	shouldRestart := false
	archivalMode := false
	if node.Config.HyperSync {
		node.Snapshot, err, shouldRestart = lib.NewSnapshot(node.ChainDB, node.Config.DataDirectory,
			node.Config.SnapshotBlockHeightPeriod, false, false, node.Params,
			node.Config.DisableEncoderMigrations, node.Config.HypersyncMaxQueueSize)
		if err != nil {
			panic(err)
		}
	}

	// We only set archival mode true if we're a hypersync node.
	if lib.IsNodeArchival(node.Config.SyncType) {
		archivalMode = true
	}
	// The same timesource is used in the chain data structure and in the connection
	// manager. It just takes and keeps track of the median time among our peers so
	// we can keep a consistent clock.
	node.timesource = chainlib.NewMedianTime()

	node.Blockchain, err = lib.NewBlockchain(
		node.Config.TrustedBlockProducerPublicKeys, node.Config.TrustedBlockProducerStartHeight, node.Config.MaxSyncBlockHeight,
		node.Config.Params, node.timesource, node.ChainDB, node.Postgres, node.EventManager, node.Snapshot, archivalMode)
	if err != nil {
		return errors.Wrapf(err, "initializeComponents: Problem initializing blockchain"), true
	}

	glog.V(1).Infof("initializeComponents: Best Header Height: %d, Header Hash: %s, Header CumWork: %s, Best Block Height: %d, Block Hash: %s, Block CumWork: %s",
		node.Blockchain.HeaderTip().Height,
		hex.EncodeToString(node.Blockchain.HeaderTip().Hash[:]),
		hex.EncodeToString(lib.BigintToHash(node.Blockchain.HeaderTip().CumWork)[:]),
		node.Blockchain.BlockTip().Height,
		hex.EncodeToString(node.Blockchain.BlockTip().Hash[:]),
		hex.EncodeToString(lib.BigintToHash(node.Blockchain.BlockTip().CumWork)[:]))

	// Create a mempool to store transactions until they're ready to be mined into
	// blocks.
	node.Mempool = lib.NewDeSoMempool(node.Blockchain, node.Config.RateLimitFeerate,
		node.Config.MinFeerate, node.Config.BlockCypherAPIKey, true, node.Config.DataDirectory,
		node.Config.MempoolDumpDirectory, false)

	// Initialize the BlockProducer
	// TODO-old(miner): Should figure out a way to get this into main.
	if node.Config.MaxBlockTemplatesCache > 0 {
		node.BlockProducer, err = lib.NewDeSoBlockProducer(
			node.Config.MinBlockUpdateInterval, node.Config.MaxBlockTemplatesCache, node.Config.BlockProducerSeed,
			node.Mempool, node.Blockchain, node.Config.Params, node.Postgres)
		if err != nil {
			panic(err)
		}
		// TODO: Copying it over, but we should start the producer next to everything else.
		go node.BlockProducer.Start()
	}

	// TODO-old(miner): Make the miner its own binary and pull it out of here.
	// Don't start the miner unless miner public keys are set.
	numMiningThreads := node.Config.NumMiningThreads
	if numMiningThreads <= 0 {
		numMiningThreads = uint64(runtime.NumCPU())
	}
	node.Miner, err = lib.NewDeSoMiner(node.Config.MinerPublicKeys, uint32(node.Config.NumMiningThreads),
		node.BlockProducer, node.Params)
	if err != nil {
		return errors.Wrapf(err, "initializeComponents: "), true
	}
	// If we only want to sync to a specific block height, we would disable the miner.
	// _maxSyncBlockHeight is used for development.
	if node.Config.MaxSyncBlockHeight > 0 {
		node.Miner = nil
	}

	node.FastHotStuffConsensus = consensus.NewFastHotStuffConsensus()

	return nil, shouldRestart
}

func (node *Node) initializeManagers() {
	node.ConsensusManager = lib.NewConsensusManager(node.FastHotStuffConsensus, node.Blockchain, node.Mempool,
		node.Server, node.EventManager)
	node.SteadyManager = lib.NewSteadyManager(node.Server, node.Blockchain, node.Mempool, node.Params, node.Config.MinFeerate,
		node.Config.StallTimeoutSeconds, node.Config.ReadOnlyMode, node.Config.IgnoreInboundInvs)
	node.SnapshotManager = lib.NewSnapshotManager(node.Blockchain, node.Snapshot, node.Server, node.Mempool, node.EventManager,
		node.Config.HyperSync, node.Config.ForceChecksum, node.Config.StallTimeoutSeconds, node.nodeMessageChan)
	node.SyncManager = lib.NewSyncManager(node.Blockchain, node.Server, node.Mempool, node.Config.SyncType,
		node.Config.MinFeerate, node.Config.StallTimeoutSeconds)
	node.StatsManager = lib.NewStatsManager(node.Server, node.Mempool, node.Blockchain, node.statsdClient)
	node.VersionManager = lib.NewVersionManager(node.Blockchain, node.Server, node.Params, node.Config.MinFeerate,
		node.Config.HyperSync)

	node.Managers = []lib.Manager{node.ConsensusManager, node.SteadyManager, node.SnapshotManager, node.SyncManager, node.StatsManager, node.VersionManager}
	for _, manager := range node.Managers {
		manager.Init(node.Managers)
	}
}

func (node *Node) startManagers() {
	for _, manager := range node.Managers {
		manager.Start()
	}
}

func (node *Node) stopManagers() {
	for _, manager := range node.Managers {
		manager.Stop()
	}
}

// Close a database and handle the stopWaitGroup accordingly. We close databases in a go routine to speed up the process.
func (node *Node) closeDb(db *badger.DB, dbName string) {
	node.stopWaitGroup.Add(1)

	glog.Infof("Node.closeDb: Preparing to close %v db", dbName)
	go func() {
		defer node.stopWaitGroup.Done()
		if err := db.Close(); err != nil {
			glog.Fatalf(lib.CLog(lib.Red, fmt.Sprintf("Node.Stop: Problem closing %v db: err: (%v)", dbName, err)))
		} else {
			glog.Infof(lib.CLog(lib.Yellow, fmt.Sprintf("Node.closeDb: Closed %v Db", dbName)))
		}
	}()
}

// listenToNodeMessages listens to the communication from the engine through the nodeMessageChan. There are currently
// two main operations that the engine can request. These are a regular node restart, and a restart with a database
// erase. The latter may seem a little harsh, but it is only triggered when the node is really broken and there's
// no way we can recover.
func (node *Node) listenToNodeMessages(exitChannels ...*chan struct{}) {
	select {
	case <-node.internalExitChan:
		break
	case operation := <-node.nodeMessageChan:
		if !node.IsRunning {
			panic("Node.listenToNodeMessages: Node is currently not running, nodeMessageChan should've not been called!")
		}
		glog.Infof("Node.listenToNodeMessages: Stopping node")
		node.Stop()
		glog.Infof("Node.listenToNodeMessages: Finished stopping node")
		switch operation {
		case lib.NodeErase:
			if err := os.RemoveAll(node.Config.DataDirectory); err != nil {
				glog.Fatal(lib.CLog(lib.Red, fmt.Sprintf("IMPORTANT: Problem removing the directory (%v), you "+
					"should run `rm -rf %v` to delete it manually. Error: (%v)", node.Config.DataDirectory,
					node.Config.DataDirectory, err)))
				return
			}
		}

		glog.Infof("Node.listenToNodeMessages: Restarting node")
		// Wait a few seconds so that all peer messages we've sent while closing the node get propagated in the network.
		go node.Start(exitChannels...)
		break
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
	netAddrs, err := lib.SafeMakeSliceWithLength[*wire.NetAddress](uint64(len(ipAddrs)))
	if err != nil {
		glog.V(2).Infof("_addSeedAddrs: Problem creating netAddrs slice with length %d", len(ipAddrs))
		return
	}
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
