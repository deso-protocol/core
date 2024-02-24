package cmd

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
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

var (
	// ErrAlreadyStarted is returned when somebody tries to start an already
	// running service.
	ErrAlreadyStarted = errors.New("already started")
	// ErrAlreadyStopped is returned when somebody tries to stop an already
	// stopped service (without resetting it).
	ErrAlreadyStopped = errors.New("already stopped")
	// ErrNodeNeverStarted is returned when somebody tries to find or change the
	// running status of the server without never starting it once.
	ErrNodeNeverStarted = errors.New("never started the node instance")
	// Cannot set node status to NEVERSTARTED.
	// NEVERSTARTED is the default status, cannot set deliberately.
	ErrCannotSetToNeverStarted = errors.New("cannot set the node status to neverstarted")
	// Erorr when invalid status is set for node
	ErrInvalidNodeStatus = errors.New("invalid node status. check cmd/node.go for valid states")
	// Invalid Status return value for the *Node.GetStatus()/*Node.getStatusWithoutLock helper functions.
	// byte(255) is a reserved status for invalid status code for the Node
	INVALIDNODESTATUS = NodeStatus(255)
)

// Valid status codes for the Node.
// Status should be retrieved using the helper functions *Node.GetStatus()
const (
	// Status when the node is not initialized or started for the first time
	NEVERSTARTED NodeStatus = iota // byte(0)
	// Status when the node is initialized using *Node.Start
	RUNNING // byte(1)
	// Status when the node is stopped
	STOPPED // byte(2)
)

// custom byte type to indicate the running status of the Node.
type NodeStatus byte

type Node struct {
	Server   *lib.Server
	ChainDB  *badger.DB
	TXIndex  *lib.TXIndex
	Params   *lib.DeSoParams
	Config   *Config
	Postgres *lib.Postgres

	// status is nil when a NewNode is created, it is initialized and set to RUNNING [byte(1)] on node.Start(),
	// set to STOPPED [byte(2)] after Stop() is called.

	// Use the convenience methods SetStatus/SetStatusRunningWithoutLock/SetStatusStoppedWithoutLock to change node status.
	// Use *Node.IsRunning() to check if the node is running.
	// Use *Node.GetStatus() to retrieve the status of the node.
	// Use *Node.getStatusWithoutLock() if the statusMutex is held by the caller.
	status *NodeStatus
	// Held whenever the status of the node is read or altered.
	statusMutex sync.Mutex
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
	node.statusMutex.Lock()
	defer node.statusMutex.Unlock()

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
	var opts badger.Options

	// If we're in hypersync mode, we use the default badger options. Otherwise, we use performance options.
	// This is because hypersync mode is very I/O intensive, so we want to use the default options to reduce
	// the amount of memory consumed by the database.
	// Blocksync requires performance options because certain indexes tracked by blocksync have extremely large
	// records (e.g. PrefixBlockHashToUtxoOperations). These large records will overflow the default badger mem table
	// size.
	//
	// FIXME: We should rewrite the code so that PrefixBlockHashToUtxoOperations is either removed or written
	// to badger in such a way as to not require the use of PerformanceBadgerOptions. See the comment on
	// dirtyHackUpdateDbOpts.

	// Check to see if this node has already been initialized with performance or default options.
	// If so, we should continue to use those options.
	// If not and the db directory exists, we will use PerformanceOptions as the default. This is because
	// prior to the use of default options for hypersync, all nodes were initialized with performance options.
	// So all nodes that are upgrading will want to continue using performance options. Only nodes that are
	// hypersyncing from scratch can use default options.
	// If not, this means we have a clean data directory and it should be based on the sync type.
	// The reason we do this check is because once a badger database is initialized with performance options,
	// re-opening it with non-performance options results in a memory error panic. In order to prevent this transition
	// from default -> performance -> default settings, we save the db options to a file. This takes the form of a
	// boolean which indicates whether the db was initialized with performance options or not. Upon restart, if the
	// file exists, we use the same options. If the file does not exist, we use the options based on the sync type.
	performanceOptions, err := lib.DbInitializedWithPerformanceOptions(node.Config.DataDirectory)

	// We hardcode performanceOptions to true if we're not using a hypersync sync-type. This helps
	// nodes recover that were running an older version that wrote the incorrect boolean to the file.
	if node.Config.SyncType != lib.NodeSyncTypeHyperSync &&
		node.Config.SyncType != lib.NodeSyncTypeHyperSyncArchival {
		performanceOptions = true
	}
	// If the db options haven't yet been saved, we should base the options on the existence of the
	// data directory and the sync type.
	if os.IsNotExist(err) {
		// Check if the db directory exists.
		_, err = os.Stat(dbDir)
		isHypersync := node.Config.SyncType == lib.NodeSyncTypeHyperSync ||
			node.Config.SyncType == lib.NodeSyncTypeHyperSyncArchival
		performanceOptions = !os.IsNotExist(err) || !isHypersync
		// Save the db options for future runs.
		lib.SaveBoolToFile(lib.GetDbPerformanceOptionsFilePath(node.Config.DataDirectory), performanceOptions)
	} else if err != nil {
		// If we get an error other than "file does not exist", we should panic.
		panic(err)
	}

	if performanceOptions {
		opts = lib.PerformanceBadgerOptions(dbDir)
	} else {
		opts = lib.DefaultBadgerOptions(dbDir)
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
		glog.Fatal("--postgres-uri is not supported when --hypersync=true. We're " +
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
	eventManager := lib.NewEventManager()

	// Setup the server. ShouldRestart is used whenever we detect an issue and should restart the node after a recovery
	// process, just in case. These issues usually arise when the node was shutdown unexpectedly mid-operation. The node
	// performs regular health checks to detect whenever this occurs.
	shouldRestart := false
	node.Server, err, shouldRestart = lib.NewServer(
		node.Params,
		listeners,
		desoAddrMgr,
		node.Config.ConnectIPs,
		node.ChainDB,
		node.Postgres,
		node.Config.TargetOutboundPeers,
		node.Config.MaxInboundPeers,
		node.Config.MinerPublicKeys,
		node.Config.NumMiningThreads,
		node.Config.OneInboundPerIp,
		node.Config.HyperSync,
		node.Config.SyncType,
		node.Config.MaxSyncBlockHeight,
		node.Config.DisableEncoderMigrations,
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
		node.nodeMessageChan,
		node.Config.ForceChecksum,
		node.Config.StateChangeDir,
		node.Config.HypersyncMaxQueueSize)
	if err != nil {
		// shouldRestart can be true if, on the previous run, we did not finish flushing all ancestral
		// records to the DB. In this case, the snapshot is corrupted and needs to be computed. See the
		// comment at the top of snapshot.go for more information on how this works.
		if shouldRestart {
			glog.Infof(lib.CLog(lib.Red, fmt.Sprintf("Start: Got en error while starting server and shouldRestart "+
				"is true. Node will be erased and resynced. Error: (%v)", err)))
			node.nodeMessageChan <- lib.NodeErase
			return
		}
		panic(err)
	}

	if !shouldRestart {
		node.Server.Start()

		// Setup TXIndex - not compatible with postgres
		if node.Config.TXIndex && node.Postgres == nil {
			node.TXIndex, err = lib.NewTXIndex(node.Server.GetBlockchain(), node.Params, node.Config.DataDirectory)
			if err != nil {
				glog.Fatal(err)
			}
			node.Server.TxIndex = node.TXIndex
			if !shouldRestart {
				node.TXIndex.Start()
			}
		}
	}

	// Load the node status.
	// This is to identify whether the node is initialized for the first time or it's a restart.
	status, err := node.getStatusWithoutLock()
	if err != nil {
		glog.Fatal("Failed to load node status")
	}
	// Handling the first time initialization and node restart cases separately.
	// This allows us to log the events and even run exclusive logic if any.
	switch status {
	case NEVERSTARTED:
		glog.Info("Changing node status from NEVERSTARTED to RUNNING...")
		// The node status is changed from NEVERSTARTED to RUNNING only once
		// when the node is started for the first time.
		err = node.SetStatusRunningWithoutLock()
		if err != nil {
			glog.Fatalf("Error running Node -- %v", err)
		}
	case STOPPED:
		// This case is called during a node restart.
		// During restart the Node is first STOPPED before setting the
		// status again to RUNNING.
		glog.Info("Changing node status from STOP to RUNNING...")
		err = node.SetStatusRunningWithoutLock()
		if err != nil {
			glog.Fatalf("Error running Node -- %v", err)
		}
	default:
		// Rare occurrence. Happens if you set an invalid node status while restarting a node.
		// cannot start the node if the status of the Node is already set to RUNNING.
		panic(fmt.Sprintf("Cannot change node status to RUNNING from the current status %v", status))

	}

	if shouldRestart {
		if node.nodeMessageChan != nil {
			node.nodeMessageChan <- lib.NodeRestart
		}
	}

	// Detect whenever an interrupt (Ctrl-c) or termination signals are sent.
	syscallChannel := make(chan os.Signal)
	signal.Notify(syscallChannel, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		// If an internalExitChan is triggered then we won't immediately signal a shutdown to the parent context through
		// the exitChannels. When internal exit is called, we will just restart the node in the background.

		// Example: First call Node.Stop(), then call Node.Start() to internally restart the service.
		// Since Stop() closes the internalExitChain, the exitChannels sent by the users of the
		// core library will not closed. Thus ensuring that an internal restart doesn't affect the users of the core library.
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

// Changes node status to STOPPED.
// Cannot transition from NEVERSTARTED to STOPPED.
// Valid transition sequence is NEVERSTARTED->RUNNING->STOPPED.
func (node *Node) SetStatusStoppedWithoutLock() error {
	if err := node.setStatusWithoutLock(STOPPED); err != nil {
		return fmt.Errorf("failed to set status to stop: %w", err)
	}
	return nil
}

// Changes node status to RUNNING.
func (node *Node) SetStatusRunningWithoutLock() error {
	if err := node.setStatusWithoutLock(RUNNING); err != nil {
		return fmt.Errorf("failed to set status to running: %w", err)
	}
	return nil
}

// Loads the status of Node.
// Modifying getStatusWithoutLock() and the validateStatus() functions and their tests are hard requirements
// to add new status codes for the node.
func (node *Node) getStatusWithoutLock() (NodeStatus, error) {
	// Never initialized the server using *Node.Start()
	if node.status == nil {
		return NEVERSTARTED, nil
	}
	// using switch and case prevents from adding new invalid codes
	// without changing the getStatusWithoutLock() function and its unit test.
	switch *node.status {
	// Node is started using *Node.Start() and not stopped yet.
	case RUNNING:
		return RUNNING, nil
	// Node was once initialized, but currently stopped.
	// Set to STOPPED on calling *Node.Stop()
	case STOPPED:
		return STOPPED, nil
	// Any other status code apart from the cases above are considered INVALID!!!!
	default:
		return INVALIDNODESTATUS, ErrInvalidNodeStatus
	}
}

// Wrapper function to get the status of the node with statusMutex.
// Use private method getStatusWithoutLock(), in case the locks are held by the caller.
func (node *Node) GetStatus() (NodeStatus, error) {
	node.statusMutex.Lock()
	defer node.statusMutex.Unlock()

	return node.getStatusWithoutLock()
}

// Verifies whether a status code of the node is a valid status code.
// Used while changing the status of the node
// Modifying getStatusWithoutLock() and the validateStatus() functions and their tests are hard requirements
// to add new status codes for the node.
func ValidateNodeStatus(status NodeStatus) error {
	switch status {
	// Instance of the *Node is created, but not yet initialized using *Node.Start()
	case NEVERSTARTED:
		return nil
	// Node is started using *Node.Start() and not stopped yet.
	case RUNNING:
		return nil
	// Node was once initialized, but currently stopped.
	// Set to STOPPED on calling *Node.Stop()
	case STOPPED:
		return nil
	// Any other status code apart from the cases above are considered INVALID,
	default:
		return ErrInvalidNodeStatus
	}
}

// changes the running status of the node
// Always use this function to change the status of the node.
func (node *Node) setStatusWithoutLock(newStatus NodeStatus) error {
	if err := ValidateNodeStatus(newStatus); err != nil {
		return err
	}

	// Cannot deliberately change the status to NEVERSTARTED.
	// NEVERSTARTED is the default status of the node before the
	// node is started using *Node.Start().
	if newStatus == NEVERSTARTED {
		return ErrCannotSetToNeverStarted
	}
	// Load the current status of the Node.
	status, err := node.getStatusWithoutLock()
	if err != nil {
		return err
	}

	// Cannot change the status of the server to STOPPED while it was never initialized
	// in the first place. Can stop the never only after it's started using *Node.Start().
	// Valid status transition is NEVERSTARTED -> RUNNING -> STOPPED -> RUNNING
	if status == NEVERSTARTED && newStatus == STOPPED {
		return ErrNodeNeverStarted
	}

	// No need to change the status if the new status is same as current status.
	if newStatus == status {
		switch newStatus {
		case RUNNING:
			return ErrAlreadyStarted
		case STOPPED:
			return ErrAlreadyStopped
		}
	}

	node.status = &newStatus

	return nil
}

// Wrapper function for changing node status with statusMutex
// use SetStatusWithoutLock if the lock is held by the caller.
// calling this function while the statusMutex lock is already held will lead to deadlocks!
func (node *Node) SetStatus(newStatus NodeStatus) error {
	node.statusMutex.Lock()
	defer node.statusMutex.Unlock()

	return node.setStatusWithoutLock(newStatus)

}

// Helper function to check if the node is running.
// returns false if node status is not set to RUNNING
func (node *Node) IsRunning() bool {
	status, err := node.GetStatus()

	if err != nil {
		return false
	}

	return status == RUNNING
}

func (node *Node) Stop() error {
	node.statusMutex.Lock()
	defer node.statusMutex.Unlock()

	// Change nodes running status to stop
	// Node's current status has to be RUNNING to be able to STOP!
	if err := node.SetStatusStoppedWithoutLock(); err != nil {
		glog.Errorf("Error stopping Node -- %v", err)
		return err
	}

	glog.Infof(lib.CLog(lib.Yellow, "Node is shutting down. This might take a minute. Please don't "+
		"close the node now or else you might corrupt the state."))

	// Server
	glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: Stopping server..."))
	node.Server.Stop()
	glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: Server successfully stopped."))

	// Snapshot
	snap := node.Server.GetBlockchain().Snapshot()
	if snap != nil {
		glog.Infof(lib.CLog(lib.Yellow, "Node.Stop: Stopping snapshot..."))
		snap.Stop()
		node.closeDb(snap.SnapshotDb, "snapshot")
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
	return nil
}

// Return internal exit channel to wait for the node to stop.
func (node *Node) Quit() chan struct{} {
	return node.internalExitChan
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
		switch operation {
		case lib.NodeRestart:
			// Using Mutex while accessing the Node status to avoid any race conditions
			glog.Infof("Node.listenToNodeMessages: Restarting node.")
			glog.Infof("Node.listenToNodeMessages: Stopping node")
			// Stopping node
			// Stop only works if the current state of the node is RUNNING.
			if err := node.Stop(); err != nil {
				panic(fmt.Sprintf("Error stopping node: %v", err))
			}

			glog.Infof("Node.listenToNodeMessages: Finished stopping node")

		case lib.NodeErase:
			glog.Infof("Node.listenToNodeMessages: Restarting node with a Database erase.")
			glog.Infof("Node.listenToNodeMessages: Stopping node")
			// cannot stop the node if the node is not already in RUNNING state.
			// Stop the node and remove the data directory if the server is in RUNNING state.

			// Stopping node.
			// When restart with database erase fails when the node starts for the first time
			// This is because the status of the node is still NEVERSTARTED.
			// We log the Stop failure, and still go ahead with the hard restart, a.k.a restart with database erase!
			if err := node.Stop(); err != nil {
				glog.Infof("Node.listenToNodeMessages: Node Stop operation failed.")
				glog.Infof("Still going ahead with the database erase.")
			} else {
				glog.Infof("Node.listenToNodeMessages: Finished stopping node")
			}

			if err := os.RemoveAll(node.Config.DataDirectory); err != nil {
				glog.Fatal(lib.CLog(lib.Red, fmt.Sprintf("IMPORTANT: Problem removing the directory (%v), you "+
					"should run `rm -rf %v` to delete it manually. Error: (%v)", node.Config.DataDirectory,
					node.Config.DataDirectory, err)))
			}
		}

		// Wait a few seconds so that all peer messages we've sent while closing the node get propagated in the network.
		go node.Start(exitChannels...)
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
