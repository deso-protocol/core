package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"net"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
	"github.com/btcsuite/btcd/addrmgr"
	chainlib "github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/consensus"
	"github.com/deso-protocol/go-deadlock"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

// ServerMessage is the core data structure processed by the Server in its main
// loop.
type ServerMessage struct {
	Peer      *Peer
	Msg       DeSoMessage
	ReplyChan chan *ServerReply
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
	cmgr          *ConnectionManager
	blockchain    *Blockchain
	datadir       string
	snapshot      *Snapshot
	forceChecksum bool
	mempool       *DeSoMempool
	posMempool    *PosMempool
	miner         *DeSoMiner
	blockProducer *DeSoBlockProducer
	eventManager  *EventManager
	TxIndex       *TXIndex
	params        *DeSoParams

	networkManager *NetworkManager

	fastHotStuffConsensus                    *FastHotStuffConsensus
	fastHotStuffConsensusTransitionCheckTime time.Time

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
	// inventoryBeingProcessed keeps track of the inventory (hashes of blocks and
	// transactions) that we've recently processed from peers. It is useful for
	// avoiding situations in which we re-fetch the same data from many peers.
	// For example, if we get the same Block inv message from multiple peers,
	// adding it to this map and checking this map before replying will make it
	// so that we only send a reply to the first peer that sent us the inv, which
	// is more efficient.
	inventoryBeingProcessed *collections.LruSet[InvVect]

	// hasRequestedSync indicates whether we've bootstrapped our mempool
	// by requesting all mempool transactions from a
	// peer. It's initially false
	// when the server boots up but gets set to true after we make a Mempool
	// request once we're fully synced.
	// The waitGroup is used to manage the cleanup of the Server.
	waitGroup deadlock.WaitGroup

	// During initial block download, we request headers and blocks from a single
	// peer. Note: These fields should only be accessed from the messageHandler thread.
	//
	// TODO: This could be much faster if we were to download blocks in parallel
	// rather than from a single peer but it won't be a problem until later, at which
	// point we can make the optimization.
	SyncPeer *Peer

	// When --connect-ips is set, we don't connect to anything from the addrmgr.
	connectIps []string

	// If we're syncing state using hypersync, we'll keep track of the progress using HyperSyncProgress.
	// It stores information about all the prefixes that we're fetching. The way that HyperSyncProgress
	// is organized allows for multi-peer state synchronization. In such case, we would assign prefixes
	// to different peers. Whenever we assign a prefix to a peer, we would append a SyncProgressPrefix
	// struct to the HyperSyncProgress.PrefixProgress array.
	HyperSyncProgress SyncProgress
	// How long we wait on a transaction we're fetching before giving
	// up on it. Note this doesn't apply to blocks because they have their own
	// process for retrying that differs from transactions, which are
	// more best-effort than blocks.
	requestTimeoutSeconds uint32

	// dataLock protects requestedTxns and requestedBlocks
	dataLock deadlock.Mutex

	// requestedTransactions contains hashes of transactions for which we have
	// requested data but have not yet received a response.
	requestedTransactionsMap map[BlockHash]*GetDataRequestInfo

	// addrsToBroadcast is a list of all the addresses we've received from valid addr
	// messages that we intend to broadcast to our peers. It is organized as:
	// <recipient address> -> <list of addresses we received from that recipient>.
	//
	// It is organized in this way so that we can limit the number of addresses we
	// are distributing for a single peer to avoid a DOS attack.
	addrsToBroadcastLock deadlock.RWMutex
	addrsToBroadcast     map[string][]*SingleAddr

	AddrMgr *addrmgr.AddrManager

	// When set to true, we disable the ConnectionManager
	DisableNetworking bool

	// When set to true, transactions created on this node will be ignored.
	ReadOnlyMode                 bool
	IgnoreInboundPeerInvMessages bool

	// Becomes true after the node has processed its first transaction bundle from
	// any peer. This is useful in a deployment setting because it makes it so that
	// a health check can wait until this value becomes true.
	hasProcessedFirstTransactionBundle bool

	statsdClient *statsd.Client

	Notifier *Notifier

	// nodeMessageChannel is used to restart the node that's currently running this server.
	// It is basically a backlink to the node that calls Stop() and Start().
	nodeMessageChannel chan NodeMessage

	shutdown int32
	// timer is a helper variable that allows timing events for development purposes.
	// It can be used to find computational bottlenecks.
	timer *Timer

	StateChangeSyncer *StateChangeSyncer
	// DbMutex protects the badger database from concurrent access when it's being closed & re-opened.
	// This is necessary because the database is closed & re-opened when the node finishes hypersyncing in order
	// to change the database options from Default options to Performance options.
	DbMutex deadlock.Mutex
}

func (srv *Server) HasProcessedFirstTransactionBundle() bool {
	return srv.hasProcessedFirstTransactionBundle
}

// ResetRequestQueues resets all the request queues.
func (srv *Server) ResetRequestQueues() {
	srv.dataLock.Lock()
	defer srv.dataLock.Unlock()

	glog.V(2).Infof("Server.ResetRequestQueues: Resetting request queues")

	srv.requestedTransactionsMap = make(map[BlockHash]*GetDataRequestInfo)
}

func (srv *Server) GetNetworkManager() *NetworkManager {
	return srv.networkManager
}

func (srv *Server) AdminOverrideViewNumber(view uint64) error {
	if srv.fastHotStuffConsensus == nil || srv.fastHotStuffConsensus.fastHotStuffEventLoop == nil {
		return fmt.Errorf("AdminOverrideViewNumber: FastHotStuffConsensus is nil")
	}
	if view < srv.fastHotStuffConsensus.fastHotStuffEventLoop.GetCurrentView() {
		return fmt.Errorf("AdminOverrideViewNumber: Cannot set view to a number less than the current view")
	}
	signer := srv.fastHotStuffConsensus.signer
	srv.fastHotStuffConsensus.Stop()
	srv.blockchain.checkpointBlockInfoLock.Lock()
	if srv.blockchain.checkpointBlockInfo == nil {
		srv.blockchain.checkpointBlockInfo = &CheckpointBlockInfo{}
	}
	srv.blockchain.checkpointBlockInfo.LatestView = view
	srv.blockchain.checkpointBlockInfoLock.Unlock()
	srv.fastHotStuffConsensus = NewFastHotStuffConsensus(
		srv.params,
		srv.networkManager,
		srv.blockchain,
		srv.posMempool,
		signer,
	)
	if err := srv.fastHotStuffConsensus.Start(); err != nil {
		return fmt.Errorf("AdminOverrideViewNumber: Problem starting FastHotStuffConsensus: %v", err)
	}
	return nil
}

// dataLock must be acquired for writing before calling this function.
func (srv *Server) _removeRequest(hash *BlockHash) {
	// Just be lazy and remove the hash from everything indiscriminately to
	// make sure it's good and purged.
	delete(srv.requestedTransactionsMap, *hash)

	invVect := &InvVect{
		Type: InvTypeTx,
		Hash: *hash,
	}
	srv.inventoryBeingProcessed.Delete(*invVect)
}

// dataLock must be acquired for writing before calling this function.
func (srv *Server) _expireRequests() {
	// TODO: It could in theory get slow to do brute force iteration over everything
	// we've requested but not yet received, which is what we do below. But we'll
	// wait until we actually have an issue with it before optimizing it, since it
	// could also be fine. Just watch out for it.

	timeout := time.Duration(int64(srv.requestTimeoutSeconds) * int64(time.Second))
	for hashIter, requestInfo := range srv.requestedTransactionsMap {
		// Note that it's safe to use the hash iterator here because _removeRequest
		// doesn't take a reference to it.
		if requestInfo.TimeRequested.Add(timeout).After(time.Now()) {
			srv._removeRequest(&hashIter)
		}
	}
}

// ExpireRequests checks to see if any requests have expired and removes them if so.
func (srv *Server) ExpireRequests() {
	srv.dataLock.Lock()
	defer srv.dataLock.Unlock()

	srv._expireRequests()
}

// TODO: The hallmark of a messy non-law-of-demeter-following interface...
func (srv *Server) GetBlockchain() *Blockchain {
	return srv.blockchain
}

// TODO: The hallmark of a messy non-law-of-demeter-following interface...
func (srv *Server) GetMempool() Mempool {
	srv.blockchain.ChainLock.RLock()
	defer srv.blockchain.ChainLock.RUnlock()

	if srv.params.IsPoSBlockHeight(uint64(srv.blockchain.BlockTip().Height)) {
		return srv.posMempool
	}
	return srv.mempool
}

// TODO: The hallmark of a messy non-law-of-demeter-following interface...
func (srv *Server) GetBlockProducer() *DeSoBlockProducer {
	return srv.blockProducer
}

func (srv *Server) GetConnectionManager() *ConnectionManager {
	return srv.cmgr
}

// TODO: The hallmark of a messy non-law-of-demeter-following interface...
func (srv *Server) GetMiner() *DeSoMiner {
	return srv.miner
}

func (srv *Server) BroadcastTransaction(txn *MsgDeSoTxn) ([]*MsgDeSoTxn, error) {
	txnHash := txn.Hash()
	if txnHash == nil {
		return nil, fmt.Errorf("BroadcastTransaction: Txn hash is nil")
	}
	// Use the backendServer to add the transaction to the mempool and
	// relay it to peers. When a transaction is created by the user there
	// is no need to consider a rateLimit and also no need to verifySignatures
	// because we generally will have done that already.
	mempoolTxs, err := srv._addNewTxn(nil /*peer*/, txn, false /*rateLimit*/)
	if err != nil {
		return nil, errors.Wrapf(err, "BroadcastTransaction: ")
	}

	// At this point, we know the transaction has been run through the mempool.
	// Now wait for an update of the ReadOnlyUtxoView so we don't break anything.
	validationErr := srv.GetMempool().WaitForTxnValidation(txnHash)
	if validationErr != nil {
		return nil, fmt.Errorf("BroadcastTransaction: Transaction %v "+
			"was not validated due to error: %v", txnHash, validationErr)
	}

	return mempoolTxs, nil
}

func (srv *Server) VerifyAndBroadcastTransaction(txn *MsgDeSoTxn) error {
	// The BroadcastTransaction call validates the transaction internally according to the
	// mempool txn addition rules. If the transaction is valid, it will broadcast the txn to
	// peers. Otherwise, it returns an error.
	if _, err := srv.BroadcastTransaction(txn); err != nil {
		return fmt.Errorf("VerifyAndBroadcastTransaction: Problem broadcasting txn: %v", err)
	}

	return nil
}

type NodeSyncType string

const (
	// Note that "any" forces the node to be archival in order to remain
	// backwards-compatible with the rest of the network. This may change
	// in the future.
	NodeSyncTypeAny               = "any"
	NodeSyncTypeBlockSync         = "blocksync"
	NodeSyncTypeHyperSyncArchival = "hypersync-archival"
	NodeSyncTypeHyperSync         = "hypersync"
)

func IsNodeArchival(syncType NodeSyncType) bool {
	return syncType == NodeSyncTypeAny ||
		syncType == NodeSyncTypeHyperSyncArchival ||
		syncType == NodeSyncTypeBlockSync
}

func NodeCanHypersyncState(syncType NodeSyncType) bool {
	// We can hypersync state from another node in all cases except
	// where block sync is required.
	return syncType != NodeSyncTypeBlockSync
}

func ValidateHyperSyncFlags(isHypersync bool, syncType NodeSyncType) {
	if syncType != NodeSyncTypeAny &&
		syncType != NodeSyncTypeBlockSync &&
		syncType != NodeSyncTypeHyperSyncArchival &&
		syncType != NodeSyncTypeHyperSync {
		glog.Fatalf("Unrecognized --sync-type flag %v", syncType)
	}
	if !isHypersync &&
		syncType == NodeSyncTypeHyperSync {
		glog.Fatal("Cannot set --sync-type=hypersync without also setting --hypersync=true")
	}
	if !isHypersync &&
		syncType == NodeSyncTypeHyperSyncArchival {
		glog.Fatal("Cannot set --sync-type=hypersync-archival without also setting --hypersync=true")
	}
}

func RunDBMigrationsOnce(db *badger.DB, snapshot *Snapshot, params *DeSoParams) error {
	if err := RunBlockIndexMigrationOnce(db, nil, params); err != nil {
		return errors.Wrapf(err, "RunDBMigrationsOnce: Problem running block index migration")
	}
	if err := RunDAOCoinLimitOrderMigrationOnce(db, nil); err != nil {
		return errors.Wrapf(err, "RunDBMigrationsOnce: Problem running DAOCoin limit order migration")
	}
	return nil
}

// RunBlockIndexMigrationOnce runs the block index migration once and saves a file to
// indicate that it has been run.
func RunBlockIndexMigrationOnce(db *badger.DB, snapshot *Snapshot, params *DeSoParams) error {
	blockIndexMigrationFileName := filepath.Join(db.Opts().Dir, BlockIndexMigrationFileName)
	glog.V(2).Info("FileName: ", blockIndexMigrationFileName)
	hasRunMigration, err := ReadBoolFromFile(blockIndexMigrationFileName)
	if err == nil && hasRunMigration {
		glog.V(2).Info("Block index migration has already been run")
		return nil
	}
	glog.V(0).Info("Running block index migration")
	if err = RunBlockIndexMigration(db, snapshot, nil, params); err != nil {
		return errors.Wrapf(err, "Problem running block index migration")
	}
	if err = SaveBoolToFile(blockIndexMigrationFileName, true); err != nil {
		return errors.Wrapf(err, "Problem saving block index migration file")
	}
	glog.V(2).Info("Block index migration complete")
	return nil
}

func RunDAOCoinLimitOrderMigrationOnce(db *badger.DB, snapshot *Snapshot) error {
	limitOrderMigrationFileName := filepath.Join(db.Opts().Dir, DAOCoinLimitOrderMigrationFileName)
	glog.V(2).Info("FileName: ", limitOrderMigrationFileName)
	hasRunMigration, err := ReadBoolFromFile(limitOrderMigrationFileName)
	if err == nil && hasRunMigration {
		glog.V(2).Info("DAOCoinLimitOrder index migration has already been run")
		return nil
	}
	glog.V(0).Info("Running dao coin limit order index migration")
	if err = RunDAOCoinLimitOrderMigration(db, snapshot, nil); err != nil {
		return errors.Wrapf(err, "Problem running dao coin limit order index migration")
	}
	if err = SaveBoolToFile(limitOrderMigrationFileName, true); err != nil {
		return errors.Wrapf(err, "Problem saving dao coin limit order index migration file")
	}
	glog.V(2).Info("dao coin limit order index migration complete")
	return nil
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
	_isRegtest bool,
	_listeners []net.Listener,
	_desoAddrMgr *addrmgr.AddrManager,
	_connectIps []string,
	_db *badger.DB,
	postgres *Postgres,
	_targetOutboundPeers uint32,
	_maxInboundPeers uint32,
	_minerPublicKeys []string,
	_numMiningThreads uint64,
	_limitOneInboundConnectionPerIP bool,
	_peerConnectionRefreshIntervalMillis uint64,
	_hyperSync bool,
	_syncType NodeSyncType,
	_maxSyncBlockHeight uint32,
	_disableEncoderMigrations bool,
	_rateLimitFeerateNanosPerKB uint64,
	_minFeeRateNanosPerKB uint64,
	_stallTimeoutSeconds uint64,
	_maxBlockTemplatesToCache uint64,
	_minBlockUpdateIntervalSeconds uint64,
	_blockCypherAPIKey string,
	_runReadOnlyUtxoViewUpdater bool,
	_snapshotBlockHeightPeriod uint64,
	_dataDir string,
	_mempoolDumpDir string,
	_disableNetworking bool,
	_readOnlyMode bool,
	_ignoreInboundPeerInvMessages bool,
	statsd *statsd.Client,
	_blockProducerSeed string,
	_trustedBlockProducerPublicKeys []string,
	_trustedBlockProducerStartHeight uint64,
	eventManager *EventManager,
	_nodeMessageChan chan NodeMessage,
	_forceChecksum bool,
	_stateChangeDir string,
	_hypersyncMaxQueueSize uint32,
	_blsKeystore *BLSKeystore,
	_mempoolBackupIntervalMillis uint64,
	_mempoolMaxValidationViewConnects uint64,
	_transactionValidationRefreshIntervalMillis uint64,
	_stateSyncerMempoolTxnSyncLimit uint64,
	_checkpointSyncingProviders []string,
	_blockIndexSize int,
) (
	_srv *Server,
	_err error,
	_shouldRestart bool,
) {
	var err error

	// Only initialize state change syncer if the directories are defined.
	var stateChangeSyncer *StateChangeSyncer
	if _stateChangeDir != "" {
		// Create the state change syncer to handle syncing state changes to disk, and assign some of its methods
		// to the event manager.
		stateChangeSyncer = NewStateChangeSyncer(_stateChangeDir, _syncType, _stateSyncerMempoolTxnSyncLimit)
		eventManager.OnStateSyncerOperation(stateChangeSyncer._handleStateSyncerOperation)
		eventManager.OnStateSyncerFlushed(stateChangeSyncer._handleStateSyncerFlush)
	}

	// Setup snapshot
	var _snapshot *Snapshot
	shouldRestart := false
	isChecksumIssue := false
	archivalMode := false
	if _hyperSync {
		_snapshot, err, shouldRestart, isChecksumIssue = NewSnapshot(
			_db,
			_snapshotBlockHeightPeriod,
			false,
			// If we aren't forcing the checksum to be correct, we set disableChecksum on the snapshot to true.
			// This allows us to skip unnecessary checksum calculations.
			!_forceChecksum,
			_params,
			_disableEncoderMigrations,
			_hypersyncMaxQueueSize,
			eventManager,
		)
		if err != nil {
			panic(err)
		}
	}

	// We only set archival mode true if we're a hypersync node.
	if IsNodeArchival(_syncType) {
		archivalMode = true
	}

	// Create an empty Server object here so we can pass a reference to it to the
	// ConnectionManager.
	srv := &Server{
		DisableNetworking:            _disableNetworking,
		ReadOnlyMode:                 _readOnlyMode,
		IgnoreInboundPeerInvMessages: _ignoreInboundPeerInvMessages,
		snapshot:                     _snapshot,
		nodeMessageChannel:           _nodeMessageChan,
		forceChecksum:                _forceChecksum,
		AddrMgr:                      _desoAddrMgr,
		params:                       _params,
		connectIps:                   _connectIps,
		datadir:                      _dataDir,
	}

	if stateChangeSyncer != nil {
		srv.StateChangeSyncer = stateChangeSyncer
	}

	// The same timesource is used in the chain data structure and in the connection
	// manager. It just takes and keeps track of the median time among our peers so
	// we can keep a consistent clock.
	timesource := chainlib.NewMedianTime()
	// We need to add an initial time sample or else it will return the zero time, which
	// messes things up during initialization.
	timesource.AddTimeSample("my-time", time.Now())

	// Create a new connection manager but note that it won't be initialized until Start().
	_incomingMessages := make(chan *ServerMessage, _params.ServerMessageChannelSize+(_targetOutboundPeers+_maxInboundPeers)*3)
	_cmgr := NewConnectionManager(
		_params, _listeners, _hyperSync, _syncType, _stallTimeoutSeconds,
		_minFeeRateNanosPerKB, _incomingMessages, srv)

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
	eventManager.OnBlockConnected(srv._handleBlockMainChainConnectedd)
	eventManager.OnBlockAccepted(srv._handleBlockAccepted)
	eventManager.OnBlockDisconnected(srv._handleBlockMainChainDisconnectedd)

	_chain, err := NewBlockchain(
		_trustedBlockProducerPublicKeys, _trustedBlockProducerStartHeight, _maxSyncBlockHeight,
		_params, timesource, _db, postgres, eventManager, _snapshot, archivalMode, _checkpointSyncingProviders,
		_blockIndexSize)
	if err != nil {
		return nil, errors.Wrapf(err, "NewServer: Problem initializing blockchain"), true
	}

	headerCumWorkStr := "<nil>"
	headerCumWork := BigintToHash(_chain.headerTip().CumWork)
	if headerCumWork != nil {
		headerCumWorkStr = hex.EncodeToString(headerCumWork[:])
	}
	blockCumWorkStr := "<nil>"
	blockCumWork := BigintToHash(_chain.blockTip().CumWork)
	if blockCumWork != nil {
		blockCumWorkStr = hex.EncodeToString(blockCumWork[:])
	}
	glog.V(1).Infof("Initialized chain: Best Header Height: %d, Header Hash: %s, Header CumWork: %s, Best Block Height: %d, Block Hash: %s, Block CumWork: %s",
		_chain.headerTip().Height,
		hex.EncodeToString(_chain.headerTip().Hash[:]),
		headerCumWorkStr,
		_chain.blockTip().Height,
		hex.EncodeToString(_chain.blockTip().Hash[:]),
		blockCumWorkStr)

	nodeServices := SFFullNodeDeprecated
	if _hyperSync {
		nodeServices |= SFHyperSync
	}
	if archivalMode {
		nodeServices |= SFArchivalNode
	}
	if _blsKeystore != nil {
		nodeServices |= SFPosValidator
	}
	srv.networkManager = NewNetworkManager(_params, srv, _chain, _cmgr, _blsKeystore, _desoAddrMgr,
		_connectIps, _targetOutboundPeers, _maxInboundPeers, _limitOneInboundConnectionPerIP,
		_peerConnectionRefreshIntervalMillis, _minFeeRateNanosPerKB, nodeServices)

	if srv.StateChangeSyncer != nil {
		srv.StateChangeSyncer.BlockHeight = uint64(_chain.headerTip().Height)
	}

	// Create a mempool to store transactions until they're ready to be mined into
	// blocks.
	_mempool := NewDeSoMempool(_chain, _rateLimitFeerateNanosPerKB,
		_minFeeRateNanosPerKB, _blockCypherAPIKey, _runReadOnlyUtxoViewUpdater, _dataDir,
		_mempoolDumpDir, true)

	// Initialize the PoS mempool. We need to initialize a best-effort UtxoView based on the current
	// known state of the chain. This will all be overwritten as we process blocks later on.
	currentUtxoView, err := _chain.GetUncommittedTipView()
	if err != nil {
		return nil, errors.Wrapf(err, "NewServer: Problem initializing latest UtxoView"), true
	}
	currentGlobalParamsEntry := currentUtxoView.GetCurrentGlobalParamsEntry()
	latestBlockHash := _chain.blockTip().Hash
	latestBlock := _chain.GetBlock(latestBlockHash)
	if latestBlock == nil {
		return nil, errors.New("NewServer: Problem getting latest block from chain"), true
	}
	_posMempool := NewPosMempool()
	err = _posMempool.Init(
		_params,
		currentGlobalParamsEntry,
		currentUtxoView,
		uint64(_chain.blockTip().Height),
		_mempoolDumpDir,
		_mempoolDumpDir == "", // If no mempool dump dir is set, then the mempool will be in memory only
		_mempoolBackupIntervalMillis,
		[]*MsgDeSoBlock{latestBlock},
		_mempoolMaxValidationViewConnects,
		_transactionValidationRefreshIntervalMillis,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "NewServer: Problem initializing PoS mempool"), true
	}

	// Useful for debugging. Every second, it outputs the contents of the mempool
	// and the contents of the addrmanager.
	/*
		go func() {
			time.Sleep(3 * time.Second)
			for {
				glog.V(2).Infof("Current mempool txns: ")
				counter := 0
				for kk, mempoolTx := range _mempool.poolMap {
					kkCopy := kk
					glog.V(2).Infof("\t%d: < %v: %v >", counter, &kkCopy, mempoolTx)
					counter++
				}
				glog.V(2).Infof("Current addrs: ")
				for ii, na := range srv.cmgr.AddrMgr.GetAllAddrs() {
					glog.V(2).Infof("Addr %d: <%s:%d>", ii, na.IP.String(), na.Port)
				}
				time.Sleep(1 * time.Second)
			}
		}()
	*/

	// Initialize the BlockProducer
	// TODO(miner): Should figure out a way to get this into main.
	var _blockProducer *DeSoBlockProducer
	glog.V(1).Infof("NewServer: Starting Block Producer: %d", _maxBlockTemplatesToCache)
	if _maxBlockTemplatesToCache > 0 {
		_blockProducer, err = NewDeSoBlockProducer(
			_minBlockUpdateIntervalSeconds, _maxBlockTemplatesToCache,
			_blockProducerSeed,
			_mempool, _chain,
			_params, postgres)
		if err != nil {
			panic(err)
		}
		glog.V(1).Infof("NewServer: Initiating block producer gofund")
		go func() {
			_blockProducer.Start()
		}()
	}

	// TODO(miner): Make the miner its own binary and pull it out of here.
	// Don't start the miner unless miner public keys are set.
	if _numMiningThreads <= 0 {
		_numMiningThreads = uint64(runtime.NumCPU())
	}
	_miner, err := NewDeSoMiner(_minerPublicKeys, uint32(_numMiningThreads), _blockProducer, _params)
	if err != nil {
		return nil, errors.Wrapf(err, "NewServer: "), true
	}
	// If we only want to sync to a specific block height, we would disable the miner.
	// _maxSyncBlockHeight is used for development.
	if _maxSyncBlockHeight > 0 {
		_miner = nil
	}

	// Only initialize the FastHotStuffConsensus if the node is a validator with a BLS keystore
	if _blsKeystore != nil {
		srv.fastHotStuffConsensus = NewFastHotStuffConsensus(
			_params,
			srv.networkManager,
			_chain,
			_posMempool,
			_blsKeystore.GetSigner(),
		)
		// On testnet, if the node is configured to be a PoW block producer, and it is configured
		// to be also a PoS validator, then we attach block mined listeners to the miner to kick
		// off the PoS consensus once the miner is done.
		if _isRegtest && _params.NetworkType == NetworkType_TESTNET && _miner != nil && _blockProducer != nil {
			_miner.AddBlockMinedListener(srv.submitRegtestValidatorRegistrationTxns)
		}
	}

	// Set all the fields on the Server object.
	srv.cmgr = _cmgr
	srv.blockchain = _chain
	srv.mempool = _mempool
	srv.posMempool = _posMempool
	srv.miner = _miner
	srv.blockProducer = _blockProducer
	srv.incomingMessages = _incomingMessages
	// Make this hold a multiple of what we hold for individual peers.
	srv.inventoryBeingProcessed, _ = collections.NewLruSet[InvVect](maxKnownInventory)

	srv.requestTimeoutSeconds = 10

	srv.statsdClient = statsd

	// TODO: Make this configurable
	//srv.Notifier = NewNotifier(_chain, postgres)
	//srv.Notifier.Start()

	// Start statsd reporter
	if srv.statsdClient != nil {
		srv.StartStatsdReporter()
	}

	// Initialize the addrs to broadcast map.
	srv.addrsToBroadcast = make(map[string][]*SingleAddr)

	// This will initialize the request queues.
	srv.ResetRequestQueues()

	// Initialize the timer struct.
	timer := &Timer{}
	timer.Initialize()
	srv.timer = timer

	// If shouldRestart is true, it means that the state checksum is likely corrupted, and we need to enter a recovery mode.
	// This can happen if the node was terminated mid-operation last time it was running. The recovery process rolls back
	// blocks to the beginning of the current snapshot epoch and resets to the state checksum to the epoch checksum.
	if shouldRestart {
		if stateChangeSyncer != nil {
			stateChangeSyncer.Reset()
		}
		if !_forceChecksum && isChecksumIssue {
			glog.Warningf(CLog(Yellow, "NewServer: Not forcing a rollback to the last snapshot epoch even though the"+
				"node was not closed properly last time."))
			shouldRestart = false
		} else {
			glog.Errorf(CLog(Red, "NewServer: Forcing a rollback to the last snapshot epoch because node was not closed "+
				"properly last time"))
			return srv, errors.Wrapf(err, "NewServer: Restart required"), true
		}
	}

	return srv, nil, shouldRestart
}

func (srv *Server) _handleGetHeaders(pp *Peer, msg *MsgDeSoGetHeaders) {
	glog.V(1).Infof("Server._handleGetHeadersMessage: called with locator: (%v), "+
		"stopHash: (%v) from Peer %v", msg.BlockLocator, msg.StopHash, pp)

	// Find the most recent known block in the best block chain based
	// on the block locator and fetch all of the headers after it until either
	// MaxHeadersPerMsg have been fetched or the provided stop
	// hash is encountered. Note that the headers we return are based on
	// our best *block* chain not our best *header* chain. The reason for
	// this is that the peer will likely follow up this request by asking
	// us for the blocks corresponding to the headers and we need to be
	// able to deliver them in this case.
	//
	// Use the block after the genesis block if no other blocks in the
	// provided locator are known. This does mean the client will start
	// over with the genesis block if unknown block locators are provided.
	maxHeadersPerMsg := MaxHeadersPerMsg
	if pp.NegotiatedProtocolVersion >= ProtocolVersion2 {
		maxHeadersPerMsg = MaxHeadersPerMsgPos
	}

	headers, err := srv.GetHeadersForLocatorAndStopHash(msg.BlockLocator, msg.StopHash, maxHeadersPerMsg)
	if err != nil {
		glog.Errorf("Server._handleGetHeadersMessage: Error getting headers: %v", err)
	}

	// Send found headers to the requesting peer.
	blockTip := srv.blockchain.blockTip()
	pp.AddDeSoMessage(&MsgDeSoHeaderBundle{
		Headers:   headers,
		TipHash:   blockTip.Hash,
		TipHeight: blockTip.Height,
	}, false)
	glog.V(2).Infof("Server._handleGetHeadersMessage: Replied to GetHeaders request "+
		"with response headers: (%v), tip hash (%v), tip height (%d) from Peer %v",
		headers, blockTip.Hash, blockTip.Height, pp)
}

// GetHeadersForLocatorAndStopHash returns a list of headers given a list of locator block hashes
// and a stop hash. Note that this may be slow if the block nodes requested are not in the cache.
func (srv *Server) GetHeadersForLocatorAndStopHash(
	locator []*BlockHash,
	stopHash *BlockHash,
	maxHeadersPerMsg uint32,
) ([]*MsgDeSoHeader, error) {
	var headers []*MsgDeSoHeader

	stopNode, stopNodeExists, stopNodeError := srv.blockchain.GetBlockFromBestChainByHashAndOptionalHeight(stopHash, nil, true)
	// Special case when there is no block locator provided but only a stop hash.
	if len(locator) == 0 {
		if stopNodeError != nil || !stopNodeExists || stopNode == nil {
			return nil, fmt.Errorf("GetHeadersForLocatorAndStopHash: Stop hash provided but no stop node found")
		}
		return []*MsgDeSoHeader{stopNode.Header}, nil
	}
	var startNode *BlockNode
	var startNodeExists bool
	var startNodeError error
	for _, blockNodeHash := range locator {
		startNode, startNodeExists, startNodeError = srv.blockchain.GetBlockFromBestChainByHashAndOptionalHeight(blockNodeHash, nil, true)
		if startNodeError != nil || !startNodeExists || startNode == nil {
			glog.Errorf("GetHeadersForLocatorAndStopHash: locator provided but no block node found at %v", blockNodeHash)
		}
		if startNodeExists && startNode != nil {
			break
		}
	}
	if startNode == nil {
		return nil, fmt.Errorf("GetHeadersForLocatorAndStopHash: No start node found after looping through locators")
	}

	var backtrackingNode *BlockNode
	var backtrackingNodeExists bool
	var backtrackingNodeError error
	// If the stop node isn't provided and the max header msgs would put us past the header tip,
	// we use the header tip to start back tracking.
	if stopNode == nil && srv.blockchain.HeaderTip().Height < startNode.Height+maxHeadersPerMsg {
		backtrackingNode = srv.blockchain.HeaderTip()
		backtrackingNodeExists = true
	} else if stopNode == nil || stopNode.Height > startNode.Height+maxHeadersPerMsg {
		// If the stop node isn't provided or the stop node is more than maxHeadersPerMsg away
		// from the start node, we compute the height of the last header expected and start
		// back tracking from there.
		backtrackingNode, backtrackingNodeExists, backtrackingNodeError = srv.blockchain.GetBlockFromBestChainByHeight(
			uint64(startNode.Height+maxHeadersPerMsg), true)
		if backtrackingNodeError != nil {
			return nil, fmt.Errorf("GetHeadersForLocatorAndStopHash: Error getting backtracking node by height: %v", backtrackingNodeError)
		}
		if !backtrackingNodeExists || backtrackingNode == nil {
			return nil, errors.New("GetHeadersForLocatorAndStopHash: Backtracking node not found")
		}
	} else {
		// Otherwise, the stop node is provided and we start back tracking from the stop node.
		backtrackingNode = stopNode
	}
	for ii := uint32(0); ii < maxHeadersPerMsg; ii++ {
		// If we've back tracked all the way to the start node, exit.
		if backtrackingNode.Hash.IsEqual(startNode.Hash) {
			break
		}
		headers = append(headers, backtrackingNode.Header)
		// Avoid underflow.
		if backtrackingNode.Height < 1 {
			break
		}
		prevNodeHeight := backtrackingNode.Header.Height - 1
		backtrackingNode, backtrackingNodeExists, backtrackingNodeError = srv.blockchain.GetBlockFromBestChainByHashAndOptionalHeight(
			backtrackingNode.Header.PrevBlockHash,
			&prevNodeHeight, true)
		if backtrackingNodeError != nil {
			glog.Errorf("Server._handleGetHeadersMessage: Error getting prev node by height: %v", backtrackingNodeError)
			break
		}
		if !backtrackingNodeExists || backtrackingNode == nil {
			break
		}
	}
	return collections.Reverse(headers), nil
}

// GetSnapshot is used for sending MsgDeSoGetSnapshot messages to peers. We will
// check if the passed peer has been assigned to an in-progress prefix and if so,
// we will request a snapshot data chunk from them. Otherwise, we will assign a
// new prefix to that peer.
func (srv *Server) GetSnapshot(pp *Peer) {

	// Start the timer to measure how much time passes from a GetSnapshot msg to
	// a SnapshotData message.
	srv.timer.Start("Get Snapshot")

	var prefix []byte
	var lastReceivedKey []byte

	// We will try to determine if the provided peer has been assigned a prefix.
	// Iterate over all incomplete prefixes in the HyperSyncProgress and see if
	// any of them has been assigned to the peer.
	syncingPrefix := false
	for _, prefixProgress := range srv.HyperSyncProgress.PrefixProgress {
		if prefixProgress.Completed {
			continue
		}
		prefix = prefixProgress.Prefix
		lastReceivedKey = prefixProgress.LastReceivedKey
		syncingPrefix = true
		if prefixProgress.PrefixSyncPeer.ID == pp.ID {
			prefix = prefixProgress.Prefix
			lastReceivedKey = prefixProgress.LastReceivedKey
			syncingPrefix = true
			break
		} else {
			glog.V(1).Infof("GetSnapshot: switching peers on prefix (%v), previous peer ID (%v) "+
				"current peer ID (%v)", prefixProgress.Prefix, prefixProgress.PrefixSyncPeer.ID, pp.ID)
			// TODO: Should disable the previous sync peer here somehow

			prefixProgress.PrefixSyncPeer.ID = pp.ID
		}
	}

	// If peer isn't assigned to any prefix, we will assign him now.
	if !syncingPrefix {
		// We will assign the peer to a non-existent prefix.
		for _, prefix = range StatePrefixes.StatePrefixesList {
			exists := false
			for _, prefixProgress := range srv.HyperSyncProgress.PrefixProgress {
				if reflect.DeepEqual(prefix, prefixProgress.Prefix) {
					exists = true
					break
				}
			}
			// If prefix doesn't exist in our prefix progress struct, append new progress tracker
			// and assign it to the current peer.
			if !exists {
				srv.HyperSyncProgress.PrefixProgress = append(srv.HyperSyncProgress.PrefixProgress, &SyncPrefixProgress{
					PrefixSyncPeer:  pp,
					Prefix:          prefix,
					LastReceivedKey: prefix,
					Completed:       false,
				})
				lastReceivedKey = prefix
				syncingPrefix = true
				break
			}
		}
		// If no prefix was found, we error and return because the state is already synced.
		if !syncingPrefix {
			glog.Errorf("Server.GetSnapshot: Error selecting a prefix for peer %v "+
				"all prefixes are synced", pp)
			return
		}
	}
	// As a pace-setting mechanism, we enqueue to the operationQueueSemaphore in a go routine. The request will be blocked
	// if there are too many requests in memory.
	go func() {
		srv.snapshot.operationQueueSemaphore <- struct{}{}
		// Now send a message to the peer to fetch the snapshot chunk.
		glog.V(2).Infof("Server.GetSnapshot: Sending a GetSnapshot message to peer (%v) "+
			"with Prefix (%v) and SnapshotStartEntry (%v)", pp, prefix, lastReceivedKey)
		pp.AddDeSoMessage(&MsgDeSoGetSnapshot{
			SnapshotStartKey: lastReceivedKey,
		}, false)
	}()
}

// GetBlocksToStore is part of the archival mode, which makes the node download all historical blocks after completing
// hypersync. We will go through all blocks corresponding to the snapshot and download the blocks.
func (srv *Server) GetBlocksToStore(pp *Peer) {
	glog.V(2).Infof("GetBlocksToStore: Calling for peer (%v)", pp)

	if srv.blockchain.ChainState() != SyncStateSyncingHistoricalBlocks {
		glog.Errorf("GetBlocksToStore: Called even though all blocks have already been downloaded. This " +
			"shouldn't happen.")
		return
	}

	// Go through the block nodes in the blockchain and download the blocks if they're not stored.
	for ii := uint32(srv.blockchain.lowestBlockNotStored); ii <= srv.blockchain.blockTip().Height; ii++ {
		// TODO: this may be really slow.
		blockNode, exists, err := srv.blockchain.GetBlockFromBestChainByHeight(uint64(ii), true)
		if err != nil {
			glog.Errorf("GetBlocksToStore: Error getting block from best chain by height: %v", err)
			return
		}
		if !exists {
			glog.Errorf("GetBlocksToStore: Block at height %v not found in best chain", ii)
			return
		}
		// We find the first block that's not stored and get ready to download blocks starting from this block onwards.
		if blockNode.Status&StatusBlockStored == 0 {
			maxBlocksInFlight := MaxBlocksInFlight
			if pp.NegotiatedProtocolVersion >= ProtocolVersion2 &&
				(srv.params.IsPoSBlockHeight(uint64(blockNode.Height)) ||
					srv.params.NetworkType == NetworkType_TESTNET) {

				maxBlocksInFlight = MaxBlocksInFlightPoS
			}
			srv.blockchain.lowestBlockNotStored = uint64(blockNode.Height)
			numBlocksToFetch := maxBlocksInFlight - len(pp.requestedBlocks)
			currentHeight := uint64(blockNode.Height)
			blockNodesToFetch := []*BlockNode{}
			// In case there are blocks at tip that are already stored (which shouldn't really happen), we'll not download them.
			// We filter those out in the loop below by checking IsFullyProcessed.
			// Find the blocks that we should download.
			for len(blockNodesToFetch) < numBlocksToFetch {
				if currentHeight > uint64(srv.blockchain.blockTip().Height) {
					break
				}
				// Get the current hash and increment the height. Genesis has height 0, so currentHeight corresponds to
				// the array index.
				// TODO: this may be really slow.
				currentNode, currNodeExists, err := srv.blockchain.GetBlockFromBestChainByHeight(currentHeight, true)
				if err != nil {
					glog.Errorf("GetBlocksToStore: Error getting block from best chain by height: %v", err)
					return
				}
				if !currNodeExists {
					glog.Errorf("GetBlocksToStore: Block at height %v not found in best chain", currentHeight)
					return
				}
				currentHeight++
				// If this node is already fully processed, then we don't need to download it.
				if currentNode.Status.IsFullyProcessed() {
					break
				}

				// If we've already requested this block then we don't request it again.
				if _, exists = pp.requestedBlocks[*currentNode.Hash]; exists {
					continue
				}

				blockNodesToFetch = append(blockNodesToFetch, currentNode)
			}

			var hashList []*BlockHash
			for _, node := range blockNodesToFetch {
				hashList = append(hashList, node.Hash)
				pp.requestedBlocks[*node.Hash] = true
			}
			pp.AddDeSoMessage(&MsgDeSoGetBlocks{
				HashList: hashList,
			}, false)

			glog.V(1).Infof("GetBlocksToStore: Downloading blocks to store for header %v from peer %v",
				blockNode.Header, pp)
			return
		}
	}

	// If we get here then it means that we've downloaded all blocks so we can update
	srv.blockchain.downloadingHistoricalBlocks = false
}

// GetBlocks computes what blocks we need to fetch and asks for them from the
// corresponding peer. It is typically called after we have exited
// SyncStateSyncingHeaders.
func (srv *Server) RequestBlocksUpToHeight(pp *Peer, maxHeight int) {
	numBlocksToFetch := srv.getMaxBlocksInFlight(pp) - len(pp.requestedBlocks)
	blockNodesToFetch := srv.blockchain.GetBlockNodesToFetch(
		numBlocksToFetch, maxHeight, pp.requestedBlocks,
	)
	if len(blockNodesToFetch) == 0 {
		glog.V(1).Infof("RequestBlocksUpToHeight: No blocks to fetch from peer %v: maxBlocksInFlight: %d, peer requested blocks: %d",
			pp, srv.getMaxBlocksInFlight(pp), len(pp.requestedBlocks))
		// This can happen if, for example, we're already requesting the maximum
		// number of blocks we can. Just return in this case.
		return
	}

	// If we're here then we have some blocks to fetch so fetch them.
	hashList := []*BlockHash{}
	for _, node := range blockNodesToFetch {
		hashList = append(hashList, node.Hash)
		pp.requestedBlocks[*node.Hash] = true
	}

	pp.AddDeSoMessage(&MsgDeSoGetBlocks{HashList: hashList}, false)

	glog.V(1).Infof("RequestBlocksUpToHeight: Downloading %d blocks from header %v to header %v from peer %v",
		len(blockNodesToFetch),
		blockNodesToFetch[0].Header,
		blockNodesToFetch[len(blockNodesToFetch)-1].Header,
		pp,
	)
}

// RequestBlocksByHash requests the exact blocks specified by the block hashes from the peer.
func (srv *Server) RequestBlocksByHash(pp *Peer, blockHashes []*BlockHash) {
	numBlocksToFetch := srv.getMaxBlocksInFlight(pp) - len(pp.requestedBlocks)
	if numBlocksToFetch <= 0 {
		return
	}

	// We will only request the blocks that we haven't already requested.
	blocksToRequest := []*BlockHash{}
	for _, blockHash := range blockHashes {
		if pp.requestedBlocks[*blockHash] {
			continue
		}
		blocksToRequest = append(blocksToRequest, blockHash)
		pp.requestedBlocks[*blockHash] = true
	}

	if len(blocksToRequest) == 0 {
		return
	}

	pp.AddDeSoMessage(&MsgDeSoGetBlocks{HashList: blocksToRequest}, false)

	glog.V(1).Infof("GetBlockByHash: Downloading %d blocks from peer %v", len(blocksToRequest), pp)
}

func (srv *Server) getMaxBlocksInFlight(pp *Peer) int {
	// Fetch as many blocks as we can from this peer. If our peer is on PoS
	// then we can safely request a lot more blocks from them in each flight.
	maxBlocksInFlight := MaxBlocksInFlight
	if pp.NegotiatedProtocolVersion >= ProtocolVersion2 &&
		(srv.params.IsPoSBlockHeight(uint64(srv.blockchain.blockTip().Height)) ||
			srv.params.NetworkType == NetworkType_TESTNET) {
		maxBlocksInFlight = MaxBlocksInFlightPoS
	}
	return maxBlocksInFlight
}

// shouldVerifySignatures determines if we should verify signatures for headers or not.
// For PoW headers, this always returns true because there are no signatures to verify and there is
// no impact on syncing.
// For PoW blocks, we verify signatures if we're not syncing.
// For PoS headers and blocks, we check if we've seen the checkpoint block.
// If the checkpoint block info is nil, we return true so that we verify signatures.
// If we haven't seen the checkpoint block yet, we skip signature verification.
// If the header height does not match the checkpoint block height, we should disconnect the peer.
// Otherwise, return true.
func (srv *Server) shouldVerifySignatures(header *MsgDeSoHeader, isHeaderChain bool) (_verifySignatures bool, _shouldDisconnect bool) {
	// For PoW headers, there is no signature to verify in the header, so we return true
	// just to be safe, but it has no impact on the syncing.
	// For PoW blocks, we verify signatures if we're not syncing.
	if srv.params.IsPoWBlockHeight(header.Height) {
		if !isHeaderChain {
			return !srv.blockchain.isSyncing(), false
		}
		return true, false
	}
	// For PoS blocks, we check if we've seen the checkpoint block.
	// If we don't have a check point block info, we return true so that we verify signatures.
	checkpointBlockInfo := srv.blockchain.GetCheckpointBlockInfo()
	if checkpointBlockInfo == nil {
		return true, false
	}
	// If the current header has a height below the checkpoint block height, we should skip signature verification
	// even if we've seen the checkpoint block hash.
	if header.Height < checkpointBlockInfo.Height {
		return false, false
	}
	srv.blockchain.ChainLock.RLock()
	defer srv.blockchain.ChainLock.RUnlock()
	checkpointBlockNode, hasSeenCheckpointBlockHash, err := srv.blockchain.GetBlockFromBestChainByHashAndOptionalHeight(
		checkpointBlockInfo.Hash, &checkpointBlockInfo.Height, isHeaderChain)
	if err != nil {
		glog.Fatalf("shouldVerifySignatures: Problem getting checkpoint block node from best chain: %v", err)
	}
	// If we haven't seen the checkpoint block hash yet, we skip signature verification.
	if !hasSeenCheckpointBlockHash {
		// If we're past the checkpoint height and we haven't seen the checkpoint block, we should
		// disconnect from the peer.
		if header.Height > checkpointBlockInfo.Height {
			return true, true
		}
		return false, false
	}
	// Make sure that the header in the best chain map has the correct height, otherwise we need to disconnect this peer.
	if uint64(checkpointBlockNode.Height) != checkpointBlockInfo.Height {
		return true, true
	}
	return true, false
}

func (srv *Server) getCheckpointSyncingStatus(isHeaders bool) string {
	checkpointBlockInfo := srv.blockchain.GetCheckpointBlockInfo()
	if checkpointBlockInfo == nil {
		return "<No checkpoint block info>"
	}
	_, hasSeenCheckPointBlockHash, err := srv.blockchain.GetBlockFromBestChainByHashAndOptionalHeight(
		checkpointBlockInfo.Hash, &checkpointBlockInfo.Height, isHeaders)

	if err != nil {
		glog.Fatalf("getCheckpointSyncingStatus: Problem getting checkpoint block node from best chain: %v", err)
	}
	if !hasSeenCheckPointBlockHash {
		return fmt.Sprintf("<Checkpoint block %v not seen yet>", checkpointBlockInfo.String())
	}
	return fmt.Sprintf("<Checkpoint block %v seen>", checkpointBlockInfo.String())
}

func (srv *Server) _handleHeaderBundle(pp *Peer, msg *MsgDeSoHeaderBundle) {
	printHeight := pp.StartingBlockHeight()
	if uint64(srv.blockchain.headerTip().Height) > printHeight {
		printHeight = uint64(srv.blockchain.headerTip().Height)
	}
	glog.Infof(CLog(Yellow, fmt.Sprintf("Received header bundle with %v headers "+
		"in state %s from peer %v. Downloaded ( %v / %v ) total headers. Checkpoint syncing status: %v",
		len(msg.Headers), srv.blockchain.chainState(), pp,
		srv.blockchain.headerTip().Header.Height, printHeight, srv.getCheckpointSyncingStatus(true))))

	if glog.V(2) {
		headerStrings := collections.Transform(msg.Headers, func(header *MsgDeSoHeader) string { return header.ShortString() })
		if len(msg.Headers) < 50 {
			glog.V(2).Infof("Received headers <Height, Hash>:\n %v", strings.Join(headerStrings, "\n"))
		} else {
			glog.V(2).Infof("Received headers <Height, Hash>:\n %v", strings.Join(
				append(headerStrings[:10], headerStrings[len(headerStrings)-10:]...), "\n"))
		}
	}
	// If we get here, it means that the node is not currently running a Fast-HotStuff
	// validator or that the node is syncing. In either case, we sync headers according
	// to the blocksync rules.

	// Start by processing all the headers given to us. They should start
	// right after the tip of our header chain ideally. While going through them
	// tally up the number that we actually process.
	var blockNodeBatch []*BlockNode
	for ii, headerReceived := range msg.Headers {
		// If we've set a maximum height for node sync and we've reached it,
		// then we will not process any more headers.
		if srv.blockchain.isTipMaxed(srv.blockchain.headerTip()) {
			break
		}

		// If we encounter a duplicate header while we're still syncing then
		// the peer is misbehaving. Disconnect so we can find one that won't
		// have this issue. Hitting duplicates after we're done syncing is
		// fine and can happen in certain cases.
		headerHash, _ := headerReceived.Hash()
		hasHeader := srv.blockchain.HasHeaderByHashAndHeight(headerHash, headerReceived.Height)
		if hasHeader {
			//if srv.blockchain.isSyncing() {
			// Always log a warning if we get a duplicate header. This is useful for debugging.
			glog.Warningf("Server._handleHeaderBundle: Duplicate header %v received from peer %v "+
				"in state %s. Local header tip height %d "+
				"hash %s with duplicate %v",
				headerHash,
				pp, srv.blockchain.chainState(), srv.blockchain.headerTip().Height,
				hex.EncodeToString(srv.blockchain.headerTip().Hash[:]), headerHash)

			// TODO: This logic should really be commented back in, but there was a bug that
			// arises when a program is killed forcefully whereby a partial write leads to this
			// logic causing the sync to stall. As such, it's more trouble than it's worth
			// at the moment but we should consider being more strict about it in the future.
			/*
				pp.Disconnect()
				return
			*/
			//}

			// Don't process duplicate headers.
			continue
		}

		// If we get here then we have a header we haven't seen before.
		// check if we need to verify signatures
		verifySignatures, shouldDisconnect := srv.shouldVerifySignatures(headerReceived, true)
		if shouldDisconnect {
			glog.Errorf("Server._handleHeaderBundle: Disconnecting peer %v in state %s because a mismatch was "+
				"found between the received header height %v does not match the checkpoint block info %v",
				pp, srv.blockchain.chainState(), headerReceived.Height,
				srv.blockchain.GetCheckpointBlockInfo().String())
			pp.Disconnect("Header height mismatch with checkpoint block info")
			return
		}

		// Process the header, as we haven't seen it before, set verifySignatures to false
		// if we're in the process of syncing.
		blockNode, _, isOrphan, err := srv.blockchain.ProcessHeader(headerReceived, headerHash, verifySignatures)

		numLogHeaders := 2000
		if ii%numLogHeaders == 0 {
			glog.Infof(CLog(Cyan, fmt.Sprintf("Server._handleHeaderBundle: Processed header ( %v / %v ) from Peer %v",
				headerReceived.Height,
				msg.Headers[len(msg.Headers)-1].Height,
				pp)))
		}

		// If this header is an orphan or we encountered an error for any reason,
		// disconnect from the peer. Because every header is sent in response to
		// a GetHeaders request, the peer should know enough to never send us
		// unconnectedTxns unless it's misbehaving.
		if err != nil || isOrphan {
			glog.Errorf("Server._handleHeaderBundle: Disconnecting from peer %v in state %s "+
				"because error occurred processing header: %v, isOrphan: %v",
				pp, srv.blockchain.chainState(), err, isOrphan)

			pp.Disconnect("Error processing header")
			// Just to be safe, we flush all the headers we just got even tho we have a header.
			currTime := time.Now()
			if err = PutHeightHashToNodeInfoBatch(
				srv.blockchain.db, srv.snapshot, blockNodeBatch, false /*bitcoinNodes*/, srv.eventManager); err != nil {
				glog.Errorf("Server._handleHeaderBundle: Problem writing block nodes to db, error: (%v)", err)
				return
			}
			glog.V(0).Info("Server._handleHeaderBundle: PutHeightHashToNodeInfoBatch took: ", time.Since(currTime))
			return
		}

		// Append the block node to the block node batch.
		if blockNode != nil {
			blockNodeBatch = append(blockNodeBatch, blockNode)
		}
	}
	currTime := time.Now()
	if err := PutHeightHashToNodeInfoBatch(
		srv.blockchain.db, srv.snapshot, blockNodeBatch, false /*bitcoinNodes*/, srv.eventManager); err != nil {
		glog.Errorf("Server._handleHeaderBundle: Problem writing block nodes to db, error: (%v)", err)
		return
	}
	if len(blockNodeBatch) > 0 {
		glog.V(0).Info("Server._handleHeaderBundle: PutHeightHashToNodeInfoBatch took: ", time.Since(currTime))
	} else {
		glog.V(0).Info("Server._handleHeaderBundle: No block nodes to write to db")
	}

	// After processing all the headers this will check to see if we are fully current
	// and send a request to our Peer to start a Mempool sync if so.
	//
	// This statement makes it so that if we boot up our node such that
	// its initial state is fully current we'll always bootstrap our mempools with a
	// mempool request. The alternative is that our state is not fully current
	// when we boot up, and we cover this second case in the _handleBlock function.
	srv._tryRequestMempoolFromPeer(pp)

	// At this point we should have processed all the headers. Now we will
	// make a decision on whether to request more headers from this peer based
	// on how many headers we received in this message. Since every HeaderBundle
	// is a response to a GetHeaders request from us with a HeaderLocator embedded in it, receiving
	// anything less than MaxHeadersPerMsg headers from a peer is sufficient to
	// make us think that the peer doesn't have any more interesting headers for us.
	// On the other hand, if the request contains MaxHeadersPerMsg, it is highly
	// likely we have not hit the tip of our peer's chain, and so requesting more
	// headers from the peer would likely be useful.
	maxHeadersPerMsg := MaxHeadersPerMsg
	if pp.NegotiatedProtocolVersion >= ProtocolVersion2 {
		maxHeadersPerMsg = MaxHeadersPerMsgPos
	}
	if uint32(len(msg.Headers)) < maxHeadersPerMsg || srv.blockchain.isTipMaxed(srv.blockchain.headerTip()) {
		// If we get here it means that we've just finished syncing headers and we will proceed to
		// syncing state either through hyper sync or block sync. First let's check if the peer
		// supports hypersync and if our block tip is old enough so that it makes sense to sync state.

		if NodeCanHypersyncState(srv.cmgr.SyncType) && srv.blockchain.isHyperSyncCondition() {
			// If hypersync conditions are satisfied, we will be syncing state. This assignment results
			// in srv.blockchain.chainState() to be equal to SyncStateSyncingSnapshot
			srv.blockchain.syncingState = true
		}

		// Fetch the header tip height once before we do anything in case we need it to compute the expected
		// snapshot height.
		currentHeaderTipHeight := uint64(srv.blockchain.headerTip().Height)

		if srv.blockchain.chainState() == SyncStateSyncingSnapshot {
			glog.V(1).Infof("Server._handleHeaderBundle: *Syncing* state starting at "+
				"height %v from peer %v", srv.blockchain.headerTip().Header.Height, pp)

			// If node is a hyper sync node and we haven't finished syncing state yet, we will kick off state sync.
			if srv.cmgr.HyperSync {
				expectedSnapshotHeight := srv.computeExpectedSnapshotHeight(currentHeaderTipHeight)
				srv.blockchain.snapshot.Migrations.CleanupMigrations(expectedSnapshotHeight)

				if len(srv.HyperSyncProgress.PrefixProgress) != 0 {
					srv.GetSnapshot(pp)
					return
				}
				glog.Infof(CLog(Magenta, fmt.Sprintf("Initiating HyperSync after finishing downloading headers. Node "+
					"will quickly download a snapshot of the blockchain taken at height (%v). HyperSync will sync each "+
					"prefix of the node's KV database. Connected peer (%v). Note: State sync is a new feature and hence "+
					"might contain some unexpected behavior. If you see an issue, please report it in DeSo Github "+
					"https://github.com/deso-protocol/core.", expectedSnapshotHeight, pp)))

				// Clean all the state prefixes from the node db so that we can populate it with snapshot entries.
				// When we start a node, it first loads a bunch of seed transactions in the genesis block. We want to
				// remove these entries from the db because we will receive them during state sync.
				glog.Infof(CLog(Magenta, "HyperSync: deleting all state records. This can take a while."))
				shouldErase, err := DBDeleteAllStateRecords(srv.blockchain.db)
				if err != nil {
					glog.Errorf(CLog(Red, fmt.Sprintf("Server._handleHeaderBundle: problem while deleting state "+
						"records, error: %v", err)))
				}
				if shouldErase {
					if srv.nodeMessageChannel != nil {
						srv.nodeMessageChannel <- NodeErase
					}
					glog.Errorf(CLog(Red, fmt.Sprintf("Server._handleHeaderBundle: Records were found in the node "+
						"directory, while trying to resync. Now erasing the node directory and restarting the node. "+
						"That's faster than manually expunging all records from the database.")))
					return
				}

				// We set the expected height and hash of the snapshot from our header chain. The snapshots should be
				// taken on a regular basis every SnapshotBlockHeightPeriod number of blocks. This means we can calculate the
				// expected height at which the snapshot should be taking place. We do this to make sure that the
				// snapshot we receive from the peer is up-to-date.
				// TODO: error handle if the hash doesn't exist for some reason.
				expectedSnapshotHeightBlock, expectedSnapshotHeightblockExists, err :=
					srv.blockchain.GetBlockFromBestChainByHeight(expectedSnapshotHeight, true)
				if err != nil {
					glog.Errorf("Server._handleHeaderBundle: Problem getting expected snapshot height block, error (%v)", err)
					return
				}
				if !expectedSnapshotHeightblockExists || expectedSnapshotHeightBlock == nil {
					glog.Errorf("Server._handleHeaderBundle: Expected snapshot height block doesn't exist.")
					return
				}
				srv.HyperSyncProgress.SnapshotMetadata = &SnapshotEpochMetadata{
					SnapshotBlockHeight:       expectedSnapshotHeight,
					FirstSnapshotBlockHeight:  expectedSnapshotHeight,
					CurrentEpochChecksumBytes: []byte{},
					CurrentEpochBlockHash:     expectedSnapshotHeightBlock.Hash,
				}
				srv.HyperSyncProgress.PrefixProgress = []*SyncPrefixProgress{}
				srv.HyperSyncProgress.Completed = false
				go srv.HyperSyncProgress.PrintLoop()

				// Initialize the snapshot checksum so that it's reset. It got modified during chain initialization
				// when processing seed transaction from the genesis block. So we need to clear it.
				srv.snapshot.Checksum.ResetChecksum()
				if err = srv.snapshot.Checksum.SaveChecksum(); err != nil {
					glog.Errorf("Server._handleHeaderBundle: Problem saving snapshot to database, error (%v)", err)
				}
				// Reset the migrations along with the main checksum.
				srv.snapshot.Migrations.ResetChecksums()
				if err = srv.snapshot.Migrations.SaveMigrations(); err != nil {
					glog.Errorf("Server._handleHeaderBundle: Problem saving migration checksums to database, error (%v)", err)
				}

				// Start a timer for hyper sync. This keeps track of how long hyper sync takes in total.
				srv.timer.Start("HyperSync")

				// Now proceed to start fetching snapshot data from the peer.
				srv.GetSnapshot(pp)
				return
			}
		}

		// If we have finished syncing peer's headers, but previously we have bootstrapped the blockchain through
		// hypersync and the node has the archival mode turned on, we might need to download historical blocks.
		// We'll check if there are any outstanding historical blocks to download.
		if srv.blockchain.checkArchivalMode() {
			glog.V(1).Infof("Server._handleHeaderBundle: Syncing historical blocks because node is in " +
				"archival mode.")
			srv.blockchain.downloadingHistoricalBlocks = true
			srv.GetBlocksToStore(pp)
			if srv.blockchain.downloadingHistoricalBlocks {
				return
			}
		}

		// If we have exhausted the peer's headers but our blocks aren't current,
		// send a GetBlocks message to the peer for as many blocks as we can get.
		if srv.blockchain.chainState() == SyncStateSyncingBlocks {
			// Regardless of whether we're hypersyncing, we need to ensure that the/ FirstSnapshotBlockHeight
			// is set correctly. This ensures that we won't do unnecessary hypersync computations until we
			// absolutely have to. We
			hasSnapshotMetadata := srv.snapshot != nil && srv.snapshot.CurrentEpochSnapshotMetadata != nil
			if hasSnapshotMetadata && srv.snapshot.CurrentEpochSnapshotMetadata.FirstSnapshotBlockHeight == 0 {
				expectedSnapshotHeight := srv.computeExpectedSnapshotHeight(currentHeaderTipHeight)
				srv.snapshot.CurrentEpochSnapshotMetadata.FirstSnapshotBlockHeight = expectedSnapshotHeight
			}

			// A maxHeight of -1 tells GetBlocks to fetch as many blocks as we can
			// from this peer without worrying about how many blocks the peer actually
			// has. We can do that in this case since this usually happens during sync
			// before we've made any GetBlocks requests to the peer.
			blockTip := srv.blockchain.blockTip()
			glog.V(1).Infof("Server._handleHeaderBundle: *Syncing* blocks starting at "+
				"height %d out of %d from peer %v",
				blockTip.Header.Height+1, msg.TipHeight, pp)
			maxHeight := -1
			srv.blockchain.updateCheckpointBlockInfo()
			srv.RequestBlocksUpToHeight(pp, maxHeight)
			return
		}

		// If we have exhausted the peer's headers and our blocks are current but
		// we still need a few more blocks to line our block chain up with
		// our header chain, send the peer a GetBlocks message for blocks we're
		// positive she has.
		if srv.blockchain.chainState() == SyncStateNeedBlocksss ||
			*(srv.blockchain.blockTip().Hash) != *(srv.blockchain.headerTip().Hash) {
			// If the peer's tip is not in our blockchain then we don't request
			// any blocks from them because they're on some kind of fork that
			// we're either not aware of or that we don't think is the best chain.
			// Doing things this way makes it so that when we request blocks we
			// are 100% positive the peer has them.
			hasHeader := srv.blockchain.HasHeaderByHashAndHeight(msg.TipHash, uint64(msg.TipHeight))
			if !hasHeader {
				glog.V(0).Infof("Server._handleHeaderBundle: Peer's tip is not in our "+
					"blockchain so not requesting anything else from them. Our block "+
					"tip %v, their tip %v:%d, peer: %v",
					srv.blockchain.blockTip().Header, msg.TipHash, msg.TipHeight, pp)
				return
			}

			// At this point, we have verified that the peer's tip is in our main
			// header chain. This implies that any blocks we would request from
			// them should be available as long as they don't exceed the peer's
			// tip height.
			blockTip := srv.blockchain.blockTip()
			glog.V(0).Infof("Server._handleHeaderBundle: *Downloading* blocks starting at "+
				"block tip %v out of %d from peer %v",
				blockTip.Header, msg.TipHeight, pp)
			srv.RequestBlocksUpToHeight(pp, int(msg.TipHeight))
			return
		}

		// If we get here it means we have all the headers and blocks we need
		// so there's nothing more to do.
		glog.V(1).Infof("Server._handleHeaderBundle: Tip is up-to-date so no "+
			"need to send anything. Our block tip: %v, their tip: %v:%d, Peer: %v",
			srv.blockchain.blockTip().Header, msg.TipHash, msg.TipHeight, pp)
		return
	}

	// If we get here it means the peer sent us a full header bundle where at
	// least one of the headers contained in the bundle was new to us. When
	// this happens it means the peer likely has more headers for us to process
	// so follow up with another GetHeaders request. Set the block locator for
	// this request using the node corresponding to the last header in this
	// message. Not doing this and using our header tip instead, for example,
	// would result in us not being able to switch away from our current chain
	// even if the peer has a long fork with more work than our current header
	// chain.
	lastHash, _ := msg.Headers[len(msg.Headers)-1].Hash()
	lastHeight := msg.Headers[len(msg.Headers)-1].Height
	headerTip := srv.blockchain.headerTip()
	currentBlockTip := srv.blockchain.blockTip()
	locator, locatorHeights, err := srv.blockchain.HeaderLocatorWithNodeHashAndHeight(lastHash, lastHeight)
	if err != nil {
		glog.Warningf("Server._handleHeaderBundle: Disconnecting peer %v because "+
			"she indicated that she has more headers but the last hash %v in "+
			"the header bundle does not correspond to a block in our index.",
			pp, lastHash)
		pp.Disconnect("Last hash in header bundle not in our index")
		return
	}
	glog.V(2).Infof("Server._handleHeaderBundle: Sending GET_HEADERS message to peer %v\n"+
		"Block Locator Hashes & Heights: (%v, %v) \n"+
		"Header Tip: (%v, %v)\nBlock Tip: (%v, %v)",
		pp, locator, locatorHeights, headerTip.Hash, headerTip.Height,
		currentBlockTip.Hash, currentBlockTip.Height)
	pp.AddDeSoMessage(&MsgDeSoGetHeaders{
		StopHash:     &BlockHash{},
		BlockLocator: locator,
	}, false)
	glog.V(1).Infof("Server._handleHeaderBundle: *Syncing* headers for blocks starting at "+
		"header tip %v out of %d from peer %v",
		headerTip.Header, msg.TipHeight, pp)
	glog.V(0).Infof("Server._handleHeaderBundle: Num Headers in header chain: (header tip height: %v) ",
		srv.blockchain.blockIndex.GetHeaderTip())
}

func (srv *Server) _handleGetBlocks(pp *Peer, msg *MsgDeSoGetBlocks) {
	glog.V(1).Infof("srv._handleGetBlocks: Called with message %v from Peer %v", msg, pp)

	// Let the peer handle this
	pp.AddDeSoMessage(msg, true /*inbound*/)
}

// _handleGetSnapshot gets called whenever we receive a GetSnapshot message from a peer. This means
// a peer is asking us to send him some data from our most recent snapshot. To respond to the peer we
// will retrieve the chunk from our main and ancestral records db and attach it to the response message.
func (srv *Server) _handleGetSnapshot(pp *Peer, msg *MsgDeSoGetSnapshot) {
	glog.V(1).Infof("srv._handleGetSnapshot: Called with message %v from Peer %v", msg, pp)

	// Let the peer handle this. We will delegate this message to the peer's queue of inbound messages, because
	// fetching a snapshot chunk is an expensive operation.
	pp.AddDeSoMessage(msg, true /*inbound*/)
}

// computeExpectedSnapshotHeight computes the highest expected Hypersync snapshot height based on the
// a header tips height. The returned value is a block height < headerTipHeight that represents the
// highest block height that we expect the network to have produced a snapshot for.
func (srv *Server) computeExpectedSnapshotHeight(headerTipHeight uint64) uint64 {
	// The peer's snapshot block height period before the first PoS fork height is expected to be the
	// PoW default value. After the fork height, it's expected to be the value defined in the params.
	snapshotBlockHeightPeriod := srv.params.GetSnapshotBlockHeightPeriod(
		headerTipHeight,
		srv.snapshot.GetSnapshotBlockHeightPeriod(),
	)
	expectedSnapshotHeight := headerTipHeight - (headerTipHeight % snapshotBlockHeightPeriod)
	posSetupForkHeight := uint64(srv.params.ForkHeights.ProofOfStake1StateSetupBlockHeight)
	if headerTipHeight > posSetupForkHeight && expectedSnapshotHeight < posSetupForkHeight {
		expectedSnapshotHeight = posSetupForkHeight - (posSetupForkHeight % srv.params.DefaultPoWSnapshotBlockHeightPeriod)
	}

	return expectedSnapshotHeight
}

// _handleSnapshot gets called when we receive a SnapshotData message from a peer. The message contains
// a snapshot chunk, which is a sorted list of <key, value> pairs representing a section of the database
// at current snapshot epoch. We will set these entries in our node's database as well as update the checksum.
func (srv *Server) _handleSnapshot(pp *Peer, msg *MsgDeSoSnapshotData) {
	srv.timer.End("Get Snapshot")

	srv.timer.Start("Server._handleSnapshot Main")
	// If there are no db entries in the msg, we should also disconnect the peer. There should always be
	// at least one entry sent, which is either the empty entry or the last key we've requested.
	if srv.snapshot == nil {
		glog.Errorf("srv._handleSnapshot: Received a snapshot message from a peer but srv.snapshot is nil. " +
			"This peer shouldn't send us snapshot messages because we didn't pass the SFHyperSync flag.")
		pp.Disconnect("handleSnapshot: Snapshot message received but snapshot is nil")
		return
	}

	// If we're not syncing then we don't need the snapshot chunk so
	if srv.blockchain.ChainState() != SyncStateSyncingSnapshot {
		glog.Errorf("srv._handleSnapshot: Received a snapshot message from peer but chain is not currently syncing from "+
			"snapshot. This means peer is most likely misbehaving so we'll disconnect them. Peer: (%v)", pp)
		pp.Disconnect("handleSnapshot: Chain is not syncing from snapshot")
		return
	}

	if len(msg.SnapshotChunk) == 0 {
		// We should disconnect the peer because he is misbehaving or doesn't have the snapshot.
		glog.Errorf("srv._handleSnapshot: Received a snapshot messages with empty snapshot chunk "+
			"disconnecting misbehaving peer (%v)", pp)
		pp.Disconnect("handleSnapshot: Empty snapshot chunk received from peer")
		return
	}

	glog.V(1).Infof(CLog(Yellow, fmt.Sprintf("Received a snapshot message with entry keys (First entry: "+
		"<%v>, Last entry: <%v>), (number of entries: %v), metadata (%v), and isEmpty (%v), from Peer %v",
		msg.SnapshotChunk[0].Key, msg.SnapshotChunk[len(msg.SnapshotChunk)-1].Key, len(msg.SnapshotChunk),
		msg.SnapshotMetadata, msg.SnapshotChunk[0].IsEmpty(), pp)))

	// This is ugly but the alternative is to meticulously call FreeOperationQueueSemaphore every time
	// we return with an error, which is worse.
	chunkProcessed := false
	freeSempahoreIfChunkNotProcessed := func() {
		if !chunkProcessed {
			srv.snapshot.FreeOperationQueueSemaphore()
		}
	}
	defer freeSempahoreIfChunkNotProcessed()

	// There is a possibility that during hypersync the network entered a new snapshot epoch. We handle this case by
	// restarting the node and starting hypersync from scratch.
	if msg.SnapshotMetadata.SnapshotBlockHeight > srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight &&
		uint64(srv.blockchain.HeaderTip().Height) >= msg.SnapshotMetadata.SnapshotBlockHeight {

		// TODO: Figure out how to handle header not reaching us, yet peer is telling us that the new epoch has started.
		if srv.nodeMessageChannel != nil {
			srv.nodeMessageChannel <- NodeRestart
			glog.Infof(CLog(Yellow, fmt.Sprintf("srv._handleSnapshot: Received a snapshot metadata with height (%v) "+
				"which is greater than the hypersync progress height (%v). This can happen when the network entered "+
				"a new snapshot epoch while we were syncing. The node will be restarted to retry hypersync with new epoch.",
				msg.SnapshotMetadata.SnapshotBlockHeight, srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight)))
			return
		} else {
			glog.Errorf(CLog(Red, "srv._handleSnapshot: Trying to restart the node but nodeMessageChannel is empty, "+
				"this should never happen."))
			return
		}
	}

	// Make sure that the expected snapshot height and blockhash match the ones in received message.
	if msg.SnapshotMetadata.SnapshotBlockHeight != srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight ||
		!bytes.Equal(msg.SnapshotMetadata.CurrentEpochBlockHash[:], srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochBlockHash[:]) {

		glog.Errorf("srv._handleSnapshot: blockheight (%v) and blockhash (%v) in msg do not match the expected "+
			"hyper sync height (%v) and hash (%v)",
			msg.SnapshotMetadata.SnapshotBlockHeight, msg.SnapshotMetadata.CurrentEpochBlockHash,
			srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight, srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochBlockHash)
		pp.Disconnect("handleSnapshot: Snapshot metadata does not match expected snapshot metadata")
		return
	}

	// First find the hyper sync progress struct that matches the received message.
	var syncPrefixProgress *SyncPrefixProgress
	for _, syncProgress := range srv.HyperSyncProgress.PrefixProgress {
		if bytes.Equal(msg.Prefix, syncProgress.Prefix) {
			syncPrefixProgress = syncProgress
			break
		}
	}
	// If peer sent a message with an incorrect prefix, we should disconnect them.
	if syncPrefixProgress == nil {
		// We should disconnect the peer because he is misbehaving
		glog.Errorf("srv._handleSnapshot: Problem finding appropriate sync prefix progress "+
			"disconnecting misbehaving peer (%v)", pp)
		pp.Disconnect("handleSnapshot: Problem finding appropriate sync prefix progress")
		return
	}

	// TODO: disable checksum support?
	// If we haven't yet set the epoch checksum bytes in the hyper sync progress, we'll do it now.
	// If we did set the checksum bytes, we will verify that they match the one that peer has sent us.
	prevChecksumBytes := make([]byte, len(srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes))
	copy(prevChecksumBytes, srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes[:])
	if len(srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes) == 0 {
		srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = msg.SnapshotMetadata.CurrentEpochChecksumBytes
	} else if !reflect.DeepEqual(srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes, msg.SnapshotMetadata.CurrentEpochChecksumBytes) {
		// We should disconnect the peer because he is misbehaving
		glog.Errorf("srv._handleSnapshot: HyperSyncProgress epoch checksum bytes does not match that received from peer, "+
			"disconnecting misbehaving peer (%v)", pp)
		pp.Disconnect("handleSnapshot: Snapshot checksum bytes do not match expected checksum bytes")
		return
	}

	// dbChunk will have the entries that we will add to the database. Usually the first entry in the chunk will
	// be the same as the lastKey that we've put in the GetSnapshot request. However, if we've asked for a prefix
	// for the first time, the lastKey can be different from the first chunk entry. Also, if the prefix is empty or
	// we've exhausted all entries for a prefix, the first snapshot chunk entry can be empty.
	var dbChunk []*DBEntry
	chunkEmpty := false
	if msg.SnapshotChunk[0].IsEmpty() {
		// We send the empty DB entry whenever we've exhausted the prefix. It can only be the first entry in the
		// chunk. We set chunkEmpty to true.
		glog.Infof("srv._handleSnapshot: First snapshot chunk is empty")
		chunkEmpty = true
	} else if bytes.Equal(syncPrefixProgress.LastReceivedKey, syncPrefixProgress.Prefix) {
		// If this is the first message that we're receiving for this sync progress, the first entry in the chunk
		// is going to be equal to the prefix.
		if !bytes.HasPrefix(msg.SnapshotChunk[0].Key, msg.Prefix) {
			// We should disconnect the peer because he is misbehaving.
			glog.Errorf("srv._handleSnapshot: Snapshot chunk DBEntry key has mismatched prefix "+
				"disconnecting misbehaving peer (%v)", pp)
			srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = prevChecksumBytes
			pp.Disconnect("handleSnapshot: Snapshot chunk DBEntry key has mismatched prefix")
			return
		}
		dbChunk = append(dbChunk, msg.SnapshotChunk[0])
	} else {
		// If this is not the first message that we're receiving for this sync prefix, then the LastKeyReceived
		// should be identical to the first key in snapshot chunk. If it is not, then the peer either re-sent
		// the same payload twice, a message was dropped by the network, or he is misbehaving.
		if !bytes.Equal(syncPrefixProgress.LastReceivedKey, msg.SnapshotChunk[0].Key) {
			glog.Errorf("srv._handleSnapshot: Received a snapshot chunk that's not in-line with the sync progress "+
				"disconnecting misbehaving peer (%v)", pp)
			srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = prevChecksumBytes
			pp.Disconnect("handleSnapshot: Snapshot chunk not in-line with sync progress")
			return
		}
	}
	// Now add the remaining snapshot entries to the list of dbEntries we want to set in the DB.
	dbChunk = append(dbChunk, msg.SnapshotChunk[1:]...)

	if !chunkEmpty {
		// Check that all entries in the chunk contain the prefix, and that they are sorted. We skip the first element,
		// because we already validated it contains the prefix and we will refer to ii-1 when verifying ordering.
		for ii := 1; ii < len(dbChunk); ii++ {
			// Make sure that all dbChunk entries have the same prefix as in the message.
			if !bytes.HasPrefix(dbChunk[ii].Key, msg.Prefix) {
				// We should disconnect the peer because he is misbehaving
				glog.Errorf("srv._handleSnapshot: DBEntry key has mismatched prefix "+
					"disconnecting misbehaving peer (%v)", pp)
				srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = prevChecksumBytes
				pp.Disconnect("handleSnapshot: DBEntry key has mismatched prefix")
				return
			}
			// Make sure that the dbChunk is sorted increasingly.
			if bytes.Compare(dbChunk[ii-1].Key, dbChunk[ii].Key) != -1 {
				// We should disconnect the peer because he is misbehaving
				glog.Errorf("srv._handleSnapshot: dbChunk entries are not sorted: first entry at index (%v) with "+
					"value (%v) and second entry with index (%v) and value (%v) disconnecting misbehaving peer (%v)",
					ii-1, dbChunk[ii-1].Key, ii, dbChunk[ii].Key, pp)
				srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = prevChecksumBytes
				pp.Disconnect("handleSnapshot: dbChunk entries are not sorted")
				return
			}
		}

		// Process the DBEntries from the msg and add them to the db.
		srv.timer.Start("Server._handleSnapshot Process Snapshot")
		chunkProcessed = true
		srv.snapshot.ProcessSnapshotChunk(srv.blockchain.db, &srv.blockchain.ChainLock, dbChunk,
			srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight)
		srv.timer.End("Server._handleSnapshot Process Snapshot")
	}

	// We will update the hyper sync progress tracker struct to reflect the newly added snapshot chunk.
	// In particular, we want to update the last received key to the last key in the received chunk.
	for ii := 0; ii < len(srv.HyperSyncProgress.PrefixProgress); ii++ {
		if reflect.DeepEqual(srv.HyperSyncProgress.PrefixProgress[ii].Prefix, msg.Prefix) {
			// We found the hyper sync progress corresponding to this snapshot chunk so update the key.
			lastKey := msg.SnapshotChunk[len(msg.SnapshotChunk)-1].Key
			srv.HyperSyncProgress.PrefixProgress[ii].LastReceivedKey = lastKey

			// If the snapshot chunk is not full, it means that we've completed this prefix. In such case,
			// there is a possibility we've finished hyper sync altogether. We will break out of the loop
			// and try to determine if we're done in the next loop.
			// TODO: verify that the prefix checksum matches the checksum provided by the peer / header checksum.
			//		We'll do this when we want to implement multi-peer sync.
			if !msg.SnapshotChunkFull {
				srv.HyperSyncProgress.PrefixProgress[ii].Completed = true
				break
			} else {
				// If chunk is full it means there's more work to do, so we will resume snapshot sync.
				srv.GetSnapshot(pp)
				return
			}
		}
	}
	srv.timer.End("Server._handleSnapshot Main")

	// If we get here, it means we've finished syncing the prefix, so now we will go through all state prefixes
	// and see what's left to do.

	var completedPrefixes [][]byte
	for _, prefix := range StatePrefixes.StatePrefixesList {
		completed := false
		// Check if the prefix has been completed.
		for _, prefixProgress := range srv.HyperSyncProgress.PrefixProgress {
			if reflect.DeepEqual(prefix, prefixProgress.Prefix) {
				completed = prefixProgress.Completed
				break
			}
		}
		if !completed {
			srv.GetSnapshot(pp)
			return
		}
		completedPrefixes = append(completedPrefixes, prefix)
	}

	srv.HyperSyncProgress.printChannel <- struct{}{}
	// Wait for the snapshot thread to process all operations and print the checksum.
	srv.snapshot.WaitForAllOperationsToFinish()

	// If we get to this point it means we synced all db prefixes, therefore finishing hyper sync.
	// Do some logging.
	srv.timer.End("HyperSync")
	srv.timer.Print("Get Snapshot")
	srv.timer.Print("Server._handleSnapshot Process Snapshot")
	srv.timer.Print("Server._handleSnapshot Checksum")
	srv.timer.Print("Server._handleSnapshot prefix progress")
	srv.timer.Print("Server._handleSnapshot Main")
	srv.timer.Print("HyperSync")
	srv.snapshot.PrintChecksum("Finished hyper sync. Checksum is:")
	glog.Infof(CLog(Magenta, fmt.Sprintf("Metadata checksum: (%v)",
		srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes)))
	blockNode, exists, err := srv.blockchain.GetBlockFromBestChainByHeight(msg.SnapshotMetadata.SnapshotBlockHeight, true)
	if err != nil {
		glog.Errorf("Server._handleSnapshot: Problem getting block node by height, error (%v)", err)
		return
	}
	if !exists {
		glog.Errorf("Server._handleSnapshot: Problem getting block node by height, block node does not exist: (%v)", msg.SnapshotMetadata.SnapshotBlockHeight)
		return
	} else {
		glog.Infof(CLog(Yellow, fmt.Sprintf("Best header chain %v best block chain %v",
			blockNode, srv.blockchain.blockIndex.GetTip())))
	}
	// Verify that the state checksum matches the one in HyperSyncProgress snapshot metadata.
	// If the checksums don't match, it means that we've been interacting with a peer that was misbehaving.
	checksumBytes, err := srv.snapshot.Checksum.ToBytes()
	if err != nil {
		glog.Errorf("Server._handleSnapshot: Problem getting checksum bytes, error (%v)", err)
	}
	if reflect.DeepEqual(checksumBytes, srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes) {
		glog.Infof(CLog(Green, fmt.Sprintf("Server._handleSnapshot: State checksum matched "+
			"what was expected!")))
	} else {
		// Checksums didn't match
		glog.Errorf(CLog(Red, fmt.Sprintf("Server._handleSnapshot: The final db checksum doesn't match the "+
			"checksum received from the peer. It is likely that HyperSync encountered some unexpected error earlier. "+
			"You should report this as an issue on DeSo github https://github.com/deso-protocol/core. It is also possible "+
			"that the peer is misbehaving and sent invalid snapshot chunks. In either way, we'll restart the node and "+
			"attempt to HyperSync from the beginning. Local db checksum %v; peer's snapshot checksum %v",
			checksumBytes, srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes)))
		if srv.forceChecksum {
			// If forceChecksum is true we signal an erasure of the state and return here,
			// which will cut off the sync.
			if srv.nodeMessageChannel != nil {
				srv.nodeMessageChannel <- NodeErase
			}
			return
		} else {
			// Otherwise, if forceChecksum is false, we error but then keep going.
			glog.Errorf(CLog(Yellow, fmt.Sprintf("Server._handleSnapshot: Ignoring checksum mismatch because "+
				"--force-checksum is set to false.")))
		}
	}

	// After syncing state from a snapshot, we will sync remaining blocks. To do so, we will
	// start downloading blocks from the snapshot height up to the blockchain tip. Since we
	// already synced all the state corresponding to the sub-blockchain ending at the snapshot
	// height, we will now mark all these blocks as processed. To do so, we will iterate through
	// the blockNodes in the header chain and set them in the blockchain data structures.
	//
	// We split the db update into batches of 10,000 block nodes to avoid a single transaction
	// being too large and possibly causing an error in badger.
	glog.V(0).Infof("Server._handleSnapshot: Updating snapshot block nodes in the database")
	var blockNodeBatch []*BlockNode
	flushBlockNodeStartTime := time.Now()
	// Disable deadlock detection, as the process of flushing entries to file can take a long time and
	// if it takes longer than the deadlock detection timeout interval, it will cause an error to be thrown.
	deadlock.Opts.Disable = true
	defer func() {
		deadlock.Opts.Disable = false
	}()
	// acquire the chain lock while we update the best chain and best chain map.
	srv.blockchain.ChainLock.Lock()
	currentNode := blockNode
	currentNodeExists := true
	// Set the block tip to the snapshot height block node.
	srv.blockchain.blockIndex.setTip(currentNode)
	for currentNode.Height > 0 {
		// Do not set the StatusBlockStored flag, because we still need to download the past blocks.
		currentNode.Status |= StatusBlockProcessed
		currentNode.Status |= StatusBlockValidated
		currentNode.Status |= StatusBlockCommitted
		srv.blockchain.addNewBlockNodeToBlockIndex(currentNode)
		blockNodeBatch = append(blockNodeBatch, currentNode)
		if (srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight-uint64(currentNode.Height))%100000 == 0 {
			glog.V(0).Infof("Time to process %v of %v block nodes in %v",
				srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight-uint64(currentNode.Height),
				srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight,
				time.Since(flushBlockNodeStartTime),
			)
		}

		prevNodeHeight := uint64(currentNode.Height) - 1
		currentNode, currentNodeExists, err = srv.blockchain.GetBlockFromBestChainByHashAndOptionalHeight(currentNode.Header.PrevBlockHash, &prevNodeHeight, true)
		if err != nil {
			glog.Errorf("Server._handleSnapshot: Problem getting block node by height, error: (%v)", err)
			break
		}
		if !currentNodeExists {
			glog.Errorf("Server._handleSnapshot: Problem getting block node by height, block node does not exist")
			break
		}
		// TODO: should we adjust this value for batch sizes?
		if len(blockNodeBatch) < 25000 {
			continue
		}
		err = PutHeightHashToNodeInfoBatch(srv.blockchain.db, srv.snapshot, blockNodeBatch, false /*bitcoinNodes*/, srv.eventManager)
		if err != nil {
			glog.Errorf("Server._handleSnapshot: Problem updating snapshot block nodes, error: (%v)", err)
			break
		}
		blockNodeBatch = []*BlockNode{}
	}
	if len(blockNodeBatch) > 0 {
		err = PutHeightHashToNodeInfoBatch(srv.blockchain.db, srv.snapshot, blockNodeBatch, false /*bitcoinNodes*/, srv.eventManager)
		if err != nil {
			glog.Errorf("Server._handleSnapshot: Problem updating snapshot block nodes, error: (%v)", err)
		}
	}
	glog.V(0).Infof("Time to store %v block nodes in the database: %v",
		srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight, time.Since(flushBlockNodeStartTime))

	err = PutBestHash(srv.blockchain.db, srv.snapshot, msg.SnapshotMetadata.CurrentEpochBlockHash, ChainTypeDeSoBlock, srv.eventManager)
	if err != nil {
		glog.Errorf("Server._handleSnapshot: Problem updating best hash, error: (%v)", err)
	}
	// We also reset the in-memory snapshot cache, because it is populated with stale records after
	// we've initialized the chain with seed transactions.
	srv.snapshot.DatabaseCache, _ = collections.NewLruCache[string, []byte](int(DatabaseCacheSize))

	// If we got here then we finished the snapshot sync so set appropriate flags.
	srv.blockchain.syncingState = false
	srv.blockchain.snapshot.CurrentEpochSnapshotMetadata = srv.HyperSyncProgress.SnapshotMetadata

	// Update the snapshot epoch metadata in the snapshot DB.
	for ii := 0; ii < MetadataRetryCount; ii++ {
		srv.snapshot.SnapshotDbMutex.Lock()
		err = srv.snapshot.mainDb.Update(func(txn *badger.Txn) error {
			return txn.Set(getMainDbPrefix(_prefixLastEpochMetadata), srv.snapshot.CurrentEpochSnapshotMetadata.ToBytes())
		})
		srv.snapshot.SnapshotDbMutex.Unlock()
		if err != nil {
			glog.Errorf("server._handleSnapshot: Problem setting snapshot epoch metadata in snapshot db, error (%v)", err)
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}

	// Update the snapshot status in the DB.
	srv.snapshot.Status.CurrentBlockHeight = msg.SnapshotMetadata.SnapshotBlockHeight
	srv.snapshot.Status.SaveStatus()

	// Unlock chain lock now that we're done modifying the chain state.
	srv.blockchain.ChainLock.Unlock()

	glog.Infof("server._handleSnapshot: FINAL snapshot checksum is (%v) (%v)",
		srv.snapshot.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes,
		hex.EncodeToString(srv.snapshot.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes))

	// Take care of any callbacks that need to run once the snapshot is completed.
	srv.eventManager.snapshotCompleted()

	// Now sync the remaining blocks.
	if srv.blockchain.archivalMode {
		srv.blockchain.downloadingHistoricalBlocks = true
		srv.GetBlocksToStore(pp)
		return
	}

	headerTip := srv.blockchain.headerTip()
	srv.RequestBlocksUpToHeight(pp, int(headerTip.Height))
}

func (srv *Server) _startSync() {
	// Return now if we're already syncing.
	if srv.SyncPeer != nil {
		glog.V(2).Infof("Server._startSync: Not running because SyncPeer != nil")
		return
	}
	glog.V(1).Infof("Server._startSync: Attempting to start sync")

	// Set our tip to be the best header tip rather than the best block tip. Using
	// the block tip instead might cause us to select a peer who is missing blocks
	// for the headers we've downloaded.
	bestHeight := srv.blockchain.headerTip().Height

	// Find a peer with StartingHeight bigger than our best header tip.
	var bestPeer *Peer
	for _, peer := range srv.cmgr.GetAllPeers() {
		// If connectIps is set, only sync from persistent peers.
		if len(srv.connectIps) > 0 && !peer.IsPersistent() {
			glog.Infof("Server._startSync: Connect-ips is set, so non-persistent peer is not a "+
				"sync candidate %v", peer)
			continue
		}

		if !peer.IsSyncCandidate() {
			glog.Infof("Peer is not sync candidate: %v (isOutbound: %v)", peer, peer.isOutbound)
			continue
		}

		// Choose the peer with the best height out of everyone who's a
		// valid sync candidate.
		if peer.StartingBlockHeight() < uint64(bestHeight) {
			continue
		}

		// TODO: Choose best peers based on ping time and/or the highest
		// starting block height. For now, keeping it simple and just choosing
		// the last one we iterate over with a block height larger than our best.
		bestPeer = peer
	}

	if bestPeer == nil {
		glog.V(1).Infof("Server._startSync: No sync peer candidates available")
		return
	}

	// Note we don't need to reset requestedBlocks when the SyncPeer changes
	// since we update requestedBlocks when a Peer disconnects to remove any
	// blocks that are currently being requested. This means that either a
	// still-connected Peer will eventually deliver the blocks OR we'll eventually
	// disconnect from that Peer, removing the blocks we requested from her from
	// requestedBlocks, which will cause us to re-download them again after.

	// Regardless of what our SyncState is, always start by sending a GetHeaders
	// message to our SyncPeer. This ensures that our header chains are in-sync
	// before we start requesting blocks. If we were to go directly to fetching
	// blocks from our SyncPeer without doing this first, we wouldn't be 100%
	// sure that she has them.
	glog.V(1).Infof("Server._startSync: Syncing headers to height %d from peer %v",
		bestPeer.StartingBlockHeight(), bestPeer)

	// Send a GetHeaders message to the Peer to start the headers sync.
	// Note that we include an empty BlockHash as the stopHash to indicate we want as
	// many headers as the Peer can give us.
	locator, locatorHeights := bestPeer.srv.blockchain.LatestHeaderLocator()
	headerTip := bestPeer.srv.blockchain.headerTip()
	currentBlockTip := bestPeer.srv.blockchain.blockTip()
	glog.V(2).Infof("Server._startSync: Sending GET_HEADERS message to peer %v\n"+
		"Block Locator Hashes & Heights: (%v, %v)\n"+
		"Header Tip: (%v, %v)\nBlock Tip: (%v, %v)",
		bestPeer, locator, locatorHeights, headerTip.Hash, headerTip.Height,
		currentBlockTip.Hash, currentBlockTip.Height)
	bestPeer.AddDeSoMessage(&MsgDeSoGetHeaders{
		StopHash:     &BlockHash{},
		BlockLocator: locator,
	}, false)
	glog.V(1).Infof("Server._startSync: Downloading headers for blocks starting at "+
		"header tip height %v from peer %v", bestHeight, bestPeer)

	srv.SyncPeer = bestPeer
}

func (srv *Server) HandleAcceptedPeer(rn *RemoteNode) {
	if rn == nil || rn.GetPeer() == nil {
		return
	}

	pp := rn.GetPeer()
	pp.SetServiceFlag(rn.GetServiceFlag())
	pp.SetLatestBlockHeight(rn.GetLatestBlockHeight())

	isSyncCandidate := pp.IsSyncCandidate()
	isSyncing := srv.blockchain.isSyncing()
	chainState := srv.blockchain.chainState()
	glog.V(1).Infof("Server.HandleAcceptedPeer: Processing NewPeer: (%v); IsSyncCandidate(%v), "+
		"syncPeerIsNil=(%v), IsSyncing=(%v), ChainState=(%v)",
		pp, isSyncCandidate, (srv.SyncPeer == nil), isSyncing, chainState)

	// Request a mempool sync if we're ready
	srv._tryRequestMempoolFromPeer(pp)

	// Start syncing by choosing the best candidate.
	if isSyncCandidate && srv.SyncPeer == nil {
		srv._startSync()
	}

	if !isSyncCandidate {
		glog.Infof("Peer is not sync candidate: %v (isOutbound: %v)", pp, pp.isOutbound)
	}
}

func (srv *Server) maybeRequestAddresses(remoteNode *RemoteNode) {
	if remoteNode == nil {
		return
	}
	// If the address manager needs more addresses, then send a GetAddr message
	// to the peer. This is best-effort.
	if !srv.AddrMgr.NeedMoreAddresses() {
		return
	}

	if err := remoteNode.SendMessage(&MsgDeSoGetAddr{}); err != nil {
		glog.Errorf("Server.maybeRequestAddresses: Problem sending GetAddr message to "+
			"remoteNode (id= %v); err: %v", remoteNode, err)
	}
}

func (srv *Server) _cleanupDonePeerState(pp *Peer) {
	// Grab the dataLock since we'll be modifying requestedBlocks
	srv.dataLock.Lock()
	defer srv.dataLock.Unlock()

	// Choose a new Peer to switch our queued and in-flight requests to. If no Peer is
	// found, just remove any requests queued or in-flight for the disconnecting Peer
	// and return.
	//
	// If we find a newPeer, reassign in-flight and queued requests to this Peer and
	// re-request them if we have room in our in-flight list.

	// If the newPeer exists but doesn't have these transactions, they will
	// simply reply with an empty TransactionBundle
	// for each GetTransactions we send them. This will result in the
	// requests eventually expiring, which will cause us to remove them from
	// inventoryProcessed and potentially get the data from another Peer in the future.
	//
	// TODO: Sending a sync/mempool message to a random Peer periodically seems like it would
	// be a good way to fill any gaps.
	newPeer := srv.cmgr.RandomPeer()
	if newPeer == nil || !newPeer.canReceiveInvMessages {
		// If we don't have a new Peer or the new peer can't receive INV messages,
		// remove everything that was destined for this Peer. Note we don't need to
		// copy the iterator because everything below doesn't take a reference to it.
		for hashIter, requestInfo := range srv.requestedTransactionsMap {
			hash := hashIter
			if requestInfo.PeerWhoSentInv.ID == pp.ID {
				srv._removeRequest(&hash)
			}
		}
		return
	}

	// If we get here then we know we have a valid newPeer so re-assign all the
	// queued requests to newPeer.

	// Now deal with transactions. They don't have a queue and so all we need to do
	// is reassign the requests that were in-flight to the old Peer and then make
	// the requests to the newPeer.
	txnHashesReassigned := []*BlockHash{}
	for hashIter, requestInfo := range srv.requestedTransactionsMap {
		// Don't do anything if the requests are not meant for the Peer
		// we're disconnecting to the new Peer.
		if requestInfo.PeerWhoSentInv.ID != pp.ID {
			continue
		}
		// Make a copy of the hash so we can take a pointer to it.
		hashCopy := &BlockHash{}
		copy(hashCopy[:], hashIter[:])

		// We will be sending this request to the new peer so update the info
		// to reflect that.
		requestInfo.PeerWhoSentInv = newPeer
		requestInfo.TimeRequested = time.Now()
		txnHashesReassigned = append(txnHashesReassigned, hashCopy)
	}
	if len(txnHashesReassigned) > 0 {
		// Request any hashes we might have reassigned in a goroutine to keep things
		// moving.
		newPeer.AddDeSoMessage(&MsgDeSoGetTransactions{
			HashList: txnHashesReassigned,
		}, false)
	}
}

func (srv *Server) _handleDisconnectedPeerMessage(pp *Peer) {
	glog.V(1).Infof("Server._handleDisconnectedPeerMessage: Processing DonePeer: %v", pp)

	srv._cleanupDonePeerState(pp)

	// Attempt to find a new peer to sync from if the quitting peer is the sync peer.
	// We need to refresh the sync peer regardless of whether we're syncing or not.
	// In the event that we fall behind, this allows us to switch to a peer allows us
	// to continue syncing.
	if srv.SyncPeer != nil && srv.SyncPeer.ID == pp.ID {
		srv.SyncPeer = nil
		srv._startSync()
	}
}

func (srv *Server) _relayTransactions() {
	// For each peer, compute the transactions they're missing from the mempool and
	// send them an inv.
	allPeers := srv.cmgr.GetAllPeers()

	// Get the current mempool. This can be the PoW or PoS mempool depending on the
	// current block height.
	mempool := srv.GetMempool()

	glog.V(3).Infof("Server._relayTransactions: Waiting for mempool readOnlyView to regenerate")
	mempool.BlockUntilReadOnlyViewRegenerated()
	glog.V(3).Infof("Server._relayTransactions: Mempool view has regenerated")

	// We pull the transactions from either the PoW mempool or the PoS mempool depending
	// on the current block height.
	txnList := mempool.GetTransactions()

	for _, pp := range allPeers {
		if !pp.canReceiveInvMessages {
			glog.V(3).Infof("Skipping invs for peer %v because not ready "+
				"yet: %v", pp, pp.canReceiveInvMessages)
			continue
		}
		// For each peer construct an inventory message that excludes transactions
		// for which the minimum fee is below what the Peer will allow.
		invMsg := &MsgDeSoInv{}
		for _, newTxn := range txnList {
			if !newTxn.IsValidated() {
				continue
			}

			invVect := &InvVect{
				Type: InvTypeTx,
				Hash: *newTxn.Hash,
			}

			// If the peer has this txn already then skip it.
			if pp.knownInventory.Contains(*invVect) {
				continue
			}

			// Add the transaction to the peer's known inventory. We do
			// it here when we enqueue the message to the peers outgoing
			// message queue so that we don't have to remember to do it later.
			pp.knownInventory.Put(*invVect)
			invMsg.InvList = append(invMsg.InvList, invVect)
		}
		if len(invMsg.InvList) > 0 {
			pp.AddDeSoMessage(invMsg, false)
		}
	}

	glog.V(3).Infof("Server._relayTransactions: Relay to all peers is complete!")
}

func (srv *Server) _addNewTxn(pp *Peer, txn *MsgDeSoTxn, rateLimit bool) ([]*MsgDeSoTxn, error) {

	if srv.ReadOnlyMode {
		err := fmt.Errorf("Server._addNewTxnAndRelay: Not processing txn from peer %v "+
			"because peer is in read-only mode: %v", pp, srv.ReadOnlyMode)
		glog.V(1).Infof(err.Error())
		return nil, err
	}

	srv.blockchain.ChainLock.RLock()
	tipHeight := uint64(srv.blockchain.BlockTip().Height)
	chainState := srv.blockchain.chainState()
	srv.blockchain.ChainLock.RUnlock()

	if chainState != SyncStateFullyCurrent && !srv.blockchain.params.IsPoSBlockHeight(tipHeight) {
		// We allow txn relay if chain is fully current OR the chain is running PoS.
		// Otherwise, we error.
		err := fmt.Errorf("Server._addNewTxnAndRelay: Cannot process txn "+
			"from peer %v while syncing: %v %v", pp, srv.blockchain.chainState(), txn.Hash())
		glog.Error(err)
		return nil, err
	}

	glog.V(1).Infof("Server._addNewTxnAndRelay: txn: %v, peer: %v", txn, pp)

	// Try and add the transaction to the mempool.
	peerID := uint64(0)
	if pp != nil {
		peerID = pp.ID
	}

	// Refresh TipHeight.
	srv.blockchain.ChainLock.RLock()
	tipHeight = uint64(srv.blockchain.BlockTip().Height)
	srv.blockchain.ChainLock.RUnlock()

	// Only attempt to add the transaction to the PoW mempool if we're on the
	// PoW protocol. If we're on the PoW protocol, then we use the PoW mempool's,
	// txn validity checks to signal whether the txn has been added or not.
	if uint64(tipHeight) < srv.params.GetFinalPoWBlockHeight() {
		_, err := srv.mempool.ProcessTransaction(txn, true, rateLimit, peerID, true)
		if err != nil {
			return nil, errors.Wrapf(err, "Server._addNewTxn: Problem adding transaction to mempool: ")
		}

		glog.V(1).Infof("Server._addNewTxn: newly accepted txn: %v, Peer: %v", txn, pp)
	}

	// Always add the txn to the PoS mempool. This will usually succeed if the txn
	// addition into the PoW mempool succeeded above. However, we only return an error
	// here if the block height is at or above the final PoW block height. In the event
	// of an edge case where txns in the mempool are reordered, it is possible for the
	// txn addition into the PoW mempool to succeed, while the addition into the PoS
	// mempool fails. This error handling catches that and gives the user the correct
	// feedback on the txn addition's success.
	if err := srv.posMempool.AddTransaction(txn, time.Now()); err != nil {
		if uint64(tipHeight) >= srv.params.GetFinalPoWBlockHeight() {
			return nil, errors.Wrapf(err, "Server._addNewTxn: problem adding txn to pos mempool")
		}
	}

	return []*MsgDeSoTxn{txn}, nil
}

// It's assumed that the caller will hold the ChainLock for reading so
// that the mempool transactions don't shift under our feet.
func (srv *Server) _handleBlockMainChainConnectedd(event *BlockEvent) {
	blk := event.Block

	// Don't do anything mempool-related until our best block chain is done
	// syncing.
	//
	// We add a second check as an edge-case to protect against when
	// this function is called with an uninitialized blockchain object. This
	// can happen during initChain() for example.
	if srv.blockchain == nil || !srv.blockchain.isInitialized || srv.blockchain.isSyncing() {
		return
	}

	// If we're current, update the mempool to remove the transactions
	// in this block from it. We can't do this in a goroutine because we
	// need each mempool update to happen in the same order as that in which
	// we connected the blocks and this wouldn't be guaranteed if we kicked
	// off a goroutine for each update.
	srv.mempool.UpdateAfterConnectBlock(blk)
	srv.posMempool.OnBlockConnected(blk)

	if err := srv._updatePosMempoolAfterTipChange(); err != nil {
		glog.Errorf("Server._handleBlockMainChainDisconnected: Problem updating pos mempool after tip change: %v", err)
	}

	blockHash, _ := blk.Header.Hash()
	glog.V(1).Infof("_handleBlockMainChainConnected: Block %s height %d connected to "+
		"main chain and chain is current.", hex.EncodeToString(blockHash[:]), blk.Header.Height)
}

// It's assumed that the caller will hold the ChainLock for reading so
// that the mempool transactions don't shift under our feet.
func (srv *Server) _handleBlockMainChainDisconnectedd(event *BlockEvent) {
	blk := event.Block

	// Don't do anything mempool-related until our best block chain is done
	// syncing.
	if srv.blockchain.isSyncing() {
		return
	}

	// If we're current, update the mempool to add back the transactions
	// in this block. We can't do this in a goroutine because we
	// need each mempool update to happen in the same order as that in which
	// we connected the blocks and this wouldn't be guaranteed if we kicked
	// off a goroutine for each update.
	srv.mempool.UpdateAfterDisconnectBlock(blk)
	srv.posMempool.OnBlockDisconnected(blk)

	if err := srv._updatePosMempoolAfterTipChange(); err != nil {
		glog.Errorf("Server._handleBlockMainChainDisconnected: Problem updating pos mempool after tip change: %v", err)
	}

	blockHash, _ := blk.Header.Hash()
	glog.V(1).Infof("_handleBlockMainChainDisconnect: Block %s height %d disconnected from "+
		"main chain and chain is current.", hex.EncodeToString(blockHash[:]), blk.Header.Height)
}

// _updatePosMempoolAfterTipChange updates the PoS mempool's latest UtxoView, block height, and
// global params.
func (srv *Server) _updatePosMempoolAfterTipChange() error {
	// Update the PoS mempool's global params
	currentBlockHeight := srv.blockchain.BlockTip().Height
	currentUtxoView, err := srv.blockchain.GetUncommittedTipView()
	if err != nil {
		return err
	}

	currentGlobalParams := currentUtxoView.GetCurrentGlobalParamsEntry()
	srv.posMempool.UpdateLatestBlock(currentUtxoView, uint64(currentBlockHeight))
	srv.posMempool.UpdateGlobalParams(currentGlobalParams)

	return nil
}

// _tryRequestMempoolFromPeer checks if the blockchain is current or in the steady state. If so,
// it sends a MsgDeSoMempool to request the peer's mempool. After this point, the peer will send
// us inv messages for transactions that we don't have in our mempool.
func (srv *Server) _tryRequestMempoolFromPeer(pp *Peer) {
	// If the peer is nil, then there's nothing to do.
	if pp == nil {
		glog.V(1).Infof("Server._tryRequestMempoolFromPeer: NOT sending mempool message because peer is nil: %v", pp)
		return
	}

	// If we have already requested the mempool from the peer, then there's nothing to do.
	if pp.hasReceivedMempoolMessage {
		glog.V(2).Infof(
			"Server._tryRequestMempoolFromPeer: NOT sending mempool message because we have already sent one: %v", pp,
		)
		return
	}

	// If the node was only configured to sync to a certain block height, then there's nothing to do.
	if srv.blockchain.MaxSyncBlockHeight != 0 {
		return
	}

	// We are OK to request the peer's mempool as long as the chain is current or we are running the
	// FastHotStuffConsensus in the steady state.
	isChainCurrent := srv.blockchain.chainState() == SyncStateFullyCurrent
	isRunningFastHotStuffConsensus := srv.fastHotStuffConsensus != nil && srv.fastHotStuffConsensus.IsRunning()

	if isChainCurrent || isRunningFastHotStuffConsensus {
		glog.V(1).Infof("Server._tryRequestMempoolFromPeer: Sending mempool message: %v", pp)
		pp.AddDeSoMessage(&MsgDeSoMempool{}, false)
	} else {
		glog.V(1).Infof(
			"Server._tryRequestMempoolFromPeer: NOT sending mempool message. The node is still syncing: %v, %v",
			srv.blockchain.chainState(),
			pp,
		)
	}
}

func (srv *Server) _handleBlockAccepted(event *BlockEvent) {
	blk := event.Block

	// Don't relay blocks until our best block chain is done syncing.
	if srv.blockchain.isSyncing() || srv.blockchain.MaxSyncBlockHeight > 0 {
		return
	}

	// Construct an inventory vector to relay to peers.
	blockHash, _ := blk.Header.Hash()
	invVect := &InvVect{
		Type: InvTypeBlock,
		Hash: *blockHash,
	}

	// Iterate through all non-validator peers and relay the InvVect to them.
	// This will only actually be relayed if it's not already in the peer's knownInventory.
	allNonValidators := srv.networkManager.GetAllNonValidators()
	for _, remoteNode := range allNonValidators {
		remoteNode.sendMessage(&MsgDeSoInv{
			InvList: []*InvVect{invVect},
		})
	}
}

func (srv *Server) _logAndDisconnectPeer(pp *Peer, blockMsg *MsgDeSoBlock, suffix string) {
	// Disconnect the Peer. Generally-speaking, disconnecting from the peer will cause its
	// requested blocks and txns to be removed from the global maps and cause it to be
	// replaced by another peer. Furthermore,
	// if we're in the process of syncing our node, the startSync process will also
	// be restarted as a resul. If we're not syncing our peer and have instead reached
	// the steady-state, then the next interesting inv message should cause us to
	// fetch headers, blocks, etc. So we'll be back.
	glog.Errorf("Server._handleBlock: Encountered an error processing "+
		"block %v. Disconnecting from peer %v: %s", blockMsg, pp, suffix)
	pp.Disconnect("Problem processing block")
}

// This function handles a single block that we receive from our peer. Originally, we would receive blocks
// one by one from our peer. However, now we receive a batch of blocks all at once via _handleBlockBundle,
// which then calls this function to process them one by one on our side.
//
// isLastBlock indicates that this is the last block in the list of blocks we received back
// via a MsgDeSoBlockBundle message. When we receive a single block, isLastBlock will automatically
// be true, which will give it its old single-block behavior.
func (srv *Server) _handleBlock(pp *Peer, blk *MsgDeSoBlock, isLastBlock bool) {
	srv.timer.Start("Server._handleBlock: General")

	// Pull out the header for easy access.
	blockHeader := blk.Header
	if blockHeader == nil {
		// Should never happen but check it nevertheless.
		srv._logAndDisconnectPeer(pp, blk, "Header was nil")
		return
	}

	// If we've set a maximum sync height and we've reached that height, then we will
	// stop accepting new blocks.
	blockTip := srv.blockchain.blockTip()
	if srv.blockchain.isTipMaxed(blockTip) && blockHeader.Height > uint64(blockTip.Height) {
		glog.Infof("Server._handleBlock: Exiting because block tip is maxed out")
		return
	}

	// Compute the hash of the block. If the hash computation fails, then we log an error and
	// disconnect from the peer. The block is obviously bad.
	blockHash, err := blk.Header.Hash()
	if err != nil {
		srv._logAndDisconnectPeer(pp, blk, "Problem computing block hash")
		return
	}

	// Unless we're running a PoS validator, we should not expect to see a block that we did not request. If
	// we see such a block, then we log an error and disconnect from the peer.
	_, isRequestedBlock := pp.requestedBlocks[*blockHash]
	if srv.fastHotStuffConsensus == nil && !isRequestedBlock {
		srv._logAndDisconnectPeer(pp, blk, "Getting a block that we haven't requested before")
		return
	}

	// Delete the block from the requested blocks map. We do this whether the block was requested or not.
	delete(pp.requestedBlocks, *blockHash)

	// Check that the mempool has not received a transaction that would forbid this block's signature pubkey.
	// This is a minimal check, a more thorough check is made in the ProcessBlock function. This check is
	// necessary because the ProcessBlock function only has access to mined transactions. Therefore, if an
	// attacker were to prevent a "forbid X pubkey" transaction from mining, they could force nodes to continue
	// processing their blocks.
	if len(srv.blockchain.trustedBlockProducerPublicKeys) > 0 && blockHeader.Height >= srv.blockchain.trustedBlockProducerStartHeight {
		if blk.BlockProducerInfo != nil {
			_, entryExists := srv.mempool.readOnlyUtxoView.ForbiddenPubKeyToForbiddenPubKeyEntry[MakePkMapKey(
				blk.BlockProducerInfo.PublicKey)]
			if entryExists {
				srv._logAndDisconnectPeer(pp, blk, "Got forbidden block signature public key.")
				return
			}
		}
	}
	srv.timer.End("Server._handleBlock: General")
	srv.timer.Start("Server._handleBlock: Process Block")

	// check if we should verify signatures or not.
	verifySignatures, shouldDisconnect := srv.shouldVerifySignatures(blk.Header, false)
	if shouldDisconnect {
		glog.Errorf("Server._handleHeaderBundle: Disconnecting peer %v in state %s because a mismatch was "+
			"found between the received header height %v does not match the checkpoint block info %v",
			pp, srv.blockchain.chainState(), blk.Header.Height,
			srv.blockchain.GetCheckpointBlockInfo().Hash.String())
		pp.Disconnect("Mismatch between received header height and checkpoint block info")
		return
	}

	var isOrphan bool
	var blockHashesToRequest []*BlockHash

	// Process the block using the FastHotStuffConsensus or through the blockchain directly. If we're in the
	// PoS steady state, we pass the block to the FastHotStuffConsensus to handle the block. If we're still
	// syncing, then we pass the block to the blockchain to handle the block with signature verification on or off.
	if srv.fastHotStuffConsensus != nil && srv.fastHotStuffConsensus.IsRunning() {
		// If the FastHotStuffConsensus has been initialized, then we pass the block to the new consensus
		// which will validate the block, try to apply it, and handle the orphan case by requesting missing
		// parents.
		glog.V(0).Infof(CLog(Cyan, fmt.Sprintf(
			"Server._handleBlock: Processing block %v with FastHotStuffConsensus with SyncState=%v for peer %v",
			blk, srv.blockchain.chainState(), pp,
		)))
		blockHashesToRequest, err = srv.fastHotStuffConsensus.HandleBlock(pp, blk)
		isOrphan = len(blockHashesToRequest) > 0
	} else if !verifySignatures {
		glog.V(0).Infof(CLog(Cyan, fmt.Sprintf(
			"Server._handleBlock: Processing block %v WITHOUT signature checking because SyncState=%v for peer %v",
			blk, srv.blockchain.chainState(), pp,
		)))
		_, isOrphan, blockHashesToRequest, err = srv.blockchain.ProcessBlock(blk, false)
	} else {
		// TODO: Signature checking slows things down because it acquires the ChainLock.
		// The optimal solution is to check signatures in a way that doesn't acquire the
		// ChainLock, which is what Bitcoin Core does.
		glog.V(0).Infof(CLog(Cyan, fmt.Sprintf(
			"Server._handleBlock: Processing block %v WITH signature checking because SyncState=%v for peer %v",
			blk, srv.blockchain.chainState(), pp,
		)))
		_, isOrphan, blockHashesToRequest, err = srv.blockchain.ProcessBlock(blk, true)
	}

	// If we hit an error then abort mission entirely. We should generally never
	// see an error with a block from a peer.
	if err != nil {
		if strings.Contains(err.Error(), "RuleErrorDuplicateBlock") {
			// Just warn on duplicate blocks but don't disconnect the peer.
			// TODO: This assuages a bug similar to the one referenced in the duplicate
			// headers comment above but in the future we should probably try and figure
			// out a way to be more strict about things.
			glog.Warningf("Got duplicate block %v from peer %v", blk, pp)
		} else if strings.Contains(err.Error(), RuleErrorFailedSpamPreventionsCheck.Error()) {
			// If the block fails the spam prevention check, then it must be signed by the
			// bad block proposer signature or it has a bad QC. In either case, we should
			// disconnect the peer.
			srv._logAndDisconnectPeer(pp, blk, errors.Wrapf(err, "Error while processing block at height %v: ", blk.Header.Height).Error())
			return
		} else {
			// For any other error, we log the error and continue.
			glog.Errorf("Server._handleBlock: Error while processing block at height %v: %v", blk.Header.Height, err)
			return
		}
	}

	srv.timer.End("Server._handleBlock: Process Block")

	srv.timer.Print("Server._handleBlock: General")
	srv.timer.Print("Server._handleBlock: Process Block")

	// If we're not at the last block yet, then we're done. The rest of this code is only
	// relevant after we've connected the last block, and it generally involves fetching
	// more data from our peer.
	if !isLastBlock {
		return
	}

	if isOrphan {
		// It's possible to receive an orphan block from the peer for a variety of reasons. If we
		// see an orphan block, we do one of two things:
		// 1. With the PoS protocol where it is possible to receive an orphan from the block producer
		//    for any number of reasons, the ProcessBlockPoS returns a non-empty blockHashesToRequest list
		//    for us to request from the peer.
		// 2. With the PoW protocol where we do not expect to ever receive an orphan block due to how
		//    we request header first before requesting blocks, we disconnect from the peer.

		glog.Warningf("ERROR: Received orphan block with hash %v height %v.", blockHash, blk.Header.Height)

		// Request the missing blocks from the peer if needed.
		if len(blockHashesToRequest) > 0 {
			glog.Warningf(
				"Server._handleBlock: Orphan block %v at height %d. Requesting missing ancestors from peer: %v",
				blockHash,
				blk.Header.Height,
				pp,
			)
			srv.RequestBlocksByHash(pp, blockHashesToRequest)
		} else {
			// If we don't have any blocks to request, then we disconnect from the peer.
			srv._logAndDisconnectPeer(pp, blk, "Received orphan block")
		}

		return
	}

	// We shouldn't be receiving blocks while syncing headers, but we can end up here
	// if it took longer than MaxTipAge to sync blocks to this point. We'll revert to
	// syncing headers and then resume syncing blocks once we're current again.
	if srv.blockchain.chainState() == SyncStateSyncingHeaders {
		glog.Warningf("Server._handleBlock: Received block while syncing headers: %v", blk)
		glog.Infof("Requesting headers: %v", pp)

		locator, locatorHeights := pp.srv.blockchain.LatestHeaderLocator()
		headerTip := pp.srv.blockchain.headerTip()
		currentBlockTip := pp.srv.blockchain.blockTip()
		glog.V(2).Infof("Server._handleBlock (chainState = SYNCING_HEADERS): Sending GET_HEADERS message to peer %v\n"+
			"Block Locator Hashes & Heights: (%v, %v) \n"+
			"Header Tip: (%v, %v)\nBlock Tip: (%v, %v)",
			pp, locator, locatorHeights, headerTip.Hash, headerTip.Height,
			currentBlockTip.Hash, currentBlockTip.Height)
		pp.AddDeSoMessage(&MsgDeSoGetHeaders{
			StopHash:     &BlockHash{},
			BlockLocator: locator,
		}, false)
		glog.V(1).Infof("Server._handleHeaderBundle: *Syncing* headers for blocks starting at "+
			"header tip %v from peer %v",
			srv.blockchain.HeaderTip(), pp)
		return
	}

	if srv.blockchain.chainState() == SyncStateSyncingHistoricalBlocks {
		srv.GetBlocksToStore(pp)
		if srv.blockchain.downloadingHistoricalBlocks {
			return
		}
	}

	// If we're syncing blocks, call GetBlocks and try to get as many blocks
	// from our peer as we can. This allows the initial block download to be
	// more incremental since every time we're able to accept a block (or
	// group of blocks) we indicate this to our peer so they can send us more.
	if srv.blockchain.chainState() == SyncStateSyncingBlocks {
		// Setting maxHeight = -1 gets us as many blocks as we can get from our
		// peer, which is OK because we can assume the peer has all of them when
		// we're syncing.
		maxHeight := -1
		srv.RequestBlocksUpToHeight(pp, maxHeight)
		return
	}

	if srv.blockchain.chainState() == SyncStateNeedBlocksss {
		// If we don't have any blocks to wait for anymore, hit the peer with
		// a GetHeaders request to see if there are any more headers we should
		// be aware of. This will generally happen in two cases:
		// - With our sync peer after we’re almost at the end of syncing blocks.
		//   In this case, calling GetHeaders once the requestedblocks is almost
		//   gone will result in us getting all of the remaining blocks right up
		//   to the tip and then stopping, which is exactly what we want.
		// - With a peer that sent us an inv. In this case, the peer could have
		//   more blocks for us or it could not. Either way, it’s good to check
		//   and worst case the peer will return an empty header bundle that will
		//   result in us not sending anything back because there won’t be any new
		//   blocks to request.
		locator, locatorHeights := srv.blockchain.LatestHeaderLocator()
		headerTip := srv.blockchain.headerTip()
		currentBlockTip := srv.blockchain.blockTip()
		glog.V(2).Infof("Server._handleBlock (chain state = NEEDS_BLOCKS): Sending GET_HEADERS message to peer %v\n"+
			"Block Locator Hashes & Heights: (%v, %v)\n"+
			"Header Tip: (%v, %v)\nBlock Tip: (%v, %v)",
			pp, locator, locatorHeights, headerTip.Hash, headerTip.Height,
			currentBlockTip.Hash, currentBlockTip.Height)
		pp.AddDeSoMessage(&MsgDeSoGetHeaders{
			StopHash:     &BlockHash{},
			BlockLocator: locator,
		}, false)
		return
	}

	// If we get here, it means we're in SyncStateFullyCurrent, which is great.
	// In this case we shoot a MEMPOOL message over to the peer to bootstrap the mempool.
	srv._tryRequestMempoolFromPeer(pp)

	// Exit early if the chain isn't SyncStateFullyCurrent.
	if srv.blockchain.chainState() != SyncStateFullyCurrent {
		return
	}

	// If the chain is current, then try to transition to the FastHotStuff consensus.
	srv.tryTransitionToFastHotStuffConsensus()
}

func (srv *Server) _handleBlockBundle(pp *Peer, bundle *MsgDeSoBlockBundle) {
	if len(bundle.Blocks) == 0 {
		glog.Infof(CLog(Cyan, fmt.Sprintf("Server._handleBlockBundle: Received EMPTY block bundle "+
			"at header height ( %v ) from Peer %v. Disconnecting peer since this should never happen.",
			srv.blockchain.headerTip().Height, pp)))
		pp.Disconnect("Received empty block bundle.")
		return
	}
	glog.Infof(CLog(Cyan, fmt.Sprintf("Server._handleBlockBundle: Received blocks ( %v->%v / %v ) from Peer %v. "+
		"Checkpoint syncing status: %v",
		bundle.Blocks[0].Header.Height, bundle.Blocks[len(bundle.Blocks)-1].Header.Height,
		srv.blockchain.headerTip().Height, pp, srv.getCheckpointSyncingStatus(false))))

	srv.timer.Start("Server._handleBlockBundle: General")

	// TODO: We should fetch the next batch of blocks while we process this batch.
	// This requires us to modify GetBlocks to take a start hash and a count
	// of the number of blocks we want. Or we could make the existing GetBlocks
	// take a start hash and the other node can just return as many blocks as it
	// can.

	// Process each block in the bundle. Record our blocks per second.
	blockProcessingStartTime := time.Now()
	for ii, blk := range bundle.Blocks {
		// TODO: We should make it so that we break out if one of the blocks errors. It's just that
		// _handleBlock is a legacy function that doesn't support erroring out. It's not a big deal
		// though as we'll just connect all the blocks after the failed one and those blocks will also
		// gracefully fail.
		srv._handleBlock(pp, blk, ii == len(bundle.Blocks)-1 /*isLastBlock*/)
		numLogBlocks := 100
		if srv.params.IsPoSBlockHeight(blk.Header.Height) ||
			srv.params.NetworkType == NetworkType_TESTNET {
			numLogBlocks = 1000
		}

		if ii%numLogBlocks == 0 {
			glog.Infof(CLog(Cyan, fmt.Sprintf("Server._handleBlockBundle: Processed block ( %v / %v ) = ( %v / %v ) from Peer %v",
				bundle.Blocks[ii].Header.Height,
				srv.blockchain.headerTip().Height,
				ii+1, len(bundle.Blocks),
				pp)))

			elapsed := time.Since(blockProcessingStartTime)
			// Reset the blockProcessingStartTime so that each 1k blocks is timed individually
			blockProcessingStartTime = time.Now()
			if ii != 0 {
				fmt.Printf("We are processing %v blocks per second\n", float64(numLogBlocks)/(float64(elapsed)/1e9))
			}
		}
	}
}

func (srv *Server) _handleInv(peer *Peer, msg *MsgDeSoInv) {
	if !peer.isOutbound && srv.IgnoreInboundPeerInvMessages {
		glog.Infof("_handleInv: Ignoring inv message from inbound peer because "+
			"ignore_outbound_peer_inv_messages=true: %v", peer)
		return
	}
	// If we've set a maximum sync height and we've reached that height, then we will
	// stop accepting inv messages.
	if srv.blockchain.isTipMaxed(srv.blockchain.blockTip()) {
		return
	}
	peer.AddDeSoMessage(msg, true /*inbound*/)
}

func (srv *Server) _handleGetTransactions(pp *Peer, msg *MsgDeSoGetTransactions) {
	glog.V(1).Infof("Server._handleGetTransactions: Received GetTransactions "+
		"message %v from Peer %v", msg, pp)

	pp.AddDeSoMessage(msg, true /*inbound*/)
}

func (srv *Server) ProcessSingleTxnWithChainLock(pp *Peer, txn *MsgDeSoTxn) ([]*MsgDeSoTxn, error) {
	// Lock the chain for reading so that transactions don't shift under our feet
	// when processing this bundle. Not doing this could cause us to miss transactions
	// erroneously.
	//
	// TODO(performance): We should probably do this less frequently.
	srv.blockchain.ChainLock.RLock()
	defer srv.blockchain.ChainLock.RUnlock()

	// Note we set rateLimit=false because we have a global minimum txn fee that should
	// prevent spam on its own.

	// Only attempt to add the transaction to the PoW mempool if we're on the
	// PoW protocol. If we're on the PoW protocol, then we use the PoW mempool's
	// txn validity checks to signal whether the txn has been added or not. The PoW
	// mempool has stricter txn validity checks than the PoS mempool, so this works
	// out conveniently, as it allows us to always add a txn to the PoS mempool.
	tipHeight := uint64(srv.blockchain.blockTip().Height)
	if uint64(tipHeight) < srv.params.GetFinalPoWBlockHeight() {
		_, err := srv.mempool.ProcessTransaction(
			txn,
			true,  /*allowUnconnectedTxn*/
			false, /*rateLimit*/
			pp.ID,
			true, /*verifySignatures*/
		)

		// If we're on the PoW chain, and the txn doesn't pass the PoW mempool's validity checks, then
		// it's an invalid txn.
		if err != nil {
			return nil, errors.Wrapf(err, "Server.ProcessSingleTxnWithChainLock: Problem adding transaction to PoW mempool: ")
		}
	}

	// Always add the txn to the PoS mempool. This will usually succeed if the txn
	// addition into the PoW mempool succeeded above. However, we only return an error
	// here if the block height is at or above the final PoW block height. In the event
	// of an edge case where txns in the mempool are reordered, it is possible for the
	// txn addition into the PoW mempool to succeed, while the addition into the PoS
	// mempool fails. This error handling catches that and gives the user the correct
	// feedback on the txn addition's success.
	if err := srv.posMempool.AddTransaction(txn, time.Now()); err != nil {
		if uint64(tipHeight) >= srv.params.GetFinalPoWBlockHeight() {
			return nil, errors.Wrapf(err, "Server._addNewTxn: problem adding txn to pos mempool")
		}
	}

	// Happy path, the txn was successfully added to the PoS (and optionally PoW) mempool.
	return []*MsgDeSoTxn{txn}, nil
}

func (srv *Server) _processTransactions(pp *Peer, transactions []*MsgDeSoTxn) []*MsgDeSoTxn {
	// Try and add all the transactions to our mempool in the order we received
	// them. If any fail to get added, just log an error.
	//
	// TODO: It would be nice if we did something fancy here like if we kept
	// track of rejected transactions and retried them every time we connected
	// a block. Doing something like this would make it so that if a transaction
	// was initially rejected due to us not having its dependencies, then we
	// will eventually add it as opposed to just forgetting about it.
	glog.V(1).Infof("Server._processTransactions: Processing %d transactions from "+
		"peer %v", len(transactions), pp)
	transactionsToRelay := []*MsgDeSoTxn{}
	for ii, txn := range transactions {
		// Take some time to allow other threads to get the ChainLock if they need it
		//
		// TODO: It's not obvious how necessary this rest period is, and it's also not obvious if
		// five seconds is the right amount. We added it during a mission-critical sprint
		// to find and fix slow block production issue as one of several patches. It clearly doesn't
		// hurt so we decided to leave it in for now.
		if (ii+1)%1000 == 0 {
			// Log
			glog.V(1).Infof("Server._processTransactions: Taking a break to allow " +
				"other services to grab the ChainLock")
			time.Sleep(5000 * time.Millisecond)
		}

		glog.V(1).Infof("Server._processTransactions: Processing txn ( %d / %d ) from "+
			"peer %v", ii, len(transactions), pp)
		// Process the transaction with rate-limiting while allowing unconnectedTxns and
		// verifying signatures.
		newlyAcceptedTxns, err := srv.ProcessSingleTxnWithChainLock(pp, txn)
		if err != nil {
			glog.V(4).Info(fmt.Sprintf("Server._handleTransactionBundle: Rejected "+
				"transaction %v from peer %v from mempool: %v", txn, pp, err))
			// A peer should know better than to send us a transaction that's below
			// our min feerate, which they see when we send them a version message.
			if errors.Is(err, TxErrorInsufficientFeeMinFee) {
				glog.Errorf(fmt.Sprintf("Server._handleTransactionBundle: Disconnecting "+
					"Peer %v for sending us a transaction %v with fee below the minimum fee %d",
					pp, txn, srv.mempool.minFeeRateNanosPerKB))
				pp.Disconnect("Transaction fee below minimum fee")
			}

			// Don't do anything else if we got an error.
			continue
		}
		if len(newlyAcceptedTxns) == 0 {
			glog.Infof(fmt.Sprintf("Server._handleTransactionBundle: "+
				"Transaction %v from peer %v was added as an ORPHAN", spew.Sdump(txn), pp))
		}

		// If we get here then the transaction was accepted into our mempool.
		// Queue the transactions that were accepted them for relay to all of the peers
		// who don't yet have them.
		transactionsToRelay = append(transactionsToRelay, newlyAcceptedTxns...)
	}

	return transactionsToRelay
}

func (srv *Server) _handleTransactionBundle(pp *Peer, msg *MsgDeSoTransactionBundle) {
	glog.V(1).Infof("Server._handleTransactionBundle: Received TransactionBundle "+
		"message of size %v from Peer %v", len(msg.Transactions), pp)

	pp.AddDeSoMessage(msg, true /*inbound*/)
}

func (srv *Server) _handleTransactionBundleV2(pp *Peer, msg *MsgDeSoTransactionBundleV2) {
	glog.V(1).Infof("Server._handleTransactionBundleV2: Received TransactionBundle "+
		"message of size %v from Peer %v", len(msg.Transactions), pp)

	pp.AddDeSoMessage(msg, true /*inbound*/)
}

func (srv *Server) _handleMempool(pp *Peer, msg *MsgDeSoMempool) {
	glog.V(1).Infof("Server._handleMempool: Received Mempool message from Peer %v", pp)

	pp.canReceiveInvMessages = true
}

func (srv *Server) StartStatsdReporter() {
	go func() {
	out:
		for {
			select {
			case <-time.After(5 * time.Second):
				tags := []string{}

				// Report mempool size
				mempoolTotal := len(srv.mempool.readOnlyUniversalTransactionList)
				srv.statsdClient.Gauge("MEMPOOL.COUNT", float64(mempoolTotal), tags, 1)

				// Report PoS Mempool size
				posMempoolTotal := srv.posMempool.txnRegister.Count()
				srv.statsdClient.Gauge("POS_MEMPOOL.COUNT", float64(posMempoolTotal), tags, 1)

				// Report block + headers height
				blocksHeight := srv.blockchain.BlockTip().Height
				srv.statsdClient.Gauge("BLOCKS.HEIGHT", float64(blocksHeight), tags, 1)

				headersHeight := srv.blockchain.HeaderTip().Height
				srv.statsdClient.Gauge("HEADERS.HEIGHT", float64(headersHeight), tags, 1)

			case <-srv.mempool.quit:
				break out
			}
		}
	}()
}

func (srv *Server) _handleAddrMessage(pp *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeAddr {
		return
	}

	id := NewRemoteNodeId(pp.ID)
	var msg *MsgDeSoAddr
	var ok bool
	if msg, ok = desoMsg.(*MsgDeSoAddr); !ok {
		glog.Errorf("Server._handleAddrMessage: Problem decoding MsgDeSoAddr: %v", spew.Sdump(desoMsg))
		srv.networkManager.DisconnectById(id, "Problem decoding MsgDeSoAddr")
		return
	}

	srv.addrsToBroadcastLock.Lock()
	defer srv.addrsToBroadcastLock.Unlock()

	glog.V(1).Infof("Server._handleAddrMessage: Received Addr from peer id=%v with addrs %v", pp.ID, spew.Sdump(msg.AddrList))

	// If this addr message contains more than the maximum allowed number of addresses
	// then disconnect this peer.
	if len(msg.AddrList) > MaxAddrsPerAddrMsg {
		glog.Errorf(fmt.Sprintf("Server._handleAddrMessage: Disconnecting "+
			"Peer id=%v for sending us an addr message with %d transactions, which exceeds "+
			"the max allowed %d",
			pp.ID, len(msg.AddrList), MaxAddrsPerAddrMsg))
		srv.networkManager.DisconnectById(id, "Addr message too large")
		return
	}

	// Add all the addresses we received to the addrmgr.
	netAddrsReceived := []*wire.NetAddressV2{}
	for _, addr := range msg.AddrList {
		addrAsNetAddr := wire.NetAddressV2FromBytes(
			addr.Timestamp, (wire.ServiceFlag)(addr.Services), addr.IP[:], addr.Port)
		if !addrmgr.IsRoutable(addrAsNetAddr) {
			glog.V(1).Infof("Server._handleAddrMessage: Dropping address %v from peer %v because it is not routable", addr, pp)
			continue
		}

		netAddrsReceived = append(
			netAddrsReceived, addrAsNetAddr)
	}
	srv.AddrMgr.AddAddresses(netAddrsReceived, pp.netAddr)

	// If the message had <= 10 addrs in it, then queue all the addresses for relaying on the next cycle.
	if len(msg.AddrList) <= 10 {
		glog.V(1).Infof("Server._handleAddrMessage: Queueing %d addrs for forwarding from "+
			"peer %v", len(msg.AddrList), pp)
		sourceAddr := &SingleAddr{
			Timestamp: time.Now(),
			IP:        pp.netAddr.ToLegacy().IP,
			Port:      pp.netAddr.Port,
			Services:  pp.serviceFlags,
		}
		listToAddTo, hasSeenSource := srv.addrsToBroadcast[sourceAddr.StringWithPort(false /*includePort*/)]
		if !hasSeenSource {
			listToAddTo = []*SingleAddr{}
		}
		// If this peer has been sending us a lot of little crap, evict a lot of their
		// stuff but don't disconnect.
		if len(listToAddTo) > MaxAddrsPerAddrMsg {
			listToAddTo = listToAddTo[:MaxAddrsPerAddrMsg/2]
		}
		listToAddTo = append(listToAddTo, msg.AddrList...)
		srv.addrsToBroadcast[sourceAddr.StringWithPort(false /*includePort*/)] = listToAddTo
	}
}

func (srv *Server) _handleGetAddrMessage(pp *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeGetAddr {
		return
	}

	id := NewRemoteNodeId(pp.ID)
	if _, ok := desoMsg.(*MsgDeSoGetAddr); !ok {
		glog.Errorf("Server._handleAddrMessage: Problem decoding "+
			"MsgDeSoAddr: %v", spew.Sdump(desoMsg))
		srv.networkManager.DisconnectById(id, "Problem decoding MsgDeSoGetAddr")
		return
	}

	glog.V(1).Infof("Server._handleGetAddrMessage: Received GetAddr from peer %v", pp)
	// When we get a GetAddr message, choose MaxAddrsPerMsg from the AddrMgr
	// and send them back to the peer.
	netAddrsFound := srv.AddrMgr.AddressCache()
	if len(netAddrsFound) == 0 {
		return
	}
	if len(netAddrsFound) > MaxAddrsPerAddrMsg {
		netAddrsFound = netAddrsFound[:MaxAddrsPerAddrMsg]
	}

	// Convert the list to a SingleAddr list.
	res := &MsgDeSoAddr{}
	for _, netAddr := range netAddrsFound {
		singleAddr := &SingleAddr{
			Timestamp: time.Now(),
			IP:        netAddr.ToLegacy().IP,
			Port:      netAddr.Port,
			Services:  (ServiceFlag)(netAddr.Services),
		}
		res.AddrList = append(res.AddrList, singleAddr)
	}
	rn := srv.networkManager.GetRemoteNodeById(id)
	if err := srv.networkManager.SendMessage(rn, res); err != nil {
		glog.Errorf("Server._handleGetAddrMessage: Problem sending addr message to peer %v: %v", pp, err)
		srv.networkManager.DisconnectById(id, "Problem sending addr message")
		return
	}
}

func (srv *Server) _handleControlMessages(serverMessage *ServerMessage) (_shouldQuit bool) {
	switch serverMessage.Msg.(type) {
	// Control messages used internally to signal to the server.
	case *MsgDeSoDisconnectedPeer:
		srv._handleDisconnectedPeerMessage(serverMessage.Peer)
		srv.networkManager._handleDisconnectedPeerMessage(serverMessage.Peer, serverMessage.Msg)
	case *MsgDeSoNewConnection:
		srv.networkManager._handleNewConnectionMessage(serverMessage.Peer, serverMessage.Msg)
	case *MsgDeSoQuit:
		return true
	}

	return false
}

func (srv *Server) _handlePeerMessages(serverMessage *ServerMessage) {
	// Handle all non-control message types from our Peers.
	switch msg := serverMessage.Msg.(type) {
	// Messages sent among peers.
	case *MsgDeSoAddr:
		srv._handleAddrMessage(serverMessage.Peer, serverMessage.Msg)
	case *MsgDeSoGetAddr:
		srv._handleGetAddrMessage(serverMessage.Peer, serverMessage.Msg)
	case *MsgDeSoGetHeaders:
		srv._handleGetHeaders(serverMessage.Peer, msg)
	case *MsgDeSoHeaderBundle:
		srv._handleHeaderBundle(serverMessage.Peer, msg)
	case *MsgDeSoBlockBundle:
		srv._handleBlockBundle(serverMessage.Peer, msg)
	case *MsgDeSoGetBlocks:
		srv._handleGetBlocks(serverMessage.Peer, msg)
	case *MsgDeSoBlock:
		// isLastBlock is always true when we get a legacy single-block message.
		srv._handleBlock(serverMessage.Peer, msg, true)
	case *MsgDeSoGetSnapshot:
		srv._handleGetSnapshot(serverMessage.Peer, msg)
	case *MsgDeSoSnapshotData:
		srv._handleSnapshot(serverMessage.Peer, msg)
	case *MsgDeSoGetTransactions:
		srv._handleGetTransactions(serverMessage.Peer, msg)
	case *MsgDeSoTransactionBundle:
		srv._handleTransactionBundle(serverMessage.Peer, msg)
	case *MsgDeSoTransactionBundleV2:
		srv._handleTransactionBundleV2(serverMessage.Peer, msg)
	case *MsgDeSoMempool:
		srv._handleMempool(serverMessage.Peer, msg)
	case *MsgDeSoInv:
		srv._handleInv(serverMessage.Peer, msg)
	case *MsgDeSoVersion:
		srv.networkManager._handleVersionMessage(serverMessage.Peer, serverMessage.Msg)
	case *MsgDeSoVerack:
		srv.networkManager._handleVerackMessage(serverMessage.Peer, serverMessage.Msg)
	case *MsgDeSoValidatorVote:
		srv._handleValidatorVote(serverMessage.Peer, msg)
	case *MsgDeSoValidatorTimeout:
		srv._handleValidatorTimeout(serverMessage.Peer, msg)
	}
}

func (srv *Server) _handleFastHotStuffConsensusEvent(event *consensus.FastHotStuffEvent) {
	// This should never happen. If the consensus message handler isn't defined, then something went
	// wrong during the node initialization. We log it and return early to avoid panicking.
	if srv.fastHotStuffConsensus == nil {
		glog.Errorf("Server._handleFastHotStuffConsensusEvent: Consensus controller is nil")
		return
	}

	switch event.EventType {
	case consensus.FastHotStuffEventTypeVote:
		srv.fastHotStuffConsensus.HandleLocalVoteEvent(event)
	case consensus.FastHotStuffEventTypeTimeout:
		srv.fastHotStuffConsensus.HandleLocalTimeoutEvent(event)
	case consensus.FastHotStuffEventTypeConstructVoteQC:
		srv.fastHotStuffConsensus.HandleLocalBlockProposalEvent(event)
	case consensus.FastHotStuffEventTypeConstructTimeoutQC:
		srv.fastHotStuffConsensus.HandleLocalTimeoutBlockProposalEvent(event)
	}
}

func (srv *Server) _handleValidatorVote(pp *Peer, msg *MsgDeSoValidatorVote) {
	if msg.GetMsgType() != MsgTypeValidatorVote {
		return
	}
	// It's possible that the consensus controller hasn't been initialized. If so,
	// we log an error and move on.
	if srv.fastHotStuffConsensus == nil {
		glog.Errorf("Server._handleValidatorVote: Consensus controller is nil")
		return
	}

	if err := srv.fastHotStuffConsensus.HandleValidatorVote(pp, msg); err != nil {
		glog.Errorf("Server._handleValidatorVote: Error handling vote message from peer: %v", err)
	}
}

func (srv *Server) _handleValidatorTimeout(pp *Peer, msg *MsgDeSoValidatorTimeout) {
	if msg.GetMsgType() != MsgTypeValidatorTimeout {
		return
	}
	// It's possible that the consensus controller hasn't been initialized. If so,
	// we log an error and move on.
	if srv.fastHotStuffConsensus == nil {
		glog.Errorf("Server._handleValidatorTimeout: Consensus controller is nil")
		return
	}

	missingBlockHashes, err := srv.fastHotStuffConsensus.HandleValidatorTimeout(pp, msg)
	if err != nil {
		glog.Errorf("Server._handleValidatorTimeout: Error handling timeout message from peer: %v", err)
	}

	// If we have missing blocks to request, then we send a GetBlocks message to the peer.
	if len(missingBlockHashes) > 0 {
		srv.RequestBlocksByHash(pp, missingBlockHashes)
	}
}

// _startConsensusEventLoop contains the top-level event loop to run both the PoW and PoS consensus. It is
// single-threaded to ensure that concurrent event do not conflict with each other. It's role is to guarantee
// single threaded processing and act as an entry point for consensus events. It does minimal validation on its
// own.
//
// For the PoW consensus:
// - It listens to all peer messages from the network and handles them as they come in. This includes
// control messages from peer, proposed blocks from peers, votes/timeouts, block requests, mempool
// requests from syncing peers
//
// For the PoS consensus:
// - It listens to all peer messages from the network and handles them as they come in. This includes
// control messages from peer, proposed blocks from peers, votes/timeouts, block requests, mempool
// requests from syncing peers
// - It listens to consensus events from the Fast HostStuff consensus engine. The consensus signals when
// it's ready to vote, timeout, propose a block, or propose an empty block with a timeout QC.
func (srv *Server) _startConsensus() {
	// Initialize the FastHotStuffConsensus transition check time.
	srv.resetFastHotStuffConsensusTransitionCheckTime()

	for {
		// This is used instead of the shouldQuit control message exist mechanism below. shouldQuit will be true only
		// when all incoming messages have been processed, on the other hand this shutdown will quit immediately.
		if atomic.LoadInt32(&srv.shutdown) >= 1 {
			break
		}

		select {
		case <-srv.getFastHotStuffTransitionCheckTime():
			{
				glog.V(2).Info("Server._startConsensus: Checking if FastHotStuffConsensus is ready to start")
				srv.tryTransitionToFastHotStuffConsensus()
			}

		case consensusEvent := <-srv.getFastHotStuffConsensusEventChannel():
			{
				glog.V(2).Infof("Server._startConsensus: Received consensus event: %s", consensusEvent.ToString())
				srv._handleFastHotStuffConsensusEvent(consensusEvent)
			}

		case serverMessage := <-srv.incomingMessages:
			{
				// There is an incoming network message from a peer.

				glog.V(2).Infof("Server._startConsensus: Handling message of type %v from Peer %v",
					serverMessage.Msg.GetMsgType(), serverMessage.Peer)
				srv._handlePeerMessages(serverMessage)

				// Always check for and handle control messages regardless of whether the
				// BitcoinManager is synced. Note that we filter control messages out in a
				// Peer's inHandler so any control message we get at this point should be bona fide.
				shouldQuit := srv._handleControlMessages(serverMessage)
				if shouldQuit {
					break
				}
			}

		}
	}

	// If we broke out of the select statement then it's time to allow things to
	// clean up.
	srv.waitGroup.Done()
	glog.V(2).Info("Server.Start: Server done")
}

func (srv *Server) getAddrsToBroadcast() []*SingleAddr {
	srv.addrsToBroadcastLock.Lock()
	defer srv.addrsToBroadcastLock.Unlock()

	// If there's nothing in the map, return.
	if len(srv.addrsToBroadcast) == 0 {
		return []*SingleAddr{}
	}

	// If we get here then we have some addresses to broadcast.
	addrsToBroadcast := []*SingleAddr{}
	for uint32(len(addrsToBroadcast)) < srv.params.MaxAddressesToBroadcast &&
		len(srv.addrsToBroadcast) > 0 {
		// Choose a key at random. This works because map iteration is random in golang.
		bucket := ""
		for kk := range srv.addrsToBroadcast {
			bucket = kk
			break
		}

		// Remove the last element from the slice for the given bucket.
		currentAddrList := srv.addrsToBroadcast[bucket]
		if len(currentAddrList) > 0 {
			lastIndex := len(currentAddrList) - 1
			currentAddr := currentAddrList[lastIndex]
			currentAddrList = currentAddrList[:lastIndex]
			if len(currentAddrList) == 0 {
				delete(srv.addrsToBroadcast, bucket)
			} else {
				srv.addrsToBroadcast[bucket] = currentAddrList
			}

			addrsToBroadcast = append(addrsToBroadcast, currentAddr)
		}
	}

	return addrsToBroadcast
}

// Must be run inside a goroutine. Relays addresses to peers at regular intervals
// and relays our own address to peers once every 24 hours.
func (srv *Server) _startAddressRelayer() {
	for numMinutesPassed := 0; ; numMinutesPassed++ {
		if atomic.LoadInt32(&srv.shutdown) >= 1 {
			break
		}
		// For the first ten minutes after the connection controller starts, relay our address to all
		// peers. After the first ten minutes, do it once every 24 hours.
		glog.V(1).Infof("Server.startAddressRelayer: Relaying our own addr to peers")
		remoteNodes := srv.networkManager.GetAllRemoteNodes().GetAll()
		if numMinutesPassed < 10 || numMinutesPassed%(RebroadcastNodeAddrIntervalMinutes) == 0 {
			for _, rn := range remoteNodes {
				if !rn.IsHandshakeCompleted() {
					continue
				}
				netAddr := rn.GetNetAddress()
				if netAddr == nil {
					continue
				}
				bestAddress := srv.AddrMgr.GetBestLocalAddress(netAddr)
				if bestAddress != nil {
					glog.V(2).Infof("Server.startAddressRelayer: Relaying address %v to "+
						"RemoteNode (id= %v)", bestAddress.Addr.String(), rn.GetId())
					addrMsg := &MsgDeSoAddr{
						AddrList: []*SingleAddr{
							{
								Timestamp: time.Now(),
								IP:        bestAddress.ToLegacy().IP,
								Port:      bestAddress.Port,
								Services:  (ServiceFlag)(bestAddress.Services),
							},
						},
					}
					if err := rn.SendMessage(addrMsg); err != nil {
						glog.Errorf("Server.startAddressRelayer: Problem sending "+
							"MsgDeSoAddr to RemoteNode (id= %v): %v", rn.GetId(), err)
					}
				}
			}
		}

		glog.V(2).Infof("Server.startAddressRelayer: Seeing if there are addrs to relay...")
		// Broadcast the addrs we have to all of our peers.
		addrsToBroadcast := srv.getAddrsToBroadcast()
		if len(addrsToBroadcast) == 0 {
			glog.V(2).Infof("Server.startAddressRelayer: No addrs to relay.")
			time.Sleep(AddrRelayIntervalSeconds * time.Second)
			continue
		}

		glog.V(2).Infof("Server.startAddressRelayer: Found %d addrs to "+
			"relay: %v", len(addrsToBroadcast), spew.Sdump(addrsToBroadcast))
		// Iterate over all our peers and broadcast the addrs to all of them.
		for _, rn := range remoteNodes {
			if !rn.IsHandshakeCompleted() {
				continue
			}
			addrMsg := &MsgDeSoAddr{
				AddrList: addrsToBroadcast,
			}
			if err := rn.SendMessage(addrMsg); err != nil {
				glog.Errorf("Server.startAddressRelayer: Problem sending "+
					"MsgDeSoAddr to RemoteNode (id= %v): %v", rn.GetId(), err)
			}
		}
		time.Sleep(AddrRelayIntervalSeconds * time.Second)
		continue
	}
}

func (srv *Server) getFastHotStuffConsensusEventChannel() chan *consensus.FastHotStuffEvent {
	if srv.fastHotStuffConsensus == nil {
		return nil
	}
	return srv.fastHotStuffConsensus.fastHotStuffEventLoop.GetEvents()
}

func (srv *Server) resetFastHotStuffConsensusTransitionCheckTime() {
	// Check if the FastHotStuffConsensus is ready to start based on the FastHotStuffConsensusTransitionCheckDuration.
	srv.fastHotStuffConsensusTransitionCheckTime = time.Now().Add(
		srv.params.FastHotStuffConsensusTransitionCheckDuration)
}

func (srv *Server) getFastHotStuffTransitionCheckTime() <-chan time.Time {
	// If the FastHotStuffConsensus does not exist, or is already running, then
	// we don't need this timer. We can exit early.
	if srv.fastHotStuffConsensus == nil || srv.fastHotStuffConsensus.IsRunning() {
		return nil
	}
	return time.After(time.Until(srv.fastHotStuffConsensusTransitionCheckTime))
}

func (srv *Server) tryTransitionToFastHotStuffConsensus() {
	// Reset the transition check timer when this function exits.
	defer srv.resetFastHotStuffConsensusTransitionCheckTime()

	// If the FastHotStuffConsensus does not exist, or is already running, then
	// there is nothing left to do. We can exit early.
	if srv.fastHotStuffConsensus == nil || srv.fastHotStuffConsensus.IsRunning() {
		return
	}

	// Get the tip height, header tip height, and sync state of the blockchain. We'll use them
	// in a heuristic here to determine if we are ready to transition to the FastHotStuffConsensus,
	// or should continue to try to sync.
	srv.blockchain.ChainLock.RLock()
	tipHeight := uint64(srv.blockchain.blockTip().Height)
	headerTipHeight := uint64(srv.blockchain.headerTip().Height)
	syncState := srv.blockchain.chainState()
	srv.blockchain.ChainLock.RUnlock()

	// Exit early if the current tip height is below the final PoW block's height. We are ready to
	// enable the FastHotStuffConsensus once we reach the final block of the PoW protocol. The
	// FastHotStuffConsensus can only be enabled once it's at or past the final block height of
	// the PoW protocol.
	if tipHeight < srv.params.GetFinalPoWBlockHeight() {
		return
	}

	// If the header's tip is not at the same height as the block tip, then we are still syncing
	// and we should not transition to the FastHotStuffConsensus.
	if headerTipHeight != tipHeight {
		return
	}

	// If we are still syncing, then we should not transition to the FastHotStuffConsensus.
	// We intentionally exclude the SyncStateSyncingHeaders to account for the case where we
	// do not have a sync peer and are stuck in the SyncStateSyncingHeaders state.
	skippedSyncStates := []SyncState{
		SyncStateSyncingSnapshot, SyncStateSyncingBlocks, SyncStateNeedBlocksss, SyncStateSyncingHistoricalBlocks,
	}
	if collections.Contains(skippedSyncStates, syncState) {
		return
	}

	// If we have a sync peer and have not reached the sync peer's starting block height, then
	// we should sync all remaining blocks from the sync peer before transitioning to the
	// FastHotStuffConsensus.
	if srv.SyncPeer != nil && srv.SyncPeer.StartingBlockHeight() > tipHeight {
		return
	}

	// At this point, we know that we have synced to the sync peer's tip or we don't have a sync
	// peer. The header tip and the chain tip are also at the same height. We are ready to transition
	// to the FastHotStuffConsensus.

	srv.fastHotStuffConsensus.Start()
}

func (srv *Server) _startTransactionRelayer() {
	// If we've set a maximum sync height, we will not relay transactions.
	if srv.blockchain.MaxSyncBlockHeight > 0 {
		return
	}

	for {
		// Just continuously relay transactions to peers that don't have them.
		srv._relayTransactions()
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

	srv.networkManager.Stop()
	glog.Infof(CLog(Yellow, "Server.Stop: Closed the NetworkManager"))

	// Stop the miner if we have one running.
	if srv.miner != nil {
		srv.miner.Stop()
		glog.Infof(CLog(Yellow, "Server.Stop: Closed the Miner"))
	}

	// Stop the PoS validator consensus if one is running
	if srv.fastHotStuffConsensus != nil {
		srv.fastHotStuffConsensus.Stop()
	}

	// Stop the PoS block proposer if we have one running.
	if srv.fastHotStuffConsensus != nil {
		srv.fastHotStuffConsensus.fastHotStuffEventLoop.Stop()
		glog.Infof(CLog(Yellow, "Server.Stop: Closed the fastHotStuffEventLoop"))
	}

	// TODO: Stop the PoS mempool if we have one running.

	if srv.mempool != nil {
		// Before the node shuts down, write all the mempool txns to disk
		// if the flag is set.
		if srv.mempool.mempoolDir != "" {
			glog.Info("Doing final mempool dump...")
			srv.mempool.DumpTxnsToDB()
			glog.Info("Final mempool dump complete!")
		}

		if !srv.mempool.stopped {
			srv.mempool.Stop()
		}
		glog.Infof(CLog(Yellow, "Server.Stop: Closed Mempool"))
	}

	glog.Infof(CLog(Yellow, "Server.Stop: Closed PosMempool"))
	srv.posMempool.Stop()

	// Stop the block producer
	if srv.blockProducer != nil {
		if srv.blockchain.MaxSyncBlockHeight == 0 {
			srv.blockProducer.Stop()
		}
		glog.Infof(CLog(Yellow, "Server.Stop: Closed BlockProducer"))
	}

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
	// TODO: shouldn't we wait for all modules to shutdown?
	srv.waitGroup.Wait()
	glog.Info("Server.Stop: Successfully shut down Server")
}

func (srv *Server) GetStatsdClient() *statsd.Client {
	return srv.statsdClient
}

// Start actually kicks off all of the management processes. Among other things, it causes
// the ConnectionManager to actually start connecting to peers and receiving messages. If
// requested, it also starts the miner.
func (srv *Server) Start() {
	// Start the Server so that it will be ready to process messages once the ConnectionManager
	// finds some Peers.
	glog.Info("Server.Start: Starting Server")
	srv.waitGroup.Add(1)

	go srv._startConsensus()

	go srv._startAddressRelayer()

	go srv._startTransactionRelayer()

	srv.posMempool.Start()

	// Once the ConnectionManager is started, peers will be found and connected to and
	// messages will begin to flow in to be processed.
	if !srv.DisableNetworking {
		go srv.cmgr.Start()
	}

	if srv.miner != nil && len(srv.miner.PublicKeys) > 0 {
		go srv.miner.Start()
	}

	// Initialize state syncer mempool job, if needed.
	if srv.StateChangeSyncer != nil {
		srv.StateChangeSyncer.StartMempoolSyncRoutine(srv)
	}

	// Start the network manager's internal event loop to open and close connections to peers.
	srv.networkManager.Start()
}

// SyncPrefixProgress keeps track of sync progress on an individual prefix. It is used in
// hyper sync to determine which peer to query about each prefix and also what was the last
// db key that we've received from that peer. Peers will send us state by chunks. But first we
// need to tell the peer the starting key for the chunk we want to retrieve.
type SyncPrefixProgress struct {
	// Peer assigned for retrieving this particular prefix.
	PrefixSyncPeer *Peer
	// DB prefix corresponding to this particular sync progress.
	Prefix []byte
	// LastReceivedKey is the last key that we've received from this peer.
	LastReceivedKey []byte

	// Completed indicates whether we've finished syncing this prefix.
	Completed bool
}

// SyncProgress is used to keep track of hyper sync progress. It stores a list of SyncPrefixProgress
// structs which are used to track progress on each individual prefix. It also has the snapshot block
// height and block hash of the current snapshot epoch.
type SyncProgress struct {
	// PrefixProgress includes a list of SyncPrefixProgress objects, each of which represents a state prefix.
	PrefixProgress []*SyncPrefixProgress

	// SnapshotMetadata is the information about the snapshot we're downloading.
	SnapshotMetadata *SnapshotEpochMetadata

	// Completed indicates whether we've finished syncing state.
	Completed bool

	printChannel chan struct{}
}

func (progress *SyncProgress) PrintLoop() {
	progress.printChannel = make(chan struct{})
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-progress.printChannel:
			return
		case <-ticker.C:
			var completedPrefixes [][]byte
			var incompletePrefixes [][]byte
			var currentPrefix []byte

			for _, prefix := range StatePrefixes.StatePrefixesList {
				// Check if the prefix has been completed.
				foundPrefix := false
				for _, prefixProgress := range progress.PrefixProgress {
					if reflect.DeepEqual(prefix, prefixProgress.Prefix) {
						foundPrefix = true
						if prefixProgress.Completed {
							completedPrefixes = append(completedPrefixes, prefix)
							break
						} else {
							currentPrefix = prefix
						}
						break
					}
				}
				if !foundPrefix {
					incompletePrefixes = append(incompletePrefixes, prefix)
				}
			}
			if len(completedPrefixes) > 0 {
				glog.Infof(CLog(Green, fmt.Sprintf("HyperSync: finished downloading prefixes (%v)", completedPrefixes)))
			}
			if len(currentPrefix) > 0 {
				glog.Infof(CLog(Magenta, fmt.Sprintf("HyperSync: currently syncing prefix: (%v)", currentPrefix)))
			}
			if len(incompletePrefixes) > 0 {
				glog.Infof("Remaining prefixes (%v)", incompletePrefixes)
			}
		}
	}
}

func (srv *Server) GetNetworkManagerConnections() []*RemoteNode {
	return srv.networkManager.GetAllRemoteNodes().GetAll()
}

func (srv *Server) GetLatestView() uint64 {
	if srv.fastHotStuffConsensus == nil || !srv.fastHotStuffConsensus.IsRunning() {
		return 0
	}
	if srv.fastHotStuffConsensus.fastHotStuffEventLoop == nil ||
		!srv.fastHotStuffConsensus.fastHotStuffEventLoop.IsRunning() {
		return 0
	}
	return srv.fastHotStuffConsensus.fastHotStuffEventLoop.GetCurrentView()
}
