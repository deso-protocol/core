package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/decred/dcrd/lru"

	"github.com/DataDog/datadog-go/statsd"

	"github.com/btcsuite/btcd/addrmgr"
	chainlib "github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/deso-protocol/go-deadlock"
	"github.com/dgraph-io/badger/v3"
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
	snapshot      *Snapshot
	mempool       *DeSoMempool
	miner         *DeSoMiner
	blockProducer *DeSoBlockProducer
	eventManager  *EventManager
	TxIndex       *TXIndex

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
	inventoryBeingProcessed lru.Cache
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
	addrsToBroadcastt    map[string][]*SingleAddr

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
func (srv *Server) GetMempool() *DeSoMempool {
	return srv.mempool
}

// TODO: The hallmark of a messy non-law-of-demeter-following interface...
func (srv *Server) GetBlockProducer() *DeSoBlockProducer {
	return srv.blockProducer
}

// TODO: The hallmark of a messy non-law-of-demeter-following interface...
func (srv *Server) GetConnectionManager() *ConnectionManager {
	return srv.cmgr
}

// TODO: The hallmark of a messy non-law-of-demeter-following interface...
func (srv *Server) GetMiner() *DeSoMiner {
	return srv.miner
}

func (srv *Server) BroadcastTransaction(txn *MsgDeSoTxn) ([]*MempoolTx, error) {
	// Use the backendServer to add the transaction to the mempool and
	// relay it to peers. When a transaction is created by the user there
	// is no need to consider a rateLimit and also no need to verifySignatures
	// because we generally will have done that already.
	mempoolTxs, err := srv._addNewTxn(nil /*peer*/, txn, false /*rateLimit*/, false /*verifySignatures*/)
	if err != nil {
		return nil, errors.Wrapf(err, "BroadcastTransaction: ")
	}

	// At this point, we know the transaction has been run through the mempool.
	// Now wait for an update of the ReadOnlyUtxoView so we don't break anything.
	srv.mempool.BlockUntilReadOnlyViewRegenerated()

	return mempoolTxs, nil
}

func (srv *Server) VerifyAndBroadcastTransaction(txn *MsgDeSoTxn) error {
	// Grab the block tip and use it as the height for validation.
	blockHeight := srv.blockchain.BlockTip().Height
	err := srv.blockchain.ValidateTransaction(
		txn,
		// blockHeight is set to the next block since that's where this
		// transaction will be mined at the earliest.
		blockHeight+1,
		true,
		srv.mempool)
	if err != nil {
		return fmt.Errorf("VerifyAndBroadcastTransaction: Problem validating txn: %v", err)
	}

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

// NewServer initializes all of the internal data structures. Right now this basically
// looks as follows:
// - ConnectionManager starts and keeps track of peers.
// - When messages are received from peers, they get forwarded on a channel to
//   the Server to handle them. In that sense the ConnectionManager is basically
//   just acting as a router.
// - When the Server receives a message from a peer, it can do any of the following:
//   * Take no action.
//   * Use the Blockchain data structure to validate the transaction or update the
//     Blockchain data structure.
//   * Send a new message. This can be a message directed back to that actually sent this
//     message or it can be a message to another peer for whatever reason. When a message
//     is sent in this way it can also have a deadline on it that the peer needs to
//     respond by or else it will be disconnected.
//   * Disconnect the peer. In this case the ConnectionManager gets notified about the
//     disconnection and may opt to replace the now-disconnected peer with a new peer.
//     This happens for example when an outbound peer is disconnected in order to
//     maintain TargetOutboundPeers.
// - The server could also receive a control message that a peer has been disconnected.
//   This can be useful to the server if, for example, it was expecting a response from
//   a particular peer, which could be the case in initial block download where a single
//   sync peer is used.
//
// TODO: Refactor all these arguments into a config object or something.
func NewServer(
	_params *DeSoParams,
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
) (_srv *Server, _err error, _shouldRestart bool) {
	var err error

	// Setup snapshot
	var _snapshot *Snapshot
	shouldRestart := false
	archivalMode := false
	if _hyperSync {
		_snapshot, err, shouldRestart = NewSnapshot(_db, _dataDir, _snapshotBlockHeightPeriod,
			false, false, _params, _disableEncoderMigrations)
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
	}

	// The same timesource is used in the chain data structure and in the connection
	// manager. It just takes and keeps track of the median time among our peers so
	// we can keep a consistent clock.
	timesource := chainlib.NewMedianTime()

	// Create a new connection manager but note that it won't be initialized until Start().
	_incomingMessages := make(chan *ServerMessage, (_targetOutboundPeers+_maxInboundPeers)*3)
	_cmgr := NewConnectionManager(
		_params, _desoAddrMgr, _listeners, _connectIps, timesource,
		_targetOutboundPeers, _maxInboundPeers, _limitOneInboundConnectionPerIP,
		_hyperSync, _syncType, _stallTimeoutSeconds, _minFeeRateNanosPerKB,
		_incomingMessages, srv)

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
		_params, timesource, _db, postgres, eventManager, _snapshot, archivalMode)
	if err != nil {
		return nil, errors.Wrapf(err, "NewServer: Problem initializing blockchain"), true
	}

	glog.V(1).Infof("Initialized chain: Best Header Height: %d, Header Hash: %s, Header CumWork: %s, Best Block Height: %d, Block Hash: %s, Block CumWork: %s",
		_chain.headerTip().Height,
		hex.EncodeToString(_chain.headerTip().Hash[:]),
		hex.EncodeToString(BigintToHash(_chain.headerTip().CumWork)[:]),
		_chain.blockTip().Height,
		hex.EncodeToString(_chain.blockTip().Hash[:]),
		hex.EncodeToString(BigintToHash(_chain.blockTip().CumWork)[:]))

	// Create a mempool to store transactions until they're ready to be mined into
	// blocks.
	_mempool := NewDeSoMempool(_chain, _rateLimitFeerateNanosPerKB,
		_minFeeRateNanosPerKB, _blockCypherAPIKey, _runReadOnlyUtxoViewUpdater, _dataDir,
		_mempoolDumpDir)

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
	if _maxBlockTemplatesToCache > 0 {
		_blockProducer, err = NewDeSoBlockProducer(
			_minBlockUpdateIntervalSeconds, _maxBlockTemplatesToCache,
			_blockProducerSeed,
			_mempool, _chain,
			_params, postgres)
		if err != nil {
			panic(err)
		}
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

	// Set all the fields on the Server object.
	srv.cmgr = _cmgr
	srv.blockchain = _chain
	srv.mempool = _mempool
	srv.miner = _miner
	srv.blockProducer = _blockProducer
	srv.incomingMessages = _incomingMessages
	// Make this hold a multiple of what we hold for individual peers.
	srv.inventoryBeingProcessed = lru.NewCache(maxKnownInventory)
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
	srv.addrsToBroadcastt = make(map[string][]*SingleAddr)

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
		glog.Errorf(CLog(Red, "NewServer: Forcing a rollback to the last snapshot epoch because node was not closed "+
			"properly last time"))
		if err := _snapshot.ForceResetToLastSnapshot(_chain); err != nil {
			return nil, errors.Wrapf(err, "NewServer: Problem in ForceResetToLastSnapshot"), true
		}
	}

	return srv, nil, shouldRestart
}

func (srv *Server) _handleGetHeaders(pp *Peer, msg *MsgDeSoGetHeaders) {
	glog.V(1).Infof("Server._handleGetHeadersMessage: called with locator: (%v), "+
		"stopHash: (%v) from Peer %v", msg.BlockLocator, msg.StopHash, pp)

	// Ignore GetHeaders requests we're still syncing.
	if srv.blockchain.isSyncing() {
		chainState := srv.blockchain.chainState()
		glog.V(1).Infof("Server._handleGetHeadersMessage: Ignoring GetHeaders from Peer %v"+
			"because node is syncing with ChainState (%v)", pp, chainState)
		return
	}

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
	headers := srv.blockchain.LocateBestBlockChainHeaders(msg.BlockLocator, msg.StopHash)

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
		// We will assign the peer to a non-existing prefix.
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

	// Now send a message to the peer to fetch the snapshot chunk.
	pp.AddDeSoMessage(&MsgDeSoGetSnapshot{
		SnapshotStartKey: lastReceivedKey,
	}, false)

	glog.V(2).Infof("Server.GetSnapshot: Sending a GetSnapshot message to peer (%v) "+
		"with Prefix (%v) and SnapshotStartEntry (%v)", pp, prefix, lastReceivedKey)
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
	for _, blockNode := range srv.blockchain.bestChain {
		// We find the first block that's not stored and get ready to download blocks starting from this block onwards.
		if blockNode.Status&StatusBlockStored == 0 {
			numBlocksToFetch := MaxBlocksInFlight - len(pp.requestedBlocks)
			currentHeight := int(blockNode.Height)
			blockNodesToFetch := []*BlockNode{}
			// In case there are blocks at tip that are already stored (which shouldn't really happen), we'll not download them.
			var heightLimit int
			for heightLimit = len(srv.blockchain.bestChain) - 1; heightLimit >= 0; heightLimit-- {
				if !srv.blockchain.bestChain[heightLimit].Status.IsFullyProcessed() {
					break
				}
			}

			// Find the blocks that we should download.
			for currentHeight <= heightLimit &&
				len(blockNodesToFetch) < numBlocksToFetch {

				// Get the current hash and increment the height. Genesis has height 0, so currentHeight corresponds to
				// the array index.
				currentNode := srv.blockchain.bestChain[currentHeight]
				currentHeight++

				// If we've already requested this block then we don't request it again.
				if _, exists := pp.requestedBlocks[*currentNode.Hash]; exists {
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
func (srv *Server) GetBlocks(pp *Peer, maxHeight int) {
	// Fetch as many blocks as we can from this peer.
	numBlocksToFetch := MaxBlocksInFlight - len(pp.requestedBlocks)
	blockNodesToFetch := srv.blockchain.GetBlockNodesToFetch(
		numBlocksToFetch, maxHeight, pp.requestedBlocks)
	if len(blockNodesToFetch) == 0 {
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
	pp.AddDeSoMessage(&MsgDeSoGetBlocks{
		HashList: hashList,
	}, false)

	glog.V(1).Infof("GetBlocks: Downloading %d blocks from header %v to header %v from peer %v",
		len(blockNodesToFetch),
		blockNodesToFetch[0].Header,
		blockNodesToFetch[len(blockNodesToFetch)-1].Header,
		pp)
}

func (srv *Server) _handleHeaderBundle(pp *Peer, msg *MsgDeSoHeaderBundle) {
	printHeight := pp.StartingBlockHeight()
	if srv.blockchain.headerTip().Height > printHeight {
		printHeight = srv.blockchain.headerTip().Height
	}
	glog.Infof(CLog(Yellow, fmt.Sprintf("Received header bundle with %v headers "+
		"in state %s from peer %v. Downloaded ( %v / %v ) total headers",
		len(msg.Headers), srv.blockchain.chainState(), pp,
		srv.blockchain.headerTip().Header.Height, printHeight)))

	// Start by processing all of the headers given to us. They should start
	// right after the tip of our header chain ideally. While going through them
	// tally up the number that we actually process.
	numNewHeaders := 0
	for _, headerReceived := range msg.Headers {
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
		if srv.blockchain.HasHeader(headerHash) {
			if srv.blockchain.isSyncing() {

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
			}

			// Don't process duplicate headers.
			continue
		}

		// If we get here then we have a header we haven't seen before.
		// TODO: Delete? This is redundant.
		numNewHeaders++

		// Process the header, as we haven't seen it before.
		_, isOrphan, err := srv.blockchain.ProcessHeader(headerReceived, headerHash)

		// If this header is an orphan or we encountered an error for any reason,
		// disconnect from the peer. Because every header is sent in response to
		// a GetHeaders request, the peer should know enough to never send us
		// unconnectedTxns unless it's misbehaving.
		if err != nil || isOrphan {
			glog.Errorf("Server._handleHeaderBundle: Disconnecting from peer %v in state %s "+
				"because error occurred processing header: %v, isOrphan: %v",
				pp, srv.blockchain.chainState(), err, isOrphan)

			pp.Disconnect()
			return
		}
	}

	// After processing all the headers this will check to see if we are fully current
	// and send a request to our Peer to start a Mempool sync if so.
	//
	// This statement makes it so that if we boot up our node such that
	// its initial state is fully current we'll always bootstrap our mempools with a
	// mempool request. The alternative is that our state is not fully current
	// when we boot up, and we cover this second case in the _handleBlock function.
	srv._maybeRequestSync(pp)

	// At this point we should have processed all the headers. Now we will
	// make a decision on whether to request more headers from this peer based
	// on how many headers we received in this message. Since every HeaderBundle
	// is a response to a GetHeaders request from us with a HeaderLocator embedded in it, receiving
	// anything less than MaxHeadersPerMsg headers from a peer is sufficient to
	// make us think that the peer doesn't have any more interesting headers for us.
	// On the other hand, if the request contains MaxHeadersPerMsg, it is highly
	// likely we have not hit the tip of our peer's chain, and so requesting more
	// headers from the peer would likely be useful.
	if uint32(len(msg.Headers)) < MaxHeadersPerMsg || srv.blockchain.isTipMaxed(srv.blockchain.headerTip()) {
		// If we have exhausted the peer's headers but our header chain still isn't
		// current it means the peer we chose isn't current either. So disconnect
		// from her and try to sync with someone else.
		if srv.blockchain.chainState() == SyncStateSyncingHeaders {
			glog.V(1).Infof("Server._handleHeaderBundle: Disconnecting from peer %v because "+
				"we have exhausted their headers but our tip is still only "+
				"at time=%v height=%d", pp,
				time.Unix(int64(srv.blockchain.headerTip().Header.TstampSecs), 0),
				srv.blockchain.headerTip().Header.Height)
			pp.Disconnect()
			return
		}

		// If we get here it means that we've just finished syncing headers and we will proceed to
		// syncing state either through hyper sync or block sync. First let's check if the peer
		// supports hypersync and if our block tip is old enough so that it makes sense to sync state.
		if NodeCanHypersyncState(srv.cmgr.SyncType) && srv.blockchain.isHyperSyncCondition() {
			// If hypersync conditions are satisfied, we will be syncing state. This assignment results
			// in srv.blockchain.chainState() to be equal to SyncStateSyncingSnapshot
			srv.blockchain.syncingState = true
		}

		if srv.blockchain.chainState() == SyncStateSyncingSnapshot {
			glog.V(1).Infof("Server._handleHeaderBundle: *Syncing* state starting at "+
				"height %v from peer %v", srv.blockchain.headerTip().Header.Height, pp)

			// If node is a hyper sync node and we haven't finished syncing state yet, we will kick off state sync.
			if srv.cmgr.HyperSync {
				bestHeaderHeight := uint64(srv.blockchain.headerTip().Height)
				expectedSnapshotHeight := bestHeaderHeight - (bestHeaderHeight % srv.snapshot.SnapshotBlockHeightPeriod)
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
				srv.HyperSyncProgress.SnapshotMetadata = &SnapshotEpochMetadata{
					SnapshotBlockHeight:       expectedSnapshotHeight,
					FirstSnapshotBlockHeight:  expectedSnapshotHeight,
					CurrentEpochChecksumBytes: []byte{},
					CurrentEpochBlockHash:     srv.blockchain.bestHeaderChain[expectedSnapshotHeight].Hash,
				}
				srv.HyperSyncProgress.PrefixProgress = []*SyncPrefixProgress{}
				srv.HyperSyncProgress.Completed = false
				go srv.HyperSyncProgress.PrintLoop()

				// Initialize the snapshot checksum so that it's reset. It got modified during chain initialization
				// when processing seed transaction from the genesis block. So we need to clear it.
				srv.snapshot.Checksum.ResetChecksum()
				if err := srv.snapshot.Checksum.SaveChecksum(); err != nil {
					glog.Errorf("Server._handleHeaderBundle: Problem saving snapshot to database, error (%v)", err)
				}
				// Reset the migrations along with the main checksum.
				srv.snapshot.Migrations.ResetChecksums()
				if err := srv.snapshot.Migrations.SaveMigrations(); err != nil {
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
			// A maxHeight of -1 tells GetBlocks to fetch as many blocks as we can
			// from this peer without worrying about how many blocks the peer actually
			// has. We can do that in this case since this usually happens during sync
			// before we've made any GetBlocks requests to the peer.
			blockTip := srv.blockchain.blockTip()
			glog.V(1).Infof("Server._handleHeaderBundle: *Syncing* blocks starting at "+
				"height %d out of %d from peer %v",
				blockTip.Header.Height+1, msg.TipHeight, pp)
			maxHeight := -1
			srv.GetBlocks(pp, maxHeight)
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
			if !srv.blockchain.HasHeader(msg.TipHash) {
				glog.V(1).Infof("Server._handleHeaderBundle: Peer's tip is not in our "+
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
			glog.V(1).Infof("Server._handleHeaderBundle: *Downloading* blocks starting at "+
				"block tip %v out of %d from peer %v",
				blockTip.Header, msg.TipHeight, pp)
			srv.GetBlocks(pp, int(msg.TipHeight))
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
	locator, err := srv.blockchain.HeaderLocatorWithNodeHash(lastHash)
	if err != nil {
		glog.Warningf("Server._handleHeaderBundle: Disconnecting peer %v because "+
			"she indicated that she has more headers but the last hash %v in "+
			"the header bundle does not correspond to a block in our index.",
			pp, lastHash)
		pp.Disconnect()
		return
	}
	pp.AddDeSoMessage(&MsgDeSoGetHeaders{
		StopHash:     &BlockHash{},
		BlockLocator: locator,
	}, false)
	headerTip := srv.blockchain.headerTip()
	glog.V(1).Infof("Server._handleHeaderBundle: *Syncing* headers for blocks starting at "+
		"header tip %v out of %d from peer %v",
		headerTip.Header, msg.TipHeight, pp)
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
		pp.Disconnect()
		return
	}

	// If we're not syncing then we don't need the snapshot chunk so
	if srv.blockchain.ChainState() != SyncStateSyncingSnapshot {
		glog.Errorf("srv._handleSnapshot: Received a snapshot message from peer but chain is not currently syncing from "+
			"snapshot. This means peer is most likely misbehaving so we'll disconnect them. Peer: (%v)", pp)
		pp.Disconnect()
		return
	}

	if len(msg.SnapshotChunk) == 0 {
		// We should disconnect the peer because he is misbehaving or doesn't have the snapshot.
		glog.Errorf("srv._handleSnapshot: Received a snapshot messages with empty snapshot chunk "+
			"disconnecting misbehaving peer (%v)", pp)
		pp.Disconnect()
		return
	}

	glog.V(1).Infof(CLog(Yellow, fmt.Sprintf("Received a snapshot message with entry keys (First entry: "+
		"<%v>, Last entry: <%v>), (number of entries: %v), metadata (%v), and isEmpty (%v), from Peer %v",
		msg.SnapshotChunk[0].Key, msg.SnapshotChunk[len(msg.SnapshotChunk)-1].Key, len(msg.SnapshotChunk),
		msg.SnapshotMetadata, msg.SnapshotChunk[0].IsEmpty(), pp)))

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
		}
	}

	// Make sure that the expected snapshot height and blockhash match the ones in received message.
	if msg.SnapshotMetadata.SnapshotBlockHeight != srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight ||
		!bytes.Equal(msg.SnapshotMetadata.CurrentEpochBlockHash[:], srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochBlockHash[:]) {

		glog.Errorf("srv._handleSnapshot: blockheight (%v) and blockhash (%v) in msg do not match the expected "+
			"hyper sync height (%v) and hash (%v)",
			msg.SnapshotMetadata.SnapshotBlockHeight, msg.SnapshotMetadata.CurrentEpochBlockHash,
			srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight, srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochBlockHash)
		pp.Disconnect()
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
		pp.Disconnect()
		return
	}

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
		pp.Disconnect()
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
			pp.Disconnect()
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
			pp.Disconnect()
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
				pp.Disconnect()
				return
			}
			// Make sure that the dbChunk is sorted increasingly.
			if bytes.Compare(dbChunk[ii-1].Key, dbChunk[ii].Key) != -1 {
				// We should disconnect the peer because he is misbehaving
				glog.Errorf("srv._handleSnapshot: dbChunk entries are not sorted: first entry at index (%v) with "+
					"value (%v) and second entry with index (%v) and value (%v) disconnecting misbehaving peer (%v)",
					ii-1, dbChunk[ii-1].Key, ii, dbChunk[ii].Key, pp)
				srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes = prevChecksumBytes
				pp.Disconnect()
				return
			}
		}

		// Process the DBEntries from the msg and add them to the db.
		srv.timer.Start("Server._handleSnapshot Process Snapshot")
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

	glog.Infof(CLog(Yellow, fmt.Sprintf("Best header chain %v best block chain %v",
		srv.blockchain.bestHeaderChain[msg.SnapshotMetadata.SnapshotBlockHeight], srv.blockchain.bestChain)))

	// Verify that the state checksum matches the one in HyperSyncProgress snapshot metadata.
	// If the checksums don't match, it means that we've been interacting with a peer that was misbehaving.
	checksumBytes, err := srv.snapshot.Checksum.ToBytes()
	if err != nil {
		glog.Errorf("Server._handleSnapshot: Problem getting checksum bytes, error (%v)", err)
	}
	if !reflect.DeepEqual(checksumBytes, srv.HyperSyncProgress.SnapshotMetadata.CurrentEpochChecksumBytes) {
		if srv.nodeMessageChannel != nil {
			srv.nodeMessageChannel <- NodeErase
		}
		glog.Errorf(CLog(Red, fmt.Sprintf("Server._handleSnapshot: The final db checksum doesn't match the "+
			"checksum received from the peer. It is likely that HyperSync encountered some unexpected error earlier. "+
			"You should report this as an issue on DeSo github https://github.com/deso-protocol/core. It is also possible "+
			"that the peer is misbehaving and sent invalid snapshot chunks. In either way, we'll restart the node and "+
			"attempt to HyperSync from the beginning.")))
		return
	}

	// After syncing state from a snapshot, we will sync remaining blocks. To do so, we will
	// start downloading blocks from the snapshot height up to the blockchain tip. Since we
	// already synced all the state corresponding to the sub-blockchain ending at the snapshot
	// height, we will now mark all these blocks as processed. To do so, we will iterate through
	// the blockNodes in the header chain and set them in the blockchain data structures.
	err = srv.blockchain.db.Update(func(txn *badger.Txn) error {
		for ii := uint64(1); ii <= srv.HyperSyncProgress.SnapshotMetadata.SnapshotBlockHeight; ii++ {
			curretNode := srv.blockchain.bestHeaderChain[ii]
			// Do not set the StatusBlockStored flag, because we still need to download the past blocks.
			curretNode.Status |= StatusBlockProcessed
			curretNode.Status |= StatusBlockValidated
			srv.blockchain.blockIndex[*curretNode.Hash] = curretNode
			srv.blockchain.bestChainMap[*curretNode.Hash] = curretNode
			srv.blockchain.bestChain = append(srv.blockchain.bestChain, curretNode)
			err := PutHeightHashToNodeInfoWithTxn(txn, srv.snapshot, curretNode, false /*bitcoinNodes*/)
			if err != nil {
				return err
			}
		}
		// We will also set the hash of the block at snapshot height as the best chain hash.
		err := PutBestHashWithTxn(txn, srv.snapshot, msg.SnapshotMetadata.CurrentEpochBlockHash, ChainTypeDeSoBlock)
		return err
	})
	if err != nil {
		glog.Errorf("Server._handleSnapshot: Problem updating snapshot blocknodes, error: (%v)", err)
	}
	// We also reset the in-memory snapshot cache, because it is populated with stale records after
	// we've initialized the chain with seed transactions.
	srv.snapshot.DatabaseCache = lru.NewKVCache(DatabaseCacheSize)

	// If we got here then we finished the snapshot sync so set appropriate flags.
	srv.blockchain.syncingState = false
	srv.blockchain.snapshot.CurrentEpochSnapshotMetadata = srv.HyperSyncProgress.SnapshotMetadata

	// Update the snapshot epoch metadata in the snapshot DB.
	for ii := 0; ii < MetadataRetryCount; ii++ {
		srv.snapshot.SnapshotDbMutex.Lock()
		err = srv.snapshot.SnapshotDb.Update(func(txn *badger.Txn) error {
			return txn.Set(_prefixLastEpochMetadata, srv.snapshot.CurrentEpochSnapshotMetadata.ToBytes())
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

	glog.Infof("server._handleSnapshot: FINAL snapshot checksum is (%v)",
		srv.snapshot.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes)

	// Take care of any callbacks that need to run once the snapshot is completed.
	srv.eventManager.snapshotCompleted()

	// Now sync the remaining blocks.
	if srv.blockchain.archivalMode {
		srv.blockchain.downloadingHistoricalBlocks = true
		srv.GetBlocksToStore(pp)
		return
	}

	headerTip := srv.blockchain.headerTip()
	srv.GetBlocks(pp, int(headerTip.Height))
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
		if !peer.IsSyncCandidate() {
			glog.Infof("Peer is not sync candidate: %v", peer)
			continue
		}

		// Choose the peer with the best height out of everyone who's a
		// valid sync candidate.
		if peer.StartingBlockHeight() < bestHeight {
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
	locator := srv.blockchain.LatestHeaderLocator()
	bestPeer.AddDeSoMessage(&MsgDeSoGetHeaders{
		StopHash:     &BlockHash{},
		BlockLocator: locator,
	}, false)
	glog.V(1).Infof("Server._startSync: Downloading headers for blocks starting at "+
		"header tip height %v from peer %v", bestHeight, bestPeer)

	srv.SyncPeer = bestPeer
}

func (srv *Server) _handleNewPeer(pp *Peer) {
	isSyncCandidate := pp.IsSyncCandidate()
	isSyncing := srv.blockchain.isSyncing()
	chainState := srv.blockchain.chainState()
	glog.V(1).Infof("Server._handleNewPeer: Processing NewPeer: (%v); IsSyncCandidate(%v), syncPeerIsNil=(%v), IsSyncing=(%v), ChainState=(%v)",
		pp, isSyncCandidate, (srv.SyncPeer == nil), isSyncing, chainState)

	// Request a sync if we're ready
	srv._maybeRequestSync(pp)

	// Start syncing by choosing the best candidate.
	if isSyncCandidate && srv.SyncPeer == nil {
		srv._startSync()
	}
	if !isSyncCandidate {
		glog.Infof("Peer is not sync candidate: %v", pp)
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
	if newPeer == nil {
		// If we don't have a new Peer, remove everything that was destined for
		// this Peer. Note we don't need to copy the iterator because everything
		// below doesn't take a reference to it.
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
	// Request any hashes we might have reassigned in a goroutine to keep things
	// moving.
	newPeer.AddDeSoMessage(&MsgDeSoGetTransactions{
		HashList: txnHashesReassigned,
	}, false)
}

func (srv *Server) _handleDonePeer(pp *Peer) {
	glog.V(1).Infof("Server._handleDonePeer: Processing DonePeer: %v", pp)

	srv._cleanupDonePeerState(pp)

	// Attempt to find a new peer to sync from if the quitting peer is the
	// sync peer and if our blockchain isn't current.
	if srv.SyncPeer == pp && srv.blockchain.isSyncing() {

		srv.SyncPeer = nil
		srv._startSync()
	}
}

func (srv *Server) _relayTransactions() {
	glog.V(1).Infof("Server._relayTransactions: Waiting for mempool readOnlyView to regenerate")
	srv.mempool.BlockUntilReadOnlyViewRegenerated()
	glog.V(1).Infof("Server._relayTransactions: Mempool view has regenerated")

	// For each peer, compute the transactions they're missing from the mempool and
	// send them an inv.
	allPeers := srv.cmgr.GetAllPeers()
	txnList := srv.mempool.readOnlyUniversalTransactionList
	for _, pp := range allPeers {
		if !pp.canReceiveInvMessagess {
			glog.V(1).Infof("Skipping invs for peer %v because not ready "+
				"yet: %v", pp, pp.canReceiveInvMessagess)
			continue
		}
		// For each peer construct an inventory message that excludes transactions
		// for which the minimum fee is below what the Peer will allow.
		invMsg := &MsgDeSoInv{}
		for _, newTxn := range txnList {
			invVect := &InvVect{
				Type: InvTypeTx,
				Hash: *newTxn.Hash,
			}

			// If the peer has this txn already then skip it.
			if pp.knownInventory.Contains(*invVect) {
				continue
			}

			invMsg.InvList = append(invMsg.InvList, invVect)
		}
		if len(invMsg.InvList) > 0 {
			pp.AddDeSoMessage(invMsg, false)
		}
	}

	glog.V(1).Infof("Server._relayTransactions: Relay to all peers is complete!")
}

func (srv *Server) _addNewTxn(
	pp *Peer, txn *MsgDeSoTxn, rateLimit bool, verifySignatures bool) ([]*MempoolTx, error) {

	if srv.ReadOnlyMode {
		err := fmt.Errorf("Server._addNewTxnAndRelay: Not processing txn from peer %v "+
			"because peer is in read-only mode: %v", pp, srv.ReadOnlyMode)
		glog.V(1).Infof(err.Error())
		return nil, err
	}

	if srv.blockchain.chainState() != SyncStateFullyCurrent {

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

	srv.blockchain.ChainLock.RLock()
	newlyAcceptedTxns, err := srv.mempool.ProcessTransaction(
		txn, true /*allowUnconnectedTxn*/, rateLimit, peerID, verifySignatures)
	srv.blockchain.ChainLock.RUnlock()
	if err != nil {
		return nil, errors.Wrapf(err, "Server._handleTransaction: Problem adding transaction to mempool: ")
	}

	glog.V(1).Infof("Server._addNewTxnAndRelay: newlyAcceptedTxns: %v, Peer: %v", newlyAcceptedTxns, pp)

	return newlyAcceptedTxns, nil
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

	blockHash, _ := blk.Header.Hash()
	glog.V(1).Infof("_handleBlockMainChainDisconnect: Block %s height %d disconnected from "+
		"main chain and chain is current.", hex.EncodeToString(blockHash[:]), blk.Header.Height)
}

func (srv *Server) _maybeRequestSync(pp *Peer) {
	// Send the mempool message if DeSo and Bitcoin are fully current
	if srv.blockchain.chainState() == SyncStateFullyCurrent {
		// If peer is not nil and we haven't set a max sync blockheight, we will
		if pp != nil && srv.blockchain.MaxSyncBlockHeight == 0 {
			glog.V(1).Infof("Server._maybeRequestSync: Sending mempool message: %v", pp)
			pp.AddDeSoMessage(&MsgDeSoMempool{}, false)
		} else {
			glog.V(1).Infof("Server._maybeRequestSync: NOT sending mempool message because peer is nil: %v", pp)
		}
	} else {
		glog.V(1).Infof("Server._maybeRequestSync: NOT sending mempool message because not current: %v, %v",
			srv.blockchain.chainState(),
			pp)
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

	// Iterate through all the peers and relay the InvVect to them. This will only
	// actually be relayed if it's not already in the peer's knownInventory.
	allPeers := srv.cmgr.GetAllPeers()
	for _, pp := range allPeers {
		pp.AddDeSoMessage(&MsgDeSoInv{
			InvList: []*InvVect{invVect},
		}, false)
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
	pp.Disconnect()
}

func (srv *Server) _handleBlock(pp *Peer, blk *MsgDeSoBlock) {
	glog.Infof(CLog(Cyan, fmt.Sprintf("Server._handleBlock: Received block ( %v / %v ) from Peer %v",
		blk.Header.Height, srv.blockchain.headerTip().Height, pp)))

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
	if srv.blockchain.isTipMaxed(srv.blockchain.blockTip()) &&
		blockHeader.Height > uint64(srv.blockchain.blockTip().Height) {

		glog.Infof("Server._handleBlock: Exiting because block tip is maxed out")
		return
	}

	// Compute the hash of the block.
	blockHash, err := blk.Header.Hash()
	if err != nil {
		// This should never happen if we got this far but log the error, clear the
		// requestedBlocks, disconnect from the peer and return just in case.
		srv._logAndDisconnectPeer(
			pp, blk, "Problem computing block hash")
		return
	}

	if pp != nil {
		if _, exists := pp.requestedBlocks[*blockHash]; !exists {
			glog.Errorf("_handleBlock: Getting a block that we haven't requested before, "+
				"block hash (%v)", *blockHash)
		}
		delete(pp.requestedBlocks, *blockHash)
	} else {
		glog.Errorf("_handleBlock: Called with nil peer, this should never happen.")
	}

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

	// Only verify signatures for recent blocks.
	var isOrphan bool
	if srv.blockchain.isSyncing() {
		glog.V(1).Infof(CLog(Cyan, fmt.Sprintf("Server._handleBlock: Processing block %v WITHOUT "+
			"signature checking because SyncState=%v for peer %v",
			blk, srv.blockchain.chainState(), pp)))
		_, isOrphan, err = srv.blockchain.ProcessBlock(blk, false)

	} else {
		// TODO: Signature checking slows things down because it acquires the ChainLock.
		// The optimal solution is to check signatures in a way that doesn't acquire the
		// ChainLock, which is what Bitcoin Core does.
		glog.V(1).Infof(CLog(Cyan, fmt.Sprintf("Server._handleBlock: Processing block %v WITH "+
			"signature checking because SyncState=%v for peer %v",
			blk, srv.blockchain.chainState(), pp)))
		_, isOrphan, err = srv.blockchain.ProcessBlock(blk, true)
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
		} else {
			srv._logAndDisconnectPeer(
				pp, blk,
				errors.Wrapf(err, "Error while processing block: ").Error())
			return
		}
	}
	if isOrphan {
		// We should generally never receive orphan blocks. It indicates something
		// went wrong in our headers syncing.
		glog.Errorf("ERROR: Received orphan block with hash %v height %v. "+
			"This should never happen", blockHash, blk.Header.Height)
		return
	}
	srv.timer.End("Server._handleBlock: Process Block")

	srv.timer.Print("Server._handleBlock: General")
	srv.timer.Print("Server._handleBlock: Process Block")

	// We shouldn't be receiving blocks while syncing headers.
	if srv.blockchain.chainState() == SyncStateSyncingHeaders {
		srv._logAndDisconnectPeer(
			pp, blk,
			"We should never get blocks when we're syncing headers")
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
		srv.GetBlocks(pp, maxHeight)
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
		locator := srv.blockchain.LatestHeaderLocator()
		pp.AddDeSoMessage(&MsgDeSoGetHeaders{
			StopHash:     &BlockHash{},
			BlockLocator: locator,
		}, false)
		return
	}

	// If we get here, it means we're in SyncStateFullySynced, which is great.
	// In this case we shoot a MEMPOOL message over to the peer to bootstrap the mempool.
	srv._maybeRequestSync(pp)
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

func (srv *Server) ProcessSingleTxnWithChainLock(
	pp *Peer, txn *MsgDeSoTxn) ([]*MempoolTx, error) {
	// Lock the chain for reading so that transactions don't shift under our feet
	// when processing this bundle. Not doing this could cause us to miss transactions
	// erroneously.
	//
	// TODO(performance): We should probably do this less frequently.
	srv.blockchain.ChainLock.RLock()
	defer func() {
		srv.blockchain.ChainLock.RUnlock()
	}()
	// Note we set rateLimit=false because we have a global minimum txn fee that should
	// prevent spam on its own.
	return srv.mempool.ProcessTransaction(
		txn, true /*allowUnconnectedTxn*/, false, /*rateLimit*/
		pp.ID, true /*verifySignatures*/)
}

func (srv *Server) _processTransactions(pp *Peer, msg *MsgDeSoTransactionBundle) []*MempoolTx {
	// Try and add all the transactions to our mempool in the order we received
	// them. If any fail to get added, just log an error.
	//
	// TODO: It would be nice if we did something fancy here like if we kept
	// track of rejected transactions and retried them every time we connected
	// a block. Doing something like this would make it so that if a transaction
	// was initially rejected due to us not having its dependencies, then we
	// will eventually add it as opposed to just forgetting about it.
	glog.V(2).Infof("Server._handleTransactionBundle: Processing message %v from "+
		"peer %v", msg, pp)
	transactionsToRelay := []*MempoolTx{}
	for _, txn := range msg.Transactions {
		// Process the transaction with rate-limiting while allowing unconnectedTxns and
		// verifying signatures.
		newlyAcceptedTxns, err := srv.ProcessSingleTxnWithChainLock(pp, txn)
		if err != nil {
			glog.Errorf(fmt.Sprintf("Server._handleTransactionBundle: Rejected "+
				"transaction %v from peer %v from mempool: %v", txn, pp, err))
			// A peer should know better than to send us a transaction that's below
			// our min feerate, which they see when we send them a version message.
			if err == TxErrorInsufficientFeeMinFee {
				glog.Errorf(fmt.Sprintf("Server._handleTransactionBundle: Disconnecting "+
					"Peer %v for sending us a transaction %v with fee below the minimum fee %d",
					pp, txn, srv.mempool.minFeeRateNanosPerKB))
				pp.Disconnect()
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

func (srv *Server) _handleMempool(pp *Peer, msg *MsgDeSoMempool) {
	glog.V(1).Infof("Server._handleMempool: Received Mempool message from Peer %v", pp)

	pp.canReceiveInvMessagess = true
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

func (srv *Server) _handleAddrMessage(pp *Peer, msg *MsgDeSoAddr) {
	srv.addrsToBroadcastLock.Lock()
	defer srv.addrsToBroadcastLock.Unlock()

	glog.V(1).Infof("Server._handleAddrMessage: Received Addr from peer %v with addrs %v", pp, spew.Sdump(msg.AddrList))

	// If this addr message contains more than the maximum allowed number of addresses
	// then disconnect this peer.
	if len(msg.AddrList) > MaxAddrsPerAddrMsg {
		glog.Errorf(fmt.Sprintf("Server._handleAddrMessage: Disconnecting "+
			"Peer %v for sending us an addr message with %d transactions, which exceeds "+
			"the max allowed %d",
			pp, len(msg.AddrList), MaxAddrsPerAddrMsg))
		pp.Disconnect()
		return
	}

	// Add all the addresses we received to the addrmgr.
	netAddrsReceived := []*wire.NetAddress{}
	for _, addr := range msg.AddrList {
		addrAsNetAddr := wire.NewNetAddressIPPort(addr.IP, addr.Port, (wire.ServiceFlag)(addr.Services))
		if !addrmgr.IsRoutable(addrAsNetAddr) {
			glog.V(1).Infof("Dropping address %v from peer %v because it is not routable", addr, pp)
			continue
		}

		netAddrsReceived = append(
			netAddrsReceived, addrAsNetAddr)
	}
	srv.cmgr.AddrMgr.AddAddresses(netAddrsReceived, pp.netAddr)

	// If the message had <= 10 addrs in it, then queue all the addresses for relaying
	// on the next cycle.
	if len(msg.AddrList) <= 10 {
		glog.V(1).Infof("Server._handleAddrMessage: Queueing %d addrs for forwarding from "+
			"peer %v", len(msg.AddrList), pp)
		sourceAddr := &SingleAddr{
			Timestamp: time.Now(),
			IP:        pp.netAddr.IP,
			Port:      pp.netAddr.Port,
			Services:  pp.serviceFlags,
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
}

func (srv *Server) _handleGetAddrMessage(pp *Peer, msg *MsgDeSoGetAddr) {
	glog.V(1).Infof("Server._handleGetAddrMessage: Received GetAddr from peer %v", pp)
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
	pp.AddDeSoMessage(res, false)
}

func (srv *Server) _handleControlMessages(serverMessage *ServerMessage) (_shouldQuit bool) {
	switch serverMessage.Msg.(type) {
	// Control messages used internally to signal to the server.
	case *MsgDeSoNewPeer:
		srv._handleNewPeer(serverMessage.Peer)
	case *MsgDeSoDonePeer:
		srv._handleDonePeer(serverMessage.Peer)
	case *MsgDeSoQuit:
		return true
	}

	return false
}

func (srv *Server) _handlePeerMessages(serverMessage *ServerMessage) {
	// Handle all non-control message types from our Peers.
	switch msg := serverMessage.Msg.(type) {
	// Messages sent among peers.
	case *MsgDeSoGetHeaders:
		srv._handleGetHeaders(serverMessage.Peer, msg)
	case *MsgDeSoHeaderBundle:
		srv._handleHeaderBundle(serverMessage.Peer, msg)
	case *MsgDeSoGetBlocks:
		srv._handleGetBlocks(serverMessage.Peer, msg)
	case *MsgDeSoBlock:
		srv._handleBlock(serverMessage.Peer, msg)
	case *MsgDeSoGetSnapshot:
		srv._handleGetSnapshot(serverMessage.Peer, msg)
	case *MsgDeSoSnapshotData:
		srv._handleSnapshot(serverMessage.Peer, msg)
	case *MsgDeSoGetTransactions:
		srv._handleGetTransactions(serverMessage.Peer, msg)
	case *MsgDeSoTransactionBundle:
		srv._handleTransactionBundle(serverMessage.Peer, msg)
	case *MsgDeSoMempool:
		srv._handleMempool(serverMessage.Peer, msg)
	case *MsgDeSoInv:
		srv._handleInv(serverMessage.Peer, msg)
	}
}

// Note that messageHandler is single-threaded and so all of the handle* functions
// it calls can assume they can access the Server's variables without concurrency
// issues.
func (srv *Server) messageHandler() {
	for {
		// This is used instead of the shouldQuit control message exist mechanism below. shouldQuit will be true only
		// when all incoming messages have been processed, on the other hand this shutdown will quit immediately.
		if atomic.LoadInt32(&srv.shutdown) >= 1 {
			break
		}
		serverMessage := <-srv.incomingMessages
		glog.V(2).Infof("Server.messageHandler: Handling message of type %v from Peer %v",
			serverMessage.Msg.GetMsgType(), serverMessage.Peer)

		// If the message is an addr message we handle it independent of whether or
		// not the BitcoinManager is synced.
		if serverMessage.Msg.GetMsgType() == MsgTypeAddr {
			srv._handleAddrMessage(serverMessage.Peer, serverMessage.Msg.(*MsgDeSoAddr))
			continue
		}
		// If the message is a GetAddr message we handle it independent of whether or
		// not the BitcoinManager is synced.
		if serverMessage.Msg.GetMsgType() == MsgTypeGetAddr {
			srv._handleGetAddrMessage(serverMessage.Peer, serverMessage.Msg.(*MsgDeSoGetAddr))
			continue
		}

		srv._handlePeerMessages(serverMessage)

		// Always check for and handle control messages regardless of whether the
		// BitcoinManager is synced. Note that we filter control messages out in a
		// Peer's inHander so any control message we get at this point should be bona fide.
		shouldQuit := srv._handleControlMessages(serverMessage)
		if shouldQuit {
			break
		}
	}

	// If we broke out of the select statement then it's time to allow things to
	// clean up.
	srv.waitGroup.Done()
	glog.V(2).Info("Server.Start: Server done")
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

// Must be run inside a goroutine. Relays addresses to peers at regular intervals
// and relays our own address to peers once every 24 hours.
func (srv *Server) _startAddressRelayer() {
	for numMinutesPassed := 0; ; numMinutesPassed++ {
		if atomic.LoadInt32(&srv.shutdown) >= 1 {
			break
		}
		// For the first ten minutes after the server starts, relay our address to all
		// peers. After the first ten minutes, do it once every 24 hours.
		glog.V(1).Infof("Server.Start._startAddressRelayer: Relaying our own addr to peers")
		if numMinutesPassed < 10 || numMinutesPassed%(RebroadcastNodeAddrIntervalMinutes) == 0 {
			for _, pp := range srv.cmgr.GetAllPeers() {
				bestAddress := srv.cmgr.AddrMgr.GetBestLocalAddress(pp.netAddr)
				if bestAddress != nil {
					glog.V(2).Infof("Server.Start._startAddressRelayer: Relaying address %v to "+
						"peer %v", bestAddress.IP.String(), pp)
					pp.AddDeSoMessage(&MsgDeSoAddr{
						AddrList: []*SingleAddr{
							{
								Timestamp: time.Now(),
								IP:        bestAddress.IP,
								Port:      bestAddress.Port,
								Services:  (ServiceFlag)(bestAddress.Services),
							},
						},
					}, false)
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
			pp.AddDeSoMessage(&MsgDeSoAddr{
				AddrList: addrsToBroadcast,
			}, false)
		}
		time.Sleep(AddrRelayIntervalSeconds * time.Second)
		continue
	}
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

	// Stop the miner if we have one running.
	if srv.miner != nil {
		srv.miner.Stop()
		glog.Infof(CLog(Yellow, "Server.Stop: Closed the Miner"))
	}

	if srv.mempool != nil {
		// Before the node shuts down, write all the mempool txns to disk
		// if the flag is set.
		if srv.mempool.mempoolDir != "" {
			glog.Info("Doing final mempool dump...")
			srv.mempool.DumpTxnsToDB()
			glog.Info("Final mempool dump complete!")
		}

		srv.mempool.Stop()
		glog.Infof(CLog(Yellow, "Server.Stop: Closed Mempool"))
	}

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
	go srv.messageHandler()

	go srv._startAddressRelayer()

	go srv._startTransactionRelayer()

	// Once the ConnectionManager is started, peers will be found and connected to and
	// messages will begin to flow in to be processed.
	if !srv.DisableNetworking {
		go srv.cmgr.Start()
	}

	if srv.miner != nil && len(srv.miner.PublicKeys) > 0 {
		go srv.miner.Start()
	}
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
