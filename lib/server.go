package lib

import (
	"encoding/hex"
	"fmt"
	"net"
	"runtime"
	"strings"
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

// ServerReply is used to signal to outside programs that a particuler ServerMessage
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
	mempool       *DeSoMempool
	miner         *DeSoMiner
	blockProducer *DeSoBlockProducer
	eventManager  *EventManager

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
	disableNetworking bool

	// When set to true, transactions created on this node will be ignored.
	readOnlyMode                 bool
	ignoreInboundPeerInvMessages bool

	// Becomes true after the node has processed its first transaction bundle from
	// any peer. This is useful in a deployment setting because it makes it so that
	// a health check can wait until this value becomes true.
	hasProcessedFirstTransactionBundle bool

	statsdClient *statsd.Client

	Notifier *Notifier
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
	// Just be lazy and remove the hash from everything indiscriminantly to
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

// NewServer initializes all of the internal data structures. Right now this basically
// looks as follows:
// - ConnectionManager starts and keeps track of peers.
// - When messages are received from peers, they get forwarded on a channel to
//   the Server to handle them. In that sense the ConnectionManager is basically
//   just acting as a router.
// - When the Server receives a message from a peer, it can do any of the following:
//   * Take no action.
//   * Use the Blockchain data structure to validate the transaction or update the.
//     Blockchain data structure.
//   * Send a new message. This can be a message directed back to that actually sent this
//     message or it can be a message to another peer for whatever reason. When a message
//     is sent in this way it can also have a deadline on it that the peer needs to
//     respond by or else it will be disconnected.
//   * Disconnect the peer. In this case the ConnectionManager gets notified about the
//     disconnection and may opt to replace the now-disconnected peer with a  new peer.
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
	_rateLimitFeerateNanosPerKB uint64,
	_minFeeRateNanosPerKB uint64,
	_stallTimeoutSeconds uint64,
	_maxBlockTemplatesToCache uint64,
	_minBlockUpdateIntervalSeconds uint64,
	_blockCypherAPIKey string,
	_runReadOnlyUtxoViewUpdater bool,
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
) (*Server, error) {

	// Create an empty Server object here so we can pass a reference to it to the
	// ConnectionManager.
	srv := &Server{
		disableNetworking:            _disableNetworking,
		readOnlyMode:                 _readOnlyMode,
		ignoreInboundPeerInvMessages: _ignoreInboundPeerInvMessages,
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
		_stallTimeoutSeconds, _minFeeRateNanosPerKB,
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
	eventManager.OnBlockConnected(srv._handleBlockMainChainConnectedd)
	eventManager.OnBlockAccepted(srv._handleBlockAccepted)
	eventManager.OnBlockDisconnected(srv._handleBlockMainChainDisconnectedd)

	_chain, err := NewBlockchain(
		_trustedBlockProducerPublicKeys,
		_trustedBlockProducerStartHeight,
		_params, timesource, _db, postgres, eventManager)
	if err != nil {
		return nil, errors.Wrapf(err, "NewServer: Problem initializing blockchain")
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
				for ii, na := range srv.cmgr.addrMgr.GetAllAddrs() {
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
		return nil, errors.Wrapf(err, "NewServer: ")
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

	return srv, nil
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
	// our best *block* chain not our best *header* chain. The reaason for
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
	glog.Infof("Received header bundle with %v headers "+
		"in state %s from peer %v. Downloaded ( %v / %v ) total headers",
		len(msg.Headers), srv.blockchain.chainState(), pp,
		srv.blockchain.headerTip().Header.Height, pp.StartingBlockHeight())

	// Start by processing all of the headers given to us. They should start
	// right after the tip of our header chain ideally. While going through them
	// tally up the number that we actually process.
	numNewHeaders := 0
	for _, headerReceived := range msg.Headers {
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
		numNewHeaders++

		// Process the header, as we haven't seen it before.
		_, isOrphan, err := srv.blockchain.ProcessHeader(headerReceived, headerHash)

		// If this header is an orphan or we encoutnered an error for any reason,
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
	if uint32(len(msg.Headers)) < MaxHeadersPerMsg {
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

		// If we have exhausted the peer's headers but our blocks aren't current,
		// send a GetBlocks message to the peer for as many blocks as we can get.
		if srv.blockchain.chainState() == SyncStateSyncingBlocks {
			// A maxHeight of -1 tells GetBlocks to fetch as many blocks as we can
			// from this peer without worrying about how many blocks the peer actually
			// has. We can do that in this case since this usually happens dring sync
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
	// since we update requestedBLocks when a Peer disconnects to remove any
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
}

func (srv *Server) _cleanupDonePeerPeerState(pp *Peer) {
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

func (srv *Server) _handleBitcoinManagerUpdate(bmUpdate *MsgDeSoBitcoinManagerUpdate) {
	glog.V(1).Infof("Server._handleBitcoinManagerUpdate: Being called")

	// Regardless of whether the DeSo chain is in-sync, consider adding any BitcoinExchange
	// transactions we've found to our mempool. We do this to minimize the chances that the
	// network ever loses track of someone's BitcoinExchange.
	if len(bmUpdate.TransactionsFound) > 0 {
		go func() {
			glog.V(2).Infof("Server._handleBitcoinManagerUpdate: BitcoinManager "+
				"found %d BitcoinExchange transactions for us to consider",
				len(bmUpdate.TransactionsFound))

			// Put all the transactions through some validation to see if they're
			// worth our time. This saves us from getting spammed by _addNewTxnAndRelay
			// when processing stale blocks.
			//
			// Note that we pass a nil mempool in order to avoid considering transactions
			// that are in the mempool but lacking a merkle proof. If transactions are
			// invalid then a separate mempool check later will catch them.
			validTransactions := []*MsgDeSoTxn{}
			for _, burnTxn := range bmUpdate.TransactionsFound {
				err := srv.blockchain.ValidateTransaction(
					burnTxn, srv.blockchain.blockTip().Height+1, true, /*verifySignatures*/
					nil /*mempool*/)
				if err == nil {
					validTransactions = append(validTransactions, burnTxn)
				} else {
					glog.V(1).Infof("Server._handleBitcoinManagerUpdate: Problem adding Bitcoin "+
						"burn transaction: %v", err)
				}
			}

			glog.V(2).Infof("Server._handleBitcoinManagerUpdate: Processing %d out of %d "+
				"transactions that were actually valid", len(validTransactions),
				len(bmUpdate.TransactionsFound))

			totalAdded := 0
			for _, validTx := range validTransactions {
				// This shouldn't care about the min burn work because it tries to add to
				// the mempool directly. We should never get an error here because we've already
				// validated all of the transactions.
				//
				// Note we set rateLimit=false because we have a global minimum txn fee that should
				// prevent spam on its own.
				mempoolTxs, err := srv._addNewTxn(
					nil, validTx, false /*rateLimit*/, true /*verifySignatures*/)
				totalAdded += len(mempoolTxs)

				if err != nil {
					glog.V(1).Infof("Server._handleBitcoinManagerUpdate: Problem adding Bitcoin "+
						"burn transaction during _addNewTxnAndRelay: %v", err)
				}
			}

			// If we're fully current after accepting all the BitcoinExchange txns then let the
			// peer start sending us INV messages
			srv._maybeRequestSync(nil)

			glog.V(2).Infof("Server._handleBitcoinManagerUpdate: Successfully added %d out of %d "+
				"transactions", totalAdded, len(bmUpdate.TransactionsFound))
		}()
	}

	// If we don't have a SyncPeer right now, kick off a sync if we can. No need to
	// check if we're syncing or not since all this does is send a getheaders to a
	// Peer who's available.
	if srv.SyncPeer == nil {
		glog.V(1).Infof("Server._handleBitcoinManagerUpdate: SyncPeer is nil; calling startSync")
		srv._startSync()
		return
	}

	if !srv.blockchain.isSyncing() {

		//glog.V(1).Infof("Server._handleBitcoinManagerUpdate: SyncPeer is NOT nil and " +
		//	"BitcoinManager is time-current; sending " +
		//	"DeSo getheaders for good measure")
		glog.V(1).Infof("Server._handleBitcoinManagerUpdate: SyncPeer is NOT nil; sending " +
			"DeSo getheaders for good measure")
		locator := srv.blockchain.LatestHeaderLocator()
		srv.SyncPeer.AddDeSoMessage(&MsgDeSoGetHeaders{
			StopHash:     &BlockHash{},
			BlockLocator: locator,
		}, false)
	}

	// Note there is an edge case where we may be stuck in state SyncingBlocks. Calilng
	// GetBlocks when we're in this state fixes the edge case and doesn't have any
	// negative side-effects otherwise.
	if srv.blockchain.chainState() == SyncStateSyncingBlocks ||
		srv.blockchain.chainState() == SyncStateNeedBlocksss {

		glog.V(1).Infof("Server._handleBitcoinManagerUpdate: SyncPeer is NOT nil and " +
			"BitcoinManager is time-current; node is in SyncStateSyncingBlocks. Calling " +
			"GetBlocks for good measure.")
		// Setting maxHeight = -1 gets us as many blocks as we can get from our
		// peer, which is OK because we can assume the peer has all of them when
		// we're syncing.
		maxHeight := -1
		srv.GetBlocks(srv.SyncPeer, maxHeight)
		return
	}
}

func (srv *Server) _handleDonePeer(pp *Peer) {
	glog.V(1).Infof("Server._handleDonePeer: Processing DonePeer: %v", pp)

	srv._cleanupDonePeerPeerState(pp)

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

	if srv.readOnlyMode {
		err := fmt.Errorf("Server._addNewTxnAndRelay: Not processing txn from peer %v "+
			"because peer is in read-only mode: %v", pp, srv.readOnlyMode)
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
	newlyAcceptedTxns := srv.mempool.UpdateAfterConnectBlock(blk)
	_ = newlyAcceptedTxns

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
		if pp != nil {
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
	if srv.blockchain.isSyncing() {
		return
	}

	// If we're fully current after accepting all the blocks but we have not
	// yet requested all of the mempool transactions from one of our peers, do
	// that now. This covers the case where our node is behind when it boots
	// up, making it so that right at the end of the node's initial sync, after
	// everything has been connected, we then bootstrap our mempool.
	srv._maybeRequestSync(nil)

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
	glog.Infof("Server._handleBlock: Received block ( %v / %v ) from Peer %v",
		blk.Header.Height, srv.blockchain.headerTip().Height, pp)

	// Pull out the header for easy access.
	blockHeader := blk.Header
	if blockHeader == nil {
		// Should never happen but check it nevertheless.
		srv._logAndDisconnectPeer(pp, blk, "Header was nil")
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
		delete(pp.requestedBlocks, *blockHash)
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

	// Only verify signatures for recent blocks.
	var isOrphan bool
	if srv.blockchain.isSyncing() {
		glog.V(1).Infof("Server._handleBlock: Processing block %v WITHOUT "+
			"signature checking because SyncState=%v for peer %v",
			blk, srv.blockchain.chainState(), pp)
		_, isOrphan, err = srv.blockchain.ProcessBlock(blk, false)

	} else {
		// TODO: Signature checking slows things down because it acquires the ChainLock.
		// The optimal solution is to check signatures in a way that doesn't acquire the
		// ChainLock, which is what Bitcoin Core does.
		glog.V(1).Infof("Server._handleBlock: Processing block %v WITH "+
			"signature checking because SyncState=%v for peer %v",
			blk, srv.blockchain.chainState(), pp)
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

	// We shouldn't be receiving blocks while syncing headers.
	if srv.blockchain.chainState() == SyncStateSyncingHeaders {
		srv._logAndDisconnectPeer(
			pp, blk,
			"We should never get blocks when we're syncing headers")
		return
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
	if !peer.isOutbound && srv.ignoreInboundPeerInvMessages {
		glog.Infof("_handleInv: Ignoring inv message from inbound peer because "+
			"ignore_outbound_peer_inv_messages=true: %v", peer)
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
	srv.cmgr.addrMgr.AddAddresses(netAddrsReceived, pp.netAddr)

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
	netAddrsFound := srv.cmgr.addrMgr.AddressCache()
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
	switch msg := serverMessage.Msg.(type) {
	// Control messages used internally to signal to the server.
	case *MsgDeSoNewPeer:
		srv._handleNewPeer(serverMessage.Peer)
	case *MsgDeSoDonePeer:
		srv._handleDonePeer(serverMessage.Peer)
	case *MsgDeSoBitcoinManagerUpdate:
		srv._handleBitcoinManagerUpdate(msg)
	case *MsgDeSoQuit:
		return true
	}

	return false
}

func (srv *Server) _handlePeerMessages(serverMessage *ServerMessage) {
	// Handle all non-control message types from our Peers.
	switch msg := serverMessage.Msg.(type) {
	// Messages sent among peers.
	case *MsgDeSoBlock:
		srv._handleBlock(serverMessage.Peer, msg)
	case *MsgDeSoGetHeaders:
		srv._handleGetHeaders(serverMessage.Peer, msg)
	case *MsgDeSoHeaderBundle:
		srv._handleHeaderBundle(serverMessage.Peer, msg)
	case *MsgDeSoGetBlocks:
		srv._handleGetBlocks(serverMessage.Peer, msg)
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

		// Signal to whatever sent us this message that we're done processing
		// the block.
		if serverMessage.ReplyChan != nil {
			serverMessage.ReplyChan <- &ServerReply{}
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
		// For the first ten minutes after the server starts, relay our address to all
		// peers. After the first ten minutes, do it once every 24 hours.
		glog.V(1).Infof("Server.Start._startAddressRelayer: Relaying our own addr to peers")
		if numMinutesPassed < 10 || numMinutesPassed%(RebroadcastNodeAddrIntervalMinutes) == 0 {
			for _, pp := range srv.cmgr.GetAllPeers() {
				bestAddress := srv.cmgr.addrMgr.GetBestLocalAddress(pp.netAddr)
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
	for {
		// Just continuously relay transactions to peers that don't have them.
		srv._relayTransactions()
	}
}

func (srv *Server) Stop() {
	glog.Info("Server.Stop: Gracefully shutting down Server")

	// Iterate through all the peers and flush their logs before we quit.
	glog.Info("Server.Stop: Flushing logs for all peers")

	// Stop the ConnectionManager
	srv.cmgr.Stop()

	// Stop the miner if we have one running.
	if srv.miner != nil {
		srv.miner.Stop()
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
	}

	// Stop the block producer
	if srv.blockProducer != nil {
		srv.blockProducer.Stop()
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
	if !srv.disableNetworking {
		go srv.cmgr.Start()
	}

	if srv.miner != nil && len(srv.miner.PublicKeys) > 0 {
		go srv.miner.Start()
	}
}
