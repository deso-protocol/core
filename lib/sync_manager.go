package lib

import (
	"fmt"
	"github.com/deso-protocol/go-deadlock"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"reflect"
	"strings"
	"time"
)

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

type SyncManager struct {
	forceChecksum bool
	// inventoryBeingProcessed keeps track of the inventory (hashes of blocks and
	// transactions) that we've recently processed from peers. It is useful for
	// avoiding situations in which we re-fetch the same data from many peers.
	// For example, if we get the same Block inv message from multiple peers,
	// adding it to this map and checking this map before replying will make it
	// so that we only send a reply to the first peer that sent us the inv, which
	// is more efficient.
	inventoryBeingProcessed lru.Cache

	// Make this hold a multiple of what we hold for individual peers.
	srv.inventoryBeingProcessed = lru.NewCache(maxKnownInventory)
	srv.requestTimeoutSeconds = 10
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


	// dataLock protects requestedTxns and requestedBlocks
	dataLock deadlock.Mutex

	// requestedTransactions contains hashes of transactions for which we have
	// requested data but have not yet received a response.
	requestedTransactionsMap     map[BlockHash]*GetDataRequestInfo
	IgnoreInboundPeerInvMessages bool
	// Becomes true after the node has processed its first transaction bundle from
	// any peer. This is useful in a deployment setting because it makes it so that
	// a health check can wait until this value becomes true.
	hasProcessedFirstTransactionBundle bool

	// DbMutex protects the badger database from concurrent access when it's being closed & re-opened.
	// This is necessary because the database is closed & re-opened when the node finishes hypersyncing in order
	// to change the database options from Default options to Performance options.
	DbMutex deadlock.Mutex

	// When --hypersync is set to true we will attempt fast block synchronization
	HyperSync bool
	// We have the following options for SyncType:
	// - any: Will sync with a node no matter what kind of syncing it supports.
	// - blocksync: Will sync by connecting blocks from the beginning of time.
	// - hypersync-archival: Will sync by hypersyncing state, but then it will
	//   still download historical blocks at the end. Can only be set if HyperSync
	//   is true.
	// - hypersync: Will sync by downloading historical state, and will NOT
	//   download historical blocks. Can only be set if HyperSync is true.
	SyncType NodeSyncType

	// Keep track of the nonces we've sent in our version messages so
	// we can prevent connections to ourselves.
	sentNonces lru.Cache
	//		sentNonces: lru.NewCache(1000),

	minFeeRateNanosPerKB uint64

	// SyncType indicates whether blocksync should not be requested for this peer. If set to true
	// then we'll only hypersync from this peer.
	syncType NodeSyncType

	// Each Peer is only allowed to have certain number of blocks being sent
	// to them at any gven time. We use
	// this value to enforce that constraint. The reason we need to do this is without
	// it one peer could theoretically clog our Server by issuing many GetBlocks
	// requests that ultimately don't get delivered. This way the number of blocks
	// being sent is limited to a multiple of the number of Peers we have.
	blocksToSendMtx deadlock.Mutex
	blocksToSend    map[BlockHash]bool

	//FIXME: Do this as a handler on version message
	// Move this to sync manager
	pp.startingHeight = verMsg.StartBlockHeight
}

func NewSyncManager() *SyncManager {

	switch {
	case MsgTypeGetBlocks:
		msg := msgToProcess.DeSoMessage.(*MsgDeSoGetBlocks)
		glog.V(1).Infof("startDeSoMessageProcessor: RECEIVED message of type %v with "+
			"num hashes %v from peer %v", msgToProcess.DeSoMessage.GetMsgType(), len(msg.HashList), pp)
		pp.HandleGetBlocks(msg)

	case MsgTypeGetSnapshot:
		msg := msgToProcess.DeSoMessage.(*MsgDeSoGetSnapshot)
		glog.V(1).Infof("startDeSoMessageProcessor: RECEIVED message of type %v with start key %v "+
			"and prefix %v from peer %v", msgToProcess.DeSoMessage.GetMsgType(), msg.SnapshotStartKey, msg.GetPrefix(), pp)

		pp.HandleGetSnapshot(msg)
	}

	return &SyncManager{
		requestedTransactionsMap: make(map[BlockHash]*GetDataRequestInfo),
	}
}


// StartingBlockHeight is the height of the peer's blockchain tip.
func (pp *Peer) StartingBlockHeight() uint32 {
	pp.StatsMtx.RLock()
	defer pp.StatsMtx.RUnlock()
	return pp.startingHeight
}

func (sm *SyncManager) _handleOutExpectedResponse(msg DeSoMessage) {
	// If we're sending the peer a GetBlocks message, we expect to receive the
	// blocks at minimum within a few seconds of each other.
	stallTimeout := time.Duration(int64(pp.stallTimeoutSeconds) * int64(time.Second))
	switch msg.GetMsgType() {
	case MsgTypeGetBlocks:
		getBlocks := msg.(*MsgDeSoGetBlocks)
		// We have one block expected for each entry in the message.
		for ii := range getBlocks.HashList {
			pp._addExpectedResponse(&ExpectedResponse{
				TimeExpected: time.Now().Add(
					stallTimeout + time.Duration(int64(ii)*int64(stallTimeout))),
				MessageType: MsgTypeBlock,
			})
		}
	case MsgTypeGetHeaders:
		// If we're sending a GetHeaders message, the Peer should respond within
		// a few seconds with a HeaderBundle.
		pp._addExpectedResponse(&ExpectedResponse{
			TimeExpected: time.Now().Add(stallTimeout),
			MessageType:  MsgTypeHeaderBundle,
		})
	}

	// TODO: This was in Peer's outHandler, this could happen while we enqueue this message.
	// TODO: ============================
	//		Move this to Sync Manager
	// If we're sending a block, remove it from our blocksToSend map to allow
	// the peer to request more blocks after receiving this one.
	if msg.GetMsgType() == MsgTypeBlock {
		pp.blocksToSendMtx.Lock()
		hash, _ := msg.(*MsgDeSoBlock).Hash()
		delete(pp.blocksToSend, *hash)
		pp.blocksToSendMtx.Unlock()
	}
}

// NumBlocksToSend is the number of blocks the Peer has requested from
// us that we have yet to send them.
func (pp *Peer) NumBlocksToSend() uint32 {
	pp.blocksToSendMtx.Lock()
	defer pp.blocksToSendMtx.Unlock()

	return uint32(len(pp.blocksToSend))
}

func (srv *Server) HasProcessedFirstTransactionBundle() bool {
	return srv.hasProcessedFirstTransactionBundle
}

func (sm *SyncManager) _handleGetHeaders(pp *Peer, msg *MsgDeSoGetHeaders) {
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


// TODO: ################################
// 	Maybe keep this
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
		glog.Infof("Peer is not sync candidate: %v (isOutbound: %v)", pp, pp.isOutbound)
	}
}

// TODO: ################################
// 	Maybe keep this
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

// GetBlocksToStore is part of the archival mode, which makes the node download all historical blocks after completing
// hypersync. We will go through all blocks corresponding to the snapshot and download the blocks.
func (sm *SyncManager) GetBlocksToStore(pp *Peer) {
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
func (sm *SyncManager) GetBlocks(pp *Peer, maxHeight int) {
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

func (sm *SyncManager) _handleHeaderBundle(pp *Peer, msg *MsgDeSoHeaderBundle) {
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
				time.Unix(int64(srv.blockchain.headerTip().Header.GetTstampSecs()), 0),
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

func (sm *SyncManager) _handleGetBlocks(pp *Peer, msg *MsgDeSoGetBlocks) {
	glog.V(1).Infof("srv._handleGetBlocks: Called with message %v from Peer %v", msg, pp)

	// Let the peer handle this
	pp.AddDeSoMessage(msg, true /*inbound*/)
}

// dirtyHackUpdateDbOpts closes the current badger DB instance and re-opens it with the provided options.
//
// FIXME: This is a dirty hack that we did in order to decrease memory usage. The reason why we needed it is
// as follows:
//   - When we run a node with --hypersync or --hypersync-archival, using PerformanceOptions the whole way
//     through causes it to use too much memory.
//   - The problem is that if we use DefaultOptions, then the block sync after HyperSync is complete will fail
//     because it writes really big entries in a single transaction to the PrefixBlockHashToUtxoOperations
//     index.
//   - So, in order to keep memory usage reasonable, we need to use DefaultOptions during the HyperSync portion
//     and then *switch over* to PerformanceOptions once the HyperSync is complete. That is what this function
//     is used for.
//   - Running a node with --blocksync requires that we use PerformanceOptions the whole way through, but we
//     are moving away from syncing nodes that way, so we don't need to worry too much about that case right now.
//
// The long-term solution is to break the writing of the PrefixBlockHashToUtxoOperations index into chunks,
// or to remove it entirely. We don't want to do that work right now, but we want to reduce the memory usage
// for the "common" case, which is why we're doing this dirty hack for now.
func (sm *SyncManager) dirtyHackUpdateDbOpts(opts badger.Options) {
	// Make sure that a mempool process doesn't try to access the DB while we're closing and re-opening it.
	srv.mempool.mtx.Lock()
	defer srv.mempool.mtx.Unlock()
	// Make sure that a server process doesn't try to access the DB while we're closing and re-opening it.
	srv.DbMutex.Lock()
	defer srv.DbMutex.Unlock()
	srv.blockchain.db.Close()
	db, err := badger.Open(opts)
	if err != nil {
		// If we can't open the DB with the new options, we need to exit the process.
		glog.Fatalf("Server._handleSnapshot: Problem switching badger db to performance opts, error: (%v)", err)
	}
	srv.blockchain.db = db
	srv.snapshot.mainDb = srv.blockchain.db
	srv.mempool.bc.db = srv.blockchain.db
	srv.mempool.backupUniversalUtxoView.Handle = srv.blockchain.db
	srv.mempool.universalUtxoView.Handle = srv.blockchain.db
}

func (sm *SyncManager) _startSync() {
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
			glog.Infof("Peer is not sync candidate: %v (isOutbound: %v)", peer, peer.isOutbound)
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

// It's assumed that the caller will hold the ChainLock for reading so
// that the mempool transactions don't shift under our feet.
func (sm *SyncManager) _handleBlockMainChainConnectedd(event *BlockEvent) {
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
func (sm *SyncManager) _handleBlockMainChainDisconnectedd(event *BlockEvent) {
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

func (sm *SyncManager) _maybeRequestSync(pp *Peer) {
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

func (sm *SyncManager) _handleBlockAccepted(event *BlockEvent) {
	blk := event.Block

	// Don't relay blocks until our best block chain is done syncing.
	if srv.blockchain.isSyncing() || srv.blockchain.MaxSyncBlockHeight > 0 {
		return
	}

	// Notify the consensus that a block was accepted.
	if srv.fastHotStuffConsensus != nil {
		srv.fastHotStuffConsensus.HandleAcceptedBlock()
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

func (sm *SyncManager) _handleBlock(pp *Peer, blk *MsgDeSoBlock) {
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

func (sm *SyncManager) _handleInv(peer *Peer, msg *MsgDeSoInv) {
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

func (sm *SyncManager) _handleGetTransactions(pp *Peer, msg *MsgDeSoGetTransactions) {
	glog.V(1).Infof("Server._handleGetTransactions: Received GetTransactions "+
		"message %v from Peer %v", msg, pp)

	pp.AddDeSoMessage(msg, true /*inbound*/)
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

func (pp *Peer) HelpHandleInv(msg *MsgDeSoInv) {
	// Get the requestedTransactions lock and release it at the end of the function.
	pp.srv.dataLock.Lock()
	defer pp.srv.dataLock.Unlock()

	// Iterate through the message. Gather the transactions and the
	// blocks we don't already have into separate inventory lists.
	glog.V(1).Infof("Server._handleInv: Processing INV message of size %v from peer %v", len(msg.InvList), pp)
	txHashList := []*BlockHash{}
	blockHashList := []*BlockHash{}

	for _, invVect := range msg.InvList {
		// No matter what, add the inv to the peer's known inventory.
		pp.knownInventory.Add(*invVect)

		// If this is a hash we are currently processing, no need to do anything.
		// This check serves to fill the gap between the time when we've decided
		// to ask for the data corresponding to an inv and when we actually receive
		// that data. Without this check, the following would happen:
		// - Receive inv from peer1
		// - Get data for inv from peer1
		// - Receive same inv from peer2
		// - Get same data for same inv from peer2 before we've received
		//   a response from peer1
		// Instead, because of this check, the following happens instead:
		// - Receive inv from peer1
		// - Get data for inv from peer1 *and* add it to inventoryBeingProcessed.
		// - Receive same inv from peer2
		// - Notice second inv is already in inventoryBeingProcessed so don't
		//   request data for it.
		if pp.srv.inventoryBeingProcessed.Contains(*invVect) {
			continue
		}

		// Extract a copy of the block hash to avoid the iterator changing the
		// value underneath us.
		currentHash := BlockHash{}
		copy(currentHash[:], invVect.Hash[:])

		if invVect.Type == InvTypeTx {
			// For transactions, check that the transaction isn't in the
			// mempool and that it isn't currently being requested.
			_, requestIsInFlight := pp.srv.requestedTransactionsMap[currentHash]
			if requestIsInFlight || pp.srv.mempool.IsTransactionInPool(&currentHash) {
				continue
			}

			txHashList = append(txHashList, &currentHash)
		} else if invVect.Type == InvTypeBlock {
			// For blocks, we check that the hash isn't known to us either in our
			// main header chain or in side chains.
			if pp.srv.blockchain.HasHeader(&currentHash) {
				continue
			}

			blockHashList = append(blockHashList, &currentHash)
		}

		// If we made it here, it means the inventory was added to one of the
		// lists so mark it as processed on the Server.
		pp.srv.inventoryBeingProcessed.Add(*invVect)
	}

	// If there were any transactions we don't yet have, request them using
	// a GetTransactions message.
	if len(txHashList) > 0 {
		// Add all the transactions we think we need to the list of transactions
		// requested (i.e. in-flight) since we're about to request them.
		for _, txHash := range txHashList {
			pp.srv.requestedTransactionsMap[*txHash] = &GetDataRequestInfo{
				PeerWhoSentInv: pp,
				TimeRequested:  time.Now(),
			}
		}

		pp.AddDeSoMessage(&MsgDeSoGetTransactions{
			HashList: txHashList,
		}, false /*inbound*/)
	} else {
		glog.V(1).Infof("Server._handleInv: Not sending GET_TRANSACTIONS because no new hashes")
	}

	// If the peer has sent us any block hashes that are new to us then send
	// a GetHeaders message to her to get back in sync with her. The flow
	// for this is generally:
	// - Receive an inv message from a peer for a block we don't have.
	// - Send them a GetHeaders message with our most up-to-date block locator.
	// - Receive back from them all the headers they're aware of that can be
	//   accepted into our chain.
	// - We will then request from them all of the block data for the new headers
	//   we have if they affect our main chain.
	// - When the blocks come in, we process them by adding them to the chain
	//   one-by-one.
	if len(blockHashList) > 0 {
		locator := pp.srv.blockchain.LatestHeaderLocator()
		pp.AddDeSoMessage(&MsgDeSoGetHeaders{
			StopHash:     &BlockHash{},
			BlockLocator: locator,
		}, false /*inbound*/)
	}
}

func (pp *Peer) HandleInv(msg *MsgDeSoInv) {
	// Ignore invs while we're still syncing and before we've requested
	// all mempool transactions from one of our peers to bootstrap.
	if pp.srv.blockchain.isSyncing() {
		glog.Infof("Server._handleInv: Ignoring INV while syncing from Peer %v", pp)
		return
	}

	// Expire any transactions that we've been waiting too long on.
	// Also remove them from inventoryProcessed in case another Peer wants to send
	// them to us in the future.
	pp.srv.ExpireRequests()

	pp.HelpHandleInv(msg)
}

func (pp *Peer) HandleGetBlocks(msg *MsgDeSoGetBlocks) {
	// Nothing to do if the request is empty.
	if len(msg.HashList) == 0 {
		glog.V(1).Infof("Server._handleGetBlocks: Received empty GetBlocks "+
			"request. No response needed for Peer %v", pp)
		return
	}

	// For each block the Peer has requested, fetch it and queue it to
	// be sent. It takes some time to fetch the blocks which is why we
	// do it in a goroutine. This might also block if the Peer's send
	// queue is full.
	//
	// Note that the requester should generally ask for the blocks in the
	// order they'd like to receive them as we will typically honor this
	// ordering.
	//
	// With HyperSync there is a potential that a node will request blocks that we haven't yet stored, although we're
	// fully synced. This can happen to archival nodes that haven't yet downloaded all historical blocks. If a GetBlock
	// is sent to a non-archival node for blocks that we don't have, then the peer is misbehaving and should be disconnected.
	for _, hashToSend := range msg.HashList {
		blockToSend := pp.srv.blockchain.GetBlock(hashToSend)
		if blockToSend == nil {
			// Don't ask us for blocks before verifying that we have them with a
			// GetHeaders request.
			glog.Errorf("Server._handleGetBlocks: Disconnecting peer %v because "+
				"she asked for a block with hash %v that we don't have", pp, msg.HashList[0])
			pp.Disconnect()
			return
		}
		pp.AddDeSoMessage(blockToSend, false)
	}
}

/*
This code was in the middle of Peer's inHandler:

		// Potentially adjust blocksToSend to account for blocks the Peer is
		// currently requesting from us. Disconnect the Peer if she's requesting too many
		// blocks now.
		if err := pp._maybeAddBlocksToSend(rmsg); err != nil {
			glog.Errorf(err.Error())
			break out
		}


Add _maybeAddBlocksToSend as one of the handlers for the server's message stream.
*/
func (pp *Peer) _maybeAddBlocksToSend(msg DeSoMessage) error {
	// If the input is not a GetBlocks message, don't do anything.
	if msg.GetMsgType() != MsgTypeGetBlocks {
		return nil
	}

	// At this point, we're sure this is a GetBlocks message. Acquire the
	// blocksToSend mutex and cast the message.
	pp.blocksToSendMtx.Lock()
	defer pp.blocksToSendMtx.Unlock()
	getBlocks := msg.(*MsgDeSoGetBlocks)

	// When blocks have been requested, add them to the list of blocks we're
	// in the process of sending to the Peer.
	for _, hash := range getBlocks.HashList {
		pp.blocksToSend[*hash] = true
	}

	// If the peer has exceeded the number of blocks she is allowed to request
	// then disconnect her.
	if len(pp.blocksToSend) > MaxBlocksInFlight {
		pp.Disconnect()
		return fmt.Errorf("_maybeAddBlocksToSend: Disconnecting peer %v because she requested %d "+
			"blocks, which is more than the %d blocks allowed "+
			"in flight", pp, len(pp.blocksToSend), MaxBlocksInFlight)
	}

	return nil
}

func (pp *Peer) IsSyncCandidate() bool {
	isFullNode := (pp.serviceFlags & SFFullNodeDeprecated) != 0
	// TODO: This is a bit of a messy way to determine whether the node was run with --hypersync
	nodeSupportsHypersync := (pp.serviceFlags & SFHyperSync) != 0
	weRequireHypersync := (pp.syncType == NodeSyncTypeHyperSync ||
		pp.syncType == NodeSyncTypeHyperSyncArchival)
	if weRequireHypersync && !nodeSupportsHypersync {
		glog.Infof("IsSyncCandidate: Rejecting node as sync candidate "+
			"because weRequireHypersync=true but nodeSupportsHypersync=false "+
			"localAddr (%v), isFullNode (%v), "+
			"nodeSupportsHypersync (%v), --sync-type (%v), weRequireHypersync (%v), "+
			"is outbound (%v)",
			pp.Conn.LocalAddr().String(), isFullNode, nodeSupportsHypersync,
			pp.syncType,
			weRequireHypersync,
			pp.isOutbound)
		return false
	}

	weRequireArchival := IsNodeArchival(pp.syncType)
	nodeIsArchival := (pp.serviceFlags & SFArchivalNode) != 0
	if weRequireArchival && !nodeIsArchival {
		glog.Infof("IsSyncCandidate: Rejecting node as sync candidate "+
			"because weRequireArchival=true but nodeIsArchival=false "+
			"localAddr (%v), isFullNode (%v), "+
			"nodeIsArchival (%v), --sync-type (%v), weRequireArchival (%v), "+
			"is outbound (%v)",
			pp.Conn.LocalAddr().String(), isFullNode, nodeIsArchival,
			pp.syncType,
			weRequireArchival,
			pp.isOutbound)
		return false
	}

	return isFullNode && pp.isOutbound
}
