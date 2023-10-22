package lib

import (
	"encoding/hex"
	"fmt"
	"github.com/deso-protocol/go-deadlock"
	"github.com/golang/glog"
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
	bc  *Blockchain
	vm  *VersionManager
	srv *Server
	mp  *DeSoMempool
	snm *SnapshotManager

	forceChecksum bool

	// During initial block download, we request headers and blocks from a single
	// peer. Note: These fields should only be accessed from the messageHandler thread.
	//
	// TODO: This could be much faster if we were to download blocks in parallel
	// rather than from a single peer but it won't be a problem until later, at which
	// point we can make the optimization.
	SyncPeer *Peer

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
	syncType NodeSyncType

	minFeeRateNanosPerKB uint64
	stallTimeoutSeconds  uint64

	// Each Peer is only allowed to have certain number of blocks being sent
	// to them at any gven time. We use
	// this value to enforce that constraint. The reason we need to do this is without
	// it one peer could theoretically clog our Server by issuing many GetBlocks
	// requests that ultimately don't get delivered. This way the number of blocks
	// being sent is limited to a multiple of the number of Peers we have.
	blocksToSendMtx deadlock.Mutex

	blocksToSend        map[uint64]map[BlockHash]bool
	peerRequestedBlocks map[uint64]map[BlockHash]bool
}

func NewSyncManager(bc *Blockchain, vm *VersionManager, srv *Server, mp *DeSoMempool, snm *SnapshotManager, forceChecksum bool,
	hyperSync bool, syncType NodeSyncType, minFeeRateNanosPerKB uint64, stallTimeoutSeconds uint64) *SyncManager {

	return &SyncManager{
		bc:                   bc,
		vm:                   vm,
		srv:                  srv,
		mp:                   mp,
		snm:                  snm,
		forceChecksum:        forceChecksum,
		HyperSync:            hyperSync,
		syncType:             syncType,
		minFeeRateNanosPerKB: minFeeRateNanosPerKB,
		stallTimeoutSeconds:  stallTimeoutSeconds,
		blocksToSend:         make(map[uint64]map[BlockHash]bool),
		peerRequestedBlocks:  make(map[uint64]map[BlockHash]bool),
	}
}

func (sm *SyncManager) Init() {
	// TODO: Change this from MsgTypeNewPeer to MsgTypeHandshakeComplete or something like that.
	sm.srv.RegisterIncomingMessagesHandler(MsgTypeNewPeer, sm._handleNewPeerMessage)
	sm.srv.RegisterIncomingMessagesHandler(MsgTypeDonePeer, sm._handleDonePeerMessage)
	sm.srv.RegisterIncomingMessagesHandler(MsgTypeGetHeaders, sm._handleGetHeadersMessage)
	sm.srv.RegisterIncomingMessagesHandler(MsgTypeHeaderBundle, sm._handleHeaderBundleMessage)
	sm.srv.RegisterIncomingMessagesHandler(MsgTypeGetBlocks, sm._handleGetBlocksMessage)
	sm.srv.RegisterIncomingMessagesHandler(MsgTypeBlock, sm._handleBlockMessage)
	sm.srv.RegisterIncomingMessagesHandler(MsgTypeQuit, sm._handleQuitMessage)
}

func (sm *SyncManager) Start() {
}

func (sm *SyncManager) Stop() {
}

// TODO: Replace this with some peer after-handshake message.
func (sm *SyncManager) _handleNewPeerMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeNewPeer {
		return MessageHandlerResponseCodeSkip
	}

	isSyncCandidate := sm.isSyncCandidate(origin)
	isSyncing := sm.bc.isSyncing()
	chainState := sm.bc.chainState()
	glog.V(1).Infof("SyncManager._handleNewPeerMessage: Processing NewPeer: "+
		"(id= %v); isSyncCandidate(%v), syncPeerIsNil=(%v), IsSyncing=(%v), ChainState=(%v)",
		origin.ID, isSyncCandidate, (sm.SyncPeer == nil), isSyncing, chainState)

	// Request a sync if we're ready
	if code := sm._maybeRequestSync(origin); code != MessageHandlerResponseCodeOK {
		return code
	}

	// Start syncing by choosing the best candidate.
	if isSyncCandidate && sm.SyncPeer == nil {
		sm._startSync()
	}
	if !isSyncCandidate {
		glog.Infof("SyncManager. Peer._handleNewPeerMessage: is not sync candidate: "+
			"(id= %v) (isOutbound= %v)", origin.ID, origin.IsOutbound())
	}
	return MessageHandlerResponseCodeOK
}

func (sm *SyncManager) isSyncCandidate(peer *Peer) bool {
	vMeta := sm.vm.GetValidatorVersionMetadata(peer.ID)
	isFullNode := (vMeta.ServiceFlag & SFFullNodeDeprecated) != 0
	// TODO: This is a bit of a messy way to determine whether the node was run with --hypersync
	nodeSupportsHypersync := (vMeta.ServiceFlag & SFHyperSync) != 0
	weRequireHypersync := (sm.syncType == NodeSyncTypeHyperSync ||
		sm.syncType == NodeSyncTypeHyperSyncArchival)
	if weRequireHypersync && !nodeSupportsHypersync {
		glog.Infof("SyncManager.isSyncCandidate: Rejecting node as sync candidate "+
			"because weRequireHypersync=true but nodeSupportsHypersync=false "+
			"isFullNode (%v), nodeSupportsHypersync (%v), --sync-type (%v), "+
			"weRequireHypersync (%v), is outbound (%v), peerId (%v)",
			isFullNode, nodeSupportsHypersync, sm.syncType,
			weRequireHypersync, peer.IsOutbound())
		return false
	}

	weRequireArchival := IsNodeArchival(sm.syncType)
	nodeIsArchival := (vMeta.ServiceFlag & SFArchivalNode) != 0
	if weRequireArchival && !nodeIsArchival {
		glog.Infof("SyncManager.isSyncCandidate: Rejecting node as sync candidate "+
			"because weRequireArchival=true but nodeIsArchival=false "+
			"isFullNode (%v), nodeIsArchival (%v), --sync-type (%v), weRequireArchival (%v), "+
			"is outbound (%v)",
			isFullNode, nodeIsArchival, sm.syncType,
			weRequireArchival, peer.IsOutbound())
		return false
	}

	return isFullNode && peer.IsOutbound()
}

func (sm *SyncManager) _maybeRequestSync(peer *Peer) MessageHandlerResponseCode {
	code := MessageHandlerResponseCodeOK

	// Send the mempool message if DeSo and Bitcoin are fully current
	if sm.bc.chainState() == SyncStateFullyCurrent {
		// If peer is not nil and we haven't set a max sync blockheight, we will
		if peer != nil && sm.bc.MaxSyncBlockHeight == 0 {
			glog.V(1).Infof("SyncManager._maybeRequestSync: Sending mempool message to peer: (id= %v)", peer.ID)
			if err := sm.srv.SendMessage(&MsgDeSoMempool{}, peer.ID, nil); err != nil {
				glog.Errorf("SyncManager._maybeRequestSync: Problem sending mempool message to peer: %v", err)
				code = MessageHandlerResponseCodePeerUnavailable
			}
		} else {
			glog.V(1).Infof("SyncManager._maybeRequestSync: NOT sending mempool message because peer is nil: %v", peer)
		}
	} else {
		glog.V(1).Infof("SyncManager._maybeRequestSync: NOT sending mempool message because not current. "+
			"Chain state: %v, Peer: %v", sm.bc.chainState(), peer)
	}
	return code
}

func (sm *SyncManager) _startSync() {
	// Return now if we're already syncing.
	if sm.SyncPeer != nil {
		glog.V(2).Infof("SyncManager._startSync: Not running because SyncPeer != nil")
		return
	}
	glog.V(1).Infof("SyncManager._startSync: Attempting to start sync")

	// Set our tip to be the best header tip rather than the best block tip. Using
	// the block tip instead might cause us to select a peer who is missing blocks
	// for the headers we've downloaded.
	bestHeight := sm.bc.headerTip().Height

	// FIXME: This should be part of the SyncManager routine
	// Find a peer with StartingHeight bigger than our best header tip.
	var bestValidator *Peer
	var bestValidatorVersionMetadata *ValidatorVersionMetadata
	for _, peer := range sm.srv.GetAllPeers() {
		if !sm.isSyncCandidate(peer) {
			glog.V(2).Infof("SyncManager._startSync: Peer is not sync candidate: %v (isOutbound: %v)", peer, peer.isOutbound)
			continue
		}
		vMeta := sm.vm.GetValidatorVersionMetadata(peer.ID)
		if vMeta == nil {
			continue
		}

		// Choose the peer with the best height out of everyone who's a
		// valid sync candidate.
		if bestValidator != nil && bestValidatorVersionMetadata.StartingBlockHeight > vMeta.StartingBlockHeight {
			continue
		}

		// TODO: Choose best peers based on ping time and/or the highest
		// starting block height. For now, keeping it simple and just choosing
		// the last one we iterate over with a block height larger than our best.
		bestValidator = peer
		bestValidatorVersionMetadata = vMeta
	}

	if bestValidator == nil {
		glog.V(1).Infof("SyncManager._startSync: No sync peer candidates available")
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
	glog.V(1).Infof("SyncManager._startSync: Syncing headers to height %d from peer %v",
		bestValidatorVersionMetadata.StartingBlockHeight, bestValidator)

	// Send a GetHeaders message to the Peer to start the headers sync.
	// Note that we include an empty BlockHash as the stopHash to indicate we want as
	// many headers as the Peer can give us.
	locator := sm.bc.LatestHeaderLocator()
	getHeaders := &MsgDeSoGetHeaders{
		StopHash:     &BlockHash{},
		BlockLocator: locator,
	}
	if code := sm.sendGetHeadersMessage(getHeaders, bestValidator.ID); code != MessageHandlerResponseCodeOK {
		glog.Errorf("SyncManager._startSync: Problem sending GetHeaders message to peer: (code= %v)", code)
		return
	}
	glog.V(1).Infof("Server._startSync: Downloading headers for blocks starting at "+
		"header tip height %v from peer %v", bestHeight, bestValidator)

	sm.SyncPeer = bestValidator
}

func (sm *SyncManager) _handleDonePeerMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeDonePeer {
		return MessageHandlerResponseCodeSkip
	}

	glog.V(1).Infof("SyncManager._handleDonePeerMessage: Processing DonePeer: (id= %v)", origin.ID)

	// Attempt to find a new peer to sync from if the quitting peer is the
	// sync peer and if our blockchain isn't current.
	if sm.SyncPeer == origin && sm.bc.isSyncing() {

		sm.SyncPeer = nil
		sm._startSync()
	}
	return MessageHandlerResponseCodeOK
}

func (sm *SyncManager) _getPeerRequestedBlocks(peerId uint64) map[BlockHash]bool {
	if _, exists := sm.peerRequestedBlocks[peerId]; !exists {
		sm.peerRequestedBlocks[peerId] = make(map[BlockHash]bool)
	}
	return sm.peerRequestedBlocks[peerId]
}

func (sm *SyncManager) _handleGetHeadersMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeGetHeaders {
		return MessageHandlerResponseCodeSkip
	}

	var getHeadrsMsg *MsgDeSoGetHeaders
	var ok bool
	if getHeadrsMsg, ok = desoMsg.(*MsgDeSoGetHeaders); !ok {
		return MessageHandlerResponseCodePeerDisconnect
	}

	glog.V(1).Infof("SyncManager._handleGetHeadersMessage: called with locator: (%v), "+
		"stopHash: (%v) from Peer (id= %v)", getHeadrsMsg.BlockLocator, getHeadrsMsg.StopHash, origin.ID)

	// Ignore GetHeaders requests we're still syncing.
	if sm.bc.isSyncing() {
		chainState := sm.bc.chainState()
		glog.V(1).Infof("SyncManager._handleGetHeadersMessage: Ignoring GetHeaders from Peer (id= %v)"+
			"because node is syncing with ChainState (%v)", origin.ID, chainState)
		return MessageHandlerResponseCodeSkip
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
	headers := sm.bc.LocateBestBlockChainHeaders(getHeadrsMsg.BlockLocator, getHeadrsMsg.StopHash)

	// Send found headers to the requesting peer.
	blockTip := sm.bc.blockTip()
	msg := &MsgDeSoHeaderBundle{
		Headers:   headers,
		TipHash:   blockTip.Hash,
		TipHeight: blockTip.Height,
	}
	if err := sm.srv.SendMessage(msg, origin.ID, nil); err != nil {
		return MessageHandlerResponseCodePeerUnavailable
	}
	glog.V(2).Infof("SyncManager._handleGetHeadersMessage: Replied to GetHeaders request "+
		"with response headers: (%v), tip hash (%v), tip height (%d) from Peer (id= %v)",
		headers, blockTip.Hash, blockTip.Height, origin.ID)
	return MessageHandlerResponseCodeOK
}

func (sm *SyncManager) _handleHeaderBundleMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeHeaderBundle {
		return MessageHandlerResponseCodeSkip
	}

	var msg *MsgDeSoHeaderBundle
	var ok bool
	if msg, ok = desoMsg.(*MsgDeSoHeaderBundle); !ok {
		return MessageHandlerResponseCodePeerDisconnect
	}

	versionMetadata := sm.vm.GetValidatorVersionMetadata(origin.ID)
	printHeight := versionMetadata.StartingBlockHeight
	if sm.bc.headerTip().Height > printHeight {
		printHeight = sm.bc.headerTip().Height
	}
	glog.Infof(CLog(Yellow, fmt.Sprintf("SyncManager._handleHeaderBundleMessage: Received header bundle "+
		"with %v headers in state %s from peer (id= %v). Downloaded ( %v / %v ) total headers",
		len(msg.Headers), sm.bc.chainState(), origin.ID, sm.bc.headerTip().Header.Height, printHeight)))

	// Start by processing all of the headers given to us. They should start
	// right after the tip of our header chain ideally. While going through them
	// tally up the number that we actually process.
	numNewHeaders := 0
	for _, headerReceived := range msg.Headers {
		// If we've set a maximum height for node sync and we've reached it,
		// then we will not process any more headers.
		if sm.bc.isTipMaxed(sm.bc.headerTip()) {
			break
		}

		// If we encounter a duplicate header while we're still syncing then
		// the peer is misbehaving. Disconnect so we can find one that won't
		// have this issue. Hitting duplicates after we're done syncing is
		// fine and can happen in certain cases.
		headerHash, _ := headerReceived.Hash()
		if sm.bc.HasHeader(headerHash) {
			if sm.bc.isSyncing() {

				glog.Warningf("SyncManager._handleHeaderBundleMessage: Duplicate header %v received "+
					"from peer (id= %v) in state %s. Local header tip height %d hash %s with duplicate %v",
					headerHash, origin.ID, sm.bc.chainState(), sm.bc.headerTip().Height,
					hex.EncodeToString(sm.bc.headerTip().Hash[:]), headerHash)

				// TODO: This logic should really be commented back in, but there was a bug that
				// arises when a program is killed forcefully whereby a partial write leads to this
				// logic causing the sync to stall. As such, it's more trouble than it's worth
				// at the moment but we should consider being more strict about it in the future.
				/*
					pp.Disconnect()
					return
				*/
				// FIXME: Look into this
			}

			// Don't process duplicate headers.
			continue
		}

		// If we get here then we have a header we haven't seen before.
		// TODO: Delete? This is redundant.
		numNewHeaders++

		// Process the header, as we haven't seen it before.
		_, isOrphan, err := sm.bc.ProcessHeader(headerReceived, headerHash)

		// If this header is an orphan or we encountered an error for any reason,
		// disconnect from the peer. Because every header is sent in response to
		// a GetHeaders request, the peer should know enough to never send us
		// unconnectedTxns unless it's misbehaving.
		if err != nil || isOrphan {
			glog.Errorf("SyncManager._handleHeaderBundleMessage: Disconnecting from peer (id= %v) in state %s "+
				"because error occurred processing header: %v, isOrphan: %v",
				origin.ID, sm.bc.chainState(), err, isOrphan)

			return MessageHandlerResponseCodePeerDisconnect
		}
	}

	// After processing all the headers this will check to see if we are fully current
	// and send a request to our Peer to start a Mempool sync if so.
	//
	// This statement makes it so that if we boot up our node such that
	// its initial state is fully current we'll always bootstrap our mempools with a
	// mempool request. The alternative is that our state is not fully current
	// when we boot up, and we cover this second case in the _handleBlock function.
	sm._maybeRequestSync(origin)

	// At this point we should have processed all the headers. Now we will
	// make a decision on whether to request more headers from this peer based
	// on how many headers we received in this message. Since every HeaderBundle
	// is a response to a GetHeaders request from us with a HeaderLocator embedded in it, receiving
	// anything less than MaxHeadersPerMsg headers from a peer is sufficient to
	// make us think that the peer doesn't have any more interesting headers for us.
	// On the other hand, if the request contains MaxHeadersPerMsg, it is highly
	// likely we have not hit the tip of our peer's chain, and so requesting more
	// headers from the peer would likely be useful.
	if uint32(len(msg.Headers)) < MaxHeadersPerMsg || sm.bc.isTipMaxed(sm.bc.headerTip()) {
		// If we have exhausted the peer's headers but our header chain still isn't
		// current it means the peer we chose isn't current either. So disconnect
		// from her and try to sync with someone else.
		if sm.bc.chainState() == SyncStateSyncingHeaders {
			glog.V(1).Infof("SyncManager._handleHeaderBundleMessage: Disconnecting from peer (id= %v) because "+
				"we have exhausted their headers but our tip is still only at time=%v height=%d",
				origin.ID, time.Unix(int64(sm.bc.headerTip().Header.GetTstampSecs()), 0), sm.bc.headerTip().Header.Height)

			return MessageHandlerResponseCodePeerDisconnect
		}

		// If we get here it means that we've just finished syncing headers and we will proceed to
		// syncing state either through hyper sync or block sync. First let's check if the peer
		// supports hypersync and if our block tip is old enough so that it makes sense to sync state.
		if NodeCanHypersyncState(sm.syncType) && sm.bc.isHyperSyncCondition() {
			// If hypersync conditions are satisfied, we will be syncing state. This assignment results
			// in srv.blockchain.chainState() to be equal to SyncStateSyncingSnapshot
			sm.bc.syncingState = true
		}

		if sm.bc.chainState() == SyncStateSyncingSnapshot {
			return sm.snm.InitSnapshotSync()
		}

		// If we have finished syncing peer's headers, but previously we have bootstrapped the blockchain through
		// hypersync and the node has the archival mode turned on, we might need to download historical blocks.
		// We'll check if there are any outstanding historical blocks to download.
		if sm.bc.checkArchivalMode() {
			glog.V(1).Infof("SyncManager._handleHeaderBundleMessage: Syncing historical blocks because node is in " +
				"archival mode.")
			sm.bc.downloadingHistoricalBlocks = true
			sm.getBlocksToStore(origin)
			if sm.bc.downloadingHistoricalBlocks {
				return MessageHandlerResponseCodeSkip
			}
		}

		// If we have exhausted the peer's headers but our blocks aren't current,
		// send a GetBlocks message to the peer for as many blocks as we can get.
		if sm.bc.chainState() == SyncStateSyncingBlocks {
			// A maxHeight of -1 tells GetBlocks to fetch as many blocks as we can
			// from this peer without worrying about how many blocks the peer actually
			// has. We can do that in this case since this usually happens during sync
			// before we've made any GetBlocks requests to the peer.
			blockTip := sm.bc.blockTip()
			glog.V(1).Infof("SyncManager._handleHeaderBundleMessage: *Syncing* blocks starting at "+
				"height %d out of %d from peer (id= %v)",
				blockTip.Header.Height+1, msg.TipHeight, origin.ID)
			maxHeight := -1
			return sm.getBlocks(origin, maxHeight)
		}

		// If we have exhausted the peer's headers and our blocks are current but
		// we still need a few more blocks to line our block chain up with
		// our header chain, send the peer a GetBlocks message for blocks we're
		// positive she has.
		if sm.bc.chainState() == SyncStateNeedBlocksss ||
			!(sm.bc.blockTip().Hash.IsEqual(sm.bc.headerTip().Hash)) {
			// If the peer's tip is not in our blockchain then we don't request
			// any blocks from them because they're on some kind of fork that
			// we're either not aware of or that we don't think is the best chain.
			// Doing things this way makes it so that when we request blocks we
			// are 100% positive the peer has them.
			if !sm.bc.HasHeader(msg.TipHash) {
				glog.V(1).Infof("SyncManager._handleHeaderBundleMessage: Peer's tip is not in our blockchain so not "+
					"requesting anything else from them. Our block tip %v, their tip %v:%d, peer: (id= %v)",
					sm.bc.blockTip().Header, msg.TipHash, msg.TipHeight, origin.ID)
				return MessageHandlerResponseCodeSkip
			}

			// At this point, we have verified that the peer's tip is in our main
			// header chain. This implies that any blocks we would request from
			// them should be available as long as they don't exceed the peer's
			// tip height.
			blockTip := sm.bc.blockTip()
			glog.V(1).Infof("SyncManager._handleHeaderBundleMessage: *Downloading* blocks starting at "+
				"block tip %v out of %d from peer (id= %v)", blockTip.Header, msg.TipHeight, origin.ID)
			return sm.getBlocks(origin, int(msg.TipHeight))
		}

		// If we get here it means we have all the headers and blocks we need
		// so there's nothing more to do.
		glog.V(1).Infof("Server._handleHeaderBundle: Tip is up-to-date so no "+
			"need to send anything. Our block tip: %v, their tip: %v:%d, Peer: (id= %v)",
			sm.bc.blockTip().Header, msg.TipHash, msg.TipHeight, origin.ID)
		return MessageHandlerResponseCodeSkip
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
	locator, err := sm.bc.HeaderLocatorWithNodeHash(lastHash)
	if err != nil {
		glog.Warningf("Server._handleHeaderBundle: Disconnecting peer (id= %v) because "+
			"she indicated that she has more headers but the last hash %v in "+
			"the header bundle does not correspond to a block in our index.",
			origin.ID, lastHash)
		return MessageHandlerResponseCodePeerDisconnect
	}
	getHeaders := &MsgDeSoGetHeaders{
		StopHash:     &BlockHash{},
		BlockLocator: locator,
	}
	if code := sm.sendGetHeadersMessage(getHeaders, origin.ID); code != MessageHandlerResponseCodeOK {
		return code
	}
	headerTip := sm.bc.headerTip()
	glog.V(1).Infof("Server._handleHeaderBundle: *Syncing* headers for blocks starting at "+
		"header tip %v out of %d from peer (id= %v)", headerTip.Header, msg.TipHeight, origin.ID)
	return MessageHandlerResponseCodeOK
}

func (sm *SyncManager) sendGetHeadersMessage(getHeaders *MsgDeSoGetHeaders, peerId uint64) MessageHandlerResponseCode {
	stallTimeout := time.Duration(int64(sm.stallTimeoutSeconds) * int64(time.Second))
	expectedResponse := []*ExpectedResponse{{
		TimeExpected: time.Now().Add(stallTimeout),
		MessageType:  MsgTypeHeaderBundle,
	}}
	if err := sm.srv.SendMessage(getHeaders, peerId, expectedResponse); err != nil {
		return MessageHandlerResponseCodePeerUnavailable
	}
	return MessageHandlerResponseCodeOK
}

func (sm *SyncManager) _handleGetBlocksMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeGetBlocks {
		return MessageHandlerResponseCodeSkip
	}

	var getBlocksMsg *MsgDeSoGetBlocks
	var ok bool
	if getBlocksMsg, ok = desoMsg.(*MsgDeSoGetBlocks); !ok {
		return MessageHandlerResponseCodePeerDisconnect
	}

	// FIXME: _maybeAddBlocksToSend appears to have been called first in the previous flow
	if code := sm._maybeAddBlocksToSend(getBlocksMsg, origin); code != MessageHandlerResponseCodeOK {
		return code
	}

	glog.V(1).Infof("SyncManager._handleGetBlocksMessage: RECEIVED message of type %v with "+
		"num hashes %v from peer (id= %v)", desoMsg.GetMsgType(), len(getBlocksMsg.HashList), origin.ID)

	glog.V(1).Infof("srv._handleGetBlocks: Called with message %v from Peer (id= %v)", getBlocksMsg, origin.ID)

	// Nothing to do if the request is empty.
	if len(getBlocksMsg.HashList) == 0 {
		glog.V(1).Infof("Server._handleGetBlocks: Received empty GetBlocks "+
			"request. No response needed for Peer (id= %v)", origin.ID)
		return MessageHandlerResponseCodeSkip
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
	for _, hashToSend := range getBlocksMsg.HashList {
		blockToSend := sm.bc.GetBlock(hashToSend)
		if blockToSend == nil {
			// Don't ask us for blocks before verifying that we have them with a
			// GetHeaders request.
			glog.Errorf("Server._handleGetBlocks: Disconnecting peer (id= %v) because "+
				"she asked for a block with hash %v that we don't have", origin.ID, getBlocksMsg.HashList[0])
			return MessageHandlerResponseCodePeerDisconnect
		}
		if err := sm.srv.SendMessage(blockToSend, origin.ID, nil); err != nil {
			return MessageHandlerResponseCodePeerUnavailable
		}
	}
	return MessageHandlerResponseCodeOK
}

func (sm *SyncManager) _maybeAddBlocksToSend(getBlocksMsg *MsgDeSoGetBlocks, peer *Peer) MessageHandlerResponseCode {
	// At this point, we're sure this is a GetBlocks message. Acquire the
	// blocksToSend mutex and cast the message.
	sm.blocksToSendMtx.Lock()
	defer sm.blocksToSendMtx.Unlock()

	// When blocks have been requested, add them to the list of blocks we're
	// in the process of sending to the Peer.
	blocksToSend := sm._getBlocksToSend(peer.ID)
	for _, hash := range getBlocksMsg.HashList {
		blocksToSend[*hash] = true
	}

	// If the peer has exceeded the number of blocks she is allowed to request
	// then disconnect her.
	if len(blocksToSend) > MaxBlocksInFlight {
		glog.Errorf("_maybeAddBlocksToSend: Disconnecting peer (id= %v) because she requested %d "+
			"blocks, which is more than the %d blocks allowed in flight", peer.ID, len(blocksToSend), MaxBlocksInFlight)
		return MessageHandlerResponseCodePeerDisconnect
	}

	return MessageHandlerResponseCodeOK
}

func (sm *SyncManager) _handleBlockMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeBlock {
		return MessageHandlerResponseCodeSkip
	}

	var blkMsg *MsgDeSoBlock
	var ok bool
	if blkMsg, ok = desoMsg.(*MsgDeSoBlock); !ok {
		return MessageHandlerResponseCodePeerDisconnect
	}

	sm.blocksToSendMtx.Lock()
	hash, _ := desoMsg.(*MsgDeSoBlock).Hash()
	delete(sm._getBlocksToSend(origin.ID), *hash)
	sm.blocksToSendMtx.Unlock()

	glog.Infof(CLog(Cyan, fmt.Sprintf("SyncManager._handleBlockMessage: Received block ( %v / %v ) from Peer (id= %v)",
		blkMsg.Header.Height, sm.bc.headerTip().Height, origin.ID)))

	// Pull out the header for easy access.
	blockHeader := blkMsg.Header
	if blockHeader == nil {
		// Should never happen but check it nevertheless.
		return MessageHandlerResponseCodePeerDisconnect
	}

	// If we've set a maximum sync height and we've reached that height, then we will
	// stop accepting new blocks.
	if sm.bc.isTipMaxed(sm.bc.blockTip()) &&
		blockHeader.Height > uint64(sm.bc.blockTip().Height) {

		glog.Infof("SyncManager._handleBlockMessage: Exiting because block tip is maxed out")
		return MessageHandlerResponseCodeSkip
	}

	// Compute the hash of the block.
	blockHash, err := blkMsg.Header.Hash()
	if err != nil {
		// This should never happen if we got this far but log the error, clear the
		// requestedBlocks, disconnect from the peer and return just in case.
		return MessageHandlerResponseCodePeerDisconnect
	}

	requestedBlocks := sm._getPeerRequestedBlocks(origin.ID)
	if _, exists := requestedBlocks[*blockHash]; !exists {
		glog.Errorf("SyncManager._handleBlockMessage: Getting a block that we haven't requested before, "+
			"peer (id= %v), block hash (%v)", origin.ID, *blockHash)
	}
	delete(requestedBlocks, *blockHash)

	// Check that the mempool has not received a transaction that would forbid this block's signature pubkey.
	// This is a minimal check, a more thorough check is made in the ProcessBlock function. This check is
	// necessary because the ProcessBlock function only has access to mined transactions. Therefore, if an
	// attacker were to prevent a "forbid X pubkey" transaction from mining, they could force nodes to continue
	// processing their blocks.
	if len(sm.bc.trustedBlockProducerPublicKeys) > 0 && blockHeader.Height >= sm.bc.trustedBlockProducerStartHeight {
		if blkMsg.BlockProducerInfo != nil {
			_, entryExists := sm.mp.readOnlyUtxoView.ForbiddenPubKeyToForbiddenPubKeyEntry[MakePkMapKey(
				blkMsg.BlockProducerInfo.PublicKey)]
			if entryExists {
				return MessageHandlerResponseCodePeerDisconnect
			}
		}
	}

	// Only verify signatures for recent blocks.
	var isOrphan bool
	if sm.bc.isSyncing() {
		glog.V(1).Infof(CLog(Cyan, fmt.Sprintf("SyncManager._handleBlockMessage: Processing block %v WITHOUT "+
			"signature checking because SyncState=%v for peer (id= %v)",
			blkMsg.String(), sm.bc.chainState(), origin.ID)))
		_, isOrphan, err = sm.bc.ProcessBlock(blkMsg, false)

	} else {
		// TODO: Signature checking slows things down because it acquires the ChainLock.
		// The optimal solution is to check signatures in a way that doesn't acquire the
		// ChainLock, which is what Bitcoin Core does.
		glog.V(1).Infof(CLog(Cyan, fmt.Sprintf("SyncManager._handleBlockMessage: Processing block %v WITH "+
			"signature checking because SyncState=%v for peer (id= %v)",
			blkMsg.String(), sm.bc.chainState(), origin.ID)))
		_, isOrphan, err = sm.bc.ProcessBlock(blkMsg, true)
	}

	// If we hit an error then abort mission entirely. We should generally never
	// see an error with a block from a peer.
	if err != nil {
		if strings.Contains(err.Error(), "RuleErrorDuplicateBlock") {
			// Just warn on duplicate blocks but don't disconnect the peer.
			// TODO: This assuages a bug similar to the one referenced in the duplicate
			// headers comment above but in the future we should probably try and figure
			// out a way to be more strict about things.
			glog.Warningf("Got duplicate block %v from peer (id= %v)", blkMsg.String(), origin.ID)
		} else {
			return MessageHandlerResponseCodePeerDisconnect
		}
	}
	if isOrphan {
		// We should generally never receive orphan blocks. It indicates something
		// went wrong in our headers syncing.
		glog.Errorf("ERROR: Received orphan block with hash %v height %v. "+
			"This should never happen", blockHash, blkMsg.Header.Height)
		return MessageHandlerResponseCodeSkip
	}

	// We shouldn't be receiving blocks while syncing headers.
	if sm.bc.chainState() == SyncStateSyncingHeaders {
		return MessageHandlerResponseCodePeerDisconnect
	}

	if sm.bc.chainState() == SyncStateSyncingHistoricalBlocks {
		if code := sm.getBlocksToStore(origin); code != MessageHandlerResponseCodeOK {
			return code
		}
		if sm.bc.downloadingHistoricalBlocks {
			return MessageHandlerResponseCodeSkip
		}
	}

	// If we're syncing blocks, call getBlocks and try to get as many blocks
	// from our peer as we can. This allows the initial block download to be
	// more incremental since every time we're able to accept a block (or
	// group of blocks) we indicate this to our peer so they can send us more.
	if sm.bc.chainState() == SyncStateSyncingBlocks {
		// Setting maxHeight = -1 gets us as many blocks as we can get from our
		// peer, which is OK because we can assume the peer has all of them when
		// we're syncing.
		maxHeight := -1
		return sm.getBlocks(origin, maxHeight)
	}

	if sm.bc.chainState() == SyncStateNeedBlocksss {
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
		locator := sm.bc.LatestHeaderLocator()
		getHeaders := &MsgDeSoGetHeaders{
			StopHash:     &BlockHash{},
			BlockLocator: locator,
		}
		if code := sm.sendGetHeadersMessage(getHeaders, origin.ID); code != MessageHandlerResponseCodeOK {
			return code
		}
		return MessageHandlerResponseCodeSkip
	}

	// If we get here, it means we're in SyncStateFullySynced, which is great.
	// In this case we shoot a MEMPOOL message over to the peer to bootstrap the mempool.
	sm._maybeRequestSync(origin)

	return MessageHandlerResponseCodeOK
}

func (sm *SyncManager) _getBlocksToSend(peerId uint64) map[BlockHash]bool {
	if _, exists := sm.blocksToSend[peerId]; !exists {
		sm.blocksToSend[peerId] = make(map[BlockHash]bool)
	}
	return sm.blocksToSend[peerId]
}

// GetBlocksToStore is part of the archival mode, which makes the node download all historical blocks after completing
// hypersync. We will go through all blocks corresponding to the snapshot and download the blocks.
func (sm *SyncManager) getBlocksToStore(peer *Peer) MessageHandlerResponseCode {
	glog.V(2).Infof("SyncManager.getBlocksToStore: Calling for peer (id= %v)", peer.ID)

	if sm.bc.ChainState() != SyncStateSyncingHistoricalBlocks {
		glog.Errorf("GetBlocksToStore: Called even though all blocks have already been downloaded. This " +
			"shouldn't happen.")
		return MessageHandlerResponseCodeSkip
	}

	// Go through the block nodes in the blockchain and download the blocks if they're not stored.
	requestedBlocks := sm._getPeerRequestedBlocks(peer.ID)
	for _, blockNode := range sm.bc.bestChain {
		// We find the first block that's not stored and get ready to download blocks starting from this block onwards.
		if blockNode.Status&StatusBlockStored == 0 {

			numBlocksToFetch := MaxBlocksInFlight - len(requestedBlocks)
			currentHeight := int(blockNode.Height)
			blockNodesToFetch := []*BlockNode{}
			// In case there are blocks at tip that are already stored (which shouldn't really happen), we'll not download them.
			var heightLimit int
			for heightLimit = len(sm.bc.bestChain) - 1; heightLimit >= 0; heightLimit-- {
				if !sm.bc.bestChain[heightLimit].Status.IsFullyProcessed() {
					break
				}
			}

			// Find the blocks that we should download.
			for currentHeight <= heightLimit &&
				len(blockNodesToFetch) < numBlocksToFetch {

				// Get the current hash and increment the height. Genesis has height 0, so currentHeight corresponds to
				// the array index.
				currentNode := sm.bc.bestChain[currentHeight]
				currentHeight++

				// If we've already requested this block then we don't request it again.
				if _, exists := requestedBlocks[*currentNode.Hash]; exists {
					continue
				}

				blockNodesToFetch = append(blockNodesToFetch, currentNode)
			}

			var hashList []*BlockHash
			for _, node := range blockNodesToFetch {
				hashList = append(hashList, node.Hash)
				requestedBlocks[*node.Hash] = true
			}

			getBlocks := &MsgDeSoGetBlocks{
				HashList: hashList,
			}
			if code := sm.sendGetBlocksMessage(getBlocks, peer.ID); code != MessageHandlerResponseCodeOK {
				return code
			}

			glog.V(1).Infof("GetBlocksToStore: Downloading blocks to store for header %v from peer (id= %v)",
				blockNode.Header, peer.ID)
			return MessageHandlerResponseCodeOK
		}
	}

	// If we get here then it means that we've downloaded all blocks so we can update
	sm.bc.downloadingHistoricalBlocks = false
	return MessageHandlerResponseCodeOK
}

// getBlocks computes what blocks we need to fetch and asks for them from the
// corresponding peer. It is typically called after we have exited
// SyncStateSyncingHeaders.
func (sm *SyncManager) getBlocks(peer *Peer, maxHeight int) MessageHandlerResponseCode {
	// Fetch as many blocks as we can from this peer.
	requestedBlocks := sm._getPeerRequestedBlocks(peer.ID)
	numBlocksToFetch := MaxBlocksInFlight - len(requestedBlocks)
	blockNodesToFetch := sm.bc.GetBlockNodesToFetch(
		numBlocksToFetch, maxHeight, requestedBlocks)
	if len(blockNodesToFetch) == 0 {
		// This can happen if, for example, we're already requesting the maximum
		// number of blocks we can. Just return in this case.
		return MessageHandlerResponseCodeOK
	}

	// If we're here then we have some blocks to fetch so fetch them.
	hashList := []*BlockHash{}
	for _, node := range blockNodesToFetch {
		hashList = append(hashList, node.Hash)

		requestedBlocks[*node.Hash] = true
	}

	getBlocks := &MsgDeSoGetBlocks{
		HashList: hashList,
	}
	if code := sm.sendGetBlocksMessage(getBlocks, peer.ID); code != MessageHandlerResponseCodeOK {
		return code
	}

	glog.V(1).Infof("getBlocks: Downloading %d blocks from header %v to header %v from peer (id= %v)",
		len(blockNodesToFetch),
		blockNodesToFetch[0].Header,
		blockNodesToFetch[len(blockNodesToFetch)-1].Header,
		peer.ID)
	return MessageHandlerResponseCodeOK
}

func (sm *SyncManager) sendGetBlocksMessage(getBlocks *MsgDeSoGetBlocks, peerId uint64) MessageHandlerResponseCode {
	// If we're sending the peer a GetBlocks message, we expect to receive the
	// blocks at minimum within a few seconds of each other.
	stallTimeout := time.Duration(int64(sm.stallTimeoutSeconds) * int64(time.Second))
	expectedResponses := []*ExpectedResponse{}
	for ii := range getBlocks.HashList {
		expectedResponses = append(expectedResponses, &ExpectedResponse{
			TimeExpected: time.Now().Add(
				stallTimeout + time.Duration(int64(ii)*int64(stallTimeout))),
			MessageType: MsgTypeBlock,
		})
	}

	if err := sm.srv.SendMessage(getBlocks, peerId, expectedResponses); err != nil {
		return MessageHandlerResponseCodePeerUnavailable
	}
	return MessageHandlerResponseCodeOK
}

func (sm *SyncManager) _handleQuitMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeQuit {
		return MessageHandlerResponseCodeSkip
	}

	// TODO: Maybe close a routine once sync manager runs one
	return MessageHandlerResponseCodeOK
}
