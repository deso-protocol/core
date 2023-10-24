package lib

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/lru"
	"github.com/deso-protocol/go-deadlock"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"sort"
	"sync/atomic"
	"time"
)

const (
	// maxKnownInventory is the maximum number of items to keep in the known
	// inventory cache.
	maxKnownInventory = 1000000
)

type SteadyManager struct {
	sm       *SyncManager
	shutdown int32

	srv *Server
	bc  *Blockchain
	mp  *DeSoMempool

	params *DeSoParams

	// dataLock protects requestedTxns and requestedBlocks
	dataLock deadlock.Mutex

	minTxFeeRateNanosPerKB uint64
	stallTimeoutSeconds    uint64

	// When set to true, transactions created on this node will be ignored.
	readOnlyMode bool

	ignoreInboundPeerInvMessages bool

	// How long we wait on a transaction we're fetching before giving
	// up on it. Note this doesn't apply to blocks because they have their own
	// process for retrying that differs from transactions, which are
	// more best-effort than blocks.
	requestTimeoutSeconds uint32

	// requestedTransactions contains hashes of transactions for which we have
	// requested data but have not yet received a response.
	requestedTransactionsMap map[BlockHash]*GetDataRequestInfo

	// inventoryBeingProcessed keeps track of the inventory (hashes of blocks and
	// transactions) that we've recently processed from peers. It is useful for
	// avoiding situations in which we re-fetch the same data from many peers.
	// For example, if we get the same Block inv message from multiple peers,
	// adding it to this map and checking this map before replying will make it
	// so that we only send a reply to the first peer that sent us the inv, which
	// is more efficient.
	inventoryBeingProcessed lru.Cache

	// Inventory stuff.
	// The inventory that we know the peer already has.
	knownInventoryMap map[uint64]*lru.Cache

	// Whether the peer is ready to receive INV messages. For a peer that
	// still needs a mempool download, this is false.
	canReceiveInvMessagesMap map[uint64]bool

	// Becomes true after the node has processed its first transaction bundle from
	// any peer. This is useful in a deployment setting because it makes it so that
	// a health check can wait until this value becomes true.
	hasProcessedFirstTransactionBundle bool
}

func NewSteadyManager(srv *Server, bc *Blockchain, mp *DeSoMempool, params *DeSoParams, minTxFeeRateNanosPerKB uint64,
	stallTimeoutSeconds uint64, readOnlyMode bool, ignoreInboundPeerInvMessages bool) *SteadyManager {
	return &SteadyManager{
		srv:                                srv,
		bc:                                 bc,
		mp:                                 mp,
		params:                             params,
		minTxFeeRateNanosPerKB:             minTxFeeRateNanosPerKB,
		stallTimeoutSeconds:                stallTimeoutSeconds,
		readOnlyMode:                       readOnlyMode,
		ignoreInboundPeerInvMessages:       ignoreInboundPeerInvMessages,
		requestTimeoutSeconds:              10,
		requestedTransactionsMap:           make(map[BlockHash]*GetDataRequestInfo),
		inventoryBeingProcessed:            lru.NewCache(maxKnownInventory),
		knownInventoryMap:                  make(map[uint64]*lru.Cache),
		canReceiveInvMessagesMap:           make(map[uint64]bool),
		hasProcessedFirstTransactionBundle: false,
	}
}

func (stm *SteadyManager) Init(managers []Manager) {
	for _, manager := range managers {
		if manager.GetType() != ManagerTypeSync {
			continue
		}
		stm.sm = manager.(*SyncManager)
	}

	stm.srv.RegisterIncomingMessagesHandler(MsgTypeDonePeer, stm._handleDonePeerMessage)
	stm.srv.RegisterIncomingMessagesHandler(MsgTypeInv, stm._handleInvMessage)
	stm.srv.RegisterIncomingMessagesHandler(MsgTypeMempool, stm._handleMempoolMessage)
	stm.srv.RegisterIncomingMessagesHandler(MsgTypeGetTransactions, stm._handleGetTransactionsMessage)
	stm.srv.RegisterIncomingMessagesHandler(MsgTypeTransactionBundle, stm._handleTransactionBundleMessage)
	stm.srv.RegisterIncomingMessagesHandler(MsgTypeTransactionBundleV2, stm._handleTransactionBundleV2Message)
}

func (stm *SteadyManager) Start() {
	go stm._startTransactionRelayer()
}

func (stm *SteadyManager) Stop() {
	atomic.StoreInt32(&stm.shutdown, 1)
}

func (stm *SteadyManager) GetType() ManagerType {
	return ManagerTypeSteady
}

// ResetRequestQueues resets all the request queues.
func (stm *SteadyManager) ResetRequestQueues() {
	stm.dataLock.Lock()
	defer stm.dataLock.Unlock()

	glog.V(2).Infof("SteadyManager.ResetRequestQueues: Resetting request queues")

	stm.requestedTransactionsMap = make(map[BlockHash]*GetDataRequestInfo)
}

func (stm *SteadyManager) HasProcessedFirstTransactionBundle() bool {
	return stm.hasProcessedFirstTransactionBundle
}

func (stm *SteadyManager) _startTransactionRelayer() {
	// If we've set a maximum sync height, we will not relay transactions.
	if stm.bc.MaxSyncBlockHeight > 0 {
		return
	}

	for {
		if atomic.LoadInt32(&stm.shutdown) > 0 {
			break
		}
		// Just continuously relay transactions to peers that don't have them.
		stm._relayTransactions()
	}
}

func (stm *SteadyManager) _relayTransactions() {
	glog.V(1).Infof("SteadyManager._relayTransactions: Waiting for mempool readOnlyView to regenerate")
	stm.mp.BlockUntilReadOnlyViewRegenerated()
	glog.V(1).Infof("SteadyManager._relayTransactions: Mempool view has regenerated")

	// For each peer, compute the transactions they're missing from the mempool and
	// send them an inv.
	allPeers := stm.srv.GetAllPeers()
	txnList := stm.mp.readOnlyUniversalTransactionList
	for _, peer := range allPeers {
		if !stm.canReceiveInvMessagesMap[peer.ID] {
			glog.V(1).Infof("Skipping invs for peer (id= %v) because not ready "+
				"yet: %v", peer.ID, stm.canReceiveInvMessagesMap[peer.ID])
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
			if stm.getKnownInventory(peer.ID).Contains(*invVect) {
				continue
			}

			invMsg.InvList = append(invMsg.InvList, invVect)
		}
		if len(invMsg.InvList) > 0 {
			if err := stm.SendInvMessage(invMsg, peer.ID); err != nil {
				glog.Errorf("SteadyManager._relayTransactions: Problem sending "+
					"inv message to peer (id= %v): %v", peer.ID, err)
			}
		}
	}
}

func (stm *SteadyManager) SendInvMessage(invMsg *MsgDeSoInv, peerId uint64) error {
	if len(invMsg.InvList) == 0 {
		// Don't send anything if the inv list is empty after filtering.
		return nil
	}

	// Add the new inventory to the peer's knownInventory.
	for _, invVect := range invMsg.InvList {
		stm.getKnownInventory(peerId).Add(*invVect)
	}

	return stm.srv.SendMessage(invMsg, peerId, nil)
}

func (stm *SteadyManager) getKnownInventory(peerId uint64) *lru.Cache {
	if _, ok := stm.knownInventoryMap[peerId]; !ok {
		newCache := lru.NewCache(maxKnownInventory)
		stm.knownInventoryMap[peerId] = &newCache
	}
	return stm.knownInventoryMap[peerId]
}

func (stm *SteadyManager) _handleMempoolMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeMempool {
		return MessageHandlerResponseCodeSkip
	}
	glog.V(1).Infof("Server._handleMempool: Received Mempool message from Peer (id= %v)", origin.ID)
	stm.canReceiveInvMessagesMap[origin.ID] = true
	return MessageHandlerResponseCodeOK
}

func (stm *SteadyManager) _handleInvMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeInv {
		return MessageHandlerResponseCodeSkip
	}

	var invMsg *MsgDeSoInv
	var ok bool
	if invMsg, ok = desoMsg.(*MsgDeSoInv); !ok {
		return MessageHandlerResponseCodePeerDisconnect
	}

	if !origin.IsOutbound() && stm.ignoreInboundPeerInvMessages {
		glog.Infof("SteadyManager._handleInvMessage: Ignoring inv message from inbound peer because "+
			"ignore_outbound_peer_inv_messages=true: (id= %v)", origin.ID)
		return MessageHandlerResponseCodeSkip
	}
	// If we've set a maximum sync height and we've reached that height, then we will
	// stop accepting inv messages.
	if stm.bc.isTipMaxed(stm.bc.blockTip()) {
		return MessageHandlerResponseCodeSkip
	}

	// Ignore invs while we're still syncing and before we've requested
	// all mempool transactions from one of our peers to bootstrap.
	if stm.bc.isSyncing() {
		glog.Infof("SteadyManager._handleInvMessage: Ignoring INV while syncing from Peer (id= %v)", origin.ID)
		return MessageHandlerResponseCodeSkip
	}

	// Expire any transactions that we've been waiting too long on.
	// Also remove them from inventoryProcessed in case another Peer wants to send
	// them to us in the future.
	stm.expireRequestedTransactions()

	// Get the requestedTransactions lock and release it at the end of the function.
	stm.dataLock.Lock()
	defer stm.dataLock.Unlock()

	// Iterate through the message. Gather the transactions and the
	// blocks we don't already have into separate inventory lists.
	glog.V(1).Infof("SteadyManager._handleInvMessage: Processing INV message of size %v "+
		"from peer (id= %v)", len(invMsg.InvList), origin.ID)
	txHashList := []*BlockHash{}
	blockHashList := []*BlockHash{}

	for _, invVect := range invMsg.InvList {
		// No matter what, add the inv to the peer's known inventory.
		stm.getKnownInventory(origin.ID).Add(*invVect)

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
		if stm.inventoryBeingProcessed.Contains(*invVect) {
			continue
		}

		// Extract a copy of the block hash to avoid the iterator changing the
		// value underneath us.
		currentHash := BlockHash{}
		copy(currentHash[:], invVect.Hash[:])

		if invVect.Type == InvTypeTx {
			// For transactions, check that the transaction isn't in the
			// mempool and that it isn't currently being requested.
			_, requestIsInFlight := stm.requestedTransactionsMap[currentHash]
			if requestIsInFlight || stm.mp.IsTransactionInPool(&currentHash) {
				continue
			}

			txHashList = append(txHashList, &currentHash)
		} else if invVect.Type == InvTypeBlock {
			// For blocks, we check that the hash isn't known to us either in our
			// main header chain or in side chains.
			if stm.bc.HasHeader(&currentHash) {
				continue
			}

			blockHashList = append(blockHashList, &currentHash)
		}

		// If we made it here, it means the inventory was added to one of the
		// lists so mark it as processed on the Server.
		stm.inventoryBeingProcessed.Add(*invVect)
	}

	// If there were any transactions we don't yet have, request them using
	// a GetTransactions message.
	if len(txHashList) > 0 {
		// Add all the transactions we think we need to the list of transactions
		// requested (i.e. in-flight) since we're about to request them.
		for _, txHash := range txHashList {
			stm.requestedTransactionsMap[*txHash] = &GetDataRequestInfo{
				PeerWhoSentInv: origin,
				TimeRequested:  time.Now(),
			}
		}

		getTxnsMsg := &MsgDeSoGetTransactions{
			HashList: txHashList,
		}
		if code := stm.sendGetTransactionsMessage(getTxnsMsg, origin.ID); code != MessageHandlerResponseCodeOK {
			glog.Errorf("SteadyManager._handleInvMessage: Problem sending GET_TRANSACTIONS "+
				"message to peer (id= %v): code %v", origin.ID, code)
		}
	} else {
		glog.V(1).Infof("SteadyManager._handleInvMessage: Not sending GET_TRANSACTIONS because no new hashes")
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
		locator := stm.bc.LatestHeaderLocator()
		getHeaders := &MsgDeSoGetHeaders{
			StopHash:     &BlockHash{},
			BlockLocator: locator,
		}
		// TODO: Is this the best function to call? Seems hacky
		if code := stm.sm.SendGetHeadersMessage(getHeaders, origin.ID); code != MessageHandlerResponseCodeOK {
			glog.Errorf("SteadyManager._handleInvMessage: Problem sending GET_HEADERS "+
				"message to peer (id= %v): code %v", origin.ID, code)
		}
	}

	return MessageHandlerResponseCodeOK
}

// ExpireRequests checks to see if any requests have expired and removes them if so.
func (stm *SteadyManager) expireRequestedTransactions() {
	stm.dataLock.Lock()
	defer stm.dataLock.Unlock()

	// TODO: It could in theory get slow to do brute force iteration over everything
	// we've requested but not yet received, which is what we do below. But we'll
	// wait until we actually have an issue with it before optimizing it, since it
	// could also be fine. Just watch out for it.

	timeout := time.Duration(int64(stm.requestTimeoutSeconds) * int64(time.Second))
	for hashIter, requestInfo := range stm.requestedTransactionsMap {
		// Note that it's safe to use the hash iterator here because _removeRequest
		// doesn't take a reference to it.
		if requestInfo.TimeRequested.Add(timeout).After(time.Now()) {
			stm._removeRequestedTransaction(&hashIter)
		}
	}
}

// dataLock must be acquired for writing before calling this function.
func (stm *SteadyManager) _removeRequestedTransaction(hash *BlockHash) {
	// Just be lazy and remove the hash from everything indiscriminately to
	// make sure it's good and purged.
	delete(stm.requestedTransactionsMap, *hash)

	invVect := &InvVect{
		Type: InvTypeTx,
		Hash: *hash,
	}
	stm.inventoryBeingProcessed.Delete(*invVect)
}

func (stm *SteadyManager) _handleGetTransactionsMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeGetTransactions {
		return MessageHandlerResponseCodeSkip
	}

	var getTxnMsg *MsgDeSoGetTransactions
	var ok bool
	if getTxnMsg, ok = desoMsg.(*MsgDeSoGetTransactions); !ok {
		return MessageHandlerResponseCodePeerDisconnect
	}

	glog.V(1).Infof("SteadyManager._handleGetTransactionsMessage: Received MsgDeSoGetTransactions "+
		"message (%v) from Peer (id= %v)", getTxnMsg.String(), origin.ID)

	mempoolTxs := []*MempoolTx{}
	txnMap := stm.mp.readOnlyUniversalTransactionMap
	for _, txHash := range getTxnMsg.HashList {
		mempoolTx, exists := txnMap[*txHash]
		// If the transaction isn't in the pool, just continue without adding
		// it. It is generally OK to respond with only a subset of the transactions
		// that were requested.
		if !exists {
			continue
		}

		mempoolTxs = append(mempoolTxs, mempoolTx)
	}

	// Sort the transactions in the order in which they were added to the mempool.
	// Doing this helps the Peer when they go to add the transactions by reducing
	// unconnectedTxns and transactions being rejected due to missing dependencies.
	sort.Slice(mempoolTxs, func(ii, jj int) bool {
		return mempoolTxs[ii].Added.Before(mempoolTxs[jj].Added)
	})

	// Create a list of the fetched transactions to a response.
	txnList := []*MsgDeSoTxn{}
	for _, mempoolTx := range mempoolTxs {
		txnList = append(txnList, mempoolTx.Tx)
	}

	// At this point the txnList should have all of the transactions that
	// we had available from the request. It should also be below the limit
	// for number of transactions since the request itself was below the
	// limit. So push the bundle to the Peer.
	glog.V(2).Infof("SteadyManager._handleGetTransactionsMessage: Sending txn bundle with size %v to peer (id= %v)",
		len(txnList), origin.ID)

	// Now we must enqueue the transactions in a transaction bundle. The type of transaction
	// bundle we enqueue depends on the blockheight. If the next block is going to be a
	// balance model block, the transactions will include TxnFeeNanos, TxnNonce, and
	// TxnVersion. These fields are only supported by the TransactionBundleV2.
	nextBlockHeight := stm.bc.blockTip().Height + 1
	if nextBlockHeight >= stm.bc.params.ForkHeights.BalanceModelBlockHeight {
		res := &MsgDeSoTransactionBundleV2{}
		res.Transactions = txnList
		if err := stm.srv.SendMessage(res, origin.ID, nil); err != nil {
			return MessageHandlerResponseCodePeerUnavailable
		}
	} else {
		res := &MsgDeSoTransactionBundle{}
		res.Transactions = txnList
		if err := stm.srv.SendMessage(res, origin.ID, nil); err != nil {
			return MessageHandlerResponseCodePeerUnavailable
		}
	}
	return MessageHandlerResponseCodeOK
}

func (stm *SteadyManager) VerifyAndBroadcastTransaction(txn *MsgDeSoTxn) error {
	// Grab the block tip and use it as the height for validation.
	blockHeight := stm.bc.BlockTip().Height
	err := stm.bc.ValidateTransaction(
		txn,
		// blockHeight is set to the next block since that's where this
		// transaction will be mined at the earliest.
		blockHeight+1,
		true,
		stm.mp)
	if err != nil {
		return fmt.Errorf("VerifyAndBroadcastTransaction: Problem validating txn: %v", err)
	}

	// Use the backendServer to add the transaction to the mempool and
	// relay it to peers. When a transaction is created by the user there
	// is no need to consider a rateLimit and also no need to verifySignatures
	// because we generally will have done that already.
	if stm.readOnlyMode {
		err := fmt.Errorf("SteadyManager.VerifyAndBroadcastTransaction: Not processing txn because we are in "+
			"read-only mode: %v", stm.readOnlyMode)
		glog.V(1).Infof(err.Error())
		return err
	}

	if stm.bc.chainState() != SyncStateFullyCurrent {

		err := fmt.Errorf("SteadyManager.VerifyAndBroadcastTransaction: Cannot process txn "+
			"while syncing: (chainState= %v, txn.Hash()= %v)", stm.bc.chainState(), txn.Hash())
		glog.Error(err)
		return err
	}

	glog.V(1).Infof("SteadyManager.VerifyAndBroadcastTransaction: txn (hash= %v)", txn.Hash().String())

	// FIXME: the peerID has always been 0 lol
	// Try and add the transaction to the mempool.
	peerID := uint64(0)
	stm.bc.ChainLock.RLock()
	newlyAcceptedTxns, err := stm.mp.ProcessTransaction(
		txn, true /*allowUnconnectedTxn*/, false, peerID, false)
	stm.bc.ChainLock.RUnlock()
	if err != nil {
		return errors.Wrapf(err, "SteadyManager.VerifyAndBroadcastTransaction: Problem adding transaction to mempool: ")
	}

	glog.V(1).Infof("SteadyManager.VerifyAndBroadcastTransaction: newlyAcceptedTxns: (len= %v)", len(newlyAcceptedTxns))

	// At this point, we know the transaction has been run through the mempool.
	// Now wait for an update of the ReadOnlyUtxoView so we don't break anything.
	stm.mp.BlockUntilReadOnlyViewRegenerated()
	return nil
}

func (stm *SteadyManager) _handleTransactionBundleMessage(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeTransactionBundle {
		return MessageHandlerResponseCodeSkip
	}

	var txnBundleMsg *MsgDeSoTransactionBundle
	var ok bool
	if txnBundleMsg, ok = desoMsg.(*MsgDeSoTransactionBundle); !ok {
		return MessageHandlerResponseCodePeerDisconnect
	}
	glog.V(1).Infof("SteadyManager._handleTransactionBundleMessage: Received TransactionBundle "+
		"message of size %v from Peer %v", len(txnBundleMsg.Transactions), origin.ID)

	// TODO (old): I think making it so that we can't process more than one TransactionBundle at
	// a time would reduce transaction reorderings. Right now, if you get multiple bundles
	// from multiple peers they'll be processed all at once, potentially interleaving with
	// one another.

	glog.V(1).Infof("SteadyManager._handleTransactionBundleMessage: Received TransactionBundle "+
		"message of size %v from Peer (id= %v)", len(txnBundleMsg.Transactions), origin)

	stm._processTransactionsAndMaybeRemoveRequests(txnBundleMsg.Transactions, origin)

	stm.hasProcessedFirstTransactionBundle = true
	return MessageHandlerResponseCodeOK
}

func (stm *SteadyManager) _handleTransactionBundleV2Message(desoMsg DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMsg.GetMsgType() != MsgTypeTransactionBundleV2 {
		return MessageHandlerResponseCodeSkip
	}

	var txnBundleMsg *MsgDeSoTransactionBundleV2
	var ok bool
	if txnBundleMsg, ok = desoMsg.(*MsgDeSoTransactionBundleV2); !ok {
		return MessageHandlerResponseCodePeerDisconnect
	}

	glog.V(2).Infof("Received TransactionBundleV2 message of size %v from Peer (id= %v)",
		len(txnBundleMsg.Transactions), origin.ID)

	// TODO: I think making it so that we can't process more than one TransactionBundle at
	// a time would reduce transaction reorderings. Right now, if you get multiple bundles
	// from multiple peers they'll be processed all at once, potentially interleaving with
	// one another.

	stm._processTransactionsAndMaybeRemoveRequests(txnBundleMsg.Transactions, origin)

	stm.hasProcessedFirstTransactionBundle = true
	return MessageHandlerResponseCodeOK
}

func (stm *SteadyManager) _processTransactionsAndMaybeRemoveRequests(transactions []*MsgDeSoTxn, peer *Peer) {
	transactionsToRelay := stm._processTransactions(peer, transactions)
	glog.V(2).Infof("SteadyManager._processTransactionsAndMaybeRemoveRequests: Accepted %v txns from Peer (id= %v)",
		len(transactionsToRelay), peer)

	_ = transactionsToRelay
	// Remove all the transactions we received from requestedTransactions now
	// that we've processed them. Don't remove them from inventoryBeingProcessed,
	// since that will guard against reprocessing transactions that had errors while
	// processing.
	stm.dataLock.Lock()
	for _, txn := range transactions {
		txHash := txn.Hash()
		delete(stm.requestedTransactionsMap, *txHash)
	}
	stm.dataLock.Unlock()
}

func (stm *SteadyManager) _processTransactions(pp *Peer, transactions []*MsgDeSoTxn) []*MempoolTx {
	// Try and add all the transactions to our mempool in the order we received
	// them. If any fail to get added, just log an error.
	//
	// TODO: It would be nice if we did something fancy here like if we kept
	// track of rejected transactions and retried them every time we connected
	// a block. Doing something like this would make it so that if a transaction
	// was initially rejected due to us not having its dependencies, then we
	// will eventually add it as opposed to just forgetting about it.
	glog.V(2).Infof("SteadyManager._processTransactions: Processing %d transactions from "+
		"peer %v", len(transactions), pp)
	transactionsToRelay := []*MempoolTx{}
	for _, txn := range transactions {
		// Process the transaction with rate-limiting while allowing unconnectedTxns and
		// verifying signatures.
		newlyAcceptedTxns, err := stm.processSingleTxnWithChainLock(pp, txn)
		if err != nil {
			glog.Errorf(fmt.Sprintf("SteadyManager._processTransactions: Rejected "+
				"transaction %v from peer %v from mempool: %v", txn, pp, err))
			// A peer should know better than to send us a transaction that's below
			// our min feerate, which they see when we send them a version message.
			if err == TxErrorInsufficientFeeMinFee {
				glog.Errorf(fmt.Sprintf("SteadyManager._processTransactions: Disconnecting "+
					"Peer %v for sending us a transaction %v with fee below the minimum fee %d",
					pp, txn, stm.mp.minFeeRateNanosPerKB))
				pp.Disconnect()
			}

			// Don't do anything else if we got an error.
			continue
		}
		if len(newlyAcceptedTxns) == 0 {
			glog.Infof(fmt.Sprintf("SteadyManager._processTransactions: "+
				"Transaction %v from peer %v was added as an ORPHAN", spew.Sdump(txn), pp))
		}

		// If we get here then the transaction was accepted into our mempool.
		// Queue the transactions that were accepted them for relay to all of the peers
		// who don't yet have them.
		transactionsToRelay = append(transactionsToRelay, newlyAcceptedTxns...)
	}

	return transactionsToRelay
}

func (stm *SteadyManager) processSingleTxnWithChainLock(peer *Peer, txn *MsgDeSoTxn) ([]*MempoolTx, error) {
	// Lock the chain for reading so that transactions don't shift under our feet
	// when processing this bundle. Not doing this could cause us to miss transactions
	// erroneously.
	//
	// TODO(performance): We should probably do this less frequently.
	stm.bc.ChainLock.RLock()
	defer func() {
		stm.bc.ChainLock.RUnlock()
	}()
	// Note we set rateLimit=false because we have a global minimum txn fee that should
	// prevent spam on its own.
	return stm.mp.ProcessTransaction(
		txn, true /*allowUnconnectedTxn*/, false, /*rateLimit*/
		peer.ID, true /*verifySignatures*/)
}

// Call this on MsgTypeDonePeer
func (stm *SteadyManager) _handleDonePeerMessage(desoMessage DeSoMessage, origin *Peer) MessageHandlerResponseCode {
	if desoMessage.GetMsgType() != MsgTypeDonePeer {
		return MessageHandlerResponseCodeSkip
	}

	// Grab the dataLock since we'll be modifying requestedBlocks
	stm.dataLock.Lock()
	defer stm.dataLock.Unlock()

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
	newPeer := stm.srv.GetRandomPeer()
	if newPeer == nil {
		// If we don't have a new Peer, remove everything that was destined for
		// this Peer. Note we don't need to copy the iterator because everything
		// below doesn't take a reference to it.
		for hashIter, requestInfo := range stm.requestedTransactionsMap {
			hash := hashIter
			if requestInfo.PeerWhoSentInv.ID == origin.ID {
				stm._removeRequestedTransaction(&hash)
			}
		}
		return MessageHandlerResponseCodeSkip
	}

	// If we get here then we know we have a valid newPeer so re-assign all the
	// queued requests to newPeer.

	// Now deal with transactions. They don't have a queue and so all we need to do
	// is reassign the requests that were in-flight to the old Peer and then make
	// the requests to the newPeer.
	txnHashesReassigned := []*BlockHash{}
	for hashIter, requestInfo := range stm.requestedTransactionsMap {
		// Don't do anything if the requests are not meant for the Peer
		// we're disconnecting to the new Peer.
		if requestInfo.PeerWhoSentInv.ID != origin.ID {
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
	getTxnsMsg := &MsgDeSoGetTransactions{
		HashList: txnHashesReassigned,
	}
	return stm.sendGetTransactionsMessage(getTxnsMsg, origin.ID)
}

func (stm *SteadyManager) sendGetTransactionsMessage(getTxnsMsg *MsgDeSoGetTransactions, peerId uint64) MessageHandlerResponseCode {
	// If we're sending a GetTransactions message, the Peer should respond within
	// a few seconds with a TransactionBundle. Every GetTransactions message should
	// receive a TransactionBundle in response. The
	// Server handles situations in which we request certain hashes but only get
	// back a subset of them in the response (i.e. a case in which we received a
	// timely reply but the reply was incomplete).
	//
	// NOTE: at the BalanceModelBlockHeight, MsgTypeTransactionBundle is replaced by
	// the more capable MsgTypeTransactionBundleV2.
	// TODO: After fork, remove this recover block and always expect msg type MsgTypeTransactionBundleV2.
	defer func() {
		if r := recover(); r != nil {
			isSrvNil := stm.srv == nil
			isBlockchainNil := isSrvNil && stm.bc == nil
			isBlockTipNil := !isSrvNil && !isBlockchainNil && stm.bc.blockTip() == nil
			glog.Errorf(
				"Peer._handleOutExpectedResponse: Recovered from panic: %v.\nsrv is nil: %t\nsrv.Blockchain is nil: %t\n,srv.Blockchain.BlockTip is nil: %t", r, isSrvNil, isBlockchainNil, isBlockTipNil)
		}
	}()
	expectedMsgType := MsgTypeTransactionBundle
	if stm.bc.blockTip().Height+1 >= stm.params.ForkHeights.BalanceModelBlockHeight {
		expectedMsgType = MsgTypeTransactionBundleV2
	}
	stallTimeout := time.Duration(int64(stm.stallTimeoutSeconds) * int64(time.Second))
	expectedResponses := []*ExpectedResponse{{
		TimeExpected: time.Now().Add(stallTimeout),
		MessageType:  expectedMsgType,
		// The Server handles situations in which the Peer doesn't send us all of
		// the hashes we were expecting using timeouts on requested hashes.
	}}

	if err := stm.srv.SendMessage(getTxnsMsg, peerId, expectedResponses); err != nil {
		return MessageHandlerResponseCodePeerUnavailable
	}
	return MessageHandlerResponseCodeOK
}
