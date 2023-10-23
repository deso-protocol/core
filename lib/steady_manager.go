package lib

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/lru"
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

type TransactionsManager struct {
	// Inventory stuff.
	// The inventory that we know the peer already has.
	knownInventory lru.Cache

	// Whether the peer is ready to receive INV messages. For a peer that
	// still needs a mempool download, this is false.
	canReceiveInvMessagess bool

	minTxFeeRateNanosPerKB    uint64

	// inventoryBeingProcessed keeps track of the inventory (hashes of blocks and
	// transactions) that we've recently processed from peers. It is useful for
	// avoiding situations in which we re-fetch the same data from many peers.
	// For example, if we get the same Block inv message from multiple peers,
	// adding it to this map and checking this map before replying will make it
	// so that we only send a reply to the first peer that sent us the inv, which
	// is more efficient.
	inventoryBeingProcessed lru.Cache

	// Make this hold a multiple of what we hold for individual peers.
	//srv.inventoryBeingProcessed = lru.NewCache(maxKnownInventory)
	//srv.requestTimeoutSeconds = 10

	// requestedTransactions contains hashes of transactions for which we have
	// requested data but have not yet received a response.
	requestedTransactionsMap     map[BlockHash]*GetDataRequestInfo
	//requestedTransactionsMap: make(map[BlockHash]*GetDataRequestInfo),
	IgnoreInboundPeerInvMessages bool

	// Becomes true after the node has processed its first transaction bundle from
	// any peer. This is useful in a deployment setting because it makes it so that
	// a health check can wait until this value becomes true.
	hasProcessedFirstTransactionBundle bool
}

func NewTransactionsManager() (*TransactionsManager, error) {
	// This will initialize the request queues.
	srv.ResetRequestQueues()
	knownInventory:         lru.NewCache(maxKnownInventory),
	blocksToSend:           make(map[BlockHash]bool),
}

// ResetRequestQueues resets all the request queues.
func (srv *Server) ResetRequestQueues() {
	srv.dataLock.Lock()
	defer srv.dataLock.Unlock()

	glog.V(2).Infof("Server.ResetRequestQueues: Resetting request queues")

	srv.requestedTransactionsMap = make(map[BlockHash]*GetDataRequestInfo)
}

func (sm *SyncManager) HasProcessedFirstTransactionBundle() bool {
	return srv.hasProcessedFirstTransactionBundle
}

func NewTransactionsManager() (*TransactionsManager, error) {
	// This will initialize the request queues.
	srv.ResetRequestQueues()
	go srv._startTransactionRelayer()
}


func (srv *Server) _startTransactionRelayer() {
	// If we've set a maximum sync height, we will not relay transactions.
	// TODO: LOOK INTO THIS MAXSYNCCCC
	/*if srv.blockchain.MaxSyncBlockHeight > 0 {
		return
	}*/

	for {
		if atomic.LoadInt32(&srv.shutdown) > 0 {
			break
		}
		// Just continuously relay transactions to peers that don't have them.
		srv._relayTransactions()
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



func (stm *TransactionsManager) _handleOutExpectedResponse(msg DeSoMessage) {
	switch msg.GetMsgType(){
	case MsgTypeGetTransactions:
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
				isSrvNil := pp.srv == nil
				isBlockchainNil := isSrvNil && pp.srv.blockchain == nil
				isBlockTipNil := !isSrvNil && !isBlockchainNil && pp.srv.blockchain.blockTip() == nil
				glog.Errorf(
					"Peer._handleOutExpectedResponse: Recovered from panic: %v.\nsrv is nil: %t\nsrv.Blockchain is nil: %t\n,srv.Blockchain.BlockTip is nil: %t", r, isSrvNil, isBlockchainNil, isBlockTipNil)
			}
		}()
		expectedMsgType := MsgTypeTransactionBundle
		if pp.srv.blockchain.blockTip().Height+1 >= pp.Params.ForkHeights.BalanceModelBlockHeight {
			expectedMsgType = MsgTypeTransactionBundleV2
		}
		pp._addExpectedResponse(&ExpectedResponse{
			TimeExpected: time.Now().Add(stallTimeout),
			MessageType:  expectedMsgType,
			// The Server handles situations in which the Peer doesn't send us all of
			// the hashes we were expecting using timeouts on requested hashes.
		})
	}

	// TODO: This was in Peer's outHandler, this could happen while we enqueue this message.
	// TODO: ============================
	//		Move this to Transactions Manager
	if msg.GetMsgType() == MsgTypeInv {
		invMsg := msg.(*MsgDeSoInv)

		if len(invMsg.InvList) == 0 {
			// Don't send anything if the inv list is empty after filtering.
			continue
		}

		// Add the new inventory to the peer's knownInventory.
		for _, invVect := range invMsg.InvList {
			pp.knownInventory.Add(*invVect)
		}
	}
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


// MinFeeRateNanosPerKB returns the minimum fee rate this peer requires in order to
// accept transactions into its mempool. We should generally not send a peer a
// transaction below this fee rate.
func (pp *Peer) MinFeeRateNanosPerKB() uint64 {
	pp.StatsMtx.RLock()
	defer pp.StatsMtx.RUnlock()

	return pp.minTxFeeRateNanosPerKB
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

// ExpireRequests checks to see if any requests have expired and removes them if so.
func (srv *Server) ExpireRequests() {
	srv.dataLock.Lock()
	defer srv.dataLock.Unlock()

	srv._expireRequests()
}

func (tr *TransactionsManager) BroadcastTransaction(txn *MsgDeSoTxn) ([]*MempoolTx, error) {
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

func (tr *TransactionsManager) VerifyAndBroadcastTransaction(txn *MsgDeSoTxn) error {
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

func (tr *TransactionsManager) _addNewTxn(
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

func (tm *TransactionsManager) _processTransactions(pp *Peer, transactions []*MsgDeSoTxn) []*MempoolTx {
	// Try and add all the transactions to our mempool in the order we received
	// them. If any fail to get added, just log an error.
	//
	// TODO: It would be nice if we did something fancy here like if we kept
	// track of rejected transactions and retried them every time we connected
	// a block. Doing something like this would make it so that if a transaction
	// was initially rejected due to us not having its dependencies, then we
	// will eventually add it as opposed to just forgetting about it.
	glog.V(2).Infof("Server._processTransactions: Processing %d transactions from "+
		"peer %v", len(transactions), pp)
	transactionsToRelay := []*MempoolTx{}
	for _, txn := range transactions {
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

func (tm *TransactionsManager) _handleTransactionBundle(pp *Peer, msg *MsgDeSoTransactionBundle) {
	glog.V(1).Infof("Server._handleTransactionBundle: Received TransactionBundle "+
		"message of size %v from Peer %v", len(msg.Transactions), pp)

	pp.AddDeSoMessage(msg, true /*inbound*/)
}

func (tm *TransactionsManager) _handleTransactionBundleV2(pp *Peer, msg *MsgDeSoTransactionBundleV2) {
	glog.V(1).Infof("Server._handleTransactionBundleV2: Received TransactionBundle "+
		"message of size %v from Peer %v", len(msg.Transactions), pp)

	pp.AddDeSoMessage(msg, true /*inbound*/)
}

func (pp *Peer) HandleTransactionBundleMessage(msg *MsgDeSoTransactionBundle) {
	// TODO: I think making it so that we can't process more than one TransactionBundle at
	// a time would reduce transaction reorderings. Right now, if you get multiple bundles
	// from multiple peers they'll be processed all at once, potentially interleaving with
	// one another.

	glog.V(1).Infof("Received TransactionBundle "+
		"message of size %v from Peer %v", len(msg.Transactions), pp)

	pp._processTransactionsAndMaybeRemoveRequests(msg.Transactions)

	pp.srv.hasProcessedFirstTransactionBundle = true
}

func (pp *Peer) HandleTransactionBundleMessageV2(msg *MsgDeSoTransactionBundleV2) {
	// TODO: I think making it so that we can't process more than one TransactionBundle at
	// a time would reduce transaction reorderings. Right now, if you get multiple bundles
	// from multiple peers they'll be processed all at once, potentially interleaving with
	// one another.

	glog.V(2).Infof("Received TransactionBundleV2 "+
		"message of size %v from Peer %v", len(msg.Transactions), pp)

	pp._processTransactionsAndMaybeRemoveRequests(msg.Transactions)

	pp.srv.hasProcessedFirstTransactionBundle = true
}

func (pp *Peer) _processTransactionsAndMaybeRemoveRequests(transactions []*MsgDeSoTxn) {
	transactionsToRelay := pp.srv._processTransactions(pp, transactions)
	glog.V(2).Infof("Server._handleTransactionBundle: Accepted %v txns from Peer %v",
		len(transactionsToRelay), pp)

	_ = transactionsToRelay
	// Remove all the transactions we received from requestedTransactions now
	// that we've processed them. Don't remove them from inventoryBeingProcessed,
	// since that will guard against reprocessing transactions that had errors while
	// processing.
	pp.srv.dataLock.Lock()
	for _, txn := range transactions {
		txHash := txn.Hash()
		delete(pp.srv.requestedTransactionsMap, *txHash)
	}
	pp.srv.dataLock.Unlock()
}

// Call this on MsgTypeDonePeer
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

// TODO: ################################
// 	Maybe keep this
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
	switch {
	case MsgTypeGetTransactions:
		msg := msgToProcess.DeSoMessage.(*MsgDeSoGetTransactions)
		glog.V(1).Infof("startDeSoMessageProcessor: RECEIVED message of type %v with "+
			"num hashes %v from peer %v", msgToProcess.DeSoMessage.GetMsgType(), len(msg.HashList), pp)
		pp.HandleGetTransactionsMsg(msg)
	case MsgTypeTransactionBundle:
		msg := msgToProcess.DeSoMessage.(*MsgDeSoTransactionBundle)
		glog.V(1).Infof("startDeSoMessageProcessor: RECEIVED message of type %v with "+
			"num txns %v from peer %v", msgToProcess.DeSoMessage.GetMsgType(), len(msg.Transactions), pp)
		pp.HandleTransactionBundleMessage(msg)
	case MsgTypeTransactionBundleV2:
		glog.V(1).Infof("startDeSoMessageProcessor: RECEIVED message of "+
			"type %v with num txns %v from peer %v", msgToProcess.DeSoMessage.GetMsgType(),
			len(msgToProcess.DeSoMessage.(*MsgDeSoTransactionBundleV2).Transactions), pp)
		pp.HandleTransactionBundleMessageV2(msgToProcess.DeSoMessage.(*MsgDeSoTransactionBundleV2))

	case MsgTypeInv:
		msg := msgToProcess.DeSoMessage.(*MsgDeSoInv)
		glog.V(1).Infof("startDeSoMessageProcessor: RECEIVED message of type %v with "+
			"num invs %v from peer %v", msgToProcess.DeSoMessage.GetMsgType(), len(msg.InvList), pp)
		pp.HandleInv(msg)
	}
}



// This call blocks on the Peer's queue.
func (pp *Peer) HandleGetTransactionsMsg(getTxnMsg *MsgDeSoGetTransactions) {
	// Get all the transactions we have from the mempool.
	glog.V(1).Infof("Peer._handleGetTransactions: Processing "+
		"MsgDeSoGetTransactions message with %v txns from peer %v",
		len(getTxnMsg.HashList), pp)

	mempoolTxs := []*MempoolTx{}
	txnMap := pp.srv.mempool.readOnlyUniversalTransactionMap
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
	glog.V(2).Infof("Peer._handleGetTransactions: Sending txn bundle with size %v to peer %v",
		len(txnList), pp)

	// Now we must enqueue the transactions in a transaction bundle. The type of transaction
	// bundle we enqueue depends on the blockheight. If the next block is going to be a
	// balance model block, the transactions will include TxnFeeNanos, TxnNonce, and
	// TxnVersion. These fields are only supported by the TransactionBundleV2.
	nextBlockHeight := pp.srv.blockchain.blockTip().Height + 1
	if nextBlockHeight >= pp.srv.blockchain.params.ForkHeights.BalanceModelBlockHeight {
		res := &MsgDeSoTransactionBundleV2{}
		res.Transactions = txnList
		// TODO: Change this to AddDeSoMessage
		pp.QueueMessage(res)
	} else {
		res := &MsgDeSoTransactionBundle{}
		res.Transactions = txnList
		pp.QueueMessage(res)
	}
}
