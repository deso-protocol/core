package lib

import (
	"fmt"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/go-deadlock"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

// peer.go defines an interface for connecting to and managing an DeSo
// peer. Each peer a node is connected to is represented by a Peer object,
// and the Peer object is how messages are sent and received to/from the
// peer. A good place to start is inHandler and outHandler in this file.

// ExpectedResponse is a struct used to enforce timeouts on peers. For example,
// if we send a GetBlocks message, we would expect a response within a given
// window and disconnect from the Peer if we don't get that response.
type ExpectedResponse struct {
	TimeExpected time.Time
	MessageType  MsgType
}

type DeSoMessageMeta struct {
	DeSoMessage DeSoMessage
	Inbound     bool
}

// Peer is an object that holds all of the state for a connection to another node.
// Any communication with other nodes happens via this object, which maintains a
// queue of messages to send to the other node.
type Peer struct {
	// TODO: Remove this and merge it with the RemoteNode.HandshakeMetaData type
	NegotiatedProtocolVersion ProtocolVersionType

	// These stats should be accessed atomically.
	bytesReceived uint64
	bytesSent     uint64
	totalMessages uint64
	lastRecv      int64
	lastSend      int64

	// Stats that should be accessed using the mutex below.
	StatsMtx       deadlock.RWMutex
	TimeOffsetSecs int64
	TimeConnected  time.Time
	ID             uint64
	// Ping-related fields.
	LastPingNonce  uint64
	LastPingTime   time.Time
	LastPingMicros int64

	// Connection info.
	cmgr                *ConnectionManager
	Conn                net.Conn
	isOutbound          bool
	isPersistent        bool
	stallTimeoutSeconds uint64
	Params              *DeSoParams
	MessageChan         chan *ServerMessage

	// A pointer to the Server
	srv *Server

	// Basic state.
	PeerInfoMtx            deadlock.Mutex
	serviceFlags           ServiceFlag
	latestHeight           uint64
	addrStr                string
	netAddr                *wire.NetAddressV2
	minTxFeeRateNanosPerKB uint64
	// Messages for which we are expecting a reply within a fixed
	// amount of time. This list is always sorted by ExpectedTime,
	// with the item having the earliest time at the front.
	expectedResponses []*ExpectedResponse

	// The addresses this peer is aware of.
	knownAddressesMapLock deadlock.RWMutex
	knownAddressesMap     map[string]bool

	// Output queue for messages that need to be sent to the peer.
	outputQueueChan      chan DeSoMessage
	peerDisconnectedChan chan *Peer

	// Set to zero until Disconnect has been called on the Peer. Used to make it
	// so that the logic in Disconnect will only be executed once.
	disconnected int32
	// TODO: This should be an enum.
	// disconnectReason is the reason the peer was disconnected. It is set the first
	// time Disconnect is called on a peer.
	disconnectReason string
	// Signals that the peer is now in the stopped state.
	quit chan interface{}

	// Each Peer is only allowed to have certain number of blocks being sent
	// to them at any gven time. We use
	// this value to enforce that constraint. The reason we need to do this is without
	// it one peer could theoretically clog our Server by issuing many GetBlocks
	// requests that ultimately don't get delivered. This way the number of blocks
	// being sent is limited to a multiple of the number of Peers we have.
	blocksToSendMtx deadlock.Mutex
	blocksToSend    map[BlockHash]bool

	// Inventory stuff.
	// The inventory that we know the peer already has.
	knownInventory *collections.LruSet[InvVect]

	// Whether the peer is ready to receive INV messages. For a peer that
	// still needs a mempool download, this is false.
	canReceiveInvMessages bool
	// Whether we have sent a MEMPOOL message to the peer to request INV messages.
	// This makes sure that we only ever send one MEMPOOL message to the peer.
	hasReceivedMempoolMessage bool

	// We process GetTransaction requests in a separate loop. This allows us
	// to ensure that the responses are ordered.
	mtxMessageQueue deadlock.RWMutex
	messageQueue    []*DeSoMessageMeta

	requestedBlocks map[BlockHash]bool

	// We will only allow peer fetch one snapshot chunk at a time so we will keep
	// track whether this peer has a get snapshot request in flight.
	snapshotChunkRequestInFlight bool

	// SyncType indicates whether blocksync should not be requested for this peer. If set to true
	// then we'll only hypersync from this peer.
	syncType NodeSyncType

	// startGroup ensures that all the Peer's go routines are started when we call Start().
	startGroup sync.WaitGroup
}

func (pp *Peer) GetId() uint64 {
	return pp.ID
}

func (pp *Peer) AddDeSoMessage(desoMessage DeSoMessage, inbound bool) {
	// Don't add any more messages if the peer is disconnected
	if pp.disconnected != 0 {
		glog.Errorf("AddDeSoMessage: Not enqueueing message %v because peer is disconnecting", desoMessage.GetMsgType())
		return
	}

	pp.mtxMessageQueue.Lock()
	defer pp.mtxMessageQueue.Unlock()

	pp.messageQueue = append(pp.messageQueue, &DeSoMessageMeta{
		DeSoMessage: desoMessage,
		Inbound:     inbound,
	})
}

func (pp *Peer) MaybeDequeueDeSoMessage() *DeSoMessageMeta {
	pp.mtxMessageQueue.Lock()
	defer pp.mtxMessageQueue.Unlock()

	// If we don't have any requests to process just return
	if len(pp.messageQueue) == 0 {
		return nil
	}
	// If we get here then we know we have messages to process.

	messageToReturn := pp.messageQueue[0]
	pp.messageQueue = pp.messageQueue[1:]

	return messageToReturn
}

// This call blocks on the Peer's queue.
func (pp *Peer) HandleGetTransactionsMsg(getTxnMsg *MsgDeSoGetTransactions) {
	// Get all the transactions we have from the mempool.
	glog.V(1).Infof("Peer._handleGetTransactions: Processing "+
		"MsgDeSoGetTransactions message with %v txns from peer %v",
		len(getTxnMsg.HashList), pp)

	mempoolTxs := []*MempoolTx{}

	// We fetch the requested txns from either the PoW mempool or the PoS mempool
	// whichever one is used for the consensus protocol at the current block height.
	for _, txHash := range getTxnMsg.HashList {
		mempoolTx := pp.srv.GetMempool().GetTransaction(txHash)
		// If the transaction isn't in the pool, or hasn't been validated, just continue without adding
		// it. It is generally OK to respond with only a subset of the transactions that were requested.
		if mempoolTx == nil || !mempoolTx.IsValidated() {
			continue
		}

		mempoolTxs = append(mempoolTxs, mempoolTx)
	}

	// Sort the transactions in the order in which they were added to the mempool.
	// Doing this helps the Peer when they go to add the transactions by reducing
	// unconnectedTxns and transactions being rejected due to missing dependencies.
	sort.Slice(mempoolTxs, func(ii, jj int) bool {
		return mempoolTxs[ii].GetTimestamp() < mempoolTxs[jj].GetTimestamp()
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
		pp.QueueMessage(res)
	} else {
		res := &MsgDeSoTransactionBundle{}
		res.Transactions = txnList
		pp.QueueMessage(res)
	}
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
		pp.knownInventory.Put(*invVect)

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
			if requestIsInFlight || pp.srv.GetMempool().IsTransactionInPool(&currentHash) {
				continue
			}

			txHashList = append(txHashList, &currentHash)
		} else if invVect.Type == InvTypeBlock {
			// For blocks, we check that the hash isn't known to us either in our
			// main header chain or in side chains.
			exists, err := pp.srv.blockchain.HasHeader(&currentHash)
			if exists {
				continue
			}
			if err != nil {
				glog.Errorf("Server._handleInv: Error checking if block exists: %v", err)
				continue
			}

			blockHashList = append(blockHashList, &currentHash)
		}

		// If we made it here, it means the inventory was added to one of the
		// lists so mark it as processed on the Server.
		pp.srv.inventoryBeingProcessed.Put(*invVect)
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
		locator, locatorHeights := pp.srv.blockchain.LatestHeaderLocator()
		headerTip := pp.srv.blockchain.headerTip()
		blockTip := pp.srv.blockchain.blockTip()
		glog.V(2).Infof("Server._handleInv: Sending GET_HEADERS message to peer %v\n"+
			"Block Locator Hashes & Heights: (%v, %v)\n"+
			"Header Tip: (%v, %v)\nBlock Tip: (%v, %v)",
			pp, locator, locatorHeights, headerTip.Hash, headerTip.Height,
			blockTip.Hash, blockTip.Height)
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
		glog.V(1).Infof("Server._handleInv: Ignoring INV while syncing from Peer %v", pp)
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

	// Before Version2 we would send each block in a single message, which was quite
	// slow. Now when we receive a GetBlocks message we will send the blocks in large
	// batches, which is much faster.
	if pp.NegotiatedProtocolVersion == ProtocolVersion2 {
		allBlocks := MsgDeSoBlockBundle{}
		for _, hashToSend := range msg.HashList {
			blockToSend := pp.srv.blockchain.GetBlock(hashToSend)
			if blockToSend == nil {
				// Don't ask us for blocks before verifying that we have them with a
				// GetHeaders request.
				glog.Errorf("Server._handleGetBlocks: Disconnecting peer %v because "+
					"she asked for a block with hash %v that we don't have", pp, msg.HashList[0])
				pp.Disconnect("handleGetBlocks - requested block with hash we don't have. protocolV2")
				return
			}
			allBlocks.Blocks = append(allBlocks.Blocks, blockToSend)
		}
		allBlocks.TipHash = pp.srv.blockchain.blockTip().Hash
		allBlocks.TipHeight = uint64(pp.srv.blockchain.blockTip().Height)
		pp.AddDeSoMessage(&allBlocks, false)

	} else {
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
				pp.Disconnect("handleGetBlocks - requested block with hash we don't have. protocol < v2")
				return
			}
			pp.AddDeSoMessage(blockToSend, false)
		}
	}
}

// HandleGetSnapshot gets called whenever we receive a GetSnapshot message from a peer. This means
// a peer is asking us to send him some data from our most recent snapshot. To respond to the peer we
// will retrieve the chunk from our main and ancestral records db and attach it to the response message.
// This function is handled within peer's inbound message loop because retrieving a chunk is costly.
func (pp *Peer) HandleGetSnapshot(msg *MsgDeSoGetSnapshot) {
	// Start a timer to measure how much time sending a snapshot takes.
	pp.srv.timer.Start("Send Snapshot")
	defer pp.srv.timer.End("Send Snapshot")
	defer pp.srv.timer.Print("Send Snapshot")

	// Make sure this peer can only request one snapshot chunk at a time.
	if pp.snapshotChunkRequestInFlight {
		glog.V(1).Infof("Peer.HandleGetSnapshot: Ignoring GetSnapshot from Peer %v"+
			"because he already requested a GetSnapshot", pp)
		pp.Disconnect("handleGetSnapshot - peer already requested a snapshot chunk")
		return
	}
	pp.snapshotChunkRequestInFlight = true
	defer func(pp *Peer) { pp.snapshotChunkRequestInFlight = false }(pp)

	// Ignore GetSnapshot requests and disconnect the peer if we're not a hypersync node.
	if pp.srv.snapshot == nil {
		glog.Errorf("Peer.HandleGetSnapshot: Ignoring GetSnapshot from Peer %v "+
			"and disconnecting because node doesn't support HyperSync", pp)
		pp.Disconnect("handleGetSnapshot - peer doesn't support HyperSync")
		return
	}

	// Ignore GetSnapshot requests if we're still syncing. We will only serve snapshot chunk when our
	// blockchain state is fully current.
	if pp.srv.blockchain.isSyncing() {
		chainState := pp.srv.blockchain.chainState()
		glog.V(1).Infof("Peer.HandleGetSnapshot: Ignoring GetSnapshot from Peer %v"+
			"because node is syncing with ChainState (%v)", pp, chainState)
		pp.AddDeSoMessage(&MsgDeSoSnapshotData{
			SnapshotMetadata:  nil,
			SnapshotChunk:     nil,
			SnapshotChunkFull: false,
			Prefix:            msg.GetPrefix(),
		}, false)
		return
	}

	// Make sure that the start key and prefix provided in the message are valid.
	if len(msg.SnapshotStartKey) == 0 || len(msg.GetPrefix()) == 0 {
		glog.Errorf("Peer.HandleGetSnapshot: Ignoring GetSnapshot from Peer %v "+
			"because SnapshotStartKey or Prefix are empty", pp)
		pp.Disconnect("handleGetSnapshot - empty SnapshotStartKey or Prefix")
		return
	}

	// FIXME: Any restrictions on how many snapshots a peer can request?

	// Get the snapshot chunk from the database. This operation can happen concurrently with updates
	// to the main DB or the ancestral records DB, and we don't want to slow down any of these updates.
	// Because of that, we will detect whenever concurrent access takes place with the concurrencyFault
	// variable. If concurrency is detected, we will re-queue the GetSnapshot message.

	// 05/09/2024: Leaving the above comment around for posterity. The concurrencyFault variable is no longer
	// used because we performant all snapshot operations in a synchronous manner that blocks until the operation
	// is completed, so badger is guaranteed to have the snapshot db prefix populated with the most
	// up-to-date data based on the most recently committed block. For more information and rationale on the change
	// to make the snapshot operations synchronous, read the long comment in snapshot.go.
	var err error

	snapshotDataMsg := &MsgDeSoSnapshotData{
		Prefix:           msg.GetPrefix(),
		SnapshotMetadata: pp.srv.snapshot.CurrentEpochSnapshotMetadata,
	}
	if isStateKey(msg.GetPrefix()) {
		snapshotDataMsg.SnapshotChunk, snapshotDataMsg.SnapshotChunkFull, err =
			pp.srv.snapshot.GetSnapshotChunk(msg.GetPrefix(), msg.SnapshotStartKey)
	} else {
		// If the received prefix is not a state key, then it is likely that the peer has newer code.
		// A peer would be requesting state data for the newly added state prefix, though this node
		// doesn't recognize the prefix yet. We respond to the peer with an empty snapshot chunk,
		// since we don't have any data for the prefix yet. Even if the peer was misbehaving and
		// intentionally requesting non-existing prefix data, it doesn't really matter.
		snapshotDataMsg.SnapshotChunk = []*DBEntry{EmptyDBEntry()}
		snapshotDataMsg.SnapshotChunkFull = false
	}
	if err != nil {
		glog.Errorf("Peer.HandleGetSnapshot: something went wrong during fetching "+
			"snapshot chunk for peer (%v), error (%v)", pp, err)
		return
	}

	pp.AddDeSoMessage(snapshotDataMsg, false)

	glog.V(2).Infof("Server._handleGetSnapshot: Sending a SnapshotChunk message to peer (%v) "+
		"with SnapshotHeight (%v) and CurrentEpochChecksumBytes (%v) and Snapshotdata length (%v)", pp,
		pp.srv.snapshot.CurrentEpochSnapshotMetadata.SnapshotBlockHeight,
		snapshotDataMsg.SnapshotMetadata, len(snapshotDataMsg.SnapshotChunk))
}

func (pp *Peer) cleanupMessageProcessor() {
	pp.mtxMessageQueue.Lock()
	defer pp.mtxMessageQueue.Unlock()

	// We assume that no more elements will be added to the message queue once this function
	// is called.
	glog.V(1).Infof("StartDeSoMessageProcessor: Cleaning up message queue for peer: %v", pp)
	pp.messageQueue = nil
	// Set a few more things to nil just to make sure the garbage collector doesn't
	// get confused when freeing up this Peer's memory. This is to fix a bug where
	// inbound peers disconnecting was causing an OOM.
	pp.cmgr = nil
	pp.srv = nil
	pp.MessageChan = nil
	//pp.Conn = nil
}

func (pp *Peer) StartDeSoMessageProcessor() {
	pp.startGroup.Done()
	glog.V(1).Infof("StartDeSoMessageProcessor: Starting for peer %v", pp)
	for {
		if pp.disconnected != 0 {
			pp.cleanupMessageProcessor()
			glog.V(1).Infof("StartDeSoMessageProcessor: Stopping because peer disconnected: %v", pp)
			return
		}
		msgToProcess := pp.MaybeDequeueDeSoMessage()
		if msgToProcess == nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		// If we get here we know we have a transaction to process.

		if msgToProcess.Inbound {
			switch msgToProcess.DeSoMessage.GetMsgType() {
			case MsgTypeGetTransactions:
				msg := msgToProcess.DeSoMessage.(*MsgDeSoGetTransactions)
				glog.V(1).Infof("StartDeSoMessageProcessor: RECEIVED message of type %v with "+
					"num hashes %v from peer %v", msgToProcess.DeSoMessage.GetMsgType(), len(msg.HashList), pp)
				pp.HandleGetTransactionsMsg(msg)
			case MsgTypeTransactionBundle:
				msg := msgToProcess.DeSoMessage.(*MsgDeSoTransactionBundle)
				glog.V(1).Infof("StartDeSoMessageProcessor: RECEIVED message of type %v with "+
					"num txns %v from peer %v", msgToProcess.DeSoMessage.GetMsgType(), len(msg.Transactions), pp)
				pp.HandleTransactionBundleMessage(msg)
			case MsgTypeTransactionBundleV2:
				glog.V(1).Infof("StartDeSoMessageProcessor: RECEIVED message of "+
					"type %v with num txns %v from peer %v", msgToProcess.DeSoMessage.GetMsgType(),
					len(msgToProcess.DeSoMessage.(*MsgDeSoTransactionBundleV2).Transactions), pp)
				pp.HandleTransactionBundleMessageV2(msgToProcess.DeSoMessage.(*MsgDeSoTransactionBundleV2))

			case MsgTypeInv:
				msg := msgToProcess.DeSoMessage.(*MsgDeSoInv)
				glog.V(1).Infof("StartDeSoMessageProcessor: RECEIVED message of type %v with "+
					"num invs %v from peer %v", msgToProcess.DeSoMessage.GetMsgType(), len(msg.InvList), pp)
				pp.HandleInv(msg)

			case MsgTypeGetBlocks:
				msg := msgToProcess.DeSoMessage.(*MsgDeSoGetBlocks)
				glog.V(1).Infof("StartDeSoMessageProcessor: RECEIVED message of type %v with "+
					"num hashes %v from peer %v", msgToProcess.DeSoMessage.GetMsgType(), len(msg.HashList), pp)
				pp.HandleGetBlocks(msg)

			case MsgTypeGetSnapshot:
				msg := msgToProcess.DeSoMessage.(*MsgDeSoGetSnapshot)
				glog.V(1).Infof("StartDeSoMessageProcessor: RECEIVED message of type %v with start key %v "+
					"and prefix %v from peer %v", msgToProcess.DeSoMessage.GetMsgType(), msg.SnapshotStartKey, msg.GetPrefix(), pp)

				pp.HandleGetSnapshot(msg)
			default:
				glog.Errorf("StartDeSoMessageProcessor: ERROR RECEIVED message of "+
					"type %v from peer %v", msgToProcess.DeSoMessage.GetMsgType(), pp)
			}
		} else {
			glog.V(1).Infof("StartDeSoMessageProcessor: SENDING message of "+
				"type %v to peer %v", msgToProcess.DeSoMessage.GetMsgType(), pp)
			pp.QueueMessage(msgToProcess.DeSoMessage)
		}
	}
}

// NewPeer creates a new Peer object.
func NewPeer(_id uint64, _conn net.Conn, _isOutbound bool, _netAddr *wire.NetAddressV2,
	_isPersistent bool, _stallTimeoutSeconds uint64,
	_minFeeRateNanosPerKB uint64,
	params *DeSoParams,
	messageChan chan *ServerMessage,
	_cmgr *ConnectionManager, _srv *Server,
	_syncType NodeSyncType,
	peerDisconnectedChan chan *Peer) *Peer {

	knownInventoryCache, _ := collections.NewLruSet[InvVect](maxKnownInventory)

	pp := Peer{
		ID:                     _id,
		cmgr:                   _cmgr,
		srv:                    _srv,
		Conn:                   _conn,
		addrStr:                _conn.RemoteAddr().String(),
		netAddr:                _netAddr,
		isOutbound:             _isOutbound,
		isPersistent:           _isPersistent,
		outputQueueChan:        make(chan DeSoMessage),
		peerDisconnectedChan:   peerDisconnectedChan,
		quit:                   make(chan interface{}),
		knownInventory:         knownInventoryCache,
		blocksToSend:           make(map[BlockHash]bool),
		stallTimeoutSeconds:    _stallTimeoutSeconds,
		minTxFeeRateNanosPerKB: _minFeeRateNanosPerKB,
		knownAddressesMap:      make(map[string]bool),
		Params:                 params,
		MessageChan:            messageChan,
		requestedBlocks:        make(map[BlockHash]bool),
		syncType:               _syncType,
	}

	// TODO: Before, we would give each Peer its own Logger object. Now we
	// have a much better way of debugging which is that we include a nonce
	// in all messages related to a Peer (i.e. PeerID=%d) that allows us to
	// pipe the output to a file and inspect it (and if we choose to filter on
	// a PeerID= then we can see exclusively that Peer's related messages).
	// Still, we're going to leave this logic here for a little while longer in
	// case a situation arises where commenting it in seems like it would be
	// useful.
	//
	// Each peer gets its own log directory. Name the directory with
	// IP:PORT_ID to ensure it's identifiable but also unique. The higher
	// the ID the more recently the peer connection was established.
	/*
		logDir := fmt.Sprintf("%s.%05d_%d.log", addrmgr.NetAddressKey(_netAddr), pp.ID, time.Now().UnixNano())
		resetLogDir := false
		pp.Logger = glog.NewLogger(logDir, resetLogDir)
		// Don't log peer information to stderr.
		pp.Logger.AlsoToStderr = false
	*/
	return &pp
}

// MinFeeRateNanosPerKB returns the minimum fee rate this peer requires in order to
// accept transactions into its mempool. We should generally not send a peer a
// transaction below this fee rate.
func (pp *Peer) MinFeeRateNanosPerKB() uint64 {
	pp.StatsMtx.RLock()
	defer pp.StatsMtx.RUnlock()

	return pp.minTxFeeRateNanosPerKB
}

// StartingBlockHeight is the height of the peer's blockchain tip.
func (pp *Peer) StartingBlockHeight() uint64 {
	pp.StatsMtx.RLock()
	defer pp.StatsMtx.RUnlock()
	return pp.latestHeight
}

// NumBlocksToSend is the number of blocks the Peer has requested from
// us that we have yet to send them.
func (pp *Peer) NumBlocksToSend() uint32 {
	pp.blocksToSendMtx.Lock()
	defer pp.blocksToSendMtx.Unlock()

	return uint32(len(pp.blocksToSend))
}

const (
	// maxKnownInventory is the maximum number of items to keep in the known
	// inventory cache.
	maxKnownInventory = 1000000

	// pingInterval is the interval of time to wait in between sending ping
	// messages.
	pingInterval = 2 * time.Minute

	// idleTimeout is the duration of inactivity before we time out a peer.
	idleTimeout = 5 * time.Minute
)

// HandlePingMsg is invoked when a peer receives a ping message. It replies with a pong
// message.
func (pp *Peer) HandlePingMsg(msg *MsgDeSoPing) {
	// Include nonce from ping so pong can be identified.
	glog.V(2).Infof("Peer.HandlePingMsg: Received ping from peer %v: %v", pp, msg)
	// Queue up a pong message.
	pp.QueueMessage(&MsgDeSoPong{Nonce: msg.Nonce})
}

// HandlePongMsg is invoked when a peer receives a pong message.  It
// updates the ping statistics.
func (pp *Peer) HandlePongMsg(msg *MsgDeSoPong) {
	// Arguably we could use a buffered channel here sending data
	// in a fifo manner whenever we send a ping, or a list keeping track of
	// the times of each ping. For now we just make a best effort and
	// only record stats if it was for the last ping sent. Any preceding
	// and overlapping pings will be ignored. It is unlikely to occur
	// without large usage of the ping call since we ping infrequently
	// enough that if they overlap we would have timed out the peer.
	glog.V(2).Infof("Peer.HandlePongMsg: Received pong from peer %v: %v", msg, pp)
	pp.StatsMtx.Lock()
	defer pp.StatsMtx.Unlock()
	if pp.LastPingNonce != 0 && msg.Nonce == pp.LastPingNonce {
		pp.LastPingMicros = time.Since(pp.LastPingTime).Nanoseconds()
		pp.LastPingMicros /= 1000 // convert to usec.
		pp.LastPingNonce = 0
		glog.V(2).Infof("Peer.HandlePongMsg: LastPingMicros(%d) from Peer %v", pp.LastPingMicros, pp)
	}
}

func (pp *Peer) PingHandler() {
	pp.startGroup.Done()
	glog.V(1).Infof("Peer.PingHandler: Starting ping handler for Peer %v", pp)
	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

out:
	for {
		select {
		case <-pingTicker.C:
			glog.V(2).Infof("Peer.PingHandler: Initiating ping for Peer %v", pp)
			nonce, err := wire.RandomUint64()
			if err != nil {
				glog.Errorf("Not sending ping to Peer %v: %v", pp, err)
				continue
			}
			// Update the ping stats when we initiate a ping.
			//
			// TODO: Setting LastPingTime here means that we're technically measuring the time
			// between *queueing* the ping and when we receive a pong vs the time between when
			// a ping is actually sent and when the pong is received. To fix it we'd have to
			// detect a ping message in the outHandler and set the stats there instead.
			pp.StatsMtx.Lock()
			pp.LastPingNonce = nonce
			pp.LastPingTime = time.Now()
			pp.StatsMtx.Unlock()
			// Queue the ping message to be sent.
			pp.QueueMessage(&MsgDeSoPing{Nonce: nonce})

		case <-pp.quit:
			break out
		}
	}
}

func (pp *Peer) String() string {
	isDisconnected := ""
	if pp.disconnected != 0 {
		isDisconnected = fmt.Sprintf(", DISCONNECTED (%v)", pp.disconnectReason)
	}
	return fmt.Sprintf("[ Remote Address: %v%s PeerID=%d ]", pp.addrStr, isDisconnected, pp.ID)
}

func (pp *Peer) Connected() bool {
	return atomic.LoadInt32(&pp.disconnected) == 0
}

func (pp *Peer) Address() string {
	return pp.addrStr
}

func (pp *Peer) NetAddress() *wire.NetAddressV2 {
	return pp.netAddr
}

func (pp *Peer) IP() string {
	return pp.netAddr.ToLegacy().IP.String()
}

func (pp *Peer) Port() uint16 {
	return pp.netAddr.Port
}

func (pp *Peer) IsOutbound() bool {
	return pp.isOutbound
}

func (pp *Peer) IsPersistent() bool {
	return pp.isPersistent
}

func (pp *Peer) QueueMessage(desoMessage DeSoMessage) {
	// If the peer is disconnected, don't queue anything.
	if !pp.Connected() {
		return
	}

	pp.outputQueueChan <- desoMessage
}

func (pp *Peer) _handleOutExpectedResponse(msg DeSoMessage) {
	pp.PeerInfoMtx.Lock()
	defer pp.PeerInfoMtx.Unlock()

	// If we're sending the peer a GetBlocks message, we expect to receive the
	// blocks at minimum within a few seconds of each other.
	stallTimeout := time.Duration(int64(pp.stallTimeoutSeconds) * int64(time.Second))
	switch msg.GetMsgType() {
	case MsgTypeGetBlocks:
		getBlocks := msg.(*MsgDeSoGetBlocks)
		if pp.NegotiatedProtocolVersion >= ProtocolVersion2 {
			// TODO: What if the amount of blocks exceeds a single MsgTypeBlockBundle response.
			// Note there isn't really a way in the current code for us to request more
			// blocks in a single bundle that we should expect in a single response, so
			// we should be ok.
			pp._addExpectedResponse(&ExpectedResponse{
				TimeExpected: time.Now().Add(stallTimeout),
				MessageType:  MsgTypeBlockBundle,
			})
		} else {
			// We have one block expected for each entry in the message.
			for ii := range getBlocks.HashList {
				pp._addExpectedResponse(&ExpectedResponse{
					TimeExpected: time.Now().Add(
						stallTimeout + time.Duration(int64(ii)*int64(stallTimeout))),
					MessageType: MsgTypeBlock,
				})
			}
		}
	case MsgTypeGetHeaders:
		// If we're sending a GetHeaders message, the Peer should respond within
		// a few seconds with a HeaderBundle.
		pp._addExpectedResponse(&ExpectedResponse{
			TimeExpected: time.Now().Add(stallTimeout),
			MessageType:  MsgTypeHeaderBundle,
		})
	case MsgTypeGetSnapshot:
		// If we're sending a GetSnapshot message, the peer should respond within a few seconds with a SnapshotData.
		pp._addExpectedResponse(&ExpectedResponse{
			TimeExpected: time.Now().Add(stallTimeout),
			MessageType:  MsgTypeSnapshotData,
		})
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
}

func (pp *Peer) _filterAddrMsg(addrMsg *MsgDeSoAddr) *MsgDeSoAddr {
	pp.knownAddressesMapLock.Lock()
	defer pp.knownAddressesMapLock.Unlock()

	filteredAddrMsg := &MsgDeSoAddr{}
	for _, addr := range addrMsg.AddrList {
		if _, hasAddr := pp.knownAddressesMap[addr.StringWithPort(false /*includePort*/)]; hasAddr {
			continue
		}

		// If we get here this is an address the peer hasn't seen before so
		// don't filter it out. Also add it to the known address map.
		filteredAddrMsg.AddrList = append(filteredAddrMsg.AddrList, addr)
		pp.knownAddressesMap[addr.StringWithPort(false /*includePort*/)] = true
	}

	return filteredAddrMsg
}

func (pp *Peer) _setKnownAddressesMap(key string, val bool) {
	pp.knownAddressesMapLock.Lock()
	defer pp.knownAddressesMapLock.Unlock()

	pp.knownAddressesMap[key] = val
}

func (pp *Peer) SetLatestBlockHeight(height uint64) {
	pp.StatsMtx.Lock()
	defer pp.StatsMtx.Unlock()

	pp.latestHeight = height
}

func (pp *Peer) SetServiceFlag(sf ServiceFlag) {
	pp.PeerInfoMtx.Lock()
	defer pp.PeerInfoMtx.Unlock()

	pp.serviceFlags = sf
}

func (pp *Peer) SetNegotiatedProtocolVersion(negotiatedProtocolVersion ProtocolVersionType) {
	pp.PeerInfoMtx.Lock()
	defer pp.PeerInfoMtx.Unlock()

	pp.NegotiatedProtocolVersion = negotiatedProtocolVersion
}

func (pp *Peer) outHandler() {
	pp.startGroup.Done()
	glog.V(1).Infof("Peer.outHandler: Starting outHandler for Peer %v", pp)
	stallTicker := time.NewTicker(time.Second)
out:
	for {
		select {
		case msg := <-pp.outputQueueChan:
			// Wire up the responses we expect from the Peer depending on what
			// type of message it is.
			pp._handleOutExpectedResponse(msg)

			if msg.GetMsgType() == MsgTypeInv {
				invMsg := msg.(*MsgDeSoInv)

				if len(invMsg.InvList) == 0 {
					// Don't send anything if the inv list is empty after filtering.
					continue
				}

				// Add the new inventory to the peer's knownInventory.
				for _, invVect := range invMsg.InvList {
					pp.knownInventory.Put(*invVect)
				}
			}

			// if we're sending a MEMPOOL message, then we
			if msg.GetMsgType() == MsgTypeMempool {
				pp.hasReceivedMempoolMessage = true
			}

			// If we're sending a block, remove it from our blocksToSend map to allow
			// the peer to request more blocks after receiving this one.
			if msg.GetMsgType() == MsgTypeBlock {
				pp.blocksToSendMtx.Lock()
				hash, _ := msg.(*MsgDeSoBlock).Hash()
				delete(pp.blocksToSend, *hash)
				pp.blocksToSendMtx.Unlock()
			}

			// If we're sending a block bundle, remove all the blocks from our blocksToSend
			// to allow the peer to request more blocks after receiving this bundle.
			if msg.GetMsgType() == MsgTypeBlockBundle {
				pp.blocksToSendMtx.Lock()
				for _, block := range msg.(*MsgDeSoBlockBundle).Blocks {
					hash, _ := block.Hash()
					delete(pp.blocksToSend, *hash)
				}
				pp.blocksToSendMtx.Unlock()
			}

			// Before we send an addr message to the peer, filter out the addresses
			// the peer is already aware of.
			if msg.GetMsgType() == MsgTypeAddr {
				msg = pp._filterAddrMsg(msg.(*MsgDeSoAddr))

				// Don't send anything if we managed to filter out all the addresses.
				if len(msg.(*MsgDeSoAddr).AddrList) == 0 {
					continue
				}
			}

			// If we have a problem sending a message to a peer then disconnect them.
			glog.V(3).Infof("Writing Message: (%v)", msg)
			if err := pp.WriteDeSoMessage(msg); err != nil {
				glog.Errorf("Peer.outHandler: Problem sending message to peer: %v: %v", pp, err)
				pp.Disconnect("outHandler - problem sending message to peer")
			}
		case <-stallTicker.C:
			// Every second take a look to see if there's something that the peer should
			// have responded to that they're delinquent on. If there is then error and
			// disconnect the Peer.
			if len(pp.expectedResponses) == 0 {
				// If there are no expected responses, nothing to do.
				continue
			}
			// The expected responses are sorted by when the corresponding requests were
			// made. As such, if the first entry is not past the deadline then nothing is.
			firstEntry := pp.expectedResponses[0]
			nowTime := time.Now()
			if nowTime.After(firstEntry.TimeExpected) {
				glog.Errorf("Peer.outHandler: Peer %v took too long to response to "+
					"reqest. Expected MsgType=%v at time %v but it is now time %v",
					pp, firstEntry.MessageType, firstEntry.TimeExpected, nowTime)
				pp.Disconnect(fmt.Sprintf(
					"outHandler - peer took too long to respond to request, expected MsgType=%v",
					firstEntry.MessageType))
			}

		case <-pp.quit:
			break out
		}
	}

	glog.V(1).Infof("Peer.outHandler: Quitting outHandler for Peer %v", pp)
}

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
	//
	// We can safely increase this without breaking backwards-compatibility because old
	// nodes will never send us more hashes than this.
	if len(pp.blocksToSend) > MaxBlocksInFlightPoS {
		pp.Disconnect("maybeAddBlocksToSend - too many blocks requested")
		return fmt.Errorf("_maybeAddBlocksToSend: Disconnecting peer %v because she requested %d "+
			"blocks, which is more than the %d blocks allowed "+
			"in flight", pp, len(pp.blocksToSend), MaxBlocksInFlightPoS)
	}

	return nil
}

func (pp *Peer) _removeEarliestExpectedResponse(msgType MsgType) *ExpectedResponse {
	pp.PeerInfoMtx.Lock()
	defer pp.PeerInfoMtx.Unlock()

	// Just remove the first instance we find of the passed-in message
	// type and return.
	for ii, res := range pp.expectedResponses {
		if res.MessageType == msgType {
			// We found the first occurrence of the message type so remove
			// that message since we're no longer waiting on it.
			left := append([]*ExpectedResponse{}, pp.expectedResponses[:ii]...)
			pp.expectedResponses = append(left, pp.expectedResponses[ii+1:]...)

			// Return so we stop processing.
			return res
		}
	}

	return nil
}

func (pp *Peer) _addExpectedResponse(item *ExpectedResponse) {
	if len(pp.expectedResponses) == 0 {
		pp.expectedResponses = []*ExpectedResponse{item}
		return
	}

	// Usually the item will need to be added at the end so start
	// from there.
	index := len(pp.expectedResponses)
	for index > 0 &&
		pp.expectedResponses[index-1].TimeExpected.After(item.TimeExpected) {

		index--
	}

	left := append([]*ExpectedResponse{}, pp.expectedResponses[:index]...)
	right := pp.expectedResponses[index:]
	pp.expectedResponses = append(append(left, item), right...)
}

func (pp *Peer) _handleInExpectedResponse(rmsg DeSoMessage) error {
	// Let the Peer off the hook if the response is one we were waiting for.
	// Do this in a separate switch to keep things clean.
	msgType := rmsg.GetMsgType()
	if msgType == MsgTypeBlock ||
		msgType == MsgTypeBlockBundle ||
		msgType == MsgTypeHeaderBundle ||
		msgType == MsgTypeTransactionBundle ||
		msgType == MsgTypeTransactionBundleV2 ||
		msgType == MsgTypeSnapshotData {

		expectedResponse := pp._removeEarliestExpectedResponse(msgType)
		if expectedResponse == nil {
			// We should never get one of these types of messages unless we've previously
			// requested it so disconnect the Peer in this case.
			errRet := fmt.Errorf("_handleInExpectedResponse: Received unsolicited message "+
				"of type %v %v from peer %v -- disconnecting", msgType, rmsg, pp)
			glog.V(1).Infof(errRet.Error())
			// TODO: Removing this check so we can inject transactions into the node.
			//return errRet
		}

		// If we get here then we managed to dequeue a message we were
		// expecting, which is good.
	}

	return nil
}

// inHandler handles all incoming messages for the peer. It must be run as a
// goroutine.
func (pp *Peer) inHandler() {
	pp.startGroup.Done()
	glog.V(1).Infof("Peer.inHandler: Starting inHandler for Peer %v", pp)

	// The timer is stopped when a new message is received and reset after it
	// is processed.
	idleTimer := time.AfterFunc(idleTimeout, func() {
		glog.V(1).Infof("Peer.inHandler: Peer %v no answer for %v -- disconnecting", pp, idleTimeout)
		pp.Disconnect("inHandler - no answer for idleTimeout")
	})

out:
	for {
		// Read a message and stop the idle timer as soon as the read
		// is done. The timer is reset below for the next iteration if
		// needed.
		rmsg, err := pp.ReadDeSoMessage()
		idleTimer.Stop()
		if err != nil {
			glog.Errorf("Peer.inHandler: Can't read message from peer %v: %v", pp, err)

			break out
		}

		// Adjust what we expect our Peer to send us based on what we're now
		// receiving with this message.
		if err := pp._handleInExpectedResponse(rmsg); err != nil {
			break out
		}

		// If we get an addr message, add all of the addresses to the known addresses
		// for the peer.
		if rmsg.GetMsgType() == MsgTypeAddr {
			addrMsg := rmsg.(*MsgDeSoAddr)
			for _, addr := range addrMsg.AddrList {
				pp._setKnownAddressesMap(addr.StringWithPort(false /*includePort*/), true)
			}
		}

		// If we receive a control message from a Peer then that Peer is misbehaving
		// and we should disconnect. Control messages should never originate from Peers.
		if IsControlMessage(rmsg.GetMsgType()) {
			glog.Errorf("Peer.inHandler: Received control message of type %v from "+
				"Peer %v; this should never happen. Disconnecting the Peer", rmsg.GetMsgType(), pp)
			break out
		}

		// Potentially adjust blocksToSend to account for blocks the Peer is
		// currently requesting from us. Disconnect the Peer if she's requesting too many
		// blocks now.
		if err := pp._maybeAddBlocksToSend(rmsg); err != nil {
			glog.Errorf(err.Error())
			break out
		}

		// This switch actually processes the message. For most messages, we just
		// pass them onto the Server.
		switch msg := rmsg.(type) {
		case *MsgDeSoPing:
			// Respond to a ping with a pong.
			pp.HandlePingMsg(msg)

		case *MsgDeSoPong:
			// Measure the ping time when we receive a pong.
			pp.HandlePongMsg(msg)

		case *MsgDeSoDisconnectedPeer, *MsgDeSoQuit:

			// We should never receive control messages from a Peer. Disconnect if we do.
			glog.Errorf("Peer.inHandler: Received control message of type %v from "+
				"Peer %v which should never happen -- disconnecting", msg.GetMsgType(), pp)
			break out

		default:
			// All other messages just forward back to the Server to handle them.
			//glog.V(2).Infof("Peer.inHandler: Received message of type %v from %v", rmsg.GetMsgType(), pp)
			pp.MessageChan <- &ServerMessage{
				Peer: pp,
				Msg:  msg,
			}
		}

		// A message was received so reset the idle timer.
		idleTimer.Reset(idleTimeout)
	}

	// Ensure the idle timer is stopped to avoid leaking the resource.
	idleTimer.Stop()

	// Disconnect the Peer if it isn't already.
	pp.Disconnect("inHandler - done processing messages")

	glog.V(1).Infof("Peer.inHandler: done for peer: %v", pp)
}

func (pp *Peer) Start() {
	glog.V(1).Infof("Peer.Start: Starting peer %v", pp)
	// The protocol has been negotiated successfully so start processing input
	// and output messages.
	pp.startGroup.Add(4)
	go pp.PingHandler()
	go pp.outHandler()
	go pp.inHandler()
	go pp.StartDeSoMessageProcessor()
	pp.startGroup.Wait()

	// Send our verack message now that the IO processing machinery has started.
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

func (pp *Peer) WriteDeSoMessage(msg DeSoMessage) error {
	payload, err := WriteMessage(pp.Conn, msg, pp.Params.NetworkType)
	if err != nil {
		return errors.Wrapf(err, "WriteDeSoMessage: ")
	}

	// Only track the payload sent in the statistics we track.
	atomic.AddUint64(&pp.bytesSent, uint64(len(payload)))
	atomic.StoreInt64(&pp.lastSend, time.Now().Unix())

	// Useful for debugging.
	// TODO: This may be too verbose
	messageSeq := atomic.AddUint64(&pp.totalMessages, 1)
	glog.V(3).Infof("SENDING( seq=%d ) message of type: %v to peer %v: %v",
		messageSeq, msg.GetMsgType(), pp, msg)

	return nil
}

func (pp *Peer) ReadDeSoMessage() (DeSoMessage, error) {
	msg, payload, err := ReadMessage(pp.Conn, pp.Params.NetworkType)
	if err != nil {
		err := errors.Wrapf(err, "ReadDeSoMessage: ")
		glog.Error(err)
		return nil, err
	}

	// Only track the payload received in the statistics we track.
	msgLen := uint64(len(payload))
	atomic.AddUint64(&pp.bytesReceived, msgLen)
	atomic.StoreInt64(&pp.lastRecv, time.Now().Unix())

	// Useful for debugging.
	messageSeq := atomic.AddUint64(&pp.totalMessages, 1)
	glog.V(3).Infof("RECEIVED( seq=%d ) message of type: %v from peer %v: %v",
		messageSeq, msg.GetMsgType(), pp, msg)

	return msg, nil
}

// TODO: Disconnect reason enum

// Disconnect closes a peer's network connection.
func (pp *Peer) Disconnect(reason string) {
	// Only run the logic the first time Disconnect is called.
	glog.V(1).Infof(CLog(Yellow, "Peer.Disconnect: Starting for Peer %v with reason: %v"), pp, reason)
	if atomic.LoadInt32(&pp.disconnected) != 0 {
		glog.V(1).Infof("Peer.Disconnect: Disconnect call ignored since it was already called before for Peer %v", pp)
		return
	}
	atomic.AddInt32(&pp.disconnected, 1)
	pp.disconnectReason = reason

	glog.V(2).Infof("Peer.Disconnect: Running Disconnect for the first time for Peer %v", pp)

	// Close the connection object.
	pp.Conn.Close()

	// Signaling the quit channel allows all the other goroutines to stop running.
	close(pp.quit)

	// Free the cache of known inventory.
	pp.knownInventory.Purge()

	// Add the Peer to donePeers so that the ConnectionManager and Server can do any
	// cleanup they need to do.
	pp.peerDisconnectedChan <- pp
}

func (pp *Peer) _logVersionSuccess() {
	inboundStr := "INBOUND"
	if pp.isOutbound {
		inboundStr = "OUTBOUND"
	}
	persistentStr := "PERSISTENT"
	if !pp.isPersistent {
		persistentStr = "NON-PERSISTENT"
	}
	logStr := fmt.Sprintf("SUCCESS version negotiation for (%s) (%s) peer (%v).", inboundStr, persistentStr, pp)
	glog.V(1).Info(logStr)
}

func (pp *Peer) _logAddPeer() {
	inboundStr := "INBOUND"
	if pp.isOutbound {
		inboundStr = "OUTBOUND"
	}
	persistentStr := "PERSISTENT"
	if !pp.isPersistent {
		persistentStr = "NON-PERSISTENT"
	}
	logStr := fmt.Sprintf("ADDING (%s) (%s) peer (%v)", inboundStr, persistentStr, pp)
	glog.V(1).Info(logStr)
}
