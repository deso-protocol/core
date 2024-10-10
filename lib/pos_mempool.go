package lib

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/golang/glog"
	"github.com/hashicorp/golang-lru/v2"
	"github.com/pkg/errors"
)

type PosMempoolStatus int

const (
	PosMempoolStatusNotInitialized PosMempoolStatus = 0
	PosMempoolStatusInitialized    PosMempoolStatus = 1
	PosMempoolStatusRunning        PosMempoolStatus = 2
)

type Mempool interface {
	Start() error
	Stop()
	IsRunning() bool
	AddTransaction(txn *MsgDeSoTxn, txnTimestamp time.Time) error
	RemoveTransaction(txnHash *BlockHash) error
	GetTransaction(txnHash *BlockHash) *MempoolTx
	GetTransactions() []*MempoolTx
	UpdateLatestBlock(blockView *UtxoView, blockHeight uint64)
	UpdateGlobalParams(globalParams *GlobalParamsEntry)

	GetAugmentedUniversalView() (*UtxoView, error)
	GetAugmentedUtxoViewForPublicKey(pk []byte, optionalTx *MsgDeSoTxn) (*UtxoView, error)
	BlockUntilReadOnlyViewRegenerated()
	WaitForTxnValidation(txHash *BlockHash) error
	CheckSpend(op UtxoKey) *MsgDeSoTxn
	GetOrderedTransactions() []*MempoolTx
	IsTransactionInPool(txHash *BlockHash) bool
	GetMempoolTipBlockHeight() uint64
	GetMempoolTx(txHash *BlockHash) *MempoolTx
	GetMempoolSummaryStats() map[string]*SummaryStats
	EstimateFee(txn *MsgDeSoTxn, minFeeRateNanosPerKB uint64) (uint64, error)
	EstimateFeeRate(minFeeRateNanosPerKB uint64) uint64
}

// GetAugmentedUniversalViewWithAdditionalTransactions is meant as a helper function
// for backend APIs to better construct atomic transactions while maintaining various
// transactional sanity checks. It SHOULD NOT be used for consensus critical tasks
// as it does not validate signatures, does not validate fees, and would likely lead
// to a nonsensical state of the blockchain.
//
// In the case of atomic transactions it's likely that a user will have a series of
// dependent transactions (transactions that MUST be submitted together in a specific order)
// that they plan to submit as a single atomic transaction. However, functions like
// GetAugmentedUniversalView may not have access to this series of transactions meaning
// backend APIs using GetAugmentedUniversalView will generate errors unnecessarily in the case
// of certain atomic transaction workflows. To deal with this, we can use
// GetAugmentedUniversalViewWithAdditionalTransactions which will create a
// view that has connected a set of transactions (specified by optionalTxns).
//
// NOTE: GetAugmentedUniversalViewWithAdditionalTransactions DOES NOT validate fees
// as fees are computed in UtxoView.ConnectBlock and optionalTxns are not included
// in any block that can be connected yet.
func GetAugmentedUniversalViewWithAdditionalTransactions(
	mempool Mempool,
	optionalTxns []*MsgDeSoTxn,
) (
	*UtxoView,
	error,
) {
	// Generate an augmented view.
	newView, err := mempool.GetAugmentedUniversalView()
	if err != nil {
		return nil, errors.Wrap(err, "GetAugmentedUniversalViewWithAdditionalTransactions")
	}

	// Connect optional txns (if any).
	currentTimestampNanoSecs := time.Now().UnixNano()
	if optionalTxns != nil && len(optionalTxns) > 0 {
		for ii, txn := range optionalTxns {
			_, _, _, _, err := newView.ConnectTransaction(
				txn,
				txn.Hash(),
				uint32(mempool.GetMempoolTipBlockHeight()+1),
				currentTimestampNanoSecs,
				false,
				true,
			)
			if err != nil {
				return nil, errors.Wrapf(err,
					"GetAugmentedUniversalViewWithAdditionalTransactions failed connecting transaction %d of %d",
					ii, len(optionalTxns))
			}
		}
	}
	return newView, nil
}

// PosMempool is used by the node to keep track of uncommitted transactions. The main responsibilities of the PosMempool
// include addition/removal of transactions, back up of transaction to database, and retrieval of transactions ordered
// by Fee-Time algorithm. More on the Fee-Time algorithm can be found in the documentation of TransactionRegister.
type PosMempool struct {
	sync.RWMutex
	// startGroup and exitGroup are concurrency control mechanisms used to ensure that all the PosMempool routines
	// are started and stopped properly. The startGroup is used to wait for all the PosMempool routines to start before
	// returning from the Start method. The exitGroup is used to wait for all the PosMempool routines to stop before
	// returning from the Stop method.
	startGroup sync.WaitGroup
	exitGroup  sync.WaitGroup

	status PosMempoolStatus
	// params of the blockchain
	params *DeSoParams
	// globalParams are used to track the latest GlobalParamsEntry. In case the GlobalParamsEntry changes, the PosMempool
	// is equipped with UpdateGlobalParams method to handle upgrading GlobalParamsEntry.
	globalParams *GlobalParamsEntry
	// inMemoryOnly is a setup flag that determines whether the mempool should be backed up to db or not. If set to true,
	// the mempool will not open a db nor instantiate the persister.
	inMemoryOnly bool
	// dir of the directory where the database should be stored.
	dir string
	// db is the database that the mempool will use to persist transactions.
	db *badger.DB

	// txnRegister is the in-memory data structure keeping track of the transactions in the mempool. The TransactionRegister
	// is responsible for ordering transactions by the Fee-Time algorithm.
	txnRegister *TransactionRegister
	// persister is responsible for interfacing with the database. The persister backs up mempool transactions so not to
	// lose them when node reboots. The persister also retrieves transactions from the database when the node starts up.
	// The persister runs on its dedicated thread and events are used to notify the persister thread whenever
	// transactions are added/removed from the mempool. The persister thread then updates the database accordingly.
	persister *MempoolPersister
	// nonceTracker is responsible for keeping track of a (public key, nonce) -> Txn index. The index is useful in
	// facilitating a "replace by higher fee" feature. This feature gives users the ability to replace their existing
	// mempool transaction with a new transaction having the same nonce but higher fee.
	nonceTracker *NonceTracker

	// readOnlyLatestBlockView is used to check if a transaction has a valid nonce before being added to the mempool.
	// The readOnlyLatestBlockView should be updated whenever a new block is added to the blockchain via UpdateLatestBlock.
	// PosMempool only needs read-access to the block view. It isn't necessary to copy the block view before passing it
	// to the mempool.
	readOnlyLatestBlockView *UtxoView
	// validateTransactionsReadOnlyLatestBlockView is the same as the readOnlyLatestBlockView but is exclusively for use
	// in the validateTransactions routine. The validateTransactions routine is a routine that validates the top Fee-Time
	// ordered transactions in the mempool.
	validateTransactionsReadOnlyLatestBlockView *UtxoView
	// augmentedReadOnlyLatestBlockView is a copy of the latest block view with all the transactions in the mempool applied to
	// it. This allows the backend to display the current state of the blockchain including the mempool.
	// The augmentedReadOnlyLatestBlockView is updated every 10 milliseconds to reflect the latest state of the mempool.
	augmentedReadOnlyLatestBlockView *UtxoView
	// augmentedReadOnlyLatestBlockViewMutex is used to protect the augmentedLatestBlockView from concurrent access.
	augmentedReadOnlyLatestBlockViewMutex sync.RWMutex
	// Signals that the mempool is now in the stopped state.
	quit chan interface{}
	// latestBlockNode is used to infer the latest block height. The latestBlockNode should be updated whenever a new
	// block is added to the blockchain via UpdateLatestBlock.
	latestBlockHeight uint64
	// mempoolBackupIntervalMillis is the frequency with which pos mempool persists transactions to storage.
	mempoolBackupIntervalMillis uint64

	// feeEstimator is used to estimate the fee required for a transaction to be included in the next block
	// based off the current state of the mempool and the most n recent blocks.
	feeEstimator *PoSFeeEstimator

	// maxValidationViewConnects is the maximum number of transactions that the mempool will connect to the validation view
	// during the validateTransactions operation. This limit applies to the number of transactions that successfully connect
	// to the validation view. Transactions that will fail the validation view connection are not counted towards this limit.
	maxValidationViewConnects uint64

	// transactionValidationRoutineRefreshIntervalMillis is the frequency with which the transactionValidationRoutine is run.
	transactionValidationRefreshIntervalMillis uint64

	// augmentedLatestBlockViewSequenceNumber is the sequence number of the augmentedLatestBlockView. It is incremented
	// every time augmentedLatestBlockView is updated. It can be used by obtainers of the augmentedLatestBlockView to
	// wait until a particular transaction has been connected.
	augmentedLatestBlockViewSequenceNumber int64

	// recentBlockTxnCache is an LRU KV cache used to track the transaction that have been included in blocks.
	// This cache is used to power logic that waits for a transaction to either be validated in the mempool
	// or be included in a block.
	recentBlockTxnCache *lru.Cache[BlockHash, struct{}]

	// recentRejectedTxnCache is a cache to store the txns that were recently rejected so that we can return better
	// errors for them.
	recentRejectedTxnCache *lru.Cache[BlockHash, error]
}

func NewPosMempool() *PosMempool {
	return &PosMempool{
		status:       PosMempoolStatusNotInitialized,
		txnRegister:  NewTransactionRegister(),
		feeEstimator: NewPoSFeeEstimator(),
		nonceTracker: NewNonceTracker(),
		quit:         make(chan interface{}),
	}
}

func (mp *PosMempool) Init(
	params *DeSoParams,
	globalParams *GlobalParamsEntry,
	readOnlyLatestBlockView *UtxoView,
	latestBlockHeight uint64,
	dir string,
	inMemoryOnly bool,
	mempoolBackupIntervalMillis uint64,
	feeEstimatorPastBlocks []*MsgDeSoBlock,
	maxValidationViewConnects uint64,
	transactionValidationRefreshIntervalMillis uint64,
) error {
	mp.Lock()
	defer mp.Unlock()

	if mp.status != PosMempoolStatusNotInitialized {
		return errors.New("PosMempool.Init: PosMempool already initialized")
	}

	// Initialize the parametrized fields.
	mp.params = params
	mp.globalParams = globalParams
	var err error
	if readOnlyLatestBlockView != nil {
		mp.readOnlyLatestBlockView = readOnlyLatestBlockView.CopyUtxoView()
		mp.augmentedReadOnlyLatestBlockView = readOnlyLatestBlockView.CopyUtxoView()
		mp.validateTransactionsReadOnlyLatestBlockView = readOnlyLatestBlockView.CopyUtxoView()
	}
	mp.latestBlockHeight = latestBlockHeight
	mp.dir = dir
	mp.inMemoryOnly = inMemoryOnly
	mp.mempoolBackupIntervalMillis = mempoolBackupIntervalMillis
	mp.maxValidationViewConnects = maxValidationViewConnects
	mp.transactionValidationRefreshIntervalMillis = transactionValidationRefreshIntervalMillis
	mp.recentBlockTxnCache, _ = lru.New[BlockHash, struct{}](100000) // cache 100K latest txns from blocks.
	mp.recentRejectedTxnCache, _ = lru.New[BlockHash, error](100000) // cache 100K rejected txns.

	// Recreate and initialize the transaction register and the nonce tracker.
	mp.txnRegister = NewTransactionRegister()
	mp.txnRegister.Init(mp.globalParams)
	mp.nonceTracker = NewNonceTracker()

	// Initialize the fee estimator
	err = mp.feeEstimator.Init(mp.txnRegister, feeEstimatorPastBlocks, mp.globalParams)
	if err != nil {
		return errors.Wrapf(err, "PosMempool.Start: Problem initializing fee estimator")
	}
	mp.status = PosMempoolStatusInitialized
	return nil
}

func (mp *PosMempool) Start() error {
	mp.Lock()
	defer mp.Unlock()

	if mp.status != PosMempoolStatusInitialized {
		return errors.New("PosMempool.Start: PosMempool not initialized")
	}

	// Setup the database and create the persister
	if !mp.inMemoryOnly {
		mempoolDirectory := filepath.Join(mp.dir, "pos_mempool")
		opts := DefaultBadgerOptions(mempoolDirectory)
		db, err := badger.Open(opts)
		if err != nil {
			return errors.Wrapf(err, "PosMempool.Start: Problem setting up database")
		}
		mp.db = db
		mp.persister = NewMempoolPersister(mp.db, int(mp.mempoolBackupIntervalMillis))

		// Start the persister and retrieve transactions from the database.
		mp.persister.Start()
		err = mp.loadPersistedTransactions()
		if err != nil {
			return errors.Wrapf(err, "PosMempool.Start: Problem loading persisted transactions")
		}
	}

	mp.startGroup.Add(1)
	mp.exitGroup.Add(1)
	mp.startTransactionValidationRoutine()
	mp.startGroup.Wait()
	mp.status = PosMempoolStatusRunning

	return nil
}

// startTransactionValidationRoutine is responsible for validating transactions in the mempool. The routine runs every
// transactionValidationRefreshIntervalMillis milliseconds. It uses the validateTransactions method to validate the
// top Fee-Time ordered transactions in the mempool.
func (mp *PosMempool) startTransactionValidationRoutine() {
	go func() {
		mp.startGroup.Done()
		for {
			select {
			case <-time.After(time.Duration(mp.transactionValidationRefreshIntervalMillis) * time.Millisecond):
				if err := mp.validateTransactions(); err != nil {
					glog.Errorf("PosMempool.startTransactionValidationRoutine: Problem validating transactions: %v", err)
				}
			case <-mp.quit:
				mp.exitGroup.Done()
				return
			}
		}
	}()
}

func (mp *PosMempool) Stop() {
	if !mp.IsRunning() {
		return
	}
	close(mp.quit)
	mp.exitGroup.Wait()

	mp.Lock()
	defer mp.Unlock()
	// Close the persister and stop the database.
	if !mp.inMemoryOnly {
		if err := mp.persister.Stop(); err != nil {
			glog.Errorf("PosMempool.Stop: Problem stopping persister: %v", err)
		}
		if err := mp.db.Close(); err != nil {
			glog.Errorf("PosMempool.Stop: Problem closing database: %v", err)
		}
	}

	// Reset the transaction register, the ledger, and the nonce tracker.
	mp.txnRegister.Reset()
	mp.nonceTracker.Reset()
	mp.feeEstimator = NewPoSFeeEstimator()
	mp.status = PosMempoolStatusNotInitialized
}

func (mp *PosMempool) IsRunning() bool {
	return mp.status == PosMempoolStatusRunning
}

// OnBlockConnected is an event handler provided by the PoS mempool to handle the blockchain
// event where a block is connected to the tip of the blockchain. The mempool updates its
// internal state based on the new block that has been connected.
//
// Whenever a block is connected, this event handler removes the block's transactions from
// the mempool and updates the internal fee estimation to include new block.
func (mp *PosMempool) OnBlockConnected(block *MsgDeSoBlock) {
	mp.Lock()
	defer mp.Unlock()

	if block.Header == nil || !mp.IsRunning() {
		return
	}

	// Remove all transactions in the block from the mempool.
	for _, txn := range block.Txns {
		txnHash := txn.Hash()

		// This should never happen. We perform a nil check on the txn hash to avoid a panic.
		if txnHash == nil {
			continue
		}

		// Get the transaction from the register. If the txn doesn't exist in the register,
		// then there's nothing left to do.
		existingTxn := mp.txnRegister.GetTransaction(txnHash)
		if existingTxn == nil {
			continue
		}

		// Add the transaction to the recentBlockTxnCache.
		mp.addTxnHashToRecentBlockCache(*txnHash)

		// Remove the transaction from the mempool.
		if err := mp.removeTransactionNoLock(existingTxn, true); err != nil {
			glog.Errorf("PosMempool.OnBlockConnected: Problem removing transaction from mempool: %v", err)
		}
	}

	// Add the block to the fee estimator. This is a best effort operation. If we fail to add the block
	// to the fee estimator, we log an error and continue.
	if err := mp.feeEstimator.AddBlock(block); err != nil {
		glog.Errorf("PosMempool.OnBlockConnected: Problem adding block to fee estimator: %v", err)
	}
}

// OnBlockDisconnected is an event handler provided by the PoS mempool to handle the blockchain
// event where a block is disconnected from the tip of the blockchain. The mempool updates its
// internal state based on the block that has been disconnected.
//
// Whenever a block is disconnected, this event handler adds the block's transactions back to
// the mempool and updates the internal fee estimation to exclude the disconnected block.
func (mp *PosMempool) OnBlockDisconnected(block *MsgDeSoBlock) {
	mp.Lock()
	defer mp.Unlock()

	if block.Header == nil || !mp.IsRunning() {
		return
	}

	// Add all transactions in the block to the mempool.
	for _, txn := range block.Txns {
		txnHash := txn.Hash()

		// This should never happen. We perform a nil check on the txn hash to avoid a panic.
		if txnHash == nil {
			continue
		}

		// Add all transactions in the block to the mempool.

		// Construct the MempoolTx from the MsgDeSoTxn.
		mempoolTx, err := NewMempoolTx(txn, NanoSecondsToTime(block.Header.TstampNanoSecs), mp.latestBlockHeight)
		if err != nil {
			continue
		}

		// Remove the transaction from the recentBlockTxnCache.
		mp.deleteTxnHashFromRecentBlockCache(*txnHash)

		// Add the transaction to the mempool and then prune if needed.
		if err := mp.addTransactionNoLock(mempoolTx, true); err != nil {
			glog.Errorf("PosMempool.AddTransaction: Problem adding transaction to mempool: %v", err)
		}
	}

	// This is a best effort operation. If we fail to prune the mempool, we log an error and continue.
	if err := mp.pruneNoLock(); err != nil {
		glog.Errorf("PosMempool.AddTransaction: Problem pruning mempool: %v", err)
	}

	// Remove the block from the fee estimator.
	if err := mp.feeEstimator.RemoveBlock(block); err != nil {
		glog.Errorf("PosMempool.OnBlockDisconnected: Problem removing block from fee estimator: %v", err)
	}
}

// AddTransaction validates a MsgDeSoTxn transaction and adds it to the mempool if it is valid.
// If the mempool overflows as a result of adding the transaction, the mempool is pruned.
func (mp *PosMempool) AddTransaction(txn *MsgDeSoTxn, txnTimestamp time.Time) error {
	if txn == nil {
		return fmt.Errorf("PosMempool.AddTransaction: Cannot add a nil transaction")
	}

	// If the transaction is already in the transaction register, then we return an error.
	if mp.txnRegister.GetTransaction(txn.Hash()) != nil {
		return errors.New("PosMempool.AddTransaction: Transaction already in mempool")
	}

	// Acquire the mempool lock for all operations related to adding the transaction
	// TODO: Do we need to wrap all of our validation logic in a write-lock? We should revisit
	// this later and try to pull as much as we can out of the critical section here. The reason
	// we added this lock is because checkTransactionSanity was calling ValidateTransactionNonce
	// on the readOnly view, which was causing a modification of the view's PKID map at the same
	// time as another thread was reading from it. This lock solves the issue but may not be the
	// most optimal.
	mp.Lock()
	defer mp.Unlock()

	// First, validate that the transaction is properly formatted according to BalanceModel. We acquire a read lock on
	// the mempool. This allows multiple goroutines to safely perform transaction validation concurrently.
	if err := mp.checkTransactionSanity(txn, false); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem verifying transaction")
	}

	// If we get this far, it means that the transaction is valid. We can now add it to the mempool.
	if !mp.IsRunning() {
		return errors.Wrapf(MempoolErrorNotRunning, "PosMempool.AddTransaction: ")
	}

	// Construct the MempoolTx from the MsgDeSoTxn.
	mempoolTx, err := NewMempoolTx(txn, txnTimestamp, mp.latestBlockHeight)
	if err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem constructing MempoolTx")
	}

	// Add the transaction to the mempool and then prune if needed.
	if err := mp.addTransactionNoLock(mempoolTx, true); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem adding transaction to mempool")
	}

	if err := mp.pruneNoLock(); err != nil {
		glog.Errorf("PosMempool.AddTransaction: Problem pruning mempool: %v", err)
	}

	return nil
}

func (mp *PosMempool) addTxnHashToRecentBlockCache(txnHash BlockHash) {
	mp.recentBlockTxnCache.Add(txnHash, struct{}{})
}

func (mp *PosMempool) deleteTxnHashFromRecentBlockCache(txnHash BlockHash) {
	mp.recentBlockTxnCache.Remove(txnHash)
}
func (mp *PosMempool) isTxnHashInRecentBlockCache(txnHash BlockHash) bool {
	return mp.recentBlockTxnCache.Contains(txnHash)
}

func (mp *PosMempool) checkTransactionSanity(txn *MsgDeSoTxn, expectInnerAtomicTxn bool) error {
	// If the txn is an atomic, we need to check the transaction sanity for each txn as well as verify the wrapper.
	if txn.TxnMeta.GetTxnType() == TxnTypeAtomicTxnsWrapper {
		// First verify the wrapper.
		atomicTxnsWrapper, ok := txn.TxnMeta.(*AtomicTxnsWrapperMetadata)
		if !ok {
			return fmt.Errorf(
				"PosMempool.AddTransaction: Problem verifying atomic txn wrapper - casting metadata failed")
		}
		// Verify the size
		if err := mp.readOnlyLatestBlockView._verifyAtomicTxnsSize(txn, mp.latestBlockHeight); err != nil {
			return errors.Wrapf(err, "PosMempool.AddTransaction: Problem verifying atomic txn size")
		}
		// Verify the wrapper.
		if err := _verifyAtomicTxnsWrapper(txn); err != nil {
			return errors.Wrapf(err, "PosMempool.AddTransaction: Problem verifying atomic txn wrapper")
		}

		// Verify the chain of transactions to make sure they are not tampered with.
		if err := _verifyAtomicTxnsChain(atomicTxnsWrapper); err != nil {
			return errors.Wrapf(err, "PosMempool.AddTransaction: Problem verifying atomic txn chain")
		}
		// Okay we've verified the wrapper and the chain of transactions. Now we need to verify each transaction.
		for _, innerTxn := range atomicTxnsWrapper.Txns {
			if err := mp.checkTransactionSanity(innerTxn, true); err != nil {
				return errors.Wrapf(err, "PosMempool.AddTransaction: Problem validating transaction sanity")
			}
		}
		// Return early so we do not assess the rest of the validation checks on the wrapper.
		return nil
	}

	// If the txn is supposed to be an inner txn in an atomic wrapper, we need to make sure it is properly formed.
	// If the txn is NOT supposed to an inner txn in an atomic wrapper, we need to make sure it does not have
	// the extra data fields that are only allowed in atomic txns.
	isInnerAtomicTxn := txn.IsAtomicTxnsInnerTxn()
	if isInnerAtomicTxn != expectInnerAtomicTxn {
		return fmt.Errorf(
			"PosMempool.AddTransaction: expected txn to be atomic: %v, got: %v",
			expectInnerAtomicTxn,
			isInnerAtomicTxn,
		)
	}

	if err := CheckTransactionSanity(txn, uint32(mp.latestBlockHeight), mp.params); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem validating transaction sanity")
	}

	if err := ValidateDeSoTxnSanityBalanceModel(txn, mp.latestBlockHeight, mp.params, mp.globalParams); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem validating transaction sanity")
	}

	if err := mp.readOnlyLatestBlockView.ValidateTransactionNonce(txn, mp.latestBlockHeight); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem validating transaction nonce")
	}

	return nil
}

func (mp *PosMempool) checkNonceTracker(txn *MempoolTx, userPk *PublicKey) (*MempoolTx, error) {

	// Check the nonceTracker to see if this transaction is meant to replace an existing one.
	existingTxn := mp.nonceTracker.GetTxnByPublicKeyNonce(*userPk, *txn.Tx.TxnNonce)
	if existingTxn != nil && existingTxn.FeePerKB > txn.FeePerKB {
		return nil, errors.Wrapf(MempoolFailedReplaceByHigherFee, "PosMempool.AddTransaction: Problem replacing transaction "+
			"by higher fee failed. New transaction has lower fee.")
	}

	// TODO: is it okay to allow if the incoming tx is an inner atomic txn?
	if existingTxn != nil && existingTxn.Tx.IsAtomicTxnsInnerTxn() {
		return nil, errors.Wrapf(MempoolFailedReplaceByHigherFee, "PosMempool.AddTransaction: Cannot replace txn that is"+
			"an inner atomic txn.")
	}
	return existingTxn, nil
}

func (mp *PosMempool) removeNonces(txns []*MsgDeSoTxn) {
	for _, txn := range txns {
		userPk := NewPublicKey(txn.PublicKey)
		mp.nonceTracker.RemoveTxnByPublicKeyNonce(*userPk, *txn.TxnNonce)
	}
}

func (mp *PosMempool) persistMempoolAddEvent(txn *MempoolTx, persistToDb bool) {
	// Emit an event for the newly added transaction.
	if persistToDb && !mp.inMemoryOnly {
		event := &MempoolEvent{
			Txn:  txn,
			Type: MempoolEventAdd,
		}
		mp.persister.EnqueueEvent(event)
	}
}

func (mp *PosMempool) addTransactionNoLock(txn *MempoolTx, persistToDb bool) error {
	userPk := NewPublicKey(txn.Tx.PublicKey)

	// Special handling for atomic txns. For atomic txns, the mempool will ignore the nonce for the wrapper txn
	// and only track nonces for the inner txns. Additionally, only the wrapper txn will be added to the transaction
	// register.
	//
	// TODO: We should allow replace-by-fee for atomic txns. To accomplish this, we can compute a "derived nonce"
	// for the atomic txn that has {lowest block height, hash(inner txn partial ids)) as its nonce. This would
	// allow one to replace an atomic txn with a new one paying a higher fee as long as they keep the nonces of
	// the inner txns the same.
	if txn.Tx.TxnMeta.GetTxnType() == TxnTypeAtomicTxnsWrapper {
		// If the txn is an atomic txn, we need to add each txn individually.
		atomicTxnsWrapper, ok := txn.Tx.TxnMeta.(*AtomicTxnsWrapperMetadata)
		if !ok {
			return fmt.Errorf(
				"PosMempool.AddTransaction: Problem adding atomic txn - casting metadata failed")
		}
		var innerMempoolTxs []*MempoolTx
		for _, innerTxn := range atomicTxnsWrapper.Txns {
			newInnerMempoolTx, err := NewMempoolTx(innerTxn, txn.Added, uint64(txn.Height))
			if err != nil {
				return errors.Wrapf(err, "PosMempool.AddTransaction: Problem creating MempoolTx from inner atomic txn")
			}
			innerMempoolTxs = append(innerMempoolTxs, newInnerMempoolTx)
		}
		// We need to track the inners txns for which we've added nonces in the event that
		// we need to remove them. We don't want to remove nonces for txns that were never added
		// as it is possible the nonce tracker returned an error because the nonce is already used
		// and removing it would effectively remove a different transaction from the nonce tracker.
		var innerTxnsWithNoncesAdded []*MsgDeSoTxn
		for _, innerMempoolTx := range innerMempoolTxs {
			innerUserPk := NewPublicKey(innerMempoolTx.Tx.PublicKey)
			if _, err := mp.checkNonceTracker(innerMempoolTx, innerUserPk); err != nil {
				// if we hit an error, we need to remove all the nonces from the nonce tracker.
				mp.removeNonces(innerTxnsWithNoncesAdded)
				return errors.Wrapf(err, "PosMempool.AddTransaction: Problem checking nonce tracker")
			}
			// At this point the transaction is in the mempool. We can now update the nonce tracker.
			mp.nonceTracker.AddTxnByPublicKeyNonce(txn, *userPk, *txn.Tx.TxnNonce)
			innerTxnsWithNoncesAdded = append(innerTxnsWithNoncesAdded, innerMempoolTx.Tx)
		}
		// Only add the wrapper transaction to the transaction register.
		if err := mp.txnRegister.AddTransaction(txn); err != nil {
			// If we failed to add the transaction to the txn register, we need to remove the inner txns'
			// nonces from the nonce tracker.
			mp.removeNonces(innerTxnsWithNoncesAdded)
			return errors.Wrapf(err, "PosMempool.addTransactionNoLock: Problem adding txn to register")
		}
		// Emit a persist event only for the wrapper transaction.
		mp.persistMempoolAddEvent(txn, persistToDb)
		return nil
	}

	// Get the existing txn and check that the incoming txn can replace it (if applicable).
	existingTxn, err := mp.checkNonceTracker(txn, userPk)
	if err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem checking nonce tracker")
	}

	// We can now add the transaction to the mempool.
	if err = mp.txnRegister.AddTransaction(txn); err != nil {
		return errors.Wrapf(err, "PosMempool.addTransactionNoLock: Problem adding txn to register")
	}

	// If we've determined that this transaction is meant to replace an existing one, we remove the existing transaction now.
	if existingTxn != nil {
		if err = mp.removeTransactionNoLock(existingTxn, true); err != nil {
			recoveryErr := mp.txnRegister.RemoveTransaction(txn)
			return errors.Wrapf(err, "PosMempool.AddTransaction: Problem removing old transaction from mempool during "+
				"replacement with higher fee. Recovery error: %v", recoveryErr)
		}
	}

	// At this point the transaction is in the mempool. We can now update the nonce tracker.
	mp.nonceTracker.AddTxnByPublicKeyNonce(txn, *userPk, *txn.Tx.TxnNonce)

	// Emit an event for the newly added transaction.
	mp.persistMempoolAddEvent(txn, persistToDb)

	return nil
}

// loadPersistedTransactions fetches transactions from the persister's storage and adds the transactions to the mempool.
// No lock is held and (persistToDb = false) flag is used when adding transactions internally.
func (mp *PosMempool) loadPersistedTransactions() error {
	if mp.inMemoryOnly {
		return nil
	}

	txns, err := mp.persister.GetPersistedTransactions()
	if err != nil {
		return errors.Wrapf(err, "PosMempool.Start: Problem retrieving transactions from persister")
	}
	// We set the persistToDb flag to false so that persister doesn't try to save the transactions.
	for _, txn := range txns {
		if err := mp.addTransactionNoLock(txn, false); err != nil {
			glog.Errorf("PosMempool.Start: Problem adding transaction with hash (%v) from persister: %v",
				txn.Hash, err)
		}
	}
	return nil
}

// RemoveTransaction is the main function for removing a transaction from the mempool.
func (mp *PosMempool) RemoveTransaction(txnHash *BlockHash) error {
	mp.Lock()
	defer mp.Unlock()

	if !mp.IsRunning() {
		return errors.Wrapf(MempoolErrorNotRunning, "PosMempool.RemoveTransaction: ")
	}

	// Get the transaction from the register.
	txn := mp.txnRegister.GetTransaction(txnHash)
	if txn == nil {
		return nil
	}

	return mp.removeTransactionNoLock(txn, true)
}

func (mp *PosMempool) removeTransaction(txn *MempoolTx, persistToDb bool) error {
	mp.Lock()
	defer mp.Unlock()

	return mp.removeTransactionNoLock(txn, persistToDb)
}

func (mp *PosMempool) removeTransactionNoLock(txn *MempoolTx, persistToDb bool) error {
	// First, sanity check our reserved balance.
	userPk := NewPublicKey(txn.Tx.PublicKey)

	// Remove the transaction from the register.
	if err := mp.txnRegister.RemoveTransaction(txn); err != nil {
		return errors.Wrapf(err, "PosMempool.removeTransactionNoLock: Problem removing txn from register")
	}

	if txn.Tx.TxnMeta.GetTxnType() == TxnTypeAtomicTxnsWrapper {
		// For atomic transactions, we remove the nonces of the inner txns, but not the wrapper txn.
		atomicTxnsWrapper, ok := txn.Tx.TxnMeta.(*AtomicTxnsWrapperMetadata)
		if !ok {
			return fmt.Errorf(
				"PosMempool.RemoveTransaction: Problem removing atomic txn - casting metadata failed")
		}
		// Remove nonces for all inner txns.
		mp.removeNonces(atomicTxnsWrapper.Txns)
	} else {
		// For non-atomic transactions, we just remove the nonce from the nonce tracker.
		// Remove the transaction from the nonce tracker.
		mp.nonceTracker.RemoveTxnByPublicKeyNonce(*userPk, *txn.Tx.TxnNonce)
	}

	// Emit an event for the removed transaction.
	if persistToDb && !mp.inMemoryOnly {
		event := &MempoolEvent{
			Txn:  txn,
			Type: MempoolEventRemove,
		}
		mp.persister.EnqueueEvent(event)
	}

	return nil
}

// GetTransaction returns the transaction with the given hash if it exists in the mempool. This function is thread-safe.
func (mp *PosMempool) GetTransaction(txnHash *BlockHash) *MempoolTx {
	mp.RLock()
	defer mp.RUnlock()

	if !mp.IsRunning() {
		return nil
	}

	txn := mp.txnRegister.GetTransaction(txnHash)
	if txn == nil || txn.Tx == nil {
		return nil
	}

	return txn
}

// GetTransactions returns all transactions in the mempool ordered by the Fee-Time algorithm. This function is thread-safe.
func (mp *PosMempool) GetTransactions() []*MempoolTx {
	mp.RLock()
	defer mp.RUnlock()

	if !mp.IsRunning() {
		return nil
	}

	var mempoolTxns []*MempoolTx
	poolTxns := mp.getTransactionsNoLock()
	for _, txn := range poolTxns {
		if txn == nil || txn.Tx == nil {
			continue
		}

		mempoolTxns = append(mempoolTxns, txn)
	}
	return mempoolTxns
}

func (mp *PosMempool) getTransactionsNoLock() []*MempoolTx {
	return mp.txnRegister.GetFeeTimeTransactions()
}

// validateTransactions updates the validated status of transactions in the mempool. The function connects the Fee-Time ordered
// mempool transactions to the readOnlyLatestBlockView, creating a cumulative validationView. Transactions that fail to
// connect to the validationView are removed from the mempool, as they would have also failed to connect during
// block production. This function is thread-safe.
func (mp *PosMempool) validateTransactions() error {
	if !mp.IsRunning() {
		return nil
	}

	// We hold a read-lock on the mempool to get the transactions and the latest block view.
	mp.RLock()

	// It's fine to create a copy of the pointer to the readOnlyLatestBlockView. Since the
	// utxoView is immutable, we don't need to copy the entire view while we hold the lock.
	validationView := mp.validateTransactionsReadOnlyLatestBlockView
	mempoolTxns := mp.getTransactionsNoLock()
	nextBlockHeight := mp.latestBlockHeight + 1
	nextBlockTimestamp := time.Now().UnixNano()

	mp.RUnlock()

	// If the validation view is nil, there's nothing to do so we return early.
	if validationView == nil {
		return nil
	}

	// Create a SafeUtxoView instance to connect the transactions into.
	safeUtxoView := NewSafeUtxoView(validationView)

	// Iterate through all the transactions in the mempool and connect them to copies of the validation view.
	for ii, txn := range mempoolTxns {
		// Break out if we've attempted to connect the maximum number of txns to the view
		if uint64(ii) >= mp.maxValidationViewConnects {
			break
		}

		// Connect the transaction into the SafeUtxoView. We can skip signatures on the transaction
		// connect if the transaction has already previously been validated and been found to have a valid
		// signature. This optimizes the connect by not repeating signature verification on a transaction
		// more than once.
		_, _, _, _, err := safeUtxoView.ConnectTransaction(
			txn.Tx, txn.Hash, uint32(nextBlockHeight), nextBlockTimestamp, !txn.IsValidated(), false,
		)

		// If the txn fails to connect, then we set its validated status to false and remove it from the
		// mempool. We also mark it as having been rejected so that it can't get re-submitted to the mempool.
		if err != nil {
			// Mark the txn as invalid and add an error to the cache so we can return it to the user if they
			// try to resubmit it.
			txn.SetValidated(false)
			mp.recentRejectedTxnCache.Put(*txn.Hash, err)

			// Try to remove the transaction with a lock.
			mp.removeTransaction(txn, true)

			continue
		}

		// The txn successfully connected. We set its validated status to true.
		txn.SetValidated(true)
	}

	// Get the final UtxoView from the SafeUtxoView.
	validationView = safeUtxoView.GetUtxoView()

	// Update the augmentedLatestBlockView with the latest validationView after the transactions
	// have been connected.
	mp.augmentedReadOnlyLatestBlockViewMutex.Lock()
	mp.augmentedReadOnlyLatestBlockView = validationView
	mp.augmentedReadOnlyLatestBlockViewMutex.Unlock()

	// Increment the augmentedLatestBlockViewSequenceNumber.
	atomic.AddInt64(&mp.augmentedLatestBlockViewSequenceNumber, 1)

	return nil
}

// pruneNoLock removes transactions from the mempool until the mempool size is below the maximum allowed size. The transactions
// are removed in lowest to highest Fee-Time priority, i.e. opposite way that transactions are ordered in
// GetTransactions().
func (mp *PosMempool) pruneNoLock() error {
	if mp.txnRegister.Size() < mp.globalParams.MempoolMaxSizeBytes {
		return nil
	}

	prunedTxns, err := mp.txnRegister.PruneToSize(mp.globalParams.MempoolMaxSizeBytes)
	if err != nil {
		return errors.Wrapf(err, "PosMempool.pruneNoLock: Problem pruning mempool")
	}
	for _, prunedTxn := range prunedTxns {
		if err := mp.removeTransactionNoLock(prunedTxn, true); err != nil {
			// We should never get to here since the transaction was already pruned from the TransactionRegister.
			glog.Errorf("PosMempool.pruneNoLock: Problem removing transaction from mempool: %v", err)
		}
	}
	return nil
}

func (mp *PosMempool) rebucketTransactionRegisterNoLock() error {
	// Check if the global params haven't changed in a way that requires rebucketing the
	// transaction register
	if !mp.txnRegister.HasGlobalParamChange(mp.globalParams) {
		return nil
	}

	// Rebucket the transaction register
	newTxnRegister, err := mp.txnRegister.CopyWithNewGlobalParams(mp.globalParams)
	if err != nil {
		return errors.Wrapf(err, "PosMempool.rebucketTransactionRegisterNoLock: Problem rebucketing transaction register")
	}

	for _, txn := range mp.txnRegister.GetFeeTimeTransactions() {
		txnInNewRegister := newTxnRegister.GetTransaction(txn.Hash)
		if txnInNewRegister == nil {
			mp.removeTransactionNoLock(txn, true)
		}
	}

	// Swap the transaction register with the new transaction register
	mp.txnRegister = newTxnRegister

	// Update the fee estimator's transaction register
	mp.feeEstimator.SetMempoolTransactionRegister(newTxnRegister)

	return nil
}

// UpdateLatestBlock updates the latest block view and latest block node in the mempool.
func (mp *PosMempool) UpdateLatestBlock(blockView *UtxoView, blockHeight uint64) {
	mp.Lock()
	defer mp.Unlock()

	if !mp.IsRunning() {
		return
	}

	if blockView != nil {
		mp.readOnlyLatestBlockView = blockView.CopyUtxoView()
		mp.validateTransactionsReadOnlyLatestBlockView = blockView.CopyUtxoView()
	}
	mp.latestBlockHeight = blockHeight
}

// UpdateGlobalParams updates the global params in the mempool. Changing GlobalParamsEntry can impact the validity of
// transactions in the mempool. For example, if the minimum network fee is increased, transactions with a fee below the
// new minimum will be removed from the mempool. To safely handle this, this method re-creates the TransactionRegister
// with the new global params and re-adds all transactions in the mempool to the new register.
func (mp *PosMempool) UpdateGlobalParams(globalParams *GlobalParamsEntry) {
	// If the global params haven't changed at all, then we don't need to do anything.
	newGlobalParamBytes := globalParams.RawEncodeWithoutMetadata(mp.latestBlockHeight, true)
	mp.RLock()
	mpGlobalParamBytes := mp.globalParams.RawEncodeWithoutMetadata(mp.latestBlockHeight, true)
	mp.RUnlock()
	if bytes.Equal(newGlobalParamBytes, mpGlobalParamBytes) {
		return
	}

	mp.Lock()
	defer mp.Unlock()

	if !mp.IsRunning() {
		return
	}

	mp.globalParams = globalParams

	// Trim the mempool size to the new maximum size.
	if err := mp.pruneNoLock(); err != nil {
		glog.Errorf("PosMempool.UpdateGlobalParams: Problem pruning mempool: %v", err)
		return
	}

	// Update the fee bucketing in the transaction register
	if err := mp.rebucketTransactionRegisterNoLock(); err != nil {
		glog.Errorf("PosMempool.UpdateGlobalParams: Problem rebucketing transaction register: %v", err)
		return
	}

	// Update the fee estimator's global params
	if err := mp.feeEstimator.UpdateGlobalParams(mp.globalParams); err != nil {
		glog.Errorf("PosMempool.UpdateGlobalParams: Problem updating fee estimator global params: %v", err)
		return
	}
}

// Implementation of the Mempool interface
// These functions are used by the backend to interact with the mempool.

func (mp *PosMempool) GetAugmentedUniversalView() (*UtxoView, error) {
	if !mp.IsRunning() {
		return nil, errors.Wrapf(MempoolErrorNotRunning, "PosMempool.GetAugmentedUniversalView: ")
	}
	mp.augmentedReadOnlyLatestBlockViewMutex.RLock()
	readOnlyViewPointer := mp.augmentedReadOnlyLatestBlockView
	mp.augmentedReadOnlyLatestBlockViewMutex.RUnlock()
	newView := readOnlyViewPointer.CopyUtxoView()
	return newView, nil
}

func (mp *PosMempool) GetAugmentedUtxoViewForPublicKey(pk []byte, optionalTx *MsgDeSoTxn) (*UtxoView, error) {
	return mp.GetAugmentedUniversalView()
}

func (mp *PosMempool) BlockUntilReadOnlyViewRegenerated() {
	oldSeqNum := atomic.LoadInt64(&mp.augmentedLatestBlockViewSequenceNumber)
	newSeqNum := oldSeqNum
	// Check fairly often. Not too often.
	checkIntervalMillis := mp.transactionValidationRefreshIntervalMillis / 5
	if checkIntervalMillis == 0 {
		checkIntervalMillis = 1
	}
	for newSeqNum == oldSeqNum {
		time.Sleep(time.Duration(checkIntervalMillis) * time.Millisecond)
		newSeqNum = atomic.LoadInt64(&mp.augmentedLatestBlockViewSequenceNumber)
	}
}

// WaitForTxnValidation blocks until the transaction with the given hash is either validated in the mempool,
// in a recent block, or no longer in the mempool.
func (mp *PosMempool) WaitForTxnValidation(txHash *BlockHash) error {
	// Check fairly often. Not too often.
	checkIntervalMillis := mp.transactionValidationRefreshIntervalMillis / 5
	if checkIntervalMillis == 0 {
		checkIntervalMillis = 1
	}
	for {
		rejectionErr, wasRejected := mp.recentRejectedTxnCache.Get(*txHash)
		if wasRejected {
			return rejectionErr
		}
		mtxn := mp.GetTransaction(txHash)
		if mtxn == nil {
			if mp.isTxnHashInRecentBlockCache(*txHash) {
				return nil
			} else {
				return fmt.Errorf("Txn was never received or it was " +
					"rejected for an unknown reason")
			}
		} else if mtxn.IsValidated() {
			return nil
		}
		// Sleep for a bit and then check again.
		time.Sleep(time.Duration(checkIntervalMillis) * time.Millisecond)
	}
}

func (mp *PosMempool) CheckSpend(op UtxoKey) *MsgDeSoTxn {
	panic("implement me")
}

func (mp *PosMempool) GetOrderedTransactions() []*MempoolTx {
	mp.RLock()
	defer mp.RUnlock()

	if !mp.IsRunning() {
		return nil
	}
	return mp.getTransactionsNoLock()
}

func (mp *PosMempool) IsTransactionInPool(txHash *BlockHash) bool {
	mp.RLock()
	defer mp.RUnlock()
	if !mp.IsRunning() || txHash == nil {
		return false
	}

	_, exists := mp.txnRegister.txnMembership[*txHash]
	return exists
}

func (mp *PosMempool) GetMempoolTipBlockHeight() uint64 {
	mp.RLock()
	defer mp.RUnlock()
	if !mp.IsRunning() {
		return 0
	}
	return mp.latestBlockHeight
}

func (mp *PosMempool) GetMempoolTx(txHash *BlockHash) *MempoolTx {
	mp.RLock()
	defer mp.RUnlock()
	if !mp.IsRunning() || txHash == nil {
		return nil
	}

	return mp.txnRegister.txnMembership[*txHash]
}

func (mp *PosMempool) GetMempoolSummaryStats() map[string]*SummaryStats {
	return convertMempoolTxsToSummaryStats(mp.txnRegister.GetFeeTimeTransactions())
}

func (mp *PosMempool) EstimateFee(txn *MsgDeSoTxn, minFeeRateNanosPerKB uint64) (uint64, error) {
	return mp.feeEstimator.EstimateFee(txn, minFeeRateNanosPerKB)
}

func (mp *PosMempool) EstimateFeeRate(minFeeRateNanosPerKB uint64) uint64 {
	return mp.feeEstimator.EstimateFeeRateNanosPerKB(minFeeRateNanosPerKB)
}
