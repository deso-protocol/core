package lib

import (
	"fmt"
	"github.com/decred/dcrd/lru"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

type PosMempoolStatus int

const (
	PosMempoolStatusNotInitialized PosMempoolStatus = iota
	PosMempoolStatusInitialized
	PosMempoolStatusRunning
)

type Mempool interface {
	Start() error
	Stop()
	IsRunning() bool
	AddTransaction(txn *MempoolTransaction) error
	RemoveTransaction(txnHash *BlockHash) error
	GetTransaction(txnHash *BlockHash) *MempoolTransaction
	GetTransactions() []*MempoolTransaction
	GetIterator() MempoolIterator
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
	EstimateFee(
		txn *MsgDeSoTxn,
		minFeeRateNanosPerKB uint64,
		mempoolCongestionFactorBasisPoints uint64,
		mempoolPriorityPercentileBasisPoints uint64,
		pastBlocksCongestionFactorBasisPoints uint64,
		pastBlocksPriorityPercentileBasisPoints uint64,
		maxBlockSize uint64,
	) (uint64, error)
	EstimateFeeRate(
		minFeeRateNanosPerKB uint64,
		mempoolCongestionFactorBasisPoints uint64,
		mempoolPriorityPercentileBasisPoints uint64,
		pastBlocksCongestionFactorBasisPoints uint64,
		pastBlocksPriorityPercentileBasisPoints uint64,
		maxBlockSize uint64,
	) (uint64, error)
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

type MempoolIterator interface {
	Next() bool
	Value() (*MempoolTransaction, bool)
	Initialized() bool
}

// MempoolTransaction is a simple wrapper around MsgDeSoTxn that adds a timestamp field.
type MempoolTransaction struct {
	*MsgDeSoTxn
	TimestampUnixMicro time.Time
	Validated          bool
}

func NewMempoolTransaction(txn *MsgDeSoTxn, timestamp time.Time, validated bool) *MempoolTransaction {
	return &MempoolTransaction{
		MsgDeSoTxn:         txn,
		TimestampUnixMicro: timestamp,
		Validated:          validated,
	}
}

func (mtxn *MempoolTransaction) GetTxn() *MsgDeSoTxn {
	return mtxn.MsgDeSoTxn
}

func (mtxn *MempoolTransaction) GetTimestamp() time.Time {
	return mtxn.TimestampUnixMicro
}

func (mtxn *MempoolTransaction) IsValidated() bool {
	return mtxn.Validated
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

	// readOnlyLatestBlockView is used to check if a transaction is valid before being added to the mempool. The readOnlyLatestBlockView
	// checks if the transaction has a valid signature and if the transaction's sender has enough funds to cover the fee.
	// The readOnlyLatestBlockView should be updated whenever a new block is added to the blockchain via UpdateLatestBlock.
	// PosMempool only needs read-access to the block view. It isn't necessary to copy the block view before passing it
	// to the mempool.
	readOnlyLatestBlockView *UtxoView
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
	// maxMempoolPosSizeBytes is the maximum aggregate number of bytes of transactions included in the PoS mempool.
	maxMempoolPosSizeBytes uint64
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
	recentBlockTxnCache lru.KVCache

	// recentRejectedTxnCache is a cache to store the txns that were recently rejected so that we can return better
	// errors for them.
	recentRejectedTxnCache lru.KVCache
}

// PosMempoolIterator is a wrapper around FeeTimeIterator, modified to return MsgDeSoTxn instead of MempoolTx.
type PosMempoolIterator struct {
	it *FeeTimeIterator
}

func (it *PosMempoolIterator) Next() bool {
	return it.it.Next()
}

func (it *PosMempoolIterator) Value() (*MempoolTransaction, bool) {
	txn, ok := it.it.Value()
	if txn == nil || txn.Tx == nil {
		return nil, ok
	}
	return NewMempoolTransaction(txn.Tx, txn.Added, txn.IsValidated()), ok
}

func (it *PosMempoolIterator) Initialized() bool {
	return it.it.Initialized()
}

func NewPosMempoolIterator(it *FeeTimeIterator) *PosMempoolIterator {
	return &PosMempoolIterator{it: it}
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
	maxMempoolPosSizeBytes uint64,
	mempoolBackupIntervalMillis uint64,
	feeEstimatorNumMempoolBlocks uint64,
	feeEstimatorPastBlocks []*MsgDeSoBlock,
	feeEstimatorNumPastBlocks uint64,
	maxValidationViewConnects uint64,
	transactionValidationRefreshIntervalMillis uint64,
) error {
	if mp.status != PosMempoolStatusNotInitialized {
		return errors.New("PosMempool.Init: PosMempool already initialized")
	}

	// Initialize the parametrized fields.
	mp.params = params
	mp.globalParams = globalParams
	mp.readOnlyLatestBlockView = readOnlyLatestBlockView
	var err error
	if readOnlyLatestBlockView != nil {
		mp.augmentedReadOnlyLatestBlockView, err = readOnlyLatestBlockView.CopyUtxoView()
		if err != nil {
			return errors.Wrapf(err, "PosMempool.Init: Problem copying utxo view")
		}
	}
	mp.latestBlockHeight = latestBlockHeight
	mp.dir = dir
	mp.inMemoryOnly = inMemoryOnly
	mp.maxMempoolPosSizeBytes = maxMempoolPosSizeBytes
	mp.mempoolBackupIntervalMillis = mempoolBackupIntervalMillis
	mp.maxValidationViewConnects = maxValidationViewConnects
	mp.transactionValidationRefreshIntervalMillis = transactionValidationRefreshIntervalMillis
	mp.recentBlockTxnCache = lru.NewKVCache(100000)    // cache 100K latest txns from blocks.
	mp.recentRejectedTxnCache = lru.NewKVCache(100000) // cache 100K rejected txns.

	// TODO: parameterize num blocks. Also, how to pass in blocks.
	err = mp.feeEstimator.Init(
		mp.txnRegister,
		feeEstimatorNumMempoolBlocks,
		feeEstimatorPastBlocks,
		feeEstimatorNumPastBlocks,
		mp.globalParams,
	)
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

	// Create the transaction register, the ledger, and the nonce tracker,
	mp.txnRegister = NewTransactionRegister()
	mp.txnRegister.Init(mp.globalParams)
	mp.nonceTracker = NewNonceTracker()

	// Setup the database and create the persister
	if !mp.inMemoryOnly {
		mempoolDirectory := filepath.Join(mp.dir, "mempool")
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

	if err := mp.refreshNoLock(); err != nil {
		glog.Errorf("PosMempool.OnBlockConnected: Problem refreshing mempool: %v", err)
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

	mp.refreshNoLock()

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
// If the mempool overflows as a result of adding the transaction, the mempool is pruned. The
// transaction signature verification can be skipped if verifySignature is passed as true.
func (mp *PosMempool) AddTransaction(mtxn *MempoolTransaction) error {
	if mtxn == nil || mtxn.GetTxn() == nil {
		return fmt.Errorf("PosMempool.AddTransaction: Cannot add a nil transaction")
	}

	// Acquire the mempool lock for all operations related to adding the transaction
	// TODO: Do we need to wrap all of our validation logic in a write-lock? We should revisit
	// this later and try to pull as much as we can out of the critical section here.
	mp.Lock()
	defer mp.Unlock()

	// First, validate that the transaction is properly formatted according to BalanceModel. We acquire a read lock on
	// the mempool. This allows multiple goroutines to safely perform transaction validation concurrently. In particular,
	// transaction signature verification can be parallelized.
	if err := mp.checkTransactionSanity(mtxn.GetTxn(), false); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem verifying transaction")
	}

	// If we get this far, it means that the transaction is valid. We can now add it to the mempool.
	if !mp.IsRunning() {
		return errors.Wrapf(MempoolErrorNotRunning, "PosMempool.AddTransaction: ")
	}

	// Construct the MempoolTx from the MsgDeSoTxn.
	mempoolTx, err := NewMempoolTx(mtxn.GetTxn(), mtxn.GetTimestamp(), mp.latestBlockHeight)
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
	mp.recentBlockTxnCache.Add(txnHash, nil)
}

func (mp *PosMempool) deleteTxnHashFromRecentBlockCache(txnHash BlockHash) {
	mp.recentBlockTxnCache.Delete(txnHash)
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

// updateTransactionValidatedStatus updates the validated status of a mempool transaction with the provided txnHash.
func (mp *PosMempool) updateTransactionValidatedStatus(txnHash *BlockHash, validated bool) {
	mp.Lock()
	defer mp.Unlock()

	if !mp.IsRunning() || txnHash == nil {
		return
	}

	txn := mp.txnRegister.GetTransaction(txnHash)
	if txn == nil {
		return
	}

	txn.SetValidated(validated)
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
func (mp *PosMempool) GetTransaction(txnHash *BlockHash) *MempoolTransaction {
	mp.RLock()
	defer mp.RUnlock()

	if !mp.IsRunning() {
		return nil
	}

	txn := mp.txnRegister.GetTransaction(txnHash)
	if txn == nil || txn.Tx == nil {
		return nil
	}

	return NewMempoolTransaction(txn.Tx, txn.Added, txn.IsValidated())
}

// GetTransactions returns all transactions in the mempool ordered by the Fee-Time algorithm. This function is thread-safe.
func (mp *PosMempool) GetTransactions() []*MempoolTransaction {
	mp.RLock()
	defer mp.RUnlock()

	if !mp.IsRunning() {
		return nil
	}

	var mempoolTxns []*MempoolTransaction
	poolTxns := mp.getTransactionsNoLock()
	for _, txn := range poolTxns {
		if txn == nil || txn.Tx == nil {
			continue
		}

		mtxn := NewMempoolTransaction(txn.Tx, txn.Added, txn.IsValidated())
		mempoolTxns = append(mempoolTxns, mtxn)
	}
	return mempoolTxns
}

func (mp *PosMempool) getTransactionsNoLock() []*MempoolTx {
	return mp.txnRegister.GetFeeTimeTransactions()
}

// GetIterator returns an iterator for the mempool transactions. The iterator can be used to peek transactions in the
// mempool ordered by the Fee-Time algorithm. Transactions can be fetched with the following pattern:
//
//	for it.Next() {
//		if txn, ok := it.Value(); ok {
//			// Do something with txn.
//		}
//	}
//
// Note that the iteration pattern is not thread-safe. Another lock should be used to ensure thread-safety.
func (mp *PosMempool) GetIterator() MempoolIterator {
	mp.RLock()
	defer mp.RUnlock()

	if !mp.IsRunning() {
		return nil
	}

	return NewPosMempoolIterator(mp.txnRegister.GetFeeTimeIterator())
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
	// We copy the reference to the readOnlyLatestBlockView. Since the utxoView is immutable, we don't need to copy the
	// entire view while we hold the lock.
	// We hold a read-lock on the mempool to get the transactions and the latest block view.
	validationView := mp.readOnlyLatestBlockView
	mempoolTxns := mp.getTransactionsNoLock()
	mp.RUnlock()

	// If the validation view is nil, there's nothing to do so we return early.
	if validationView == nil {
		return nil
	}

	// Convert the mempool transactions to the MsgDeSoTxn format, which we can use for connecting to the validation view.
	var txns []*MsgDeSoTxn
	var txHashes []*BlockHash
	for _, txn := range mempoolTxns {
		txns = append(txns, txn.Tx)
		txHashes = append(txHashes, txn.Hash)
	}
	// Copy the validation view to avoid modifying the readOnlyLatestBlockView.
	copyValidationView, err := validationView.CopyUtxoView()
	if err != nil {
		return errors.Wrapf(err, "PosMempool.validateTransactions: Problem copying utxo view")
	}
	// Connect the transactions to the validation view. We use the latest block height + 1 as the block height to connect
	// the transactions. This is because the mempool contains transactions that we use for producing the next block.
	_, _, _, _, errorsFound, err := copyValidationView.ConnectTransactionsFailSafeWithLimit(
		txns, txHashes, uint32(mp.latestBlockHeight)+1,
		time.Now().UnixNano(), true, false, true, mp.maxValidationViewConnects)
	if err != nil {
		return errors.Wrapf(err, "PosMempool.validateTransactions: Problem connecting transactions")
	}

	// We iterate through the successFlags and update the validated status of the transactions in the mempool.
	var txnsToRemove []*MempoolTx
	for ii, errFound := range errorsFound {
		if ii >= len(mempoolTxns) {
			break
		}
		// If the transaction successfully connected to the validation view, we update the validated status of the
		// transaction in the mempool. If the transaction failed to connect to the validation view, we add it to the
		// txnsToRemove list. Note that we don't need to hold a lock while updating the validated status of the
		// transactions in the mempool, since the updateTransactionValidatedStatus already holds the lock.
		if errFound == nil {
			mp.updateTransactionValidatedStatus(mempoolTxns[ii].Hash, true)
		} else {
			txnsToRemove = append(txnsToRemove, mempoolTxns[ii])
			// Add an error for the txn to our cache so we can return it to the user if they
			// ask for it later.
			mp.recentRejectedTxnCache.Add(*mempoolTxns[ii].Hash, errFound)
		}
	}

	// Now remove all transactions from the txnsToRemove list from the main mempool.
	mp.Lock()
	for _, txn := range txnsToRemove {
		if err := mp.removeTransactionNoLock(txn, true); err != nil {
			glog.Errorf("PosMempool.validateTransactions: Problem removing transaction with hash (%v): %v", txn.Hash, err)
		}
	}
	mp.Unlock()
	// We also update the augmentedLatestBlockView with the view after the transactions have been connected.
	mp.augmentedReadOnlyLatestBlockViewMutex.Lock()
	mp.augmentedReadOnlyLatestBlockView = copyValidationView
	mp.augmentedReadOnlyLatestBlockViewMutex.Unlock()
	// Increment the augmentedLatestBlockViewSequenceNumber.
	atomic.AddInt64(&mp.augmentedLatestBlockViewSequenceNumber, 1)

	// Log the hashes for transactions that were removed.
	if len(txnsToRemove) > 0 {
		var removedTxnHashes []string
		for _, txn := range txnsToRemove {
			removedTxnHashes = append(removedTxnHashes, txn.Hash.String())
		}
		glog.V(1).Infof("PosMempool.validateTransactions: Transactions with the following hashes were removed: %v",
			strings.Join(removedTxnHashes, ","))
	}
	return nil
}

// refreshNoLock can be used to evict stale transactions from the mempool. However, it is a bit expensive and should be used
// sparingly. Upon being called, refreshNoLock will create an in-memory temp PosMempool and populate it with transactions from
// the main mempool. The temp mempool will have the most up-to-date readOnlyLatestBlockView, Height, and globalParams. Any
// transaction that fails to add to the temp mempool will be removed from the main mempool.
func (mp *PosMempool) refreshNoLock() error {
	// Create the temporary in-memory mempool with the most up-to-date readOnlyLatestBlockView, Height, and globalParams.
	tempPool := NewPosMempool()
	err := tempPool.Init(
		mp.params,
		mp.globalParams,
		mp.readOnlyLatestBlockView,
		mp.latestBlockHeight,
		"",
		true,
		mp.maxMempoolPosSizeBytes,
		mp.mempoolBackupIntervalMillis,
		mp.feeEstimator.numMempoolBlocks,
		mp.feeEstimator.cachedBlocks,
		mp.feeEstimator.numPastBlocks,
		mp.maxValidationViewConnects,
		mp.transactionValidationRefreshIntervalMillis,
	)
	if err != nil {
		return errors.Wrapf(err, "PosMempool.refreshNoLock: Problem initializing temp pool")
	}
	if err := tempPool.Start(); err != nil {
		return errors.Wrapf(err, "PosMempool.refreshNoLock: Problem starting temp pool")
	}
	defer tempPool.Stop()

	// Add all transactions from the main mempool to the temp mempool. Skip signature verification.
	var txnsToRemove []*MempoolTx
	txns := mp.getTransactionsNoLock()
	for _, txn := range txns {
		mtxn := NewMempoolTransaction(txn.Tx, txn.Added, txn.IsValidated())
		err := tempPool.AddTransaction(mtxn)
		if err == nil {
			continue
		}

		// If we've encountered an error while adding the transaction to the temp mempool, we add it to our txnsToRemove list.
		txnsToRemove = append(txnsToRemove, txn)
	}

	// Now remove all transactions from the txnsToRemove list from the main mempool.
	for _, txn := range txnsToRemove {
		if err := mp.removeTransactionNoLock(txn, true); err != nil {
			glog.Errorf("PosMempool.refreshNoLock: Problem removing transaction with hash (%v): %v", txn.Hash, err)
		}
	}

	// Log the hashes for transactions that were removed.
	if len(txnsToRemove) > 0 {
		var removedTxnHashes []string
		for _, txn := range txnsToRemove {
			removedTxnHashes = append(removedTxnHashes, txn.Hash.String())
		}
		glog.V(1).Infof("PosMempool.refreshNoLock: Transactions with the following hashes were removed: %v",
			strings.Join(removedTxnHashes, ","))
	}
	return nil
}

// pruneNoLock removes transactions from the mempool until the mempool size is below the maximum allowed size. The transactions
// are removed in lowest to highest Fee-Time priority, i.e. opposite way that transactions are ordered in
// GetTransactions().
func (mp *PosMempool) pruneNoLock() error {
	if mp.txnRegister.Size() < mp.maxMempoolPosSizeBytes {
		return nil
	}

	prunedTxns, err := mp.txnRegister.PruneToSize(mp.maxMempoolPosSizeBytes)
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

// UpdateLatestBlock updates the latest block view and latest block node in the mempool.
func (mp *PosMempool) UpdateLatestBlock(blockView *UtxoView, blockHeight uint64) {
	mp.Lock()
	defer mp.Unlock()

	if !mp.IsRunning() {
		return
	}

	mp.readOnlyLatestBlockView = blockView
	mp.latestBlockHeight = blockHeight
}

// UpdateGlobalParams updates the global params in the mempool. Changing GlobalParamsEntry can impact the validity of
// transactions in the mempool. For example, if the minimum network fee is increased, transactions with a fee below the
// new minimum will be removed from the mempool. To safely handle this, this method re-creates the TransactionRegister
// with the new global params and re-adds all transactions in the mempool to the new register.
func (mp *PosMempool) UpdateGlobalParams(globalParams *GlobalParamsEntry) {
	mp.Lock()
	defer mp.Unlock()

	if !mp.IsRunning() {
		return
	}

	mp.globalParams = globalParams
	if err := mp.refreshNoLock(); err != nil {
		glog.Errorf("PosMempool.UpdateGlobalParams: Problem refreshing mempool: %v", err)
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
	newView, err := readOnlyViewPointer.CopyUtxoView()
	if err != nil {
		return nil, errors.Wrapf(err, "PosMempool.GetAugmentedUniversalView: Problem copying utxo view")
	}
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
		rejectionErr, wasRejected := mp.recentRejectedTxnCache.Lookup(*txHash)
		if wasRejected {
			return rejectionErr.(error)
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

func (mp *PosMempool) EstimateFee(
	txn *MsgDeSoTxn,
	minFeeRateNanosPerKB uint64,
	mempoolCongestionFactorBasisPoints uint64,
	mempoolPriorityPercentileBasisPoints uint64,
	pastBlocksCongestionFactorBasisPoints uint64,
	pastBlocksPriorityPercentileBasisPoints uint64,
	maxBlockSize uint64,
) (uint64, error) {
	return mp.feeEstimator.EstimateFee(
		txn, minFeeRateNanosPerKB, mempoolCongestionFactorBasisPoints, mempoolPriorityPercentileBasisPoints,
		pastBlocksCongestionFactorBasisPoints, pastBlocksPriorityPercentileBasisPoints, maxBlockSize)
}

func (mp *PosMempool) EstimateFeeRate(
	minFeeRateNanosPerKB uint64,
	mempoolCongestionFactorBasisPoints uint64,
	mempoolPriorityPercentileBasisPoints uint64,
	pastBlocksCongestionFactorBasisPoints uint64,
	pastBlocksPriorityPercentileBasisPoints uint64,
	maxBlockSize uint64) (uint64, error) {
	return mp.feeEstimator.EstimateFeeRateNanosPerKB(
		minFeeRateNanosPerKB, mempoolCongestionFactorBasisPoints, mempoolPriorityPercentileBasisPoints,
		pastBlocksCongestionFactorBasisPoints, pastBlocksPriorityPercentileBasisPoints, maxBlockSize)
}
