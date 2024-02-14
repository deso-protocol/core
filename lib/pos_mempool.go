package lib

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/badger/v3"
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
	AddTransaction(txn *MempoolTransaction, verifySignature bool) error
	RemoveTransaction(txnHash *BlockHash) error
	GetTransaction(txnHash *BlockHash) *MempoolTransaction
	GetTransactions() []*MempoolTransaction
	GetIterator() MempoolIterator
	Refresh() error
	UpdateLatestBlock(blockView *UtxoView, blockHeight uint64)
	UpdateGlobalParams(globalParams *GlobalParamsEntry)

	GetAugmentedUniversalView() (*UtxoView, error)
	GetAugmentedUtxoViewForPublicKey(pk []byte, optionalTx *MsgDeSoTxn) (*UtxoView, error)
	BlockUntilReadOnlyViewRegenerated()
	CheckSpend(op UtxoKey) *MsgDeSoTxn
	GetOrderedTransactions() []*MempoolTx
	IsTransactionInPool(txHash *BlockHash) bool
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
}

type MempoolIterator interface {
	Next() bool
	Value() (*MempoolTransaction, bool)
	Initialized() bool
}

// MempoolTransaction is a simple wrapper around MsgDeSoTxn that adds a timestamp field.
type MempoolTransaction struct {
	*MsgDeSoTxn
	TimestampUnixMicro uint64
}

func NewMempoolTransaction(txn *MsgDeSoTxn, timestampUnixMicro uint64) *MempoolTransaction {
	return &MempoolTransaction{
		MsgDeSoTxn:         txn,
		TimestampUnixMicro: timestampUnixMicro,
	}
}

func (mtxn *MempoolTransaction) GetTxn() *MsgDeSoTxn {
	return mtxn.MsgDeSoTxn
}

func (mtxn *MempoolTransaction) GetTimestampUnixMicro() uint64 {
	return mtxn.TimestampUnixMicro
}

// PosMempool is used by the node to keep track of uncommitted transactions. The main responsibilities of the PosMempool
// include addition/removal of transactions, back up of transaction to database, and retrieval of transactions ordered
// by Fee-Time algorithm. More on the Fee-Time algorithm can be found in the documentation of TransactionRegister.
type PosMempool struct {
	sync.RWMutex
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
	// ledger is a simple data structure that keeps track of cumulative transaction fees in the mempool.
	// The ledger keeps track of how much each user would have spent in fees across all their transactions in the mempool.
	ledger *BalanceLedger
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
	// mempoolBackupIntervalMillis is the frequency with which pos mempool persists transactions to storage.
	mempoolBackupIntervalMillis uint64

	// feeEstimator is used to estimate the fee required for a transaction to be included in the next block
	// based off the current state of the mempool and the most n recent blocks.
	feeEstimator *PoSFeeEstimator

	// augmentedBlockViewRefreshIntervalMillis is the frequency with which the augmentedLatestBlockView is updated.
	augmentedBlockViewRefreshIntervalMillis uint64

	// augmentedLatestBlockViewSequenceNumber is the sequence number of the readOnlyLatestBlockView. It is incremented
	// every time augmentedLatestBlockView is updated. It can be used by obtainers of the augmentedLatestBlockView to
	// wait until a particular transaction has been connected.
	augmentedLatestBlockViewSequenceNumber int64
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
	added := uint64(txn.Added.UnixMicro())
	return NewMempoolTransaction(txn.Tx, added), ok
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
		ledger:       NewBalanceLedger(),
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
	augmentedBlockViewRefreshIntervalMillis uint64,
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
	mp.mempoolBackupIntervalMillis = mempoolBackupIntervalMillis
	mp.augmentedBlockViewRefreshIntervalMillis = augmentedBlockViewRefreshIntervalMillis

	err = mp.feeEstimator.Init(
		mp.txnRegister,
		globalParams.MempoolFeeEstimatorNumMempoolBlocks,
		feeEstimatorPastBlocks,
		globalParams.MempoolFeeEstimatorNumPastBlocks,
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
	mp.ledger = NewBalanceLedger()
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
	mp.startAugmentedViewRefreshRoutine()

	mp.status = PosMempoolStatusRunning
	return nil
}

func (mp *PosMempool) startAugmentedViewRefreshRoutine() {
	go func() {
		for {
			select {
			case <-time.After(time.Duration(mp.augmentedBlockViewRefreshIntervalMillis) * time.Millisecond):
				// If we're not within 10 blocks of the PoS cutover, we don't need to update the
				// augmentedLatestBlockView.
				if mp.latestBlockHeight+10 < uint64(mp.params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight) {
					continue
				}
				// Update the augmentedLatestBlockView with the latest block view.
				mp.RLock()
				readOnlyViewPointer := mp.readOnlyLatestBlockView
				mp.RUnlock()
				newView, err := readOnlyViewPointer.CopyUtxoView()
				if err != nil {
					glog.Errorf("PosMempool.startAugmentedViewRefreshRoutine: Problem copying utxo view outer: %v", err)
					continue
				}
				for _, txn := range mp.GetTransactions() {
					copiedView, err := newView.CopyUtxoView()
					if err != nil {
						glog.Errorf("PosMempool.startAugmentedViewRefreshRoutine: Problem copying utxo view: %v", err)
						continue
					}
					_, _, _, _, err = copiedView.ConnectTransaction(
						txn.GetTxn(), txn.Hash(), uint32(mp.latestBlockHeight)+1, time.Now().UnixNano(), false,
						false)
					// If the transaction successfully connects, we set the newView to the copiedView
					// and proceed to the next transaction.
					if err == nil {
						newView = copiedView
						continue
					}
					// If the transaction failed to connect, we connect the transaction as a failed txn
					// directly on newView.
					if mp.params.IsPoSBlockHeight(mp.latestBlockHeight + 1) {
						// Copy the view again in case we hit an error.
						copiedView, err = newView.CopyUtxoView()
						if err != nil {
							glog.Errorf("PosMempool.startAugmentedViewRefreshRoutine: Problem copying utxo view inner: %v", err)
							continue
						}
						// Try to connect as failing txn directly to newView
						_, _, _, err = copiedView._connectFailingTransaction(
							txn.GetTxn(), uint32(mp.latestBlockHeight+1), false)
						if err != nil {
							glog.Errorf(
								"PosMempool.startAugmentedViewRefreshRoutine: Problem connecting transaction: %v", err)
							continue
						}
						newView = copiedView
					}
				}
				// Grab the augmentedLatestBlockViewMutex write lock and update the augmentedLatestBlockView.
				mp.augmentedReadOnlyLatestBlockViewMutex.Lock()
				mp.augmentedReadOnlyLatestBlockView = newView
				mp.augmentedReadOnlyLatestBlockViewMutex.Unlock()
				// Increment the augmentedLatestBlockViewSequenceNumber.
				atomic.AddInt64(&mp.augmentedLatestBlockViewSequenceNumber, 1)
			case <-mp.quit:
				return
			}
		}
	}()
}

func (mp *PosMempool) Stop() {
	mp.Lock()
	defer mp.Unlock()

	if !mp.IsRunning() {
		return
	}

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
	mp.ledger.Reset()
	mp.nonceTracker.Reset()
	mp.feeEstimator = NewPoSFeeEstimator()
	close(mp.quit)
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

		mp.removeTransactionNoLock(existingTxn, true)
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

	// Remove all transactions in the block from the mempool.
	for _, txn := range block.Txns {
		txnHash := txn.Hash()

		// This should never happen. We perform a nil check on the txn hash to avoid a panic.
		if txnHash == nil {
			continue
		}

		// Add all transactions in the block to the mempool.

		// Construct the MempoolTx from the MsgDeSoTxn.
		mempoolTx, err := NewMempoolTx(txn, NanoSecondsToUint64MicroSeconds(block.Header.TstampNanoSecs), mp.latestBlockHeight)
		if err != nil {
			continue
		}

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
// If the mempool overflows as a result of adding the transaction, the mempool is pruned. The
// transaction signature verification can be skipped if verifySignature is passed as true.
func (mp *PosMempool) AddTransaction(mtxn *MempoolTransaction, verifySignature bool) error {
	if mtxn == nil || mtxn.GetTxn() == nil {
		return fmt.Errorf("PosMempool.AddTransaction: Cannot add a nil transaction")
	}

	// First, validate that the transaction is properly formatted according to BalanceModel. We acquire a read lock on
	// the mempool. This allows multiple goroutines to safely perform transaction validation concurrently. In particular,
	// transaction signature verification can be parallelized.
	if err := mp.validateTransaction(mtxn.GetTxn(), verifySignature); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem verifying transaction")
	}

	// If we get this far, it means that the transaction is valid. We can now add it to the mempool.
	// We lock the mempool to ensure that no other thread is modifying it while we add the transaction.
	mp.Lock()
	defer mp.Unlock()

	if !mp.IsRunning() {
		return errors.Wrapf(MempoolErrorNotRunning, "PosMempool.AddTransaction: ")
	}

	// Construct the MempoolTx from the MsgDeSoTxn.
	mempoolTx, err := NewMempoolTx(mtxn.GetTxn(), mtxn.GetTimestampUnixMicro(), mp.latestBlockHeight)
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

func (mp *PosMempool) validateTransaction(txn *MsgDeSoTxn, verifySignature bool) error {
	mp.RLock()
	defer mp.RUnlock()

	if err := CheckTransactionSanity(txn, uint32(mp.latestBlockHeight), mp.params); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem validating transaction sanity")
	}

	if err := ValidateDeSoTxnSanityBalanceModel(txn, mp.latestBlockHeight, mp.params, mp.globalParams); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem validating transaction sanity")
	}

	if err := mp.readOnlyLatestBlockView.ValidateTransactionNonce(txn, mp.latestBlockHeight); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem validating transaction nonce")
	}

	if !verifySignature {
		return nil
	}

	// Check transaction signature.
	if _, err := mp.readOnlyLatestBlockView.VerifySignature(txn, uint32(mp.latestBlockHeight)); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Signature validation failed")
	}

	return nil
}

func (mp *PosMempool) addTransactionNoLock(txn *MempoolTx, persistToDb bool) error {
	userPk := NewPublicKey(txn.Tx.PublicKey)
	txnFee := txn.Tx.TxnFeeNanos

	// Validate that the user has enough balance to cover the transaction fees.
	spendableBalanceNanos, err := mp.readOnlyLatestBlockView.GetSpendableDeSoBalanceNanosForPublicKey(userPk.ToBytes(),
		uint32(mp.latestBlockHeight))
	if err != nil {
		return errors.Wrapf(err, "PosMempool.addTransactionNoLock: Problem getting spendable balance")
	}
	if err := mp.ledger.CanIncreaseEntryWithLimit(*userPk, txnFee, spendableBalanceNanos); err != nil {
		return errors.Wrapf(err, "PosMempool.addTransactionNoLock: Problem checking balance increase for transaction with"+
			"hash %v, fee %v", txn.Tx.Hash(), txnFee)
	}

	// Check the nonceTracker to see if this transaction is meant to replace an existing one.
	existingTxn := mp.nonceTracker.GetTxnByPublicKeyNonce(*userPk, *txn.Tx.TxnNonce)
	if existingTxn != nil && existingTxn.FeePerKB > txn.FeePerKB {
		return errors.Wrapf(MempoolFailedReplaceByHigherFee, "PosMempool.AddTransaction: Problem replacing transaction "+
			"by higher fee failed. New transaction has lower fee.")
	}

	// If we get here, it means that the transaction's sender has enough balance to cover transaction fees. Moreover, if
	// this transaction is meant to replace an existing one, at this point we know the new txn has a sufficient fee to
	// do so. We can now add the transaction to mempool.
	if err := mp.txnRegister.AddTransaction(txn); err != nil {
		return errors.Wrapf(err, "PosMempool.addTransactionNoLock: Problem adding txn to register")
	}

	// If we've determined that this transaction is meant to replace an existing one, we remove the existing transaction now.
	if existingTxn != nil {
		if err := mp.removeTransactionNoLock(existingTxn, true); err != nil {
			recoveryErr := mp.txnRegister.RemoveTransaction(txn)
			return errors.Wrapf(err, "PosMempool.AddTransaction: Problem removing old transaction from mempool during "+
				"replacement with higher fee. Recovery error: %v", recoveryErr)
		}
	}

	// At this point the transaction is in the mempool. We can now update the ledger and nonce tracker.
	mp.ledger.IncreaseEntry(*userPk, txnFee)
	mp.nonceTracker.AddTxnByPublicKeyNonce(txn, *userPk, *txn.Tx.TxnNonce)

	// Emit an event for the newly added transaction.
	if persistToDb && !mp.inMemoryOnly {
		event := &MempoolEvent{
			Txn:  txn,
			Type: MempoolEventAdd,
		}
		mp.persister.EnqueueEvent(event)
	}

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

	// Remove the txn from the balance ledger and the nonce tracker.
	mp.ledger.DecreaseEntry(*userPk, txn.Fee)
	mp.nonceTracker.RemoveTxnByPublicKeyNonce(*userPk, *txn.Tx.TxnNonce)

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

	return NewMempoolTransaction(txn.Tx, uint64(txn.Added.UnixMicro()))
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

		mtxn := NewMempoolTransaction(txn.Tx, uint64(txn.Added.UnixMicro()))
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

// Refresh can be used to evict stale transactions from the mempool. However, it is a bit expensive and should be used
// sparingly. Upon being called, Refresh will create an in-memory temp PosMempool and populate it with transactions from
// the main mempool. The temp mempool will have the most up-to-date readOnlyLatestBlockView, Height, and globalParams. Any
// transaction that fails to add to the temp mempool will be removed from the main mempool.
func (mp *PosMempool) Refresh() error {
	mp.Lock()
	defer mp.Unlock()

	if !mp.IsRunning() {
		return nil
	}

	if err := mp.refreshNoLock(); err != nil {
		return errors.Wrapf(err, "PosMempool.Refresh: Problem refreshing mempool")
	}
	return nil
}

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
		mp.mempoolBackupIntervalMillis,
		mp.feeEstimator.cachedBlocks,
		mp.augmentedBlockViewRefreshIntervalMillis,
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
		mtxn := NewMempoolTransaction(txn.Tx, uint64(txn.Added.UnixMicro()))
		err := tempPool.AddTransaction(mtxn, false)
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
		glog.Infof("PosMempool.refreshNoLock: Transactions with the following hashes were removed: %v",
			strings.Join(removedTxnHashes, ","))
	}
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
	checkIntervalMillis := mp.augmentedBlockViewRefreshIntervalMillis / 5
	if checkIntervalMillis == 0 {
		checkIntervalMillis = 1
	}
	for newSeqNum == oldSeqNum {
		time.Sleep(time.Duration(checkIntervalMillis) * time.Millisecond)
		newSeqNum = atomic.LoadInt64(&mp.augmentedLatestBlockViewSequenceNumber)
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
	_, exists := mp.txnRegister.txnMembership[*txHash]
	return exists
}

func (mp *PosMempool) GetMempoolTx(txHash *BlockHash) *MempoolTx {
	mp.RLock()
	defer mp.RUnlock()
	return mp.txnRegister.txnMembership[*txHash]
}

func (mp *PosMempool) GetMempoolSummaryStats() map[string]*SummaryStats {
	return convertMempoolTxsToSummaryStats(mp.txnRegister.GetFeeTimeTransactions())
}

func (mp *PosMempool) EstimateFee(txn *MsgDeSoTxn,
	_ uint64,
	mempoolCongestionFactorBasisPoints uint64,
	mempoolPriorityPercentileBasisPoints uint64,
	pastBlocksCongestionFactorBasisPoints uint64,
	pastBlocksPriorityPercentileBasisPoints uint64,
	maxBlockSize uint64) (uint64, error) {
	// TODO: replace MaxBasisPoints with variables configured by flags.
	return mp.feeEstimator.EstimateFee(
		txn, mempoolCongestionFactorBasisPoints, mempoolPriorityPercentileBasisPoints,
		pastBlocksCongestionFactorBasisPoints, pastBlocksPriorityPercentileBasisPoints, maxBlockSize)
}
