package lib

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	PosMempoolStatusNotRunning = iota
	PosMempoolStatusRunning
)

type Mempool interface {
	Start() error
	Stop()
	IsRunning() bool
	AddTransaction(txn *MsgDeSoTxn) error
	RemoveTransaction(txnHash *BlockHash) error
	GetTransaction(txnHash *BlockHash) *MsgDeSoTxn
	GetTransactions() []*MsgDeSoTxn
	GetIterator() MempoolIterator
	UpdateLatestBlock(blockView *UtxoView, blockHeight uint64)
	UpdateGlobalParams(globalParams *GlobalParamsEntry)
}

type MempoolIterator interface {
	Next() bool
	Value() (*MsgDeSoTxn, bool)
	Initialized() bool
}

// PosMempool is used by the node to keep track of uncommitted transactions. The main responsibilities of the PosMempool
// include addition/removal of transactions, back up of transaction to database, and retrieval of transactions ordered
// by Fee-Time algorithm. More on the Fee-Time algorithm can be found in the documentation of TransactionRegister.
type PosMempool struct {
	sync.RWMutex
	status *atomic.Int32
	// params of the blockchain
	params *DeSoParams
	// globalParams are used to track the latest GlobalParamsEntry. In case the GlobalParamsEntry changes, the PosMempool
	// is equipped with UpdateGlobalParams method to handle upgrading GlobalParamsEntry.
	globalParams *GlobalParamsEntry
	// dir of the directory where the database should be stored.
	dir string
	// db is the database that the mempool will use to persist transactions.
	db *badger.DB

	// txnRegister is the in-memory data structure keeping track of the transactions in the mempool. The TransactionRegister
	// is responsible for ordering transactions by the Fee-Time algorithm.
	txnRegister *TransactionRegister
	// ledger is a simple in-memory data structure that keeps track of cumulative transaction fees in the mempool.
	// The ledger keeps track of how much each user would have spent in fees across all their transactions in the mempool.
	ledger *BalanceLedger
	// persister is responsible for interfacing with the database. The persister backs up mempool transactions so not to
	// lose them when node reboots. The persister also retrieves transactions from the database when the node starts up.
	// The persister runs on its dedicated thread and events are used to notify the persister thread whenever
	// transactions are added/removed from the mempool. The persister thread then updates the database accordingly.
	persister *MempoolPersister

	// latestBlockView is used to check if a transaction is valid before being added to the mempool. The latestBlockView
	// checks if the transaction has a valid signature and if the transaction's sender has enough funds to cover the fee.
	// The latestBlockView should be updated whenever a new block is added to the blockchain via UpdateLatestBlock.
	latestBlockView *UtxoView
	// latestBlockNode is used to infer the latest block height. The latestBlockNode should be updated whenever a new
	// block is added to the blockchain via UpdateLatestBlock.
	latestBlockHeight uint64
}

// PosMempoolIterator is a wrapper around FeeTimeIterator, modified to return MsgDeSoTxn instead of MempoolTx.
type PosMempoolIterator struct {
	it *FeeTimeIterator
}

func (it *PosMempoolIterator) Next() bool {
	return it.it.Next()
}

func (it *PosMempoolIterator) Value() (*MsgDeSoTxn, bool) {
	txn, ok := it.it.Value()
	if txn == nil || txn.Tx == nil {
		return nil, ok
	}
	return txn.Tx, ok
}

func (it *PosMempoolIterator) Initialized() bool {
	return it.it.Initialized()
}

func NewPosMempoolIterator(it *FeeTimeIterator) *PosMempoolIterator {
	return &PosMempoolIterator{it: it}
}

func NewPosMempool(params *DeSoParams, globalParams *GlobalParamsEntry, latestBlockView *UtxoView,
	latestBlockHeight uint64, dir string) *PosMempool {

	var status atomic.Int32
	status.Store(PosMempoolStatusNotRunning)
	return &PosMempool{
		status:            &status,
		params:            params,
		globalParams:      globalParams,
		dir:               dir,
		latestBlockView:   latestBlockView,
		latestBlockHeight: latestBlockHeight,
	}
}

func (dmp *PosMempool) Start() error {
	dmp.Lock()
	defer dmp.Unlock()

	if dmp.IsRunning() {
		return nil
	}

	// Setup the database.
	mempoolDirectory := filepath.Join(dmp.dir, "mempool")
	opts := DefaultBadgerOptions(mempoolDirectory)
	db, err := badger.Open(opts)
	if err != nil {
		return errors.Wrapf(err, "PosMempool.Start: Problem setting up database")
	}
	dmp.db = db

	// Create the transaction register and ledger
	dmp.txnRegister = NewTransactionRegister(dmp.globalParams)
	dmp.ledger = NewBalanceLedger()

	// Create the persister
	dmp.persister = NewMempoolPersister(dmp.db, int(dmp.params.MempoolBackupTimeMilliseconds))

	// Start the persister and retrieve transactions from the database.
	dmp.persister.Start()
	err = dmp.loadPersistedTransactions()
	if err != nil {
		return errors.Wrapf(err, "PosMempool.Start: Problem loading persisted transactions")
	}

	dmp.status.Store(PosMempoolStatusRunning)
	return nil
}

func (dmp *PosMempool) Stop() {
	dmp.Lock()
	defer dmp.Unlock()

	if !dmp.IsRunning() {
		return
	}

	// Close the persister and stop the database.
	if err := dmp.persister.Stop(); err != nil {
		glog.Errorf("PosMempool.Stop: Problem stopping persister: %v", err)
	}
	if err := dmp.db.Close(); err != nil {
		glog.Errorf("PosMempool.Stop: Problem closing database: %v", err)
	}
	// Reset the transaction register and the ledger.
	dmp.txnRegister.Reset()
	dmp.ledger.Reset()

	dmp.status.Store(PosMempoolStatusNotRunning)
}

func (dmp *PosMempool) IsRunning() bool {
	return dmp.status.Load() == PosMempoolStatusRunning
}

// AddTransaction validates a MsgDeSoTxn transaction and adds it to the mempool if it is valid.
// If the mempool overflows as a result of adding the transaction, the mempool is pruned.
func (dmp *PosMempool) AddTransaction(txn *MsgDeSoTxn) error {
	// First, validate that the transaction is properly formatted according to BalanceModel. We acquire a read lock on
	// the mempool. This allows multiple goroutines to safely perform transaction validation concurrently. In particular,
	// transaction signature verification can be parallelized.
	dmp.RLock()

	if err := ValidateDeSoTxnSanityBalanceModel(txn, dmp.latestBlockHeight, dmp.params, dmp.globalParams); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem validating transaction sanity")
	}

	// Construct the MempoolTx from the MsgDeSoTxn.
	mempoolTx, err := NewMempoolTx(txn, dmp.latestBlockHeight)
	if err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem constructing MempoolTx")
	}

	// Check transaction signature
	if _, err := dmp.latestBlockView.VerifySignature(txn, uint32(dmp.latestBlockHeight)); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Signature validation failed")
	}
	dmp.RUnlock()

	// If we get this far, it means that the transaction is valid. We can now add it to the mempool.
	// We lock the mempool to ensure that no other thread is modifying it while we add the transaction.
	dmp.Lock()
	defer dmp.Unlock()

	if !dmp.IsRunning() {
		return errors.Wrapf(MempoolErrorNotRunning, "PosMempool.AddTransaction: ")
	}

	// Add the transaction to the mempool and then prune if needed.
	if err := dmp.addTransactionNoLock(mempoolTx, true); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem adding transaction to mempool")
	}

	if err := dmp.pruneNoLock(); err != nil {
		glog.Errorf("PosMempool.AddTransaction: Problem pruning mempool: %v", err)
	}

	return nil
}

func (dmp *PosMempool) addTransactionNoLock(txn *MempoolTx, persistToDb bool) error {
	userPk := NewPublicKey(txn.Tx.PublicKey)
	txnFee := txn.Tx.TxnFeeNanos

	// Validate that the user has enough balance to cover the transaction fees.
	spendableBalanceNanos, err := dmp.latestBlockView.GetSpendableDeSoBalanceNanosForPublicKey(userPk.ToBytes(),
		uint32(dmp.latestBlockHeight))
	if err != nil {
		return errors.Wrapf(err, "PosMempool.addTransactionNoLock: Problem getting spendable balance")
	}
	if err := dmp.ledger.CanIncreaseEntryWithLimit(*userPk, txnFee, spendableBalanceNanos); err != nil {
		return errors.Wrapf(err, "PosMempool.addTransactionNoLock: Problem checking balance increase for transaction with"+
			"hash %v, fee %v", txn.Tx.Hash(), txnFee)
	}

	// If we get here, it means that the transaction's sender has enough balance to cover transaction fees. We can now
	// add the transaction to mempool.
	if err := dmp.txnRegister.AddTransaction(txn); err != nil {
		return errors.Wrapf(err, "PosMempool.addTransactionNoLock: Problem adding txn to register")
	}

	// We update the reserved balance to include the newly added transaction's fee.
	dmp.ledger.IncreaseEntry(*userPk, txnFee)

	// Emit an event for the newly added transaction.
	if persistToDb {
		event := &MempoolEvent{
			Txn:  txn,
			Type: MempoolEventAdd,
		}
		dmp.persister.EnqueueEvent(event)
	}

	return nil
}

// loadPersistedTransactions fetches transactions from the persister's storage and adds the transactions to the mempool.
// No lock is held and (persistToDb = false) flag is used when adding transactions internally.
func (dmp *PosMempool) loadPersistedTransactions() error {
	txns, err := dmp.persister.GetPersistedTransactions()
	if err != nil {
		return errors.Wrapf(err, "PosMempool.Start: Problem retrieving transactions from persister")
	}
	// We set the persistToDb flag to false so that persister doesn't try to save the transactions.
	for _, txn := range txns {
		if err := dmp.addTransactionNoLock(txn, false); err != nil {
			glog.Errorf("PosMempool.Start: Problem adding transaction with hash (%v) from persister: %v",
				txn.Hash, err)
		}
	}
	return nil
}

// RemoveTransaction is the main function for removing a transaction from the mempool.
func (dmp *PosMempool) RemoveTransaction(txnHash *BlockHash) error {
	dmp.Lock()
	defer dmp.Unlock()

	if !dmp.IsRunning() {
		return errors.Wrapf(MempoolErrorNotRunning, "PosMempool.RemoveTransaction: ")
	}

	// Get the transaction from the register.
	txn := dmp.txnRegister.GetTransaction(txnHash)
	if txn == nil {
		return nil
	}

	return dmp.removeTransactionNoLock(txn, true)
}

func (dmp *PosMempool) removeTransactionNoLock(txn *MempoolTx, persistToDb bool) error {
	// First, sanity check our reserved balance.
	userPk := NewPublicKey(txn.Tx.PublicKey)

	// Remove the transaction from the register.
	if err := dmp.txnRegister.RemoveTransaction(txn); err != nil {
		return errors.Wrapf(err, "PosMempool.removeTransactionNoLock: Problem removing txn from register")
	}
	// Decrease the appropriate ledger's balance by the transaction fee.
	dmp.ledger.DecreaseEntry(*userPk, txn.Fee)

	// Emit an event for the removed transaction.
	if persistToDb {
		event := &MempoolEvent{
			Txn:  txn,
			Type: MempoolEventRemove,
		}
		dmp.persister.EnqueueEvent(event)
	}

	return nil
}

// GetTransaction returns the transaction with the given hash if it exists in the mempool. This function is thread-safe.
func (dmp *PosMempool) GetTransaction(txnHash *BlockHash) *MsgDeSoTxn {
	dmp.RLock()
	defer dmp.RUnlock()

	if !dmp.IsRunning() {
		return nil
	}

	txn := dmp.txnRegister.GetTransaction(txnHash)
	if txn == nil || txn.Tx == nil {
		return nil
	}

	return txn.Tx
}

// GetTransactions returns all transactions in the mempool ordered by the Fee-Time algorithm. This function is thread-safe.
func (dmp *PosMempool) GetTransactions() []*MsgDeSoTxn {
	dmp.RLock()
	defer dmp.RUnlock()

	if !dmp.IsRunning() {
		return nil
	}

	var desoTxns []*MsgDeSoTxn
	poolTxns := dmp.txnRegister.GetFeeTimeTransactions()
	for _, txn := range poolTxns {
		if txn == nil || txn.Tx == nil {
			continue
		}
		desoTxns = append(desoTxns, txn.Tx)
	}
	return desoTxns
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
func (dmp *PosMempool) GetIterator() MempoolIterator {
	dmp.RLock()
	defer dmp.RUnlock()

	if !dmp.IsRunning() {
		return nil
	}

	return NewPosMempoolIterator(dmp.txnRegister.GetFeeTimeIterator())
}

// pruneNoLock removes transactions from the mempool until the mempool size is below the maximum allowed size. The transactions
// are removed in lowest to highest Fee-Time priority, i.e. opposite way that transactions are ordered in
// GetTransactions().
func (dmp *PosMempool) pruneNoLock() error {
	if dmp.txnRegister.Size() < dmp.params.MaxMempoolPosSizeBytes {
		return nil
	}

	prunedTxns, err := dmp.txnRegister.PruneToSize(dmp.params.MaxMempoolPosSizeBytes)
	if err != nil {
		return errors.Wrapf(err, "PosMempool.pruneNoLock: Problem pruning mempool")
	}
	for _, prunedTxn := range prunedTxns {
		if err := dmp.removeTransactionNoLock(prunedTxn, true); err != nil {
			// We should never get to here since the transaction was already pruned from the TransactionRegister.
			glog.Errorf("PosMempool.pruneNoLock: Problem removing transaction from mempool: %v", err)
		}
	}
	return nil
}

// UpdateLatestBlock updates the latest block view and latest block node in the mempool.
func (dmp *PosMempool) UpdateLatestBlock(blockView *UtxoView, blockHeight uint64) {
	dmp.Lock()
	defer dmp.Unlock()

	if !dmp.IsRunning() {
		return
	}

	dmp.latestBlockView = blockView
	dmp.latestBlockHeight = blockHeight
}

// UpdateGlobalParams updates the global params in the mempool. Changing GlobalParamsEntry can impact the validity of
// transactions in the mempool. For example, if the minimum network fee is increased, transactions with a fee below the
// new minimum will be removed from the mempool. To safely handle this, this method re-creates the TransactionRegister
// with the new global params and re-adds all transactions in the mempool to the new register.
func (dmp *PosMempool) UpdateGlobalParams(globalParams *GlobalParamsEntry) {
	dmp.Lock()
	defer dmp.Unlock()

	if !dmp.IsRunning() {
		return
	}

	dmp.globalParams = globalParams
	mempoolTxns := dmp.txnRegister.GetFeeTimeTransactions()
	newRegister := NewTransactionRegister(dmp.globalParams)
	removedTxnHashes := []string{}

	for _, mempoolTx := range mempoolTxns {
		if err := newRegister.AddTransaction(mempoolTx); err == nil {
			continue
		}
		// If we get here, it means that the transaction is no longer valid. We remove it from the mempool.
		removedTxnHashes = append(removedTxnHashes, mempoolTx.Hash.String())
		if err := dmp.removeTransactionNoLock(mempoolTx, true); err != nil {
			glog.Errorf("PosMempool.UpdateGlobalParams: Problem removing txn with hash %v from register: %v",
				mempoolTx.Hash.String(), err)
		}
	}

	if len(removedTxnHashes) > 0 {
		glog.Infof("PosMempool.UpdateGlobalParams: Transactions with the following hashes were removed: %v",
			strings.Join(removedTxnHashes, ","))
	}
	dmp.txnRegister.Reset()
	dmp.txnRegister = newRegister
}
