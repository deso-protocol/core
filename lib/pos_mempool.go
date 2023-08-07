package lib

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"path/filepath"
	"strings"
	"sync"
)

type PosMempoolStatus int

const (
	PosMempoolStatusRunning PosMempoolStatus = iota
	PosMempoolStatusNotRunning
)

type Mempool interface {
	Start() error
	Stop()
	IsRunning() bool
	ProcessMsgDeSoTxn(msg *MsgDeSoTxn) error
	AddTransaction(txn *MempoolTx) error
	RemoveTransaction(txn *MempoolTx) error
	GetTransaction(txHash *BlockHash) *MempoolTx
	GetTransactions() []*MempoolTx
	GetIterator() MempoolIterator
	UpdateLatestBlock(blockView *UtxoView, blockNode *BlockNode)
	UpdateGlobalParams(globalParams *GlobalParamsEntry)
}

type MempoolIterator interface {
	Next() bool
	Value() (*MempoolTx, bool)
	Initialized() bool
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
	persister  *MempoolPersister
	emitEvents bool

	// latestBlockView is used to check if a transaction is valid before being added to the mempool. The latestBlockView
	// checks if the transaction has a valid signature and if the transaction's sender has enough funds to cover the fee.
	// The latestBlockView should be updated whenever a new block is added to the blockchain via UpdateLatestBlock.
	latestBlockView *UtxoView
	// latestBlockNode is used to infer the latest block height. The latestBlockNode should be updated whenever a new
	// block is added to the blockchain via UpdateLatestBlock.
	latestBlockNode *BlockNode
}

func NewPosMempool(params *DeSoParams, globalParams *GlobalParamsEntry, latestBlockView *UtxoView,
	latestBlockNode *BlockNode, dir string) *PosMempool {
	return &PosMempool{
		status:          PosMempoolStatusNotRunning,
		params:          params,
		globalParams:    globalParams,
		dir:             dir,
		emitEvents:      false,
		latestBlockView: latestBlockView,
		latestBlockNode: latestBlockNode,
	}
}

func (dmp *PosMempool) Start() error {
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
	dmp.persister = NewMempoolPersister(dmp.db, 30000)

	// Start the persister and retrieve transactions from the database.
	dmp.persister.Start()
	txns, err := dmp.persister.GetPersistedTransactions()
	if err != nil {
		return errors.Wrapf(err, "PosMempool.Start: Problem retrieving transactions from persister")
	}
	// We set the emitEvents flag to false so that we don't emit events when adding transactions from the persister.
	dmp.emitEvents = false
	for _, txn := range txns {
		if err := dmp.addTransactionNoLock(txn); err != nil {
			glog.Errorf("PosMempool.Start: Problem adding transaction with hash (%v) from persister: %v",
				txn.Hash, err)
		}
	}
	dmp.emitEvents = true
	dmp.status = PosMempoolStatusRunning

	return nil
}

func (dmp *PosMempool) Stop() {
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

	dmp.emitEvents = false
	dmp.status = PosMempoolStatusNotRunning
}

func (dmp *PosMempool) IsRunning() bool {
	return dmp.status == PosMempoolStatusRunning
}

// ProcessMsgDeSoTxn validates a MsgDeSoTxn transaction and adds it to the mempool if it is valid.
// If the mempool overflows as a result of adding the transaction, the mempool is pruned.
func (dmp *PosMempool) ProcessMsgDeSoTxn(txn *MsgDeSoTxn) error {
	if !dmp.IsRunning() {
		return errors.Wrapf(MempoolErrorNotRunning, "PosMempool.ProcessMsgDeSoTxn: ")
	}

	// First, validate that the transaction is properly formatted according to BalanceModel.
	latestBlockHeight := dmp.latestBlockNode.Height
	if err := ValidateDeSoTxnSanityBalanceModel(txn, uint64(latestBlockHeight), dmp.params, dmp.globalParams); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem validating transaction sanity")
	}

	// Construct the MempoolTx from the MsgDeSoTxn.
	mempoolTx, err := NewMempoolTx(txn, uint64(latestBlockHeight))
	if err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem constructing MempoolTx")
	}

	// Check transaction signature
	if _, err := dmp.latestBlockView.VerifySignature(txn, latestBlockHeight); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Signature validation failed")
	}

	// Add the transaction to the mempool.
	if err := dmp.AddTransaction(mempoolTx); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem adding transaction to mempool")
	}
	return nil
}

// AddTransaction is the main function for adding a new transaction to the mempool.
func (dmp *PosMempool) AddTransaction(txn *MempoolTx) error {
	if !dmp.IsRunning() {
		return errors.Wrapf(MempoolErrorNotRunning, "PosMempool.AddTransaction: ")
	}

	dmp.Lock()
	defer dmp.Unlock()

	// Add the transaction to the mempool and then prune if needed.
	if err := dmp.addTransactionNoLock(txn); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem adding transaction to mempool")
	}

	if err := dmp.pruneNoLock(); err != nil {
		glog.Errorf("PosMempool.AddTransaction: Problem pruning mempool: %v", err)
	}

	return nil
}

func (dmp *PosMempool) addTransactionNoLock(txn *MempoolTx) error {
	userPk := NewPublicKey(txn.Tx.PublicKey)
	txnFee := txn.Tx.TxnFeeNanos
	latestBlockHeight := dmp.latestBlockNode.Height

	// Validate that the user has enough balance to cover the transaction fees.
	spendableBalanceNanos, err := dmp.latestBlockView.GetSpendableDeSoBalanceNanosForPublicKey(userPk.ToBytes(), latestBlockHeight)
	if err != nil {
		return errors.Wrapf(err, "CheckBalanceIncrease: Problem getting spendable balance")
	}
	if err := dmp.ledger.CanIncreaseBalance(*userPk, txnFee, spendableBalanceNanos); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem checking balance increase for transaction with"+
			"hash %v, fee %v", txn.Tx.Hash(), txnFee)
	}

	// If we get here, it means that the transaction's sender has enough balance to cover transaction fees. We can now
	// add the transaction to mempool.
	if err := dmp.txnRegister.AddTransaction(txn); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem adding txn to register")
	}

	// We update the reserved balance to include the newly added transaction's fee.
	dmp.ledger.IncreaseBalance(*userPk, txnFee)

	// Emit an event for the newly added transaction.
	if dmp.emitEvents {
		event := &MempoolEvent{
			Txn:  txn,
			Type: MempoolEventAdd,
		}
		dmp.persister.EnqueueEvent(event)
	}

	return nil
}

// RemoveTransaction is the main function for removing a transaction from the mempool.
func (dmp *PosMempool) RemoveTransaction(txn *MempoolTx) error {
	if !dmp.IsRunning() {
		return errors.Wrapf(MempoolErrorNotRunning, "PosMempool.RemoveTransaction: ")
	}

	dmp.Lock()
	defer dmp.Unlock()

	return dmp.removeTransactionNoLock(txn)
}

func (dmp *PosMempool) removeTransactionNoLock(txn *MempoolTx) error {
	// First, sanity check our reserved balance.
	userPk := NewPublicKey(txn.Tx.PublicKey)

	// Remove the transaction from the register.
	if err := dmp.txnRegister.RemoveTransaction(txn); err != nil {
		return errors.Wrapf(err, "PosMempool.RemoveTransaction: Problem removing txn from register")
	}
	// Decrease the appropriate ledger's balance by the transaction fee.
	dmp.ledger.DecreaseBalance(*userPk, txn.Fee)

	// Emit an event for the removed transaction.
	if dmp.emitEvents {
		event := &MempoolEvent{
			Txn:  txn,
			Type: MempoolEventRemove,
		}
		dmp.persister.EnqueueEvent(event)
	}

	return nil
}

// GetTransaction returns the transaction with the given hash if it exists in the mempool. This function is thread-safe.
func (dmp *PosMempool) GetTransaction(txHash *BlockHash) *MempoolTx {
	if !dmp.IsRunning() {
		return nil
	}

	dmp.RLock()
	defer dmp.RUnlock()

	return dmp.txnRegister.GetTransaction(txHash)
}

// GetTransactions returns all transactions in the mempool ordered by the Fee-Time algorithm. This function is thread-safe.
func (dmp *PosMempool) GetTransactions() []*MempoolTx {
	if !dmp.IsRunning() {
		return nil
	}

	dmp.RLock()
	defer dmp.RUnlock()

	return dmp.txnRegister.GetFeeTimeTransactions()
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
	if !dmp.IsRunning() {
		return nil
	}

	dmp.RLock()
	defer dmp.RUnlock()

	return dmp.txnRegister.GetFeeTimeIterator()
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
		return errors.Wrapf(err, "PosMempool.prune: Problem pruning mempool")
	}
	for _, prunedTxn := range prunedTxns {
		if err := dmp.removeTransactionNoLock(prunedTxn); err != nil {
			glog.Errorf("PosMempool.prune: Problem removing transaction from mempool: %v", err)
		}
	}
	return nil
}

// UpdateLatestBlock updates the latest block view and latest block node in the mempool.
func (dmp *PosMempool) UpdateLatestBlock(blockView *UtxoView, blockNode *BlockNode) {
	if !dmp.IsRunning() {
		return
	}

	dmp.Lock()
	defer dmp.Unlock()

	dmp.latestBlockView = blockView
	dmp.latestBlockNode = blockNode
}

// UpdateGlobalParams updates the global params in the mempool. Changing GlobalParamsEntry can impact the validity of
// transactions in the mempool. For example, if the minimum network fee is increased, transactions with a fee below the
// new minimum will be removed from the mempool. To safely handle this, this method re-creates the TransactionRegister
// with the new global params and re-adds all transactions in the mempool to the new register.
func (dmp *PosMempool) UpdateGlobalParams(globalParams *GlobalParamsEntry) {
	if !dmp.IsRunning() {
		return
	}

	dmp.Lock()
	defer dmp.Unlock()

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
		if err := dmp.removeTransactionNoLock(mempoolTx); err != nil {
			glog.Errorf("PosMempool.UpdateGlobalParams: Problem removing txn with hash %v from register: %v",
				mempoolTx.Hash.String(), err)
		}
	}

	if len(removedTxnHashes) > 0 {
		glog.Errorf("PosMempool.UpdateGlobalParams: Transactions with the following hashes were removed: %v",
			strings.Join(removedTxnHashes, ","))
	}
	dmp.txnRegister.Reset()
	dmp.txnRegister = newRegister
}
