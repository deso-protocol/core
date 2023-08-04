package lib

import (
	"github.com/deso-protocol/core/storage"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"path/filepath"
	"sync"
)

type PosMempoolStatus int

const (
	PosMempoolStatusRunning PosMempoolStatus = iota
	PosMempoolStatusNotRunning
)

type PosMempool struct {
	sync.RWMutex

	status       PosMempoolStatus
	params       *DeSoParams
	globalParams *GlobalParamsEntry
	dir          string
	dbCtx        *storage.DatabaseContext

	txnRegister *TransactionRegister
	ledger      *BalanceLedger
	persister   *MempoolPersister

	eventManager *EventManager
	emitEvents   bool

	latestBlockView *UtxoView
	latestBlockNode *BlockNode
}

func NewDeSoMempoolPos(params *DeSoParams, globalParams *GlobalParamsEntry, latestBlockView *UtxoView,
	latestBlockNode *BlockNode, dir string, eventManager *EventManager) *PosMempool {
	return &PosMempool{
		status:          PosMempoolStatusNotRunning,
		params:          params,
		globalParams:    globalParams,
		dir:             dir,
		eventManager:    eventManager,
		emitEvents:      false,
		latestBlockView: latestBlockView,
		latestBlockNode: latestBlockNode,
	}
}

func (dmp *PosMempool) Start() error {
	if dmp.status == PosMempoolStatusRunning {
		return nil
	}

	mempoolDirectory := filepath.Join(dmp.dir, "mempool")
	opts := storage.DefaultBadgerOptions(mempoolDirectory)
	db := storage.NewBadgerDatabase(opts, true)
	if err := db.Setup(); err != nil {
		return errors.Wrapf(err, "PosMempool.Start: Problem setting up database")
	}
	ctx := db.GetContext([]byte{})
	dbCtx := storage.NewDatabaseContext(db, ctx)
	dmp.dbCtx = dbCtx

	// Create the transaction register and ledger
	dmp.txnRegister = NewTransactionRegister(dmp.globalParams)
	dmp.ledger = NewBalanceLedger()

	// Load transactions from the persister
	dmp.persister = NewMempoolPersister(dmp.dbCtx, 30000)
	dmp.eventManager.OnMempoolEvent(dmp.persister.OnMempoolEvent)
	dmp.persister.Start()
	txns, err := dmp.persister.RetrieveTransactions()
	if err != nil {
		return errors.Wrapf(err, "PosMempool.Start: Problem retrieving transactions from persister")
	}
	for _, txn := range txns {
		if err := dmp.AddTransaction(txn); err != nil {
			// TODO: Should we return an error here.
			glog.Errorf("PosMempool.Start: Problem adding transaction with hash (%v) from persister: %v",
				txn.Hash, err)
		}
	}
	dmp.emitEvents = true
	dmp.status = PosMempoolStatusRunning

	return nil
}

func (dmp *PosMempool) Stop() {
	if dmp.status == PosMempoolStatusNotRunning {
		return
	}

	if err := dmp.persister.Stop(); err != nil {
		glog.Errorf("PosMempool.Stop: Problem stopping persister: %v", err)
	}
	if err := dmp.dbCtx.Close(); err != nil {
		glog.Errorf("PosMempool.Stop: Problem closing database: %v", err)
	}
	dmp.txnRegister.Reset()
	dmp.ledger.Reset()

	dmp.status = PosMempoolStatusNotRunning
}

// ProcessMsgDeSoTxn validates a MsgDeSoTxn transaction and adds it to the mempool if it is valid.
// If the mempool overflows as a result of adding the transaction, the mempool is pruned.
func (dmp *PosMempool) ProcessMsgDeSoTxn(txn *MsgDeSoTxn) error {
	if dmp.status == PosMempoolStatusNotRunning {
		return errors.Wrapf(MempoolErrorNotRunning, "PosMempool.ProcessMsgDeSoTxn: ")
	}

	latestBlockHeight := dmp.latestBlockNode.Height

	// First, validate that the transaction is properly formatted according to BalanceModel.
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

func (dmp *PosMempool) AddTransaction(txn *MempoolTx) error {
	dmp.Lock()
	defer dmp.prune()
	defer dmp.Unlock()

	return dmp.addTransactionNoLock(txn)
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

	if err := dmp.txnRegister.AddTransaction(txn); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem adding txn to register")
	}

	// We update the reserved balance to include the newly added transaction's fee.
	dmp.ledger.IncreaseBalance(*userPk, txnFee)

	if dmp.emitEvents {
		event := &MempoolEvent{
			Txn:  txn,
			Type: MempoolEventAdd,
		}
		dmp.eventManager.mempoolEvent(event)
	}

	return nil
}

func (dmp *PosMempool) RemoveTransaction(txn *MempoolTx) error {
	dmp.Lock()
	defer dmp.Unlock()

	return dmp.removeTransactionNoLock(txn)
}

func (dmp *PosMempool) removeTransactionNoLock(txn *MempoolTx) error {
	// First, sanity check our reserved balance.
	userPk := NewPublicKey(txn.Tx.PublicKey)
	if err := dmp.ledger.CanDecreaseBalance(*userPk, txn.Fee); err != nil {
		return errors.Wrapf(err, "PosMempool.RemoveTransaction: Problem checking balance decrease")
	}

	// Remove the transaction from the register.
	if err := dmp.txnRegister.RemoveTransaction(txn); err != nil {
		return errors.Wrapf(err, "PosMempool.RemoveTransaction: Problem removing txn from register")
	}

	dmp.ledger.DecreaseBalance(*userPk, txn.Fee)

	if dmp.emitEvents {
		event := &MempoolEvent{
			Txn:  txn,
			Type: MempoolEventRemove,
		}
		dmp.eventManager.mempoolEvent(event)
	}

	return nil
}

func (dmp *PosMempool) GetIterator() *FeeTimeIterator {
	dmp.RLock()
	defer dmp.RUnlock()

	return dmp.txnRegister.GetFeeTimeIterator()
}

func (dmp *PosMempool) GetTransactions() []*MempoolTx {
	dmp.RLock()
	defer dmp.RUnlock()

	return dmp.txnRegister.GetFeeTimeTransactions()
}

func (dmp *PosMempool) prune() error {
	dmp.Lock()
	defer dmp.Unlock()

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

func (dmp *PosMempool) UpdateLatestBlock(blockView *UtxoView, blockNode *BlockNode) {
	dmp.Lock()
	defer dmp.Unlock()

	dmp.latestBlockView = blockView
	dmp.latestBlockNode = blockNode
}

func (dmp *PosMempool) UpdateGlobalParams(globalParams *GlobalParamsEntry) {
	dmp.Lock()
	defer dmp.Unlock()

	dmp.globalParams = globalParams
	mempoolTxns := dmp.txnRegister.GetFeeTimeTransactions()
	newRegister := NewTransactionRegister(dmp.globalParams)
	for _, mempoolTx := range mempoolTxns {
		if err := newRegister.AddTransaction(mempoolTx); err != nil {
			// FIXME: Updating global params can mean that some transaction are no longer accepted in the new
			// 	TransactionRegister. What should we do with these txns? Currently, we just log an error. Maybe we
			//	 should make it a single, lower-priority log message containing hashes of all dropped txns.
			glog.Errorf("PosMempool.UpdateGlobalParams: Problem adding txn with hash %v to new register: %v",
				mempoolTx.Hash.String(), err)
		}
	}
	dmp.txnRegister.Reset()
	dmp.txnRegister = newRegister
}
