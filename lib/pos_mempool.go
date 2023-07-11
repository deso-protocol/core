package lib

import (
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"sync"
)

const (
	MempoolPruneFactor = 20
)

type PosMempool struct {
	sync.RWMutex

	params       *DeSoParams
	globalParams *GlobalParamsEntry

	txnRegister *TransactionRegister
	ledger      *PosMempoolLedger

	latestBlockView *UtxoView
	latestBlockNode *BlockNode
}

func NewDeSoMempoolPos(params *DeSoParams, globalParams *GlobalParamsEntry) *PosMempool {
	return &PosMempool{
		txnRegister:  NewTransactionRegister(globalParams),
		params:       params,
		globalParams: globalParams,
		ledger:       NewPosMempoolLedger(),
	}
}

// ProcessMsgDeSoTxn validates a MsgDeSoTxn transaction and adds it to the mempool if it is valid.
// If the mempool overflows as a result of adding the transaction, the mempool is pruned.
func (dmp *PosMempool) ProcessMsgDeSoTxn(txn *MsgDeSoTxn) error {
	latestBlockHeight := dmp.latestBlockNode.Height

	// First, validate that the transaction is properly formatted according to BalanceModel.
	txnValidator := NewMsgDeSoTxnValidator(txn, dmp.params, dmp.globalParams)
	if err := txnValidator.ValidateTransactionSanityBalanceModel(uint64(latestBlockHeight)); err != nil {
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
	defer GlogIfError(dmp.prune(), "PosMempool.AddTransaction: Problem pruning mempool")
	defer dmp.Unlock()

	userPk := NewPublicKey(txn.Tx.PublicKey)
	txnFee := txn.Tx.TxnFeeNanos
	latestBlockHeight := dmp.latestBlockNode.Height

	// Validate that the user has enough balance to cover the transaction fees.
	if err := dmp.ledger.CheckBalanceIncrease(*userPk, txnFee, dmp.latestBlockView, latestBlockHeight); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem checking balance increase for transaction with"+
			"hash %v, fee %v", txn.Tx.Hash(), txnFee)
	}

	if err := dmp.txnRegister.AddTransaction(txn); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem adding txn to register")
	}

	// We update the reserved balance to include the newly added transaction's fee.
	dmp.ledger.IncreaseBalance(*userPk, txnFee)

	return nil
}

func (dmp *PosMempool) RemoveTransaction(txn *MempoolTx) error {
	dmp.Lock()
	defer dmp.Unlock()

	// First, sanity check our reserved balance.
	userPk := NewPublicKey(txn.Tx.PublicKey)
	if err := dmp.ledger.CheckBalanceDecrease(*userPk, txn.Fee); err != nil {
		return errors.Wrapf(err, "PosMempool.RemoveTransaction: Problem checking balance decrease")
	}

	// Remove the transaction from the register.
	if err := dmp.txnRegister.RemoveTransaction(txn); err != nil {
		return errors.Wrapf(err, "PosMempool.RemoveTransaction: Problem removing txn from register")
	}

	dmp.ledger.DecreaseBalance(*userPk, txn.Fee)

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

	pruneSizeBytes := dmp.params.MaxMempoolPosSizeBytes / MempoolPruneFactor
	prunedTxns, err := dmp.txnRegister.Prune(pruneSizeBytes)
	if err != nil {
		return errors.Wrapf(err, "PosMempool.prune: Problem pruning mempool")
	}
	// TODO: Log pruned txns
	_ = prunedTxns
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
	dmp.txnRegister.Clear()
	dmp.txnRegister = newRegister
}

// Create a DB persister
