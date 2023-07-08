package lib

import (
	"github.com/pkg/errors"
	"time"
)

type PosMempool struct {
	bc           *Blockchain
	txnRegister  *TransactionRegister
	globalParams *GlobalParamsEntry
	ledger       *PosMempoolLedger

	latestBlockView *UtxoView
	latestBlockNode *BlockNode
}

func NewDeSoMempoolPos(bc *Blockchain) *PosMempool {
	// TODO: Think about how to handle global params.
	globalParams := DbGetGlobalParamsEntry(bc.db, bc.snapshot)

	return &PosMempool{
		bc:           bc,
		txnRegister:  NewTransactionRegister(bc.params, globalParams),
		globalParams: globalParams,
		ledger:       NewPosMempoolLedger(),
	}
}

func (dmp *PosMempool) AddTransaction(txn *MsgDeSoTxn) error {
	userPk := NewPublicKey(txn.PublicKey)
	txnFee := txn.TxnFeeNanos
	latestBlockHeight := dmp.latestBlockNode.Height

	// First, validate that the transaction is properly formatted.
	txnValidator := NewMsgDeSoTxnValidator(txn, dmp.bc.params, dmp.globalParams)
	if err := txnValidator.ValidateTransactionSanityBalanceModel(uint64(latestBlockHeight)); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem validating transaction sanity")
	}

	// Validate that the user has enough balance to cover the transaction fees.
	if err := dmp.ledger.CheckBalanceIncrease(*userPk, txnFee, dmp.latestBlockView, latestBlockHeight); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem checking balance increase for transaction with"+
			"hash %v, fee %v", txn.Hash(), txnFee)
	}

	// Check transaction signature
	if _, err := dmp.latestBlockView._verifySignature(txn, latestBlockHeight); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Signature validation failed")
	}

	// Construct the MempoolTx from the MsgDeSoTxn.
	mempoolTx, err := NewMempoolTx(txn, uint64(latestBlockHeight))
	if err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem constructing MempoolTx")
	}

	if err = dmp.txnRegister.AddTransaction(mempoolTx); err != nil {
		return errors.Wrapf(err, "PosMempool.AddTransaction: Problem adding txn to register")
	}

	// We update the reserved balance to include the newly added transaction's fee.
	dmp.ledger.IncreaseBalance(*userPk, txnFee)

	return nil
}

func (dmp *PosMempool) RemoveTransaction(txn *MempoolTx) error {
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

func NewMempoolTx(txn *MsgDeSoTxn, blockHeight uint64) (*MempoolTx, error) {
	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		return nil, errors.Wrapf(err, "PosMempool.GetMempoolTx: Problem serializing txn")
	}
	serializedLen := uint64(len(txnBytes))

	txnHash := txn.Hash()
	if txnHash == nil {
		return nil, errors.Errorf("PosMempool.GetMempoolTx: Problem hashing txn")
	}
	feePerKb, err := txn.ComputeFeePerKB()
	if err != nil {
		return nil, errors.Wrapf(err, "PosMempool.GetMempoolTx: Problem computing fee per KB")
	}

	return &MempoolTx{
		Tx:          txn,
		Hash:        txnHash,
		TxSizeBytes: serializedLen,
		Added:       time.Now(),
		Height:      uint32(blockHeight),
		Fee:         txn.TxnFeeNanos,
		FeePerKB:    feePerKb,
	}, nil
}
