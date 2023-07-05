package lib

import (
	"github.com/pkg/errors"
	"math"
	"time"
)

type DeSoMempoolPos struct {
	bc           *Blockchain
	txnRegister  *TransactionRegister
	globalParams *GlobalParamsEntry

	reservedBalances map[PublicKey]uint64
}

func NewDeSoMempoolPos(bc *Blockchain) *DeSoMempoolPos {
	// TODO: Think about how to handle global params.
	globalParams := DbGetGlobalParamsEntry(bc.db, bc.snapshot)

	return &DeSoMempoolPos{
		bc:               bc,
		txnRegister:      NewTransactionRegister(bc.params, globalParams),
		globalParams:     globalParams,
		reservedBalances: make(map[PublicKey]uint64),
	}
}

func (dmp *DeSoMempoolPos) AddTransaction(txn *MsgDeSoTxn, blockHeight uint64, utxoView *UtxoView) error {
	// First, validate that the transaction is properly formatted.
	if err := txn.ValidateTransactionSanityBalanceModel(blockHeight, dmp.bc.params, dmp.globalParams); err != nil {
		return errors.Wrapf(err, "DeSoMempoolPos.AddTransaction: ")
	}

	// Validate that the user has enough balance to cover the transaction fees.
	userPk := NewPublicKey(txn.PublicKey)
	txnFee := txn.TxnFeeNanos
	reservedBalance, exists := dmp.reservedBalances[*userPk]

	// Check for reserved balance overflow.
	if exists && txnFee > math.MaxUint64-reservedBalance {
		return errors.Errorf("DeSoMempoolPos.AddTransaction: Reserved balance overflow")
	}
	newReservedBalance := reservedBalance + txnFee
	spendableBalanceNanos, err := utxoView.GetSpendableDeSoBalanceNanosForPublicKey(txn.PublicKey, uint32(blockHeight))
	if err != nil {
		return errors.Wrapf(err, "DeSoMempoolPos.AddTransaction: ")
	}
	if newReservedBalance > spendableBalanceNanos {
		return errors.Errorf("DeSoMempoolPos.AddTransaction: Not enough balance to cover txn fees "+
			"(newReservedBalance: %d, spendableBalanceNanos: %d)", newReservedBalance, spendableBalanceNanos)
	}

	// Check transaction signature
	if _, err = utxoView._verifySignature(txn, uint32(blockHeight)); err != nil {
		return errors.Wrapf(err, "DeSoMempoolPos.AddTransaction: Signature validation failed")
	}

	// Construct the MempoolTx from the MsgDeSoTxn.
	mempoolTx, err := NewMempoolTx(txn, blockHeight)
	if err != nil {
		return errors.Wrapf(err, "DeSoMempoolPos.AddTransaction: Problem constructing MempoolTx")
	}

	if err = dmp.txnRegister.AddTransaction(mempoolTx); err != nil {
		return errors.Wrapf(err, "DeSoMempoolPos.AddTransaction: Problem adding txn to register")
	}

	// If we get here, this means the transaction was successfully added to the mempool. We update the reserved balance to
	// include the newly added transaction's fee.
	dmp.reservedBalances[*userPk] = newReservedBalance

	return nil
}

func (dmp *DeSoMempoolPos) RemoveTransaction(txn *MempoolTx) error {
	// First, sanity check our reserved balance.
	userPk := NewPublicKey(txn.Tx.PublicKey)
	reservedBalance := dmp.reservedBalances[*userPk]
	if txn.Fee > reservedBalance {
		return errors.Errorf("DeSoMempoolPos.RemoveTransaction: Fee exceeds reserved balance")
	}

	// Remove the transaction from the register.
	if err := dmp.txnRegister.RemoveTransaction(txn); err != nil {
		return errors.Wrapf(err, "DeSoMempoolPos.RemoveTransaction: Problem removing txn from register")
	}
	dmp.reservedBalances[*userPk] = reservedBalance - txn.Fee

	return nil
}

func NewMempoolTx(txn *MsgDeSoTxn, blockHeight uint64) (*MempoolTx, error) {
	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		return nil, errors.Wrapf(err, "DeSoMempoolPos.GetMempoolTx: Problem serializing txn")
	}
	serializedLen := uint64(len(txnBytes))

	txnHash := txn.Hash()
	if txnHash == nil {
		return nil, errors.Errorf("DeSoMempoolPos.GetMempoolTx: Problem hashing txn")
	}
	feePerKb, err := txn.ComputeFeePerKB()
	if err != nil {
		return nil, errors.Wrapf(err, "DeSoMempoolPos.GetMempoolTx: Problem computing fee per KB")
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
