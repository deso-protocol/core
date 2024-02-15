package lib

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"math"
	"time"
)

// MempoolTx contains a transaction along with additional metadata like the
// fee and time added.
type MempoolTx struct {
	Tx *MsgDeSoTxn

	// TxMeta is the transaction metadata
	TxMeta *TransactionMetadata

	// Hash is a hash of the transaction so we don't have to recompute
	// it all the time.
	Hash *BlockHash

	// TxSizeBytes is the cached size of the transaction.
	TxSizeBytes uint64

	// The time when the txn was added to the pool
	Added time.Time

	// The block height when the txn was added to the pool. It's generally set
	// to tip+1.
	Height uint32

	// The total fee the txn pays. Cached for efficiency reasons.
	Fee uint64

	// The fee rate of the transaction in nanos per KB.
	FeePerKB uint64

	// index is used by the heap logic to allow for modification in-place.
	index int
}

func NewMempoolTx(txn *MsgDeSoTxn, addedUnixMicro time.Time, blockHeight uint64) (*MempoolTx, error) {
	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		return nil, errors.Wrapf(err, "PosMempool.GetMempoolTx: Problem serializing txn")
	}
	serializedLen := uint64(len(txnBytes))

	txnHash := txn.Hash()
	if txnHash == nil {
		return nil, errors.Errorf("PosMempool.GetMempoolTx: Problem hashing txn")
	}
	feePerKb, err := txn.ComputeFeeRatePerKBNanos()
	if err != nil {
		return nil, errors.Wrapf(err, "PosMempool.GetMempoolTx: Problem computing fee per KB")
	}

	return &MempoolTx{
		Tx:          txn,
		Hash:        txnHash,
		TxSizeBytes: serializedLen,
		Added:       addedUnixMicro,
		Height:      uint32(blockHeight),
		Fee:         txn.TxnFeeNanos,
		FeePerKB:    feePerKb,
	}, nil
}

func (mempoolTx *MempoolTx) String() string {
	return fmt.Sprintf("< Added: %v, index: %d, Fee: %d, Type: %v, Hash: %v", mempoolTx.Added, mempoolTx.index, mempoolTx.Fee, mempoolTx.Tx.TxnMeta.GetTxnType(), mempoolTx.Hash)
}

func (mempoolTx *MempoolTx) GetTimestamp() uint64 {
	return uint64(mempoolTx.Added.UnixMicro())
}

func (mempoolTx *MempoolTx) ToBytes() ([]byte, error) {
	var data []byte

	txnBytes, err := mempoolTx.Tx.ToBytes(false)
	if err != nil {
		return nil, errors.Wrapf(err, "MempoolTx.Encode: Problem serializing txn")
	}
	data = append(data, EncodeByteArray(txnBytes)...)
	data = append(data, UintToBuf(uint64(mempoolTx.Height))...)
	data = append(data, UintToBuf(mempoolTx.GetTimestamp())...)
	return data, nil
}

func (mempoolTx *MempoolTx) FromBytes(rr *bytes.Reader) error {
	if mempoolTx == nil {
		return errors.New("MempoolTx.Decode: mempoolTx is nil")
	}

	// Decode the transaction
	txn := &MsgDeSoTxn{}
	txnBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MempoolTx.Decode: Problem reading txnBytes")
	}
	err = txn.FromBytes(txnBytes)
	if err != nil {
		return errors.Wrapf(err, "MempoolTx.Decode: Problem deserializing txn")
	}

	// Decode the height
	height, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MempoolTx.Decode: Problem reading height")
	}

	// Decode the timestamp
	timestampUnixMicro, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MempoolTx.Decode: Problem reading timestamp")
	}
	if timestampUnixMicro > math.MaxInt64 {
		return errors.Errorf("MempoolTx.Decode: Invalid timestamp %d exceeds max int64 %d",
			timestampUnixMicro, math.MaxInt64)
	}

	// Create a new MempoolTx
	newTxn, err := NewMempoolTx(txn, time.UnixMicro(int64(timestampUnixMicro)), height)
	*mempoolTx = *newTxn
	return nil
}
