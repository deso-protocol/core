package lib

import (
	"bytes"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

//
// SnapshotGlobalActiveStakeAmountNanos: UTXO VIEW UTILS
//

func (bav *UtxoView) GetSnapshotGlobalActiveStakeAmountNanos(epochNumber uint64) (*uint256.Int, error) {
	// Check the UtxoView first.
	if globalActiveStakeAmountNanos, exists := bav.SnapshotGlobalActiveStakeAmountNanos[epochNumber]; exists {
		return globalActiveStakeAmountNanos, nil
	}
	// If we don't have it in the UtxoView, check the db.
	globalActiveStakeAmountNanos, err := DBGetSnapshotGlobalActiveStakeAmountNanos(bav.Handle, bav.Snapshot, epochNumber)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetSnapshotGlobalActiveStakeAmountNanos: problem retrieving SnapshotGlobalActiveStakeAmountNanos from db: ")
	}
	if globalActiveStakeAmountNanos != nil {
		// Cache the result in the UtxoView.
		bav.SnapshotGlobalActiveStakeAmountNanos[epochNumber] = globalActiveStakeAmountNanos
	}
	return globalActiveStakeAmountNanos, nil
}

func (bav *UtxoView) _setSnapshotGlobalActiveStakeAmountNanos(globalActiveStakeAmountNanos *uint256.Int, epochNumber uint64) {
	if globalActiveStakeAmountNanos == nil {
		glog.Errorf("UtxoView._setSnapshotGlobalActiveStakeAmountNanos: called with nil entry, this should never happen")
	}
	bav.SnapshotGlobalActiveStakeAmountNanos[epochNumber] = globalActiveStakeAmountNanos.Clone()
}

func (bav *UtxoView) _flushSnapshotGlobalActiveStakeAmountNanosToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	for epochNumber, globalActiveStakeAmountNanos := range bav.SnapshotGlobalActiveStakeAmountNanos {
		if globalActiveStakeAmountNanos == nil {
			return fmt.Errorf("UtxoView._flushSnapshotGlobalActiveStakeAmountNanosToDbWithTxn: found nil entry for epochNumber %d, this should never happen", epochNumber)
		}
		if err := DBPutSnapshotGlobalActiveStakeAmountNanosWithTxn(txn, bav.Snapshot, globalActiveStakeAmountNanos, epochNumber, blockHeight); err != nil {
			return errors.Wrapf(err, "UtxoView._flushSnapshotGlobalActiveStakeAmountNanosToDbWithTxn: problem setting SnapshotGlobalActiveStakeAmountNanos for epochNumber %d: ", epochNumber)
		}
	}
	return nil
}

//
// SnapshotGlobalActiveStakeAmountNanos: DB UTILS
//

func DBKeyForSnapshotGlobalActiveStakeAmountNanos(epochNumber uint64) []byte {
	data := append([]byte{}, Prefixes.PrefixSnapshotGlobalActiveStakeAmountNanos...)
	data = append(data, UintToBuf(epochNumber)...)
	return data
}

func DBGetSnapshotGlobalActiveStakeAmountNanos(handle *badger.DB, snap *Snapshot, epochNumber uint64) (*uint256.Int, error) {
	var ret *uint256.Int
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetSnapshotGlobalActiveStakeAmountNanosWithTxn(txn, snap, epochNumber)
		return innerErr
	})
	return ret, err
}

func DBGetSnapshotGlobalActiveStakeAmountNanosWithTxn(txn *badger.Txn, snap *Snapshot, epochNumber uint64) (*uint256.Int, error) {
	// Retrieve from db.
	key := DBKeyForSnapshotGlobalActiveStakeAmountNanos(epochNumber)
	globalActiveStakeAmountNanosBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return 0.
		if err == badger.ErrKeyNotFound {
			return uint256.NewInt(), nil
		}
		return nil, errors.Wrapf(err, "DBGetSnapshotGlobalActiveStakeAmountNanosWithTxn: problem retrieving value")
	}

	// Decode from bytes.
	var globalActiveStakeAmountNanos *uint256.Int
	rr := bytes.NewReader(globalActiveStakeAmountNanosBytes)
	globalActiveStakeAmountNanos, err = VariableDecodeUint256(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetSnapshotGlobalActiveStakeAmountNanosWithTxn: problem decoding value")
	}
	return globalActiveStakeAmountNanos, nil
}

func DBPutSnapshotGlobalActiveStakeAmountNanosWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	globalActiveStakeAmountNanos *uint256.Int,
	epochNumber uint64,
	blockHeight uint64,
) error {
	if globalActiveStakeAmountNanos == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutSnapshotGlobalActiveStakeAmountNanosWithTxn: called with nil GlobalActiveStakeAmountNanos")
		return nil
	}
	key := DBKeyForSnapshotGlobalActiveStakeAmountNanos(epochNumber)
	return DBSetWithTxn(txn, snap, key, VariableEncodeUint256(globalActiveStakeAmountNanos))
}
