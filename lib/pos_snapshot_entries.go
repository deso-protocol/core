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
// SnapshotGlobalParamsEntry
//

func (bav *UtxoView) GetSnapshotGlobalParamsEntry(epochNumber uint64) (*GlobalParamsEntry, error) {
	// Check the UtxoView first.
	if globalParamsEntry, exists := bav.SnapshotGlobalParamsEntries[epochNumber]; exists {
		return globalParamsEntry, nil
	}
	// If we don't have it in the UtxoView, check the db.
	globalParamsEntry, err := DBGetSnapshotGlobalParamsEntry(bav.Handle, bav.Snapshot, epochNumber)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetSnapshotGlobalParamsEntry: problem retrieving SnapshotGlobalParamsEntry from db: ")
	}
	if globalParamsEntry != nil {
		// Cache the result in the UtxoView.
		bav._setSnapshotGlobalParamsEntry(globalParamsEntry, epochNumber)
	}
	return globalParamsEntry, nil
}

func (bav *UtxoView) _setSnapshotGlobalParamsEntry(globalParamsEntry *GlobalParamsEntry, epochNumber uint64) {
	if globalParamsEntry == nil {
		glog.Errorf("UtxoView._setSnapshotGlobalParamsEntry: called with nil entry, this should never happen")
	}
	bav.SnapshotGlobalParamsEntries[epochNumber] = globalParamsEntry.Copy()
}

func (bav *UtxoView) _flushSnapshotGlobalParamsEntryToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	for epochNumber, globalParamsEntry := range bav.SnapshotGlobalParamsEntries {
		if globalParamsEntry == nil {
			return fmt.Errorf("UtxoView._flushSnapshotGlobalParamsEntryToDbWithTxn: found nil entry for epochNumber %d, this should never happen", epochNumber)
		}
		if err := DBPutSnapshotGlobalParamsEntryWithTxn(txn, bav.Snapshot, globalParamsEntry, epochNumber, blockHeight); err != nil {
			return errors.Wrapf(err, "UtxoView._flushSnapshotGlobalParamsEntryToDbWithTxn: problem setting SnapshotGlobalParamsEntry for epochNumber %d: ", epochNumber)
		}
	}
	return nil
}

func DBKeyForSnapshotGlobalParamsEntry(epochNumber uint64) []byte {
	data := append([]byte{}, Prefixes.PrefixSnapshotGlobalParamsEntryByEpochNumber...)
	data = append(data, UintToBuf(epochNumber)...)
	return data
}

func DBGetSnapshotGlobalParamsEntry(handle *badger.DB, snap *Snapshot, epochNumber uint64) (*GlobalParamsEntry, error) {
	var ret *GlobalParamsEntry
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetSnapshotGlobalParamsEntryWithTxn(txn, snap, epochNumber)
		return innerErr
	})
	return ret, err
}

func DBGetSnapshotGlobalParamsEntryWithTxn(txn *badger.Txn, snap *Snapshot, epochNumber uint64) (*GlobalParamsEntry, error) {
	// Retrieve from db.
	key := DBKeyForSnapshotGlobalParamsEntry(epochNumber)
	globalParamsEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return nil.
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "DBGetSnapshotGlobalParamsEntryWithTxn: problem retrieving value")
	}

	// Decode from bytes.
	globalParamsEntry := &GlobalParamsEntry{}
	rr := bytes.NewReader(globalParamsEntryBytes)
	if exist, err := DecodeFromBytes(globalParamsEntry, rr); !exist || err != nil {
		return nil, errors.Wrapf(err, "DBGetSnapshotGlobalParamsEntryWithTxn: problem decoding GlobalParamsEntry: ")
	}
	return globalParamsEntry, nil
}

func DBPutSnapshotGlobalParamsEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	globalParamsEntry *GlobalParamsEntry,
	epochNumber uint64,
	blockHeight uint64,
) error {
	if globalParamsEntry == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutSnapshotGlobalParamsEntryWithTxn: called with nil GlobalParamsEntry, this should never happen")
		return nil
	}
	key := DBKeyForSnapshotGlobalParamsEntry(epochNumber)
	return DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, globalParamsEntry))
}

//
// SnapshotGlobalActiveStakeAmountNanos
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
		bav._setSnapshotGlobalActiveStakeAmountNanos(globalActiveStakeAmountNanos, epochNumber)
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

func DBKeyForSnapshotGlobalActiveStakeAmountNanos(epochNumber uint64) []byte {
	data := append([]byte{}, Prefixes.PrefixSnapshotGlobalActiveStakeAmountNanosByEpochNumber...)
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
		glog.Errorf("DBPutSnapshotGlobalActiveStakeAmountNanosWithTxn: called with nil GlobalActiveStakeAmountNanos, this should never happen")
		return nil
	}
	key := DBKeyForSnapshotGlobalActiveStakeAmountNanos(epochNumber)
	return DBSetWithTxn(txn, snap, key, VariableEncodeUint256(globalActiveStakeAmountNanos))
}
