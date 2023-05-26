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
	key := append([]byte{}, Prefixes.PrefixSnapshotGlobalParamsEntryByEpochNumber...)
	key = append(key, UintToBuf(epochNumber)...)
	return key
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
// SnapshotValidatorEntry
//

type SnapshotValidatorMapKey struct {
	EpochNumber   uint64
	ValidatorPKID PKID
}

func (bav *UtxoView) SnapshotCurrentValidators(epochNumber uint64) error {
	// First, snapshot any !isDeleted ValidatorEntries in the UtxoView.
	var utxoViewValidatorPKIDs []*PKID
	for _, validatorEntry := range bav.ValidatorPKIDToValidatorEntry {
		if !validatorEntry.isDeleted {
			// We only want to snapshot !isDeleted ValidatorEntries.
			bav._setSnapshotValidatorEntry(validatorEntry, epochNumber)
		}
		// We don't want to retrieve any ValidatorEntries from the db that are present in the UtxoView.
		utxoViewValidatorPKIDs = append(utxoViewValidatorPKIDs, validatorEntry.ValidatorPKID)
	}
	// Second, snapshot the ValidatorEntries in the db (skipping any in the UtxoView).
	dbValidatorEntries, err := DBEnumerateAllCurrentValidators(bav.Handle, utxoViewValidatorPKIDs)
	if err != nil {
		return errors.Wrapf(err, "UtxoView.SnapshotValidators: problem retrieving ValidatorEntries: ")
	}
	for _, validatorEntry := range dbValidatorEntries {
		bav._setSnapshotValidatorEntry(validatorEntry, epochNumber)
	}
	return nil
}

func (bav *UtxoView) GetSnapshotValidatorByPKID(pkid *PKID, epochNumber uint64) (*ValidatorEntry, error) {
	// Check the UtxoView first.
	mapKey := SnapshotValidatorMapKey{EpochNumber: epochNumber, ValidatorPKID: *pkid}
	if validatorEntry, exists := bav.SnapshotValidatorEntries[mapKey]; exists {
		return validatorEntry, nil
	}
	// If we don't have it in the UtxoView, check the db.
	validatorEntry, err := DBGetSnapshotValidatorByPKID(bav.Handle, bav.Snapshot, pkid, epochNumber)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetSnapshotValidatorByPKID: problem retrieving ValidatorEntry from db: ")
	}
	if validatorEntry != nil {
		// Cache the result in the UtxoView.
		bav._setSnapshotValidatorEntry(validatorEntry, epochNumber)
	}
	return validatorEntry, nil
}

func (bav *UtxoView) GetSnapshotTopActiveValidatorsByStake(epochNumber uint64) (*ValidatorEntry, error) {
	// TODO
	return nil, nil
}

func (bav *UtxoView) _setSnapshotValidatorEntry(validatorEntry *ValidatorEntry, epochNumber uint64) {
	if validatorEntry == nil {
		glog.Errorf("UtxoView._setSnapshotValidatorEntry: called with nil entry, this should never happen")
		return
	}
	mapKey := SnapshotValidatorMapKey{EpochNumber: epochNumber, ValidatorPKID: *validatorEntry.ValidatorPKID}
	bav.SnapshotValidatorEntries[mapKey] = validatorEntry.Copy()
}

func (bav *UtxoView) _flushSnapshotValidatorEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	for mapKey, validatorEntry := range bav.SnapshotValidatorEntries {
		if validatorEntry == nil {
			return fmt.Errorf(
				"UtxoView._flushSnapshotValidatorEntriesToDbWithTxn: found nil entry for epochNumber %d, this should never happen",
				mapKey.EpochNumber,
			)
		}
		if err := DBPutSnapshotValidatorEntryWithTxn(txn, bav.Snapshot, validatorEntry, mapKey.EpochNumber, blockHeight); err != nil {
			return errors.Wrapf(
				err,
				"UtxoView._flushSnapshotValidatorEntryToDbWithTxn: problem setting ValidatorEntry for epochNumber %d: ",
				mapKey.EpochNumber,
			)
		}
	}
	return nil
}

func DBKeyForSnapshotValidatorByPKID(validatorEntry *ValidatorEntry, epochNumber uint64) []byte {
	key := append([]byte{}, Prefixes.PrefixSnapshotValidatorByEpochNumberAndPKID...)
	key = append(key, UintToBuf(epochNumber)...)
	key = append(key, validatorEntry.ValidatorPKID.ToBytes()...)
	return key
}

func DBKeyForSnapshotValidatorByStake(validatorEntry *ValidatorEntry, epochNumber uint64) []byte {
	key := append([]byte{}, Prefixes.PrefixSnapshotValidatorByEpochNumberAndStake...)
	key = append(key, UintToBuf(epochNumber)...)
	key = append(key, EncodeUint8(uint8(validatorEntry.Status()))...)
	key = append(key, FixedWidthEncodeUint256(validatorEntry.TotalStakeAmountNanos)...)
	key = append(key, validatorEntry.ValidatorPKID.ToBytes()...)
	return key
}

func DBGetSnapshotValidatorByPKID(handle *badger.DB, snap *Snapshot, pkid *PKID, epochNumber uint64) (*ValidatorEntry, error) {
	var ret *ValidatorEntry
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetSnapshotValidatorByPKIDWithTxn(txn, snap, pkid, epochNumber)
		return innerErr
	})
	return ret, err
}

func DBGetSnapshotValidatorByPKIDWithTxn(txn *badger.Txn, snap *Snapshot, pkid *PKID, epochNumber uint64) (*ValidatorEntry, error) {
	// Retrieve ValidatorEntry from db.
	key := DBKeyForSnapshotValidatorByPKID(&ValidatorEntry{ValidatorPKID: pkid}, epochNumber)
	validatorBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return nil.
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "DBGetSnapshotValidatorByPKID: problem retrieving ValidatorEntry")
	}

	// Decode ValidatorEntry from bytes.
	validatorEntry := &ValidatorEntry{}
	rr := bytes.NewReader(validatorBytes)
	if exist, err := DecodeFromBytes(validatorEntry, rr); !exist || err != nil {
		return nil, errors.Wrapf(err, "DBGetSnapshotValidatorByPKID: problem decoding ValidatorEntry")
	}
	return validatorEntry, nil
}

func DBPutSnapshotValidatorEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	validatorEntry *ValidatorEntry,
	epochNumber uint64,
	blockHeight uint64,
) error {
	if validatorEntry == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutSnapshotValidatorEntryWithTxn: called with nil ValidatorEntry, this should never happen")
		return nil
	}

	// Put the ValidatorEntry in the SnapshotValidatorByPKID index.
	key := DBKeyForSnapshotValidatorByPKID(validatorEntry, epochNumber)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, validatorEntry)); err != nil {
		return errors.Wrapf(err, "DBPutSnapshotValidatorEntryWithTxn: problem putting ValidatorEntry in the SnapshotValidatorByPKID index: ")
	}

	// Put the ValidatorPKID in the SnapshotValidatorByStake index.
	key = DBKeyForSnapshotValidatorByStake(validatorEntry, epochNumber)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, validatorEntry.ValidatorPKID)); err != nil {
		return errors.Wrapf(err, "DBPutSnapshotValidatorEntryWithTxn: problem putting ValidatorPKID in the SnapshotValidatorByStake index: ")
	}

	return nil
}

func DBEnumerateAllCurrentValidators(handle *badger.DB, pkidsToSkip []*PKID) ([]*ValidatorEntry, error) {
	// Convert []*PKIDs of validators to skip to a Set[string] of db keys to skip.
	skipKeys := NewSet([]string{})
	for _, pkid := range pkidsToSkip {
		skipKeys.Add(string(DBKeyForValidatorByPKID(&ValidatorEntry{ValidatorPKID: pkid})))
	}
	// Retrieve all non-skipped validators.
	_, valsFound, err := EnumerateKeysForPrefixWithLimitOffsetOrder(
		handle, Prefixes.PrefixValidatorByPKID, 0, nil, false, skipKeys,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "DBEnumerateValidators: problem retrieving ValidatorEntries")
	}
	// Convert ValidatorEntryBytes to ValidatorEntries.
	var validatorEntries []*ValidatorEntry
	for _, validatorEntryBytes := range valsFound {
		validatorEntry := &ValidatorEntry{}
		rr := bytes.NewReader(validatorEntryBytes)
		if exist, err := DecodeFromBytes(validatorEntry, rr); !exist || err != nil {
			return nil, errors.Wrapf(err, "DBEnumerateValidators: problem decoding ValidatorEntry")
		}
		validatorEntries = append(validatorEntries, validatorEntry)
	}
	return validatorEntries, nil
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
	key := append([]byte{}, Prefixes.PrefixSnapshotGlobalActiveStakeAmountNanosByEpochNumber...)
	key = append(key, UintToBuf(epochNumber)...)
	return key
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
		// We don't want to error if the key isn't found. Instead, return nil.
		if err == badger.ErrKeyNotFound {
			return nil, nil
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
