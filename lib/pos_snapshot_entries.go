package lib

import (
	"bytes"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"math"
	"sort"
)

//
// SnapshotGlobalParamsEntry
//

func (bav *UtxoView) GetSnapshotGlobalParamsEntry(snapshotAtEpochNumber uint64) (*GlobalParamsEntry, error) {
	// Check the UtxoView first.
	if globalParamsEntry, exists := bav.SnapshotGlobalParamsEntries[snapshotAtEpochNumber]; exists {
		return globalParamsEntry, nil
	}
	// If we don't have it in the UtxoView, check the db.
	globalParamsEntry, err := DBGetSnapshotGlobalParamsEntry(bav.Handle, bav.Snapshot, snapshotAtEpochNumber)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"GetSnapshotGlobalParamsEntry: problem retrieving SnapshotGlobalParamsEntry from db: ",
		)
	}
	if globalParamsEntry != nil {
		// Cache the result in the UtxoView.
		bav._setSnapshotGlobalParamsEntry(globalParamsEntry, snapshotAtEpochNumber)
	}
	return globalParamsEntry, nil
}

func (bav *UtxoView) _setSnapshotGlobalParamsEntry(globalParamsEntry *GlobalParamsEntry, snapshotAtEpochNumber uint64) {
	if globalParamsEntry == nil {
		glog.Errorf("_setSnapshotGlobalParamsEntry: called with nil entry, this should never happen")
	}
	bav.SnapshotGlobalParamsEntries[snapshotAtEpochNumber] = globalParamsEntry.Copy()
}

func (bav *UtxoView) _flushSnapshotGlobalParamsEntryToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	for snapshotAtEpochNumber, globalParamsEntry := range bav.SnapshotGlobalParamsEntries {
		if globalParamsEntry == nil {
			return fmt.Errorf(
				"_flushSnapshotGlobalParamsEntryToDbWithTxn: found nil entry for SnapshotAtEpochNumber %d, this should never happen",
				snapshotAtEpochNumber,
			)
		}
		if err := DBPutSnapshotGlobalParamsEntryWithTxn(
			txn, bav.Snapshot, globalParamsEntry, snapshotAtEpochNumber, blockHeight,
		); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotGlobalParamsEntryToDbWithTxn: problem setting SnapshotGlobalParamsEntry for SnapshotAtEpochNumber %d: ",
				snapshotAtEpochNumber,
			)
		}
	}
	return nil
}

func DBKeyForSnapshotGlobalParamsEntry(snapshotEpochNumber uint64) []byte {
	key := append([]byte{}, Prefixes.PrefixSnapshotGlobalParamsEntry...)
	key = append(key, UintToBuf(snapshotEpochNumber)...)
	return key
}

func DBGetSnapshotGlobalParamsEntry(handle *badger.DB, snap *Snapshot, snapshotAtEpochNumber uint64) (*GlobalParamsEntry, error) {
	var ret *GlobalParamsEntry
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetSnapshotGlobalParamsEntryWithTxn(txn, snap, snapshotAtEpochNumber)
		return innerErr
	})
	return ret, err
}

func DBGetSnapshotGlobalParamsEntryWithTxn(txn *badger.Txn, snap *Snapshot, snapshotAtEpochNumber uint64) (*GlobalParamsEntry, error) {
	// Retrieve from db.
	key := DBKeyForSnapshotGlobalParamsEntry(snapshotAtEpochNumber)
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
	snapshotAtEpochNumber uint64,
	blockHeight uint64,
) error {
	if globalParamsEntry == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutSnapshotGlobalParamsEntryWithTxn: called with nil GlobalParamsEntry, this should never happen")
		return nil
	}
	key := DBKeyForSnapshotGlobalParamsEntry(snapshotAtEpochNumber)
	return DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, globalParamsEntry))
}

//
// SnapshotValidatorEntry
//

type SnapshotValidatorMapKey struct {
	EpochNumber   uint64
	ValidatorPKID PKID
}

func (bav *UtxoView) SnapshotCurrentValidators(snapshotAtEpochNumber uint64) error {
	// First, snapshot any !isDeleted ValidatorEntries in the UtxoView.
	var utxoViewValidatorPKIDs []*PKID
	for _, validatorEntry := range bav.ValidatorPKIDToValidatorEntry {
		if !validatorEntry.isDeleted {
			// We only want to snapshot !isDeleted ValidatorEntries.
			bav._setSnapshotValidatorEntry(validatorEntry, snapshotAtEpochNumber)
		}
		// We don't want to retrieve any ValidatorEntries from the db that are present in the UtxoView.
		utxoViewValidatorPKIDs = append(utxoViewValidatorPKIDs, validatorEntry.ValidatorPKID)
	}
	// Second, snapshot the ValidatorEntries in the db (skipping any in the UtxoView).
	dbValidatorEntries, err := DBEnumerateAllCurrentValidators(bav.Handle, utxoViewValidatorPKIDs)
	if err != nil {
		return errors.Wrapf(err, "SnapshotValidators: problem retrieving ValidatorEntries: ")
	}
	for _, validatorEntry := range dbValidatorEntries {
		bav._setSnapshotValidatorEntry(validatorEntry, snapshotAtEpochNumber)
	}
	return nil
}

func (bav *UtxoView) GetSnapshotValidatorByPKID(pkid *PKID, snapshotAtEpochNumber uint64) (*ValidatorEntry, error) {
	// Check the UtxoView first.
	mapKey := SnapshotValidatorMapKey{EpochNumber: snapshotAtEpochNumber, ValidatorPKID: *pkid}
	if validatorEntry, exists := bav.SnapshotValidatorEntries[mapKey]; exists {
		return validatorEntry, nil
	}
	// If we don't have it in the UtxoView, check the db.
	validatorEntry, err := DBGetSnapshotValidatorByPKID(bav.Handle, bav.Snapshot, pkid, snapshotAtEpochNumber)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"GetSnapshotValidatorByPKID: problem retrieving ValidatorEntry from db: ",
		)
	}
	if validatorEntry != nil {
		// Cache the result in the UtxoView.
		bav._setSnapshotValidatorEntry(validatorEntry, snapshotAtEpochNumber)
	}
	return validatorEntry, nil
}

func (bav *UtxoView) GetSnapshotTopActiveValidatorsByStake(limit uint64, snapshotAtEpochNumber uint64) ([]*ValidatorEntry, error) {
	var utxoViewValidatorEntries []*ValidatorEntry
	for mapKey, validatorEntry := range bav.SnapshotValidatorEntries {
		if mapKey.EpochNumber == snapshotAtEpochNumber {
			utxoViewValidatorEntries = append(utxoViewValidatorEntries, validatorEntry)
		}
	}
	// Pull top N active ValidatorEntries from the database (not present in the UtxoView).
	// Note that we will skip validators that are present in the view because we pass
	// utxoViewValidatorEntries to the function.
	dbValidatorEntries, err := DBGetSnapshotTopActiveValidatorsByStake(
		bav.Handle, bav.Snapshot, limit, snapshotAtEpochNumber, utxoViewValidatorEntries,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "GetSnapshotTopActiveValidatorsByStake: error retrieving entries from db: ")
	}
	// Cache top N active ValidatorEntries from the db in the UtxoView.
	for _, validatorEntry := range dbValidatorEntries {
		// We only pull ValidatorEntries from the db that are not present in the
		// UtxoView. As a sanity check, we double-check that the ValidatorEntry
		// is not already in the UtxoView here.
		mapKey := SnapshotValidatorMapKey{EpochNumber: snapshotAtEpochNumber, ValidatorPKID: *validatorEntry.ValidatorPKID}
		if _, exists := bav.SnapshotValidatorEntries[mapKey]; !exists {
			bav._setValidatorEntryMappings(validatorEntry)
		}
	}
	// Pull !isDeleted, active ValidatorEntries from the UtxoView with stake > 0.
	var validatorEntries []*ValidatorEntry
	for mapKey, validatorEntry := range bav.SnapshotValidatorEntries {
		if mapKey.EpochNumber == snapshotAtEpochNumber &&
			!validatorEntry.isDeleted &&
			validatorEntry.Status() == ValidatorStatusActive &&
			!validatorEntry.TotalStakeAmountNanos.IsZero() {
			validatorEntries = append(validatorEntries, validatorEntry)
		}
	}
	// Sort the ValidatorEntries DESC by TotalStakeAmountNanos.
	sort.Slice(validatorEntries, func(ii, jj int) bool {
		return validatorEntries[ii].TotalStakeAmountNanos.Cmp(validatorEntries[jj].TotalStakeAmountNanos) > 0
	})
	// Return top N.
	upperBound := int(math.Min(float64(limit), float64(len(validatorEntries))))
	return validatorEntries[0:upperBound], nil
}

func (bav *UtxoView) _setSnapshotValidatorEntry(validatorEntry *ValidatorEntry, snapshotAtEpochNumber uint64) {
	if validatorEntry == nil {
		glog.Errorf("_setSnapshotValidatorEntry: called with nil entry, this should never happen")
		return
	}
	mapKey := SnapshotValidatorMapKey{EpochNumber: snapshotAtEpochNumber, ValidatorPKID: *validatorEntry.ValidatorPKID}
	bav.SnapshotValidatorEntries[mapKey] = validatorEntry.Copy()
}

func (bav *UtxoView) _flushSnapshotValidatorEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	for mapKey, validatorEntry := range bav.SnapshotValidatorEntries {
		if validatorEntry == nil {
			return fmt.Errorf(
				"_flushSnapshotValidatorEntriesToDbWithTxn: found nil entry for SnapshotAtEpochNumber %d, this should never happen",
				mapKey.EpochNumber,
			)
		}
		if err := DBPutSnapshotValidatorEntryWithTxn(txn, bav.Snapshot, validatorEntry, mapKey.EpochNumber, blockHeight); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotValidatorEntryToDbWithTxn: problem setting ValidatorEntry for SnapshotAtEpochNumber %d: ",
				mapKey.EpochNumber,
			)
		}
	}
	return nil
}

func DBKeyForSnapshotValidatorByPKID(validatorEntry *ValidatorEntry, snapshotAtEpochNumber uint64) []byte {
	key := append([]byte{}, Prefixes.PrefixSnapshotValidatorByPKID...)
	key = append(key, UintToBuf(snapshotAtEpochNumber)...)
	key = append(key, validatorEntry.ValidatorPKID.ToBytes()...)
	return key
}

func DBKeyForSnapshotValidatorByStake(validatorEntry *ValidatorEntry, snapshotAtEpochNumber uint64) []byte {
	key := append([]byte{}, Prefixes.PrefixSnapshotValidatorByStake...)
	key = append(key, UintToBuf(snapshotAtEpochNumber)...)
	key = append(key, EncodeUint8(uint8(validatorEntry.Status()))...)
	key = append(key, FixedWidthEncodeUint256(validatorEntry.TotalStakeAmountNanos)...)
	key = append(key, validatorEntry.ValidatorPKID.ToBytes()...)
	return key
}

func DBGetSnapshotValidatorByPKID(handle *badger.DB, snap *Snapshot, pkid *PKID, snapshotAtEpochNumber uint64) (*ValidatorEntry, error) {
	var ret *ValidatorEntry
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetSnapshotValidatorByPKIDWithTxn(txn, snap, pkid, snapshotAtEpochNumber)
		return innerErr
	})
	return ret, err
}

func DBGetSnapshotValidatorByPKIDWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	pkid *PKID,
	snapshotAtEpochNumber uint64,
) (*ValidatorEntry, error) {
	// Retrieve ValidatorEntry from db.
	key := DBKeyForSnapshotValidatorByPKID(&ValidatorEntry{ValidatorPKID: pkid}, snapshotAtEpochNumber)
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

func DBGetSnapshotTopActiveValidatorsByStake(
	handle *badger.DB,
	snap *Snapshot,
	limit uint64,
	snapshotAtEpochNumber uint64,
	validatorEntriesToSkip []*ValidatorEntry,
) ([]*ValidatorEntry, error) {
	var validatorEntries []*ValidatorEntry

	// Convert ValidatorEntriesToSkip to ValidatorEntryKeysToSkip.
	validatorKeysToSkip := NewSet([]string{})
	for _, validatorEntryToSkip := range validatorEntriesToSkip {
		validatorKeysToSkip.Add(string(DBKeyForSnapshotValidatorByStake(validatorEntryToSkip, snapshotAtEpochNumber)))
	}

	// Retrieve top N active ValidatorEntry keys by stake.
	key := append([]byte{}, Prefixes.PrefixSnapshotValidatorByStake...)
	key = append(key, UintToBuf(snapshotAtEpochNumber)...)
	key = append(key, EncodeUint8(uint8(ValidatorStatusActive))...)
	keysFound, _, err := EnumerateKeysForPrefixWithLimitOffsetOrder(
		handle, key, int(limit), nil, true, validatorKeysToSkip,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetSnapshotTopActiveValidatorsByStake: problem retrieving top validators: ")
	}

	// For each key found, parse the ValidatorPKID from the key,
	// then retrieve the ValidatorEntry by the ValidatorPKID.
	for _, keyFound := range keysFound {
		// Parse the PKIDBytes from the key. The ValidatorPKID is the last component of the key.
		validatorPKIDBytes := keyFound[len(keyFound)-PublicKeyLenCompressed:]
		// Convert PKIDBytes to PKID.
		validatorPKID := &PKID{}
		if err = validatorPKID.FromBytes(bytes.NewReader(validatorPKIDBytes)); err != nil {
			return nil, errors.Wrapf(err, "DBGetSnapshotTopActiveValidatorsByStake: problem reading ValidatorPKID: ")
		}
		// Retrieve ValidatorEntry by PKID.
		validatorEntry, err := DBGetSnapshotValidatorByPKID(handle, snap, validatorPKID, snapshotAtEpochNumber)
		if err != nil {
			return nil, errors.Wrapf(err, "DBGetSnapshotTopActiveValidatorsByStake: problem retrieving validator by PKID: ")
		}
		validatorEntries = append(validatorEntries, validatorEntry)
	}

	return validatorEntries, nil
}

func DBPutSnapshotValidatorEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	validatorEntry *ValidatorEntry,
	snapshotAtEpochNumber uint64,
	blockHeight uint64,
) error {
	if validatorEntry == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutSnapshotValidatorEntryWithTxn: called with nil ValidatorEntry, this should never happen")
		return nil
	}

	// Put the ValidatorEntry in the SnapshotValidatorByPKID index.
	key := DBKeyForSnapshotValidatorByPKID(validatorEntry, snapshotAtEpochNumber)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, validatorEntry)); err != nil {
		return errors.Wrapf(
			err,
			"DBPutSnapshotValidatorEntryWithTxn: problem putting ValidatorEntry in the SnapshotValidatorByPKID index: ",
		)
	}

	// Put the ValidatorPKID in the SnapshotValidatorByStake index.
	key = DBKeyForSnapshotValidatorByStake(validatorEntry, snapshotAtEpochNumber)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, validatorEntry.ValidatorPKID)); err != nil {
		return errors.Wrapf(
			err,
			"DBPutSnapshotValidatorEntryWithTxn: problem putting ValidatorPKID in the SnapshotValidatorByStake index: ",
		)
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

func (bav *UtxoView) GetSnapshotGlobalActiveStakeAmountNanos(snapshotAtEpochNumber uint64) (*uint256.Int, error) {
	// Check the UtxoView first.
	if globalActiveStakeAmountNanos, exists := bav.SnapshotGlobalActiveStakeAmountNanos[snapshotAtEpochNumber]; exists {
		return globalActiveStakeAmountNanos, nil
	}
	// If we don't have it in the UtxoView, check the db.
	globalActiveStakeAmountNanos, err := DBGetSnapshotGlobalActiveStakeAmountNanos(bav.Handle, bav.Snapshot, snapshotAtEpochNumber)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"GetSnapshotGlobalActiveStakeAmountNanos: problem retrieving SnapshotGlobalActiveStakeAmountNanos from db: ",
		)
	}
	if globalActiveStakeAmountNanos != nil {
		// Cache the result in the UtxoView.
		bav._setSnapshotGlobalActiveStakeAmountNanos(globalActiveStakeAmountNanos, snapshotAtEpochNumber)
	}
	return globalActiveStakeAmountNanos, nil
}

func (bav *UtxoView) _setSnapshotGlobalActiveStakeAmountNanos(globalActiveStakeAmountNanos *uint256.Int, snapshotAtEpochNumber uint64) {
	if globalActiveStakeAmountNanos == nil {
		glog.Errorf("_setSnapshotGlobalActiveStakeAmountNanos: called with nil entry, this should never happen")
	}
	bav.SnapshotGlobalActiveStakeAmountNanos[snapshotAtEpochNumber] = globalActiveStakeAmountNanos.Clone()
}

func (bav *UtxoView) _flushSnapshotGlobalActiveStakeAmountNanosToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	for snapshotAtEpochNumber, globalActiveStakeAmountNanos := range bav.SnapshotGlobalActiveStakeAmountNanos {
		if globalActiveStakeAmountNanos == nil {
			return fmt.Errorf(
				"_flushSnapshotGlobalActiveStakeAmountNanosToDbWithTxn: found nil entry for SnapshotAtEpochNumber %d, this should never happen",
				snapshotAtEpochNumber,
			)
		}
		if err := DBPutSnapshotGlobalActiveStakeAmountNanosWithTxn(
			txn, bav.Snapshot, globalActiveStakeAmountNanos, snapshotAtEpochNumber, blockHeight,
		); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotGlobalActiveStakeAmountNanosToDbWithTxn: problem setting SnapshotGlobalActiveStakeAmountNanos for SnapshotAtEpochNumber %d: ",
				snapshotAtEpochNumber,
			)
		}
	}
	return nil
}

func DBKeyForSnapshotGlobalActiveStakeAmountNanos(snapshotAtEpochNumber uint64) []byte {
	key := append([]byte{}, Prefixes.PrefixSnapshotGlobalActiveStakeAmountNanos...)
	key = append(key, UintToBuf(snapshotAtEpochNumber)...)
	return key
}

func DBGetSnapshotGlobalActiveStakeAmountNanos(handle *badger.DB, snap *Snapshot, snapshotAtEpochNumber uint64) (*uint256.Int, error) {
	var ret *uint256.Int
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetSnapshotGlobalActiveStakeAmountNanosWithTxn(txn, snap, snapshotAtEpochNumber)
		return innerErr
	})
	return ret, err
}

func DBGetSnapshotGlobalActiveStakeAmountNanosWithTxn(txn *badger.Txn, snap *Snapshot, snapshotAtEpochNumber uint64) (*uint256.Int, error) {
	// Retrieve from db.
	key := DBKeyForSnapshotGlobalActiveStakeAmountNanos(snapshotAtEpochNumber)
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
	snapshotAtEpochNumber uint64,
	blockHeight uint64,
) error {
	if globalActiveStakeAmountNanos == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutSnapshotGlobalActiveStakeAmountNanosWithTxn: called with nil GlobalActiveStakeAmountNanos, this should never happen")
		return nil
	}
	key := DBKeyForSnapshotGlobalActiveStakeAmountNanos(snapshotAtEpochNumber)
	return DBSetWithTxn(txn, snap, key, VariableEncodeUint256(globalActiveStakeAmountNanos))
}

//
// SnapshotLeaderScheduleValidator
//

type SnapshotLeaderScheduleMapKey struct {
	SnapshotAtEpochNumber uint64
	LeaderIndex           uint8
}

func (bav *UtxoView) GetSnapshotLeaderScheduleValidator(leaderIndex uint8, snapshotAtEpochNumber uint64) (*ValidatorEntry, error) {
	// First, check the UtxoView.
	mapKey := SnapshotLeaderScheduleMapKey{SnapshotAtEpochNumber: snapshotAtEpochNumber, LeaderIndex: leaderIndex}
	if validatorPKID, exists := bav.SnapshotLeaderSchedule[mapKey]; exists {
		return bav.GetSnapshotValidatorByPKID(validatorPKID, snapshotAtEpochNumber)
	}
	// Next, check the db.
	validatorEntry, err := DBGetSnapshotLeaderScheduleValidator(bav.Handle, bav.Snapshot, leaderIndex, snapshotAtEpochNumber)
	if err != nil {
		return nil, errors.Wrapf(err, "GetSnapshotLeaderScheduleValidator: error retrieving ValidatorPKID: ")
	}
	if validatorEntry != nil {
		// Cache the ValidatorPKID in the UtxoView.
		bav._setSnapshotLeaderScheduleValidator(validatorEntry.ValidatorPKID, leaderIndex, snapshotAtEpochNumber)
	}
	return validatorEntry, nil
}

func (bav *UtxoView) _setSnapshotLeaderScheduleValidator(validatorPKID *PKID, index uint8, snapshotAtEpochNumber uint64) {
	if validatorPKID == nil {
		glog.Errorf("_setSnapshotLeaderScheduleValidator: called with nil ValidatorPKID, this should never happen")
		return
	}
	mapKey := SnapshotLeaderScheduleMapKey{SnapshotAtEpochNumber: snapshotAtEpochNumber, LeaderIndex: index}
	bav.SnapshotLeaderSchedule[mapKey] = validatorPKID.NewPKID()
}

func (bav *UtxoView) _flushSnapshotLeaderScheduleToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	for mapKey, validatorPKID := range bav.SnapshotLeaderSchedule {
		if validatorPKID == nil {
			return fmt.Errorf(
				"_flushSnapshotLeaderScheduleToDbWithTxn: found nil PKID for SnapshotAtEpochNumber %d, this should never happen",
				mapKey.SnapshotAtEpochNumber,
			)
		}
		if err := DBPutSnapshotLeaderScheduleValidatorWithTxn(
			txn, bav.Snapshot, validatorPKID, mapKey.LeaderIndex, mapKey.SnapshotAtEpochNumber, blockHeight,
		); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotLeaderScheduleToDbWithTxn: problem setting ValidatorPKID for SnapshotAtEpochNumber %d: ",
				mapKey.SnapshotAtEpochNumber,
			)
		}
	}
	return nil
}

func DBKeyForSnapshotLeaderScheduleValidator(leaderIndex uint8, snapshotAtEpochNumber uint64) []byte {
	data := append([]byte{}, Prefixes.PrefixSnapshotLeaderSchedule...)
	data = append(data, UintToBuf(snapshotAtEpochNumber)...)
	data = append(data, EncodeUint8(leaderIndex)...)
	return data
}

func DBGetSnapshotLeaderScheduleValidator(
	handle *badger.DB,
	snap *Snapshot,
	leaderIndex uint8,
	snapshotAtEpochNumber uint64,
) (*ValidatorEntry, error) {
	var ret *ValidatorEntry
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetSnapshotLeaderScheduleValidatorWithTxn(txn, snap, leaderIndex, snapshotAtEpochNumber)
		return innerErr
	})
	return ret, err
}

func DBGetSnapshotLeaderScheduleValidatorWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	leaderIndex uint8,
	snapshotAtEpochNumber uint64,
) (*ValidatorEntry, error) {
	// Retrieve ValidatorPKID from db.
	key := DBKeyForSnapshotLeaderScheduleValidator(leaderIndex, snapshotAtEpochNumber)
	validatorPKIDBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return nil.
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "DBGetSnapshotLeaderScheduleValidator: problem retrieving ValidatorPKID")
	}

	// Decode ValidatorPKID from bytes.
	validatorPKID := &PKID{}
	rr := bytes.NewReader(validatorPKIDBytes)
	if exist, err := DecodeFromBytes(validatorPKID, rr); !exist || err != nil {
		return nil, errors.Wrapf(err, "DBGetSnapshotLeaderScheduleValidator: problem decoding ValidatorPKID")
	}

	// Retrieve ValidatorEntry by PKID from db.
	return DBGetSnapshotValidatorByPKIDWithTxn(txn, snap, validatorPKID, snapshotAtEpochNumber)
}

func DBPutSnapshotLeaderScheduleValidatorWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	validatorPKID *PKID,
	leaderIndex uint8,
	snapshotAtEpochNumber uint64,
	blockHeight uint64,
) error {
	if validatorPKID == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutSnapshotLeaderScheduleValidatorWithTxn: called with nil ValidatorPKID, this should never happen")
		return nil
	}
	key := DBKeyForSnapshotLeaderScheduleValidator(leaderIndex, snapshotAtEpochNumber)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, validatorPKID)); err != nil {
		return errors.Wrapf(
			err,
			"DBPutSnapshotLeaderScheduleValidatorWithTxn: problem putting ValidatorPKID in the SnapshotLeaderSchedule index: ",
		)
	}
	return nil
}
