package lib

import (
	"bytes"
	"fmt"
	"math"
	"sort"

	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

const SnapshotLookbackNumEpochs uint64 = 2

func (bav *UtxoView) GetSnapshotEpochNumber() (uint64, error) {
	// Retrieve the CurrentEpochNumber.
	currentEpochNumber, err := bav.GetCurrentEpochNumber()
	if err != nil {
		return 0, errors.Wrapf(err, "GetSnapshotEpochNumber: problem retrieving CurrentEpochNumber: ")
	}
	if currentEpochNumber < SnapshotLookbackNumEpochs {
		// We want to return 0 in this case and not error. We start snapshotting with our StateSetup block height,
		// so we should have the correct number of snapshots and not hit this case once we hit the ConsensusCutover
		// block height. This case will only be hit immediately following the StateSetup block height. We run one
		// OnEpochCompleteHook right away on the StateSetup block height which will increment our CurrentEpochNumber
		// from zero (the starting default) to one. Then we wait one epoch and run our second OnEpochCompleteHook to
		// increment our CurrentEpochNumber from one to two. At this point, we will have the correct number of
		// snapshots and no longer hit this edge case.
		//
		// The problem is what about snapshot values we need to use in that first block where CurrentBlockHeight =
		// StateSetup block height and then the first epoch after that? The only snapshot values that we use relate
		// to our new PoS txn types. We pull the snapshot GlobalParamsEntry to retrieve the StakeLockupEpochDuration
		// and the ValidatorJailEpochDuration. Both of these impact the new PoS txn types which are unlocked after
		// the StateSetup block height. The ValidatorJailEpochDuration value doesn't really matter since no validators
		// will be jailed until the ConsensusCutover block height. For the StakeLockupEpochDuration (and all other
		// snapshot GlobalParamsEntry values), if there is no snapshot value, we return an empty GlobalParamsEntry with
		// just our defaults, which is what we intend. There's one other small edge case here which is if we update the
		// StakeLockupEpochDuration parameter within that first block (which would be weird and should not happen),
		// then that value will take immediate effect in the first epoch with no lagged snapshot wait period.
		return 0, nil
	}
	return SafeUint64().Sub(currentEpochNumber, SnapshotLookbackNumEpochs)
}

//
// SnapshotGlobalParamsEntry
//

func (bav *UtxoView) GetCurrentGlobalParamsEntry() *GlobalParamsEntry {
	return _mergeGlobalParamEntryDefaults(bav, bav.GlobalParamsEntry)
}

func (bav *UtxoView) GetSnapshotGlobalParamsEntry() (*GlobalParamsEntry, error) {
	// Calculate the SnapshotEpochNumber.
	snapshotAtEpochNumber, err := bav.GetSnapshotEpochNumber()
	if err != nil {
		return nil, errors.Wrapf(err, "GetSnapshotGlobalParamsEntry: problem calculating SnapshotEpochNumber: ")
	}
	// Check the UtxoView first.
	if globalParamsEntry, exists := bav.SnapshotGlobalParamEntries[snapshotAtEpochNumber]; exists {
		return _mergeGlobalParamEntryDefaults(bav, globalParamsEntry), nil
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
	return _mergeGlobalParamEntryDefaults(bav, globalParamsEntry), nil
}

func _mergeGlobalParamEntryDefaults(bav *UtxoView, globalParamsEntry *GlobalParamsEntry) *GlobalParamsEntry {
	// Merge the input GlobalParamsEntry with the default param values.
	if globalParamsEntry == nil {
		// This could happen before we have any SnapshotGlobalParamEntries set.
		// In this case, we fall back to all default values.
		globalParamsEntry = &GlobalParamsEntry{}
	}

	// Take a copy, so we don't modify the original.
	globalParamsEntryCopy := globalParamsEntry.Copy()

	// Merge the default values.
	if globalParamsEntryCopy.StakeLockupEpochDuration == 0 {
		globalParamsEntryCopy.StakeLockupEpochDuration = bav.Params.DefaultStakeLockupEpochDuration
	}
	if globalParamsEntryCopy.ValidatorJailEpochDuration == 0 {
		globalParamsEntryCopy.ValidatorJailEpochDuration = bav.Params.DefaultValidatorJailEpochDuration
	}
	if globalParamsEntryCopy.LeaderScheduleMaxNumValidators == 0 {
		globalParamsEntryCopy.LeaderScheduleMaxNumValidators = bav.Params.DefaultLeaderScheduleMaxNumValidators
	}
	if globalParamsEntryCopy.ValidatorSetMaxNumValidators == 0 {
		globalParamsEntryCopy.ValidatorSetMaxNumValidators = bav.Params.DefaultValidatorSetMaxNumValidators
	}
	if globalParamsEntryCopy.StakingRewardDistributionMaxNumStakers == 0 {
		globalParamsEntryCopy.StakingRewardDistributionMaxNumStakers = bav.Params.DefaultStakingRewardDistributionMaxNumStakers
	}
	if globalParamsEntryCopy.EpochDurationNumBlocks == 0 {
		globalParamsEntryCopy.EpochDurationNumBlocks = bav.Params.DefaultEpochDurationNumBlocks
	}
	if globalParamsEntryCopy.JailInactiveValidatorGracePeriodEpochs == 0 {
		globalParamsEntryCopy.JailInactiveValidatorGracePeriodEpochs = bav.Params.DefaultJailInactiveValidatorGracePeriodEpochs
	}

	// Return the merged result.
	return globalParamsEntryCopy
}

func (bav *UtxoView) _setSnapshotGlobalParamsEntry(globalParamsEntry *GlobalParamsEntry, snapshotAtEpochNumber uint64) {
	if globalParamsEntry == nil {
		glog.Errorf("_setSnapshotGlobalParamsEntry: called with nil entry, this should never happen")
		return
	}
	bav.SnapshotGlobalParamEntries[snapshotAtEpochNumber] = globalParamsEntry.Copy()
}

func (bav *UtxoView) _flushSnapshotGlobalParamsEntryToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	for snapshotAtEpochNumber, globalParamsEntry := range bav.SnapshotGlobalParamEntries {
		if globalParamsEntry == nil {
			return fmt.Errorf(
				"_flushSnapshotGlobalParamsEntryToDb: found nil entry for EpochNumber %d, this should never happen",
				snapshotAtEpochNumber,
			)
		}
		if err := DBPutSnapshotGlobalParamsEntryWithTxn(
			txn, bav.Snapshot, globalParamsEntry, snapshotAtEpochNumber, blockHeight,
		); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotGlobalParamsEntryToDb: problem setting SnapshotGlobalParamsEntry for EpochNumber %d: ",
				snapshotAtEpochNumber,
			)
		}
	}
	return nil
}

func DBKeyForSnapshotGlobalParamsEntry(snapshotEpochNumber uint64) []byte {
	key := append([]byte{}, Prefixes.PrefixSnapshotGlobalParamsEntry...)
	key = append(key, EncodeUint64(snapshotEpochNumber)...)
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
	SnapshotAtEpochNumber uint64
	ValidatorPKID         PKID
}

func (bav *UtxoView) SnapshotCurrentValidators(snapshotAtEpochNumber uint64, blockHeight uint64) error {
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

func (bav *UtxoView) GetSnapshotValidatorByPKID(pkid *PKID) (*ValidatorEntry, error) {
	// Calculate the SnapshotEpochNumber.
	snapshotAtEpochNumber, err := bav.GetSnapshotEpochNumber()
	if err != nil {
		return nil, errors.Wrapf(err, "GetSnapshotValidatorByPKID: problem calculating SnapshotEpochNumber: ")
	}
	// Check the UtxoView first.
	mapKey := SnapshotValidatorMapKey{SnapshotAtEpochNumber: snapshotAtEpochNumber, ValidatorPKID: *pkid}
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

func (bav *UtxoView) GetSnapshotTopActiveValidatorsByStake(limit uint64) ([]*ValidatorEntry, error) {
	// Calculate the SnapshotEpochNumber.
	snapshotAtEpochNumber, err := bav.GetSnapshotEpochNumber()
	if err != nil {
		return nil, errors.Wrapf(err, "GetSnapshotTopActiveValidatorsByStake: problem calculating SnapshotEpochNumber: ")
	}
	// Create a slice of all UtxoView ValidatorEntries to prevent pulling them from the db.
	var utxoViewValidatorEntries []*ValidatorEntry
	for mapKey, validatorEntry := range bav.SnapshotValidatorEntries {
		if mapKey.SnapshotAtEpochNumber == snapshotAtEpochNumber {
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
		mapKey := SnapshotValidatorMapKey{
			SnapshotAtEpochNumber: snapshotAtEpochNumber, ValidatorPKID: *validatorEntry.ValidatorPKID,
		}
		if _, exists := bav.SnapshotValidatorEntries[mapKey]; !exists {
			bav._setSnapshotValidatorEntry(validatorEntry, snapshotAtEpochNumber)
		}
	}
	// Pull !isDeleted, active ValidatorEntries from the UtxoView with stake > 0.
	var validatorEntries []*ValidatorEntry
	for mapKey, validatorEntry := range bav.SnapshotValidatorEntries {
		if mapKey.SnapshotAtEpochNumber == snapshotAtEpochNumber &&
			!validatorEntry.isDeleted &&
			validatorEntry.Status() == ValidatorStatusActive &&
			!validatorEntry.TotalStakeAmountNanos.IsZero() {
			validatorEntries = append(validatorEntries, validatorEntry)
		}
	}
	// Sort the ValidatorEntries DESC by TotalStakeAmountNanos.
	sort.SliceStable(validatorEntries, func(ii, jj int) bool {
		stakeCmp := validatorEntries[ii].TotalStakeAmountNanos.Cmp(validatorEntries[jj].TotalStakeAmountNanos)
		if stakeCmp == 0 {
			// Use ValidatorPKID as a tie-breaker if equal TotalStakeAmountNanos.
			return bytes.Compare(
				validatorEntries[ii].ValidatorPKID.ToBytes(),
				validatorEntries[jj].ValidatorPKID.ToBytes(),
			) > 0
		}
		return stakeCmp > 0
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
	mapKey := SnapshotValidatorMapKey{
		SnapshotAtEpochNumber: snapshotAtEpochNumber, ValidatorPKID: *validatorEntry.ValidatorPKID,
	}
	bav.SnapshotValidatorEntries[mapKey] = validatorEntry.Copy()
}

func (bav *UtxoView) _deleteSnapshotValidatorEntry(validatorEntry *ValidatorEntry, snapshotAtEpochNumber uint64) {
	// This function shouldn't be called with nil.
	if validatorEntry == nil {
		glog.Errorf("_deleteSnapshotValidatorEntry: called with nil entry, this should never happen")
		return
	}
	// Create a tombstone entry.
	tombstoneEntry := *validatorEntry
	tombstoneEntry.isDeleted = true
	// Set the mappings to the point to the tombstone entry.
	bav._setSnapshotValidatorEntry(&tombstoneEntry, snapshotAtEpochNumber)
}

func (bav *UtxoView) _flushSnapshotValidatorEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// Delete all SnapshotValidatorEntries from the db that are in the UtxoView.
	for mapKey, validatorEntry := range bav.SnapshotValidatorEntries {
		if validatorEntry == nil {
			return fmt.Errorf(
				"_flushSnapshotValidatorEntriesToDb: found nil entry for EpochNumber %d, this should never happen",
				mapKey.SnapshotAtEpochNumber,
			)
		}
		if err := DBDeleteSnapshotValidatorEntryWithTxn(
			txn, bav.Snapshot, &mapKey.ValidatorPKID, mapKey.SnapshotAtEpochNumber,
		); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotValidatorEntriesToDb: problem deleting ValidatorEntry for EpochNumber %d: ",
				mapKey.SnapshotAtEpochNumber,
			)
		}
	}

	// Set all !isDeleted SnapshotValidatorEntries into the db from the UtxoView.
	for mapKey, validatorEntry := range bav.SnapshotValidatorEntries {
		if validatorEntry == nil {
			return fmt.Errorf(
				"_flushSnapshotValidatorEntriesToDb: found nil entry for EpochNumber %d, this should never happen",
				mapKey.SnapshotAtEpochNumber,
			)
		}
		if validatorEntry.isDeleted {
			// Skip any deleted SnapshotValidatorEntries.
			continue
		}
		if err := DBPutSnapshotValidatorEntryWithTxn(
			txn, bav.Snapshot, validatorEntry, mapKey.SnapshotAtEpochNumber, blockHeight,
		); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotValidatorEntriesToDb: problem setting ValidatorEntry for EpochNumber %d: ",
				mapKey.SnapshotAtEpochNumber,
			)
		}
	}
	return nil
}

func DBKeyForSnapshotValidatorByPKID(validatorEntry *ValidatorEntry, snapshotAtEpochNumber uint64) []byte {
	key := append([]byte{}, Prefixes.PrefixSnapshotValidatorByPKID...)
	key = append(key, EncodeUint64(snapshotAtEpochNumber)...)
	key = append(key, validatorEntry.ValidatorPKID.ToBytes()...)
	return key
}

func DBKeyForSnapshotValidatorByStake(validatorEntry *ValidatorEntry, snapshotAtEpochNumber uint64) []byte {
	key := append([]byte{}, Prefixes.PrefixSnapshotValidatorByStatusAndStake...)
	key = append(key, EncodeUint64(snapshotAtEpochNumber)...)
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
	key := append([]byte{}, Prefixes.PrefixSnapshotValidatorByStatusAndStake...)
	key = append(key, EncodeUint64(snapshotAtEpochNumber)...)
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

	// Put the ValidatorPKID in the SnapshotValidatorByStatusAndStake index.
	key = DBKeyForSnapshotValidatorByStake(validatorEntry, snapshotAtEpochNumber)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, validatorEntry.ValidatorPKID)); err != nil {
		return errors.Wrapf(
			err,
			"DBPutSnapshotValidatorEntryWithTxn: problem putting ValidatorPKID in the SnapshotValidatorByStake index: ",
		)
	}

	return nil
}

func DBDeleteSnapshotValidatorEntryWithTxn(
	txn *badger.Txn, snap *Snapshot, validatorPKID *PKID, snapshotAtEpochNumber uint64,
) error {
	if validatorPKID == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBDeleteSnapshotValidatorEntryWithTxn: called with nil ValidatorPKID")
		return nil
	}

	// Look up the existing SnapshotValidatorEntry in the db using the PKID.
	// We need to use this validator's values to delete the corresponding indexes.
	validatorEntry, err := DBGetSnapshotValidatorByPKIDWithTxn(txn, snap, validatorPKID, snapshotAtEpochNumber)
	if err != nil {
		return errors.Wrapf(
			err, "DBDeleteSnapshotValidatorEntryWithTxn: problem retrieving ValidatorEntry for PKID %v: ", validatorPKID,
		)
	}

	// If there is no ValidatorEntry in the DB for this PKID, then there is nothing to delete.
	if validatorEntry == nil {
		return nil
	}

	// Delete ValidatorEntry from PrefixSnapshotValidatorByPKID.
	key := DBKeyForSnapshotValidatorByPKID(validatorEntry, snapshotAtEpochNumber)
	if err = DBDeleteWithTxn(txn, snap, key); err != nil {
		return errors.Wrapf(
			err, "DBDeleteSnapshotValidatorEntryWithTxn: problem deleting ValidatorEntry from index PrefixSnapshotValidatorByPKID",
		)
	}

	// Delete ValidatorEntry.PKID from PrefixSnapshotValidatorByStatusAndStake.
	key = DBKeyForSnapshotValidatorByStake(validatorEntry, snapshotAtEpochNumber)
	if err = DBDeleteWithTxn(txn, snap, key); err != nil {
		return errors.Wrapf(
			err, "DBDeleteSnapshotValidatorEntryWithTxn: problem deleting ValidatorEntry from index PrefixSnapshotValidatorByStatusAndStake",
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

func (bav *UtxoView) GetSnapshotGlobalActiveStakeAmountNanos() (*uint256.Int, error) {
	// Calculate the SnapshotEpochNumber.
	snapshotAtEpochNumber, err := bav.GetSnapshotEpochNumber()
	if err != nil {
		return nil, errors.Wrapf(err, "GetSnapshotGlobalActiveStakeAmountNanos: problem calculating SnapshotEpochNumber: ")
	}
	// Check the UtxoView first.
	if globalActiveStakeAmountNanos, exists := bav.SnapshotGlobalActiveStakeAmountNanos[snapshotAtEpochNumber]; exists {
		return globalActiveStakeAmountNanos.Clone(), nil
	}
	// If we don't have it in the UtxoView, check the db.
	globalActiveStakeAmountNanos, err := DBGetSnapshotGlobalActiveStakeAmountNanos(bav.Handle, bav.Snapshot, snapshotAtEpochNumber)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"GetSnapshotGlobalActiveStakeAmountNanos: problem retrieving SnapshotGlobalActiveStakeAmountNanos from db: ",
		)
	}
	if globalActiveStakeAmountNanos == nil {
		globalActiveStakeAmountNanos = uint256.NewInt()
	}
	// Cache the result in the UtxoView.
	bav._setSnapshotGlobalActiveStakeAmountNanos(globalActiveStakeAmountNanos, snapshotAtEpochNumber)
	return globalActiveStakeAmountNanos, nil
}

func (bav *UtxoView) _setSnapshotGlobalActiveStakeAmountNanos(globalActiveStakeAmountNanos *uint256.Int, snapshotAtEpochNumber uint64) {
	if globalActiveStakeAmountNanos == nil {
		glog.Errorf("_setSnapshotGlobalActiveStakeAmountNanos: called with nil entry, this should never happen")
		return
	}
	bav.SnapshotGlobalActiveStakeAmountNanos[snapshotAtEpochNumber] = globalActiveStakeAmountNanos.Clone()
}

func (bav *UtxoView) _flushSnapshotGlobalActiveStakeAmountNanosToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	for snapshotAtEpochNumber, globalActiveStakeAmountNanos := range bav.SnapshotGlobalActiveStakeAmountNanos {
		if globalActiveStakeAmountNanos == nil {
			return fmt.Errorf(
				"_flushSnapshotGlobalActiveStakeToDb: found nil entry for EpochNumber %d, this should never happen",
				snapshotAtEpochNumber,
			)
		}
		if err := DBPutSnapshotGlobalActiveStakeAmountNanosWithTxn(
			txn, bav.Snapshot, globalActiveStakeAmountNanos, snapshotAtEpochNumber, blockHeight,
		); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotGlobalActiveStakeToDb: problem setting SnapshotGlobalActiveStake for EpochNumber %d: ",
				snapshotAtEpochNumber,
			)
		}
	}
	return nil
}

func DBKeyForSnapshotGlobalActiveStakeAmountNanos(snapshotAtEpochNumber uint64) []byte {
	key := append([]byte{}, Prefixes.PrefixSnapshotGlobalActiveStakeAmountNanos...)
	key = append(key, EncodeUint64(snapshotAtEpochNumber)...)
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
		glog.Errorf("DBPutSnapshotGlobalActiveStakeAmountNanos: called with nil GlobalActiveStake, this should never happen")
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
	LeaderIndex           uint16
}

func (bav *UtxoView) GetSnapshotLeaderScheduleValidator(leaderIndex uint16) (*ValidatorEntry, error) {
	// Calculate the SnapshotEpochNumber.
	snapshotAtEpochNumber, err := bav.GetSnapshotEpochNumber()
	if err != nil {
		return nil, errors.Wrapf(err, " GetSnapshotLeaderScheduleValidator: problem calculating SnapshotEpochNumber: ")
	}
	// First, check the UtxoView.
	mapKey := SnapshotLeaderScheduleMapKey{SnapshotAtEpochNumber: snapshotAtEpochNumber, LeaderIndex: leaderIndex}
	if validatorPKID, exists := bav.SnapshotLeaderSchedule[mapKey]; exists {
		return bav.GetSnapshotValidatorByPKID(validatorPKID)
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

func (bav *UtxoView) _setSnapshotLeaderScheduleValidator(validatorPKID *PKID, index uint16, snapshotAtEpochNumber uint64) {
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
				"_flushSnapshotLeaderScheduleToDb: found nil PKID for EpochNumber %d, this should never happen",
				mapKey.SnapshotAtEpochNumber,
			)
		}
		if err := DBPutSnapshotLeaderScheduleValidatorWithTxn(
			txn, bav.Snapshot, validatorPKID, mapKey.LeaderIndex, mapKey.SnapshotAtEpochNumber, blockHeight,
		); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotLeaderScheduleToDb: problem setting ValidatorPKID for SnapshotAtEpochNumber %d: ",
				mapKey.SnapshotAtEpochNumber,
			)
		}
	}
	return nil
}

func DBKeyForSnapshotLeaderScheduleValidator(leaderIndex uint16, snapshotAtEpochNumber uint64) []byte {
	data := append([]byte{}, Prefixes.PrefixSnapshotLeaderSchedule...)
	data = append(data, EncodeUint64(snapshotAtEpochNumber)...)
	data = append(data, EncodeUint16(leaderIndex)...)
	return data
}

func DBGetSnapshotLeaderScheduleValidator(
	handle *badger.DB,
	snap *Snapshot,
	leaderIndex uint16,
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
	leaderIndex uint16,
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
	leaderIndex uint16,
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
