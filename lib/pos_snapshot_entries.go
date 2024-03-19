package lib

import (
	"bytes"
	"fmt"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"math"
	"sort"
)

const SnapshotLookbackNumEpochs uint64 = 2

func (bav *UtxoView) GetCurrentSnapshotEpochNumber() (uint64, error) {
	// Retrieve the CurrentEpochNumber.
	currentEpochNumber, err := bav.GetCurrentEpochNumber()
	if err != nil {
		return 0, errors.Wrapf(err, "GetCurrentSnapshotEpochNumber: problem retrieving CurrentEpochNumber: ")
	}
	return bav.ComputeSnapshotEpochNumberForEpoch(currentEpochNumber)
}

func (bav *UtxoView) ComputeSnapshotEpochNumberForEpoch(epochNumber uint64) (uint64, error) {
	if epochNumber < SnapshotLookbackNumEpochs {
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
	return SafeUint64().Sub(epochNumber, SnapshotLookbackNumEpochs)
}

//
// SnapshotGlobalParamsEntry
//

func (bav *UtxoView) GetCurrentGlobalParamsEntry() *GlobalParamsEntry {
	return MergeGlobalParamEntryDefaults(bav.GlobalParamsEntry, bav.Params)
}

// GetCurrentSnapshotGlobalParamsEntry retrieves a snapshot of the GlobalParamsEntry from n epochs ago. If a snapshot
// does not exist for that epoch, it will return the default values. We snapshot GlobalParams to make sure that
// the validator set in the PoS consensus is in agreement ahead of time on the params used for an epoch long
// before that epoch begins. Snapshot GlobalParams are only appropriate to use in two scenarios:
//   - In the PoS consensus logic run by validators for block proposal, voting, and timeouts; validators need to
//     be in agreement on the size of the validator set, leader schedule, stakes to reward, and epoch duration.
//   - When transitioning to a new epoch, we use the snapshot GlobalParams to determine the length of the next
//     epoch. All validators need to be in agreement ahead of time on what length of the next epoch will be before
//     the epoch begins.
//
// For all other uses, only the CurrentGlobalParamsEntry is appropriate to use. This includes all transaction connect
// logic and end of epoch operations that mutate the validator entries and stake entries BEFORE they are
// snapshotted. This approach ensures that whenever we create a snapshot of the validator set, leader schedule,
// and stakes to reward... the GlobalParams used to create the snapshots are snapshotted along with that data, and
// live alongside them.
func (bav *UtxoView) GetCurrentSnapshotGlobalParamsEntry() (*GlobalParamsEntry, error) {
	// Calculate the SnapshotEpochNumber.
	snapshotAtEpochNumber, err := bav.GetCurrentSnapshotEpochNumber()
	if err != nil {
		return nil, errors.Wrapf(err, "GetCurrentSnapshotGlobalParamsEntry: problem calculating SnapshotEpochNumber: ")
	}
	return bav.GetSnapshotGlobalParamsEntryByEpochNumber(snapshotAtEpochNumber)
}

func (bav *UtxoView) GetSnapshotGlobalParamsEntryByEpochNumber(snapshotAtEpochNumber uint64) (*GlobalParamsEntry, error) {
	// Check the UtxoView first.
	if globalParamsEntry, exists := bav.SnapshotGlobalParamEntries[snapshotAtEpochNumber]; exists {
		return MergeGlobalParamEntryDefaults(globalParamsEntry, bav.Params), nil
	}
	// If we don't have it in the UtxoView, check the db.
	globalParamsEntry, err := DBGetSnapshotGlobalParamsEntry(bav.Handle, bav.Snapshot, snapshotAtEpochNumber)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"GetSnapshotGlobalParamsEntryByEpochNumber: problem retrieving SnapshotGlobalParamsEntry from db: ",
		)
	}
	if globalParamsEntry != nil {
		// Cache the result in the UtxoView.
		bav._setSnapshotGlobalParamsEntry(globalParamsEntry, snapshotAtEpochNumber)
	}
	return MergeGlobalParamEntryDefaults(globalParamsEntry, bav.Params), nil
}

func MergeGlobalParamEntryDefaults(globalParamsEntry *GlobalParamsEntry, params *DeSoParams) *GlobalParamsEntry {
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
		globalParamsEntryCopy.StakeLockupEpochDuration = params.DefaultStakeLockupEpochDuration
	}
	if globalParamsEntryCopy.ValidatorJailEpochDuration == 0 {
		globalParamsEntryCopy.ValidatorJailEpochDuration = params.DefaultValidatorJailEpochDuration
	}
	if globalParamsEntryCopy.LeaderScheduleMaxNumValidators == 0 {
		globalParamsEntryCopy.LeaderScheduleMaxNumValidators = params.DefaultLeaderScheduleMaxNumValidators
	}
	if globalParamsEntryCopy.ValidatorSetMaxNumValidators == 0 {
		globalParamsEntryCopy.ValidatorSetMaxNumValidators = params.DefaultValidatorSetMaxNumValidators
	}
	if globalParamsEntryCopy.StakingRewardsMaxNumStakes == 0 {
		globalParamsEntryCopy.StakingRewardsMaxNumStakes = params.DefaultStakingRewardsMaxNumStakes
	}
	if globalParamsEntryCopy.StakingRewardsAPYBasisPoints == 0 {
		globalParamsEntryCopy.StakingRewardsAPYBasisPoints = params.DefaultStakingRewardsAPYBasisPoints
	}
	if globalParamsEntryCopy.EpochDurationNumBlocks == 0 {
		globalParamsEntryCopy.EpochDurationNumBlocks = params.DefaultEpochDurationNumBlocks
	}
	if globalParamsEntryCopy.JailInactiveValidatorGracePeriodEpochs == 0 {
		globalParamsEntryCopy.JailInactiveValidatorGracePeriodEpochs = params.DefaultJailInactiveValidatorGracePeriodEpochs
	}
	if globalParamsEntryCopy.FeeBucketGrowthRateBasisPoints == 0 {
		globalParamsEntryCopy.FeeBucketGrowthRateBasisPoints = params.DefaultFeeBucketGrowthRateBasisPoints
	}
	if globalParamsEntryCopy.FailingTransactionBMFMultiplierBasisPoints == 0 {
		globalParamsEntryCopy.FailingTransactionBMFMultiplierBasisPoints = params.DefaultFailingTransactionBMFMultiplierBasisPoints
	}
	if globalParamsEntryCopy.MaximumVestedIntersectionsPerLockupTransaction == 0 {
		globalParamsEntryCopy.MaximumVestedIntersectionsPerLockupTransaction =
			params.DefaultMaximumVestedIntersectionsPerLockupTransaction
	}
	if globalParamsEntryCopy.BlockTimestampDriftNanoSecs == 0 {
		globalParamsEntryCopy.BlockTimestampDriftNanoSecs = params.DefaultBlockTimestampDriftNanoSecs
	}
	if globalParamsEntryCopy.MempoolMaxSizeBytes == 0 {
		globalParamsEntryCopy.MempoolMaxSizeBytes = params.DefaultMempoolMaxSizeBytes
	}
	if globalParamsEntryCopy.MempoolFeeEstimatorNumMempoolBlocks == 0 {
		globalParamsEntryCopy.MempoolFeeEstimatorNumMempoolBlocks = params.DefaultMempoolFeeEstimatorNumMempoolBlocks
	}
	if globalParamsEntryCopy.MempoolFeeEstimatorNumPastBlocks == 0 {
		globalParamsEntryCopy.MempoolFeeEstimatorNumPastBlocks = params.DefaultMempoolFeeEstimatorNumPastBlocks
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
			txn, bav.Snapshot, globalParamsEntry, snapshotAtEpochNumber, blockHeight, bav.EventManager,
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
	eventManager *EventManager,
) error {
	if globalParamsEntry == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutSnapshotGlobalParamsEntryWithTxn: called with nil GlobalParamsEntry, this should never happen")
		return nil
	}
	key := DBKeyForSnapshotGlobalParamsEntry(snapshotAtEpochNumber)
	return DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, globalParamsEntry), eventManager)
}

//
// SnapshotValidatorSet
//

type SnapshotValidatorSetMapKey struct {
	SnapshotAtEpochNumber uint64
	ValidatorPKID         PKID
}

func (bav *UtxoView) GetCurrentSnapshotValidatorSetEntryByPKID(pkid *PKID) (*ValidatorEntry, error) {
	// Calculate the SnapshotEpochNumber.
	snapshotAtEpochNumber, err := bav.GetCurrentSnapshotEpochNumber()
	if err != nil {
		return nil, errors.Wrapf(err, "GetCurrentSnapshotValidatorSetEntryByPKID: problem calculating SnapshotEpochNumber: ")
	}
	return bav.GetSnapshotValidatorSetEntryByPKIDAtEpochNumber(pkid, snapshotAtEpochNumber)
}
func (bav *UtxoView) GetSnapshotValidatorSetEntryByPKIDAtEpochNumber(pkid *PKID, snapshotAtEpochNumber uint64) (*ValidatorEntry, error) {
	validatorEntry, err := bav.SnapshotCache.GetSnapshotValidatorEntryByPKID(snapshotAtEpochNumber, pkid, bav.Handle, bav.Snapshot)
	if err != nil {
		return nil, errors.Wrapf(err, "GetSnapshotValidatorSetEntryByPKIDAtEpochNumber: ")
	}
	return validatorEntry, nil
}

func (bav *UtxoView) GetSnapshotValidatorSetByStakeAmount(limit uint64) ([]*ValidatorEntry, error) {
	// Calculate the SnapshotEpochNumber.
	snapshotAtEpochNumber, err := bav.GetCurrentSnapshotEpochNumber()
	if err != nil {
		return nil, errors.Wrapf(err, "GetSnapshotValidatorSetEntriesByStake: problem calculating SnapshotEpochNumber: ")
	}
	return bav.GetSnapshotValidatorSetByStakeAmountAtEpochNumber(snapshotAtEpochNumber, limit)
}
func (bav *UtxoView) GetSnapshotValidatorSetByStakeAmountAtEpochNumber(snapshotAtEpochNumber uint64, limit uint64) ([]*ValidatorEntry, error) {
	// Create a slice of all UtxoView ValidatorEntries to prevent pulling them from the db.
	var utxoViewValidatorEntries []*ValidatorEntry
	for mapKey, validatorEntry := range bav.SnapshotValidatorSet {
		if mapKey.SnapshotAtEpochNumber == snapshotAtEpochNumber {
			utxoViewValidatorEntries = append(utxoViewValidatorEntries, validatorEntry)
		}
	}
	// If the view hasn't loaded the full set of validators for this snapshot, pull them from the db.
	if !bav.HasFullSnapshotValidatorSetByEpoch[snapshotAtEpochNumber] {

		// Pull top N ValidatorEntries from the database (not present in the UtxoView).
		// Note that we will skip validators that are present in the view because we pass
		// utxoViewValidatorEntries to the function.
		dbValidatorEntries, err := DBGetSnapshotValidatorSetByStakeAmount(
			bav.Handle, bav.Snapshot, limit, snapshotAtEpochNumber, utxoViewValidatorEntries,
		)
		if err != nil {
			return nil, errors.Wrapf(
				err, "GetSnapshotValidatorSetByStakeAmountAtEpochNumber: error retrieving entries from db: ")
		}
		// Cache top N active ValidatorEntries from the db in the UtxoView.
		for _, validatorEntry := range dbValidatorEntries {
			// We only pull ValidatorEntries from the db that are not present in the
			// UtxoView. As a sanity check, we double-check that the ValidatorEntry
			// is not already in the UtxoView here.
			mapKey := SnapshotValidatorSetMapKey{
				SnapshotAtEpochNumber: snapshotAtEpochNumber, ValidatorPKID: *validatorEntry.ValidatorPKID,
			}
			if _, exists := bav.SnapshotValidatorSet[mapKey]; !exists {
				bav._setSnapshotValidatorSetEntry(validatorEntry, snapshotAtEpochNumber)
			}
		}
	}
	// Pull !isDeleted, active ValidatorEntries from the UtxoView with stake > 0.
	var validatorEntries []*ValidatorEntry
	for mapKey, validatorEntry := range bav.SnapshotValidatorSet {
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

// GetAllSnapshotValidatorSetEntriesByStake returns all validators in the snapshot
// ordered by stake. This is useful when we need to know all the validators that
// are in a leader schedule.
func (bav *UtxoView) GetAllSnapshotValidatorSetEntriesByStake() ([]*ValidatorEntry, error) {
	snapshotGlobalParams, err := bav.GetCurrentSnapshotGlobalParamsEntry()
	if err != nil {
		return nil, errors.Wrapf(err, "GetAllSnapshotValidatorSetEntriesByStake: problem getting SnapshotGlobalParamsEntry: ")
	}
	return bav.GetSnapshotValidatorSetByStakeAmount(snapshotGlobalParams.ValidatorSetMaxNumValidators)
}

func (bav *UtxoView) GetAllSnapshotValidatorSetEntriesByStakeAtEpochNumber(snapshotAtEpochNumber uint64) ([]*ValidatorEntry, error) {
	snapshotGlobalParams, err := bav.GetSnapshotGlobalParamsEntryByEpochNumber(snapshotAtEpochNumber)
	if err != nil {
		return nil, errors.Wrapf(err, "GetSnapshotValidatorSetEntriesByStakeAtEpochNumber: problem getting SnapshotGlobalParamsEntry: ")
	}
	return bav.GetSnapshotValidatorSetByStakeAmountAtEpochNumber(snapshotAtEpochNumber, snapshotGlobalParams.ValidatorSetMaxNumValidators)
}

func (bav *UtxoView) _setSnapshotValidatorSetEntry(validatorEntry *ValidatorEntry, snapshotAtEpochNumber uint64) {
	if validatorEntry == nil {
		glog.Errorf("_setSnapshotValidatorSetEntry: called with nil entry, this should never happen")
		return
	}
	mapKey := SnapshotValidatorSetMapKey{
		SnapshotAtEpochNumber: snapshotAtEpochNumber, ValidatorPKID: *validatorEntry.ValidatorPKID,
	}
	bav.SnapshotValidatorSet[mapKey] = validatorEntry.Copy()

	bav._setSnapshotValidatorBLSPublicKeyPKIDPairEntry(validatorEntry.ToBLSPublicKeyPKIDPairEntry(), snapshotAtEpochNumber)
}

func (bav *UtxoView) _deleteSnapshotValidatorSetEntry(validatorEntry *ValidatorEntry, snapshotAtEpochNumber uint64) {
	// This function shouldn't be called with nil.
	if validatorEntry == nil {
		glog.Errorf("_deleteSnapshotValidatorSetEntry: called with nil entry, this should never happen")
		return
	}
	// Create a tombstone entry.
	tombstoneEntry := *validatorEntry
	tombstoneEntry.isDeleted = true
	// Set the mappings to the point to the tombstone entry.
	bav._setSnapshotValidatorSetEntry(&tombstoneEntry, snapshotAtEpochNumber)
}

func (bav *UtxoView) _flushSnapshotValidatorSetToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// Delete all SnapshotValidatorSet entries from the db that are in the UtxoView.
	for mapKey, validatorEntry := range bav.SnapshotValidatorSet {
		if validatorEntry == nil {
			return fmt.Errorf(
				"_flushSnapshotValidatorSetToDbWithTxn: found nil entry for EpochNumber %d, this should never happen",
				mapKey.SnapshotAtEpochNumber,
			)
		}
		if err := DBDeleteSnapshotValidatorSetEntryWithTxn(
			txn, bav.Snapshot, &mapKey.ValidatorPKID, mapKey.SnapshotAtEpochNumber, bav.EventManager, validatorEntry.isDeleted,
		); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotValidatorSetToDbWithTxn: problem deleting ValidatorEntry for EpochNumber %d: ",
				mapKey.SnapshotAtEpochNumber,
			)
		}
	}

	// Put all !isDeleted SnapshotValidatorSet entry into the db from the UtxoView.
	for mapKey, validatorEntry := range bav.SnapshotValidatorSet {
		if validatorEntry == nil {
			return fmt.Errorf(
				"_flushSnapshotValidatorSetToDbWithTxn: found nil entry for EpochNumber %d, this should never happen",
				mapKey.SnapshotAtEpochNumber,
			)
		}
		if validatorEntry.isDeleted {
			// Skip any deleted SnapshotValidatorSet.
			continue
		}
		if err := DBPutSnapshotValidatorSetEntryWithTxn(
			txn, bav.Snapshot, validatorEntry, mapKey.SnapshotAtEpochNumber, blockHeight, bav.EventManager,
		); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotValidatorSetToDbWithTxn: problem setting ValidatorEntry for EpochNumber %d: ",
				mapKey.SnapshotAtEpochNumber,
			)
		}
	}
	return nil
}

func DBKeyForSnapshotValidatorSetByPKID(validatorEntry *ValidatorEntry, snapshotAtEpochNumber uint64) []byte {
	key := append([]byte{}, Prefixes.PrefixSnapshotValidatorSetByPKID...)
	key = append(key, EncodeUint64(snapshotAtEpochNumber)...)
	key = append(key, validatorEntry.ValidatorPKID.ToBytes()...)
	return key
}

func DBKeyForSnapshotValidatorSetByStakeAmount(validatorEntry *ValidatorEntry, snapshotAtEpochNumber uint64) []byte {
	key := append([]byte{}, Prefixes.PrefixSnapshotValidatorSetByStakeAmount...)
	key = append(key, EncodeUint64(snapshotAtEpochNumber)...)
	key = append(key, FixedWidthEncodeUint256(validatorEntry.TotalStakeAmountNanos)...)
	key = append(key, validatorEntry.ValidatorPKID.ToBytes()...)
	return key
}

func DBGetSnapshotValidatorSetEntryByPKID(handle *badger.DB, snap *Snapshot, pkid *PKID, snapshotAtEpochNumber uint64) (*ValidatorEntry, error) {
	var ret *ValidatorEntry
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetSnapshotValidatorSetEntryByPKIDWithTxn(txn, snap, pkid, snapshotAtEpochNumber)
		return innerErr
	})
	return ret, err
}

func DBGetSnapshotValidatorSetEntryByPKIDWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	pkid *PKID,
	snapshotAtEpochNumber uint64,
) (*ValidatorEntry, error) {
	// Retrieve ValidatorEntry from db.
	key := DBKeyForSnapshotValidatorSetByPKID(&ValidatorEntry{ValidatorPKID: pkid}, snapshotAtEpochNumber)
	validatorBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return nil.
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "DBGetSnapshotValidatorSetEntryByPKIDWithTxn: problem retrieving ValidatorEntry")
	}

	// Decode ValidatorEntry from bytes.
	validatorEntry := &ValidatorEntry{}
	rr := bytes.NewReader(validatorBytes)
	if exist, err := DecodeFromBytes(validatorEntry, rr); !exist || err != nil {
		return nil, errors.Wrapf(err, "DBGetSnapshotValidatorSetEntryByPKIDWithTxn: problem decoding ValidatorEntry")
	}
	return validatorEntry, nil
}

func DBGetSnapshotValidatorSetByStakeAmount(
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
		validatorKeysToSkip.Add(string(DBKeyForSnapshotValidatorSetByStakeAmount(validatorEntryToSkip, snapshotAtEpochNumber)))
	}

	// Retrieve top N active ValidatorEntry keys by stake.
	key := append([]byte{}, Prefixes.PrefixSnapshotValidatorSetByStakeAmount...)
	key = append(key, EncodeUint64(snapshotAtEpochNumber)...)
	keysFound, _, err := EnumerateKeysForPrefixWithLimitOffsetOrder(
		handle, key, int(limit), nil, true, validatorKeysToSkip,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetSnapshotValidatorSetByStakeAmount: problem retrieving top validators: ")
	}

	// For each key found, parse the ValidatorPKID from the key,
	// then retrieve the ValidatorEntry by the ValidatorPKID.
	for _, keyFound := range keysFound {
		// Parse the PKIDBytes from the key. The ValidatorPKID is the last component of the key.
		validatorPKIDBytes := keyFound[len(keyFound)-PublicKeyLenCompressed:]
		// Convert PKIDBytes to PKID.
		validatorPKID := &PKID{}
		if err = validatorPKID.FromBytes(bytes.NewReader(validatorPKIDBytes)); err != nil {
			return nil, errors.Wrapf(err, "DBGetSnapshotValidatorSetByStakeAmount: problem reading ValidatorPKID: ")
		}
		// Retrieve ValidatorEntry by PKID.
		validatorEntry, err := DBGetSnapshotValidatorSetEntryByPKID(handle, snap, validatorPKID, snapshotAtEpochNumber)
		if err != nil {
			return nil, errors.Wrapf(err, "DBGetSnapshotValidatorSetByStakeAmount: problem retrieving validator by PKID: ")
		}
		validatorEntries = append(validatorEntries, validatorEntry)
	}

	return validatorEntries, nil
}

func DBPutSnapshotValidatorSetEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	validatorEntry *ValidatorEntry,
	snapshotAtEpochNumber uint64,
	blockHeight uint64,
	eventManager *EventManager,
) error {
	if validatorEntry == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutSnapshotValidatorSetEntryWithTxn: called with nil ValidatorEntry, this should never happen")
		return nil
	}

	// Put the ValidatorEntry in the SnapshotSetByPKID index.
	key := DBKeyForSnapshotValidatorSetByPKID(validatorEntry, snapshotAtEpochNumber)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, validatorEntry), eventManager); err != nil {
		return errors.Wrapf(
			err,
			"DBPutSnapshotValidatorSetEntryWithTxn: problem putting ValidatorEntry in the SnapshotValidatorByPKID index: ",
		)
	}

	// Put the ValidatorPKID in the SnapshotValidatorByStatusAndStakeAmount index.
	key = DBKeyForSnapshotValidatorSetByStakeAmount(validatorEntry, snapshotAtEpochNumber)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, validatorEntry.ValidatorPKID), eventManager); err != nil {
		return errors.Wrapf(
			err,
			"DBPutSnapshotValidatorSetEntryWithTxn: problem putting ValidatorPKID in the SnapshotValidatorByStake index: ",
		)
	}

	return nil
}

func DBDeleteSnapshotValidatorSetEntryWithTxn(
	txn *badger.Txn, snap *Snapshot, validatorPKID *PKID, snapshotAtEpochNumber uint64, eventManager *EventManager, entryIsDeleted bool,
) error {
	if validatorPKID == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBDeleteSnapshotValidatorSetEntryWithTxn: called with nil ValidatorPKID")
		return nil
	}

	// Look up the existing SnapshotValidatorSetEntry in the db using the PKID.
	// We need to use this validator's values to delete the corresponding indexes.
	snapshotValidatorSetEntry, err := DBGetSnapshotValidatorSetEntryByPKIDWithTxn(txn, snap, validatorPKID, snapshotAtEpochNumber)
	if err != nil {
		return errors.Wrapf(
			err, "DBDeleteSnapshotValidatorSetEntryWithTxn: problem retrieving ValidatorEntry for PKID %v: ", validatorPKID,
		)
	}

	// If there is no ValidatorEntry in the DB for this PKID, then there is nothing to delete.
	if snapshotValidatorSetEntry == nil {
		return nil
	}

	// Delete ValidatorEntry from PrefixSnapshotSetByPKID.
	key := DBKeyForSnapshotValidatorSetByPKID(snapshotValidatorSetEntry, snapshotAtEpochNumber)
	if err = DBDeleteWithTxn(txn, snap, key, eventManager, entryIsDeleted); err != nil {
		return errors.Wrapf(
			err, "DBDeleteSnapshotValidatorSetEntryWithTxn: problem deleting ValidatorEntry from index PrefixSnapshotSetByPKID",
		)
	}

	// Delete ValidatorEntry.PKID from PrefixSnapshotValidatorByStatusAndStakeAmount.
	key = DBKeyForSnapshotValidatorSetByStakeAmount(snapshotValidatorSetEntry, snapshotAtEpochNumber)
	if err = DBDeleteWithTxn(txn, snap, key, eventManager, entryIsDeleted); err != nil {
		return errors.Wrapf(
			err, "DBDeleteSnapshotValidatorSetEntryWithTxn: problem deleting ValidatorEntry from index PrefixSnapshotValidatorByStatusAndStakeAmount",
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
// SnapshotValidatorBLSPublicKeyToPKID
//

type SnapshotValidatorBLSPublicKeyMapKey struct {
	SnapshotAtEpochNumber uint64
	ValidatorBLSPublicKey bls.SerializedPublicKey
}

func (bav *UtxoView) GetCurrentSnapshotValidatorBLSPublicKeyPKIDPairEntry(blsPublicKey *bls.PublicKey) (*BLSPublicKeyPKIDPairEntry, error) {
	// Calculate the SnapshotEpochNumber.
	snapshotAtEpochNumber, err := bav.GetCurrentSnapshotEpochNumber()
	if err != nil {
		return nil, errors.Wrapf(err, "GetCurrentSnapshotValidatorBLSPublicKeyPKIDPairEntry: problem calculating SnapshotEpochNumber: ")
	}
	return bav.GetSnapshotValidatorBLSPublicKeyPKIDPairEntry(blsPublicKey, snapshotAtEpochNumber)
}

func (bav *UtxoView) GetSnapshotValidatorEntryByBLSPublicKey(blsPublicKey *bls.PublicKey, snapshotAtEpochNumber uint64) (*ValidatorEntry, error) {
	blsPublicKeyPKIDPairEntry, err := bav.GetSnapshotValidatorBLSPublicKeyPKIDPairEntry(blsPublicKey, snapshotAtEpochNumber)
	if err != nil {
		return nil, errors.Wrapf(err, "GetSnapshotValidatorEntryByBLSPublicKey: problem getting BLSPublicKeyPKIDPairEntry: ")
	}
	if blsPublicKeyPKIDPairEntry == nil {
		return nil, nil
	}
	return bav.GetSnapshotValidatorSetEntryByPKIDAtEpochNumber(blsPublicKeyPKIDPairEntry.PKID, snapshotAtEpochNumber)
}

func (bav *UtxoView) GetSnapshotValidatorBLSPublicKeyPKIDPairEntry(blsPublicKey *bls.PublicKey, snapshotAtEpochNumber uint64) (*BLSPublicKeyPKIDPairEntry, error) {
	blsPublicKeyPKIDPairEntry, err := bav.SnapshotCache.GetSnapshotValidatorEntryByBLSPublicKey(
		snapshotAtEpochNumber, blsPublicKey, bav.Handle, bav.Snapshot)
	if err != nil {
		return nil, errors.Wrapf(err, "GetSnapshotValidatorBLSPublicKeyPKIDPairEntry: ")
	}
	return blsPublicKeyPKIDPairEntry, nil
}

func DBKeyForSnapshotValidatorBLSPublicKeyPKIDPairEntry(blsPublicKeyPKIDPairEntry *BLSPublicKeyPKIDPairEntry, snapshotAtEpochNumber uint64) []byte {
	key := append([]byte{}, Prefixes.PrefixSnapshotValidatorBLSPublicKeyPKIDPairEntry...)
	key = append(key, EncodeUint64(snapshotAtEpochNumber)...)
	key = append(key, blsPublicKeyPKIDPairEntry.BLSPublicKey.ToBytes()...)
	return key
}

func DBGetSnapshotValidatorBLSPublicKeyPKIDPairEntry(handle *badger.DB, snap *Snapshot, blsPublicKey *bls.PublicKey, snapshotAtEpochNumber uint64) (*BLSPublicKeyPKIDPairEntry, error) {
	var ret *BLSPublicKeyPKIDPairEntry
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetSnapshotValidatorBLSPublicKeyPKIDPairEntryWithTxn(txn, snap, blsPublicKey, snapshotAtEpochNumber)
		return innerErr
	})
	return ret, err
}

func DBGetSnapshotValidatorBLSPublicKeyPKIDPairEntryWithTxn(txn *badger.Txn, snap *Snapshot, blsPublicKey *bls.PublicKey, snapshotAtEpochNumber uint64) (*BLSPublicKeyPKIDPairEntry, error) {
	// Retrieve from db.
	key := DBKeyForSnapshotValidatorBLSPublicKeyPKIDPairEntry(&BLSPublicKeyPKIDPairEntry{BLSPublicKey: blsPublicKey}, snapshotAtEpochNumber)
	blsPublicKeyPKIDPairEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return nil.
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "DBGetSnapshotValidatorBLSPublicKeyPKIDPairEntryWithTxn: problem retrieving BLSPublicKeyPKIDPairEntry")
	}

	// Decode from bytes.
	blsPublicKeyPKIDPairEntry := &BLSPublicKeyPKIDPairEntry{}
	rr := bytes.NewReader(blsPublicKeyPKIDPairEntryBytes)
	if exist, err := DecodeFromBytes(blsPublicKeyPKIDPairEntry, rr); !exist || err != nil {
		return nil, errors.Wrapf(err, "DBGetSnapshotValidatorBLSPublicKeyPKIDPairEntryWithTxn: problem decoding BLSPublicKeyPKIDPairEntry")
	}
	return blsPublicKeyPKIDPairEntry, nil
}

func DBPutSnapshotValidatorBLSPublicKeyPKIDPairEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	blsPublicKeyPKIDPairEntry *BLSPublicKeyPKIDPairEntry,
	snapshotAtEpochNumber uint64,
	blockHeight uint64,
	eventManager *EventManager,
) error {
	if blsPublicKeyPKIDPairEntry == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutSnapshotValidatorBLSPublicKeyPKIDPairEntryWithTxn: called with nil BLSPublicKeyPKIDPairEntry, this should never happen")
		return nil
	}

	// Put the BLSPublicKeyPKIDPairEntry in the SnapshotValidatorBLSPublicKeyPKIDPairEntries index.
	key := DBKeyForSnapshotValidatorBLSPublicKeyPKIDPairEntry(blsPublicKeyPKIDPairEntry, snapshotAtEpochNumber)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, blsPublicKeyPKIDPairEntry), eventManager); err != nil {
		return errors.Wrapf(
			err,
			"DBPutSnapshotValidatorBLSPublicKeyPKIDPairEntryWithTxn: problem putting BLSPublicKeyPKIDPairEntry in the SnapshotValidatorBLSPublicKeyPKIDPairEntry index: ",
		)
	}
	return nil
}

func DBDeleteSnapshotValidatorBLSPublicKeyPKIDPairEntryWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	blsPublicKeyPKIDPairEntry *BLSPublicKeyPKIDPairEntry,
	snapshotAtEpochNumber uint64,
	eventManager *EventManager,
	entryIsDeleted bool,
) error {
	if blsPublicKeyPKIDPairEntry == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBDeleteSnapshotValidatorBLSPublicKeyPKIDPairEntryWithTxn: called with nil BLSPublicKeyPKIDPairEntry, this should never happen")
		return nil
	}

	key := DBKeyForSnapshotValidatorBLSPublicKeyPKIDPairEntry(blsPublicKeyPKIDPairEntry, snapshotAtEpochNumber)
	if err := DBDeleteWithTxn(txn, snap, key, eventManager, entryIsDeleted); err != nil {
		return errors.Wrap(
			err, "DBDeleteSnapshotValidatorBLSPublicKeyPKIDPairEntryWithTxn: problem deleting BLSPublicKeyPKIDPairEntry from index PrefixSnapshotValidatorBLSPublicKeyPKIDPairEntry",
		)
	}
	return nil
}

func (bav *UtxoView) _setSnapshotValidatorBLSPublicKeyPKIDPairEntry(blsPublicKeyPKIDPairEntry *BLSPublicKeyPKIDPairEntry, snapshotAtEpochNumber uint64) {
	if blsPublicKeyPKIDPairEntry == nil {
		glog.Errorf("_setSnapshotValidatorBLSPublicKeyPKIDPairEntry: called with nil entry, this should never happen")
		return
	}

	bav.SnapshotValidatorBLSPublicKeyPKIDPairEntries[blsPublicKeyPKIDPairEntry.ToSnapshotMapKey(snapshotAtEpochNumber)] = blsPublicKeyPKIDPairEntry
}

func (bav *UtxoView) _flushSnapshotValidatorBLSPublicKeyPKIDPairEntryToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// Delete all SnapshotValidatorBLSPublicKeyToPKID entries from the db that are in the UtxoView.
	for mapKey, blsPublicKeyPKIDPairEntry := range bav.SnapshotValidatorBLSPublicKeyPKIDPairEntries {
		if blsPublicKeyPKIDPairEntry == nil {
			return fmt.Errorf(
				"_flushSnapshotValidatorBLSPublicKeyPKIDPairEntryToDbWithTxn: found nil entry for EpochNumber %d, this should never happen",
				mapKey.SnapshotAtEpochNumber,
			)
		}

		if err := DBDeleteSnapshotValidatorBLSPublicKeyPKIDPairEntryWithTxn(
			txn, bav.Snapshot, blsPublicKeyPKIDPairEntry, mapKey.SnapshotAtEpochNumber, bav.EventManager, blsPublicKeyPKIDPairEntry.isDeleted,
		); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotValidatorBLSPublicKeyPKIDPairEntryToDbWithTxn: problem deleting BLSPublicKeyPKIDPairEntry for EpochNumber %d: ",
				mapKey.SnapshotAtEpochNumber,
			)
		}
	}

	// Put all !isDeleted Snapshot BLSPublicKeyPKIDPairEntries into the db from the UtxoView.
	for mapKey, blsPublicKeyPKIDPairEntry := range bav.SnapshotValidatorBLSPublicKeyPKIDPairEntries {
		if blsPublicKeyPKIDPairEntry == nil {
			return fmt.Errorf(
				"_flushSnapshotValidatorBLSPublicKeyPKIDPairEntryToDbWithTxn: found nil entry for EpochNumber %d, this should never happen",
				mapKey.SnapshotAtEpochNumber,
			)
		}
		if blsPublicKeyPKIDPairEntry.isDeleted {
			// Skip any deleted BLSPublicKeyPKIDPairEntry.
			continue
		}
		if err := DBPutSnapshotValidatorBLSPublicKeyPKIDPairEntryWithTxn(
			txn, bav.Snapshot, blsPublicKeyPKIDPairEntry, mapKey.SnapshotAtEpochNumber, blockHeight, bav.EventManager,
		); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotValidatorBLSPublicKeyPKIDPairEntryToDbWithTxn: problem setting BLSPublicKeyPKIDPairEntry for EpochNumber %d: ",
				mapKey.SnapshotAtEpochNumber,
			)
		}
	}
	return nil
}

//
// SnapshotValidatorSetTotalStakeAmountNanos
//

func (bav *UtxoView) GetSnapshotValidatorSetTotalStakeAmountNanos() (*uint256.Int, error) {
	// Calculate the SnapshotEpochNumber.
	snapshotAtEpochNumber, err := bav.GetCurrentSnapshotEpochNumber()
	if err != nil {
		return nil, errors.Wrapf(err, "GetSnapshotValidatorSetTotalStakeAmountNanos: problem calculating SnapshotEpochNumber: ")
	}
	// Check the UtxoView first.
	if globalActiveStakeAmountNanos, exists := bav.SnapshotValidatorSetTotalStakeAmountNanos[snapshotAtEpochNumber]; exists {
		return globalActiveStakeAmountNanos.Clone(), nil
	}
	// If we don't have it in the UtxoView, check the db.
	globalActiveStakeAmountNanos, err := DBGetSnapshotValidatorSetTotalStakeAmountNanos(bav.Handle, bav.Snapshot, snapshotAtEpochNumber)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"GetSnapshotValidatorSetTotalStakeAmountNanos: problem retrieving SnapshotValidatorSetTotalStakeAmountNanos from db: ",
		)
	}
	if globalActiveStakeAmountNanos == nil {
		globalActiveStakeAmountNanos = uint256.NewInt()
	}
	// Cache the result in the UtxoView.
	bav._setSnapshotValidatorSetTotalStakeAmountNanos(globalActiveStakeAmountNanos, snapshotAtEpochNumber)
	return globalActiveStakeAmountNanos, nil
}

func (bav *UtxoView) _setSnapshotValidatorSetTotalStakeAmountNanos(globalActiveStakeAmountNanos *uint256.Int, snapshotAtEpochNumber uint64) {
	if globalActiveStakeAmountNanos == nil {
		glog.Errorf("_setSnapshotValidatorSetTotalStakeAmountNanos: called with nil entry, this should never happen")
		return
	}
	bav.SnapshotValidatorSetTotalStakeAmountNanos[snapshotAtEpochNumber] = globalActiveStakeAmountNanos.Clone()
}

func (bav *UtxoView) _flushSnapshotValidatorSetTotalStakeAmountNanosToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	for snapshotAtEpochNumber, globalActiveStakeAmountNanos := range bav.SnapshotValidatorSetTotalStakeAmountNanos {
		if globalActiveStakeAmountNanos == nil {
			return fmt.Errorf(
				"_flushSnapshotValidatorSetTotalStakeAmountNanosToDbWithTxn: found nil entry for EpochNumber %d, this should never happen",
				snapshotAtEpochNumber,
			)
		}
		if err := DBPutSnapshotValidatorSetTotalStakeAmountNanosWithTxn(
			txn, bav.Snapshot, globalActiveStakeAmountNanos, snapshotAtEpochNumber, blockHeight, bav.EventManager,
		); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotValidatorSetTotalStakeAmountNanosToDbWithTxn: problem setting SnapshotValidatorSetTotalStake for EpochNumber %d: ",
				snapshotAtEpochNumber,
			)
		}
	}
	return nil
}

func DBKeyForSnapshotValidatorSetTotalStakeAmountNanos(snapshotAtEpochNumber uint64) []byte {
	key := append([]byte{}, Prefixes.PrefixSnapshotValidatorSetTotalStakeAmountNanos...)
	key = append(key, EncodeUint64(snapshotAtEpochNumber)...)
	return key
}

func DBGetSnapshotValidatorSetTotalStakeAmountNanos(handle *badger.DB, snap *Snapshot, snapshotAtEpochNumber uint64) (*uint256.Int, error) {
	var ret *uint256.Int
	err := handle.View(func(txn *badger.Txn) error {
		var innerErr error
		ret, innerErr = DBGetSnapshotValidatorSetTotalStakeAmountNanosWithTxn(txn, snap, snapshotAtEpochNumber)
		return innerErr
	})
	return ret, err
}

func DBGetSnapshotValidatorSetTotalStakeAmountNanosWithTxn(txn *badger.Txn, snap *Snapshot, snapshotAtEpochNumber uint64) (*uint256.Int, error) {
	// Retrieve from db.
	key := DBKeyForSnapshotValidatorSetTotalStakeAmountNanos(snapshotAtEpochNumber)
	globalActiveStakeAmountNanosBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found. Instead, return nil.
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "DBGetSnapshotValidatorSetTotalStakeAmountNanosWithTxn: problem retrieving value")
	}

	// Decode from bytes.
	var globalActiveStakeAmountNanos *uint256.Int
	rr := bytes.NewReader(globalActiveStakeAmountNanosBytes)
	globalActiveStakeAmountNanos, err = VariableDecodeUint256(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetSnapshotValidatorSetTotalStakeAmountNanosWithTxn: problem decoding value")
	}
	return globalActiveStakeAmountNanos, nil
}

func DBPutSnapshotValidatorSetTotalStakeAmountNanosWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	globalActiveStakeAmountNanos *uint256.Int,
	snapshotAtEpochNumber uint64,
	blockHeight uint64,
	eventManager *EventManager,
) error {
	if globalActiveStakeAmountNanos == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutSnapshotValidatorSetTotalStakeAmountNanosWithTxn: called with nil GlobalActiveStake, this should never happen")
		return nil
	}
	key := DBKeyForSnapshotValidatorSetTotalStakeAmountNanos(snapshotAtEpochNumber)
	return DBSetWithTxn(txn, snap, key, VariableEncodeUint256(globalActiveStakeAmountNanos), eventManager)
}

//
// SnapshotStakeToReward
//

type SnapshotStakeMapKey struct {
	SnapshotAtEpochNumber uint64
	ValidatorPKID         PKID
	StakerPKID            PKID
}

func NewSnapshotStakeMapKey(stakeEntry *StakeEntry, snapshotAtEpochNumber uint64) SnapshotStakeMapKey {
	return SnapshotStakeMapKey{
		SnapshotAtEpochNumber: snapshotAtEpochNumber,
		ValidatorPKID:         *stakeEntry.ValidatorPKID,
		StakerPKID:            *stakeEntry.StakerPKID,
	}
}

func (bav *UtxoView) _setSnapshotStakeToReward(stakeEntry *StakeEntry, snapshotAtEpochNumber uint64) {
	if stakeEntry == nil {
		glog.Errorf("_setSnapshotStakeToReward: called with nil stakeEntry")
		return
	}
	bav.SnapshotStakesToReward[NewSnapshotStakeMapKey(stakeEntry, snapshotAtEpochNumber)] = stakeEntry.Copy()
}

// GetAllSnapshotStakesToReward returns all snapshotted StakeEntries that are eligible to receive staking
// rewards for the current snapshot epoch. The order of the returned entries is arbitrary.
func (bav *UtxoView) GetAllSnapshotStakesToReward() ([]*StakeEntry, error) {
	snapshotGlobalParams, err := bav.GetCurrentSnapshotGlobalParamsEntry()
	if err != nil {
		return nil, errors.Wrapf(err, "GetAllSnapshotStakesToReward: problem calculating SnapshotEpochNumber: ")
	}

	// If the max number of snapshot stakes is 0, then we don't need to do anything.
	maxNumSnapshotStakes := snapshotGlobalParams.StakingRewardsMaxNumStakes
	if maxNumSnapshotStakes == 0 {
		return nil, nil
	}

	// Calculate the SnapshotEpochNumber.
	snapshotAtEpochNumber, err := bav.GetCurrentSnapshotEpochNumber()
	if err != nil {
		return nil, errors.Wrapf(err, "GetAllSnapshotStakesToReward: problem calculating SnapshotEpochNumber: ")
	}

	// Create a slice of all UtxoView snapshot StakeEntries to prevent pulling them from the db.
	var utxoViewStakeEntries []*StakeEntry
	for mapKey, stakeEntry := range bav.SnapshotStakesToReward {
		if mapKey.SnapshotAtEpochNumber == snapshotAtEpochNumber {
			utxoViewStakeEntries = append(utxoViewStakeEntries, stakeEntry)
		}
	}

	// Pull top N snapshot StakeEntries from the database (not present in the UtxoView).
	dbStakeEntries, err := DBGetSnapshotStakesToReward(
		bav.Handle, bav.Snapshot, maxNumSnapshotStakes, snapshotAtEpochNumber, utxoViewStakeEntries,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "GetAllSnapshotStakesToReward: error retrieving entries from db: ")
	}

	// Cache the snapshot StakeEntries from the db in the UtxoView.
	for _, stakeEntry := range dbStakeEntries {
		mapKey := NewSnapshotStakeMapKey(stakeEntry, snapshotAtEpochNumber)
		if _, exists := bav.SnapshotStakesToReward[mapKey]; exists {
			// We should never see duplicate entries from the db that are already in the UtxoView. This is a
			// sign of a bug and that the utxoViewStakeEntries isn't being used correctly.
			return nil, fmt.Errorf("GetAllSnapshotStakesToReward: db returned a snapshot StakeEntry" +
				" that already exists in the UtxoView")
		}

		bav._setSnapshotStakeToReward(stakeEntry, snapshotAtEpochNumber)
	}

	// Pull all non-deleted snapshot StakeEntries from the UtxoView with stake > 0.
	var mergedStakeEntries []*StakeEntry
	for mapKey, stakeEntry := range bav.SnapshotStakesToReward {
		if stakeEntry.isDeleted {
			// Skip any deleted StakeEntries.
			continue
		}

		// All entries should have > 0 stake to begin with, but we filter here again just in case.
		if mapKey.SnapshotAtEpochNumber != snapshotAtEpochNumber || stakeEntry.StakeAmountNanos.IsZero() {
			continue
		}

		mergedStakeEntries = append(mergedStakeEntries, stakeEntry)
	}

	return mergedStakeEntries, nil
}

func DBGetSnapshotStakesToReward(
	handle *badger.DB,
	snap *Snapshot,
	limit uint64,
	snapshotAtEpochNumber uint64,
	stakeEntriesToSkip []*StakeEntry,
) ([]*StakeEntry, error) {
	// Convert StakeEntriesToSkip to the SnapshotStakeMapKeys we need to skip.
	snapshotStakeDBKeysToSkip := NewSet([]string{})
	for _, stakeEntryToSkip := range stakeEntriesToSkip {
		snapshotStakeDBKeysToSkip.Add(
			string(DBKeyForSnapshotStakeToRewardByValidatorAndStaker(
				snapshotAtEpochNumber,
				stakeEntryToSkip.ValidatorPKID,
				stakeEntryToSkip.StakerPKID,
			)),
		)
	}

	// Retrieve the snapshot StakeEntries from the DB.
	prefix := DBKeyForSnapshotStakeToRewardAtEpochNumber(snapshotAtEpochNumber)
	_, valsFound, err := EnumerateKeysForPrefixWithLimitOffsetOrder(
		handle, prefix, int(limit), nil, true, snapshotStakeDBKeysToSkip,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetSnapshotStakesToReward:"+
			" problem retrieving top stakes: ")
	}

	// Decode StakeEntries from bytes.
	var stakeEntries []*StakeEntry
	for _, stakeEntryBytes := range valsFound {
		rr := bytes.NewReader(stakeEntryBytes)
		stakeEntry, err := DecodeDeSoEncoder(&StakeEntry{}, rr)
		if err != nil {
			return nil, errors.Wrapf(err, "DBGetSnapshotStakesToReward: problem decoding StakeEntry: ")
		}
		stakeEntries = append(stakeEntries, stakeEntry)
	}
	return stakeEntries, nil
}

func (bav *UtxoView) _flushSnapshotStakesToRewardToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// Delete all snapshot StakeEntries in the UtxoView map.
	for mapKeyIter, stakeEntryIter := range bav.SnapshotStakesToReward {
		// Make a copy of the iterators since we make references to them below.
		mapKey := mapKeyIter
		stakeEntry := *stakeEntryIter

		// Sanity-check that the entry matches the map key.
		mapKeyFromEntry := NewSnapshotStakeMapKey(&stakeEntry, mapKey.SnapshotAtEpochNumber)
		if mapKeyFromEntry != mapKey {
			return fmt.Errorf(
				"_flushSnapshotStakesToRewardToDbWithTxn: snapshot StakeEntry key %v doesn't match MapKey %v",
				&mapKeyFromEntry,
				&mapKey,
			)
		}

		// Delete the existing mappings in the db for this map key. They will be
		// re-added if the corresponding entry in-memory has isDeleted=false.
		if err := DBDeleteSnapshotStakeToRewardWithTxn(
			txn, bav.Snapshot, stakeEntry.ValidatorPKID, stakeEntry.StakerPKID, mapKey.SnapshotAtEpochNumber, blockHeight, bav.EventManager, stakeEntry.isDeleted,
		); err != nil {
			return errors.Wrapf(err, "_flushSnapshotStakesToRewardToDbWithTxn: ")
		}
	}

	for mapKey, stakeEntry := range bav.SnapshotStakesToReward {
		if stakeEntry.isDeleted {
			// Skip any deleted StakeEntries.
			continue
		}

		if err := DBPutSnapshotStakeToRewardWithTxn(
			txn, bav.Snapshot, stakeEntry, mapKey.SnapshotAtEpochNumber, blockHeight, bav.EventManager,
		); err != nil {
			return errors.Wrapf(
				err,
				"_flushSnapshotStakesToRewardToDbWithTxn: problem setting snapshot stakeEntry"+
					" for SnapshotAtEpochNumber %d: ",
				mapKey.SnapshotAtEpochNumber,
			)
		}
	}
	return nil
}

func DBDeleteSnapshotStakeToRewardWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	validatorPKID *PKID,
	stakerPKID *PKID,
	snapshotAtEpochNumber uint64,
	blockHeight uint64,
	eventManager *EventManager,
	entryIsDeleted bool,
) error {
	if validatorPKID == nil || stakerPKID == nil {
		return nil
	}

	// Delete the snapshot StakeEntry from PrefixSnapshotStakeToRewardByValidatorByStaker.
	stakeByValidatorAndStakerKey := DBKeyForSnapshotStakeToRewardByValidatorAndStaker(snapshotAtEpochNumber, validatorPKID, stakerPKID)
	if err := DBDeleteWithTxn(txn, snap, stakeByValidatorAndStakerKey, eventManager, entryIsDeleted); err != nil {
		return errors.Wrapf(
			err, "DBDeleteSnapshotStakeToRewardWithTxn: problem deleting snapshot StakeEntry from index PrefixSnapshotStakeToRewardByValidatorByStaker: ",
		)
	}

	return nil
}

func DBPutSnapshotStakeToRewardWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	stakeEntry *StakeEntry,
	snapshotAtEpochNumber uint64,
	blockHeight uint64,
	eventManager *EventManager,
) error {
	if stakeEntry == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutSnapshotStakeToRewardWithTxn: called with nil stakeEntry")
		return nil
	}

	dbKey := DBKeyForSnapshotStakeToRewardByValidatorAndStaker(snapshotAtEpochNumber, stakeEntry.ValidatorPKID, stakeEntry.StakerPKID)
	if err := DBSetWithTxn(txn, snap, dbKey, EncodeToBytes(blockHeight, stakeEntry), eventManager); err != nil {
		return errors.Wrapf(
			err,
			"DBPutSnapshotStakeToRewardWithTxn: problem putting snapshot stakeEntry in the SnapshotStakeToRewardByValidatorAndStaker index: ",
		)
	}
	return nil
}

func DBKeyForSnapshotStakeToRewardByValidatorAndStaker(snapshotAtEpochNumber uint64, validatorPKID *PKID, stakerPKID *PKID) []byte {
	data := DBKeyForSnapshotStakeToRewardAtEpochNumber(snapshotAtEpochNumber)
	data = append(data, validatorPKID.ToBytes()...)
	data = append(data, stakerPKID.ToBytes()...)
	return data
}

func DBKeyForSnapshotStakeToRewardAtEpochNumber(snapshotAtEpochNumber uint64) []byte {
	data := append([]byte{}, Prefixes.PrefixSnapshotStakeToRewardByValidatorAndStaker...)
	data = append(data, EncodeUint64(snapshotAtEpochNumber)...)
	return data
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
	snapshotAtEpochNumber, err := bav.GetCurrentSnapshotEpochNumber()
	if err != nil {
		return nil, errors.Wrapf(err, " GetSnapshotLeaderScheduleValidator: problem calculating SnapshotEpochNumber: ")
	}
	validatorEntry, err := bav.SnapshotCache.GetSnapshotLeaderScheduleValidator(
		snapshotAtEpochNumber, leaderIndex, bav.Handle, bav.Snapshot)
	if err != nil {
		return nil, errors.Wrapf(err, "GetSnapshotLeaderScheduleValidator: ")
	}
	return validatorEntry, nil
}

type LeaderPKIDAndIndex struct {
	leaderIdx  uint16
	leaderPKID *PKID
}

func (bav *UtxoView) GetCurrentSnapshotLeaderSchedule() ([]*PKID, error) {
	snapshotAtEpochNumber, err := bav.GetCurrentSnapshotEpochNumber()
	if err != nil {
		return nil, errors.Wrapf(err, "GetCurrentSnapshotLeaderSchedule: problem calculating SnapshotEpochNumber: ")
	}
	snapshotLeaderSchedule, err := bav.GetSnapshotLeaderScheduleAtEpochNumber(snapshotAtEpochNumber)
	if err != nil {
		return nil, errors.Wrapf(err, "GetCurrentSnapshotLeaderSchedule: problem retrieving LeaderSchedule: ")
	}
	return snapshotLeaderSchedule, nil
}
func (bav *UtxoView) GetSnapshotLeaderScheduleAtEpochNumber(snapshotAtEpochNumber uint64) ([]*PKID, error) {
	if !bav.HasFullSnapshotLeaderScheduleByEpoch[snapshotAtEpochNumber] {
		// Seek over DB prefix and merge into view.
		leaderIdxToValidatorPKIDMap, err := DBSeekSnapshotLeaderSchedule(bav.Handle, snapshotAtEpochNumber)
		if err != nil {
			return nil, errors.Wrapf(err, "GetSnapshotLeaderScheduleAtEpochNumber: error retrieving ValidatorPKIDs: ")
		}
		// Merge the DB entries into the UtxoView.
		for leaderIdx, validatorPKID := range leaderIdxToValidatorPKIDMap {
			snapshotLeaderScheduleMapKey := SnapshotLeaderScheduleMapKey{
				SnapshotAtEpochNumber: snapshotAtEpochNumber,
				LeaderIndex:           leaderIdx,
			}
			if _, exists := bav.SnapshotLeaderSchedule[snapshotLeaderScheduleMapKey]; !exists {
				bav._setSnapshotLeaderScheduleValidator(validatorPKID, leaderIdx, snapshotAtEpochNumber)
			}
		}
	}

	// First, check the UtxoView.
	var leaderPKIDAndIndexSlice []LeaderPKIDAndIndex
	for mapKey, validatorPKID := range bav.SnapshotLeaderSchedule {
		if mapKey.SnapshotAtEpochNumber == snapshotAtEpochNumber {
			leaderPKIDAndIndexSlice = append(leaderPKIDAndIndexSlice, LeaderPKIDAndIndex{
				leaderIdx:  mapKey.LeaderIndex,
				leaderPKID: validatorPKID,
			})
		}
	}
	sort.Slice(leaderPKIDAndIndexSlice, func(ii, jj int) bool {
		return leaderPKIDAndIndexSlice[ii].leaderIdx < leaderPKIDAndIndexSlice[jj].leaderIdx
	})
	leaderPKIDs := collections.Transform(leaderPKIDAndIndexSlice, func(index LeaderPKIDAndIndex) *PKID {
		return index.leaderPKID
	})
	return leaderPKIDs, nil
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
			txn, bav.Snapshot, validatorPKID, mapKey.LeaderIndex, mapKey.SnapshotAtEpochNumber, blockHeight, bav.EventManager,
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

func DBSSeekKeyForSnapshotLeaderSchedule(snapshotAtEpochNumber uint64) []byte {
	data := append([]byte{}, Prefixes.PrefixSnapshotLeaderSchedule...)
	data = append(data, EncodeUint64(snapshotAtEpochNumber)...)
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
	return DBGetSnapshotValidatorSetEntryByPKIDWithTxn(txn, snap, validatorPKID, snapshotAtEpochNumber)
}

func DBSeekSnapshotLeaderSchedule(
	handle *badger.DB,
	snapshotAtEpochNumber uint64,
) (map[uint16]*PKID, error) {
	seekKey := DBSSeekKeyForSnapshotLeaderSchedule(snapshotAtEpochNumber)
	keysFound, valsFound := EnumerateKeysForPrefix(handle, seekKey)
	leaderIdxToPKID := make(map[uint16]*PKID)
	for idx, keyFound := range keysFound {
		// TODO: Make sure this decode is correct
		leaderIndex := DecodeUint16(keyFound[len(seekKey):])
		// Decode ValidatorPKID from bytes.
		validatorPKID := &PKID{}
		rr := bytes.NewReader(valsFound[idx])
		if exist, err := DecodeFromBytes(validatorPKID, rr); !exist || err != nil {
			return nil, errors.Wrapf(err, "DBSeekSnapshotLeaderSchedule: problem decoding ValidatorPKID")
		}
		leaderIdxToPKID[leaderIndex] = validatorPKID
	}
	return leaderIdxToPKID, nil
}

func DBPutSnapshotLeaderScheduleValidatorWithTxn(
	txn *badger.Txn,
	snap *Snapshot,
	validatorPKID *PKID,
	leaderIndex uint16,
	snapshotAtEpochNumber uint64,
	blockHeight uint64,
	eventManager *EventManager,
) error {
	if validatorPKID == nil {
		// This should never happen but is a sanity check.
		glog.Errorf("DBPutSnapshotLeaderScheduleValidatorWithTxn: called with nil ValidatorPKID, this should never happen")
		return nil
	}
	key := DBKeyForSnapshotLeaderScheduleValidator(leaderIndex, snapshotAtEpochNumber)
	if err := DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, validatorPKID), eventManager); err != nil {
		return errors.Wrapf(
			err,
			"DBPutSnapshotLeaderScheduleValidatorWithTxn: problem putting ValidatorPKID in the SnapshotLeaderSchedule index: ",
		)
	}
	return nil
}
