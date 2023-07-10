package lib

import (
	"math"

	"github.com/pkg/errors"
)

func (bav *UtxoView) IsLastBlockInCurrentEpoch(blockHeight uint64) (bool, error) {
	// Returns true if this is the last block in the current epoch.

	if blockHeight < uint64(bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight) {
		// Return false if we have not started snapshotting the relevant PoS entries yet.
		return false, nil
	}
	if blockHeight == uint64(bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight) {
		// As soon as we enable snapshotting for the first time, we should run the OnEpochCompleteHook.
		return true, nil
	}
	currentEpochEntry, err := bav.GetCurrentEpochEntry()
	if err != nil {
		return false, errors.Wrapf(err, "IsEpochComplete: problem retrieving CurrentEpochEntry: ")
	}
	if currentEpochEntry == nil {
		return false, errors.New("IsEpochComplete: CurrentEpochEntry is nil, this should never happen")
	}
	return currentEpochEntry.FinalBlockHeight == blockHeight, nil
}

// RunEpochCompleteHook performs all of the end-of-epoch operations when connecting the final
// block of a epoch. There epoch completion has two steps.
//
// Step 1: Create snapshots of current state. Snapshotting operations here should only create new
// snapshot state. They should have no other side effects that mutate the existing state of the view.
// 1. Snapshot the current GlobalParamsEntry.
// 2. Snapshot the current validator set.
// 3. Snapshot the current GlobalActiveStakeAmountNanos.
// 4. Snapshot the leader schedule.
//
// Step 2: Transition to the next epoch. This runs all state-mutating operations that need to be run for
// the epoch transition. We always perform state-mutating operations after creating snapshots. This way,
// the snapshot created at the end of epoch n always reflects the state of the view at the end of epoch n.
// And it does not reflect the state changes that occur AFTER epoch n ends and before epoch n+1 BEGINS.
// 1. Jail all inactive validators from the current snapshot validator set.
// 2. Compute the final block height for the next epoch.
// 3. Transition CurrentEpochEntry to the next epoch.
func (bav *UtxoView) RunEpochCompleteHook(blockHeight uint64) error {
	// Rolls-over the current epoch into a new one. Handles the associated snapshotting + accounting.

	// Sanity-check that the current block is the last block in the current epoch.
	//
	// Note that this will also return true if we're currently at the
	// ProofOfStake1StateSetupBlockHeight so that we can run the hook for the first time
	// to initialize the CurrentEpochEntry.
	isLastBlockInCurrentEpoch, err := bav.IsLastBlockInCurrentEpoch(blockHeight)
	if err != nil {
		return errors.Wrapf(err, "RunEpochCompleteHook: ")
	}
	if !isLastBlockInCurrentEpoch {
		return errors.New("RunEpochCompleteHook: called before current epoch is complete, this should never happen")
	}

	// Retrieve the CurrentEpochEntry.
	currentEpochEntry, err := bav.GetCurrentEpochEntry()
	if err != nil {
		return errors.Wrapf(err, "RunEpochCompleteHook: problem retrieving CurrentEpochEntry: ")
	}
	if currentEpochEntry == nil {
		return errors.New("RunEpochCompleteHook: CurrentEpochEntry is nil, this should never happen")
	}

	currentGlobalParamsEntry := bav.GetCurrentGlobalParamsEntry()

	// Snapshot the current GlobalParamsEntry.
	bav._setSnapshotGlobalParamsEntry(bav.GlobalParamsEntry, currentEpochEntry.EpochNumber)

	// Snapshot the current top n active validators as the current validator set.
	validatorSet, err := bav.GetTopActiveValidatorsByStake(currentGlobalParamsEntry.ValidatorSetMaxNumValidators)
	if err != nil {
		return errors.Wrapf(err, "RunEpochCompleteHook: error retrieving top ValidatorEntries: ")
	}
	for _, validatorEntry := range validatorSet {
		bav._setSnapshotValidatorSetEntry(validatorEntry, currentEpochEntry.EpochNumber)
	}

	// Snapshot the current validator set's total stake.
	globalActiveStakeAmountNanos := SumValidatorStakeAmountNanos(validatorSet)
	bav._setSnapshotGlobalActiveStakeAmountNanos(globalActiveStakeAmountNanos, currentEpochEntry.EpochNumber)

	// Generate + snapshot a leader schedule.
	leaderSchedule, err := bav.GenerateLeaderSchedule()
	if err != nil {
		return errors.Wrapf(err, "RunEpochCompleteHook: problem generating leader schedule: ")
	}
	for index, validatorPKID := range leaderSchedule {
		if index > math.MaxUint16 {
			return errors.Errorf("RunEpochCompleteHook: LeaderIndex %d overflows uint16", index)
		}
		bav._setSnapshotLeaderScheduleValidator(validatorPKID, uint16(index), currentEpochEntry.EpochNumber)
	}

	// TODO: Delete old snapshots that are no longer used.

	// Retrieve the SnapshotGlobalParamsEntry.
	snapshotGlobalParamsEntry, err := bav.GetSnapshotGlobalParamsEntry()
	if err != nil {
		return errors.Wrapf(err, "RunEpochCompleteHook: problem retrieving SnapshotGlobalParamsEntry: ")
	}

	// Jail all inactive validators from the current snapshot validator set. This is an O(n) operation
	// that loops through all validators and jails them if they are inactive. A jailed validator should be
	// considered jailed in the next epoch we are transition into.
	if err = bav.JailAllInactiveValidators(blockHeight); err != nil {
		return errors.Wrapf(err, "RunEpochCompleteHook: problem jailing all inactive validators: ")
	}

	// Calculate the NextEpochFinalBlockHeight.
	nextEpochFinalBlockHeight, err := SafeUint64().Add(blockHeight, snapshotGlobalParamsEntry.EpochDurationNumBlocks)
	if err != nil {
		return errors.Wrapf(err, "RunEpochCompleteHook: problem calculating NextEpochFinalBlockHeight: ")
	}

	// Roll-over a new epoch by setting a new CurrentEpochEntry.
	nextEpochEntry := &EpochEntry{
		EpochNumber:      currentEpochEntry.EpochNumber + 1,
		FinalBlockHeight: nextEpochFinalBlockHeight,
	}
	bav._setCurrentEpochEntry(nextEpochEntry)

	return nil
}
