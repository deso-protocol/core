package lib

import (
	"github.com/pkg/errors"
	"math"
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

	// Snapshot the current GlobalParamsEntry.
	bav._setSnapshotGlobalParamsEntry(bav.GlobalParamsEntry, currentEpochEntry.EpochNumber)

	// Snapshot the current ValidatorEntries. This loops through all validators to snapshot them in O(N).
	// To save on runtime, in this loop we also check if we should jail each validator and jail them if so.
	// We optionally jail a validator after we snapshot them. A jailed validator should be considered jailed
	// in the new epoch starting after this OnEpochCompleteHook, and not the previous epoch which is snapshot.
	if err = bav.SnapshotCurrentValidators(currentEpochEntry.EpochNumber, blockHeight); err != nil {
		return errors.Wrapf(err, "RunEpochCompleteHook: problem snapshotting validators: ")
	}

	// Snapshot the current GlobalActiveStakeAmountNanos.
	globalActiveStakeAmountNanos, err := bav.GetGlobalActiveStakeAmountNanos()
	if err != nil {
		return errors.Wrapf(err, "RunEpochCompleteHook: problem retrieving GlobalActiveStakeAmountNanos: ")
	}
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

	// Retrieve the SnapshotGlobalParamsEntry.EpochDurationNumBlocks.
	snapshotGlobalParamsEntry, err := bav.GetSnapshotGlobalParamsEntry()
	if err != nil {
		return errors.Wrapf(err, "RunEpochCompleteHook: problem retrieving SnapshotGlobalParamsEntry: ")
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
