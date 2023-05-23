package lib

import "github.com/pkg/errors"

func (bav *UtxoView) IsLastBlockInCurrentEpoch(blockHeight uint64) (bool, error) {
	// Returns true if this is the last block in the current epoch.
	currentEpochEntry, err := bav.GetCurrentEpochEntry()
	if err != nil {
		return false, errors.Wrapf(err, "UtxoView.IsEpochComplete: problem retrieving CurrentEpochEntry: ")
	}
	if currentEpochEntry == nil {
		return false, errors.New("UtxoView.IsEpochComplete: CurrentEpochEntry is nil, this should never happen")
	}
	return currentEpochEntry.FinalBlockHeight == blockHeight, nil
}

func (bav *UtxoView) RolloverEpochs(blockHeight uint64) error {
	// Rolls-over the current epoch into a new one. Takes care of the associated snapshotting + accounting.

	// Sanity-check that the current block is the last block in the current epoch.
	isLastBlockInCurrentEpoch, err := bav.IsLastBlockInCurrentEpoch(blockHeight)
	if err != nil {
		return errors.Wrapf(err, "UtxoView.RolloverEpochs: ")
	}
	if !isLastBlockInCurrentEpoch {
		return errors.New("UtxoView.RolloverEpochs: called before current epoch is complete, this should never happen")
	}

	// Snapshot the current GlobalParamsEntry.
	// TODO

	// Snapshot the current validator set.
	// TODO

	// Generate + store a leader schedule.
	// TODO

	// Roll-over a new epoch by setting a new CurrentEpochEntry.
	currentEpochEntry, err := bav.GetCurrentEpochEntry()
	if err != nil {
		return errors.Wrapf(err, "UtxoView.RolloverEpochs: problem retrieving CurrentEpochEntry: ")
	}
	if currentEpochEntry == nil {
		return errors.New("UtxoView.RolloverEpochs: CurrentEpochEntry is nil, this should never happen")
	}
	newEpochEntry := &EpochEntry{
		EpochNumber:      currentEpochEntry.EpochNumber + 1,
		FinalBlockHeight: blockHeight + 100, // TODO: read this duration from the GlobalParamsEntry.
	}
	bav._setCurrentEpochEntry(newEpochEntry)

	return nil
}
