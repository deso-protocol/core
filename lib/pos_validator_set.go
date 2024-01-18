package lib

import "github.com/pkg/errors"

// GetSnapshotValidatorSetsForBlockHeights returns the validator set for each block height provided.
// It requires all input block heights to be in the previous, current, or next epoch.
func (bav *UtxoView) GetSnapshotValidatorSetsForBlockHeights(blockHeights []uint64) (map[uint64][]*ValidatorEntry, error) {
	// Create a map to cache the validator set entries by epoch number. Two blocks in the same epoch will have
	// the same validator set, so we can use an in-memory cache to optimize the validator set lookup for them.
	validatorSetEntriesBySnapshotEpochNumber := make(map[uint64][]*ValidatorEntry)

	// Fetch the current epoch entry
	currentEpochEntry, err := bav.GetCurrentEpochEntry()
	if err != nil {
		return nil, errors.Errorf("Error fetching current epoch entry: %v", err)
	}

	// Fetch the previous epoch entry
	prevEpochEntry, err := bav.simulatePrevEpochEntry(currentEpochEntry.EpochNumber, currentEpochEntry.FinalBlockHeight)
	if err != nil {
		return nil, errors.Errorf("Error fetching previous epoch entry: %v", err)
	}

	// Fetch the next epoch entry
	nextEpochEntry, err := bav.simulateNextEpochEntry(currentEpochEntry.EpochNumber, currentEpochEntry.FinalBlockHeight)
	if err != nil {
		return nil, errors.Errorf("Error fetching next epoch entry: %v", err)
	}

	// The supported block heights can only be part of the previous, current, or next epoch.
	possibleEpochEntriesForBlocks := []*EpochEntry{prevEpochEntry, currentEpochEntry, nextEpochEntry}

	// Output map that will hold the validator set for each block height
	validatorSetByBlockHeight := map[uint64][]*ValidatorEntry{}

	// Fetch the validator set at each block height
	for _, blockHeight := range blockHeights {
		epochEntryForBlock, err := findEpochEntryForBlockHeight(blockHeight, possibleEpochEntriesForBlocks)
		if err != nil {
			return nil, errors.Errorf("Error fetching epoch number for block height %d: %v", blockHeight, err)
		}

		// Compute the snapshot epoch number for the block height. This is the epoch number that the validator set
		// for the block was snapshotted in.
		snapshotEpochNumber, err := bav.ComputeSnapshotEpochNumberForEpoch(epochEntryForBlock.EpochNumber)
		if err != nil {
			return nil, errors.Errorf("error computing snapshot epoch number for epoch number %d: %v", epochEntryForBlock.EpochNumber, err)
		}

		var validatorSet []*ValidatorEntry
		var ok bool

		// If the validator set for the block is already cached by the snapshot epoch number, then use it.
		// Otherwise, fetch it from the UtxoView.
		if validatorSet, ok = validatorSetEntriesBySnapshotEpochNumber[snapshotEpochNumber]; !ok {
			// We don't have the validator set for the block cached. Fetch it from the UtxoView.
			validatorSet, err = bav.GetAllSnapshotValidatorSetEntriesByStakeAtEpochNumber(snapshotEpochNumber)
			if err != nil {
				return nil, errors.Errorf("Error fetching validator set for block: %v", err)
			}
		}

		validatorSetByBlockHeight[blockHeight] = validatorSet
	}

	// Happy path: we fetched the validator lists for all block heights successfully.
	return validatorSetByBlockHeight, nil
}

// Given a list of epoch entries, this finds the epoch entry for the given block height.
func findEpochEntryForBlockHeight(blockHeight uint64, epochEntries []*EpochEntry) (*EpochEntry, error) {
	for _, epochEntry := range epochEntries {
		if epochEntry.ContainsBlockHeight(blockHeight) {
			return epochEntry, nil
		}
	}

	return nil, errors.Errorf("error finding epoch entry for block height: %v", blockHeight)
}
