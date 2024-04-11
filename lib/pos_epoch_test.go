package lib

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCurrentEpoch(t *testing.T) {
	var epochEntry *EpochEntry
	var err error

	// Initialize blockchain.
	chain, params, db := NewLowDifficultyBlockchain(t)
	blockHeight := uint64(chain.blockTip().Height) + 1
	blockTimestampNanoSecs := chain.blockTip().Header.TstampNanoSecs + 1e9
	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
	require.NoError(t, err)

	// Test that the CurrentEpoch is nil in the db.
	epochEntry, err = DBGetCurrentEpochEntry(db, utxoView.Snapshot)
	require.NoError(t, err)
	require.Nil(t, epochEntry)

	// Test that the CurrentEpoch is nil in the UtxoView.
	require.Nil(t, utxoView.CurrentEpochEntry)

	// Test GetCurrentEpoch() returns the GenesisEpochEntry.
	epochEntry, err = utxoView.GetCurrentEpochEntry()
	require.NoError(t, err)
	require.NotNil(t, epochEntry)
	require.Equal(t, epochEntry.EpochNumber, uint64(0))
	require.Equal(t, epochEntry.FinalBlockHeight, uint64(utxoView.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight))

	// Set the CurrentEpoch.
	epochEntry = &EpochEntry{
		EpochNumber:                     1,
		InitialBlockHeight:              blockHeight + 1,
		InitialView:                     1,
		FinalBlockHeight:                blockHeight + 5,
		InitialLeaderIndexOffset:        2,
		CreatedAtBlockTimestampNanoSecs: blockTimestampNanoSecs + 5*1e9,
	}
	utxoView._setCurrentEpochEntry(epochEntry)
	require.NoError(t, utxoView.FlushToDb(blockHeight))

	// Test that the CurrentEpoch is set in the db.
	epochEntry, err = DBGetCurrentEpochEntry(db, utxoView.Snapshot)
	require.NoError(t, err)
	require.NotNil(t, epochEntry)
	require.Equal(t, epochEntry.EpochNumber, uint64(1))
	require.Equal(t, epochEntry.InitialBlockHeight, blockHeight+1)
	require.Equal(t, epochEntry.InitialView, uint64(1))
	require.Equal(t, epochEntry.FinalBlockHeight, blockHeight+5)
	require.Equal(t, epochEntry.InitialLeaderIndexOffset, uint64(2))
	require.Equal(t, epochEntry.CreatedAtBlockTimestampNanoSecs, blockTimestampNanoSecs+5*1e9)

	// Test that the CurrentEpoch is flushed from the UtxoView.
	require.Nil(t, utxoView.CurrentEpochEntry)

	// Test GetCurrentEpoch().
	epochEntry, err = utxoView.GetCurrentEpochEntry()
	require.NoError(t, err)
	require.NotNil(t, epochEntry)
	require.Equal(t, epochEntry.EpochNumber, uint64(1))
	require.Equal(t, epochEntry.InitialBlockHeight, blockHeight+1)
	require.Equal(t, epochEntry.InitialView, uint64(1))
	require.Equal(t, epochEntry.FinalBlockHeight, blockHeight+5)
	require.Equal(t, epochEntry.InitialLeaderIndexOffset, uint64(2))
	require.Equal(t, epochEntry.CreatedAtBlockTimestampNanoSecs, blockTimestampNanoSecs+5*1e9)

	// Test that the CurrentEpoch is set in the UtxoView.
	epochEntry = utxoView.CurrentEpochEntry
	require.NotNil(t, epochEntry)
	require.Equal(t, epochEntry.EpochNumber, uint64(1))
	require.Equal(t, epochEntry.InitialBlockHeight, blockHeight+1)
	require.Equal(t, epochEntry.InitialView, uint64(1))
	require.Equal(t, epochEntry.FinalBlockHeight, blockHeight+5)
	require.Equal(t, epochEntry.InitialLeaderIndexOffset, uint64(2))
	require.Equal(t, epochEntry.CreatedAtBlockTimestampNanoSecs, blockTimestampNanoSecs+5*1e9)

	// Delete CurrentEpoch from the UtxoView.
	utxoView.CurrentEpochEntry = nil
	require.Nil(t, utxoView.CurrentEpochEntry)

	// CurrentEpoch still exists in the db.
	epochEntry, err = DBGetCurrentEpochEntry(db, utxoView.Snapshot)
	require.NoError(t, err)
	require.NotNil(t, epochEntry)

	// GetCurrentEpoch() should return the CurrentEpoch from the db.
	epochEntry, err = utxoView.GetCurrentEpochEntry()
	require.NoError(t, err)
	require.NotNil(t, epochEntry)

	// CurrentEpoch gets cached in the UtxoView.
	require.NotNil(t, utxoView.CurrentEpochEntry)

	// Test GetCurrentEpochNumber().
	require.Equal(t, utxoView.CurrentEpochEntry.EpochNumber, uint64(1))
}
