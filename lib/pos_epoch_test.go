package lib

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCurrentEpoch(t *testing.T) {
	var epochEntry *EpochEntry
	var err error

	// Initialize blockchain.
	chain, params, db := NewLowDifficultyBlockchain(t)
	blockHeight := uint64(chain.blockTip().Height) + 1
	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
	require.NoError(t, err)

	// Test that the CurrentEpoch is nil in the db.
	epochEntry, err = DBGetCurrentEpoch(db, utxoView.Snapshot)
	require.NoError(t, err)
	require.Nil(t, epochEntry)

	// Test that the CurrentEpoch is nil in the UtxoView.
	require.Nil(t, utxoView.CurrentEpochEntry)

	// Test GetCurrentEpoch().
	epochEntry, err = utxoView.GetCurrentEpoch()
	require.NoError(t, err)
	require.Nil(t, epochEntry)

	// Set the CurrentEpoch.
	epochEntry = &EpochEntry{
		EpochNumber:            1,
		LastBlockHeightInEpoch: blockHeight + 5,
	}
	err = utxoView.SetCurrentEpoch(epochEntry, blockHeight)
	require.NoError(t, err)

	// Test that the CurrentEpoch is set in the db.
	epochEntry, err = DBGetCurrentEpoch(db, utxoView.Snapshot)
	require.NoError(t, err)
	require.NotNil(t, epochEntry)
	require.Equal(t, epochEntry.EpochNumber, uint64(1))
	require.Equal(t, epochEntry.LastBlockHeightInEpoch, blockHeight+5)

	// Test that the CurrentEpoch is set in the UtxoView.
	epochEntry = utxoView.CurrentEpochEntry
	require.NotNil(t, epochEntry)
	require.Equal(t, epochEntry.EpochNumber, uint64(1))
	require.Equal(t, epochEntry.LastBlockHeightInEpoch, blockHeight+5)

	// Test GetCurrentEpoch().
	epochEntry, err = utxoView.GetCurrentEpoch()
	require.NoError(t, err)
	require.NotNil(t, epochEntry)
	require.Equal(t, epochEntry.EpochNumber, uint64(1))
	require.Equal(t, epochEntry.LastBlockHeightInEpoch, blockHeight+5)

	// Delete CurrentEpoch from the UtxoView.
	utxoView.DeleteCurrentEpoch()
	require.Nil(t, utxoView.CurrentEpochEntry)

	// CurrentEpoch still exists in the db.
	epochEntry, err = DBGetCurrentEpoch(db, utxoView.Snapshot)
	require.NoError(t, err)
	require.NotNil(t, epochEntry)

	// GetCurrentEpoch() should return the CurrentEpoch from the db.
	epochEntry, err = utxoView.GetCurrentEpoch()
	require.NoError(t, err)
	require.NotNil(t, epochEntry)

	// CurrentEpoch gets cached in the UtxoView.
	require.NotNil(t, utxoView.CurrentEpochEntry)
}
