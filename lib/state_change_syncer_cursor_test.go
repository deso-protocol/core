package lib

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStateChangeSyncerCursorHelpers(t *testing.T) {
	require := require.New(t)

	// In-memory Badger helper (exists in test utils)
	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	// Temp dir for syncer log files (not used by helpers but required for ctor)
	dir, err := os.MkdirTemp("", "state-syncer-test")
	require.NoError(err)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	// 1. Fresh DB should return 0
	since, err := syncer.getLastSince(db)
	require.NoError(err)
	require.Equal(uint64(0), since)

	// 2. Persist a value and read back
	var testVal uint64 = 987654321
	require.NoError(syncer.setLastSince(db, testVal))

	since2, err := syncer.getLastSince(db)
	require.NoError(err)
	require.Equal(testVal, since2)

	// 3. Overwrite with new value
	var testVal2 uint64 = 42
	require.NoError(syncer.setLastSince(db, testVal2))

	since3, err := syncer.getLastSince(db)
	require.NoError(err)
	require.Equal(testVal2, since3)
}
