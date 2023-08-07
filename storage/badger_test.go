package storage

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

// TestBadger_Default_Generic is a BadgerDB test in which we write small amount of data to the database.
// In the test, we:
//  1. Write 100 equal size KV items to the database.
//  2. Remove 20 items from the database.
//  3. Retrieve 20 items from the database.
//  4. Iterate over 20 items in the database.
//  5. Iterate over all items in the database.
func TestBadger_Default_Generic(t *testing.T) {
	require := require.New(t)

	testConfig := &TestConfig{
		BatchSizeBytes:      10000,
		BatchSizeItems:      100,
		BatchItemsRemoved:   20,
		BatchItemsRetrieved: 20,
		BatchItemsIterated:  20,
	}
	dir, err := os.MkdirTemp("", "badgerdb-default-10mb")
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	opts := DefaultBadgerOptions(dir)
	_doBadgerTest(t, testConfig, opts, false)
	_doBadgerTest(t, testConfig, opts, true)

	opts = PerformanceBadgerOptions(dir)
	_doBadgerTest(t, testConfig, opts, false)
	_doBadgerTest(t, testConfig, opts, true)
}

func _doBadgerTest(t *testing.T, testConfig *TestConfig, opts badger.Options, useWriteBatch bool) {
	require := require.New(t)

	db := NewBadgerDatabase(opts, useWriteBatch)
	require.NoError(db.Setup())

	GenericTest(db, testConfig, t)
	require.NoError(db.Close())
	require.NoError(db.Erase())
}
