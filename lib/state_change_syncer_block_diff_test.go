package lib

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/require"
)

func TestGenerateCommittedBlockDiff(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "state-syncer-blockdiff")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	preCommitTxn := db.NewTransaction(false)
	defer preCommitTxn.Discard()

	// Use a core-state prefix so it passes filter (PostEntry prefix = PrefixPostHashToPostEntry)
	key1 := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
	key1 = append(key1, 0xAA)
	val1 := []byte("value1")
	err = db.Update(func(txn *badger.Txn) error {
		return txn.Set(key1, val1)
	})
	require.NoError(err)

	// Generate diff for block 1.
	require.NoError(syncer.GenerateCommittedBlockDiff(db, preCommitTxn, 1))

	diffPath := filepath.Join(dir, "state_changes_1.bin")
	diffBytes, err := os.ReadFile(diffPath)
	require.NoError(err)
	require.NotEmpty(diffBytes)

	// Capture current cursor.
	since1, err := syncer.getLastSince(db)
	require.NoError(err)
	require.NotZero(since1)

	preCommitTxn2 := db.NewTransaction(false)
	defer preCommitTxn2.Discard()

	// Second key under same core-state prefix
	key2 := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
	key2 = append(key2, 0xBB)
	val2 := []byte("value2")
	err = db.Update(func(txn *badger.Txn) error {
		return txn.Set(key2, val2)
	})
	require.NoError(err)

	// Generate diff for block 2.
	require.NoError(syncer.GenerateCommittedBlockDiff(db, preCommitTxn2, 2))
	diffPath2 := filepath.Join(dir, "state_changes_2.bin")
	// Depending on filter, file should exist and be non-empty.
	diffBytes2, err := os.ReadFile(diffPath2)
	require.NoError(err)
	require.NotEmpty(diffBytes2)
}
