package lib

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/dgraph-io/badger/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// This integration-style test exercises GenerateCommittedBlockDiff across
// multiple block heights and verifies that ExtractStateChangesFromBackup
// returns the expected StateChangeEntry records for inserts, updates and
// deletes.  It works directly at the Badger layer to avoid the complexity of
// crafting full blockchain transactions, but still covers core-state prefixes
// and the diff streaming logic.
func TestStateChangeSyncer_DiffWorkflow_InsertUpdateDelete(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "state-syncer-int")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	// Helper to build a PostEntry key (core state)
	makePostKey := func(suffix byte) []byte {
		k := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
		k = append(k, suffix)
		return k
	}

	// ---- Block 1: Insert ---------------------------------------
	key := makePostKey(0x01)
	post1 := &PostEntry{Body: []byte("post-v1")}
	val1 := EncodeToBytes(0, post1, false)
	
	preCommitTxn := db.NewTransaction(false)
	defer preCommitTxn.Discard()
	

	err = db.Update(func(txn *badger.Txn) error { return txn.Set(key, val1) })
	require.NoError(err)

	require.NoError(syncer.GenerateCommittedBlockDiff(db, preCommitTxn, 1))
	diff1 := filepath.Join(dir, "state_changes_1.bin")
	bytes1, err := os.ReadFile(diff1)
	require.NoError(err)
	require.NotEmpty(bytes1)

	// Parse and validate
	flushId := uuid.New()
	entries1, err := syncer.ExtractStateChangesFromBackup(bytes1, flushId, 1)
	require.NoError(err)
	require.Len(entries1, 1)
	require.Equal(DbOperationTypeUpsert, entries1[0].OperationType)
	require.True(bytes.Equal(entries1[0].KeyBytes, key))
	require.Equal(val1, entries1[0].EncoderBytes)

	// ---- Block 2: Update same key --------------------------------
	post2 := &PostEntry{Body: []byte("post-v2")}
	val2 := EncodeToBytes(0, post2, false)

	preCommitTxn = db.NewTransaction(false)
	defer preCommitTxn.Discard()

	err = db.Update(func(txn *badger.Txn) error { return txn.Set(key, val2) })
	require.NoError(err)
	// Insert another key that we'll delete in block3 to ensure multi-entry diff
	keyDel := makePostKey(0x02)
	delEntry := &PostEntry{Body: []byte("to-delete")}
	err = db.Update(func(txn *badger.Txn) error { return txn.Set(keyDel, EncodeToBytes(0, delEntry, false)) })
	require.NoError(err)

	require.NoError(syncer.GenerateCommittedBlockDiff(db, preCommitTxn, 2))
	diff2 := filepath.Join(dir, "state_changes_2.bin")
	bytes2, err := os.ReadFile(diff2)
	require.NoError(err)
	require.NotEmpty(bytes2)

	entries2, err := syncer.ExtractStateChangesFromBackup(bytes2, flushId, 2)
	require.NoError(err)
	// Expect 2 upserts (updated key and new keyDel)
	require.Len(entries2, 2)
	// Verify update captured with new bytes
	var foundUpdate bool
	for _, e := range entries2 {
		if bytes.Equal(e.KeyBytes, key) {
			require.Equal(DbOperationTypeUpsert, e.OperationType)
			require.True(bytes.Contains(e.EncoderBytes, []byte("post-v2")))
			foundUpdate = true
		}
	}
	require.True(foundUpdate, "updated key not found in diff")

	preCommitTxn = db.NewTransaction(false)
	defer preCommitTxn.Discard()
	// ---- Block 3: Delete keyDel ---------------------------------
	err = db.Update(func(txn *badger.Txn) error { return txn.Delete(keyDel) })
	require.NoError(err)

	require.NoError(syncer.GenerateCommittedBlockDiff(db, preCommitTxn, 3))
	diff3 := filepath.Join(dir, "state_changes_3.bin")
	bytes3, err := os.ReadFile(diff3)
	require.NoError(err)
	require.NotEmpty(bytes3)

	entries3, err := syncer.ExtractStateChangesFromBackup(bytes3, flushId, 3)
	require.NoError(err)
	// Expect single delete entry
	require.Len(entries3, 1)
	require.Equal(DbOperationTypeDelete, entries3[0].OperationType)
	require.True(bytes.Equal(entries3[0].KeyBytes, keyDel))
	require.Empty(entries3[0].EncoderBytes)
}

// Ensures that when the same key is updated multiple times prior to diff
// generation, only the latest revision is emitted.
func TestStateChangeSyncer_DiffWorkflow_MultiUpdateSingleBlock(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, _ := os.MkdirTemp("", "state-syncer-multi")
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	key := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
	key = append(key, 0x99)

	// valA then valB before diff generation.
	valA := EncodeToBytes(0, &PostEntry{Body: []byte("vA")}, false)
	valB := EncodeToBytes(0, &PostEntry{Body: []byte("vB")}, false)

	preCommitTxn := db.NewTransaction(false)
	defer preCommitTxn.Discard()

	err := db.Update(func(txn *badger.Txn) error {
		if err := txn.Set(key, valA); err != nil {
			return err
		}
		return txn.Set(key, valB)
	})
	require.NoError(err)

	require.NoError(syncer.GenerateCommittedBlockDiff(db, preCommitTxn, 1))
	diffPath := filepath.Join(dir, "state_changes_1.bin")
	diffBytes, err := os.ReadFile(diffPath)
	require.NoError(err)

	entries, err := syncer.ExtractStateChangesFromBackup(diffBytes, uuid.New(), 1)
	require.NoError(err)
	require.Len(entries, 1)
	require.True(bytes.Equal(entries[0].KeyBytes, key))
	require.True(bytes.Contains(entries[0].EncoderBytes, []byte("vB")))
}

// Verifies that keys outside CoreState prefixes are ignored by diff generator.
func TestStateChangeSyncer_DiffWorkflow_NonCoreFiltered(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, _ := os.MkdirTemp("", "state-syncer-filter")
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	// Non-core prefix 0xFE (assumed not core state)
	nonCoreKey := []byte{0xFE, 0x01}
	preCommitTxn := db.NewTransaction(false)
	defer preCommitTxn.Discard()

	err := db.Update(func(txn *badger.Txn) error { return txn.Set(nonCoreKey, []byte("junk")) })
	require.NoError(err)

	require.NoError(syncer.GenerateCommittedBlockDiff(db, preCommitTxn, 1))
	diffPath := filepath.Join(dir, "state_changes_1.bin")
	if _, err := os.Stat(diffPath); os.IsNotExist(err) {
		// expected: no file since diffBytes == 0
		return
	}
	require.NoError(err)
	diffBytes, err := os.ReadFile(diffPath)
	require.NoError(err)
	entries, err := syncer.ExtractStateChangesFromBackup(diffBytes, uuid.New(), 1)
	require.NoError(err)
	require.Len(entries, 0)
}

// TestStateChangeSyncer_DuplicateKeyUpdates verifies that when the same key is updated 
// with identical content multiple times, these no-op updates are still included in the backup.
// This test demonstrates the issue we need to fix: duplicate identical entries should be filtered out.
func TestStateChangeSyncer_DuplicateKeyUpdates(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, _ := os.MkdirTemp("", "state-syncer-noop")
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	// Create a ProfileEntry key (simulating a user profile)
	profileKey := append([]byte{}, Prefixes.PrefixPKIDToProfileEntry...)
	profileKey = append(profileKey, []byte("testuser")...)

	// Create a profile entry with some content
	profile := &ProfileEntry{
		Username:               []byte("testuser"),
		Description:            []byte("Test description"),
		ProfilePic:            []byte("https://example.com/pic.jpg"),
		IsHidden:              false,
	}
	profileBytes := EncodeToBytes(0, profile, false)

	preCommitTxn := db.NewTransaction(false)
	defer preCommitTxn.Discard()
	// First block: Insert the profile
	err := db.Update(func(txn *badger.Txn) error { 
		return txn.Set(profileKey, profileBytes) 
	})
	require.NoError(err)

	require.NoError(syncer.GenerateCommittedBlockDiff(db, preCommitTxn, 1))
	diff1 := filepath.Join(dir, "state_changes_1.bin")
	bytes1, err := os.ReadFile(diff1)
	require.NoError(err)
	entries1, err := syncer.ExtractStateChangesFromBackup(bytes1, uuid.New(), 1)
	require.NoError(err)
	require.Len(entries1, 1, "Block 1 should have 1 entry")

	preCommitTxn = db.NewTransaction(false)
	defer preCommitTxn.Discard()
	// Second block: Insert the SAME profile with identical content (no-op update)
	// This simulates what happens in the blockchain test when a follow transaction
	// causes the same profile entry to be written again with identical content
	err = db.Update(func(txn *badger.Txn) error { 
		return txn.Set(profileKey, profileBytes) 
	})
	require.NoError(err)

	require.NoError(syncer.GenerateCommittedBlockDiff(db, preCommitTxn, 2))
	diff2 := filepath.Join(dir, "state_changes_2.bin")
	_, err = os.ReadFile(diff2)
	// Require a no such file error
	require.ErrorIs(err, os.ErrNotExist)

	// require.NoError(err)
	// entries2, err := syncer.ExtractStateChangesFromBackup(bytes2, uuid.New(), 2)
	// require.NoError(err)

	// // This is the key assertion that demonstrates the issue:
	// // Currently, we expect 1 entry because the no-op update is included
	// // After our fix, this should be 0 entries since nothing actually changed
	// require.Len(entries2, 1, "Block 2 currently includes no-op updates (this is the issue we need to fix)")

	// // Verify it's the same key
	// if len(entries2) > 0 {
	// 	require.Equal(DbOperationTypeUpsert, entries2[0].OperationType)
	// 	require.True(bytes.Equal(entries2[0].KeyBytes, profileKey))
	// 	require.True(bytes.Equal(entries2[0].EncoderBytes, profileBytes))
	// }

	// Third block: Make an actual change to the profile
	profile.Description = []byte("Updated description")
	updatedBytes := EncodeToBytes(0, profile, false)

	preCommitTxn = db.NewTransaction(false)
	defer preCommitTxn.Discard()

	err = db.Update(func(txn *badger.Txn) error { 
		return txn.Set(profileKey, updatedBytes) 
	})
	require.NoError(err)

	require.NoError(syncer.GenerateCommittedBlockDiff(db, preCommitTxn, 3))
	diff3 := filepath.Join(dir, "state_changes_3.bin")
	bytes3, err := os.ReadFile(diff3)
	require.NoError(err)
	entries3, err := syncer.ExtractStateChangesFromBackup(bytes3, uuid.New(), 3)
	require.NoError(err)

	// This should always be 1 since there was an actual change
	require.Len(entries3, 1, "Block 3 should have 1 entry (real update)")
	require.Equal(DbOperationTypeUpsert, entries3[0].OperationType)
	require.True(bytes.Equal(entries3[0].KeyBytes, profileKey))
	require.True(bytes.Equal(entries3[0].EncoderBytes, updatedBytes))
}
