package lib

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dgraph-io/badger/v3/pb"
	"github.com/stretchr/testify/require"
)

// TestGenerateHypersyncChunkDiff tests that hypersync chunks generate proper diff files
func TestGenerateHypersyncChunkDiff(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "hypersync-diff-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	// Create StateChangeSyncer for diff generation
	syncer := NewStateChangeSyncer(dir, NodeSyncTypeHyperSync, 0)

	// Create snapshot with StateChangeSyncer
	snap, err, _, _ := NewSnapshot(
		db,
		SnapshotBlockHeightPeriod,
		false,
		true, // disable checksum for test
		&DeSoTestnetParams,
		false,
		HypersyncDefaultMaxQueueSize,
		nil,
		syncer,
	)
	require.NoError(err)

	// Create test chunk with core state entries
	chunk := []*DBEntry{
		{
			Key:   append([]byte{}, Prefixes.PrefixPostHashToPostEntry...),
			Value: []byte("test_post_data"),
		},
		{
			Key:   append([]byte{}, Prefixes.PrefixPKIDToProfileEntry...),
			Value: []byte("test_profile_data"),
		},
		// Add non-core state entry that should be filtered out
		{
			Key:   []byte("non_core_key"),
			Value: []byte("non_core_data"),
		},
	}

	blockHeight := uint64(100)
	chunkId := uint64(1)

	// Generate hypersync chunk diff
	err = snap.generateHypersyncChunkDiff(chunk, blockHeight, chunkId)
	require.NoError(err)

	// Verify diff file was created
	files, err := os.ReadDir(dir)
	require.NoError(err)

	var diffFile string
	for _, file := range files {
		name := file.Name()
		if strings.HasPrefix(name, "hypersync_chunk_100_1_") && strings.HasSuffix(name, ".bin") {
			diffFile = name
			break
		}
	}

	require.NotEmpty(diffFile, "Should have created a hypersync chunk diff file")

	// Verify file content by reading it back
	diffBytes, err := os.ReadFile(filepath.Join(dir, diffFile))
	require.NoError(err)
	require.NotEmpty(diffBytes, "Diff file should not be empty")

	// Parse the diff file using badger backup format
	var foundEntries int
	var foundPostEntry, foundProfileEntry bool

	err = readBadgerBackup(bytes.NewReader(diffBytes), func(kvl *pb.KVList) error {
		for _, kv := range kvl.Kv {
			foundEntries++

			// Check that only core state entries are included
			require.True(isCoreStateKey(kv.Key), "Only core state keys should be in diff file")

			if bytes.HasPrefix(kv.Key, Prefixes.PrefixPostHashToPostEntry) {
				foundPostEntry = true
				require.Equal([]byte("test_post_data"), kv.Value, "Post entry value should match")
			}
			if bytes.HasPrefix(kv.Key, Prefixes.PrefixPKIDToProfileEntry) {
				foundProfileEntry = true
				require.Equal([]byte("test_profile_data"), kv.Value, "Profile entry value should match")
			}
		}
		return nil
	})
	require.NoError(err)

	require.Equal(2, foundEntries, "Should find exactly 2 core state entries (non-core filtered out)")
	require.True(foundPostEntry, "Should find post entry")
	require.True(foundProfileEntry, "Should find profile entry")
}

// TestGenerateHypersyncChunkDiff_EmptyChunk tests handling of chunks with no core state entries
func TestGenerateHypersyncChunkDiff_EmptyChunk(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "hypersync-empty-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeHyperSync, 0)
	snap, err, _, _ := NewSnapshot(db, SnapshotBlockHeightPeriod, false, true, &DeSoTestnetParams, false, HypersyncDefaultMaxQueueSize, nil, syncer)
	require.NoError(err)

	// Create chunk with only non-core state entries
	chunk := []*DBEntry{
		{Key: []byte("non_core_key1"), Value: []byte("data1")},
		{Key: []byte("non_core_key2"), Value: []byte("data2")},
	}

	err = snap.generateHypersyncChunkDiff(chunk, 100, 1)
	require.NoError(err)

	// Verify no diff files were created
	files, err := os.ReadDir(dir)
	require.NoError(err)

	var hypersyncFiles int
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "hypersync_chunk_") {
			hypersyncFiles++
		}
	}

	require.Equal(0, hypersyncFiles, "Should not create diff files for chunks with no core state entries")
}

// TestGenerateHypersyncChunkDiff_NoStateChangeSyncer tests graceful handling when no StateChangeSyncer is available
func TestGenerateHypersyncChunkDiff_NoStateChangeSyncer(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	// Create snapshot without StateChangeSyncer (nil)
	snap, err, _, _ := NewSnapshot(db, SnapshotBlockHeightPeriod, false, true, &DeSoTestnetParams, false, HypersyncDefaultMaxQueueSize, nil, nil)
	require.NoError(err)

	chunk := []*DBEntry{
		{Key: append([]byte{}, Prefixes.PrefixPostHashToPostEntry...), Value: []byte("test_data")},
	}

	// Should not error when StateChangeSyncer is nil
	err = snap.generateHypersyncChunkDiff(chunk, 100, 1)
	require.NoError(err)
}
