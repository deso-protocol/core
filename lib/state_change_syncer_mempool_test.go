package lib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v3/pb"
	"github.com/stretchr/testify/require"
)

// TestExtractStateFromTransaction_CoreStateUpdate tests that core state updates
// in a badger transaction are properly extracted.
func TestExtractStateFromTransaction_CoreStateUpdate(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "state-syncer-mempool")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	// Create a core state key (PostEntry)
	postKey := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
	postKey = append(postKey, []byte("test-post-hash")...)

	// Create a PostEntry value
	post := &PostEntry{
		Body:           []byte("This is a test post"),
		TimestampNanos: 1234567890,
	}
	postBytes := EncodeToBytes(0, post, false)

	// Create a transaction and add the core state update
	txn := db.NewTransaction(true)
	defer txn.Discard()

	err = txn.Set(postKey, postBytes)
	require.NoError(err)

	// Extract state from transaction
	state := syncer.extractStateFromTransaction(txn)

	// Verify the core state update is captured
	require.Len(state, 1, "Should extract exactly one core state entry")

	extractedValue, exists := state[string(postKey)]
	require.True(exists, "Post key should exist in extracted state")
	require.True(bytes.Equal(extractedValue, postBytes), "Extracted value should match original post bytes")
}

// TestExtractStateFromTransaction_MultipleUpdates tests that when the same key
// is updated multiple times in a transaction, only the most recent value is extracted.
func TestExtractStateFromTransaction_MultipleUpdates(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "state-syncer-mempool-multi")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	// Create a core state key
	profileKey := append([]byte{}, Prefixes.PrefixPKIDToProfileEntry...)
	profileKey = append(profileKey, []byte("test-user")...)

	// Create first profile version
	profile1 := &ProfileEntry{
		Username:    []byte("testuser"),
		Description: []byte("First description"),
	}
	profile1Bytes := EncodeToBytes(0, profile1, false)

	// Create second profile version
	profile2 := &ProfileEntry{
		Username:    []byte("testuser"),
		Description: []byte("Updated description"),
	}
	profile2Bytes := EncodeToBytes(0, profile2, false)

	// Create third profile version
	profile3 := &ProfileEntry{
		Username:    []byte("testuser"),
		Description: []byte("Final description"),
	}
	profile3Bytes := EncodeToBytes(0, profile3, false)

	// Create transaction and update the same key multiple times
	txn := db.NewTransaction(true)
	defer txn.Discard()

	err = txn.Set(profileKey, profile1Bytes)
	require.NoError(err)

	err = txn.Set(profileKey, profile2Bytes)
	require.NoError(err)

	err = txn.Set(profileKey, profile3Bytes)
	require.NoError(err)

	// Extract state from transaction
	state := syncer.extractStateFromTransaction(txn)

	// Verify only one entry (the most recent) is extracted
	require.Len(state, 1, "Should extract exactly one entry despite multiple updates")

	extractedValue, exists := state[string(profileKey)]
	require.True(exists, "Profile key should exist in extracted state")
	require.True(bytes.Equal(extractedValue, profile3Bytes), "Should extract the most recent (final) value")
	require.False(bytes.Equal(extractedValue, profile1Bytes), "Should not contain first value")
	require.False(bytes.Equal(extractedValue, profile2Bytes), "Should not contain second value")
}

// TestExtractStateFromTransaction_NonCoreStateFiltered tests that non-core state
// updates are filtered out during extraction.
func TestExtractStateFromTransaction_NonCoreStateFiltered(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "state-syncer-mempool-filter")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	// Create a core state key
	coreKey := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
	coreKey = append(coreKey, []byte("core-entry")...)
	coreValue := []byte("core state value")

	// Create a non-core state key (using a prefix that's not in core state)
	nonCoreKey := []byte{0xFE, 0xFF} // Using an unlikely prefix
	nonCoreKey = append(nonCoreKey, []byte("non-core-entry")...)
	nonCoreValue := []byte("non-core state value")

	// Create transaction with both core and non-core updates
	txn := db.NewTransaction(true)
	defer txn.Discard()

	err = txn.Set(coreKey, coreValue)
	require.NoError(err)

	err = txn.Set(nonCoreKey, nonCoreValue)
	require.NoError(err)

	// Extract state from transaction
	state := syncer.extractStateFromTransaction(txn)

	// Verify only core state entry is extracted
	require.Len(state, 1, "Should extract only core state entries")

	extractedValue, exists := state[string(coreKey)]
	require.True(exists, "Core state key should exist in extracted state")
	require.True(bytes.Equal(extractedValue, coreValue), "Core state value should match")

	_, nonCoreExists := state[string(nonCoreKey)]
	require.False(nonCoreExists, "Non-core state key should be filtered out")
}

// TestExtractStateFromTransaction_EmptyTransaction tests extraction from an empty transaction.
func TestExtractStateFromTransaction_EmptyTransaction(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "state-syncer-mempool-empty")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	// Create empty transaction
	txn := db.NewTransaction(true)
	defer txn.Discard()

	// Extract state from empty transaction
	state := syncer.extractStateFromTransaction(txn)

	// Verify no entries are extracted
	require.Len(state, 0, "Should extract no entries from empty transaction")
	require.NotNil(state, "Should return non-nil map even for empty transaction")
}

// TestExtractStateFromTransaction_SubmitPostIntegration tests extraction from a transaction
// that contains the state changes from a realistic submit post operation.
func TestExtractStateFromTransaction_SubmitPostIntegration(t *testing.T) {
	require := require.New(t)

	// Create test blockchain environment
	chain, params, db := NewLowDifficultyBlockchain(t)

	dir, err := os.MkdirTemp("", "state-syncer-integration")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	// Create test miner and mempool
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Mine a few blocks to set up the chain with block rewards
	for i := 0; i < 3; i++ {
		_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
	}

	// Create a test user with a known public key (from existing tests)
	senderPkString := "tBCKXFJEDSF7Thcc6BUBcB6kicE5qzmLbAtvFf9LfKSXN4LwFt36oX"
	senderPrivString := "tbc31669t2YuZ2mi1VLtK6a17RXFPdsuBDcenPLc1eU1ZVRHF9Zv4"
	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)

	// Create a UtxoView for testing
	utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, nil)

	// Create a submit post transaction using the chain's helper method
	blockHeight := uint64(chain.blockIndex.GetTip().Height + 1)
	submitPostTxn, _, _, _, err := chain.CreateSubmitPostTxn(
		senderPkBytes, // updaterPublicKey
		[]byte{},      // postHashToModify (empty for new post)
		[]byte{},      // parentStakeID
		[]byte("This is a test post for mempool extraction"), // body
		[]byte{},                      // repostPostHashBytes
		false,                         // isQuotedRepost
		uint64(time.Now().UnixNano()), // tstampNanos
		map[string][]byte{},           // postExtraData
		false,                         // isHidden
		10000,                         // minFeeRateNanosPerKB
		mempool,                       // mempool
		[]*DeSoOutput{},               // additionalOutputs
	)
	require.NoError(err)

	// Sign the transaction
	_signTxn(t, submitPostTxn, senderPrivString)

	// Create a transaction for flushing
	flushTxn := db.NewTransaction(true)
	defer flushTxn.Discard()

	// Connect the submit post transaction to generate state changes
	utxoOps, _, _, _, err := utxoView.ConnectTransaction(
		submitPostTxn,
		submitPostTxn.Hash(),
		uint32(blockHeight),
		0,     // timestamp
		false, // verifySignatures
		false, // ignoreUtxos
	)
	require.NoError(err)
	require.NotEmpty(utxoOps, "Submit post should generate UTXO operations")

	// Flush the UTXO view to the transaction
	err = utxoView.FlushToDbWithTxn(flushTxn, blockHeight)
	require.NoError(err)

	// Extract state from the transaction
	state := syncer.extractStateFromTransaction(flushTxn)

	// Verify that we extracted state changes
	require.NotEmpty(state, "Should extract state changes from submit post transaction")

	// Verify we have expected types of entries
	var hasPostEntry bool

	for keyStr, value := range state {
		keyBytes := []byte(keyStr)

		// Check for PostEntry
		if bytes.HasPrefix(keyBytes, Prefixes.PrefixPostHashToPostEntry) {
			hasPostEntry = true
			require.NotEmpty(value, "Post entry should have non-empty value")
		}

		// Check for UTXO entries
		if bytes.HasPrefix(keyBytes, Prefixes.PrefixUtxoKeyToUtxoEntry) {
			require.NotEmpty(value, "UTXO entry should have non-empty value")
		}
	}

	require.True(hasPostEntry, "Should extract PostEntry from submit post transaction")
}

// TestComputeMempoolDiff_SingleTransaction tests that computeMempoolDiff correctly identifies
// a single new transaction entry.
func TestComputeMempoolDiff_SingleTransaction(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "compute-diff-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	// Create a base transaction (committed state)
	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	// Create previous state (empty - no previous mempool entries)
	previousState := make(map[string][]byte)

	// Create current state with one entry
	currentState := make(map[string][]byte)
	testKey := string(append([]byte{}, Prefixes.PrefixPostHashToPostEntry...))
	testKey = testKey + "test_post_hash"
	testValue := []byte("test_post_entry_data")
	currentState[testKey] = testValue

	// Run computeMempoolDiff
	changed, deleted, ancestralRecords := syncer.computeMempoolDiff(
		previousState,
		currentState,
		baseTxn,
	)

	// Verify results
	require.Len(changed, 1, "Should have one changed entry")
	require.Len(deleted, 0, "Should have no deleted entries")
	require.Len(ancestralRecords, 1, "Should have one ancestral record")

	// Check changed entry
	require.Equal(testValue, changed[testKey], "Changed entry should match current state")

	// Check ancestral record
	record := ancestralRecords[0]
	require.Equal([]byte(testKey), record.Key, "Ancestral record key should match")
	require.Equal(AncestralOperationInsert, record.Operation, "Should be insert operation")
	require.Empty(record.PreviousValue, "Previous value should be empty for new entry")
}

// TestGenerateSequentialMempoolDiff_SingleTransaction tests that generateSequentialMempoolDiff
// correctly generates files for a single mempool transaction and includes transaction entries.
func TestGenerateSequentialMempoolDiff_SingleTransaction(t *testing.T) {
	require := require.New(t)

	// Create test blockchain environment with mempool
	chain, params, db := NewLowDifficultyBlockchain(t)
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "sequential-diff-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	// Create test miner and mempool
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Mine a few blocks to set up the chain with block rewards
	for i := 0; i < 3; i++ {
		_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
	}

	// Create a test transaction with mempool state
	mempoolTxn := db.NewTransaction(true)
	defer mempoolTxn.Discard()

	// Add a test entry to the transaction (flushed state)
	testKey := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
	testKey = append(testKey, []byte("test_post_hash")...)
	testValue := []byte("test_post_entry_data")

	err = mempoolTxn.Set(testKey, testValue)
	require.NoError(err)

	// Add a real transaction to the mempool to test transaction extraction
	senderPkString := "tBCKXFJEDSF7Thcc6BUBcB6kicE5qzmLbAtvFf9LfKSXN4LwFt36oX"
	senderPrivString := "tbc31669t2YuZ2mi1VLtK6a17RXFPdsuBDcenPLc1eU1ZVRHF9Zv4"
	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)

	submitPostTxn, _, _, _, err := chain.CreateSubmitPostTxn(
		senderPkBytes, []byte{}, []byte{},
		[]byte("Test post for sequential diff"), []byte{}, false,
		uint64(time.Now().UnixNano()), map[string][]byte{}, false,
		10000, mempool, []*DeSoOutput{})
	require.NoError(err)

	_signTxn(t, submitPostTxn, senderPrivString)
	_, err = mempool.ProcessTransaction(submitPostTxn, false, false, 0, true)
	require.NoError(err)

	// Create base transaction (committed state)
	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	blockHeight := uint64(chain.blockTip().Height)

	// Call generateSequentialMempoolDiff with new signature
	err = syncer.generateSequentialMempoolDiff(mempoolTxn, baseTxn, chain, mempool, blockHeight)
	require.NoError(err)

	// Verify files were created
	files, err := os.ReadDir(dir)
	require.NoError(err)

	var diffFile, ancestralFile string
	blockHeightStr := fmt.Sprintf("%d", blockHeight)
	for _, file := range files {
		name := file.Name()
		if strings.HasPrefix(name, "mempool_"+blockHeightStr+"_") && strings.HasSuffix(name, ".bin") {
			diffFile = name
		}
		if strings.HasPrefix(name, "mempool_ancestral_"+blockHeightStr+"_") && strings.HasSuffix(name, ".bin") {
			ancestralFile = name
		}
	}

	require.NotEmpty(diffFile, "Should have created a diff file")
	require.NotEmpty(ancestralFile, "Should have created an ancestral file")

	// Verify file naming format
	require.True(strings.HasPrefix(diffFile, "mempool_"+blockHeightStr+"_"), "Diff file should start with mempool_<height>_")
	require.True(strings.HasSuffix(diffFile, ".bin"), "Diff file should end with .bin")

	// Verify diff file content by reading it back
	diffBytes, err := os.ReadFile(filepath.Join(dir, diffFile))
	require.NoError(err)
	require.NotEmpty(diffBytes, "Diff file should not be empty")

	// Parse the diff file to validate both flushed state and transaction entries
	var foundEntries int
	var foundFlushedEntry, foundTxnEntry, foundUtxoOpsEntry bool

	err = readBadgerBackup(bytes.NewReader(diffBytes), func(kvl *pb.KVList) error {
		for _, kv := range kvl.Kv {
			foundEntries++

			// Check for our test flushed state entry
			if bytes.Equal(kv.Key, testKey) {
				foundFlushedEntry = true
				require.Equal(testValue, kv.Value, "Flushed state value should match")
			}

			// Check for transaction entry
			if bytes.HasPrefix(kv.Key, Prefixes.PrefixTxnHashToTxn) {
				foundTxnEntry = true
				require.NotEmpty(kv.Value, "Transaction entry should have value")
			}

			// Check for transaction UtxoOps entry
			if bytes.HasPrefix(kv.Key, Prefixes.PrefixTxnHashToUtxoOps) {
				foundUtxoOpsEntry = true
				require.NotEmpty(kv.Value, "UtxoOps entry should have value")
			}
		}
		return nil
	})
	require.NoError(err)
	require.GreaterOrEqual(foundEntries, 3, "Should find at least 3 entries: flushed state + transaction + utxoops")
	require.True(foundFlushedEntry, "Should find the flushed state entry")
	require.True(foundTxnEntry, "Should find the transaction entry")
	require.True(foundUtxoOpsEntry, "Should find the UtxoOps entry")

	// Verify ancestral file content
	ancestralBytes, err := os.ReadFile(filepath.Join(dir, ancestralFile))
	require.NoError(err)
	require.NotEmpty(ancestralBytes, "Ancestral file should not be empty")

	// Parse ancestral file manually - now need to find our specific test entry
	reader := bytes.NewReader(ancestralBytes)
	var foundTestEntry bool

	// Read all ancestral records to find our test entry
	for reader.Len() > 0 {
		// Read operation type
		var operation uint8
		err = binary.Read(reader, binary.LittleEndian, &operation)
		require.NoError(err)

		// Read key length and key
		var keyLen uint32
		err = binary.Read(reader, binary.LittleEndian, &keyLen)
		require.NoError(err)

		key := make([]byte, keyLen)
		_, err = reader.Read(key)
		require.NoError(err)

		// Read value length and value
		var valueLen uint32
		err = binary.Read(reader, binary.LittleEndian, &valueLen)
		require.NoError(err)

		if valueLen > 0 {
			value := make([]byte, valueLen)
			_, err = reader.Read(value)
			require.NoError(err)
		}

		// Check if this is our test entry
		if bytes.Equal(key, testKey) {
			foundTestEntry = true
			require.Equal(uint8(AncestralOperationInsert), operation, "Test entry should be insert operation")
			require.Equal(uint32(0), valueLen, "Test entry previous value should be empty for new entry")
			break
		}
	}

	require.True(foundTestEntry, "Should find ancestral record for test entry")

	// Verify state was updated for next sync
	require.NotNil(syncer.mempoolSyncState, "Mempool sync state should be initialized")
	require.Equal(blockHeight, syncer.mempoolSyncState.currentBlockHeight, "Block height should be set")
	require.GreaterOrEqual(len(syncer.mempoolSyncState.lastSyncState), 3, "Should track at least 3 entries (flushed + transaction + utxoops)")
	require.Equal(testValue, syncer.mempoolSyncState.lastSyncState[string(testKey)], "Should track the flushed state entry value")

	// Verify transaction entries are also tracked in state
	var foundTxnInState, foundUtxoOpsInState bool
	for key := range syncer.mempoolSyncState.lastSyncState {
		if strings.Contains(key, string(Prefixes.PrefixTxnHashToTxn)) {
			foundTxnInState = true
		}
		if strings.Contains(key, string(Prefixes.PrefixTxnHashToUtxoOps)) {
			foundUtxoOpsInState = true
		}
	}
	require.True(foundTxnInState, "Should track transaction entry in state")
	require.True(foundUtxoOpsInState, "Should track UtxoOps entry in state")
}

// TestComputeMempoolDiff_MultipleSameKey tests that computeMempoolDiff correctly handles
// multiple updates to the same key in a single state.
func TestComputeMempoolDiff_MultipleSameKey(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "compute-diff-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	// Create states with same key having different values
	previousState := make(map[string][]byte)
	currentState := make(map[string][]byte)

	testKey := string(append([]byte{}, Prefixes.PrefixPostHashToPostEntry...))
	testKey = testKey + "test_post_hash"

	previousState[testKey] = []byte("old_value")
	currentState[testKey] = []byte("new_value")

	// Run computeMempoolDiff
	changed, deleted, ancestralRecords := syncer.computeMempoolDiff(
		previousState, currentState, baseTxn,
	)

	// Verify results - should see an update
	require.Len(changed, 1, "Should have one changed entry")
	require.Len(deleted, 0, "Should have no deleted entries")
	require.Len(ancestralRecords, 1, "Should have one ancestral record")

	require.Equal([]byte("new_value"), changed[testKey], "Should have new value")

	record := ancestralRecords[0]
	require.Equal([]byte(testKey), record.Key, "Key should match")
	require.Equal(AncestralOperationUpdate, record.Operation, "Should be update operation")
	require.Equal([]byte("old_value"), record.PreviousValue, "Should track old value")
}

// TestComputeMempoolDiff_CrossScanCreation tests creating different entries with same key
// across different scans.
func TestComputeMempoolDiff_CrossScanCreation(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "compute-diff-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	// Previous scan had one entry, current scan has different entry for same key
	previousState := make(map[string][]byte)
	currentState := make(map[string][]byte)

	testKey := string(append([]byte{}, Prefixes.PrefixPostHashToPostEntry...))
	testKey = testKey + "test_post_hash"

	previousState[testKey] = []byte("first_entry")
	currentState[testKey] = []byte("second_entry")

	changed, deleted, ancestralRecords := syncer.computeMempoolDiff(
		previousState, currentState, baseTxn,
	)

	require.Len(changed, 1, "Should have one changed entry")
	require.Len(deleted, 0, "Should have no deleted entries")
	require.Len(ancestralRecords, 1, "Should have one ancestral record")

	require.Equal([]byte("second_entry"), changed[testKey], "Should have new entry")

	record := ancestralRecords[0]
	require.Equal(AncestralOperationUpdate, record.Operation, "Should be update operation")
	require.Equal([]byte("first_entry"), record.PreviousValue, "Should track previous entry")
}

// TestComputeMempoolDiff_CrossScanUpdate tests updating an entry from previous scan.
func TestComputeMempoolDiff_CrossScanUpdate(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "compute-diff-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	previousState := make(map[string][]byte)
	currentState := make(map[string][]byte)

	testKey := string(append([]byte{}, Prefixes.PrefixPostHashToPostEntry...))
	testKey = testKey + "test_post_hash"

	previousState[testKey] = []byte("original_value")
	currentState[testKey] = []byte("updated_value")

	changed, deleted, ancestralRecords := syncer.computeMempoolDiff(
		previousState, currentState, baseTxn,
	)

	require.Len(changed, 1, "Should have one changed entry")
	require.Len(deleted, 0, "Should have no deleted entries")
	require.Len(ancestralRecords, 1, "Should have one ancestral record")

	require.Equal([]byte("updated_value"), changed[testKey], "Should have updated value")
}

// TestComputeMempoolDiff_DeleteRecreate tests the cycle: create → delete → recreate with original value.
func TestComputeMempoolDiff_DeleteRecreate(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "compute-diff-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	testKey := string(append([]byte{}, Prefixes.PrefixPostHashToPostEntry...))
	testKey = testKey + "test_post_hash"
	originalValue := []byte("original_value")

	// Simulate: Scan 1 has entry, Scan 2 doesn't (delete), Scan 3 recreates with original
	scan1State := map[string][]byte{testKey: originalValue}
	scan2State := make(map[string][]byte)                   // empty - entry deleted
	scan3State := map[string][]byte{testKey: originalValue} // recreated

	// Test Scan 1 → Scan 2 (deletion)
	changed, deleted, ancestralRecords := syncer.computeMempoolDiff(scan1State, scan2State, baseTxn)

	require.Len(changed, 0, "Should have no changed entries")
	require.Len(deleted, 1, "Should have one deleted entry")
	require.Len(ancestralRecords, 1, "Should have one ancestral record")

	require.Equal(originalValue, deleted[testKey], "Should track deleted value")
	require.Equal(AncestralOperationDelete, ancestralRecords[0].Operation, "Should be delete operation")

	// Test Scan 2 → Scan 3 (recreation)
	changed, deleted, ancestralRecords = syncer.computeMempoolDiff(scan2State, scan3State, baseTxn)

	require.Len(changed, 1, "Should have one changed entry")
	require.Len(deleted, 0, "Should have no deleted entries")
	require.Len(ancestralRecords, 1, "Should have one ancestral record")

	require.Equal(originalValue, changed[testKey], "Should recreate with original value")
	require.Equal(AncestralOperationInsert, ancestralRecords[0].Operation, "Should be insert operation")
}

// TestComputeMempoolDiff_MixedOperations tests a combination of creates, updates, and deletes.
func TestComputeMempoolDiff_MixedOperations(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "compute-diff-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	previousState := make(map[string][]byte)
	currentState := make(map[string][]byte)

	// Setup keys
	keyPrefix := string(append([]byte{}, Prefixes.PrefixPostHashToPostEntry...))
	createKey := keyPrefix + "new_post"
	updateKey := keyPrefix + "existing_post"
	deleteKey := keyPrefix + "removed_post"
	unchangedKey := keyPrefix + "unchanged_post"

	// Previous state: has update, delete, and unchanged keys
	previousState[updateKey] = []byte("old_value")
	previousState[deleteKey] = []byte("will_be_deleted")
	previousState[unchangedKey] = []byte("same_value")

	// Current state: has create, updated update, missing delete, same unchanged
	currentState[createKey] = []byte("new_entry")
	currentState[updateKey] = []byte("new_value")
	currentState[unchangedKey] = []byte("same_value")
	// deleteKey is missing (deleted)

	changed, deleted, ancestralRecords := syncer.computeMempoolDiff(
		previousState, currentState, baseTxn,
	)

	// Verify results
	require.Len(changed, 2, "Should have two changed entries (create + update)")
	require.Len(deleted, 1, "Should have one deleted entry")
	require.Len(ancestralRecords, 3, "Should have three ancestral records")

	// Check changed entries
	require.Equal([]byte("new_entry"), changed[createKey], "Should have new entry")
	require.Equal([]byte("new_value"), changed[updateKey], "Should have updated value")

	// Check deleted entry
	require.Equal([]byte("will_be_deleted"), deleted[deleteKey], "Should have deleted entry")

	// Verify ancestral records contain all operations
	var insertOps, updateOps, deleteOps int
	for _, record := range ancestralRecords {
		switch record.Operation {
		case AncestralOperationInsert:
			insertOps++
		case AncestralOperationUpdate:
			updateOps++
		case AncestralOperationDelete:
			deleteOps++
		}
	}
	require.Equal(1, insertOps, "Should have one insert operation")
	require.Equal(1, updateOps, "Should have one update operation")
	require.Equal(1, deleteOps, "Should have one delete operation")
}

// TestComputeMempoolDiff_EmptyStates tests edge cases with empty states.
func TestComputeMempoolDiff_EmptyStates(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "compute-diff-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	// Test 1: Both states empty
	emptyState1 := make(map[string][]byte)
	emptyState2 := make(map[string][]byte)

	changed, deleted, ancestralRecords := syncer.computeMempoolDiff(emptyState1, emptyState2, baseTxn)
	require.Len(changed, 0, "Both empty should have no changes")
	require.Len(deleted, 0, "Both empty should have no deletions")
	require.Len(ancestralRecords, 0, "Both empty should have no ancestral records")

	// Test 2: Previous empty, current has entries
	testKey := string(append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)) + "test"
	currentWithEntry := map[string][]byte{testKey: []byte("value")}

	changed, deleted, ancestralRecords = syncer.computeMempoolDiff(emptyState1, currentWithEntry, baseTxn)
	require.Len(changed, 1, "Should have one new entry")
	require.Len(deleted, 0, "Should have no deletions")
	require.Len(ancestralRecords, 1, "Should have one ancestral record")
	require.Equal(AncestralOperationInsert, ancestralRecords[0].Operation, "Should be insert")

	// Test 3: Previous has entries, current empty
	previousWithEntry := map[string][]byte{testKey: []byte("value")}

	changed, deleted, ancestralRecords = syncer.computeMempoolDiff(previousWithEntry, emptyState2, baseTxn)
	require.Len(changed, 0, "Should have no new entries")
	require.Len(deleted, 1, "Should have one deletion")
	require.Len(ancestralRecords, 1, "Should have one ancestral record")
	require.Equal(AncestralOperationDelete, ancestralRecords[0].Operation, "Should be delete")
}

// TestGenerateSequentialMempoolDiff_MultipleSameKeyFile tests that multiple updates to the same key
// generate a single entry in the diff file (with the latest value).
func TestGenerateSequentialMempoolDiff_MultipleSameKeyFile(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "sequential-diff-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	blockHeight := uint64(100)

	// First call - create initial state
	mempoolTxn1 := db.NewTransaction(true)
	defer mempoolTxn1.Discard()

	testKey := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
	testKey = append(testKey, []byte("test_post_hash")...)

	err = mempoolTxn1.Set(testKey, []byte("first_value"))
	require.NoError(err)

	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	// Create minimal blockchain and mempool for this test
	chain, params, _ := NewLowDifficultyBlockchain(t)
	mempool, _ := NewTestMiner(t, chain, params, true)

	err = syncer.generateSequentialMempoolDiff(mempoolTxn1, baseTxn, chain, mempool, blockHeight)
	require.NoError(err)

	// Second call - update same key
	mempoolTxn2 := db.NewTransaction(true)
	defer mempoolTxn2.Discard()

	err = mempoolTxn2.Set(testKey, []byte("second_value"))
	require.NoError(err)

	err = syncer.generateSequentialMempoolDiff(mempoolTxn2, baseTxn, chain, mempool, blockHeight)
	require.NoError(err)

	// Verify only one entry in the second diff file (incremental)
	files, err := os.ReadDir(dir)
	require.NoError(err)

	var secondDiffFile string
	var fileCount int
	for _, file := range files {
		name := file.Name()
		if strings.HasPrefix(name, "mempool_100_") && strings.HasSuffix(name, ".bin") {
			fileCount++
			if fileCount == 2 { // Second file created
				secondDiffFile = name
			}
		}
	}

	require.Equal(2, fileCount, "Should have created two diff files")
	require.NotEmpty(secondDiffFile, "Should have second diff file")

	// Parse second diff file - should contain update to "second_value"
	diffBytes, err := os.ReadFile(filepath.Join(dir, secondDiffFile))
	require.NoError(err)

	var foundEntries int
	err = readBadgerBackup(bytes.NewReader(diffBytes), func(kvl *pb.KVList) error {
		for _, kv := range kvl.Kv {
			foundEntries++
			require.Equal(testKey, kv.Key, "Key should match")
			require.Equal([]byte("second_value"), kv.Value, "Should have latest value")
		}
		return nil
	})
	require.NoError(err)
	require.Equal(1, foundEntries, "Should find exactly one entry in second diff file")
}

// TestGenerateSequentialMempoolDiff_SequentialFiles tests that multiple scans generate
// properly named sequential files.
func TestGenerateSequentialMempoolDiff_SequentialFiles(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "sequential-diff-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	blockHeight := uint64(200)

	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	// Create minimal blockchain and mempool for this test
	chain, params, _ := NewLowDifficultyBlockchain(t)
	mempool, _ := NewTestMiner(t, chain, params, true)

	// Generate 3 sequential diff files
	var timestamps []int64
	for i := 0; i < 3; i++ {
		mempoolTxn := db.NewTransaction(true)
		defer mempoolTxn.Discard()

		testKey := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
		testKey = append(testKey, []byte(fmt.Sprintf("test_post_%d", i))...)

		err = mempoolTxn.Set(testKey, []byte(fmt.Sprintf("value_%d", i)))
		require.NoError(err)

		beforeTime := time.Now().UnixNano()
		err = syncer.generateSequentialMempoolDiff(mempoolTxn, baseTxn, chain, mempool, blockHeight)
		require.NoError(err)
		afterTime := time.Now().UnixNano()

		// Track timestamp range for validation
		timestamps = append(timestamps, beforeTime, afterTime)

		// Small delay to ensure different timestamps
		time.Sleep(1 * time.Millisecond)
	}

	// Verify files were created with correct naming
	files, err := os.ReadDir(dir)
	require.NoError(err)

	var diffFiles []string
	var ancestralFiles []string
	for _, file := range files {
		name := file.Name()
		if strings.HasPrefix(name, "mempool_200_") && strings.HasSuffix(name, ".bin") {
			diffFiles = append(diffFiles, name)
		}
		if strings.HasPrefix(name, "mempool_ancestral_200_") && strings.HasSuffix(name, ".bin") {
			ancestralFiles = append(ancestralFiles, name)
		}
	}

	require.Len(diffFiles, 3, "Should have three diff files")
	require.Len(ancestralFiles, 3, "Should have three ancestral files")

	// Verify file naming format and timestamp ordering
	sort.Strings(diffFiles)
	sort.Strings(ancestralFiles)

	for i, filename := range diffFiles {
		// Check naming format: mempool_200_<timestamp>.bin
		require.True(strings.HasPrefix(filename, "mempool_200_"), "Should have correct prefix")
		require.True(strings.HasSuffix(filename, ".bin"), "Should have correct suffix")

		// Extract timestamp
		parts := strings.Split(filename, "_")
		require.Len(parts, 3, "Should have 3 parts")
		timestampStr := strings.TrimSuffix(parts[2], ".bin")
		fileTimestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		require.NoError(err, "Should parse timestamp")

		// Verify timestamp is within expected range
		require.True(fileTimestamp >= timestamps[i*2] && fileTimestamp <= timestamps[i*2+1],
			"Timestamp should be within expected range")
	}
}

// TestGenerateSequentialMempoolDiff_FileCleanup tests that old files are removed when
// block height changes.
func TestGenerateSequentialMempoolDiff_FileCleanup(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "cleanup-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	// Create files for block height 100
	mempoolTxn1 := db.NewTransaction(true)
	defer mempoolTxn1.Discard()

	testKey1 := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
	testKey1 = append(testKey1, []byte("test_post_1")...)
	err = mempoolTxn1.Set(testKey1, []byte("value_1"))
	require.NoError(err)

	// Create minimal blockchain and mempool for this test
	chain, params, _ := NewLowDifficultyBlockchain(t)
	mempool, _ := NewTestMiner(t, chain, params, true)

	err = syncer.generateSequentialMempoolDiff(mempoolTxn1, baseTxn, chain, mempool, uint64(100))
	require.NoError(err)

	// Verify files exist for block 100
	files, err := os.ReadDir(dir)
	require.NoError(err)

	var block100Files int
	for _, file := range files {
		name := file.Name()
		if strings.Contains(name, "_100_") {
			block100Files++
		}
	}
	require.Greater(block100Files, 0, "Should have files for block 100")

	// Create files for block height 101 (should trigger cleanup)
	mempoolTxn2 := db.NewTransaction(true)
	defer mempoolTxn2.Discard()

	testKey2 := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
	testKey2 = append(testKey2, []byte("test_post_2")...)
	err = mempoolTxn2.Set(testKey2, []byte("value_2"))
	require.NoError(err)

	err = syncer.generateSequentialMempoolDiff(mempoolTxn2, baseTxn, chain, mempool, uint64(102))
	require.NoError(err)

	// Verify block 100 files are cleaned up (now 2 blocks old), block 102 files exist
	files, err = os.ReadDir(dir)
	require.NoError(err)

	var block100FilesAfter, block102Files int
	for _, file := range files {
		name := file.Name()
		if strings.Contains(name, "_100_") {
			block100FilesAfter++
		}
		if strings.Contains(name, "_102_") {
			block102Files++
		}
	}

	require.Equal(0, block100FilesAfter, "Block 100 files should be cleaned up (2 blocks old)")
	require.Greater(block102Files, 0, "Should have files for block 102")
}

// TestGenerateSequentialMempoolDiff_TimestampOrdering tests that files are generated
// in correct timestamp order.
func TestGenerateSequentialMempoolDiff_TimestampOrdering(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "timestamp-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	blockHeight := uint64(300)
	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	// Create minimal blockchain and mempool for this test
	chain, params, _ := NewLowDifficultyBlockchain(t)
	mempool, _ := NewTestMiner(t, chain, params, true)

	var generatedFiles []string
	var generatedTimestamps []int64

	// Generate multiple files with small delays
	for i := 0; i < 5; i++ {
		mempoolTxn := db.NewTransaction(true)
		defer mempoolTxn.Discard()

		testKey := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
		testKey = append(testKey, []byte(fmt.Sprintf("test_post_%d", i))...)
		err = mempoolTxn.Set(testKey, []byte(fmt.Sprintf("value_%d", i)))
		require.NoError(err)

		err = syncer.generateSequentialMempoolDiff(mempoolTxn, baseTxn, chain, mempool, blockHeight)
		require.NoError(err)

		// Record the last timestamp used
		require.NotNil(syncer.mempoolSyncState, "Should have sync state")
		generatedTimestamps = append(generatedTimestamps, syncer.mempoolSyncState.lastSyncTimestamp)

		time.Sleep(2 * time.Millisecond) // Ensure timestamp difference
	}

	// Verify timestamps are monotonically increasing
	for i := 1; i < len(generatedTimestamps); i++ {
		require.Greater(generatedTimestamps[i], generatedTimestamps[i-1],
			"Timestamps should be increasing")
	}

	// Verify files can be sorted by timestamp
	files, err := os.ReadDir(dir)
	require.NoError(err)

	for _, file := range files {
		name := file.Name()
		if strings.HasPrefix(name, "mempool_300_") && strings.HasSuffix(name, ".bin") {
			generatedFiles = append(generatedFiles, name)
		}
	}

	require.Len(generatedFiles, 5, "Should have 5 diff files")

	// Extract and verify timestamp ordering
	var fileTimestamps []int64
	for _, filename := range generatedFiles {
		parts := strings.Split(filename, "_")
		timestampStr := strings.TrimSuffix(parts[2], ".bin")
		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		require.NoError(err)
		fileTimestamps = append(fileTimestamps, timestamp)
	}

	// Sort files by extracted timestamp
	sort.SliceStable(generatedFiles, func(i, j int) bool {
		return fileTimestamps[i] < fileTimestamps[j]
	})

	// Verify sorted order matches generated order
	for i := 1; i < len(fileTimestamps); i++ {
		require.Less(fileTimestamps[i-1], fileTimestamps[i],
			"File timestamps should be in increasing order")
	}
}

// TestGenerateSequentialMempoolDiff_BlockHeightTransition tests proper file naming
// across block height changes.
func TestGenerateSequentialMempoolDiff_BlockHeightTransition(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "block-transition-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	// Create minimal blockchain and mempool for this test
	chain, params, _ := NewLowDifficultyBlockchain(t)
	mempool, _ := NewTestMiner(t, chain, params, true)

	// Generate files for block height 100
	for i := 0; i < 2; i++ {
		mempoolTxn := db.NewTransaction(true)
		defer mempoolTxn.Discard()

		testKey := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
		testKey = append(testKey, []byte(fmt.Sprintf("post_100_%d", i))...)
		err = mempoolTxn.Set(testKey, []byte(fmt.Sprintf("value_%d", i)))
		require.NoError(err)

		err = syncer.generateSequentialMempoolDiff(mempoolTxn, baseTxn, chain, mempool, uint64(100))
		require.NoError(err)
		time.Sleep(1 * time.Millisecond)
	}

	// Transition to block height 101 - should reset state
	for i := 0; i < 2; i++ {
		mempoolTxn := db.NewTransaction(true)
		defer mempoolTxn.Discard()

		testKey := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
		testKey = append(testKey, []byte(fmt.Sprintf("post_101_%d", i))...)
		err = mempoolTxn.Set(testKey, []byte(fmt.Sprintf("value_%d", i)))
		require.NoError(err)

		err = syncer.generateSequentialMempoolDiff(mempoolTxn, baseTxn, chain, mempool, uint64(101))
		require.NoError(err)
		time.Sleep(1 * time.Millisecond)
	}

	// Verify file naming and state reset
	files, err := os.ReadDir(dir)
	require.NoError(err)

	var block101Files []string
	for _, file := range files {
		name := file.Name()
		if strings.HasPrefix(name, "mempool_101_") && strings.HasSuffix(name, ".bin") {
			block101Files = append(block101Files, name)
		}
	}

	require.Len(block101Files, 2, "Should have 2 files for block 101")

	// Verify sync state was reset for new block height
	require.NotNil(syncer.mempoolSyncState, "Should have sync state")
	require.Equal(uint64(101), syncer.mempoolSyncState.currentBlockHeight, "Should be at block 101")

	// First file for block 101 should contain all entries (state was reset)
	sort.Strings(block101Files)
	firstFile := block101Files[0]

	diffBytes, err := os.ReadFile(filepath.Join(dir, firstFile))
	require.NoError(err)

	var foundEntries int
	err = readBadgerBackup(bytes.NewReader(diffBytes), func(kvl *pb.KVList) error {
		for range kvl.Kv {
			foundEntries++
		}
		return nil
	})
	require.NoError(err)
	require.Equal(1, foundEntries, "First file should have 1 entry (new state)")
}

// TestGenerateSequentialMempoolDiff_ErrorHandling tests error scenarios.
func TestGenerateSequentialMempoolDiff_ErrorHandling(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	// Create a valid temp directory first
	dir, err := os.MkdirTemp("", "error-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	mempoolTxn := db.NewTransaction(true)
	defer mempoolTxn.Discard()

	testKey := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
	testKey = append(testKey, []byte("test_post")...)
	err = mempoolTxn.Set(testKey, []byte("test_value"))
	require.NoError(err)

	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	// Create minimal blockchain and mempool for this test
	chain, params, _ := NewLowDifficultyBlockchain(t)
	mempool, _ := NewTestMiner(t, chain, params, true)

	// Test error by making directory read-only after creating the syncer
	err = os.Chmod(dir, 0444) // Read-only
	require.NoError(err)

	// Should return error due to read-only directory
	err = syncer.generateSequentialMempoolDiff(mempoolTxn, baseTxn, chain, mempool, uint64(100))
	require.Error(err, "Should fail with read-only directory")
	require.Contains(err.Error(), "failed to write diff file", "Should have appropriate error message")

	// Restore directory permissions for cleanup
	os.Chmod(dir, 0755)
}

// TestGenerateSequentialMempoolDiff_LargeState tests performance with large mempool state.
func TestGenerateSequentialMempoolDiff_LargeState(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "large-state-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	blockHeight := uint64(400)

	mempoolTxn := db.NewTransaction(true)
	defer mempoolTxn.Discard()

	// Create a large number of entries
	numEntries := 1000
	for i := 0; i < numEntries; i++ {
		testKey := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
		testKey = append(testKey, []byte(fmt.Sprintf("post_%d", i))...)
		testValue := []byte(fmt.Sprintf("value_%d_with_some_extra_data_to_make_it_larger", i))

		err = mempoolTxn.Set(testKey, testValue)
		require.NoError(err)
	}

	baseTxn := db.NewTransaction(false)
	defer baseTxn.Discard()

	// Create minimal blockchain and mempool for this test
	chain, params, _ := NewLowDifficultyBlockchain(t)
	mempool, _ := NewTestMiner(t, chain, params, true)

	// Measure performance
	startTime := time.Now()
	err = syncer.generateSequentialMempoolDiff(mempoolTxn, baseTxn, chain, mempool, blockHeight)
	duration := time.Since(startTime)

	require.NoError(err, "Should handle large state without error")
	require.Less(duration, 5*time.Second, "Should complete within reasonable time")

	// Verify correct number of entries in diff file
	files, err := os.ReadDir(dir)
	require.NoError(err)

	var diffFile string
	for _, file := range files {
		name := file.Name()
		if strings.HasPrefix(name, "mempool_400_") && strings.HasSuffix(name, ".bin") {
			diffFile = name
			break
		}
	}

	require.NotEmpty(diffFile, "Should have created diff file")

	diffBytes, err := os.ReadFile(filepath.Join(dir, diffFile))
	require.NoError(err)
	require.Greater(len(diffBytes), numEntries*10, "Diff file should be reasonably sized")

	// Verify all entries are present
	var foundEntries int
	err = readBadgerBackup(bytes.NewReader(diffBytes), func(kvl *pb.KVList) error {
		foundEntries += len(kvl.Kv)
		return nil
	})
	require.NoError(err)
	require.Equal(numEntries, foundEntries, "Should find all entries in diff file")

	// Verify sync state tracking
	require.NotNil(syncer.mempoolSyncState, "Should have sync state")
	require.Len(syncer.mempoolSyncState.lastSyncState, numEntries, "Should track all entries")

	t.Logf("Large state test completed: %d entries processed in %v", numEntries, duration)
}

// TestExtractTransactionEntries_SingleTransaction tests that extractTransactionEntries correctly
// creates transaction and associated entries for a single mempool transaction.
func TestExtractTransactionEntries_SingleTransaction(t *testing.T) {
	require := require.New(t)

	// Create test blockchain environment
	chain, params, db := NewLowDifficultyBlockchain(t)
	_ = params
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "extract-transaction-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	// Create test miner and mempool
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Mine a few blocks to set up the chain with block rewards
	for i := 0; i < 3; i++ {
		_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
	}

	// Get a funded key for transactions
	senderPkString := "tBCKXFJEDSF7Thcc6BUBcB6kicE5qzmLbAtvFf9LfKSXN4LwFt36oX"
	senderPrivString := "tbc31669t2YuZ2mi1VLtK6a17RXFPdsuBDcenPLc1eU1ZVRHF9Zv4"
	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)

	// Create and submit a test transaction to the mempool
	submitPostTxn, _, _, _, err := chain.CreateSubmitPostTxn(
		senderPkBytes, // updaterPublicKey
		[]byte{},      // postHashToModify (empty for new post)
		[]byte{},      // parentStakeID
		[]byte("This is a test post for transaction extraction"), // body
		[]byte{},                      // repostPostHashBytes
		false,                         // isQuotedRepost
		uint64(time.Now().UnixNano()), // tstampNanos
		map[string][]byte{},           // postExtraData
		false,                         // isHidden
		10000,                         // minFeeRateNanosPerKB
		mempool,                       // mempool
		[]*DeSoOutput{},               // additionalOutputs
	)
	require.NoError(err)
	require.NotNil(submitPostTxn)

	// Sign the transaction
	_signTxn(t, submitPostTxn, senderPrivString)

	// Add the transaction to the mempool
	_, err = mempool.ProcessTransaction(submitPostTxn, false, false, 0, true)
	require.NoError(err)

	// Verify transaction is in mempool
	mempoolTxns := mempool.GetOrderedTransactions()
	require.Len(mempoolTxns, 1, "Should have one transaction in mempool")
	require.Equal(submitPostTxn.Hash(), mempoolTxns[0].Hash, "Transaction hash should match")

	blockHeight := uint64(chain.blockTip().Height)

	// Call extractTransactionEntries
	transactionState, err := syncer.extractTransactionEntries(chain, mempool, blockHeight)
	require.NoError(err)
	require.NotEmpty(transactionState, "Should extract transaction entries")

	// Verify transaction entry was created
	txnKey := string(TxnHashToTxnKey(submitPostTxn.Hash()))
	txnBytes, exists := transactionState[txnKey]
	require.True(exists, "Should have transaction entry")
	require.NotEmpty(txnBytes, "Transaction bytes should not be empty")

	// Verify transaction UtxoOps entry was created
	utxoOpsKey := string(_DbKeyForTxnUtxoOps(submitPostTxn.Hash()))
	utxoOpsBytes, exists := transactionState[utxoOpsKey]
	require.True(exists, "Should have transaction UtxoOps entry")
	require.NotEmpty(utxoOpsBytes, "UtxoOps bytes should not be empty")

	// Verify we can decode the transaction bytes
	decodedTxn := &MsgDeSoTxn{}
	rr := bytes.NewReader(txnBytes)
	exist, err := DecodeFromBytes(decodedTxn, rr)
	require.NoError(err, "Should be able to decode transaction bytes")
	require.True(exist, "Transaction should exist in bytes")
	require.Equal(submitPostTxn.Hash(), decodedTxn.Hash(), "Decoded transaction should match original")

	// Verify we can decode the UtxoOps bytes
	utxoOpBundle := &UtxoOperationBundle{}
	rr = bytes.NewReader(utxoOpsBytes)
	exist, err = DecodeFromBytes(utxoOpBundle, rr)
	require.NoError(err, "Should be able to decode UtxoOps bytes")
	require.True(exist, "UtxoOps should exist in bytes")
	require.NotEmpty(utxoOpBundle.UtxoOpBundle, "Should have UtxoOps in bundle")
	require.Len(utxoOpBundle.UtxoOpBundle, 1, "Should have one transaction's worth of UtxoOps")

	// Verify the UtxoOps are for a SubmitPost operation
	txnUtxoOps := utxoOpBundle.UtxoOpBundle[0]
	require.NotEmpty(txnUtxoOps, "Should have UtxoOps for the transaction")

	// Look for SubmitPost operation in the UtxoOps
	var hasSubmitPostOp bool
	for _, utxoOp := range txnUtxoOps {
		if utxoOp.Type == OperationTypeSubmitPost {
			hasSubmitPostOp = true
			break
		}
	}
	require.True(hasSubmitPostOp, "Should have SubmitPost UtxoOp")

	t.Logf("Successfully extracted transaction entries: TxnKey=%s, UtxoOpsKey=%s, total entries=%d",
		txnKey, utxoOpsKey, len(transactionState))
}

// TestExtractTransactionEntries_EmptyMempool tests extractTransactionEntries with an empty mempool.
func TestExtractTransactionEntries_EmptyMempool(t *testing.T) {
	require := require.New(t)

	chain, params, db := NewLowDifficultyBlockchain(t)
	_ = params
	defer CleanUpBadger(db)

	dir, err := os.MkdirTemp("", "extract-empty-mempool-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	// Create test miner and mempool but don't add any transactions
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Mine a block but don't add any transactions to mempool
	_, err = miner.MineAndProcessSingleBlock(0, mempool)
	require.NoError(err)

	blockHeight := uint64(chain.blockTip().Height)

	// Extract transaction entries from empty mempool
	transactionState, err := syncer.extractTransactionEntries(chain, mempool, blockHeight)
	require.NoError(err)

	// May have uncommitted block entries, but no transaction entries
	for key := range transactionState {
		keyBytes := []byte(key)
		// Should not have any transaction keys
		require.False(bytes.HasPrefix(keyBytes, Prefixes.PrefixTxnHashToTxn),
			"Should not have transaction entries with empty mempool, found key: %x", keyBytes)
	}

	t.Logf("Empty mempool test passed, extracted %d entries (blocks/utxoops only)",
		len(transactionState))
}

// TestMergeMempoolStates tests the mergeMempoolStates helper function.
func TestMergeMempoolStates(t *testing.T) {
	require := require.New(t)

	// Create test states
	flushedState := map[string][]byte{
		"flushed_key_1": []byte("flushed_value_1"),
		"flushed_key_2": []byte("flushed_value_2"),
		"shared_key":    []byte("flushed_shared_value"),
	}

	transactionState := map[string][]byte{
		"transaction_key_1": []byte("transaction_value_1"),
		"transaction_key_2": []byte("transaction_value_2"),
		"shared_key":        []byte("transaction_shared_value"), // Should override flushed
	}

	// Merge states
	mergedState := mergeMempoolStates(flushedState, transactionState)

	// Verify all keys are present
	require.Len(mergedState, 5, "Should have 5 unique keys")

	// Verify flushed keys
	require.Equal([]byte("flushed_value_1"), mergedState["flushed_key_1"])
	require.Equal([]byte("flushed_value_2"), mergedState["flushed_key_2"])

	// Verify transaction keys
	require.Equal([]byte("transaction_value_1"), mergedState["transaction_key_1"])
	require.Equal([]byte("transaction_value_2"), mergedState["transaction_key_2"])

	// Verify transaction state takes precedence
	require.Equal([]byte("transaction_shared_value"), mergedState["shared_key"],
		"Transaction state should override flushed state")
}

// TestMergeMempoolStates_EmptyStates tests mergeMempoolStates with empty states.
func TestMergeMempoolStates_EmptyStates(t *testing.T) {
	require := require.New(t)

	// Test with empty flushed state
	flushedEmpty := make(map[string][]byte)
	transactionFull := map[string][]byte{"key": []byte("value")}

	merged1 := mergeMempoolStates(flushedEmpty, transactionFull)
	require.Len(merged1, 1)
	require.Equal([]byte("value"), merged1["key"])

	// Test with empty transaction state
	flushedFull := map[string][]byte{"key": []byte("value")}
	transactionEmpty := make(map[string][]byte)

	merged2 := mergeMempoolStates(flushedFull, transactionEmpty)
	require.Len(merged2, 1)
	require.Equal([]byte("value"), merged2["key"])

	// Test with both empty
	merged3 := mergeMempoolStates(flushedEmpty, transactionEmpty)
	require.Len(merged3, 0)
}

// TestCleanupOldMempoolFiles_TwoBlockRetention tests that cleanup keeps files for current block and 1 block back
func TestCleanupOldMempoolFiles_TwoBlockRetention(t *testing.T) {
	require := require.New(t)

	dir, err := os.MkdirTemp("", "mempool-cleanup-test")
	require.NoError(err)
	defer os.RemoveAll(dir)

	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)

	// Create test files for different block heights
	testFiles := []string{
		"mempool_100_1234567890.bin",           // Current block
		"mempool_99_1234567890.bin",            // 1 block back - should be kept
		"mempool_98_1234567890.bin",            // 2 blocks back - should be deleted
		"mempool_97_1234567890.bin",            // 3 blocks back - should be deleted
		"mempool_ancestral_100_1234567890.bin", // Current block ancestral
		"mempool_ancestral_99_1234567890.bin",  // 1 block back ancestral - should be kept
		"mempool_ancestral_98_1234567890.bin",  // 2 blocks back ancestral - should be deleted
		"mempool_ancestral_97_1234567890.bin",  // 3 blocks back ancestral - should be deleted
	}

	// Create all test files
	for _, filename := range testFiles {
		filePath := filepath.Join(dir, filename)
		err = os.WriteFile(filePath, []byte("test"), 0644)
		require.NoError(err)
	}

	// Verify all files exist
	for _, filename := range testFiles {
		filePath := filepath.Join(dir, filename)
		_, err = os.Stat(filePath)
		require.NoError(err, "File should exist before cleanup: %s", filename)
	}

	// Run cleanup for block height 100
	err = syncer.cleanupOldMempoolFiles(100)
	require.NoError(err)

	// Check which files still exist
	expectedToExist := []string{
		"mempool_100_1234567890.bin",           // Current block - should exist
		"mempool_99_1234567890.bin",            // 1 block back - should exist
		"mempool_ancestral_100_1234567890.bin", // Current block ancestral - should exist
		"mempool_ancestral_99_1234567890.bin",  // 1 block back ancestral - should exist
	}

	expectedToBeDeleted := []string{
		"mempool_98_1234567890.bin",           // 2 blocks back - should be deleted
		"mempool_97_1234567890.bin",           // 3 blocks back - should be deleted
		"mempool_ancestral_98_1234567890.bin", // 2 blocks back ancestral - should be deleted
		"mempool_ancestral_97_1234567890.bin", // 3 blocks back ancestral - should be deleted
	}

	// Verify files that should still exist
	for _, filename := range expectedToExist {
		filePath := filepath.Join(dir, filename)
		_, err = os.Stat(filePath)
		require.NoError(err, "File should still exist after cleanup: %s", filename)
	}

	// Verify files that should be deleted
	for _, filename := range expectedToBeDeleted {
		filePath := filepath.Join(dir, filename)
		_, err = os.Stat(filePath)
		require.True(os.IsNotExist(err), "File should be deleted after cleanup: %s", filename)
	}
}
