package lib

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"testing"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/dgraph-io/badger/v3/pb"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestStateChangeEntryEncoder(t *testing.T) {
	postBytesHex := "13a546bba07e9cd96e29cea659b3bb6de1b5144a50bf2a0c94d05701861d8254"
	byteArray, err := hex.DecodeString(postBytesHex)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	blockHash := NewBlockHash(byteArray)

	blockHash.ToBytes()
	postBody := &DeSoBodySchema{
		Body:      "Test string",
		ImageURLs: []string{"https://test.com/image1.jpg", "https://test.com/image2.jpg"},
		VideoURLs: []string{"https://test.com/video1.mp4", "https://test.com/video2.mp4"},
	}

	bodyBytes, err := json.Marshal(postBody)
	require.NoError(t, err)

	currentTimeNanos := time.Now()

	postEntry := &PostEntry{
		TimestampNanos:  uint64(currentTimeNanos.UnixNano()),
		PostHash:        blockHash,
		ParentStakeID:   blockHash.ToBytes(),
		Body:            bodyBytes,
		PosterPublicKey: []byte{2, 57, 123, 26, 128, 235, 160, 166, 6, 68, 101, 10, 241, 60, 42, 111, 253, 251, 191, 56, 131, 12, 175, 195, 73, 55, 167, 93, 221, 68, 184, 206, 82},
	}

	stateChangeEntry := &StateChangeEntry{
		OperationType: DbOperationTypeUpsert,
		KeyBytes:      []byte{1, 2, 3},
		Encoder:       postEntry,
		EncoderType:   postEntry.GetEncoderType(),
		IsReverted:    false,
	}

	stateChangeEntryBytes := EncodeToBytes(0, stateChangeEntry)

	stateChangeEntryDecoded := &StateChangeEntry{}

	exists, err := DecodeFromBytes(stateChangeEntryDecoded, bytes.NewReader(stateChangeEntryBytes))
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, stateChangeEntry.EncoderType, stateChangeEntryDecoded.EncoderType)
	require.Equal(t, stateChangeEntry.KeyBytes, stateChangeEntryDecoded.KeyBytes)
	require.Equal(t, stateChangeEntry.OperationType, stateChangeEntryDecoded.OperationType)
	require.Equal(t, &stateChangeEntry.Encoder, &stateChangeEntryDecoded.Encoder)
}

// TestBackupDatabase is a very small proof-of-concept that demonstrates how we can take a full
// and an incremental Badger backup and then verify that a newly inserted PostEntry is captured
// in the incremental backup stream.
func TestBackupDatabase(t *testing.T) {
	require := require.New(t)

	// ---------------------------------------------------------------------
	// 1. Setup – create an in-memory Badger database and a state change syncer
	// ---------------------------------------------------------------------

	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	// Create a temporary directory for the StateChangeSyncer log files.
	stateDir, err := os.MkdirTemp("", "state-syncer")
	require.NoError(err)

	syncer := NewStateChangeSyncer(stateDir, NodeSyncTypeBlockSync, 0 /*mempoolTxnSyncLimit*/)

	// ---------------------------------------------------------------------
	// 2. Take an initial backup – this represents the state prior to any txns
	// ---------------------------------------------------------------------

	postHash := NewBlockHash([]byte("test-post-hash"))
	postKey := _dbKeyForPostEntryHash(postHash)

	var since uint64 = 0
	preCommitTxn := db.NewTransaction(false)
	defer preCommitTxn.Discard()
	_, since, err = syncer.BackupDatabase(db, preCommitTxn, since)
	require.NoError(err)

	// ---------------------------------------------------------------------
	// 3. Execute a simple "transaction" – we persist a PostEntry to the DB
	// ---------------------------------------------------------------------

	// Build a dummy PostEntry.
	postEntry := &PostEntry{
		TimestampNanos: uint64(time.Now().UnixNano()),
		Body:           []byte("hello world from backup test"),
		// For this unit test, the remaining fields are irrelevant so we leave them nil/zero.
	}

	// Encode the entry using the DeSo encoder helpers so that it mimics how the real node would
	// store it on disk.
	postEntryEncoded := EncodeToBytes(0, postEntry)

	preCommitTxn2 := db.NewTransaction(false)
	defer preCommitTxn2.Discard()

	err = db.Update(func(txn *badger.Txn) error {
		return txn.Set(postKey, postEntryEncoded)
	})
	require.NoError(err)

	// ---------------------------------------------------------------------
	// 4. Take an incremental backup and perform basic assertions
	// ---------------------------------------------------------------------

	incrBackupBytes, nextSince, err := syncer.BackupDatabase(db, preCommitTxn2, since)
	require.NoError(err)

	// Use the new ExtractStateChangesFromBackup function
	flushId := uuid.New()
	blockHeight := uint64(1)
	stateChanges, err := syncer.ExtractStateChangesFromBackup(incrBackupBytes, flushId, blockHeight)
	require.NoError(err)

	// Find the post entry in the state changes
	found := false

	for _, change := range stateChanges {
		if bytes.Equal(change.KeyBytes, postKey) {
			require.Equal(DbOperationTypeUpsert, change.OperationType)
			require.Equal(EncoderTypePostEntry, change.EncoderType)
			require.Equal(flushId, change.FlushId)
			require.Equal(blockHeight, change.BlockHeight)

			// For upsert operations, both Encoder and EncoderBytes should be set
			require.NotNil(change.Encoder, "Encoder should not be nil for upsert operations")
			require.NotEmpty(change.EncoderBytes, "EncoderBytes should not be empty for upsert operations")

			// Verify the cast encoder
			castEncoder := change.Encoder.(*PostEntry)
			require.Equal(postEntry.Body, castEncoder.Body)

			// Verify by decoding the encoder bytes
			decodedFromBytes := new(PostEntry)
			ok, err := DecodeFromBytes(decodedFromBytes, bytes.NewReader(change.EncoderBytes))
			require.NoError(err)
			require.True(ok)
			require.Equal(postEntry.Body, decodedFromBytes.Body)

			// Both should have the same data
			require.Equal(castEncoder.Body, decodedFromBytes.Body)
			found = true
			break
		}
	}
	require.True(found)

	since = nextSince

	// Backup again, ensure that the post entry is not in the backup.
	preCommitTxn3 := db.NewTransaction(false)
	defer preCommitTxn3.Discard()
	incrBackupBytes, nextSince, err = syncer.BackupDatabase(db, preCommitTxn3, since)
	require.NoError(err)

	// Use the new ExtractStateChangesFromBackup function
	stateChanges, err = syncer.ExtractStateChangesFromBackup(incrBackupBytes, flushId, blockHeight)
	require.NoError(err)

	// Ensure the post entry is not in the state changes
	for _, change := range stateChanges {
		if bytes.Equal(change.KeyBytes, postKey) {
			require.Fail("post entry should not be in the backup")
		}
	}

	since = nextSince

	// Backup again, ensure that the post entry is updated.
	preCommitTxn4 := db.NewTransaction(false)
	defer preCommitTxn4.Discard()
	
	// Update the post entry.
	postEntry.Body = []byte("hello world from backup test 2")
	postEntryEncoded = EncodeToBytes(0, postEntry)
	err = db.Update(func(txn *badger.Txn) error {
		return txn.Set(postKey, postEntryEncoded)
	})
	require.NoError(err)

	
	incrBackupBytes, nextSince, err = syncer.BackupDatabase(db, preCommitTxn4, since)
	require.NoError(err)

	// Use the new ExtractStateChangesFromBackup function
	stateChanges, err = syncer.ExtractStateChangesFromBackup(incrBackupBytes, flushId, blockHeight)
	require.NoError(err)

	// Find the updated post entry in the state changes
	found = false
	for _, change := range stateChanges {
		if bytes.Equal(change.KeyBytes, postKey) {
			require.Equal(DbOperationTypeUpsert, change.OperationType)
			require.Equal(EncoderTypePostEntry, change.EncoderType)

			// For upsert operations, both Encoder and EncoderBytes should be set
			require.NotNil(change.Encoder, "Encoder should not be nil for upsert operations")
			require.NotEmpty(change.EncoderBytes, "EncoderBytes should not be empty for upsert operations")

			// Verify the cast encoder
			castEncoder := change.Encoder.(*PostEntry)
			require.Equal(postEntry.Body, castEncoder.Body)

			// Verify by decoding the encoder bytes
			decodedFromBytes := new(PostEntry)
			ok, err := DecodeFromBytes(decodedFromBytes, bytes.NewReader(change.EncoderBytes))
			require.NoError(err)
			require.True(ok)
			require.Equal(postEntry.Body, decodedFromBytes.Body)

			// Both should have the same data
			require.Equal(castEncoder.Body, decodedFromBytes.Body)
			found = true
			break
		}
	}
	require.True(found)

	since = nextSince

	// Delete the post entry.
	err = db.Update(func(txn *badger.Txn) error {
		return txn.Delete(postKey)
	})
	require.NoError(err)

	preCommitTxn5 := db.NewTransaction(false)
	defer preCommitTxn5.Discard()
	incrBackupBytes, nextSince, err = syncer.BackupDatabase(db, preCommitTxn5, since)
	require.NoError(err)

	// Use the new ExtractStateChangesFromBackup function
	stateChanges, err = syncer.ExtractStateChangesFromBackup(incrBackupBytes, flushId, blockHeight)
	require.NoError(err)

	// Find the deleted post entry in the state changes
	found = false
	for _, change := range stateChanges {
		if bytes.Equal(change.KeyBytes, postKey) {
			require.Equal(DbOperationTypeDelete, change.OperationType)
			require.Equal(EncoderTypePostEntry, change.EncoderType)

			// For delete operations, EncoderBytes should be empty and Encoder should be nil
			require.Equal(0, len(change.EncoderBytes), "EncoderBytes should be empty for delete operations")
			require.Nil(change.Encoder, "Encoder should be nil for delete operations")
			found = true
			break
		}
	}
	require.True(found)
}

// TODO:
// 1. Build out more generalized means of extracting all entries from a backup.
//  - Return slice of state change entries.
//  - No anc records for now.
//  - Use versions to differentiate between updates and creates?
// 1.5 Figure out how to handle the since value - should we just store it globally? Probably need it in badger somewhere so that we can use it for recovery.
//  - Create utils for reading/writing since value.
// 2. Figure out if there's a way to only stream indexes we care about.
//  - Update above test to use this.
// 3. Come up with a way to determine which version to use.
//  - Change extract function should automatically use the highest version.
// 4. Build out function to execute global backup.
//  - Basically just the extract function.
// 5. Build out function to execute recovery.
//  test recovery, ensure that the correct entries are recorded.
// test that deletes and updates are handled correctly.
// 6. Encode all recovered entries, save to file.
// 7. Build consumer functions to read saved entries.
// 8. Plan out mempool sync.
//  - On block flush, update the stored badger txn.
//  - Figure out how to handle versioning/since.
// Plan out hypersync (keep as is?)

func readBadgerBackupOld(r io.Reader, handle func(*pb.KVList) error) error {
	for chunk := 0; ; chunk++ {
		// (1) length header
		var sz uint32
		if err := binary.Read(r, binary.LittleEndian, &sz); err != nil {
			if err == io.EOF {
				return nil // end of stream
			}
			return fmt.Errorf("chunk %d: reading len: %w", chunk, err)
		}

		// (2) checksum – read and ignore (or verify with crc32.ChecksumIEEE)
		var crc uint32
		if err := binary.Read(r, binary.LittleEndian, &crc); err != nil {
			return fmt.Errorf("chunk %d: reading crc32: %w", chunk, err)
		}

		// (3) protobuf payload
		data := make([]byte, sz)
		if _, err := io.ReadFull(r, data); err != nil {
			return fmt.Errorf("chunk %d: reading payload: %w", chunk, err)
		}

		kvList := new(pb.KVList)
		if err := proto.Unmarshal(data, kvList); err != nil {
			return fmt.Errorf("chunk %d: unmarshal: %w", chunk, err)
		}

		if err := handle(kvList); err != nil {
			return err
		}
	}
}
