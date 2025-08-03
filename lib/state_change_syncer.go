package lib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deso-protocol/go-deadlock"

	"github.com/dgraph-io/badger/v3"
	"github.com/dgraph-io/badger/v3/pb"
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// StateSyncerOperationType is an enum that represents the type of operation that should be performed on the
// state consumer database.
type StateSyncerOperationType uint8

const (
	DbOperationTypeInsert StateSyncerOperationType = 0
	DbOperationTypeDelete StateSyncerOperationType = 1
	DbOperationTypeUpsert StateSyncerOperationType = 2
)

const (
	StateChangeFileName             = "state-changes.bin"
	StateChangeIndexFileName        = "state-changes-index.bin"
	StateChangeMempoolFileName      = "mempool.bin"
	StateChangeMempoolIndexFileName = "mempool-index.bin"
)

// StateChangeEntry is used to capture the state of the database. These changes are then written to a file, which is
// then used to sync data consumers who subscribe to changes to that file.
type StateChangeEntry struct {
	// The type of operation that should be performed on the database.
	OperationType StateSyncerOperationType
	// The key that should be used for the operation.
	KeyBytes []byte
	// The encoder that is being captured by this state change.
	Encoder DeSoEncoder
	// The encoder represented in bytes. This could be created by just calling EncodeToBytes on the encoder, but
	// during operations like hypersync, we are given the raw bytes of the encoder, which is all we need to encode the
	// StateChangeEntry. Thus, we store the raw bytes here to avoid having to re-encode the encoder.
	EncoderBytes []byte
	// The ancestral record that should be used to revert this transaction.
	AncestralRecord DeSoEncoder
	// The ancestral record represented in bytes.
	// This is used in order to revert applied mempool entries. When a new block mines, all applied mempool entries
	// need to be reverted before applying the entries from the block. Ancestral records are what tells the consumer
	// how to revert a given entry.
	AncestralRecordBytes []byte
	// The type of encoder that should be used for the operation.
	EncoderType EncoderType
	// The flush this entry belongs to.
	FlushId uuid.UUID
	// The height of the block this entry belongs to.
	BlockHeight uint64
	// The block associated with this state change event. Only applicable to utxo operations.
	Block *MsgDeSoBlock
	// For mempool state changes, whether this operation has been booted from the mempool and should be reverted
	// from the state change record.
	IsReverted bool
}

// RawEncodeWithoutMetadata constructs the bytes to represent a StateChangeEntry.
// The format is:
// [operation type (varint)][is reverted bool][encoder type (varint)][key length (varint)][key bytes]
// [encoder length (varint)][encoder bytes][is mempool (1 byte)][utxo ops length (varint)][utxo ops bytes]
func (stateChangeEntry *StateChangeEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	// Get byte length of keyBytes (will be nil for mempool transactions)
	var data []byte

	// OperationType
	data = append(data, UintToBuf(uint64(stateChangeEntry.OperationType))...)
	// IsReverted
	data = append(data, BoolToByte(stateChangeEntry.IsReverted))
	// EncoderType
	data = append(data, UintToBuf(uint64(stateChangeEntry.EncoderType))...)
	// KeyBytes
	data = append(data, EncodeByteArray(stateChangeEntry.KeyBytes)...)

	// The encoder can either be represented in raw bytes or as an encoder. If it's represented in bytes, we use that.
	// This is because during hypersync, we are given the raw bytes of the encoder, which is all we need to encode the
	// StateChangeEntry. Thus, we store the raw bytes here to avoid having to re-encode the encoder.

	// Get bytes for the encoder.
	encoderBytes := stateChangeEntry.EncoderBytes

	// If the encoderBytes is nil and the encoder is not nil, encode the encoder.
	if len(encoderBytes) == 0 && stateChangeEntry.Encoder != nil {
		encoderBytes = EncodeToBytes(blockHeight, stateChangeEntry.Encoder)
	} else if len(encoderBytes) == 0 && stateChangeEntry.Encoder == nil {
		// If both the encoder and encoder bytes are null, encode a blank encoder.
		// This will happen with delete operations.
		encoderBytes = EncodeToBytes(blockHeight, nil)
	}

	data = append(data, encoderBytes...)

	// Get bytes for the ancestral record.
	ancestralRecordBytes := stateChangeEntry.AncestralRecordBytes

	// If the ancestralRecordBytes is nil and the ancestral record is not nil, encode the ancestral record.
	if len(ancestralRecordBytes) == 0 && stateChangeEntry.AncestralRecord != nil {
		ancestralRecordBytes = EncodeToBytes(blockHeight, stateChangeEntry.AncestralRecord)
	} else if len(ancestralRecordBytes) == 0 && stateChangeEntry.AncestralRecord == nil {
		// If both the ancestral record and ancestral record bytes are null, encode a blank encoder.
		// This will happen with insert operations.
		ancestralRecordBytes = EncodeToBytes(blockHeight, nil)
	}

	data = append(data, ancestralRecordBytes...)

	// Encode the flush UUID.
	// Error handling can be skipped here, the error is guaranteed to be nil.
	flushIdBytes, _ := stateChangeEntry.FlushId.MarshalBinary()

	data = append(data, flushIdBytes...)

	// Encode the block height.
	data = append(data, UintToBuf(blockHeight)...)

	// Encode the block, only for utxo operations.
	if stateChangeEntry.EncoderType == EncoderTypeUtxoOperation ||
		stateChangeEntry.EncoderType == EncoderTypeUtxoOperationBundle {
		data = append(data, EncodeToBytes(blockHeight, stateChangeEntry.Block)...)
	}

	return data
}

func (stateChangeEntry *StateChangeEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	// Decode OperationType
	operationType, err := ReadUvarint(rr)
	if err != nil || operationType > 4 {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding operation type")
	}
	stateChangeEntry.OperationType = StateSyncerOperationType(operationType)

	// Decode IsReverted
	isReverted, err := ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding is reverted")
	}
	stateChangeEntry.IsReverted = isReverted

	// Decode EncoderType
	encoderType, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding encoder type")
	}
	stateChangeEntry.EncoderType = EncoderType(encoderType)

	stateChangeEntry.KeyBytes, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding key bytes")
	}

	// Decode the encoder bytes.
	encoder := stateChangeEntry.EncoderType.New()
	if exist, err := DecodeFromBytes(encoder, rr); exist && err == nil {
		stateChangeEntry.Encoder = encoder
	} else if err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding encoder")
	}

	// Store the encoder bytes.
	stateChangeEntry.EncoderBytes = EncodeToBytes(blockHeight, encoder)

	// Decode the ancestral record bytes.
	ancestralRecord := stateChangeEntry.EncoderType.New()
	if exist, err := DecodeFromBytes(ancestralRecord, rr); exist && err == nil {
		stateChangeEntry.AncestralRecord = ancestralRecord
		stateChangeEntry.AncestralRecordBytes = EncodeToBytes(blockHeight, ancestralRecord)
	} else if err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding ancestral record")
	} else {
		// Encode a blank ancestral record, so that we can still decode the state change entry.
		stateChangeEntry.AncestralRecordBytes = EncodeToBytes(blockHeight, nil)
	}

	// Decode the flush UUID.
	flushIdBytes := make([]byte, 16)
	_, err = rr.Read(flushIdBytes)
	if err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding flush UUID")
	}
	stateChangeEntry.FlushId, err = uuid.FromBytes(flushIdBytes)
	if err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding flush UUID")
	}

	// Decode the block height.
	entryBlockHeight, err := ReadUvarint(rr)
	if err != nil {
		entryBlockHeight = blockHeight
		fmt.Printf("StateChangeEntry.RawDecodeWithoutMetadata: error decoding block height: %v", err)
	}
	stateChangeEntry.BlockHeight = entryBlockHeight

	// Don't decode the block if the encoder type is not a utxo operation.
	if stateChangeEntry.EncoderType != EncoderTypeUtxoOperation && stateChangeEntry.EncoderType != EncoderTypeUtxoOperationBundle {
		return nil
	}

	block := &MsgDeSoBlock{}
	if exist, err := DecodeFromBytes(block, rr); exist && err == nil {
		stateChangeEntry.Block = block
	} else if err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding block")
	}
	return nil
}

func (stateChangeEntry *StateChangeEntry) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (stateChangeEntry *StateChangeEntry) GetEncoderType() EncoderType {
	return EncoderTypeStateChangeEntry
}

// UnflushedStateSyncerBytes is used to keep track of the bytes that should be written to the state change file upon a db flush.
type UnflushedStateSyncerBytes struct {
	// These raw bytes represent each state change entry that should be written to the state change file in a flush.
	// This is represented by a uvarint that represents the length of the StateChangeEntry encoder bytes,
	// followed by the encoder bytes.
	StateChangeBytes []byte
	// This is a list of the indexes of the state change bytes that should be written to the state change index file.
	StateChangeOperationIndexes []uint64
}

// StateChangeSyncer is used to keep track of the state changes that should be written to the state change file.
type StateChangeSyncer struct {
	// The file that the state changes are written to.
	StateChangeFile        *os.File
	StateChangeMempoolFile *os.File
	// The file that allows quick lookup of a StateChangeEntry given its index in the file.
	// This is represented by a list of uint32s, where each uint32 is the offset of the state change entry in the state change file.
	StateChangeIndexFile        *os.File
	StateChangeFileSize         uint64
	StateChangeMempoolIndexFile *os.File
	StateChangeMempoolFileSize  uint64

	// This map is used to keep track of the bytes should be written to the state change file upon a db flush.
	// The ID of the flush is to track which entries should be written to the state change file upon flush completion.
	// This is needed because many flushes can occur asynchronously during hypersync, and we need to make sure that
	// we write the correct entries to the state change file.
	// During blocksync, all flushes are synchronous, so we don't need to worry about this. As such, those flushes
	// are given the uuid.Nil ID.
	UnflushedCommittedBytes map[uuid.UUID]UnflushedStateSyncerBytes
	UnflushedMempoolBytes   map[uuid.UUID]UnflushedStateSyncerBytes

	// This map is used to keep track of all the key and value pairs that state syncer is tracking (and therefore
	// don't need to be re-emitted to the state change file).
	// The key is the stringifyed key of the entry, plus the operation type.
	// The value is the badger entry that was flushed to the db.
	MempoolSyncedKeyValueMap map[string]*StateChangeEntry

	MempoolNewlyFlushedTxns map[string]*StateChangeEntry
	// This map tracks the keys that were flushed to the mempool in a single flush.
	// Every time a flush occurs, this map is cleared, as opposed to the MempoolSyncedKeyValueMap, which is only cleared
	// This is used to determine if there are any tracked mempool transactions that have been ejected from the current
	// mempool state.
	// When this occurs, the mempool is reset, and all tracked mempool transactions are re-emitted to the state change file.
	// This allows the consumer to revert all mempool entries and get a fresh mempool state, which is needed to
	// clear out any mempool entries that were ejected from the mempool.
	MempoolFlushKeySet map[string]bool

	// This cache stores the transactions and their associated utxo ops that are currently in the mempool.
	// This allows us to reduce the number of connect transaction calls when syncing the mempool
	MempoolCachedTxns map[string][]*StateChangeEntry

	MempoolCachedUtxoView *UtxoView
	// Tracks the flush IDs of the last block sync flush and the last mempool flush.
	// These are not used during hypersync, as many flushes are being processed asynchronously.
	BlockSyncFlushId uuid.UUID
	MempoolFlushId   uuid.UUID

	// Mutex to prevent concurrent writes to the state change file.
	StateSyncerMutex *sync.Mutex

	BlockHeight uint64

	SyncType NodeSyncType

	// During blocksync, we flush all entries by index to the state change file once the sync is complete.
	// This is done to optimize the time required by the consumer to process the state change file.
	// There are 2 optimizations here:
	// 1. The consumer can batch-insert entries by entry type. When entry types are mixed, the consumer has to
	// insert each individual entry into the db, which is much slower.
	// 2. Only one state change entry is required for each entry in the database. Rather than following each iteration
	// of each entry, the consumer only has to sync the most recent version of each entry.
	// BlocksyncCompleteEntriesFlushed is used to track whether this one time flush has been completed.
	BlocksyncCompleteEntriesFlushed bool

	MempoolTxnSyncLimit uint64

	// Directory where per-block / hypersync diff files are written.
	StateChangeDir string

	// Mutex guarding BackupDatabase streaming and diff file IO.
	DiffGenerationMutex *sync.Mutex

	// State tracking for incremental mempool diff generation
	mempoolSyncState *MempoolSyncState
}

// AncestralOperation represents the type of operation that needs to be reverted
type AncestralOperation uint8

const (
	AncestralOperationInsert AncestralOperation = 0
	AncestralOperationUpdate AncestralOperation = 1
	AncestralOperationDelete AncestralOperation = 2
)

// AncestralRecord stores the information needed to revert a mempool change
type AncestralRecord struct {
	Key           []byte
	PreviousValue []byte
	Operation     AncestralOperation
}

// MempoolSyncState tracks the state between mempool syncs for incremental diff generation
type MempoolSyncState struct {
	// Track what was written in the last mempool sync for this block height
	lastSyncState      map[string][]byte // key -> value from last sync
	currentBlockHeight uint64
	lastSyncTimestamp  int64
}

// BackupDatabase performs a Badger backup of the supplied database starting from the provided
// "since" timestamp.  This function supports filtering by multiple prefixes, creating separate
// backup streams for each prefix and combining the results. This is a wrapper around badger.DB.Backup
// that returns the bytes produced by the backup as well as the value that should be passed as the next
// "since" value on subsequent incremental backups. This helper makes it easy for downstream callers
// (including tests and the future state‐consumer plumbing) to perform full and incremental backups
// without duplicating boiler-plate buffer management or worrying about the backup cursor bookkeeping.
//
// Example usage:
//
//	var since uint64 = 0
//	// Backup everything:
//	preCommitTxn := db.NewTransaction(false)
//	defer preCommitTxn.Discard()
//	backupBytes, since, err := stateChangeSyncer.BackupDatabase(db, preCommitTxn, since)
//	// Persist backupBytes or forward them to a consumer...
//
// The function is **stateless** with respect to StateChangeSyncer – callers are expected to persist
// the returned `since` value if they wish to subsequently make incremental backups.  Keeping the
// helper on StateChangeSyncer simply provides a convenient, namespaced location that fits this
// package's responsibilities.
func (s *StateChangeSyncer) BackupDatabase(
	db *badger.DB,
	preCommitTxn *badger.Txn, // snapshot taken right before the block's writes
	since uint64,
) (backupBytes []byte, nextSince uint64, err error) {

	prefixes := StatePrefixes.CoreStatePrefixesList

	var combined bytes.Buffer
	maxNextSince := since

	buildStream := func(logPref string, pref []byte) (*badger.Stream, *bytes.Buffer) {
		var buf bytes.Buffer
		st := db.NewStream()
		st.LogPrefix = logPref
		st.SinceTs = since
		st.Prefix = pref

		// Filter out no-ops in-flight
		st.ChooseKey = func(it *badger.Item) bool {
			return isMeaningfulChange(it, preCommitTxn)
		}
		st.KeyToList = func(key []byte, itr *badger.Iterator) (*pb.KVList, error) {
			// itr is already positioned at the newest version for this key.
			item := itr.Item()

			// Build a single-entry KVList.
			kv := &pb.KV{
				Key:      append([]byte(nil), item.Key()...),
				Version:  item.Version(),
				UserMeta: []byte{item.UserMeta()},
			}
			if !item.IsDeletedOrExpired() {
				val, err := item.ValueCopy(nil)
				if err != nil {
					return nil, err
				}
				kv.Value = val
			} // else leave Value nil → represents a delete/expiry

			return &pb.KVList{Kv: []*pb.KV{kv}}, nil
		}
		return st, &buf
	}

	if len(prefixes) == 0 {
		st, buf := buildStream("DB.Backup", nil)
		nextSince, err = st.Backup(buf, since)
		if err != nil {
			return nil, 0, err
		}
		return buf.Bytes(), nextSince, nil
	}

	for i, p := range prefixes {
		st, buf := buildStream(fmt.Sprintf("DB.Backup.Prefix%d", i), p)

		curNext, err := st.Backup(buf, since)
		if err != nil {
			return nil, 0, err
		}
		if curNext > maxNextSince {
			maxNextSince = curNext
		}
		combined.Write(buf.Bytes())
	}

	return combined.Bytes(), maxNextSince, nil
}

func isMeaningfulChange(it *badger.Item, preTxn *badger.Txn) bool {
	// Always propagate deletions / expiries
	if it.IsDeletedOrExpired() {
		return true
	}

	// Get the value we're about to back up.
	newVal, err := it.ValueCopy(nil)
	if err != nil {
		// Defensive: if we can't read it, better to include it.
		return true
	}

	// Compare with the value that existed *before* the block.
	oldIt, err := preTxn.Get(it.Key())
	if err == badger.ErrKeyNotFound {
		// Key didn't exist → definitely a real change.
		return true
	}
	if err != nil {
		return true // on unexpected error, fail open
	}

	oldVal, err := oldIt.ValueCopy(nil)
	if err != nil {
		return true
	}

	return !bytes.Equal(oldVal, newVal) // true ⇢ keep, false ⇢ skip (no-op)
}

// readBadgerBackup reads a Badger backup stream and calls the provided handler for each KVList chunk.
func readBadgerBackup(r io.Reader, handle func(*pb.KVList) error) error {
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

// ExtractStateChangesFromBackup extracts StateChangeEntry structs from backup bytes.
// It processes the backup data to find the latest revision of each entry and converts
// them into StateChangeEntry structs with the specified flushId and blockHeight.
func (s *StateChangeSyncer) ExtractStateChangesFromBackup(
	backupBytes []byte,
	flushID uuid.UUID,
	blockHeight uint64,
) ([]*StateChangeEntry, error) {

	var entries []*StateChangeEntry
	seen := make(map[string]struct{}) // cheap safety net; normally stays empty

	err := readBadgerBackup(bytes.NewReader(backupBytes), func(kvl *pb.KVList) error {
		for _, kv := range kvl.Kv {
			keyStr := string(kv.Key)
			if _, dup := seen[keyStr]; dup {
				// Shouldn't happen with the new stream, but bail defensively.
				continue
			}
			seen[keyStr] = struct{}{}

			// Ignore non-core keys early.
			if !isCoreStateKey(kv.Key) {
				continue
			}

			entry := &StateChangeEntry{
				KeyBytes:    kv.Key,
				FlushId:     flushID,
				BlockHeight: blockHeight,
			}

			// Decide op-type and hold raw value if needed.
			encoderStoredInValue, _ := StateKeyToDeSoEncoder(kv.Key)
			if len(kv.Value) == 0 && encoderStoredInValue {
				entry.OperationType = DbOperationTypeDelete
			} else {
				entry.OperationType = DbOperationTypeUpsert
				entry.EncoderBytes = kv.Value
			}

			// Derive encoder type + decoded encoder.
			if isEnc, enc := StateKeyToDeSoEncoder(kv.Key); isEnc && enc != nil {
				switch enc.GetEncoderType() {
				case EncoderTypeBlock:
					entry.EncoderBytes = AddEncoderMetadataToMsgDeSoBlockBytes(kv.Value, blockHeight)
				case EncoderTypeBlockNode:
					entry.EncoderBytes = AddEncoderMetadataToBlockNodeBytes(kv.Value, blockHeight)
				}

				entry.EncoderType = enc.GetEncoderType()

				if len(entry.EncoderBytes) > 0 {
					dst := entry.EncoderType.New()
					if ok, err := DecodeFromBytes(dst, bytes.NewReader(entry.EncoderBytes)); ok && err == nil {
						entry.Encoder = dst
					} else if err != nil {
						return fmt.Errorf("decode error for key %x: %w", kv.Key, err)
					}
				}
			} else {
				// Value encoded in key.
				keyEnc, err := DecodeStateKey(kv.Key, kv.Value)
				if err != nil {
					return fmt.Errorf("state-key decode error for %x: %w", kv.Key, err)
				}
				entry.EncoderType = keyEnc.GetEncoderType()
				entry.Encoder = keyEnc
			}

			entries = append(entries, entry)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error reading backup: %w", err)
	}

	return entries, nil
}

// Open a file, create if it doesn't exist.
func openOrCreateLogFile(filePath string) (*os.File, error) {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("Error creating directory: %v", err)
	}

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// NewStateChangeSyncer initializes necessary log files and returns a StateChangeSyncer.
func NewStateChangeSyncer(stateChangeDir string, nodeSyncType NodeSyncType, mempoolTxnSyncLimit uint64,
) *StateChangeSyncer {
	stateChangeFilePath := filepath.Join(stateChangeDir, StateChangeFileName)
	stateChangeIndexFilePath := filepath.Join(stateChangeDir, StateChangeIndexFileName)
	stateChangeMempoolFilePath := filepath.Join(stateChangeDir, StateChangeMempoolFileName)
	stateChangeMempoolIndexFilePath := filepath.Join(stateChangeDir, StateChangeMempoolIndexFileName)
	stateChangeFile, err := openOrCreateLogFile(stateChangeFilePath)
	if err != nil {
		glog.Fatalf("Error opening stateChangeFile: %v", err)
	}
	stateChangeIndexFile, err := openOrCreateLogFile(stateChangeIndexFilePath)
	if err != nil {
		glog.Fatalf("Error opening stateChangeIndexFile: %v", err)
	}
	stateChangeMempoolFile, err := openOrCreateLogFile(stateChangeMempoolFilePath)
	if err != nil {
		glog.Fatalf("Error opening stateChangeMempoolFile: %v", err)
	}
	stateChangeFileInfo, err := stateChangeFile.Stat()
	if err != nil {
		glog.Fatalf("Error getting stateChangeFileInfo: %v", err)
	}
	stateChangeMempoolIndexFile, err := openOrCreateLogFile(stateChangeMempoolIndexFilePath)
	if err != nil {
		glog.Fatalf("Error opening stateChangeMempoolIndexFile: %v", err)
	}

	stateChangeMempoolFileInfo, err := stateChangeMempoolFile.Stat()
	if err != nil {
		glog.Fatalf("Error getting stateChangeMempoolFileInfo: %v", err)
	}

	// Check if the state change file is empty. If not, BlocksyncCompleteEntriesFlushed should be true.
	blocksyncCompleteEntriesFlushed := false
	if stateChangeFileInfo.Size() > 0 {
		blocksyncCompleteEntriesFlushed = true
	}

	return &StateChangeSyncer{
		StateChangeFile:                 stateChangeFile,
		StateChangeIndexFile:            stateChangeIndexFile,
		StateChangeFileSize:             uint64(stateChangeFileInfo.Size()),
		StateChangeMempoolFile:          stateChangeMempoolFile,
		StateChangeMempoolIndexFile:     stateChangeMempoolIndexFile,
		StateChangeMempoolFileSize:      uint64(stateChangeMempoolFileInfo.Size()),
		UnflushedCommittedBytes:         make(map[uuid.UUID]UnflushedStateSyncerBytes),
		UnflushedMempoolBytes:           make(map[uuid.UUID]UnflushedStateSyncerBytes),
		MempoolSyncedKeyValueMap:        make(map[string]*StateChangeEntry),
		MempoolNewlyFlushedTxns:         make(map[string]*StateChangeEntry),
		MempoolFlushKeySet:              make(map[string]bool),
		MempoolCachedTxns:               make(map[string][]*StateChangeEntry),
		StateSyncerMutex:                &sync.Mutex{},
		SyncType:                        nodeSyncType,
		BlocksyncCompleteEntriesFlushed: blocksyncCompleteEntriesFlushed,
		MempoolTxnSyncLimit:             mempoolTxnSyncLimit,
		StateChangeDir:                  stateChangeDir,
		DiffGenerationMutex:             &sync.Mutex{},
	}
}

// GenerateCommittedBlockDiff streams all Badger KVs that have changed since the
// last successful commit (tracked via PrefixStateSyncerSince) and persists
// them to a per-block diff file.  The file is named
//
//	state_changes_<blockHeight>.bin
//
// and is written atomically via a temporary file + rename pattern.
//
// Callers **must** supply the block height being committed so the consumer can
// later ingest files in order.  The function is concurrency-safe via the
// DiffGenerationMutex field.
func (stateChangeSyncer *StateChangeSyncer) GenerateCommittedBlockDiff(db *badger.DB, preCommitTxn *badger.Txn, blockHeight uint64) error {

	stateChangeSyncer.DiffGenerationMutex.Lock()
	defer stateChangeSyncer.DiffGenerationMutex.Unlock()

	// Fetch last cursor.
	since, err := stateChangeSyncer.getLastSince(db)
	if err != nil {
		return fmt.Errorf("GenerateCommittedBlockDiff: getLastSince: %v", err)
	}

	// Stream diff via BackupDatabase.
	diffBytes, nextSince, err := stateChangeSyncer.BackupDatabase(db, preCommitTxn, since)
	if err != nil {
		return fmt.Errorf("GenerateCommittedBlockDiff: BackupDatabase: %v", err)
	}

	// Nothing changed (possible for empty blocks).
	if len(diffBytes) == 0 {
		// Still update cursor so we don't re-emit same 0-byte diff.
		if err := stateChangeSyncer.setLastSince(db, nextSince); err != nil {
			return fmt.Errorf("GenerateCommittedBlockDiff: update cursor: %v", err)
		}
		return nil
	}

	// Ensure destination dir exists.
	if err := os.MkdirAll(stateChangeSyncer.StateChangeDir, 0o755); err != nil {
		return fmt.Errorf("GenerateCommittedBlockDiff: mkdir: %v", err)
	}

	finalPath := filepath.Join(stateChangeSyncer.StateChangeDir, fmt.Sprintf("state_changes_%d.bin", blockHeight))
	tmpPath := finalPath + ".tmp"

	// Write to temp file.
	if err := os.WriteFile(tmpPath, diffBytes, 0o644); err != nil {
		return fmt.Errorf("GenerateCommittedBlockDiff: write tmp: %v", err)
	}

	// Atomic rename.
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("GenerateCommittedBlockDiff: rename: %v", err)
	}

	// Persist new cursor.
	if err := stateChangeSyncer.setLastSince(db, nextSince); err != nil {
		return fmt.Errorf("GenerateCommittedBlockDiff: setLastSince: %v", err)
	}

	return nil
}

// Reset resets the state change syncer by truncating the state change file and index file.
func (stateChangeSyncer *StateChangeSyncer) Reset() {
	err := stateChangeSyncer.StateChangeFile.Truncate(0)
	if err != nil {
		glog.Fatalf("Error truncating stateChangeFile: %v", err)
	}

	err = stateChangeSyncer.StateChangeIndexFile.Truncate(0)
	if err != nil {
		glog.Fatalf("Error truncating stateChangeIndexFile: %v", err)
	}

	stateChangeSyncer.StateChangeFileSize = 0
}

// handleDbTransactionConnected is called when a badger db operation takes place.
// This function checks to see if the operation effects a "core_state" index, and if so it encodes a StateChangeEntry
// to be written to the state change file upon DB flush.
// It also writes the offset of the entry in the file to a separate index file, such that a consumer can look up a
// particular entry index in the state change file.
func (stateChangeSyncer *StateChangeSyncer) _handleStateSyncerOperation(event *StateSyncerOperationEvent) {
	// If we're in blocksync mode, we only want to flush entries once the sync is complete.
	if !stateChangeSyncer.BlocksyncCompleteEntriesFlushed && stateChangeSyncer.SyncType == NodeSyncTypeBlockSync {
		return
	}

	stateChangeEntry := event.StateChangeEntry

	// Check to see if the index in question has a "core_state" annotation in its definition.
	if !isCoreStateKey(stateChangeEntry.KeyBytes) {
		return
	}

	// Make sure 2 operations aren't logged simultaneously.
	stateChangeSyncer.StateSyncerMutex.Lock()
	defer stateChangeSyncer.StateSyncerMutex.Unlock()

	flushId := event.FlushId

	// Crate a block sync flush ID if one doesn't already exist.
	if event.FlushId == uuid.Nil && stateChangeSyncer.BlockSyncFlushId == uuid.Nil {
		stateChangeSyncer.BlockSyncFlushId = uuid.New()
	}

	if event.IsMempoolTxn {
		// Set the flushId to the mempool flush ID.
		//flushId = StateChangeSyncer.BlockSyncFlushI

		// If the event flush ID is nil, then we need to use the global mempool flush ID.
		if flushId == uuid.Nil {
			flushId = stateChangeSyncer.MempoolFlushId
		}
	} else {
		// If the flush ID is nil, then we need to use the global block sync flush ID.
		if flushId == uuid.Nil {
			flushId = stateChangeSyncer.BlockSyncFlushId
		}
	}

	// Get the relevant deso encoder for this keyBytes.
	var encoderType EncoderType

	// Certain badger indexes don't store values, so we need to extract the value from the key.
	// If isEncoder is set to true, then we can get the encoder type from the value itself.
	// Examples of this are PostEntry, ProfileEntry, etc.
	if isEncoder, encoder := StateKeyToDeSoEncoder(stateChangeEntry.KeyBytes); isEncoder && encoder != nil {
		// Blocks are serialized in Badger as MsgDesoBlock,
		//so we need to convert these bytes to the appropriate DeSo-Encoder format by appending metadata.
		if encoder.GetEncoderType() == EncoderTypeBlock {
			stateChangeEntry.EncoderBytes = AddEncoderMetadataToMsgDeSoBlockBytes(stateChangeEntry.EncoderBytes, stateChangeEntry.BlockHeight)
		}
		if encoder.GetEncoderType() == EncoderTypeBlockNode {
			stateChangeEntry.EncoderBytes = AddEncoderMetadataToBlockNodeBytes(stateChangeEntry.EncoderBytes, stateChangeEntry.BlockHeight)
		}

		encoderType = encoder.GetEncoderType()

	} else {
		// If the value associated with the key is not an encoder, then we decode the encoder entirely from the key bytes.
		// Examples of this are FollowEntry, LikeEntry, DeSoBalanceEntry, etc.
		keyEncoder, err := DecodeStateKey(stateChangeEntry.KeyBytes, stateChangeEntry.EncoderBytes)
		if err != nil {
			glog.Fatalf("Server._handleStateSyncerOperation: Error decoding state key: %v", err)
		}
		encoderType = keyEncoder.GetEncoderType()
		stateChangeEntry.Encoder = keyEncoder
		stateChangeEntry.EncoderBytes = nil

		if stateChangeEntry.AncestralRecordBytes != nil && len(stateChangeEntry.AncestralRecordBytes) > 0 {
			// Decode the ancestral record.
			ancestralRecord, err := DecodeStateKey(stateChangeEntry.KeyBytes, stateChangeEntry.AncestralRecordBytes)
			if err != nil {
				glog.Fatalf("Server._handleStateSyncerOperation: Error decoding ancestral record: %v", err)
			}
			stateChangeEntry.AncestralRecord = ancestralRecord
			// Remove the ancestral record bytes - when this entry is decoded, we want the decoder to use the AncestralRecord field.
			stateChangeEntry.AncestralRecordBytes = nil
		}
	}

	// Set the encoder type.
	stateChangeEntry.EncoderType = encoderType

	// Set the flush ID.
	stateChangeEntry.FlushId = flushId

	if event.IsMempoolTxn {
		// The current state of the tracked mempool is stored in the MempoolSyncedKeyValueMap. If this entry is already in there
		// then we don't need to re-write it to the state change file.
		// Create key for op + key map
		txKey := createMempoolTxKey(stateChangeEntry.KeyBytes)

		// Track the key in the MempoolFlushKeySet.
		stateChangeSyncer.MempoolFlushKeySet[txKey] = true

		// Check to see if the key is in the map, and if the value is the same as the value in the event.
		if cachedSCE, ok := stateChangeSyncer.MempoolSyncedKeyValueMap[txKey]; ok && bytes.Equal(cachedSCE.EncoderBytes, event.StateChangeEntry.EncoderBytes) && cachedSCE.OperationType == event.StateChangeEntry.OperationType {
			// If the key is in the map, and the entry bytes are the same as those that are already tracked by state syncer,
			// then we don't need to write the state change entry to the state change file - it's already being tracked.
			return
		} else if ok {
			// If the key is in the map, and the entry bytes are different, then we need to track the new entry.
			// Skip if the entry is already being tracked as a new flush.
			if _, newFlushExists := stateChangeSyncer.MempoolNewlyFlushedTxns[txKey]; !newFlushExists {
				// If the key is in the map, and the entry bytes are different, then we need to track the new entry.
				stateChangeSyncer.MempoolNewlyFlushedTxns[txKey] = cachedSCE
			}
		} else {
			// If the key is not in the map, then we need to track the new entry.
			stateChangeSyncer.MempoolNewlyFlushedTxns[txKey] = nil
		}

		// Track the key and value if this is a new entry to the mempool, or if the encoder bytes or operation type
		// changed since it was last synced.
		stateChangeSyncer.MempoolSyncedKeyValueMap[txKey] = event.StateChangeEntry
	}

	// Encode the state change entry. We encode as a byte array, so the consumer can buffer just the bytes needed
	// to decode this entry when reading from file.
	entryBytes := EncodeToBytes(stateChangeSyncer.BlockHeight, stateChangeEntry, false)
	writeBytes := EncodeByteArray(entryBytes)

	// Add the StateChangeEntry bytes to the queue of bytes to be written to the state change file upon Badger db flush.
	stateChangeSyncer.addTransactionToQueue(stateChangeEntry.FlushId, writeBytes, event.IsMempoolTxn)
}

// _handleStateSyncerFlush is called when a Badger db flush takes place. It calls a helper function that takes the bytes that
// have been cached on the StateChangeSyncer and writes them to the state change file.
func (stateChangeSyncer *StateChangeSyncer) _handleStateSyncerFlush(event *StateSyncerFlushedEvent) {
	stateChangeSyncer.StateSyncerMutex.Lock()
	defer stateChangeSyncer.StateSyncerMutex.Unlock()

	glog.V(2).Infof("Handling state syncer flush: %+v", event)

	if event.IsMempoolFlush {
		// If this is a mempool flush, make sure a block hasn't mined since the mempool entries were added to queue.
		// If not, reset the mempool maps and file, and start from scratch. The consumer will revert the mempool transactions
		// it currently has and sync from scratch.
		if (stateChangeSyncer.BlockSyncFlushId != event.BlockSyncFlushId && event.BlockSyncFlushId != uuid.Nil) ||
			stateChangeSyncer.BlockSyncFlushId != event.FlushId {
			glog.V(2).Infof(
				"The flush ID has changed, bailing now. Event: %v, Event block sync: %v, Global block sync: %v\n",
				event.FlushId, event.BlockSyncFlushId, stateChangeSyncer.BlockSyncFlushId)
			stateChangeSyncer.ResetMempool()
			return
		}

		// Check to see if any of the keys in the mempool flush key set are not in the mempool key value map.
		// This would mean that an entry was ejected from the mempool.
		// When this happens, we need to reset the mempool and start from scratch, so that the consumer can revert the
		// mempool transactions it currently has and sync the mempool from scratch.
		//
		// Example:
		//
		// Flush:
		// Key: a
		// Key: b
		// Key: d

		// Synced:
		// Key: a
		// Key: b
		// Key: c <- Revert this one
		// Key: d

		if event.Succeeded {
			for key, cachedSCE := range stateChangeSyncer.MempoolSyncedKeyValueMap {
				// If any of the keys that the mempool is currently tracking weren't included in the flush, that entry
				// needs to be reverted from the mempool.
				if _, ok := stateChangeSyncer.MempoolFlushKeySet[key]; !ok {
					// Confirm that the block sync ID hasn't shifted. If it has, bail now.
					if cachedSCE.FlushId != stateChangeSyncer.BlockSyncFlushId {
						glog.V(2).Infof("The flush ID has changed, inside key/value check, bailing now.\n")
						stateChangeSyncer.ResetMempool()
						return
					}

					cachedSCE.IsReverted = true

					// Create a revert state change entry and add it to the queue. This will signal the state change
					// consumer to revert the synced entry.
					entryBytes := EncodeToBytes(stateChangeSyncer.BlockHeight, cachedSCE, false)
					writeBytes := EncodeByteArray(entryBytes)

					glog.V(2).Infof("Reverting entry %d\n", cachedSCE.EncoderType)

					// Add the StateChangeEntry bytes to the queue of bytes to be written to the state change file upon Badger db flush.
					stateChangeSyncer.addTransactionToQueue(cachedSCE.FlushId, writeBytes, true)

					// Remove this entry from the synced map
					delete(stateChangeSyncer.MempoolSyncedKeyValueMap, key)
				}
			}
		}

		// Reset the mempool flush set.
		stateChangeSyncer.MempoolFlushKeySet = make(map[string]bool)
	} else {
		glog.V(2).Infof("Here is the flush ID: %v\n", event.FlushId)
		glog.V(2).Infof("Here is the block sync flush ID: %v\n", event.BlockSyncFlushId)
	}

	err := stateChangeSyncer.FlushTransactionsToFile(event)
	if err != nil {
		glog.Errorf("StateChangeSyncer._handleStateSyncerFlush: Error flushing transactions to file: %v", err)
	}

	if !event.IsMempoolFlush {
		// After flushing blocksync transactions to file, reset the block sync flush ID, and reset the mempool.
		stateChangeSyncer.BlockSyncFlushId = uuid.New()
		glog.V(2).Infof("Setting a new blocksync flush ID: %v\n", stateChangeSyncer.BlockSyncFlushId)
		stateChangeSyncer.ResetMempool()
	}
}

func (stateChangeSyncer *StateChangeSyncer) ResetMempool() {
	glog.V(2).Info("Resetting mempool.\n")
	stateChangeSyncer.MempoolSyncedKeyValueMap = make(map[string]*StateChangeEntry)
	stateChangeSyncer.MempoolNewlyFlushedTxns = make(map[string]*StateChangeEntry)
	stateChangeSyncer.MempoolFlushKeySet = make(map[string]bool)
	delete(stateChangeSyncer.UnflushedMempoolBytes, stateChangeSyncer.MempoolFlushId)
	stateChangeSyncer.MempoolFlushId = uuid.Nil
	stateChangeSyncer.MempoolCachedTxns = make(map[string][]*StateChangeEntry)
	// Truncate the mempool files.
	stateChangeSyncer.StateChangeMempoolFile.Truncate(0)
	stateChangeSyncer.StateChangeMempoolIndexFile.Truncate(0)
	stateChangeSyncer.StateChangeMempoolFileSize = 0
}

// Add a transaction to the queue of transactions to be flushed to disk upon badger db flush.
func (stateChangeSyncer *StateChangeSyncer) addTransactionToQueue(flushId uuid.UUID, writeBytes []byte, isMempool bool) {

	var unflushedBytes UnflushedStateSyncerBytes
	var exists bool

	if isMempool {
		unflushedBytes, exists = stateChangeSyncer.UnflushedMempoolBytes[flushId]
	} else {
		unflushedBytes, exists = stateChangeSyncer.UnflushedCommittedBytes[flushId]
	}

	if !exists {
		unflushedBytes = UnflushedStateSyncerBytes{
			StateChangeBytes:            []byte{},
			StateChangeOperationIndexes: []uint64{},
		}
	}
	// Get the byte index of where this transaction occurs in the unflushed bytes, and add it to the list of
	// indexes that should be written to the index file.
	dbOperationIndex := uint64(len(unflushedBytes.StateChangeBytes))
	unflushedBytes.StateChangeOperationIndexes = append(unflushedBytes.StateChangeOperationIndexes, dbOperationIndex)

	unflushedBytes.StateChangeBytes = append(unflushedBytes.StateChangeBytes, writeBytes...)

	if isMempool {
		stateChangeSyncer.UnflushedMempoolBytes[flushId] = unflushedBytes
	} else {
		stateChangeSyncer.UnflushedCommittedBytes[flushId] = unflushedBytes
	}
}

// FlushTransactionsToFile writes the bytes that have been cached on the StateChangeSyncer to the state change file.
func (stateChangeSyncer *StateChangeSyncer) FlushTransactionsToFile(event *StateSyncerFlushedEvent) error {
	flushId := event.FlushId

	glog.V(2).Infof("Flushing to file: %+v", event)
	// Get the relevant global flush ID from the state change syncer if the flush ID is nil.
	if event.FlushId == uuid.Nil {
		if event.IsMempoolFlush {
			flushId = stateChangeSyncer.MempoolFlushId
		} else {
			flushId = stateChangeSyncer.BlockSyncFlushId
		}
	}

	var flushFile *os.File
	var flushFileSize uint64
	var indexFile *os.File
	if event.IsMempoolFlush {
		flushFile = stateChangeSyncer.StateChangeMempoolFile
		flushFileSize = stateChangeSyncer.StateChangeMempoolFileSize
		indexFile = stateChangeSyncer.StateChangeMempoolIndexFile
	} else {
		flushFile = stateChangeSyncer.StateChangeFile
		flushFileSize = stateChangeSyncer.StateChangeFileSize
		indexFile = stateChangeSyncer.StateChangeIndexFile
	}

	// If the flush failed, delete the unflushed bytes and associated metadata.
	// Also delete any unconnected mempool txns from our cache.
	if !event.Succeeded {
		glog.V(2).Infof("Deleting unflushed bytes for id: %s", flushId)
		if event.IsMempoolFlush {
			delete(stateChangeSyncer.UnflushedMempoolBytes, flushId)
			// Loop through the unflushed mempool transactions and delete them from the cache.
			for key, sce := range stateChangeSyncer.MempoolNewlyFlushedTxns {
				if sce != nil {
					stateChangeSyncer.MempoolSyncedKeyValueMap[key] = sce
				} else {
					delete(stateChangeSyncer.MempoolSyncedKeyValueMap, key)
					delete(stateChangeSyncer.MempoolFlushKeySet, key)
				}
			}
		} else {
			delete(stateChangeSyncer.UnflushedCommittedBytes, flushId)
		}
		return nil
	}

	var unflushedBytes UnflushedStateSyncerBytes
	var exists bool
	if event.IsMempoolFlush {
		unflushedBytes, exists = stateChangeSyncer.UnflushedMempoolBytes[flushId]
	} else {
		unflushedBytes, exists = stateChangeSyncer.UnflushedCommittedBytes[flushId]
	}

	if !exists {
		glog.V(2).Infof("Unflushed bytes for flush ID doesn't exist: %s", flushId.String())
		return nil
	}

	stateChangeType := "committed"
	if event.IsMempoolFlush {
		stateChangeType = "mempool"
	}

	if len(unflushedBytes.StateChangeBytes) == 0 || len(unflushedBytes.StateChangeOperationIndexes) == 0 {
		return fmt.Errorf("Error flushing to %s state change file: FlushId %v has nil bytes\n", stateChangeType, flushId)
	}

	// Write the encoded StateChangeEntry bytes to the state changer file.
	_, err := flushFile.Write(unflushedBytes.StateChangeBytes)

	if err != nil {
		return fmt.Errorf("Error writing to %s state change file: %v", stateChangeType, err)
	}

	// Buffer to hold bytes for index file
	stateChangeIndexBuf := make([]byte, 0)

	// Loop through the index bytes of the state change file and write them to the index file.
	// The StateChangeOperationIndexes array contains the byte index of where each transaction occurs within the
	// unflushed state change bytes (e.g. the first value in the slice will always be 0).
	// We need to add the size of the state change file to each of these values to get the byte index
	// in the state change file.
	for _, indexBytes := range unflushedBytes.StateChangeOperationIndexes {
		// Get the byte index of where this transaction occurs in the state change file.
		dbOperationIndex, err := SafeUint64().Add(indexBytes, flushFileSize)
		if err != nil {
			return fmt.Errorf("Error writing to %s state change index file: %v", stateChangeType, err)
		}
		// Convert the byte index value to a uint64 byte slice.
		dbOperationIndexBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(dbOperationIndexBytes, dbOperationIndex)

		stateChangeIndexBuf = append(stateChangeIndexBuf, dbOperationIndexBytes...)
	}

	// Write the encoded uint32 indexes to the index file.
	_, err = indexFile.Write(stateChangeIndexBuf)
	if err != nil {
		return fmt.Errorf("Error writing to state change index file: %v", err)
	}
	if event.IsMempoolFlush {
		stateChangeSyncer.StateChangeMempoolFileSize += uint64(len(unflushedBytes.StateChangeBytes))
	} else {
		stateChangeSyncer.StateChangeFileSize += uint64(len(unflushedBytes.StateChangeBytes))
	}

	// Update unflushed bytes map to remove the flushed bytes.
	if event.IsMempoolFlush {
		delete(stateChangeSyncer.UnflushedMempoolBytes, flushId)
		stateChangeSyncer.MempoolNewlyFlushedTxns = make(map[string]*StateChangeEntry)
	} else {
		delete(stateChangeSyncer.UnflushedCommittedBytes, flushId)
	}

	return nil
}

func createMempoolTxKey(keyBytes []byte) string {
	return fmt.Sprintf("%v", string(keyBytes))
}

// SyncMempoolToStateSyncer flushes all mempool transactions to the db, capturing those state changes
// in the mempool state change file. It also loops through all unconnected transactions and their associated
// utxo ops and adds them to the mempool state change file.
func (stateChangeSyncer *StateChangeSyncer) SyncMempoolToStateSyncer(server *Server) (bool, error) {
	startTime := time.Now()
	originalCommittedFlushId := stateChangeSyncer.BlockSyncFlushId

	if originalCommittedFlushId == uuid.Nil {
		return false, nil
	}

	if !server.GetMempool().IsRunning() {
		return true, nil
	}

	blockHeight := uint64(server.blockchain.blockIndex.GetTip().Height)

	stateChangeSyncer.MempoolFlushId = originalCommittedFlushId

	stateChangeSyncer.BlockHeight = blockHeight

	mempoolUtxoView, err := server.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return false, errors.Wrapf(err, "StateChangeSyncer.SyncMempoolToStateSyncer: ")
	}

	// Create a copy of the event manager, assign it to this utxo view.
	mempoolEventManager := *mempoolUtxoView.EventManager

	// Reset event manager handlers
	mempoolEventManager.stateSyncerOperationHandlers = nil
	mempoolEventManager.stateSyncerFlushedHandlers = nil
	mempoolEventManager.OnStateSyncerOperation(stateChangeSyncer._handleStateSyncerOperation)
	mempoolEventManager.OnStateSyncerFlushed(stateChangeSyncer._handleStateSyncerFlush)

	mempoolEventManager.isMempoolManager = true
	mempoolUtxoView.EventManager = &mempoolEventManager

	// Kill the snapshot so that it doesn't affect the original snapshot.
	mempoolUtxoView.Snapshot = nil

	server.blockchain.ChainLock.RLock()
	mempoolUtxoView.TipHash = server.blockchain.blockIndex.GetTip().Hash
	server.blockchain.ChainLock.RUnlock()

	// A new transaction is created so that we can simulate writes to the db without actually writing to the db.
	// Using the transaction here rather than a stubbed badger db allows the process to query the db for any entries
	// inserted during the flush process. This is necessary to get ancestral records for an entry that is being modified
	// more than once in the mempool transactions.
	txn := server.blockchain.db.NewTransaction(true)
	defer txn.Discard()

	// Create a read-only view of the badger DB prior to the mempool flush. This view will be used to get the ancestral
	// records of entries that are being modified in the mempool.
	mempoolEventManager.lastCommittedViewTxn = server.blockchain.db.NewTransaction(false)
	defer mempoolEventManager.lastCommittedViewTxn.Discard()

	glog.V(2).Infof("Time since mempool sync start: %v", time.Since(startTime))
	startTime = time.Now()
	glog.V(2).Infof("Time since db flush: %v", time.Since(startTime))
	mempoolTxUtxoView := NewUtxoView(server.blockchain.db, server.blockchain.params, server.blockchain.postgres, nil, &mempoolEventManager)
	glog.V(2).Infof("Time since utxo view: %v", time.Since(startTime))

	// Get the uncommitted blocks from the chain.
	uncommittedBlocks, err := server.blockchain.GetUncommittedBlocks(mempoolUtxoView.TipHash)
	if err != nil {
		mempoolUtxoView.EventManager.stateSyncerFlushed(&StateSyncerFlushedEvent{
			FlushId:        originalCommittedFlushId,
			Succeeded:      false,
			IsMempoolFlush: true,
		})
		glog.V(2).Infof("After the mempool flush: %+v", &StateSyncerFlushedEvent{
			FlushId:        originalCommittedFlushId,
			Succeeded:      false,
			IsMempoolFlush: true,
		})
		return false, errors.Wrapf(err, "StateChangeSyncer.SyncMempoolToStateSyncer: ")
	}

	// TODO: Have Z look at if we need to do some caching in the uncommitted blocks logic.
	// First connect the uncommitted blocks to the mempool view.
	for _, uncommittedBlock := range uncommittedBlocks {
		utxoViewAndOpsAtBlockHash, err := server.blockchain.GetUtxoViewAndUtxoOpsAtBlockHash(*uncommittedBlock.Hash, uint64(uncommittedBlock.Height))
		if err != nil {
			mempoolUtxoView.EventManager.stateSyncerFlushed(&StateSyncerFlushedEvent{
				FlushId:        originalCommittedFlushId,
				Succeeded:      false,
				IsMempoolFlush: true,
			})
			return false, errors.Wrapf(err, "StateChangeSyncer.SyncMempoolToStateSyncer ConnectBlock uncommitted block: ")
		}
		// Emit the Block event.
		blockBytes, err := utxoViewAndOpsAtBlockHash.Block.ToBytes(false)
		if err != nil {
			mempoolUtxoView.EventManager.stateSyncerFlushed(&StateSyncerFlushedEvent{
				FlushId:        originalCommittedFlushId,
				Succeeded:      false,
				IsMempoolFlush: true,
			})
			return false, errors.Wrapf(err, "StateChangeSyncer.SyncMempoolToStateSyncer: error converting block to bytes: ")
		}
		mempoolUtxoView.EventManager.stateSyncerOperation(&StateSyncerOperationEvent{
			StateChangeEntry: &StateChangeEntry{
				OperationType: DbOperationTypeUpsert,
				KeyBytes:      BlockHashToBlockKey(uncommittedBlock.Hash),
				EncoderBytes:  blockBytes,
			},
			FlushId:      originalCommittedFlushId,
			IsMempoolTxn: true,
		})
		// Emit the UtxoOps event.
		mempoolUtxoView.EventManager.stateSyncerOperation(&StateSyncerOperationEvent{
			StateChangeEntry: &StateChangeEntry{
				OperationType: DbOperationTypeUpsert,
				KeyBytes:      _DbKeyForUtxoOps(uncommittedBlock.Hash),
				EncoderBytes: EncodeToBytes(blockHeight, &UtxoOperationBundle{
					UtxoOpBundle: utxoViewAndOpsAtBlockHash.UtxoOps,
				}, false),
			},
			FlushId:      originalCommittedFlushId,
			IsMempoolTxn: true,
		})
		// getUtxoViewAtBlockHash returns a copy of the view, so we
		// set the mempoolTxUtxoView to the view at the block hash
		// and update its event manager to match the mempoolEventManager.
		mempoolTxUtxoView = utxoViewAndOpsAtBlockHash.UtxoView
		mempoolTxUtxoView.EventManager = &mempoolEventManager
	}

	// Loop through all the transactions in the mempool and connect them and their utxo ops to the mempool view.
	mempoolTxns := server.GetMempool().GetOrderedTransactions()
	startTime = time.Now()
	glog.V(2).Infof("Mempool synced len after flush: %d", len(stateChangeSyncer.MempoolSyncedKeyValueMap))

	currentTimestamp := time.Now().UnixNano()
	for _, mempoolTx := range mempoolTxns {
		var txnStateChangeEntry *StateChangeEntry
		var utxoOpStateChangeEntry *StateChangeEntry

		if !mempoolTx.validated {
			continue
		}
		utxoOpsForTxn, _, _, _, err := mempoolTxUtxoView.ConnectTransaction(
			mempoolTx.Tx, mempoolTx.Hash, uint32(blockHeight+1), currentTimestamp, false, false /*ignoreUtxos*/)
		if err != nil {
			mempoolUtxoView.EventManager.stateSyncerFlushed(&StateSyncerFlushedEvent{
				FlushId:        originalCommittedFlushId,
				Succeeded:      false,
				IsMempoolFlush: true,
			})
			stateChangeSyncer.MempoolCachedTxns = make(map[string][]*StateChangeEntry)
			stateChangeSyncer.MempoolCachedUtxoView = nil
			return false, errors.Wrapf(err, "StateChangeSyncer.SyncMempoolToStateSyncer ConnectTransaction: ")
		}
		txnStateChangeEntry = &StateChangeEntry{
			OperationType: DbOperationTypeUpsert,
			KeyBytes:      TxnHashToTxnKey(mempoolTx.Hash),
			EncoderBytes:  EncodeToBytes(blockHeight, mempoolTx.Tx, false),
			IsReverted:    false,
		}

		// Capture the utxo ops for the transaction in a UTXOOp bundle.
		utxoOpBundle := &UtxoOperationBundle{
			UtxoOpBundle: [][]*UtxoOperation{},
		}

		utxoOpBundle.UtxoOpBundle = append(utxoOpBundle.UtxoOpBundle, utxoOpsForTxn)

		utxoOpStateChangeEntry = &StateChangeEntry{
			OperationType: DbOperationTypeUpsert,
			KeyBytes:      _DbKeyForTxnUtxoOps(mempoolTx.Hash),
			EncoderBytes:  EncodeToBytes(blockHeight, utxoOpBundle, false),
			IsReverted:    false,
		}

		// Emit transaction state change.
		mempoolUtxoView.EventManager.stateSyncerOperation(&StateSyncerOperationEvent{
			StateChangeEntry: txnStateChangeEntry,
			FlushId:          originalCommittedFlushId,
			IsMempoolTxn:     true,
		})

		// Emit UTXOOp bundle event
		mempoolUtxoView.EventManager.stateSyncerOperation(&StateSyncerOperationEvent{
			StateChangeEntry: utxoOpStateChangeEntry,
			FlushId:          originalCommittedFlushId,
			IsMempoolTxn:     true,
		})
	}

	// Create a copy of the event manager, assign it to this utxo view.
	mempoolTxEventManager := *mempoolTxUtxoView.EventManager

	// Reset event manager handlers
	mempoolTxEventManager.stateSyncerOperationHandlers = nil
	mempoolTxEventManager.stateSyncerFlushedHandlers = nil
	mempoolTxEventManager.OnStateSyncerOperation(stateChangeSyncer._handleStateSyncerOperation)
	mempoolTxEventManager.OnStateSyncerFlushed(stateChangeSyncer._handleStateSyncerFlush)

	mempoolTxEventManager.isMempoolManager = true
	mempoolTxUtxoView.EventManager = &mempoolTxEventManager

	// Kill the snapshot so that it doesn't affect the original snapshot.
	mempoolTxUtxoView.Snapshot = nil

	server.blockchain.ChainLock.RLock()
	mempoolTxUtxoView.TipHash = server.blockchain.BlockTip().Hash
	server.blockchain.ChainLock.RUnlock()

	// A new transaction is created so that we can simulate writes to the db without actually writing to the db.
	// Using the transaction here rather than a stubbed badger db allows the process to query the db for any entries
	// inserted during the flush process. This is necessary to get ancestral records for an entry that is being modified
	// more than once in the mempool transactions.
	txn2 := server.blockchain.db.NewTransaction(true)
	defer txn2.Discard()

	// Create a read-only view of the badger DB prior to the mempool flush. This view will be used to get the ancestral
	// records of entries that are being modified in the mempool.
	mempoolTxEventManager.lastCommittedViewTxn = server.blockchain.db.NewTransaction(false)
	defer mempoolTxEventManager.lastCommittedViewTxn.Discard()

	err = mempoolTxUtxoView.FlushToDbWithTxn(txn, uint64(server.blockchain.BlockTip().Height))
	if err != nil {
		mempoolUtxoView.EventManager.stateSyncerFlushed(&StateSyncerFlushedEvent{
			FlushId:        originalCommittedFlushId,
			Succeeded:      false,
			IsMempoolFlush: true,
		})
		return false, errors.Wrapf(err, "StateChangeSyncer.SyncMempoolToStateSyncer: FlushToDbWithTxn: ")
	}
	// Update the cached utxo view to represent the new cached state.
	stateChangeSyncer.MempoolCachedUtxoView = mempoolTxUtxoView.CopyUtxoView()
	glog.V(2).Infof("Time to connect all %d txns: %v", len(mempoolTxns), time.Since(startTime))
	startTime = time.Now()
	glog.V(2).Infof("Mempool flushed len: %d", len(stateChangeSyncer.MempoolFlushKeySet))
	glog.V(2).Infof("Mempool synced len after all: %d", len(stateChangeSyncer.MempoolSyncedKeyValueMap))

	// Before flushing the mempool to the state change file, check if a block has mined. If so, abort the flush.
	if originalCommittedFlushId != stateChangeSyncer.BlockSyncFlushId {
		mempoolUtxoView.EventManager.stateSyncerFlushed(&StateSyncerFlushedEvent{
			FlushId:        originalCommittedFlushId,
			Succeeded:      false,
			IsMempoolFlush: true,
		})
		return false, errors.Wrapf(err, "StateChangeSyncer.SyncMempoolToStateSyncer: ")
	}

	mempoolUtxoView.EventManager.stateSyncerFlushed(&StateSyncerFlushedEvent{
		FlushId:          originalCommittedFlushId,
		Succeeded:        true,
		IsMempoolFlush:   true,
		BlockSyncFlushId: originalCommittedFlushId,
	})
	glog.V(2).Infof("Time to flush: %v", time.Since(startTime))

	return false, nil
}

func (stateChangeSyncer *StateChangeSyncer) StartMempoolSyncRoutine(server *Server) {
	go func() {
		// Wait for mempool to be initialized.
		for server.GetMempool() == nil || server.blockchain.chainState() != SyncStateFullyCurrent {
			time.Sleep(15000 * time.Millisecond)
			glog.V(2).Infof("Mempool: %v", server.mempool)
			glog.V(2).Infof("Chain state: %v", server.blockchain.chainState())
		}
		if !stateChangeSyncer.BlocksyncCompleteEntriesFlushed && stateChangeSyncer.SyncType == NodeSyncTypeBlockSync {
			err := stateChangeSyncer.FlushAllEntriesToFile(server)
			if err != nil {
				glog.Errorf("StateChangeSyncer.StartMempoolSyncRoutine: Error flushing all entries to file: %v", err)
			}
		}
		mempoolClosed := !server.GetMempool().IsRunning()
		for !mempoolClosed {
			// Sleep for a short while to avoid a tight loop.
			time.Sleep(100 * time.Millisecond)
			var err error

			// If the mempool is not empty, sync the mempool to the state syncer.
			mempoolClosed, err = stateChangeSyncer.SyncMempoolToStateSyncer(server)
			if err != nil {
				glog.Errorf("StateChangeSyncer.StartMempoolSyncRoutine: Error syncing mempool to state syncer: %v", err)
			}
		}
	}()
}

// extractStateFromTransaction extracts all core state key-value pairs from a badger transaction.
// This is used to capture the current mempool state that has been flushed to a transaction
// but not yet committed to the main database.
func (stateChangeSyncer *StateChangeSyncer) extractStateFromTransaction(txn *badger.Txn) map[string][]byte {
	state := make(map[string][]byte)

	opts := badger.DefaultIteratorOptions
	opts.PrefetchValues = true

	it := txn.NewIterator(opts)
	defer it.Close()

	for it.Rewind(); it.Valid(); it.Next() {
		item := it.Item()
		key := item.Key()

		// Only process core state keys
		if !isCoreStateKey(key) {
			continue
		}

		value, err := item.ValueCopy(nil)
		if err != nil {
			continue
		}

		state[string(key)] = value
	}

	return state
}

func (stateChangeSyncer *StateChangeSyncer) FlushAllEntriesToFile(server *Server) error {
	// Check if the state change file already exists and is not empty. If so, return.
	stateChangeFileInfo, err := stateChangeSyncer.StateChangeFile.Stat()
	if err == nil {
		// If the file is non-empty, no need to flush entries to file.
		if stateChangeFileInfo.Size() > 0 {
			return nil
		}
	}

	// Disable deadlock detection, as the process of flushing entries to file can take a long time and
	// if it takes longer than the deadlock detection timeout interval, it will cause an error to be thrown.
	deadlock.Opts.Disable = true
	defer func() {
		deadlock.Opts.Disable = false
	}()
	// Lock the blockchain so that nothing shifts under our feet while dumping the current state to the state change file.
	server.blockchain.ChainLock.Lock()
	defer server.blockchain.ChainLock.Unlock()

	// Allow the state change syncer to flush entries to file.
	stateChangeSyncer.BlocksyncCompleteEntriesFlushed = true

	// Loop through all prefixes that hold state change entries.
	for _, prefix := range StatePrefixes.CoreStatePrefixesList {
		// Start with the first key in the prefix.
		lastReceivedKey := prefix
		chunkFull := true
		var err error
		var dbBatchEntries []*DBEntry

		// Loop through all the batches of entries for the prefix until we get a non-full chunk.
		for chunkFull {
			glog.V(2).Infof("Processing chunk for prefix: %+v\n", prefix)
			// Create a flush ID for this chunk.
			dbFlushId := uuid.New()
			// Fetch the batch from main DB records with a batch size of about snap.BatchSize.
			dbBatchEntries, chunkFull, err = DBIteratePrefixKeys(server.blockchain.db, prefix, lastReceivedKey, SnapshotBatchSize/10)
			if err != nil {
				return errors.Wrapf(err, "StateChangeSyncer.FlushAllEntriesToFile: ")
			}
			if len(dbBatchEntries) != 0 {
				lastReceivedKey = dbBatchEntries[len(dbBatchEntries)-1].Key
			}
			for _, dbEntry := range dbBatchEntries {
				stateChangeEntry := &StateChangeEntry{
					OperationType: DbOperationTypeInsert,
					KeyBytes:      dbEntry.Key,
					EncoderBytes:  dbEntry.Value,
					IsReverted:    false,
				}

				// If this prefix is the prefix for UTXO Ops, fetch the transaction for each UTXO Op and attach it to the UTXO Op.
				if bytes.Equal(prefix, Prefixes.PrefixBlockHashToUtxoOperations) {
					// Get block hash from the key.
					blockHashBytes := dbEntry.Key[1:]
					blockHash := NewBlockHash(blockHashBytes)

					block, err := GetBlock(blockHash, server.blockchain.db, server.blockchain.snapshot)
					if err != nil {
						return errors.Wrapf(err, "StateChangeSyncer.FlushAllEntriesToFile: Error fetching block: ")
					}
					// Attach the block to the UTXO Op via the ancestral record.
					stateChangeEntry.Block = block
				}

				server.eventManager.stateSyncerOperation(&StateSyncerOperationEvent{
					StateChangeEntry: stateChangeEntry,
					FlushId:          dbFlushId,
					IsMempoolTxn:     false,
				})
			}
			server.eventManager.stateSyncerFlushed(&StateSyncerFlushedEvent{
				FlushId:        dbFlushId,
				Succeeded:      true,
				IsMempoolFlush: false,
			})
		}
	}
	return nil
}

// computeMempoolDiff compares current mempool state with previous sync state to find changes.
// Returns changed entries (new/modified) and deleted entries separately.
func (stateChangeSyncer *StateChangeSyncer) computeMempoolDiff(
	previousState map[string][]byte,
	currentState map[string][]byte,
	baseTxn *badger.Txn,
) (changed map[string][]byte, deleted map[string][]byte, ancestralRecords []AncestralRecord) {

	changed = make(map[string][]byte)
	deleted = make(map[string][]byte)
	ancestralRecords = make([]AncestralRecord, 0)

	// Find new and modified entries
	for key, currentValue := range currentState {
		previousValue, existed := previousState[key]

		if !existed {
			// New entry
			changed[key] = currentValue

			// Get original value from committed state for ancestral record
			var originalValue []byte
			if item, err := baseTxn.Get([]byte(key)); err == nil {
				originalValue, _ = item.ValueCopy(nil)
			}

			ancestralRecords = append(ancestralRecords, AncestralRecord{
				Key:           []byte(key),
				PreviousValue: originalValue,
				Operation:     AncestralOperationInsert,
			})

		} else if !bytes.Equal(previousValue, currentValue) {
			// Modified entry
			changed[key] = currentValue

			ancestralRecords = append(ancestralRecords, AncestralRecord{
				Key:           []byte(key),
				PreviousValue: previousValue,
				Operation:     AncestralOperationUpdate,
			})
		}
	}

	// Find deleted entries (in previous state but not current)
	for key, previousValue := range previousState {
		if _, exists := currentState[key]; !exists {
			// Entry was deleted/ejected
			deleted[key] = previousValue

			ancestralRecords = append(ancestralRecords, AncestralRecord{
				Key:           []byte(key),
				PreviousValue: previousValue,
				Operation:     AncestralOperationDelete,
			})
		}
	}

	return changed, deleted, ancestralRecords
}

// generateSequentialMempoolDiff generates incremental mempool diff files.
// This is the main function that orchestrates the mempool diff generation process.
func (stateChangeSyncer *StateChangeSyncer) generateSequentialMempoolDiff(
	mempoolTxn *badger.Txn,
	baseTxn *badger.Txn,
	blockchain *Blockchain,
	mempool Mempool,
	blockHeight uint64,
) error {
	stateChangeSyncer.DiffGenerationMutex.Lock()
	defer stateChangeSyncer.DiffGenerationMutex.Unlock()

	// Initialize or reset state tracking for new block height
	if stateChangeSyncer.mempoolSyncState == nil ||
		stateChangeSyncer.mempoolSyncState.currentBlockHeight != blockHeight {
		stateChangeSyncer.mempoolSyncState = &MempoolSyncState{
			lastSyncState:      make(map[string][]byte),
			currentBlockHeight: blockHeight,
			lastSyncTimestamp:  0,
		}
	}

	// 1. Extract flushed state changes from transaction
	flushedState := stateChangeSyncer.extractStateFromTransaction(mempoolTxn)

	// 2. Extract transaction entries (uncommitted blocks + mempool transactions)
	transactionState, err := stateChangeSyncer.extractTransactionEntries(blockchain, mempool, blockHeight)
	if err != nil {
		return fmt.Errorf("failed to extract transaction entries: %w", err)
	}

	// 3. Merge both states (transaction state takes precedence)
	currentMempoolState := mergeMempoolStates(flushedState, transactionState)

	// 4. Compare with last sync to find changes
	changed, deleted, ancestralRecords := stateChangeSyncer.computeMempoolDiff(
		stateChangeSyncer.mempoolSyncState.lastSyncState,
		currentMempoolState,
		baseTxn,
	)

	// Skip if no changes
	if len(changed) == 0 && len(deleted) == 0 {
		return nil
	}

	// 5. Generate file names
	timestamp := time.Now().UnixNano()
	diffFile := fmt.Sprintf("mempool_%d_%d.bin", blockHeight, timestamp)
	ancestralFile := fmt.Sprintf("mempool_ancestral_%d_%d.bin", blockHeight, timestamp)

	// 6. Write diff file (only changes since last sync)
	diffBytes, err := stateChangeSyncer.encodeMempoolChanges(changed, deleted)
	if err != nil {
		return fmt.Errorf("failed to encode mempool changes: %w", err)
	}

	err = stateChangeSyncer.writeAtomicFile(diffFile, diffBytes)
	if err != nil {
		return fmt.Errorf("failed to write diff file: %w", err)
	}

	// 7. Write ancestral records for this diff
	if len(ancestralRecords) > 0 {
		ancestralBytes, err := stateChangeSyncer.encodeAncestralRecords(ancestralRecords)
		if err != nil {
			return fmt.Errorf("failed to encode ancestral records: %w", err)
		}

		err = stateChangeSyncer.writeAtomicFile(ancestralFile, ancestralBytes)
		if err != nil {
			return fmt.Errorf("failed to write ancestral file: %w", err)
		}
	}

	// 8. Update state tracking for next diff
	stateChangeSyncer.mempoolSyncState.lastSyncState = currentMempoolState
	stateChangeSyncer.mempoolSyncState.lastSyncTimestamp = timestamp

	// 9. Clean up old files (different block heights)
	return stateChangeSyncer.cleanupOldMempoolFiles(int32(blockHeight))
}

// encodeMempoolChanges encodes mempool changes into badger backup format
func (stateChangeSyncer *StateChangeSyncer) encodeMempoolChanges(
	changed map[string][]byte,
	deleted map[string][]byte,
) ([]byte, error) {
	var buffer bytes.Buffer

	// Encode changed entries
	for key, value := range changed {
		kv := &pb.KV{
			Key:   []byte(key),
			Value: value,
		}

		kvList := &pb.KVList{Kv: []*pb.KV{kv}}
		kvBytes, err := proto.Marshal(kvList)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal KV for key %s: %w", key, err)
		}

		// Write in badger backup format
		if err := binary.Write(&buffer, binary.LittleEndian, uint32(len(kvBytes))); err != nil {
			return nil, err
		}
		if err := binary.Write(&buffer, binary.LittleEndian, uint32(0)); err != nil { // CRC placeholder
			return nil, err
		}
		buffer.Write(kvBytes)
	}

	// Encode deleted entries (with nil values)
	for key := range deleted {
		kv := &pb.KV{
			Key:   []byte(key),
			Value: nil, // nil value indicates deletion
		}

		kvList := &pb.KVList{Kv: []*pb.KV{kv}}
		kvBytes, err := proto.Marshal(kvList)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal deleted KV for key %s: %w", key, err)
		}

		// Write in badger backup format
		if err := binary.Write(&buffer, binary.LittleEndian, uint32(len(kvBytes))); err != nil {
			return nil, err
		}
		if err := binary.Write(&buffer, binary.LittleEndian, uint32(0)); err != nil { // CRC placeholder
			return nil, err
		}
		buffer.Write(kvBytes)
	}

	return buffer.Bytes(), nil
}

// encodeAncestralRecords encodes ancestral records for revert operations
func (stateChangeSyncer *StateChangeSyncer) encodeAncestralRecords(records []AncestralRecord) ([]byte, error) {
	var buffer bytes.Buffer

	for _, record := range records {
		// Simple encoding: operation(1) + key_len(4) + key + value_len(4) + value
		if err := binary.Write(&buffer, binary.LittleEndian, uint8(record.Operation)); err != nil {
			return nil, err
		}
		if err := binary.Write(&buffer, binary.LittleEndian, uint32(len(record.Key))); err != nil {
			return nil, err
		}
		buffer.Write(record.Key)
		if err := binary.Write(&buffer, binary.LittleEndian, uint32(len(record.PreviousValue))); err != nil {
			return nil, err
		}
		buffer.Write(record.PreviousValue)
	}

	return buffer.Bytes(), nil
}

// writeAtomicFile writes data to a file atomically using temp file + rename
func (stateChangeSyncer *StateChangeSyncer) writeAtomicFile(filename string, data []byte) error {
	fullPath := filepath.Join(stateChangeSyncer.StateChangeDir, filename)
	tmpPath := fullPath + ".tmp"

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write to temp file
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, fullPath); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// cleanupOldMempoolFiles removes mempool files for block heights older than the current one
func (stateChangeSyncer *StateChangeSyncer) cleanupOldMempoolFiles(currentBlockHeight int32) error {
	pattern := filepath.Join(stateChangeSyncer.StateChangeDir, "mempool_*.bin")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to glob mempool files: %w", err)
	}

	for _, file := range files {
		filename := filepath.Base(file)

		// Parse block height from filename (mempool_<height>_<timestamp>.bin)
		parts := strings.Split(filename, "_")
		if len(parts) < 3 {
			continue
		}

		heightStr := parts[1]
		fileHeight, err := strconv.ParseInt(heightStr, 10, 32)
		if err != nil {
			continue
		}

		// Remove files from previous block heights
		if int32(fileHeight) < currentBlockHeight {
			if err := os.Remove(file); err != nil {
				glog.Warningf("Failed to remove old mempool file %s: %v", file, err)
			}
		}
	}

	// Also clean up ancestral files
	ancestralPattern := filepath.Join(stateChangeSyncer.StateChangeDir, "mempool_ancestral_*.bin")
	ancestralFiles, err := filepath.Glob(ancestralPattern)
	if err != nil {
		return fmt.Errorf("failed to glob ancestral files: %w", err)
	}

	for _, file := range ancestralFiles {
		filename := filepath.Base(file)

		// Parse block height from filename (mempool_ancestral_<height>_<timestamp>.bin)
		parts := strings.Split(filename, "_")
		if len(parts) < 4 {
			continue
		}

		heightStr := parts[2]
		fileHeight, err := strconv.ParseInt(heightStr, 10, 32)
		if err != nil {
			continue
		}

		// Remove files from previous block heights
		if int32(fileHeight) < currentBlockHeight {
			if err := os.Remove(file); err != nil {
				glog.Warningf("Failed to remove old ancestral file %s: %v", file, err)
			}
		}
	}

	return nil
}

// extractTransactionEntries extracts transaction and block entries that need to be manually created
// for the mempool. This includes uncommitted blocks and mempool transactions with their associated
// UtxoOp bundles. Returns entries in the same map[string][]byte format as extractStateFromTransaction.
func (stateChangeSyncer *StateChangeSyncer) extractTransactionEntries(
	blockchain *Blockchain,
	mempool Mempool,
	blockHeight uint64,
) (map[string][]byte, error) {
	transactionState := make(map[string][]byte)

	// Get mempool and validate it's running
	if !mempool.IsRunning() {
		return transactionState, nil // Return empty state if mempool not running
	}

	// Create a fresh UtxoView (not the augmented one that already includes mempool transactions)
	// This mirrors the pattern in SyncMempoolToStateSyncer
	mempoolTxUtxoView := NewUtxoView(blockchain.db, blockchain.params, blockchain.postgres, nil, nil)

	blockchain.ChainLock.RLock()
	tipHash := blockchain.blockIndex.GetTip().Hash
	mempoolTxUtxoView.TipHash = tipHash
	blockchain.ChainLock.RUnlock()

	// 1. Handle Uncommitted Blocks
	uncommittedBlocks, err := blockchain.GetUncommittedBlocks(tipHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get uncommitted blocks: %w", err)
	}
	// Process each uncommitted block (following SyncMempoolToStateSyncer pattern)
	for _, uncommittedBlock := range uncommittedBlocks {
		utxoViewAndOpsAtBlockHash, err := blockchain.GetUtxoViewAndUtxoOpsAtBlockHash(
			*uncommittedBlock.Hash,
			uint64(uncommittedBlock.Height),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to get utxo view for block %s: %w",
				uncommittedBlock.Hash.String(), err)
		}

		// Create Block entry
		blockBytes, err := utxoViewAndOpsAtBlockHash.Block.ToBytes(false)
		if err != nil {
			return nil, fmt.Errorf("failed to convert block to bytes: %w", err)
		}

		blockKey := string(BlockHashToBlockKey(uncommittedBlock.Hash))
		transactionState[blockKey] = blockBytes

		// Create Block UtxoOps entry
		utxoOpBundle := &UtxoOperationBundle{
			UtxoOpBundle: utxoViewAndOpsAtBlockHash.UtxoOps,
		}
		utxoOpsBytes := EncodeToBytes(blockHeight, utxoOpBundle, false)
		utxoOpsKey := string(_DbKeyForUtxoOps(uncommittedBlock.Hash))
		transactionState[utxoOpsKey] = utxoOpsBytes

		// Update the view for the next iteration (key pattern from SyncMempoolToStateSyncer)
		mempoolTxUtxoView = utxoViewAndOpsAtBlockHash.UtxoView
	}

	// 2. Handle Mempool Transactions
	mempoolTxns := mempool.GetOrderedTransactions()
	currentTimestamp := time.Now().UnixNano()

	for _, mempoolTx := range mempoolTxns {
		if !mempoolTx.validated {
			continue
		}

		// Connect the transaction to get UtxoOps
		utxoOpsForTxn, _, _, _, err := mempoolTxUtxoView.ConnectTransaction(
			mempoolTx.Tx,
			mempoolTx.Hash,
			uint32(blockHeight+1),
			currentTimestamp,
			false, // verifySignatures
			false, // ignoreUtxos
		)
		if err != nil {
			return nil, fmt.Errorf("failed to connect transaction %s: %w",
				mempoolTx.Hash.String(), err)
		}

		// Create Transaction entry
		txnBytes := EncodeToBytes(blockHeight, mempoolTx.Tx, false)
		txnKey := string(TxnHashToTxnKey(mempoolTx.Hash))
		transactionState[txnKey] = txnBytes

		// Create Transaction UtxoOps entry
		utxoOpBundle := &UtxoOperationBundle{
			UtxoOpBundle: [][]*UtxoOperation{utxoOpsForTxn},
		}
		utxoOpsBytes := EncodeToBytes(blockHeight, utxoOpBundle, false)
		utxoOpsKey := string(_DbKeyForTxnUtxoOps(mempoolTx.Hash))
		transactionState[utxoOpsKey] = utxoOpsBytes
	}

	return transactionState, nil
}

// mergeMempoolStates combines flushed state and transaction state into a single map.
// Transaction state takes precedence over flushed state in case of key conflicts.
func mergeMempoolStates(
	flushedState map[string][]byte,
	transactionState map[string][]byte,
) map[string][]byte {
	// Start with flushed state
	mergedState := make(map[string][]byte, len(flushedState)+len(transactionState))

	// Copy flushed state
	for key, value := range flushedState {
		mergedState[key] = value
	}

	// Overlay transaction state (takes precedence)
	for key, value := range transactionState {
		mergedState[key] = value
	}

	return mergedState
}
