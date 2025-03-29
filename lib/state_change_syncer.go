package lib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/deso-protocol/go-deadlock"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang/glog"
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
	}
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

	blockHeight := uint64(server.blockchain.bestChain[len(server.blockchain.bestChain)-1].Height)

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
	mempoolUtxoView.TipHash = server.blockchain.bestChain[len(server.blockchain.bestChain)-1].Hash
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
	err = mempoolUtxoView.FlushToDbWithTxn(txn, uint64(server.blockchain.bestChain[len(server.blockchain.bestChain)-1].Height))
	if err != nil {
		mempoolUtxoView.EventManager.stateSyncerFlushed(&StateSyncerFlushedEvent{
			FlushId:        originalCommittedFlushId,
			Succeeded:      false,
			IsMempoolFlush: true,
		})
		return false, errors.Wrapf(err, "StateChangeSyncer.SyncMempoolToStateSyncer: FlushToDbWithTxn: ")
	}
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
		utxoViewAndOpsAtBlockHash, err := server.blockchain.GetUtxoViewAndUtxoOpsAtBlockHash(*uncommittedBlock.Hash)
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

	//Check to see if every txn hash in our cached txns is in the first n txns in the mempool.
	//N represents the length of our cached txn map.
	for ii, mempoolTx := range mempoolTxns {
		if _, ok := stateChangeSyncer.MempoolCachedTxns[mempoolTx.Hash.String()]; !ok {
			// If any of the transaction hashes in the first n transactions don't line up with our cache map, the mempool
			// has changed since the last cache, and we need to reset it.
			stateChangeSyncer.MempoolCachedTxns = make(map[string][]*StateChangeEntry)
			stateChangeSyncer.MempoolCachedUtxoView = nil
			glog.V(2).Info("Txn not in cache, resetting\n")
			break
		}

		// Once we're past the number of cached txns, we have confirmed that nothing in our cache is out of date and can break.
		if ii >= len(stateChangeSyncer.MempoolCachedTxns)-1 {
			if stateChangeSyncer.MempoolCachedUtxoView != nil {
				// If we know that all our transactions are good, set the state of the utxo view to the cached one, and exit.
				mempoolUtxoView = stateChangeSyncer.MempoolCachedUtxoView
			}
			glog.V(2).Infof("All txns match, continuing: %v\n", ii)
			break
		}
	}

	currentTimestamp := time.Now().UnixNano()
	for _, mempoolTx := range mempoolTxns {
		var txnStateChangeEntry *StateChangeEntry
		var utxoOpStateChangeEntry *StateChangeEntry
		// Check if the transaction is already in the cache. If so, skip it.
		txHash := mempoolTx.Hash.String()
		if stateChangeEntries, ok := stateChangeSyncer.MempoolCachedTxns[txHash]; ok {
			txnStateChangeEntry = stateChangeEntries[0]
			utxoOpStateChangeEntry = stateChangeEntries[1]
		} else {
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

			// Add both state change entries to the mempool sync map.
			stateChangeSyncer.MempoolCachedTxns[txHash] = []*StateChangeEntry{txnStateChangeEntry, utxoOpStateChangeEntry}
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
