package lib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"os"
	"sync"
	"time"
)

// StateSyncerOperationType is an enum that represents the type of operation that should be performed on the
// state consumer database.
type StateSyncerOperationType uint8

const (
	DbOperationTypeInsert StateSyncerOperationType = 0
	DbOperationTypeDelete StateSyncerOperationType = 1
	DbOperationTypeUpdate StateSyncerOperationType = 2
	DbOperationTypeUpsert StateSyncerOperationType = 3
	// DbOperationTypeSkip is used to indicate that the operation is not relevant to DeSo state and should be skipped.
	DbOperationTypeSkip StateSyncerOperationType = 4
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
	AncestralRecordBytes []byte
	// The type of encoder that should be used for the operation.
	EncoderType EncoderType
	// The flush this entry belongs to.
	FlushId uuid.UUID
	// The height of the block this entry belongs to.
	BlockHeight uint64
}

// RawEncodeWithoutMetadata constructs the bytes to represent a StateChangeEntry.
// The format is:
// [operation type (varint)][encoder type (varint)][key length (varint)][key bytes]
// [encoder length (varint)][encoder bytes][is mempool (1 byte)][utxo ops length (varint)][utxo ops bytes]
func (stateChangeEntry *StateChangeEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	// Get byte length of keyBytes (will be nil for mempool transactions)
	var data []byte

	data = append(data, UintToBuf(uint64(stateChangeEntry.OperationType))...)
	data = append(data, UintToBuf(uint64(stateChangeEntry.EncoderType))...)
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

	return data
}

func (stateChangeEntry *StateChangeEntry) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	// Decode OperationType
	operationType, err := ReadUvarint(rr)
	if err != nil || operationType > 4 {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding operation type")
	}
	stateChangeEntry.OperationType = StateSyncerOperationType(operationType)

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

	// Decode the ancestral record bytes.
	ancestralRecord := stateChangeEntry.EncoderType.New()
	if exist, err := DecodeFromBytes(ancestralRecord, rr); exist && err == nil {
		stateChangeEntry.AncestralRecord = ancestralRecord
	} else if err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding ancestral record")
	}

	// Decode the flush UUID.
	flushIdBytes := make([]byte, 16)
	_, err = rr.Read(flushIdBytes)
	if err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding flush UUID")
	}
	stateChangeEntry.FlushId, err = uuid.FromBytes(flushIdBytes)

	// Decode the block height.
	entryBlockHeight, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding block height")
	}
	stateChangeEntry.BlockHeight = entryBlockHeight

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
	StateChangeBytes     []byte
	StateChangeBytesSize uint64
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

	DeSoParams *DeSoParams
	// This map is used to keep track of the bytes should be written to the state change file upon a db flush.
	// The ID of the flush is to track which entries should be written to the state change file upon flush completion.
	// This is needed because many flushes can occur asynchronously during hypersync, and we need to make sure that
	// we write the correct entries to the state change file.
	// During blocksync, all flushes are synchronous, so we don't need to worry about this. As such, those flushes
	// are given the uuid.Nil ID.
	UnflushedBytes map[uuid.UUID]UnflushedStateSyncerBytes

	// This map is used to keep track of the key and value pairs that state syncer has already tracked (and therefore
	// don't need to be re-emitted to the state change file).
	// The key is the stringifyed key of the entry, plus the operation type.
	// The value is the badger entry that was flushed to the db.
	MempoolKeyValueMap map[string][]byte
	// This map tracks the keys that were flushed to the mempool in a single flush.
	// This is used to determine if there are any mempool transactions currently tracked by state syncer that are
	// no longer in the mempool. If so, state syncer should completely refresh the mempool.
	MempoolFlushKeySet map[string]bool

	MempoolBlock *MsgDeSoBlock

	MempoolUtxoOpBundle *UtxoOperationBundle

	// Tracks the flush IDs of the last block sync flush and the last mempool flush.
	// These are not used during hypersync, as many flushes are being processed asynchronously.
	BlockSyncFlushId uuid.UUID
	MempoolFlushId   uuid.UUID

	// Mutex to prevent concurrent writes to the state change file.
	StateSyncerMutex *sync.Mutex
	EntryCount       uint64

	BlockHeight uint64

	SyncType NodeSyncType

	// During blocksync, we flush all entries by index to the state change file once the sync is complete.
	// This is used to track whether this procedure has been initiated.
	BlocksyncCompleteEntriesFlushed bool
}

// Open a file, create if it doesn't exist.
func openOrCreateLogFile(fileName string) (*os.File, error) {
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// NewStateChangeSyncer initializes necessary log files and returns a StateChangeSyncer.
func NewStateChangeSyncer(desoParams *DeSoParams, stateChangeFilePath string, nodeSyncType NodeSyncType) *StateChangeSyncer {
	stateChangeIndexFilePath := fmt.Sprintf("%s-index", stateChangeFilePath)
	stateChangeMemPoolFilePath := fmt.Sprintf("%s-mempool", stateChangeFilePath)
	stateChangeMempoolIndexFilePath := fmt.Sprintf("%s-mempool-index", stateChangeFilePath)
	stateChangeFile, err := openOrCreateLogFile(stateChangeFilePath)
	if err != nil {
		glog.Fatalf("Error opening stateChangeFile: %v", err)
	}
	stateChangeIndexFile, err := openOrCreateLogFile(stateChangeIndexFilePath)
	if err != nil {
		glog.Fatalf("Error opening stateChangeIndexFile: %v", err)
	}
	stateChangeMempoolFile, err := openOrCreateLogFile(stateChangeMemPoolFilePath)
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

	return &StateChangeSyncer{
		StateChangeFile:             stateChangeFile,
		StateChangeIndexFile:        stateChangeIndexFile,
		StateChangeFileSize:         uint64(stateChangeFileInfo.Size()),
		StateChangeMempoolFile:      stateChangeMempoolFile,
		StateChangeMempoolIndexFile: stateChangeMempoolIndexFile,
		StateChangeMempoolFileSize:  uint64(stateChangeMempoolFileInfo.Size()),
		DeSoParams:                  desoParams,
		UnflushedBytes:              make(map[uuid.UUID]UnflushedStateSyncerBytes),
		MempoolKeyValueMap:          make(map[string][]byte),
		MempoolFlushKeySet:          make(map[string]bool),
		StateSyncerMutex:            &sync.Mutex{},
		SyncType:                    nodeSyncType,
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

	stateChangeSyncer.EntryCount = 0
}

// handleDbTransactionConnected is called when a badger db operation takes place.
// This function checks to see if the operation effects a "core_state" index, and if so it encodes a StateChangeEntry
// to be written to the state change file upon DB flush.
// It also writes the offset of the entry in the file to a separate index file, such that a consumer can look up a
// particular entry index in the state change file.
func (stateChangeSyncer *StateChangeSyncer) _handleDbTransaction(event *DBTransactionEvent) {
	stateChangeSyncer.StateSyncerMutex.Lock()
	defer stateChangeSyncer.StateSyncerMutex.Unlock()

	// If we're in blocksync mode, we only want to flush entries once the sync is complete.
	if !stateChangeSyncer.BlocksyncCompleteEntriesFlushed && stateChangeSyncer.SyncType == NodeSyncTypeBlockSync {
		return
	}

	stateChangeEntry := event.StateChangeEntry

	// Check to see if the index in question has a "core_state" annotation in its definition.
	if !isCoreStateKey(stateChangeEntry.KeyBytes) {
		return
	}

	flushId := event.FlushId

	// TODO: Clean this up.
	if event.IsMempoolTxn {
		// Create a mempool flush ID if one doesn't already exist.
		if event.FlushId == uuid.Nil && stateChangeSyncer.MempoolFlushId == uuid.Nil {
			stateChangeSyncer.MempoolFlushId = uuid.New()
		}
		// Crate a committed flush ID if one doesn't already exist.
		if event.FlushId == uuid.Nil && stateChangeSyncer.BlockSyncFlushId == uuid.Nil {
			stateChangeSyncer.BlockSyncFlushId = uuid.New()
		}

		// If the flush ID is nil, then we need to use the mempool flush ID.
		if event.FlushId == uuid.Nil {
			flushId = stateChangeSyncer.MempoolFlushId
		} else {
			flushId = event.FlushId
		}

		// Create key for op + key map
		txKey := fmt.Sprintf("%v%v", event.StateChangeEntry.OperationType, string(event.StateChangeEntry.KeyBytes))

		// Check to see if the key is in the map, and if the value is the same as the value in the event.
		if valueBytes, ok := stateChangeSyncer.MempoolKeyValueMap[txKey]; ok && bytes.Equal(valueBytes, event.StateChangeEntry.EncoderBytes) {
			// If the key is in the map, and the entry bytes are the same as those that are already tracked by state syncer,
			// then we don't need to write the state change entry to the state change file - it's already being tracked.
			return
		}

		stateChangeSyncer.MempoolKeyValueMap[txKey] = event.StateChangeEntry.EncoderBytes
		stateChangeSyncer.MempoolFlushKeySet[txKey] = true
	} else {
		// Create a flush ID if one doesn't already exist.
		if event.FlushId == uuid.Nil && stateChangeSyncer.BlockSyncFlushId == uuid.Nil {
			stateChangeSyncer.BlockSyncFlushId = uuid.New()
		}

		if event.FlushId == uuid.Nil {
			flushId = stateChangeSyncer.BlockSyncFlushId
		} else {
			flushId = event.FlushId
		}
	}

	// Get the relevant deso encoder for this keyBytes.
	var encoderType EncoderType
	if isEncoder, encoder := StateKeyToDeSoEncoder(stateChangeEntry.KeyBytes); isEncoder && encoder != nil {
		// Convert block encoder bytes to deso encoder bytes (append metadata).
		if encoder.GetEncoderType() == EncoderTypeBlock {
			var blockData []byte
			blockData = append(blockData, BoolToByte(true))
			blockData = append(blockData, UintToBuf(uint64(encoder.GetEncoderType()))...)
			blockData = append(blockData, UintToBuf(uint64(encoder.GetVersionByte(stateChangeEntry.BlockHeight)))...)
			blockData = append(blockData, EncodeByteArray(stateChangeEntry.EncoderBytes)...)
			stateChangeEntry.EncoderBytes = blockData
		}

		encoderType = encoder.GetEncoderType()
	} else {
		// If the keyBytes is not an encoder, then we decode the entry from the key value.
		keyEncoder, err := DecodeStateKey(stateChangeEntry.KeyBytes, stateChangeEntry.EncoderBytes)
		if err != nil {
			glog.Fatalf("Server._handleDbTransaction: Error decoding state key: %v", err)
		}
		encoderType = keyEncoder.GetEncoderType()
		stateChangeEntry.Encoder = keyEncoder
		stateChangeEntry.EncoderBytes = nil
	}

	// Set the encoder type.
	stateChangeEntry.EncoderType = encoderType

	// Set the flush ID.
	stateChangeEntry.FlushId = flushId

	// Encode the state change entry. We encode as a byte array, so the consumer can buffer just the bytes needed
	// to decode this entry when reading from file.
	entryBytes := EncodeToBytes(stateChangeSyncer.BlockHeight, stateChangeEntry, false)
	writeBytes := EncodeByteArray(entryBytes)

	// Add the StateChangeEntry bytes to the queue of bytes to be written to the state change file upon Badger db flush.
	stateChangeSyncer.addTransactionToQueue(stateChangeEntry.FlushId, writeBytes)
}

// _handleDbFlush is called when a Badger db flush takes place. It calls a helper function that takes the bytes that
// have been cached on the StateChangeSyncer and writes them to the state change file.
func (stateChangeSyncer *StateChangeSyncer) _handleDbFlush(event *DBFlushedEvent) {
	stateChangeSyncer.StateSyncerMutex.Lock()
	defer stateChangeSyncer.StateSyncerMutex.Unlock()

	// If this is a mempool flush, make sure they entries to be flushed are compatible with what is currently tracked
	// by state syncer. If not, reset the mempool maps and file, and start from scratch. The consumer will revert everything
	// it currently has and sync from scratch.
	if event.IsMempoolFlush {
		if stateChangeSyncer.BlockSyncFlushId != event.CommittedFlushId {
			stateChangeSyncer.ResetMempool()
			return
		}

		// Check to see if any of the keys in the mempool key set are not in the mempool key value map.
		// If so, reset the mempool key value map, mempool key set, and mempool file, start from scratch.
		for key, _ := range stateChangeSyncer.MempoolKeyValueMap {
			// If any of the keys that the mempool is currently tracking weren't included in the flush, the state syncer
			// mempool is bad and needs to be reset.
			if _, ok := stateChangeSyncer.MempoolFlushKeySet[key]; !ok {
				stateChangeSyncer.ResetMempool()
				return
			}
		}
	}

	err := stateChangeSyncer.FlushTransactionsToFile(event)
	if err != nil {
		glog.Errorf("StateChangeSyncer._handleDbFlush: Error flushing transactions to file: %v", err)
	}

	if !event.IsMempoolFlush {
		// Reset the block sync flush ID.
		stateChangeSyncer.BlockSyncFlushId = uuid.New()
		stateChangeSyncer.ResetMempool()
	}
}

func (stateChangeSyncer *StateChangeSyncer) ResetMempool() {
	stateChangeSyncer.MempoolKeyValueMap = make(map[string][]byte)
	stateChangeSyncer.MempoolFlushKeySet = make(map[string]bool)
	delete(stateChangeSyncer.UnflushedBytes, stateChangeSyncer.MempoolFlushId)
	stateChangeSyncer.MempoolFlushId = uuid.Nil
	// Truncate the mempool files.
	stateChangeSyncer.StateChangeMempoolFile.Truncate(0)
	stateChangeSyncer.StateChangeMempoolIndexFile.Truncate(0)
	stateChangeSyncer.StateChangeMempoolFileSize = 0
}

// Add a transaction to the queue of transactions to be flushed to disk upon badger db flush.
func (stateChangeSyncer *StateChangeSyncer) addTransactionToQueue(flushId uuid.UUID, writeBytes []byte) {
	stateChangeSyncer.EntryCount++

	unflushedBytes, exists := stateChangeSyncer.UnflushedBytes[flushId]
	if !exists {
		unflushedBytes = UnflushedStateSyncerBytes{
			StateChangeBytes:            []byte{},
			StateChangeBytesSize:        0,
			StateChangeOperationIndexes: []uint64{},
		}
	}

	unflushedBytes.StateChangeBytes = append(unflushedBytes.StateChangeBytes, writeBytes...)

	// Get the byte index of where this transaction occurs in the unflushed bytes, and add it to the list of
	// indexes that should be written to the index file.
	dbOperationIndex := unflushedBytes.StateChangeBytesSize
	unflushedBytes.StateChangeOperationIndexes = append(unflushedBytes.StateChangeOperationIndexes, dbOperationIndex)

	// Update the state change file size.
	transactionLen := uint64(len(writeBytes))
	unflushedBytes.StateChangeBytesSize += transactionLen

	stateChangeSyncer.UnflushedBytes[flushId] = unflushedBytes
}

// FlushTransactionsToFile writes the bytes that have been cached on the StateChangeSyncer to the state change file.
func (stateChangeSyncer *StateChangeSyncer) FlushTransactionsToFile(event *DBFlushedEvent) error {
	flushId := event.FlushId
	// Get the flush ID from the state change syncer if the flush ID is nil.
	if event.IsMempoolFlush && event.FlushId == uuid.Nil {
		flushId = stateChangeSyncer.MempoolFlushId
	} else if !event.IsMempoolFlush && event.FlushId == uuid.Nil {
		flushId = stateChangeSyncer.BlockSyncFlushId
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
		delete(stateChangeSyncer.UnflushedBytes, flushId)
	}

	unflushedBytes, exists := stateChangeSyncer.UnflushedBytes[flushId]

	if !exists {
		return nil
	}

	if event.IsMempoolFlush {
		fmt.Printf("\n\n\n*****Flushing mempool state changes to file. FlushId: %v\n", flushId)
		fmt.Printf("Committed ID: %v\n", event.CommittedFlushId)
		fmt.Printf("Block ID: %v\n", stateChangeSyncer.BlockSyncFlushId)
	}

	if unflushedBytes.StateChangeBytes == nil || unflushedBytes.StateChangeOperationIndexes == nil || len(unflushedBytes.StateChangeOperationIndexes) == 0 {
		return fmt.Errorf("Error flushing state change file: FlushId %v has nil bytes\n", flushId)
	}

	// Write the encoded StateChangeEntry bytes to the state changer file.
	_, err := flushFile.Write(unflushedBytes.StateChangeBytes)

	if err != nil {
		return fmt.Errorf("Error writing to state change file: %v", err)
	}

	// Buffer to hold bytes for index file
	stateChangeIndexBuf := make([]byte, 0)

	// Loop through the index bytes of the state change file and write them to the index file.
	// The StateChangeOperationIndexes array contains the byte index of		 where each transaction occurs within the
	// unflushed state change bytes (e.g. the first value in the slice will always be 0).
	// We need to add the size of the state change file to each of these values to get the byte index
	// in the state change file.
	for _, indexBytes := range unflushedBytes.StateChangeOperationIndexes {
		// Get the byte index of where this transaction occurs in the state change file.
		dbOperationIndex := indexBytes + flushFileSize
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
		stateChangeSyncer.StateChangeMempoolFileSize += unflushedBytes.StateChangeBytesSize
	} else {
		stateChangeSyncer.StateChangeFileSize += unflushedBytes.StateChangeBytesSize
	}

	// Update unflushed bytes map to remove the flushed bytes.
	delete(stateChangeSyncer.UnflushedBytes, flushId)
	return nil
}

// SyncMempoolToStateSyncer flushes all mempool transactions to the db, capturing those state changes
// in the mempool state change file. It also loops through all unconnected transactions and their associated
// utxo ops and adds them to the mempool state change file.
func (stateChangeSyncer *StateChangeSyncer) SyncMempoolToStateSyncer(server *Server) (bool, error) {
	originalCommittedFlushId := stateChangeSyncer.BlockSyncFlushId

	if server.mempool.stopped {
		return true, nil
	}

	blockHeight := uint64(server.blockchain.bestChain[len(server.blockchain.bestChain)-1].Height)

	stateChangeSyncer.BlockHeight = blockHeight

	mempoolUtxoView, err := server.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return false, errors.Wrapf(err, "StateChangeSyncer.SyncMempoolToStateSyncer: ")
	}
	// Kill the snapshot so that it doesn't affect the original snapshot.
	mempoolUtxoView.Snapshot = nil
	mempoolUtxoView.IsMempoolView = true

	// A new transaction is created so that we can simulate writes to the db without actually writing to the db.
	// Using the transaction here rather than a stubbed badger db allows the process to query the db for any entries
	// inserted during the flush process. This is necessary to get ancestral records for an entry that is being modified
	// more than once in the mempool transactions.
	txn := server.blockchain.db.NewTransaction(true)
	defer txn.Discard()

	err = mempoolUtxoView.FlushToDbWithTxn(txn, uint64(server.blockchain.bestChain[len(server.blockchain.bestChain)-1].Height))

	if err != nil || originalCommittedFlushId != stateChangeSyncer.BlockSyncFlushId {
		mempoolUtxoView.EventManager.dbFlushed(&DBFlushedEvent{
			FlushId:        uuid.Nil,
			Succeeded:      false,
			IsMempoolFlush: true,
		})
		return false, errors.Wrapf(err, "StateChangeSyncer.SyncMempoolToStateSyncer: ")
	}
	mempoolUtxoView.EventManager.dbFlushed(&DBFlushedEvent{
		FlushId:          uuid.Nil,
		Succeeded:        true,
		IsMempoolFlush:   true,
		CommittedFlushId: originalCommittedFlushId,
	})

	// Loop through all the unconnected transactions in the mempool and connect them and their utxo ops to the mempool view.
	for txHash, unconnectedTxn := range server.mempool.unconnectedTxns {
		utxoOpsForTxn, _, _, _, err := mempoolUtxoView.ConnectTransaction(
			unconnectedTxn.tx, &txHash, 0, uint32(blockHeight), false, false /*ignoreUtxos*/)
		if err != nil {
			return false, errors.Wrapf(err, "StateChangeSyncer.SyncMempoolToStateSyncer ConnectTransaction: ")
		}

		// Emit transaction state change.
		mempoolUtxoView.EventManager.dbTransactionConnected(&DBTransactionEvent{
			StateChangeEntry: &StateChangeEntry{
				OperationType: DbOperationTypeUpsert,
				KeyBytes:      TxnHashToTxnKey(&txHash),
				EncoderBytes:  EncodeToBytes(blockHeight, unconnectedTxn.tx, false),
			},
			FlushId:      uuid.Nil,
			IsMempoolTxn: true,
		})

		// Capture the utxo ops for the transaction in a UTXOOp bundle.
		utxoOpBundle := &UtxoOperationBundle{
			UtxoOpBundle: [][]*UtxoOperation{},
		}

		utxoOpBundle.UtxoOpBundle = append(utxoOpBundle.UtxoOpBundle, utxoOpsForTxn)

		// Emit UTXOOp bundle event
		mempoolUtxoView.EventManager.dbTransactionConnected(&DBTransactionEvent{
			StateChangeEntry: &StateChangeEntry{
				OperationType: DbOperationTypeUpsert,
				KeyBytes:      _DbKeyForTxnUtxoOps(&txHash),
				EncoderBytes:  EncodeToBytes(blockHeight, utxoOpBundle, false),
			},
			FlushId:      uuid.Nil,
			IsMempoolTxn: true,
		})
	}

	return false, nil
}

func (stateChangeSyncer *StateChangeSyncer) StartMempoolSyncRoutine(server *Server) {
	go func() {
		// Wait for mempool to be initialized.
		for server.mempool == nil || server.blockchain.chainState() != SyncStateFullyCurrent {
			time.Sleep(1000 * time.Millisecond)
		}
		fmt.Printf("\n\n*****STARTING THE MEMPOOL SYNC****\n")
		if !stateChangeSyncer.BlocksyncCompleteEntriesFlushed && stateChangeSyncer.SyncType == NodeSyncTypeBlockSync {
			stateChangeSyncer.FlushAllEntriesToFile(server)
		}
		// TODO: Exit if mempool is closed.
		mempoolClosed := server.mempool.stopped
		for !mempoolClosed {
			// Sleep for a short while to avoid a tight loop.
			time.Sleep(1000 * time.Millisecond)
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
	// Lock the blockchain so that nothing shifts under our feet while dumping the current state to the state change file.
	server.blockchain.ChainLock.Lock()
	defer server.blockchain.ChainLock.Unlock()

	fmt.Printf("\n\n*****FLUSHING ALL ENTRIES TO FILE****\n")

	// Loop through all prefixes that hold state change entries.
	for _, prefix := range StatePrefixes.CoreStatePrefixesList {
		// Start with the first key in the prefix.
		lastReceivedKey := prefix
		chunkComplete := false
		var err error
		var dbBatchEntries []*DBEntry

		// Loop through all the batches of entries for the prefix until we get a non-full chunk.
		for !chunkComplete {
			fmt.Printf("Processing chunk for prefix: %+v\n", prefix)
			// Create a flush ID for this chunk.
			dbFlushId := uuid.New()
			// Fetch the batch from main DB records with a batch size of about snap.BatchSize.
			dbBatchEntries, chunkComplete, err = DBIteratePrefixKeys(server.blockchain.db, prefix, lastReceivedKey, SnapshotBatchSize)
			if err != nil {
				return errors.Wrapf(err, "StateChangeSyncer.FlushAllEntriesToFile: ")
			}
			if len(dbBatchEntries) != 0 {
				lastReceivedKey = dbBatchEntries[len(dbBatchEntries)-1].Key
			}
			for _, dbEntry := range dbBatchEntries {
				server.eventManager.dbTransactionConnected(&DBTransactionEvent{
					StateChangeEntry: &StateChangeEntry{
						OperationType: DbOperationTypeInsert,
						KeyBytes:      dbEntry.Key,
						EncoderBytes:  dbEntry.Value,
					},
					FlushId: dbFlushId,
				})
			}
		}
	}
	// Mark the blocksync complete entries as flushed.
	stateChangeSyncer.BlocksyncCompleteEntriesFlushed = true
	return nil
}
