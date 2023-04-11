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
	// The type of encoder that should be used for the operation.
	EncoderType EncoderType
	// If this transaction is a mempool transaction.
	IsMempoolTx bool
	// The length of the UtxoOps bytes.
	UtxoOpsBytesSize uint64
	// The UtxoOps for a transaction. This is used to disconnect mempool transactions that have been included in a block.
	UtxoOps []*UtxoOperation
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
		encoderBytes = EncodeToBytes(blockHeight, stateChangeEntry.EncoderType.New())
	}

	data = append(data, encoderBytes...)
	data = append(data, BoolToByte(stateChangeEntry.IsMempoolTx))
	utxoOpsBytes := []byte{}

	utxoOpBundle := &UtxoOperationBundle{}

	// If there are utxo ops (i.e. this is a mempool disconnect event), encode them as a bundle.
	if len(stateChangeEntry.UtxoOps) > 0 {
		utxoOpBundle.UtxoOpBundle = [][]*UtxoOperation{stateChangeEntry.UtxoOps}
	}
	utxoOpsBytes = EncodeToBytes(blockHeight, utxoOpBundle, false)
	data = append(data, utxoOpsBytes...)

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

	if stateChangeEntry.IsMempoolTx, err = ReadBoolByte(rr); err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding isMempoolTx")
	}

	// Decode utxo ops.
	utxoOpBundle := &UtxoOperationBundle{}
	if exist, err := DecodeFromBytes(utxoOpBundle, rr); exist && err == nil && len(utxoOpBundle.UtxoOpBundle) > 0 {
		stateChangeEntry.UtxoOps = utxoOpBundle.UtxoOpBundle[0]
	} else if err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding utxoOpBundle")
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
	StateChangeBytes     []byte
	StateChangeBytesSize uint32
	// This is a list of the indexes of the state change bytes that should be written to the state change index file.
	StateChangeOperationIndexes []uint32
}

// StateChangeSyncer is used to keep track of the state changes that should be written to the state change file.
type StateChangeSyncer struct {
	// The file that the state changes are written to.
	StateChangeFile *os.File
	// The file that allows quick lookup of a StateChangeEntry given its index in the file.
	// This is represented by a list of uint32s, where each uint32 is the offset of the state change entry in the state change file.
	StateChangeIndexFile *os.File
	StateChangeFileSize  uint32
	DeSoParams           *DeSoParams
	// This map is used to keep track of the bytes should be written to the state change file upon a db flush.
	// The ID of the flush is to track which entries should be written to the state change file upon flush completion.
	// This is needed because many flushes can occur asynchronously during hypersync, and we need to make sure that
	// we write the correct entries to the state change file.
	// During blocksync, all flushes are synchronous, so we don't need to worry about this. As such, those flushes
	// are given the uuid.Nil ID.
	UnflushedBytes map[uuid.UUID]UnflushedStateSyncerBytes
	// Mutex to prevent concurrent writes to the state change file.
	StateSyncerMutex *sync.Mutex
	EntryCount       uint32
	// ConnectedMempoolTxMap is used to keep track of the mempool transactions that are currently connected.
	// Upon disconnect, we use the txn hash to look up the state change entry in this map and write it to the state change file.
	ConnectedMempoolTxMap map[BlockHash]*StateChangeEntry
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
func NewStateChangeSyncer(desoParams *DeSoParams, stateChangeFilePath string) *StateChangeSyncer {
	stateChangeIndexFilePath := fmt.Sprintf("%s-index", stateChangeFilePath)
	stateChangeFile, err := openOrCreateLogFile(stateChangeFilePath)
	if err != nil {
		glog.Fatalf("Error opening stateChangeFile: %v", err)
	}
	stateChangeIndexFile, err := openOrCreateLogFile(stateChangeIndexFilePath)
	if err != nil {
		glog.Fatalf("Error opening stateChangeIndexFile: %v", err)
	}
	stateChangeFileInfo, err := stateChangeFile.Stat()
	if err != nil {
		glog.Fatalf("Error getting stateChangeFileInfo: %v", err)
	}

	return &StateChangeSyncer{
		StateChangeFile:       stateChangeFile,
		StateChangeIndexFile:  stateChangeIndexFile,
		StateChangeFileSize:   uint32(stateChangeFileInfo.Size()),
		DeSoParams:            desoParams,
		UnflushedBytes:        make(map[uuid.UUID]UnflushedStateSyncerBytes),
		StateSyncerMutex:      &sync.Mutex{},
		ConnectedMempoolTxMap: make(map[BlockHash]*StateChangeEntry),
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

// _handleMempoolTransaction constructs a StateChangeEntry for a given mempool transaction. Upon connect, this entry
// is added directly to the state change file. Upon disconnect, we look up the entry in the ConnectedMempoolTxMap
// and add it to the bytes to be written to the state change file upon DB flush.
func (stateChangeSyncer *StateChangeSyncer) _handleMempoolTransaction(event *MempoolTransactionEvent) {
	// We shouldn't need this for mempool transactions, as they all occur on the same thread.
	// Just adding for completeness.
	stateChangeSyncer.StateSyncerMutex.Lock()
	defer stateChangeSyncer.StateSyncerMutex.Unlock()

	stateChangeEntry := event.StateChangeEntry
	stateChangeEntry.IsMempoolTx = true

	// If the transaction is connected, add it to the connected mempool map. Upon disconnect, we'll look this up and pass
	// it to the state change file so the consumer can use them to revert the mempool transaction.
	if event.IsConnected {
		// Check to see if the operation in question has a "core_state" annotation for its key.
		if !isCoreStateKey(stateChangeEntry.KeyBytes) {
			return
		}
		// Create a copy of the state change entry for the map so that the utxoOps don't get deleted when they're removed
		//from the stateChangeEntry struct (utxoOps are only included for disconnects).
		mapStateChangeEntry := *stateChangeEntry
		stateChangeSyncer.ConnectedMempoolTxMap[*event.TxHash] = &mapStateChangeEntry
		// Only pass UtxoOps to the state change syncer if this is a disconnect transaction (we need them to revert the
		// connected mempool transaction.
		stateChangeEntry.UtxoOps = nil
	} else {
		// Get the cached mempool transaction from the connected mempool map.
		if connectedMempoolTx, ok := stateChangeSyncer.ConnectedMempoolTxMap[*event.TxHash]; ok {
			// Check to see if the index in question has a "core_state" annotation in its definition.
			if !isCoreStateKey(connectedMempoolTx.KeyBytes) {
				return
			}

			stateChangeEntry.Encoder = connectedMempoolTx.Encoder
			stateChangeEntry.KeyBytes = connectedMempoolTx.KeyBytes
			stateChangeEntry.UtxoOps = connectedMempoolTx.UtxoOps
		} else {
			return
		}
	}

	// Set the encoder type.
	stateChangeEntry.EncoderType = stateChangeEntry.Encoder.GetEncoderType()

	// Encode the state change entry. They are encoded as a byte array, so the consumer can buffer just the bytes needed
	// to decode this entry when reading from file.
	entryBytes := EncodeToBytes(0, stateChangeEntry, false)
	writeBytes := EncodeByteArray(entryBytes)

	// All mempool transactions occur within the same thread, so they'll be on the uuid.Nil flush ID.
	stateChangeSyncer.addTransactionToQueue(uuid.Nil, writeBytes)

	if event.IsConnected {
		// With mempool connects, instantly flush to db.
		// As soon as this callback is called, the mempool transaction is considered "connected".
		err := stateChangeSyncer.FlushTransactionsToFile(&DBFlushedEvent{FlushId: uuid.Nil, Succeeded: true})
		if err != nil {
			glog.Fatalf("StateChangeSyncer._handleMempoolTransaction: Error flushing mempool transaction to file: %v", err)
		}
	} else {
		// After the disconnect is written to file, remove this mempool tx from our map.
		delete(stateChangeSyncer.ConnectedMempoolTxMap, *event.TxHash)
	}
}

// handleDbTransactionConnected is called when a badger db operation takes place.
// This function checks to see if the operation effects a "core_state" index, and if so it encodes a StateChangeEntry
// to be written to the state change file upon DB flush.
// It also writes the offset of the entry in the file to a separate index file, such that a consumer can look up a
// particular entry index in the state change file.
func (stateChangeSyncer *StateChangeSyncer) _handleDbTransaction(event *DBTransactionEvent) {
	stateChangeSyncer.StateSyncerMutex.Lock()
	defer stateChangeSyncer.StateSyncerMutex.Unlock()

	stateChangeEntry := event.StateChangeEntry

	// Check to see if the index in question has a "core_state" annotation in its definition.
	if !isCoreStateKey(stateChangeEntry.KeyBytes) {
		return
	}

	// Get the relevant deso encoder for this keyBytes.
	var encoderType EncoderType
	if isEncoder, encoder := StateKeyToDeSoEncoder(stateChangeEntry.KeyBytes); isEncoder && encoder != nil {
		encoderType = encoder.GetEncoderType()
	} else {
		// If the keyBytes is not an encoder, then we decode the entry from the key value.
		keyEncoder, err := DecodeStateKey(stateChangeEntry.KeyBytes)
		if err != nil {
			glog.Fatalf("Server._handleDbTransaction: Error decoding state key: %v", err)
		}
		encoderType = keyEncoder.GetEncoderType()
		stateChangeEntry.Encoder = keyEncoder
	}
	// Set the encoder type.
	stateChangeEntry.EncoderType = encoderType

	// Encode the state change entry. We encode as a byte array, so the consumer can buffer just the bytes needed
	// to decode this entry when reading from file.
	entryBytes := EncodeToBytes(0, stateChangeEntry, false)
	writeBytes := EncodeByteArray(entryBytes)

	decodedStateChangeEntry := &StateChangeEntry{}
	DecodeFromBytes(decodedStateChangeEntry, bytes.NewReader(entryBytes))
	// Add the StateChangeEntry bytes to the queue of bytes to be written to the state change file upon Badger db flush.
	stateChangeSyncer.addTransactionToQueue(event.FlushId, writeBytes)
}

// _handleDbFlush is called when a Badger db flush takes place. It calls a helper function that takes the bytes that
// have been cached on the StateChangeSyncer and writes them to the state change file.
func (stateChangeSyncer *StateChangeSyncer) _handleDbFlush(event *DBFlushedEvent) {
	stateChangeSyncer.StateSyncerMutex.Lock()
	defer stateChangeSyncer.StateSyncerMutex.Unlock()
	err := stateChangeSyncer.FlushTransactionsToFile(event)
	if err != nil {
		glog.Errorf("StateChangeSyncer._handleDbFlush: Error flushing transactions to file: %v", err)
	}
}

// Add a transaction to the queue of transactions to be flushed to disk upon badger db flush.
func (stateChangeSyncer *StateChangeSyncer) addTransactionToQueue(flushId uuid.UUID, writeBytes []byte) {
	stateChangeSyncer.EntryCount++

	unflushedBytes, exists := stateChangeSyncer.UnflushedBytes[flushId]
	if !exists {
		unflushedBytes = UnflushedStateSyncerBytes{
			StateChangeBytes:            []byte{},
			StateChangeBytesSize:        0,
			StateChangeOperationIndexes: []uint32{},
		}
	}

	unflushedBytes.StateChangeBytes = append(unflushedBytes.StateChangeBytes, writeBytes...)

	// Get the byte index of where this transaction occurs in the unflushed bytes, and add it to the list of
	// indexes that should be written to the index file.
	dbOperationIndex := unflushedBytes.StateChangeBytesSize
	unflushedBytes.StateChangeOperationIndexes = append(unflushedBytes.StateChangeOperationIndexes, dbOperationIndex)

	// Update the state change file size.
	transactionLen := uint32(len(writeBytes))
	unflushedBytes.StateChangeBytesSize += transactionLen

	stateChangeSyncer.UnflushedBytes[flushId] = unflushedBytes
}

// FlushTransactionsToFile writes the bytes that have been cached on the StateChangeSyncer to the state change file.
func (stateChangeSyncer *StateChangeSyncer) FlushTransactionsToFile(event *DBFlushedEvent) error {

	// If the flush failed, delete the unflushed bytes and associated metadata.
	// Also delete any unconnected mempool txns from our cache.
	if !event.Succeeded {
		delete(stateChangeSyncer.UnflushedBytes, event.FlushId)
		stateChangeSyncer.ConnectedMempoolTxMap = make(map[BlockHash]*StateChangeEntry)
	}

	unflushedBytes, exists := stateChangeSyncer.UnflushedBytes[event.FlushId]

	if !exists {
		return nil
	}

	if unflushedBytes.StateChangeBytes == nil || unflushedBytes.StateChangeOperationIndexes == nil || len(unflushedBytes.StateChangeOperationIndexes) == 0 {
		return fmt.Errorf("Error flushing state change file: FlushId %v has nil bytes\n", event.FlushId)
	}

	// Write the encoded StateChangeEntry bytes to the state changer file.
	_, err := stateChangeSyncer.StateChangeFile.Write(unflushedBytes.StateChangeBytes)

	if err != nil {
		return fmt.Errorf("Error writing to state change file: %v", err)
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
		dbOperationIndex := indexBytes + stateChangeSyncer.StateChangeFileSize
		// Convert the byte index value to a uint32 byte slice.
		dbOperationIndexBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(dbOperationIndexBytes, dbOperationIndex)

		stateChangeIndexBuf = append(stateChangeIndexBuf, dbOperationIndexBytes...)
	}

	// Write the encoded uint32 indexes to the index file.
	_, err = stateChangeSyncer.StateChangeIndexFile.Write(stateChangeIndexBuf)
	if err != nil {
		return fmt.Errorf("Error writing to state change index file: %v", err)
	}
	stateChangeSyncer.StateChangeFileSize += unflushedBytes.StateChangeBytesSize

	// Update unflushed bytes map to remove the flushed bytes.
	delete(stateChangeSyncer.UnflushedBytes, event.FlushId)
	return nil
}
