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

type StateSyncerOperationType uint8

const (
	DbOperationTypeInsert StateSyncerOperationType = 0
	DbOperationTypeDelete StateSyncerOperationType = 1
	DbOperationTypeUpdate StateSyncerOperationType = 2
	DbOperationTypeUpsert StateSyncerOperationType = 3
	DbOperationTypeSkip   StateSyncerOperationType = 4
)

// StateChangeEntry represents a single change to the database. It is used to capture the state of the database.
// These changes are then written to a file, which is then used to sync data consumers who subscribe to changes to
// that file.
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
	// The UtxoOps bytes.
	UtxoOps []*UtxoOperation
}

// Construct the bytes to be written to the file.
// The format is:
// [operation type (varint)][encoder type (varint)][key length (varint)][key bytes]
// [encoder length (varint)][encoder bytes][is mempool (1 byte)][utxo ops length (varint)][utxo ops bytes]
func (stateChangeEntry *StateChangeEntry) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	// Get byte length of keyBytes (will be nil for mempool transactions)
	var data []byte

	data = append(data, UintToBuf(uint64(stateChangeEntry.OperationType))...)
	data = append(data, UintToBuf(uint64(stateChangeEntry.EncoderType))...)
	data = append(data, EncodeByteArray(stateChangeEntry.KeyBytes)...)

	// The encoder can either be represented in bytes or as an encoder. If it's represented in bytes, we use that.
	// This is because during hypersync, we are given the raw bytes of the encoder, which is all we need to encode the
	// StateChangeEntry. Thus, we store the raw bytes here to avoid having to re-encode the encoder.

	// Get bytes for the encoder.
	encoderBytes := stateChangeEntry.EncoderBytes

	// If the encoderBytes is nil and the encoder is not nil, encode the encoder.
	if encoderBytes == nil && stateChangeEntry.Encoder != nil {
		encoderBytes = EncodeToBytes(blockHeight, stateChangeEntry.Encoder)
	} else if encoderBytes == nil && stateChangeEntry.Encoder == nil {
		// If both the encoder and encoder bytes are null, encode a blank encoder.
		encoderBytes = EncodeToBytes(blockHeight, stateChangeEntry.EncoderType.New())
	}

	data = append(data, encoderBytes...)
	data = append(data, BoolToByte(stateChangeEntry.IsMempoolTx))
	utxoOpsBytes := []byte{}

	// If there are utxo ops (i.e. this is a mempool disconnect event), encode them.
	if len(stateChangeEntry.UtxoOps) > 0 {
		utxoOpsBytes = EncodeUtxoOpsToBytes(blockHeight, stateChangeEntry.UtxoOps, false)
	}
	data = append(data, EncodeByteArray(utxoOpsBytes)...)

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

	encoder := stateChangeEntry.EncoderType.New()
	if exist, err := DecodeFromBytes(encoder, rr); exist && err == nil {
		stateChangeEntry.Encoder = encoder
		// TODO: is there any reason to set the encoder bytes here?
	} else if err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding encoder")
	}

	if stateChangeEntry.IsMempoolTx, err = ReadBoolByte(rr); err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding isMempoolTx")
	}

	utxoOpsBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding utxoOpsBytes")
	}

	var utxoOps []*UtxoOperation
	if len(utxoOpsBytes) > 0 {
		utxoOps, err = DecodeUtxoOpsFromBytes(utxoOpsBytes)
		if err != nil {
			return errors.Wrapf(err, "StateChangeEntry.RawDecodeWithoutMetadata: error decoding utxoOps")
		}
		stateChangeEntry.UtxoOps = utxoOps
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
	StateChangeFile      *os.File
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
	// Mutex to prevent concurrent writes to the state change file or .
	StateSyncerMutex      *sync.Mutex
	EntryCount            uint32
	ConnectedMempoolTxMap map[BlockHash]*StateChangeEntry
}

func openOrCreateLogFile(fileName string) (*os.File, error) {
	// Open file, create if it doesn't exist.
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return file, nil
}

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
		// Check to see if the index in question has a "core_state" annotation in its definition.
		if !isCoreStateKey(stateChangeEntry.KeyBytes) {
			return
		}
		// Create a copy of the state change entry for the map so that the utxoOps don't get deleted.
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

	// Encode the state change entry. We encode as a byte array, so the consumer can buffer just the bytes needed
	// to decode this entry when reading from file.
	entryBytes := EncodeToBytes(0, stateChangeEntry, false)
	writeBytes := EncodeByteArray(entryBytes)

	// All mempool transactions occur within the same thread, so they'll be on the uuid.Nil flush.
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
// We use this to keep track of the state of the db so that we can sync it to other data stores.
// This function checks to see if the operation effects a "core_state" index, and if so it encodes the relevant
// entry via protobuf and writes it to a file.
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
		glog.Fatalf("Server._handleDbTransaction: Problem getting deso encoder from keyBytes")
	}

	// Set the encoder type.
	stateChangeEntry.EncoderType = encoderType

	// Encode the state change entry. We encode as a byte array, so the consumer can buffer just the bytes needed
	// to decode this entry when reading from file.
	entryBytes := EncodeToBytes(0, stateChangeEntry, false)
	writeBytes := EncodeByteArray(entryBytes)

	stateChangeSyncer.addTransactionToQueue(event.FlushId, writeBytes)
}

func (stateChangeSyncer *StateChangeSyncer) _handleDbFlush(event *DBFlushedEvent) {
	stateChangeSyncer.StateSyncerMutex.Lock()
	defer stateChangeSyncer.StateSyncerMutex.Unlock()
	err := stateChangeSyncer.FlushTransactionsToFile(event)
	if err != nil {
		glog.Errorf("StateChangeSyncer._handleDbFlush: Error flushing transactions to file: %v", err)
	}
}

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

	fmt.Printf("\n\n*****Handling flush completed: %+v\n\n", event)

	//fmt.Printf("\n\n*****Printing to file: %+v\n\n", unflushedBytes.StateChangeBytes)

	// Write the bytes to the state changer file.
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
		//fmt.Printf("\n\n*****Appending to index bytes: %+v\n\n", dbOperationIndexBytes)

		stateChangeIndexBuf = append(stateChangeIndexBuf, dbOperationIndexBytes...)
	}

	//fmt.Printf("\n\n*****Printing to index file: %+v\n\n", stateChangeIndexBuf)
	_, err = stateChangeSyncer.StateChangeIndexFile.Write(stateChangeIndexBuf)
	if err != nil {
		return fmt.Errorf("Error writing to state change index file: %v", err)
	}
	stateChangeSyncer.StateChangeFileSize += unflushedBytes.StateChangeBytesSize

	// Update unflushed bytes map to remove the flushed bytes.
	delete(stateChangeSyncer.UnflushedBytes, event.FlushId)
	return nil
}

// EncodeArrayToBytes encodes an array of UtxoOps to bytes.
func EncodeUtxoOpsToBytes(blockHeight uint64, utxoOps []*UtxoOperation, skipMetadata bool) []byte {
	var encodedOps [][]byte
	for _, op := range utxoOps {
		encodedOp := EncodeToBytes(blockHeight, op, skipMetadata)
		encodedOps = append(encodedOps, encodedOp)
	}
	return bytes.Join(encodedOps, []byte{})
}

// DecodeArrayFromBytes decodes an array of UtxoOps from bytes.
func DecodeUtxoOpsFromBytes(encodedOps []byte) ([]*UtxoOperation, error) {
	var utxoOps []*UtxoOperation
	reader := bytes.NewReader(encodedOps)
	for reader.Len() > 0 {
		op := &UtxoOperation{}
		_, err := DecodeFromBytes(op, reader)
		if err != nil {
			return nil, err
		}
		utxoOps = append(utxoOps, op)
	}
	return utxoOps, nil
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

	//fmt.Printf("\n\n*****Adding to write bytes queue: %v\n\n", writeBytes)
	unflushedBytes.StateChangeBytes = append(unflushedBytes.StateChangeBytes, writeBytes...)

	// Get the byte index of where this transaction occurs in the unflushed bytes, and add it to the list of
	// indexes that should be written to the index file.
	dbOperationIndex := unflushedBytes.StateChangeBytesSize
	//fmt.Printf("\n\n*****Adding to bytes index: %v\n\n", dbOperationIndex)
	unflushedBytes.StateChangeOperationIndexes = append(unflushedBytes.StateChangeOperationIndexes, dbOperationIndex)
	//fmt.Printf("\n\n*****operation indexes: %+v\n\n", unflushedBytes.StateChangeOperationIndexes)

	// Update the state change file size.
	transactionLen := uint32(len(writeBytes))
	unflushedBytes.StateChangeBytesSize += transactionLen

	stateChangeSyncer.UnflushedBytes[flushId] = unflushedBytes
}
