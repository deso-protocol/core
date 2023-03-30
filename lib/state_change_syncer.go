package lib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/golang/glog"
	"github.com/google/uuid"
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

type UnflushedStateSyncerBytes struct {
	StateChangeBytes     []byte
	StateChangeBytesSize uint32
	// This is a list of the indexes of the state change bytes that should be written to the state change index file.
	StateChangeOperationIndexes []uint32
}

type ConnectedMempoolTx struct {
	Encoder  DeSoEncoder
	KeyBytes []byte
	UtxoOps  []*UtxoOperation
}

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
	ConnectedMempoolTxMap map[BlockHash]*ConnectedMempoolTx
}

func openOrCreateLogFile(fileName string) (*os.File, error) {
	// Open file, create if it doesn't exist.
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func NewStateChangeSyncer(desoParams *DeSoParams, stateChangeFilePath string, stateChangeIndexFilePath string) *StateChangeSyncer {
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
		ConnectedMempoolTxMap: make(map[BlockHash]*ConnectedMempoolTx),
	}
}

func (stateChangeSyncer *StateChangeSyncer) _handleMempoolTransaction(event *MempoolTransactionEvent) {
	// We shouldn't need this for mempool transactions, as they all occur on the same thread.
	// Just adding for completeness.
	stateChangeSyncer.StateSyncerMutex.Lock()
	defer stateChangeSyncer.StateSyncerMutex.Unlock()

	// If the transaction is connected, add it to the connected mempool map. Upon disconnect, we'll look this up and pass
	// it to the state change file so the consumer can use them to revert the mempool transaction.
	if event.IsConnected {
		stateChangeSyncer.ConnectedMempoolTxMap[*event.TxHash] = &ConnectedMempoolTx{
			Encoder:  event.Encoder,
			UtxoOps:  event.UtxoOps,
			KeyBytes: event.KeyBytes,
		}
		// Only pass UtxoOps to the state change syncer if this is a disconnect transaction (we need them to revert the
		// connected mempool transaction.
		event.UtxoOps = nil
	} else {
		if connectedMempoolTx, ok := stateChangeSyncer.ConnectedMempoolTxMap[*event.TxHash]; ok {
			event.Encoder = connectedMempoolTx.Encoder
			event.KeyBytes = connectedMempoolTx.KeyBytes
			event.UtxoOps = connectedMempoolTx.UtxoOps
		} else {
			glog.Fatalf("StateChangeSyncer._handleMempoolTransaction: Mempool transaction %v not found in "+
				"connected mempool map", *event.TxHash)
		}
	}

	// Encode the entry to bytes.
	valueBytes := EncodeToBytes(event.BlockHeight, event.Encoder, false)

	writeBytes, err := stateChangeSyncer.composeWriteBytes(event.KeyBytes, valueBytes, DbOperationTypeUpsert,
		event.UtxoOps, event.BlockHeight, event.Encoder.GetEncoderType(), true)
	if err != nil {
		glog.Fatalf("StateChangeSyncer._handleMempoolTransaction: Error composing write bytes: %v", err)
	}

	fmt.Printf("\n\n**********Mempool transaction: %+v\n\n**********\n\n", writeBytes)

	// All mempool transactions occur within the same thread, so they'll be on the uuid.Nil flush.
	stateChangeSyncer.addTransactionToQueue(uuid.Nil, writeBytes)

	if event.IsConnected {
		// With mempool connects, instantly flush to db.
		// As soon as this callback is called, the mempool transaction is considered "connected".
		err = stateChangeSyncer.FlushTransactionsToFile(&DBFlushedEvent{FlushId: uuid.Nil, Succeeded: true})
		if err != nil {
			glog.Fatalf("StateChangeSyncer._handleMempoolTransaction: Error flushing mempool transaction to file: %v", err)
		}
	} else {
		// After the disconnect completes, remove this mempool tx from our map.
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
	keyBytes := event.Key
	valueBytes := event.Value
	// Check to see if the index in question has a "core_state" annotation in it's definition.
	if !isCoreStateKey(keyBytes) {
		return
	}

	// Get the relevant deso encoder for this keyBytes.
	var encoderType EncoderType
	if isEncoder, encoder := StateKeyToDeSoEncoder(keyBytes); isEncoder && encoder != nil {
		encoderType = encoder.GetEncoderType()
	} else {
		glog.Fatalf("Server._handleDbTransaction: Problem getting deso encoder from keyBytes")
	}

	writeBytes, err := stateChangeSyncer.composeWriteBytes(keyBytes, valueBytes, event.OperationType, nil,
		0, encoderType, false)

	if err != nil {
		glog.Fatalf(err.Error())
	}

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
		stateChangeSyncer.ConnectedMempoolTxMap = make(map[BlockHash]*ConnectedMempoolTx)
	}

	unflushedBytes, exists := stateChangeSyncer.UnflushedBytes[event.FlushId]

	if !exists {
		return nil
	}
	fmt.Printf("\n\n*****Handling flush completed: %+v\n\n", event)

	if unflushedBytes.StateChangeBytes == nil || unflushedBytes.StateChangeOperationIndexes == nil || len(unflushedBytes.StateChangeOperationIndexes) == 0 {
		return fmt.Errorf("Error flushing state change file: FlushId %v has nil bytes\n", event.FlushId)
	}

	fmt.Printf("\n\n*****Printing to file: %+v\n\n", unflushedBytes.StateChangeBytes)

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
func EncodeUtxoOpsToBytes(blockHeight uint64, utxoOps []*UtxoOperation, skipMetadata bool) ([]byte, error) {
	var encodedOps [][]byte
	for _, op := range utxoOps {
		encodedOp := EncodeToBytes(blockHeight, op, skipMetadata)
		encodedOps = append(encodedOps, encodedOp)
	}
	return bytes.Join(encodedOps, []byte{}), nil
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

// TODO: DeSoStateChange should become its own DeSoEncoder.
// composeWriteBytes takes in a keyBytes, valueBytes, and operationType and returns a byte slice
// representing a state change operation to the DeSo blockchain. It also takes in a list of utxoOps
// that can be used to revert mempool transactions that may be disconnected.
func (stateChangeSyncer *StateChangeSyncer) composeWriteBytes(keyBytes []byte, valueBytes []byte,
	operationType StateSyncerOperationType, utxoOps []*UtxoOperation,
	blockheight uint64, encoderType EncoderType, isMempool bool) ([]byte, error) {

	// Get byte length of keyBytes (will be nil for mempool transactions)
	keyLen := uint16(len(keyBytes))
	keyLenBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(keyLenBytes, keyLen)

	// Get byte length of value (will be nil for deletes).
	valueLen := uint32(0)
	if valueBytes != nil {
		valueLen = uint32(len(valueBytes))
	}
	// Convert the value length to a byte slice.
	valueLenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueLenBytes, valueLen)

	// Convert the encoder type to a byte slice.
	encoderTypeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(encoderTypeBytes, uint16(encoderType))

	// Convert the encoder type to a byte slice.
	operationTypeBytes := make([]byte, 1)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, operationType)
	operationTypeBytes = buf.Bytes()

	isMempoolBytes := make([]byte, 1)
	if isMempool {
		isMempoolBytes[0] = 1
	} else {
		isMempoolBytes[0] = 0
	}

	// Get byte length of utxoOps (will be nil for non-mempool, non-disconnect txns).
	utxoOpsLen := uint32(0)

	utxoOpsBytes := []byte{}
	if len(utxoOps) > 0 {
		fmt.Printf("\n\n****Encoding utxo ops")
		var err error
		utxoOpsBytes, err = EncodeUtxoOpsToBytes(blockheight, utxoOps, false)
		if err != nil {
			return nil, err
		}
		fmt.Printf("\n\n****Utxo ops bytes: %+v", utxoOpsBytes)
		utxoOpsLen = uint32(len(utxoOpsBytes))
	}

	utxoOpsLenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(utxoOpsLenBytes, utxoOpsLen)

	// Construct the bytes to be written to the file.
	// The format is:
	// [operation type (1 byte)][encoder type (2 bytes)][key length (2 bytes)][key bytes]
	// [value length (4 bytes)][value bytes][is mempool (1 byte)][utxo ops length (4 bytes)][utxo ops bytes]
	writeBytes := append(operationTypeBytes, encoderTypeBytes...)
	writeBytes = append(writeBytes, keyLenBytes...)
	writeBytes = append(writeBytes, keyBytes...)
	writeBytes = append(writeBytes, valueLenBytes...)
	writeBytes = append(writeBytes, valueBytes...)
	writeBytes = append(writeBytes, isMempoolBytes...)
	writeBytes = append(writeBytes, utxoOpsLenBytes...)

	if utxoOpsLen > 0 {
		writeBytes = append(writeBytes, utxoOpsBytes...)
	}

	return writeBytes, nil
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

	fmt.Printf("\n\n*****Adding to write bytes queue: %v\n\n", writeBytes)
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
