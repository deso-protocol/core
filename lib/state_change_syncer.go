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
	// We intentionally skip zero as otherwise that would be the default value.
	DbOperationTypeInsert StateSyncerOperationType = 0
	DbOperationTypeDelete StateSyncerOperationType = 1
	DbOperationTypeUpdate StateSyncerOperationType = 2
	DbOperationTypeUpsert StateSyncerOperationType = 3
)

type UnflushedStateSyncerBytes struct {
	StateChangeBytes     []byte
	StateChangeBytesSize uint32
	// This is a list of the indexes of the state change bytes that should be written to the state change index file.
	StateChangeOperationIndexes []uint32
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
	UnflushedBytes map[uuid.UUID]UnflushedStateSyncerBytes
	// Mutex to prevent concurrent writes to the state change file or .
	StateSyncerMutex *sync.Mutex
	EntryCount       uint32
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
		StateChangeFile:      stateChangeFile,
		StateChangeIndexFile: stateChangeIndexFile,
		StateChangeFileSize:  uint32(stateChangeFileInfo.Size()),
		DeSoParams:           desoParams,
		UnflushedBytes:       make(map[uuid.UUID]UnflushedStateSyncerBytes),
		StateSyncerMutex:     &sync.Mutex{},
	}
}

// TODO Error handling.
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

	// Get the encoder type for this keyBytes.
	var encoderType EncoderType
	// Get the relevant deso encoder for this keyBytes.
	if isEncoder, encoder := StateKeyToDeSoEncoder(keyBytes); isEncoder && encoder != nil {
		encoderType = encoder.GetEncoderType()
	} else {
		glog.Fatal("Server._handleDbTransaction: Problem getting deso encoder from keyBytes")
		return
	}

	// Get byte length of keyBytes
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
	binary.Write(buf, binary.LittleEndian, event.OperationType)
	operationTypeBytes = buf.Bytes()

	// Construct the bytes to be written to the file.
	// The format is:
	// [operation type (1 byte)][encoder type (2 bytes)][key length (2 bytes)][key bytes][value length (2 bytes)][value bytes]
	writeBytes := append(operationTypeBytes, encoderTypeBytes...)
	writeBytes = append(writeBytes, keyLenBytes...)
	writeBytes = append(writeBytes, keyBytes...)
	writeBytes = append(writeBytes, valueLenBytes...)
	writeBytes = append(writeBytes, valueBytes...)

	stateChangeSyncer.EntryCount++

	//if stateChangeSyncer.EntryCount >= 336844 && stateChangeSyncer.EntryCount < 336847 {
	//	fmt.Printf("\n****EntryCount: %v\n", stateChangeSyncer.EntryCount)
	//	fmt.Printf("\n\n*****Adding to unflushed bytes: %+v\n\n", writeBytes)
	//}

	unflushedBytes, exists := stateChangeSyncer.UnflushedBytes[event.FlushId]
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
	//fmt.Printf("\n\n*****Adding to bytes index: %v\n\n", dbOperationIndex)
	unflushedBytes.StateChangeOperationIndexes = append(unflushedBytes.StateChangeOperationIndexes, dbOperationIndex)
	//fmt.Printf("\n\n*****operation indexes: %+v\n\n", unflushedBytes.StateChangeOperationIndexes)

	// Update the state change file size.
	transactionLen := uint32(len(writeBytes))
	unflushedBytes.StateChangeBytesSize += transactionLen

	stateChangeSyncer.UnflushedBytes[event.FlushId] = unflushedBytes
}

func (stateChangeSyncer *StateChangeSyncer) _handleDbFlush(event *DBFlushedEvent) {
	stateChangeSyncer.StateSyncerMutex.Lock()
	defer stateChangeSyncer.StateSyncerMutex.Unlock()

	// If the flush failed, delete the unflushed bytes and associated metadata.
	if !event.Succeeded {
		delete(stateChangeSyncer.UnflushedBytes, event.FlushId)
	}

	unflushedBytes, exists := stateChangeSyncer.UnflushedBytes[event.FlushId]

	if !exists {
		return
	}
	fmt.Printf("\n\n*****Handling flush completed: %+v\n\n", event)

	if unflushedBytes.StateChangeBytes == nil || unflushedBytes.StateChangeOperationIndexes == nil || len(unflushedBytes.StateChangeOperationIndexes) == 0 {
		glog.Fatalf("Error flushing state change file: FlushId %v has nil bytes\n", event.FlushId)
	}

	//fmt.Printf("\n\n*****Printing to file: %+v\n\n", unflushedBytes.StateChangeBytes)

	// Write the bytes to the state changer file.
	_, err := stateChangeSyncer.StateChangeFile.Write(unflushedBytes.StateChangeBytes)

	if err != nil {
		glog.Fatalf("Error writing to state change file: %v", err)
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
		glog.Fatalf("Error writing to state change index file: %v", err)
	}
	stateChangeSyncer.StateChangeFileSize += unflushedBytes.StateChangeBytesSize

	// Update unflushed bytes map to remove the flushed bytes.
	delete(stateChangeSyncer.UnflushedBytes, event.FlushId)
}
