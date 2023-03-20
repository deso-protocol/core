package lib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/golang/glog"
	"os"
)

type StateSyncerOperationType uint8

const (
	// We intentionally skip zero as otherwise that would be the default value.
	DbOperationTypeInsert StateSyncerOperationType = 0
	DbOperationTypeDelete StateSyncerOperationType = 1
	DbOperationTypeUpdate StateSyncerOperationType = 2
	DbOperationTypeUpsert StateSyncerOperationType = 3
)

func createLogFile(fileName string) *os.File {
	file, _ := os.Create(fileName)
	return file
}

type StateChangeSyncer struct {
	StateChangeFile      *os.File
	StateChangeIndexFile *os.File
	StateChangeFileSize  uint32
	DeSoParams           *DeSoParams
}

func NewStateChangeSyncer(desoParams *DeSoParams) *StateChangeSyncer {
	return &StateChangeSyncer{
		StateChangeFile:      createLogFile("/tmp/db-state-changes"),
		StateChangeIndexFile: createLogFile("/tmp/db-state-changes-index"),
		StateChangeFileSize:  0,
		DeSoParams:           desoParams,
	}
}

// handleDbTransactionConnected is called when a badger db operation takes place.
// We use this to keep track of the state of the db so that we can sync it to other data stores.
// This function checks to see if the operation effects a "core_state" index, and if so it encodes the relevant
// entry via protobuf and writes it to a file.
// It also writes the offset of the entry in the file to a separate index file, such that a consumer can look up a
// particular entry index in the state change file.
func (stateChangeSyncer *StateChangeSyncer) _handleDbTransaction(event *DBTransactionEvent) {
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
		glog.Errorf("Server._handleDbTransaction: Problem getting deso encoder from keyBytes")
		return
	}

	// Get byte length of keyBytes
	keyLen := uint16(len(keyBytes))
	keyLenBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(keyLenBytes, keyLen)

	// Get byte length of value.
	valueLen := uint16(len(valueBytes))
	// Convert the value length to a byte slice.
	valueLenBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(valueLenBytes, valueLen)

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

	fmt.Printf("\n\n*****Printing to file: %+v\n\n", writeBytes)
	// Write the bytes to file.
	_, err := stateChangeSyncer.StateChangeFile.Write(writeBytes)
	if err != nil {
		glog.Errorf("Error writing to state change file: %v", err)
	}

	// Get the byte index of where this transaction occurs in the state change file.
	dbOperationIndex := stateChangeSyncer.StateChangeFileSize
	// Convert the byte index value to a byte slice.
	dbOperationIndexBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(dbOperationIndexBytes, dbOperationIndex)

	// Write the byte index to the index file.
	_, err = stateChangeSyncer.StateChangeIndexFile.Write(dbOperationIndexBytes)
	if err != nil {
		glog.Errorf("Error writing to state change file: %v", err)
	}
	fmt.Printf("\n\n*****Printing to index file: %+v\n\n", dbOperationIndexBytes)

	// Update the state change file size.
	transactionLen := uint32(len(valueBytes) + 5)
	stateChangeSyncer.StateChangeFileSize += transactionLen
}
