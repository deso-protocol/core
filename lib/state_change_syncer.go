package lib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/golang/glog"
	"os"
)

const (
	DbOperationTypeInsert = uint8(0)
	DbOperationTypeDelete = uint8(1)
	DbOperationTypeUpdate = uint8(2)
	DbOperationTypeUpsert = uint8(3)
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
	key := event.Key
	value := event.Value
	// Check to see if the index in question has a "core_state" annotation in it's definition.
	if !isCoreStateKey(key) {
		return
	}

	// Decode the value to a DeSo encoder, and encode the entry to protobuf bytes.
	var protobufBytes []byte
	var encoderType EncoderType
	// Get the relevant deso encoder for this key.
	if isEncoder, encoder := StateKeyToDeSoEncoder(key); isEncoder && encoder != nil {
		rr := bytes.NewReader(value)
		encoderType = encoder.GetEncoderType()
		// Extract the DeSo entry struct interface from the bytes.
		if exists, err := DecodeFromBytes(encoder, rr); exists && err == nil {
			// Encode the entry to protobuf bytes.
			protobufBytes, err = encoder.RawEncodeToProtobufBytes(stateChangeSyncer.DeSoParams)
			if err != nil {
				glog.Errorf("Server._handleDbTransaction: Problem encoding protobuf bytes: %v", err)
				return
			}
		} else if err != nil {
			glog.Errorf("Some odd problem: isEncoder %v encoder %v, key bytes (%v), value bytes (%v)",
				isEncoder, encoder, key, value)
		}
	}

	// Get byte length of value + encoder type (uint16).
	valueLen := uint16(len(protobufBytes) + 2)

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

	// Append the value length and encoder type to the protobuf bytes.
	valueWithLengthAndEncoderTypeBytes := append(valueLenBytes, encoderTypeBytes...)
	valueWithLengthAndEncoderTypeBytes = append(valueWithLengthAndEncoderTypeBytes, operationTypeBytes...)
	valueWithLengthAndEncoderTypeBytes = append(valueWithLengthAndEncoderTypeBytes, protobufBytes...)

	fmt.Printf("\n\n*****Printing to file: %+v\n\n", valueWithLengthAndEncoderTypeBytes)
	// Write the bytes to file.
	_, err := stateChangeSyncer.StateChangeFile.Write(valueWithLengthAndEncoderTypeBytes)
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
	transactionLen := uint32(len(protobufBytes) + 4)
	stateChangeSyncer.StateChangeFileSize += transactionLen
}
