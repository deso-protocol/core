package lib

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
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
