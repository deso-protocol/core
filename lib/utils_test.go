package lib

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/proto_schemas/entries"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestSafeMakeSliceWithLength(t *testing.T) {
	badSlice, err := SafeMakeSliceWithLength[byte](math.MaxUint64)
	require.NotNil(t, err)
	require.Nil(t, badSlice)

	goodSlice, err := SafeMakeSliceWithLength[byte](10)
	require.Nil(t, err)
	require.Len(t, goodSlice, 10)
}

func TestSafeMakeSliceWithLengthAndCapacity(t *testing.T) {
	badSliceLength, err := SafeMakeSliceWithLengthAndCapacity[byte](math.MaxUint64-10, 0)
	require.NotNil(t, err)
	require.Nil(t, badSliceLength)

	badSliceCapacity, err := SafeMakeSliceWithLengthAndCapacity[byte](10, math.MaxUint64)
	require.NotNil(t, err)
	require.Nil(t, badSliceCapacity)

	goodSlice, err := SafeMakeSliceWithLength[byte](10)
	require.Nil(t, err)
	require.Len(t, goodSlice, 10)
}

// Note: I can't find a capacity that breaks the make map function
func TestSafeMakeMapWithCapacity(t *testing.T) {
	goodMap, err := SafeMakeMapWithCapacity[string, []byte](1000)
	require.Nil(t, err)
	require.NotNil(t, goodMap)
}

type testResponse struct {
	PosterPublicKey string
	PostHash        string
	Body            *entries.DeSoBodySchema
}

func TestCopyStruct(t *testing.T) {
	postBytesHex := "13a546bba07e9cd96e29cea659b3bb6de1b5144a50bf2a0c94d05701861d8254"
	byteArray, err := hex.DecodeString(postBytesHex)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	blockHash := NewBlockHash(byteArray)

	postBody := &DeSoBodySchema{
		Body:      "Test string",
		ImageURLs: []string{"https://test.com/image1.jpg", "https://test.com/image2.jpg"},
		VideoURLs: []string{"https://test.com/video1.mp4", "https://test.com/video2.mp4"},
	}

	bodyBytes, err := json.Marshal(postBody)

	struct1 := &PostEntry{
		PostHash:        blockHash,
		Body:            bodyBytes,
		PosterPublicKey: []byte{2, 57, 123, 26, 128, 235, 160, 166, 6, 68, 101, 10, 241, 60, 42, 111, 253, 251, 191, 56, 131, 12, 175, 195, 73, 55, 167, 93, 221, 68, 184, 206, 82},
	}

	struct2 := &testResponse{}

	err = CopyStruct(struct1, struct2, &DeSoParams{})
	fmt.Printf("struct2: %+v\n", struct2.Body)

}

func TestProtoPost(t *testing.T) {
	postBody := &DeSoBodySchema{
		Body:      "Test string",
		ImageURLs: []string{"https://test.com/image1.jpg", "https://test.com/image2.jpg"},
		VideoURLs: []string{"https://test.com/video1.mp4", "https://test.com/video2.mp4"},
	}

	bodyBytes, err := json.Marshal(postBody)
	require.NoError(t, err)
	postEntry := &PostEntry{
		PostHash:        NewBlockHash([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}),
		PosterPublicKey: []byte{2, 57, 123, 26, 128, 235, 160, 166, 6, 68, 101, 10, 241, 60, 42, 111, 253, 251, 191, 56, 131, 12, 175, 195, 73, 55, 167, 93, 221, 68, 184, 206, 82},
		Body:            bodyBytes,
	}

	desoParams := &DeSoParams{}
	protoPost := postEntry.GetProtobufEncoderType()
	CopyStruct(postEntry, protoPost, desoParams)

	protobufBytes, err := proto.Marshal(protoPost)

	decodedPost := &entries.Post{}

	proto.Unmarshal(protobufBytes, decodedPost)

	require.Equal(t, EncodeBlockhashToHexString(postEntry.PostHash), decodedPost.PostHash)
	require.Equal(t, PkToString(postEntry.PosterPublicKey, desoParams), decodedPost.PosterPublicKey)
	require.Equal(t, postBody.Body, decodedPost.Body.Body)
	require.Equal(t, postBody.ImageURLs, decodedPost.Body.ImageURLs)
	require.Equal(t, postBody.VideoURLs, decodedPost.Body.VideoURLs)

}
