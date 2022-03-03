package lib

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"reflect"
	"testing"
	"time"
)

func TestMessageEntryDecoding(t *testing.T) {
	// Create a message entry
	messageEntry := MessageEntry{
		NewPublicKey(m0PkBytes),
		NewPublicKey(m1PkBytes),
		[]byte{1, 2, 3, 4, 5, 6},
		uint64(time.Now().UnixNano()),
		false,
		MessagesVersion1,
		NewPublicKey(m0PkBytes),
		NewGroupKeyName([]byte("default")),
		NewPublicKey(m1PkBytes),
		BaseGroupKeyName(),
		nil,
	}

	encodedWithExtraData := messageEntry.Encode()

	// We know the last byte is a 0 representing the length of the extra data, so chop that off
	missingExtraDataEncoding := encodedWithExtraData[:len(encodedWithExtraData)-1]

	decodedMessageEntryMissingExtraData := MessageEntry{}
	err := decodedMessageEntryMissingExtraData.Decode(missingExtraDataEncoding)
	require.NoError(t, err)

	decodedMessageEntryWithExtraData := MessageEntry{}
	err = decodedMessageEntryWithExtraData.Decode(encodedWithExtraData)
	require.NoError(t, err)

	// The message decoded without extra data should
	require.True(t, reflect.DeepEqual(decodedMessageEntryWithExtraData, decodedMessageEntryMissingExtraData))
	require.True(t, reflect.DeepEqual(decodedMessageEntryMissingExtraData, messageEntry))

	// Now encode them again and prove they're the same
	require.True(t, bytes.Equal(encodedWithExtraData, decodedMessageEntryMissingExtraData.Encode()))

	// Okay now let's set the extra data on the message entry
	messageEntry.ExtraData = map[string][]byte{
		"test": {0, 1, 2},
	}

	encodedExtraData := EncodeExtraData(messageEntry.ExtraData)

	encodedIncludingExtraData := messageEntry.Encode()

	extraDataBytesRemoved := encodedIncludingExtraData[:len(encodedIncludingExtraData)-len(encodedExtraData)]

	messageEntryWithExtraDataRemoved := MessageEntry{}
	err = messageEntryWithExtraDataRemoved.Decode(extraDataBytesRemoved)
	require.NoError(t, err)

	messageEntryWithExtraDataRemovedBytes := messageEntryWithExtraDataRemoved.Encode()

	// This should be effectively equivalent to the original message entry above without extra data
	require.True(t, reflect.DeepEqual(messageEntryWithExtraDataRemoved, decodedMessageEntryWithExtraData))

	// The bytes should be the same up until the extra data segment of the bytes
	require.Equal(t, len(encodedIncludingExtraData), len(messageEntryWithExtraDataRemovedBytes)+len(encodedExtraData)-1)
	reflect.DeepEqual(encodedIncludingExtraData, append(messageEntryWithExtraDataRemovedBytes[:len(messageEntryWithExtraDataRemovedBytes)-1], encodedExtraData...))
}

func TestMessagingGroupEntryDecoding(t *testing.T) {
	// Create a messaging group entry

	messagingGroupEntry := MessagingGroupEntry{
		GroupOwnerPublicKey:   NewPublicKey(m0PkBytes),
		MessagingPublicKey:    NewPublicKey(m0PkBytes),
		MessagingGroupKeyName: BaseGroupKeyName(),
	}

	encodedWithExtraData := messagingGroupEntry.Encode()

	// We know the last byte is a 0 representing the length of the extra data, so chop that off
	missingExtraDataEncoding := encodedWithExtraData[:len(encodedWithExtraData)-1]

	decodedMessagingGroupEntryMissingExtraData := MessagingGroupEntry{}
	err := decodedMessagingGroupEntryMissingExtraData.Decode(missingExtraDataEncoding)
	require.NoError(t, err)

	decodedMessagingGroupEntryWithExtraData := MessagingGroupEntry{}
	err = decodedMessagingGroupEntryWithExtraData.Decode(encodedWithExtraData)
	require.NoError(t, err)

	// The message decoded without extra data should
	require.True(t, reflect.DeepEqual(decodedMessagingGroupEntryWithExtraData, decodedMessagingGroupEntryMissingExtraData))
	require.True(t, reflect.DeepEqual(decodedMessagingGroupEntryMissingExtraData, messagingGroupEntry))

	// Now encode them again and prove they're the same
	require.True(t, bytes.Equal(encodedWithExtraData, decodedMessagingGroupEntryMissingExtraData.Encode()))

	// Okay now let's set the extra data on the message entry
	messagingGroupEntry.ExtraData = map[string][]byte{
		"test": {0, 1, 2},
	}

	encodedExtraData := EncodeExtraData(messagingGroupEntry.ExtraData)

	encodedIncludingExtraData := messagingGroupEntry.Encode()

	extraDataBytesRemoved := encodedIncludingExtraData[:len(encodedIncludingExtraData)-len(encodedExtraData)]

	messagingGroupEntryWithExtraDataRemoved := MessagingGroupEntry{}
	err = messagingGroupEntryWithExtraDataRemoved.Decode(extraDataBytesRemoved)
	require.NoError(t, err)

	messagingGroupEntryWithExtraDataRemovedBytes := messagingGroupEntryWithExtraDataRemoved.Encode()

	// This should be effectively equivalent to the original message entry above without extra data
	require.True(t, reflect.DeepEqual(messagingGroupEntryWithExtraDataRemoved, decodedMessagingGroupEntryWithExtraData))

	// The bytes should be the same up until the extra data segment of the bytes
	require.Equal(t, len(encodedIncludingExtraData), len(messagingGroupEntryWithExtraDataRemovedBytes)+len(encodedExtraData)-1)
	reflect.DeepEqual(encodedIncludingExtraData, append(messagingGroupEntryWithExtraDataRemovedBytes[:len(messagingGroupEntryWithExtraDataRemovedBytes)-1], encodedExtraData...))
}
