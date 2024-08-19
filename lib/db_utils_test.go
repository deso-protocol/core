package lib

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var expectedBlockHeaderVersion1 = &MsgDeSoHeader{
	Version: 1,
	PrevBlockHash: &BlockHash{
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
		0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21,
		0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31,
		0x32, 0x33,
	},
	TransactionMerkleRoot: &BlockHash{
		0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43,
		0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50, 0x51, 0x52, 0x53,
		0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x60, 0x61, 0x62, 0x63,
		0x64, 0x65,
	},
	// Use full uint64 values to make sure serialization and de-serialization work
	TstampNanoSecs: SecondsToNanoSeconds(1678943210),
	Height:         uint64(1321012345),
	Nonce:          uint64(12345678901234),
	ExtraNonce:     uint64(101234123456789),
}

// Check that all state db prefixes have been correctly mapped to DeSoEncoder types via StatePrefixToDeSoEncoder
func TestStatePrefixToDeSoEncoder(t *testing.T) {
	for prefixByte, isState := range StatePrefixes.StatePrefixesMap {
		prefix := []byte{prefixByte}
		isEncoder, encoder := StatePrefixToDeSoEncoder(prefix)
		isCoreState := isCoreStateKey(prefix)
		if isState || isCoreState {
			if isEncoder && encoder == nil {
				t.Fatalf("State prefix (%v) mapped to an incorrect encoder, isEncoder is true and encoder is nil", prefix)
			} else if !isEncoder && encoder != nil {
				t.Fatalf("State prefix (%v) mapped to an incorrect encoder, isEncoder is false and encoder is not nil", prefix)
			}
		} else {
			if !isEncoder || (isEncoder && encoder != nil) {
				fmt.Printf("Is encoder: %v, encoder: %+v\n", isEncoder, encoder)
				t.Fatalf("Non-state prefix (%v) mapped to an incorrect encoder", prefix)
			}
		}
	}
}

func _GetTestBlockNode() *BlockNode {
	bs := BlockNode{}

	// Hash
	bs.Hash = &BlockHash{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
		0x30, 0x31,
	}

	// Height
	bs.Height = 123456789

	// DifficultyTarget
	bs.DifficultyTarget = &BlockHash{
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x30, 0x31,
	}

	// CumWork
	bs.CumWork = big.NewInt(5)

	// Header (make a copy)
	bs.Header = NewMessage(MsgTypeHeader).(*MsgDeSoHeader)
	headerBytes, _ := expectedBlockHeaderVersion1.ToBytes(false)
	bs.Header.FromBytes(headerBytes)

	// Status
	bs.Status = StatusBlockValidated

	return &bs
}

func GetTestBadgerDb() (_db *badger.DB, _dir string) {
	dir, err := os.MkdirTemp("", "badgerdb")
	if err != nil {
		log.Fatal(err)
	}

	// Open a badgerdb in a temporary directory.
	opts := DefaultBadgerOptions(dir)
	opts.Dir = dir
	opts.ValueDir = dir
	// Turn off logging for tests.
	opts.Logger = nil
	db, err := badger.Open(opts)
	if err != nil {
		log.Fatal(err)
	}

	return db, dir
}

func TestBlockNodeSerialize(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	bs := _GetTestBlockNode()

	serialized, err := SerializeBlockNode(bs)
	require.NoError(err)
	deserialized, err := DeserializeBlockNode(serialized)
	require.NoError(err)

	assert.Equal(bs, deserialized)
}

func TestBlockNodePutGet(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// Create a test db and clean up the files at the end.
	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	// Make a blockchain that looks as follows:
	// b1 - -> b2 -> b3
	//    \ -> b4
	// I.e. there's a side chain in there.
	b1 := _GetTestBlockNode()
	b1.Height = 0
	b2 := _GetTestBlockNode()
	b2.Hash[0] = 0x99 // Make the hash of b2 sort lexographically later than b4 for kicks.
	b2.Header.PrevBlockHash = b1.Hash
	b2.Height = 1
	b3 := _GetTestBlockNode()
	b3.Hash[0] = 0x03
	b3.Header.PrevBlockHash = b2.Hash
	b3.Height = 2
	b4 := _GetTestBlockNode()
	b4.Hash[0] = 0x04
	b4.Header.PrevBlockHash = b1.Hash
	b4.Height = 1

	err := PutHeightHashToNodeInfo(db, nil, b1, false /*bitcoinNodes*/, nil)
	require.NoError(err)

	err = PutHeightHashToNodeInfo(db, nil, b2, false /*bitcoinNodes*/, nil)
	require.NoError(err)

	err = PutHeightHashToNodeInfo(db, nil, b3, false /*bitcoinNodes*/, nil)
	require.NoError(err)

	err = PutHeightHashToNodeInfo(db, nil, b4, false /*bitcoinNodes*/, nil)
	require.NoError(err)

	blockIndex, err := GetBlockIndex(db, false /*bitcoinNodes*/, &DeSoTestnetParams)
	require.NoError(err)

	require.Len(blockIndex, 4)
	b1Ret, exists := blockIndex[*b1.Hash]
	require.True(exists, "b1 not found")

	b2Ret, exists := blockIndex[*b2.Hash]
	require.True(exists, "b2 not found")

	b3Ret, exists := blockIndex[*b3.Hash]
	require.True(exists, "b3 not found")

	b4Ret, exists := blockIndex[*b4.Hash]
	require.True(exists, "b4 not found")

	// Make sure the hashes all line up.
	require.Equal(b1.Hash[:], b1Ret.Hash[:])
	require.Equal(b2.Hash[:], b2Ret.Hash[:])
	require.Equal(b3.Hash[:], b3Ret.Hash[:])
	require.Equal(b4.Hash[:], b4Ret.Hash[:])

	// Make sure the nodes are connected properly.
	require.Nil(b1Ret.Parent)
	require.Equal(b2Ret.Parent, b1Ret)
	require.Equal(b3Ret.Parent, b2Ret)
	require.Equal(b4Ret.Parent, b1Ret)

	// Check that getting the best chain works.
	{
		bestChain, err := GetBestChain(b3Ret, blockIndex)
		require.NoError(err)
		require.Len(bestChain, 3)
		require.Equal(b1Ret, bestChain[0])
		require.Equal(b2Ret, bestChain[1])
		require.Equal(b3Ret, bestChain[2])
	}
}

func TestInitDbWithGenesisBlock(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// Create a test db and clean up the files at the end.
	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	err := InitDbWithDeSoGenesisBlock(&DeSoTestnetParams, db, nil, nil, nil)
	require.NoError(err)

	// Check the block index.
	blockIndex, err := GetBlockIndex(db, false /*bitcoinNodes*/, &DeSoTestnetParams)
	require.NoError(err)
	require.Len(blockIndex, 1)
	genesisHash := *MustDecodeHexBlockHash(DeSoTestnetParams.GenesisBlockHashHex)
	genesis, exists := blockIndex[genesisHash]
	require.True(exists, "genesis block not found in index")
	require.NotNil(genesis)
	require.Equal(&genesisHash, genesis.Hash)

	// Check the bestChain.
	bestChain, err := GetBestChain(genesis, blockIndex)
	require.NoError(err)
	require.Len(bestChain, 1)
	require.Equal(genesis, bestChain[0])
}

func TestPrivateMessages(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// Create a test db and clean up the files at the end.
	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	priv1, err := btcec.NewPrivateKey()
	require.NoError(err)
	pk1 := priv1.PubKey().SerializeCompressed()

	priv2, err := btcec.NewPrivateKey()
	require.NoError(err)
	pk2 := priv2.PubKey().SerializeCompressed()

	priv3, err := btcec.NewPrivateKey()
	require.NoError(err)
	pk3 := priv3.PubKey().SerializeCompressed()

	tstamp1 := uint64(1)
	tstamp2 := uint64(2)
	tstamp3 := uint64(12345)
	tstamp4 := uint64(time.Now().UnixNano())
	tstamp5 := uint64(time.Now().UnixNano())
	// Because M1 actually evaluates two consecutive time.Now().UnixNano() to the same number lol!
	if tstamp5 == tstamp4 {
		tstamp5 = tstamp4 + 1
	}

	message1Str := []byte("message1: abcdef")
	message2Str := []byte("message2: ghi")
	message3Str := []byte("message3: klmn\123\000\000\000_")
	message4Str := append([]byte("message4: "), RandomBytes(100)...)
	message5Str := append([]byte("message5: "), RandomBytes(123)...)

	// Define all the messages as they appear in the db.
	message1 := &MessageEntry{
		SenderPublicKey:                NewPublicKey(pk1),
		RecipientPublicKey:             NewPublicKey(pk2),
		EncryptedText:                  message1Str,
		TstampNanos:                    tstamp1,
		Version:                        1,
		SenderMessagingPublicKey:       NewPublicKey(pk1),
		SenderMessagingGroupKeyName:    BaseGroupKeyName(),
		RecipientMessagingPublicKey:    NewPublicKey(pk2),
		RecipientMessagingGroupKeyName: BaseGroupKeyName(),
	}
	message2 := &MessageEntry{
		SenderPublicKey:                NewPublicKey(pk2),
		RecipientPublicKey:             NewPublicKey(pk1),
		EncryptedText:                  message2Str,
		TstampNanos:                    tstamp2,
		Version:                        1,
		SenderMessagingPublicKey:       NewPublicKey(pk2),
		SenderMessagingGroupKeyName:    BaseGroupKeyName(),
		RecipientMessagingPublicKey:    NewPublicKey(pk1),
		RecipientMessagingGroupKeyName: BaseGroupKeyName(),
	}
	message3 := &MessageEntry{
		SenderPublicKey:                NewPublicKey(pk3),
		RecipientPublicKey:             NewPublicKey(pk1),
		EncryptedText:                  message3Str,
		TstampNanos:                    tstamp3,
		Version:                        1,
		SenderMessagingPublicKey:       NewPublicKey(pk3),
		SenderMessagingGroupKeyName:    BaseGroupKeyName(),
		RecipientMessagingPublicKey:    NewPublicKey(pk1),
		RecipientMessagingGroupKeyName: BaseGroupKeyName(),
	}
	message4 := &MessageEntry{
		SenderPublicKey:                NewPublicKey(pk2),
		RecipientPublicKey:             NewPublicKey(pk1),
		EncryptedText:                  message4Str,
		TstampNanos:                    tstamp4,
		Version:                        1,
		SenderMessagingPublicKey:       NewPublicKey(pk2),
		SenderMessagingGroupKeyName:    BaseGroupKeyName(),
		RecipientMessagingPublicKey:    NewPublicKey(pk1),
		RecipientMessagingGroupKeyName: BaseGroupKeyName(),
	}
	message5 := &MessageEntry{
		SenderPublicKey:                NewPublicKey(pk1),
		RecipientPublicKey:             NewPublicKey(pk3),
		EncryptedText:                  message5Str,
		TstampNanos:                    tstamp5,
		Version:                        1,
		SenderMessagingPublicKey:       NewPublicKey(pk1),
		SenderMessagingGroupKeyName:    BaseGroupKeyName(),
		RecipientMessagingPublicKey:    NewPublicKey(pk3),
		RecipientMessagingGroupKeyName: BaseGroupKeyName(),
	}

	// pk1 -> pk2: message1Str, tstamp1
	require.NoError(DBPutMessageEntry(db, nil, 0, MessageKey{
		PublicKey:   *NewPublicKey(pk1),
		TstampNanos: tstamp1,
	}, message1, nil))
	// same message but also store for pk2
	require.NoError(DBPutMessageEntry(db, nil, 0, MessageKey{
		PublicKey:   *NewPublicKey(pk2),
		TstampNanos: tstamp1,
	}, message1, nil))

	// pk2 -> pk1: message2Str, tstamp2
	require.NoError(DBPutMessageEntry(db, nil, 0, MessageKey{
		PublicKey:   *NewPublicKey(pk2),
		TstampNanos: tstamp2,
	}, message2, nil))
	// same message but also store for pk1
	require.NoError(DBPutMessageEntry(db, nil, 0, MessageKey{
		PublicKey:   *NewPublicKey(pk1),
		TstampNanos: tstamp2,
	}, message2, nil))

	// pk3 -> pk1: message3Str, tstamp3
	require.NoError(DBPutMessageEntry(db, nil, 0, MessageKey{
		PublicKey:   *NewPublicKey(pk3),
		TstampNanos: tstamp3,
	}, message3, nil))
	// same message but also store for pk1
	require.NoError(DBPutMessageEntry(db, nil, 0, MessageKey{
		PublicKey:   *NewPublicKey(pk1),
		TstampNanos: tstamp3,
	}, message3, nil))

	// pk2 -> pk1: message4Str, tstamp4
	require.NoError(DBPutMessageEntry(db, nil, 0, MessageKey{
		PublicKey:   *NewPublicKey(pk2),
		TstampNanos: tstamp4,
	}, message4, nil))
	// same message but also store for pk1
	require.NoError(DBPutMessageEntry(db, nil, 0, MessageKey{
		PublicKey:   *NewPublicKey(pk1),
		TstampNanos: tstamp4,
	}, message4, nil))

	// pk1 -> pk3: message5Str, tstamp5
	require.NoError(DBPutMessageEntry(db, nil, 0, MessageKey{
		PublicKey:   *NewPublicKey(pk1),
		TstampNanos: tstamp5,
	}, message5, nil))
	// same message but also store for pk3
	require.NoError(DBPutMessageEntry(db, nil, 0, MessageKey{
		PublicKey:   *NewPublicKey(pk3),
		TstampNanos: tstamp5,
	}, message5, nil))

	// Fetch message3 directly using both public keys.
	{
		msg := DBGetMessageEntry(db, nil, pk3, tstamp3)
		require.Equal(message3, msg)
	}
	{
		msg := DBGetMessageEntry(db, nil, pk1, tstamp3)
		require.Equal(message3, msg)
	}

	// Fetch all messages for pk1
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, pk1)
		require.NoError(err)

		require.Equal([]*MessageEntry{
			message1,
			message2,
			message3,
			message4,
			message5,
		}, messages)
	}

	// Fetch all messages for pk2
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, pk2)
		require.NoError(err)

		require.Equal([]*MessageEntry{
			message1,
			message2,
			message4,
		}, messages)
	}

	// Fetch all messages for pk3
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, pk3)
		require.NoError(err)

		require.Equal([]*MessageEntry{
			message3,
			message5,
		}, messages)
	}

	// Delete message3
	require.NoError(DBDeleteMessageEntryMappings(db, nil, pk1, tstamp3, nil, false))
	require.NoError(DBDeleteMessageEntryMappings(db, nil, pk3, tstamp3, nil, false))

	// Now all the messages returned should exclude message3
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, pk1)
		require.NoError(err)

		require.Equal([]*MessageEntry{
			message1,
			message2,
			message4,
			message5,
		}, messages)
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, pk2)
		require.NoError(err)

		require.Equal([]*MessageEntry{
			message1,
			message2,
			message4,
		}, messages)
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, pk3)
		require.NoError(err)

		require.Equal([]*MessageEntry{
			message5,
		}, messages)
	}

	// Delete all remaining messages
	// message1
	require.NoError(DBDeleteMessageEntryMappings(db, nil, pk2, tstamp1, nil, false))
	require.NoError(DBDeleteMessageEntryMappings(db, nil, pk1, tstamp1, nil, false))
	// message2
	require.NoError(DBDeleteMessageEntryMappings(db, nil, pk1, tstamp2, nil, false))
	require.NoError(DBDeleteMessageEntryMappings(db, nil, pk2, tstamp2, nil, false))
	// message4
	require.NoError(DBDeleteMessageEntryMappings(db, nil, pk2, tstamp4, nil, false))
	require.NoError(DBDeleteMessageEntryMappings(db, nil, pk1, tstamp4, nil, false))
	// message5
	require.NoError(DBDeleteMessageEntryMappings(db, nil, pk1, tstamp5, nil, false))
	require.NoError(DBDeleteMessageEntryMappings(db, nil, pk3, tstamp5, nil, false))

	// Now all public keys should have zero messages.
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, pk1)
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, pk2)
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, pk3)
		require.NoError(err)
		require.Equal(0, len(messages))
	}
}

func TestFollows(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// Create a test db and clean up the files at the end.
	db, _ := GetTestBadgerDb()
	defer CleanUpBadger(db)

	priv1, err := btcec.NewPrivateKey()
	require.NoError(err)
	pk1 := priv1.PubKey().SerializeCompressed()

	priv2, err := btcec.NewPrivateKey()
	require.NoError(err)
	pk2 := priv2.PubKey().SerializeCompressed()

	priv3, err := btcec.NewPrivateKey()
	require.NoError(err)
	pk3 := priv3.PubKey().SerializeCompressed()

	// Get the PKIDs for all the public keys
	pkid1 := DBGetPKIDEntryForPublicKey(db, nil, pk1).PKID
	pkid2 := DBGetPKIDEntryForPublicKey(db, nil, pk2).PKID
	pkid3 := DBGetPKIDEntryForPublicKey(db, nil, pk3).PKID

	// PK2 follows everyone. Make sure "get" works properly.
	require.Nil(DbGetFollowerToFollowedMapping(db, nil, pkid2, pkid1))
	require.NoError(DbPutFollowMappings(db, nil, pkid2, pkid1, nil))
	require.NotNil(DbGetFollowerToFollowedMapping(db, nil, pkid2, pkid1))
	require.Nil(DbGetFollowerToFollowedMapping(db, nil, pkid2, pkid3))
	require.NoError(DbPutFollowMappings(db, nil, pkid2, pkid3, nil))
	require.NotNil(DbGetFollowerToFollowedMapping(db, nil, pkid2, pkid3))

	// pkid3 only follows pkid1. Make sure "get" works properly.
	require.Nil(DbGetFollowerToFollowedMapping(db, nil, pkid3, pkid1))
	require.NoError(DbPutFollowMappings(db, nil, pkid3, pkid1, nil))
	require.NotNil(DbGetFollowerToFollowedMapping(db, nil, pkid3, pkid1))

	// Check PK1's followers.
	{
		pubKeys, err := DbGetPubKeysFollowingYou(db, nil, pk1)
		require.NoError(err)
		for i := 0; i < len(pubKeys); i++ {
			require.Contains([][]byte{pk2, pk3}, pubKeys[i])
		}
	}

	// Check PK1's follows.
	{
		pubKeys, err := DbGetPubKeysYouFollow(db, nil, pk1)
		require.NoError(err)
		require.Equal(len(pubKeys), 0)
	}

	// Check PK2's followers.
	{
		pubKeys, err := DbGetPubKeysFollowingYou(db, nil, pk2)
		require.NoError(err)
		require.Equal(len(pubKeys), 0)
	}

	// Check PK2's follows.
	{
		pubKeys, err := DbGetPubKeysYouFollow(db, nil, pk2)
		require.NoError(err)
		for i := 0; i < len(pubKeys); i++ {
			require.Contains([][]byte{pk1, pk3}, pubKeys[i])
		}
	}

	// Check PK3's followers.
	{
		pubKeys, err := DbGetPubKeysFollowingYou(db, nil, pk3)
		require.NoError(err)
		for i := 0; i < len(pubKeys); i++ {
			require.Contains([][]byte{pk2}, pubKeys[i])
		}
	}

	// Check PK3's follows.
	{
		pubKeys, err := DbGetPubKeysYouFollow(db, nil, pk3)
		require.NoError(err)
		for i := 0; i < len(pubKeys); i++ {
			require.Contains([][]byte{pk1, pk1}, pubKeys[i])
		}
	}

	// Delete PK2's follows.
	require.NoError(DbDeleteFollowMappings(db, nil, pkid2, pkid1, nil, false))
	require.NoError(DbDeleteFollowMappings(db, nil, pkid2, pkid3, nil, false))

	// Check PK2's follows were actually deleted.
	{
		pubKeys, err := DbGetPubKeysYouFollow(db, nil, pk2)
		require.NoError(err)
		require.Equal(len(pubKeys), 0)
	}
}

func TestEncodeUint16(t *testing.T) {
	for _, num := range []uint16{0, 5819, math.MaxUint16} {
		// Encode to bytes.
		encoded := EncodeUint16(num)
		require.Len(t, encoded, 2)

		// Decode from bytes.
		decoded := DecodeUint16(encoded)
		require.Equal(t, num, decoded)
	}
}

func TestEncodeUint8(t *testing.T) {
	for _, num := range []uint8{0, 95, math.MaxUint8} {
		// Encode to bytes.
		encoded := EncodeUint8(num)
		require.Len(t, encoded, 1)

		// Decode from bytes.
		decoded := DecodeUint8(encoded)
		require.Equal(t, num, decoded)

		// Read from bytes.
		rr := bytes.NewReader(encoded)
		decoded2, err := ReadUint8(rr)
		require.NoError(t, err)
		require.Equal(t, num, decoded2)
	}
}
