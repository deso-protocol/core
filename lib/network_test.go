package lib

import (
	"bytes"
	"encoding/hex"
	"github.com/holiman/uint256"
	"math/big"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"

	"github.com/btcsuite/btcd/wire"
	"github.com/bxcodec/faker"
	merkletree "github.com/deso-protocol/go-merkle-tree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var pkForTesting1 = []byte{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2}

var postHashForTesting1 = BlockHash{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}

var expectedVer = &MsgDeSoVersion{
	Version:              1,
	Services:             SFFullNodeDeprecated,
	TstampSecs:           2,
	Nonce:                uint64(0xffffffffffffffff),
	UserAgent:            "abcdef",
	StartBlockHeight:     4,
	MinFeeRateNanosPerKB: 10,
}

func TestVersionConversion(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	{
		data, err := expectedVer.ToBytes(false)
		assert.NoError(err)

		testVer := NewMessage(MsgTypeVersion)
		err = testVer.FromBytes(data)
		assert.NoError(err)

		assert.Equal(expectedVer, testVer)
	}

	assert.Equalf(7, reflect.TypeOf(expectedVer).Elem().NumField(),
		"Number of fields in VERSION message is different from expected. "+
			"Did you add a new field? If so, make sure the serialization code "+
			"works, add the new field to the test case, and fix this error.")
}

func TestVerack(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	networkType := NetworkType_MAINNET
	var buf bytes.Buffer

	nonce := uint64(12345678910)
	_, err := WriteMessage(&buf, &MsgDeSoVerack{Nonce: nonce}, networkType)
	require.NoError(err)
	verBytes := buf.Bytes()
	testMsg, _, err := ReadMessage(bytes.NewReader(verBytes),
		networkType)
	require.NoError(err)
	require.Equal(&MsgDeSoVerack{Nonce: nonce}, testMsg)
}

var expectedBlockHeader = &MsgDeSoHeader{
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
	TstampSecs: uint64(1678943210),
	Height:     uint64(1321012345),
	Nonce:      uint64(12345678901234),
	ExtraNonce: uint64(101234123456789),
}

func TestHeaderConversionAndReadWriteMessage(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require
	networkType := NetworkType_MAINNET

	{
		data, err := expectedBlockHeader.ToBytes(false)
		assert.NoError(err)

		testHdr := NewMessage(MsgTypeHeader)
		err = testHdr.FromBytes(data)
		assert.NoError(err)

		assert.Equal(expectedBlockHeader, testHdr)

		// Test read write.
		var buf bytes.Buffer
		payload, err := WriteMessage(&buf, expectedBlockHeader, networkType)
		assert.NoError(err)
		// Form the header from the payload and make sure it matches.
		hdrFromPayload := NewMessage(MsgTypeHeader).(*MsgDeSoHeader)
		assert.NotNil(hdrFromPayload, "NewMessage(MsgTypeHeader) should not return nil.")
		assert.Equal(uint64(0), hdrFromPayload.Nonce, "NewMessage(MsgTypeHeader) should initialize Nonce to empty byte slice.")
		err = hdrFromPayload.FromBytes(payload)
		assert.NoError(err)
		assert.Equal(expectedBlockHeader, hdrFromPayload)

		hdrBytes := buf.Bytes()
		testMsg, data, err := ReadMessage(bytes.NewReader(hdrBytes),
			networkType)
		assert.NoError(err)
		assert.Equal(expectedBlockHeader, testMsg)

		// Compute the header payload bytes so we can compare them.
		hdrPayload, err := expectedBlockHeader.ToBytes(false)
		assert.NoError(err)
		assert.Equal(hdrPayload, data)
	}

	assert.Equalf(7, reflect.TypeOf(expectedBlockHeader).Elem().NumField(),
		"Number of fields in HEADER message is different from expected. "+
			"Did you add a new field? If so, make sure the serialization code "+
			"works, add the new field to the test case, and fix this error.")
}

func TestGetHeadersSerialization(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	hash1 := expectedBlockHeader.PrevBlockHash
	hash2 := expectedBlockHeader.TransactionMerkleRoot

	getHeaders := &MsgDeSoGetHeaders{
		StopHash:     hash1,
		BlockLocator: []*BlockHash{hash1, hash2, hash1},
	}

	messageBytes, err := getHeaders.ToBytes(false)
	require.NoError(err)
	newMessage := &MsgDeSoGetHeaders{}
	err = newMessage.FromBytes(messageBytes)
	require.NoError(err)
	require.Equal(getHeaders, newMessage)
}

func TestHeaderBundleSerialization(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	hash1 := expectedBlockHeader.PrevBlockHash

	headerBundle := &MsgDeSoHeaderBundle{
		Headers:   []*MsgDeSoHeader{expectedBlockHeader, expectedBlockHeader},
		TipHash:   hash1,
		TipHeight: 12345,
	}

	messageBytes, err := headerBundle.ToBytes(false)
	require.NoError(err)
	newMessage := &MsgDeSoHeaderBundle{}
	err = newMessage.FromBytes(messageBytes)
	require.NoError(err)
	require.Equal(headerBundle, newMessage)
}

func TestEnumExtras(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// For all the enum strings we've defined, ensure we return
	// a non-nil NewMessage.
	for ii := uint8(1); !strings.Contains(MsgType(ii).String(), "UNRECOGNIZED"); ii++ {
		assert.NotNilf(NewMessage(MsgType(ii)), "String() defined for MsgType (%v) but NewMessage() returns nil.", MsgType(ii))
	}

	// For all the NewMessage() calls that return non-nil, ensure we have a String()
	for ii := uint8(1); NewMessage(MsgType(ii)) != nil; ii++ {
		hasString := !strings.Contains(MsgType(ii).String(), "UNRECOGNIZED")
		assert.Truef(hasString, "String() undefined for MsgType (%v) but NewMessage() returns non-nil.", MsgType(ii))
	}
}

func TestReadWrite(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	networkType := NetworkType_MAINNET
	var buf bytes.Buffer

	payload, err := WriteMessage(&buf, expectedVer, networkType)
	assert.NoError(err)
	// Form the version from the payload and make sure it matches.
	verFromPayload := NewMessage(MsgTypeVersion)
	assert.NotNil(verFromPayload, "NewMessage(MsgTypeVersion) should not return nil.")
	err = verFromPayload.FromBytes(payload)
	assert.NoError(err)
	assert.Equal(expectedVer, verFromPayload)

	verBytes := buf.Bytes()
	testMsg, data, err := ReadMessage(bytes.NewReader(verBytes),
		networkType)
	assert.NoError(err)
	assert.Equal(expectedVer, testMsg)

	// Compute the version payload bytes so we can compare them.
	verPayload, err := expectedVer.ToBytes(false)
	assert.NoError(err)
	assert.Equal(verPayload, data)

	// Incorrect network type should error.
	_, _, err = ReadMessage(bytes.NewReader(verBytes),
		NetworkType_TESTNET)
	assert.Error(err, "Incorrect network should fail.")

	// Payload too large should error.
	bigBytes := make([]byte, MaxMessagePayload*1.1)
	_, _, err = ReadMessage(bytes.NewReader(bigBytes),
		NetworkType_MAINNET)
	assert.Error(err, "Payload too large should fail.")
}

var expectedBlock = &MsgDeSoBlock{
	Header: expectedBlockHeader,
	Txns: []*MsgDeSoTxn{
		{
			TxInputs: []*DeSoInput{
				{
					TxID: *CopyBytesIntoBlockHash([]byte{
						// random bytes
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
						0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20,
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x31, 0x32,
					}),
					Index: 111,
				},
				{
					TxID: *CopyBytesIntoBlockHash([]byte{
						// random bytes
						0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50,
						0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70,
						0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x90,
						0x91, 0x92,
					}),
					Index: 222,
				},
			},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey: []byte{
						// random bytes
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x21, 0x22, 0x23,
					},
					AmountNanos: 333,
				},
				{
					PublicKey: []byte{
						// random bytes
						0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x10,
						0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x30,
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x21, 0x22, 0x23,
					},
					AmountNanos: 333,
				},
			},
			TxnMeta: &BlockRewardMetadataa{
				ExtraData: []byte{
					// random bytes
					0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x10,
					0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x90,
				},
			},
			// random bytes
			PublicKey: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
			ExtraData: map[string][]byte{"dummykey": {0x01, 0x02, 0x03, 0x04, 0x05}},
			//Signature: []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90},
		},
		{
			TxInputs: []*DeSoInput{
				{
					TxID: *CopyBytesIntoBlockHash([]byte{
						// random bytes
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20,
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
						0x31, 0x32,
					}),
					Index: 111,
				},
				{
					TxID: *CopyBytesIntoBlockHash([]byte{
						// random bytes
						0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70,
						0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50,
						0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x90,
						0x91, 0x92,
					}),
					Index: 222,
				},
			},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey: []byte{
						// random bytes
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x21, 0x22, 0x23,
					},
					AmountNanos: 333,
				},
				{
					PublicKey: []byte{
						// random bytes
						0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x30,
						0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x10,
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x21, 0x22, 0x23,
					},
					AmountNanos: 333,
				},
			},
			TxnMeta: &BlockRewardMetadataa{
				ExtraData: []byte{
					// random bytes
					0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x90,
					0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x10,
				},
			},
			// random bytes
			PublicKey: []byte{0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x99},
			//Signature: []byte{0x50, 0x60, 0x70, 0x80, 0x90, 0x10, 0x20, 0x30, 0x40},
		},
	},

	BlockProducerInfo: &BlockProducerInfo{
		PublicKey: []byte{
			// random bytes
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x30,
			0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x10,
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
			0x21, 0x22, 0x23,
		},
	},
}

var expectedV0Header = &MsgDeSoHeader{
	Version: 0,
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
	TstampSecs: uint64(0x70717273),
	Height:     uint64(99999),
	Nonce:      uint64(123456),
}

func TestBlockSerialize(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// Add a signature to the block
	priv, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	expectedBlock.BlockProducerInfo.Signature, err = priv.Sign([]byte{0x01, 0x02, 0x03})
	require.NoError(err)

	data, err := expectedBlock.ToBytes(false)
	require.NoError(err)

	testBlock := NewMessage(MsgTypeBlock).(*MsgDeSoBlock)
	err = testBlock.FromBytes(data)
	require.NoError(err)

	assert.Equal(*expectedBlock, *testBlock)
}

func TestBlockSerializeNoBlockProducerInfo(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// Add a signature to the block
	blockWithoutProducerInfo := *expectedBlock
	blockWithoutProducerInfo.BlockProducerInfo = nil

	data, err := blockWithoutProducerInfo.ToBytes(false)
	require.NoError(err)

	testBlock := NewMessage(MsgTypeBlock).(*MsgDeSoBlock)
	err = testBlock.FromBytes(data)
	require.NoError(err)

	assert.Equal(blockWithoutProducerInfo, *testBlock)
}

func TestBlockRewardTransactionSerialize(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// Add a signature to the block
	priv, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	expectedBlock.BlockProducerInfo.Signature, err = priv.Sign([]byte{0x01, 0x02, 0x03})
	require.NoError(err)

	data, err := expectedBlock.Txns[0].ToBytes(false)
	require.NoError(err)

	testTxn := NewMessage(MsgTypeTxn).(*MsgDeSoTxn)
	err = testTxn.FromBytes(data)
	require.NoError(err)
	require.Equal(expectedBlock.Txns[0], testTxn)
}

func TestSerializeInv(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	invMsg := &MsgDeSoInv{
		InvList: []*InvVect{
			{
				Type: InvTypeBlock,
				Hash: BlockHash{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
			},
			{
				Type: InvTypeTx,
				Hash: BlockHash{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0},
			},
		},
		IsSyncResponse: true,
	}

	bb, err := invMsg.ToBytes(false)
	require.NoError(err)
	invMsgFromBuf := &MsgDeSoInv{}
	invMsgFromBuf.FromBytes(bb)
	require.Equal(*invMsg, *invMsgFromBuf)
}

func TestSerializeAddresses(t *testing.T) {
	require := require.New(t)

	addrs := &MsgDeSoAddr{
		AddrList: []*SingleAddr{
			{
				Timestamp: time.Unix(1000, 0),
				Services:  SFFullNodeDeprecated,
				IP:        []byte{0x01, 0x02, 0x03, 0x04},
				Port:      12345,
			},
			{
				Timestamp: time.Unix(100000, 0),
				Services:  0,
				IP:        []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
				Port:      54321,
			},
		},
	}

	bb, err := addrs.ToBytes(false)
	require.NoError(err)
	parsedAddrs := &MsgDeSoAddr{}
	err = parsedAddrs.FromBytes(bb)
	require.NoError(err)
	require.Equal(addrs, parsedAddrs)
}

func TestSerializeGetBlocks(t *testing.T) {
	require := require.New(t)

	msg := &MsgDeSoGetBlocks{
		HashList: []*BlockHash{
			{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
			{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0},
			{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0},
		},
	}

	bb, err := msg.ToBytes(false)
	require.NoError(err)
	parsedMsg := &MsgDeSoGetBlocks{}
	err = parsedMsg.FromBytes(bb)
	require.NoError(err)
	require.Equal(msg, parsedMsg)
}

func TestSerializePingPong(t *testing.T) {
	require := require.New(t)

	{
		msg := &MsgDeSoPing{
			Nonce: uint64(1234567891011),
		}

		bb, err := msg.ToBytes(false)
		require.NoError(err)
		parsedMsg := &MsgDeSoPing{}
		err = parsedMsg.FromBytes(bb)
		require.NoError(err)
		require.Equal(msg, parsedMsg)
	}
	{
		msg := &MsgDeSoPong{
			Nonce: uint64(1234567891011),
		}

		bb, err := msg.ToBytes(false)
		require.NoError(err)
		parsedMsg := &MsgDeSoPong{}
		err = parsedMsg.FromBytes(bb)
		require.NoError(err)
		require.Equal(msg, parsedMsg)
	}
}

func TestSerializeGetTransactions(t *testing.T) {
	require := require.New(t)

	msg := &MsgDeSoGetTransactions{
		HashList: []*BlockHash{
			{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
			{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0},
			{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0},
		},
	}

	bb, err := msg.ToBytes(false)
	require.NoError(err)
	parsedMsg := &MsgDeSoGetTransactions{}
	err = parsedMsg.FromBytes(bb)
	require.NoError(err)
	require.Equal(msg, parsedMsg)
}

func TestSerializeTransactionBundle(t *testing.T) {
	require := require.New(t)

	msg := &MsgDeSoTransactionBundle{
		Transactions: expectedBlock.Txns,
	}

	bb, err := msg.ToBytes(false)
	require.NoError(err)
	parsedMsg := &MsgDeSoTransactionBundle{}
	err = parsedMsg.FromBytes(bb)
	require.NoError(err)
	require.Equal(msg, parsedMsg)
}

func TestSerializeMempool(t *testing.T) {
	require := require.New(t)

	{
		msg := &MsgDeSoMempool{}
		networkType := NetworkType_MAINNET
		var buf bytes.Buffer
		_, err := WriteMessage(&buf, msg, networkType)
		require.NoError(err)
		verBytes := buf.Bytes()
		testMsg, _, err := ReadMessage(bytes.NewReader(verBytes),
			networkType)
		require.NoError(err)
		require.Equal(msg, testMsg)
	}
}

func TestSerializeGetAddr(t *testing.T) {
	require := require.New(t)

	{
		msg := &MsgDeSoGetAddr{}
		networkType := NetworkType_MAINNET
		var buf bytes.Buffer
		_, err := WriteMessage(&buf, msg, networkType)
		require.NoError(err)
		verBytes := buf.Bytes()
		testMsg, _, err := ReadMessage(bytes.NewReader(verBytes),
			networkType)
		require.NoError(err)
		require.Equal(msg, testMsg)
	}
}

func TestSerializeBitcoinExchange(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	bitcoinTxBytes, err := hex.DecodeString("0100000000010171bb05b9f14c063412df904395b4a53ba195b60e38db395f4857dcf801f4a07e0100000017160014187f260400f5fe38ad6d83f839ec19fd57e49d9ffdffffff01d0471f000000000017a91401a68eb55a152f2d12775c371a9cb2052df5fe3887024730440220077b9ad6612e491924516ceceb78d2667bca35e89f402718787b949144d0e0c0022014c503ece0f8c1a3b2dfc77e198ff90c3ef5932285b9697d83b298854838054d0121030e8c515e19a966e882f4c9dcb8f9d47e09de282d8b52364789df207468ed9405e7f50900")
	require.NoError(err)
	bitcoinTx := wire.MsgTx{}
	bitcoinTx.Deserialize(bytes.NewReader(bitcoinTxBytes))

	txMeta := &BitcoinExchangeMetadata{
		BitcoinTransaction: &bitcoinTx,
		BitcoinBlockHash:   &BlockHash{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
		BitcoinMerkleRoot:  &BlockHash{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0},
		BitcoinMerkleProof: []*merkletree.ProofPart{
			{
				IsRight: true,
				Hash:    []byte{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0},
			},
			{
				IsRight: true,
				Hash:    []byte{5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0},
			},
		},
	}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeBitcoinExchange)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(testMeta, txMeta)
}

func TestSerializePrivateMessage(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &PrivateMessageMetadata{
		RecipientPublicKey: pkForTesting1,
		EncryptedText:      []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		TimestampNanos:     uint64(1234578901234),
	}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypePrivateMessage)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(testMeta, txMeta)
}

func TestSerializeLike(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &LikeMetadata{LikedPostHash: &postHashForTesting1}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeLike)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(txMeta, testMeta)
}

func TestSerializeUnlike(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &LikeMetadata{
		LikedPostHash: &postHashForTesting1,
		IsUnlike:      true,
	}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeLike)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(txMeta, testMeta)
}

func TestSerializeFollow(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &FollowMetadata{FollowedPublicKey: pkForTesting1}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeFollow)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(txMeta, testMeta)
}

func TestSerializeUnfollow(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &FollowMetadata{
		FollowedPublicKey: pkForTesting1,
		IsUnfollow:        true,
	}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeFollow)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(testMeta, txMeta)
}

func TestSerializeSubmitPost(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &SubmitPostMetadata{
		PostHashToModify:         pkForTesting1,
		ParentStakeID:            pkForTesting1,
		Body:                     []byte("This is a body text"),
		CreatorBasisPoints:       10 * 100,
		StakeMultipleBasisPoints: 2 * 100 * 100,
		TimestampNanos:           uint64(1234567890123),
		IsHidden:                 true,
	}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeSubmitPost)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(testMeta, txMeta)
}

func TestSerializeUpdateProfile(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &UpdateProfileMetadata{
		ProfilePublicKey:            pkForTesting1,
		NewUsername:                 []byte("new username"),
		NewDescription:              []byte("new description"),
		NewProfilePic:               []byte("profile pic data"),
		NewCreatorBasisPoints:       10 * 100,
		NewStakeMultipleBasisPoints: 2 * 100 * 100,
	}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeUpdateProfile)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(testMeta, txMeta)
}

func TestSerializeCreatorCoin(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &CreatorCoinMetadataa{}
	txMeta.ProfilePublicKey = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01}
	faker.FakeData(&txMeta)

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeCreatorCoin)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(txMeta, testMeta)
}

func TestSerializeCreatorCoinTransfer(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &CreatorCoinTransferMetadataa{}
	txMeta.ProfilePublicKey = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02}
	faker.FakeData(&txMeta)

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeCreatorCoinTransfer)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(txMeta, testMeta)
}

func TestSerializeCreateNFT(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &CreateNFTMetadata{}
	txMeta.NFTPostHash = &BlockHash{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
	txMeta.NumCopies = uint64(100)
	txMeta.HasUnlockable = true
	txMeta.IsForSale = true
	txMeta.MinBidAmountNanos = 9876
	txMeta.NFTRoyaltyToCreatorBasisPoints = 1234
	txMeta.NFTRoyaltyToCoinBasisPoints = 4321

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeCreateNFT)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(txMeta, testMeta)
}

func TestSerializeUpdateNFT(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &UpdateNFTMetadata{}
	txMeta.NFTPostHash = &BlockHash{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
	txMeta.SerialNumber = uint64(99)
	txMeta.IsForSale = true
	txMeta.MinBidAmountNanos = 9876

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeUpdateNFT)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(txMeta, testMeta)
}

func TestSerializeAcceptNFTBid(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &AcceptNFTBidMetadata{}
	txMeta.NFTPostHash = &BlockHash{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
	txMeta.SerialNumber = uint64(99)
	txMeta.BidderPKID = PublicKeyToPKID([]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02})
	txMeta.BidAmountNanos = 999
	txMeta.BidderInputs = []*DeSoInput{
		{
			TxID: *CopyBytesIntoBlockHash([]byte{
				// random bytes
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20,
				0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
				0x31, 0x32,
			}),
			Index: 111,
		},
		{
			TxID: *CopyBytesIntoBlockHash([]byte{
				// random bytes
				0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50,
				0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70,
				0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x90,
				0x91, 0x92,
			}),
			Index: 222,
		},
	}
	txMeta.UnlockableText = []byte("accept nft bid")

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeAcceptNFTBid)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(txMeta, testMeta)
}

func TestSerializeNFTBid(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &NFTBidMetadata{}
	txMeta.NFTPostHash = &BlockHash{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
	txMeta.SerialNumber = uint64(99)
	txMeta.BidAmountNanos = uint64(123456789)

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeNFTBid)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(txMeta, testMeta)
}

func TestSerializeNFTTransfer(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &NFTTransferMetadata{}
	txMeta.NFTPostHash = &BlockHash{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
	txMeta.SerialNumber = uint64(99)
	txMeta.ReceiverPublicKey = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02}
	txMeta.UnlockableText = []byte("accept nft bid")

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeNFTTransfer)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(txMeta, testMeta)
}

func TestAcceptNFTTransfer(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &AcceptNFTTransferMetadata{}
	txMeta.NFTPostHash = &BlockHash{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
	txMeta.SerialNumber = uint64(99)

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeAcceptNFTTransfer)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(txMeta, testMeta)
}

func TestBurnNFT(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &BurnNFTMetadata{}
	txMeta.NFTPostHash = &BlockHash{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
	txMeta.SerialNumber = uint64(99)

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeBurnNFT)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(txMeta, testMeta)
}

func TestDAOCoin(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	{
		txMeta := &DAOCoinMetadata{}
		txMeta.ProfilePublicKey = []byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x00, 0x01, 0x02}
		txMeta.OperationType = DAOCoinOperationTypeMint
		txMeta.CoinsToMintNanos = *uint256.NewInt().SetUint64(100)

		data, err := txMeta.ToBytes(false)
		require.NoError(err)

		testMeta, err := NewTxnMetadata(TxnTypeDAOCoin)
		require.NoError(err)
		err = testMeta.FromBytes(data)
		require.NoError(err)
		require.Equal(txMeta, testMeta)
	}

	{
		txMeta := &DAOCoinMetadata{}
		txMeta.ProfilePublicKey = []byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x00, 0x01, 0x02}
		txMeta.OperationType = DAOCoinOperationTypeBurn
		txMeta.CoinsToBurnNanos = *uint256.NewInt().SetUint64(100)

		data, err := txMeta.ToBytes(false)
		require.NoError(err)

		testMeta, err := NewTxnMetadata(TxnTypeDAOCoin)
		require.NoError(err)
		err = testMeta.FromBytes(data)
		require.NoError(err)
		require.Equal(txMeta, testMeta)
	}

	{
		txMeta := &DAOCoinMetadata{}
		txMeta.ProfilePublicKey = []byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x00, 0x01, 0x02}
		txMeta.OperationType = DAOCoinOperationTypeDisableMinting

		data, err := txMeta.ToBytes(false)
		require.NoError(err)

		testMeta, err := NewTxnMetadata(TxnTypeDAOCoin)
		require.NoError(err)
		err = testMeta.FromBytes(data)
		require.NoError(err)
		require.Equal(txMeta, testMeta)
	}

	{
		txMeta := &DAOCoinMetadata{}
		txMeta.ProfilePublicKey = []byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x00, 0x01, 0x02}
		txMeta.OperationType = DAOCoinOperationTypeUpdateTransferRestrictionStatus
		txMeta.TransferRestrictionStatus = TransferRestrictionStatusProfileOwnerOnly

		data, err := txMeta.ToBytes(false)
		require.NoError(err)

		testMeta, err := NewTxnMetadata(TxnTypeDAOCoin)
		require.NoError(err)
		err = testMeta.FromBytes(data)
		require.NoError(err)
		require.Equal(txMeta, testMeta)
	}
}

func TestDAOCoinTransfer(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txMeta := &DAOCoinTransferMetadata{}
	txMeta.ProfilePublicKey = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02}
	txMeta.ReceiverPublicKey = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02}
	txMeta.DAOCoinToTransferNanos = *uint256.NewInt().SetUint64(100)

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := NewTxnMetadata(TxnTypeDAOCoinTransfer)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(txMeta, testMeta)
}

func TestMessagingKey(t *testing.T) {
	require := require.New(t)

	m0PrivBytes, _, err := Base58CheckDecode(m0Priv)
	require.NoError(err)

	privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), m0PrivBytes)
	hash := Sha256DoubleHash([]byte{0x00, 0x01})
	signature, err := privKey.Sign(hash[:])
	require.NoError(err)

	encrypted, err := EncryptBytesWithPublicKey(hash[:], pubKey.ToECDSA())
	require.NoError(err)

	keyName := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01,
	}

	txMeta := MessagingGroupMetadata{
		MessagingPublicKey:    m0PkBytes,
		MessagingGroupKeyName: keyName,
		GroupOwnerSignature:   signature.Serialize(),
		MessagingGroupMembers: []*MessagingGroupMember{},
	}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testTxMeta, err := NewTxnMetadata(TxnTypeMessagingGroup)
	require.NoError(err)
	err = testTxMeta.FromBytes(data)
	require.NoError(err)
	testData, err := testTxMeta.ToBytes(false)
	require.NoError(err)
	require.Equal(data, testData)

	txMeta.MessagingGroupMembers = append(txMeta.MessagingGroupMembers, &MessagingGroupMember{
		GroupMemberPublicKey: NewPublicKey(m1PkBytes),
		GroupMemberKeyName:   NewGroupKeyName(keyName),
		EncryptedKey:         encrypted,
	})
	txMeta.MessagingGroupMembers = append(txMeta.MessagingGroupMembers, &MessagingGroupMember{
		GroupMemberPublicKey: NewPublicKey(m2PkBytes),
		GroupMemberKeyName:   NewGroupKeyName(keyName),
		EncryptedKey:         encrypted,
	})
	data, err = txMeta.ToBytes(false)
	require.NoError(err)

	testTxMeta, err = NewTxnMetadata(TxnTypeMessagingGroup)
	require.NoError(err)
	err = testTxMeta.FromBytes(data)
	require.NoError(err)
	testData, err = testTxMeta.ToBytes(false)
	require.NoError(err)
	require.Equal(data, testData)
}

func TestDecodeHeaderVersion0(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	// This header was serialized on an old branch that does not incorporate the v1 changes
	headerHex := "0000000002030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162636465737271709f86010040e20100"
	headerBytes, err := hex.DecodeString(headerHex)
	require.NoError(err)
	v0Header := &MsgDeSoHeader{}
	v0Header.FromBytes(headerBytes)

	require.Equal(expectedV0Header, v0Header)

	// Serialize the expected header and verify the same hex is produced
	expectedBytes, err := expectedV0Header.ToBytes(false)
	require.NoError(err)

	require.Equal(expectedBytes, headerBytes)
}

func TestDecodeBlockVersion0(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	blockHex := "500000000002030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162636465737271709f86010040e2010002bd010201020304050607080910111213141516171819202122232425262728293031326f4142434445464748495061626364656667686970818283848586878889909192de0102010203040506070809102122232425262728293021222324252627282930212223cd02313233343536373839104142434445464748493021222324252627282930212223cd02011514919293949596979899107172737475767778799009112233445566778899010864756d6d796b657905010203040500ae010221222324252627282930111213141516171819200102030405060708091031326f6162636465666768697041424344454647484950818283848586878889909192de0102212223242526272829300102030405060708091021222324252627282930212223cd02414243444546474849303132333435363738391021222324252627282930212223cd020115147172737475767778799091929394959697989910095566778811223344990000"
	blockBytes, err := hex.DecodeString(blockHex)
	require.NoError(err)
	v0Block := &MsgDeSoBlock{}
	v0Block.FromBytes(blockBytes)

	expectedV0Block := *expectedBlock
	expectedV0Block.Header = expectedV0Header
	expectedV0Block.BlockProducerInfo = nil

	require.Equal(&expectedV0Block, v0Block)

	// Serialize the expected block and verify the same hex is produced
	expectedBytes, err := expectedV0Block.ToBytes(false)
	require.NoError(err)

	require.Equal(expectedBytes, blockBytes)
}

// This test will test determinism and correctness of TransactionSpendingLimit.ToMetamaskString().
func TestSpendingLimitMetamaskString(t *testing.T) {
	require := require.New(t)
	_ = require

	// Number of operations to choose from during tests. The following fields should reflect the upper bound on
	// the corresponding TransactionSpendingLimit fields.
	maxTxnType := 26
	maxCreatorCoinLimitOperation := 4
	maxDAOCoinLimitOperation := 6
	maxNFTLimitOperation := 7

	// Number of random operations to generate for each field.
	testOperationCount := 2

	// We test different configurations of TransactionSpendingLimit fields.
	// Generate a random GlobalDESOLimit field.
	_populateTotalDESOLimit := func() uint64 {
		return rand.Uint64()
	}
	// Generate a random TransactionCountLimitMap field.
	_populateTransactionCountLimitMap := func(operationCount int) map[TxnType]uint64 {
		operationMap := make(map[TxnType]uint64)

		var indexList []byte
		for ii := 0; ii < maxTxnType; ii++ {
			indexList = append(indexList, byte(ii))
		}
		rand.Shuffle(len(indexList), func(i, j int) {
			temp := indexList[i]
			indexList[i] = indexList[j]
			indexList[j] = temp
		})

		if operationCount > maxTxnType {
			operationCount = maxTxnType
		}
		for ii := 0; ii < operationCount; ii++ {
			txnTyp := TxnType(indexList[ii])
			operationMap[txnTyp] = rand.Uint64()
		}
		return operationMap
	}
	// Generate a random TransactionCountLimitMap field.
	_populateCreatorCoinOperationLimitMap := func(operationCount int) map[CreatorCoinOperationLimitKey]uint64 {
		operationMap := make(map[CreatorCoinOperationLimitKey]uint64)

		for ; operationCount > 0; operationCount-- {
			randomCreatorCoinOperationKey := CreatorCoinOperationLimitKey{
				CreatorPKID: *NewPKID(RandomBytes(int32(PublicKeyLenCompressed))),
				Operation:   CreatorCoinLimitOperation(uint8(rand.Int()%maxCreatorCoinLimitOperation + 1)),
			}
			operationMap[randomCreatorCoinOperationKey] = rand.Uint64()
		}
		return operationMap
	}
	// Generate a random DAOCoinOperationLimitMap field.
	_populateDAOCoinOperationLimitMap := func(operationCount int) map[DAOCoinOperationLimitKey]uint64 {
		operationMap := make(map[DAOCoinOperationLimitKey]uint64)

		for ; operationCount > 0; operationCount-- {
			randomDAOCoinOperationKey := DAOCoinOperationLimitKey{
				CreatorPKID: *NewPKID(RandomBytes(int32(PublicKeyLenCompressed))),
				Operation:   DAOCoinLimitOperation(uint8(rand.Int()%maxDAOCoinLimitOperation + 1)),
			}
			operationMap[randomDAOCoinOperationKey] = rand.Uint64()
		}
		return operationMap
	}
	// Generate a random NFTOperationLimitMap field.
	_populateNFTOperationLimitKey := func(operationCount int) map[NFTOperationLimitKey]uint64 {
		operationMap := make(map[NFTOperationLimitKey]uint64)

		for ; operationCount > 0; operationCount-- {
			randomNFTOperationKey := NFTOperationLimitKey{
				BlockHash:    *NewBlockHash(RandomBytes(HashSizeBytes)),
				SerialNumber: rand.Uint64(),
				Operation:    NFTLimitOperation(uint8(rand.Int()%maxNFTLimitOperation + 1)),
			}
			operationMap[randomNFTOperationKey] = rand.Uint64()
		}
		return operationMap
	}
	// Generate a random DAOCoinLimitOrderLimitMap field.
	_populateDAOCoinLimitOrderLimitMap := func(operationCount int) map[DAOCoinLimitOrderLimitKey]uint64 {
		operationMap := make(map[DAOCoinLimitOrderLimitKey]uint64)

		for ; operationCount > 0; operationCount-- {
			randomDAOLimitOperation := DAOCoinLimitOrderLimitKey{
				BuyingDAOCoinCreatorPKID:  *NewPKID(RandomBytes(int32(PublicKeyLenCompressed))),
				SellingDAOCoinCreatorPKID: *NewPKID(RandomBytes(int32(PublicKeyLenCompressed))),
			}
			operationMap[randomDAOLimitOperation] = rand.Uint64()
		}
		return operationMap
	}

	// Test encoding of all possible combinations of TransactionSpendingLimit fields.
	_runTestOnSpendingLimit := func(spendingLimit *TransactionSpendingLimit, params *DeSoParams) bool {
		return spendingLimit.ToMetamaskString(params) == spendingLimit.ToMetamaskString(params)
	}

	// Do the binomial sum trick 2^n = \sum^n_{i=0} (n choose i)
	for ii := 0; ii < 1<<(reflect.ValueOf(TransactionSpendingLimit{}).Type().NumField()); ii++ {
		spendingLimit := TransactionSpendingLimit{}
		if ii&(1<<0) > 0 {
			spendingLimit.GlobalDESOLimit = _populateTotalDESOLimit()
		}
		if ii&(1<<1) > 0 {
			spendingLimit.TransactionCountLimitMap = _populateTransactionCountLimitMap(testOperationCount)
		}
		if ii&(1<<2) > 0 {
			spendingLimit.CreatorCoinOperationLimitMap = _populateCreatorCoinOperationLimitMap(testOperationCount)
		}
		if ii&(1<<3) > 0 {
			spendingLimit.DAOCoinOperationLimitMap = _populateDAOCoinOperationLimitMap(testOperationCount)
		}
		if ii&(1<<4) > 0 {
			spendingLimit.NFTOperationLimitMap = _populateNFTOperationLimitKey(testOperationCount)
		}
		if ii&(1<<5) > 0 {
			spendingLimit.DAOCoinLimitOrderLimitMap = _populateDAOCoinLimitOrderLimitMap(testOperationCount)
		}
		// Make sure the encoding is deterministic.
		require.Equal(true, _runTestOnSpendingLimit(&spendingLimit, &DeSoTestnetParams))
		require.Equal(true, _runTestOnSpendingLimit(&spendingLimit, &DeSoMainnetParams))

		// Make sure the encoding contains all the spending limit fields
		_verifyEncodingCorrectness := func(tsl *TransactionSpendingLimit, params *DeSoParams) bool {
			encoding := spendingLimit.ToMetamaskString(params)
			if tsl.GlobalDESOLimit > 0 {
				if !strings.Contains(encoding, FormatScaledUint256AsDecimalString(
					big.NewInt(0).SetUint64(tsl.GlobalDESOLimit), big.NewInt(int64(NanosPerUnit)))) {
					return false
				}
			}
			if len(tsl.TransactionCountLimitMap) > 0 {
				for txnType, limit := range tsl.TransactionCountLimitMap {
					if !strings.Contains(encoding, txnType.String()) {
						return false
					}
					if !strings.Contains(encoding, strconv.FormatUint(limit, 10)) {
						return false
					}
				}
			}
			if len(tsl.CreatorCoinOperationLimitMap) > 0 {
				for limitKey, limit := range tsl.CreatorCoinOperationLimitMap {
					if !strings.Contains(encoding, Base58CheckEncode(limitKey.CreatorPKID.ToBytes(), false, params)) {
						return false
					}
					if !strings.Contains(encoding, limitKey.Operation.ToString()) {
						return false
					}
					if !strings.Contains(encoding, strconv.FormatUint(limit, 10)) {
						return false
					}
				}
			}
			if len(tsl.DAOCoinOperationLimitMap) > 0 {
				for limitKey, limit := range tsl.DAOCoinOperationLimitMap {
					if !strings.Contains(encoding, Base58CheckEncode(limitKey.CreatorPKID.ToBytes(), false, params)) {
						return false
					}
					if !strings.Contains(encoding, limitKey.Operation.ToString()) {
						return false
					}
					if !strings.Contains(encoding, strconv.FormatUint(limit, 10)) {
						return false
					}
				}
			}
			if len(tsl.NFTOperationLimitMap) > 0 {
				for limitKey, limit := range tsl.NFTOperationLimitMap {
					if !strings.Contains(encoding, limitKey.BlockHash.String()) {
						return false
					}
					if !strings.Contains(encoding, strconv.FormatUint(limitKey.SerialNumber, 10)) {
						return false
					}
					if !strings.Contains(encoding, limitKey.Operation.ToString()) {
						return false
					}
					if !strings.Contains(encoding, strconv.FormatUint(limit, 10)) {
						return false
					}
				}
			}
			if len(tsl.DAOCoinLimitOrderLimitMap) > 0 {
				for limitKey, limit := range tsl.DAOCoinLimitOrderLimitMap {
					if !strings.Contains(encoding, Base58CheckEncode(limitKey.BuyingDAOCoinCreatorPKID.ToBytes(), false, params)) {
						return false
					}
					if !strings.Contains(encoding, Base58CheckEncode(limitKey.SellingDAOCoinCreatorPKID.ToBytes(), false, params)) {
						return false
					}
					if !strings.Contains(encoding, strconv.FormatUint(limit, 10)) {
						return false
					}
				}
			}
			return true
		}
		require.Equal(true, _verifyEncodingCorrectness(&spendingLimit, &DeSoTestnetParams))
		require.Equal(true, _verifyEncodingCorrectness(&spendingLimit, &DeSoMainnetParams))
	}
}

// Test encoding of unlimited derived key spending limits.
func TestUnlimitedSpendingLimitMetamaskEncoding(t *testing.T) {
	require := require.New(t)

	// Set the blockheights for encoder migration.
	GlobalDeSoParams = DeSoTestnetParams
	GlobalDeSoParams.ForkHeights.DeSoUnlimitedDerivedKeysBlockHeight = 0
	for ii := range GlobalDeSoParams.EncoderMigrationHeightsList {
		GlobalDeSoParams.EncoderMigrationHeightsList[ii].Height = 0
	}

	// Encode the spending limit with just the IsUnlimited field.
	spendingLimit := &TransactionSpendingLimit{
		IsUnlimited: true,
	}

	// Test the spending limit encoding using the standard scheme.
	spendingLimitBytes, err := spendingLimit.ToBytes(1)
	require.NoError(err)
	require.Equal(true, reflect.DeepEqual(spendingLimitBytes, []byte{0, 0, 0, 0, 0, 0, 1, 0, 0, 0}))

	// Test the spending limit encoding using the metamask scheme.
	require.Equal(true, reflect.DeepEqual(
		"Spending limits on the derived key:\nUnlimited",
		spendingLimit.ToMetamaskString(&GlobalDeSoParams),
	))
}

// Verify that DeSoSignature.SerializeCompact correctly encodes the signature into compact format.
func TestDeSoSignature_SerializeCompact(t *testing.T) {
	require := require.New(t)
	_ = require

	// Number of test cases. In each test case we generate a new signer private key.
	numTestCases := 100
	// Number of messages signed for each signer private key.
	numIterations := 10

	for ; numTestCases > 0; numTestCases-- {
		// Generate a random (private, public) keypair.
		privateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		publicKeyBytes := privateKey.PubKey().SerializeCompressed()

		for iter := 0; iter < numIterations; iter++ {
			// Generate a random message and sign it.
			message := RandomBytes(10)
			messageHash := Sha256DoubleHash(message)[:]
			desoSignature, err := SignRecoverable(messageHash, privateKey)
			require.NoError(err)

			// Verify that the compact signature is equal to what we serialized.
			signatureCompact, err := btcec.SignCompact(btcec.S256(), privateKey, messageHash, true)
			require.NoError(err)

			// Use the DeSoSignature.SerializeCompact encoding.
			signatureCompactCustom, err := desoSignature._btcecSerializeCompact()
			require.NoError(err)
			// Make sure the btcec and our custom encoding are identical.
			require.Equal(true, reflect.DeepEqual(signatureCompact, signatureCompactCustom))

			// Recover the public key from our custom encoding.
			recoveredPublicKey, _, err := btcec.RecoverCompact(btcec.S256(), signatureCompactCustom, messageHash)
			require.NoError(err)

			// Verify that the recovered public key matches the original public key.
			recoveredPublicKeyBytes := recoveredPublicKey.SerializeCompressed()
			require.Equal(true, reflect.DeepEqual(publicKeyBytes, recoveredPublicKeyBytes))
		}
	}
}
