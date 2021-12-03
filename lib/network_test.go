package lib

import (
	"bytes"
	"encoding/hex"
	"github.com/deso-protocol/core/network"
	"github.com/deso-protocol/core/types"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"

	"github.com/btcsuite/btcd/wire"
	"github.com/bxcodec/faker"
	merkletree "github.com/laser/go-merkle-tree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var pkForTesting1 = []byte{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2}

var postHashForTesting1 = types.BlockHash{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}

var expectedVer = &network.MsgDeSoVersion{
	Version:              1,
	Services:             network.SFFullNode,
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

		testVer := network.NewMessage(network.MsgTypeVersion)
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

	networkType := types.NetworkType_MAINNET
	var buf bytes.Buffer

	nonce := uint64(12345678910)
	_, err := network.WriteMessage(&buf, &network.MsgDeSoVerack{Nonce: nonce}, networkType)
	require.NoError(err)
	verBytes := buf.Bytes()
	testMsg, _, err := network.ReadMessage(bytes.NewReader(verBytes),
		networkType)
	require.NoError(err)
	require.Equal(&network.MsgDeSoVerack{Nonce: nonce}, testMsg)
}

var expectedBlockHeader = &types.MsgDeSoHeader{
	Version: 1,
	PrevBlockHash: &types.BlockHash{
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
		0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21,
		0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31,
		0x32, 0x33,
	},
	TransactionMerkleRoot: &types.BlockHash{
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
	networkType := types.NetworkType_MAINNET

	{
		data, err := expectedBlockHeader.ToBytes(false)
		assert.NoError(err)

		testHdr := network.NewMessage(network.MsgTypeHeader)
		err = testHdr.FromBytes(data)
		assert.NoError(err)

		assert.Equal(expectedBlockHeader, testHdr)

		// Test read write.
		var buf bytes.Buffer
		payload, err := network.WriteMessage(&buf, expectedBlockHeader, networkType)
		assert.NoError(err)
		// Form the header from the payload and make sure it matches.
		hdrFromPayload := network.NewMessage(network.MsgTypeHeader).(*types.MsgDeSoHeader)
		assert.NotNil(hdrFromPayload, "NewMessage(MsgTypeHeader) should not return nil.")
		assert.Equal(uint64(0), hdrFromPayload.Nonce, "NewMessage(MsgTypeHeader) should initialize Nonce to empty byte slice.")
		err = hdrFromPayload.FromBytes(payload)
		assert.NoError(err)
		assert.Equal(expectedBlockHeader, hdrFromPayload)

		hdrBytes := buf.Bytes()
		testMsg, data, err := network.ReadMessage(bytes.NewReader(hdrBytes),
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

	getHeaders := &network.MsgDeSoGetHeaders{
		StopHash:     hash1,
		BlockLocator: []*types.BlockHash{hash1, hash2, hash1},
	}

	messageBytes, err := getHeaders.ToBytes(false)
	require.NoError(err)
	newMessage := &network.MsgDeSoGetHeaders{}
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

	headerBundle := &network.MsgDeSoHeaderBundle{
		Headers:   []*types.MsgDeSoHeader{expectedBlockHeader, expectedBlockHeader},
		TipHash:   hash1,
		TipHeight: 12345,
	}

	messageBytes, err := headerBundle.ToBytes(false)
	require.NoError(err)
	newMessage := &network.MsgDeSoHeaderBundle{}
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
	for ii := uint8(1); !strings.Contains(network.MsgType(ii).String(), "UNRECOGNIZED"); ii++ {
		assert.NotNilf(network.NewMessage(network.MsgType(ii)), "String() defined for MsgType (%v) but NewMessage() returns nil.", network.MsgType(ii))
	}

	// For all the NewMessage() calls that return non-nil, ensure we have a String()
	for ii := uint8(1); network.NewMessage(network.MsgType(ii)) != nil; ii++ {
		hasString := !strings.Contains(network.MsgType(ii).String(), "UNRECOGNIZED")
		assert.Truef(hasString, "String() undefined for MsgType (%v) but NewMessage() returns non-nil.", network.MsgType(ii))
	}
}

func TestReadWrite(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	networkType := types.NetworkType_MAINNET
	var buf bytes.Buffer

	payload, err := network.WriteMessage(&buf, expectedVer, networkType)
	assert.NoError(err)
	// Form the version from the payload and make sure it matches.
	verFromPayload := network.NewMessage(network.MsgTypeVersion)
	assert.NotNil(verFromPayload, "NewMessage(MsgTypeVersion) should not return nil.")
	err = verFromPayload.FromBytes(payload)
	assert.NoError(err)
	assert.Equal(expectedVer, verFromPayload)

	verBytes := buf.Bytes()
	testMsg, data, err := network.ReadMessage(bytes.NewReader(verBytes),
		networkType)
	assert.NoError(err)
	assert.Equal(expectedVer, testMsg)

	// Compute the version payload bytes so we can compare them.
	verPayload, err := expectedVer.ToBytes(false)
	assert.NoError(err)
	assert.Equal(verPayload, data)

	// Incorrect network type should error.
	_, _, err = network.ReadMessage(bytes.NewReader(verBytes),
		types.NetworkType_TESTNET)
	assert.Error(err, "Incorrect network should fail.")

	// Payload too large should error.
	bigBytes := make([]byte, network.MaxMessagePayload*1.1)
	_, _, err = network.ReadMessage(bytes.NewReader(bigBytes),
		types.NetworkType_MAINNET)
	assert.Error(err, "Payload too large should fail.")
}

var expectedBlock = &network.MsgDeSoBlock{
	Header: expectedBlockHeader,
	Txns: []*network.MsgDeSoTxn{
		{
			TxInputs: []*network.DeSoInput{
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
			TxOutputs: []*network.DeSoOutput{
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
			TxnMeta: &network.BlockRewardMetadataa{
				ExtraData: []byte{
					// random bytes
					0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x10,
					0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x90,
				},
			},
			// random bytes
			PublicKey: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
			ExtraData: map[string][]byte{"dummykey": []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
			//Signature: []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90},
		},
		{
			TxInputs: []*network.DeSoInput{
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
			TxOutputs: []*network.DeSoOutput{
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
			TxnMeta: &network.BlockRewardMetadataa{
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

	BlockProducerInfo: &network.BlockProducerInfo{
		PublicKey: []byte{
			// random bytes
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x30,
			0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x10,
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
			0x21, 0x22, 0x23,
		},
	},
}

var expectedV0Header = &types.MsgDeSoHeader{
	Version: 0,
	PrevBlockHash: &types.BlockHash{
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
		0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21,
		0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31,
		0x32, 0x33,
	},
	TransactionMerkleRoot: &types.BlockHash{
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

	testBlock := network.NewMessage(network.MsgTypeBlock).(*network.MsgDeSoBlock)
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

	testBlock := network.NewMessage(network.MsgTypeBlock).(*network.MsgDeSoBlock)
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

	testTxn := network.NewMessage(network.MsgTypeTxn).(*network.MsgDeSoTxn)
	err = testTxn.FromBytes(data)
	require.NoError(err)
	require.Equal(expectedBlock.Txns[0], testTxn)
}

func TestSerializeInv(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	invMsg := &network.MsgDeSoInv{
		InvList: []*network.InvVect{
			{
				Type: network.InvTypeBlock,
				Hash: types.BlockHash{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
			},
			{
				Type: network.InvTypeTx,
				Hash: types.BlockHash{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0},
			},
		},
		IsSyncResponse: true,
	}

	bb, err := invMsg.ToBytes(false)
	require.NoError(err)
	invMsgFromBuf := &network.MsgDeSoInv{}
	invMsgFromBuf.FromBytes(bb)
	require.Equal(*invMsg, *invMsgFromBuf)
}

func TestSerializeAddresses(t *testing.T) {
	require := require.New(t)

	addrs := &network.MsgDeSoAddr{
		AddrList: []*network.SingleAddr{
			{
				Timestamp: time.Unix(1000, 0),
				Services:  network.SFFullNode,
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
	parsedAddrs := &network.MsgDeSoAddr{}
	err = parsedAddrs.FromBytes(bb)
	require.NoError(err)
	require.Equal(addrs, parsedAddrs)
}

func TestSerializeGetBlocks(t *testing.T) {
	require := require.New(t)

	msg := &network.MsgDeSoGetBlocks{
		HashList: []*types.BlockHash{
			{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
			{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0},
			{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0},
		},
	}

	bb, err := msg.ToBytes(false)
	require.NoError(err)
	parsedMsg := &network.MsgDeSoGetBlocks{}
	err = parsedMsg.FromBytes(bb)
	require.NoError(err)
	require.Equal(msg, parsedMsg)
}

func TestSerializePingPong(t *testing.T) {
	require := require.New(t)

	{
		msg := &network.MsgDeSoPing{
			Nonce: uint64(1234567891011),
		}

		bb, err := msg.ToBytes(false)
		require.NoError(err)
		parsedMsg := &network.MsgDeSoPing{}
		err = parsedMsg.FromBytes(bb)
		require.NoError(err)
		require.Equal(msg, parsedMsg)
	}
	{
		msg := &network.MsgDeSoPong{
			Nonce: uint64(1234567891011),
		}

		bb, err := msg.ToBytes(false)
		require.NoError(err)
		parsedMsg := &network.MsgDeSoPong{}
		err = parsedMsg.FromBytes(bb)
		require.NoError(err)
		require.Equal(msg, parsedMsg)
	}
}

func TestSerializeGetTransactions(t *testing.T) {
	require := require.New(t)

	msg := &network.MsgDeSoGetTransactions{
		HashList: []*types.BlockHash{
			{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
			{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0},
			{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0},
		},
	}

	bb, err := msg.ToBytes(false)
	require.NoError(err)
	parsedMsg := &network.MsgDeSoGetTransactions{}
	err = parsedMsg.FromBytes(bb)
	require.NoError(err)
	require.Equal(msg, parsedMsg)
}

func TestSerializeTransactionBundle(t *testing.T) {
	require := require.New(t)

	msg := &network.MsgDeSoTransactionBundle{
		Transactions: expectedBlock.Txns,
	}

	bb, err := msg.ToBytes(false)
	require.NoError(err)
	parsedMsg := &network.MsgDeSoTransactionBundle{}
	err = parsedMsg.FromBytes(bb)
	require.NoError(err)
	require.Equal(msg, parsedMsg)
}

func TestSerializeMempool(t *testing.T) {
	require := require.New(t)

	{
		msg := &network.MsgDeSoMempool{}
		networkType := types.NetworkType_MAINNET
		var buf bytes.Buffer
		_, err := network.WriteMessage(&buf, msg, networkType)
		require.NoError(err)
		verBytes := buf.Bytes()
		testMsg, _, err := network.ReadMessage(bytes.NewReader(verBytes),
			networkType)
		require.NoError(err)
		require.Equal(msg, testMsg)
	}
}

func TestSerializeGetAddr(t *testing.T) {
	require := require.New(t)

	{
		msg := &network.MsgDeSoGetAddr{}
		networkType := types.NetworkType_MAINNET
		var buf bytes.Buffer
		_, err := network.WriteMessage(&buf, msg, networkType)
		require.NoError(err)
		verBytes := buf.Bytes()
		testMsg, _, err := network.ReadMessage(bytes.NewReader(verBytes),
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

	txMeta := &network.BitcoinExchangeMetadata{
		BitcoinTransaction: &bitcoinTx,
		BitcoinBlockHash:   &types.BlockHash{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
		BitcoinMerkleRoot:  &types.BlockHash{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0},
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

	testMeta, err := network.NewTxnMetadata(network.TxnTypeBitcoinExchange)
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

	txMeta := &network.PrivateMessageMetadata{
		RecipientPublicKey: pkForTesting1,
		EncryptedText:      []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		TimestampNanos:     uint64(1234578901234),
	}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := network.NewTxnMetadata(network.TxnTypePrivateMessage)
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

	txMeta := &network.LikeMetadata{LikedPostHash: &postHashForTesting1}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := network.NewTxnMetadata(network.TxnTypeLike)
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

	txMeta := &network.LikeMetadata{
		LikedPostHash: &postHashForTesting1,
		IsUnlike:      true,
	}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := network.NewTxnMetadata(network.TxnTypeLike)
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

	txMeta := &network.FollowMetadata{FollowedPublicKey: pkForTesting1}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := network.NewTxnMetadata(network.TxnTypeFollow)
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

	txMeta := &network.FollowMetadata{
		FollowedPublicKey: pkForTesting1,
		IsUnfollow:        true,
	}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := network.NewTxnMetadata(network.TxnTypeFollow)
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

	txMeta := &network.SubmitPostMetadata{
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

	testMeta, err := network.NewTxnMetadata(network.TxnTypeSubmitPost)
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

	txMeta := &network.UpdateProfileMetadata{
		ProfilePublicKey:            pkForTesting1,
		NewUsername:                 []byte("new username"),
		NewDescription:              []byte("new description"),
		NewProfilePic:               []byte("profile pic data"),
		NewCreatorBasisPoints:       10 * 100,
		NewStakeMultipleBasisPoints: 2 * 100 * 100,
	}

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := network.NewTxnMetadata(network.TxnTypeUpdateProfile)
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

	txMeta := &network.CreatorCoinMetadataa{}
	txMeta.ProfilePublicKey = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01}
	faker.FakeData(&txMeta)

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := network.NewTxnMetadata(network.TxnTypeCreatorCoin)
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

	txMeta := &network.CreatorCoinTransferMetadataa{}
	txMeta.ProfilePublicKey = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02}
	faker.FakeData(&txMeta)

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := network.NewTxnMetadata(network.TxnTypeCreatorCoinTransfer)
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

	txMeta := &network.CreateNFTMetadata{}
	txMeta.NFTPostHash = &types.BlockHash{
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

	testMeta, err := network.NewTxnMetadata(network.TxnTypeCreateNFT)
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

	txMeta := &network.UpdateNFTMetadata{}
	txMeta.NFTPostHash = &types.BlockHash{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
	txMeta.SerialNumber = uint64(99)
	txMeta.IsForSale = true
	txMeta.MinBidAmountNanos = 9876

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := network.NewTxnMetadata(network.TxnTypeUpdateNFT)
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

	txMeta := &network.AcceptNFTBidMetadata{}
	txMeta.NFTPostHash = &types.BlockHash{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
	txMeta.SerialNumber = uint64(99)
	txMeta.BidderPKID = types.PublicKeyToPKID([]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x00, 0x01, 0x02})
	txMeta.BidAmountNanos = 999
	txMeta.BidderInputs = []*network.DeSoInput{
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

	testMeta, err := network.NewTxnMetadata(network.TxnTypeAcceptNFTBid)
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

	txMeta := &network.NFTBidMetadata{}
	txMeta.NFTPostHash = &types.BlockHash{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
	txMeta.SerialNumber = uint64(99)
	txMeta.BidAmountNanos = uint64(123456789)

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := network.NewTxnMetadata(network.TxnTypeNFTBid)
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

	txMeta := &network.NFTTransferMetadata{}
	txMeta.NFTPostHash = &types.BlockHash{
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

	testMeta, err := network.NewTxnMetadata(network.TxnTypeNFTTransfer)
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

	txMeta := &network.AcceptNFTTransferMetadata{}
	txMeta.NFTPostHash = &types.BlockHash{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
	txMeta.SerialNumber = uint64(99)

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := network.NewTxnMetadata(network.TxnTypeAcceptNFTTransfer)
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

	txMeta := &network.BurnNFTMetadata{}
	txMeta.NFTPostHash = &types.BlockHash{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
	txMeta.SerialNumber = uint64(99)

	data, err := txMeta.ToBytes(false)
	require.NoError(err)

	testMeta, err := network.NewTxnMetadata(network.TxnTypeBurnNFT)
	require.NoError(err)
	err = testMeta.FromBytes(data)
	require.NoError(err)
	require.Equal(txMeta, testMeta)
}

func TestDecodeHeaderVersion0(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	// This header was serialized on an old branch that does not incorporate the v1 changes
	headerHex := "0000000002030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162636465737271709f86010040e20100"
	headerBytes, err := hex.DecodeString(headerHex)
	require.NoError(err)
	v0Header := &types.MsgDeSoHeader{}
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
	v0Block := &network.MsgDeSoBlock{}
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
