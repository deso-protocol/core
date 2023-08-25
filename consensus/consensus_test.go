//go:build relic

package consensus

import (
	"testing"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestFastHotStuffInitialization(t *testing.T) {

	// Test initial status for newly constructed instance
	{
		fc := NewFastHotStuffConsensus()
		require.Equal(t, consensusStatusUninitialized, fc.status)
		require.Equal(t, fc.IsInitialized(), false)
		require.Equal(t, fc.IsRunning(), false)
		require.NotPanics(t, fc.Stop) // Calling Stop() on an uninitialized instance should be a no-op
	}

	// Test Init() function with invalid block construction cadence
	{
		fc := NewFastHotStuffConsensus()
		err := fc.Init(0, 1, createDummyBlock(), createDummyValidatorSet())
		require.Error(t, err)
	}

	// Test Init() function with invalid timeout duration
	{
		fc := NewFastHotStuffConsensus()
		err := fc.Init(1, 0, createDummyBlock(), createDummyValidatorSet())
		require.Error(t, err)
	}

	// Test Init() function with valid parameters
	{
		fc := NewFastHotStuffConsensus()
		err := fc.Init(1000000000, 100, createDummyBlock(), createDummyValidatorSet())
		require.NoError(t, err)

		require.Equal(t, consensusStatusNotRunning, fc.status)
		require.Equal(t, fc.IsInitialized(), true)
		require.Equal(t, fc.IsRunning(), false)

		require.NotPanics(t, fc.Stop) // Calling Stop() on an initialized instance should be a no-op

		require.Equal(t, fc.chainTip.GetBlockHash().GetValue(), createDummyBlockHash().GetValue())
	}
}

func createDummyValidatorSet() []Validator {
	validators := []*validator{
		{
			publicKey:   createDummyBLSPublicKey(),
			stakeAmount: uint256.NewInt().SetUint64(100),
		},
		{
			publicKey:   createDummyBLSPublicKey(),
			stakeAmount: uint256.NewInt().SetUint64(50),
		},
	}
	// Cast the slice of concrete structs []*validators to a slice of interfaces []Validator
	return collections.TransformSlice(validators, func(v *validator) Validator {
		return v
	})
}

func createDummyBlock() *block {
	return &block{
		blockHash: createDummyBlockHash(),
		view:      0,
		height:    0,
		qc:        createDummyQC(),
	}
}

func createDummyQC() *quorumCertificate {
	return &quorumCertificate{
		blockHash:           createDummyBlockHash(),
		view:                0,
		signersList:         bitset.NewBitset().FromBytes([]byte{0x3}),
		aggregatedSignature: createDummyBLSSignature(),
	}
}

func createDummyBLSSignature() *bls.Signature {
	blsPrivateKey, _ := bls.NewPrivateKey()
	blockHashValue := createDummyBlockHash().GetValue()
	blsSignature, _ := blsPrivateKey.Sign(blockHashValue[:])
	return blsSignature
}

func createDummyBLSPublicKey() *bls.PublicKey {
	blsPrivateKey, _ := bls.NewPrivateKey()
	return blsPrivateKey.PublicKey()
}

func createDummyBlockHash() *blockHash {
	return &blockHash{
		value: [32]byte{
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0xf,
			0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
			0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		},
	}
}
