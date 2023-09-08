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

func TestIsProperlyFormedBlock(t *testing.T) {
	// Test nil block
	{
		require.False(t, isProperlyFormedBlock(nil))
	}

	// Test zero height
	{
		block := block{height: 0, view: 1, blockHash: createDummyBlockHash(), qc: createDummyQC()}
		require.False(t, isProperlyFormedBlock(&block))
	}

	// Test zero view
	{
		block := block{height: 1, view: 0, blockHash: createDummyBlockHash(), qc: createDummyQC()}
		require.False(t, isProperlyFormedBlock(&block))
	}

	// Test nil block hash
	{
		block := block{height: 1, view: 1, blockHash: nil, qc: createDummyQC()}
		require.False(t, isProperlyFormedBlock(&block))
	}

	// Test nil QC
	{
		block := block{height: 1, view: 1, blockHash: createDummyBlockHash(), qc: nil}
		require.False(t, isProperlyFormedBlock(&block))
	}

	// Test valid block
	{
		require.True(t, isProperlyFormedBlock(createDummyBlock()))
	}
}

func TestIsProperlyFormedValidatorSet(t *testing.T) {
	// Test empty slice
	{
		require.False(t, isProperlyFormedValidatorSet([]Validator{}))
	}

	// Test nil validator
	{
		require.False(t, isProperlyFormedValidatorSet([]Validator{nil}))
	}

	// Test nil public key
	{
		validator := validator{publicKey: nil, stakeAmount: uint256.NewInt().SetUint64(1)}
		require.False(t, isProperlyFormedValidatorSet([]Validator{&validator}))
	}

	// Test nil stake amount
	{
		validator := validator{publicKey: createDummyBLSPublicKey(), stakeAmount: nil}
		require.False(t, isProperlyFormedValidatorSet([]Validator{&validator}))
	}

	// Test zero stake amount
	{
		validator := validator{publicKey: createDummyBLSPublicKey(), stakeAmount: uint256.NewInt()}
		require.False(t, isProperlyFormedValidatorSet([]Validator{&validator}))
	}

	// Test valid validator
	{
		validator := validator{publicKey: createDummyBLSPublicKey(), stakeAmount: uint256.NewInt().SetUint64(1)}
		require.True(t, isProperlyFormedValidatorSet([]Validator{&validator}))
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
	return collections.Transform(validators, func(v *validator) Validator {
		return v
	})
}

func createDummyBlock() *block {
	return &block{
		blockHash: createDummyBlockHash(),
		view:      1,
		height:    1,
		qc:        createDummyQC(),
	}
}

func createDummyVoteMessage(view uint64) *voteMessage {
	return &voteMessage{
		blockHash: createDummyBlockHash(),
		view:      view,
		publicKey: createDummyBLSPublicKey(),
		signature: createDummyBLSSignature(),
	}
}

func createDummyTimeoutMessage(view uint64) *timeoutMessage {
	return &timeoutMessage{
		highQC:    createDummyQC(),
		view:      view,
		publicKey: createDummyBLSPublicKey(),
		signature: createDummyBLSSignature(),
	}
}

func createDummyQC() *quorumCertificate {
	return &quorumCertificate{
		blockHash:           createDummyBlockHash(),
		view:                1,
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
