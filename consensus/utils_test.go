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
		block := block{height: 0, view: 2, blockHash: createDummyBlockHash(), qc: createDummyQC(1)}
		require.False(t, isProperlyFormedBlock(&block))
	}

	// Test zero view
	{
		block := block{height: 1, view: 0, blockHash: createDummyBlockHash(), qc: createDummyQC(0)}
		require.False(t, isProperlyFormedBlock(&block))
	}

	// Test nil block hash
	{
		block := block{height: 1, view: 1, blockHash: nil, qc: createDummyQC(0)}
		require.False(t, isProperlyFormedBlock(&block))
	}

	// Test nil QC
	{
		block := block{height: 1, view: 1, blockHash: createDummyBlockHash(), qc: nil}
		require.False(t, isProperlyFormedBlock(&block))
	}

	// Test valid block
	{
		require.True(t, isProperlyFormedBlock(createDummyBlock(2)))
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

func TestIsProperlyFormedVote(t *testing.T) {
	// Test nil value
	{
		require.False(t, isProperlyFormedVote(nil))
	}

	// Test zero-value view
	{
		vote := createDummyVoteMessage(0)
		require.False(t, isProperlyFormedVote(vote))
	}

	// Test nil block hash
	{
		vote := createDummyVoteMessage(1)
		vote.blockHash = nil
		require.False(t, isProperlyFormedVote(vote))
	}

	// Test nil public key
	{
		vote := createDummyVoteMessage(1)
		vote.publicKey = nil
		require.False(t, isProperlyFormedVote(vote))
	}

	// Test nil signature
	{
		vote := createDummyVoteMessage(1)
		vote.signature = nil
		require.False(t, isProperlyFormedVote(vote))
	}

	// Test happy path
	{
		vote := createDummyVoteMessage(1)
		require.True(t, isProperlyFormedVote(vote))
	}
}

func TestIsProperlyFormedTimeout(t *testing.T) {
	// Test nil value
	{
		require.False(t, isProperlyFormedTimeout(nil))
	}

	// Test zero-value view
	{
		timeout := createDummyTimeoutMessage(0)
		require.False(t, isProperlyFormedTimeout(timeout))
	}

	// Test nil high QC
	{
		timeout := createDummyTimeoutMessage(1)
		timeout.highQC = nil
		require.False(t, isProperlyFormedTimeout(timeout))
	}

	// Test nil public key
	{
		timeout := createDummyTimeoutMessage(1)
		timeout.publicKey = nil
		require.False(t, isProperlyFormedTimeout(timeout))
	}

	// Test nil signature
	{
		timeout := createDummyTimeoutMessage(1)
		timeout.signature = nil
		require.False(t, isProperlyFormedTimeout(timeout))
	}

	// Test happy path
	{
		timeout := createDummyTimeoutMessage(1)
		require.True(t, isProperlyFormedTimeout(timeout))
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

func createDummyBlock(view uint64) *block {
	return &block{
		blockHash: createDummyBlockHash(),
		view:      view,
		height:    1,
		qc:        createDummyQC(view - 1),
	}
}

func createDummyVoteMessage(view uint64) *voteMessage {
	blockHash := createDummyBlockHash()
	signaturePayload := GetVoteSignaturePayload(view, blockHash)

	blsPrivateKey, _ := bls.NewPrivateKey()
	blsSignature, _ := blsPrivateKey.Sign(signaturePayload[:])

	return &voteMessage{
		blockHash: blockHash,
		view:      view,
		publicKey: blsPrivateKey.PublicKey(),
		signature: blsSignature,
	}
}

func createDummyTimeoutMessage(view uint64) *timeoutMessage {
	highQC := createDummyQC(view - 1)

	signaturePayload := GetTimeoutSignaturePayload(view, highQC.view)

	blsPrivateKey, _ := bls.NewPrivateKey()
	blsSignature, _ := blsPrivateKey.Sign(signaturePayload[:])

	return &timeoutMessage{
		highQC:    highQC,
		view:      view,
		publicKey: blsPrivateKey.PublicKey(),
		signature: blsSignature,
	}
}

func createDummyQC(view uint64) *quorumCertificate {
	return &quorumCertificate{
		blockHash:           createDummyBlockHash(),
		view:                view,
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