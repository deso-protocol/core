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

func TestIsValidSuperMajorityQuorumCertificate(t *testing.T) {
	// Test malformed QC
	{
		require.False(t, IsValidSuperMajorityQuorumCertificate(nil, createDummyValidatorSet()))
	}

	// Test malformed validator set
	{
		require.False(t, IsValidSuperMajorityQuorumCertificate(createDummyQC(1), nil))
	}

	// Set up test validator data
	validatorPrivateKey1 := createDummyBLSPrivateKey()
	validatorPrivateKey2 := createDummyBLSPrivateKey()
	validatorPrivateKey3 := createDummyBLSPrivateKey()

	validator1 := validator{
		publicKey:   validatorPrivateKey1.PublicKey(),
		stakeAmount: uint256.NewInt().SetUint64(3),
	}

	validator2 := validator{
		publicKey:   validatorPrivateKey2.PublicKey(),
		stakeAmount: uint256.NewInt().SetUint64(2),
	}

	validator3 := validator{
		publicKey:   validatorPrivateKey3.PublicKey(),
		stakeAmount: uint256.NewInt().SetUint64(1),
	}

	validators := []Validator{&validator1, &validator2, &validator3}

	// Set up the block hash and view
	blockHash := createDummyBlockHash()
	view := uint64(10)

	// Compute the signature payload
	signaturePayload := GetVoteSignaturePayload(view, blockHash)

	// Test with no super-majority stake
	{
		validator1Signature, err := validatorPrivateKey1.Sign(signaturePayload[:])
		require.NoError(t, err)

		qc := quorumCertificate{
			blockHash:           blockHash,
			view:                view,
			signersList:         bitset.NewBitset().FromBytes([]byte{0x1}), // 0b0001, which represents validator 1
			aggregatedSignature: validator1Signature,
		}

		require.False(t, IsValidSuperMajorityQuorumCertificate(&qc, validators))
	}

	// Test with 5/6 super-majority stake
	{
		validator1Signature, err := validatorPrivateKey1.Sign(signaturePayload[:])
		require.NoError(t, err)

		validator2Signature, err := validatorPrivateKey2.Sign(signaturePayload[:])
		require.NoError(t, err)

		aggregatedSignature, err := bls.AggregateSignatures([]*bls.Signature{validator1Signature, validator2Signature})
		require.NoError(t, err)

		qc := quorumCertificate{
			blockHash:           blockHash,
			view:                view,
			signersList:         bitset.NewBitset().FromBytes([]byte{0x3}), // 0b0011, which represents validators 1 and 2
			aggregatedSignature: aggregatedSignature,
		}

		require.True(t, IsValidSuperMajorityQuorumCertificate(&qc, validators))
	}
}

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

func TestIsSuperMajorityStake(t *testing.T) {
	// Test nil values
	{
		require.False(t, isSuperMajorityStake(nil, nil))
	}

	// Test zero values
	{
		require.False(t, isSuperMajorityStake(uint256.NewInt(), uint256.NewInt()))
	}

	// Test stake amount greater than total stake
	{
		require.False(t, isSuperMajorityStake(uint256.NewInt().SetUint64(2), uint256.NewInt().SetUint64(1)))
	}

	// Test stake amount much less than super majority
	{
		stake := uint256.NewInt().SetUint64(1)
		totalStake := uint256.NewInt().SetUint64(1000)
		require.False(t, isSuperMajorityStake(stake, totalStake))
	}

	// Test stake amount less than super majority
	{
		stake := uint256.NewInt().SetUint64(666)
		totalStake := uint256.NewInt().SetUint64(1000)
		require.False(t, isSuperMajorityStake(stake, totalStake))
	}

	// Test stake amount equal to super majority
	{
		stake := uint256.NewInt().SetUint64(667)
		totalStake := uint256.NewInt().SetUint64(1000)
		require.True(t, isSuperMajorityStake(stake, totalStake))
	}

	// Test stake amount greater than super majority
	{
		stake := uint256.NewInt().SetUint64(668)
		totalStake := uint256.NewInt().SetUint64(1000)
		require.True(t, isSuperMajorityStake(stake, totalStake))
	}

	// Test stake amount much greater than super majority
	{
		stake := uint256.NewInt().SetUint64(999)
		totalStake := uint256.NewInt().SetUint64(1000)
		require.True(t, isSuperMajorityStake(stake, totalStake))
	}

	// Test stake amount equal to total stake
	{
		totalStake := uint256.NewInt().SetUint64(1000)
		require.True(t, isSuperMajorityStake(totalStake, totalStake))
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

func createDummyBLSPrivateKey() *bls.PrivateKey {
	blsPrivateKey, _ := bls.NewPrivateKey()
	return blsPrivateKey
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
