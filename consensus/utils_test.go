//go:build relic

package consensus

import (
	"testing"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestIsValidSuperMajorityQuorumCertificate(t *testing.T) {
	// Test malformed QC
	{
		require.False(t, IsValidSuperMajorityQuorumCertificate(nil, createDummyValidatorList()))
	}

	// Test malformed validator list
	{
		require.False(t, IsValidSuperMajorityQuorumCertificate(createDummyQC(1, createDummyBlockHash()), nil))
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
			blockHash: blockHash,
			view:      view,
			aggregatedSignature: &aggregatedSignature{
				signersList: bitset.NewBitset().FromBytes([]byte{0x1}), // 0b0001, which represents validator 1
				signature:   validator1Signature,
			},
		}

		require.False(t, IsValidSuperMajorityQuorumCertificate(&qc, validators))
	}

	// Test with 5/6 super-majority stake
	{
		validator1Signature, err := validatorPrivateKey1.Sign(signaturePayload[:])
		require.NoError(t, err)

		validator2Signature, err := validatorPrivateKey2.Sign(signaturePayload[:])
		require.NoError(t, err)

		// Aggregate the two validators' signatures
		signature, err := bls.AggregateSignatures([]*bls.Signature{validator1Signature, validator2Signature})
		require.NoError(t, err)

		qc := quorumCertificate{
			blockHash: blockHash,
			view:      view,
			aggregatedSignature: &aggregatedSignature{
				signersList: bitset.NewBitset().FromBytes([]byte{0x3}), // 0b0011, which represents validators 1 and 2
				signature:   signature,
			},
		}

		require.True(t, IsValidSuperMajorityQuorumCertificate(&qc, validators))
	}
}

func TestIsValidSuperMajorityAggregateQuorumCertificate(t *testing.T) {
	// Test malformed aggregate QC
	{
		validatorList := createDummyValidatorList()
		require.False(t, IsValidSuperMajorityAggregateQuorumCertificate(nil, validatorList, validatorList))
	}

	// Test malformed validator set
	{
		require.False(t, IsValidSuperMajorityAggregateQuorumCertificate(createDummyAggQc(2, 1), nil, nil))
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
		stakeAmount: uint256.NewInt().SetUint64(1),
	}

	validator3 := validator{
		publicKey:   validatorPrivateKey3.PublicKey(),
		stakeAmount: uint256.NewInt().SetUint64(1),
	}

	validators := []Validator{&validator1, &validator2, &validator3}

	// Set up the block hash and view
	dummyBlockHash := createDummyBlockHash()
	view := uint64(10)

	// Compute the signature payload
	signaturePayload := GetVoteSignaturePayload(view, dummyBlockHash)

	validator1Signature, err := validatorPrivateKey1.Sign(signaturePayload[:])
	require.NoError(t, err)
	validator2Signature, err := validatorPrivateKey2.Sign(signaturePayload[:])
	require.NoError(t, err)
	aggSig, err := bls.AggregateSignatures([]*bls.Signature{validator1Signature, validator2Signature})
	highQC := quorumCertificate{
		blockHash: dummyBlockHash,
		view:      view,
		aggregatedSignature: &aggregatedSignature{
			signersList: bitset.NewBitset().FromBytes([]byte{0x3}), // 0b0011, which represents validators 1 and 2
			signature:   aggSig,
		},
	}

	// Sad Path: Test 3/5 stake which is not a super-majority
	{
		// Validator 1 signs a timeout payload where its high QC view is equal to the aggQC's high QC view.
		validator1TimeoutPayload := GetTimeoutSignaturePayload(view+2, view)
		validator1TimeoutSignature, err := validatorPrivateKey1.Sign(validator1TimeoutPayload[:])
		require.NoError(t, err)

		// Validator 2 does not time out.

		// Validator 3 does not time out.

		qc := aggregateQuorumCertificate{
			view:        view + 2,
			highQC:      &highQC,
			highQCViews: []uint64{view},
			aggregatedSignature: &aggregatedSignature{
				signersList: bitset.NewBitset().FromBytes([]byte{0x1}), // 0b0001, which represents validator 1
				signature:   validator1TimeoutSignature,
			},
		}
		require.False(t, IsValidSuperMajorityAggregateQuorumCertificate(&qc, validators, validators))
	}

	// Sad Path: Test 4/5 stake but one of the validators has a higher view than the highQC view.
	{
		// Validator 1 signs a timeout payload where its high QC view is equal to the aggQC's high QC view.
		validator1TimeoutPayload := GetTimeoutSignaturePayload(view+2, view)
		validator1TimeoutSignature, err := validatorPrivateKey1.Sign(validator1TimeoutPayload[:])
		require.NoError(t, err)

		// Validator 2 signs a timeout payload where its high QC view is higher than the aggQC's high QC view.
		validator2TimeoutPayload := GetTimeoutSignaturePayload(view+2, view+1)
		validator2TimeoutSignature, err := validatorPrivateKey2.Sign(validator2TimeoutPayload[:])
		require.NoError(t, err)

		// Validator 3 does not time out.

		timeoutAggSig, err := bls.AggregateSignatures([]*bls.Signature{validator1TimeoutSignature, validator2TimeoutSignature})
		require.NoError(t, err)
		qc := aggregateQuorumCertificate{
			view:        view + 2,
			highQC:      &highQC,
			highQCViews: []uint64{view, view + 1},
			aggregatedSignature: &aggregatedSignature{
				signersList: bitset.NewBitset().FromBytes([]byte{0x3}), // 0b0011, which represents validators 1 and 2
				signature:   timeoutAggSig,
			},
		}
		require.False(t, IsValidSuperMajorityAggregateQuorumCertificate(&qc, validators, validators))
	}

	// Happy Path: Test with 4/5 super-majority stake
	{
		// Validator 1 signs a timeout payload where its high QC view is equal to the aggQC's high QC view.
		validator1TimeoutPayload := GetTimeoutSignaturePayload(view+2, view)
		validator1TimeoutSignature, err := validatorPrivateKey1.Sign(validator1TimeoutPayload[:])
		require.NoError(t, err)

		// Validator 2 signs a timeout payload where its high QC view is lower than the aggQC's high QC view.
		validator2TimeoutPayload := GetTimeoutSignaturePayload(view+2, view-1)
		validator2TimeoutSignature, err := validatorPrivateKey2.Sign(validator2TimeoutPayload[:])
		require.NoError(t, err)

		// Validator 3 does not time out.

		timeoutAggSig, err := bls.AggregateSignatures([]*bls.Signature{validator1TimeoutSignature, validator2TimeoutSignature})
		require.NoError(t, err)
		qc := aggregateQuorumCertificate{
			view:        view + 2,
			highQC:      &highQC,
			highQCViews: []uint64{view, view - 1},
			aggregatedSignature: &aggregatedSignature{
				signersList: bitset.NewBitset().FromBytes([]byte{0x3}), // 0b0011, which represents validators 1 and 2
				signature:   timeoutAggSig,
			},
		}
		require.True(t, IsValidSuperMajorityAggregateQuorumCertificate(&qc, validators, validators))
	}

	// Happy Path: Test with 4/5 super-majority stake, where the highQC views slice has a 0 due to validator 2
	// not timing out.
	{
		// Validator 1 signs a timeout payload where its high QC view is equal to the aggQC's high QC view.
		validator1TimeoutPayload := GetTimeoutSignaturePayload(view+2, view)
		validator1TimeoutSignature, err := validatorPrivateKey1.Sign(validator1TimeoutPayload[:])
		require.NoError(t, err)

		// Validator 2 does not time out.

		// Validator 3 signs a timeout payload where its high QC view is lower than the aggQC's high QC view.
		validator3TimeoutPayload := GetTimeoutSignaturePayload(view+2, view-1)
		validator3TimeoutSignature, err := validatorPrivateKey3.Sign(validator3TimeoutPayload[:])
		require.NoError(t, err)

		timeoutAggSig, err := bls.AggregateSignatures([]*bls.Signature{validator1TimeoutSignature, validator3TimeoutSignature})
		require.NoError(t, err)
		qc := aggregateQuorumCertificate{
			view:        view + 2,
			highQC:      &highQC,
			highQCViews: []uint64{view, 0, view - 1}, // The 0 is due to validator 2 not timing out.
			aggregatedSignature: &aggregatedSignature{
				signersList: bitset.NewBitset().FromBytes([]byte{0x5}), // 0b0101, which represents validators 1 and 3
				signature:   timeoutAggSig,
			},
		}
		require.True(t, IsValidSuperMajorityAggregateQuorumCertificate(&qc, validators, validators))
	}

	// Happy Path: Test with 5/5 super-majority stake where all validators time out.
	{
		// Validator 1 signs a timeout payload where its high QC view is equal to the aggQC's high QC view.
		validator1TimeoutPayload := GetTimeoutSignaturePayload(view+2, view)
		validator1TimeoutSignature, err := validatorPrivateKey1.Sign(validator1TimeoutPayload[:])
		require.NoError(t, err)

		// Validator 2 signs a timeout payload where its high QC view is lower than the aggQC's high QC view.
		validator2TimeoutPayload := GetTimeoutSignaturePayload(view+2, view-2)
		validator2TimeoutSignature, err := validatorPrivateKey2.Sign(validator2TimeoutPayload[:])
		require.NoError(t, err)

		// Validator 2 signs a timeout payload where its high QC view is lower than the aggQC's high QC view.
		validator3TimeoutPayload := GetTimeoutSignaturePayload(view+2, view-1)
		validator3TimeoutSignature, err := validatorPrivateKey3.Sign(validator3TimeoutPayload[:])
		require.NoError(t, err)

		timeoutAggSig, err := bls.AggregateSignatures([]*bls.Signature{validator1TimeoutSignature, validator2TimeoutSignature, validator3TimeoutSignature})
		require.NoError(t, err)
		qc := aggregateQuorumCertificate{
			view:        view + 2,
			highQC:      &highQC,
			highQCViews: []uint64{view, view - 2, view - 1},
			aggregatedSignature: &aggregatedSignature{
				signersList: bitset.NewBitset().FromBytes([]byte{0x7}), // 0b0111, which represents validators 1, 2 and 3
				signature:   timeoutAggSig,
			},
		}
		require.True(t, IsValidSuperMajorityAggregateQuorumCertificate(&qc, validators, validators))
	}
}

func TestIsProperlyFormedBlock(t *testing.T) {
	// Test nil block
	{
		require.False(t, isProperlyFormedBlock(nil))
	}

	// Test zero height
	{
		block := block{height: 0, view: 2, blockHash: createDummyBlockHash(), qc: createDummyQC(1, createDummyBlockHash())}
		require.False(t, isProperlyFormedBlock(&block))
	}

	// Test zero view
	{
		block := block{height: 1, view: 0, blockHash: createDummyBlockHash(), qc: createDummyQC(0, createDummyBlockHash())}
		require.False(t, isProperlyFormedBlock(&block))
	}

	// Test nil block hash
	{
		block := block{height: 1, view: 1, blockHash: nil, qc: createDummyQC(0, createDummyBlockHash())}
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
		require.False(t, IsProperlyFormedVote(nil))
	}

	// Test zero-value view
	{
		vote := createDummyVoteMessage(0)
		require.False(t, IsProperlyFormedVote(vote))
	}

	// Test nil block hash
	{
		vote := createDummyVoteMessage(1)
		vote.blockHash = nil
		require.False(t, IsProperlyFormedVote(vote))
	}

	// Test nil public key
	{
		vote := createDummyVoteMessage(1)
		vote.publicKey = nil
		require.False(t, IsProperlyFormedVote(vote))
	}

	// Test nil signature
	{
		vote := createDummyVoteMessage(1)
		vote.signature = nil
		require.False(t, IsProperlyFormedVote(vote))
	}

	// Test happy path
	{
		vote := createDummyVoteMessage(1)
		require.True(t, IsProperlyFormedVote(vote))
	}
}

func TestIsProperlyFormedTimeout(t *testing.T) {
	// Test nil value
	{
		require.False(t, IsProperlyFormedTimeout(nil))
	}

	// Test zero-value view
	{
		timeout := createDummyTimeoutMessage(0)
		require.False(t, IsProperlyFormedTimeout(timeout))
	}

	// Test nil high QC
	{
		timeout := createDummyTimeoutMessage(2)
		timeout.highQC = nil
		require.False(t, IsProperlyFormedTimeout(timeout))
	}

	// Test nil public key
	{
		timeout := createDummyTimeoutMessage(2)
		timeout.publicKey = nil
		require.False(t, IsProperlyFormedTimeout(timeout))
	}

	// Test nil signature
	{
		timeout := createDummyTimeoutMessage(2)
		timeout.signature = nil
		require.False(t, IsProperlyFormedTimeout(timeout))
	}

	// Test malformed high QC
	{
		highQC := createDummyQC(1, createDummyBlockHash())
		highQC.aggregatedSignature = nil
		timeout := createTimeoutMessageWithPrivateKeyAndHighQC(2, createDummyBLSPrivateKey(), highQC)
		require.False(t, IsProperlyFormedTimeout(timeout))
	}

	// Test happy path
	{
		timeout := createDummyTimeoutMessage(2)
		require.True(t, IsProperlyFormedTimeout(timeout))
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

func TestIsEqualQC(t *testing.T) {
	// Test nil QCs
	{
		require.False(t, IsEqualQC(nil, nil))
	}

	// Test one nil and one non-nil QC
	{
		require.False(t, IsEqualQC(nil, createDummyQC(1, createDummyBlockHash())))
		require.False(t, IsEqualQC(createDummyQC(1, createDummyBlockHash()), nil))
	}

	// Test two non-equal non-nil QCs with different block hashes
	{
		require.False(t, IsEqualQC(createDummyQC(1, createDummyBlockHash()), createDummyQC(1, createDummyBlockHash())))
	}

	// Test two non-equal non-nil QCs with different views
	{
		blockHash := createDummyBlockHash()
		require.False(t, IsEqualQC(createDummyQC(1, blockHash), createDummyQC(2, blockHash)))
	}

	// Test two non-equal non-nil QCs with different aggregated signatures
	{
		blockHash := createDummyBlockHash()
		require.False(t, IsEqualQC(createDummyQC(1, blockHash), createDummyQC(1, blockHash)))
	}

	// Test two equal QCs
	{
		qc := createDummyQC(1, createDummyBlockHash())
		require.True(t, IsEqualQC(qc, qc))
	}
}
