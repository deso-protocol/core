package consensus

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"reflect"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
)

// Given a QC and a sorted validator set, this function returns true if the QC contains a valid
// super-majority of signatures from the validator set for the QC's (View, BlockHash) pair.
func IsValidSuperMajorityQuorumCertificate(qc QuorumCertificate, validators []Validator) bool {
	if !isProperlyFormedQC(qc) || !isProperlyFormedValidatorSet(validators) {
		return false
	}

	// Compute the signature that validators in the QC would have signed
	signaturePayload := GetVoteSignaturePayload(qc.GetView(), qc.GetBlockHash())

	// Compute the total stake in the QC and the total stake in the network
	stakeInQC := uint256.NewInt()
	totalStake := uint256.NewInt()

	// Fetch the validators in the QC
	validatorPublicKeysInQC := []*bls.PublicKey{}

	// Fetch the aggregated signature in the QC
	aggregatedSignature := qc.GetAggregatedSignature()

	// Fetch the validators in the QC, and compute the sum of stake in the QC and in the network
	for ii := range validators {
		if aggregatedSignature.GetSignersList().Get(ii) {
			stakeInQC.Add(stakeInQC, validators[ii].GetStakeAmount())
			validatorPublicKeysInQC = append(validatorPublicKeysInQC, validators[ii].GetPublicKey())
		}
		totalStake.Add(totalStake, validators[ii].GetStakeAmount())
	}

	// Check if the QC contains a super-majority of stake
	if !isSuperMajorityStake(stakeInQC, totalStake) {
		return false
	}

	// Finally, validate the signature
	return isValidSignatureManyPublicKeys(validatorPublicKeysInQC, aggregatedSignature.GetSignature(), signaturePayload[:])
}

// When voting on a block, validators sign the payload sha3-256(View, BlockHash) with their BLS
// private key. This hash guarantees that the view and block hash fields in a VoteMessage
// have not been tampered with, while maintaining all existing guarantees that the validator
// has voted for a given block.
//
// Reference Implementation:
// https://github.com/deso-protocol/hotstuff_pseudocode/blob/6409b51c3a9a953b383e90619076887e9cebf38d/fast_hotstuff_bls.go#L294
func GetVoteSignaturePayload(view uint64, blockHash BlockHash) [32]byte {
	viewBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(viewBytes, view)
	blockHashBytes := blockHash.GetValue()

	return sha3.Sum256(append(viewBytes, blockHashBytes[:]...))
}

// When timing out for a view, validators sign the payload sha3-256(View, HighQCView) with their BLS
// private key. This hash guarantees that the view and high QC view fields in a TimeoutMessage
// have not been tampered with.
func GetTimeoutSignaturePayload(view uint64, highQCView uint64) [32]byte {
	viewBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(viewBytes, view)

	highQCViewBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(highQCViewBytes, highQCView)

	return sha3.Sum256(append(viewBytes, highQCViewBytes...))
}

// This function checks if the block is properly formed. These are all surface level checks that
// ensure that critical fields in the block are not nil so that the code in this package does not
// panic.
func isProperlyFormedBlock(block Block) bool {
	// The block must be non-nil
	if isInterfaceNil(block) {
		return false
	}

	// The block height and view must be non-zero
	if block.GetHeight() == 0 || block.GetView() == 0 {
		return false
	}

	// The block hash and QC must be non-nil
	if isInterfaceNil(block.GetBlockHash()) || !isProperlyFormedQC(block.GetQC()) {
		return false
	}

	// The QC's view must be less than the block's view
	if block.GetQC().GetView() >= block.GetView() {
		return false
	}

	return true
}

func isProperlyFormedValidatorSet(validators []Validator) bool {
	// The validator set must be non-empty
	if len(validators) == 0 {
		return false
	}

	// If any validator in the slice has an invalid property, then something is wrong.
	return !collections.Any(validators, func(v Validator) bool {
		return isInterfaceNil(v) || v.GetPublicKey() == nil || v.GetStakeAmount() == nil || v.GetStakeAmount().IsZero()
	})
}

func isProperlyFormedVote(vote VoteMessage) bool {
	// The vote must be non-nil
	if vote == nil {
		return false
	}

	// The view must be non-zero and and block hash non-nil
	if vote.GetView() == 0 || isInterfaceNil(vote.GetBlockHash()) {
		return false
	}

	// The signature and public key must be non-nil
	if vote.GetSignature() == nil || vote.GetPublicKey() == nil {
		return false
	}

	return true
}

func isProperlyFormedTimeout(timeout TimeoutMessage) bool {
	// The timeout must be non-nil
	if isInterfaceNil(timeout) {
		return false
	}

	// The view must be non-zero and the high QC non-nil
	if timeout.GetView() == 0 || isInterfaceNil(timeout.GetHighQC()) {
		return false
	}

	// The signature and public key must be non-nil
	if timeout.GetSignature() == nil || timeout.GetPublicKey() == nil {
		return false
	}

	// The QC's view must be less than the timed out view
	if timeout.GetHighQC().GetView() >= timeout.GetView() {
		return false
	}

	return true
}

func isProperlyFormedQC(qc QuorumCertificate) bool {
	// The QC must be non-nil
	if isInterfaceNil(qc) {
		return false
	}

	// The view must be non-zero and the block hash must be non-nil
	if qc.GetView() == 0 || isInterfaceNil(qc.GetBlockHash()) {
		return false
	}

	return isProperlyFormedAggregateSignature(qc.GetAggregatedSignature())
}

func isProperlyFormedAggregateSignature(agg AggregatedSignature) bool {
	// The signature must be non-nil
	if isInterfaceNil(agg) {
		return false
	}

	return agg.GetSignersList() != nil && agg.GetSignature() != nil
}

// golang interface types are stored as a tuple of (type, value). A single i==nil check is not enough to
// determine if a pointer that implements an interface is nil. This function checks if the interface is nil
// by checking if the pointer itself is nil.
func isInterfaceNil(i interface{}) bool {
	if i == nil {
		return true
	}

	value := reflect.ValueOf(i)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

func isValidSignatureSinglePublicKey(publicKey *bls.PublicKey, signature *bls.Signature, payload []byte) bool {
	isValid, err := bls.VerifyAggregateSignatureSinglePayload([]*bls.PublicKey{publicKey}, signature, payload)
	return err == nil && isValid
}

func isValidSignatureManyPublicKeys(publicKeys []*bls.PublicKey, signature *bls.Signature, payload []byte) bool {
	isValid, err := bls.VerifyAggregateSignatureSinglePayload(publicKeys, signature, payload)
	return err == nil && isValid
}

// This function uses integer math to verify if the provided stake amount represents a
// super-majority 2f+1 Byzantine Quorum. First we need the following context:
// - Assume N = total stake in the network
// - Assume f = faulty stake in the network
// - Assume C = honest stake in the network
// - We have N = C + f.
//
// As our security assumptions, we need C >= 2f+1. If we consider worst-case scenario (C=2f+1), we have N = 3f + 1.
// - We want to determine if we have a super-majority Quorum containing the majority of C
// - The minimal size of such Quorum is f + [floor(C/2) + 1]
//   - For a fixed N, this function grows larger as C gets smaller relative to f.
//   - We would need the largest Quorum for C = 2f+1, and it's size would also be 2f+1 = f + floor((2f+1)/2) + 1.
//
// So, for a given N, we check for a super-majority Quorum, containing at least 2f+1 votes, where f is defined
// in worst-case scenario of N = 3f+1.
//
// Given the above, let's say Cq := stake that is provided to this function. We can derive the following
// super-majority check:
// - Cq >= 2f + 1
// - 3Cq >= 6f + 3
// - 3Cq >= 2(3f + 1) + 1
// - 3Cq >= 2N + 1
// - Finally, this gives us the condition: 3Cq - 2N - 1 >= 0. Which is what we will verify in this function.
func isSuperMajorityStake(stake *uint256.Int, totalStake *uint256.Int) bool {
	// Both values must be > 0
	if stake == nil || totalStake == nil || stake.IsZero() || totalStake.IsZero() {
		return false
	}

	// The stake must be less than or equal to the total stake
	if stake.Cmp(totalStake) > 0 {
		return false
	}

	// Compute 3Cq
	honestStakeComponent := uint256.NewInt().Mul(stake, uint256.NewInt().SetUint64(3))

	// Compute 2N
	totalStakeComponent := uint256.NewInt().Mul(totalStake, uint256.NewInt().SetUint64(2))

	// Compute 3Cq - 2N - 1
	superMajorityConditionSum := uint256.NewInt().Sub(
		uint256.NewInt().Sub(honestStakeComponent, totalStakeComponent),
		uint256.NewInt().SetOne(),
	)

	// Check if 3Cq - 2N - 1 >= 0
	return superMajorityConditionSum.Sign() >= 0
}

func isEqualBlockHashes(hash1 BlockHash, hash2 BlockHash) bool {
	hash1Value := hash1.GetValue()
	hash2Value := hash2.GetValue()

	return bytes.Equal(hash1Value[:], hash2Value[:])
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
		qc:        createDummyQC(view-1, createDummyBlockHash()),
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
	highQC := createDummyQC(view-1, createDummyBlockHash())

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

func createDummyQC(view uint64, blockHash BlockHash) *quorumCertificate {
	signaturePayload := GetVoteSignaturePayload(view, blockHash)

	blsPrivateKey1, _ := bls.NewPrivateKey()
	blsSignature1, _ := blsPrivateKey1.Sign(signaturePayload[:])

	blsPrivateKey2, _ := bls.NewPrivateKey()
	blsSignature2, _ := blsPrivateKey2.Sign(signaturePayload[:])

	signersList := bitset.NewBitset().Set(0, true).Set(1, true)
	aggregateSignature, _ := bls.AggregateSignatures([]*bls.Signature{blsSignature1, blsSignature2})

	return &quorumCertificate{
		blockHash: blockHash,
		view:      view,
		aggregatedSignature: &aggregatedSignature{
			signersList: signersList,
			signature:   aggregateSignature,
		},
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
	byteArray := [32]byte{}
	copy(byteArray[:], generateRandomBytes(32))

	return &blockHash{
		value: byteArray,
	}
}

func generateRandomBytes(numBytes int) []byte {
	randomBytes := make([]byte, numBytes)
	rand.Read(randomBytes)
	return randomBytes
}
