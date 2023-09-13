package consensus

import (
	"encoding/binary"
	"reflect"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"golang.org/x/crypto/sha3"
)

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

	// The view must be non-zero and the aggregated signature non-nil
	if qc.GetView() == 0 || isInterfaceNil(qc.GetAggregatedSignature()) {
		return false
	}

	// The signers list must be non-nil
	if qc.GetSignersList() == nil {
		return false
	}

	return true
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

func isValidSignature(publicKey *bls.PublicKey, signature *bls.Signature, payload []byte) bool {
	isValid, err := bls.VerifyAggregateSignatureSinglePayload([]*bls.PublicKey{publicKey}, signature, payload)
	return err == nil && isValid
}
