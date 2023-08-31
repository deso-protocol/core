package consensus

import (
	"crypto/sha256"
	"fmt"
	"reflect"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
)

// When voting on a block, validators sign the payload sha256(View, BlockHash) with their BLS
// private key. This hash guarantees that the view and block hash fields in a VoteMessage
// have not been tampered with, while maintaining all existing guarantees that the validator
// has voted for a given block.
//
// Reference Implementation:
// https://github.com/deso-protocol/hotstuff_pseudocode/blob/6409b51c3a9a953b383e90619076887e9cebf38d/fast_hotstuff_bls.go#L294
func GetVoteSignaturePayload(view uint64, blockHash BlockHash) [32]byte {
	viewBytes := []byte(fmt.Sprintf("%d", view))
	blockHashBytes := blockHash.GetValue()

	return sha256.Sum256(append(viewBytes, blockHashBytes[:]...))
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
	if isInterfaceNil(block.GetBlockHash()) || isInterfaceNil(block.GetQC()) {
		return false
	}

	qc := block.GetQC()

	// The QC fields must be non-nil and the view non-zero
	if isInterfaceNil(qc.GetAggregatedSignature()) ||
		isInterfaceNil(qc.GetBlockHash()) ||
		qc.GetSignersList() == nil ||
		qc.GetView() == 0 {
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
