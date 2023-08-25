package consensus

import "github.com/deso-protocol/core/collections"

func isValidBlock(block Block) bool {
	// The block must be non-nil
	if block == nil {
		return false
	}

	// The block height and view must be non-zero
	if block.GetHeight() == 0 || block.GetView() == 0 {
		return false
	}

	// The block hash and QC must be non-nil
	if block.GetBlockHash() == nil || block.GetQC() == nil {
		return false
	}

	qc := block.GetQC()

	// The QC fields must be non-nil and the view non-zero
	if qc.GetAggregatedSignature() == nil || qc.GetBlockHash() == nil || qc.GetSignersList() == nil || qc.GetView() == 0 {
		return false
	}

	return true
}

func isValidValidatorSet(validators []Validator) bool {
	// The validator set must be non-empty
	if len(validators) == 0 {
		return false
	}

	// If any validator in the slice has an invalid property, then something is wrong.
	return !collections.Any(validators, func(v Validator) bool {
		return v == nil || v.GetPublicKey() == nil || v.GetStakeAmount() == nil || v.GetStakeAmount().IsZero()
	})
}
