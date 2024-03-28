package lib

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/deso-protocol/core/consensus"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

// The Proof of Work -> Proof of Stake cutover requires a synthetic QC to protect against a timeout
// during the exact point of the cutover. This synthetic QC is built and signed locally by every node
// using a known and hard-coded private key.
//
// We need a synthetic QC for the final PoW block in case we have a timeout during the first 1-2 block
// heights of the PoS chain. If we have such timeouts, validators need to be able to send a high QC
// for the final PoW block. To guarantee that validators can do this, we have a synthetic QC that
// can only be built and signed by this hard-coded private key. The synthetic QC can only be applied
// to the final PoW block. Every validator has access to this private key and can build this QC.
const proofOfStakeCutoverValidatorBLSPrivateKeyHex = "0x0570b78ce822f902b203ee075a7e2147d6b9a420a9409c038154589de64eec96"

func BuildProofOfStakeCutoverValidatorBLSPrivateKey() (*bls.PrivateKey, error) {
	return (&bls.PrivateKey{}).FromString(proofOfStakeCutoverValidatorBLSPrivateKeyHex)
}

func BuildProofOfStakeCutoverValidator() (consensus.Validator, error) {
	// Parse the BLS private key
	blsPrivateKey, err := BuildProofOfStakeCutoverValidatorBLSPrivateKey()
	if err != nil {
		return nil, errors.Wrapf(err, "BuildProofOfStakeCutoverValidator: Problem parsing BLS private key")
	}
	validatorEntry := &ValidatorEntry{
		VotingPublicKey:       blsPrivateKey.PublicKey(),
		TotalStakeAmountNanos: uint256.NewInt().SetUint64(1e9),
	}
	return validatorEntry, nil
}

func BuildQuorumCertificateAsProofOfStakeCutoverValidator(view uint64, blockHash *BlockHash) (
	_aggregatedSignature *bls.Signature,
	_signersList *bitset.Bitset,
	_err error,
) {
	// Construct the payload first
	votePayload := consensus.GetVoteSignaturePayload(view, blockHash)

	// Build the validator's private key
	privateKey, err := BuildProofOfStakeCutoverValidatorBLSPrivateKey()
	if err != nil {
		return nil, nil, errors.Errorf("BuildQuorumCertificateAsProofOfStakeCutoverValidator: %v", err)
	}

	// Sign the payload
	signature, err := privateKey.Sign(votePayload[:])
	if err != nil {
		return nil, nil, errors.Errorf("BuildQuorumCertificateAsProofOfStakeCutoverValidator: Error signing payload: %v", err)
	}

	return signature, bitset.NewBitset().Set(0, true), nil
}
