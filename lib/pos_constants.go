package lib

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/consensus"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

// The Proof of Work -> Proof of Stake cutover requires a synthetic QC to protect against a timeout
// during the exact point of the cutover. This synthetic QC is built and signed locally by every node
// using a known and consistent private key.
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
