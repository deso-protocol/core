package lib

import (
	"errors"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/consensus"
)

// BLSSigner is a wrapper for the bls.PrivateKey type, which abstracts away the private key
// and only exposes protected methods for signing a select set of message types needed for
// Proof of Stake. It allows signing for:
// - PoS Validator Votes Messages
// - PoS Validator Timeout Messages
// - PoS Block Proposals
// - PoS Validator Connection Handshakes
type BLSSigner struct {
	privateKey *bls.PrivateKey
}

func NewBLSSigner(privateKey *bls.PrivateKey) (*BLSSigner, error) {
	if privateKey == nil {
		return nil, errors.New("NewBLSSigner: privateKey cannot be nil")
	}
	return &BLSSigner{privateKey: privateKey}, nil
}

func (signer *BLSSigner) GetPublicKey() *bls.PublicKey {
	return signer.privateKey.PublicKey()
}

func (signer *BLSSigner) SignValidatorVote(view uint64, blockHash consensus.BlockHash) (*bls.Signature, error) {
	payload := consensus.GetVoteSignaturePayload(view, blockHash)
	return signer.privateKey.Sign(payload[:])
}

func (signer *BLSSigner) SignValidatorTimeout(view uint64, highQCView uint64) (*bls.Signature, error) {
	payload := consensus.GetTimeoutSignaturePayload(view, highQCView)
	return signer.privateKey.Sign(payload[:])
}

// TODO: Add signing function for PoS blocks

// TODO: Add signing function for PoS validator connection handshake
