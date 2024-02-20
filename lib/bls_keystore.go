package lib

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/consensus"
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
	"strings"
)

// BLSSigner is a wrapper for the bls.PrivateKey type, which abstracts away the private key
// and only exposes protected methods for signing a select set of message types needed for
// Proof of Stake. It allows signing for:
// - PoS Validator Votes Messages
// - PoS Validator Timeout Messages
// - PoS Block Proposals
// - PoS Validator Connection Handshakes
// - PoS Random Seed Signature
//
// We need to associate individual op-codes for each message type that can be signed, so that there is no risk
// of signature collisions between different message types. The payload signed per message type must be made
// up of the following tuples:
// - PoS Validator Vote:        (0x01, view uint64, blockHash consensus.BlockHash)
// - PoS Validator Timeout:     (0x02, view uint64, highQCView uint64)
// - PoS Validator Handshake:   (0x04, peer's random nonce, our node's random nonce)
// - PoS Random Seed Signature: (previous block's random seed hash)

type BLSSignatureOpCode byte

const (
	BLSSignatureOpCodeValidatorVote         BLSSignatureOpCode = BLSSignatureOpCode(consensus.SignatureOpCodeValidatorVote)
	BLSSignatureOpCodeValidatorTimeout      BLSSignatureOpCode = BLSSignatureOpCode(consensus.SignatureOpCodeValidatorTimeout)
	BLSSignatureOpCodePoSValidatorHandshake BLSSignatureOpCode = 3
)

func GetAllBLSSignatureOpCodes() []BLSSignatureOpCode {
	return []BLSSignatureOpCode{
		BLSSignatureOpCodeValidatorVote,
		BLSSignatureOpCodeValidatorTimeout,
		BLSSignatureOpCodePoSValidatorHandshake,
	}
}

//////////////////////////////////////////////////////////
// BLSKeystore
//////////////////////////////////////////////////////////

type BLSKeystore struct {
	signer *BLSSigner
}

// NewBLSKeystore creates a new BLSKeystore from either a seed phrase or a seed hex.
// If the seed begins with 0x, it is assumed to be a hex seed. Otherwise, it is assumed to be a seed phrase.
func NewBLSKeystore(seed string) (*BLSKeystore, error) {
	privateKey, err := bls.NewPrivateKey()
	if err != nil {
		return nil, errors.Wrapf(err, "NewBLSKeystore: Problem generating private key from seed phrase")
	}
	if strings.HasPrefix(seed, "0x") {
		if _, err = privateKey.FromString(seed); err != nil {
			return nil, errors.Wrapf(err, "NewBLSKeystore: Problem generating private key from seed hex")
		}
	} else {
		var seedBytes []byte
		seedBytes, err = bip39.NewSeedWithErrorChecking(seed, "")
		if err != nil {
			return nil, errors.Wrapf(err, "NewBLSKeystore: Problem generating seed bytes from seed phrase")
		}
		if _, err = privateKey.FromSeed(seedBytes); err != nil {
			return nil, errors.Wrapf(err, "NewBLSKeystore: Problem generating private key from seed phrase")
		}
	}

	signer, err := NewBLSSigner(privateKey)
	if err != nil {
		return nil, err
	}
	return &BLSKeystore{signer: signer}, nil
}

func (keystore *BLSKeystore) GetSigner() *BLSSigner {
	return keystore.signer
}

//////////////////////////////////////////////////////////
// BLSSigner
//////////////////////////////////////////////////////////

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

func (signer *BLSSigner) Sign(payload []byte) (*bls.Signature, error) {
	return signer.privateKey.Sign(payload)
}

func (signer *BLSSigner) SignBlockProposal(view uint64, blockHash consensus.BlockHash) (*bls.Signature, error) {
	// A block proposer's signature on a block is just its partial vote signature. This allows us to aggregate
	// signatures from the proposer and validators into a single aggregated signature to build a QC.
	return signer.SignValidatorVote(view, blockHash)
}

func (signer *BLSSigner) SignValidatorVote(view uint64, blockHash consensus.BlockHash) (*bls.Signature, error) {
	payload := consensus.GetVoteSignaturePayload(view, blockHash)
	return signer.privateKey.Sign(payload[:])
}

func (signer *BLSSigner) SignValidatorTimeout(view uint64, highQCView uint64) (*bls.Signature, error) {
	payload := consensus.GetTimeoutSignaturePayload(view, highQCView)
	return signer.privateKey.Sign(payload[:])
}

func (signer *BLSSigner) SignRandomSeedHash(randomSeedHash *RandomSeedHash) (*bls.Signature, error) {
	return SignRandomSeedHash(signer.privateKey, randomSeedHash)
}

func (signer *BLSSigner) SignPoSValidatorHandshake(nonceSent uint64, nonceReceived uint64, tstampMicro uint64) (*bls.Signature, error) {
	// FIXME
	payload := []byte{}
	return signer.privateKey.Sign(payload[:])
}

//////////////////////////////////////////////////////////
// BLS Verification
//////////////////////////////////////////////////////////

func _blsVerify(payload []byte, signature *bls.Signature, publicKey *bls.PublicKey) (bool, error) {
	return publicKey.Verify(signature, payload)
}

func BLSVerifyValidatorVote(view uint64, blockHash consensus.BlockHash, signature *bls.Signature, publicKey *bls.PublicKey) (bool, error) {
	payload := consensus.GetVoteSignaturePayload(view, blockHash)
	return _blsVerify(payload[:], signature, publicKey)
}

func BLSVerifyValidatorTimeout(view uint64, highQCView uint64, signature *bls.Signature, publicKey *bls.PublicKey) (bool, error) {
	payload := consensus.GetTimeoutSignaturePayload(view, highQCView)
	return _blsVerify(payload[:], signature, publicKey)
}

func BLSVerifyPoSValidatorHandshake(
	nonceSent uint64,
	nonceReceived uint64,
	tstampMicro uint64,
	signature *bls.Signature,
	publicKey *bls.PublicKey,
) (bool, error) {
	// FIXME
	payload := []byte{}
	return _blsVerify(payload[:], signature, publicKey)
}
