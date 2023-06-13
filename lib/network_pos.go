package lib

import (
	"bytes"
	"fmt"

	"github.com/deso-protocol/core/bls"
	"github.com/pkg/errors"
)

// ==================================================================
// Proof of Stake Vote Message
// ==================================================================

type MsgDeSoValidatorVote struct {
	MsgVersion uint8

	// BLS public key of the validator voting for this block. This can be
	// mapped directly to the validator's ECDSA public key to verify their
	// stale. We include the BLS public key here so that it's easy to verify
	// the signature on the block without having to look up the validator's
	// ECDSA public key.
	ValidatorVotingPublicKey *bls.PublicKey

	// The block hash corresponding to the block that this vote is for.
	BlockHash *BlockHash

	// TODO: Do we want to add BlockHeight and ProposedInView here too? They're
	// not strictly necessary because they can be looked up based on BlockHash,
	// but they are convenient to have on-hand here for debugging.

	// The validator's partial BLS signature of the block hash, representing
	// the validator's vote for this block. The block hash captures the block
	// height and view.
	VotePartialSignature *bls.Signature
}

func (msg *MsgDeSoValidatorVote) GetMsgType() MsgType {
	return MsgTypeValidatorVote
}

func (msg *MsgDeSoValidatorVote) ToBytes(bool) ([]byte, error) {
	if msg.MsgVersion != ValidatorVoteVersion0 {
		return nil, fmt.Errorf("MsgDeSoValidatorVote.ToBytes: Invalid MsgVersion %d", msg.MsgVersion)
	}

	retBytes := []byte{}

	// MsgVersion
	retBytes = append(retBytes, msg.MsgVersion)

	// ValidatorVotingPublicKey
	if msg.ValidatorVotingPublicKey == nil {
		return nil, errors.New("MsgDeSoValidatorTimeout.ToBytes: HighQC must not be nil")
	}
	encodedValidatorVotingPublicKey := msg.ValidatorVotingPublicKey.ToBytes()
	retBytes = append(retBytes, UintToBuf(uint64(len(encodedValidatorVotingPublicKey)))...)
	retBytes = append(retBytes, msg.ValidatorVotingPublicKey.ToBytes()...)

	// BlockHash
	if msg.BlockHash == nil {
		return nil, errors.New("MsgDeSoValidatorTimeout.ToBytes: BlockHash must not be nil")
	}
	retBytes = append(retBytes, msg.BlockHash.ToBytes()...)

	// VotePartialSignature
	if msg.VotePartialSignature == nil {
		return nil, errors.New("MsgDeSoValidatorTimeout.ToBytes: VotePartialSignature must not be nil")
	}
	retBytes = append(retBytes, msg.VotePartialSignature.ToBytes()...)

	return retBytes, nil
}

func (msg *MsgDeSoValidatorVote) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// MsgVersion
	msgVersion, err := rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Problem reading MsgVersion")
	}
	if msgVersion != ValidatorVoteVersion0 {
		return fmt.Errorf("MsgDeSoValidatorVote.FromBytes: Invalid MsgVersion %d", msgVersion)
	}
	msg.MsgVersion = msgVersion

	// ValidatorVotingPublicKey
	validatorVotingPublicKeyLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Problem reading length for ValidatorVotingPublicKey")
	}
	validatorVotingPublicKeyBytes := make([]byte, validatorVotingPublicKeyLen)
	_, err = rr.Read(validatorVotingPublicKeyBytes)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Problem reading ValidatorVotingPublicKey")
	}
	validatorVotingPublicKey, err := (&bls.PublicKey{}).FromBytes(validatorVotingPublicKeyBytes)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Problem decoding ValidatorVotingPublicKey")
	}
	msg.ValidatorVotingPublicKey = validatorVotingPublicKey

	// BlockHash
	blockHashBytes := make([]byte, HashSizeBytes)
	_, err = rr.Read(blockHashBytes)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Problem reading BlockHash")
	}

	// VotePartialSignature
	// TODO

	return nil
}

// ==================================================================
// Proof of Stake Timeout Message
// ==================================================================

type MsgDeSoValidatorTimeout struct {
	MsgVersion uint8

	// BLS public key of the validator that's timed out for this block. This
	// public key can be mapped directly to the validator's ECDSA public key
	// to verify their stale. We include the BLS public key here so that it's
	// easy to verify the signature on the block without having to look up the
	// validator's ECDSA public key.
	ValidatorVotingPublicKey *bls.PublicKey

	// The view that the validator has timed out on and to skip over because
	// they haven't received a valid block for it and they timed out.
	TimedOutView uint64

	// This BlockQuorumCertificate has the highest view that the validator is aware
	// of. This QC allows the leader to link back to the most recent block that
	// 2/3rds of validators are aware of when constructing the next block.
	HighQC *BlockQuorumCertificate

	// A signature of (TimeoutView, HighQC.View) that indicates this validator
	// wants to timeout. Notice that we include the HighQC.View in the signature
	// payload rather than signing the full serialized HighQC itself. This allows
	// the leader to better aggregate validator signatures without compromising the
	// integrity of the protocol.
	TimeoutPartialSignature *bls.Signature
}

func (msg *MsgDeSoValidatorTimeout) GetMsgType() MsgType {
	return MsgTypeValidatorTimeout
}

func (msg *MsgDeSoValidatorTimeout) ToBytes(bool) ([]byte, error) {
	if msg.MsgVersion != ValidatorTimeoutVersion0 {
		return nil, fmt.Errorf("MsgDeSoValidatorTimeout.ToBytes: Invalid MsgVersion %d", msg.MsgVersion)
	}

	retBytes := []byte{}

	// MsgVersion
	retBytes = append(retBytes, msg.MsgVersion)

	// ValidatorVotingPublicKey
	if msg.ValidatorVotingPublicKey == nil {
		return nil, errors.New("MsgDeSoValidatorTimeout.ToBytes: ValidatorVotingPublicKey must not be nil")
	}
	retBytes = append(retBytes, msg.ValidatorVotingPublicKey.ToBytes()...)

	// TimeoutView
	retBytes = append(retBytes, UintToBuf(msg.TimedOutView)...)

	// HighQC
	if msg.HighQC == nil {
		return nil, errors.New("MsgDeSoValidatorTimeout.ToBytes: HighQC must not be nil")
	}
	encodedHighQC, err := msg.HighQC.ToBytes()
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoValidatorTimeout.ToBytes: Problem encoding HighQC")
	}
	retBytes = append(retBytes, encodedHighQC...)

	// TimeoutPartialSignature
	if msg.TimeoutPartialSignature == nil {
		return nil, errors.New("MsgDeSoValidatorTimeout.ToBytes: TimeoutPartialSignature must not be nil")
	}
	retBytes = append(retBytes, msg.TimeoutPartialSignature.ToBytes()...)

	return retBytes, nil
}

func (msg *MsgDeSoValidatorTimeout) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// MsgVersion
	msgVersion, err := rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Problem reading MsgVersion")
	}
	if msgVersion != ValidatorVoteVersion0 {
		return fmt.Errorf("MsgDeSoValidatorVote.FromBytes: Invalid MsgVersion %d", msgVersion)
	}
	msg.MsgVersion = msgVersion

	// ValidatorVotingPublicKey
	// TODO

	// TimedOutView
	// TODO

	// HighQC
	// TODO

	// TimeoutPartialSignature
	// TODO

	return nil
}

// A QuorumCertificate contains an aggregated signature from 2/3rds of the validators
// on the network, weighted by stake. The signatures are associated with a block hash
// and view both of which are identified in the certificate.
type BlockQuorumCertificate struct {
	// No versioning field is needed for this type since it is a member field
	// for other top-level P2P messages, which will be versioned themselves.

	// The block hash corresponding to the block that this QC authorizes.
	BlockHash *BlockHash

	// The view number when the the block was proposed.
	ProposedInView uint64

	// This BLS signature is aggregated from all of the partial BLS signatures for vote
	// messages that have been aggregated by the leader. The partial signatures sign the
	// block hash for the block this QC authorizes.
	//
	// Based on the block hash, we can determine the view number, block height, and ordering
	// of validators in this signature.
	AggregatedVoteSignature *bls.Signature
}

func (qc *BlockQuorumCertificate) ToBytes() ([]byte, error) {
	retBytes := []byte{}

	// BlockHash
	if qc.BlockHash == nil {
		return nil, errors.New("QuorumCertificate.ToBytes: BlockHash must not be nil")
	}
	retBytes = append(retBytes, qc.BlockHash.ToBytes()...)

	// ProposedInView
	retBytes = append(retBytes, UintToBuf(qc.ProposedInView)...)

	// AggregatedVoteSignature
	if qc.AggregatedVoteSignature == nil {
		return nil, errors.New("QuorumCertificate.ToBytes: AggregatedVoteSignature must not be nil")
	}
	retBytes = append(retBytes, qc.AggregatedVoteSignature.ToBytes()...)

	return retBytes, nil
}

func (qc *BlockQuorumCertificate) Read(rr *bytes.Reader) error {
	return nil
}
