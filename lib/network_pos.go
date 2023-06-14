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

	// BLS voting public key of the validator who constructed this vote. This public
	// key can be mapped directly to the validator's ECDSA public key to verify
	// their stake. We use the BLS public key here instead of the ECDSA so that
	// so that it's trivial to verify the signature in this message without
	// having to look up anything for the validator in consensus.
	ValidatorVotingPublicKey *bls.PublicKey

	// The block hash corresponding to the block that this vote is for.
	BlockHash *BlockHash

	// The view number when the the block was proposed.
	ProposedInView uint64

	// TODO: Do we want to add BlockHeight here too? It's not strictly necessary
	// because it can be derived based on BlockHash alone, but it is convenient
	// to have on-hand here for debugging. The trade-off of including it is that
	// it results in a larger size message. In general, we should try to keep the
	// size of vote messages as small as possible as there will be O(n) votes per block
	// where n is the number of validators.

	// The validator's partial BLS signature of the (ProposedInView, BlockHash) pair
	// This represents the validator's vote for this block. The block height is implicitly
	// captured in the block hash.
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
		return nil, errors.New("MsgDeSoValidatorVote.ToBytes: ValidatorVotingPublicKey must not be nil")
	}
	retBytes = append(retBytes, EncodeBLSPublicKey(msg.ValidatorVotingPublicKey)...)

	// BlockHash
	if msg.BlockHash == nil {
		return nil, errors.New("MsgDeSoValidatorVote.ToBytes: BlockHash must not be nil")
	}
	retBytes = append(retBytes, msg.BlockHash.ToBytes()...)

	// ProposedInView
	retBytes = append(retBytes, UintToBuf(msg.ProposedInView)...)

	// VotePartialSignature
	if msg.VotePartialSignature == nil {
		return nil, errors.New("MsgDeSoValidatorVote.ToBytes: VotePartialSignature must not be nil")
	}
	retBytes = append(retBytes, EncodeBLSSignature(msg.VotePartialSignature)...)

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
	msg.ValidatorVotingPublicKey, err = DecodeBLSPublicKey(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Problem decoding ValidatorVotingPublicKey")
	}

	// BlockHash
	msg.BlockHash, err = ReadBlockHash(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Problem reading BlockHash")
	}

	// ProposedInView
	msg.ProposedInView, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Problem reading ProposedInView")
	}

	// VotePartialSignature
	msg.VotePartialSignature, err = DecodeBLSSignature(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Problem decoding VotePartialSignature")
	}

	return nil
}

// ==================================================================
// Proof of Stake Timeout Message
// ==================================================================

type MsgDeSoValidatorTimeout struct {
	MsgVersion uint8

	// BLS voting public key of the validator who constructed this timeout message.
	// The public key can be mapped directly to the validator's ECDSA public key
	// to verify their stake. We use the BLS public key here instead of the ECDSA
	// so that so that it's trivial to verify the signature in this message without
	// having to look up anything for the validator in consensus.
	ValidatorVotingPublicKey *bls.PublicKey

	// The view that the validator has timed out on.
	TimedOutView uint64

	// This QC has the highest view that the validator is aware of. This QC allows
	// the leader to link back to the most recent block that 2/3rds of validators
	// are aware of when constructing the next block.
	HighQC *VoteQuorumCertificate

	// The validator's BLS signature on (TimedOutView, HighQC.View). Notice that we
	// include the HighQC.View in the signature payload rather than signing the full
	// serialized HighQC itself. This allows the leader to better aggregate validator
	// signatures without compromising the integrity of the protocol.
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
	retBytes = append(retBytes, EncodeBLSPublicKey(msg.ValidatorVotingPublicKey)...)

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
	retBytes = append(retBytes, EncodeBLSSignature(msg.TimeoutPartialSignature)...)

	return retBytes, nil
}

func (msg *MsgDeSoValidatorTimeout) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// MsgVersion
	msgVersion, err := rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Problem reading MsgVersion")
	}
	if msgVersion != ValidatorVoteVersion0 {
		return fmt.Errorf("MsgDeSoValidatorTimeout.FromBytes: Invalid MsgVersion %d", msgVersion)
	}
	msg.MsgVersion = msgVersion

	// ValidatorVotingPublicKey
	msg.ValidatorVotingPublicKey, err = DecodeBLSPublicKey(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Problem decoding ValidatorVotingPublicKey")
	}

	// TimedOutView
	msg.TimedOutView, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Problem reading TimedOutView")
	}

	// HighQC
	msg.HighQC, err = DecodeQuorumCertificate(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Problem reading HighQC")
	}

	// TimeoutPartialSignature
	msg.TimeoutPartialSignature, err = DecodeBLSSignature(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Problem decoding TimeoutPartialSignature")
	}

	return nil
}

// A QuorumCertificate contains an aggregated signature from 2/3rds of the validators
// on the network, weighted by stake. The signatures are associated with a block hash
// and a view, both of which are identified in the certificate.
type VoteQuorumCertificate struct {
	// No versioning field is needed for this type since it is a member field
	// for other top-level P2P messages, which will be versioned themselves.

	// The block hash corresponding to the block that this QC authorizes.
	BlockHash *BlockHash

	// The view number when the the block was proposed.
	ProposedInView uint64

	// This BLS signature is aggregated from all of the partial BLS signatures for vote
	// messages that have been aggregated by the leader. The partial signatures sign the
	// (ProposedInView, BlockHash) for the block.
	//
	// Based on the block hash, block height, and ordering of validator BLS public keys in
	// the aggregated signature.
	AggregatedVoteSignature *bls.Signature
}

func (qc *VoteQuorumCertificate) ToBytes() ([]byte, error) {
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
	retBytes = append(retBytes, EncodeBLSSignature(qc.AggregatedVoteSignature)...)

	return retBytes, nil
}

func DecodeQuorumCertificate(rr *bytes.Reader) (*VoteQuorumCertificate, error) {
	var qc VoteQuorumCertificate
	var err error

	qc.BlockHash, err = ReadBlockHash(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeQuorumCertificate: Problem reading BlockHash")
	}

	qc.ProposedInView, err = ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeQuorumCertificate: Problem reading ProposedInView")
	}

	qc.AggregatedVoteSignature, err = DecodeBLSSignature(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeQuorumCertificate: Problem reading AggregatedVoteSignature")
	}

	return &qc, nil
}
