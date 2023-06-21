package lib

import (
	"bytes"
	"fmt"
	"io"

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
	if msg.MsgVersion != MsgValidatorVoteVersion0 {
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
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Error decoding MsgVersion")
	}
	if msgVersion != MsgValidatorVoteVersion0 {
		return fmt.Errorf("MsgDeSoValidatorVote.FromBytes: Invalid MsgVersion %d", msgVersion)
	}
	msg.MsgVersion = msgVersion

	// ValidatorVotingPublicKey
	msg.ValidatorVotingPublicKey, err = DecodeBLSPublicKey(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Error decoding ValidatorVotingPublicKey")
	}

	// BlockHash
	msg.BlockHash, err = ReadBlockHash(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Error decoding BlockHash")
	}

	// ProposedInView
	msg.ProposedInView, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Error decoding ProposedInView")
	}

	// VotePartialSignature
	msg.VotePartialSignature, err = DecodeBLSSignature(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Error decoding VotePartialSignature")
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
	HighQC *QuorumCertificate

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
	if msg.MsgVersion != MsgValidatorTimeoutVersion0 {
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
		return nil, errors.Wrapf(err, "MsgDeSoValidatorTimeout.ToBytes: Error encoding HighQC")
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
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Error decoding MsgVersion")
	}
	if msgVersion != MsgValidatorVoteVersion0 {
		return fmt.Errorf("MsgDeSoValidatorTimeout.FromBytes: Invalid MsgVersion %d", msgVersion)
	}
	msg.MsgVersion = msgVersion

	// ValidatorVotingPublicKey
	msg.ValidatorVotingPublicKey, err = DecodeBLSPublicKey(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Error decoding ValidatorVotingPublicKey")
	}

	// TimedOutView
	msg.TimedOutView, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Error decoding TimedOutView")
	}

	// HighQC
	msg.HighQC, err = DecodeQuorumCertificate(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Error decoding HighQC")
	}

	// TimeoutPartialSignature
	msg.TimeoutPartialSignature, err = DecodeBLSSignature(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Error decoding TimeoutPartialSignature")
	}

	return nil
}

// A QuorumCertificate contains an aggregated signature from 2/3rds of the validators
// on the network, weighted by stake. The signatures are associated with a block hash
// and a view, both of which are identified in the certificate.
type QuorumCertificate struct {
	// No versioning field is needed for this type since it is a member field
	// for other top-level P2P messages, which will be versioned themselves.

	// The block hash corresponding to the block that this QC authorizes.
	BlockHash *BlockHash

	// The view number when the the block was proposed.
	ProposedInView uint64

	// This BLS signature is aggregated from all of the partial BLS signatures for
	// vote messages that have been aggregated by the leader. The partial signatures
	// sign the (ProposedInView, BlockHash) pair for the block.
	//
	// From the block hash, we can look up the block height, the validator set at that
	// block height, and the ordering of validators in consensus which identifies the
	// present signers in the provided signers list. We can then use this to determine
	// if the QC has 2/3rds of the total stake.
	ValidatorsVoteAggregatedSignature *AggregatedBLSSignature
}

// Performs a deep equality check between two QuorumCertificates, and returns
// true if the values of the two are identical.
func (qc *QuorumCertificate) Eq(other *QuorumCertificate) bool {
	if qc == nil && other == nil {
		return true
	}

	if (qc == nil) != (other == nil) {
		return false
	}

	return bytes.Equal(qc.BlockHash.ToBytes(), other.BlockHash.ToBytes()) &&
		qc.ProposedInView == other.ProposedInView &&
		qc.ValidatorsVoteAggregatedSignature.Eq(other.ValidatorsVoteAggregatedSignature)
}

func (qc *QuorumCertificate) ToBytes() ([]byte, error) {
	retBytes := []byte{}

	// BlockHash
	if qc.BlockHash == nil {
		return nil, errors.New("QuorumCertificate.ToBytes: BlockHash must not be nil")
	}
	retBytes = append(retBytes, qc.BlockHash.ToBytes()...)

	// ProposedInView
	retBytes = append(retBytes, UintToBuf(qc.ProposedInView)...)

	// ValidatorsVoteAggregatedSignature
	if qc.ValidatorsVoteAggregatedSignature == nil {
		return nil, errors.New("QuorumCertificate.ToBytes: ValidatorsVoteAggregatedSignature must not be nil")
	}
	encodedValidatorsVoteAggregatedSignature, err := qc.ValidatorsVoteAggregatedSignature.ToBytes()
	if err != nil {
		return nil, errors.Wrapf(err, "QuorumCertificate.ToBytes: Error encoding ValidatorsVoteAggregatedSignature")
	}
	retBytes = append(retBytes, encodedValidatorsVoteAggregatedSignature...)

	return retBytes, nil
}

func DecodeQuorumCertificate(rr io.Reader) (*QuorumCertificate, error) {
	var qc QuorumCertificate
	var err error

	qc.BlockHash, err = ReadBlockHash(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeQuorumCertificate: Error decoding BlockHash")
	}

	qc.ProposedInView, err = ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeQuorumCertificate: Error decoding ProposedInView")
	}

	qc.ValidatorsVoteAggregatedSignature, err = DecodeAggregatedBLSSignature(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeQuorumCertificate: Error decoding ValidatorsVoteAggregatedSignature")
	}

	return &qc, nil
}

// This is an aggregated BLS signature from a set of validators. Each validator's
// presence in the signature is denoted in the provided signers list. I.e. if the
// list's value at index 0 is 1, then the validator identified by that index is
// present in the aggregated signature. The indices of all validators are expected
// to be known by the caller.
type AggregatedBLSSignature struct {
	// TODO: Switch this to a bitlist, which will result in ~8x reduction in total
	// size of this construct.
	SignersList []byte
	Signature   *bls.Signature
}

func (sig *AggregatedBLSSignature) Eq(other *AggregatedBLSSignature) bool {
	if sig == nil && other == nil {
		return true
	}

	if (sig == nil) != (other == nil) {
		return false
	}

	return bytes.Equal(sig.SignersList, other.SignersList) &&
		sig.Signature.Eq(other.Signature)
}

func (sig *AggregatedBLSSignature) ToBytes() ([]byte, error) {
	retBytes := []byte{}

	// SignersList
	retBytes = append(retBytes, EncodeByteArray(sig.SignersList)...)

	// Signature
	if sig.Signature == nil {
		return nil, errors.New("AggregatedBLSSignature.ToBytes: Signature must not be nil")
	}
	retBytes = append(retBytes, EncodeBLSSignature(sig.Signature)...)

	return retBytes, nil
}

func DecodeAggregatedBLSSignature(rr io.Reader) (*AggregatedBLSSignature, error) {
	var sig AggregatedBLSSignature
	var err error

	sig.SignersList, err = DecodeByteArray(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeAggregatedBLSSignature: Error decoding SignersList")
	}

	sig.Signature, err = DecodeBLSSignature(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeAggregatedBLSSignature: Error decoding Signature")
	}

	return &sig, nil
}
