package lib

import (
	"bytes"
	"fmt"
	"io"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/utils/bitset"
	"github.com/pkg/errors"
)

// ==================================================================
// Proof of Stake Vote Message
// ==================================================================

type MsgDeSoValidatorVote struct {
	MsgVersion MsgValidatorVoteVersion

	// The ECDSA public key for the validator who constructed this vote message.
	// Given the validator's ECDSA public key, we can look up their Validator PKID
	// and their stake in consensus. This allows us to verify that the vote message
	// was sent by a registered validator.
	ValidatorPublicKey *PublicKey
	// The BLS voting public key for the validator who constructed this vote message.
	// The BLS public key is included in the vote message because it allows us to
	// easily verify if the BLS VotePartialSignature is correctly formed, without having
	// to first look up the validator's BLS public key in consensus. It helps optimize
	// vote validation.
	ValidatorVotingPublicKey *bls.PublicKey

	// The block hash corresponding to the block that this vote is for.
	BlockHash *BlockHash

	// The view number when the the block was proposed.
	ProposedInView uint64

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

	// ValidatorPublicKey
	if msg.ValidatorPublicKey == nil {
		return nil, errors.New("MsgDeSoValidatorVote.ToBytes: ValidatorPublicKey must not be nil")
	}
	retBytes = append(retBytes, msg.ValidatorPublicKey.ToBytes()...)

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

	// ValidatorPublicKey
	msg.ValidatorPublicKey, err = ReadPublicKey(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Error decoding ValidatorPublicKey")
	}

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
	MsgVersion MsgValidatorTimeoutVersion

	// The ECDSA public key for the validator who constructed this timeout message.
	// Given the validator's ECDSA public key, we can look up their Validator PKID.
	// This allows us to verify that the timeout originated from a registered validator.
	ValidatorPublicKey *PublicKey
	// The BLS voting public key for the validator who constructed this timeout. The BLS
	// public key is included in the timeout message because it allows us to easily
	// verify that the BLS TimeoutPartialSignature is correctly formed, without having to
	// first look up the validator's BLS public key in consensus. It helps optimize timeout
	// message validation.
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

	// ValidatorPublicKey
	if msg.ValidatorPublicKey == nil {
		return nil, errors.New("MsgDeSoValidatorTimeout.ToBytes: ValidatorPublicKey must not be nil")
	}
	retBytes = append(retBytes, msg.ValidatorPublicKey.ToBytes()...)

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

	// ValidatorPublicKey
	msg.ValidatorPublicKey, err = ReadPublicKey(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Error decoding ValidatorPublicKey")
	}

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

	qc.ValidatorsVoteAggregatedSignature = &AggregatedBLSSignature{}
	if err = qc.ValidatorsVoteAggregatedSignature.FromBytes(rr); err != nil {
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
	SignersList *bitset.Bitset
	Signature   *bls.Signature
}

func (sig *AggregatedBLSSignature) Eq(other *AggregatedBLSSignature) bool {
	if sig == nil && other == nil {
		return true
	}

	if (sig == nil) != (other == nil) {
		return false
	}

	if !sig.Signature.Eq(other.Signature) {
		return false
	}

	return bytes.Equal(sig.SignersList.ToBytes(), other.SignersList.ToBytes())
}

func (sig *AggregatedBLSSignature) ToBytes() ([]byte, error) {
	retBytes := []byte{}

	// SignersList
	if sig.SignersList == nil {
		return nil, errors.New("AggregatedBLSSignature.ToBytes: SignersList must not be nil")
	}
	retBytes = append(retBytes, EncodeBitset(sig.SignersList)...)

	// Signature
	if sig.Signature == nil {
		return nil, errors.New("AggregatedBLSSignature.ToBytes: Signature must not be nil")
	}
	retBytes = append(retBytes, EncodeBLSSignature(sig.Signature)...)

	return retBytes, nil
}

func (sig *AggregatedBLSSignature) FromBytes(rr io.Reader) error {
	var err error

	sig.SignersList, err = DecodeBitset(rr)
	if err != nil {
		return errors.Wrapf(err, "AggregatedBLSSignature.FromBytes: Error decoding SignersList")
	}

	sig.Signature, err = DecodeBLSSignature(rr)
	if err != nil {
		return errors.Wrapf(err, "AggregatedBLSSignature.FromBytes: Error decoding Signature")
	}

	return nil
}

// TimeoutAggregateQuorumCertificate is an aggregation of timeout messages from 2/3rds
// of all validators, weighted by stake, which indicates that these validators want to
// time out a particular view.
//
// When validators want to time out a view, they send their high QCs to the block proposer
// who builds an aggregate QC extending the chain from the highest QC that it received
// from all validators who timed out. To prove that it has selected the highest QC, the
// proposer also includes a list of the high QC views that each validator has sent.
type TimeoutAggregateQuorumCertificate struct {

	// The view that the block proposers has produced a timeout QC for.
	TimedOutView uint64

	// This is the highest QC that the block proposer received from any validator who
	// has timed out for the current view.
	ValidatorsHighQC *QuorumCertificate

	// Here we include a list of the HighQC.View values we got from each of the
	// validators in the ValidatorsTimeoutHighQCViews field. In addition, for each
	// unique HighQC.View value we received, we combine all the partial signatures
	// for that HighQC.View into a single BLSMultiSignature.
	//
	//
	// The aggregated signature is made up of partial signatures for all present
	// validators, each of whom signed a payload with the pair
	// (current view, the validator's local HighQC.View).
	//
	// The ordering of high QC views and validators in the aggregate signature will
	// match the ordering of active validators in descending order of stake for the
	// current view's epoch. I.e. index 0 will correspond to the highest-staked active
	// validator in the epoch, index 1 will correspond to the second-highest-staked active
	// validator, ...
	ValidatorsTimeoutHighQCViews         []uint64
	ValidatorsTimeoutAggregatedSignature *AggregatedBLSSignature
}

// Performs a deep equality check between two TimeoutAggregateQuorumCertificate, and
// returns true if the values of the two are identical.
func (aggQC *TimeoutAggregateQuorumCertificate) Eq(
	other *TimeoutAggregateQuorumCertificate,
) bool {
	if aggQC == nil && other == nil {
		return true
	}

	if (aggQC == nil) != (other == nil) {
		return false
	}

	if len(aggQC.ValidatorsTimeoutHighQCViews) != len(other.ValidatorsTimeoutHighQCViews) {
		return false
	}

	if aggQC.TimedOutView != other.TimedOutView {
		return false
	}

	if !aggQC.ValidatorsHighQC.Eq(other.ValidatorsHighQC) {
		return false
	}

	if !aggQC.ValidatorsTimeoutAggregatedSignature.Eq(other.ValidatorsTimeoutAggregatedSignature) {
		return false
	}

	for i := 0; i < len(aggQC.ValidatorsTimeoutHighQCViews); i++ {
		if aggQC.ValidatorsTimeoutHighQCViews[i] != other.ValidatorsTimeoutHighQCViews[i] {
			return false
		}
	}

	return true
}

func (aggQC *TimeoutAggregateQuorumCertificate) ToBytes() ([]byte, error) {
	retBytes := []byte{}

	// TimedOutView
	retBytes = append(retBytes, UintToBuf(aggQC.TimedOutView)...)

	// ValidatorsHighQC
	if aggQC.ValidatorsHighQC == nil {
		return nil, errors.New("TimeoutAggregateQuorumCertificate.ToBytes: ValidatorsHighQC must not be nil")
	}
	encodedValidatorsHighQC, err := aggQC.ValidatorsHighQC.ToBytes()
	if err != nil {
		return nil, errors.Wrapf(err, "TimeoutAggregateQuorumCertificate.ToBytes: Error encoding ValidatorsHighQC")
	}
	retBytes = append(retBytes, encodedValidatorsHighQC...)

	// ValidatorsTimeoutHighQCViews
	retBytes = append(retBytes, EncodeUint64Array(aggQC.ValidatorsTimeoutHighQCViews)...)

	// ValidatorsTimeoutAggregatedSignature
	if aggQC.ValidatorsTimeoutAggregatedSignature == nil {
		return nil, errors.New("TimeoutAggregateQuorumCertificate.ToBytes: ValidatorsTimeoutAggregatedSignature must not be nil")
	}
	encodedValidatorsTimeoutAggregatedSignature, err := aggQC.ValidatorsTimeoutAggregatedSignature.ToBytes()
	if err != nil {
		return nil, errors.Wrapf(err, "TimeoutAggregateQuorumCertificate.ToBytes: Error encoding ValidatorsTimeoutAggregatedSignature")
	}
	retBytes = append(retBytes, encodedValidatorsTimeoutAggregatedSignature...)

	return retBytes, nil
}

func (aggQC *TimeoutAggregateQuorumCertificate) FromBytes(rr io.Reader) error {
	var err error

	aggQC.TimedOutView, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "TimeoutAggregateQuorumCertificate.FromBytes: Error decoding TimedOutView")
	}

	aggQC.ValidatorsHighQC, err = DecodeQuorumCertificate(rr)
	if err != nil {
		return errors.Wrapf(err, "TimeoutAggregateQuorumCertificate.FromBytes: Error decoding ValidatorsHighQC")
	}

	aggQC.ValidatorsTimeoutHighQCViews, err = DecodeUint64Array(rr)
	if err != nil {
		return errors.Wrapf(err, "TimeoutAggregateQuorumCertificate.FromBytes: Error decoding ValidatorsTimeoutHighQCViews")
	}

	aggQC.ValidatorsTimeoutAggregatedSignature = &AggregatedBLSSignature{}
	if aggQC.ValidatorsTimeoutAggregatedSignature.FromBytes(rr); err != nil {
		return errors.Wrapf(err, "TimeoutAggregateQuorumCertificate.FromBytes: Error decoding ValidatorsTimeoutAggregatedSignature")
	}

	return nil
}

// ==================================================================
// Bitset Utils
// ==================================================================

func EncodeBitset(b *bitset.Bitset) []byte {
	var encodedBytes []byte
	if b != nil {
		encodedBytes = b.ToBytes()
	}
	return EncodeByteArray(encodedBytes)
}

func DecodeBitset(rr io.Reader) (*bitset.Bitset, error) {
	encodedBytes, err := DecodeByteArray(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeBitset: Error decoding bitset")
	}
	return (bitset.NewBitset()).FromBytes(encodedBytes), nil
}
