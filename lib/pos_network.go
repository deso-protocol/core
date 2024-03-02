package lib

import (
	"bytes"
	"fmt"
	"io"

	"github.com/deso-protocol/core/consensus"
	"golang.org/x/crypto/sha3"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/pkg/errors"
)

// ==================================================================
// Proof of Stake Vote Message
// ==================================================================

type MsgDeSoValidatorVote struct {
	// We use the MsgVersion field to determine how to encode and decode this message to
	// bytes when sending it over the wire. Note, when receiving a message for a peer,
	// we won't always know the block height ahead of time, so we can't rely on block
	// height gating or encoder migrations to determine how to decode the message. So,
	// we rely on a separate message version field whose sole purpose to define how to
	// encode and decode the message.
	MsgVersion MsgValidatorVoteVersion

	// The ECDSA public key for the validator who constructed this vote message.
	// Given the validator's ECDSA public key, we can look up their Validator PKID
	// and their stake in consensus. This allows us to verify that the vote message
	// was sent by a registered validator.
	PublicKey *PublicKey

	// The BLS voting public key for the validator who constructed this vote message.
	// The BLS public key is included in the vote message because it allows us to
	// easily verify if the BLS VotePartialSignature is correctly formed, without having
	// to first look up the validator's BLS public key in consensus. It helps optimize
	// vote validation.
	VotingPublicKey *bls.PublicKey

	// The block hash corresponding to the block that this vote is for.
	BlockHash *BlockHash

	// The view number when the block was proposed.
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

	// VotingPublicKey
	if msg.VotingPublicKey == nil {
		return nil, errors.New("MsgDeSoValidatorVote.ToBytes: VotingPublicKey must not be nil")
	}
	retBytes = append(retBytes, EncodeBLSPublicKey(msg.VotingPublicKey)...)

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

	// VotingPublicKey
	msg.VotingPublicKey, err = DecodeBLSPublicKey(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorVote.FromBytes: Error decoding VotingPublicKey")
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

func (msg *MsgDeSoValidatorVote) ToString() string {
	return fmt.Sprintf(
		"{MsgVersion: %d, VotingPublicKey: %s, BlockHash: %v, ProposedInView: %d, VotePartialSignature: %v}",
		msg.MsgVersion,
		msg.VotingPublicKey.ToAbbreviatedString(),
		msg.BlockHash,
		msg.ProposedInView,
		msg.VotePartialSignature.ToAbbreviatedString(),
	)
}

// ==================================================================
// Proof of Stake Timeout Message
// ==================================================================

type MsgDeSoValidatorTimeout struct {
	// We use the MsgVersion field to determine how to encode and decode this message to
	// bytes when sending it over the wire. Note, when receiving a message for a peer,
	// we won't always know the block height ahead of time, so we can't rely on block
	// height gating or encoder migrations to determine how to decode the message. So,
	// we rely on a separate message version field whose sole purpose to define how to
	// encode and decode the message.
	MsgVersion MsgValidatorTimeoutVersion

	// The BLS voting public key for the validator who constructed this timeout. The BLS
	// public key is included in the timeout message because it allows us to easily
	// verify that the BLS TimeoutPartialSignature is correctly formed, without having to
	// first look up the validator's BLS public key in consensus. It helps optimize timeout
	// message validation.
	VotingPublicKey *bls.PublicKey

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

	// VotingPublicKey
	if msg.VotingPublicKey == nil {
		return nil, errors.New("MsgDeSoValidatorTimeout.ToBytes: VotingPublicKey must not be nil")
	}
	retBytes = append(retBytes, EncodeBLSPublicKey(msg.VotingPublicKey)...)

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

	// VotingPublicKey
	msg.VotingPublicKey, err = DecodeBLSPublicKey(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Error decoding VotingPublicKey")
	}

	// TimedOutView
	msg.TimedOutView, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Error decoding TimedOutView")
	}

	// HighQC
	msg.HighQC = &QuorumCertificate{}
	if err = msg.HighQC.FromBytes(rr); err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Error decoding HighQC")
	}

	// TimeoutPartialSignature
	msg.TimeoutPartialSignature, err = DecodeBLSSignature(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoValidatorTimeout.FromBytes: Error decoding TimeoutPartialSignature")
	}

	return nil
}

func (msg *MsgDeSoValidatorTimeout) ToString() string {
	return fmt.Sprintf(
		"{MsgVersion: %d, VotingPublicKey: %s, TimedOutView: %d, HighQCView: %v, HighQCBlockHash: %v, TimeoutPartialSignature: %s}",
		msg.MsgVersion,
		msg.VotingPublicKey.ToAbbreviatedString(),
		msg.TimedOutView,
		msg.HighQC.ProposedInView,
		msg.HighQC.BlockHash,
		msg.TimeoutPartialSignature.ToAbbreviatedString(),
	)
}

// A QuorumCertificate contains an aggregated signature from 2/3rds of the validators
// on the network, weighted by stake. The signatures are associated with a block hash
// and a view, both of which are identified in the certificate.
type QuorumCertificate struct {
	// No versioning field is needed for this type since it is a member field
	// for other top-level P2P messages, which will be versioned themselves.

	// The block hash corresponding to the block that this QC authorizes.
	BlockHash *BlockHash

	// The view number when the block was proposed.
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

// Performs a deep equality check between two QuorumCertificates, and returns true
// if the two are fully initialized and have identical values. In all other cases,
// it return false.
func (qc *QuorumCertificate) Eq(other *QuorumCertificate) bool {
	if qc == nil || other == nil {
		return false
	}

	qcEncodedBytes, err := qc.ToBytes()
	if err != nil {
		return false
	}

	otherEncodedBytes, err := other.ToBytes()
	if err != nil {
		return false
	}

	return bytes.Equal(qcEncodedBytes, otherEncodedBytes)
}

func (qc *QuorumCertificate) isEmpty() bool {
	return qc == nil ||
		qc.BlockHash == nil ||
		qc.ProposedInView == 0 ||
		qc.ValidatorsVoteAggregatedSignature == nil ||
		qc.ValidatorsVoteAggregatedSignature.Signature == nil ||
		qc.ValidatorsVoteAggregatedSignature.SignersList == nil
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

func (qc *QuorumCertificate) FromBytes(rr io.Reader) error {
	var err error

	qc.BlockHash, err = ReadBlockHash(rr)
	if err != nil {
		return errors.Wrapf(err, "QuorumCertificate.FromBytes: Error decoding BlockHash")
	}

	qc.ProposedInView, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "QuorumCertificate.FromBytes: Error decoding ProposedInView")
	}

	qc.ValidatorsVoteAggregatedSignature = &AggregatedBLSSignature{}
	if err = qc.ValidatorsVoteAggregatedSignature.FromBytes(rr); err != nil {
		return errors.Wrapf(err, "QuorumCertificate.FromBytes: Error decoding ValidatorsVoteAggregatedSignature")
	}

	return nil
}

func EncodeQuorumCertificate(qc *QuorumCertificate) ([]byte, error) {
	if qc == nil {
		return EncodeByteArray(nil), nil
	}

	encodedBytes, err := qc.ToBytes()
	if err != nil {
		return nil, errors.Wrapf(err, "EncodeQuorumCertificate: Error encoding qc")
	}

	return EncodeByteArray(encodedBytes), nil
}

func DecodeQuorumCertificate(rr io.Reader) (*QuorumCertificate, error) {
	encodedBytes, err := DecodeByteArray(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeQuorumCertificate: Error decoding encodedBytes")
	}

	if len(encodedBytes) == 0 {
		return nil, nil
	}

	qc := &QuorumCertificate{}
	if err := qc.FromBytes(bytes.NewReader(encodedBytes)); err != nil {
		return nil, errors.Wrapf(err, "DecodeQuorumCertificate: Error decoding qc")
	}

	return qc, nil
}

// This is an aggregated BLS signature from a set of validators. Each validator's
// presence in the signature is denoted in the provided signers list. I.e. if the
// list's value at index 0 is 1, then the validator identified by that index is
// present in the aggregated signature.
//
// The validators in the signers list will match the ordering of active validators
// in descending order of stake for the relevant view's epoch. I.e. index 0 will
// correspond to the highest-staked active validator in the epoch, index 1 will
// correspond to the second-highest-staked active validator, ...
type AggregatedBLSSignature struct {
	SignersList *bitset.Bitset
	Signature   *bls.Signature
}

// Performs a deep equality check between two AggregatedBLSSignatures, and returns true
// if the two are fully initialized and have identical values. In all other cases,
// it return false.
func (sig *AggregatedBLSSignature) Eq(other *AggregatedBLSSignature) bool {
	if sig == nil || other == nil {
		return false
	}

	sigEncodedBytes, err := sig.ToBytes()
	if err != nil {
		return false
	}

	otherEncodedBytes, err := other.ToBytes()
	if err != nil {
		return false
	}

	return bytes.Equal(sigEncodedBytes, otherEncodedBytes)
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
	// timed out view's epoch. I.e. index 0 will correspond to the highest-staked active
	// validator in the epoch, index 1 will correspond to the second-highest-staked active
	// validator, ...
	ValidatorsTimeoutHighQCViews         []uint64
	ValidatorsTimeoutAggregatedSignature *AggregatedBLSSignature
}

func (aggQC *TimeoutAggregateQuorumCertificate) GetView() uint64 {
	return aggQC.TimedOutView
}

func (aggQC *TimeoutAggregateQuorumCertificate) GetHighQC() consensus.QuorumCertificate {
	return aggQC.ValidatorsHighQC
}

func (aggQC *TimeoutAggregateQuorumCertificate) GetHighQCViews() []uint64 {
	return aggQC.ValidatorsTimeoutHighQCViews
}

func (aggQC *TimeoutAggregateQuorumCertificate) GetAggregatedSignature() consensus.AggregatedSignature {
	return aggQC.ValidatorsTimeoutAggregatedSignature
}

// Performs a deep equality check between two TimeoutAggregateQuorumCertificates, and
// returns true if the two are fully initialized and have identical values. In all other
// cases, it return false.
func (aggQC *TimeoutAggregateQuorumCertificate) Eq(
	other *TimeoutAggregateQuorumCertificate,
) bool {
	if aggQC == nil || other == nil {
		return false
	}

	aggQcEncodedBytes, err := aggQC.ToBytes()
	if err != nil {
		return false
	}

	otherEncodedBytes, err := other.ToBytes()
	if err != nil {
		return false
	}

	return bytes.Equal(aggQcEncodedBytes, otherEncodedBytes)
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

	aggQC.ValidatorsHighQC = &QuorumCertificate{}
	if err = aggQC.ValidatorsHighQC.FromBytes(rr); err != nil {
		return errors.Wrapf(err, "TimeoutAggregateQuorumCertificate.FromBytes: Error decoding ValidatorsHighQC")
	}

	aggQC.ValidatorsTimeoutHighQCViews, err = DecodeUint64Array(rr)
	if err != nil {
		return errors.Wrapf(err, "TimeoutAggregateQuorumCertificate.FromBytes: Error decoding ValidatorsTimeoutHighQCViews")
	}

	aggQC.ValidatorsTimeoutAggregatedSignature = &AggregatedBLSSignature{}
	if err = aggQC.ValidatorsTimeoutAggregatedSignature.FromBytes(rr); err != nil {
		return errors.Wrapf(err, "TimeoutAggregateQuorumCertificate.FromBytes: Error decoding ValidatorsTimeoutAggregatedSignature")
	}

	return nil
}

// isEmpty returns true if the TimeoutAggregateQuorumCertificate is nil or if it contains no data.
// Reference implementation: https://github.com/deso-protocol/hotstuff_pseudocode/blob/6409b51c3a9a953b383e90619076887e9cebf38d/fast_hotstuff_bls.go#L119
func (aggQC *TimeoutAggregateQuorumCertificate) isEmpty() bool {
	return aggQC == nil ||
		aggQC.TimedOutView == 0 ||
		aggQC.ValidatorsHighQC.isEmpty() ||
		len(aggQC.ValidatorsTimeoutHighQCViews) == 0 ||
		aggQC.ValidatorsTimeoutAggregatedSignature == nil ||
		aggQC.ValidatorsTimeoutAggregatedSignature.Signature == nil ||
		aggQC.ValidatorsTimeoutAggregatedSignature.SignersList == nil
}

func EncodeTimeoutAggregateQuorumCertificate(aggQC *TimeoutAggregateQuorumCertificate) ([]byte, error) {
	if aggQC == nil {
		return EncodeByteArray(nil), nil
	}

	encodedBytes, err := aggQC.ToBytes()
	if err != nil {
		return nil, errors.Wrapf(err, "EncodeTimeoutAggregateQuorumCertificate: Error encoding aggQC")
	}

	return EncodeByteArray(encodedBytes), nil
}

func DecodeTimeoutAggregateQuorumCertificate(rr io.Reader) (*TimeoutAggregateQuorumCertificate, error) {
	encodedBytes, err := DecodeByteArray(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeTimeoutAggregateQuorumCertificate: Error decoding encodedBytes")
	}

	if len(encodedBytes) == 0 {
		return nil, nil
	}

	aggQC := &TimeoutAggregateQuorumCertificate{}
	if err := aggQC.FromBytes(bytes.NewReader(encodedBytes)); err != nil {
		return nil, errors.Wrapf(err, "DecodeTimeoutAggregateQuorumCertificate: Error decoding aggQC")
	}

	return aggQC, nil
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

func HashBitset(b *bitset.Bitset) *BlockHash {
	encodedBytes := EncodeBitset(b)
	hash := sha3.Sum256(encodedBytes)
	return NewBlockHash(hash[:])
}
