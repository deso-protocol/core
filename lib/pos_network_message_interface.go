package lib

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/deso-protocol/core/consensus"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
)

//////////////////////////////////////////////////////////////////////////////////
// This file implements the network message interfaces for the PoS messages     //
// defined in the consensus package. These interfaces are used by the consensus //
// package to run the Fast-HotStuff protocol. This file is a good spot to       //
// place all translations between types defined in lib and consensus packages.  //
//////////////////////////////////////////////////////////////////////////////////

// MsgDeSoHeader struct <-> consensus.Block interface translation

func (msg *MsgDeSoHeader) GetBlockHash() consensus.BlockHash {
	hash, err := msg.Hash()
	if err != nil {
		glog.Errorf("MsgDeSoHeader.GetBlockHash: Problem hashing header: %v", err)
		// If we can't generate the block hash, return an empty hash. We return a non-nil
		// value to avoid panics. An empty block hash will always have a value that can
		// be compared to other block hashes.
		return &BlockHash{}
	}
	return hash
}

func (msg *MsgDeSoHeader) GetView() uint64 {
	// Header version 0 and 1 are Proof of Work block header versions, and do not have a view.
	// In order to be able to extend from a PoW block once the PoS chain begins, we need some
	// way to attach a "view" to it. Using the PoW block's height as its view allows us to do
	// this in a simple and self-contained way.
	//
	// With this change, PoW blocks can be considered to always have their view = height. As
	// a result, PoS blocks will always have their view >= height.
	if msg.Version < HeaderVersion2 {
		return msg.Height
	}
	return msg.ProposedInView
}

func (msg *MsgDeSoHeader) GetQC() consensus.QuorumCertificate {
	if msg.ValidatorsTimeoutAggregateQC.isEmpty() {
		return msg.ValidatorsVoteQC
	}
	return msg.ValidatorsTimeoutAggregateQC.ValidatorsHighQC
}

// MsgDeSoValidatorVote struct <-> consensus.VoteMessage interface translation

func (msg *MsgDeSoValidatorVote) GetPublicKey() *bls.PublicKey {
	return msg.VotingPublicKey
}

func (msg *MsgDeSoValidatorVote) GetView() uint64 {
	return msg.ProposedInView
}

func (msg *MsgDeSoValidatorVote) GetBlockHash() consensus.BlockHash {
	return msg.BlockHash
}

func (msg *MsgDeSoValidatorVote) GetSignature() *bls.Signature {
	return msg.VotePartialSignature
}

// MsgDeSoValidatorTimeout struct <-> consensus.TimeoutMessage interface translation

func (msg *MsgDeSoValidatorTimeout) GetPublicKey() *bls.PublicKey {
	return msg.VotingPublicKey
}

func (msg *MsgDeSoValidatorTimeout) GetView() uint64 {
	return msg.TimedOutView
}

func (msg *MsgDeSoValidatorTimeout) GetHighQC() consensus.QuorumCertificate {
	return msg.HighQC
}

func (msg *MsgDeSoValidatorTimeout) GetSignature() *bls.Signature {
	return msg.TimeoutPartialSignature
}

// QuorumCertificate struct <-> consensus.QuorumCertificate interface translation

func (qc *QuorumCertificate) GetBlockHash() consensus.BlockHash {
	return qc.BlockHash
}

func (qc *QuorumCertificate) GetView() uint64 {
	return qc.ProposedInView
}

func (qc *QuorumCertificate) GetAggregatedSignature() consensus.AggregatedSignature {
	return qc.ValidatorsVoteAggregatedSignature
}

func QuorumCertificateFromConsensusInterface(qc consensus.QuorumCertificate) *QuorumCertificate {
	return &QuorumCertificate{
		ProposedInView: qc.GetView(),
		BlockHash:      BlockHashFromConsensusInterface(qc.GetBlockHash()),
		ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
			Signature:   qc.GetAggregatedSignature().GetSignature(),
			SignersList: qc.GetAggregatedSignature().GetSignersList(),
		},
	}
}

// AggregateQuorumCertificate struct <-> consensus.AggregateQuorumCertificate interface translation
func AggregateQuorumCertificateFromConsensusInterface(aggQC consensus.AggregateQuorumCertificate) *TimeoutAggregateQuorumCertificate {
	return &TimeoutAggregateQuorumCertificate{
		TimedOutView:                 aggQC.GetView(),
		ValidatorsHighQC:             QuorumCertificateFromConsensusInterface(aggQC.GetHighQC()),
		ValidatorsTimeoutHighQCViews: aggQC.GetHighQCViews(),
		ValidatorsTimeoutAggregatedSignature: &AggregatedBLSSignature{
			Signature:   aggQC.GetAggregatedSignature().GetSignature(),
			SignersList: aggQC.GetAggregatedSignature().GetSignersList(),
		},
	}
}

// AggregatedBLSSignature struct <-> consensus.AggregatedSignature interface translation

func (aggSig *AggregatedBLSSignature) GetSignersList() *bitset.Bitset {
	return aggSig.SignersList
}

func (aggSig *AggregatedBLSSignature) GetSignature() *bls.Signature {
	return aggSig.Signature
}

// BlockHash struct <-> consensus.BlockHash interface translation

func (blockhash *BlockHash) GetValue() [HashSizeBytes]byte {
	return [HashSizeBytes]byte(blockhash.ToBytes())
}

func BlockHashFromConsensusInterface(blockHash consensus.BlockHash) *BlockHash {
	blockHashValue := blockHash.GetValue()
	return NewBlockHash(blockHashValue[:])
}

// ValidatorEntry struct <-> consensus.Validator interface translation

func (validator *ValidatorEntry) GetPublicKey() *bls.PublicKey {
	return validator.VotingPublicKey
}

func (validator *ValidatorEntry) GetStakeAmount() *uint256.Int {
	return validator.TotalStakeAmountNanos
}

func (validator *ValidatorEntry) GetDomains() [][]byte {
	return validator.Domains
}

func ValidatorEntriesToConsensusInterface(validatorEntries []*ValidatorEntry) []consensus.Validator {
	validatorInterfaces := make([]consensus.Validator, len(validatorEntries))
	for idx, validatorEntry := range validatorEntries {
		validatorInterfaces[idx] = validatorEntry
	}
	return validatorInterfaces
}
