package lib

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/deso-protocol/core/consensus"
)

//////////////////////////////////////////////////////////////////////////////////
// This file implements the network message interfaces for the PoS messages     //
// defined in the consensus package. These interfaces are used by the consensus //
// package to run the Fast-HotStuff protocol. This file is a good spot to       //
// place all translations between types defined in lib and consensus packages.  //
//////////////////////////////////////////////////////////////////////////////////

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
