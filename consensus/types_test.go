package consensus

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/holiman/uint256"
)

//////////////////////////////////////////////////////////
// BlockHash interface implementation for testing
//////////////////////////////////////////////////////////

type blockHash struct {
	value [32]byte
}

func (bh *blockHash) GetValue() [32]byte {
	return bh.value
}

//////////////////////////////////////////////////////////
// Validator interface implementation for testing
//////////////////////////////////////////////////////////

type validator struct {
	publicKey   *bls.PublicKey
	stakeAmount *uint256.Int
}

func (v *validator) GetPublicKey() *bls.PublicKey {
	return v.publicKey
}

func (v *validator) GetStakeAmount() *uint256.Int {
	return v.stakeAmount
}

//////////////////////////////////////////////////////////
// QuorumCertificate interface implementation for testing
//////////////////////////////////////////////////////////

type quorumCertificate struct {
	blockHash           *blockHash
	view                uint64
	signersList         *bitset.Bitset
	aggregatedSignature *bls.Signature
}

func (qc *quorumCertificate) GetBlockHash() BlockHash {
	return qc.blockHash
}

func (qc *quorumCertificate) GetView() uint64 {
	return qc.view
}

func (qc *quorumCertificate) GetSignersList() *bitset.Bitset {
	return qc.signersList
}

func (qc *quorumCertificate) GetAggregatedSignature() *bls.Signature {
	return qc.aggregatedSignature
}

//////////////////////////////////////////////////////////
// Block interface implementation for testing
//////////////////////////////////////////////////////////

type block struct {
	blockHash *blockHash
	height    uint64
	view      uint64
	qc        *quorumCertificate
}

func (b *block) GetBlockHash() BlockHash {
	return b.blockHash
}

func (b *block) GetHeight() uint64 {
	return b.height
}

func (b *block) GetView() uint64 {
	return b.view
}

func (b *block) GetQC() QuorumCertificate {
	return b.qc
}

//////////////////////////////////////////////////////////
// VoteMessage interface implementation for testing
//////////////////////////////////////////////////////////

type voteMessage struct {
	view      uint64
	blockHash *blockHash
	publicKey *bls.PublicKey
	signature *bls.Signature
}

func (vm *voteMessage) GetView() uint64 {
	return vm.view
}

func (vm *voteMessage) GetBlockHash() BlockHash {
	return vm.blockHash
}

func (vm *voteMessage) GetPublicKey() *bls.PublicKey {
	return vm.publicKey
}

func (vm *voteMessage) GetSignature() *bls.Signature {
	return vm.signature
}

//////////////////////////////////////////////////////////
// TimeoutMessage interface implementation for testing
//////////////////////////////////////////////////////////

type timeoutMessage struct {
	view      uint64
	highQC    *quorumCertificate
	publicKey *bls.PublicKey
	signature *bls.Signature
}

func (tm *timeoutMessage) GetView() uint64 {
	return tm.view
}

func (tm *timeoutMessage) GetHighQC() QuorumCertificate {
	return tm.highQC
}

func (tm *timeoutMessage) GetPublicKey() *bls.PublicKey {
	return tm.publicKey
}

func (tm *timeoutMessage) GetSignature() *bls.Signature {
	return tm.signature
}