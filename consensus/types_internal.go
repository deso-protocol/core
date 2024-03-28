package consensus

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/holiman/uint256"
)

//////////////////////////////////////////////////////////
// BlockHash interface implementation for unit tests
//////////////////////////////////////////////////////////

type blockHash struct {
	value [32]byte
}

func (bh *blockHash) GetValue() [32]byte {
	return bh.value
}

//////////////////////////////////////////////////////////
// Validator interface implementation for unit tests
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

func (v *validator) GetDomains() [][]byte {
	return [][]byte{}
}

////////////////////////////////////////////////////////////////////////
// AggregateQuorumCertificate interface implementation for internal use.
// We use this type for unit tests, and to construct timeout QCs for
// external signaling.
////////////////////////////////////////////////////////////////////////

type aggregateQuorumCertificate struct {
	view                uint64
	highQC              QuorumCertificate
	highQCViews         []uint64
	aggregatedSignature AggregatedSignature
}

func (qc *aggregateQuorumCertificate) GetView() uint64 {
	return qc.view
}

func (qc *aggregateQuorumCertificate) GetHighQC() QuorumCertificate {
	return qc.highQC
}

func (qc *aggregateQuorumCertificate) GetHighQCViews() []uint64 {
	return qc.highQCViews
}

func (qc *aggregateQuorumCertificate) GetAggregatedSignature() AggregatedSignature {
	return qc.aggregatedSignature
}

//////////////////////////////////////////////////////////
// QuorumCertificate interface implementation for unit tests
//////////////////////////////////////////////////////////

type quorumCertificate struct {
	blockHash           BlockHash
	view                uint64
	aggregatedSignature AggregatedSignature
}

func (qc *quorumCertificate) GetBlockHash() BlockHash {
	return qc.blockHash
}

func (qc *quorumCertificate) GetView() uint64 {
	return qc.view
}

func (qc *quorumCertificate) GetAggregatedSignature() AggregatedSignature {
	return qc.aggregatedSignature
}

//////////////////////////////////////////////////////////
// AggregatedSignature interface implementation for testing
//////////////////////////////////////////////////////////

type aggregatedSignature struct {
	signersList *bitset.Bitset
	signature   *bls.Signature
}

func (as *aggregatedSignature) GetSignersList() *bitset.Bitset {
	return as.signersList
}

func (as *aggregatedSignature) GetSignature() *bls.Signature {
	return as.signature
}

//////////////////////////////////////////////////////////
// Block interface implementation for unit tests
//////////////////////////////////////////////////////////

type block struct {
	blockHash   BlockHash
	height      uint64
	view        uint64
	qc          QuorumCertificate
	aggregateQC AggregateQuorumCertificate
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
	if !isInterfaceNil(b.aggregateQC) {
		return b.aggregateQC.GetHighQC()
	}
	return b.qc
}

//////////////////////////////////////////////////////////
// VoteMessage interface implementation for unit tests
//////////////////////////////////////////////////////////

type voteMessage struct {
	view      uint64
	blockHash BlockHash
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
// TimeoutMessage interface implementation for unit tests
//////////////////////////////////////////////////////////

type timeoutMessage struct {
	view      uint64
	highQC    QuorumCertificate
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

//////////////////////////////////////////////////////////
// Internal blockWithValidatorLookup type. We use this type
// to bundle a block with its validator list and a lookup
// of validators by public key string.
//////////////////////////////////////////////////////////

type blockWithValidatorLookup struct {
	block           Block
	validatorList   []Validator          // Ordered slice of validators
	validatorLookup map[string]Validator // Lookup of validators by validator public key string
}
