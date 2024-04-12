package lib

import (
	"math"
	"time"

	"github.com/btcsuite/btcd/wire"

	"github.com/deso-protocol/core/bls"
	"github.com/pkg/errors"
)

// BlockTemplate is a dummy type that is used to label incomplete blocks. The only purpose of this type is to make it
// clear that the produced block is not yet ready to be processed, or sent to other nodes. Usually a BlockTemplate means
// that the block is missing the producer's signature.
type BlockTemplate *MsgDeSoBlock

// PosBlockProducer is the new struct responsible for producing blocks in PoS. The PosBlockProducer struct is lightweight
// and does not maintain any new internal state. Instead, most of the information needed to produce a block is passed in
// as arguments. Both while instantiating the producer, or while creating a block to the CreateUnsignedBlock or
// CreateUnsignedTimeoutBlock methods. As such, PosBlockProducer exists primarily for the purpose of cleaner separation of
// concerns. Instantiating the PosBlockProducer can also be optional for nodes who do not wish to produce blocks.
type PosBlockProducer struct {
	mp                             Mempool
	params                         *DeSoParams
	proposerPublicKey              *PublicKey
	proposerVotingPublicKey        *bls.PublicKey
	previousBlockTimestampNanoSecs int64
	mockBlockSignature             *bls.Signature
}

func NewPosBlockProducer(
	mp Mempool,
	params *DeSoParams,
	proposerPublicKey *PublicKey,
	proposerVotingPublicKey *bls.PublicKey,
	previousBlockTimestampNanoSecs int64,
) *PosBlockProducer {
	return &PosBlockProducer{
		mp:                             mp,
		params:                         params,
		proposerPublicKey:              proposerPublicKey,
		proposerVotingPublicKey:        proposerVotingPublicKey,
		previousBlockTimestampNanoSecs: previousBlockTimestampNanoSecs,
	}
}

// CreateUnsignedBlock constructs an unsigned, PoS block with Fee-Time ordered transactions. This function should be used
// during happy path in consensus when a vote QC has been assembled. The block is unsigned, so to indicate its incompleteness,
// the block is returned as a BlockTemplate.
func (pbp *PosBlockProducer) CreateUnsignedBlock(latestBlockView *UtxoView, newBlockHeight uint64, view uint64,
	proposerRandomSeedSignature *bls.Signature, validatorsVoteQC *QuorumCertificate) (BlockTemplate, error) {

	headerSizeEstimate, err := pbp.estimateHeaderSize(
		latestBlockView,
		newBlockHeight,
		view,
		proposerRandomSeedSignature,
		validatorsVoteQC,
		nil,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "PosBlockProducer.CreateUnsignedBlock: Problem creating mock header")
	}
	// Create the block template.
	block, err := pbp.createBlockTemplate(
		latestBlockView, newBlockHeight, view, proposerRandomSeedSignature, headerSizeEstimate)
	if err != nil {
		return nil, errors.Wrapf(err, "PosBlockProducer.CreateUnsignedTimeoutBlock: Problem creating block template")
	}

	// Fill out the validators vote QC field.
	block.Header.ValidatorsVoteQC = validatorsVoteQC
	return block, nil
}

// CreateUnsignedTimeoutBlock constructs an unsigned, PoS block with Fee-Time ordered transactions. This function should be used
// during a timeout in consensus when a validators timeout aggregate QC has been assembled. The block is unsigned,
// and so is returned as a BlockTemplate.
func (pbp *PosBlockProducer) CreateUnsignedTimeoutBlock(
	latestBlockView *UtxoView,
	newBlockHeight uint64,
	view uint64,
	proposerRandomSeedSignature *bls.Signature,
	validatorsTimeoutAggregateQC *TimeoutAggregateQuorumCertificate,
) (BlockTemplate, error) {
	headerSizeEstimate, err := pbp.estimateHeaderSize(
		latestBlockView,
		newBlockHeight,
		view,
		proposerRandomSeedSignature,
		nil,
		validatorsTimeoutAggregateQC,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "PosBlockProducer.CreateUnsignedTimeoutBlock: Problem creating mock header")
	}
	// Create the block template.
	block, err := pbp.createBlockTemplate(
		latestBlockView, newBlockHeight, view, proposerRandomSeedSignature, headerSizeEstimate)
	if err != nil {
		return nil, errors.Wrapf(err, "PosBlockProducer.CreateUnsignedTimeoutBlock: Problem creating block template")
	}

	// Fill out the validators timeout aggregate QC field.
	block.Header.ValidatorsTimeoutAggregateQC = validatorsTimeoutAggregateQC
	return block, nil
}

// createBlockTemplate is a helper function used by CreateUnsignedBlock and CreateUnsignedTimeoutBlock. It constructs
// a partially filled out block with Fee-Time ordered transactions. The returned block is complete except for
// the qc / aggregateQc fields, and the signature.
func (pbp *PosBlockProducer) createBlockTemplate(
	latestBlockView *UtxoView,
	newBlockHeight uint64,
	view uint64,
	proposerRandomSeedSignature *bls.Signature,
	headerSizeEstimate uint64,
) (BlockTemplate, error) {
	// First get the block without the header.
	currentTimestamp := _maxInt64(time.Now().UnixNano(), pbp.previousBlockTimestampNanoSecs+1)
	block, err := pbp.createBlockWithoutHeader(latestBlockView, newBlockHeight, currentTimestamp, headerSizeEstimate)
	if err != nil {
		return nil, errors.Wrapf(err, "PosBlockProducer.CreateBlockTemplate: Problem creating block without header")
	}

	// Fill out what we can in the block header. This function won't fill out any of the consensus QC fields.
	block.Header.Version = HeaderVersion2
	block.Header.PrevBlockHash = latestBlockView.TipHash

	// Compute the merkle root for the block now that all of the transactions have been added.
	merkleRoot, _, err := ComputeMerkleRoot(block.Txns)
	if err != nil {
		return nil, err
	}
	block.Header.TransactionMerkleRoot = merkleRoot
	block.Header.TstampNanoSecs = currentTimestamp
	block.Header.Height = newBlockHeight
	block.Header.ProposedInView = view

	// Set the proposer information.
	block.Header.ProposerVotingPublicKey = pbp.proposerVotingPublicKey
	block.Header.ProposerRandomSeedSignature = proposerRandomSeedSignature

	return block, nil
}

func (pbp *PosBlockProducer) getMockBlockSignature() (*bls.Signature, error) {
	if pbp.mockBlockSignature != nil {
		return pbp.mockBlockSignature, nil
	}
	mockBLSPrivateKey, err := bls.NewPrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, "Error creating mock BLS private key")
	}
	mockBLSSigner, err := NewBLSSigner(mockBLSPrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating mock BLSSigner")
	}
	mockBlockSignature, err := mockBLSSigner.SignBlockProposal(math.MaxUint64, NewBlockHash(RandomBytes(32)))
	if err != nil {
		return nil, errors.Wrap(err, "Error creating mock block signature")
	}
	pbp.mockBlockSignature = mockBlockSignature
	return mockBlockSignature, nil
}

func (pbp *PosBlockProducer) estimateHeaderSize(
	latestBlockView *UtxoView,
	newBlockHeight uint64,
	view uint64,
	proposerRandomSeedSignature *bls.Signature,
	validatorsVoteQC *QuorumCertificate,
	validatorTimeoutAggregateQC *TimeoutAggregateQuorumCertificate,
) (uint64, error) {
	if validatorsVoteQC == nil && validatorTimeoutAggregateQC == nil {
		return 0, errors.New(
			"PosBlockProducer.mockHeader: both validatorsVoteQC and validatorTimeoutAggregateQC are nil")
	}
	if validatorsVoteQC != nil && validatorTimeoutAggregateQC != nil {
		return 0, errors.New(
			"PosBlockProducer.mockHeader: both validatorsVoteQC and validatorTimeoutAggregateQC are not nil")
	}
	if proposerRandomSeedSignature == nil {
		return 0, errors.New("PosBlockProducer.mockHeader: proposerRandomSeedSignature is nil")
	}
	mockHeader := &MsgDeSoHeader{}
	mockHeader.Version = HeaderVersion2
	mockHeader.PrevBlockHash = latestBlockView.TipHash
	randomBlockHash := NewBlockHash(RandomBytes(32))
	// Any random block hash is fine here.
	mockHeader.TransactionMerkleRoot = randomBlockHash
	mockHeader.TstampNanoSecs = _maxInt64(time.Now().UnixNano(), pbp.previousBlockTimestampNanoSecs+1)
	mockHeader.Height = newBlockHeight
	mockHeader.ProposedInView = view
	mockHeader.ProposerVotingPublicKey = pbp.proposerVotingPublicKey
	mockHeader.ProposerRandomSeedSignature = proposerRandomSeedSignature
	if validatorsVoteQC != nil {
		mockHeader.ValidatorsVoteQC = validatorsVoteQC
	} else {
		mockHeader.ValidatorsTimeoutAggregateQC = validatorTimeoutAggregateQC
	}
	var err error
	mockHeader.ProposerVotePartialSignature, err = pbp.getMockBlockSignature()
	if err != nil {
		return 0, errors.Wrap(err, "PosBlockProducer.mockHeader: Problem getting mock block signature")
	}
	headerBytes, err := mockHeader.ToBytes(false)
	if err != nil {
		return 0, errors.Wrap(err, "PosBlockProducer.mockHeader: Problem getting header size")
	}
	return uint64(len(headerBytes)), nil
}

// createBlockWithoutHeader is a helper function used by createBlockTemplate. It constructs a partially filled out
// block with Fee-Time ordered transactions. The returned block all its contents filled, except for the header.
func (pbp *PosBlockProducer) createBlockWithoutHeader(
	latestBlockView *UtxoView,
	newBlockHeight uint64,
	newBlockTimestampNanoSecs int64,
	headerSizeEstimate uint64,
) (BlockTemplate, error) {
	block := NewMessage(MsgTypeBlock).(*MsgDeSoBlock)

	// Create the block reward transaction.
	blockRewardTxn := NewMessage(MsgTypeTxn).(*MsgDeSoTxn)
	blockRewardOutput := &DeSoOutput{}
	blockRewardOutput.AmountNanos = math.MaxUint64
	blockRewardOutput.PublicKey = pbp.proposerPublicKey.ToBytes()
	blockRewardTxn.TxOutputs = append(blockRewardTxn.TxOutputs, blockRewardOutput)
	extraNonce, err := wire.RandomUint64()
	if err != nil {
		return nil, errors.Wrapf(err, "Error generating random nonce: ")
	}
	blockRewardTxn.TxnMeta = &BlockRewardMetadataa{
		ExtraData: UintToBuf(extraNonce),
	}
	blockRewardTxnSizeBytes, err := blockRewardTxn.ToBytes(true)
	if err != nil {
		return nil, errors.Wrapf(err, "Error computing block reward txn size: ")
	}
	blockRewardTxnSize := uint64(len(blockRewardTxnSizeBytes))

	// PoS Block producer only uses PoS, so we just directly fetch the soft max and hard max block sizes.
	softMaxBlockSizeBytes := latestBlockView.GetSoftMaxBlockSizeBytesPoS()
	hardMaxBlockSizeBytes := latestBlockView.GetMaxBlockSizeBytesPoS()

	numBytesForHeaderAndBlockRewardTxn, err := SafeUint64().Add(headerSizeEstimate, blockRewardTxnSize)
	if err != nil {
		return nil, errors.Wrapf(err, "Error computing block reward txn size + mock header size: ")
	}

	softMaxTxnSizeBytes, err := SafeUint64().Sub(softMaxBlockSizeBytes, numBytesForHeaderAndBlockRewardTxn)
	if err != nil {
		return nil, errors.Wrapf(err, "Error computing soft max txn size: ")
	}

	hardMaxTxnSizeBytes, err := SafeUint64().Sub(hardMaxBlockSizeBytes, numBytesForHeaderAndBlockRewardTxn)
	if err != nil {
		return nil, errors.Wrapf(err, "Error computing hard max txn size: ")
	}

	// Get block transactions from the mempool.
	feeTimeTxns, maxUtilityFee, err := pbp.getBlockTransactions(
		pbp.proposerPublicKey,
		latestBlockView,
		newBlockHeight,
		newBlockTimestampNanoSecs,
		softMaxTxnSizeBytes,
		hardMaxTxnSizeBytes,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "PosBlockProducer.createBlockWithoutHeader: Problem retrieving block transactions: ")
	}

	// Update the block reward output and block transactions.
	blockRewardOutput.AmountNanos = maxUtilityFee
	block.Txns = append([]*MsgDeSoTxn{blockRewardTxn}, feeTimeTxns...)

	// Set the RevolutionMetadata
	return block, nil
}

// getBlockTransactions is used to retrieve fee-time ordered transactions from the mempool.
func (pbp *PosBlockProducer) getBlockTransactions(
	blockProducerPublicKey *PublicKey,
	latestBlockView *UtxoView,
	newBlockHeight uint64,
	newBlockTimestampNanoSecs int64,
	softMaxBlockSizeBytes uint64,
	hardMaxBlockSizeBytes uint64,
) (
	_txns []*MsgDeSoTxn,
	_maxUtilityFee uint64,
	_err error,
) {
	// Get Fee-Time ordered transactions from the mempool
	feeTimeTxns := pbp.mp.GetTransactions()

	// Try to connect transactions one by one.
	blocksTxns := []*MsgDeSoTxn{}
	maxUtilityFee := uint64(0)
	currentBlockSize := uint64(0)
	blockUtxoView := latestBlockView.CopyUtxoView()
	for _, txn := range feeTimeTxns {
		// If we've exceeded the soft max block size, we exit. We want to allow at least one txn that moves the
		// cumulative block size past the soft max, but don't want to add more txns beyond that.
		if currentBlockSize > softMaxBlockSizeBytes {
			break
		}
		txnBytes, err := txn.ToBytes(false)
		if err != nil {
			return nil, 0, errors.Wrapf(err, "Error getting transaction size: ")
		}

		// Skip over transactions that are too big. The block would be too large
		// to be accepted by the network.
		if currentBlockSize+uint64(len(txnBytes)) > hardMaxBlockSizeBytes {
			continue
		}

		blockUtxoViewCopy := blockUtxoView.CopyUtxoView()
		_, _, _, fees, err := blockUtxoViewCopy._connectTransaction(
			txn.GetTxn(), txn.Hash(), uint32(newBlockHeight), newBlockTimestampNanoSecs,
			true, false)

		// Check if the transaction connected.
		if err != nil {
			continue
		}
		blockUtxoView = blockUtxoViewCopy
		blocksTxns = append(blocksTxns, txn.GetTxn())
		currentBlockSize += uint64(len(txnBytes))

		// If the transactor is the block producer, then they won't receive the utility fee.
		if blockProducerPublicKey.Equal(*NewPublicKey(txn.PublicKey)) {
			continue
		}

		// Compute BMF for the transaction.
		_, utilityFee := computeBMF(fees)
		maxUtilityFee, err = SafeUint64().Add(maxUtilityFee, utilityFee)
		if err != nil {
			return nil, 0, errors.Wrapf(err, "Error computing max utility fee: ")
		}
	}

	return blocksTxns, maxUtilityFee, nil
}

func _maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
