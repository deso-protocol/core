package lib

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/pkg/errors"
	"math"
	"time"
)

type BlockTemplate *MsgDeSoBlock

type PosBlockProducer struct {
	mp     Mempool
	params *DeSoParams
}

func NewPosBlockProducer(mp Mempool, params *DeSoParams) *PosBlockProducer {
	return &PosBlockProducer{
		mp:     mp,
		params: params,
	}
}

type PosBlockProposerMetadata struct {
	ProposerPublicKey       *PublicKey
	ProposerVotingPublicKey *bls.PublicKey
	ProposerRandomSeedHash  *RandomSeedHash
}

func NewPosBlockProposerMetadata(
	ProposerPublicKey *PublicKey, ProposerVotingPublicKey *bls.PublicKey, ProposerRandomSeedHash *RandomSeedHash) *PosBlockProposerMetadata {
	return &PosBlockProposerMetadata{
		ProposerPublicKey:       ProposerPublicKey,
		ProposerVotingPublicKey: ProposerVotingPublicKey,
		ProposerRandomSeedHash:  ProposerRandomSeedHash,
	}
}

func (pbp *PosBlockProducer) SignBlock(blockTemplate BlockTemplate, signerPrivateKey *bls.PrivateKey) (*MsgDeSoBlock, error) {
	// TODO
	return nil, nil
}

func (pbp *PosBlockProducer) CreateUnsignedBlock(latestBlockView *UtxoView, newBlockHeight uint64, view uint64,
	proposerMetadata *PosBlockProposerMetadata, validatorsVoteQC *QuorumCertificate) (BlockTemplate, error) {

	// Create the block template.
	block, err := pbp.createBlockTemplate(latestBlockView, newBlockHeight, view, proposerMetadata)
	if err != nil {
		return nil, errors.Wrapf(err, "PosBlockProducer.CreateUnsignedTimeoutBlock: Problem creating block template")
	}

	// Fill out the validators vote QC field.
	block.Header.ValidatorsVoteQC = validatorsVoteQC
	return block, nil
}

func (pbp *PosBlockProducer) CreateUnsignedTimeoutBlock(latestBlockView *UtxoView, newBlockHeight uint64, view uint64,
	proposerMetadata *PosBlockProposerMetadata, validatorsTimeoutAggregateQC *TimeoutAggregateQuorumCertificate) (BlockTemplate, error) {

	// Create the block template.
	block, err := pbp.createBlockTemplate(latestBlockView, newBlockHeight, view, proposerMetadata)
	if err != nil {
		return nil, errors.Wrapf(err, "PosBlockProducer.CreateUnsignedTimeoutBlock: Problem creating block template")
	}

	// Fill out the validators timeout aggregate QC field.
	block.Header.ValidatorsTimeoutAggregateQC = validatorsTimeoutAggregateQC
	return block, nil
}

// CreateBlockTemplate constructs a block with Fee-Time ordered transactions.
func (pbp *PosBlockProducer) createBlockTemplate(latestBlockView *UtxoView, newBlockHeight uint64, view uint64,
	proposerMetadata *PosBlockProposerMetadata) (BlockTemplate, error) {
	// First get the block without the header.
	block, err := pbp.createBlockWithoutHeader(latestBlockView, newBlockHeight)
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
	// FIXME: Anything special that we should do with the timestamp?
	block.Header.TstampNanoSecs = uint64(time.Now().UnixNano())
	block.Header.Height = newBlockHeight
	block.Header.ProposedInView = view

	// Set the proposer information.
	block.Header.ProposerPublicKey = proposerMetadata.ProposerPublicKey
	block.Header.ProposerVotingPublicKey = proposerMetadata.ProposerVotingPublicKey
	block.Header.ProposerRandomSeedHash = proposerMetadata.ProposerRandomSeedHash
	return block, nil
}

func (pbp *PosBlockProducer) createBlockWithoutHeader(latestBlockView *UtxoView, newBlockHeight uint64) (BlockTemplate, error) {
	block := NewMessage(MsgTypeBlock).(*MsgDeSoBlock)

	// Create the block reward transaction.
	blockRewardTxn := NewMessage(MsgTypeTxn).(*MsgDeSoTxn)
	blockRewardOutput := &DeSoOutput{}
	blockRewardOutput.AmountNanos = math.MaxUint64
	blockRewardTxn.TxOutputs = append(blockRewardTxn.TxOutputs, blockRewardOutput)
	blockRewardTxn.TxnMeta = &BlockRewardMetadataa{}
	blockRewardTxnSizeBytes, err := blockRewardTxn.ToBytes(true)
	if err != nil {
		return nil, errors.Wrapf(err, "Error computing block reward txn size: ")
	}

	// Get block transactions from the mempool.
	feeTimeTxns, txnConnectStatusByIndex, txnTimestampsUnixMicro, maxUtilityFee, err := pbp.getBlockTransactions(
		latestBlockView, newBlockHeight, pbp.params.MinerMaxBlockSizeBytes-uint64(len(blockRewardTxnSizeBytes)))
	if err != nil {
		return nil, errors.Wrapf(err, "PosBlockProducer.createBlockWithoutHeader: Problem retrieving block transactions: ")
	}

	// Update the block reward output and block transactions.
	blockRewardOutput.AmountNanos = maxUtilityFee
	block.Txns = append([]*MsgDeSoTxn{blockRewardTxn}, feeTimeTxns...)

	// Set the RevolutionMetadata
	block.RevolutionMetadata = NewRevolutionMetadata(txnConnectStatusByIndex, txnTimestampsUnixMicro)
	return block, nil
}

func (pbp *PosBlockProducer) getBlockTransactions(latestBlockView *UtxoView, newBlockHeight uint64, maxBlockSizeBytes uint64) (
	_txns []*MsgDeSoTxn, _txnConnectStatusByIndex *bitset.Bitset, _txnTimestampsUnixMicro []uint64, _maxUtilityFee uint64, _err error) {
	// Get Fee-Time ordered transactions from the mempool
	feeTimeTxns := pbp.mp.GetTransactions()

	// Try to connect transactions one by one.
	blocksTxns := []*MsgDeSoTxn{}
	txnConnectStatusByIndex := bitset.NewBitset()
	txnTimestampsUnixMicro := []uint64{}
	maxUtilityFee := uint64(0)
	currentBlockSize := uint64(0)
	blockUtxoView, err := latestBlockView.CopyUtxoView()
	if err != nil {
		return nil, nil, nil, 0, errors.Wrapf(err, "Error copying UtxoView: ")
	}
	for _, txn := range feeTimeTxns {
		txnBytes, err := txn.ToBytes(false)
		if err != nil {
			return nil, nil, nil, 0, errors.Wrapf(err, "Error getting transaction size: ")
		}
		// Skip over transactions that are too big.
		if currentBlockSize+uint64(len(txnBytes)) > maxBlockSizeBytes {
			continue
		}

		blockUtxoViewCopy, err := blockUtxoView.CopyUtxoView()
		if err != nil {
			return nil, nil, nil, 0, errors.Wrapf(err, "Error copying UtxoView: ")
		}
		_, _, _, fees, err := blockUtxoViewCopy._connectTransaction(
			txn.GetTxn(), txn.Hash(), int64(len(txnBytes)), uint32(newBlockHeight), true, false)

		// Check if the transaction connected.
		if err == nil {
			blockUtxoView = blockUtxoViewCopy
			txnConnectStatusByIndex.Set(len(blocksTxns), true)
			txnTimestampsUnixMicro = append(txnTimestampsUnixMicro, txn.GetTimestampUnixMicro())
			blocksTxns = append(blocksTxns, txn.GetTxn())
			currentBlockSize += uint64(len(txnBytes))
			// Compute BMF for the transaction.
			_, utilityFee := computeBMF(fees)
			maxUtilityFee += utilityFee
			continue
		}
		// If the transaction didn't connect, we will try to add it as a failing transaction.
		blockUtxoViewCopy, err = blockUtxoView.CopyUtxoView()
		if err != nil {
			return nil, nil, nil, 0, errors.Wrapf(err, "Error copying UtxoView: ")
		}
		_, _, utilityFee, err := blockUtxoViewCopy._connectFailingTransaction(txn.GetTxn(), uint32(newBlockHeight), true)
		if err != nil {
			// If the transaction still doesn't connect, this means we encountered an invalid transaction. We will skip
			// it and let some other process figure out what to do with it. Removing invalid transactions is a fast
			// process, so we don't need to worry about it here.
			continue
		}
		// If we get to this point, it means the transaction didn't connect but it was a valid transaction. We will
		// add it to the block as a failing transaction.
		blockUtxoView = blockUtxoViewCopy
		txnConnectStatusByIndex.Set(len(blocksTxns), false)
		txnTimestampsUnixMicro = append(txnTimestampsUnixMicro, txn.GetTimestampUnixMicro())
		blocksTxns = append(blocksTxns, txn.GetTxn())
		currentBlockSize += uint64(len(txnBytes))
		maxUtilityFee += utilityFee
	}

	return blocksTxns, txnConnectStatusByIndex, txnTimestampsUnixMicro, maxUtilityFee, nil
}
