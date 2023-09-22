package lib

import (
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/pkg/errors"
	"math"
)

type PosBlockProducer struct {
	mm       *MempoolManager
	utxoView *UtxoView

	params *DeSoParams
}

func NewPosBlockProducer(mm *MempoolManager, params *DeSoParams) *PosBlockProducer {
	return &PosBlockProducer{
		mm:     mm,
		params: params,
	}
}

// CreateBlockTemplate constructs a block with Fee-Time ordered transactions.
// TODO: how do we set the following Header fields?
//	 - ProposerPublicKey
//	 - ProposerVotingPublicKey
//   - ProposerRandomSeedHash
//   - ProposedInView
//   - ValidatorsVoteQC
//   - ValidatorsTimeoutAggregateQC
//   - ProposerVotePartialSignature
//  Perhaps the caller of CreateBlockTemplate (server/consensus) will fill these out. The block is also unsigned.
func (pbp *PosBlockProducer) CreateBlockTemplate(chainTip *BlockNode, latestBlockView *UtxoView) (*MsgDeSoBlock, error) {
	// Fill out some initial header info
	block := NewMessage(MsgTypeBlock).(*MsgDeSoBlock)
	block.Header.Version = HeaderVersion2
	block.Header.Height = uint64(chainTip.Height + 1)
	block.Header.PrevBlockHash = chainTip.Hash
	// TODO: determine block timestamp, blockTstamp
	//  block.Header.SetTstampSecs(uint64(blockTstamp))

	// Create a placeholder block reward transaction. We will update the amount later.
	blockRewardOutput := &DeSoOutput{}
	blockRewardOutput.AmountNanos = math.MaxUint64
	blockRewardTxn := NewMessage(MsgTypeTxn).(*MsgDeSoTxn)
	blockRewardTxn.TxOutputs = append(blockRewardTxn.TxOutputs, blockRewardOutput)
	blockRewardTxn.TxnMeta = &BlockRewardMetadataa{
		ExtraData: UintToBuf(0),
	}
	blockRewardTxnSizeBytes, err := blockRewardTxn.ToBytes(true)
	if err != nil {
		return nil, errors.Wrapf(err, "Error computing block reward txn size: ")
	}

	block.Txns = append(block.Txns, blockRewardTxn)

	// TODO: we should probably have another parameter for this
	maxBlockContentsSizeBytes := pbp.params.MinerMaxBlockSizeBytes

	// 2. Get Fee-Time ordered transactions from the mempool and determine the pass/fail flags for each txn.
	// TODO: We should also include per-transaction timestamps from the proposer.
	feeTimeTxns, txnConnectStatusByIndex, maxUtilityFee, err := pbp.getBlockTransactions(chainTip, latestBlockView,
		maxBlockContentsSizeBytes-uint64(len(blockRewardTxnSizeBytes)))
	if err != nil {
		return nil, errors.Wrapf(err, "Error getting block transactions: ")
	}
	// Append the feeTImeTxns to our block.
	block.Txns = append(block.Txns, feeTimeTxns...)
	// Set the txnConnectStatusByIndex in the block and header.
	// TODO: Add fixed-length bitset encoding.
	block.TxnConnectStatusByIndex = txnConnectStatusByIndex
	block.Header.TxnConnectStatusByIndexHash = HashBitset(txnConnectStatusByIndex)

	// Update the block reward transaction with the correct amount.
	blockRewardOutput.AmountNanos = maxUtilityFee

	// Compute the merkle root for the block now that all of the transactions have been added.
	merkleRoot, _, err := ComputeMerkleRoot(block.Txns)
	if err != nil {
		return nil, err
	}
	block.Header.TransactionMerkleRoot = merkleRoot

	return block, nil
}

func (pbp *PosBlockProducer) getBlockTransactions(chainTip *BlockNode, latestBlockView *UtxoView, maxBlockSizeBytes uint64) (
	_txns []*MsgDeSoTxn, _txnConnectStatusByIndex *bitset.Bitset, _maxUtilityFee uint64, _err error) {
	// Get Fee-Time ordered transactions from the mempool
	feeTimeTxns := pbp.mm.Mempool().GetTransactions()

	// Try to connect transactions one by one.
	blocksTxns := []*MsgDeSoTxn{}
	txnConnectStatusByIndex := bitset.NewBitset()
	maxUtilityFee := uint64(0)
	currentBlockSize := uint64(0)
	for _, txn := range feeTimeTxns {
		txnBytes, err := txn.ToBytes(false)
		if err != nil {
			return nil, nil, 0, errors.Wrapf(err, "Error getting transaction size: ")
		}
		// Skip over transactions that are too big.
		if currentBlockSize+uint64(len(txnBytes)) > maxBlockSizeBytes {
			continue
		}

		utxoViewCopy, err := latestBlockView.CopyUtxoView()
		if err != nil {
			return nil, nil, 0, errors.Wrapf(err, "Error copying UtxoView: ")
		}
		_, _, _, fees, err := utxoViewCopy._connectTransaction(
			txn, txn.Hash(), int64(len(txnBytes)), chainTip.Height+1, true, false)

		// Check if the transaction connected.
		if err == nil {
			txnConnectStatusByIndex.Set(len(blocksTxns), true)
			blocksTxns = append(blocksTxns, txn)
			currentBlockSize += uint64(len(txnBytes))
			// Compute BMF for the transaction.
			_, utilityFee := computeBMF(fees)
			maxUtilityFee += utilityFee
			continue
		}
		// If the transaction didn't connect, we will try to add it as a failing transaction.
		utxoViewCopy, err = latestBlockView.CopyUtxoView()
		if err != nil {
			return nil, nil, 0, errors.Wrapf(err, "Error copying UtxoView: ")
		}
		_, _, utilityFee, err := utxoViewCopy._connectFailingTransaction(txn, chainTip.Height+1, true)
		if err != nil {
			// If the transaction still doesn't connect, this means we encountered an invalid transaction. We will skip
			// it and let some other process figure out what to do with it. Removing invalid transactions is a fast
			// process, so we don't need to worry about it here.
			continue
		}
		// If we get to this point, it means the transaction didn't connect but it was a valid transaction. We will
		// add it to the block as a failing transaction.
		txnConnectStatusByIndex.Set(len(blocksTxns), false)
		blocksTxns = append(blocksTxns, txn)
		currentBlockSize += uint64(len(txnBytes))
		maxUtilityFee += utilityFee
	}

	return blocksTxns, txnConnectStatusByIndex, maxUtilityFee, nil
}
