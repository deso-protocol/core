package lib

import (
	"math"
	"time"

	"github.com/btcsuite/btcd/wire"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
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

	// Create the block template.
	block, err := pbp.createBlockTemplate(latestBlockView, newBlockHeight, view, proposerRandomSeedSignature)
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
func (pbp *PosBlockProducer) CreateUnsignedTimeoutBlock(latestBlockView *UtxoView, newBlockHeight uint64, view uint64,
	proposerRandomSeedSignature *bls.Signature, validatorsTimeoutAggregateQC *TimeoutAggregateQuorumCertificate) (BlockTemplate, error) {

	// Create the block template.
	block, err := pbp.createBlockTemplate(latestBlockView, newBlockHeight, view, proposerRandomSeedSignature)
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
func (pbp *PosBlockProducer) createBlockTemplate(latestBlockView *UtxoView, newBlockHeight uint64, view uint64,
	proposerRandomSeedSignature *bls.Signature) (BlockTemplate, error) {
	// First get the block without the header.
	currentTimestamp := _maxInt64(time.Now().UnixNano(), pbp.previousBlockTimestampNanoSecs+1)
	block, err := pbp.createBlockWithoutHeader(latestBlockView, newBlockHeight, currentTimestamp)
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

	// Hash the TxnConnectStatusByIndex
	block.Header.TxnConnectStatusByIndexHash = HashBitset(block.TxnConnectStatusByIndex)
	return block, nil
}

// createBlockWithoutHeader is a helper function used by createBlockTemplate. It constructs a partially filled out
// block with Fee-Time ordered transactions. The returned block all its contents filled, except for the header.
func (pbp *PosBlockProducer) createBlockWithoutHeader(
	latestBlockView *UtxoView, newBlockHeight uint64, newBlockTimestampNanoSecs int64) (BlockTemplate, error) {
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

	// Get block transactions from the mempool.
	feeTimeTxns, txnConnectStatusByIndex, maxUtilityFee, err := pbp.getBlockTransactions(
		pbp.proposerPublicKey,
		latestBlockView,
		newBlockHeight,
		newBlockTimestampNanoSecs,
		pbp.params.PosBlockProducerMaxBlockSizeBytes-uint64(len(blockRewardTxnSizeBytes)),
	)
	if err != nil {
		return nil, errors.Wrapf(err, "PosBlockProducer.createBlockWithoutHeader: Problem retrieving block transactions: ")
	}

	// Update the block reward output and block transactions.
	blockRewardOutput.AmountNanos = maxUtilityFee
	block.Txns = append([]*MsgDeSoTxn{blockRewardTxn}, feeTimeTxns...)

	// Set the RevolutionMetadata
	block.TxnConnectStatusByIndex = txnConnectStatusByIndex
	return block, nil
}

// getBlockTransactions is used to retrieve fee-time ordered transactions from the mempool.
func (pbp *PosBlockProducer) getBlockTransactions(
	blockProducerPublicKey *PublicKey,
	latestBlockView *UtxoView,
	newBlockHeight uint64,
	newBlockTimestampNanoSecs int64,
	maxBlockSizeBytes uint64,
) (
	_txns []*MsgDeSoTxn,
	_txnConnectStatusByIndex *bitset.Bitset,
	_maxUtilityFee uint64,
	_err error,
) {
	// Get Fee-Time ordered transactions from the mempool
	feeTimeTxns := pbp.mp.GetTransactions()

	// Try to connect transactions one by one.
	blocksTxns := []*MsgDeSoTxn{}
	txnConnectStatusByIndex := bitset.NewBitset()
	maxUtilityFee := uint64(0)
	currentBlockSize := uint64(0)
	blockUtxoView, err := latestBlockView.CopyUtxoView()
	if err != nil {
		return nil, nil, 0, errors.Wrapf(err, "Error copying UtxoView: ")
	}
	for _, txn := range feeTimeTxns {
		txnBytes, err := txn.ToBytes(false)
		if err != nil {
			return nil, nil, 0, errors.Wrapf(err, "Error getting transaction size: ")
		}

		// Skip over transactions that are too big.
		if currentBlockSize+uint64(len(txnBytes)) > maxBlockSizeBytes {
			continue
		}

		blockUtxoViewCopy, err := blockUtxoView.CopyUtxoView()
		if err != nil {
			return nil, nil, 0, errors.Wrapf(err, "Error copying UtxoView: ")
		}
		_, _, _, fees, err := blockUtxoViewCopy._connectTransaction(
			txn.GetTxn(), txn.Hash(), uint32(newBlockHeight), newBlockTimestampNanoSecs,
			true, false)

		// Check if the transaction connected.
		if err == nil {
			blockUtxoView = blockUtxoViewCopy
			txnConnectStatusByIndex.Set(len(blocksTxns), true)
			blocksTxns = append(blocksTxns, txn.GetTxn())
			currentBlockSize += uint64(len(txnBytes))

			// If the transactor is the block producer, then they won't receive the utility
			// fee.
			if blockProducerPublicKey.Equal(*NewPublicKey(txn.PublicKey)) {
				continue
			}

			// Compute BMF for the transaction.
			_, utilityFee := computeBMF(fees)
			maxUtilityFee, err = SafeUint64().Add(maxUtilityFee, utilityFee)
			if err != nil {
				return nil, nil, 0, errors.Wrapf(err, "Error computing max utility fee: ")
			}
			continue
		}

		// If the transaction didn't connect, we will try to add it as a failing transaction.
		blockUtxoViewCopy, err = blockUtxoView.CopyUtxoView()
		if err != nil {
			return nil, nil, 0, errors.Wrapf(err, "Error copying UtxoView: ")
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
		blocksTxns = append(blocksTxns, txn.GetTxn())
		currentBlockSize += uint64(len(txnBytes))

		// If the transactor is the block producer, then they won't receive the utility
		// fee.
		if blockProducerPublicKey.Equal(*NewPublicKey(txn.PublicKey)) {
			continue
		}

		maxUtilityFee, err = SafeUint64().Add(maxUtilityFee, utilityFee)
		if err != nil {
			return nil, nil, 0, errors.Wrapf(err, "Error computing max utility fee: ")
		}
	}

	return blocksTxns, txnConnectStatusByIndex, maxUtilityFee, nil
}

func _maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
