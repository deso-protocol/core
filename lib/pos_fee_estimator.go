package lib

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/pkg/errors"
	"math"
)

func mempoolFeeEstimator(mempool *PosMempool, numBlocks uint64, congestionFactorBasisPoints uint64, priorityPercentileBasisPoints uint64, maxBlockSize uint64) (uint64, error) {
	it := mempool.GetIterator()
	maxSizeOfNumBlocks := maxBlockSize * numBlocks
	totalTxnsSize := uint64(0)
	var txns []*MempoolTransaction
	for it.Next() {
		tx, ok := it.Value()
		if !ok {
			break
		}
		txnBytes, err := tx.ToBytes(false)
		if err != nil {
			return 0, errors.Wrap(err, "mempoolFeeEstimator: Problem serializing txn")
		}
		totalTxnsSize += uint64(len(txnBytes))
		txns = append(txns, tx)
		// TODO: I think we want to include the txn that puts us over the limit, but
		// we can just move this check up a few lines if that's wrong.
		if totalTxnsSize > maxSizeOfNumBlocks {
			break
		}
	}
	// TODO: global min fee? or is 0 okay?
	if len(txns) == 0 {
		return 0, nil
	}

	// Compute the congestion threshold. If our congestion factor is 100% (or 10,000 bps),
	// then congestion threshold is simply max block size * numBlocks
	// TODO: I don't know if I like this name really.
	congestionThreshold := (congestionFactorBasisPoints * numBlocks * maxBlockSize) / (100 * 100)
	bucketMinFee, bucketMaxFee, err := getPriorityFeeBucketFromTxns(mempool, txns, priorityPercentileBasisPoints)
	if err != nil {
		return 0, errors.Wrap(err, "mempoolFeeEstimator: Problem computing priority fee bucket")
	}
	// If the bucketMinFee is 0, we simply return 0.
	if bucketMinFee == 0 {
		// Ugh I don't like this.
		globalMinFeeRate, _ := mempool.txnRegister.minimumNetworkFeeNanosPerKB.Uint64()
		return globalMinFeeRate, nil
	}
	// If the total size of the txns in the mempool is less than the computed congestion threshold,
	// we return one bucket lower than the Priority fee.
	if totalTxnsSize <= congestionThreshold {
		// Return one bucket lower than Priority fee
		oneBucketLowerMinFee, _ := computeFeeTimeBucketRangeFromFeeNanosPerKB(bucketMinFee-1, mempool.txnRegister.minimumNetworkFeeNanosPerKB, mempool.txnRegister.feeBucketGrowthRateBasisPoints)
		return oneBucketLowerMinFee, nil
	}
	// If the total size of the txns in the mempool is greater than the computed congestion threshold
	// but less than the max size of num blocks, we return the Priority fee.
	if totalTxnsSize > congestionThreshold && totalTxnsSize <= maxSizeOfNumBlocks {
		// Return Priority fee
		return bucketMinFee, nil
	}
	// Otherwise, we return one bucket higher than Priority fee
	return bucketMaxFee + 1, nil
}

// TODO: It'll probably be easier to have some external function that maintains the fake mempool.
func pastBlocksFeeEstimator(pastBlocks []*MsgDeSoBlock, congestionFactorBasisPoints uint64, priorityPercentileBasisPoints uint64, maxBlockSize uint64, params *DeSoParams, globalParams *GlobalParamsEntry) (uint64, error) {
	// TODO: validations. blocks[0].height >0, blocks are ordered by height.
	if len(pastBlocks) == 0 {
		// TODO: Should this be an error? It does keep it consistent w/ the mempool estimator which is kinda neat.
		return 0, nil
	}
	// Get min height from blocks.
	minHeight := uint64(math.MaxUint64)
	for _, block := range pastBlocks {
		if block.Header.Height < minHeight {
			minHeight = block.Header.Height
		}
	}
	if minHeight == 0 {
		return 0, errors.New("pastBlocksFeeEstimator: pastBlocks must have min height > 0")
	}
	// First we create a new in-memory mempool and add all the txns from the past blocks to it.
	// Create a fake badger instance, so we can have an entirely empty view.
	defaultOptions := DefaultBadgerOptions("")
	defaultOptions.InMemory = true

	fakeBadgerInstance, err := badger.Open(defaultOptions)
	if err != nil {
		return 0, errors.Wrap(err, "pastBlocksFeeEstimator: Problem opening fake badger instance")
	}
	defer fakeBadgerInstance.Close()
	// Create a fake UTXO view
	fakeUtxoView, err := NewUtxoView(fakeBadgerInstance, params, nil, nil, nil)
	if err != nil {
		return 0, errors.Wrap(err, "pastBlocksFeeEstimator: Problem creating fake UtxoView")
	}
	// Create a new mempool with the fake utxo view.
	pastBlocksMempool := NewPosMempoolNoValidation(params, globalParams.Copy(), fakeUtxoView, minHeight-1, "dummy-mempool-dir", true, math.MaxUint64, 0)
	if err = pastBlocksMempool.Start(); err != nil {
		return 0, errors.Wrap(err, "pastBlocksFeeEstimator: Problem starting pastBlocksMempool")
	}
	defer pastBlocksMempool.Stop()

	// Add all the txns from the past blocks to the new mempool.
	for _, block := range pastBlocks {
		for _, txn := range block.Txns {
			mtxn := NewMempoolTransaction(txn, block.Header.TstampNanoSecs)
			if err = pastBlocksMempool.AddTransaction(mtxn, false); err != nil {
				// THIS SHOULD NEVER HAPPEN?! If we hit this, it means I probably screwed up in how I created the
				// pastBlocksMempool.
				return 0, errors.Wrap(err, "pastBlocksFeeEstimator: Problem adding txn to mempool")
			}
		}
	}
	// Okay now we can simply use the mempool estimator!
	return mempoolFeeEstimator(pastBlocksMempool, uint64(len(pastBlocks)), congestionFactorBasisPoints, priorityPercentileBasisPoints, maxBlockSize)
}

func getPriorityFeeBucketFromTxns(mempool *PosMempool, feeTimeOrderedTxns []*MempoolTransaction, priorityPercentileBasisPoints uint64) (uint64, uint64, error) {
	percentilePosition := uint64(len(feeTimeOrderedTxns)) - ((priorityPercentileBasisPoints * uint64(len(feeTimeOrderedTxns))) / 10000)
	if percentilePosition >= uint64(len(feeTimeOrderedTxns)) {
		return 0, 0, errors.New("getPriorityFeeBucketFromTxns: error computing percentile position")
	}
	feeRatePerKB, err := feeTimeOrderedTxns[percentilePosition].ComputeFeeRatePerKBNanos()
	if err != nil {
		return 0, 0, errors.Wrap(err, "getPriorityFeeBucketFromTxns: error computing fee rate per KB")
	}
	bucketMin, bucketMax := computeFeeTimeBucketRangeFromFeeNanosPerKB(feeRatePerKB, mempool.txnRegister.minimumNetworkFeeNanosPerKB, mempool.txnRegister.feeBucketGrowthRateBasisPoints)
	return bucketMin, bucketMax, nil
}
