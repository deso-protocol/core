package lib

import (
	"github.com/pkg/errors"
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
