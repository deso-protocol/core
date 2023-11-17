package lib

import (
	"github.com/deso-protocol/core/collections"
	"github.com/pkg/errors"
	"math"
	"math/big"
	"sync"
)

type PoSFeeEstimator struct {
	mempoolFeeEstimatorMempool    *PosMempool
	pastBlocksTransactionRegister *TransactionRegister
	numBlocks                     uint64
	cachedBlocks                  []*MsgDeSoBlock
	rwLock                        *sync.RWMutex
}

// Init initializes the PoSFeeEstimator with the given mempool and past blocks. The mempool
// must be running and the number of past blocks must equal the numBlocks param provided.
// Init will add all the transactions from the past blocks to the pastBlocksTransactionRegister
// and cache the initial past blocks.
func (posFeeEstimator *PoSFeeEstimator) Init(mempool *PosMempool, pastBlocks []*MsgDeSoBlock, numBlocks uint64) error {
	posFeeEstimator.rwLock = &sync.RWMutex{}
	posFeeEstimator.rwLock.Lock()
	defer posFeeEstimator.rwLock.Unlock()
	if mempool == nil {
		return errors.New("PoSFeeEstimator.Init: mempool cannot be nil")
	}
	if !mempool.IsRunning() {
		return errors.New("PoSFeeEstimator.Init: mempool must be running")
	}
	if len(pastBlocks) == 0 {
		return errors.New("PoSFeeEstimator.Init: pastBlocks cannot be empty")
	}
	if numBlocks == 0 {
		return errors.New("PoSFeeEstimator.Init: numBlocks cannot be zero")
	}
	if numBlocks != uint64(len(pastBlocks)) {
		return errors.New("PoSFeeEstimator.Init: numBlocks must equal the number of pastBlocks")
	}
	// Sort the past blocks by height just to be safe.
	sortedPastBlocks := collections.SortStable(pastBlocks, func(ii, jj *MsgDeSoBlock) bool {
		return ii.Header.Height < jj.Header.Height
	})
	minHeight := sortedPastBlocks[0].Header.Height
	if minHeight == 0 {
		return errors.New("PoSFeeEstimator.Init: minHeight cannot be zero")
	}
	posFeeEstimator.mempoolFeeEstimatorMempool = mempool
	posFeeEstimator.numBlocks = numBlocks
	// Create a transaction register we can use to estimate fees for past blocks.
	posFeeEstimator.pastBlocksTransactionRegister = NewTransactionRegister(mempool.globalParams.Copy())

	// Add all the txns from the past blocks to the new pastBlocksTransactionRegister.
	for _, block := range sortedPastBlocks {
		if err := posFeeEstimator.addBlockNoLock(block); err != nil {
			return errors.Wrap(err, "PosFeeEstimator.Init: error adding block to pastBlocksMempool")
		}
	}
	return nil
}

// AddBlock adds a block to the PoSFeeEstimator. This will add all the transactions from the block
// to the pastBlocksTransactionRegister and cache the block. If there are now more blocks cached
// than the numBlocks param provided to Init, the oldest block will be removed from the cache
// and all its transactions removed from the pastBlocksTransactionRegister.
func (posFeeEstimator *PoSFeeEstimator) AddBlock(block *MsgDeSoBlock) error {
	posFeeEstimator.rwLock.Lock()
	defer posFeeEstimator.rwLock.Unlock()
	if err := posFeeEstimator.addBlockNoLock(block); err != nil {
		return errors.Wrap(err, "PoSFeeEstimator.AddBlock: error adding block to PoSFeeEstimator")
	}
	return nil
}

// addBlockNoLock is the same as AddBlock but assumes the caller has already acquired the rwLock.
func (posFeeEstimator *PoSFeeEstimator) addBlockNoLock(block *MsgDeSoBlock) error {
	// Add all transactions from the block to the pastBlocksTransactionRegister.
	if err := addBlockToTransactionRegister(posFeeEstimator.pastBlocksTransactionRegister, block); err != nil {
		return errors.Wrap(err, "PoSFeeEstimator.addBlockNoLock: error adding block to pastBlocksTransactionRegister")
	}
	posFeeEstimator.cachedBlocks = append(posFeeEstimator.cachedBlocks, block)
	// Sort the cached blocks by height & tstamp just to be safe.
	posFeeEstimator.sortCachedBlocks()
	if uint64(len(posFeeEstimator.cachedBlocks)) > posFeeEstimator.numBlocks {
		// Remove the oldest block.
		if err := posFeeEstimator.removeBlockNoLock(posFeeEstimator.cachedBlocks[0]); err != nil {
			return errors.Wrap(err, "PoSFeeEstimator.addBlockNoLock: error removing block from PoSFeeEstimator")
		}
	}
	return nil
}

// addBlockToTransactionRegister adds all the transactions from the block to the given transaction register.
// Should only be called when the rwLock over a TransactionRegister is held.
func addBlockToTransactionRegister(txnRegister *TransactionRegister, block *MsgDeSoBlock) error {
	for _, txn := range block.Txns {
		// We explicitly exclude block reward transactions as they do not have fees.
		if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward {
			continue
		}
		mtxn, err := NewMempoolTx(txn, block.Header.TstampNanoSecs, block.Header.Height)
		if err != nil {
			return errors.Wrap(err, "PoSFeeEstimator.addBlockToTransactionRegister: error creating MempoolTx")
		}
		if err = txnRegister.AddTransaction(mtxn); err != nil {
			return errors.Wrap(err, "PoSFeeEstimator.addBlockToTransactionRegister: error adding txn to pastBlocksTransactionRegister")
		}
	}
	return nil
}

// RemoveBlock removes a block from the PoSFeeEstimator. This will remove all the transactions from the block
// from the pastBlocksTransactionRegister and remove the block from the cache.
func (posFeeEstimator *PoSFeeEstimator) RemoveBlock(block *MsgDeSoBlock) error {
	posFeeEstimator.rwLock.Lock()
	defer posFeeEstimator.rwLock.Unlock()

	if err := posFeeEstimator.removeBlockNoLock(block); err != nil {
		return errors.Wrap(err, "PoSFeeEstimator.RemoveBlock: error removing block from PoSFeeEstimator")
	}
	return nil
}

// removeBlockNoLock is the same as RemoveBlock but assumes the caller has already acquired the rwLock.
func (posFeeEstimator *PoSFeeEstimator) removeBlockNoLock(block *MsgDeSoBlock) error {
	// Remove all transaction from the block from the pastBlocksTransactionRegister.
	for _, txn := range block.Txns {
		// We explicitly exclude block reward transactions as they do not have fees.
		// They were never added in the first place.
		if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward {
			continue
		}
		mtxn, err := NewMempoolTx(txn, block.Header.TstampNanoSecs, block.Header.Height)
		if err != nil {
			return errors.Wrap(err, "PoSFeeEstimator.RemoveBlock: error creating MempoolTx")
		}
		if err = posFeeEstimator.pastBlocksTransactionRegister.RemoveTransaction(mtxn); err != nil {
			return errors.Wrap(err, "PoSFeeEstimator.removeBlockNoLock: error removing txn from pastBlocksTransactionRegister")
		}
	}
	blockHash, err := block.Hash()
	if err != nil {
		return errors.Wrap(err, "PoSFeeEstimator.removeBlockNoLock: error computing blockHash")
	}
	// Remove the block from the cached blocks.
	for ii, cachedBlock := range posFeeEstimator.cachedBlocks {
		cachedBlockHash, err := cachedBlock.Hash()
		if err != nil {
			return errors.Wrap(err, "PoSFeeEstimator.removeBlockNoLock: error computing cachedBlockHash")
		}
		if blockHash.IsEqual(cachedBlockHash) {
			posFeeEstimator.cachedBlocks = append(posFeeEstimator.cachedBlocks[:ii], posFeeEstimator.cachedBlocks[ii+1:]...)
			break
		}
	}
	return nil
}

// UpdateGlobalParams updates the global params used by the PoSFeeEstimator. This only modifies the GlobalParams
// used by the pastBlockTransactionRegister and allows it to properly compute the fee buckets. The mempool's
// global params are not modified and are controlled externally.
func (posFeeEstimator *PoSFeeEstimator) UpdateGlobalParams(globalParams *GlobalParamsEntry) error {
	posFeeEstimator.rwLock.Lock()
	defer posFeeEstimator.rwLock.Unlock()
	tempTransactionRegister := NewTransactionRegister(globalParams.Copy())
	for _, block := range posFeeEstimator.cachedBlocks {
		if err := addBlockToTransactionRegister(tempTransactionRegister, block); err != nil {
			return errors.Wrap(err, "PosFeeEstimator.UpdateGlobalParams: error adding block to tempTransactionRegister")
		}
	}
	return nil
}

// sortCachedBlocks sorts the cached blocks by height & tstamp just to be safe.
func (posFeeEstimator *PoSFeeEstimator) sortCachedBlocks() {
	posFeeEstimator.cachedBlocks = collections.SortStable(posFeeEstimator.cachedBlocks, func(ii, jj *MsgDeSoBlock) bool {
		if ii.Header.Height == jj.Header.Height {
			return ii.Header.TstampNanoSecs < jj.Header.TstampNanoSecs
		}
		return ii.Header.Height < jj.Header.Height
	})
}

// EstimateFee estimates the fee in nanos for the provided transaction by taking the
// max of the mempoolFeeEstimate and pastBlocksFeeEstimate.
func (posFeeEstimator *PoSFeeEstimator) EstimateFee(
	txn *MsgDeSoTxn,
	congestionFactorBasisPoints uint64,
	priorityPercentileBasisPoints uint64,
	maxBlockSize uint64,
) (uint64, error) {
	posFeeEstimator.rwLock.RLock()
	defer posFeeEstimator.rwLock.RUnlock()
	mempoolFeeEstimate, err := posFeeEstimator.mempoolFeeEstimate(txn, congestionFactorBasisPoints, priorityPercentileBasisPoints, maxBlockSize)
	if err != nil {
		return 0, errors.Wrap(err, "EstimateFee: Problem computing mempool fee estimate")
	}
	pastBlocksFeeEstimate, err := posFeeEstimator.pastBlocksFeeEstimate(txn, congestionFactorBasisPoints, priorityPercentileBasisPoints, maxBlockSize)
	if err != nil {
		return 0, errors.Wrap(err, "EstimateFee: Problem computing past blocks fee estimate")
	}
	if mempoolFeeEstimate < pastBlocksFeeEstimate {
		return pastBlocksFeeEstimate, nil
	}
	return mempoolFeeEstimate, nil
}

// pastBlocksFeeEstimate estimates the fee in nanos for the provided transaction using the
// pastBlocksTransactionRegister and fee estimation parameters.
func (posFeeEstimator *PoSFeeEstimator) pastBlocksFeeEstimate(
	txn *MsgDeSoTxn,
	congestionFactorBasisPoints uint64,
	priorityPercentileBasisPoints uint64,
	maxBlockSize uint64,
) (uint64, error) {
	txnFee, err := posFeeEstimator.estimateTxnFeeGivenTransactionRegister(txn, posFeeEstimator.pastBlocksTransactionRegister, congestionFactorBasisPoints, priorityPercentileBasisPoints, maxBlockSize)
	if err != nil {
		return 0, errors.Wrap(err, "pastBlocksFeeEstimate: Problem computing txn fee")
	}
	return txnFee, nil
}

// mempoolFeeEstimate estimates the fee in nanos for the provided transaction using the
// mempoolFeeEstimatorMempool's TransactionRegister and fee estimation parameters.
func (posFeeEstimator *PoSFeeEstimator) mempoolFeeEstimate(
	txn *MsgDeSoTxn,
	congestionFactorBasisPoints uint64,
	priorityPercentileBasisPoints uint64,
	maxBlockSize uint64,
) (uint64, error) {
	txnFee, err := posFeeEstimator.estimateTxnFeeGivenTransactionRegister(txn, posFeeEstimator.mempoolFeeEstimatorMempool.txnRegister, congestionFactorBasisPoints, priorityPercentileBasisPoints, maxBlockSize)
	if err != nil {
		return 0, errors.Wrap(err, "mempoolFeeEstimate: Problem computing txn fee")
	}
	return txnFee, nil
}

// computeFeeGivenTxnAndFeeRate computes the fee in nanos for the provided transaction and fee rate
// in nanos per KB. It does this by recursively computing the fee until the fee converges.
func computeFeeGivenTxnAndFeeRate(txn *MsgDeSoTxn, feeRateNanosPerKB uint64) (uint64, error) {
	// Create a clone of the txn, so we don't modify the original.
	txnClone, err := txn.Copy()
	if err != nil {
		return 0, errors.Wrap(err, "computeFeeGivenTxnAndFeeRate: Problem copying txn")
	}
	// Set the nonce to the maximum value if it's not already set.
	if txnClone.TxnNonce == nil {
		txnClone.TxnNonce = &DeSoNonce{
			ExpirationBlockHeight: math.MaxUint64,
			PartialID:             math.MaxUint64,
		}
	}
	if txnClone.TxnNonce.ExpirationBlockHeight == 0 {
		txnClone.TxnNonce.ExpirationBlockHeight = math.MaxUint64
	}
	if txnClone.TxnNonce.PartialID == 0 {
		txnClone.TxnNonce.PartialID = math.MaxUint64
	}

	// Set the TxnFeeNanos to the maximum value.
	txnClone.TxnFeeNanos = math.MaxUint64
	txnFeeNanos, err := computeFeeRecursive(txnClone, feeRateNanosPerKB)
	if err != nil {
		return 0, errors.Wrap(err, "computeFeeGivenTxnAndFeeRate: Problem computing fee rate recursively")
	}
	return txnFeeNanos, nil
}

// computeFeeRecursive computes the fee in nanos for the provided transaction and fee rate
// in nanos per KB. It does this by recursively computing the fee until the fee converges.
// It should only be called from computeFeeGivenTxnAndFeeRate and assumes that the TxnFeeNanos
// field of the txn is set to the maximum value on the first call.
// It computes the length of the unsigned transaction bytes and then adds the maximum DER sig
// length to estimate an upper bound on the size of the signed transaction. Next,
// it will compute the fee by taking the fee rate in nanos per KB and multiplying it by the
// estimated size of the signed transaction in KB. If the fee computed here is less than the
// TxnFeeNanos field of the txn, it will set the TxnFeeNanos field to the computed fee and
// call itself recursively. This will continue until the computed fee is greater than or equal
// to the TxnFeeNanos field of the txn. At this point, it will return the TxnFeeNanos field.
// This will converge in 9 iterations or fewer. The maximum number of iterations is 9 because
// the transaction fee is the only field that gets modified so there are only 8 possible
// byte lengths that can be used to represent the transaction fee, and we ensure that the
// number of bytes that are required to represent computed transaction fee field is always less than
// the number of bytes to represent the TxnFeeNanos field at the previous iteration.
func computeFeeRecursive(txn *MsgDeSoTxn, feeRateNanosPerKB uint64) (uint64, error) {
	// Get the length of bytes in the txn.
	txnBytesNoSignature, err := txn.ToBytes(true)
	if err != nil {
		return 0, errors.Wrap(err, "computeFeeRecursive: Problem serializing txn")
	}
	const MaxDERSigLen = 74
	txnBytesLen := uint64(len(txnBytesNoSignature)) + MaxDERSigLen

	// Compute the new txn fee. If the computed fee is a decimal, we round up to the
	// next integer value. We define the math as follows:
	// - We need to compute CEIL(txnBytesLen * feeRateNanosPerKB / BytesPerKB)
	// - We use integer math to compute FLOOR(txnBytesLen * feeRateNanosPerKB + BytesPerKB - 1) / BytesPerKB)
	// Ref: https://stackoverflow.com/questions/17944/how-to-round-up-the-result-of-integer-division
	txnFeeNanos := (txnBytesLen*feeRateNanosPerKB + BytesPerKB - 1) / BytesPerKB
	if txnFeeNanos < txn.TxnFeeNanos {
		txn.TxnFeeNanos = txnFeeNanos
		return computeFeeRecursive(txn, feeRateNanosPerKB)
	}
	return txnFeeNanos, nil
}

// estimateTxnFeeGivenTransactionRegister estimates the fee in nanos for the provided transaction
// and transaction register using the congestionFactorBasisPoints, priorityPercentileBasisPoints,
// and maxBlockSize params. It calls estimateFeeRateNanosPerKBGivenTransactionRegister to estimate
// the fee rate and then computes the fee using computeFeeGivenTxnAndFeeRate.
func (posFeeEstimator *PoSFeeEstimator) estimateTxnFeeGivenTransactionRegister(
	txn *MsgDeSoTxn,
	txnRegister *TransactionRegister,
	congestionFactorBasisPoints uint64,
	priorityPercentileBasisPoints uint64,
	maxBlockSize uint64,
) (uint64, error) {
	feeRateNanosPerKB, err := posFeeEstimator.estimateFeeRateNanosPerKBGivenTransactionRegister(txnRegister, congestionFactorBasisPoints, priorityPercentileBasisPoints, maxBlockSize)
	if err != nil {
		return 0, errors.Wrap(err, "estimateTxnFeeGivenTransactionRegister: Problem computing fee rate")
	}
	txnFee, err := computeFeeGivenTxnAndFeeRate(txn, feeRateNanosPerKB)
	if err != nil {
		return 0, errors.Wrap(err, "estimateTxnFeeGivenTransactionRegister: Problem computing txn fee")
	}
	return txnFee, nil
}

// estimateFeeRateNanosPerKBGivenTransactionRegister estimates the fee rate in nanos per KB for the provided
// transaction register and fee estimation parameters. The congestionFactorBasisPoints param is the congestion
// factor in basis points (100 bps = 1%). The priorityPercentileBasisPoints param is the percentile of the
// priority fee bucket to use for the fee rate estimation. The maxBlockSize param is the maximum block size
// in bytes.
// This estimates fee rates using the following approach:
//  1. Compute the maximum size of numBlocks blocks as maxBlockSize * numBlocks, called maxSizeOfNumBlocks.
//  2. Iterate over all transactions in the transaction register in fee time order until the total size of
//     the transactions is greater than maxSizeOfNumBlocks and append those transactions to a slice.
//  3. If there are no transactions in the slice after step 2, return the minimum network fee.
//  4. Compute the priority fee bucket for the transactions in the slice using the priorityPercentileBasisPoints param
//     by calling getPriorityFeeBucketFromTxns on the slice.
//  5. If the resulting priority fee bucket from step 4 is less than the global minimum network fee, return the global
//     minimum network fee.
//  6. Compute the congestion threshold as congestionFactorBasisPoints * maxSizeOfNumBlocks / 10000.
//  7. If the total size of the transactions in the slice is less than the congestion threshold, return one bucket lower
//     than the priority fee bucket from step 4.
//  8. If the total size of the transactions in the size is greater than the congestion threshold and less
//     than or equal to maxSizeOfNumBlocks, return the priority fee bucket from step 4.
//  9. Otherwise, return one bucket higher than the priority fee bucket from step 4.
func (posFeeEstimator *PoSFeeEstimator) estimateFeeRateNanosPerKBGivenTransactionRegister(
	txnRegister *TransactionRegister,
	congestionFactorBasisPoints uint64,
	priorityPercentileBasisPoints uint64,
	maxBlockSize uint64,
) (uint64, error) {
	txnRegister.RLock()
	defer txnRegister.RUnlock()
	it := txnRegister.GetFeeTimeIterator()
	maxSizeOfNumBlocks := maxBlockSize * posFeeEstimator.numBlocks
	totalTxnsSize := uint64(0)
	var txns []*MempoolTx
	for it.Next() {
		tx, ok := it.Value()
		if !ok {
			break
		}
		txnBytes, err := tx.Tx.ToBytes(false)
		if err != nil {
			return 0, errors.Wrap(err, "estimateFeeRateNanosPerKBGivenTransactionRegister: Problem serializing txn")
		}
		totalTxnsSize += uint64(len(txnBytes))
		txns = append(txns, tx)
		// TODO: I think we want to include the txn that puts us over the limit, but
		// we can just move this check up a few lines if that's wrong.
		if totalTxnsSize > maxSizeOfNumBlocks {
			break
		}
	}
	globalMinFeeRate, _ := txnRegister.minimumNetworkFeeNanosPerKB.Uint64()
	if len(txns) == 0 {
		// If there are no txns in the transaction register, we simply return the minimum network fee.
		return globalMinFeeRate, nil
	}

	bucketMinFee, bucketMaxFee, err := getPriorityFeeBucketFromTxns(
		txns,
		priorityPercentileBasisPoints,
		txnRegister.minimumNetworkFeeNanosPerKB,
		txnRegister.feeBucketGrowthRateBasisPoints)
	if err != nil {
		return 0, errors.Wrap(err, "estimateFeeRateNanosPerKBGivenTransactionRegister: Problem computing priority fee bucket")
	}
	// If the bucketMinFee is less than or equal to the global min fee rate, we return the global min fee rate.
	if bucketMinFee <= globalMinFeeRate {
		return globalMinFeeRate, nil
	}

	// Compute the congestion threshold. If our congestion factor is 100% (or 10,000 bps),
	// then congestion threshold is simply max block size * numBlocks
	// TODO: I don't know if I like this name really.
	congestionThreshold := (congestionFactorBasisPoints * maxSizeOfNumBlocks) / MaxBasisPoints
	// If the total size of the txns in the transaction register is less than the computed congestion threshold,
	// we return one bucket lower than the Priority fee.
	if totalTxnsSize <= congestionThreshold {
		// Return one bucket lower than Priority fee
		oneBucketLowerMinFee, _ := computeFeeTimeBucketRangeFromFeeNanosPerKB(bucketMinFee-1, txnRegister.minimumNetworkFeeNanosPerKB, txnRegister.feeBucketGrowthRateBasisPoints)
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

// getPriorityFeeBucketFromTxns computes the priority fee bucket for the given transactions using the
// priorityPercentileBasisPoints, minimumNetworkFeeNanosPerKB, and feeBucketGrowthRateBasisPoints params.
// The feeTimeOrderedTxns have the highest fees first and the lowest fees last, so we need to compute
// the percentile position of the priorityPercentileBasisPoints param and then compute the fee bucket
// range based on the fee rate per KB of the transaction at that position.
func getPriorityFeeBucketFromTxns(
	feeTimeOrderedTxns []*MempoolTx,
	priorityPercentileBasisPoints uint64,
	minimumNetworkFeeNanosPerKB *big.Float,
	feeBucketGrowthRateBasisPoints *big.Float,
) (uint64, uint64, error) {
	percentilePosition := uint64(len(feeTimeOrderedTxns)) - ((priorityPercentileBasisPoints * uint64(len(feeTimeOrderedTxns))) / 10000)
	if percentilePosition >= uint64(len(feeTimeOrderedTxns)) {
		return 0, 0, errors.New("getPriorityFeeBucketFromTxns: error computing percentile position")
	}
	bucketMin, bucketMax := computeFeeTimeBucketRangeFromFeeNanosPerKB(feeTimeOrderedTxns[percentilePosition].FeePerKB, minimumNetworkFeeNanosPerKB, feeBucketGrowthRateBasisPoints)
	return bucketMin, bucketMax, nil
}
