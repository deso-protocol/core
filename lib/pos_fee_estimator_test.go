package lib

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFeeEstimator(t *testing.T) {
	randSource := rand.New(rand.NewSource(2373))
	globalParams := _testGetDefaultGlobalParams()

	maxMempoolPosSizeBytes := uint64(1e9)
	mempoolBackupIntervalMillis := uint64(30000)

	params, db := _posTestBlockchainSetup(t)
	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	m1PubBytes, _, _ := Base58CheckDecode(m1Pub)

	latestBlockView, err := NewUtxoView(db, params, nil, nil, nil)
	require.NoError(t, err)
	dir := _dbDirSetup(t)

	mempool := NewPosMempool()
	err = mempool.Init(
		params, globalParams, latestBlockView, 2, dir, false, maxMempoolPosSizeBytes, mempoolBackupIntervalMillis, 1,
		nil, 1, 10000, 100, 100,
	)
	require.NoError(t, err)
	require.NoError(t, mempool.Start())
	require.True(t, mempool.IsRunning())
	defer mempool.Stop()
	minFeeBucketMin, minFeeBucketMax := computeFeeTimeBucketRangeFromFeeNanosPerKB(
		globalParams.MinimumNetworkFeeNanosPerKB,
		big.NewFloat(float64(globalParams.MinimumNetworkFeeNanosPerKB)),
		mempool.txnRegister.feeBucketGrowthRateBasisPoints)
	// set the feeMin to the second fee bucket.
	feeMin := minFeeBucketMax + 1
	// Construct a FeeEstimator with no transactions in it. We should get the minimum fee bucket.
	// We make some dummy block to get around validations.
	posFeeEstimator := &PoSFeeEstimator{}
	err = posFeeEstimator.Init(mempool.txnRegister, 1, []*MsgDeSoBlock{{
		Header: &MsgDeSoHeader{Height: 10},
	}}, 1, mempool.globalParams)
	require.NoError(t, err)
	// When there's nothing in the mempool, we return the global minimum fee rate.
	baseFeeRate, err := posFeeEstimator.estimateFeeRateNanosPerKBGivenTransactionRegister(
		posFeeEstimator.mempoolTransactionRegister, 10000, 10000, 1, 1000)
	require.NoError(t, err)
	require.Equal(t, globalParams.MinimumNetworkFeeNanosPerKB, baseFeeRate)
	// When there's nothing in the past blocks, we return the global minimum fee rate.
	baseFeeRate, err = posFeeEstimator.estimateFeeRateNanosPerKBGivenTransactionRegister(
		posFeeEstimator.pastBlocksTransactionRegister, 10000, 10000, 1, 1000)
	require.NoError(t, err)
	require.Equal(t, globalParams.MinimumNetworkFeeNanosPerKB, baseFeeRate)
	// Make a dummy transaction, so we can check the fee rate.
	txn := _generateTestTxnWithFeeRate(t, randSource, feeMin, m0PubBytes, m0Priv, 100, 25)
	computedFee, err := posFeeEstimator.mempoolFeeEstimate(txn, 10000, 10000, 1000)
	require.NoError(t, err)
	validateTxnFee(t, txn, computedFee, baseFeeRate)
	computedFee, err = posFeeEstimator.pastBlocksFeeEstimate(txn, 10000, 10000, 1000)
	require.NoError(t, err)
	validateTxnFee(t, txn, computedFee, baseFeeRate)
	// Hybrid estimator will also return the base fee rate * number of bytes.
	computedFee, err = posFeeEstimator.EstimateFee(txn, 10000, 10000, 1000, 10000, 1000)
	require.NoError(t, err)
	validateTxnFee(t, txn, computedFee, baseFeeRate)

	numBytesMempool := uint64(0)
	var txns []*MsgDeSoTxn
	// Generate dummy transactions to put in the mempool.
	for ii := 0; ii < 10; ii++ {
		pk := m0PubBytes
		priv := m0Priv
		if ii%2 == 1 {
			pk = m1PubBytes
			priv = m1Priv
		}
		// Just add everything with the global min fee.
		mempoolTxn := _generateTestTxnWithFeeRate(t, randSource, feeMin, pk, priv, 100, 25)
		txnBytes, err := mempoolTxn.ToBytes(false)

		require.NoError(t, err)
		numBytesMempool += uint64(len(txnBytes))
		txns = append(txns, mempoolTxn)

		_wrappedPosMempoolAddTransaction(t, mempool, mempoolTxn)
	}
	// Generate dummy transactions to put in the past blocks.
	numBytesPastBlocks := uint64(0)
	//congestionFactorBasisPoints := 50 * 100 // 50%
	var pastBlocksTxns []*MsgDeSoTxn
	for ii := 0; ii < 10; ii++ {
		pk := m0PubBytes
		priv := m0Priv
		if ii%2 == 1 {
			pk = m1PubBytes
			priv = m1Priv
		}
		// Just add everything with the global min fee.
		pastBlockTxn := _generateTestTxnWithFeeRate(t, randSource, feeMin, pk, priv, 100, 25)
		txnBytes, err := pastBlockTxn.ToBytes(false)

		require.NoError(t, err)
		numBytesPastBlocks += uint64(len(txnBytes))
		pastBlocksTxns = append(pastBlocksTxns, pastBlockTxn)
	}
	dummyBlock := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			Height: 10,
		},
		Txns: pastBlocksTxns,
	}
	err = posFeeEstimator.AddBlock(dummyBlock)
	require.NoError(t, err)
	// Compute the next fee bucket min
	_, feeBucketMax := computeFeeTimeBucketRangeFromFeeNanosPerKB(
		feeMin,
		big.NewFloat(float64(globalParams.MinimumNetworkFeeNanosPerKB)),
		mempool.txnRegister.feeBucketGrowthRateBasisPoints)
	nextFeeBucketMin := feeBucketMax + 1
	var estimatedMempoolFeeRate uint64
	var estimatedMempoolFee uint64
	var estimatedPastBlocksFeeRate uint64
	var estimatedPastBlocksFee uint64
	var estimatedHybridFee uint64
	{
		// Let's set the max block size to be less than total size of transactions we added and make sure
		// we get the next fee bucket.
		congestionFactor := uint64(10000)
		priorityPercentileBasisPoints := uint64(10000)
		maxBlockSizeMempool := numBytesMempool - 1
		maxBlockSizePastBlocks := numBytesPastBlocks - 1
		// We use the max to determine which to pass to the hybrid estimator.
		maxBlockSizeHybrid := maxBlockSizePastBlocks
		if maxBlockSizeMempool > maxBlockSizePastBlocks {
			maxBlockSizeHybrid = maxBlockSizeMempool
		}
		estimatedMempoolFeeRate, err = posFeeEstimator.estimateFeeRateNanosPerKBGivenTransactionRegister(
			posFeeEstimator.mempoolTransactionRegister, congestionFactor, priorityPercentileBasisPoints, 1,
			maxBlockSizeMempool)
		require.NoError(t, err)
		require.Equal(t, nextFeeBucketMin, estimatedMempoolFeeRate)
		estimatedMempoolFee, err = posFeeEstimator.mempoolFeeEstimate(txn, congestionFactor,
			priorityPercentileBasisPoints, maxBlockSizeMempool)
		require.NoError(t, err)
		validateTxnFee(t, txn, estimatedMempoolFee, estimatedMempoolFeeRate)

		// Let's do the same for past blocks estimator
		estimatedPastBlocksFeeRate, err = posFeeEstimator.estimateFeeRateNanosPerKBGivenTransactionRegister(
			posFeeEstimator.pastBlocksTransactionRegister, congestionFactor, priorityPercentileBasisPoints, 1,
			maxBlockSizePastBlocks)
		require.NoError(t, err)
		require.Equal(t, nextFeeBucketMin, estimatedPastBlocksFeeRate)
		estimatedPastBlocksFee, err = posFeeEstimator.pastBlocksFeeEstimate(txn, congestionFactor,
			priorityPercentileBasisPoints, maxBlockSizePastBlocks)
		require.NoError(t, err)
		validateTxnFee(t, txn, estimatedPastBlocksFee, estimatedPastBlocksFeeRate)

		// Both the mempool and next block fee and fee rates should be equal since we have
		// everything in the same fee bucket.
		require.Equal(t, estimatedMempoolFee, estimatedPastBlocksFee)
		require.Equal(t, estimatedMempoolFeeRate, estimatedPastBlocksFeeRate)

		// And the hybrid estimator is just the max, but for completeness, we check it.
		estimatedHybridFee, err = posFeeEstimator.EstimateFee(
			txn, congestionFactor, priorityPercentileBasisPoints, congestionFactor, priorityPercentileBasisPoints,
			maxBlockSizeHybrid)
		require.NoError(t, err)
		require.Equal(t, estimatedMempoolFee, estimatedHybridFee)
		require.Equal(t, estimatedPastBlocksFee, estimatedHybridFee)
	}

	{
		// Make the max block size be greater than the total size of transactions we added and set the
		// congestion percentage to 95% and make sure we go up one priority fee bucket.
		congestionFactor := uint64(95 * 100)
		priorityPercentileBasisPoints := uint64(10000)
		maxBlockSizeMempool := numBytesMempool + 1
		maxBlockSizePastBlocks := numBytesPastBlocks + 1
		// We use the max to determine which to pass to the hybrid estimator.
		maxBlockSizeHybrid := maxBlockSizePastBlocks
		if maxBlockSizeMempool > maxBlockSizePastBlocks {
			maxBlockSizeHybrid = maxBlockSizeMempool
		}
		estimatedMempoolFeeRate, err = posFeeEstimator.estimateFeeRateNanosPerKBGivenTransactionRegister(
			posFeeEstimator.mempoolTransactionRegister, congestionFactor, priorityPercentileBasisPoints, 1,
			maxBlockSizeMempool)
		require.NoError(t, err)
		require.Equal(t, nextFeeBucketMin, estimatedMempoolFeeRate)
		estimatedMempoolFee, err = posFeeEstimator.mempoolFeeEstimate(txn, congestionFactor,
			priorityPercentileBasisPoints, maxBlockSizeMempool)
		require.NoError(t, err)
		validateTxnFee(t, txn, estimatedMempoolFee, estimatedMempoolFeeRate)

		// Let's do the same for past blocks estimator
		estimatedPastBlocksFeeRate, err = posFeeEstimator.estimateFeeRateNanosPerKBGivenTransactionRegister(
			posFeeEstimator.pastBlocksTransactionRegister, congestionFactor, priorityPercentileBasisPoints, 1,
			maxBlockSizePastBlocks)
		require.NoError(t, err)
		require.Equal(t, nextFeeBucketMin, estimatedPastBlocksFeeRate)
		estimatedPastBlocksFee, err = posFeeEstimator.pastBlocksFeeEstimate(txn, congestionFactor,
			priorityPercentileBasisPoints, maxBlockSizePastBlocks)
		require.NoError(t, err)
		validateTxnFee(t, txn, estimatedPastBlocksFee, estimatedPastBlocksFeeRate)

		// Both the mempool and next block fee and fee rates should be equal since we have
		// everything in the same fee bucket.
		require.Equal(t, estimatedMempoolFee, estimatedPastBlocksFee)
		require.Equal(t, estimatedMempoolFeeRate, estimatedPastBlocksFeeRate)

		// And the hybrid estimator is just the max, but for completeness, we check it.
		estimatedHybridFee, err = posFeeEstimator.EstimateFee(
			txn, congestionFactor, priorityPercentileBasisPoints, congestionFactor, priorityPercentileBasisPoints,
			maxBlockSizeHybrid)
		require.NoError(t, err)
		require.Equal(t, estimatedMempoolFee, estimatedHybridFee)
		require.Equal(t, estimatedPastBlocksFee, estimatedHybridFee)
	}
	{
		// Make the max block size 2x-1 the total size of transactions we added and set the congestion factor
		// to 50%. We should get the next priority fee bucket.
		congestionFactor := uint64(50 * 100)

		priorityPercentileBasisPoints := uint64(10000)
		maxBlockSizeMempool := 2*numBytesMempool - 1
		maxBlockSizePastBlocks := 2*numBytesPastBlocks - 1
		// We use the max to determine which to pass to the hybrid estimator.
		maxBlockSizeHybrid := maxBlockSizePastBlocks
		if maxBlockSizeMempool > maxBlockSizePastBlocks {
			maxBlockSizeHybrid = maxBlockSizeMempool
		}
		estimatedMempoolFeeRate, err = posFeeEstimator.estimateFeeRateNanosPerKBGivenTransactionRegister(
			posFeeEstimator.mempoolTransactionRegister, congestionFactor, priorityPercentileBasisPoints, 1,
			maxBlockSizeMempool)
		require.NoError(t, err)
		require.Equal(t, nextFeeBucketMin, estimatedMempoolFeeRate)
		estimatedMempoolFee, err = posFeeEstimator.mempoolFeeEstimate(txn, congestionFactor,
			priorityPercentileBasisPoints, maxBlockSizeMempool)
		require.NoError(t, err)
		validateTxnFee(t, txn, estimatedMempoolFee, estimatedMempoolFeeRate)

		// Let's do the same for past blocks estimator
		estimatedPastBlocksFeeRate, err = posFeeEstimator.estimateFeeRateNanosPerKBGivenTransactionRegister(
			posFeeEstimator.pastBlocksTransactionRegister, congestionFactor, priorityPercentileBasisPoints, 1,
			maxBlockSizePastBlocks)
		require.NoError(t, err)
		require.Equal(t, nextFeeBucketMin, estimatedPastBlocksFeeRate)
		estimatedPastBlocksFee, err = posFeeEstimator.pastBlocksFeeEstimate(txn, congestionFactor,
			priorityPercentileBasisPoints, maxBlockSizePastBlocks)
		require.NoError(t, err)
		validateTxnFee(t, txn, estimatedPastBlocksFee, estimatedPastBlocksFeeRate)

		// Both the mempool and next block fee and fee rates should be equal since we have
		// everything in the same fee bucket.
		require.Equal(t, estimatedMempoolFee, estimatedPastBlocksFee)
		require.Equal(t, estimatedMempoolFeeRate, estimatedPastBlocksFeeRate)

		// And the hybrid estimator is just the max, but for completeness, we check it.
		estimatedHybridFee, err = posFeeEstimator.EstimateFee(
			txn, congestionFactor, priorityPercentileBasisPoints, congestionFactor, priorityPercentileBasisPoints,
			maxBlockSizeHybrid)
		require.NoError(t, err)
		require.Equal(t, estimatedMempoolFee, estimatedHybridFee)
		require.Equal(t, estimatedPastBlocksFee, estimatedHybridFee)
	}
	{
		// Okay now make congestion factor 50% and make the max block size be more than 2x the
		// total size of transactions we added. We should get the previous fee bucket, in this
		// case this is the minimum fee rate bucket.
		congestionFactor := uint64(50 * 100)
		priorityPercentileBasisPoints := uint64(10000)
		maxBlockSizeMempool := 2 * numBytesMempool
		maxBlockSizePastBlocks := 2 * numBytesPastBlocks
		// We use the max to determine which to pass to the hybrid estimator.
		maxBlockSizeHybrid := maxBlockSizePastBlocks
		if maxBlockSizeMempool > maxBlockSizePastBlocks {
			maxBlockSizeHybrid = maxBlockSizeMempool
		}
		estimatedMempoolFeeRate, err = posFeeEstimator.estimateFeeRateNanosPerKBGivenTransactionRegister(
			posFeeEstimator.mempoolTransactionRegister, congestionFactor, priorityPercentileBasisPoints, 1,
			maxBlockSizeMempool)
		require.NoError(t, err)
		require.Equal(t, minFeeBucketMin, estimatedMempoolFeeRate)
		estimatedMempoolFee, err = posFeeEstimator.mempoolFeeEstimate(txn, congestionFactor,
			priorityPercentileBasisPoints, maxBlockSizeMempool)
		require.NoError(t, err)
		validateTxnFee(t, txn, estimatedMempoolFee, estimatedMempoolFeeRate)

		// Let's do the same for past blocks estimator
		estimatedPastBlocksFeeRate, err = posFeeEstimator.estimateFeeRateNanosPerKBGivenTransactionRegister(
			posFeeEstimator.pastBlocksTransactionRegister, congestionFactor, priorityPercentileBasisPoints, 1,
			maxBlockSizePastBlocks)
		require.NoError(t, err)
		require.Equal(t, minFeeBucketMin, estimatedPastBlocksFeeRate)
		estimatedPastBlocksFee, err = posFeeEstimator.pastBlocksFeeEstimate(txn, congestionFactor,
			priorityPercentileBasisPoints, maxBlockSizePastBlocks)
		require.NoError(t, err)
		validateTxnFee(t, txn, estimatedPastBlocksFee, estimatedPastBlocksFeeRate)

		// Both the mempool and next block fee and fee rates should be equal since we have
		// everything in the same fee bucket.
		require.Equal(t, estimatedMempoolFee, estimatedPastBlocksFee)
		require.Equal(t, estimatedMempoolFeeRate, estimatedPastBlocksFeeRate)

		// And the hybrid estimator is just the max, but for completeness, we check it.
		estimatedHybridFee, err = posFeeEstimator.EstimateFee(
			txn, congestionFactor, priorityPercentileBasisPoints, congestionFactor, priorityPercentileBasisPoints,
			maxBlockSizeHybrid)
		require.NoError(t, err)
		require.Equal(t, estimatedMempoolFee, estimatedHybridFee)
		require.Equal(t, estimatedPastBlocksFee, estimatedHybridFee)
	}
}

func _generateTestTxnWithFeeRate(t *testing.T, rand *rand.Rand, feeRate uint64, pk []byte, priv string,
	expirationHeight uint64, extraDataBytes int32) *MsgDeSoTxn {

	extraData := make(map[string][]byte)
	extraData["key"] = RandomBytes(extraDataBytes)
	txn := &MsgDeSoTxn{
		TxnVersion:  DeSoTxnVersion1,
		PublicKey:   pk,
		TxnMeta:     &BasicTransferMetadata{},
		TxnFeeNanos: 0,
		TxnNonce: &DeSoNonce{
			ExpirationBlockHeight: expirationHeight,
			PartialID:             rand.Uint64() % 10000,
		},
		ExtraData: extraData,
	}
	// Sign it so we have the correct # of bytes
	_signTxn(t, txn, priv)
	// Compute fee manually so things are correct... ugh.
	computeFeeRateIterative(t, txn, priv, feeRate)
	return txn
}

func computeFeeRateIterative(t *testing.T, txn *MsgDeSoTxn, priv string, feeRate uint64) {
	txnBytes, err := txn.ToBytes(false)
	require.NoError(t, err)
	shouldBumpByOne := (feeRate * uint64(len(txnBytes)) % 1000) != 0
	txnFeeNanos := feeRate * uint64(len(txnBytes)) / 1000
	if shouldBumpByOne {
		txnFeeNanos++
	}
	txn.TxnFeeNanos = txnFeeNanos
	_signTxn(t, txn, priv)
	newTxnBytes, err := txn.ToBytes(false)
	require.NoError(t, err)
	if (txn.TxnFeeNanos*1000)/uint64(len(newTxnBytes)) < feeRate {
		computeFeeRateIterative(t, txn, priv, feeRate)
	}
}

func validateTxnFee(t *testing.T, txn *MsgDeSoTxn, estimatedFee uint64, estimatedFeeRate uint64) {
	// Set the fee and sign the transaction, so we can get the real byte length.
	txn.TxnFeeNanos = estimatedFee
	_signTxn(t, txn, m0Priv)
	// Make sure the fee is the same as the estimated fee.
	txnBytes, err := txn.ToBytes(false)
	require.NoError(t, err)
	computedFeeByFeeRate := (uint64(len(txnBytes)) * estimatedFeeRate) / 1000
	require.GreaterOrEqual(t, estimatedFee, computedFeeByFeeRate)
}
