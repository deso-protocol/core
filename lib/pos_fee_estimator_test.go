package lib

import (
	"github.com/stretchr/testify/require"
	"math/big"
	"math/rand"
	"testing"
)

func TestMempoolFeeEstimator(t *testing.T) {
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

	mempool := NewPosMempool(params, globalParams, latestBlockView, 2, dir, false,
		maxMempoolPosSizeBytes, mempoolBackupIntervalMillis)
	require.NoError(t, mempool.Start())
	require.True(t, mempool.IsRunning())
	minFeeBucketMin, minFeeBucketMax := computeFeeTimeBucketRangeFromFeeNanosPerKB(globalParams.MinimumNetworkFeeNanosPerKB, big.NewFloat(float64(globalParams.MinimumNetworkFeeNanosPerKB)), mempool.txnRegister.feeBucketGrowthRateBasisPoints)
	// set the feeMin to the second fee bucket.
	feeMin := minFeeBucketMax + 1
	// When there's nothing in the mempool, we return 0!
	baseFee, err := mempoolFeeEstimator(mempool, 1, 10000, 10000, 1000)
	require.NoError(t, err)
	require.Equal(t, uint64(0), baseFee)

	numBytes := uint64(0)
	//congestionFactorBasisPoints := 50 * 100 // 50%
	var txns []*MsgDeSoTxn
	for ii := 0; ii < 10; ii++ {
		pk := m0PubBytes
		priv := m0Priv
		if ii%2 == 1 {
			pk = m1PubBytes
			priv = m1Priv
		}
		// Just add everything with the global min fee.
		txn := _generateTestTxnWithFeeRate(t, randSource, feeMin, pk, priv, 100, 25)
		txnBytes, err := txn.ToBytes(false)

		require.NoError(t, err)
		numBytes += uint64(len(txnBytes))
		txns = append(txns, txn)

		_wrappedPosMempoolAddTransaction(t, mempool, txn)
	}
	// Compute the next fee bucket min
	feeBucketMin, feeBucketMax := computeFeeTimeBucketRangeFromFeeNanosPerKB(feeMin, big.NewFloat(float64(globalParams.MinimumNetworkFeeNanosPerKB)), mempool.txnRegister.feeBucketGrowthRateBasisPoints)
	nextFeeBucketMin := feeBucketMax + 1
	// Let's set the max block size to be less than total size of transactions we added and make sure
	// we get the next fee bucket.
	estimatedFee, err := mempoolFeeEstimator(mempool, 1, 10000, 10000, numBytes-1)
	require.NoError(t, err)
	require.Equal(t, nextFeeBucketMin, estimatedFee)

	// Make the max block size be greater than the total size of transactions we added and set the
	// congestion percentage to 95% and make sure same priority fee bucket.
	estimatedFee, err = mempoolFeeEstimator(mempool, 1, 95*100, 10000, numBytes+1)
	require.NoError(t, err)
	require.Equal(t, feeBucketMin, estimatedFee)

	// Make the max block size 2x-1 the total size of transactions we added and set the congestion factor
	// to 50%. We should get the same priority fee bucket.
	estimatedFee, err = mempoolFeeEstimator(mempool, 1, 50*100, 10000, numBytes*2-1)
	require.NoError(t, err)
	require.Equal(t, feeBucketMin, estimatedFee)

	// Okay now make congestion factor 50% and make the max block size be more than 2x the
	// total size of transactions we added. We should get the previous fee bucket, in this
	// case this is the minimum fee rate bucket.
	estimatedFee, err = mempoolFeeEstimator(mempool, 1, 50*100, 10000, numBytes*2)
	require.NoError(t, err)
	require.Equal(t, minFeeBucketMin, estimatedFee)
}

func _generateTestTxnWithFeeRate(t *testing.T, rand *rand.Rand, feeRate uint64, pk []byte, priv string, expirationHeight uint64,
	extraDataBytes int32) *MsgDeSoTxn {

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
