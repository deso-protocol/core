package lib

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"math/rand"
	"sort"
	"testing"
	"time"
)

func TestSanityCheckTransactionRegister(t *testing.T) {
	require := require.New(t)

	// Empty TransactionRegister
	txnRegister := NewTransactionRegister(&DeSoTestnetParams, _testGetDefaultGlobalParams())
	require.Equal(true, txnRegister.Empty())
	it := txnRegister.GetFeeTimeIterator()
	require.Equal(false, it.Next())

	// TransactionRegister with a single transaction
	txn := &MempoolTx{
		FeePerKB: 100000,
		Added:    time.UnixMicro(1000000),
		Hash:     NewBlockHash(RandomBytes(32)),
	}
	require.Nil(txnRegister.AddTransaction(txn))
	require.Equal(false, txnRegister.Empty())
	it = txnRegister.GetFeeTimeIterator()
	require.Equal(true, it.Next())
	recTxn, ok := it.Value()
	require.Equal(true, ok)
	require.Equal(true, bytes.Equal(txn.Hash[:], recTxn.Hash[:]))
	require.Nil(txnRegister.RemoveTransaction(recTxn))

	// TransactionRegister with no transactions and a single empty FeeTimeBucket.
	// This should never happen but let's see what happens.
	txnRegister = NewTransactionRegister(&DeSoTestnetParams, _testGetDefaultGlobalParams())
	emptyFeeTimeBucket := NewFeeTimeBucket(0, 1000)
	txnRegister.feeTimeBucketSet.Add(emptyFeeTimeBucket)
	txnRegister.feeTimeBucketsByMinFeeMap[0] = emptyFeeTimeBucket
	newIt := txnRegister.GetFeeTimeIterator()
	require.Equal(false, newIt.Next())
}

func TestTransactionRegisterWithRemoves(t *testing.T) {
	seed := int64(88)
	testCases := 1000
	feeRange := uint64(10000)
	timestampRange := uint64(10000)

	require := require.New(t)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()
	txnPool := _testGetRandomMempoolTxns(rand, globalParams.MinimumNetworkFeeNanosPerKB, feeRange, timestampRange, testCases)

	txnRegister := NewTransactionRegister(&DeSoTestnetParams, globalParams)
	_testBucketStandardRemoveTest(t, txnPool, globalParams, false,
		func(tx *MempoolTx) {
			require.Nil(txnRegister.AddTransaction(tx))
		},
		func(tx *MempoolTx) {
			txnRegister.RemoveTransaction(tx)
		},
		func() []*MempoolTx {
			return txnRegister.GetFeeTimeTransactions()
		},
		func() {
			require.Equal(true, txnRegister.Empty())
		},
	)
}

func TestTransactionRegisterBasic(t *testing.T) {
	seed := int64(77)
	testCases := 1000
	feeRange := uint64(10000)
	timestampRange := uint64(10000)

	require := require.New(t)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()
	txnPool := _testGetRandomMempoolTxns(rand, globalParams.MinimumNetworkFeeNanosPerKB, feeRange, timestampRange, testCases)

	txnRegister := NewTransactionRegister(&DeSoTestnetParams, globalParams)
	_testBucketStandardAddTest(t, txnPool, globalParams, false,
		func(tx *MempoolTx) {
			require.Nil(txnRegister.AddTransaction(tx))
		},
		func() []*MempoolTx {
			return txnRegister.GetFeeTimeTransactions()
		},
	)
}

func TestFeeTimeBucketRemove(t *testing.T) {
	seed := int64(44)
	testCases := 1000
	exponentRange := 100
	timestampRange := uint64(10000)

	require := require.New(t)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()
	randomExponent := uint32(rand.Intn(exponentRange))
	baseRate, bucketMultiplier := globalParams.ComputeFeeTimeBucketMinimumFeeAndMultiplier()
	feeMin, feeMax := computeFeeTimeBucketRangeFromExponent(randomExponent, baseRate, bucketMultiplier)
	txnPool := _testGetRandomMempoolTxns(rand, feeMin, feeMax, timestampRange, testCases)

	// Create new FeeBucket and add the txn pool
	bucketFeeMin, bucketFeeMax := computeFeeTimeBucketRangeFromExponent(randomExponent, baseRate, bucketMultiplier)
	timeBucket := NewFeeTimeBucket(bucketFeeMin, bucketFeeMax)
	_testBucketStandardRemoveTest(t, txnPool, globalParams, false,
		func(tx *MempoolTx) {
			require.Equal(nil, timeBucket.AddTransaction(tx))
		},
		func(tx *MempoolTx) {
			timeBucket.RemoveTransaction(tx)
		},
		func() []*MempoolTx {
			return timeBucket.GetTransactions()
		},
		func() {
			require.Equal(true, timeBucket.Empty())
		},
	)
}

func TestFeeTimeBucketBasic(t *testing.T) {
	seed := int64(33)
	testCases := 1000
	exponentRange := 100
	timestampRange := uint64(10000)

	require := require.New(t)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()
	randomExponent := uint32(rand.Intn(exponentRange))
	baseRate, bucketMultiplier := globalParams.ComputeFeeTimeBucketMinimumFeeAndMultiplier()
	feeMin, feeMax := computeFeeTimeBucketRangeFromExponent(randomExponent, baseRate, bucketMultiplier)
	txnPool := _testGetRandomMempoolTxns(rand, feeMin, feeMax, timestampRange, testCases)

	// Create new FeeBucket and add the txn pool
	bucketFeeMin, bucketFeeMax := computeFeeTimeBucketRangeFromExponent(randomExponent, baseRate, bucketMultiplier)
	timeBucket := NewFeeTimeBucket(bucketFeeMin, bucketFeeMax)
	_testBucketStandardAddTest(t, txnPool, globalParams, true,
		func(tx *MempoolTx) {
			require.Equal(nil, timeBucket.AddTransaction(tx))
		},
		func() []*MempoolTx {
			return timeBucket.GetTransactions()
		},
	)
}

func _testGetDefaultGlobalParams() *GlobalParamsEntry {
	globalParams := InitialGlobalParamsEntry
	globalParams.MinimumNetworkFeeNanosPerKB = 1000
	globalParams.FeeBucketRateMultiplierBasisPoints = 1000

	return &globalParams
}

func _testGetRandomMempoolTxns(rand *rand.Rand, feeMin uint64, feeMax uint64, timestampRange uint64, numTxns int) []*MempoolTx {
	txnPool := []*MempoolTx{}
	for ii := 0; ii < numTxns; ii++ {
		txnPool = append(txnPool, &MempoolTx{
			FeePerKB: rand.Uint64()%(feeMax-feeMin) + feeMin,
			Added:    time.UnixMicro(int64(rand.Uint64() % timestampRange)),
			Hash:     NewBlockHash(RandomBytes(32)),
		})
	}
	return txnPool
}

func _testMapMempoolTxnToTimeBucket(txn *MempoolTx, globalParams *GlobalParamsEntry) *FeeTimeBucket {
	baseRate, bucketMultiplier := globalParams.ComputeFeeTimeBucketMinimumFeeAndMultiplier()
	timeBucketExponent := computeFeeTimeBucketExponentFromFeeNanosPerKB(txn.FeePerKB, baseRate, bucketMultiplier)
	bucketFeeMin, bucketFeeMax := computeFeeTimeBucketRangeFromExponent(timeBucketExponent, baseRate, bucketMultiplier)
	return NewFeeTimeBucket(bucketFeeMin, bucketFeeMax)
}

func _testSortMempoolTxnsByFeeTime(txnPool []*MempoolTx, globalParams *GlobalParamsEntry, timeOnly bool) []*MempoolTx {
	if !timeOnly {
		sort.Slice(txnPool, func(i, j int) bool {
			timeBucketI := _testMapMempoolTxnToTimeBucket(txnPool[i], globalParams)
			timeBucketJ := _testMapMempoolTxnToTimeBucket(txnPool[j], globalParams)

			feeComparison := feeTimeBucketComparator(timeBucketI, timeBucketJ)
			if feeComparison == 1 {
				return false
			} else if feeComparison == -1 {
				return true
			}

			timeComparison := mempoolTxTimeOrderComparator(txnPool[i], txnPool[j])
			if timeComparison == 1 {
				return false
			}
			return true
		})
	} else {
		sort.Slice(txnPool, func(i, j int) bool {
			timeComparison := mempoolTxTimeOrderComparator(txnPool[i], txnPool[j])
			if timeComparison == 1 {
				return false
			}
			return true
		})
	}
	return txnPool
}

func _testBucketStandardAddTest(t *testing.T, txns []*MempoolTx, globalParams *GlobalParamsEntry, timeOnly bool,
	add func(tx *MempoolTx), getTxns func() []*MempoolTx) {

	require := require.New(t)
	for ii := 0; ii < len(txns); ii++ {
		add(txns[ii])
	}

	feeTimeTxns := getTxns()
	sortedTxns := _testSortMempoolTxnsByFeeTime(txns, _testGetDefaultGlobalParams(), timeOnly)
	require.Equal(len(sortedTxns), len(feeTimeTxns))
	for ii := 0; ii < len(sortedTxns); ii++ {
		require.Equal(sortedTxns[ii].FeePerKB, feeTimeTxns[ii].FeePerKB)
		require.Equal(sortedTxns[ii].Added.UnixNano(), feeTimeTxns[ii].Added.UnixNano())
	}
}

func _testBucketStandardRemoveTest(t *testing.T, txns []*MempoolTx, globalParams *GlobalParamsEntry, timeOnly bool,
	add func(tx *MempoolTx), remove func(tx *MempoolTx), getTxns func() []*MempoolTx, checkEmpty func()) {

	require := require.New(t)
	for ii := 0; ii < len(txns); ii++ {
		add(txns[ii])
	}

	// Now remove half of the transactions.
	txnToRemove := len(txns) / 2
	for ii := 0; ii < txnToRemove; ii++ {
		remove(txns[ii])
	}

	// Iterate through buckets to get Fee-Time ordering.
	halfTxnsFeeTime := getTxns()

	// Make a slice of the remaining transactions.
	remainingTxns := txns[txnToRemove:]
	remainingTxnsSorted := _testSortMempoolTxnsByFeeTime(remainingTxns, globalParams, timeOnly)

	// Now compare the tree set ordering with explicit sort ordering.
	require.Equal(len(halfTxnsFeeTime), len(remainingTxnsSorted))
	for ii := 0; ii < len(remainingTxnsSorted); ii++ {
		require.Equal(halfTxnsFeeTime[ii].FeePerKB, remainingTxnsSorted[ii].FeePerKB)
		require.Equal(halfTxnsFeeTime[ii].Added.UnixNano(), remainingTxnsSorted[ii].Added.UnixNano())
	}

	// Add back the transactions we removed to make sure they are added back in the correct order.
	for ii := 0; ii < txnToRemove; ii++ {
		add(txns[ii])
	}

	// Iterate through buckets to get Fee-Time ordering.
	allTxnsFeeTime := getTxns()

	// Get all the transactions and sort them by Fee-Time.
	allTxns := txns[:]
	allTxnsSorted := _testSortMempoolTxnsByFeeTime(allTxns, globalParams, timeOnly)

	// Now compare the tree set ordering with explicit sort ordering.
	require.Equal(len(allTxnsFeeTime), len(allTxnsSorted))
	for ii := 0; ii < len(allTxnsFeeTime); ii++ {
		require.Equal(allTxnsFeeTime[ii].FeePerKB, allTxnsSorted[ii].FeePerKB)
		require.Equal(allTxnsFeeTime[ii].Added.UnixNano(), allTxnsSorted[ii].Added.UnixNano())
	}

	// Now remove all the transactions.
	for ii := 0; ii < len(txns); ii++ {
		remove(txns[ii])
	}

	// Make sure the fee bucket is empty.
	checkEmpty()
}

// TestComputeFeeBucketRanges checks that the fee bucket ranges are computed correctly and deterministically.
func TestComputeFeeBucketRanges(t *testing.T) {
	require := require.New(t)
	_ = require

	globalParams := _testGetDefaultGlobalParams()
	baseRate, bucketMultiplier := globalParams.ComputeFeeTimeBucketMinimumFeeAndMultiplier()

	feeMins, feeMaxs := []uint64{}, []uint64{}
	for ii := uint32(0); ii < 100; ii++ {
		feeMin, feeMax := computeFeeTimeBucketRangeFromExponent(ii, baseRate, bucketMultiplier)
		feeMins = append(feeMins, feeMin)
		feeMaxs = append(feeMaxs, feeMax)
	}

	for ii := 0; ii < 99; ii++ {
		require.Equal(feeMaxs[ii], feeMins[ii+1]-1)
	}

	for ii := uint32(0); ii < 100; ii++ {
		feeMin, feeMax := computeFeeTimeBucketRangeFromExponent(ii, baseRate, bucketMultiplier)
		require.Equal(feeMins[ii], feeMin)
		require.Equal(feeMaxs[ii], feeMax)
	}
}

// TestComputeFeeBucketWithFee checks that the fee bucket exponent is computed correctly from a fee.
func TestComputeFeeBucketWithFee(t *testing.T) {
	globalParams := _testGetDefaultGlobalParams()
	baseRate, bucketMultiplier := globalParams.ComputeFeeTimeBucketMinimumFeeAndMultiplier()

	verifyFeeBucket := func(exponent uint32, fee uint64) bool {
		feeMin, feeMax := computeFeeTimeBucketRangeFromExponent(exponent, baseRate, bucketMultiplier)
		return fee >= feeMin && fee <= feeMax
	}

	require := require.New(t)
	_ = require
	for ii := uint64(1000); ii < 100000; ii++ {
		n := computeFeeTimeBucketExponentFromFeeNanosPerKB(ii, baseRate, bucketMultiplier)
		require.True(verifyFeeBucket(n, ii))
	}
}
