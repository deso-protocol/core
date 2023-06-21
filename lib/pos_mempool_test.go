package lib

import (
	"fmt"
	"github.com/emirpasic/gods/sets/treeset"
	"github.com/stretchr/testify/require"
	"math/rand"
	"sort"
	"testing"
	"time"
)

func TestTreeSet(t *testing.T) {
	set := treeset.NewWithIntComparator(7, 10, 15, 22, 13, 200, 5, 0)
	it := set.Iterator()
	for it.Next() {
		fmt.Printf("%v ", it.Value())
	}
	fmt.Println()

	set.Remove(22)

	it = set.Iterator()
	for it.Next() {
		fmt.Printf("%v ", it.Value())
	}
	fmt.Println()
}

func TestTransactionRegisterWithRemoves(t *testing.T) {
	seed := int64(88)
	testCases := 1000
	feeRange := uint64(10000)
	timestampRange := uint64(10000)

	require := require.New(t)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()
	txnPool := _testGetRandomMempoolTxns(rand, globalParams.FeeBucketBaseRate, feeRange, timestampRange, testCases)

	txnRegister := NewTransactionRegister(&DeSoTestnetParams, globalParams)
	_testBucketStandardRemoveTest(t, txnPool, globalParams, false,
		func(tx *MempoolTx) {
			require.Equal(true, txnRegister.AddTransaction(tx))
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
	txnPool := _testGetRandomMempoolTxns(rand, globalParams.FeeBucketBaseRate, feeRange, timestampRange, testCases)

	txnRegister := NewTransactionRegister(&DeSoTestnetParams, globalParams)
	_testBucketStandardAddTest(t, txnPool, globalParams, false,
		func(tx *MempoolTx) {
			require.Equal(true, txnRegister.AddTransaction(tx))
		},
		func() []*MempoolTx {
			return txnRegister.GetFeeTimeTransactions()
		},
	)
}

func TestFeeBucketWithRemoves(t *testing.T) {
	seed := int64(6)
	testCases := 1000
	feeRange := uint64(10000)
	timestampRange := uint64(10000)

	require := require.New(t)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()
	txnPool := _testGetRandomMempoolTxns(rand, globalParams.FeeBucketBaseRate, feeRange, timestampRange, testCases)

	// Create new FeeBucket and add the txn pool
	feeBucket := NewFeeBucket(globalParams)
	_testBucketStandardRemoveTest(t, txnPool, globalParams, false,
		func(tx *MempoolTx) {
			require.Equal(nil, feeBucket.AddTransaction(tx))
		},
		func(tx *MempoolTx) {
			feeBucket.RemoveTransaction(tx)
		},
		func() []*MempoolTx {
			return feeBucket.GetFeeTimeTransactions()
		},
		func() {
			require.Equal(true, feeBucket.Empty())
		},
	)
}

func TestFeeBucketBasic(t *testing.T) {
	seed := int64(7)
	testCases := 1000
	feeRange := uint64(10000)
	timestampRange := uint64(10000)

	require := require.New(t)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()
	txnPool := _testGetRandomMempoolTxns(rand, globalParams.FeeBucketBaseRate, feeRange, timestampRange, testCases)

	// Create new FeeBucket and add the txn pool
	feeBucket := NewFeeBucket(globalParams)
	_testBucketStandardAddTest(t, txnPool, globalParams, false,
		func(tx *MempoolTx) {
			require.Equal(nil, feeBucket.AddTransaction(tx))
		},
		func() []*MempoolTx {
			return feeBucket.GetFeeTimeTransactions()
		},
	)
}

func TestTimeBucketRemove(t *testing.T) {
	seed := int64(44)
	testCases := 1000
	indexRange := 100
	timestampRange := uint64(10000)

	require := require.New(t)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()
	randomIndex := rand.Intn(indexRange)
	feeMin, feeMax := ComputeTimeBucketRangeFromIndex(randomIndex, globalParams)
	txnPool := _testGetRandomMempoolTxns(rand, feeMin, feeMax, timestampRange, testCases)

	// Create new FeeBucket and add the txn pool
	timeBucket := NewTimeBucket(randomIndex, globalParams)
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

func TestTimeBucketBasic(t *testing.T) {
	seed := int64(33)
	testCases := 1000
	indexRange := 100
	timestampRange := uint64(10000)

	require := require.New(t)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()
	randomIndex := rand.Intn(indexRange)
	feeMin, feeMax := ComputeTimeBucketRangeFromIndex(randomIndex, globalParams)
	txnPool := _testGetRandomMempoolTxns(rand, feeMin, feeMax, timestampRange, testCases)

	// Create new FeeBucket and add the txn pool
	timeBucket := NewTimeBucket(randomIndex, globalParams)
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
	globalParams.FeeBucketBaseRate = 1000
	globalParams.FeeBucketMultiplierBasisPoints = 1000

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

func _testMapMempoolTxnToTimeBucket(txn *MempoolTx, globalParams *GlobalParamsEntry) *TimeBucket {
	timeBucketIndex := ComputeTimeBucketIndexFromFeePerKBNanos(txn.FeePerKB, globalParams)
	return NewTimeBucket(timeBucketIndex, globalParams)
}

func _testSortMempoolTxnsByFeeTime(txnPool []*MempoolTx, globalParams *GlobalParamsEntry, timeOnly bool) []*MempoolTx {
	if !timeOnly {
		sort.Slice(txnPool, func(i, j int) bool {
			timeBucketI := _testMapMempoolTxnToTimeBucket(txnPool[i], globalParams)
			timeBucketJ := _testMapMempoolTxnToTimeBucket(txnPool[j], globalParams)

			feeComparison := FeeBucketComparator(timeBucketI, timeBucketJ)
			if feeComparison == 1 {
				return false
			} else if feeComparison == -1 {
				return true
			} else {
				timeComparison := TimeBucketComparator(txnPool[i], txnPool[j])
				if timeComparison == 1 {
					return false
				} else if timeComparison == -1 {
					return true
				} else {
					return true
				}
			}

		})
	} else {
		sort.Slice(txnPool, func(i, j int) bool {
			timeComparison := TimeBucketComparator(txnPool[i], txnPool[j])
			if timeComparison == 1 {
				return false
			} else if timeComparison == -1 {
				return true
			} else {
				return true
			}
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

	feeMins, feeMaxs := []uint64{}, []uint64{}
	for ii := 0; ii < 100; ii++ {
		feeMin, feeMax := ComputeTimeBucketRangeFromIndex(ii, globalParams)
		feeMins = append(feeMins, feeMin)
		feeMaxs = append(feeMaxs, feeMax)
	}

	for ii := 0; ii < 99; ii++ {
		require.Equal(feeMaxs[ii], feeMins[ii+1]-1)
	}

	for ii := 0; ii < 100; ii++ {
		feeMin, feeMax := ComputeTimeBucketRangeFromIndex(ii, globalParams)
		require.Equal(feeMins[ii], feeMin)
		require.Equal(feeMaxs[ii], feeMax)
	}
}

// TestComputeFeeBucketWithFee checks that the fee bucket index is computed correctly from a fee.
func TestComputeFeeBucketWithFee(t *testing.T) {
	globalParams := _testGetDefaultGlobalParams()

	verifyFeeBucket := func(n int, fee uint64) bool {
		feeMin, feeMax := ComputeTimeBucketRangeFromIndex(n, globalParams)
		if fee < feeMin {
			return false
		}
		if fee > feeMax {
			return false
		}
		return true
	}

	require := require.New(t)
	_ = require
	for ii := uint64(1000); ii < 100000; ii++ {
		n := ComputeTimeBucketIndexFromFeePerKBNanos(ii, globalParams)
		require.True(verifyFeeBucket(n, ii))
	}
}
