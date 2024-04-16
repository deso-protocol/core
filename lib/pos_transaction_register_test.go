package lib

import (
	"bytes"
	"math"
	"math/rand"
	"sort"
	"testing"
	"time"

	ecdsa2 "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestSanityCheckTransactionRegister(t *testing.T) {
	require := require.New(t)

	// Empty TransactionRegister
	txnRegister := NewTransactionRegister()
	txnRegister.Init(_testGetDefaultGlobalParams())
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
	require.Len(txnRegister.GetFeeTimeTransactions(), 1)
	require.Equal(true, txnRegister.Includes(txn))
	it = txnRegister.GetFeeTimeIterator()
	require.Equal(true, it.Next())
	recTxn, ok := it.Value()
	require.Equal(true, ok)
	require.Equal(true, bytes.Equal(txn.Hash[:], recTxn.Hash[:]))
	require.Nil(txnRegister.RemoveTransaction(recTxn))
	require.Len(txnRegister.GetFeeTimeTransactions(), 0)
	require.Equal(true, txnRegister.Empty())

	// TransactionRegister with no transactions and a single empty FeeTimeBucket.
	// This should never happen but let's see what happens.
	txnRegister = NewTransactionRegister()
	txnRegister.Init(_testGetDefaultGlobalParams())
	emptyFeeTimeBucket := NewFeeTimeBucket(0, 1000)
	txnRegister.feeTimeBucketSet.Add(emptyFeeTimeBucket)
	txnRegister.feeTimeBucketsByMinFeeMap[0] = emptyFeeTimeBucket
	newIt := txnRegister.GetFeeTimeIterator()
	require.Equal(false, newIt.Next())
	require.Len(txnRegister.GetFeeTimeTransactions(), 0)

	// Remove non-existing transaction from empty TransactionRegister.
	txn2 := &MempoolTx{
		FeePerKB: 10050,
		Added:    time.UnixMicro(1000050),
		Hash:     NewBlockHash(RandomBytes(32)),
	}
	require.Nil(txnRegister.RemoveTransaction(txn2))
	require.Len(txnRegister.GetFeeTimeTransactions(), 0)

	// Remove non-existing transaction from non-empty TransactionRegister.
	require.NoError(txnRegister.AddTransaction(txn))
	require.Len(txnRegister.GetFeeTimeTransactions(), 1)
	require.Equal(true, txnRegister.Includes(txn))
	require.Nil(txnRegister.RemoveTransaction(txn2))
	require.Len(txnRegister.GetFeeTimeTransactions(), 1)
	require.Equal(true, txnRegister.Includes(txn))
	require.Equal(false, txnRegister.Includes(txn2))
	require.Equal(true, bytes.Equal(txnRegister.GetFeeTimeTransactions()[0].Hash[:], txn.Hash[:]))
}

func TestSanityCheckFeeTimeBucket(t *testing.T) {
	require := require.New(t)

	// Empty FeeTimeBucket
	feeTimeBucket := NewFeeTimeBucket(100000, 110000)
	require.Len(feeTimeBucket.GetTransactions(), 0)
	require.Equal(uint64(0), feeTimeBucket.totalTxnsSizeBytes)
	require.Equal(true, feeTimeBucket.Empty())

	// FeeTimeBucket with a single transaction
	txn := &MempoolTx{
		FeePerKB:    100000,
		Added:       time.UnixMicro(1000000),
		Hash:        NewBlockHash(RandomBytes(32)),
		TxSizeBytes: 100,
	}

	require.Nil(feeTimeBucket.AddTransaction(txn))
	require.Len(feeTimeBucket.GetTransactions(), 1)
	require.Equal(txn.TxSizeBytes, feeTimeBucket.totalTxnsSizeBytes)
	require.Equal(false, feeTimeBucket.Empty())

	// Try adding the same transaction again.
	require.Nil(feeTimeBucket.AddTransaction(txn))
	require.Len(feeTimeBucket.GetTransactions(), 1)
	require.Equal(txn.TxSizeBytes, feeTimeBucket.totalTxnsSizeBytes)
	require.Equal(false, feeTimeBucket.Empty())

	// Remove non-existing transaction from non-empty FeeTimeBucket.
	txn2 := &MempoolTx{
		FeePerKB: 10050,
		Added:    time.UnixMicro(1000050),
		Hash:     NewBlockHash(RandomBytes(32)),
	}
	feeTimeBucket.RemoveTransaction(txn2)
	require.Len(feeTimeBucket.GetTransactions(), 1)
	require.Equal(txn.TxSizeBytes, feeTimeBucket.totalTxnsSizeBytes)
	require.Equal(false, feeTimeBucket.Empty())
	require.Equal(true, feeTimeBucket.Includes(txn))
	require.Equal(false, feeTimeBucket.Includes(txn2))

	// Remove existing transactions from FeeTimeBucket.
	feeTimeBucket.RemoveTransaction(txn)
	require.Len(feeTimeBucket.GetTransactions(), 0)
	require.Equal(uint64(0), feeTimeBucket.totalTxnsSizeBytes)
	require.Equal(true, feeTimeBucket.Empty())
	require.Equal(false, feeTimeBucket.Includes(txn))
	require.Equal(false, feeTimeBucket.Includes(txn2))

	// Remove non-existing transaction from empty FeeTimeBucket.
	feeTimeBucket.RemoveTransaction(txn2)
	require.Len(feeTimeBucket.GetTransactions(), 0)
	require.Equal(uint64(0), feeTimeBucket.totalTxnsSizeBytes)
	require.Equal(true, feeTimeBucket.Empty())
	require.Equal(false, feeTimeBucket.Includes(txn))
	require.Equal(false, feeTimeBucket.Includes(txn2))
}

func TestTransactionRegisterPrune(t *testing.T) {
	seed := int64(111)
	testCases := 1000
	feeRange := uint64(10000)
	timestampRange := uint64(10000)

	require := require.New(t)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()
	txnPool := _testGetRandomMempoolTxns(rand, globalParams.MinimumNetworkFeeNanosPerKB, feeRange, 1000, timestampRange, testCases)

	txnRegister := NewTransactionRegister()
	txnRegister.Init(globalParams)
	totalSize := uint64(0)
	for _, tx := range txnPool {
		require.Nil(txnRegister.AddTransaction(tx))
		totalSize += tx.TxSizeBytes
	}

	// Try pruning 0 bytes
	txns, err := txnRegister.PruneToSize(txnRegister.totalTxnsSizeBytes)
	require.Nil(err)
	require.Len(txns, 0)

	// Remove a single transaction
	txns, err = txnRegister.PruneToSize(txnRegister.totalTxnsSizeBytes - 1)
	require.Nil(err)
	require.Len(txns, 1)
	totalSize -= txns[0].TxSizeBytes
	require.Equal(totalSize, txnRegister.totalTxnsSizeBytes)

	sortedTxns := _testSortMempoolTxnsByFeeTime(txnPool, globalParams, false)
	lastTxn := sortedTxns[len(sortedTxns)-1]
	require.Equal(true, bytes.Equal(lastTxn.Hash[:], txns[0].Hash[:]))
	sortedTxns = sortedTxns[:len(sortedTxns)-1]
	registerTxns := txnRegister.GetFeeTimeTransactions()
	require.Equal(len(sortedTxns), len(registerTxns))
	for ii := 0; ii < len(sortedTxns); ii++ {
		require.Equal(true, bytes.Equal(sortedTxns[ii].Hash[:], registerTxns[ii].Hash[:]))
	}

	// Remove 10 transactions
	last10Txns := sortedTxns[len(sortedTxns)-10:]
	last10TxnsByteSize := uint64(0)
	for _, txn := range last10Txns {
		last10TxnsByteSize += txn.TxSizeBytes
	}

	txns, err = txnRegister.PruneToSize(txnRegister.totalTxnsSizeBytes - last10TxnsByteSize)
	require.Nil(err)
	require.Equal(10, len(txns))
	totalSize -= last10TxnsByteSize
	require.Equal(totalSize, txnRegister.totalTxnsSizeBytes)

	for ii := len(sortedTxns) - 1; ii >= len(sortedTxns)-10; ii-- {
		require.Equal(true, bytes.Equal(sortedTxns[ii].Hash[:], txns[len(sortedTxns)-1-ii].Hash[:]))
	}
	sortedTxns = sortedTxns[:len(sortedTxns)-10]
	registerTxns = txnRegister.GetFeeTimeTransactions()
	require.Equal(len(sortedTxns), len(registerTxns))
	for ii := 0; ii < len(sortedTxns); ii++ {
		require.Equal(true, bytes.Equal(sortedTxns[ii].Hash[:], registerTxns[ii].Hash[:]))
	}

	// Remove all but 1 transaction
	firstTxn := sortedTxns[0]
	txns, err = txnRegister.PruneToSize(firstTxn.TxSizeBytes)
	require.Nil(err)
	require.Equal(len(sortedTxns)-1, len(txns))
	require.Equal(firstTxn.TxSizeBytes, txnRegister.totalTxnsSizeBytes)
	totalSize = firstTxn.TxSizeBytes
	for ii := len(sortedTxns) - 1; ii >= 1; ii-- {
		require.Equal(true, bytes.Equal(sortedTxns[ii].Hash[:], txns[len(sortedTxns)-1-ii].Hash[:]))
	}
	sortedTxns = sortedTxns[:1]
	registerTxns = txnRegister.GetFeeTimeTransactions()
	require.Equal(len(sortedTxns), len(registerTxns))
	for ii := 0; ii < len(sortedTxns); ii++ {
		require.Equal(true, bytes.Equal(sortedTxns[ii].Hash[:], registerTxns[ii].Hash[:]))
	}

	// Remove the last transaction
	txns, err = txnRegister.PruneToSize(txnRegister.totalTxnsSizeBytes - 1)
	require.Nil(err)
	require.Len(txns, 1)
	require.Equal(uint64(0), txnRegister.totalTxnsSizeBytes)
	require.Equal(0, len(txnRegister.GetFeeTimeTransactions()))
	require.Equal(true, bytes.Equal(firstTxn.Hash[:], txns[0].Hash[:]))

	// Try pruning empty register
	txns, err = txnRegister.PruneToSize(txnRegister.totalTxnsSizeBytes - 1)
	require.Nil(err)
	require.Len(txns, 0)

	// Re-add all transactions
	totalSize = 0
	for _, tx := range txnPool {
		require.Nil(txnRegister.AddTransaction(tx))
		totalSize += tx.TxSizeBytes
	}
	require.Equal(totalSize, txnRegister.totalTxnsSizeBytes)

	// Remove all transactions
	txns, err = txnRegister.PruneToSize(0)
	require.Nil(err)
	require.Equal(len(txnPool), len(txns))
	require.Equal(uint64(0), txnRegister.totalTxnsSizeBytes)
	require.Equal(0, len(txnRegister.GetFeeTimeTransactions()))

	// Re-add all transactions again
	totalSize = 0
	for _, tx := range txnPool {
		require.Nil(txnRegister.AddTransaction(tx))
		totalSize += tx.TxSizeBytes
	}

	// Remove all transactions with higher min byte count
	txns, err = txnRegister.PruneToSize(math.MaxUint64)
	require.Nil(err)
	require.Len(txns, 0)
	require.Equal(len(txnPool), len(txnRegister.GetFeeTimeTransactions()))
}

func TestTransactionRegisterWithRemoves(t *testing.T) {
	seed := int64(88)
	testCases := 1000
	feeRange := uint64(10000)
	timestampRange := uint64(10000)

	require := require.New(t)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()
	txnPool := _testGetRandomMempoolTxns(rand, globalParams.MinimumNetworkFeeNanosPerKB, feeRange, 1000, timestampRange, testCases)

	txnRegister := NewTransactionRegister()
	txnRegister.Init(globalParams)
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
	txnPool := _testGetRandomMempoolTxns(rand, globalParams.MinimumNetworkFeeNanosPerKB, feeRange, 1000, timestampRange, testCases)

	txnRegister := NewTransactionRegister()
	txnRegister.Init(globalParams)
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
	txnPool := _testGetRandomMempoolTxns(rand, feeMin, feeMax, 1000, timestampRange, testCases)

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
	txnPool := _testGetRandomMempoolTxns(rand, feeMin, feeMax, 1000, timestampRange, testCases)

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
	globalParams.FeeBucketGrowthRateBasisPoints = 1000
	globalParams.MempoolFeeEstimatorNumMempoolBlocks = 1
	globalParams.MempoolFeeEstimatorNumPastBlocks = 1

	return &globalParams
}

func _testGetRandomMempoolTxns(rand *rand.Rand, feeMin uint64, feeMax uint64, sizeMax uint64, timestampRange uint64, numTxns int) []*MempoolTx {
	txnPool := []*MempoolTx{}
	for ii := 0; ii < numTxns; ii++ {
		randPriv, _ := btcec.NewPrivateKey()
		randMsg := RandomBytes(32)
		randSig := ecdsa2.Sign(randPriv, randMsg)
		fee := rand.Uint64()%(feeMax-feeMin) + feeMin

		txnPool = append(txnPool, &MempoolTx{
			Tx: &MsgDeSoTxn{
				TxnVersion: DeSoTxnVersion1,
				TxnMeta:    &BasicTransferMetadata{},
				Signature: DeSoSignature{
					Sign:          randSig,
					RecoveryId:    0,
					IsRecoverable: false,
				},
				TxnFeeNanos: fee,
				TxnNonce:    &DeSoNonce{},
			},
			FeePerKB:    fee,
			Added:       time.UnixMicro(int64(rand.Uint64() % timestampRange)),
			Hash:        NewBlockHash(RandomBytes(32)),
			TxSizeBytes: 1 + rand.Uint64()%sizeMax,
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

func TestHasGlobalParamChange(t *testing.T) {
	// Create the transaction register.
	globalParams := _testGetDefaultGlobalParams()
	tr := NewTransactionRegister()
	tr.Init(globalParams)

	// Test with no changes.
	unchangedGlobalParams := _testGetDefaultGlobalParams()
	require.False(t, tr.HasGlobalParamChange(unchangedGlobalParams))

	// Test with MinimumNetworkFeeNanosPerKB change.
	globalParamsWithNewFeeRate := _testGetDefaultGlobalParams()
	globalParamsWithNewFeeRate.MinimumNetworkFeeNanosPerKB = 2000
	require.True(t, tr.HasGlobalParamChange(globalParamsWithNewFeeRate))

	// Test with FeeBucketGrowthRateBasisPoints change.
	globalParamsWithNewGrowthRate := _testGetDefaultGlobalParams()
	globalParamsWithNewGrowthRate.FeeBucketGrowthRateBasisPoints = 2000
	require.True(t, tr.HasGlobalParamChange(globalParamsWithNewGrowthRate))
}

func TestCopyWithNewGlobalParams(t *testing.T) {
	// Create the transaction register.
	globalParams := _testGetDefaultGlobalParams()
	tr := NewTransactionRegister()
	tr.Init(globalParams)

	seed := int64(44)
	testCases := 1000
	exponentRange := 100
	timestampRange := uint64(10000)

	rand := rand.New(rand.NewSource(seed))
	randomExponent := uint32(rand.Intn(exponentRange))
	baseRate, bucketMultiplier := globalParams.ComputeFeeTimeBucketMinimumFeeAndMultiplier()
	feeMin, feeMax := computeFeeTimeBucketRangeFromExponent(randomExponent, baseRate, bucketMultiplier)

	// Create the txns
	txnPool := _testGetRandomMempoolTxns(rand, feeMin, feeMax, 1000, timestampRange, testCases)

	// Add the txns to the transaction register.
	for _, txn := range txnPool {
		err := tr.AddTransaction(txn)
		require.Nil(t, err)
	}

	// Copy the transaction register with new global params.
	newGlobalParams := _testGetDefaultGlobalParams()
	newGlobalParams.MinimumNetworkFeeNanosPerKB = 500

	newTr, err := tr.CopyWithNewGlobalParams(newGlobalParams)
	require.Nil(t, err)
	require.NotNil(t, newTr)

	originalTxns := tr.GetFeeTimeTransactions()
	rebucketedTxns := newTr.GetFeeTimeTransactions()

	// Make sure the number of txns is the same.
	require.Equal(t, len(originalTxns), len(rebucketedTxns))
}
