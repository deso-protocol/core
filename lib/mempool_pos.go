package lib

import (
	"github.com/emirpasic/gods/sets/treeset"
	"math/big"
)

type DeSoMempoolPos struct {
	quit chan struct{}

	txnRegister *TransactionRegister
}

// ========================
//	TransactionRegister
// ========================

type TransactionRegister struct {
	buckets *FeeBucket
}

func NewTransactionRegister(params *GlobalParamsEntry) *TransactionRegister {
	buckets := NewFeeBucket([]*TimeBucket{}, params)
	return &TransactionRegister{
		buckets: buckets,
	}
}

func (tr *TransactionRegister) AddTransaction(txn *MempoolTx) {
	tr.buckets.AddTransaction(txn)
}

func (tr *TransactionRegister) GetIterator() *TransactionRegisterIterator {
	return &TransactionRegisterIterator{
		initialized:       false,
		feeBucketIterator: tr.buckets.bucketSet.Iterator(),
	}
}

func (tr *TransactionRegister) GetFeeTimeTransactions() []*MempoolTx {
	txns := []*MempoolTx{}
	it := tr.GetIterator()
	for it.Next() {
		if txn, ok := it.Value(); ok {
			txns = append(txns, txn)
		}
	}
	return txns
}

type TransactionRegisterIterator struct {
	feeBucketIterator  treeset.Iterator
	timeBucketIterator treeset.Iterator
	initialized        bool
}

func (tri *TransactionRegisterIterator) Next() bool {
	timeBucketNext := false

	if !tri.initialized {
		timeBucketNext = false
		tri.initialized = true
	} else {
		timeBucketNext = tri.timeBucketIterator.Next()
	}

	if !timeBucketNext {
		if !tri.feeBucketIterator.Next() {
			return false
		}

		if timeBucketVal, ok := tri.feeBucketIterator.Value().(*TimeBucket); ok {
			tri.timeBucketIterator = timeBucketVal.txnsSet.Iterator()
			if !tri.timeBucketIterator.Next() {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

func (tri *TransactionRegisterIterator) Value() (*MempoolTx, bool) {
	if !tri.initialized {
		return nil, false
	}

	if txn, ok := tri.timeBucketIterator.Value().(*MempoolTx); ok {
		return txn, true
	} else {
		return nil, false
	}
}

// ========================
//	FeeBucket
// ========================

type FeeBucket struct {
	bucketSet    *treeset.Set
	bucketNthMap map[int]*TimeBucket
	params       *GlobalParamsEntry
}

func NewFeeBucket(timeBuckets []*TimeBucket, params *GlobalParamsEntry) *FeeBucket {
	timeBucketSet := treeset.NewWith(FeeBucketComparator)
	for _, tb := range timeBuckets {
		timeBucketSet.Add(tb)
	}

	return &FeeBucket{
		bucketSet:    timeBucketSet,
		bucketNthMap: make(map[int]*TimeBucket),
		params:       params,
	}
}

func FeeBucketComparator(a, b interface{}) int {
	aVal := a.(*TimeBucket)
	bVal := b.(*TimeBucket)

	if aVal.fee < bVal.fee {
		return 1
	} else if aVal.fee > bVal.fee {
		return -1
	} else {
		return 0
	}
}

func (fb *FeeBucket) AddTransaction(txn *MempoolTx) {
	nthBucket := MapFeeToNthBucket(txn.FeePerKB, fb.params)
	if bucket, exists := fb.bucketNthMap[nthBucket]; exists {
		bucket.txnsSet.Add(txn)
	} else {
		newBucket := NewTimeBucketHeap(txn.FeePerKB, []*MempoolTx{txn})
		fb.bucketSet.Add(newBucket)
		fb.bucketNthMap[nthBucket] = newBucket
	}
}

func (fb *FeeBucket) GetIterator() treeset.Iterator {
	return fb.bucketSet.Iterator()
}

// ========================
//	TimeBucket
// ========================

type TimeBucket struct {
	fee     uint64
	txnsSet *treeset.Set
}

func NewTimeBucketHeap(fee uint64, txns []*MempoolTx) *TimeBucket {
	txnsSet := treeset.NewWith(TimeBucketComparator)
	for _, txn := range txns {
		txnsSet.Add(txn)
	}

	return &TimeBucket{
		fee:     fee,
		txnsSet: txnsSet,
	}
}

func TimeBucketComparator(a, b interface{}) int {
	aVal := a.(*MempoolTx)
	bVal := b.(*MempoolTx)

	if aVal.Added.UnixNano() > bVal.Added.UnixNano() {
		return 1
	} else if aVal.Added.UnixNano() < bVal.Added.UnixNano() {
		return -1
	} else {
		if aVal.FeePerKB < bVal.FeePerKB {
			return 1
		} else if aVal.FeePerKB > bVal.FeePerKB {
			return -1
		} else {
			if aVal.Hash.String() < bVal.Hash.String() {
				return 1
			} else if aVal.Hash.String() > bVal.Hash.String() {
				return -1
			} else {
				return 0
			}
		}
	}
}

func (tb *TimeBucket) GetIterator() treeset.Iterator {
	return tb.txnsSet.Iterator()
}

//============================================
//	Fee-Time Bucket Math
//============================================

func ComputeNthFeeBucket(n int, params *GlobalParamsEntry) uint64 {
	// TODO: replace with params from GlobalParamsEntry
	feeBucketBaseRate := NewFloat().SetFloat64(1000)
	feeBucketMultiplier := NewFloat().SetFloat64(1.1)

	if n == 0 {
		fee, _ := feeBucketBaseRate.Uint64()
		return fee
	}

	pow := NewFloat().SetInt(big.NewInt(int64(n)))
	multiplier := BigFloatPow(feeBucketMultiplier, pow)
	fee := NewFloat().Mul(feeBucketBaseRate, multiplier)

	feeUint64, _ := fee.Uint64()
	return feeUint64
}

func MapFeeToNthBucket(fee uint64, params *GlobalParamsEntry) int {
	// TODO: replace with params from GlobalParamsEntry
	feeBucketBaseRate := NewFloat().SetFloat64(1000)
	feeBucketMultiplier := NewFloat().SetFloat64(1.1)

	feeFloat := NewFloat().SetUint64(fee)
	logFeeFloat := BigFloatLog(feeFloat)
	logBaseRate := BigFloatLog(feeBucketBaseRate)
	logMultiplier := BigFloatLog(feeBucketMultiplier)

	subFee := Sub(logFeeFloat, logBaseRate)
	if subFee.Cmp(NewFloat().SetFloat64(0)) < 0 {
		return 0
	}

	divFee := Div(subFee, logMultiplier)
	feeBucket, _ := divFee.Uint64()
	feeBucketInt := int(feeBucket)
	if ComputeNthFeeBucket(feeBucketInt, params) > fee {
		return feeBucketInt - 1
	} else if ComputeNthFeeBucket(feeBucketInt+1, params) <= fee {
		// This condition actually gets triggered while the above doesn't. It happens exactly on fee bucket boundaries
		// and the float rounding makes the number slightly smaller like .9999999991 instead of 1.0.
		return feeBucketInt + 1
	} else {
		return feeBucketInt
	}
}
