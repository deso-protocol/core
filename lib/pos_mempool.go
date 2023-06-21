package lib

import (
	"fmt"
	"github.com/emirpasic/gods/sets/treeset"
	"github.com/golang/glog"
	"math/big"
)

// ========================
//	TransactionRegister
// ========================

// TransactionRegister is the primary transaction store of the PoS Mempool. The register is responsible for determining
// the Fee-Time ordering of transactions. The operations supported by the register are: adding a transaction, removing
// a transaction, iterating through all transactions in fee-time order, and retrieving all transactions ordered in
// fee-time. The TransactionRegister doesn't perform any validation on the transactions, it just accepts the provided
// MempoolTx and adds it to the appropriate FeeBucket and TimeBucket.
type TransactionRegister struct {
	// buckets is the data structure storing the transactions in fee-time order.
	buckets *FeeBucket
	// txnMembership is a map of transaction hashes. It is used to determine existence of a transaction in the register.
	txnMembership map[BlockHash]struct{}
	// totalTxnSize is the total size of all transactions in the register.
	totalTxnSize uint64

	params       *DeSoParams
	globalParams *GlobalParamsEntry
}

func NewTransactionRegister(params *DeSoParams, globalParams *GlobalParamsEntry) *TransactionRegister {
	buckets := NewFeeBucket(globalParams)
	return &TransactionRegister{
		buckets:       buckets,
		txnMembership: map[BlockHash]struct{}{},
		totalTxnSize:  0,
		params:        params,
		globalParams:  globalParams,
	}
}

// AddTransaction adds a transaction to the register. If the transaction already exists in the register, or its size
// exceeds the maximum mempool capacity, it is not added.
func (tr *TransactionRegister) AddTransaction(txn *MempoolTx) bool {
	if txn.Hash == nil {
		return false
	}

	if _, ok := tr.txnMembership[*txn.Hash]; ok {
		return false
	}

	// If the transaction overflows the maximum mempool size, reject it.
	if tr.totalTxnSize+txn.TxSizeBytes > tr.params.MaxMempoolPosSizeBytes {
		return false
	}

	if err := tr.buckets.AddTransaction(txn); err != nil {
		glog.Errorf("TransactionRegister.AddTransaction: Problem adding txn: %v", err)
		return false
	}
	tr.totalTxnSize += txn.TxSizeBytes
	tr.txnMembership[*txn.Hash] = struct{}{}
	return true
}

// RemoveTransaction removes a transaction from the register.
func (tr *TransactionRegister) RemoveTransaction(txn *MempoolTx) bool {
	if _, ok := tr.txnMembership[*txn.Hash]; !ok {
		return false
	}

	tr.buckets.RemoveTransaction(txn)
	delete(tr.txnMembership, *txn.Hash)
	tr.totalTxnSize -= txn.TxSizeBytes
	return true
}

func (tr *TransactionRegister) Empty() bool {
	return tr.buckets.Empty()
}

// GetFeeTimeIterator returns an iterator over the transactions in the register. The iterator goes through all transactions
// as ordered by Fee-Time.
func (tr *TransactionRegister) GetFeeTimeIterator() *FeeTimeIterator {
	return tr.buckets.GetFeeTimeIterator()
}

// GetFeeTimeTransactions returns all transactions in the register ordered by Fee-Time.
func (tr *TransactionRegister) GetFeeTimeTransactions() []*MempoolTx {
	txns := []*MempoolTx{}
	it := tr.GetFeeTimeIterator()
	for it.Next() {
		if txn, ok := it.Value(); ok {
			txns = append(txns, txn)
		}
	}
	return txns
}

// ========================
//	FeeBucket
// ========================

// FeeBucket is a data structure storing time buckets. Time buckets, in turn, store timestamp-ordered mempool transactions
// that have neighbouring fees. When a transaction is added to the FeeBucket, an appropriate TimeBucket is found or created,
// depending on the transaction's fee, and the transactions is inserted into it.
type FeeBucket struct {
	// timeBucketSet is a set of TimeBuckets. The set is ordered by the TimeBucket's index, based on FeeBucketComparator.
	timeBucketSet *treeset.Set
	// timeBucketIndex is a map of TimeBucket indices to TimeBuckets. It is used to quickly find a TimeBucket given its index.
	timeBucketIndex map[int]*TimeBucket

	globalParams *GlobalParamsEntry
}

func NewFeeBucket(globalParams *GlobalParamsEntry) *FeeBucket {
	timeBucketSet := treeset.NewWith(FeeBucketComparator)

	return &FeeBucket{
		timeBucketSet:   timeBucketSet,
		timeBucketIndex: make(map[int]*TimeBucket),
		globalParams:    globalParams,
	}
}

// FeeBucketComparator is a comparator function for TimeBuckets. It is used to order TimeBuckets in
// the FeeBucket's timeBucketSet.
func FeeBucketComparator(a, b interface{}) int {
	aVal := a.(*TimeBucket)
	bVal := b.(*TimeBucket)

	// Determine the TimeBucket with a higher fee range. We can easily find out by comparing TimeBucket indices.
	if aVal.index < bVal.index {
		return 1
	} else if aVal.index > bVal.index {
		return -1
	} else {
		return 0
	}
}

// AddTransaction adds a transaction to the FeeBucket. The transaction is added to the appropriate TimeBucket, which is
// determined by the transaction's fee rate. If the TimeBucket doesn't exist, it is created.
func (fb *FeeBucket) AddTransaction(txn *MempoolTx) error {
	if txn.Hash == nil {
		return fmt.Errorf("FeeBucket.AddTransaction: Txn hash is nil")
	}

	// Determine the index of the bucket based on the transaction's fee rate.
	bucketIndex := ComputeTimeBucketIndexFromFeePerKBNanos(txn.FeePerKB, fb.globalParams)
	if bucket, exists := fb.timeBucketIndex[bucketIndex]; exists {
		// If the bucket already exists, add the transaction to it.
		if err := bucket.AddTransaction(txn); err != nil {
			return fmt.Errorf("FeeBucket.AddTransaction: Error adding transaction to bucket: %v", err)
		}
	} else {
		// If the bucket doesn't exist, create it and add the transaction to it.
		newBucket := NewTimeBucket(bucketIndex, fb.globalParams)
		if err := newBucket.AddTransaction(txn); err != nil {
			return fmt.Errorf("FeeBucket.AddTransaction: Error adding transaction to bucket: %v", err)
		}
		fb.timeBucketSet.Add(newBucket)
		fb.timeBucketIndex[bucketIndex] = newBucket
	}
	return nil
}

// RemoveTransaction removes a transaction from the FeeBucket. The transaction is removed from the appropriate TimeBucket,
// which is determined by the transaction's fee rate. If the TimeBucket becomes empty after the transaction is removed,
// it is removed from the FeeBucket.
func (fb *FeeBucket) RemoveTransaction(txn *MempoolTx) {
	// Determine the index of the bucket based on the transaction's fee rate.
	bucketIndex := ComputeTimeBucketIndexFromFeePerKBNanos(txn.FeePerKB, fb.globalParams)
	// Remove the transaction from the bucket.
	if bucket, exists := fb.timeBucketIndex[bucketIndex]; exists {
		bucket.RemoveTransaction(txn)
		// If the bucket becomes empty, remove it from the FeeBucket.
		if bucket.Empty() {
			fb.timeBucketSet.Remove(bucket)
			delete(fb.timeBucketIndex, bucketIndex)
		}
	}
}

func (fb *FeeBucket) Empty() bool {
	return fb.timeBucketSet.Empty()
}

// GetIterator returns an iterator over the TimeBuckets in the FeeBucket. The iterator goes through all TimeBuckets
// as ordered by FeeBucketComparator.
func (fb *FeeBucket) GetIterator() treeset.Iterator {
	return fb.timeBucketSet.Iterator()
}

func (fb *FeeBucket) GetFeeTimeIterator() *FeeTimeIterator {
	return &FeeTimeIterator{
		initialized:       false,
		feeBucketIterator: fb.timeBucketSet.Iterator(),
	}
}

// GetFeeTimeTransactions returns all transactions in the FeeBucket ordered by Fee-Time.
func (fb *FeeBucket) GetFeeTimeTransactions() []*MempoolTx {
	txns := []*MempoolTx{}
	it := fb.GetFeeTimeIterator()
	for it.Next() {
		if txn, ok := it.Value(); ok {
			txns = append(txns, txn)
		}
	}
	return txns
}

// FeeTimeIterator is an iterator over the transactions in a FeeBucket. The iterator goes through all transactions
// as ordered by Fee-Time.
type FeeTimeIterator struct {
	// feeBucketIterator is an iterator over the TimeBuckets in the FeeBucket.
	feeBucketIterator treeset.Iterator
	// timeBucketIterator is an iterator over the transactions in the current TimeBucket.
	timeBucketIterator treeset.Iterator
	// initialized is set to true when the iterator is pointing at a transactions.
	initialized bool
}

// Next moves the FeeTimeIterator to the next transaction. It returns true if the iterator is pointing at a transaction
// after the move, and false otherwise.
func (fti *FeeTimeIterator) Next() bool {
	timeBucketNext := false

	// If the iterator is not initialized, we will make it advance the feeBucketIterator and timeBucketIterator.
	if !fti.initialized {
		timeBucketNext = false
		fti.initialized = true
	} else {
		// If the iterator is initialized, we will first see if there are more transactions in the current TimeBucket.
		// We do this by advancing the timeBucketIterator and checking if it is pointing at a transaction.
		timeBucketNext = fti.timeBucketIterator.Next()
	}

	if !timeBucketNext {
		// If there are no more transactions in the current TimeBucket, we will advance the feeBucketIterator.
		if !fti.feeBucketIterator.Next() {
			// If there are no more TimeBuckets in the FeeBucket, we are done.
			return false
		}

		// If there are more TimeBuckets in the FeeBucket, we will advance the timeBucketIterator to the first transaction
		// in the new TimeBucket.
		if timeBucketVal, ok := fti.feeBucketIterator.Value().(*TimeBucket); ok {
			fti.timeBucketIterator = timeBucketVal.txnsSet.Iterator()
			// We will advance the timeBucketIterator to the first transaction in the new TimeBucket.
			if !fti.timeBucketIterator.Next() {
				// This shouldn't happen, but if it does, we've reached the end of the FeeBucket.
				return false
			}
		} else {
			return false
		}
	}
	return true
}

// Value returns the transaction that the iterator is pointing at.
func (fti *FeeTimeIterator) Value() (*MempoolTx, bool) {
	if !fti.initialized {
		return nil, false
	}

	if txn, ok := fti.timeBucketIterator.Value().(*MempoolTx); ok {
		return txn, true
	} else {
		return nil, false
	}
}

// ========================
//	TimeBucket
// ========================

// TimeBucket is a data structure storing MempoolTx with similar fee rates. It has an index, which determines the
// range of fee rates that are accepted by the TimeBucket.
type TimeBucket struct {
	// feeMin is the minimum fee rate (inclusive) accepted by the TimeBucket, in nanos per KB.
	feeMin uint64
	// feeMax is the maximum fee rate (inclusive) accepted by the TimeBucket, in nanos per KB.
	feeMax uint64
	// index is the fee range index of the TimeBucket.
	index int
	// txnsSet is a set of MempoolTx transactions stored in the TimeBucket.
	txnsSet *treeset.Set

	globalParams *GlobalParamsEntry
}

func NewTimeBucket(index int, globalParams *GlobalParamsEntry) *TimeBucket {
	txnsSet := treeset.NewWith(TimeBucketComparator)

	feeMin, feeMax := ComputeTimeBucketRangeFromIndex(index, globalParams)
	return &TimeBucket{
		feeMin:       feeMin,
		feeMax:       feeMax,
		index:        index,
		txnsSet:      txnsSet,
		globalParams: globalParams,
	}
}

// TimeBucketComparator is a comparator function for MempoolTx transactions stored inside a TimeBucket. The comparator
// orders the transactions by smallest timestamp. In case of a tie, transactions are ordered by greatest fee rate. Finally,
// in case of another tie, transactions are ordered by their hash.
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
			return HashToBigint(aVal.Hash).Cmp(HashToBigint(bVal.Hash))
		}
	}
}

// AddTransaction adds a transaction to the TimeBucket. It returns an error if the transaction is outside the
// TimeBucket's fee range, or if the transaction hash is nil.
func (tb *TimeBucket) AddTransaction(txn *MempoolTx) error {
	if txn.Hash == nil {
		return fmt.Errorf("transaction hash is nil")
	}

	if tb.feeMin > txn.FeePerKB || tb.feeMax < txn.FeePerKB {
		return fmt.Errorf("transaction fee %d outside of bucket range [%d, %d]", txn.FeePerKB, tb.feeMin, tb.feeMax)
	}

	tb.txnsSet.Add(txn)
	return nil
}

// RemoveTransaction removes a transaction from the TimeBucket.
func (tb *TimeBucket) RemoveTransaction(txn *MempoolTx) {
	tb.txnsSet.Remove(txn)
}

func (tb *TimeBucket) Empty() bool {
	return tb.txnsSet.Empty()
}

// GetIterator returns an iterator over the MempoolTx inside the TimeBucket.
func (tb *TimeBucket) GetIterator() treeset.Iterator {
	return tb.txnsSet.Iterator()
}

// GetTransactions returns a slice of MempoolTx inside the TimeBucket. The slice is ordered according to the
// TimeBucketComparator.
func (tb *TimeBucket) GetTransactions() []*MempoolTx {
	txns := []*MempoolTx{}
	it := tb.GetIterator()
	for it.Next() {
		if txn, ok := it.Value().(*MempoolTx); ok {
			txns = append(txns, txn)
		}
	}
	return txns
}

//============================================
//	Fee-Time Bucket Math
//============================================

// computeFeeBucketBaseAndMultiplierFromGlobalParams takes the fee base rate and multiplier for the GlobalParamsEntry,
// and returns them as big.Floats.
func computeFeeBucketBaseAndMultiplierFromGlobalParams(globalParams *GlobalParamsEntry) (
	_baseRate *big.Float, _bucketMultiplier *big.Float) {

	feeBucketBaseRate := NewFloat().SetUint64(globalParams.FeeBucketBaseRate)
	feeBucketMultiplier := NewFloat().SetUint64(10000 + globalParams.FeeBucketMultiplierBasisPoints)
	feeBucketMultiplier.Quo(feeBucketMultiplier, NewFloat().SetUint64(10000))
	return feeBucketBaseRate, feeBucketMultiplier
}

// computeTimeBucketMinFromIndex takes a fee range index and the GlobalParamsEntry, and returns the minimum fee rate
// of this fee range.
func computeTimeBucketMinFromIndex(index int, globalParams *GlobalParamsEntry) uint64 {
	feeBucketBaseRate, feeBucketMultiplier := computeFeeBucketBaseAndMultiplierFromGlobalParams(globalParams)

	// The first fee range has a fee rate of feeBucketBaseRate.
	if index == 0 {
		fee, _ := feeBucketBaseRate.Uint64()
		return fee
	}

	// Compute feeBucketBaseRate * feeBucketMultiplier^index.
	pow := NewFloat().SetInt(big.NewInt(int64(index)))
	multiplier := BigFloatPow(feeBucketMultiplier, pow)
	fee := NewFloat().Mul(feeBucketBaseRate, multiplier)

	feeUint64, _ := fee.Uint64()
	return feeUint64
}

// ComputeTimeBucketRangeFromIndex takes a fee range index and the GlobalParamsEntry, and returns the
// [feeMin, feeMax] of the fee range.
func ComputeTimeBucketRangeFromIndex(index int, globalParams *GlobalParamsEntry) (_min uint64, _max uint64) {
	feeMin := computeTimeBucketMinFromIndex(index, globalParams)
	feeMax := computeTimeBucketMinFromIndex(index+1, globalParams) - 1
	return feeMin, feeMax
}

// ComputeTimeBucketIndexFromFeePerKBNanos takes a fee rate and the GlobalParamsEntry, and returns the fee range index.
func ComputeTimeBucketIndexFromFeePerKBNanos(feePerKBNanos uint64, globalParams *GlobalParamsEntry) int {
	feeBucketBaseRate, feeBucketMultiplier := computeFeeBucketBaseAndMultiplierFromGlobalParams(globalParams)

	// Compute index = (log(feePerKBNanos) - log(feeBucketBaseRate)) / log(feeBucketMultiplier).
	feeFloat := NewFloat().SetUint64(feePerKBNanos)
	logFeeFloat := BigFloatLog(feeFloat)
	logBaseRate := BigFloatLog(feeBucketBaseRate)
	logMultiplier := BigFloatLog(feeBucketMultiplier)

	subFee := Sub(logFeeFloat, logBaseRate)
	// If the fee is less than the base rate, return 0.
	if subFee.Cmp(NewFloat().SetFloat64(0)) < 0 {
		return 0
	}

	divFee := Div(subFee, logMultiplier)
	timeBucketIndexUint64, _ := divFee.Uint64()
	timeBucketIndex := int(timeBucketIndexUint64)
	// Now verify that float precision hasn't caused us to be off by one.
	if computeTimeBucketMinFromIndex(timeBucketIndex, globalParams) > feePerKBNanos {
		// If this condition is true, then the computed index is overestimated by 1.
		return timeBucketIndex - 1
	} else if computeTimeBucketMinFromIndex(timeBucketIndex+1, globalParams) <= feePerKBNanos {
		// This condition gets triggered exactly on fee bucket boundaries, i.e. when feePerKBNanos = FeeMax for some bucket.
		// The float rounding makes the number slightly smaller like 5.9999999991 instead of 6.0.
		return timeBucketIndex + 1
	} else {
		return timeBucketIndex
	}
}
