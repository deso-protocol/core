package lib

import (
	"fmt"
	"github.com/emirpasic/gods/sets/treeset"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"math"
	"math/big"
)

// ========================
//	TransactionRegister
// ========================

// TransactionRegister is the primary transaction store of the PoS Mempool. The register is responsible for determining
// the Fee-Time ordering of transactions. The operations supported by the register are: adding a transaction, removing
// a transaction, iterating through all transactions in fee-time order, and retrieving all transactions ordered in
// fee-time. The TransactionRegister doesn't perform any validation on the transactions, it just accepts the provided
// MempoolTx and adds it to the appropriate FeeTimeBucket.
type TransactionRegister struct {
	// feeTimeBucketSet is a set of FeeTimeBucket objects. The set is ordered by the FeeTimeBucket's ranges, based on feeTimeBucketComparator.
	feeTimeBucketSet *treeset.Set
	// feeTimeBucketsByMinFeeMap is a map of FeeTimeBucket minimum fees to FeeTimeBucket objects. It is used to quickly find
	// a FeeTimeBucket given its min fee. Note that using a map here is preferable over e.g. a slice, since the index of a
	// FeeTimeBucket is not necessarily its position in the set.
	feeTimeBucketsByMinFeeMap map[uint64]*FeeTimeBucket
	// txnMembership is a set of transaction hashes. It is used to determine existence of a transaction in the register.
	txnMembership *Set[BlockHash]
	// totalTxnSize is the total size of all transactions in the register.
	totalTxnSize uint64

	params *DeSoParams

	// minimumNetworkFeeNanosPerKB is the base fee rate for the lowest fee FeeTimeBucket. This value corresponds to
	// GlobalParamsEntry's MinimumNetworkFeeNanosPerKB.
	minimumNetworkFeeNanosPerKB *big.Float
	// feeBucketRateMultiplierBasisPoints is the fee rate multiplier for FeeTimeBucket objects. This value corresponds to
	// GlobalParamsEntry's FeeBucketRateMultiplierBasisPoints.
	feeBucketRateMultiplierBasisPoints *big.Float
}

func NewTransactionRegister(params *DeSoParams, globalParams *GlobalParamsEntry) *TransactionRegister {
	feeTimeBucketSet := treeset.NewWith(feeTimeBucketComparator)
	minNetworkFee, bucketMultiplier := globalParams.ComputeFeeTimeBucketMinimumFeeAndMultiplier()

	return &TransactionRegister{
		feeTimeBucketSet:                   feeTimeBucketSet,
		feeTimeBucketsByMinFeeMap:          make(map[uint64]*FeeTimeBucket),
		txnMembership:                      NewSet([]BlockHash{}),
		totalTxnSize:                       0,
		params:                             params,
		minimumNetworkFeeNanosPerKB:        minNetworkFee,
		feeBucketRateMultiplierBasisPoints: bucketMultiplier,
	}
}

// feeTimeBucketComparator is a comparator function for FeeTimeBucket objects. It is used to order FeeTimeBucket objects
// in the TransactionRegister's feeTimeBucketSet based on fee ranges (higher fee ranges are ordered first).
func feeTimeBucketComparator(a, b interface{}) int {
	aVal, aOk := a.(*FeeTimeBucket)
	bVal, bOk := b.(*FeeTimeBucket)
	if !aOk || !bOk {
		glog.Error(CLog(Red, "feeTimeBucketComparator: Invalid types. This is BAD NEWS, we should never get here."))
		return 0
	}

	// Determine the FeeTimeBucket with a higher fee range. We can easily find out by comparing FeeTimeBucket minFeeNanosPerKB.
	if aVal.minFeeNanosPerKB < bVal.minFeeNanosPerKB {
		return 1
	} else if aVal.minFeeNanosPerKB > bVal.minFeeNanosPerKB {
		return -1
	}

	return 0
}

// AddTransaction adds a transaction to the register. If the transaction already exists in the register, or its size
// exceeds the maximum mempool capacity, it is not added. Returns nil when transaction was successfully added to the
// register, or an error otherwise.
func (tr *TransactionRegister) AddTransaction(txn *MempoolTx) error {
	if txn == nil || txn.Hash == nil {
		return fmt.Errorf("TransactionRegister.AddTransaction: Transaction or transaction hash is nil")
	}

	if tr.txnMembership.Includes(*txn.Hash) {
		return fmt.Errorf("TransactionRegister.AddTransaction: Transaction already exists in register")
	}

	// If the transaction overflows the maximum mempool size, reject it.
	if tr.totalTxnSize+txn.TxSizeBytes > tr.params.MaxMempoolPosSizeBytes || tr.totalTxnSize > math.MaxUint64-txn.TxSizeBytes {
		return fmt.Errorf("TransactionRegister.AddTransaction: Transaction size exceeds maximum mempool size")
	}

	// Determine the min fee of the bucket based on the transaction's fee rate.
	bucketMinFeeNanosPerKb, bucketMaxFeeNanosPerKB := ComputeFeeTimeBucketRangeFromFeeNanosPerKB(txn.FeePerKB,
		tr.minimumNetworkFeeNanosPerKB, tr.feeBucketRateMultiplierBasisPoints)
	if bucket, exists := tr.feeTimeBucketsByMinFeeMap[bucketMinFeeNanosPerKb]; exists {
		// If the bucket already exists, add the transaction to it.
		if err := bucket.AddTransaction(txn); err != nil {
			return errors.Wrapf(err, "TransactionRegister.AddTransaction: Error adding transaction to bucket: ")
		}
	} else {
		// If the bucket doesn't exist, create it and add the transaction to it.
		newBucket := NewFeeTimeBucket(bucketMinFeeNanosPerKb, bucketMaxFeeNanosPerKB)
		if err := newBucket.AddTransaction(txn); err != nil {
			return errors.Wrapf(err, "TransactionRegister.AddTransaction: Error adding transaction to bucket: %v", err)
		}
		tr.feeTimeBucketSet.Add(newBucket)
		tr.feeTimeBucketsByMinFeeMap[bucketMinFeeNanosPerKb] = newBucket
	}

	tr.totalTxnSize += txn.TxSizeBytes
	tr.txnMembership.Add(*txn.Hash)
	return nil
}

// RemoveTransaction removes a transaction from the register. If the transaction does not exist in the register, or its
// size exceeds the current register size (which should never happen), it is not removed. Returns nil when transaction
// was successfully removed from the register, or an error otherwise.
func (tr *TransactionRegister) RemoveTransaction(txn *MempoolTx) error {
	if txn == nil || txn.Hash == nil {
		return fmt.Errorf("TransactionRegister.RemoveTransaction: Transaction or transaction hash is nil")
	}

	if !tr.txnMembership.Includes(*txn.Hash) {
		return fmt.Errorf("TransactionRegister.RemoveTransaction: Transaction does not exist in register")
	}

	if tr.totalTxnSize < txn.TxSizeBytes {
		return fmt.Errorf("TransactionRegister.RemoveTransaction: Transaction size exceeds total mempool size")
	}

	// Determine the index of the bucket based on the transaction's fee rate.
	bucketMinFeeNanosPerKb, _ := ComputeFeeTimeBucketRangeFromFeeNanosPerKB(txn.FeePerKB,
		tr.minimumNetworkFeeNanosPerKB, tr.feeBucketRateMultiplierBasisPoints)
	// Remove the transaction from the bucket.
	if bucket, exists := tr.feeTimeBucketsByMinFeeMap[bucketMinFeeNanosPerKb]; exists {
		bucket.RemoveTransaction(txn)
		// If the bucket becomes empty, remove it from the TransactionRegister.
		if bucket.Empty() {
			tr.feeTimeBucketSet.Remove(bucket)
			delete(tr.feeTimeBucketsByMinFeeMap, bucketMinFeeNanosPerKb)
		}
	}

	tr.txnMembership.Remove(*txn.Hash)
	tr.totalTxnSize -= txn.TxSizeBytes
	return nil
}

func (tr *TransactionRegister) Empty() bool {
	return tr.feeTimeBucketSet.Empty()
}

// GetFeeTimeIterator returns an iterator over the transactions in the register. The iterator goes through all transactions
// as ordered by Fee-Time.
func (tr *TransactionRegister) GetFeeTimeIterator() *FeeTimeIterator {
	return &FeeTimeIterator{
		initialized:    false,
		bucketIterator: tr.feeTimeBucketSet.Iterator(),
	}
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

// FeeTimeIterator is an iterator over the transactions in a TransactionRegister. The iterator goes through all transactions
// as ordered by Fee-Time.
type FeeTimeIterator struct {
	// bucketIterator is an iterator over the FeeTimeBucket objects in the TransactionRegister.
	bucketIterator treeset.Iterator
	// mempoolTxIterator is an iterator over the transactions in the current FeeTimeBucket.
	mempoolTxIterator treeset.Iterator
	// initialized is set to true when the iterator is pointing at a transactions.
	initialized bool
}

// Next moves the FeeTimeIterator to the next transaction. It returns true if the iterator is pointing at a transaction
// after the move, and false otherwise.
func (fti *FeeTimeIterator) Next() bool {
	hasNextMempoolTxn := false

	// If the iterator is not initialized, we will make it advance the bucketIterator and the mempoolTxIterator.
	if !fti.initialized {
		hasNextMempoolTxn = false
		fti.initialized = true
	} else {
		// If the iterator is initialized, we will first see if there are more transactions in the current FeeTimeBucket.
		// We do this by advancing the mempoolTxIterator and checking if it is pointing at a transaction.
		hasNextMempoolTxn = fti.mempoolTxIterator.Next()
	}

	// If we've successfully advanced mempoolTxIterator for the current FeeTimeBucket, we are done.
	if hasNextMempoolTxn {
		return true
	}

	// If there are no more transactions in the current FeeTimeBucket, we will advance the bucketIterator.
	if !fti.bucketIterator.Next() {
		// If there are no more FeeTimeBucket objects in the TransactionRegister, we are done.
		return false
	}

	// If there are more FeeTimeBucket objects in the TransactionRegister, we will advance the mempoolTxIterator
	// to the first transaction in the next FeeTimeBucket. First, we fetch the newly pointed-at FeeTimeBucket.
	nextFeeTimeBucket, ok := fti.bucketIterator.Value().(*FeeTimeBucket)
	if !ok {
		return false
	}

	// We will set the mempoolTxIterator to point at the first transaction in the new FeeTimeBucket.
	fti.mempoolTxIterator = nextFeeTimeBucket.txnsSet.Iterator()
	if !fti.mempoolTxIterator.Next() {
		// This shouldn't happen, but if it does, we've reached the end of the TransactionRegister.
		return false
	}

	return true
}

// Value returns the transaction that the iterator is pointing at.
func (fti *FeeTimeIterator) Value() (*MempoolTx, bool) {
	if !fti.initialized {
		return nil, false
	}

	if txn, ok := fti.mempoolTxIterator.Value().(*MempoolTx); ok {
		return txn, true
	}
	return nil, false
}

// ========================
//	FeeTimeBucket
// ========================

// FeeTimeBucket is a data structure storing MempoolTx with similar fee rates. It has an index, which determines the
// range of fee rates that are accepted by the FeeTimeBucket.
type FeeTimeBucket struct {
	// txnsSet is a set of MempoolTx transactions stored in the FeeTimeBucket.
	txnsSet *treeset.Set
	// minFeeNanosPerKB is the minimum fee rate (inclusive) accepted by the FeeTimeBucket, in nanos per KB.
	minFeeNanosPerKB uint64
	// maxFeeNanosPerKB is the maximum fee rate (inclusive) accepted by the FeeTimeBucket, in nanos per KB. It's worth
	// noting that the maximum fee rate is always 1 below the minimum fee rate of the FeeTimeBucket with index+1.
	maxFeeNanosPerKB uint64
}

func NewFeeTimeBucket(minFeeNanosPerKB uint64, maxFeeNanosPerKB uint64) *FeeTimeBucket {

	txnsSet := treeset.NewWith(mempoolTxTimeOrderComparator)
	return &FeeTimeBucket{
		minFeeNanosPerKB: minFeeNanosPerKB,
		maxFeeNanosPerKB: maxFeeNanosPerKB,
		txnsSet:          txnsSet,
	}
}

// mempoolTxTimeOrderComparator is a comparator function for MempoolTx transactions stored inside a FeeTimeBucket. The comparator
// orders the transactions by smallest timestamp. In case of a tie, transactions are ordered by greatest fee rate. Finally,
// in case of another tie, transactions are ordered by their hash.
func mempoolTxTimeOrderComparator(a, b interface{}) int {
	aVal, aOk := a.(*MempoolTx)
	bVal, bOk := b.(*MempoolTx)
	if !aOk || !bOk {
		glog.Error(CLog(Red, "mempoolTxTimeOrderComparator: Invalid types. This is BAD NEWS, we should never get here."))
		return 0
	}

	if aVal.Added.UnixMicro() > bVal.Added.UnixMicro() {
		return 1
	} else if aVal.Added.UnixMicro() < bVal.Added.UnixMicro() {
		return -1
	} else if aVal.FeePerKB < bVal.FeePerKB {
		return 1
	} else if aVal.FeePerKB > bVal.FeePerKB {
		return -1
	}
	// If the timestamps and fee rates are the same, we order by the transaction hash.
	return HashToBigint(aVal.Hash).Cmp(HashToBigint(bVal.Hash))
}

// AddTransaction adds a transaction to the FeeTimeBucket. It returns an error if the transaction is outside the
// FeeTimeBucket's fee range, or if the transaction hash is nil.
func (tb *FeeTimeBucket) AddTransaction(txn *MempoolTx) error {
	if txn == nil || txn.Hash == nil {
		return fmt.Errorf("FeeTimeBucket.AddTransaction: Transaction or transaction hash is nil")
	}

	if tb.minFeeNanosPerKB > txn.FeePerKB || tb.maxFeeNanosPerKB < txn.FeePerKB {
		return fmt.Errorf("FeeTimeBucket.AddTransaction: Transaction fee %d outside of bucket range [%d, %d]",
			txn.FeePerKB, tb.minFeeNanosPerKB, tb.maxFeeNanosPerKB)
	}

	tb.txnsSet.Add(txn)
	return nil
}

// RemoveTransaction removes a transaction from the FeeTimeBucket.
func (tb *FeeTimeBucket) RemoveTransaction(txn *MempoolTx) {
	tb.txnsSet.Remove(txn)
}

func (tb *FeeTimeBucket) Empty() bool {
	return tb.txnsSet.Empty()
}

// GetIterator returns an iterator over the MempoolTx inside the FeeTimeBucket.
func (tb *FeeTimeBucket) GetIterator() treeset.Iterator {
	return tb.txnsSet.Iterator()
}

// GetTransactions returns a slice of MempoolTx inside the FeeTimeBucket. The slice is ordered according to the
// mempoolTxTimeOrderComparator.
func (tb *FeeTimeBucket) GetTransactions() []*MempoolTx {
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

// ComputeFeeTimeBucketRangeFromFeeNanosPerKB takes a fee rate, minimumNetworkFeeNanosPerKB, and feeBucketMultiplier,
// and returns the [minFeeNanosPerKB, maxFeeNanosPerKB] of the fee range.
func ComputeFeeTimeBucketRangeFromFeeNanosPerKB(feeNanosPerKB uint64, minimumNetworkFeeNanosPerKB *big.Float,
	feeBucketMultiplier *big.Float) (uint64, uint64) {

	bucketIndex := ComputeFeeTimeBucketIndexFromFeeNanosPerKB(feeNanosPerKB, minimumNetworkFeeNanosPerKB, feeBucketMultiplier)
	return ComputeFeeTimeBucketRangeFromIndex(bucketIndex, minimumNetworkFeeNanosPerKB, feeBucketMultiplier)
}

// ComputeFeeTimeBucketRangeFromIndex takes a fee range index, minimumNetworkFeeNanosPerKB, and feeBucketMultiplier, and returns the
// [minFeeNanosPerKB, maxFeeNanosPerKB] of the fee range.
func ComputeFeeTimeBucketRangeFromIndex(index uint32, minimumNetworkFeeNanosPerKB *big.Float, feeBucketMultiplier *big.Float) (
	_minFeeNanosPerKB uint64, _maxFeeNanosPerKB uint64) {

	minFeeNanosPerKB := ComputeFeeTimeBucketMinFromIndex(index, minimumNetworkFeeNanosPerKB, feeBucketMultiplier)
	maxFeeNanosPerKB := ComputeFeeTimeBucketMinFromIndex(index+1, minimumNetworkFeeNanosPerKB, feeBucketMultiplier) - 1
	return minFeeNanosPerKB, maxFeeNanosPerKB
}

// ComputeFeeTimeBucketMinFromIndex takes a fee range index, minimumNetworkFeeNanosPerKB, and feeBucketMultiplier, and uses them to
// return the minimum fee rate of this fee range.
func ComputeFeeTimeBucketMinFromIndex(index uint32, minimumNetworkFeeNanosPerKB *big.Float, feeBucketMultiplier *big.Float) uint64 {
	// The first fee range has a fee rate of minimumNetworkFeeNanosPerKB.
	if index == 0 {
		fee, _ := minimumNetworkFeeNanosPerKB.Uint64()
		return fee
	}

	// Compute minimumNetworkFeeNanosPerKB * feeBucketMultiplier^index.
	pow := NewFloat().SetUint64(uint64(index))
	multiplier := BigFloatPow(feeBucketMultiplier, pow)
	fee := NewFloat().Mul(minimumNetworkFeeNanosPerKB, multiplier)

	feeUint64, _ := fee.Uint64()
	return feeUint64
}

// ComputeFeeTimeBucketIndexFromFeeNanosPerKB takes a fee rate, minimumNetworkFeeNanosPerKB, and feeBucketMultiplier, and
// returns the fee range index.
func ComputeFeeTimeBucketIndexFromFeeNanosPerKB(feeNanosPerKB uint64, minimumNetworkFeeNanosPerKB *big.Float,
	feeBucketMultiplier *big.Float) uint32 {

	// Compute the fee time bucket index for the fee rate. We can compute the index as follows:
	// feeNanosPerKB = minimumNetworkFeeNanosPerKB * feeBucketMultiplier ^ index
	// log(feeNanosPerKB) = log(minimumNetworkFeeNanosPerKB) + index * log(feeBucketMultiplier^index)
	// index = (log(feeNanosPerKB) - log(minimumNetworkFeeNanosPerKB)) / log(feeBucketMultiplier).

	feeFloat := NewFloat().SetUint64(feeNanosPerKB)
	// If the fee is less than the base rate, return 0.
	if feeFloat.Cmp(minimumNetworkFeeNanosPerKB) < 0 {
		return 0
	}

	logFeeFloat := BigFloatLog(feeFloat)
	logBaseRate := BigFloatLog(minimumNetworkFeeNanosPerKB)
	logMultiplier := BigFloatLog(feeBucketMultiplier)
	subFee := Sub(logFeeFloat, logBaseRate)
	divFee := Div(subFee, logMultiplier)
	feeTimeBucketIndexUint64, _ := divFee.Uint64()
	feeTimeBucketIndex := uint32(feeTimeBucketIndexUint64)
	if feeTimeBucketIndex < 0 {
		return 0
	}

	// Now verify that float precision hasn't caused us to be off by one.
	// If this condition is true, then the computed index is overestimated by 1.
	if ComputeFeeTimeBucketMinFromIndex(feeTimeBucketIndex, minimumNetworkFeeNanosPerKB, feeBucketMultiplier) > feeNanosPerKB {
		return feeTimeBucketIndex - 1
	}

	// This condition gets triggered exactly on fee bucket boundaries, i.e. when feeNanosPerKB = FeeMax for some bucket.
	// The float rounding makes the number slightly smaller like 5.9999999991 instead of 6.0.
	if ComputeFeeTimeBucketMinFromIndex(feeTimeBucketIndex+1, minimumNetworkFeeNanosPerKB, feeBucketMultiplier) <= feeNanosPerKB {
		return feeTimeBucketIndex + 1
	}

	// If we get here, then the computed index is correct.
	return feeTimeBucketIndex
}
