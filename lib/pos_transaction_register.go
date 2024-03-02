package lib

import (
	"bytes"
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/emirpasic/gods/sets/treeset"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

// ========================
//	TransactionRegister
// ========================

// TransactionRegister is the primary transaction store of the PoS Mempool. The register is responsible for determining
// the Fee-Time ordering of transactions. The operations supported by the register are: adding a transaction, removing
// a transaction, iterating through all transactions in fee-time order, and retrieving all transactions ordered in
// fee-time. The TransactionRegister doesn't perform any validation on the transactions, it just accepts the provided
// MempoolTx and adds it to the appropriate FeeTimeBucket. The structure is thread safe.
type TransactionRegister struct {
	sync.RWMutex
	// feeTimeBucketSet is a set of FeeTimeBucket objects. The set is ordered by the FeeTimeBucket's ranges, based on feeTimeBucketComparator.
	feeTimeBucketSet *treeset.Set
	// feeTimeBucketsByMinFeeMap is a map of FeeTimeBucket minimum fees to FeeTimeBucket objects. It is used to quickly find
	// a FeeTimeBucket given its min fee.
	feeTimeBucketsByMinFeeMap map[uint64]*FeeTimeBucket
	// txnMembership is a set of transaction hashes. It is used to determine existence of a transaction in the register.
	txnMembership map[BlockHash]*MempoolTx
	// totalTxnsSizeBytes is the total size of all transactions in the register.
	totalTxnsSizeBytes uint64
	// minimumNetworkFeeNanosPerKB is the base fee rate for the lowest fee FeeTimeBucket. This value corresponds to
	// GlobalParamsEntry's MinimumNetworkFeeNanosPerKB.
	minimumNetworkFeeNanosPerKB *big.Float
	// feeBucketGrowthRateBasisPoints is the fee rate multiplier for FeeTimeBucket objects. This value corresponds to
	// GlobalParamsEntry's FeeBucketGrowthRateBasisPoints.
	feeBucketGrowthRateBasisPoints *big.Float
}

func NewTransactionRegister() *TransactionRegister {
	feeTimeBucketSet := treeset.NewWith(feeTimeBucketComparator)
	minimumNetworkFeeNanosPerKB, feeBucketMultiplier := _getFallbackSafeMinimumFeeAndMultiplier()
	return &TransactionRegister{
		feeTimeBucketSet:          feeTimeBucketSet,
		feeTimeBucketsByMinFeeMap: make(map[uint64]*FeeTimeBucket),
		txnMembership:             make(map[BlockHash]*MempoolTx),
		totalTxnsSizeBytes:        0,
		// Set default values for the uninitialized fields. This is safe because any transactions
		// added to the register will be re-bucketed once the params are updated.
		minimumNetworkFeeNanosPerKB:    minimumNetworkFeeNanosPerKB, // Default to 100 nanos per KB
		feeBucketGrowthRateBasisPoints: feeBucketMultiplier,         // Default to 10%
	}
}

func (tr *TransactionRegister) Init(globalParams *GlobalParamsEntry) {
	minNetworkFee, bucketMultiplier := globalParams.ComputeFeeTimeBucketMinimumFeeAndMultiplier()
	if !_isValidMinimumFeeAndMultiplier(minNetworkFee, bucketMultiplier) {
		minNetworkFee, bucketMultiplier = _getFallbackSafeMinimumFeeAndMultiplier()
	}
	tr.minimumNetworkFeeNanosPerKB = minNetworkFee
	tr.feeBucketGrowthRateBasisPoints = bucketMultiplier
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
	tr.Lock()
	defer tr.Unlock()

	return tr.addTransactionNoLock(txn)
}

func (tr *TransactionRegister) addTransactionNoLock(txn *MempoolTx) error {
	if txn == nil || txn.Hash == nil {
		return fmt.Errorf("TransactionRegister.AddTransaction: Transaction or transaction hash is nil")
	}

	if _, ok := tr.txnMembership[*txn.Hash]; ok {
		return nil
	}

	// If the transaction is too large, reject it.
	if tr.totalTxnsSizeBytes > math.MaxUint64-txn.TxSizeBytes {
		return fmt.Errorf("TransactionRegister.AddTransaction: Transaction size overflows uint64. Txn size %v, "+
			"total size %v", txn.TxSizeBytes, tr.totalTxnsSizeBytes)
	}

	// Determine the min fee of the bucket based on the transaction's fee rate.
	bucketMinFeeNanosPerKb, bucketMaxFeeNanosPerKB := computeFeeTimeBucketRangeFromFeeNanosPerKB(txn.FeePerKB,
		tr.minimumNetworkFeeNanosPerKB, tr.feeBucketGrowthRateBasisPoints)
	// Lookup the bucket in the map.
	bucket, bucketExists := tr.feeTimeBucketsByMinFeeMap[bucketMinFeeNanosPerKb]
	if !bucketExists {
		// If the bucket doesn't exist, create it and add the transaction to it.
		bucket = NewFeeTimeBucket(bucketMinFeeNanosPerKb, bucketMaxFeeNanosPerKB)
	}

	// Add the transaction to the bucket.
	if err := bucket.AddTransaction(txn); err != nil {
		return errors.Wrapf(err, "TransactionRegister.AddTransaction: Error adding transaction to bucket: ")
	}

	if !bucketExists {
		// If the bucket didn't exist, add it to the set and the map.
		tr.addBucketNoLock(bucket)
	}

	tr.totalTxnsSizeBytes += txn.TxSizeBytes
	tr.txnMembership[*txn.Hash] = txn
	return nil
}

// RemoveTransaction removes a transaction from the register. If the transaction does not exist in the register, or its
// size exceeds the current register size (which should never happen), it is not removed. Returns nil when transaction
// was successfully removed from the register, or an error otherwise.
func (tr *TransactionRegister) RemoveTransaction(txn *MempoolTx) error {
	tr.Lock()
	defer tr.Unlock()

	return tr.removeTransactionNoLock(txn)
}

func (tr *TransactionRegister) removeTransactionNoLock(txn *MempoolTx) error {
	if txn == nil || txn.Hash == nil {
		return fmt.Errorf("TransactionRegister.RemoveTransaction: Transaction or transaction hash is nil")
	}

	if _, ok := tr.txnMembership[*txn.Hash]; !ok {
		return nil
	}

	// Sanity-check that the size of the transaction doesn't exceed the current size of the TransactionRegister.
	// This should never happen, unless somehow the underlying transaction was modified. Which won't happen.
	if tr.totalTxnsSizeBytes < txn.TxSizeBytes {
		return fmt.Errorf("TransactionRegister.RemoveTransaction: Transaction with transaction hash %v size %v "+
			"exceeds total mempool size %v", txn.Hash.String(), txn.TxSizeBytes, tr.totalTxnsSizeBytes)
	}

	// Determine the min fee of the bucket based on the transaction's fee rate.
	bucketMinFeeNanosPerKb, _ := computeFeeTimeBucketRangeFromFeeNanosPerKB(txn.FeePerKB,
		tr.minimumNetworkFeeNanosPerKB, tr.feeBucketGrowthRateBasisPoints)
	// Remove the transaction from the bucket.
	if bucket, exists := tr.feeTimeBucketsByMinFeeMap[bucketMinFeeNanosPerKb]; exists {
		if bucket.minFeeNanosPerKB != bucketMinFeeNanosPerKb {
			return fmt.Errorf("TransactionRegister.RemoveTransaction: Bucket min fee %v does not match "+
				"bucketMinFeeNanosPerKb %v", bucket.minFeeNanosPerKB, bucketMinFeeNanosPerKb)
		}

		bucket.RemoveTransaction(txn)
		// If the bucket becomes empty, remove it from the TransactionRegister.
		if bucket.Empty() {
			tr.removeBucketNoLock(bucket)
		}
	} else if !exists {
		return fmt.Errorf("TransactionRegister.RemoveTransaction: Bucket with min fee %v does not exist",
			bucketMinFeeNanosPerKb)
	}

	delete(tr.txnMembership, *txn.Hash)
	tr.totalTxnsSizeBytes -= txn.TxSizeBytes
	return nil
}

func (tr *TransactionRegister) addBucketNoLock(bucket *FeeTimeBucket) {
	if bucket == nil {
		return
	}

	tr.feeTimeBucketSet.Add(bucket)
	tr.feeTimeBucketsByMinFeeMap[bucket.minFeeNanosPerKB] = bucket
}

func (tr *TransactionRegister) removeBucketNoLock(bucket *FeeTimeBucket) {
	if bucket == nil {
		return
	}

	tr.feeTimeBucketSet.Remove(bucket)
	bucket.Clear()
	delete(tr.feeTimeBucketsByMinFeeMap, bucket.minFeeNanosPerKB)
}

func (tr *TransactionRegister) Empty() bool {
	tr.RLock()
	defer tr.RUnlock()

	return tr.feeTimeBucketSet.Empty()
}

func (tr *TransactionRegister) Size() uint64 {
	tr.RLock()
	defer tr.RUnlock()

	return tr.totalTxnsSizeBytes
}

func (tr *TransactionRegister) Count() uint64 {
	tr.RLock()
	defer tr.RUnlock()

	return uint64(len(tr.txnMembership))
}

func (tr *TransactionRegister) Includes(txn *MempoolTx) bool {
	tr.RLock()
	defer tr.RUnlock()

	if txn == nil || txn.Hash == nil {
		return false
	}

	_, ok := tr.txnMembership[*txn.Hash]
	return ok
}

func (tr *TransactionRegister) Reset() {
	tr.Lock()
	defer tr.Unlock()

	tr.feeTimeBucketSet.Clear()
	tr.feeTimeBucketsByMinFeeMap = make(map[uint64]*FeeTimeBucket)
	tr.txnMembership = make(map[BlockHash]*MempoolTx)
	tr.totalTxnsSizeBytes = 0
}

// GetFeeTimeIterator returns an iterator over the transactions in the register. The iterator goes through all transactions
// as ordered by Fee-Time.
func (tr *TransactionRegister) GetFeeTimeIterator() *FeeTimeIterator {
	tr.RLock()
	defer tr.RUnlock()

	return &FeeTimeIterator{
		bucketIterator:    tr.feeTimeBucketSet.Iterator(),
		mempoolTxIterator: nil,
	}
}

// GetFeeTimeTransactions returns all transactions in the register ordered by Fee-Time.
func (tr *TransactionRegister) GetFeeTimeTransactions() []*MempoolTx {
	tr.RLock()
	defer tr.RUnlock()

	txns := []*MempoolTx{}
	it := tr.GetFeeTimeIterator()
	for it.Next() {
		if txn, ok := it.Value(); ok {
			txns = append(txns, txn)
		}
	}
	return txns
}

// GetTransaction returns the transaction with the given hash if it exists in the register, or nil otherwise.
func (tr *TransactionRegister) GetTransaction(hash *BlockHash) *MempoolTx {
	if hash == nil {
		return nil
	}

	tr.RLock()
	defer tr.RUnlock()

	return tr.txnMembership[*hash]
}

// PruneToSize removes transactions from the end of the register until the size of the register shrinks to the desired
// number of bytes. The returned transactions, _prunedTxns, are ordered by lowest-to-highest priority, i.e. first
// transaction will have the smallest fee, last transaction will have the highest fee. Returns _err = nil if no
// transactions were pruned.
func (tr *TransactionRegister) PruneToSize(maxSizeBytes uint64) (_prunedTxns []*MempoolTx, _err error) {
	tr.Lock()
	defer tr.Unlock()

	// If the maximum number of bytes is greater or equal to the current size of the register, return.
	if maxSizeBytes >= tr.totalTxnsSizeBytes {
		return nil, nil
	}

	// If the register is empty, return.
	if tr.feeTimeBucketSet.Empty() {
		return nil, nil
	}

	// Determine how many bytes we need to prune and get the transactions to prune.
	minPrunedBytes := tr.totalTxnsSizeBytes - maxSizeBytes
	prunedTxns, err := tr.getTransactionsToPrune(minPrunedBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "TransactionRegister.PruneToSize: Error getting transactions to prune")
	}

	// Remove the transactions from prunedTxns.
	for _, txn := range prunedTxns {
		if err := tr.removeTransactionNoLock(txn); err != nil {
			return nil, errors.Wrapf(err, "TransactionRegister.PruneToSize: Error removing transaction %v", txn.Hash.String())
		}
	}
	return prunedTxns, nil
}

func (tr *TransactionRegister) getTransactionsToPrune(minPrunedBytes uint64) (_prunedTxns []*MempoolTx, _err error) {
	if minPrunedBytes == 0 {
		return nil, nil
	}

	prunedBytes := uint64(0)
	prunedTxns := []*MempoolTx{}

	// Find the FeeTime bucket at the end of the Set. It'll have the smallest fee among the buckets in the register.
	// We iterate in reverse order, starting from the end, so that we drop transactions ordered by least-to-highest priority.
	it := tr.feeTimeBucketSet.Iterator()
	it.End()
	// Iterate through the buckets in reverse order so that we drop transactions ordered by least-to-highest priority.
	for it.Prev() {
		bucket, ok := it.Value().(*FeeTimeBucket)
		if !ok {
			return nil, fmt.Errorf("TransactionRegister.getTransactionsToPrune: " +
				"Error casting value of FeeTimeBucket")
		}

		// Iterate through the transactions in the current FeeTime bucket. We iterate in reverse order, starting from the
		// end, so that we drop transactions ordered by least-to-highest priority.
		bucketIt := bucket.GetIterator()
		bucketIt.End()
		for bucketIt.Prev() {
			txn, ok := bucketIt.Value().(*MempoolTx)
			if !ok {
				return nil, fmt.Errorf("TransactionRegister.getTransactionsToPrune: " +
					"Error casting value of MempoolTx")
			}
			// Add the transaction to the prunedTxns list.
			prunedTxns = append(prunedTxns, txn)
			prunedBytes += txn.TxSizeBytes
			// If we've pruned sufficiently many bytes, we can return early.
			if prunedBytes >= minPrunedBytes {
				return prunedTxns, nil
			}
		}
	}

	// If we reach this point, it means that we've iterated through the entire TransactionRegister and have no remaining
	// transactions to prune. We can return the txns we've found so far.
	return prunedTxns, nil
}

// FeeTimeIterator is an iterator over the transactions in a TransactionRegister. The iterator goes through all transactions
// as ordered by Fee-Time.
type FeeTimeIterator struct {
	// bucketIterator is an iterator over the FeeTimeBucket objects in the TransactionRegister.
	bucketIterator treeset.Iterator
	// mempoolTxIterator is an iterator over the transactions in the current FeeTimeBucket. It is nil if the iterator
	// is uninitialized.
	mempoolTxIterator *treeset.Iterator
}

// Next moves the FeeTimeIterator to the next transaction. It returns true if the iterator is pointing at a transaction
// after the move, and false otherwise.
func (fti *FeeTimeIterator) Next() bool {
	// If the iterator is uninitialized, then mempoolTxIterator is nil. In this case, we will first advance the
	// bucketIterator to the first FeeTime bucket, and then initialize mempoolTxIterator to point at the first transaction
	// in the bucket.
	// If the iterator is initialized, then mempoolTxIterator is not nil. In this case, we will first see if there are
	// more transactions in the current FeeTimeBucket. We do this by advancing the mempoolTxIterator and checking if it
	// is pointing at a transaction.
	if fti.mempoolTxIterator != nil && fti.mempoolTxIterator.Next() {
		return true
	}

	// If there are no more transactions in the current FeeTimeBucket, we will advance the bucketIterator.
	for fti.bucketIterator.Next() {
		// If there are more FeeTimeBucket objects in the TransactionRegister, we will advance the mempoolTxIterator
		// to the first transaction in the next FeeTimeBucket. First, we fetch the newly pointed-at FeeTimeBucket.
		nextFeeTimeBucket, ok := fti.bucketIterator.Value().(*FeeTimeBucket)
		if !ok {
			return false
		}

		// We will set the mempoolTxIterator to point at the first transaction in the new FeeTimeBucket.
		it := nextFeeTimeBucket.txnsSet.Iterator()
		fti.mempoolTxIterator = &it

		// Check if the newly found FeeTimeBucket is empty. If it's not empty, then we're done.
		if fti.mempoolTxIterator.Next() {
			return true
		}
	}

	return false
}

// Value returns the transaction that the iterator is pointing at.
func (fti *FeeTimeIterator) Value() (*MempoolTx, bool) {
	if !fti.Initialized() {
		return nil, false
	}

	if txn, ok := fti.mempoolTxIterator.Value().(*MempoolTx); ok {
		return txn, true
	}
	return nil, false
}

// Initialized returns true if the iterator is initialized, and false otherwise.
func (fti *FeeTimeIterator) Initialized() bool {
	return fti.mempoolTxIterator != nil
}

// ========================
//	FeeTimeBucket
// ========================

// FeeTimeBucket is a data structure storing MempoolTx with similar fee rates. The structure is thread safe.
// The transactions accepted by the FeeTimeBucket must have a fee rate above or equal to the configured minFeeNanosPerKB,
// and below or equal to the configured maxFeeNanosPerKB. The transactions are stored in a treeset, which orders the
// transactions by timestamp. The earliest timestamp is at the front of the txnsSet, and the latest timestamp is at the
// back of the txnsSet. In case of a timestamp tie, the transactions are ordered by greatest fee rate first. If a tie
// still exists, the transactions are ordered by greatest lexicographic transaction hash first.
type FeeTimeBucket struct {
	sync.RWMutex

	// txnsSet is a set of MempoolTx transactions stored in the FeeTimeBucket.
	txnsSet *treeset.Set
	// txnMembership is a set of transaction hashes. It is used to determine existence of a transaction in the register.
	txnMembership *Set[BlockHash]
	// minFeeNanosPerKB is the minimum fee rate (inclusive) accepted by the FeeTimeBucket, in nanos per KB.
	minFeeNanosPerKB uint64
	// maxFeeNanosPerKB is the maximum fee rate (inclusive) accepted by the FeeTimeBucket, in nanos per KB. It's worth
	// noting that the maximum fee rate is always 1 below the minimum fee rate of the FeeTimeBucket with exponent+1.
	maxFeeNanosPerKB uint64
	// totalTxnsSizeBytes is the total size of all transactions in the FeeTimeBucket, in bytes.
	totalTxnsSizeBytes uint64
}

func NewFeeTimeBucket(minFeeNanosPerKB uint64, maxFeeNanosPerKB uint64) *FeeTimeBucket {

	txnsSet := treeset.NewWith(mempoolTxTimeOrderComparator)
	return &FeeTimeBucket{
		minFeeNanosPerKB:   minFeeNanosPerKB,
		maxFeeNanosPerKB:   maxFeeNanosPerKB,
		totalTxnsSizeBytes: 0,
		txnsSet:            txnsSet,
		txnMembership:      NewSet([]BlockHash{}),
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
	return bytes.Compare(aVal.Hash[:], bVal.Hash[:])
}

// AddTransaction adds a transaction to the FeeTimeBucket. It returns an error if the transaction is outside the
// FeeTimeBucket's fee range, or if the transaction hash is nil.
func (tb *FeeTimeBucket) AddTransaction(txn *MempoolTx) error {
	tb.Lock()
	defer tb.Unlock()

	if txn == nil || txn.Hash == nil {
		return fmt.Errorf("FeeTimeBucket.AddTransaction: Transaction or transaction hash is nil")
	}

	if tb.txnMembership.Includes(*txn.Hash) {
		return nil
	}

	if tb.totalTxnsSizeBytes > math.MaxUint64-txn.TxSizeBytes {
		return fmt.Errorf("FeeTimeBucket.AddTransaction: Transaction size %d would overflow bucket size %d",
			txn.TxSizeBytes, tb.totalTxnsSizeBytes)
	}

	if tb.minFeeNanosPerKB > txn.FeePerKB || tb.maxFeeNanosPerKB < txn.FeePerKB {
		return fmt.Errorf("FeeTimeBucket.AddTransaction: Transaction fee %d outside of bucket range [%d, %d]",
			txn.FeePerKB, tb.minFeeNanosPerKB, tb.maxFeeNanosPerKB)
	}

	tb.txnsSet.Add(txn)
	tb.txnMembership.Add(*txn.Hash)
	tb.totalTxnsSizeBytes += txn.TxSizeBytes
	return nil
}

// RemoveTransaction removes a transaction from the FeeTimeBucket.
func (tb *FeeTimeBucket) RemoveTransaction(txn *MempoolTx) {
	tb.Lock()
	defer tb.Unlock()

	if txn == nil || txn.Hash == nil {
		return
	}

	if !tb.txnMembership.Includes(*txn.Hash) {
		return
	}

	tb.txnsSet.Remove(txn)
	tb.txnMembership.Remove(*txn.Hash)
	tb.totalTxnsSizeBytes -= txn.TxSizeBytes
}

func (tb *FeeTimeBucket) Empty() bool {
	tb.RLock()
	defer tb.RUnlock()

	return tb.txnsSet.Empty()
}

// GetIterator returns an iterator over the MempoolTx inside the FeeTimeBucket.
func (tb *FeeTimeBucket) GetIterator() treeset.Iterator {
	tb.RLock()
	defer tb.RUnlock()

	return tb.txnsSet.Iterator()
}

// GetTransactions returns a slice of MempoolTx inside the FeeTimeBucket. The slice is ordered according to the
// mempoolTxTimeOrderComparator.
func (tb *FeeTimeBucket) GetTransactions() []*MempoolTx {
	tb.RLock()
	defer tb.RUnlock()

	txns := []*MempoolTx{}
	it := tb.GetIterator()
	for it.Next() {
		if txn, ok := it.Value().(*MempoolTx); ok {
			txns = append(txns, txn)
		}
	}
	return txns
}

func (tb *FeeTimeBucket) Size() uint64 {
	tb.RLock()
	defer tb.RUnlock()

	return tb.totalTxnsSizeBytes
}

func (tb *FeeTimeBucket) Includes(txn *MempoolTx) bool {
	tb.RLock()
	defer tb.RUnlock()

	if txn == nil || txn.Hash == nil {
		return false
	}

	return tb.txnMembership.Includes(*txn.Hash)
}

func (tb *FeeTimeBucket) Clear() {
	tb.Lock()
	defer tb.Unlock()

	tb.txnsSet.Clear()
	tb.txnMembership = NewSet([]BlockHash{})
	tb.totalTxnsSizeBytes = 0
}

//============================================
//	Fee-Time Bucket Math
//============================================

// computeFeeTimeBucketRangeFromFeeNanosPerKB takes a fee rate, minimumNetworkFeeNanosPerKB, and feeBucketMultiplier,
// and returns the [minFeeNanosPerKB, maxFeeNanosPerKB] of the fee range.
func computeFeeTimeBucketRangeFromFeeNanosPerKB(feeNanosPerKB uint64, minimumNetworkFeeNanosPerKB *big.Float,
	feeBucketMultiplier *big.Float) (uint64, uint64) {

	bucketExponent := computeFeeTimeBucketExponentFromFeeNanosPerKB(feeNanosPerKB, minimumNetworkFeeNanosPerKB, feeBucketMultiplier)
	return computeFeeTimeBucketRangeFromExponent(bucketExponent, minimumNetworkFeeNanosPerKB, feeBucketMultiplier)
}

// computeFeeTimeBucketRangeFromExponent takes a fee range exponent, minimumNetworkFeeNanosPerKB, and feeBucketMultiplier, and returns the
// [minFeeNanosPerKB, maxFeeNanosPerKB] of the fee range.
func computeFeeTimeBucketRangeFromExponent(exponent uint32, minimumNetworkFeeNanosPerKB *big.Float, feeBucketMultiplier *big.Float) (
	_minFeeNanosPerKB uint64, _maxFeeNanosPerKB uint64) {

	minFeeNanosPerKB := computeFeeTimeBucketMinFromExponent(exponent, minimumNetworkFeeNanosPerKB, feeBucketMultiplier)
	maxFeeNanosPerKB := computeFeeTimeBucketMinFromExponent(exponent+1, minimumNetworkFeeNanosPerKB, feeBucketMultiplier) - 1
	return minFeeNanosPerKB, maxFeeNanosPerKB
}

// computeFeeTimeBucketMinFromExponent takes a fee range exponent, minimumNetworkFeeNanosPerKB, and feeBucketMultiplier, and uses them to
// return the minimum fee rate of this fee range.
func computeFeeTimeBucketMinFromExponent(exponent uint32, minimumNetworkFeeNanosPerKB *big.Float, feeBucketMultiplier *big.Float) uint64 {
	// The first fee range has a fee rate of minimumNetworkFeeNanosPerKB.
	if exponent == 0 {
		fee, _ := minimumNetworkFeeNanosPerKB.Uint64()
		return fee
	}

	// Compute minimumNetworkFeeNanosPerKB * feeBucketMultiplier^exponent.
	pow := NewFloat().SetUint64(uint64(exponent))
	multiplier := BigFloatPow(feeBucketMultiplier, pow)
	fee := NewFloat().Mul(minimumNetworkFeeNanosPerKB, multiplier)

	feeUint64, _ := fee.Uint64()
	return feeUint64
}

// computeFeeTimeBucketExponentFromFeeNanosPerKB takes a fee rate, minimumNetworkFeeNanosPerKB, and feeBucketMultiplier, and
// returns the fee range exponent.
func computeFeeTimeBucketExponentFromFeeNanosPerKB(feeNanosPerKB uint64, minimumNetworkFeeNanosPerKB *big.Float,
	feeBucketMultiplier *big.Float) uint32 {

	// Compute the fee time bucket exponent for the fee rate. We can compute the exponent as follows:
	// feeNanosPerKB = minimumNetworkFeeNanosPerKB * feeBucketMultiplier ^ exponent
	// log(feeNanosPerKB) = log(minimumNetworkFeeNanosPerKB) + exponent * log(feeBucketMultiplier^exponent)
	// exponent = (log(feeNanosPerKB) - log(minimumNetworkFeeNanosPerKB)) / log(feeBucketMultiplier).

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
	feeTimeBucketExponentUint64, _ := divFee.Uint64()
	feeTimeBucketExponent := uint32(feeTimeBucketExponentUint64)
	if feeTimeBucketExponent < 0 {
		return 0
	}

	// Now verify that float precision hasn't caused us to be off by one.
	// If this condition is true, then the computed exponent is overestimated by 1.
	if computeFeeTimeBucketMinFromExponent(feeTimeBucketExponent, minimumNetworkFeeNanosPerKB, feeBucketMultiplier) > feeNanosPerKB {
		return feeTimeBucketExponent - 1
	}

	// This condition gets triggered exactly on fee bucket boundaries, i.e. when feeNanosPerKB = FeeMax for some bucket.
	// The float rounding makes the number slightly smaller like 5.9999999991 instead of 6.0.
	if computeFeeTimeBucketMinFromExponent(feeTimeBucketExponent+1, minimumNetworkFeeNanosPerKB, feeBucketMultiplier) <= feeNanosPerKB {
		return feeTimeBucketExponent + 1
	}

	// If we get here, then the computed exponent is correct.
	return feeTimeBucketExponent
}

func _isValidMinimumFeeAndMultiplier(minimumNetworkFeeNanosPerKB *big.Float, feeBucketMultiplier *big.Float) bool {
	if minimumNetworkFeeNanosPerKB == nil || feeBucketMultiplier == nil {
		return false
	}

	if minimumNetworkFeeNanosPerKB.Sign() <= 0 || feeBucketMultiplier.Sign() <= 0 {
		return false
	}

	return true
}

func _getFallbackSafeMinimumFeeAndMultiplier() (*big.Float, *big.Float) {
	minimumNetworkFeeNanosPerKB := big.NewFloat(100) // Default to 100 nanos per KB
	feeBucketMultiplier := big.NewFloat(1000)        // Default to 10%
	return minimumNetworkFeeNanosPerKB, feeBucketMultiplier
}
