package lib

import (
	"github.com/emirpasic/gods/sets/treeset"
	"github.com/pkg/errors"
	"math"
	"math/big"
	"time"
)

type DeSoMempoolPos struct {
	bc           *Blockchain
	txnRegister  *TransactionRegister
	globalParams *GlobalParamsEntry

	reservedBalances map[PublicKey]uint64
}

func NewDeSoMempoolPos(bc *Blockchain) *DeSoMempoolPos {
	// TODO: Think about how to handle global params.
	globalParams := DbGetGlobalParamsEntry(bc.db, bc.snapshot)

	return &DeSoMempoolPos{
		bc:               bc,
		txnRegister:      NewTransactionRegister(bc.params, globalParams),
		globalParams:     globalParams,
		reservedBalances: make(map[PublicKey]uint64),
	}
}

func (dmp *DeSoMempoolPos) AddTransaction(txn *MsgDeSoTxn, blockHeight uint64, utxoView *UtxoView) error {
	// First, validate that the transaction is properly formatted.
	if err := txn.ValidateTransactionSanityBalanceModel(blockHeight, dmp.bc.params, dmp.globalParams); err != nil {
		return errors.Wrapf(err, "DeSoMempoolPos.AddTransaction: ")
	}

	// Validate that the user has enough balance to cover the transaction fees.
	userPk := NewPublicKey(txn.PublicKey)
	txnFee := txn.TxnFeeNanos
	reservedBalance, exists := dmp.reservedBalances[*userPk]

	// Check for reserved balance overflow.
	if exists && txnFee > math.MaxUint64-reservedBalance {
		return errors.Errorf("DeSoMempoolPos.AddTransaction: Reserved balance overflow")
	}
	newReservedBalance := reservedBalance + txnFee
	spendableBalanceNanos, err := utxoView.GetSpendableDeSoBalanceNanosForPublicKey(txn.PublicKey, uint32(blockHeight))
	if err != nil {
		return errors.Wrapf(err, "DeSoMempoolPos.AddTransaction: ")
	}

	if newReservedBalance > spendableBalanceNanos {
		return errors.Errorf("DeSoMempoolPos.AddTransaction: Not enough balance to cover txn fees "+
			"(newReservedBalance: %d, spendableBalanceNanos: %d)", newReservedBalance, spendableBalanceNanos)
	}
	// If we get here, this means user has enough balance to cover the txn fees. We update the reserved balance to
	// include the newly added transaction's fee.
	dmp.reservedBalances[*userPk] = newReservedBalance

	// Construct the MempoolTx from the MsgDeSoTxn.
	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		return errors.Wrapf(err, "DeSoMempoolPos.AddTransaction: Problem serializing txn")
	}
	serializedLen := uint64(len(txnBytes))

	txnHash := txn.Hash()
	if txnHash == nil {
		return errors.Errorf("DeSoMempoolPos.AddTransaction: Problem hashing txn")
	}
	feePerKb, err := txn.ComputeFeePerKB()
	if err != nil {
		return errors.Wrapf(err, "DeSoMempoolPos.AddTransaction: Problem computing fee per KB")
	}

	mempoolTx := &MempoolTx{
		Tx:          txn,
		Hash:        txnHash,
		TxSizeBytes: serializedLen,
		Added:       time.Now(),
		Height:      uint32(blockHeight),
		Fee:         txnFee,
		FeePerKB:    feePerKb,
	}
	if !dmp.txnRegister.AddTransaction(mempoolTx) {
		return errors.Errorf("DeSoMempoolPos.AddTransaction: Problem adding txn to register")
	}

	return nil
}

// ========================
//	TransactionRegister
// ========================

type TransactionRegister struct {
	buckets       *FeeBucket
	txnMembership map[BlockHash]struct{}
	totalTxnSize  uint64

	params       *DeSoParams
	globalParams *GlobalParamsEntry
}

func NewTransactionRegister(params *DeSoParams, globalParams *GlobalParamsEntry) *TransactionRegister {
	buckets := NewFeeBucket([]*TimeBucket{}, globalParams)
	return &TransactionRegister{
		buckets:       buckets,
		txnMembership: map[BlockHash]struct{}{},
		totalTxnSize:  0,
		params:        params,
		globalParams:  globalParams,
	}
}

func (tr *TransactionRegister) AddTransaction(txn *MempoolTx) bool {
	if _, ok := tr.txnMembership[*txn.Hash]; ok {
		return false
	}

	// If the transaction overflows the maximum mempool size, reject it.
	if tr.totalTxnSize+txn.TxSizeBytes > tr.params.MaxMempoolPosSizeBytes {
		return false
	}
	tr.totalTxnSize += txn.TxSizeBytes

	tr.buckets.AddTransaction(txn)
	tr.txnMembership[*txn.Hash] = struct{}{}
	return true
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
