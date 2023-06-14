package lib

import (
	"container/heap"
	"github.com/golang/glog"
	"math"
	"time"
)

const RevolutionViolationLimit = 10
const RevolutionViolationExpirationBlocks = 50

//============================================
//	Block Proposer side of Revolution
//============================================

// FIXME: Note, this clears out the txn register. It has to be regenerated afterwards.
//func (txnRegister *TransactionRegister) GetFeeTimeTransactions() []*MempoolTx {
//	feeTimeTxns := []*MempoolTx{}
//	for !txnRegister.buckets.Empty() {
//		bucket := heap.Pop(txnRegister.buckets).(*TimeBucket)
//		for !bucket.Empty() {
//			txn := heap.Pop(bucket).(*MempoolTx)
//			feeTimeTxns = append(feeTimeTxns, txn)
//		}
//	}
//	return feeTimeTxns
//}

// FIXME: Debatable whether we want a TransactionRegister method to be aware of block size and regenerate by itself.
//
//	The other option could be to make it a regular function, or make it a Blockchain's method.
func (txnRegister *TransactionRegister) GetBlockTransactions(params *DeSoParams) []*MempoolTx {
	feeTimeTxns := txnRegister.GetFeeTimeTransactions()
	blockTxns := []*MempoolTx{}
	currentSize := uint64(0)
	for ii := 0; ii < len(feeTimeTxns); ii++ {
		if currentSize+feeTimeTxns[ii].TxSizeBytes > params.MaxBlockSizeBytes {
			// FIXME: Comment at the top
			txnRegister.AddTransaction(feeTimeTxns[ii])
			continue
		}
		blockTxns = append(blockTxns, feeTimeTxns[ii])
		currentSize += feeTimeTxns[ii].TxSizeBytes
	}
	return blockTxns
}

//============================================
//	Validator side of Revolution
//============================================

type RevolutionRegister struct {
	TransactionsMap      map[BlockHash]*RevolutionMetadata
	ViolationCounter     uint64
	ViolationExpirations *HeapMinUint64
}

func NewRevolutionRegister() *RevolutionRegister {
	txnMap := make(map[BlockHash]*RevolutionMetadata)
	violationExpirations := NewHeapMinUint64()

	return &RevolutionRegister{
		TransactionsMap:      txnMap,
		ViolationExpirations: violationExpirations,
	}
}

func (revRegister *RevolutionRegister) AddTransactionViolation(txnHash *BlockHash, currentHeight uint64) {
	revMetadata, exists := revRegister.TransactionsMap[*txnHash]
	if !exists {
		revRegister.TransactionsMap[*txnHash] = NewRevolutionMetadata()
		revMetadata = revRegister.TransactionsMap[*txnHash]
	}

	revMetadata.Increment()
	// Check if the transaction counter exceeds the violation limit. If so, we will increment the RevolutionCounter.
	if revMetadata.Get() >= RevolutionViolationLimit {
		// If we get here, it means the transaction is being censored for over RevolutionViolationLimit blocks.
		// We will increment ViolationCounter for this proposer.
		revRegister.AddViolation(currentHeight)
	}
}

func (revRegister *RevolutionRegister) RemoveTransactionViolation(txnHash *BlockHash) {
	if revRegister.TransactionsMap == nil {
		return
	}

	delete(revRegister.TransactionsMap, *txnHash)
}

func (revRegister *RevolutionRegister) AddViolation(currentHeight uint64) {
	revRegister.ViolationCounter++
	// Add the expiration block for this violation.
	heap.Push(revRegister.ViolationExpirations, currentHeight+RevolutionViolationExpirationBlocks)
}

func (revRegister *RevolutionRegister) ExpireViolations(currentHeight uint64) {
	// We will look through violation expirations and find all that expired by the currentHeight.
	for !revRegister.ViolationExpirations.Empty() {
		expiration := heap.Pop(revRegister.ViolationExpirations).(uint64)

		// TODO: < or <= ? Think about it.
		if expiration <= currentHeight {
			revRegister.ViolationCounter--
		} else {
			heap.Push(revRegister.ViolationExpirations, expiration)
			break
		}
	}
}

func (revRegister *RevolutionRegister) GetViolations(currentHeight uint64) uint64 {
	revRegister.ExpireViolations(currentHeight)
	return revRegister.ViolationCounter
}

type RevolutionMetadata struct {
	RevolutionTransactionCounter uint64
}

func NewRevolutionMetadata() *RevolutionMetadata {
	return &RevolutionMetadata{}
}

func (revMeta *RevolutionMetadata) Increment() {
	revMeta.RevolutionTransactionCounter++
}

func (revMeta *RevolutionMetadata) Decrement() {
	revMeta.RevolutionTransactionCounter--
}

func (revMeta *RevolutionMetadata) Get() uint64 {
	return revMeta.RevolutionTransactionCounter
}

type RevolutionModule struct {
	LeaderRevolutionRegisters map[PublicKey]*RevolutionRegister
}

func NewRevolutionModule() *RevolutionModule {
	leaderRevRegisters := make(map[PublicKey]*RevolutionRegister)
	return &RevolutionModule{
		LeaderRevolutionRegisters: leaderRevRegisters,
	}
}

// ValidateBlock checks if the transaction ordering in the block follows Fee-Time.
func (rev *RevolutionModule) ValidateBlock(txns []*MsgDeSoTxn) bool {
	// Add the block transactions to an empty TransactionRegister, and use it to fetch Fee-Time transactions.
	// This is the same computation the leader should have done during block construction.
	txnRegister := NewTransactionRegister(nil, nil)
	for _, txn := range txns {
		mempoolTx := &MempoolTx{
			Tx:          txn,
			TxMeta:      nil,
			Hash:        nil,
			TxSizeBytes: 0,
			Added:       time.Now(),
			Height:      0,
			Fee:         0,
			FeePerKB:    0,
		}
		txnRegister.AddTransaction(mempoolTx)
	}

	// Get Fee-Time
	feeTimeTxns := txnRegister.GetFeeTimeTransactions()
	for ii, txn := range feeTimeTxns {
		if !txn.Hash.IsEqual(txns[ii].Hash()) {
			glog.Errorf("Block doesn't follow Fee-Time, do something.")
			return false
		}
	}

	return true
}

// ProcessCommittedBlock updates the RevolutionModule internal state on a committed block. This method will compare
// the block's transactions with the node's local mempool to determine whether the proposer is potentially censoring
// transactions.
func (rev *RevolutionModule) ProcessCommittedBlock(block *MsgDeSoBlock, txnPool *TransactionRegister) {
	// To check for transaction censorship, our node will try to simulate the leader's block construction process.
	// In the simulation, we will take our local mempool's TransactionRegister and augment it with the block's
	// transactions. Finally, we will apply Block Rule to the augmented mempool to fetch a Fee-Time ordered block.
	// To see if a transaction is censored, and if the proposer should be revolted, we keep appropriate records in
	// the RevolutionModule

	// First create a blank TransactionRegister.
	txnRegister := NewTransactionRegister(nil, nil)
	// Now add all block transactions to the register. We also determine the lowest fee-bucket in the block, and the
	// cumulative size of the block's transactions.
	txnsSize := uint64(0)
	lowestFeeBucket := uint64(math.MaxUint64)
	blockTxns := []*MempoolTx{}
	for _, txn := range block.Txns {
		mempoolTx := &MempoolTx{
			Tx:          txn,
			TxMeta:      nil,
			Hash:        nil,
			TxSizeBytes: 0,
			Added:       time.Now(),
			Height:      0,
			Fee:         0,
			FeePerKB:    0,
		}
		txnRegister.AddTransaction(mempoolTx)

		// Update the lowest fee-bucket.
		feeBucket := mempoolTx.FeePerKB - (mempoolTx.FeePerKB % 1000)
		if feeBucket < lowestFeeBucket {
			lowestFeeBucket = feeBucket
		}

		// Keep track of cumulative transaction size.
		txnsSize += mempoolTx.TxSizeBytes
		blockTxns = append(blockTxns, mempoolTx)
	}

	// Now we will merge the txnRegister with the mempool transactions.
	// FIXME: Mutex needed.
	mempoolTxns := txnPool.GetFeeTimeTransactions()
	// Max size in bytes of transactions in the block.
	MaxBlockTransactionsSize := uint64(1234)
	for _, txn := range mempoolTxns {
		feeBucket := txn.FeePerKB - (txn.FeePerKB % 1000)
		// If the transaction is not the lowest fee-bucket, add it to our txnRegister.
		if feeBucket > lowestFeeBucket {
			txnRegister.AddTransaction(txn)
		} else {
			// If the transaction is the lowest fee-bucket, or a lower one, then only add the txn if the block isn't full.
			if txnsSize+txn.TxSizeBytes < MaxBlockTransactionsSize {
				txnRegister.AddTransaction(txn)
			}
		}
	}
	// FIXME: Temporary. Regenerate the mempool.
	for _, txn := range mempoolTxns {
		txnPool.AddTransaction(txn)
	}

	// TODO: We could potentially add another constraint to above merge step. We could skip transactions which have
	// 	a later time-of-arrival than the block's time-of-arrival. This way we won't consider transactions that
	// 	arrived to us after we've seen the block.

	// TODO: Make sure to remove mempool's transactions that appeared in the committed block.

	// Now, we fetch Fee-Time ordered transactions from the txnRegister and compare it to the block.
	feeTimeTxns := txnRegister.GetFeeTimeTransactions()
	// We will iterate through the fee-time transactions and look for any in-between transactions that didn't make it
	// into the block.
	index := 0
	cumulativeTxnsSize := uint64(0)
	proposerPk := NewPublicKey(block.BlockProducerInfo.PublicKey)
	for ii := 0; ii < len(blockTxns); {
		txn := blockTxns[ii]
		simTxn := feeTimeTxns[index]

		// Our simulated Fee-Time ordering matches the block's ordering, so we can move forward.
		if txn.Hash.IsEqual(simTxn.Hash) {
			ii++
			index++
			cumulativeTxnsSize += txn.TxSizeBytes
			rev.RemoveTransactionViolation(proposerPk, simTxn.Hash)
			continue
		}

		// If we get here, it means the block transaction is not what it's supposed to. In this case, we will check
		// if this transaction could be possibly added to the block. If so, then we detected potential transaction
		// censorship. We will then increment the RevolutionTransactionCounter for this transaction.
		if cumulativeTxnsSize+simTxn.TxSizeBytes < MaxBlockTransactionsSize {
			index++
			rev.AddTransactionViolation(proposerPk, simTxn.Hash, block.Header.Height)
		}

		if index == len(feeTimeTxns) {
			break
		}
	}
}

func (rev *RevolutionModule) RemoveTransactionViolation(proposer *PublicKey, txnHash *BlockHash) {
	revRegister, exists := rev.LeaderRevolutionRegisters[*proposer]
	if !exists {
		return
	}
	revRegister.RemoveTransactionViolation(txnHash)
}

func (rev *RevolutionModule) AddTransactionViolation(proposer *PublicKey, txnHash *BlockHash, currentHeight uint64) {
	revRegister, exists := rev.LeaderRevolutionRegisters[*proposer]
	if !exists {
		rev.LeaderRevolutionRegisters[*proposer] = NewRevolutionRegister()
		revRegister = rev.LeaderRevolutionRegisters[*proposer]
	}

	revRegister.AddTransactionViolation(txnHash, currentHeight)
}

func (rev *RevolutionModule) ShouldRevolt(block *MsgDeSoBlock) bool {
	proposerPk := NewPublicKey(block.BlockProducerInfo.PublicKey)
	revRegister, exists := rev.LeaderRevolutionRegisters[*proposerPk]
	if !exists {
		return false
	}

	// Proposers are revolted if their violation counter exceeds the RevolutionViolationLimit.
	violationCounter := revRegister.GetViolations(block.Header.Height)
	return violationCounter >= RevolutionViolationLimit
}
