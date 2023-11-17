package lib

import (
	"github.com/deso-protocol/core/collections"
	"github.com/pkg/errors"
	"sync"
)

type PoSFeeEstimator struct {
	mempoolFeeEstimatorMempool    *PosMempool
	pastBlocksTransactionRegister *TransactionRegister
	numBlocks                     uint64
	cachedBlocks                  []*MsgDeSoBlock
	rwLock                        *sync.RWMutex
}

// Init initializes the PoSFeeEstimator with the given mempool and past blocks. The mempool
// must be running and the number of past blocks must equal the numBlocks param provided.
// Init will add all the transactions from the past blocks to the pastBlocksTransactionRegister
// and cache the initial past blocks.
func (posFeeEstimator *PoSFeeEstimator) Init(mempool *PosMempool, pastBlocks []*MsgDeSoBlock, numBlocks uint64) error {
	posFeeEstimator.rwLock = &sync.RWMutex{}
	posFeeEstimator.rwLock.Lock()
	defer posFeeEstimator.rwLock.Unlock()
	if mempool == nil {
		return errors.New("PoSFeeEstimator.Init: mempool cannot be nil")
	}
	if !mempool.IsRunning() {
		return errors.New("PoSFeeEstimator.Init: mempool must be running")
	}
	if len(pastBlocks) == 0 {
		return errors.New("PoSFeeEstimator.Init: pastBlocks cannot be empty")
	}
	if numBlocks == 0 {
		return errors.New("PoSFeeEstimator.Init: numBlocks cannot be zero")
	}
	if numBlocks != uint64(len(pastBlocks)) {
		return errors.New("PoSFeeEstimator.Init: numBlocks must equal the number of pastBlocks")
	}
	// Sort the past blocks by height just to be safe.
	sortedPastBlocks := collections.SortStable(pastBlocks, func(ii, jj *MsgDeSoBlock) bool {
		return ii.Header.Height < jj.Header.Height
	})
	minHeight := sortedPastBlocks[0].Header.Height
	if minHeight == 0 {
		return errors.New("PoSFeeEstimator.Init: minHeight cannot be zero")
	}
	posFeeEstimator.mempoolFeeEstimatorMempool = mempool
	posFeeEstimator.numBlocks = numBlocks
	// Create a transaction register we can use to estimate fees for past blocks.
	posFeeEstimator.pastBlocksTransactionRegister = NewTransactionRegister(mempool.globalParams.Copy())

	// Add all the txns from the past blocks to the new pastBlocksTransactionRegister.
	for _, block := range sortedPastBlocks {
		if err := posFeeEstimator.addBlockNoLock(block); err != nil {
			return errors.Wrap(err, "PosFeeEstimator.Init: error adding block to pastBlocksMempool")
		}
	}
	return nil
}

// AddBlock adds a block to the PoSFeeEstimator. This will add all the transactions from the block
// to the pastBlocksTransactionRegister and cache the block. If there are now more blocks cached
// than the numBlocks param provided to Init, the oldest block will be removed from the cache
// and all its transactions removed from the pastBlocksTransactionRegister.
func (posFeeEstimator *PoSFeeEstimator) AddBlock(block *MsgDeSoBlock) error {
	posFeeEstimator.rwLock.Lock()
	defer posFeeEstimator.rwLock.Unlock()
	if err := posFeeEstimator.addBlockNoLock(block); err != nil {
		return errors.Wrap(err, "PoSFeeEstimator.AddBlock: error adding block to PoSFeeEstimator")
	}
	return nil
}

// addBlockNoLock is the same as AddBlock but assumes the caller has already acquired the rwLock.
func (posFeeEstimator *PoSFeeEstimator) addBlockNoLock(block *MsgDeSoBlock) error {
	// Add all transactions from the block to the pastBlocksTransactionRegister.
	if err := addBlockToTransactionRegister(posFeeEstimator.pastBlocksTransactionRegister, block); err != nil {
		return errors.Wrap(err, "PoSFeeEstimator.addBlockNoLock: error adding block to pastBlocksTransactionRegister")
	}
	posFeeEstimator.cachedBlocks = append(posFeeEstimator.cachedBlocks, block)
	// Sort the cached blocks by height & tstamp just to be safe.
	posFeeEstimator.sortCachedBlocks()
	if uint64(len(posFeeEstimator.cachedBlocks)) > posFeeEstimator.numBlocks {
		// Remove the oldest block.
		if err := posFeeEstimator.removeBlockNoLock(posFeeEstimator.cachedBlocks[0]); err != nil {
			return errors.Wrap(err, "PoSFeeEstimator.addBlockNoLock: error removing block from PoSFeeEstimator")
		}
	}
	return nil
}

// addBlockToTransactionRegister adds all the transactions from the block to the given transaction register.
// Should only be called when the rwLock over a TransactionRegister is held.
func addBlockToTransactionRegister(txnRegister *TransactionRegister, block *MsgDeSoBlock) error {
	for _, txn := range block.Txns {
		mtxn, err := NewMempoolTx(txn, block.Header.TstampNanoSecs, block.Header.Height)
		if err != nil {
			return errors.Wrap(err, "PoSFeeEstimator.addBlockToTransactionRegister: error creating MempoolTx")
		}
		if err = txnRegister.AddTransaction(mtxn); err != nil {
			return errors.Wrap(err, "PoSFeeEstimator.addBlockToTransactionRegister: error adding txn to pastBlocksTransactionRegister")
		}
	}
	return nil
}

// RemoveBlock removes a block from the PoSFeeEstimator. This will remove all the transactions from the block
// from the pastBlocksTransactionRegister and remove the block from the cache.
func (posFeeEstimator *PoSFeeEstimator) RemoveBlock(block *MsgDeSoBlock) error {
	posFeeEstimator.rwLock.Lock()
	defer posFeeEstimator.rwLock.Unlock()

	if err := posFeeEstimator.removeBlockNoLock(block); err != nil {
		return errors.Wrap(err, "PoSFeeEstimator.RemoveBlock: error removing block from PoSFeeEstimator")
	}
	return nil
}

func (posFeeEstimator *PoSFeeEstimator) removeBlockNoLock(block *MsgDeSoBlock) error {
	// Remove all transaction from the block from the pastBlocksTransactionRegister.
	for _, txn := range block.Txns {
		mtxn, err := NewMempoolTx(txn, block.Header.TstampNanoSecs, block.Header.Height)
		if err != nil {
			return errors.Wrap(err, "PoSFeeEstimator.RemoveBlock: error creating MempoolTx")
		}
		if err = posFeeEstimator.pastBlocksTransactionRegister.RemoveTransaction(mtxn); err != nil {
			return errors.Wrap(err, "PoSFeeEstimator.removeBlockNoLock: error removing txn from pastBlocksTransactionRegister")
		}
	}
	blockHash, err := block.Hash()
	if err != nil {
		return errors.Wrap(err, "PoSFeeEstimator.removeBlockNoLock: error computing blockHash")
	}
	// Remove the block from the cached blocks.
	for ii, cachedBlock := range posFeeEstimator.cachedBlocks {
		cachedBlockHash, err := cachedBlock.Hash()
		if err != nil {
			return errors.Wrap(err, "PoSFeeEstimator.removeBlockNoLock: error computing cachedBlockHash")
		}
		if blockHash.IsEqual(cachedBlockHash) {
			posFeeEstimator.cachedBlocks = append(posFeeEstimator.cachedBlocks[:ii], posFeeEstimator.cachedBlocks[ii+1:]...)
			break
		}
	}
	return nil
}

// UpdateGlobalParams updates the global params used by the PoSFeeEstimator. This only modifies the GlobalParams
// used by the pastBlockTransactionRegister and allows it to properly compute the fee buckets. The mempool's
// global params are not modified and are controlled externally.
func (posFeeEstimator *PoSFeeEstimator) UpdateGlobalParams(globalParams *GlobalParamsEntry) error {
	posFeeEstimator.rwLock.Lock()
	defer posFeeEstimator.rwLock.Unlock()
	tempTransactionRegister := NewTransactionRegister(globalParams.Copy())
	for _, block := range posFeeEstimator.cachedBlocks {
		if err := addBlockToTransactionRegister(tempTransactionRegister, block); err != nil {
			return errors.Wrap(err, "PosFeeEstimator.UpdateGlobalParams: error adding block to tempTransactionRegister")
		}
	}
	return nil
}

// sortCachedBlocks sorts the cached blocks by height & tstamp just to be safe.
func (posFeeEstimator *PoSFeeEstimator) sortCachedBlocks() {
	posFeeEstimator.cachedBlocks = collections.SortStable(posFeeEstimator.cachedBlocks, func(ii, jj *MsgDeSoBlock) bool {
		if ii.Header.Height == jj.Header.Height {
			return ii.Header.TstampNanoSecs < jj.Header.TstampNanoSecs
		}
		return ii.Header.Height < jj.Header.Height
	})
}

func (posFeeEstimator *PoSFeeEstimator) EstimateFee(
	txn *MsgDeSoTxn,
	congestionFactorBasisPoints uint64,
	priorityPercentileBasisPoints uint64,
	maxBlockSize uint64,
) (uint64, error) {
	panic("TODO: IMPLEMENT ME")
}

func (posFeeEstimator *PoSFeeEstimator) pastBlocksFeeEstimate(
	txn *MsgDeSoTxn,
	congestionFactorBasisPoints uint64,
	priorityPercentileBasisPoints uint64,
	maxBlockSize uint64,
) (uint64, error) {
	panic("TODO: IMPLEMENT ME")
}

func (posFeeEstimator *PoSFeeEstimator) mempoolFeeEstimate(
	txn *MsgDeSoTxn,
	congestionFactorBasisPoints uint64,
	priorityPercentileBasisPoints uint64,
	maxBlockSize uint64,
) (uint64, error) {
	panic("TODO: IMPLEMENT ME")
}
