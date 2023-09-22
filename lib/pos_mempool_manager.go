package lib

import "sync"

type MempoolManager struct {
	sync.RWMutex
	mp Mempool
}

func NewPosMempoolManager(params *DeSoParams, globalParams *GlobalParamsEntry, latestBlockView *UtxoView,
	latestBlockHeight uint64, dir string) *MempoolManager {
	return &MempoolManager{
		mp: NewPosMempool(params, globalParams, latestBlockView, latestBlockHeight, dir),
	}
}

func (mm *MempoolManager) Mempool() Mempool {
	mm.RLock()
	defer mm.RUnlock()

	return mm.mp
}

func (mm *MempoolManager) AddBlock(txns []*MsgDeSoTxn) error {
	mm.RLock()
	defer mm.RUnlock()

	// Only hold read-lock because we are only retrieving the mempool instance like in Mempool().
	// Add the block transactions to the mempool one by one.
	return nil
}

func (mm *MempoolManager) RemoveBlock(txns []*MsgDeSoTxn) error {
	mm.RLock()
	defer mm.RUnlock()

	// Only hold read-lock because we are only retrieving the mempool instance like in Mempool().
	// Remove the block transactions from the mempool one by one.
	return nil
}

func (mm *MempoolManager) RefreshMempool() error {
	mm.Lock()
	defer mm.Unlock()

	// Hold write-lock because we will be modifying the mempool instance.
	// This function will retrieve all the transactions from the mempool and then re-add them one by one. This will
	// remove the stale transactions from the mempool.
	return nil
}
