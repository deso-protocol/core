package lib

import (
	"github.com/golang/glog"
	"time"
)

type MempoolManager struct {
}

func (mm *MempoolManager) NewMempoolManager() *MempoolManager {
	// Start statsd reporter
	if srv.statsdClient != nil {
		srv.StartStatsdReporter()
	}
	return &MempoolManager{}
}

func (mm *MempoolManager) _handleMempool(pp *Peer, msg *MsgDeSoMempool) {
	glog.V(1).Infof("Server._handleMempool: Received Mempool message from Peer %v", pp)

	pp.canReceiveInvMessagess = true
}

func (mm *MempoolManager) StartStatsdReporter() {
	go func() {
	out:
		for {
			select {
			case <-time.After(5 * time.Second):
				tags := []string{}

				// Report mempool size
				mempoolTotal := len(srv.mempool.readOnlyUniversalTransactionList)
				srv.statsdClient.Gauge("MEMPOOL.COUNT", float64(mempoolTotal), tags, 1)

				// Report block + headers height
				blocksHeight := srv.blockchain.BlockTip().Height
				srv.statsdClient.Gauge("BLOCKS.HEIGHT", float64(blocksHeight), tags, 1)

				headersHeight := srv.blockchain.HeaderTip().Height
				srv.statsdClient.Gauge("HEADERS.HEIGHT", float64(headersHeight), tags, 1)

			case <-srv.mempool.quit:
				break out
			}
		}
	}()
}

// It's assumed that the caller will hold the ChainLock for reading so
// that the mempool transactions don't shift under our feet.
func (sm *SyncManager) _handleBlockMainChainConnectedd(event *BlockEvent) {
	blk := event.Block

	// Don't do anything mempool-related until our best block chain is done
	// syncing.
	//
	// We add a second check as an edge-case to protect against when
	// this function is called with an uninitialized blockchain object. This
	// can happen during initChain() for example.
	if srv.blockchain == nil || !srv.blockchain.isInitialized || srv.blockchain.isSyncing() {
		return
	}

	// If we're current, update the mempool to remove the transactions
	// in this block from it. We can't do this in a goroutine because we
	// need each mempool update to happen in the same order as that in which
	// we connected the blocks and this wouldn't be guaranteed if we kicked
	// off a goroutine for each update.
	srv.mempool.UpdateAfterConnectBlock(blk)

	blockHash, _ := blk.Header.Hash()
	glog.V(1).Infof("_handleBlockMainChainConnected: Block %s height %d connected to "+
		"main chain and chain is current.", hex.EncodeToString(blockHash[:]), blk.Header.Height)
}

// It's assumed that the caller will hold the ChainLock for reading so
// that the mempool transactions don't shift under our feet.
func (sm *SyncManager) _handleBlockMainChainDisconnectedd(event *BlockEvent) {
	blk := event.Block

	// Don't do anything mempool-related until our best block chain is done
	// syncing.
	if srv.blockchain.isSyncing() {
		return
	}

	// If we're current, update the mempool to add back the transactions
	// in this block. We can't do this in a goroutine because we
	// need each mempool update to happen in the same order as that in which
	// we connected the blocks and this wouldn't be guaranteed if we kicked
	// off a goroutine for each update.
	srv.mempool.UpdateAfterDisconnectBlock(blk)

	blockHash, _ := blk.Header.Hash()
	glog.V(1).Infof("_handleBlockMainChainDisconnect: Block %s height %d disconnected from "+
		"main chain and chain is current.", hex.EncodeToString(blockHash[:]), blk.Header.Height)
}

func (sm *SyncManager) _handleBlockAccepted(event *BlockEvent) {
	blk := event.Block

	// Don't relay blocks until our best block chain is done syncing.
	if srv.blockchain.isSyncing() || srv.blockchain.MaxSyncBlockHeight > 0 {
		return
	}

	// Notify the consensus that a block was accepted.
	if srv.fastHotStuffConsensus != nil {
		srv.fastHotStuffConsensus.HandleAcceptedBlock()
	}

	// Construct an inventory vector to relay to peers.
	blockHash, _ := blk.Header.Hash()
	invVect := &InvVect{
		Type: InvTypeBlock,
		Hash: *blockHash,
	}

	// Iterate through all the peers and relay the InvVect to them. This will only
	// actually be relayed if it's not already in the peer's knownInventory.
	allPeers := srv.cmgr.GetAllPeers()
	for _, pp := range allPeers {
		pp.AddDeSoMessage(&MsgDeSoInv{
			InvList: []*InvVect{invVect},
		}, false)
	}
}
