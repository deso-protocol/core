package lib

import (
	"encoding/hex"
	"github.com/deso-protocol/core/consensus"
	"github.com/golang/glog"
	"sync"
)

type ConsensusManager struct {
	stm *SteadyManager

	fastHotStuffConsensus *consensus.FastHotStuffConsensus
	bc                    *Blockchain
	mp                    *DeSoMempool
	srv                   *Server
	eventManager          *EventManager

	waitGroup sync.WaitGroup

	exitChan chan struct{}
}

func NewConsensusManager(fastHotStuffConsensus *consensus.FastHotStuffConsensus, bc *Blockchain,
	mp *DeSoMempool, srv *Server, eventManager *EventManager) *ConsensusManager {
	return &ConsensusManager{
		fastHotStuffConsensus: fastHotStuffConsensus,
		bc:                    bc,
		mp:                    mp,
		srv:                   srv,
		eventManager:          eventManager,
		exitChan:              make(chan struct{}),
	}
}

func (cm *ConsensusManager) Init(managers []Manager) {
	for _, manager := range managers {
		if manager.GetType() != ManagerTypeSteady {
			continue
		}
		cm.stm = manager.(*SteadyManager)
	}

	cm.eventManager.OnBlockConnected(cm._handleBlockMainChainConnected)
	cm.eventManager.OnBlockAccepted(cm._handleBlockAccepted)
	cm.eventManager.OnBlockDisconnected(cm._handleBlockMainChainDisconnected)
}

func (cm *ConsensusManager) Start() {
	go cm._startConsensus()
}

func (cm *ConsensusManager) Stop() {
	close(cm.exitChan)
	cm.waitGroup.Wait()
	glog.V(2).Info("ConsensusManager._startConsensus: Server done")
}

func (cm *ConsensusManager) GetType() ManagerType {
	return ManagerTypeConsensus
}

func (cm *ConsensusManager) _handleFastHostStuffBlockProposal(event *consensus.ConsensusEvent) {
	// The consensus module has signaled that we can propose a block at a certain block
	// height. We construct the block and broadcast it here:
	// 1. Verify that the block height we want to propose at is valid
	// 2. Get a QC from the consensus module
	// 3. Iterate over the top n transactions from the mempool
	// 4. Construct a block with the QC and the top n transactions from the mempool
	// 5. Sign the block
	// 6. Process the block locally
	//   - This will connect the block to the blockchain, remove the transactions from the
	//   - mempool, and process the vote in the consensus module
	// 7. Broadcast the block to the network
}

func (cm *ConsensusManager) _handleFastHostStuffVote(event *consensus.ConsensusEvent) {
	// The consensus module has signaled that we can vote on a block. We construct and
	// broadcast the vote here:
	// 1. Verify that the block height we want to vote on is valid
	// 2. Construct the vote message
	// 3. Process the vote in the consensus module
	// 4. Broadcast the timeout msg to the network
}

func (cm *ConsensusManager) _handleFastHostStuffTimeout(event *consensus.ConsensusEvent) {
	// The consensus module has signaled that we have timed out for a view. We construct and
	// broadcast the timeout here:
	// 1. Verify the block height and view we want to timeout on are valid
	// 2. Construct the timeout message
	// 3. Process the timeout in the consensus module
	// 4. Broadcast the timeout msg to the network
}

func (cm *ConsensusManager) _handleFastHostStuffConsensusEvent(event *consensus.ConsensusEvent) {
	switch event.EventType {
	case consensus.ConsensusEventTypeBlockProposal:
		cm._handleFastHostStuffBlockProposal(event)
	case consensus.ConsensusEventTypeVote:
		cm._handleFastHostStuffVote(event)
	case consensus.ConsensusEventTypeTimeout:
		cm._handleFastHostStuffTimeout(event)
	}
}

// _startConsensusEventLoop contains the top-level event loop to run both the PoW and PoS consensus. It is
// single-threaded to ensure that concurrent event do not conflict with each other. It's role is to guarantee
// single threaded processing and act as an entry point for consensus events. It does minimal validation on its
// own.
//
// For the PoW consensus:
// - It listens to all peer messages from the network and handles them as they come in. This includes
// control messages from peer, proposed blocks from peers, votes/timeouts, block requests, mempool
// requests from syncing peers
//
// For the PoS consensus:
// - It listens to all peer messages from the network and handles them as they come in. This includes
// control messages from peer, proposed blocks from peers, votes/timeouts, block requests, mempool
// requests from syncing peers
// - It listens to consensus events from the Fast HostStuff consensus engine. The consensus signals when
// it's ready to vote, timeout, or propose a block.
func (cm *ConsensusManager) _startConsensus() {
	cm.waitGroup.Add(1)
	defer cm.waitGroup.Done()

	for {
		select {
		case consensusEvent := <-cm.fastHotStuffConsensus.ConsensusEvents:
			glog.Infof("ConsensusManager._startConsensus: Received consensus event for block height: %v",
				consensusEvent.BlockHeight)
			cm._handleFastHostStuffConsensusEvent(consensusEvent)
		case <-cm.exitChan:
			return
		}
	}
}

// It's assumed that the caller will hold the ChainLock for reading so
// that the mempool transactions don't shift under our feet.
func (cm *ConsensusManager) _handleBlockMainChainConnected(event *BlockEvent) {
	blk := event.Block

	// Don't do anything mempool-related until our best block chain is done
	// syncing.
	//
	// We add a second check as an edge-case to protect against when
	// this function is called with an uninitialized blockchain object. This
	// can happen during initChain() for example.
	if cm.bc == nil || !cm.bc.isInitialized || cm.bc.isSyncing() {
		return
	}

	// If we're current, update the mempool to remove the transactions
	// in this block from it. We can't do this in a goroutine because we
	// need each mempool update to happen in the same order as that in which
	// we connected the blocks and this wouldn't be guaranteed if we kicked
	// off a goroutine for each update.
	cm.mp.UpdateAfterConnectBlock(blk)

	blockHash, _ := blk.Header.Hash()
	glog.V(1).Infof("ConsensusManager._handleBlockMainChainConnected: Block %s height %d connected to "+
		"main chain and chain is current.", hex.EncodeToString(blockHash[:]), blk.Header.Height)
}

// It's assumed that the caller will hold the ChainLock for reading so
// that the mempool transactions don't shift under our feet.
func (cm *ConsensusManager) _handleBlockMainChainDisconnected(event *BlockEvent) {
	blk := event.Block

	// Don't do anything mempool-related until our best block chain is done
	// syncing.
	if cm.bc.isSyncing() {
		return
	}

	// If we're current, update the mempool to add back the transactions
	// in this block. We can't do this in a goroutine because we
	// need each mempool update to happen in the same order as that in which
	// we connected the blocks and this wouldn't be guaranteed if we kicked
	// off a goroutine for each update.
	cm.mp.UpdateAfterDisconnectBlock(blk)

	blockHash, _ := blk.Header.Hash()
	glog.V(1).Infof("ConsensusManager._handleBlockMainChainDisconnected: Block %s height %d disconnected from "+
		"main chain and chain is current.", hex.EncodeToString(blockHash[:]), blk.Header.Height)
}

func (cm *ConsensusManager) _handleBlockAccepted(event *BlockEvent) {
	blk := event.Block

	// Don't relay blocks until our best block chain is done syncing.
	if cm.bc.isSyncing() || cm.bc.MaxSyncBlockHeight > 0 {
		return
	}

	// Notify the consensus that a block was accepted.
	if cm.fastHotStuffConsensus != nil {
		cm.fastHotStuffConsensus.HandleAcceptedBlock()
	}

	// Construct an inventory vector to relay to peers.
	blockHash, _ := blk.Header.Hash()
	invVect := &InvVect{
		Type: InvTypeBlock,
		Hash: *blockHash,
	}

	// Iterate through all the peers and relay the InvVect to them. This will only
	// actually be relayed if it's not already in the peer's knownInventory.
	allPeers := cm.srv.GetAllPeers()
	for _, peer := range allPeers {
		invMsg := &MsgDeSoInv{
			InvList: []*InvVect{invVect},
		}
		if err := cm.stm.SendInvMessage(invMsg, peer.ID); err != nil {
			glog.V(2).Infof("ConsensusManager._handleBlockAccepted: Problem sending inv message "+
				"to peer (id= %v); err: %v", peer.ID, err)
		}
	}
}
