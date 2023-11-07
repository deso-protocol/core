package lib

import (
	"sync"

	"github.com/deso-protocol/core/consensus"
)

type ConsensusController struct {
	lock                  sync.RWMutex
	fastHotStuffEventLoop consensus.FastHotStuffEventLoop
	blockchain            *Blockchain
}

func NewConsensusController(blockchain *Blockchain) *ConsensusController {
	return &ConsensusController{
		fastHotStuffEventLoop: consensus.NewFastHotStuffEventLoop(),
		blockchain:            blockchain,
	}
}

func (cc *ConsensusController) Init() {
	// This initializes the FastHotStuffEventLoop based on the blockchain state. This should
	// only be called once the blockchain has synced, the node is ready to join the validator
	// network, and the node is able validate blocks in the steady state.
	//
	// TODO: Implement this later once the Blockchain struct changes are merged. We need to be
	// able to fetch the tip block and current persisted view from DB from the Blockchain struct.
}

func (cc *ConsensusController) HandleFastHostStuffBlockProposal(event *consensus.FastHotStuffEvent) {
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

func (cc *ConsensusController) HandleFastHostStuffEmptyTimeoutBlockProposal(event *consensus.FastHotStuffEvent) {
	// The consensus module has signaled that we have a timeout QC and can propose one at a certain
	// block height. We construct an empty block with a timeout QC and broadcast it here:
	// 1. Verify that the block height and view we want to propose at is valid
	// 2. Get a timeout QC from the consensus module
	// 3. Construct a block with the timeout QC
	// 4. Sign the block
	// 5. Process the block locally
	// 6. Broadcast the block to the network
}

func (cc *ConsensusController) HandleFastHostStuffVote(event *consensus.FastHotStuffEvent) {
	// The consensus module has signaled that we can vote on a block. We construct and
	// broadcast the vote here:
	// 1. Verify that the block height we want to vote on is valid
	// 2. Construct the vote message
	// 3. Process the vote in the consensus module
	// 4. Broadcast the timeout msg to the network
}

func (cc *ConsensusController) HandleFastHostStuffTimeout(event *consensus.FastHotStuffEvent) {
	// The consensus module has signaled that we have timed out for a view. We construct and
	// broadcast the timeout here:
	// 1. Verify the block height and view we want to timeout on are valid
	// 2. Construct the timeout message
	// 3. Process the timeout in the consensus module
	// 4. Broadcast the timeout msg to the network
}

func (cc *ConsensusController) HandleHeaderBundle(pp *Peer, msg *MsgDeSoHeaderBundle) {
	// TODO
}

func (cc *ConsensusController) HandleGetBlocks(pp *Peer, msg *MsgDeSoGetBlocks) {
	// TODO
}

func (cc *ConsensusController) HandleHeader(pp *Peer, msg *MsgDeSoHeader) {
	// TODO
}

func (cc *ConsensusController) HandleBlock(pp *Peer, msg *MsgDeSoBlock) {
	// TODO
}
