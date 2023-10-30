package lib

import "github.com/deso-protocol/core/consensus"

func isSynced() bool {
	return false
}

func (srv *Server) _handleFastHostStuffConsensusEvent(event *consensus.FastHotStuffEvent) {
	switch event.EventType {
	case consensus.FastHotStuffEventTypeVote:
		srv._handleFastHostStuffVote(event)
	case consensus.FastHotStuffEventTypeTimeout:
		srv._handleFastHostStuffTimeout(event)
	case consensus.FastHotStuffEventTypeConstructVoteQC:
		srv._handleFastHostStuffBlockProposal(event)
	case consensus.FastHotStuffEventTypeConstructTimeoutQC:
		srv._handleFastHostStuffEmptyTimeoutBlockProposal(event)
	}
}

func (srv *Server) _handleFastHostStuffBlockProposal(event *consensus.FastHotStuffEvent) {
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

func (srv *Server) _handleFastHostStuffEmptyTimeoutBlockProposal(event *consensus.FastHotStuffEvent) {
	// The consensus module has signaled that we have a timeout QC and can propose one at a certain
	// block height. We construct an empty block with a timeout QC and broadcast it here:
	// 1. Verify that the block height and view we want to propose at is valid
	// 2. Get a timeout QC from the consensus module
	// 3. Construct a block with the timeout QC
	// 4. Sign the block
	// 5. Process the block locally
	// 6. Broadcast the block to the network
}

func (srv *Server) _handleFastHostStuffVote(event *consensus.FastHotStuffEvent) {
	// The consensus module has signaled that we can vote on a block. We construct and
	// broadcast the vote here:
	// 1. Verify that the block height we want to vote on is valid
	// 2. Construct the vote message
	// 3. Process the vote in the consensus module
	// 4. Broadcast the timeout msg to the network
}

func (srv *Server) _handleFastHostStuffTimeout(event *consensus.FastHotStuffEvent) {
	// The consensus module has signaled that we have timed out for a view. We construct and
	// broadcast the timeout here:
	// 1. Verify the block height and view we want to timeout on are valid
	// 2. Construct the timeout message
	// 3. Process the timeout in the consensus module
	// 4. Broadcast the timeout msg to the network
}

func (srv *Server) _handleHeaderBundlePoS(pp *Peer, msg *MsgDeSoHeaderBundle) {
	// TODO
}

func (srv *Server) _handleGetBlocksPoS(pp *Peer, msg *MsgDeSoGetBlocks) {
	// TODO
}

func (srv *Server) _handleHeaderPoS(pp *Peer, msg *MsgDeSoHeader) {
	// TODO
}

func (srv *Server) _handleBlockPoS(pp *Peer, msg *MsgDeSoBlock) {
	// TODO
}
