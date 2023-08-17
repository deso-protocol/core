package consensus

import (
	"time"

	"github.com/deso-protocol/core/bls"
)

func NewFastHotStuffConsensus() *FastHotStuffConsensus {
	return &FastHotStuffConsensus{
		internalTimersUpdated: make(chan interface{}),
		votesSeen:             make(map[BlockHash]map[bls.PublicKey]*bls.Signature),
		timeoutsSeen:          make(map[BlockHash]map[bls.PublicKey]*bls.Signature),
		ConsensusEvents:       make(chan *ConsensusEvent),
	}
}

func (fc *FastHotStuffConsensus) Init( /*TODO */ ) {
	// TODO
}

func (fc *FastHotStuffConsensus) UpdateChainTip( /* TODO */ ) {
	// Here there's a bit of a question with regard to what we put here vs what we put
	// in blockchain.go. Right now, blockchain.go does the following:
	// - It holds the index of all blocks we've received and their states
	// - It provides functions you can call to augment that index
	//
	// Overall, it seems to make sense to have blockchain.go do 90% of the work with regard
	// to validating blocks. With this said, below is a proposal for how we can process a
	// block once it's received, while also voting on it:
	// - When a block is received, it first hits server.go.
	// - I recommend we have server.go call ProcessBlockPoS on its blockchain.go object
	//   just like it does today. This means the block will be validated and added to
	//   our indexes *before* touching FastHotStuffConsensus. This means the following fields
	//   will be updated on blockchain.go, and passed in here via tipView:
	//    - The current view
	//    - The highest block we've seen
	//    - The highest QC we've seen
	// - After ProcessBlockPos, server.go should call UpdateChainTip on its FastHotStuffConsensus,
	//   which should bring us here.
	// - This function should then be responsible for the following:
	//   - First, it should determine if we need to reset any of our data structures.
	//     For example, if the current view has increased, then we need to reset
	//     all of our data structures and timeouts. I *think* this is straightforward,
	//     but I haven't fully fleshed out exactly how we determine that we need to do
	//     an update in this function.
	//   - Separately, we need to decide whether or not we want to vote on this block.
	//     I recommend this be handled by a function on the UtxoView like tipView.CanVoteOnBlock().
	//     The reason for this is that the UtxoView is the master of our block state,
	//     and so we can lean on it rather than muddy the logic of this function/struct.
	//   - If we can vote on the block, then we should do so by emitting a ConsensusEvent
	//     back to server.go. Once server.go receives this ConsensusEvent it can then
	//     send the vote to its peers and update blockchain.go to make it aware of the
	//     fact that we have voted on this block (which then can feed back into future
	//     calls to tipView.CanVoteOnBlock() to make sure we don't vote twice). This
	//     can be an actual function on blockchain.go like VoteOnBlock(blockHash *BlockHash)
	//     or something that just updates its indexes accordingly.
	//   - If we can't vote on the block, then I'm not sure we need to do anything here.
	//     If our data structures are in a bad state then we can maybe check and fix that
	//     here.
	//
	// In terms of testing, this function can be fed a UtxoView that has been set up
	// in a certain way, and then it can be verified whether or not its data structures
	// update appropriately. Then, totally separately,
	//
	// ===
	//
	// Below are old raw notes that I had from previous noodling. It would be good for
	// you to read them so you see the iteration with regard to how we want to separate
	// concerns.
	//
	// I think this leads to a rather nice separation of concerns. blockchain.go can
	// be responsible for essentially maintaining and updating our internal index of
	// which blocks we've received, while FastHotStuffConsensus can be responsible for
	// figuring out what events we need to emit to the Server.
	//
	// If we follow this logic, then the decision becomes: What should we put in
	// blockchain.go, and where should we call the function that we put in there?
	// Below is a proposal that I think is coherent:
	// 1. When a block is received, it first hits server.go
	// 2. server.go then calls ProcessBlockPoS on its blockchain.go object to
	//    validate it and to update its internal index. Notice that this will cause
	//    the following fields to update on tipView:

	// I went through the handleBlock function in fast_hotstuff_bls.go to figure out
	// what we want to do here vs what we want to do in blockchain.go. Here's what I
	// think we need in order for this to work:
	// - The current view so that we can compare it to block.View. This information can
	//   live in blockchain.go, and be accessed here only via tipView.
	// - The view that we last voted on so that we can compare it to block.View. This is a
	//   bit tricky. We may need to add a utility on blockchain.go to update it whenever
	//   we vote on something. This can work by emitting a ConsensusEvent from here
	//   that server.go then consumes and uses to update blockchain.go's internal state.
	// - Block validation requires checking the current leader and things like that. This
	//   is something that blockchain.go can handle on its own.
	// - blockchain.go should have everything it needs to validate QCs and signatures.
	// - We need to know what our highestQC is in order to validate the block and in order
	//   for us to be able to vote on a block. I recommend that this logic live in
	//   blockchain.go and we access it through tipView.
	// - After a block has been validated, we need to vote. I recommend that the logic that
	//   figures out if we need to vote or not be the piece that lives here.
}

func (pc *FastHotStuffConsensus) AdvanceView() {
	// The way this function gets called is by emitting a ConsensusEvent to server.go,
	// and then having server.go call this function after it receives the event. This
	// ensures that the server.go event loop's sacred single-threadedness is preserved.
	//
	// In this function we can emit a timeout event to server.go, which can then send
	// the event and maybe update blockchain.go to let it know that we timed out on a
	// particular view or something like that. Anything we need to assemble the timeout
	// message can be gotten via tipView. After we send the ConsensusEvent back to
	// server.go, we can then reset the crank time and the timeout time.
}

func (fc *FastHotStuffConsensus) HandleVoteMessage( /* TODO */ ) {
	// This function is called when server.go receives a vote message. It validates
	// the message and passes it to this function, so this module can store the message
	// for later QC construction at the next block height.
}

func (pc *FastHotStuffConsensus) HandleTimeoutMessage( /* TODO */ ) {
	// This function is called when server.go receives a timeout message. It validates
	// the message and passes it to this function, so this module can store the message
	// for later timeout QC construction at the next block height.
}

func (fc *FastHotStuffConsensus) ConstructVoteQC( /* TODO */ ) {
	// The way this function gets called is by emitting a ConsensusEvent to server.go,
	// and then having server.go call this function after it receives the event. This
	// ensures that the server.go event loop's sacred single-threadedness is preserved.
	//
	// This function would be the "money" function that aggregates all the votes and
	// assembles a QC with all votes for the current chain tip. This QC can be used in
	// the next block.
}

func (fc *FastHotStuffConsensus) ConstructTimeoutQC( /* TODO */ ) {
	// The way this function gets called is by emitting a ConsensusEvent to server.go,
	// and then having server.go call this function after it receives the event. This
	// ensures that the server.go event loop's sacred single-threadedness is preserved.
	//
	// This function would be the "money" function that aggregates all the timeouts and
	// assembles a timeout QC. This QC can be used to construct an empty block.
}

func (fc *FastHotStuffConsensus) Start() {
	for {
		select {
		case <-time.After(time.Until(fc.nextBlockProposalTime)):
			{
				// Signal server.go via the ConsensusEvents channel when we have a QC to construct
				// the next block. This could be a QC for a regular block or a timeout QC for
				// the current view.
				//
				// server.go should always be the main event loop, and we should ensure that
				// everything is happening in a single thread so that we don't have to worry
				// about locking.
			}
		case <-time.After(time.Until(fc.nextTimeoutTime)):
			{
				// Signal server.go via the ConsensusEvents channel when we have timed out
				// for the current view.
				//
				// server.go should always be the main event loop, and we should ensure that
				// everything is happening in a single thread so that we don't have to worry
				// about locking.
			}
		case <-fc.internalTimersUpdated:
			{
				// Anytime nextCrankTime or nextTimeoutTime is updated, this channel
				// should be written to so that the nextBlockProposalTime and nextTimeoutTime
				// values in this select are updated.
			}
		case <-fc.quit:
			{
				// This is how we stop the consensus event loop.
				close(fc.quit)
				return
			}
		}
	}
}

func (fc *FastHotStuffConsensus) Stop() {
	fc.quit <- struct{}{}
}
