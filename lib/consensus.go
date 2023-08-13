package lib

import (
	"time"

	"github.com/deso-protocol/core/bls"
)

type VoteMsg struct {
}

type TimeoutMsg struct {
}

type PosBlock struct {
}

// ConsensusEvent is a way for PosConsensus to send messages back to the Server.
// For example, if we need to fetch a missing block or something like that, this
// type of event can be used to communicate that to the Server, which can then
// fetch said block for us (and then later call HandleBlock once it's received).
//
// Using this channel to create a separation also makes testing much easier.
// Rather than having to mock out a whole Server, we can just selectively call
// the functions on PosConsensus in our tests, and then verify that the right
// ConsensusEvents are being sent back to the Server.
type ConsensusEvent struct {
}

type PosConsensus struct {
	// I think the way we're doing timeouts here makes testing much easier. Rather
	// than wait for timeouts, we can just check that our variables have updated as
	// we would expect after calls to particular functions. For example, we can check
	// that nextTimeoutTime has been updated after a call to HandleBlock.
	nextCrankTime     time.Time
	nextTimeoutTime   time.Time
	timeoutUpdateChan chan bool

	// votesSeen is an in-memory map of all the votes we've seen so far, organized
	// by their block hash and then by the public key of the voter.
	votesSeen    map[BlockHash]map[bls.PublicKey]*VoteMsg
	timeoutsSeen map[BlockHash]map[bls.PublicKey]*VoteMsg

	outputEventChan chan *ConsensusEvent
}

func (pc *PosConsensus) UpdateNextCrankTime(newTime time.Time) {
	pc.nextCrankTime = newTime
	// This should be instantly consumed, and so shouldn't block ever
	pc.timeoutUpdateChan <- true
}

func (pc *PosConsensus) UpdateNextTimeoutTime(newTime time.Time) {
	pc.nextTimeoutTime = newTime
	// This should be instantly consumed, and so shouldn't block ever
	pc.timeoutUpdateChan <- true
}

// I want to point out that if you want to be *extremely* hardcore about making things easy
// to test, you could pass the *specific* values that each function needs rather than passing
// it a generic UtxoView. This would make it so that you don't have to mock out the UtxoView
// at all, and can instead pass values directly in a "clean room" of sorts. Not saying we should
// do this, but suggesting it as an alternative to consider when developing.
func (pc *PosConsensus) HandleVote(vote *VoteMsg, tipView *UtxoView) {
	// Things we need in order for this to work (pulling from the hotstuff_pseudocode repo):
	// - What the current view is. tipView can tell us this.
	// - We need to know who's the leader. tipView can tell us this.
	// - We need to know who all the validators are. tipView can tell us this.
	// - We need to know how much stake each person has at this view. tipView can tell us this.
	// - A way to determine if we are the leader right now. tipView can tell us this.
	// - We need to konw all the votes we've seen, and whether we have enough to propose a block.
	//   The votes we've seen are stored in pc.votesSeen.
	// - We need to know the total stake so we can calculate supermajority. tipView can tell us this.
	// - We need to construct a QC. We can do this by looking at the votes we've seen.
	//
	// After we have all of the above, we technically have enough to construct a block and sign it.
	// The question is: Should we do this here or somewhere else?
	//
	// In this case, I think it's clear actually: We don't want to do anything here other than
	// simply add votesSeen to our list. Why? Because we're going to assume that nextCrankTime
	// is going to trigger, and *that's* where we're going to combine all the votesSeen in order
	// to construct the block.
	//
	// If we want, we can just have this function return whether or not the vote is
	// valid given the current state of the tip, which would make it easy to test.
}

func (pc *PosConsensus) HandleBlock(block *PosBlock, tipView *UtxoView) {
	// Here there's a bit of a question with regard to what we put here vs what we put
	// in blockchain.go. Right now, blockchain.go does the following:
	// - It holds the index of all blocks we've received and their states
	// - It provides functions you can call to augment that index
	//
	// Overall, when I looked at it pretty closely, it seemed to make sense to have
	// blockchain.go do 90% of the work with regard to validating blocks. With this
	// said, below is a proposal for how we can process a block once it's received,
	// while also voting on it and whatnot:
	// - When a block is received, it first hits server.go.
	// - I recommend we have server.go call ProcessBlockPoS on its blockchain.go object
	//   just like it does today. This means the block will be validated and added to
	//   our indexes *before* touching PosConsensus. This means the following fields
	//   will be updated on blockchain.go, and passed in here via tipView:
	//    - The current view
	//    - The highest block we've seen
	//    - The highest QC we've seen
	// - After ProcessBlockPos, server.go should call HandleBlock on its PosConsensus,
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
	// which blocks we've received, while PosConsensus can be responsible for
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

func (pc *PosConsensus) HandleTimeout(tipView *UtxoView) {
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

func (pc *PosConsensus) HandleCrank(tipView *UtxoView) {
	// The way this function gets called is by emitting a ConsensusEvent to server.go,
	// and then having server.go call this function after it receives the event. This
	// ensures that the server.go event loop's sacred single-threadedness is preserved.
	//
	// This function would be the "money" function that aggregates all the votes and
	// assembles the block. It's possible that, by the time the crank is called, that
	// we don't have enough votes or timeouts. In this case, we would reset the crank
	// time or something like that in order to ensure we'll try again. We can then keep
	// trying until we either get enough votes or we time out. I don't think there's
	// a need for exponential backoff here, so you can just add a fixed delta to time.Now()
	// and reset the crank time to that.
}

func (pc *PosConsensus) Start() {
	// Set up the nextTimeoutTime and the nextCrankTime based on
	// what's going on in consensus.

	for {
		select {
		case <-time.After(time.Until(pc.nextCrankTime)):
			{
				// Adds something to outputEventChan that is then processed by server.go
				//
				// server.go should always be the main event loop, and we should ensure that
				// everything is happening in a single thread so that we don't have to worry
				// about locking.
			}
		case <-time.After(time.Until(pc.nextTimeoutTime)):
			{
				// Adds something to outputEventChan that is then processed by server.go
				//
				// server.go should always be the main event loop, and we should ensure that
				// everything is happening in a single thread so that we don't have to worry
				// about locking.
			}
		case <-pc.timeoutUpdateChan:
			{
				// Causes the timeouts in this select to update to their latest values.
				// Anytime nextCrankTime or nextTimeoutTime is updated, this channel
				// should be written to so that the timeouts in this select are updated.
			}
		}
	}
}
