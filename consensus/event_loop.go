package consensus

import (
	"errors"
	"sync"
	"time"
)

func NewFastHotStuffEventLoop() *FastHotStuffEventLoop {
	return &FastHotStuffEventLoop{
		status:     consensusStatusNotInitialized,
		startGroup: sync.WaitGroup{},
		stopGroup:  sync.WaitGroup{},
	}
}

// Initializes the consensus instance with the latest known valid block in the blockchain, and
// the validator set for the next block height. The functions expects the following for the input
// params:
//   - blockConstructionCadence: block construction duration must be > 0
//   - timeoutBaseDuration: timeout base duration must be > 0
//   - chainTip: the input block must have a valid block hash, block height, view, and QC
//   - validators: the validators must be sorted in decreasing order of stake, with a
//     consistent tie breaking scheme. The validator set is expected to be valid for
//     validating votes and timeouts for the next block height.
//
// Given the above, This function updates the chain tip internally, and re-initializes all internal
// data structures that are used to track incoming votes and timeout messages for QC construction.
func (fc *FastHotStuffEventLoop) Init(
	blockConstructionCadence time.Duration,
	timeoutBaseDuration time.Duration,
	chainTip Block,
	validators []Validator,
) error {
	// Grab the consensus instance's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the consensus instance is not already running
	if fc.status == consensusStatusRunning {
		return errors.New("FastHotStuffEventLoop.Init: Consensus instance is already running")
	}

	// Validate the timer durations
	if blockConstructionCadence <= 0 {
		return errors.New("FastHotStuffEventLoop.Init: Block construction duration must be > 0")
	}
	if timeoutBaseDuration <= 0 {
		return errors.New("FastHotStuffEventLoop.Init: Timeout base duration must be > 0")
	}

	// Validate the integrity of the block
	if !isProperlyFormedBlock(chainTip) {
		return errors.New("FastHotStuffEventLoop.Init: Invalid block")
	}

	// Validate the integrity of the validator set
	if !isProperlyFormedValidatorSet(validators) {
		return errors.New("FastHotStuffEventLoop.Init: Invalid validator set")
	}

	// Update the latest safe block and validator set
	fc.chainTip = chainTip
	fc.currentView = chainTip.GetView() + 1
	fc.validatorsAtChainTip = validators

	// Reset all internal data structures for votes and timeouts
	fc.votesSeen = make(map[[32]byte]map[string]VoteMessage)
	fc.timeoutsSeen = make(map[uint64]map[string]TimeoutMessage)

	// Reset all internal and external channels used for signaling
	fc.resetEventLoopSignal = make(chan interface{}, signalChannelBufferSize)
	fc.stopSignal = make(chan interface{}, signalChannelBufferSize)
	fc.ConsensusEvents = make(chan *ConsensusEvent, signalChannelBufferSize)

	// Set the block construction and timeout base durations
	fc.blockConstructionCadence = blockConstructionCadence
	fc.timeoutBaseDuration = timeoutBaseDuration

	// Update the consensus status
	fc.status = consensusStatusInitialized

	return nil
}

// ProcessSafeBlock must only be called when the caller has accepted a new block, connected it
// to the tip of the blockchain, and determined that the block is safe to vote on. Given such a
// block, this function resets the internal timers and state of the Fast HotStuff consensus that
// determine the next action. The functions expects the following for the input params:
//   - block: the input block that was safely added to the blockchain and is safe to vote on
//   - validators: the validator set for the next block height
func (fc *FastHotStuffEventLoop) ProcessSafeBlock(block Block, validators []Validator) error {
	// Grab the consensus instance's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the consensus instance is running
	if fc.status != consensusStatusRunning {
		return errors.New("FastHotStuffEventLoop.ProcessSafeBlock: Consensus instance is not running")
	}

	// Do a basic integrity check on the block
	if !isProperlyFormedBlock(block) {
		return errors.New("FastHotStuffEventLoop.ProcessSafeBlock: Invalid block")
	}

	// Do a basic integrity check on the validator set
	if !isProperlyFormedValidatorSet(validators) {
		return errors.New("FastHotStuffEventLoop.ProcessSafeBlock: Invalid validator set")
	}

	// Update the chain tip and validator set
	fc.chainTip = block

	// We track the current view here so we know which view to start the timeout timer for.
	fc.currentView = block.GetView() + 1

	// Update the validator set so we know when we have a QC from votes at the next block height
	// and view.
	fc.validatorsAtChainTip = validators

	// Evict all stale votes and timeouts
	fc.evictStaleVotesAndTimeouts()

	// Signal the caller that we can vote for the block. The caller will decide whether to construct and
	// broadcast the vote.
	fc.ConsensusEvents <- &ConsensusEvent{
		EventType:   ConsensusEventTypeVote,
		BlockHash:   fc.chainTip.GetBlockHash(),
		BlockHeight: fc.chainTip.GetHeight(),
		View:        fc.chainTip.GetView(),
	}

	// Signal the event loop to reset the internal timers
	fc.resetEventLoopSignal <- struct{}{}

	return nil
}

func (fc *FastHotStuffEventLoop) UpdateView( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffEventLoop) ProcessVoteMsg( /* TODO */ ) {
	// TODO
}

func (pc *FastHotStuffEventLoop) ProcessTimeoutMsg( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffEventLoop) ConstructVoteQC( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffEventLoop) ConstructTimeoutQC( /* TODO */ ) {
	// TODO
}

// Sets the initial times for the block construction and timeout timers and starts
// the event loop building off of the current chain tip.
func (fc *FastHotStuffEventLoop) Start() {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Check if the consensus instance is either running or uninitialized.
	// If it's running or uninitialized, then there's nothing to do here.
	if fc.status != consensusStatusInitialized {
		return
	}

	// Set the initial times for the block construction and timeout timers
	fc.nextBlockConstructionTimeStamp = time.Now().Add(fc.blockConstructionCadence)
	fc.nextTimeoutTimeStamp = time.Now().Add(fc.timeoutBaseDuration)

	// Kick off the event loop in a separate goroutine
	fc.startGroup.Add(1)
	go fc.runEventLoop()

	// Wait for the event loop to start
	fc.startGroup.Wait()

	// Update the consensus status to mark it as running.
	fc.status = consensusStatusRunning
}

func (fc *FastHotStuffEventLoop) Stop() {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Check if the consensus instance is no longer running. If it's not running
	// we can simply return here.
	if fc.status != consensusStatusRunning {
		return
	}

	// Signal the event loop to stop
	fc.stopGroup.Add(1)
	fc.stopSignal <- struct{}{}

	// Wait for the event loop to stop
	fc.stopGroup.Wait()

	// Update the consensus status
	fc.status = consensusStatusInitialized

	// Close all internal channels used for signaling
	close(fc.resetEventLoopSignal)
	close(fc.stopSignal)
}

// Runs the internal event loop that waits for all internal or external signals. If the
// event loop is running, the consensus instance status must be set to consensusStatusRunning.
// Note, this function does not directly update the consensus status. To simplify the inner
// implementation of the loop, the caller who starts and stops should always be responsible
// for updating the status as it starts and stop the loop.
func (fc *FastHotStuffEventLoop) runEventLoop() {
	// Signal that the event loop has started
	fc.startGroup.Done()

	// Start the event loop
	for {
		select {
		case <-time.After(time.Until(fc.nextBlockConstructionTimeStamp)):
			{
				// TODO
			}
		case <-time.After(time.Until(fc.nextTimeoutTimeStamp)):
			{
				// TODO
			}
		case <-fc.resetEventLoopSignal:
			{
				// TODO
			}
		case <-fc.stopSignal:
			{
				// Signal that the event loop has stopped
				fc.stopGroup.Done()
				return
			}
		}
	}
}

func (fc *FastHotStuffEventLoop) IsInitialized() bool {
	fc.lock.RLock()
	defer fc.lock.RUnlock()

	return fc.status != consensusStatusNotInitialized
}

func (fc *FastHotStuffEventLoop) IsRunning() bool {
	fc.lock.RLock()
	defer fc.lock.RUnlock()

	return fc.status == consensusStatusRunning
}

// Evict all locally stored votes and timeout messages with stale views. We can safely use the current
// view to determine what is stale. The consensus mechanism will never construct a block with a view
// that's lower than its current view. Consider the following:
// - In the event the event update the chain tip, we will vote for that block and the view it was proposed in
// - In the event we locally time out a view locally, we will send a timeout message for that view
//
// In both cases, we will never roll back the chain tip, or decrement the current view to construct a
// conflicting block at that lower view that we have previously voted or timed out on. So we are safe to evict
// locally stored votes and timeout messages with stale views because we expect to never use them for
// block construction.
//
// The eviction works as follows:
// - Votes: if the next block were to be a regular block with a QC aggregated from votes, then the it must
// satisfy nextBlock.GetView() = chainTip.GetView() + 1, which means that currentView = chainTip.GetView() + 1.
// We can safely evict all votes where vote.GetView() < currentView - 1.
// - Timeouts: if the next block were be an empty block with a timeout QC aggregated from timeout messages,
// then it must satisfy nextBlock.GetView() = timeout.GetView() + 1. We can safely evict all timeout messages with
// currentView > timeout.GetView() + 1.
func (fc *FastHotStuffEventLoop) evictStaleVotesAndTimeouts() {
	// Evict stale vote messages
	for blockHash, voters := range fc.votesSeen {
		for _, vote := range voters {
			if fc.currentView > vote.GetView()+1 {
				// Each block is proposed at a known view, and has an immutable block hash. Votes are signed on the
				// tuple (blockhash, view). So, if any vote message for the blockhash has a view that satisfies this
				// condition, then it's guaranteed that all votes for the same block hash have satisfy this condition.
				// We can safely evict all votes for this block hash.
				delete(fc.votesSeen, blockHash)
				break
			}
		}
	}

	// Evict stale timeout messages
	for view := range fc.timeoutsSeen {
		if fc.currentView > view+1 {
			delete(fc.timeoutsSeen, view)
		}
	}
}
