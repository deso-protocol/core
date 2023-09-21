package consensus

import (
	"time"

	"github.com/pkg/errors"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
)

func NewFastHotStuffEventLoop() *FastHotStuffEventLoop {
	return &FastHotStuffEventLoop{
		status:                    consensusStatusNotInitialized,
		nextBlockConstructionTask: NewScheduledTask[uint64](),
		nextTimeoutTask:           NewScheduledTask[uint64](),
	}
}

// Initializes the consensus instance with the latest known valid block in the blockchain, and
// the validator set for the next block height. The functions expects the following for the input
// params:
//   - blockConstructionInterval: block construction duration must be > 0
//   - timeoutBaseDuration: timeout base duration must be > 0
//   - tip: the current tip of the blockchain, with the validator set at that block height
//   - safeBlocks: an unordered slice of blocks including the committed tip, the uncommitted tip,
//     all ancestors of the uncommitted tip that are safe to extend from, and all blocks from forks
//     that are safe to extend from. This function does not validate the collection of blocks. It
//     expects caller to know and decide what blocks are safe to extend from.
//
// Given the above, This function updates the tip internally, stores the safe blocks, and re-initializes
// all internal data structures that are used to track incoming votes and timeout messages for QC construction.
func (fc *FastHotStuffEventLoop) Init(
	blockConstructionInterval time.Duration,
	timeoutBaseDuration time.Duration,
	tip BlockWithValidators,
	safeBlocks []BlockWithValidators,
) error {
	// Grab the consensus instance's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the consensus instance is not already running
	if fc.status == consensusStatusRunning {
		return errors.New("FastHotStuffEventLoop.Init: Consensus instance is already running")
	}

	// Validate the scheduled task durations
	if blockConstructionInterval <= 0 {
		return errors.New("FastHotStuffEventLoop.Init: Block construction duration must be > 0")
	}
	if timeoutBaseDuration <= 0 {
		return errors.New("FastHotStuffEventLoop.Init: Timeout base duration must be > 0")
	}

	// Validate the safe blocks and validator sets, and store them
	if err := fc.storeBlocks(tip, safeBlocks); err != nil {
		return errors.Wrap(err, "FastHotStuffEventLoop.Init: ")
	}

	// We track the current view here so we know which view to time out on later on.
	fc.currentView = safeBlocks[len(safeBlocks)-1].Block.GetView() + 1

	// Reset all internal data structures for votes and timeouts
	fc.votesSeen = make(map[[32]byte]map[string]VoteMessage)
	fc.timeoutsSeen = make(map[uint64]map[string]TimeoutMessage)

	// Reset the external channel used for signaling
	fc.ConsensusEvents = make(chan *ConsensusEvent, signalChannelBufferSize)

	// Set the block construction and timeout base durations
	fc.blockConstructionInterval = blockConstructionInterval
	fc.timeoutBaseDuration = timeoutBaseDuration

	// Update the consensus status
	fc.status = consensusStatusInitialized

	return nil
}

// AdvanceView is called when the tip has not changed but the consensus instance has timed out. This
// function advances the view and resets the timeout scheduled task and block production scheduled
// tasks.
func (fc *FastHotStuffEventLoop) AdvanceView() (uint64, error) {
	// Grab the consensus instance's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the consensus instance is running. This guarantees that the chain tip and validator set
	// have already been set.
	if fc.status != consensusStatusRunning {
		return 0, errors.New("FastHotStuffEventLoop.AdvanceView: Consensus instance is not running")
	}

	// Advance the view
	fc.currentView++

	// Evict all stale votes and timeouts
	fc.evictStaleVotesAndTimeouts()

	// Schedule the next block construction and timeout scheduled tasks
	fc.resetScheduledTasks()

	return fc.currentView, nil
}

// ProcessTipBlock must only be called when the caller has accepted a new block, connected it
// to the tip of the blockchain, and determined that the block is safe to vote on. Given such a
// block, this function resets internal state and schedules the next block construction and timeout
// timers.
//
// Expected params:
//   - tip: the current tip of the blockchain, with the validator set at that block height
//   - safeBlocks: an unordered slice of blocks including the committed tip, the uncommitted tip,
//     all ancestors of the uncommitted tip that are safe to extend from, and all blocks from forks
//     that are safe to extend from. This function does not validate the collection of blocks. It
//     expects the caller to know and decide what blocks are safe to extend from.
func (fc *FastHotStuffEventLoop) ProcessTipBlock(tip BlockWithValidators, safeBlocks []BlockWithValidators) error {
	// Grab the consensus instance's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the consensus instance is running
	if fc.status != consensusStatusRunning {
		return errors.New("FastHotStuffEventLoop.ProcessTipBlock: Consensus instance is not running")
	}

	// Validate the safe blocks and validator sets, and store them
	if err := fc.storeBlocks(tip, safeBlocks); err != nil {
		return errors.Wrap(err, "FastHotStuffEventLoop.ProcessTipBlock: ")
	}

	// We track the current view here so we know which view to time out on later on.
	fc.currentView = fc.tip.block.GetView() + 1

	// Evict all stale votes and timeouts
	fc.evictStaleVotesAndTimeouts()

	// Signal the caller that we can vote for the block. The caller will decide whether to construct and
	// broadcast the vote.
	fc.ConsensusEvents <- &ConsensusEvent{
		EventType:   ConsensusEventTypeVote,
		BlockHash:   fc.tip.block.GetBlockHash(),
		BlockHeight: fc.tip.block.GetHeight(),
		View:        fc.tip.block.GetView(),
	}

	// Schedule the next block construction and timeout scheduled tasks
	fc.resetScheduledTasks()

	return nil
}

// setSafeBlocks is a helper function that validates the provided blocks, validator sets, and stores them.
// It must be called while holding the consensus instance's lock.
func (fc *FastHotStuffEventLoop) storeBlocks(tip BlockWithValidators, safeBlocks []BlockWithValidators) error {
	// Do a basic integrity check on the tip block and validator set
	if !isProperlyFormedBlock(tip.Block) || !isProperlyFormedValidatorSet(tip.Validators) {
		return errors.New("Invalid tip block or validator set")
	}

	// Do a basic integrity check on the blocks and validator sets
	hasMalformedInput := collections.Any(safeBlocks, func(block BlockWithValidators) bool {
		return !isProperlyFormedBlock(block.Block) || !isProperlyFormedValidatorSet(block.Validators)
	})

	// There must be at least one block
	if len(safeBlocks) == 0 || hasMalformedInput {
		return errors.New("Invalid safe blocks or validator sets")
	}

	// Store the tip block and validator set
	fc.tip = blockWithValidatorLookup{
		block:        tip.Block,
		validatorSet: tip.Validators,
		validatorLookup: collections.ToMap(tip.Validators, func(validator Validator) string {
			return validator.GetPublicKey().ToString()
		}),
	}

	// Store the blocks and validator sets
	fc.safeBlocks = collections.Transform(safeBlocks, func(block BlockWithValidators) blockWithValidatorLookup {
		return blockWithValidatorLookup{
			block:        block.Block,
			validatorSet: block.Validators,
			validatorLookup: collections.ToMap(block.Validators, func(validator Validator) string {
				return validator.GetPublicKey().ToString()
			}),
		}
	})

	return nil
}

// ProcessValidatorVote captures an incoming vote message from a validator. This module has no knowledge
// of who the leader is for a given view, so it is up to the caller to decide whether to process the vote
// message or not. If a vote message is passed here, then the consensus instance will store it until
// it can construct a QC with it or until the vote's view has gone stale.
//
// This function does not directly check if the vote results in a stake weighted super majority vote
// for the target block. Instead, it stores the vote locally and waits for the crank timer to determine
// when to run the super majority vote check, and to signal the caller that we can construct a QC.
//
// Reference implementation:
// https://github.com/deso-protocol/hotstuff_pseudocode/blob/6409b51c3a9a953b383e90619076887e9cebf38d/fast_hotstuff_bls.go#L756
func (fc *FastHotStuffEventLoop) ProcessValidatorVote(vote VoteMessage) error {
	// Grab the consensus instance's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the consensus instance is running. This guarantees that the chain tip and validator set
	// have already been set.
	if fc.status != consensusStatusRunning {
		return errors.New("FastHotStuffEventLoop.ProcessValidatorVote: Consensus instance is not running")
	}

	// Do a basic integrity check on the vote message
	if !isProperlyFormedVote(vote) {
		return errors.New("FastHotStuffEventLoop.ProcessValidatorVote: Malformed vote message")
	}

	// Check if the vote is stale
	if isStaleView(fc.currentView, vote.GetView()) {
		return errors.Errorf("FastHotStuffEventLoop.ProcessValidatorVote: Vote has a stale view %d", vote.GetView())
	}

	// Check if the public key has already voted for this view. The protocol does not allow
	// a validator to vote for more than one block in a given view.
	if fc.hasVotedForView(vote.GetPublicKey(), vote.GetView()) {
		return errors.Errorf(
			"FastHotStuffEventLoop.ProcessValidatorVote: validator %s has already voted for view %d",
			vote.GetPublicKey().ToString(),
			vote.GetView(),
		)
	}

	// Check if the public key has already timed out for this view. The protocol does not allow
	// for a validator to vote for a block in a view that it has already timed out for.
	if fc.hasTimedOutForView(vote.GetPublicKey(), vote.GetView()) {
		return errors.Errorf(
			"FastHotStuffEventLoop.ProcessValidatorVote: validator %s has already timed out for view %d",
			vote.GetPublicKey().ToString(),
			vote.GetView(),
		)
	}

	// Compute the value sha3-256(vote.View, vote.BlockHash)
	voteSignaturePayload := GetVoteSignaturePayload(vote.GetView(), vote.GetBlockHash())

	// Verify the vote signature
	if !isValidSignatureSinglePublicKey(vote.GetPublicKey(), vote.GetSignature(), voteSignaturePayload[:]) {
		return errors.New("FastHotStuffEventLoop.ProcessValidatorVote: Invalid signature")
	}

	// Note: we do not check if the vote is for the current chain tip's blockhash. During leader changes
	// where we will be the next block proposer, it is possible for us to receive a vote for a block that
	// we haven't seen yet, but we will need to construct the QC for the block as we are the next leader.
	// To make this code resilient to these race conditions during leader changes, we simply store the vote
	// as long as it's properly formed and not stale.

	fc.storeVote(voteSignaturePayload, vote)

	return nil
}

// ProcessValidatorTimeout captures an incoming timeout message from a validator. This module has no knowledge
// of who the leader is for a given view, so it is up to the caller to decide whether to process the timeout
// message or not. If a timeout message is passed here, then the consensus instance will store it until
// it can construct a QC with it or until the timeout's view has gone stale.
//
// This function does not directly check if the timeout results in a stake weighted super majority to build
// a timeout QC. Instead, it stores the timeout locally and waits for the block production scheduled task to determine
// when to run the super majority timeout check, and to signal the caller that we can construct a timeout QC.
//
// Reference implementation:
// https://github.com/deso-protocol/hotstuff_pseudocode/blob/6409b51c3a9a953b383e90619076887e9cebf38d/fast_hotstuff_bls.go#L958
func (fc *FastHotStuffEventLoop) ProcessValidatorTimeout(timeout TimeoutMessage) error {
	// Grab the consensus instance's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the consensus instance is running. This guarantees that the chain tip and validator set
	// have already been set.
	if fc.status != consensusStatusRunning {
		return errors.New("FastHotStuffEventLoop.ProcessValidatorTimeout: Consensus instance is not running")
	}

	// Do a basic integrity check on the timeout message
	if !isProperlyFormedTimeout(timeout) {
		return errors.New("FastHotStuffEventLoop.ProcessValidatorTimeout: Malformed timeout message")
	}

	// Check if the timeout is stale
	if isStaleView(fc.currentView, timeout.GetView()) {
		return errors.Errorf("FastHotStuffEventLoop.ProcessValidatorTimeout: Timeout has a stale view %d", timeout.GetView())
	}

	// Check if the public key has already voted for this view. The protocol does not allow
	// a validator to time out for a view it has already voted on.
	if fc.hasVotedForView(timeout.GetPublicKey(), timeout.GetView()) {
		return errors.Errorf(
			"FastHotStuffEventLoop.ProcessValidatorTimeout: validator %s has already voted for view %d",
			timeout.GetPublicKey().ToString(),
			timeout.GetView(),
		)
	}

	// Check if the public key has already timed out for this view. The protocol does not allow
	// for a validator to time out more than once for the same view.
	if fc.hasTimedOutForView(timeout.GetPublicKey(), timeout.GetView()) {
		return errors.Errorf(
			"FastHotStuffEventLoop.ProcessValidatorTimeout: validator %s has already timed out for view %d",
			timeout.GetPublicKey().ToString(),
			timeout.GetView(),
		)
	}

	// Compute the value sha3-256(timeout.View, timeout.HighQC.View)
	timeoutSignaturePayload := GetTimeoutSignaturePayload(timeout.GetView(), timeout.GetHighQC().GetView())

	// Verify the vote signature
	if !isValidSignatureSinglePublicKey(timeout.GetPublicKey(), timeout.GetSignature(), timeoutSignaturePayload[:]) {
		return errors.New("FastHotStuffEventLoop.ProcessValidatorTimeout: Invalid signature")
	}

	// Note: we do not check if the timeout is for the current view. Nodes in the network are expected to have
	// slightly different timings and may be at different views. To make this code resilient to timing
	// differences between nodes, we simply store the timeout as long as it's properly formed and not stale.
	// Stored timeouts will be evicted once we advance beyond them.

	fc.storeTimeout(timeout)

	return nil
}

func (fc *FastHotStuffEventLoop) ConstructVoteQC( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffEventLoop) ConstructTimeoutQC( /* TODO */ ) {
	// TODO
}

// Sets the initial times for the block construction and timeouts and starts scheduled tasks.
func (fc *FastHotStuffEventLoop) Start() {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Check if the consensus instance is either running or uninitialized.
	// If it's running or uninitialized, then there's nothing to do here.
	if fc.status != consensusStatusInitialized {
		return
	}

	// Update the consensus status to mark it as running.
	fc.status = consensusStatusRunning

	// Set the initial block construction and timeout scheduled tasks
	fc.resetScheduledTasks()
}

func (fc *FastHotStuffEventLoop) Stop() {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Check if the consensus instance is no longer running. If it's not running
	// we can simply return here.
	if fc.status != consensusStatusRunning {
		return
	}

	// Cancel the next block construction and timeout scheduled tasks, if any.
	fc.nextBlockConstructionTask.Cancel()
	fc.nextTimeoutTask.Cancel()

	// Update the consensus status so it is no longer marked as running.
	fc.status = consensusStatusInitialized
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

// resetScheduledTasks recomputes the nextBlockConstructionTimeStamp and nextTimeoutTimeStamp
// values, and reschedules the next block construction and timeout tasks.
func (fc *FastHotStuffEventLoop) resetScheduledTasks() {
	// Compute the next timeout ETA. We use exponential back-off for timeouts when there are
	// multiple consecutive timeouts. We use the difference between the current view and the
	// chain tip's view to determine this. The current view can only drift from the chain tip's
	// view as a result of timeouts. This guarantees that the number of consecutive timeouts is
	// always: max(currentView - tip.block.GetView() - 1, 0).

	timeoutDuration := fc.timeoutBaseDuration

	// Check if we have timed out at for the last n views. If so, we apply exponential
	// back-off to the timeout base duration.
	if fc.tip.block.GetView() < fc.currentView-1 {
		// Note, there is no risk of underflow here because the following is guaranteed:
		// currentView > tip.block.GetView() + 1.
		numTimeouts := fc.currentView - fc.tip.block.GetView() - 1

		// Compute the exponential back-off: nextTimeoutDuration * 2^numTimeouts
		timeoutDuration = fc.timeoutBaseDuration << numTimeouts
	}

	// Schedule the next block construction task. This will run with currentView param.
	fc.nextBlockConstructionTask.Schedule(fc.blockConstructionInterval, fc.currentView, fc.onBlockConstructionScheduledTask)

	// Schedule the next timeout task. This will run with currentView param.
	fc.nextTimeoutTask.Schedule(timeoutDuration, fc.currentView, fc.onTimeoutScheduledTaskExecuted)
}

func (fc *FastHotStuffEventLoop) onBlockConstructionScheduledTask(blockConstructionView uint64) {
	// TODO
}

// When this function is triggered, it means that we have reached out the timeout ETA for the
// timedOutView. In the event of a timeout, we signal the server that we are ready to time out
// and cancel the timeout task.
func (fc *FastHotStuffEventLoop) onTimeoutScheduledTaskExecuted(timedOutView uint64) {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Check if the consensus instance is running. If it's not running, then there's nothing
	// to do here.
	if fc.status != consensusStatusRunning {
		return
	}

	// Check if the timed out view is stale. If it's stale, then there's nothing to do here.
	// The view may be stale in the race condition where the view advanced at the exact moment
	// this task began to execute and wait for the event loop's lock at the top of this function.
	if fc.currentView != timedOutView {
		return
	}

	// Signal the server that we are ready to time out
	fc.ConsensusEvents <- &ConsensusEvent{
		EventType: ConsensusEventTypeTimeout,   // The timeout event type
		View:      timedOutView,                // The view we timed out
		BlockHash: fc.tip.block.GetBlockHash(), // The last block we saw
	}

	// Cancel the timeout task. The server will reschedule it when it advances the view.
	fc.nextTimeoutTask.Cancel()
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
// satisfy nextBlock.GetView() = tip.block.GetView() + 1, which means that currentView = tip.block.GetView() + 1.
// We can safely evict all votes where vote.GetView() < currentView - 1.
// - Timeouts: if the next block were be an empty block with a timeout QC aggregated from timeout messages,
// then it must satisfy nextBlock.GetView() = timeout.GetView() + 1. We can safely evict all timeout messages with
// currentView > timeout.GetView() + 1.
func (fc *FastHotStuffEventLoop) evictStaleVotesAndTimeouts() {
	// Evict stale vote messages
	for blockHash, voters := range fc.votesSeen {
		for _, vote := range voters {
			if isStaleView(fc.currentView, vote.GetView()) {
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
		if isStaleView(fc.currentView, view) {
			delete(fc.timeoutsSeen, view)
		}
	}
}

func (fc *FastHotStuffEventLoop) storeVote(signaturePayload [32]byte, vote VoteMessage) {
	votesForBlockHash, ok := fc.votesSeen[signaturePayload]
	if !ok {
		votesForBlockHash = make(map[string]VoteMessage)
		fc.votesSeen[signaturePayload] = votesForBlockHash
	}

	votesForBlockHash[vote.GetPublicKey().ToString()] = vote
}

func (fc *FastHotStuffEventLoop) hasVotedForView(publicKey *bls.PublicKey, view uint64) bool {
	// This is an O(n) operation that scales with the number of block hashes that we have stored
	// votes for. In practice, n will be very small because we evict stale votes, and server.go
	// will be smart about not processing votes for views we won't be the block proposer for.
	//
	// TODO: We can further optimize this by adding a second map[view][publicKey]VoteMessage, but
	// this is unnecessary for the forseeable future.

	// Compute the string encoding for the public key
	publicKeyString := publicKey.ToString()

	// Search for the public key's votes across all existing block hashes
	for _, votesForBlock := range fc.votesSeen {
		vote, ok := votesForBlock[publicKeyString]
		if ok && vote.GetView() == view {
			return true
		}
	}

	return false
}

func (fc *FastHotStuffEventLoop) storeTimeout(timeout TimeoutMessage) {
	timeoutsForView, ok := fc.timeoutsSeen[timeout.GetView()]
	if !ok {
		timeoutsForView = make(map[string]TimeoutMessage)
		fc.timeoutsSeen[timeout.GetView()] = timeoutsForView
	}

	timeoutsForView[timeout.GetPublicKey().ToString()] = timeout
}

func (fc *FastHotStuffEventLoop) hasTimedOutForView(publicKey *bls.PublicKey, view uint64) bool {
	timeoutsForView, ok := fc.timeoutsSeen[view]
	if !ok {
		return false
	}

	// If the public key exists for the view, then we know the validator has sent a valid
	// timeout message for the view.
	_, ok = timeoutsForView[publicKey.ToString()]
	return ok
}

func (fc *FastHotStuffEventLoop) getBlockAndValidatorSetByHash(blockHash BlockHash) (
	bool, Block, []Validator, map[string]Validator,
) {
	// A linear search here is fine. The safeBlocks slice is expected to be extremely small as it represents the
	// number of uncommitted blocks in the blockchain. During steady stake, it will have a size of 3 blocks
	// (one committed, two uncommitted). In the worse case, where the network has an unlucky series of
	// timeout -> block -> timeout -> block,... it can still be expected to have < 10 blocks.
	blockHashValue := blockHash.GetValue()
	for _, block := range fc.safeBlocks {
		if block.block.GetBlockHash().GetValue() == blockHashValue {
			return true, block.block, block.validatorSet, block.validatorLookup
		}
	}

	return false, nil, nil, nil
}

func isStaleView(currentView uint64, testView uint64) bool {
	return currentView > testView+1
}
