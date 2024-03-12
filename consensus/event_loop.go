package consensus

import (
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/collections/bitset"
)

func NewFastHotStuffEventLoop() *fastHotStuffEventLoop {
	return &fastHotStuffEventLoop{
		status:          eventLoopStatusNotInitialized,
		crankTimerTask:  NewScheduledTask[uint64](),
		nextTimeoutTask: NewScheduledTask[uint64](),
		Events:          make(chan *FastHotStuffEvent, signalChannelBufferSize),
	}
}

// Initializes the consensus event loop with the latest known valid block in the blockchain, and
// the validator list for the next block height. The functions expects the following for the input
// params:
//   - crankTimerInterval: crank timer interval duration must be > 0
//   - timeoutBaseDuration: timeout base duration must be > 0
//   - genesisQC: quorum certificate used as the genesis for the PoS chain. This QC is a trusted input
//     that is used to override the highQC in timeout messages and timeout aggregate QCs when there
//     is a timeout at the first block height of the PoS chain.
//   - tip: the current tip of the blockchain, with the validator list at that block height. This may
//     be a committed or uncommitted block.
//   - safeBlocks: an unordered slice of blocks including the committed tip, the uncommitted tip,
//     all ancestors of the uncommitted tip that are safe to extend from, and all blocks from forks
//     that are safe to extend from. This function does not validate the collection of blocks. It
//     expects the server to know and decide what blocks are safe to extend from.
//
// Given the above, This function updates the tip internally, stores the safe blocks, and re-initializes
// all internal data structures that are used to track incoming votes and timeout messages for QC construction.
func (fc *fastHotStuffEventLoop) Init(
	crankTimerInterval time.Duration,
	timeoutBaseDuration time.Duration,
	genesisQC QuorumCertificate,
	tip BlockWithValidatorList,
	safeBlocks []BlockWithValidatorList,
) error {
	// Grab the event loop's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the event loop is not already running
	if fc.status == eventLoopStatusRunning {
		return errors.New("FastHotStuffEventLoop.Init: event loop is already running")
	}

	// Validate the scheduled task durations
	if crankTimerInterval <= 0 {
		return errors.New("FastHotStuffEventLoop.Init: Crank timer interval must be > 0")
	}
	if timeoutBaseDuration <= 0 {
		return errors.New("FastHotStuffEventLoop.Init: Timeout base duration must be > 0")
	}

	// Store the genesis QC
	fc.genesisQC = genesisQC

	// Validate the safe blocks and validator lists, and store them
	if err := fc.storeBlocks(tip, safeBlocks); err != nil {
		return errors.Wrap(err, "FastHotStuffEventLoop.Init: ")
	}

	// We track the current view here so we know which view to time out on later on.
	fc.currentView = tip.Block.GetView() + 1

	// Reset QC construction status for the current view
	fc.hasCrankTimerRunForCurrentView = false
	fc.hasConstructedQCInCurrentView = false

	// Reset all internal data structures for votes and timeouts
	fc.votesSeenByBlockHash = make(map[BlockHashValue]map[string]VoteMessage)
	fc.timeoutsSeenByView = make(map[uint64]map[string]TimeoutMessage)

	// Set the crank timer interval and timeout base duration
	fc.crankTimerInterval = crankTimerInterval
	fc.timeoutBaseDuration = timeoutBaseDuration

	// Update the event loop's status
	fc.status = eventLoopStatusInitialized

	return nil
}

// GetEvents returns the event loop's external channel for signaling. We need a getter function
// to ensure that this struct implements the FastHotStuffEventLoop interface type.
func (fc *fastHotStuffEventLoop) GetEvents() chan *FastHotStuffEvent {
	return fc.Events
}

// GetCurrentView is a simple getter that returns the event loop's current view. It does not need
// to be thread-safe. The caller is expected to use it in a thread-safe manner, at a time when
// the view is guaranteed to not change.
func (fc *fastHotStuffEventLoop) GetCurrentView() uint64 {
	return fc.currentView
}

// AdvanceViewOnTimeout is called when the tip has not changed but the event loop has timed out. This
// function advances the view and resets the crank timer and timeout scheduled tasks.
func (fc *fastHotStuffEventLoop) AdvanceViewOnTimeout() (uint64, error) {
	// Grab the event loop's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the event loop is running. This guarantees that the chain tip and validator list
	// have already been set.
	if fc.status != eventLoopStatusRunning {
		return 0, errors.New("FastHotStuffEventLoop.AdvanceViewOnTimeout: Event loop is not running")
	}

	// Advance the view
	fc.currentView++

	// Reset QC construction status for the current view
	fc.hasCrankTimerRunForCurrentView = false
	fc.hasConstructedQCInCurrentView = false

	// Evict all stale votes and timeouts
	fc.evictStaleVotesAndTimeouts()

	// Schedule the next crank timer and timeout scheduled tasks
	fc.resetScheduledTasks()

	return fc.currentView, nil
}

// ProcessTipBlock must only be called when the server has accepted a new block, connected it
// to the tip of the blockchain, and determined that the block is safe to vote on. Given such a
// block, this function resets internal state and schedules the next crank timer and timeout
// timer.
//
// Expected params:
//   - tip: the current uncommitted tip of the blockchain, with the validator list at that block height
//   - safeBlocks: an unordered slice of blocks including the committed tip, the uncommitted tip,
//     all ancestors of the uncommitted tip that are safe to extend from, and all blocks from forks
//     that are safe to extend from. This function does not validate the collection of blocks. It
//     expects the server to know and decide what blocks are safe to extend from.
func (fc *fastHotStuffEventLoop) ProcessTipBlock(tip BlockWithValidatorList, safeBlocks []BlockWithValidatorList) error {
	// Grab the event loop's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the event loop is running
	if fc.status != eventLoopStatusRunning {
		return errors.New("FastHotStuffEventLoop.ProcessTipBlock: Event loop is not running")
	}

	// Validate the safe blocks and validator lists, and store them
	if err := fc.storeBlocks(tip, safeBlocks); err != nil {
		return errors.Wrap(err, "FastHotStuffEventLoop.ProcessTipBlock: ")
	}

	// We track the current view here so we know which view to time out on later on.
	fc.currentView = fc.tip.block.GetView() + 1

	// Reset QC construction status for the current view
	fc.hasCrankTimerRunForCurrentView = false
	fc.hasConstructedQCInCurrentView = false

	// Evict all stale votes and timeouts
	fc.evictStaleVotesAndTimeouts()

	// Signal the server that we can vote for the block. The server will decide whether to construct and
	// broadcast the vote.
	fc.emitEvent(&FastHotStuffEvent{
		EventType:      FastHotStuffEventTypeVote,
		TipBlockHash:   fc.tip.block.GetBlockHash(),
		TipBlockHeight: fc.tip.block.GetHeight(),
		View:           fc.tip.block.GetView(),
	})

	// Schedule the next crank timer and timeout scheduled tasks
	fc.resetScheduledTasks()

	return nil
}

// UpdateSafeBlocks is used to update the safe blocks and their validator lists. This function
// can be used instead of the above ProcessTipBlock when a new block has been added to a fork
// in the blockchain, and the server has determined that the fork is safe to extend from. This
// can happen even if the blockchain's current tip does not change.
//
// Expected param:
//   - safeBlocks: an unordered slice of blocks including the committed tip, the uncommitted tip,
//     all ancestors of the uncommitted tip that are safe to extend from, and all blocks from forks
//     that are safe to extend from. This function does not validate the collection of blocks. It
//     expects the server to know and decide what blocks are safe to extend from.
func (fc *fastHotStuffEventLoop) UpdateSafeBlocks(safeBlocks []BlockWithValidatorList) error {
	// Grab the event loop's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the event loop is running
	if fc.status != eventLoopStatusRunning {
		return errors.New("FastHotStuffEventLoop.UpdateSafeBlocks: Event loop is not running")
	}

	// Fetch the current tip block
	tipBlock := BlockWithValidatorList{
		Block:         fc.tip.block,
		ValidatorList: fc.tip.validatorList,
	}

	// Validate the safe blocks and validator lists, and store them
	if err := fc.storeBlocks(tipBlock, safeBlocks); err != nil {
		return errors.Wrap(err, "FastHotStuffEventLoop.ProcessTipBlock: ")
	}

	// Happy path. There's no need to reschedule the crank timer or timeout scheduled tasks here.
	return nil
}

// storeBlocks is a helper function that validates the provided blocks, validator lists, and stores them.
// It must be called while holding the event loop's lock.
func (fc *fastHotStuffEventLoop) storeBlocks(tip BlockWithValidatorList, safeBlocks []BlockWithValidatorList) error {
	// Do a basic integrity check on the tip block and validator list
	if !isProperlyFormedBlockWithValidatorList(tip) {
		return errors.New("Invalid tip block or validator list")
	}

	// Do a basic integrity check on the safe blocks and validator lists
	hasProperlyFormedSafeBlocksAndValidatorLists := collections.All(safeBlocks, isProperlyFormedBlockWithValidatorList)

	// There must be at least one block
	if len(safeBlocks) == 0 || !hasProperlyFormedSafeBlocksAndValidatorLists {
		return errors.New("Invalid safe blocks or validator lists")
	}

	// Sanity check: the tip block and safe blocks must not have lower views than the genesis QC's view.
	if tip.Block.GetView() < fc.genesisQC.GetView() {
		return errors.New("Tip block view must be greater than or equal to the genesis QC view")
	}

	for _, block := range safeBlocks {
		if block.Block.GetView() < fc.genesisQC.GetView() {
			return errors.New("Safe block view must be greater than or equal to the genesis QC view")
		}
	}

	// Extract the block hashes for the tip block and safe blocks
	tipBlockHash := tip.Block.GetBlockHash()
	safeBlockHashes := collections.Transform(safeBlocks, extractBlockHash)

	// The safe blocks must contain the tip block. The tip block can always be extended from.
	if !containsBlockHash(safeBlockHashes, tipBlockHash) {
		return errors.New("Safe blocks do not contain the tip block")
	}

	// Store the tip block and validator list
	fc.tip = blockWithValidatorLookup{
		block:           tip.Block,
		validatorList:   tip.ValidatorList,
		validatorLookup: collections.ToMap(tip.ValidatorList, validatorToPublicKeyString),
	}

	// Store the blocks and validator lists
	fc.safeBlocks = collections.Transform(safeBlocks, func(block BlockWithValidatorList) blockWithValidatorLookup {
		return blockWithValidatorLookup{
			block:           block.Block,
			validatorList:   block.ValidatorList,
			validatorLookup: collections.ToMap(block.ValidatorList, validatorToPublicKeyString),
		}
	})

	return nil
}

// ProcessValidatorVote captures an incoming vote message from a validator. This module has no knowledge
// of who the leader is for a given view, so it is up to the server to decide whether to process the vote
// message or not. If a vote message is passed here, then the event loop will store it until
// it can construct a QC with it or until the vote's view has gone stale.
//
// This function does not directly check if the vote results in a stake weighted super majority vote
// for the target block. Instead, it stores the vote locally and waits for the crank timer to determine
// when to run the super majority vote check, and to signal the server that we can construct a QC.
//
// Reference implementation:
// https://github.com/deso-protocol/hotstuff_pseudocode/blob/6409b51c3a9a953b383e90619076887e9cebf38d/fast_hotstuff_bls.go#L756
func (fc *fastHotStuffEventLoop) ProcessValidatorVote(vote VoteMessage) error {
	// Grab the event loop's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the event loop is running. This guarantees that the chain tip and validator list
	// have already been set.
	if fc.status != eventLoopStatusRunning {
		return errors.New("FastHotStuffEventLoop.ProcessValidatorVote: Event loop is not running")
	}

	// Do a basic integrity check on the vote message
	if !IsProperlyFormedVote(vote) {
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

	// Cache the vote in case we need it for later
	fc.storeVote(voteSignaturePayload, vote)

	// Check if the crank timer has elapsed or the event loop has constructed a QC in the current view.
	// If so, then there's nothing more to do.
	if !fc.hasCrankTimerRunForCurrentView || fc.hasConstructedQCInCurrentView {
		return nil
	}

	// Check if the vote is for the chain tip. If not, then there's nothing more to do.
	if vote.GetBlockHash() != fc.tip.block.GetBlockHash() {
		return nil
	}

	// Check if we have a super-majority vote for the chain tip.
	if voteQCEvent := fc.tryConstructVoteQCInCurrentView(); voteQCEvent != nil {
		// Signal the server that we can construct a QC for the chain tip, and mark that we have
		// constructed a QC for the current view.
		fc.hasConstructedQCInCurrentView = true
		fc.emitEvent(voteQCEvent)
	}

	return nil
}

// ProcessValidatorTimeout captures an incoming timeout message from a validator. This module has no knowledge
// of who the leader is for a given view, so it is up to the server to decide whether to process the timeout
// message or not. If a timeout message is passed here, then the event loop will store it until
// it can construct a QC with it or until the timeout's view has gone stale.
//
// This function does not directly check if the timeout results in a stake weighted super majority to build
// a timeout QC. Instead, it stores the timeout locally and waits for the block production scheduled task to determine
// when to run the super majority timeout check, and to signal the server that we can construct a timeout QC.
//
// Reference implementation:
// https://github.com/deso-protocol/hotstuff_pseudocode/blob/6409b51c3a9a953b383e90619076887e9cebf38d/fast_hotstuff_bls.go#L958
func (fc *fastHotStuffEventLoop) ProcessValidatorTimeout(timeout TimeoutMessage) error {
	// Grab the event loop's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the event loop is running. This guarantees that the chain tip and validator list
	// have already been set.
	if fc.status != eventLoopStatusRunning {
		return errors.New("FastHotStuffEventLoop.ProcessValidatorTimeout: Event loop is not running")
	}

	// Do a basic integrity check on the timeout message
	if !IsProperlyFormedTimeout(timeout) {
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

	// Check if the high QC's block hash is in our safeBlocks slice
	// - If it is, then the high QC's block has already been validated and is safe to extend from
	// - If it's not, then we have no knowledge of the block, or the block is not safe to extend from.
	//   This can happen if the timeout's creator is malicious, or if our node is far enough behind the
	//   blockchain to not have seen the high QC before other nodes have timed out. In either case, the
	//   simple and safe option is to reject the timeout and move on.
	isSafeBlock, _, validatorList, validatorLookup := fc.fetchSafeBlockInfo(timeout.GetHighQC().GetBlockHash())
	if !isSafeBlock {
		return errors.Errorf(
			"FastHotStuffEventLoop.ProcessValidatorTimeout: Timeout from public key %s has an unknown high QC with view %d",
			timeout.GetPublicKey().ToString(),
			timeout.GetView(),
		)
	}

	// Check if the timeout's public key is in the validator set. If it is not, then the sender is not a validator
	// at the block height after the high QC.
	if _, isValidator := validatorLookup[timeout.GetPublicKey().ToString()]; !isValidator {
		return errors.Errorf(
			"FastHotStuffEventLoop.ProcessValidatorTimeout: Sender %s for timeout message is not in the validator list",
			timeout.GetPublicKey().ToString(),
		)
	}

	// Compute the value sha3-256(timeout.View, timeout.HighQC.View)
	timeoutSignaturePayload := GetTimeoutSignaturePayload(timeout.GetView(), timeout.GetHighQC().GetView())

	// Verify the vote signature
	if !isValidSignatureSinglePublicKey(timeout.GetPublicKey(), timeout.GetSignature(), timeoutSignaturePayload[:]) {
		return errors.Errorf(
			"FastHotStuffEventLoop.ProcessValidatorTimeout: Invalid signature in timeout message from validator %s for view %d",
			timeout.GetPublicKey().ToString(),
			timeout.GetView(),
		)
	}

	// Verify the high QC in the timeout message. The highQC is valid if it exactly matches the genesis QC or it is a
	// valid QC signed by a super-majority of validators for a safe block.
	if !IsEqualQC(timeout.GetHighQC(), fc.genesisQC) && !IsValidSuperMajorityQuorumCertificate(timeout.GetHighQC(), validatorList) {
		return errors.Errorf(
			"FastHotStuffEventLoop.ProcessValidatorTimeout: Invalid high QC received in timeout message from validator %s for view %d",
			timeout.GetPublicKey().ToString(),
			timeout.GetView(),
		)
	}

	// Cache the timeout message in case we need it for later
	fc.storeTimeout(timeout)

	// Check if the crank timer has elapsed or the event loop has constructed a QC in the current view.
	// If so, then there's nothing more to do.
	if !fc.hasCrankTimerRunForCurrentView || fc.hasConstructedQCInCurrentView {
		return nil
	}

	// Check if the timeout is not for the previous view. If not, then there's nothing more to do.
	if timeout.GetView() != fc.currentView-1 {
		return nil
	}

	// Check if we have a super-majority of stake has timed out of the previous view. If so, we signal
	// the server that we can construct a timeoutQC in the current view.
	if timeoutQCEvent := fc.tryConstructTimeoutQCInCurrentView(); timeoutQCEvent != nil {
		// Signal the server that we can construct a timeout QC for the current view, and mark
		// that we have constructed a QC for the current view.
		fc.hasConstructedQCInCurrentView = true
		fc.emitEvent(timeoutQCEvent)
	}

	return nil
}

// Sets the initial times for the crank timer and timeouts and starts scheduled tasks.
func (fc *fastHotStuffEventLoop) Start() {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Check if the event loop is either running or uninitialized.
	// If it's running or uninitialized, then there's nothing to do here.
	if fc.status != eventLoopStatusInitialized {
		return
	}

	// Update the event loop's status to mark it as running.
	fc.status = eventLoopStatusRunning

	// Set the initial crank timer and timeout scheduled tasks
	fc.resetScheduledTasks()
}

func (fc *fastHotStuffEventLoop) Stop() {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Check if the event loop is no longer running. If it's not running
	// we can simply return here.
	if fc.status != eventLoopStatusRunning {
		return
	}

	// Cancel the crank timer and timeout scheduled tasks, if any.
	fc.crankTimerTask.Cancel()
	fc.nextTimeoutTask.Cancel()

	// Update the event loop's status so it is no longer marked as running.
	fc.status = eventLoopStatusInitialized
}

func (fc *fastHotStuffEventLoop) IsInitialized() bool {
	fc.lock.RLock()
	defer fc.lock.RUnlock()

	return fc.status != eventLoopStatusNotInitialized
}

func (fc *fastHotStuffEventLoop) IsRunning() bool {
	fc.lock.RLock()
	defer fc.lock.RUnlock()

	return fc.status == eventLoopStatusRunning
}

func (fc *fastHotStuffEventLoop) ToString() string {
	fc.lock.RLock()
	defer fc.lock.RUnlock()

	if fc.status != eventLoopStatusRunning {
		return "FastHotStuffEventLoop is not running"
	}

	// Get the Tip Block
	tipBlock := fc.tip.block

	// Get the votes for the tip
	tipBlockVotePayload := GetVoteSignaturePayload(tipBlock.GetView(), tipBlock.GetBlockHash())
	votesForTip := fc.votesSeenByBlockHash[tipBlockVotePayload]

	// Get the timeouts for the current and previous view
	timeoutsForCurrentView := fc.timeoutsSeenByView[fc.currentView]
	timeoutsForPreviousView := fc.timeoutsSeenByView[fc.currentView-1]

	return fmt.Sprintf(
		"\n====================================== Printing FastHotStuffEventLoop State ======================================"+
			"\n  Status: %d, CurrentView: %d"+
			"\n  Tip Height: %d, Tip Hash: %v, Tip View: %d, Num Safe Blocks: %d"+
			"\n  Crank Duration: %v, Timeout Interval: %v"+
			"\n  Votes For Tip: %d, Timeouts For Current View: %d, Timeouts For Prev View: %d"+
			"\n=================================================================================================================\n",
		fc.status,
		fc.currentView,
		tipBlock.GetHeight(),
		tipBlock.GetBlockHash(),
		tipBlock.GetView(),
		len(fc.safeBlocks),
		fc.crankTimerTask.GetDuration(),
		fc.nextTimeoutTask.GetDuration(),
		len(votesForTip),
		len(timeoutsForCurrentView),
		len(timeoutsForPreviousView),
	)
}

// resetScheduledTasks recomputes the nextBlockConstructionTimeStamp and nextTimeoutTimeStamp
// values, and reschedules the crank timer and timeout tasks.
func (fc *fastHotStuffEventLoop) resetScheduledTasks() {
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
		timeoutDuration = fc.timeoutBaseDuration * time.Duration(powerOfTwo(numTimeouts, maxConsecutiveTimeouts))
	}

	// Schedule the next crank timer task. This will run with currentView param.
	fc.crankTimerTask.Schedule(fc.crankTimerInterval, fc.currentView, fc.onCrankTimerTaskExecuted)

	// Schedule the next timeout task. This will run with currentView param.
	fc.nextTimeoutTask.Schedule(timeoutDuration, fc.currentView, fc.onTimeoutScheduledTaskExecuted)
}

// When this function is triggered, it means that we have reached the crank timer
// time ETA for blockConstructionView. If we have a QC or timeout QC for the view, then we
// signal the server.
func (fc *fastHotStuffEventLoop) onCrankTimerTaskExecuted(blockConstructionView uint64) {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Check if the event loop is running. If it's not running, then there's nothing
	// to do here.
	if fc.status != eventLoopStatusRunning {
		return
	}

	// Check for race conditions where the view advanced at the exact moment this task began
	// or we have already signaled for this view. If so, then there's nothing to do here.
	if fc.currentView != blockConstructionView {
		return
	}

	// Mark that the crank timer has elapsed
	fc.hasCrankTimerRunForCurrentView = true

	// Check if the conditions are met to construct a QC from votes for the chain tip. If so,
	// we send a signal to the server and cancel the crank timer task. The server will
	// reschedule the task when it advances the view.
	if voteQCEvent := fc.tryConstructVoteQCInCurrentView(); voteQCEvent != nil {
		// Signal the server that we can construct a QC for the chain tip
		fc.hasConstructedQCInCurrentView = true
		fc.emitEvent(voteQCEvent)
		return
	}

	// Check if we have enough timeouts to build an aggregate QC for the previous view. If so,
	// we send a signal to the server and cancel all scheduled tasks.
	if timeoutQCEvent := fc.tryConstructTimeoutQCInCurrentView(); timeoutQCEvent != nil {
		// Signal the server that we can construct a timeout QC for the current view
		fc.hasConstructedQCInCurrentView = true
		fc.emitEvent(timeoutQCEvent)
		return
	}
}

// tryConstructVoteQCInCurrentView is a helper function that attempts to construct a QC for the tip block
// so that it can be proposed in a block in the current view. The function internally performs all view and vote
// validations to ensure that the resulting QC is valid. If a QC can be constructed, the function returns
// the signers list and aggregate signature that can be used to construct the QC.
//
// This function must be called while holding the event loop's lock.
func (fc *fastHotStuffEventLoop) tryConstructVoteQCInCurrentView() *FastHotStuffEvent {
	// If currentView != tipBlock.View + 1, then we have timed out at some point, and can no longer
	// construct a block with a QC of votes for the tip block.
	tipBlock := fc.tip.block
	if fc.currentView != tipBlock.GetView()+1 {
		return nil
	}

	// Fetch the validator list at the tip.
	validatorList := fc.tip.validatorList

	// Compute the chain tip's signature payload.
	voteSignaturePayload := GetVoteSignaturePayload(tipBlock.GetView(), tipBlock.GetBlockHash())

	// Fetch the validator votes for the tip block.
	votesByValidator := fc.votesSeenByBlockHash[voteSignaturePayload]

	// Compute the total stake and total stake with votes
	totalStake := uint256.NewInt()
	totalVotingStake := uint256.NewInt()

	// Track the signatures and signers list for the chain tip
	signersList := bitset.NewBitset()
	signatures := []*bls.Signature{}

	// Iterate through the entire validator list and check if each one has voted for the tip block. Track
	// all voters and their stakes.
	for ii, validator := range validatorList {
		totalStake = uint256.NewInt().Add(totalStake, validator.GetStakeAmount())

		// Skip the validator if it hasn't voted for the the block
		vote, hasVoted := votesByValidator[validator.GetPublicKey().ToString()]
		if !hasVoted {
			continue
		}

		// Verify the vote signature
		if !isValidSignatureSinglePublicKey(vote.GetPublicKey(), vote.GetSignature(), voteSignaturePayload[:]) {
			continue
		}

		// Track the vote's signature, stake, and place in the validator list
		totalVotingStake = uint256.NewInt().Add(totalVotingStake, validator.GetStakeAmount())
		signersList.Set(ii, true)
		signatures = append(signatures, vote.GetSignature())
	}

	// If we don't have a super-majority vote for the chain tip, then we can't build a QC.
	if !isSuperMajorityStake(totalVotingStake, totalStake) {
		return nil
	}

	// If we reach this point, then we have enough signatures to build a QC for the tip block. Try to
	// aggregate the signatures. This should never fail.
	aggregateSignature, err := bls.AggregateSignatures(signatures)
	if err != nil {
		// This should never happen. If it does, then we log an error and return.
		glog.Errorf("FastHotStuffEventLoop.tryConstructVoteQCInCurrentView: Failed to aggregate signatures: %v", err)
		return nil
	}

	// Happy path. Construct the QC and return as an event to signal to the server.
	return &FastHotStuffEvent{
		EventType:      FastHotStuffEventTypeConstructVoteQC, // The event type
		View:           fc.currentView,                       // The current view in which we can construct a block
		TipBlockHash:   fc.tip.block.GetBlockHash(),          // Block hash for the tip, which we are extending from
		TipBlockHeight: fc.tip.block.GetHeight(),             // Block height for the tip, which we are extending from
		QC: &quorumCertificate{
			blockHash: fc.tip.block.GetBlockHash(), // Block hash for the tip, which we are extending from
			view:      fc.tip.block.GetView(),      // The view from the tip block. This is always fc.currentView - 1
			aggregatedSignature: &aggregatedSignature{
				signersList: signersList,        // The signers list who voted on the tip block
				signature:   aggregateSignature, // Aggregated signature from votes on the tip block
			},
		},
	}
}

// tryConstructTimeoutQCInCurrentView is a helper function that attempts to construct a timeout QC for the
// previous view, so that it can be proposed in an empty block in the current view. The function internally performs
// all view and timeout message validations to ensure that the resulting timeout QC is valid and extends from a
// known safe block. If a timeout QC can be constructed, the function returns the safe block that it extends
// from, the highQC, highQC views from validator timeout messages, signers list, and aggregate signature needed
// to construct the timeout QC.
//
// This function must be called while holding the consensus instance's lock.
func (fc *fastHotStuffEventLoop) tryConstructTimeoutQCInCurrentView() *FastHotStuffEvent {

	// Fetch all timeouts for the previous view. All timeout messages for a view are aggregated and
	// proposed in the next view. So if we want to propose a timeout QC in the current view, we need
	// to aggregate timeouts from the previous one.
	timeoutsByValidator := fc.timeoutsSeenByView[fc.currentView-1]

	// Tracks the highQC from validators as we go along.
	var validatorsHighQC QuorumCertificate

	// Iterate through all timeouts for the previous view to find the highQC
	for _, timeout := range timeoutsByValidator {
		// Check if the high QC from the timeout messages is for a block in our safeBlocks slice. If not,
		// then we have no knowledge of the block, or the block is not safe to extend from. This should never
		// happen, but may be possible in the event we receive a timeout message at the same time the block
		// becomes unsafe to extend from (ex: it's part of an stale reorg). We check for the edge case here to
		// be 100% safe.
		isSafeBlock, _, _, validatorLookup := fc.fetchSafeBlockInfo(timeout.GetHighQC().GetBlockHash())
		if !isSafeBlock {
			continue
		}

		// Make sure the timeout message was sent by a validator registered at the block height of the extracted QC.
		if _, ok := validatorLookup[timeout.GetPublicKey().ToString()]; !ok {
			continue
		}

		// Update the highQC if the timeout message has a higher QC view than the current highQC's view
		if isInterfaceNil(validatorsHighQC) || timeout.GetHighQC().GetView() > validatorsHighQC.GetView() {
			validatorsHighQC = timeout.GetHighQC()
		}
	}

	// If we didn't find a high QC or didn't find any valid timeout messages, then we can't build a timeout QC.
	if isInterfaceNil(validatorsHighQC) {
		return nil
	}

	// Fetch the validator list for the block height of the high QC. This lookup is guaranteed to succeed
	// because it succeeded above.
	ok, safeBlock, validatorList, _ := fc.fetchSafeBlockInfo(validatorsHighQC.GetBlockHash())
	if !ok {
		return nil
	}

	// Compute the total stake and total stake with timeouts
	totalStake := uint256.NewInt()
	totalTimedOutStake := uint256.NewInt()

	// Track the high QC view for each validator
	highQCViews := make([]uint64, len(validatorList))

	// Track the signatures and signers list for validators who timed out
	signersList := bitset.NewBitset()
	signatures := []*bls.Signature{}

	// Iterate through the entire validator list and check if each one has timed out for the previous
	// view. Track all validators who timed out and their stakes. We iterate through the validator list
	// here rather than the timeoutsByValidator map because we want to preserve the order of the validator
	// for the signersList bitset. In practice, the validator list is expected to be <= 1000 in size, so
	// this loop will be fast.
	for ii, validator := range validatorList {
		totalStake = uint256.NewInt().Add(totalStake, validator.GetStakeAmount())

		// Skip the validator if it hasn't timed out for the previous view
		timeout, hasTimedOut := timeoutsByValidator[validator.GetPublicKey().ToString()]
		if !hasTimedOut {
			continue
		}

		// Compute the signature payload that the validator should have signed
		signaturePayload := GetTimeoutSignaturePayload(timeout.GetView(), timeout.GetHighQC().GetView())

		// Verify the timeout signature
		if !isValidSignatureSinglePublicKey(timeout.GetPublicKey(), timeout.GetSignature(), signaturePayload[:]) {
			continue
		}

		// Track the signatures, timed out stake, and high QC views for the validator
		totalTimedOutStake = uint256.NewInt().Add(totalTimedOutStake, validator.GetStakeAmount())
		signersList.Set(ii, true)
		signatures = append(signatures, timeout.GetSignature())
		highQCViews[ii] = timeout.GetHighQC().GetView()
	}

	// Check if we have a super majority of stake that has timed out
	if !isSuperMajorityStake(totalTimedOutStake, totalStake) {
		return nil
	}

	// Finally aggregate the signatures from the timeouts
	aggregateSignature, err := bls.AggregateSignatures(signatures)
	if err != nil {
		return nil
	}

	// Happy path
	return &FastHotStuffEvent{
		EventType:      FastHotStuffEventTypeConstructTimeoutQC, // The event type
		View:           fc.currentView,                          // The view that the timeout QC is proposed in
		TipBlockHash:   validatorsHighQC.GetBlockHash(),         // The block hash that we extend from
		TipBlockHeight: safeBlock.GetHeight(),                   // The block height that we extend from
		QC:             validatorsHighQC,                        // The high QC aggregated from the timeout messages
		AggregateQC: &aggregateQuorumCertificate{
			view:        fc.currentView - 1, // The timed out view is always the previous view
			highQC:      validatorsHighQC,   // The high QC aggregated from the timeout messages
			highQCViews: highQCViews,        // The high view for each validator who timed out
			aggregatedSignature: &aggregatedSignature{
				signersList: signersList,        // The signers list of validators who timed out
				signature:   aggregateSignature, // The aggregated signature from validators who timed out
			},
		},
	}
}

// When this function is triggered, it means that we have reached out the timeout ETA for the
// timedOutView. In the event of a timeout, we signal the server that we are ready to time out
// and cancel the timeout task.
func (fc *fastHotStuffEventLoop) onTimeoutScheduledTaskExecuted(timedOutView uint64) {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Check if the event loop is running. If it's not running, then there's nothing
	// to do here.
	if fc.status != eventLoopStatusRunning {
		return
	}

	// Check if the timed out view is stale. If it's stale, then there's nothing to do here.
	// The view may be stale in the race condition where the view advanced at the exact moment
	// this task began to execute and wait for the event loop's lock at the top of this function.
	if fc.currentView != timedOutView {
		return
	}

	// Signal the server that we are ready to time out
	fc.emitEvent(&FastHotStuffEvent{
		EventType:      FastHotStuffEventTypeTimeout, // The timeout event type
		View:           timedOutView,                 // The view we timed out
		TipBlockHash:   fc.tip.block.GetBlockHash(),  // The last block we saw
		TipBlockHeight: fc.tip.block.GetHeight(),     // The last block we saw
	})

	// Cancel the timeout task. The server will reschedule it when it advances the view.
	fc.nextTimeoutTask.Cancel()
}

// Evict all locally stored votes and timeout messages with stale views. We can safely use the current
// view to determine what is stale. The consensus mechanism will never construct a block with a view
// that's lower than its current view. We can use the following to determine which votes & timeouts are
// stale:
// - The currentView value is the view that the next block is going to be proposed on
// - The next block must contain a QC of votes or aggregate QC of timeouts for the previous view
//   - For votes, currentView = vote.GetView() + 1
//   - For timeouts, currentView = timeout.GetView() + 1
//
// Any votes or timeouts with a view that's less than currentView - 1 are stale because they cannot
// be used in the next block or any future blocks.
func (fc *fastHotStuffEventLoop) evictStaleVotesAndTimeouts() {
	// Evict stale vote messages
	for blockHash, voters := range fc.votesSeenByBlockHash {
		for _, vote := range voters {
			if isStaleView(fc.currentView, vote.GetView()) {
				// Each block is proposed at a known view, and has an immutable block hash. Votes are signed on the
				// tuple (blockhash, view). So, if any vote message for the blockhash has a view that satisfies this
				// condition, then it's guaranteed that all votes for the same block hash have satisfy this condition.
				// We can safely evict all votes for this block hash.
				delete(fc.votesSeenByBlockHash, blockHash)
				break
			}
		}
	}

	// Evict stale timeout messages
	for view := range fc.timeoutsSeenByView {
		if isStaleView(fc.currentView, view) {
			delete(fc.timeoutsSeenByView, view)
		}
	}
}

func (fc *fastHotStuffEventLoop) storeVote(signaturePayload [32]byte, vote VoteMessage) {
	votesForBlockHash, ok := fc.votesSeenByBlockHash[signaturePayload]
	if !ok {
		votesForBlockHash = make(map[string]VoteMessage)
		fc.votesSeenByBlockHash[signaturePayload] = votesForBlockHash
	}

	votesForBlockHash[vote.GetPublicKey().ToString()] = vote
}

func (fc *fastHotStuffEventLoop) hasVotedForView(publicKey *bls.PublicKey, view uint64) bool {
	// This is an O(n) operation that scales with the number of block hashes that we have stored
	// votes for. In practice, n will be very small because we evict stale votes, and server.go
	// will be smart about not processing votes for views we won't be the block proposer for.
	//
	// TODO: We can further optimize this by adding a second map[view][publicKey]VoteMessage, but
	// this is unnecessary for the forseeable future.

	// Compute the string encoding for the public key
	publicKeyString := publicKey.ToString()

	// Search for the public key's votes across all existing block hashes
	for _, votesForBlock := range fc.votesSeenByBlockHash {
		vote, ok := votesForBlock[publicKeyString]
		if ok && vote.GetView() == view {
			return true
		}
	}

	return false
}

func (fc *fastHotStuffEventLoop) storeTimeout(timeout TimeoutMessage) {
	timeoutsForView, ok := fc.timeoutsSeenByView[timeout.GetView()]
	if !ok {
		timeoutsForView = make(map[string]TimeoutMessage)
		fc.timeoutsSeenByView[timeout.GetView()] = timeoutsForView
	}

	timeoutsForView[timeout.GetPublicKey().ToString()] = timeout
}

func (fc *fastHotStuffEventLoop) hasTimedOutForView(publicKey *bls.PublicKey, view uint64) bool {
	timeoutsForView, ok := fc.timeoutsSeenByView[view]
	if !ok {
		return false
	}

	// If the public key exists for the view, then we know the validator has sent a valid
	// timeout message for the view.
	_, ok = timeoutsForView[publicKey.ToString()]
	return ok
}

func (fc *fastHotStuffEventLoop) fetchSafeBlockInfo(blockHash BlockHash) (
	_isSafeBlock bool,
	_safeBlock Block,
	_validatorList []Validator,
	_validatorLookup map[string]Validator,
) {
	// A linear search here is fine. The safeBlocks slice is expected to be extremely small as it represents the
	// number of uncommitted blocks in the blockchain. During steady stake, it will have a size of 3 blocks
	// (one committed, two uncommitted). In the worse case, where the network has an unlucky series of
	// timeout -> block -> timeout -> block,... it can still be expected to have < 10 blocks.
	for _, block := range fc.safeBlocks {
		if IsEqualBlockHash(block.block.GetBlockHash(), blockHash) {
			return true, block.block, block.validatorList, block.validatorLookup
		}
	}

	return false, nil, nil, nil
}

// emitEvent emits the event via a non-blocking operation. This ensures that even if the Events channel
// is full, the emit operation completes without blocking. This guarantees that there will be no risk of
// deadlock when a thread holding the event loop's lock is blocked from emitting an event because another
// thread that needs to read an emitted event is blocked from doing so because it needs to first operate
// on the event loop.
func (fc *fastHotStuffEventLoop) emitEvent(event *FastHotStuffEvent) {
	go func() { fc.Events <- event }()
}

func isStaleView(currentView uint64, testView uint64) bool {
	return testView < currentView-1
}
