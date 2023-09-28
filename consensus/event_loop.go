package consensus

import (
	"time"

	"github.com/holiman/uint256"
	"github.com/pkg/errors"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/collections/bitset"
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
//   - tip: the current tip of the blockchain, with the validator set at that block height. This may
//     be a committed or uncommitted block.
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
	fc.currentView = tip.Block.GetView() + 1

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
//   - tip: the current uncommitted tip of the blockchain, with the validator set at that block height
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
		EventType:      ConsensusEventTypeVote,
		TipBlockHash:   fc.tip.block.GetBlockHash(),
		TipBlockHeight: fc.tip.block.GetHeight(),
		View:           fc.tip.block.GetView(),
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
	fc.nextBlockConstructionTask.Schedule(fc.blockConstructionInterval, fc.currentView, fc.onBlockConstructionScheduledTaskExecuted)

	// Schedule the next timeout task. This will run with currentView param.
	fc.nextTimeoutTask.Schedule(timeoutDuration, fc.currentView, fc.onTimeoutScheduledTaskExecuted)
}

// When this function is triggered, it means that we have reached the block construction
// time ETA for blockConstructionView. If we have a QC or timeout QC for the view, then we
// signal the server.
func (fc *FastHotStuffEventLoop) onBlockConstructionScheduledTaskExecuted(blockConstructionView uint64) {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Check if the consensus instance is running. If it's not running, then there's nothing
	// to do here.
	if fc.status != consensusStatusRunning {
		return
	}

	// Check for race conditions where the view advanced at the exact moment this task began
	// or we have already signaled for this view. If so, then there's nothing to do here.
	if fc.currentView != blockConstructionView {
		return
	}

	// Check if the conditions are met to construct a QC from votes for the chain tip. If so,
	// we send a signal to the server and cancel the block construction task. The server will
	// reschedule the task when it advances the view.
	if success, signersList, signature := fc.tryConstructVoteQCInCurrentView(); success {
		// Signal the server that we can construct a QC for the chain tip
		fc.ConsensusEvents <- &ConsensusEvent{
			EventType:      ConsensusEventTypeConstructVoteQC, // The event type
			View:           fc.currentView,                    // The current view in which we can construct a block
			TipBlockHash:   fc.tip.block.GetBlockHash(),       // Block hash for the tip, which we are extending from
			TipBlockHeight: fc.tip.block.GetHeight(),          // Block height for the tip, which we are extending from
			QC: &quorumCertificate{
				blockHash: fc.tip.block.GetBlockHash(), // Block hash for the tip, which we are extending from
				view:      fc.tip.block.GetView(),      // The view from the tip block. This is always fc.currentView - 1
				aggregatedSignature: &aggregatedSignature{
					signersList: signersList, // The signers list who voted on the tip block
					signature:   signature,   // Aggregated signature from votes on the tip block
				},
			},
		}

		return
	}

	// Check if we have enough timeouts to build an aggregate QC for the previous view. If so,
	// we send a signal to the server and cancel all scheduled tasks.
	if success, previousBlock, highQC, highQCViews, signersList, signature := fc.tryConstructTimeoutQCInCurrentView(); success {
		// Signal the server that we can construct a timeout QC for the current view
		fc.ConsensusEvents <- &ConsensusEvent{
			EventType:   ConsensusEventTypeConstructTimeoutQC, // The event type
			View:        fc.currentView,                       // The view that we have a timeout QC for
			BlockHash:   highQC.GetBlockHash(),                // The block hash we can build the aggregate QC from
			BlockHeight: previousBlock.GetHeight() + 1,        // The block height we can propose a block with this timeout aggregate QC
			AggregateQC: &aggregateQuorumCertificate{
				view:        fc.currentView - 1, // The timed out view is always the previous view
				highQC:      highQC,             // The high QC aggregated from the timeout messages
				highQCViews: highQCViews,        // The high view for each validator who timed out
				aggregatedSignature: &aggregatedSignature{
					signersList: signersList, // The signers list of validators who timed out
					signature:   signature,   // The aggregated signature from validators who timed out
				},
			},
		}

		// Cancel the block construction task since we know we can construct a timeout QC in the current view.
		// It will be rescheduled when we advance view.
		fc.nextBlockConstructionTask.Cancel()
		return
	}

	// We have not found a super majority of votes or timeouts. We can schedule the task to check again later.
	fc.nextBlockConstructionTask.Schedule(
		fc.blockConstructionInterval,
		fc.currentView,
		fc.onBlockConstructionScheduledTaskExecuted,
	)

	return
}

// tryConstructVoteQCInCurrentView is a helper function that attempts to construct a QC for the tip block
// so that it can be proposed in a block in the current view. The function internally performs all view and vote
// validations to ensure that the resulting QC is valid. If a QC can be constructed, the function returns
// the signers list and aggregate signature that can be used to construct the QC.
//
// This function must be called while holding the consensus instance's lock.
func (fc *FastHotStuffEventLoop) tryConstructVoteQCInCurrentView() (
	_success bool, // true if and only if we are able to construct a vote QC for the tip block in the current view
	_signersList *bitset.Bitset, // bitset of signers for the aggregated signature for the tip block
	_aggregateSignature *bls.Signature, // aggregated signature for the tip block
) {
	// If currentView != tipBlock.View + 1, then we have timed out at some point, and can no longer
	// construct a block with a QC of votes for the tip block.
	tipBlock := fc.tip.block
	if fc.currentView != tipBlock.GetView()+1 {
		return false, nil, nil
	}

	// Fetch the validator set at the tip.
	validatorSet := fc.tip.validatorSet

	// Compute the chain tip's signature payload.
	voteSignaturePayload := GetVoteSignaturePayload(tipBlock.GetView(), tipBlock.GetBlockHash())

	// Fetch the validator votes for the tip block.
	votesByValidator := fc.votesSeen[voteSignaturePayload]

	// Compute the total stake and total stake with votes
	totalStake := uint256.NewInt()
	totalVotingStake := uint256.NewInt()

	// Track the signatures and signers list for the chain tip
	signersList := bitset.NewBitset()
	signatures := []*bls.Signature{}

	// Iterate through the entire validator set and check if each one has voted for the tip block. Track
	// all voters and their stakes.
	for ii, validator := range validatorSet {
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

		// Track the vote's signature, stake, and place in the validator set
		totalVotingStake = uint256.NewInt().Add(totalVotingStake, validator.GetStakeAmount())
		signersList.Set(ii, true)
		signatures = append(signatures, vote.GetSignature())
	}

	// If we don't have a super-majority vote for the chain tip, then we can't build a QC.
	if !isSuperMajorityStake(totalVotingStake, totalStake) {
		return false, nil, nil
	}

	// If we reach this point, then we have enough signatures to build a QC for the tip block. Try to
	// aggregate the signatures. This should never fail.
	aggregateSignature, err := bls.AggregateSignatures(signatures)
	if err != nil {
		return false, nil, nil
	}

	// Happy path
	return true, signersList, aggregateSignature
}

func (fc *FastHotStuffEventLoop) tryConstructTimeoutQCInCurrentView() (
	_success bool, // true if and only if we are able to construct a timeout QC in the current view
	_previousBlock Block, // the safe block that the high QC is for; the timeout QC will be proposed extending from block
	_highQC QuorumCertificate, // high QC aggregated from validators who timed out
	_highQCViews []uint64, // high QC views for each validator who timed out
	_signersList *bitset.Bitset, // bitset of signers for the aggregated signature from the timeout messages
	_aggregatedSignature *bls.Signature, // aggregated signature from the validators' timeout messages
) {

	// Fetch all timeouts for the previous view. All timeout messages for a view are aggregated and
	// proposed in the next view. So if we want to propose a timeout QC in the current view, we need
	// to aggregate timeouts from the previous one.
	timeoutsByValidator := fc.timeoutsSeen[fc.currentView-1]

	// Tracks the highQC from validators as we go along.
	var validatorsHighQC QuorumCertificate

	// Iterate through all timeouts for the previous view to find the highQC
	for _, timeout := range timeoutsByValidator {
		// Check if the high QC from the timeout messages is for a block in our safeBlocks slice. If not,
		// then we have no knowledge of the block, or the block is not safe to extend from. This should never
		// happen, but may be possible in the event we receive a timeout message at the same time the block is
		// becomes unsafe to extend from (ex: it's part of an stale reorg). We check for the edge case here to
		// be 100% safe.
		isSafeBlock, _, _, validatorSetAtBlock := fc.getBlockAndValidatorSetByHash(timeout.GetHighQC().GetBlockHash())
		if !isSafeBlock {
			continue
		}

		// Make sure the timeout message was sent by a validator registered at the block height of the extracted QC.
		if _, ok := validatorSetAtBlock[timeout.GetPublicKey().ToString()]; !ok {
			continue
		}

		// Update the highQC if the timeout message has a higher QC view than the current highQC's view
		if isInterfaceNil(validatorsHighQC) || timeout.GetHighQC().GetView() > validatorsHighQC.GetView() {
			validatorsHighQC = timeout.GetHighQC()
		}
	}

	// If we didn't find a high QC or didn't find any valid timeout messages, then we can't build a timeout QC.
	if isInterfaceNil(validatorsHighQC) {
		return false, nil, nil, nil, nil, nil
	}

	// Fetch the validator set for the block height of the high QC. This lookup is guaranteed to succeed
	// because it succeeded above.
	ok, previousBlock, validatorSet, _ := fc.getBlockAndValidatorSetByHash(validatorsHighQC.GetBlockHash())
	if !ok {
		return false, nil, nil, nil, nil, nil
	}

	// Compute the total stake and total stake with timeouts
	totalStake := uint256.NewInt()
	totalTimedOutStake := uint256.NewInt()

	// Track the high QC view for each validator
	highQCViews := make([]uint64, len(validatorSet))

	// Track the signatures and signers list for validators who timed out
	signersList := bitset.NewBitset()
	signatures := []*bls.Signature{}

	// Iterate through the entire validator set and check if each one has timed out for the previous
	// view. Track all validators who timed out and their stakes. We iterate through the validator set
	// here rather than the timeoutsByValidator map because we want to preserve the order of the validator
	// for the signersList bitset. In practice, the validator set is expected to be <= 1000 in size, so
	// this loop will be fast.
	for ii, validator := range validatorSet {
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
		return false, nil, nil, nil, nil, nil
	}

	// Finally aggregate the signatures from the timeouts
	aggregateSignature, err := bls.AggregateSignatures(signatures)
	if err != nil {
		return false, nil, nil, nil, nil, nil
	}

	// Happy path
	return true, previousBlock, validatorsHighQC, highQCViews, signersList, aggregateSignature
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
		EventType:      ConsensusEventTypeTimeout,   // The timeout event type
		View:           timedOutView,                // The view we timed out
		TipBlockHash:   fc.tip.block.GetBlockHash(), // The last block we saw
		TipBlockHeight: fc.tip.block.GetHeight(),    // The last block we saw
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
