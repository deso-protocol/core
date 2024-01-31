package lib

import (
	"fmt"
	"sync"
	"time"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/consensus"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

type FastHotStuffConsensus struct {
	lock                                sync.RWMutex
	blockchain                          *Blockchain
	fastHotStuffEventLoop               consensus.FastHotStuffEventLoop
	mempool                             Mempool
	params                              *DeSoParams
	signer                              *BLSSigner
	blockProductionIntervalMilliseconds uint64
	timeoutBaseDurationMilliseconds     uint64
}

func NewFastHotStuffConsensus(
	params *DeSoParams,
	blockchain *Blockchain,
	mempool Mempool,
	signer *BLSSigner,
	blockProductionIntervalMilliseconds uint64,
	timeoutBaseDurationMilliseconds uint64,
) *FastHotStuffConsensus {
	return &FastHotStuffConsensus{
		blockchain:                          blockchain,
		fastHotStuffEventLoop:               consensus.NewFastHotStuffEventLoop(),
		mempool:                             mempool,
		params:                              params,
		signer:                              signer,
		blockProductionIntervalMilliseconds: blockProductionIntervalMilliseconds,
		timeoutBaseDurationMilliseconds:     timeoutBaseDurationMilliseconds,
	}
}

// FastHotStuffConsensus.Start initializes and starts the FastHotStuffEventLoop based on the
// blockchain state. This should only be called once the blockchain has synced, the node is
// ready to join the validator network, and the node is able to validate blocks in the steady state.
func (cc *FastHotStuffConsensus) Start() error {
	// Hold the consensus' write lock for thread-safety.
	cc.lock.Lock()
	defer cc.lock.Unlock()

	// The consensus can only be kicked off with an uninitialized event loop
	if cc.fastHotStuffEventLoop.IsInitialized() {
		return errors.New("FastHotStuffConsensus.Start: FastHotStuffEventLoop is already initialized")
	}

	// Hold the blockchain's read lock so that the chain cannot be mutated underneath us. In practice,
	// this is a no-op, but it guarantees thread-safety in the event that other parts of the codebase
	// change.
	cc.blockchain.ChainLock.RLock()
	defer cc.blockchain.ChainLock.RUnlock()

	// Fetch the current tip of the chain
	tipBlock := cc.blockchain.BlockTip()
	tipHeight := tipBlock.Header.Height

	// If the chain is not at the final PoW block height or higher, then we cannot start the PoS consensus.
	if cc.blockchain.IsPoWBlockHeight(tipHeight) && !cc.blockchain.IsFinalPoWBlockHeight(tipHeight) {
		return errors.Errorf(
			"FastHotStuffConsensus.Start: Block tip %d is not at the final PoW block height", tipBlock.Height,
		)
	}

	genesisQC, err := cc.blockchain.GetProofOfStakeGenesisQuorumCertificate()
	if err != nil {
		return errors.Errorf("FastHotStuffConsensus.Start: Error creating PoS cutover genesis QC: %v", err)
	}

	// Fetch the validator set at each safe block
	tipBlockWithValidators, err := cc.fetchValidatorListsForSafeBlocks([]*MsgDeSoHeader{tipBlock.Header})
	if err != nil {
		return errors.Errorf("FastHotStuffConsensus.Start: Error fetching validator list for tip blocks: %v", err)
	}

	// Fetch the safe blocks that are eligible to be extended from by the next incoming tip block
	safeBlocks, err := cc.blockchain.GetSafeBlocks()
	if err != nil {
		return errors.Errorf("FastHotStuffConsensus.Start: Error fetching safe blocks: %v", err)
	}

	// Fetch the validator set at each safe block
	safeBlocksWithValidators, err := cc.fetchValidatorListsForSafeBlocks(safeBlocks)
	if err != nil {
		return errors.Errorf("FastHotStuffConsensus.Start: Error fetching validator lists for safe blocks: %v", err)
	}

	// Compute the block production internal and timeout base duration as time.Duration
	blockProductionInterval := time.Millisecond * time.Duration(cc.blockProductionIntervalMilliseconds)
	timeoutBaseDuration := time.Millisecond * time.Duration(cc.timeoutBaseDurationMilliseconds)

	// Initialize and start the event loop
	cc.fastHotStuffEventLoop.Init(blockProductionInterval, timeoutBaseDuration, genesisQC, tipBlockWithValidators[0], safeBlocksWithValidators)
	cc.fastHotStuffEventLoop.Start()

	return nil
}

func (cc *FastHotStuffConsensus) IsRunning() bool {
	return cc.fastHotStuffEventLoop.IsRunning()
}

func (fc *FastHotStuffConsensus) Stop() {
	// Hold the consensus' write lock for thread-safety.
	fc.lock.Lock()
	defer fc.lock.Unlock()

	fc.fastHotStuffEventLoop.Stop()
}

// HandleLocalBlockProposalEvent is called when FastHotStuffEventLoop has signaled that it can
// construct a block at a certain block height. This function validates the block proposal signal,
// constructs, processes locally, and then broadcasts the block.
func (cc *FastHotStuffConsensus) HandleLocalBlockProposalEvent(event *consensus.FastHotStuffEvent) error {
	// Hold a read and write lock on the consensus. This is because we need to check
	// the current view of the consensus event loop, and to update the blockchain.
	cc.lock.Lock()
	defer cc.lock.Unlock()

	if !cc.fastHotStuffEventLoop.IsRunning() {
		return errors.Errorf("FastHotStuffConsensus.HandleLocalBlockProposalEvent: FastHotStuffEventLoop is not running")
	}

	// Hold the blockchain's write lock so that the chain cannot be mutated underneath us.
	// In practice, this is a no-op, but it guarantees thread-safety in the event that other
	// parts of the codebase change.
	cc.blockchain.ChainLock.Lock()
	defer cc.blockchain.ChainLock.Unlock()

	// Handle the event as a block proposal event for a regular block
	if err := cc.handleBlockProposalEvent(event, consensus.FastHotStuffEventTypeConstructVoteQC); err != nil {
		return errors.Wrapf(err, "FastHotStuffConsensus.HandleLocalBlockProposalEvent: ")
	}

	// Happy path: nothing left to do
	return nil
}

// HandleLocalTimeoutBlockProposalEvent is called when FastHotStuffEventLoop has signaled that it can
// construct a timeout block at a certain block height. This function validates the timeout block proposal
// signal, constructs, processes locally, and then broadcasts the block.
func (cc *FastHotStuffConsensus) HandleLocalTimeoutBlockProposalEvent(event *consensus.FastHotStuffEvent) error {
	// Hold a read and write lock on the consensus. This is because we need to check
	// the current view of the consensus event loop, and to update the blockchain.
	cc.lock.Lock()
	defer cc.lock.Unlock()

	if !cc.fastHotStuffEventLoop.IsRunning() {
		return errors.Errorf("FastHotStuffConsensus.HandleLocalTimeoutBlockProposalEvent: FastHotStuffEventLoop is not running")
	}

	// Hold the blockchain's write lock so that the chain cannot be mutated underneath us.
	// In practice, this is a no-op, but it guarantees thread-safety in the event that other
	// parts of the codebase change.
	cc.blockchain.ChainLock.Lock()
	defer cc.blockchain.ChainLock.Unlock()

	// Handle the event as a block proposal event for a timeout block
	if err := cc.handleBlockProposalEvent(event, consensus.FastHotStuffEventTypeConstructTimeoutQC); err != nil {
		return errors.Wrapf(err, "FastHotStuffConsensus.HandleLocalTimeoutBlockProposalEvent: ")
	}

	// Happy path: nothing left to do
	return nil
}

// handleBlockProposalEvent is a helper function that can process a block proposal event for either
// a regular block or a timeout block. It can be called with a expectedEventType param that toggles
// whether the event should be validated and processed as normal block or timeout block proposal.
//
// Steps:
//  1. Validate that the block height and view we want to propose the block with are not stale
//  2. Iterate over the top n transactions from the mempool
//  3. Construct a block with the QC or aggregate QC and the top n transactions from the mempool
//  4. Sign the block
//  5. Process the block locally
//     - This will connect the block to the blockchain, remove the transactions from the
//     mempool, and process the vote in the FastHotStuffEventLoop
//  6. Broadcast the block to the network
func (cc *FastHotStuffConsensus) handleBlockProposalEvent(
	event *consensus.FastHotStuffEvent,
	expectedEventType consensus.FastHotStuffEventType,
) error {
	// Validate that the event's type is the expected proposal event type
	if !isValidBlockProposalEvent(event, expectedEventType) {
		return errors.Errorf("Unexpected event type: %v vs %v", event.EventType, expectedEventType)
	}

	// Validate that the event is properly formed
	if !isProperlyFormedBlockProposalEvent(event) {
		return errors.Errorf("Received improperly formed block construction event: %v", event)
	}

	// Fetch the parent block
	parentBlockHash := BlockHashFromConsensusInterface(event.QC.GetBlockHash())
	parentBlock, parentBlockExists := cc.blockchain.blockIndexByHash[*parentBlockHash]
	if !parentBlockExists {
		return errors.Errorf("Error fetching parent block: %v", parentBlockHash)
	}

	// Make sure that the parent has a validated status. This should never fail. If it does, something is
	// very wrong with the safeBlocks parameter in the FastHotStuffEventLoop.
	if !parentBlock.IsValidated() {
		return errors.Errorf("Parent block is not validated: %v", parentBlockHash)
	}

	// Perform simple block height and view sanity checks on the block construction signal.

	// Cross-validate that the event's tip block height matches the parent's height. If the two don't match
	// then something is very wrong.
	if uint64(parentBlock.Height) != event.TipBlockHeight {
		return errors.Errorf(
			"Error constructing block at height %d. Expected block height %d",
			event.TipBlockHeight+1,
			parentBlock.Height+1,
		)
	}

	// Validate that the event's view is not stale. If the view is stale, then it means that the consensus
	// has advanced to the next view after queuing this block proposal event. This is normal and an expected
	// race condition in the steady-state.
	currentView := cc.fastHotStuffEventLoop.GetCurrentView()
	if currentView > event.View {
		return errors.Errorf(
			"Error constructing block at height %d. Stale view %d",
			event.TipBlockHeight+1,
			event.View,
		)
	}

	// Compute the random seed hash for the previous block's proposer signature
	parentBlockRandomSeedHash, err := HashRandomSeedSignature(parentBlock.Header.ProposerRandomSeedSignature)
	if err != nil {
		return errors.Wrapf(err, "Error computing random seed hash for block at height %d: ", event.TipBlockHeight+1)
	}

	// Compute the next proposer random seed signature
	proposerRandomSeedSignature, err := cc.signer.SignRandomSeedHash(parentBlockRandomSeedHash)
	if err != nil {
		return errors.Wrapf(err, "Error signing random seed hash for block at height %d: ", event.TipBlockHeight+1)
	}

	// Construct the unsigned block
	unsignedBlock, err := cc.produceUnsignedBlockForBlockProposalEvent(event, proposerRandomSeedSignature)
	if err != nil {
		return errors.Wrapf(err, "Error producing unsigned block for proposal at height %d", event.TipBlockHeight+1)
	}

	// Sign the block
	blockHash, err := unsignedBlock.Header.Hash()
	if err != nil {
		return errors.Errorf("Error hashing block: %v", err)
	}
	unsignedBlock.Header.ProposerVotePartialSignature, err = cc.signer.SignBlockProposal(unsignedBlock.Header.ProposedInView, blockHash)
	if err != nil {
		return errors.Errorf("Error signing block: %v", err)
	}

	// Process the block locally
	missingBlockHashes, err := cc.tryProcessBlockAsNewTip(unsignedBlock)
	if err != nil {
		return errors.Errorf("Error processing block locally: %v", err)
	}

	if len(missingBlockHashes) > 0 {
		// This should not be possible. If we successfully constructed the block, then we should
		// have its ancestors on-hand too. Something is very wrong. We should not broadcast this block.
		return errors.Errorf(
			"Error processing block locally: missing block hashes: %v",
			missingBlockHashes,
		)
	}

	// TODO: Broadcast the block proposal to the network

	cc.logBlockProposal(unsignedBlock, blockHash)
	return nil
}

// HandleLocalVoteEvent is triggered when FastHotStuffEventLoop has signaled that it wants to
// vote on the current tip. This functions validates the vote signal, then it constructs the
// vote message here.
//
// Steps:
// 1. Verify that the event is properly formed.
// 2. Construct the vote message
// 3. Process the vote in the consensus module
// 4. Broadcast the vote msg to the network
func (cc *FastHotStuffConsensus) HandleLocalVoteEvent(event *consensus.FastHotStuffEvent) error {
	// Hold a read lock on the consensus. This is because we need to check the
	// current view and block height of the consensus module.
	cc.lock.Lock()
	defer cc.lock.Unlock()

	if !cc.fastHotStuffEventLoop.IsRunning() {
		return errors.Errorf("FastHotStuffConsensus.HandleLocalVoteEvent: FastHotStuffEventLoop is not running")
	}

	var err error

	if !consensus.IsProperlyFormedVoteEvent(event) {
		// If the event is not properly formed, we ignore it and log it. This should never happen.
		return errors.Errorf("FastHotStuffConsensus.HandleLocalVoteEvent: Received improperly formed vote event: %v", event)
	}

	// Provided the vote message is properly formed, we construct and broadcast it in a best effort
	// manner. We do this even if the consensus event loop has advanced the view or block height. We
	// maintain the invariant here that if consensus connected a new tip and wanted to vote on it, the
	// vote should be broadcasted regardless of other concurrent events that may have happened.
	//
	// The block acceptance rules in Blockchain.ProcessBlockPoS guarantee that we cannot vote more
	// than once per view, so this best effort approach is safe, and in-line with the Fast-HotStuff
	// protocol.

	// Construct the vote message
	voteMsg := NewMessage(MsgTypeValidatorVote).(*MsgDeSoValidatorVote)
	voteMsg.MsgVersion = MsgValidatorVoteVersion0
	voteMsg.ProposedInView = event.View
	voteMsg.VotingPublicKey = cc.signer.GetPublicKey()

	// Get the block hash
	voteMsg.BlockHash = BlockHashFromConsensusInterface(event.TipBlockHash)

	// Sign the vote message
	voteMsg.VotePartialSignature, err = cc.signer.SignValidatorVote(event.View, event.TipBlockHash)
	if err != nil {
		// This should never happen as long as the BLS signer is initialized correctly.
		return errors.Errorf("FastHotStuffConsensus.HandleLocalVoteEvent: Error signing validator vote: %v", err)
	}

	// Process the vote message locally in the FastHotStuffEventLoop
	if err := cc.fastHotStuffEventLoop.ProcessValidatorVote(voteMsg); err != nil {
		// If we can't process the vote locally, then it must somehow be malformed, stale,
		// or a duplicate vote/timeout for the same view. Something is very wrong. We should not
		// broadcast it to the network.
		return errors.Errorf("FastHotStuffConsensus.HandleLocalVoteEvent: Error processing vote locally: %v", err)
	}

	// Broadcast the vote message to the network
	// TODO: Broadcast the vote message to the network or alternatively to just the block proposer

	return nil
}

// HandleValidatorVote is called when we receive a validator vote message from a peer. This function processes
// the vote locally in the FastHotStuffEventLoop.
func (cc *FastHotStuffConsensus) HandleValidatorVote(pp *Peer, msg *MsgDeSoValidatorVote) error {
	// No need to hold a lock on the consensus because this function is a pass-through
	// for the FastHotStuffEventLoop which guarantees thread-safety for its callers

	// Process the vote message locally in the FastHotStuffEventLoop
	if err := cc.fastHotStuffEventLoop.ProcessValidatorVote(msg); err != nil {
		// If we can't process the vote locally, then it must somehow be malformed, stale,
		// or a duplicate vote/timeout for the same view.
		return errors.Wrapf(err, "FastHotStuffConsensus.HandleValidatorVote: Error processing vote: ")
	}

	// Happy path
	return nil
}

// HandleLocalTimeoutEvent is triggered when the FastHotStuffEventLoop has signaled that
// it is ready to time out the current view. This function validates the timeout signal for
// staleness. If the signal is valid, then it constructs and broadcasts the timeout msg here.
//
// Steps:
// 1. Verify the timeout message and the view we want to timeout on
// 2. Construct the timeout message
// 3. Process the timeout in the consensus module
// 4. Broadcast the timeout msg to the network
func (cc *FastHotStuffConsensus) HandleLocalTimeoutEvent(event *consensus.FastHotStuffEvent) error {
	// Hold a read lock on the consensus. This is because we need to check the
	// current view and block height of the consensus module.
	cc.lock.Lock()
	defer cc.lock.Unlock()

	if !cc.fastHotStuffEventLoop.IsRunning() {
		return errors.Errorf("FastHotStuffConsensus.HandleLocalTimeoutEvent: FastHotStuffEventLoop is not running")
	}

	// Hold the blockchain's write lock so that the chain cannot be mutated underneath us.
	// In practice, this is a no-op, but it guarantees thread-safety in the event that other
	// parts of the codebase change.
	cc.blockchain.ChainLock.RLock()
	defer cc.blockchain.ChainLock.RUnlock()

	var err error

	if !consensus.IsProperlyFormedTimeoutEvent(event) {
		// If the event is not properly formed, we ignore it and log it. This should never happen.
		return errors.Errorf("FastHotStuffConsensus.HandleLocalTimeoutEvent: Received improperly formed timeout event: %v", event)
	}

	if event.View != cc.fastHotStuffEventLoop.GetCurrentView() {
		// It's possible that the event loop signaled to timeout, but at the same time, we
		// received a block proposal from the network and advanced the view. This is normal
		// and an expected race condition in the steady-state.
		//
		// Nothing to do here.
		return errors.Errorf("FastHotStuffConsensus.HandleLocalTimeoutEvent: Stale timeout event: %v", event)
	}

	// Locally advance the event loop's view so that the node is locally running the Fast-HotStuff
	// protocol correctly. Any errors below related to broadcasting the timeout message should not
	// affect the correctness of the protocol's local execution.
	if _, err := cc.fastHotStuffEventLoop.AdvanceViewOnTimeout(); err != nil {
		// This should never happen as long as the event loop is running. If it happens, we return
		// the error and let the caller handle it.
		return errors.Errorf("FastHotStuffConsensus.HandleLocalTimeoutEvent: Error advancing view on timeout: %v", err)
	}

	// Extract the tip block hash from the timeout message
	tipBlockHash := BlockHashFromConsensusInterface(event.TipBlockHash)

	// Fetch the HighQC from the Blockchain struct
	tipBlockNode, tipBlockExists := cc.blockchain.blockIndexByHash[*tipBlockHash]
	if !tipBlockExists {
		return errors.Errorf("FastHotStuffConsensus.HandleLocalTimeoutEvent: Error fetching tip block: %v", tipBlockHash)
	}

	// Construct the timeout message
	timeoutMsg := NewMessage(MsgTypeValidatorTimeout).(*MsgDeSoValidatorTimeout)
	timeoutMsg.MsgVersion = MsgValidatorTimeoutVersion0
	timeoutMsg.TimedOutView = event.View
	timeoutMsg.VotingPublicKey = cc.signer.GetPublicKey()

	if cc.blockchain.IsFinalPoWBlockHeight(tipBlockNode.Header.Height) {
		// If the tip block is the final block of the PoW chain, then we can use the PoS chain's genesis block
		// as the highQC for it.
		if timeoutMsg.HighQC, err = cc.blockchain.GetProofOfStakeGenesisQuorumCertificate(); err != nil {
			return errors.Errorf("FastHotStuffConsensus.Start: Error creating PoS cutover genesis QC: %v", err)
		}
	} else {
		// Otherwise, we use the QC from the tip block as the highQC
		timeoutMsg.HighQC = QuorumCertificateFromConsensusInterface(tipBlockNode.Header.GetQC())
	}

	// Sign the timeout message
	timeoutMsg.TimeoutPartialSignature, err = cc.signer.SignValidatorTimeout(event.View, timeoutMsg.HighQC.GetView())
	if err != nil {
		// This should never happen as long as the BLS signer is initialized correctly.
		return errors.Errorf("FastHotStuffConsensus.HandleLocalTimeoutEvent: Error signing validator timeout: %v", err)
	}

	// Process the timeout message locally in the FastHotStuffEventLoop
	if err := cc.fastHotStuffEventLoop.ProcessValidatorTimeout(timeoutMsg); err != nil {
		// This should never happen. If we error here, it means that the timeout message is stale
		// beyond the committed tip, the timeout message is malformed, or the timeout message is
		// is duplicated for the same view. In any case, something is very wrong. We should not
		// broadcast this message to the network.
		return errors.Errorf("FastHotStuffConsensus.HandleLocalTimeoutEvent: Error processing timeout locally: %v", err)
	}

	// Broadcast the timeout message to the network
	// TODO: Broadcast the timeout message to the network or alternatively to just the block proposer

	return nil
}

// HandleValidatorTimeout is called when we receive a validator timeout message from a peer. This function
// processes the timeout locally in the FastHotStuffEventLoop.
func (cc *FastHotStuffConsensus) HandleValidatorTimeout(pp *Peer, msg *MsgDeSoValidatorTimeout) error {
	// No need to hold a lock on the consensus because this function is a pass-through
	// for the FastHotStuffEventLoop which guarantees thread-safety for its callers.

	// Process the timeout message locally in the FastHotStuffEventLoop
	if err := cc.fastHotStuffEventLoop.ProcessValidatorTimeout(msg); err != nil {
		// If we can't process the timeout locally, then it must somehow be malformed, stale,
		// or a duplicate vote/timeout for the same view.
		return errors.Wrapf(err, "FastHotStuffConsensus.HandleValidatorTimeout: Error processing timeout: ")
	}

	// Happy path
	return nil
}

func (cc *FastHotStuffConsensus) HandleBlock(pp *Peer, msg *MsgDeSoBlock) error {
	// Hold a lock on the consensus, because we will need to mutate the Blockchain
	// and the FastHotStuffEventLoop data structures.
	cc.lock.Lock()
	defer cc.lock.Unlock()

	if !cc.fastHotStuffEventLoop.IsRunning() {
		return errors.Errorf("FastHotStuffConsensus.HandleBlock: FastHotStuffEventLoop is not running")
	}

	// Hold the blockchain's write lock so that the chain cannot be mutated underneath us.
	// In practice, this is a no-op, but it guarantees thread-safety in the event that other
	// parts of the codebase change.
	cc.blockchain.ChainLock.Lock()
	defer cc.blockchain.ChainLock.Unlock()

	// Try to apply the block as the new tip of the blockchain. If the block is an orphan, then
	// we will get back a list of missing ancestor block hashes. We can fetch the missing blocks
	// from the network and retry.
	missingBlockHashes, err := cc.tryProcessBlockAsNewTip(msg)
	if err != nil {
		// If we get an error here, it means something went wrong with the block processing algorithm.
		// Nothing we can do to recover here.
		return errors.Errorf("FastHotStuffConsensus.HandleBlock: Error processing block as new tip: %v", err)
	}

	// If there are missing block hashes, then we need to fetch the missing blocks from the network
	// and retry processing the block as a new tip. We'll request the blocks from the same peer.
	//
	// If we need to optimize this in the future, we can additionally send the block hash of our
	// current committed tip. The peer can then send us all of the blocks that are missing starting
	// from our current committed tip all the way through to the requested block hashes.
	//
	// See https://github.com/deso-protocol/core/pull/875#discussion_r1460183510 for more details.
	if len(missingBlockHashes) > 0 {
		pp.QueueMessage(&MsgDeSoGetBlocks{
			HashList: missingBlockHashes,
		})
	}

	return nil
}

// tryProcessBlockAsNewTip tries to apply a new tip block to both the Blockchain and FastHotStuffEventLoop data
// structures. It wraps the ProcessBlockPoS and ProcessTipBlock functions in the Blockchain and FastHotStuffEventLoop
// data structures, which together implement the Fast-HotStuff block handling algorithm end-to-end.
//
// Reference Implementation:
// https://github.com/deso-protocol/hotstuff_pseudocode/blob/6409b51c3a9a953b383e90619076887e9cebf38d/fast_hotstuff_bls.go#L573
func (cc *FastHotStuffConsensus) tryProcessBlockAsNewTip(block *MsgDeSoBlock) ([]*BlockHash, error) {
	// Try to apply the block locally as the new tip of the blockchain
	successfullyAppliedNewTip, _, missingBlockHashes, err := cc.blockchain.processBlockPoS(
		block, // Pass in the block itself
		cc.fastHotStuffEventLoop.GetCurrentView(), // Pass in the current view to ensure we don't process a stale block
		true, // Make sure we verify signatures in the block
	)
	if err != nil {
		return nil, errors.Errorf("Error processing block locally: %v", err)
	}

	// If the incoming block is an orphan, then there's nothing we can do. We return the missing ancestor
	// block hashes to the caller. The caller can then fetch the missing blocks from the network and retry
	// if needed.
	if len(missingBlockHashes) > 0 {
		return missingBlockHashes, nil
	}

	// At this point we know that the blockchain was mutated. Either the incoming block resulted in a new
	// tip for the blockchain, or the incoming block was part of a fork that resulted in a change in the
	// safe blocks

	// Fetch the safe blocks that are eligible to be extended from by the next incoming tip block
	safeBlocks, err := cc.blockchain.GetSafeBlocks()
	if err != nil {
		return nil, errors.Errorf("error fetching safe blocks: %v", err)
	}

	// Fetch the validator set at each safe block
	safeBlocksWithValidators, err := cc.fetchValidatorListsForSafeBlocks(safeBlocks)
	if err != nil {
		return nil, errors.Errorf("error fetching validator lists for safe blocks: %v", err)
	}

	// If the block was processed successfully but was not applied as the new tip, we need up date the safe
	// blocks in the FastHotStuffEventLoop. This is because the new block may be safe to extend even though
	// it did not result in a new tip.
	if !successfullyAppliedNewTip {
		// Update the safe blocks to the FastHotStuffEventLoop
		if err = cc.fastHotStuffEventLoop.UpdateSafeBlocks(safeBlocksWithValidators); err != nil {
			return nil, errors.Errorf("Error processing safe blocks locally: %v", err)
		}

		// Happy path. The safe blocks were successfully updated in the FastHotStuffEventLoop. Nothing left to do.
		return nil, nil
	}

	// If the block was processed successfully and resulted in a change to the blockchain's tip, then
	// we need to pass the new tip to the FastHotStuffEventLoop as well.

	// Fetch the new tip from the blockchain. Note: the new tip may or may not be the input block itself.
	// It's possible that there was a descendant of the tip block that was previously stored as an orphan
	// in the Blockchain, and was applied as the new tip.
	tipBlock := cc.blockchain.BlockTip().Header

	// Fetch the validator set at the new tip block
	tipBlockWithValidators, err := cc.fetchValidatorListsForSafeBlocks([]*MsgDeSoHeader{tipBlock})
	if err != nil {
		return nil, errors.Errorf("Error fetching validator lists for tip block: %v", err)
	}

	// Pass the new tip and safe blocks to the FastHotStuffEventLoop
	if err = cc.fastHotStuffEventLoop.ProcessTipBlock(tipBlockWithValidators[0], safeBlocksWithValidators); err != nil {
		return nil, errors.Errorf("Error processing tip block locally: %v", err)
	}

	// Happy path. The block was processed successfully and applied as the new tip. Nothing left to do.
	return nil, nil
}

// produceUnsignedBlockForBlockProposalEvent is a helper function that can produce a new block for proposal based
// on Fast-HotStuff block proposal event. This function expects the event to have been pre-validated by the caller.
// If the event is malformed or invalid, then the behavior of this function is undefined.
func (cc *FastHotStuffConsensus) produceUnsignedBlockForBlockProposalEvent(
	event *consensus.FastHotStuffEvent,
	proposerRandomSeedSignature *bls.Signature,
) (*MsgDeSoBlock, error) {
	// Get the parent block's hash
	parentBlockHash := BlockHashFromConsensusInterface(event.QC.GetBlockHash())

	// Build a UtxoView at the parent block
	utxoViewAtParent, err := cc.blockchain.getUtxoViewAtBlockHash(*parentBlockHash)
	if err != nil {
		// This should never happen as long as the parent block is a descendant of the committed tip.
		return nil, errors.Errorf("Error fetching UtxoView for parent block: %v", parentBlockHash)
	}

	// Dynamically create a new block producer at the current block height
	blockProducer, err := cc.createBlockProducer(utxoViewAtParent)
	if err != nil {
		return nil, errors.Errorf("Error creating block producer: %v", err)
	}

	// Construct an unsigned block
	if event.EventType == consensus.FastHotStuffEventTypeConstructVoteQC {
		block, err := blockProducer.CreateUnsignedBlock(
			utxoViewAtParent,
			event.TipBlockHeight+1,
			event.View,
			proposerRandomSeedSignature,
			QuorumCertificateFromConsensusInterface(event.QC),
		)
		if err != nil {
			return nil, errors.Errorf("Error constructing unsigned block: %v", err)
		}

		return block, nil
	}

	// Construct an unsigned timeout block
	if event.EventType == consensus.FastHotStuffEventTypeConstructTimeoutQC {
		block, err := blockProducer.CreateUnsignedTimeoutBlock(
			utxoViewAtParent,
			event.TipBlockHeight+1,
			event.View,
			proposerRandomSeedSignature,
			AggregateQuorumCertificateFromConsensusInterface(event.AggregateQC),
		)
		if err != nil {
			return nil, errors.Errorf("Error constructing unsigned timeout block: %v", err)
		}

		return block, nil
	}

	// We should never reach this if the event had been pre-validated by the caller. We support this
	// case here
	return nil, errors.Errorf("Unexpected FastHotStuffEventType :%v", event.EventType)
}

// fetchValidatorListsForSafeBlocks takes in a set of safe blocks that can be extended from, and fetches the
// the validator set for each safe block. The result is returned as type BlockWithValidatorList so it can be
// passed to the FastHotStuffEventLoop. If the input blocks precede the committed tip or they do no exist within
// the current or next epoch after the committed tip, then this function returns an error. Note: it is not possible
// for safe blocks to precede the committed tip or to belong to an epoch that is more than one epoch ahead of the
// committed tip.
func (cc *FastHotStuffConsensus) fetchValidatorListsForSafeBlocks(blocks []*MsgDeSoHeader) (
	[]consensus.BlockWithValidatorList,
	error,
) {
	// If there are no blocks, then there's nothing to do.
	if len(blocks) == 0 {
		return nil, nil
	}

	// Create a map to cache the validator set entries by epoch number. Two blocks in the same epoch will have
	// the same validator set, so we can use an in-memory cache to optimize the validator set lookup for them.
	validatorSetEntriesBySnapshotEpochNumber := make(map[uint64][]*ValidatorEntry)

	// Create a UtxoView for the committed tip block. We will use this to fetch the validator set for
	// all of the safe blocks.
	utxoView, err := NewUtxoView(cc.blockchain.db, cc.params, cc.blockchain.postgres, cc.blockchain.snapshot, nil)
	if err != nil {
		return nil, errors.Errorf("Error creating UtxoView: %v", err)
	}

	// Fetch the current epoch entry for the committed tip
	epochEntryAtCommittedTip, err := utxoView.GetCurrentEpochEntry()
	if err != nil {
		return nil, errors.Errorf("Error fetching epoch entry for committed tip: %v", err)
	}

	// Fetch the next epoch entry
	nextEpochEntryAfterCommittedTip, err := utxoView.simulateNextEpochEntry(epochEntryAtCommittedTip.EpochNumber, epochEntryAtCommittedTip.FinalBlockHeight)
	if err != nil {
		return nil, errors.Errorf("Error fetching next epoch entry after committed tip: %v", err)
	}

	// The input blocks can only be part of the current or next epoch entries.
	possibleEpochEntriesForBlocks := []*EpochEntry{epochEntryAtCommittedTip, nextEpochEntryAfterCommittedTip}

	// Fetch the validator set at each block
	blocksWithValidatorLists := make([]consensus.BlockWithValidatorList, len(blocks))
	for ii, block := range blocks {
		// Find the epoch entry for the block. It'll either be the current epoch entry or the next one.
		// We add 1 to the block height because we need the validator set that results AFTER connecting the
		// block to the blockchain, and triggering an epoch transition (if at an epoch boundary).
		epochEntryForBlock, err := getEpochEntryForBlockHeight(block.Height+1, possibleEpochEntriesForBlocks)
		if err != nil {
			return nil, errors.Errorf("Error fetching epoch number for block: %v", err)
		}

		// Compute the snapshot epoch number for the block. This is the epoch number that the validator set
		// for the block was snapshotted in.
		snapshotEpochNumber, err := utxoView.ComputeSnapshotEpochNumberForEpoch(epochEntryForBlock.EpochNumber)
		if err != nil {
			return nil, errors.Errorf("error computing snapshot epoch number for epoch: %v", err)
		}

		var validatorSetAtBlock []*ValidatorEntry
		var ok bool

		// If the validator set for the block is already cached by the snapshot epoch number, then use it.
		// Otherwise, fetch it from the UtxoView.
		if validatorSetAtBlock, ok = validatorSetEntriesBySnapshotEpochNumber[snapshotEpochNumber]; !ok {
			// We don't have the validator set for the block cached. Fetch it from the UtxoView.
			validatorSetAtBlock, err = utxoView.GetAllSnapshotValidatorSetEntriesByStakeAtEpochNumber(snapshotEpochNumber)
			if err != nil {
				return nil, errors.Errorf("Error fetching validator set for block: %v", err)
			}
		}

		blocksWithValidatorLists[ii] = consensus.BlockWithValidatorList{
			Block:         block,
			ValidatorList: ValidatorEntriesToConsensusInterface(validatorSetAtBlock),
		}
	}

	// Happy path: we fetched the validator lists for all blocks successfully.
	return blocksWithValidatorLists, nil
}

func (fc *FastHotStuffConsensus) createBlockProducer(bav *UtxoView) (*PosBlockProducer, error) {
	blockProducerBlsPublicKey := fc.signer.GetPublicKey()
	blockProducerValidatorEntry, err := bav.GetCurrentSnapshotValidatorBLSPublicKeyPKIDPairEntry(blockProducerBlsPublicKey)
	if err != nil {
		return nil, errors.Errorf("Error fetching validator entry for block producer: %v", err)
	}
	blockProducerPublicKeyBytes := bav.GetPublicKeyForPKID(blockProducerValidatorEntry.PKID)
	blockProducerPublicKey := NewPublicKey(blockProducerPublicKeyBytes)
	if blockProducerPublicKey == nil {
		return nil, errors.Errorf("Error fetching public key for block producer: %v", err)
	}
	blockProducer := NewPosBlockProducer(
		fc.mempool,
		fc.params,
		fc.blockchain.timeSource,
		blockProducerPublicKey,
		blockProducerBlsPublicKey,
	)
	return blockProducer, nil
}

// Finds the epoch entry for the block and returns the epoch number.
func getEpochEntryForBlockHeight(blockHeight uint64, epochEntries []*EpochEntry) (*EpochEntry, error) {
	for _, epochEntry := range epochEntries {
		if epochEntry.ContainsBlockHeight(blockHeight) {
			return epochEntry, nil
		}
	}

	return nil, errors.Errorf("error finding epoch number for block height: %v", blockHeight)
}

func isValidBlockProposalEvent(event *consensus.FastHotStuffEvent, expectedEventType consensus.FastHotStuffEventType) bool {
	// Validate that the expected event type is a block proposal event type
	possibleExpectedEventTypes := []consensus.FastHotStuffEventType{
		consensus.FastHotStuffEventTypeConstructVoteQC,
		consensus.FastHotStuffEventTypeConstructTimeoutQC,
	}

	// The event's type must be one of the two block proposal hard-coded values
	if !collections.Contains(possibleExpectedEventTypes, expectedEventType) {
		return false
	}

	// The event's type should match the expected event type
	if event.EventType != expectedEventType {
		return false
	}

	return true
}

func isProperlyFormedBlockProposalEvent(event *consensus.FastHotStuffEvent) bool {
	if event.EventType == consensus.FastHotStuffEventTypeConstructVoteQC {
		return consensus.IsProperlyFormedConstructVoteQCEvent(event)
	}

	if event.EventType == consensus.FastHotStuffEventTypeConstructTimeoutQC {
		return consensus.IsProperlyFormedConstructTimeoutQCEvent(event)
	}

	return false
}

////////////////////////////////////////// Logging Helper Functions ///////////////////////////////////////////////

func (fc *FastHotStuffConsensus) logBlockProposal(block *MsgDeSoBlock, blockHash *BlockHash) {
	aggQCView := uint64(0)
	aggQCNumValidators := 0
	aggQCHighQCViews := "[]"

	if !block.Header.ValidatorsTimeoutAggregateQC.isEmpty() {
		aggQCView = block.Header.ValidatorsTimeoutAggregateQC.GetView()
		aggQCNumValidators = block.Header.ValidatorsTimeoutAggregateQC.GetAggregatedSignature().GetSignersList().Size()
		aggQCHighQCViews = fmt.Sprint(block.Header.ValidatorsTimeoutAggregateQC.GetHighQCViews())
	}

	glog.Infof(
		"\n==================================== YOU PROPOSED A NEW FAST-HOTSTUFF BLOCK! ===================================="+
			"\n  Timestamp: %d, View: %d, Height: %d, BlockHash: %v"+
			"\n  Proposer PKey: %s"+
			"\n  Proposer Voting PKey: %s"+
			"\n  Proposer Signature: %s"+
			"\n  High QC View: %d, High QC Num Validators: %d, High QC BlockHash: %s"+
			"\n  Timeout Agg QC View: %d, Timeout Agg QC Num Validators: %d, Timeout High QC Views: %s"+
			"\n  Num Block Transactions: %d, Num Transactions Remaining In Mempool: %d"+
			"\n=================================================================================================================",
		block.Header.GetTstampSecs(), block.Header.GetView(), block.Header.Height, blockHash.String(),
		PkToString(block.Header.ProposerPublicKey.ToBytes(), fc.params),
		block.Header.ProposerVotingPublicKey.ToString(),
		block.Header.ProposerVotePartialSignature.ToString(),
		block.Header.GetQC().GetView(), block.Header.GetQC().GetAggregatedSignature().GetSignersList().Size(), block.Header.PrevBlockHash.String(),
		aggQCView, aggQCNumValidators, aggQCHighQCViews,
		len(block.Txns), len(fc.mempool.GetTransactions()),
	)
}
