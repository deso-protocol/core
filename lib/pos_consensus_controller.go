package lib

import (
	"sync"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/consensus"
	"github.com/pkg/errors"
)

type ConsensusController struct {
	lock                  sync.RWMutex
	blockchain            *Blockchain
	blockProducer         *PosBlockProducer
	fastHotStuffEventLoop consensus.FastHotStuffEventLoop
	mempool               Mempool
	params                *DeSoParams
	signer                *BLSSigner
}

func NewConsensusController(params *DeSoParams, blockchain *Blockchain, mempool Mempool, signer *BLSSigner) *ConsensusController {
	return &ConsensusController{
		blockchain:            blockchain,
		blockProducer:         NewPosBlockProducer(mempool, params, nil, signer.GetPublicKey()),
		fastHotStuffEventLoop: consensus.NewFastHotStuffEventLoop(),
		mempool:               mempool,
		signer:                signer,
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

// HandleFastHostStuffBlockProposal is called when FastHotStuffEventLoop has signaled that it can
// construct a block at a certain block height. This function validates the block proposal signal,
// constructs, processes locally, and then broadcasts the block.
func (cc *ConsensusController) HandleFastHostStuffBlockProposal(event *consensus.FastHotStuffEvent) error {
	// Hold a read and write lock on the consensus controller. This is because we need to check
	// the current view of the consensus event loop, and to update the blockchain.
	cc.lock.Lock()
	defer cc.lock.Unlock()

	// Handle the event as a block proposal event for a regular block
	if err := cc.handleBlockProposerEvent(event, consensus.FastHotStuffEventTypeConstructVoteQC); err != nil {
		return errors.Wrapf(err, "HandleFastHostStuffBlockProposal:")
	}

	// Happy path: nothing left to do
	return nil
}

// HandleFastHostStuffEmptyTimeoutBlockProposal is called when FastHotStuffEventLoop has signaled that it can
// construct a timeout block at a certain block height. This function validates the timeout block proposal
// signal, constructs, processes locally, and then broadcasts the block.
func (cc *ConsensusController) HandleFastHostStuffEmptyTimeoutBlockProposal(event *consensus.FastHotStuffEvent) error {
	// Hold a read and write lock on the consensus controller. This is because we need to check
	// the current view of the consensus event loop, and to update the blockchain.
	cc.lock.Lock()
	defer cc.lock.Unlock()

	// Handle the event as a block proposal event for a timeout block
	if err := cc.handleBlockProposerEvent(event, consensus.FastHotStuffEventTypeConstructTimeoutQC); err != nil {
		return errors.Wrapf(err, "HandleFastHostStuffEmptyTimeoutBlockProposal:")
	}

	// Happy path: nothing left to do
	return nil
}

// handleBlockProposerEvent is a helper function that can process a block proposal event for either
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
func (cc *ConsensusController) handleBlockProposerEvent(
	event *consensus.FastHotStuffEvent,
	expectedEventType consensus.FastHotStuffEventType,
) error {
	// Validate that the expected event type is a block proposal event type
	possibleExpectedEventTypes := []consensus.FastHotStuffEventType{
		consensus.FastHotStuffEventTypeConstructVoteQC,
		consensus.FastHotStuffEventTypeConstructTimeoutQC,
	}
	if !collections.Contains(possibleExpectedEventTypes, expectedEventType) {
		return errors.Errorf("Invalid expected event type: %v", expectedEventType)
	}

	// The event's type should match the expected event type
	if event.EventType != expectedEventType {
		return errors.Errorf("Unexpected event type: %v", event.EventType)
	}

	// If the event is a regular block proposal event, then we validate and process it as a regular block
	if expectedEventType == consensus.FastHotStuffEventTypeConstructVoteQC {
		if !consensus.IsProperlyFormedConstructVoteQCEvent(event) {
			// If the event is not properly formed, we ignore it and log it. This should never happen.
			return errors.Errorf("Received improperly formed vote QC construction event: %v", event)
		}
	} else { // expectedEventType == consensus.FastHotStuffEventTypeConstructTimeoutQC
		if !consensus.IsProperlyFormedConstructTimeoutQCEvent(event) {
			// If the event is not properly formed, we ignore it and log it. This should never happen.
			return errors.Errorf("Received improperly formed timeout QC construction event: %v", event)
		}
	}

	// If the block proposal is properly formed, we try to construct and broadcast the block here.

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

	// Build a UtxoView at the parent block
	utxoViewAtParent, err := cc.blockchain.getUtxoViewAtBlockHash(*parentBlock.Hash)
	if err != nil {
		// This should never happen as long as the parent block is a descendant of the committed tip.
		return errors.Errorf("Error fetching UtxoView for parent block: %v", parentBlockHash)
	}

	// TODO: Compute the random seed hash for the block proposer
	var proposerRandomSeedSignature *bls.Signature

	var block *MsgDeSoBlock

	if expectedEventType == consensus.FastHotStuffEventTypeConstructVoteQC {
		// Construct an unsigned block
		block, err = cc.blockProducer.CreateUnsignedBlock(
			utxoViewAtParent,
			event.TipBlockHeight+1,
			event.View,
			proposerRandomSeedSignature,
			QuorumCertificateFromConsensusInterface(event.QC),
		)
		if err != nil {
			return errors.Errorf("Error constructing unsigned block: %v", err)
		}
	} else { // expectedEventType == consensus.FastHotStuffEventTypeConstructTimeoutQC
		// Construct an unsigned timeout block
		block, err = cc.blockProducer.CreateUnsignedTimeoutBlock(
			utxoViewAtParent,
			event.TipBlockHeight+1,
			event.View,
			proposerRandomSeedSignature,
			AggregateQuorumCertificateFromConsensusInterface(event.AggregateQC),
		)
		if err != nil {
			return errors.Errorf("Error constructing unsigned timeout block: %v", err)
		}
	}

	// Sign the block
	blockHash, err := block.Header.Hash()
	if err != nil {
		return errors.Errorf("Error hashing block: %v", err)
	}
	block.Header.ProposerVotePartialSignature, err = cc.signer.SignBlockProposal(block.Header.ProposedInView, blockHash)
	if err != nil {
		return errors.Errorf("Error signing block: %v", err)
	}

	// Process the block locally
	missingBlockHashes, err := cc.tryProcessBlockAsNewTip(block)
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

	return nil
}

// HandleFastHostStuffVote is triggered when FastHotStuffEventLoop has signaled that it wants to
// vote on the current tip. This functions validates the vote signal, then it constructs the
// vote message here.
//
// Steps:
// 1. Verify that the event is properly formed.
// 2. Construct the vote message
// 3. Process the vote in the consensus module
// 4. Broadcast the vote msg to the network
func (cc *ConsensusController) HandleFastHostStuffVote(event *consensus.FastHotStuffEvent) error {
	// Hold a read lock on the consensus controller. This is because we need to check the
	// current view and block height of the consensus module.
	cc.lock.Lock()
	defer cc.lock.Unlock()

	var err error

	if !consensus.IsProperlyFormedVoteEvent(event) {
		// If the event is not properly formed, we ignore it and log it. This should never happen.
		return errors.Errorf("HandleFastHostStuffVote: Received improperly formed vote event: %v", event)
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
		return errors.Errorf("HandleFastHostStuffVote: Error signing validator vote: %v", err)
	}

	// Process the vote message locally in the FastHotStuffEventLoop
	if err := cc.fastHotStuffEventLoop.ProcessValidatorVote(voteMsg); err != nil {
		// If we can't process the vote locally, then it must somehow be malformed, stale,
		// or a duplicate vote/timeout for the same view. Something is very wrong. We should not
		// broadcast it to the network.
		return errors.Errorf("HandleFastHostStuffVote: Error processing vote locally: %v", err)
	}

	// Broadcast the vote message to the network
	// TODO: Broadcast the vote message to the network or alternatively to just the block proposer

	return nil
}

// HandleFastHostStuffTimeout is triggered when the FastHotStuffEventLoop has signaled that
// it is ready to time out the current view. This function validates the timeout signal for
// staleness. If the signal is valid, then it constructs and broadcasts the timeout msg here.
//
// Steps:
// 1. Verify the timeout message and the view we want to timeout on
// 2. Construct the timeout message
// 3. Process the timeout in the consensus module
// 4. Broadcast the timeout msg to the network
func (cc *ConsensusController) HandleFastHostStuffTimeout(event *consensus.FastHotStuffEvent) error {
	// Hold a read lock on the consensus controller. This is because we need to check the
	// current view and block height of the consensus module.
	cc.lock.Lock()
	defer cc.lock.Unlock()

	var err error

	if !consensus.IsProperlyFormedTimeoutEvent(event) {
		// If the event is not properly formed, we ignore it and log it. This should never happen.
		return errors.Errorf("HandleFastHostStuffTimeout: Received improperly formed timeout event: %v", event)
	}

	if event.View != cc.fastHotStuffEventLoop.GetCurrentView() {
		// It's possible that the event loop signaled to timeout, but at the same time, we
		// received a block proposal from the network and advanced the view. This is normal
		// and an expected race condition in the steady-state.
		//
		// Nothing to do here.
		return errors.Errorf("HandleFastHostStuffTimeout: Stale timeout event: %v", event)
	}

	// Locally advance the event loop's view so that the node is locally running the Fast-HotStuff
	// protocol correctly. Any errors below related to broadcasting the timeout message should not
	// affect the correctness of the protocol's local execution.
	if _, err := cc.fastHotStuffEventLoop.AdvanceViewOnTimeout(); err != nil {
		// This should never happen as long as the event loop is running. If it happens, we return
		// the error and let the caller handle it.
		return errors.Errorf("HandleFastHostStuffTimeout: Error advancing view on timeout: %v", err)
	}

	// Construct the timeout message
	timeoutMsg := NewMessage(MsgTypeValidatorTimeout).(*MsgDeSoValidatorTimeout)
	timeoutMsg.MsgVersion = MsgValidatorTimeoutVersion0
	timeoutMsg.TimedOutView = event.View
	timeoutMsg.VotingPublicKey = cc.signer.GetPublicKey()
	timeoutMsg.HighQC = QuorumCertificateFromConsensusInterface(event.QC)

	// Sign the timeout message
	timeoutMsg.TimeoutPartialSignature, err = cc.signer.SignValidatorTimeout(event.View, event.QC.GetView())
	if err != nil {
		// This should never happen as long as the BLS signer is initialized correctly.
		return errors.Errorf("HandleFastHostStuffTimeout: Error signing validator timeout: %v", err)
	}

	// Process the timeout message locally in the FastHotStuffEventLoop
	if err := cc.fastHotStuffEventLoop.ProcessValidatorTimeout(timeoutMsg); err != nil {
		// This should never happen. If we error here, it means that the timeout message is stale
		// beyond the committed tip, the timeout message is malformed, or the timeout message is
		// is duplicated for the same view. In any case, something is very wrong. We should not
		// broadcast this message to the network.
		return errors.Errorf("HandleFastHostStuffTimeout: Error processing timeout locally: %v", err)

	}

	// Broadcast the timeout message to the network
	// TODO: Broadcast the timeout message to the network or alternatively to just the block proposer

	return nil
}

func (cc *ConsensusController) HandleHeaderBundle(pp *Peer, msg *MsgDeSoHeaderBundle) {
	// TODO
}

func (cc *ConsensusController) HandleHeader(pp *Peer, msg *MsgDeSoHeader) {
	// TODO
}

func (cc *ConsensusController) HandleBlock(pp *Peer, msg *MsgDeSoBlock) error {
	// Hold a lock on the consensus controller, because we will need to mutate the Blockchain
	// and the FastHotStuffEventLoop data structures.
	cc.lock.Lock()
	defer cc.lock.Unlock()

	// Try to apply the block as the new tip of the blockchain. If the block is an orphan, then
	// we will get back a list of missing ancestor block hashes. We can fetch the missing blocks
	// from the network and retry.
	missingBlockHashes, err := cc.tryProcessBlockAsNewTip(msg)
	if err != nil {
		// If we get an error here, it means something went wrong with the block processing algorithm.
		// Nothing we can do to recover here.
		return errors.Errorf("HandleBlock: Error processing block as new tip: %v", err)
	}

	// If there are missing block hashes, then we need to fetch the missing blocks from the network
	// and retry processing the block as a new tip. We'll request the blocks from the same peer.
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
func (cc *ConsensusController) tryProcessBlockAsNewTip(block *MsgDeSoBlock) ([]*BlockHash, error) {
	// Try to apply the block locally as the new tip of the blockchain
	successfullyAppliedNewTip, _, missingBlockHashes, err := cc.blockchain.processBlockPoS(
		block, // Pass in the block itself
		cc.fastHotStuffEventLoop.GetCurrentView(), // Pass in the current view to ensure we don't process a stale block
		true, // Make sure we verify signatures in the block
	)
	if err != nil {
		return nil, errors.Errorf("HandleFastHostStuffBlockProposal: Error processing block locally: %v", err)
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
		return nil, errors.Errorf("HandleFastHostStuffBlockProposal: Error fetching safe blocks: %v", err)
	}

	// Fetch the validator set at each safe block
	safeBlocksWithValidators, err := cc.fetchValidatorListsForSafeBlocks(safeBlocks)
	if err != nil {
		return nil, errors.Errorf("HandleFastHostStuffBlockProposal: Error fetching validator lists for safe blocks: %v", err)
	}

	// If the block was processed successfully but was not applied as the new tip, we need up date the safe
	// blocks in the FastHotStuffEventLoop. This is because the new block may be safe to extend even though
	// it did not result in a new tip.
	if !successfullyAppliedNewTip {
		// Update the safe blocks to the FastHotStuffEventLoop
		if err = cc.fastHotStuffEventLoop.UpdateSafeBlocks(safeBlocksWithValidators); err != nil {
			return nil, errors.Errorf("HandleFastHostStuffBlockProposal: Error processing safe blocks locally: %v", err)
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
		return nil, errors.Errorf("HandleFastHostStuffBlockProposal: Error fetching validator lists for tip block: %v", err)
	}

	// Pass the new tip and safe blocks to the FastHotStuffEventLoop
	if err = cc.fastHotStuffEventLoop.ProcessTipBlock(tipBlockWithValidators[0], safeBlocksWithValidators); err != nil {
		return nil, errors.Errorf("HandleFastHostStuffBlockProposal: Error processing tip block locally: %v", err)
	}

	// Happy path. The block was processed successfully and applied as the new tip. Nothing left to do.
	return nil, nil
}

// fetchValidatorListsForSafeBlocks takes in a set of safe blocks that can be extended from, and fetches the
// the validator set for each safe block. The result is returned as type BlockWithValidatorList so it can be
// passed to the FastHotStuffEventLoop. If the input blocks precede the committed tip or they do no exist within
// the current or next epoch after the committed tip, then this function returns an error. Note: it is not possible
// for safe blocks to precede the committed tip or to belong to an epoch that is more than one epoch ahead of the
// committed tip.
func (cc *ConsensusController) fetchValidatorListsForSafeBlocks(blocks []*MsgDeSoHeader) (
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

	// Create a UtxoView for the committed tip block. We will use this to fetch the validator set for the
	// all of the safe blocks.
	utxoView, err := NewUtxoView(cc.blockchain.db, cc.params, cc.blockchain.postgres, cc.blockchain.snapshot, nil)
	if err != nil {
		return nil, errors.Errorf("error creating UtxoView: %v", err)
	}

	// Fetch the current epoch entry for the committed tip
	epochEntryAtCommittedTip, err := utxoView.GetCurrentEpochEntry()
	if err != nil {
		return nil, errors.Errorf("error fetching epoch entry for committed tip: %v", err)
	}

	// Fetch the next epoch entry
	nextEpochEntryAfterCommittedTip, err := utxoView.SimulateNextEpochEntry(epochEntryAtCommittedTip)
	if err != nil {
		return nil, errors.Errorf("error fetching next epoch entry after committed tip: %v", err)
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
			return nil, errors.Errorf("error fetching epoch number for block: %v", err)
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
				return nil, errors.Errorf("error fetching validator set for block: %v", err)
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

// Finds the epoch entry for the block and returns the epoch number.
func getEpochEntryForBlockHeight(blockHeight uint64, epochEntries []*EpochEntry) (*EpochEntry, error) {
	for _, epochEntry := range epochEntries {
		if epochEntry.ContainsBlockHeight(blockHeight) {
			return epochEntry, nil
		}
	}

	return nil, errors.Errorf("error finding epoch number for block height: %v", blockHeight)
}

func (bav *UtxoView) SimulateNextEpochEntry(epochEntry *EpochEntry) (*EpochEntry, error) {
	return bav.computeNextEpochEntry(
		epochEntry.EpochNumber,
		epochEntry.FinalBlockHeight,
		epochEntry.InitialView,
		epochEntry.CreatedAtBlockTimestampNanoSecs,
	)
}
