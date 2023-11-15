package lib

import (
	"sync"

	"github.com/deso-protocol/core/consensus"
	"github.com/pkg/errors"
)

type ConsensusController struct {
	lock                  sync.RWMutex
	fastHotStuffEventLoop consensus.FastHotStuffEventLoop
	blockchain            *Blockchain
	params                *DeSoParams
	signer                *BLSSigner
}

func NewConsensusController(blockchain *Blockchain, signer *BLSSigner) *ConsensusController {
	return &ConsensusController{
		blockchain:            blockchain,
		fastHotStuffEventLoop: consensus.NewFastHotStuffEventLoop(),
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
// then it constructs, processes locally, and then and broadcasts the block.
//
// Steps:
// 1. Verify that the block height we want to propose at is valid
// 2. Get a QC from the consensus module
// 3. Iterate over the top n transactions from the mempool
// 4. Construct a block with the QC and the top n transactions from the mempool
// 5. Sign the block
// 6. Process the block locally
// - This will connect the block to the blockchain, remove the transactions from the
// - mempool, and process the vote in the consensus module
// 7. Broadcast the block to the network
func (cc *ConsensusController) HandleFastHostStuffBlockProposal(event *consensus.FastHotStuffEvent) {
	// Hold a read lock on the consensus controller. This is because we need to check the
	// current view and block height of the consensus module.
	cc.lock.Lock()
	defer cc.lock.Unlock()

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

func (cc *ConsensusController) HandleGetBlocks(pp *Peer, msg *MsgDeSoGetBlocks) {
	// TODO
}

func (cc *ConsensusController) HandleHeader(pp *Peer, msg *MsgDeSoHeader) {
	// TODO
}

func (cc *ConsensusController) HandleBlock(pp *Peer, msg *MsgDeSoBlock) {
	// TODO
}

// fetchValidatorListsForSafeBlocks takes in a set of safe blocks that can be extended from, this functions
// fetches the validator set and returns them as type BlockWithValidatorList so they can be passed to the
// FastHotStuffEventLoop. If the input blocks precede the committed tip or they do no exist within the current
// or next epoch after the committed tip, then this function returns an error. In this case, the blocks cannot
// possibly be safe blocks.
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
	utxoView, err := NewUtxoView(cc.blockchain.db, cc.params, nil, cc.blockchain.snapshot, nil)
	if err != nil {
		return nil, errors.Errorf("error creating UtxoView: %v", err)
	}

	// Fetch the current epoch entry for the committed tip
	epochEntryAtCommittedTip, err := utxoView.GetCurrentEpochEntry()
	if err != nil {
		return nil, errors.Errorf("error fetching epoch entry for committed tip: %v", err)
	}

	// Fetch the next epoch entry after the committed tip
	nextEpochEntryAfterCommittedTip, err := utxoView.SimulateNextEpochEntry(epochEntryAtCommittedTip)
	if err != nil {
		return nil, errors.Errorf("error fetching next epoch entry after committed tip: %v", err)
	}

	// The input blocks can only be part of the current or next epoch entries starting from the committed tip's height.
	possibleEpochEntriesForBlocks := []*EpochEntry{epochEntryAtCommittedTip, nextEpochEntryAfterCommittedTip}

	// Fetch the validator set at each block
	blocksWithValidatorLists := make([]consensus.BlockWithValidatorList, len(blocks))
	for ii, block := range blocks {
		// Find the epoch entry for the block. It'll either be the current epoch entry or the next one.
		epochEntryForBlock, err := getEpochEntryForBlock(block, possibleEpochEntriesForBlocks)
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

		// If the validator set for the block is already cached by the epoch number, then use it.
		// Otherwise, fetch it from the UtxoView.
		//
		// We want to use the validator set after connecting the block and triggering an epoch transition
		// (if there is one), because we want to fetch the validator set needed to validate the next block after
		// the tip block.
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
func getEpochEntryForBlock(block *MsgDeSoHeader, epochEntries []*EpochEntry) (*EpochEntry, error) {
	for _, epochEntry := range epochEntries {
		if epochEntry.ContainsBlockHeight(block.Height) {
			return epochEntry, nil
		}
	}

	return nil, errors.Errorf("error finding epoch number for block height: %v", block.Height)
}

////////////////////////////////////////////////////////////////////////////////
// TODO: delete all of the functions below. They are dummy stubbed out functions
// needed by ConsensusController, but are implemented in other feature branches.
// We stub them out here to unblock consensus work.
////////////////////////////////////////////////////////////////////////////////

func (bc *Blockchain) getUtxoViewAtBlockHash(blockHash BlockHash) (*UtxoView, error) {
	return nil, errors.New("getUtxoViewAtBlockHash: replace me with a real implementation later")
}

func (bav *UtxoView) SimulateNextEpochEntry(epochEntry *EpochEntry) (*EpochEntry, error) {
	return nil, errors.New("SimulateNextEpochEntry: replace me with a real implementation later")
}

func (bav *UtxoView) ComputeSnapshotEpochNumberForEpoch(epochNumber uint64) (uint64, error) {
	return 0, errors.New("ComputeSnapshotEpochNumberForEpoch: replace me with a real implementation later")
}

func (bav *UtxoView) GetAllSnapshotValidatorSetEntriesByStakeAtEpochNumber(snapshotAtEpochNumber uint64) ([]*ValidatorEntry, error) {
	return nil, errors.New("GetAllSnapshotValidatorSetEntriesByStakeAtEpochNumber: replace me with a real implementation later")
}

func (epochEntry *EpochEntry) ContainsBlockHeight(blockHeight uint64) bool {
	// TODO: Implement this later
	return false
}
