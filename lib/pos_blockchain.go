package lib

import (
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/consensus"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"math"
	"time"
)

// processBlockPoS runs the Fast-Hotstuff block connect and commit rule as follows:
//  1. Determine if we're missing the parent block of this block.
//     If so, return the hash of the missing block and add this block to the orphans list.
//  2. Validate on an incoming block, its header, its block height, the leader, and its QCs (vote or timeout)
//  3. Store the block in the block index and uncommitted blocks map.
//  4. Resolves forks within the last two blocks
//  5. Connect the block to the blockchain's tip
//  6. Run the commit rule - If applicable, flushes the incoming block's grandparent to the DB
//  7. Prune in-memory struct holding uncommitted block.
//  8. Update the currentView to this new block's view + 1
func (bc *Blockchain) processBlockPoS(desoBlock *MsgDeSoBlock, currentView uint64, verifySignatures bool) (_success bool, _isOrphan bool, _missingBlockHashes []*BlockHash, _err error) {
	// 1. Determine if we're missing the parent block of this block. If it's parent exists in the blockIndex,
	// it is safe to assume we have all ancestors of this block in the block index.
	// If the parent block is missing, process the orphan, but don't add to the block index or uncommitted block map.
	lineageFromCommittedTip, err := bc.getLineageFromCommittedTip(desoBlock)
	if err != nil && err != RuleErrorMissingAncestorBlock {
		return false, false, nil, err
	}

	if err == RuleErrorMissingAncestorBlock {
		missingBlockHashes := []*BlockHash{desoBlock.Header.PrevBlockHash}
		blockHash, err := desoBlock.Header.Hash()
		// If we fail to get the block hash, this block isn't valid at all, so we
		// don't need to worry about adding it to the orphan list or block index.
		if err != nil {
			return false, true, missingBlockHashes, err
		}
		// ProcessOrphanBlock validates the block and adds it to the orphan list.
		// TODO: update _validateOrphanBlock to perform additional validation required.
		if err = bc.ProcessOrphanBlock(desoBlock, blockHash); err != nil {
			return false, true, missingBlockHashes, errors.Wrap(err, "processBlockPoS: Problem processing orphan block: ")
		}
		return false, true, missingBlockHashes, nil
	}

	// 2. Start with all sanity checks of the block.
	// TODO: Check if err is for view > latest committed block view and <= latest uncommitted block.
	// If so, we need to perform the rest of the validations and then add to our block index.
	if err = bc.validateDeSoBlockPoS(desoBlock); err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: block validation failed: ")
	}

	utxoView, err := bc.getUtxoViewAtBlockHash(*desoBlock.Header.PrevBlockHash)
	if err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem initializing UtxoView: ")
	}
	validatorsByStake, err := utxoView.GetAllSnapshotValidatorSetEntriesByStake()
	if err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem getting validator set: ")
	}
	// 1e. Validate QC
	if err = bc.validateQC(desoBlock, validatorsByStake); err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: QC validation failed: ")
	}

	// @sofonias @piotr - should we move this to
	// If the block doesn’t contain a ValidatorsTimeoutAggregateQC, then that indicates that we
	// did NOT timeout in the previous view, which means we should just check that
	// the QC corresponds to the previous view.
	if desoBlock.Header.ValidatorsTimeoutAggregateQC.isEmpty() {
		// The block is safe to vote on if it is a direct child of the previous
		// block. This means that the parent and child blocks have consecutive
		// views. We use the current block’s QC to find the view of the parent.
		// TODO: Any processing related to the block's vote QC.
	} else {
		// TODO: Get highest timeout QC from the block.
		// We find the QC with the highest view among the QCs contained in the
		// AggregateQC.
		var highestTimeoutQC *QuorumCertificate
		// TODO: Check if our local highestQC has a smaller view than the highestTimeoutQC.
		// If our local highestQC has a smaller view than the highestTimeoutQC,
		// we update our local highestQC.
		_ = highestTimeoutQC
	}

	// 2. We can now add this block to the block index since we have performed
	// all basic validations. We can also add it to the uncommittedBlocksMap
	if err = bc.addBlockToBlockIndex(desoBlock); err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem adding block to block index: ")
	}

	// 4. Handle reorgs if necessary
	if _, err = bc.tryReorgToNewTip(desoBlock, currentView, lineageFromCommittedTip); err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem handling reorg: ")
	}

	// Happy path
	// Make a block node struct for this block.
	newBlockNode, err := bc.msgDeSoBlockToNewBlockNode(desoBlock)
	if err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem creating new block node: ")
	}
	// 5. Add block to best chain.
	bc.addBlockToBestChain(newBlockNode)

	// 6. Commit grandparent if possible.
	if err = bc.runCommitRuleOnBestChain(); err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: error committing grandparents: ")
	}

	// 7. Update in-memory struct holding uncommitted blocks.
	if err = bc.pruneUncommittedBlocks(desoBlock); err != nil {
		// We glog and continue here as failing to prune the uncommitted blocks map is not a
		// critical error.
		glog.Errorf("processBlockPoS: Error pruning uncommitted blocks: %v", err)
	}

	// 8. Update current view to block's view + 1
	bc.updateCurrentView(desoBlock)

	return true, false, nil, nil
}

// validateDeSoBlockPoS performs all basic validations on a block as it relates to
// the Blockchain struct.
func (bc *Blockchain) validateDeSoBlockPoS(desoBlock *MsgDeSoBlock) error {
	// Surface Level validation of the block
	if err := bc.validateBlockIntegrity(desoBlock); err != nil {
		return err
	}
	// Validate Block Height
	if err := bc.validateBlockHeight(desoBlock); err != nil {
		return err
	}
	// Validate View
	if err := bc.validateBlockView(desoBlock); err != nil {
		// Check if err is for view > latest committed block view and <= latest uncommitted block.
		// If so, we need to perform the rest of the validations and then add to our block index.
		// TODO: implement check on error described above. Caller will handle this.
		return err
	}
	// Validate Leader
	if err := bc.validateBlockLeader(desoBlock); err != nil {
		return err
	}
	return nil
}

// validateBlockIntegrity validates the block at a surface level. It checks
// that the timestamp is valid, that the version of the header is valid,
// and other general integrity checks (such as not malformed).
func (bc *Blockchain) validateBlockIntegrity(desoBlock *MsgDeSoBlock) error {
	// First make sure we have a non-nil header
	if desoBlock.Header == nil {
		return RuleErrorNilBlockHeader
	}

	// Make sure we have a prevBlockHash
	if desoBlock.Header.PrevBlockHash == nil {
		return RuleErrorNilPrevBlockHash
	}

	// Timestamp validation

	// Validate that the timestamp is not less than its parent.
	parentBlock, exists := bc.blockIndex[*desoBlock.Header.PrevBlockHash]
	if !exists {
		// Note: this should never happen as we only call this function after
		// we've validated that all ancestors exist in the block index.
		return RuleErrorMissingParentBlock
	}
	if desoBlock.Header.TstampNanoSecs < parentBlock.Header.TstampNanoSecs {
		return RuleErrorPoSBlockTstampNanoSecsTooOld
	}
	// TODO: Add support for putting the drift into global params.
	if desoBlock.Header.TstampNanoSecs > uint64(time.Now().UnixNano())+bc.params.DefaultBlockTimestampDriftNanoSecs {
		return RuleErrorPoSBlockTstampNanoSecsInFuture
	}

	// Header validation
	if desoBlock.Header.Version != HeaderVersion2 {
		return RuleErrorInvalidPoSBlockHeaderVersion
	}

	// Malformed block checks
	// Require header to have either vote or timeout QC
	isTimeoutQCEmpty := desoBlock.Header.ValidatorsTimeoutAggregateQC.isEmpty()
	isVoteQCEmpty := desoBlock.Header.ValidatorsVoteQC.isEmpty()
	if isTimeoutQCEmpty && isVoteQCEmpty {
		return RuleErrorNoTimeoutOrVoteQC
	}

	if !isTimeoutQCEmpty && !isVoteQCEmpty {
		return RuleErrorBothTimeoutAndVoteQC
	}

	if !isTimeoutQCEmpty && len(desoBlock.Txns) != 0 {
		return RuleErrorTimeoutQCWithTransactions
	}

	if desoBlock.Header.ProposerVotingPublicKey.IsEmpty() {
		return RuleErrorInvalidProposerVotingPublicKey
	}

	if desoBlock.Header.ProposerPublicKey == nil || desoBlock.Header.ProposerPublicKey.IsZeroPublicKey() {
		return RuleErrorInvalidProposerPublicKey
	}

	if desoBlock.Header.ProposerRandomSeedHash.isEmpty() {
		return RuleErrorInvalidRandomSeedHash
	}

	merkleRoot := desoBlock.Header.TransactionMerkleRoot

	// We only want to check the merkle root if we have more than 0 transactions.
	if len(desoBlock.Txns) > 0 {
		if merkleRoot == nil {
			return RuleErrorNilMerkleRoot
		}
		computedMerkleRoot, _, err := ComputeMerkleRoot(desoBlock.Txns)
		if err != nil {
			return errors.Wrapf(err, "validateBlockIntegrity: Problem computing merkle root")
		}
		if !merkleRoot.IsEqual(computedMerkleRoot) {
			return RuleErrorInvalidMerkleRoot
		}
	} else {
		if merkleRoot != nil {
			return RuleErrorNoTxnsWithMerkleRoot
		}
	}

	// TODO: What other checks do we need to do here?
	return nil
}

// validateBlockHeight validates the block height for a given block. First,
// it checks that we've passed the PoS cutover fork height. Then it checks
// that this block height is exactly one greater than its parent's block height.
func (bc *Blockchain) validateBlockHeight(desoBlock *MsgDeSoBlock) error {
	blockHeight := desoBlock.Header.Height
	if blockHeight < uint64(bc.params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight) {
		return RuleErrorPoSBlockBeforeCutoverHeight
	}
	// Validate that the block height is exactly one greater than its parent.
	parentBlock, exists := bc.blockIndex[*desoBlock.Header.PrevBlockHash]
	if !exists {
		// Note: this should never happen as we only call this function after
		// we've validated that all ancestors exist in the block index.
		return RuleErrorMissingParentBlock
	}
	if desoBlock.Header.Height != parentBlock.Header.Height+1 {
		return RuleErrorInvalidPoSBlockHeight
	}
	return nil
}

// validateBlockView validates the view for a given block. First, it checks that
// the view is greater than the latest committed block view. If not,
// we return an error indicating that we'll never accept this block. Next,
// it checks that the view is less than or equal to its parent.
// If not, we return an error indicating that we'll want to add this block as an
// orphan. Then it will check if that the view is exactly one greater than the
// latest uncommitted block if we have an regular vote QC. If this block has a
// timeout QC, it will check that the view is at least greater than the latest
// uncommitted block's view + 1.
func (bc *Blockchain) validateBlockView(desoBlock *MsgDeSoBlock) error {
	// Validate that the view is greater than the latest uncommitted block.
	parentBlock, exists := bc.blockIndex[*desoBlock.Header.PrevBlockHash]
	if !exists {
		// Note: this should never happen as we only call this function after
		// we've validated that all ancestors exist in the block index.
		return RuleErrorMissingParentBlock
	}
	// If our current block has a vote QC, then we need to validate that the
	// view is exactly one greater than the latest uncommitted block.
	if desoBlock.Header.ValidatorsTimeoutAggregateQC.isEmpty() {
		if desoBlock.Header.ProposedInView != parentBlock.Header.ProposedInView+1 {
			return RuleErrorPoSVoteBlockViewNotOneGreaterThanParent
		}
	} else {
		// If our current block has a timeout QC, then we need to validate that the
		// view is strictly greater than the latest uncommitted block's view.
		if desoBlock.Header.ProposedInView <= parentBlock.Header.ProposedInView {
			return RuleErrorPoSTimeoutBlockViewNotGreaterThanParent
		}
	}
	return nil
}

// validateBlockLeader validates that the proposer is the expected proposer for the
// block height + view number pair.
func (bc *Blockchain) validateBlockLeader(desoBlock *MsgDeSoBlock) error {
	utxoView, err := NewUtxoView(bc.db, bc.params, bc.postgres, bc.snapshot)
	if err != nil {
		return errors.Wrapf(err, "validateBlockLeader: Problem initializing UtxoView")
	}
	currentEpochEntry, err := utxoView.GetCurrentEpochEntry()
	if err != nil {
		return errors.Wrapf(err, "validateBlockLeader: Problem getting current epoch entry")
	}
	leaders, err := utxoView.GetSnapshotLeaderSchedule()
	if err != nil {
		return errors.Wrapf(err, "validateBlockLeader: Problem getting leader schedule")
	}
	if len(leaders) == 0 {
		return errors.Wrapf(err, "validateBlockLeader: No leaders found in leader schedule")
	}
	if desoBlock.Header.Height < currentEpochEntry.InitialBlockHeight {
		return RuleErrorBlockHeightLessThanInitialHeightForEpoch
	}
	if desoBlock.Header.ProposedInView < currentEpochEntry.InitialView {
		return RuleErrorBlockViewLessThanInitialViewForEpoch
	}
	heightDiff := desoBlock.Header.Height - currentEpochEntry.InitialBlockHeight
	viewDiff := desoBlock.Header.ProposedInView - currentEpochEntry.InitialView
	if viewDiff < heightDiff {
		return RuleErrorBlockDiffLessThanHeightDiff
	}
	// We compute the current index in the leader schedule as follows:
	// [(block.View - currentEpoch.InitialView) - (block.Height - currentEpoch.InitialHeight)] % len(leaders)
	// The number of views that have elapsed since the start of the epoch is block.View - currentEpoch.InitialView.
	// The number of blocks that have been added to the chain since the start of the epoch is block.Height - currentEpoch.InitialHeight.
	// The difference between these two numbers is the number of timeouts that have occurred in this epoch.
	// For each timeout, we need to go to the next leader in the schedule.
	// If we have more timeouts than leaders in the schedule, we start from the top of the schedule again,
	// which is why we take the modulo of the length of the leader schedule.
	// A quick example: If we have 3 leaders in the schedule and the epoch started at height 10 and view 11,
	// and the current block is at height 15 and view 17, then the number of timeouts that have occurred is
	// (17 - 11) - (15 - 10) = 1. This means this block should be proposed by the 2nd leader in the schedule,
	// which is at index 1.
	leaderIdxUint64 := (viewDiff - heightDiff) % uint64(len(leaders))
	if leaderIdxUint64 > math.MaxUint16 {
		return RuleErrorLeaderIdxExceedsMaxUint16
	}
	leaderIdx := uint16(leaderIdxUint64)
	leaderEntry, err := utxoView.GetSnapshotLeaderScheduleValidator(leaderIdx)
	if err != nil {
		return errors.Wrapf(err, "validateBlockLeader: Problem getting leader schedule validator")
	}
	leaderPKIDFromBlock := utxoView.GetPKIDForPublicKey(desoBlock.Header.ProposerPublicKey[:])
	if !leaderEntry.VotingPublicKey.Eq(desoBlock.Header.ProposerVotingPublicKey) ||
		!leaderEntry.ValidatorPKID.Eq(leaderPKIDFromBlock.PKID) {
		return RuleErrorLeaderForBlockDoesNotMatchSchedule
	}
	return nil
}

// validateQC validates that the QC of this block is valid, meaning a super majority
// of the validator set has voted (or timed out). Assumes ValidatorEntry list is sorted.
func (bc *Blockchain) validateQC(desoBlock *MsgDeSoBlock, validatorSet []*ValidatorEntry) error {
	validators := toConsensusValidators(validatorSet)
	if !desoBlock.Header.ValidatorsTimeoutAggregateQC.isEmpty() {
		if !consensus.IsValidSuperMajorityAggregateQuorumCertificate(desoBlock.Header.ValidatorsTimeoutAggregateQC, validators) {
			return RuleErrorInvalidTimeoutQC
		}
		return nil
	}
	if !consensus.IsValidSuperMajorityQuorumCertificate(desoBlock.Header.ValidatorsVoteQC, validators) {
		return RuleErrorInvalidVoteQC
	}
	return nil
}

// getLineageFromCommittedTip returns the ancestors of the block provided up to, but not
// including the committed tip. The first block in the returned slice is the first uncommitted
// ancestor.
func (bc *Blockchain) getLineageFromCommittedTip(desoBlock *MsgDeSoBlock) ([]*BlockNode, error) {
	highestCommittedBlock, idx := bc.getHighestCommittedBlock()
	if idx == -1 || highestCommittedBlock == nil {
		return nil, errors.New("getLineageFromCommittedTip: No committed blocks found")
	}
	currentHash := desoBlock.Header.PrevBlockHash.NewBlockHash()
	ancestors := []*BlockNode{}
	for {
		currentBlock, exists := bc.blockIndex[*currentHash]
		if !exists {
			return nil, RuleErrorMissingAncestorBlock
		}
		if currentBlock.Hash.IsEqual(highestCommittedBlock.Hash) {
			break
		}
		if currentBlock.CommittedStatus == COMMITTED {
			return nil, RuleErrorDoesNotExtendCommittedTip
		}
		ancestors = append(ancestors, currentBlock)
		currentHash = currentBlock.Header.PrevBlockHash
	}
	collections.Reverse(ancestors)
	return ancestors, nil
}

// addBlockToBlockIndex adds the block to the block index and uncommitted blocks map.
func (bc *Blockchain) addBlockToBlockIndex(desoBlock *MsgDeSoBlock) error {
	hash, err := desoBlock.Hash()
	if err != nil {
		return errors.Wrapf(err, "addBlockToBlockIndex: Problem hashing block %v", desoBlock)
	}
	// Need to get parent block node from block index
	prevBlock := bc.blockIndex[*desoBlock.Header.PrevBlockHash]
	// TODO: What should the block status be here? Validated? What combo is correct? Need to check in with Diamondhands.
	bc.blockIndex[*hash] = NewPoSBlockNode(prevBlock, hash, uint32(desoBlock.Header.Height), desoBlock.Header, StatusHeaderValidated|StatusBlockValidated, UNCOMMITTED)

	bc.uncommittedBlocksMap[*hash] = desoBlock
	return nil
}

// shouldReorg determines if we should reorg to the block provided. We should reorg if
// this block is proposed in a view greater than or equal to the currentView. Other
// functions have validated that this block is not extending from a committed block
// that is not the latest committed block, so there is no need to validate that here.
func (bc *Blockchain) shouldReorg(desoBlock *MsgDeSoBlock, currentView uint64) bool {
	chainTip := bc.GetBestChainTip()
	// If this block extends from the chain tip, there's no need to reorg.
	if chainTip.Hash.IsEqual(desoBlock.Header.PrevBlockHash) {
		return false
	}
	// If the block is proposed in a view less than the current view, there's no need to reorg.
	return desoBlock.Header.ProposedInView >= currentView
}

// tryReorgToNewTip handles a reorg to the block provided. It will do the following:
// 1. Check if we should perform a reorg. If not, exit early.
// 2. Update the bestChain and bestChainMap by removing blocks that are uncommitted and are not ancestors of this block.
// 3. Update the bestChain and bestChainMap by adding blocks that are uncommitted ancestors of this block.
// Note: addBlockToBestChain will be called after this to handle adding THIS block to the best chain.
func (bc *Blockchain) tryReorgToNewTip(desoBlock *MsgDeSoBlock, currentView uint64, lineageFromCommittedTip []*BlockNode) (_hasReorg bool, _err error) {
	// Check if we should perform a reorg here
	if !bc.shouldReorg(desoBlock, currentView) {
		return false, nil
	}
	// For simplicity, we remove all uncommitted blocks and then re-add them.
	highestCommittedBlock, idx := bc.getHighestCommittedBlock()
	if highestCommittedBlock == nil || idx == -1 {
		// This is an edge case we'll never hit in practice since all the PoW blocks
		// are committed.
		return false, errors.New("tryReorgToNewTip: No committed blocks found")
	}

	// Remove all uncommitted blocks. These are all blocks that come after the highestCommittedBlock
	// in the best chain.
	// Delete all blocks from bc.bestChainMap that come after the highest committed block.
	for ii := idx + 1; ii < len(bc.bestChain); ii++ {
		delete(bc.bestChainMap, *bc.bestChain[ii].Hash)
	}
	// Shorten best chain back to committed tip.
	bc.bestChain = bc.bestChain[:idx+1]

	for _, ancestor := range lineageFromCommittedTip {
		bc.addBlockToBestChain(ancestor)
	}
	return true, nil
}

func (bc *Blockchain) msgDeSoBlockToNewBlockNode(desoBlock *MsgDeSoBlock) (*BlockNode, error) {
	parent, exists := bc.blockIndex[*desoBlock.Header.PrevBlockHash]
	if !exists {
		return nil, errors.Errorf("msgDeSoBlockToNewBlockNode: Parent block %v not found in block index", desoBlock.Header.PrevBlockHash)
	}
	hash, err := desoBlock.Hash()
	if err != nil {
		return nil, errors.Wrapf(err, "msgDeSoBlockToNewBlockNode: Problem hashing block %v", desoBlock)
	}
	// TODO: What's the proper status?
	return NewPoSBlockNode(parent, hash, uint32(desoBlock.Header.Height), desoBlock.Header, StatusBlockValidated, UNCOMMITTED), nil
}

// addBlockToBestChain adds the block to the best chain.
func (bc *Blockchain) addBlockToBestChain(desoBlockNode *BlockNode) {
	bc.bestChain = append(bc.bestChain, desoBlockNode)
	bc.bestChainMap[*desoBlockNode.Hash] = desoBlockNode
}

// pruneUncommittedBlocks prunes the in-memory struct holding uncommitted blocks.
func (bc *Blockchain) pruneUncommittedBlocks(desoBlock *MsgDeSoBlock) error {
	// TODO: Implement me.
	return errors.New("IMPLEMENT ME")
}

// runCommitRuleOnBestChain commits the grandparent of the block if possible.
// Specifically, this updates the CommittedBlockStatus of its grandparent
// and flushes the view after connecting the grandparent block to the DB.
func (bc *Blockchain) runCommitRuleOnBestChain() error {
	currentBlock := bc.GetBestChainTip()
	// If we can commit the grandparent, commit it.
	// Otherwise, we can't commit it and return nil.
	blockToCommit, canCommit := bc.canCommitGrandparent(currentBlock)
	if !canCommit {
		return nil
	}
	// Find all uncommitted ancestors of block to commit
	_, idx := bc.getHighestCommittedBlock()
	if idx == -1 {
		// This is an edge case we'll never hit in practice since all the PoW blocks
		// are committed.
		return errors.New("runCommitRuleOnBestChain: No committed blocks found")
	}
	uncommittedAncestors := []*BlockNode{}
	for ii := idx + 1; ii < len(bc.bestChain); ii++ {
		uncommittedAncestors = append(uncommittedAncestors, bc.bestChain[ii])
		if bc.bestChain[ii].Hash.IsEqual(blockToCommit) {
			break
		}
	}
	for ii := 0; ii < len(uncommittedAncestors); ii++ {
		if err := bc.commitBlock(uncommittedAncestors[ii].Hash); err != nil {
			return errors.Wrapf(err, "runCommitRuleOnBestChain: Problem committing block %v", uncommittedAncestors[ii].Hash.String())
		}
	}
	return nil
}

// canCommitGrandparent determines if the grandparent of the current block can be committed.
// The grandparent can be committed if there exists a direct parent-child relationship
// between the grandparent and parent of the new block, meaning the grandparent and parent
// are proposed in consecutive views, and the "parent" is an ancestor of the incoming block (not necessarily consecutive views).
// Additionally, the grandparent must not already be committed.
func (bc *Blockchain) canCommitGrandparent(currentBlock *BlockNode) (_grandparentBlockHash *BlockHash, _canCommit bool) {
	// TODO: Is it sufficient that the current block's header points to the parent
	// or does it need to have something to do with the QC?
	parent := bc.bestChainMap[*currentBlock.Header.PrevBlockHash]
	grandParent := bc.bestChainMap[*parent.Header.PrevBlockHash]
	if grandParent.CommittedStatus == COMMITTED {
		return nil, false
	}
	if grandParent.Header.ProposedInView == parent.Header.ProposedInView-1 {
		// Then we can run the commit rule up to the grandparent!
		return grandParent.Hash, true
	}
	return nil, false
}

// commitBlock commits the block with the given hash. Specifically, this updates the
// CommittedBlockStatus of the block and flushes the view after connecting the block
// to the DB and updates relevant badger indexes with info about the block.
func (bc *Blockchain) commitBlock(blockHash *BlockHash) error {
	block, exists := bc.uncommittedBlocksMap[*blockHash]
	if !exists {
		return errors.Errorf("commitBlock: Block %v not found in uncommitted blocks map", blockHash.String())
	}
	// block must be in the best chain. we grab the block node from there.
	blockNode, exists := bc.bestChainMap[*blockHash]
	if !exists {
		return errors.Errorf("commitBlock: Block %v not found in best chain map", blockHash.String())
	}
	// Connect a view up to the parent of the block we are committing.
	utxoView, err := bc.getUtxoViewAtBlockHash(*block.Header.PrevBlockHash)
	if err != nil {
		return errors.Wrapf(err, "runCommitRuleOnBestChain: Problem initializing UtxoView: ")
	}
	// Get the full uncommitted block from the uncommitted blocks map
	grandParentBlock, exists := bc.uncommittedBlocksMap[*blockHash]
	if !exists {
		return errors.Errorf("runCommitRuleOnBestChain: Block %v not found in uncommitted blocks map", blockHash.String())
	}
	txHashes := collections.Transform(grandParentBlock.Txns, func(txn *MsgDeSoTxn) *BlockHash {
		return txn.Hash()
	})
	// Connect the block to the view!
	utxoOpsForBlock, err := utxoView.ConnectBlock(grandParentBlock, txHashes, true /*verifySignatures*/, bc.eventManager, block.Header.Height)
	if err != nil {
		// TODO: rule error handling? mark blocks invalid?
		return errors.Wrapf(err, "runCommitRuleOnBestChain: Problem connecting block to view: ")
	}
	// Put the block in the db
	// Note: we're skipping postgres.
	// TODO: this is copy pasta from ProcessBlockPoW. Refactor.
	err = bc.db.Update(func(txn *badger.Txn) error {
		if bc.snapshot != nil {
			bc.snapshot.PrepareAncestralRecordsFlush()
			defer bc.snapshot.StartAncestralRecordsFlush(true)
			glog.V(2).Infof("ProcessBlock: Preparing snapshot flush")
		}
		// Store the new block in the db under the
		//   <blockHash> -> <serialized block>
		// index.
		// TODO: In the archival mode, we'll be setting ancestral entries for the block reward. Note that it is
		// 	set in PutBlockWithTxn. Block rewards are part of the state, and they should be identical to the ones
		// 	we've fetched during Hypersync. Is there an edge-case where for some reason they're not identical? Or
		// 	somehow ancestral records get corrupted?
		if innerErr := PutBlockWithTxn(txn, bc.snapshot, block); innerErr != nil {
			return errors.Wrapf(err, "ProcessBlock: Problem calling PutBlock")
		}

		// Store the new block's node in our node index in the db under the
		//   <height uin32, blockHash BlockHash> -> <node info>
		// index.
		if innerErr := PutHeightHashToNodeInfoWithTxn(txn, bc.snapshot, blockNode, false /*bitcoinNodes*/); innerErr != nil {
			return errors.Wrapf(err, "ProcessBlock: Problem calling PutHeightHashToNodeInfo before validation")
		}

		// Set the best node hash to this one. Note the header chain should already
		// be fully aware of this block so we shouldn't update it here.
		if innerErr := PutBestHashWithTxn(txn, bc.snapshot, blockNode.Hash, ChainTypeDeSoBlock); innerErr != nil {
			return errors.Wrapf(innerErr, "ProcessBlock: Problem calling PutBestHash after validation")
		}
		// Write the utxo operations for this block to the db so we can have the
		// ability to roll it back in the future.
		if innerErr := PutUtxoOperationsForBlockWithTxn(txn, bc.snapshot, uint64(blockNode.Height), blockNode.Hash, utxoOpsForBlock); innerErr != nil {
			return errors.Wrapf(innerErr, "ProcessBlock: Problem writing utxo operations to db on simple add to tip")
		}
		if innerErr := utxoView.FlushToDbWithTxn(txn, uint64(blockNode.Height)); innerErr != nil {
			return errors.Wrapf(innerErr, "ProcessBlock: Problem flushing UtxoView to db")
		}
		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "runCommitRuleOnBestChain: Problem putting block in db: ")
	}
	// Update the block node's committed status
	bc.bestChainMap[*blockNode.Hash].CommittedStatus = COMMITTED
	bc.blockIndex[*blockNode.Hash].CommittedStatus = COMMITTED
	for _, node := range bc.bestChain {
		if node.Hash.IsEqual(blockNode.Hash) {
			node.CommittedStatus = COMMITTED
			break
		}
	}
	if bc.eventManager != nil {
		bc.eventManager.blockConnected(&BlockEvent{
			Block:    block,
			UtxoView: utxoView,
			UtxoOps:  utxoOpsForBlock,
		})
	}
	// TODO: What else do we need to do in here?
	return nil
}

// updateCurrentView updates the current view to the block's view + 1.
func (bc *Blockchain) updateCurrentView(desoBlock *MsgDeSoBlock) {
	// TODO: Implement me.
	panic(errors.New("IMPLEMENT ME"))
}

// GetUncommittedTipView builds a UtxoView to the uncommitted tip.
func (bc *Blockchain) GetUncommittedTipView() (*UtxoView, error) {
	// Connect the uncommitted blocks to the tip so that we can validate subsequent blocks
	return bc.getUtxoViewAtBlockHash(*bc.GetBestChainTip().Hash)
}

// getUtxoViewAtBlockHash builds a UtxoView to the block provided. It does this by
// identifying all uncommitted ancestors of this block and then connecting those blocks.
func (bc *Blockchain) getUtxoViewAtBlockHash(blockHash BlockHash) (*UtxoView, error) {
	uncommittedAncestors := []*BlockNode{}
	currentBlock := bc.blockIndex[blockHash]
	if currentBlock == nil {
		return nil, errors.Errorf("getUtxoViewAtBlockHash: Block %v not found in block index", blockHash)
	}
	// If the provided block is committed, we need to make sure it's the committed tip.
	// Otherwise, we return an error.
	if currentBlock.CommittedStatus == COMMITTED {
		highestCommittedBlock, _ := bc.getHighestCommittedBlock()
		if highestCommittedBlock == nil {
			return nil, errors.Errorf("getUtxoViewAtBlockHash: No committed blocks found")
		}
		if !highestCommittedBlock.Hash.IsEqual(&blockHash) {
			return nil, errors.Errorf("getUtxoViewAtBlockHash: Block %v is committed but not the committed tip", blockHash)
		}
	}
	for currentBlock.CommittedStatus == UNCOMMITTED {
		uncommittedAncestors = append(uncommittedAncestors, currentBlock)
		currentParentHash := currentBlock.Header.PrevBlockHash
		if currentParentHash == nil {
			return nil, errors.Errorf("getUtxoViewAtBlockHash: Block %v has nil PrevBlockHash", currentBlock.Hash)
		}
		currentBlock = bc.blockIndex[*currentParentHash]
		if currentBlock == nil {
			return nil, errors.Errorf("getUtxoViewAtBlockHash: Block %v not found in block index", blockHash)
		}
	}
	// Connect the uncommitted blocks to the tip so that we can validate subsequent blocks
	utxoView, err := NewUtxoView(bc.db, bc.params, bc.postgres, bc.snapshot)
	if err != nil {
		return nil, errors.Wrapf(err, "getUtxoViewAtBlockHash: Problem initializing UtxoView")
	}
	for ii := len(uncommittedAncestors) - 1; ii >= 0; ii-- {
		// We need to get these blocks from the uncommitted blocks map
		fullBlock, exists := bc.uncommittedBlocksMap[*uncommittedAncestors[ii].Hash]
		if !exists {
			return nil, errors.Errorf("GetUncommittedTipView: Block %v not found in block index", uncommittedAncestors[ii].Hash)
		}
		txnHashes := collections.Transform(fullBlock.Txns, func(txn *MsgDeSoTxn) *BlockHash {
			return txn.Hash()
		})
		_, err = utxoView.ConnectBlock(fullBlock, txnHashes, false, nil, fullBlock.Header.Height)
		if err != nil {
			hash, _ := fullBlock.Hash()
			return nil, errors.Wrapf(err, "GetUncommittedTipView: Problem connecting block hash %v", hash.String())
		}
	}
	// Always update the tiphash of the utxo view to be the block hash provided.
	utxoView.TipHash = &blockHash
	return utxoView, nil
}

func (bc *Blockchain) GetBestChainTip() *BlockNode {
	return bc.bestChain[len(bc.bestChain)-1]
}

func (bc *Blockchain) getHighestCommittedBlock() (*BlockNode, int) {
	for ii := len(bc.bestChain) - 1; ii >= 0; ii-- {
		if bc.bestChain[ii].CommittedStatus == COMMITTED {
			return bc.bestChain[ii], ii
		}
	}
	return nil, -1
}

const (
	RuleErrorNilBlockHeader                 RuleError = "RuleErrorNilBlockHeader"
	RuleErrorNilPrevBlockHash               RuleError = "RuleErrorNilPrevBlockHash"
	RuleErrorPoSBlockTstampNanoSecsTooOld   RuleError = "RuleErrorPoSBlockTstampNanoSecsTooOld"
	RuleErrorPoSBlockTstampNanoSecsInFuture RuleError = "RuleErrorPoSBlockTstampNanoSecsInFuture"
	RuleErrorInvalidPoSBlockHeaderVersion   RuleError = "RuleErrorInvalidPoSBlockHeaderVersion"
	RuleErrorNoTimeoutOrVoteQC              RuleError = "RuleErrorNoTimeoutOrVoteQC"
	RuleErrorBothTimeoutAndVoteQC           RuleError = "RuleErrorBothTimeoutAndVoteQC"
	RuleErrorTimeoutQCWithTransactions      RuleError = "RuleErrorTimeoutQCWithTransactions"
	RuleErrorMissingParentBlock             RuleError = "RuleErrorMissingParentBlock"
	RuleErrorMissingAncestorBlock           RuleError = "RuleErrorMissingAncestorBlock"
	RuleErrorDoesNotExtendCommittedTip      RuleError = "RuleErrorDoesNotExtendCommittedTip"
	RuleErrorNilMerkleRoot                  RuleError = "RuleErrorNilMerkleRoot"
	RuleErrorInvalidMerkleRoot              RuleError = "RuleErrorInvalidMerkleRoot"
	RuleErrorNoTxnsWithMerkleRoot           RuleError = "RuleErrorNoTxnsWithMerkleRoot"
	RuleErrorInvalidProposerVotingPublicKey RuleError = "RuleErrorInvalidProposerVotingPublicKey"
	RuleErrorInvalidProposerPublicKey       RuleError = "RuleErrorInvalidProposerPublicKey"
	RuleErrorInvalidRandomSeedHash          RuleError = "RuleErrorInvalidRandomSeedHash"

	RuleErrorInvalidPoSBlockHeight       RuleError = "RuleErrorInvalidPoSBlockHeight"
	RuleErrorPoSBlockBeforeCutoverHeight RuleError = "RuleErrorPoSBlockBeforeCutoverHeight"

	RuleErrorPoSVoteBlockViewNotOneGreaterThanParent RuleError = "RuleErrorPoSVoteBlockViewNotOneGreaterThanParent"
	RuleErrorPoSTimeoutBlockViewNotGreaterThanParent RuleError = "RuleErrorPoSTimeoutBlockViewNotGreaterThanParent"

	RuleErrorLeaderForBlockDoesNotMatchSchedule       RuleError = "RuleErrorLeaderForBlockDoesNotMatchSchedule"
	RuleErrorBlockHeightLessThanInitialHeightForEpoch RuleError = "RuleErrorBlockHeightLessThanInitialHeightForEpoch"
	RuleErrorBlockViewLessThanInitialViewForEpoch     RuleError = "RuleErrorBlockViewLessThanInitialViewForEpoch"
	RuleErrorBlockDiffLessThanHeightDiff              RuleError = "RuleErrorBlockDiffLessThanHeightDiff"
	RuleErrorLeaderIdxExceedsMaxUint16                RuleError = "RuleErrorLeaderIdxExceedsMaxUint16"

	RuleErrorInvalidVoteQC    RuleError = "RuleErrorInvalidVoteQC"
	RuleErrorInvalidTimeoutQC RuleError = "RuleErrorInvalidTimeoutQC"
)
