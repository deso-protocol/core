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
//  2. Validate the incoming block, its header, its block height, the leader, and its QCs (vote or timeout)
//  3. Store the block in the block index and save to DB.
//  4. try to apply the incoming block as the tip (performing reorgs as necessary). If it can't be applied, we exit here.
//  5. Run the commit rule - If applicable, flushes the incoming block's grandparent to the DB
func (bc *Blockchain) processBlockPoS(block *MsgDeSoBlock, currentView uint64, verifySignatures bool) (_success bool, _isOrphan bool, _missingBlockHashes []*BlockHash, _err error) {
	if block.Header.Height < uint64(bc.params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight) {
		return false, false, nil, RuleErrorProcessBlockPoSBeforeCutOverHeight
	}
	// Start by pulling out the block hash.
	blockHash, err := block.Header.Hash()
	if err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem hashing block: ")
	}

	// Get all the blocks between the current block and the committed tip. If the block
	// is an orphan, then we store it without validating it. If the block extends from any
	// committed block other than the committed tip, then we throw it away.
	lineageFromCommittedTip, err := bc.getLineageFromCommittedTip(block)
	if err == RuleErrorDoesNotExtendCommittedTip {
		// In this case, the block extends a committed block that is NOT the tip
		// block. There is no point in storing this block because we will never
		// reorg to it.
		return false, false, nil, err

	}
	if err == RuleErrorMissingAncestorBlock {
		// In this case, the block is an orphan that does not extend from any blocks
		// on our best chain. In this case we'll store it with the hope that we
		// will eventually get a parent that connects to our best chain.
		missingBlockHashes := []*BlockHash{block.Header.PrevBlockHash}
		// FIXME: I sketeched some of these steps but not all...
		// Step 0: I think we still need to do some basic validation on this block, like
		// verifying that it's signed by the leader for example to prevent spamming.
		// I didn't do that.
		// Step 1: Create a new BlockNode for this block with status STORED.
		// Step 2: Add it to the blockIndex and store it in Badger. This is handled by addBlockToBlockIndex

		// Add to blockIndex with status STORED only.
		if err = bc.storeBlockInBlockIndex(block); err != nil {
			return false, true, missingBlockHashes, errors.Wrap(err, "processBlockPoS: Problem adding block to block index: ")
		}

		// In this case there is no error. We got a block that seemed ostensibly valid, it just
		// didn't extend from a known block. We request the block's parent as missingBlockHashes.
		return false, true, missingBlockHashes, nil
	}

	// Make sure its parent is validated. If not, we need to validate it first by calling processBlockPoS.
	// Note that if any other ancestor is not validated, calling processBlockPoS on the parent will
	// end up calling processBlockPoS on all of its ancestors that aren't validated yet.
	parentBlockNode, exists := bc.blockIndexByHash[*block.Header.PrevBlockHash]
	if !exists {
		return false, false, nil, errors.New("processBlockPoS: Parent block not found in block index. This should never happen.")
	}
	if parentBlockNode.IsValidateFailed() {
		// We'll never add this to the best chain because its parent is invalid.
		// If its parent is ValidateFailed, we can update the block index with the block status ValidateFailed
		if err = bc.storeValidateFailedBlockInBlockIndex(block); err != nil {
			return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem adding validate failed block to block index")
		}
		return false, false, nil, errors.New("processBlockPoS: block's parent failed validation: ")
	}
	if !parentBlockNode.IsValidated() {
		blk, err := GetBlock(parentBlockNode.Hash, bc.db, bc.snapshot)
		if err != nil {
			return false, false, nil, errors.Wrapf(err, "processBlockPoS: Problem getting parent block %v", parentBlockNode.Hash)
		}
		_, _, _, err = bc.processBlockPoS(blk, currentView, verifySignatures)
		if err != nil {
			return false, false, nil, errors.Wrapf(err, "processBlockPoS: Problem processing parent block %v", parentBlockNode.Hash)
		}
	}

	// At this point, we know that all the ancestors of this block have been successfully
	// validated. That means we can now proceed with attempting to validate THIS block.

	// Do all the sanity checks on the block.
	// TODO: Check if err is for view > latest committed block view and <= latest uncommitted block.
	// If so, we need to perform the rest of the validations and then add to our block index.
	if err = bc.validateDeSoBlockPoS(block); err != nil {
		// TODO: If validations fail, do we want to even bother storing the block? Are there any validations that
		// wouldn't result in us wanting to mark the block as StatusBlockValidateFailed?
		// If validations fail, we can update the block index with the block status ValidateFailed
		if storeInBlockIndexErr := bc.storeValidateFailedBlockInBlockIndex(block); storeInBlockIndexErr != nil {
			return false, false, nil, errors.Wrapf(err, "processBlockPoS: Problem adding validate failed block to block index: %v", storeInBlockIndexErr)
		}
		return false, false, nil, errors.Wrap(err, "processBlockPoS: block validation failed: ")
	}

	// We know the utxoView will be valid because we check that all ancestor blocks have been validated.
	utxoView, err := bc.getUtxoViewAtBlockHash(*block.Header.PrevBlockHash)
	if err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem initializing UtxoView: ")
	}
	// Connect this block to the UtxoView.
	txHashes := collections.Transform(block.Txns, func(txn *MsgDeSoTxn) *BlockHash {
		return txn.Hash()
	})
	_, err = utxoView.ConnectBlock(block, txHashes, true, nil, block.Header.Height)
	if err != nil {
		// If it doesn't connect, do we want to mark it as ValidateFailed and store the block?
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem connecting block to UtxoView: ")
	}

	validatorsByStake, err := utxoView.GetAllSnapshotValidatorSetEntriesByStake()
	if err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem getting validator set: ")
	}
	// TODO(diamondhands): I don't think the TODO below makes sense given the changes but take a look.
	// TODO: If block belongs in the next epoch or it's from an epoch far ahead in the future, we may not be able to validate its QC at all.
	// the validator set for that epoch may be entirely different.
	// A couple of options on how to handle:
	//   - Add utility to UtxoView to fetch the validator set given an arbitrary block height. If we can't fetch the
	//     validator set for the block, then we reject it (even if it later turns out to be a valid block)
	//   - Add block to the block index before QC validation such that even if we aren't able to fetch the validator
	//     set for the block, we can at least store it locally.
	// 2. Validate QC
	if err = bc.validateQC(block, validatorsByStake); err != nil {
		if storeInBlockIndexErr := bc.storeValidateFailedBlockInBlockIndex(block); storeInBlockIndexErr != nil {
			return false, false, nil, errors.Wrapf(err, "processBlockPoS: Problem adding validate failed block to block index: %v", storeInBlockIndexErr)
		}
		return false, false, nil, errors.Wrap(err, "processBlockPoS: QC validation failed: ")
	}

	// 3. We can now add this block to the block index since we have performed
	// all basic validations.
	if err = bc.storeValidatedBlockInBlockIndex(block); err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem adding block to block index: ")
	}
	newBlockNode, exists := bc.blockIndexByHash[*blockHash]
	if !exists {
		return false, false, nil, errors.New("processBlockPoS: Block not found in block index after adding it. " +
			"This should never happen.")
	}

	// 4. Try to apply the incoming block as the new tip. This function will
	// first perform any required reorgs and then determine if the incoming block
	// extends the chain tip. If it does, it will apply the block to the best chain
	// and appliedNewTip will be true and we can continue to running the commit rule.
	appliedNewTip, err := bc.tryApplyNewTip(newBlockNode, currentView, lineageFromCommittedTip)
	if err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem applying new tip: ")
	}

	// If the incoming block is not applied as the new tip, we return early.
	if !appliedNewTip {
		return false, false, nil, nil
	}

	// 5. Commit grandparent if possible.
	if err = bc.runCommitRuleOnBestChain(); err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: error committing grandparents: ")
	}

	// TODO: This should probably happen regardless of whether or not we apply a new tip.
	// Now that we've processed this block, we check for any orphans that
	// are children of this block and try to process them.
	orphansAtNextHeight := bc.blockIndexByHeight[newBlockNode.Height+1]
	for _, orphan := range orphansAtNextHeight {
		if orphan.Header.PrevBlockHash.IsEqual(newBlockNode.Hash) && orphan.IsStored() && !orphan.IsValidated() {
			// TODO: how do we want to handle failures when processing orphans.
			orphanBlock, err := GetBlock(orphan.Hash, bc.db, bc.snapshot)
			if err != nil {
				glog.Errorf("processBlockPoS: Problem getting orphan block %v", orphan.Hash)
				continue
			}
			if _, _, _, err = bc.processBlockPoS(orphanBlock, currentView, verifySignatures); err != nil {
				glog.Errorf("processBlockPoS: Problem processing orphan block %v", orphan.Hash)
				continue
			}
		}
	}

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
	parentBlock, exists := bc.blockIndexByHash[*desoBlock.Header.PrevBlockHash]
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

	// All blocks must have at least one txn
	if len(desoBlock.Txns) == 0 {
		return RuleErrorBlockWithNoTxns
	}
	// Must have non-nil TxnConnectStatusByIndex
	if desoBlock.TxnConnectStatusByIndex == nil {
		return RuleErrorNilTxnConnectStatusByIndex
	}

	// Must have TxnConnectStatusByIndexHash
	if desoBlock.Header.TxnConnectStatusByIndexHash == nil {
		return RuleErrorNilTxnConnectStatusByIndexHash
	}

	// Make sure the TxnConnectStatusByIndex matches the TxnConnectStatusByIndexHash
	if !(HashBitset(desoBlock.TxnConnectStatusByIndex).IsEqual(desoBlock.Header.TxnConnectStatusByIndexHash)) {
		return RuleErrorTxnConnectStatusByIndexHashMismatch
	}

	// Require header to have either vote or timeout QC
	isTimeoutQCEmpty := desoBlock.Header.ValidatorsTimeoutAggregateQC.isEmpty()
	isVoteQCEmpty := desoBlock.Header.ValidatorsVoteQC.isEmpty()
	if isTimeoutQCEmpty && isVoteQCEmpty {
		return RuleErrorNoTimeoutOrVoteQC
	}

	if !isTimeoutQCEmpty && !isVoteQCEmpty {
		return RuleErrorBothTimeoutAndVoteQC
	}

	if desoBlock.Txns[0].TxnMeta.GetTxnType() != TxnTypeBlockReward {
		return RuleErrorBlockDoesNotStartWithRewardTxn
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

	// We always need to check the merkle root.
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
	parentBlock, exists := bc.blockIndexByHash[*desoBlock.Header.PrevBlockHash]
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
	parentBlock, exists := bc.blockIndexByHash[*desoBlock.Header.PrevBlockHash]
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
		currentBlock, exists := bc.blockIndexByHash[*currentHash]
		if !exists {
			return nil, RuleErrorMissingAncestorBlock
		}
		if currentBlock.Hash.IsEqual(highestCommittedBlock.Hash) {
			break
		}
		if currentBlock.IsCommitted() {
			return nil, RuleErrorDoesNotExtendCommittedTip
		}
		ancestors = append(ancestors, currentBlock)
		currentHash = currentBlock.Header.PrevBlockHash
	}
	collections.Reverse(ancestors)
	return ancestors, nil
}

// getOrCreateBlockNodeFromBlockIndex returns the block node from the block index if it exists.
// Otherwise, it creates a new block node and adds it to the blockIndexByHash and blockIndexByHeight.
func (bc *Blockchain) getOrCreateBlockNodeFromBlockIndex(block *MsgDeSoBlock) (*BlockNode, error) {
	hash, err := block.Header.Hash()
	if err != nil {
		return nil, errors.Wrapf(err, "getOrCreateBlockNodeFromBlockIndex: Problem hashing block %v", block)
	}
	blockNode := bc.blockIndexByHash[*hash]
	if blockNode != nil {
		return blockNode, nil
	}
	prevBlockNode := bc.blockIndexByHash[*block.Header.PrevBlockHash]
	newBlockNode := NewBlockNode(prevBlockNode, hash, uint32(block.Header.Height), nil, nil, block.Header, StatusNone)
	bc.blockIndexByHash[*hash] = newBlockNode
	bc.blockIndexByHeight[newBlockNode.Height] = append(bc.blockIndexByHeight[newBlockNode.Height], newBlockNode)
	return newBlockNode, nil
}

// storeBlockInBlockIndex upserts the blocks into the in-memory block index and updates its status to
// StatusBlockStored. It also writes the block to the block index in badger
// by calling upsertBlockAndBlockNodeToDB.
func (bc *Blockchain) storeBlockInBlockIndex(block *MsgDeSoBlock) error {
	blockNode, err := bc.getOrCreateBlockNodeFromBlockIndex(block)
	if err != nil {
		return errors.Wrapf(err, "storeBlockInBlockIndex: Problem getting or creating block node")
	}
	// We should throw an error if the BlockNode is already Stored.
	if blockNode.IsStored() {
		return errors.New("storeBlockInBlockIndex: BlockNode is already stored")
	}
	blockNode.Status |= StatusBlockStored
	return bc.upsertBlockAndBlockNodeToDB(block, blockNode, true)
}

// storeValidatedBlockInBlockIndex upserts the blocks into the in-memory block index and updates its status to
// StatusBlockValidated. If it does not have the status StatusBlockStored already, we add that as we will
// store the block in the DB after updating its status.  It also writes the block to the block index in badger
// by calling upsertBlockAndBlockNodeToDB.
func (bc *Blockchain) storeValidatedBlockInBlockIndex(block *MsgDeSoBlock) error {
	blockNode, err := bc.getOrCreateBlockNodeFromBlockIndex(block)
	if err != nil {
		return errors.Wrapf(err, "storeValidatedBlockInBlockIndex: Problem getting or creating block node")
	}
	// We should throw an error if the BlockNode is already Validated.
	if blockNode.IsValidated() {
		return errors.New("storeValidatedBlockInBlockIndex: BlockNode is already validated")
	}
	blockNode.Status |= StatusBlockValidated
	// If the BlockNode is not already stored, we should set its status to stored.
	if !blockNode.IsStored() {
		blockNode.Status |= StatusBlockStored
	}
	return bc.upsertBlockAndBlockNodeToDB(block, blockNode, true)
}

// storeValidateFailedBlockInBlockIndex upserts the blocks into the in-memory block index and updates its status to
// StatusBlockValidateFailed. If it does not have the status StatusBlockStored already, we add that as we will
// store the block in the DB after updating its status.  It also writes the block to the block index in badger
// by calling upsertBlockAndBlockNodeToDB.
func (bc *Blockchain) storeValidateFailedBlockInBlockIndex(block *MsgDeSoBlock) error {
	blockNode, err := bc.getOrCreateBlockNodeFromBlockIndex(block)
	if err != nil {
		return errors.Wrapf(err, "storeValidateFailedBlockInBlockIndex: Problem getting or creating block node")
	}
	// We should throw an error if the BlockNode is already Validate Failed.
	if blockNode.IsValidateFailed() {
		return errors.New("storeValidateFailedBlockInBlockIndex: BlockNode is already validate failed")
	}
	// We should throw an error if the BlockNode is already Validated
	if blockNode.IsValidated() {
		return errors.New("storeValidateFailedBlockInBlockIndex: can't set BlockNode to validate failed after it's already validated")
	}
	blockNode.Status |= StatusBlockValidateFailed
	// If the BlockNode is not already stored, we should set it to stored.
	if !blockNode.IsStored() {
		blockNode.Status |= StatusBlockStored
	}
	return bc.upsertBlockAndBlockNodeToDB(block, blockNode, false)
}

// storeCommittedBlockInBlockIndex upserts the blocks into the in-memory block index and updates its status to
// StatusBlockCommitted. If the BlockNode does not have StatusBlockValidated and StatusBlockStored statuses,
// we also add those. It also writes the block to the block index in badger by calling upsertBlockAndBlockNodeToDB.
func (bc *Blockchain) storeCommittedBlockInBlockIndex(block *MsgDeSoBlock) error {
	blockNode, err := bc.getOrCreateBlockNodeFromBlockIndex(block)
	if err != nil {
		return errors.Wrapf(err, "storeCommittedBlockInBlockIndex: Problem getting or creating block node")
	}
	// We should throw an error if the BlockNode is already Committed.
	if blockNode.IsCommitted() {
		return errors.New("storeCommittedBlockInBlockIndex: BlockNode is already committed")
	}
	blockNode.Status |= StatusBlockCommitted
	if !blockNode.IsValidated() {
		blockNode.Status |= StatusBlockValidated
	}
	if !blockNode.IsStored() {
		blockNode.Status |= StatusBlockStored
	}
	// Do we want any side effects here or nah?
	return bc.upsertBlockAndBlockNodeToDB(block, blockNode, true)
}

// upsertBlockAndBlockNodeToDB writes the BlockNode to the blockIndex in badger and writes the full block
// to the db under the <blockHash> -> <serialized block> index.
func (bc *Blockchain) upsertBlockAndBlockNodeToDB(block *MsgDeSoBlock, blockNode *BlockNode, storeFullBlock bool) error {
	// Store the block in badger
	err := bc.db.Update(func(txn *badger.Txn) error {
		if bc.snapshot != nil {
			bc.snapshot.PrepareAncestralRecordsFlush()
			defer bc.snapshot.StartAncestralRecordsFlush(true)
			glog.V(2).Infof("upsertBlockAndBlockNodeToDB: Preparing snapshot flush")
		}
		// TODO: Do we want to write the full block once.
		// Store the new block in the db under the
		//   <blockHash> -> <serialized block>
		// index.
		// TODO: In the archival mode, we'll be setting ancestral entries for the block reward. Note that it is
		// 	set in PutBlockWithTxn. Block rewards are part of the state, and they should be identical to the ones
		// 	we've fetched during Hypersync. Is there an edge-case where for some reason they're not identical? Or
		// 	somehow ancestral records get corrupted?
		if storeFullBlock {
			if innerErr := PutBlockWithTxn(txn, bc.snapshot, block); innerErr != nil {
				return errors.Wrapf(innerErr, "upsertBlockAndBlockNodeToDB: Problem calling PutBlock")
			}
		}

		// Store the new block's node in our node index in the db under the
		//   <height uin32, blockHash BlockHash> -> <node info>
		// index.
		if innerErr := PutHeightHashToNodeInfoWithTxn(txn, bc.snapshot, blockNode, false /*bitcoinNodes*/); innerErr != nil {
			return errors.Wrapf(innerErr, "upsertBlockAndBlockNodeToDB: Problem calling PutHeightHashToNodeInfo before validation")
		}

		// Notice we don't call PutBestHash or PutUtxoOperationsForBlockWithTxn because we're not
		// affecting those right now.

		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "upsertBlockAndBlockNodeToDB: Problem putting block in db: ")
	}
	return nil
}

// tryApplyNewTip attempts to apply the new tip to the best chain. It will do the following:
// 1. Check if we should perform a reorg. If so, it will handle the reorg. If reorging causes an error, return false and error.
// 2. Check if the incoming block extends the chain tip after reorg. If not, return false and nil
// 3. If the incoming block extends the chain tip, we can apply it by calling addBlockToBestChain. Return true and nil.
func (bc *Blockchain) tryApplyNewTip(blockNode *BlockNode, currentView uint64, lineageFromCommittedTip []*BlockNode) (_appliedNewTip bool, _err error) {

	// Check if the incoming block extends the chain tip. If so, we don't need to reorg
	// and can just add this block to the best chain.
	chainTip := bc.GetBestChainTip()
	if chainTip.Hash.IsEqual(blockNode.Header.PrevBlockHash) {
		bc.addBlockToBestChain(blockNode)
		return true, nil
	}
	// Check if we should perform a reorg here.
	// If we shouldn't reorg AND the incoming block doesn't extend the chain tip, we know that
	// the incoming block will not get applied as the new tip.
	if !bc.shouldReorg(blockNode, currentView) {
		return false, nil
	}

	// We need to perform a reorg here. For simplicity, we remove all uncommitted blocks and then re-add them.
	committedTip, idx := bc.getHighestCommittedBlock()
	if committedTip == nil || idx == -1 {
		// This is an edge case we'll never hit in practice since all the PoW blocks
		// are committed.
		return false, errors.New("tryApplyNewTip: No committed blocks found")
	}
	// Remove all uncommitted blocks. These are all blocks that come after the committedTip
	// in the best chain.
	// Delete all blocks from bc.bestChainMap that come after the highest committed block.
	for ii := idx + 1; ii < len(bc.bestChain); ii++ {
		delete(bc.bestChainMap, *bc.bestChain[ii].Hash)
	}
	// Shorten best chain back to committed tip.
	bc.bestChain = bc.bestChain[:idx+1]
	// Add the ancestors of the new tip to the best chain.
	for _, ancestor := range lineageFromCommittedTip {
		bc.addBlockToBestChain(ancestor)
	}
	// Add the new tip to the best chain.
	bc.addBlockToBestChain(blockNode)
	return true, nil
}

// shouldReorg determines if we should reorg to the block provided. We should reorg if
// this block is proposed in a view greater than or equal to the currentView. Other
// functions have validated that this block is not extending from a committed block
// that is not the latest committed block, so there is no need to validate that here.
func (bc *Blockchain) shouldReorg(blockNode *BlockNode, currentView uint64) bool {
	chainTip := bc.GetBestChainTip()
	// If this block extends from the chain tip, there's no need to reorg.
	if chainTip.Hash.IsEqual(blockNode.Header.PrevBlockHash) {
		return false
	}
	// If the block is proposed in a view less than the current view, there's no need to reorg.
	return blockNode.Header.ProposedInView >= currentView
}

// addBlockToBestChain adds the block to the best chain.
func (bc *Blockchain) addBlockToBestChain(desoBlockNode *BlockNode) {
	bc.bestChain = append(bc.bestChain, desoBlockNode)
	bc.bestChainMap[*desoBlockNode.Hash] = desoBlockNode
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
	if grandParent.IsCommitted() {
		return nil, false
	}
	if grandParent.Header.ProposedInView+1 == parent.Header.ProposedInView {
		// Then we can run the commit rule up to the grandparent!
		return grandParent.Hash, true
	}
	return nil, false
}

// commitBlock commits the block with the given hash. Specifically, this updates the
// CommittedBlockStatus of the block and flushes the view after connecting the block
// to the DB and updates relevant badger indexes with info about the block.
func (bc *Blockchain) commitBlock(blockHash *BlockHash) error {
	// block must be in the best chain. we grab the block node from there.
	blockNode, exists := bc.bestChainMap[*blockHash]
	if !exists {
		return errors.Errorf("commitBlock: Block %v not found in best chain map", blockHash.String())
	}
	// TODO: Do we want other validation in here?
	if blockNode.IsCommitted() {
		// Can't commit a block that's already committed.
		return errors.Errorf("commitBlock: Block %v is already committed", blockHash.String())
	}
	block, err := GetBlock(blockHash, bc.db, bc.snapshot)
	if err != nil {
		return errors.Wrapf(err, "commitBlock: Problem getting block from db %v", blockHash.String())
	}
	// Connect a view up to the parent of the block we are committing.
	utxoView, err := bc.getUtxoViewAtBlockHash(*block.Header.PrevBlockHash)
	if err != nil {
		return errors.Wrapf(err, "commitBlock: Problem initializing UtxoView: ")
	}
	txHashes := collections.Transform(block.Txns, func(txn *MsgDeSoTxn) *BlockHash {
		return txn.Hash()
	})
	// Connect the block to the view!
	utxoOpsForBlock, err := utxoView.ConnectBlock(block, txHashes, true /*verifySignatures*/, bc.eventManager, block.Header.Height)
	if err != nil {
		// TODO: rule error handling? mark blocks invalid?
		return errors.Wrapf(err, "commitBlock: Problem connecting block to view: ")
	}
	// Put the block in the db
	// Note: we're skipping postgres.
	// TODO: this is copy pasta from ProcessBlockPoW. Refactor.
	blockNode.Status |= StatusBlockCommitted
	err = bc.db.Update(func(txn *badger.Txn) error {
		if bc.snapshot != nil {
			bc.snapshot.PrepareAncestralRecordsFlush()
			defer bc.snapshot.StartAncestralRecordsFlush(true)
			glog.V(2).Infof("commitBlock: Preparing snapshot flush")
		}
		// Store the new block in the db under the
		//   <blockHash> -> <serialized block>
		// index.
		// TODO: In the archival mode, we'll be setting ancestral entries for the block reward. Note that it is
		// 	set in PutBlockWithTxn. Block rewards are part of the state, and they should be identical to the ones
		// 	we've fetched during Hypersync. Is there an edge-case where for some reason they're not identical? Or
		// 	somehow ancestral records get corrupted?
		if innerErr := PutBlockWithTxn(txn, bc.snapshot, block); innerErr != nil {
			return errors.Wrapf(innerErr, "commitBlock: Problem calling PutBlock")
		}

		// Store the new block's node in our node index in the db under the
		//   <height uin32, blockHash BlockHash> -> <node info>
		// index.
		if innerErr := PutHeightHashToNodeInfoWithTxn(txn, bc.snapshot, blockNode, false /*bitcoinNodes*/); innerErr != nil {
			return errors.Wrapf(innerErr, "commitBlock: Problem calling PutHeightHashToNodeInfo before validation")
		}

		// Set the best node hash to this one. Note the header chain should already
		// be fully aware of this block so we shouldn't update it here.
		if innerErr := PutBestHashWithTxn(txn, bc.snapshot, blockNode.Hash, ChainTypeDeSoBlock); innerErr != nil {
			return errors.Wrapf(innerErr, "commitBlock: Problem calling PutBestHash after validation")
		}
		// Write the utxo operations for this block to the db so we can have the
		// ability to roll it back in the future.
		if innerErr := PutUtxoOperationsForBlockWithTxn(txn, bc.snapshot, uint64(blockNode.Height), blockNode.Hash, utxoOpsForBlock); innerErr != nil {
			return errors.Wrapf(innerErr, "ProcessBlock: Problem writing utxo operations to db on simple add to tip")
		}
		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "commitBlock: Problem putting block in db: ")
	}
	if err = utxoView.FlushToDb(uint64(blockNode.Height)); err != nil {
		return errors.Wrapf(err, "commitBlock: Problem flushing UtxoView to db")
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

// GetUncommittedTipView builds a UtxoView to the uncommitted tip.
func (bc *Blockchain) GetUncommittedTipView() (*UtxoView, error) {
	// Connect the uncommitted blocks to the tip so that we can validate subsequent blocks
	return bc.getUtxoViewAtBlockHash(*bc.GetBestChainTip().Hash)
}

// getUtxoViewAtBlockHash builds a UtxoView to the block provided. It does this by
// identifying all uncommitted ancestors of this block and then connecting those blocks.
func (bc *Blockchain) getUtxoViewAtBlockHash(blockHash BlockHash) (*UtxoView, error) {
	uncommittedAncestors := []*BlockNode{}
	currentBlock := bc.blockIndexByHash[blockHash]
	if currentBlock == nil {
		return nil, errors.Errorf("getUtxoViewAtBlockHash: Block %v not found in block index", blockHash)
	}
	// If the provided block is committed, we need to make sure it's the committed tip.
	// Otherwise, we return an error.
	if currentBlock.IsCommitted() {
		highestCommittedBlock, _ := bc.getHighestCommittedBlock()
		if highestCommittedBlock == nil {
			return nil, errors.Errorf("getUtxoViewAtBlockHash: No committed blocks found")
		}
		if !highestCommittedBlock.Hash.IsEqual(&blockHash) {
			return nil, errors.Errorf("getUtxoViewAtBlockHash: Block %v is committed but not the committed tip", blockHash)
		}
	}
	for !currentBlock.IsCommitted() {
		uncommittedAncestors = append(uncommittedAncestors, currentBlock)
		currentParentHash := currentBlock.Header.PrevBlockHash
		if currentParentHash == nil {
			return nil, errors.Errorf("getUtxoViewAtBlockHash: Block %v has nil PrevBlockHash", currentBlock.Hash)
		}
		currentBlock = bc.blockIndexByHash[*currentParentHash]
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
		// We need to get these blocks from badger
		fullBlock, err := GetBlock(uncommittedAncestors[ii].Hash, bc.db, bc.snapshot)
		if err != nil {
			return nil, errors.Wrapf(err, "GetUncommittedTipView: Error fetching Block %v not found in block index", uncommittedAncestors[ii].Hash.String())
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
	// Update the TipHash saved on the UtxoView to the blockHash provided.
	utxoView.TipHash = &blockHash
	return utxoView, nil
}

func (bc *Blockchain) GetBestChainTip() *BlockNode {
	return bc.bestChain[len(bc.bestChain)-1]
}

func (bc *Blockchain) getHighestCommittedBlock() (*BlockNode, int) {
	for ii := len(bc.bestChain) - 1; ii >= 0; ii-- {
		if bc.bestChain[ii].IsCommitted() {
			return bc.bestChain[ii], ii
		}
	}
	return nil, -1
}

func (bc *Blockchain) GetSafeBlocks() ([]*BlockNode, error) {
	// First get committed tip.
	committedTip, idx := bc.getHighestCommittedBlock()
	if idx == -1 || committedTip == nil {
		return nil, errors.New("GetSafeBlocks: No committed blocks found")
	}
	// Now get all blocks from the committed tip to the best chain tip.
	safeBlocks := []*BlockNode{committedTip}
	// TODO: How to determine the highest safe block height efficiently.
	maxHeightSeen := bc.getMaxHeightSeen()
	for ii := committedTip.Height + 1; ii < maxHeightSeen+1; ii++ {
		blockNodes, exists := bc.blockIndexByHeight[ii]
		if !exists {
			continue
		}
		for _, blockNode := range blockNodes {
			// TODO: Are there other conditions we should consider?
			if blockNode.IsValidated() {
				safeBlocks = append(safeBlocks, blockNode)
			}
		}
	}
	return safeBlocks, nil
}

func (bc *Blockchain) getMaxHeightSeen() uint32 {
	// TODO: How to determine the highest safe block height efficiently. We
	// may need to track it so we don't have to iterate over all heights.
	maxHeightSeen := uint32(0)
	for height := range bc.blockIndexByHeight {
		if height > maxHeightSeen {
			maxHeightSeen = height
		}
	}
	return maxHeightSeen
}

const (
	RuleErrorNilBlockHeader                      RuleError = "RuleErrorNilBlockHeader"
	RuleErrorNilPrevBlockHash                    RuleError = "RuleErrorNilPrevBlockHash"
	RuleErrorPoSBlockTstampNanoSecsTooOld        RuleError = "RuleErrorPoSBlockTstampNanoSecsTooOld"
	RuleErrorPoSBlockTstampNanoSecsInFuture      RuleError = "RuleErrorPoSBlockTstampNanoSecsInFuture"
	RuleErrorInvalidPoSBlockHeaderVersion        RuleError = "RuleErrorInvalidPoSBlockHeaderVersion"
	RuleErrorNilTxnConnectStatusByIndex          RuleError = "RuleErrorNilTxnConnectStatusByIndex"
	RuleErrorNilTxnConnectStatusByIndexHash      RuleError = "RuleErrorNilTxnConnectStatusByIndexHash"
	RuleErrorTxnConnectStatusByIndexHashMismatch RuleError = "RuleErrorTxnConnectStatusByIndexHashMismatch"
	RuleErrorNoTimeoutOrVoteQC                   RuleError = "RuleErrorNoTimeoutOrVoteQC"
	RuleErrorBothTimeoutAndVoteQC                RuleError = "RuleErrorBothTimeoutAndVoteQC"
	RuleErrorBlockWithNoTxns                     RuleError = "RuleErrorBlockWithNoTxns"
	RuleErrorBlockDoesNotStartWithRewardTxn      RuleError = "RuleErrorBlockDoesNotStartWithRewardTxn"
	RuleErrorMissingParentBlock                  RuleError = "RuleErrorMissingParentBlock"
	RuleErrorMissingAncestorBlock                RuleError = "RuleErrorMissingAncestorBlock"
	RuleErrorDoesNotExtendCommittedTip           RuleError = "RuleErrorDoesNotExtendCommittedTip"
	RuleErrorNilMerkleRoot                       RuleError = "RuleErrorNilMerkleRoot"
	RuleErrorInvalidMerkleRoot                   RuleError = "RuleErrorInvalidMerkleRoot"
	RuleErrorInvalidProposerVotingPublicKey      RuleError = "RuleErrorInvalidProposerVotingPublicKey"
	RuleErrorInvalidProposerPublicKey            RuleError = "RuleErrorInvalidProposerPublicKey"
	RuleErrorInvalidRandomSeedHash               RuleError = "RuleErrorInvalidRandomSeedHash"

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

	RuleErrorProcessBlockPoWAfterPoSCutOver     RuleError = "RuleErrorProcessBlockPoWAfterPoSCutOver"
	RuleErrorProcessBlockPoSBeforeCutOverHeight RuleError = "RuleErrorProcessBlockPoSBeforeCutOverHeight"
)
