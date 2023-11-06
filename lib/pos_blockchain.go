package lib

import (
	"math"
	"time"

	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/consensus"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

// processBlockPoS runs the Fast-Hotstuff block connect and commit rule as follows:
//  1. Determine if we're missing the parent block of this block.
//     If so, return the hash of the missing block and add this block to the orphans list.
//  2. Validate the incoming block, its header, its block height, the leader, and its QCs (vote or timeout)
//  3. Store the block in the block index and save to DB.
//  4. try to apply the incoming block as the tip (performing reorgs as necessary). If it can't be applied, we exit here.
//  5. Run the commit rule - If applicable, flushes the incoming block's grandparent to the DB
func (bc *Blockchain) processBlockPoS(block *MsgDeSoBlock, currentView uint64, verifySignatures bool) (_success bool, _isOrphan bool, _missingBlockHashes []*BlockHash, _err error) {
	// If we can't hash the block, we can never store in the block index and we should throw it out immediately.
	if _, err := block.Hash(); err != nil {
		return false, false, nil, errors.New("processBlockPoS: Problem hashing block")
	}
	// Get all the blocks between the current block and the committed tip. If the block
	// is an orphan, then we store it after performing basic validations.
	// If the block extends from any committed block other than the committed tip,
	// then we throw it away.
	lineageFromCommittedTip, err := bc.getLineageFromCommittedTip(block)
	if err == RuleErrorDoesNotExtendCommittedTip ||
		err == RuleErrorParentBlockHasViewGreaterOrEqualToChildBlock ||
		err == RuleErrorParentBlockHeightNotSequentialWithChildBlockHeight ||
		err == RuleErrorAncestorBlockValidationFailed {
		// In this case, the block extends a committed block that is NOT the tip
		// block. We will never accept this block, so mark it as ValidateFailed.
		return false, false, nil, err
	}
	if err == RuleErrorMissingAncestorBlock {
		// In this case, the block is an orphan that does not extend from any blocks
		// on our best chain. Try to process the orphan by running basic validations.
		// If it passes basic integrity checks, we'll store it with the hope that we
		// will eventually get a parent that connects to our best chain.
		missingBlockHashes := []*BlockHash{block.Header.PrevBlockHash}
		// FIXME: I sketeched some of these steps but not all...
		// Step 0: I think we still need to do some basic validation on this block, like
		// verifying that it's signed by the leader for example to prevent spamming.
		// I didn't do that.
		// Step 1: Create a new BlockNode for this block with status STORED.
		// Step 2: Add it to the blockIndexByHash and store it in Badger. This is handled by addBlockToBlockIndex
		return false, true, missingBlockHashes, bc.processOrphanBlockPoS(block)
	}

	if err != nil {
		return false, false, _missingBlockHashes, errors.Wrap(err, "processBlockPoS: Problem getting lineage from committed tip: UNEXPECTED ERROR!!!")
	}

	// TODO: Is there any error that would require special handling? If that's the case, we should
	// probably push that logic in validateAndIndexBlockPoS anyway.
	blockNode, err := bc.validateAndIndexBlockPoS(block)
	if err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem validating block: ")
	}
	if !blockNode.IsValidated() {
		return false, false, nil, errors.New("processBlockPoS: Block not validated after performing all validations.")
	}

	// 4. Try to apply the incoming block as the new tip. This function will
	// first perform any required reorgs and then determine if the incoming block
	// extends the chain tip. If it does, it will apply the block to the best chain
	// and appliedNewTip will be true and we can continue to running the commit rule.
	appliedNewTip, err := bc.tryApplyNewTip(blockNode, currentView, lineageFromCommittedTip)
	if err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem applying new tip: ")
	}

	// 5. Commit grandparent if possible. Only need to do this if we applied a new tip.
	if appliedNewTip {
		if err = bc.runCommitRuleOnBestChain(); err != nil {
			return false, false, nil, errors.Wrap(err, "processBlockPoS: error running commit rule: ")
		}
	}

	// Now that we've processed this block, we check for any blocks that were previously
	// stored as orphans, which are children of this block. We can  process them now.
	blockNodesAtNextHeight := bc.blockIndexByHeight[uint64(blockNode.Height)+1]
	for _, blockNodeAtNextHeight := range blockNodesAtNextHeight {
		if blockNodeAtNextHeight.Header.PrevBlockHash.IsEqual(blockNode.Hash) && blockNodeAtNextHeight.IsStored() && !blockNodeAtNextHeight.IsValidated() {
			var orphanBlock *MsgDeSoBlock
			orphanBlock, err = GetBlock(blockNodeAtNextHeight.Hash, bc.db, bc.snapshot)
			if err != nil {
				glog.Errorf("processBlockPoS: Problem getting orphan block %v", blockNodeAtNextHeight.Hash)
				continue
			}
			var appliedNewTipOrphan bool
			if appliedNewTipOrphan, _, _, err = bc.processBlockPoS(orphanBlock, currentView, verifySignatures); err != nil {
				glog.Errorf("processBlockPoS: Problem validating orphan block %v", blockNodeAtNextHeight.Hash)
				continue
			}
			if appliedNewTipOrphan {
				appliedNewTip = true
			}
		}
	}
	// Returns whether a new tip was applied, whether the block is an orphan, and any missing blocks, and an error.
	return appliedNewTip, false, nil, nil
}

// processOrphanBlockPoS validates that an orphan block is properly formed. If
// an orphan block is properly formed, we will save it as Stored in the block index.
// If not, we mark it as ValidateFailed.
func (bc *Blockchain) processOrphanBlockPoS(block *MsgDeSoBlock) error {
	// All blocks should pass the basic integrity validations, which ensure the block
	// is not malformed. If the block is malformed, we should store it as ValidateFailed.
	if err := bc.isProperlyFormedBlockPoS(block); err != nil {
		if _, innerErr := bc.storeValidateFailedBlockInBlockIndex(block); innerErr != nil {
			return errors.Wrapf(innerErr, "processBlockPoS: Problem adding validate failed block to block index: %v", err)
		}
		return nil
	}
	// Add to blockIndexByHash with status STORED only as we are not sure if it's valid yet.
	_, err := bc.storeBlockInBlockIndex(block)
	return errors.Wrap(err, "processBlockPoS: Problem adding block to block index: ")
}

// storeValidateFailedBlockWithWrappedError is a helper function that takes in a block and an error and
// stores the block in the block index with status VALIDATE_FAILED. It returns the resulting BlockNode.
func (bc *Blockchain) storeValidateFailedBlockWithWrappedError(block *MsgDeSoBlock, outerErr error) (*BlockNode, error) {
	blockNode, innerErr := bc.storeValidateFailedBlockInBlockIndex(block)
	if innerErr != nil {
		return nil, errors.Wrapf(innerErr, "storeValidateFailedBlockWithWrappedError: Problem adding validate failed block to block index: %v", outerErr)
	}
	return blockNode, nil
}

// validateAndIndexBlockPoS performs all validation checks for a given block and adds it to the block index with
// the appropriate status.
//  1. If the block is already VALIDATE_FAILED, we return the BlockNode as-is without perform further validations and
//     throw an error.
//  2. If the block is already VALIDATED, we return the BlockNode as-is without performing further validations and no error.
//  3. We check if its parent is VALIDATE_FAILED, if so we add the block to the block index with status VALIDATE_FAILED
//     and throw an error.
//  4. If its parent is NOT VALIDATED and NOT VALIDATE_FAILED, we recursively call this function on its parent.
//  5. If after calling this function on its parent, the parent is VALIDATE_FAILED, we add the block to the block index
//     with status VALIDATE_FAILED and throw an error.
//  6. If after calling this function on its parent, the parent is VALIDATED, we perform all other validations on the block.
//
// The recursive function's invariant is described as follows:
//   - Base case: If block is VALIDATED or VALIDATE_FAILED, return the BlockNode as-is.
//   - Recursive case: If the block is not VALIDATED or VALIDATE_FAILED in the blockIndexByHash, we will perform all
//     validations and add the block to the block index with the appropriate status (VALIDATED OR VALIDATE_FAILED) and
//     return the new BlockNode.
//   - Error case: Something goes wrong that doesn't result in the block being marked VALIDATE or VALIDATE_FAILED. In
//     this case, we will add the block to the block index with status STORED and return the BlockNode.
func (bc *Blockchain) validateAndIndexBlockPoS(block *MsgDeSoBlock) (*BlockNode, error) {
	blockHash, err := block.Header.Hash()
	if err != nil {
		return nil, errors.Wrapf(err, "validateAndIndexBlockPoS: Problem hashing block %v", block)
	}

	// Base case - Check if the block is validated or validate failed. If so, we can return early.
	blockNode, exists := bc.blockIndexByHash[*blockHash]
	if exists && (blockNode.IsValidateFailed() || blockNode.IsValidated()) {
		return blockNode, nil
	}

	// Run the validation for the parent and update the block index with the parent's status. We first
	// check if the parent has a cached status. If so, we use the cached status. Otherwise, we run
	// the full validation algorithm on it, then index and an use the result.
	parentBlockNode, err := bc.validatePreviouslyIndexedBlockPoS(block.Header.PrevBlockHash)
	if err != nil {
		return nil, errors.Wrapf(err, "validateAndIndexBlockPoS: Problem validating previously indexed block: ")
	}

	// Here's where it gets a little tricky. If the parent has a status of ValidateFailed, then we know we store
	// this block as ValidateFailed. If the parent is not ValidateFailed, we ONLY store the block and move on.
	// We don't want to store it as ValidateFailed because we don't know if it's actually invalid.
	if parentBlockNode.IsValidateFailed() {
		return bc.storeValidateFailedBlockWithWrappedError(block, errors.New("parent block is ValidateFailed"))
	}

	// If the parent block still has a Stored status, it means that we weren't able to validate it
	// despite trying. The current block will also be stored as a Stored block.
	if !parentBlockNode.IsValidated() {
		return bc.storeValidateFailedBlockWithWrappedError(block, errors.New("parent block is neither Validated nor ValidateFailed"))
	}

	// At this point, we know the parent block is validated. We can now perform all other validations
	// on the current block. First we store the block in the block index.
	blockNode, err = bc.storeBlockInBlockIndex(block)
	if err != nil {
		return nil, errors.Wrapf(err, "validateAndIndexBlockPoS: Problem adding block to block index: %v", err)
	}

	// Check if the block is properly formed and passes all basic validations.
	if err = bc.isValidBlockPoS(block); err != nil {
		return bc.storeValidateFailedBlockWithWrappedError(block, err)
	}

	// We expect the utxoView for the parent block to be valid because we check that all ancestor blocks have
	// been validated.
	utxoView, err := bc.getUtxoViewAtBlockHash(*block.Header.PrevBlockHash)
	if err != nil {
		// This should never happen. If the parent is validated and extends from the tip, then we should
		// be able to build a UtxoView for it. This failure can only happen due to transient or badger issues.
		// We return the block node as-is as a best effort thing.
		return blockNode, nil
	}
	// A couple of options on how to handle:
	//   - Add utility to UtxoView to fetch the validator set given an arbitrary block height. If we can't fetch the
	//     validator set for the block, then we reject it (even if it later turns out to be a valid block)
	//   - Add block to the block index before QC validation such that even if we aren't able to fetch the validator
	//     set for the block, we can at least store it locally.
	// 2. Validate QC
	validatorsByStake, err := utxoView.GetAllSnapshotValidatorSetEntriesByStake()
	if err != nil {
		// This should never happen. If the parent is validated and extends from the tip, then we should
		// be able to fetch the validator set at its block height for it. This failure can only happen due
		// to transient badger issues. We return the block node as-is as a best effort thing.
		return blockNode, nil
	}

	// Validate the block's QC. If it's invalid, we store it as ValidateFailed.
	if err = bc.isValidPoSQuorumCertificate(block, validatorsByStake); err != nil {
		return bc.storeValidateFailedBlockWithWrappedError(block, err)
	}

	isBlockProposerValid, err := bc.hasValidBlockProposerPoS(block)
	if err != nil {
		return nil, errors.Wrapf(err, "validateAndIndexBlockPoS: Problem validating block proposer")
	}
	if !isBlockProposerValid {
		return bc.storeValidateFailedBlockWithWrappedError(block, errors.New("invalid block proposer"))
	}

	// Connect this block to the parent block's UtxoView.
	txHashes := collections.Transform(block.Txns, func(txn *MsgDeSoTxn) *BlockHash {
		return txn.Hash()
	})

	// If we fail to connect the block, then it means the block is invalid. We should store it as ValidateFailed.
	if _, err = utxoView.ConnectBlock(block, txHashes, true, nil, block.Header.Height); err != nil {
		// If it doesn't connect, we want to mark it as ValidateFailed.
		return bc.storeValidateFailedBlockWithWrappedError(block, err)
	}

	// We can now add this block to the block index since we have performed all basic validations.
	blockNode, err = bc.storeValidatedBlockInBlockIndex(block)
	if err != nil {
		return nil, errors.Wrap(err, "validateAndIndexBlockPoS: Problem adding block to block index: ")
	}
	return blockNode, nil
}

// validatePreviouslyIndexedBlockPoS is a helper function that takes in a block hash for a previously
// cached block, and runs the validateAndIndexBlockPoS algorithm on it. It returns the resulting BlockNode.
func (bc *Blockchain) validatePreviouslyIndexedBlockPoS(blockHash *BlockHash) (*BlockNode, error) {
	// Check if the block is already in the block index. If so, we check its current status first.
	blockNode, exists := bc.blockIndexByHash[*blockHash]
	if !exists {
		// We should never really hit this if the block has already been cached in the block index first.
		// We check here anyway to be safe.
		return nil, errors.New("validatePreviouslyIndexedBlockPoS: Block not found in block index. This should never happen.")
	}

	// If the block has already been validated or had validation failed, then we can return early.
	if blockNode.IsValidateFailed() || blockNode.IsValidated() {
		return blockNode, nil
	}

	// At this point we know that we have the block node in the index, but it hasn't gone through full
	// validations yet. We fetch the block from the DB and run the full validation algorithm on it.
	block, err := GetBlock(blockHash, bc.db, bc.snapshot)
	if err != nil {
		// If we can't fetch the block from the DB, we should return an error. This should never happen
		// provided the block was cached in the block index and stored in the DB first.
		return nil, errors.Wrapf(err, "validatePreviouslyIndexedBlockPoS: Problem fetching block from DB")
	}

	// We run the full validation algorithm on the block.
	return bc.validateAndIndexBlockPoS(block)
}

// isValidBlockPoS performs all basic validations on a block as it relates to
// the Blockchain struct.
func (bc *Blockchain) isValidBlockPoS(block *MsgDeSoBlock) error {
	// Surface Level validation of the block
	if err := bc.isProperlyFormedBlockPoS(block); err != nil {
		return err
	}
	if err := bc.isBlockTimestampValidRelativeToParentPoS(block); err != nil {
		return err
	}
	// Validate Block Height
	if err := bc.hasValidBlockHeightPoS(block); err != nil {
		return err
	}
	// Validate View
	if err := bc.hasValidBlockViewPoS(block); err != nil {
		// Check if err is for view > latest committed block view and <= latest uncommitted block.
		// If so, we need to perform the rest of the validations and then add to our block index.
		// TODO: implement check on error described above. Caller will handle this.
		return err
	}
	return nil
}

// isBlockTimestampValidRelativeToParentPoS validates that the block's timestamp is
// greater than its parent's timestamp.
func (bc *Blockchain) isBlockTimestampValidRelativeToParentPoS(block *MsgDeSoBlock) error {
	// Validate that the timestamp is not less than its parent.
	parentBlock, exists := bc.blockIndexByHash[*block.Header.PrevBlockHash]
	if !exists {
		// Note: this should never happen as we only call this function after
		// we've validated that all ancestors exist in the block index.
		return RuleErrorMissingParentBlock
	}
	if block.Header.TstampNanoSecs < parentBlock.Header.TstampNanoSecs {
		return RuleErrorPoSBlockTstampNanoSecsTooOld
	}
	return nil
}

// isProperlyFormedBlockPoS validates the block at a surface level. It checks
// that the timestamp is valid, that the version of the header is valid,
// and other general integrity checks (such as not malformed).
func (bc *Blockchain) isProperlyFormedBlockPoS(block *MsgDeSoBlock) error {
	// First make sure we have a non-nil header
	if block.Header == nil {
		return RuleErrorNilBlockHeader
	}

	// Make sure we have a prevBlockHash
	if block.Header.PrevBlockHash == nil {
		return RuleErrorNilPrevBlockHash
	}

	// Timestamp validation
	// First make sure we have a non-nil header
	if block.Header == nil {
		return RuleErrorNilBlockHeader
	}

	// Make sure we have a prevBlockHash
	if block.Header.PrevBlockHash == nil {
		return RuleErrorNilPrevBlockHash
	}

	// Timestamp validation
	// TODO: Add support for putting the drift into global params.
	if block.Header.TstampNanoSecs > uint64(time.Now().UnixNano())+bc.params.DefaultBlockTimestampDriftNanoSecs {
		return RuleErrorPoSBlockTstampNanoSecsInFuture
	}

	// Header validation
	if block.Header.Version != HeaderVersion2 {
		return RuleErrorInvalidPoSBlockHeaderVersion
	}

	// Malformed block checks
	// All blocks must have at least one txn
	if len(block.Txns) == 0 {
		return RuleErrorBlockWithNoTxns
	}
	// Must have non-nil TxnConnectStatusByIndex
	if block.TxnConnectStatusByIndex == nil {
		return RuleErrorNilTxnConnectStatusByIndex
	}

	// Must have TxnConnectStatusByIndexHash
	if block.Header.TxnConnectStatusByIndexHash == nil {
		return RuleErrorNilTxnConnectStatusByIndexHash
	}

	// Make sure the TxnConnectStatusByIndex matches the TxnConnectStatusByIndexHash
	if !(HashBitset(block.TxnConnectStatusByIndex).IsEqual(block.Header.TxnConnectStatusByIndexHash)) {
		return RuleErrorTxnConnectStatusByIndexHashMismatch
	}

	// Require header to have either vote or timeout QC
	isTimeoutQCEmpty := block.Header.ValidatorsTimeoutAggregateQC.isEmpty()
	isVoteQCEmpty := block.Header.ValidatorsVoteQC.isEmpty()
	if isTimeoutQCEmpty && isVoteQCEmpty {
		return RuleErrorNoTimeoutOrVoteQC
	}

	if !isTimeoutQCEmpty && !isVoteQCEmpty {
		return RuleErrorBothTimeoutAndVoteQC
	}

	if len(block.Txns) == 0 {
		return RuleErrorBlockWithNoTxns
	}

	if block.Txns[0].TxnMeta.GetTxnType() != TxnTypeBlockReward {
		return RuleErrorBlockDoesNotStartWithRewardTxn
	}

	if block.Header.ProposerVotingPublicKey.IsEmpty() {
		return RuleErrorInvalidProposerVotingPublicKey
	}

	if block.Header.ProposerPublicKey == nil || block.Header.ProposerPublicKey.IsZeroPublicKey() {
		return RuleErrorInvalidProposerPublicKey
	}

	if block.Header.ProposerRandomSeedHash.isEmpty() {
		return RuleErrorInvalidRandomSeedHash
	}

	merkleRoot := block.Header.TransactionMerkleRoot

	// We always need to check the merkle root.
	if merkleRoot == nil {
		return RuleErrorNilMerkleRoot
	}
	computedMerkleRoot, _, err := ComputeMerkleRoot(block.Txns)
	if err != nil {
		return errors.Wrapf(err, "isProperlyFormedBlockPoS: Problem computing merkle root")
	}
	if !merkleRoot.IsEqual(computedMerkleRoot) {
		return RuleErrorInvalidMerkleRoot
	}

	// TODO: What other checks do we need to do here?
	return nil
}

// hasValidBlockHeightPoS validates the block height for a given block. First,
// it checks that we've passed the PoS cutover fork height. Then it checks
// that this block height is exactly one greater than its parent's block height.
func (bc *Blockchain) hasValidBlockHeightPoS(block *MsgDeSoBlock) error {
	blockHeight := block.Header.Height
	if blockHeight < uint64(bc.params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight) {
		return RuleErrorPoSBlockBeforeCutoverHeight
	}
	// Validate that the block height is exactly one greater than its parent.
	parentBlock, exists := bc.blockIndexByHash[*block.Header.PrevBlockHash]
	if !exists {
		// Note: this should never happen as we only call this function after
		// we've validated that all ancestors exist in the block index.
		return RuleErrorMissingParentBlock
	}
	if block.Header.Height != parentBlock.Header.Height+1 {
		return RuleErrorInvalidPoSBlockHeight
	}
	return nil
}

// hasValidBlockViewPoS validates the view for a given block. First, it checks that
// the view is greater than the latest committed block view. If not,
// we return an error indicating that we'll never accept this block. Next,
// it checks that the view is less than or equal to its parent.
// If not, we return an error indicating that we'll want to add this block as an
// orphan. Then it will check if that the view is exactly one greater than the
// latest uncommitted block if we have an regular vote QC. If this block has a
// timeout QC, it will check that the view is at least greater than the latest
// uncommitted block's view + 1.
func (bc *Blockchain) hasValidBlockViewPoS(block *MsgDeSoBlock) error {
	// Validate that the view is greater than the latest uncommitted block.
	parentBlock, exists := bc.blockIndexByHash[*block.Header.PrevBlockHash]
	if !exists {
		// Note: this should never happen as we only call this function after
		// we've validated that all ancestors exist in the block index.
		return RuleErrorMissingParentBlock
	}
	// If the parent block was a PoW block, we can't validate this block's view
	// in comparison.
	if !blockNodeProofOfStakeCutoverMigrationTriggered(parentBlock.Height) {
		return nil
	}
	// If our current block has a vote QC, then we need to validate that the
	// view is exactly one greater than the latest uncommitted block.
	if block.Header.ValidatorsTimeoutAggregateQC.isEmpty() {
		if block.Header.ProposedInView != parentBlock.Header.ProposedInView+1 {
			return RuleErrorPoSVoteBlockViewNotOneGreaterThanParent
		}
	} else {
		// If our current block has a timeout QC, then we need to validate that the
		// view is strictly greater than the latest uncommitted block's view.
		if block.Header.ProposedInView <= parentBlock.Header.ProposedInView {
			return RuleErrorPoSTimeoutBlockViewNotGreaterThanParent
		}
	}
	return nil
}

// hasValidBlockProposerPoS validates that the proposer is the expected proposer for the
// block height + view number pair. It returns a bool indicating whether
// we confirmed that the leader is valid. If we receive an error, we are unsure
// if the leader is invalid or not, so we return false.
func (bc *Blockchain) hasValidBlockProposerPoS(block *MsgDeSoBlock) (_isValidBlockProposer bool, _err error) {
	utxoView, err := bc.getUtxoViewAtBlockHash(*block.Header.PrevBlockHash)
	if err != nil {
		return false, errors.Wrapf(err, "hasValidBlockProposerPoS: Problem initializing UtxoView")
	}
	currentEpochEntry, err := utxoView.GetCurrentEpochEntry()
	if err != nil {
		return false, errors.Wrapf(err, "hasValidBlockProposerPoS: Problem getting current epoch entry")
	}
	leaders, err := utxoView.GetSnapshotLeaderSchedule()
	if err != nil {
		return false, errors.Wrapf(err, "hasValidBlockProposerPoS: Problem getting leader schedule")
	}
	if len(leaders) == 0 {
		return false, errors.Wrapf(err, "hasValidBlockProposerPoS: No leaders found in leader schedule")
	}
	if block.Header.Height < currentEpochEntry.InitialBlockHeight {
		return false, nil
	}
	if block.Header.ProposedInView < currentEpochEntry.InitialView {
		return false, nil
	}
	heightDiff := block.Header.Height - currentEpochEntry.InitialBlockHeight
	viewDiff := block.Header.ProposedInView - currentEpochEntry.InitialView
	if viewDiff < heightDiff {
		return false, nil
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
		return false, nil
	}
	leaderIdx := uint16(leaderIdxUint64)
	leaderEntry, err := utxoView.GetSnapshotLeaderScheduleValidator(leaderIdx)
	if err != nil {
		return false, errors.Wrapf(err, "hasValidBlockProposerPoS: Problem getting leader schedule validator")
	}
	leaderPKIDFromBlock := utxoView.GetPKIDForPublicKey(block.Header.ProposerPublicKey[:])
	if !leaderEntry.VotingPublicKey.Eq(block.Header.ProposerVotingPublicKey) ||
		!leaderEntry.ValidatorPKID.Eq(leaderPKIDFromBlock.PKID) {
		return false, nil
	}
	return true, nil
}

// isValidPoSQuorumCertificate validates that the QC of this block is valid, meaning a super majority
// of the validator set has voted (or timed out). Assumes ValidatorEntry list is sorted.
func (bc *Blockchain) isValidPoSQuorumCertificate(block *MsgDeSoBlock, validatorSet []*ValidatorEntry) error {
	validators := toConsensusValidators(validatorSet)
	if !block.Header.ValidatorsTimeoutAggregateQC.isEmpty() {
		if !consensus.IsValidSuperMajorityAggregateQuorumCertificate(block.Header.ValidatorsTimeoutAggregateQC, validators) {
			return RuleErrorInvalidTimeoutQC
		}
		return nil
	}
	if !consensus.IsValidSuperMajorityQuorumCertificate(block.Header.ValidatorsVoteQC, validators) {
		return RuleErrorInvalidVoteQC
	}
	return nil
}

// getLineageFromCommittedTip returns the ancestors of the block provided up to, but not
// including the committed tip. The first block in the returned slice is the first uncommitted
// ancestor.
func (bc *Blockchain) getLineageFromCommittedTip(block *MsgDeSoBlock) ([]*BlockNode, error) {
	highestCommittedBlock, idx := bc.getCommittedTip()
	if idx == -1 || highestCommittedBlock == nil {
		return nil, errors.New("getLineageFromCommittedTip: No committed blocks found")
	}
	currentHash := block.Header.PrevBlockHash.NewBlockHash()
	ancestors := []*BlockNode{}
	prevHeight := block.Header.Height
	prevView := block.Header.ProposedInView
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
		if currentBlock.IsValidateFailed() {
			return nil, RuleErrorAncestorBlockValidationFailed
		}
		if currentBlock.Header.ProposedInView >= prevView {
			return nil, RuleErrorParentBlockHasViewGreaterOrEqualToChildBlock
		}
		if uint64(currentBlock.Header.Height)+1 != prevHeight {
			return nil, RuleErrorParentBlockHeightNotSequentialWithChildBlockHeight
		}
		ancestors = append(ancestors, currentBlock)
		currentHash = currentBlock.Header.PrevBlockHash
		prevHeight = currentBlock.Header.Height
		prevView = currentBlock.Header.ProposedInView
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
	bc.addNewBlockNodeToBlockIndex(newBlockNode)
	return newBlockNode, nil
}

// storeBlockInBlockIndex upserts the blocks into the in-memory block index and updates its status to
// StatusBlockStored. It also writes the block to the block index in badger
// by calling upsertBlockAndBlockNodeToDB.
func (bc *Blockchain) storeBlockInBlockIndex(block *MsgDeSoBlock) (*BlockNode, error) {
	blockNode, err := bc.getOrCreateBlockNodeFromBlockIndex(block)
	if err != nil {
		return nil, errors.Wrapf(err, "storeBlockInBlockIndex: Problem getting or creating block node")
	}
	// If the block is stored, then this is a no-op.
	if blockNode.IsStored() {
		return blockNode, nil
	}
	blockNode.Status |= StatusBlockStored
	// If the DB update fails, then we should return an error.
	if err = bc.upsertBlockAndBlockNodeToDB(block, blockNode, true); err != nil {
		return nil, errors.Wrapf(err, "storeBlockInBlockIndex: Problem upserting block and block node to DB")
	}
	return blockNode, nil
}

// storeValidatedBlockInBlockIndex upserts the blocks into the in-memory block index and updates its status to
// StatusBlockValidated. If it does not have the status StatusBlockStored already, we add that as we will
// store the block in the DB after updating its status.  It also writes the block to the block index in badger
// by calling upsertBlockAndBlockNodeToDB.
func (bc *Blockchain) storeValidatedBlockInBlockIndex(block *MsgDeSoBlock) (*BlockNode, error) {
	blockNode, err := bc.getOrCreateBlockNodeFromBlockIndex(block)
	if err != nil {
		return nil, errors.Wrapf(err, "storeValidatedBlockInBlockIndex: Problem getting or creating block node")
	}
	// If the block is validated, then this is a no-op.
	if blockNode.IsValidated() {
		return blockNode, nil
	}
	blockNode.Status |= StatusBlockValidated
	// If the BlockNode is not already stored, we should set its status to stored.
	if !blockNode.IsStored() {
		blockNode.Status |= StatusBlockStored
	}
	// If the DB update fails, then we should return an error.
	if err = bc.upsertBlockAndBlockNodeToDB(block, blockNode, true); err != nil {
		return nil, errors.Wrapf(err, "storeValidatedBlockInBlockIndex: Problem upserting block and block node to DB")
	}
	return blockNode, nil
}

// storeValidateFailedBlockInBlockIndex upserts the blocks into the in-memory block index and updates its status to
// StatusBlockValidateFailed. If it does not have the status StatusBlockStored already, we add that as we will
// store the block in the DB after updating its status.  It also writes the block to the block index in badger
// by calling upsertBlockAndBlockNodeToDB.
func (bc *Blockchain) storeValidateFailedBlockInBlockIndex(block *MsgDeSoBlock) (*BlockNode, error) {
	blockNode, err := bc.getOrCreateBlockNodeFromBlockIndex(block)
	if err != nil {
		return nil, errors.Wrapf(err, "storeValidateFailedBlockInBlockIndex: Problem getting or creating block node")
	}
	// If the block has had validation failed, then this is a no-op.
	if blockNode.IsValidateFailed() {
		return blockNode, nil
	}
	// We should throw an error if the BlockNode is already Validated
	if blockNode.IsValidated() {
		return nil, errors.New("storeValidateFailedBlockInBlockIndex: can't set BlockNode to validate failed after it's already validated")
	}
	blockNode.Status |= StatusBlockValidateFailed
	// If the BlockNode is not already stored, we should set it to stored.
	if !blockNode.IsStored() {
		blockNode.Status |= StatusBlockStored
	}
	// If the DB update fails, then we should return an error.
	if err = bc.upsertBlockAndBlockNodeToDB(block, blockNode, false); err != nil {
		return nil, errors.Wrapf(err, "storeValidateFailedBlockInBlockIndex: Problem upserting block and block node to DB")
	}
	return blockNode, nil
}

// storeCommittedBlockInBlockIndex upserts the blocks into the in-memory block index and updates its status to
// StatusBlockCommitted. If the BlockNode does not have StatusBlockValidated and StatusBlockStored statuses,
// we also add those. It also writes the block to the block index in badger by calling upsertBlockAndBlockNodeToDB.
func (bc *Blockchain) storeCommittedBlockInBlockIndex(block *MsgDeSoBlock) (*BlockNode, error) {
	blockNode, err := bc.getOrCreateBlockNodeFromBlockIndex(block)
	if err != nil {
		return nil, errors.Wrapf(err, "storeCommittedBlockInBlockIndex: Problem getting or creating block node")
	}
	// If the block is committed, then this is a no-op.
	if blockNode.IsCommitted() {
		return blockNode, nil
	}
	blockNode.Status |= StatusBlockCommitted
	if !blockNode.IsValidated() {
		blockNode.Status |= StatusBlockValidated
	}
	if !blockNode.IsStored() {
		blockNode.Status |= StatusBlockStored
	}
	// If the DB update fails, then we should return an error.
	if err = bc.upsertBlockAndBlockNodeToDB(block, blockNode, true); err != nil {
		return nil, errors.Wrapf(err, "storeCommittedBlockInBlockIndex: Problem upserting block and block node to DB")
	}
	return blockNode, nil
}

// upsertBlockAndBlockNodeToDB writes the BlockNode to the blockIndexByHash in badger and writes the full block
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

		// TODO: if storeFullBlock = false, then we should probably remove the block from the DB? This can
		// happen if we had a block stored in the DB but then determined that it would have failed validation.
		// We would need to evict the block from the DB in that case.

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
	committedTip, idx := bc.getCommittedTip()
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
func (bc *Blockchain) addBlockToBestChain(blockNode *BlockNode) {
	bc.bestChain = append(bc.bestChain, blockNode)
	bc.bestChainMap[*blockNode.Hash] = blockNode
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
	_, idx := bc.getCommittedTip()
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
		if err := bc.commitBlockPoS(uncommittedAncestors[ii].Hash); err != nil {
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

// commitBlockPoS commits the block with the given hash. Specifically, this updates the
// BlockStatus to include StatusBlockCommitted and flushes the view after connecting the block
// to the DB and updates relevant badger indexes with info about the block.
func (bc *Blockchain) commitBlockPoS(blockHash *BlockHash) error {
	// block must be in the best chain. we grab the block node from there.
	blockNode, exists := bc.bestChainMap[*blockHash]
	if !exists {
		return errors.Errorf("commitBlockPoS: Block %v not found in best chain map", blockHash.String())
	}
	// TODO: Do we want other validation in here?
	if blockNode.IsCommitted() {
		// Can't commit a block that's already committed.
		return errors.Errorf("commitBlockPoS: Block %v is already committed", blockHash.String())
	}
	block, err := GetBlock(blockHash, bc.db, bc.snapshot)
	if err != nil {
		return errors.Wrapf(err, "commitBlockPoS: Problem getting block from db %v", blockHash.String())
	}
	// Connect a view up to the parent of the block we are committing.
	utxoView, err := bc.getUtxoViewAtBlockHash(*block.Header.PrevBlockHash)
	if err != nil {
		return errors.Wrapf(err, "commitBlockPoS: Problem initializing UtxoView: ")
	}
	txHashes := collections.Transform(block.Txns, func(txn *MsgDeSoTxn) *BlockHash {
		return txn.Hash()
	})
	// Connect the block to the view!
	utxoOpsForBlock, err := utxoView.ConnectBlock(block, txHashes, true /*verifySignatures*/, bc.eventManager, block.Header.Height)
	if err != nil {
		// TODO: rule error handling? mark blocks invalid?
		return errors.Wrapf(err, "commitBlockPoS: Problem connecting block to view: ")
	}
	// Put the block in the db
	// Note: we're skipping postgres.
	// TODO: this is copy pasta from ProcessBlockPoW. Refactor.
	blockNode.Status |= StatusBlockCommitted
	err = bc.db.Update(func(txn *badger.Txn) error {
		if bc.snapshot != nil {
			bc.snapshot.PrepareAncestralRecordsFlush()
			defer bc.snapshot.StartAncestralRecordsFlush(true)
			glog.V(2).Infof("commitBlockPoS: Preparing snapshot flush")
		}
		// Store the new block in the db under the
		//   <blockHash> -> <serialized block>
		// index.
		// TODO: In the archival mode, we'll be setting ancestral entries for the block reward. Note that it is
		// 	set in PutBlockWithTxn. Block rewards are part of the state, and they should be identical to the ones
		// 	we've fetched during Hypersync. Is there an edge-case where for some reason they're not identical? Or
		// 	somehow ancestral records get corrupted?
		if innerErr := PutBlockWithTxn(txn, bc.snapshot, block); innerErr != nil {
			return errors.Wrapf(innerErr, "commitBlockPoS: Problem calling PutBlock")
		}

		// Store the new block's node in our node index in the db under the
		//   <height uin32, blockHash BlockHash> -> <node info>
		// index.
		if innerErr := PutHeightHashToNodeInfoWithTxn(txn, bc.snapshot, blockNode, false /*bitcoinNodes*/); innerErr != nil {
			return errors.Wrapf(innerErr, "commitBlockPoS: Problem calling PutHeightHashToNodeInfo before validation")
		}

		// Set the best node hash to this one. Note the header chain should already
		// be fully aware of this block so we shouldn't update it here.
		if innerErr := PutBestHashWithTxn(txn, bc.snapshot, blockNode.Hash, ChainTypeDeSoBlock); innerErr != nil {
			return errors.Wrapf(innerErr, "commitBlockPoS: Problem calling PutBestHash after validation")
		}
		// Write the utxo operations for this block to the db so we can have the
		// ability to roll it back in the future.
		if innerErr := PutUtxoOperationsForBlockWithTxn(txn, bc.snapshot, uint64(blockNode.Height), blockNode.Hash, utxoOpsForBlock); innerErr != nil {
			return errors.Wrapf(innerErr, "ProcessBlock: Problem writing utxo operations to db on simple add to tip")
		}
		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "commitBlockPoS: Problem putting block in db: ")
	}
	if err = utxoView.FlushToDb(uint64(blockNode.Height)); err != nil {
		return errors.Wrapf(err, "commitBlockPoS: Problem flushing UtxoView to db")
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
		highestCommittedBlock, _ := bc.getCommittedTip()
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

// GetBestChainTip is a helper function that returns the tip of the best chain.
func (bc *Blockchain) GetBestChainTip() *BlockNode {
	return bc.bestChain[len(bc.bestChain)-1]
}

// getCommittedTip returns the highest committed block and its index in the best chain.
func (bc *Blockchain) getCommittedTip() (*BlockNode, int) {
	for ii := len(bc.bestChain) - 1; ii >= 0; ii-- {
		if bc.bestChain[ii].IsCommitted() {
			return bc.bestChain[ii], ii
		}
	}
	return nil, -1
}

// GetSafeBlocks returns all blocks from which the chain can safely extend. A
// safe block is defined as a block that has been validated and all of its
// ancestors have been validated and extending from this block would not
// change any committed blocks. This means we return the committed tip and
// all blocks from the committed tip that have been validated.
func (bc *Blockchain) GetSafeBlocks() ([]*BlockNode, error) {
	// First get committed tip.
	committedTip, idx := bc.getCommittedTip()
	if idx == -1 || committedTip == nil {
		return nil, errors.New("GetSafeBlocks: No committed blocks found")
	}
	// Now get all blocks from the committed tip to the best chain tip.
	safeBlocks := []*BlockNode{committedTip}
	maxHeightWithSafeBlocks := bc.getMaxSequentialBlockHeightAfter(uint64(committedTip.Height))
	for ii := uint64(committedTip.Height + 1); ii < maxHeightWithSafeBlocks+1; ii++ {
		// If we don't have any blocks at this height, we know that any blocks at a later height are not safe blocks.
		if !bc.hasBlockNodesIndexedAtHeight(ii) {
			break
		}
		hasSeenValidatedBlockAtThisHeight := false
		blockNodes := bc.getAllBlockNodesIndexedAtHeight(ii)
		for _, blockNode := range blockNodes {
			// TODO: Are there other conditions we should consider?
			if blockNode.IsValidated() {
				hasSeenValidatedBlockAtThisHeight = true
				safeBlocks = append(safeBlocks, blockNode)
			}
		}
		// If we didn't see any validated blocks at this height, we know
		// that no blocks at a later height can be validated and thus
		// cannot be safe blocks.
		if !hasSeenValidatedBlockAtThisHeight {
			break
		}
	}
	return safeBlocks, nil
}

// getMaxSequentialBlockHeightAfter returns the max sequential block height after the starting height.
// If the blockIndexByHeight does not have any blocks at a certain height, we know that any blocks
// at a later height are not valid.
func (bc *Blockchain) getMaxSequentialBlockHeightAfter(startingHeight uint64) uint64 {
	hasBlocksAtCurrentHeight := true
	maxSequentialHeightWithBlocks := startingHeight
	for currentHeight := startingHeight; hasBlocksAtCurrentHeight; currentHeight++ {
		maxSequentialHeightWithBlocks = currentHeight
		hasBlocksAtCurrentHeight = bc.hasBlockNodesIndexedAtHeight(currentHeight)
	}
	return maxSequentialHeightWithBlocks
}

const (
	RuleErrorNilBlockHeader                                     RuleError = "RuleErrorNilBlockHeader"
	RuleErrorNilPrevBlockHash                                   RuleError = "RuleErrorNilPrevBlockHash"
	RuleErrorPoSBlockTstampNanoSecsTooOld                       RuleError = "RuleErrorPoSBlockTstampNanoSecsTooOld"
	RuleErrorPoSBlockTstampNanoSecsInFuture                     RuleError = "RuleErrorPoSBlockTstampNanoSecsInFuture"
	RuleErrorInvalidPoSBlockHeaderVersion                       RuleError = "RuleErrorInvalidPoSBlockHeaderVersion"
	RuleErrorNilTxnConnectStatusByIndex                         RuleError = "RuleErrorNilTxnConnectStatusByIndex"
	RuleErrorNilTxnConnectStatusByIndexHash                     RuleError = "RuleErrorNilTxnConnectStatusByIndexHash"
	RuleErrorTxnConnectStatusByIndexHashMismatch                RuleError = "RuleErrorTxnConnectStatusByIndexHashMismatch"
	RuleErrorNoTimeoutOrVoteQC                                  RuleError = "RuleErrorNoTimeoutOrVoteQC"
	RuleErrorBothTimeoutAndVoteQC                               RuleError = "RuleErrorBothTimeoutAndVoteQC"
	RuleErrorBlockWithNoTxns                                    RuleError = "RuleErrorBlockWithNoTxns"
	RuleErrorBlockDoesNotStartWithRewardTxn                     RuleError = "RuleErrorBlockDoesNotStartWithRewardTxn"
	RuleErrorMissingParentBlock                                 RuleError = "RuleErrorMissingParentBlock"
	RuleErrorMissingAncestorBlock                               RuleError = "RuleErrorMissingAncestorBlock"
	RuleErrorDoesNotExtendCommittedTip                          RuleError = "RuleErrorDoesNotExtendCommittedTip"
	RuleErrorAncestorBlockValidationFailed                      RuleError = "RuleErrorAncestorBlockValidationFailed"
	RuleErrorParentBlockHasViewGreaterOrEqualToChildBlock       RuleError = "RuleErrorParentBlockHasViewGreaterOrEqualToChildBlock"
	RuleErrorParentBlockHeightNotSequentialWithChildBlockHeight RuleError = "RuleErrorParentBlockHeightNotSequentialWithChildBlockHeight"

	RuleErrorNilMerkleRoot                  RuleError = "RuleErrorNilMerkleRoot"
	RuleErrorInvalidMerkleRoot              RuleError = "RuleErrorInvalidMerkleRoot"
	RuleErrorInvalidProposerVotingPublicKey RuleError = "RuleErrorInvalidProposerVotingPublicKey"
	RuleErrorInvalidProposerPublicKey       RuleError = "RuleErrorInvalidProposerPublicKey"
	RuleErrorInvalidRandomSeedHash          RuleError = "RuleErrorInvalidRandomSeedHash"

	RuleErrorInvalidPoSBlockHeight       RuleError = "RuleErrorInvalidPoSBlockHeight"
	RuleErrorPoSBlockBeforeCutoverHeight RuleError = "RuleErrorPoSBlockBeforeCutoverHeight"

	RuleErrorPoSVoteBlockViewNotOneGreaterThanParent RuleError = "RuleErrorPoSVoteBlockViewNotOneGreaterThanParent"
	RuleErrorPoSTimeoutBlockViewNotGreaterThanParent RuleError = "RuleErrorPoSTimeoutBlockViewNotGreaterThanParent"

	RuleErrorInvalidVoteQC    RuleError = "RuleErrorInvalidVoteQC"
	RuleErrorInvalidTimeoutQC RuleError = "RuleErrorInvalidTimeoutQC"
)
