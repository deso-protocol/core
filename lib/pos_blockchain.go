package lib

import (
	"fmt"
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
//  3. Store the block in the block index and uncommitted blocks map.
//  4. try to apply the incoming block as the tip (performing reorgs as necessary). If it can't be applied, we exit here.
//  5. Run the commit rule - If applicable, flushes the incoming block's grandparent to the DB
//  6. Prune in-memory struct holding uncommitted block.
func (bc *Blockchain) processBlockPoS(desoBlock *MsgDeSoBlock, currentView uint64, verifySignatures bool) (_connected bool, _err error) {
	// Start by pulling out the block hash.
	blockHash, err := desoBlock.Hash()
	if err != nil {
		return false, errors.Wrapf(err, "processBlockPoS: Problem hashing block %v", desoBlock)
	}

	// Get all the blocks between the current block and the committed tip. If the block
	// is an orphan, then we store it without validating it. If the block connects to a
	// block other than the committed tip, then we throw it away.
	lineageFromCommittedTip, lineageErr := bc.getLineageFromCommittedTip(desoBlock)
	if lineageErr == RuleErrorDoesNotExtendCommittedTip {
		// In this case, the block extends a committed block that is NOT the tip
		// block. There is no point in storing this block because we will never
		// reorg to it.
		return false, lineageErr
	}
	if lineageErr == RuleErrorMissingAncestorBlock {
		// In this case, the block is an orphan that does not connect to any blocks
		// on our best chain. In this case we'll store it with the hope that we
		// will eventually get a parent that connects to our best chain.

		// FIXME: I sketeched some of these steps but not all...
		// Step 0: I think we still need to do some basic validation on this block, like
		// verifying that it's signed by the leader for example to prevent spamming.
		// I didn't do that.
		// Step 1: Create a new BlockNode for this block with status STORED. I did this below.
		// Step 2: Add it to the blockIndex and store it in Badger. Did this below.
		// Step 3: We may want to send a signal back to server.go to fetch the PrevBlockHash block
		// so that we can consistently fix cases where we get hit with orphans. If we did this, then
		// an unhappy path would look as follows:
		// - We miss a block for some reason. Say it's block 100
		// - We get block 101, which is an orphan. We store it and tell server.go to ask
		//   someone for block 100
		// - server.go does this, and this function is called with block 100, which connects (woohoo!)
		// - Eventually we'll get block 102, which will connect 101 (see below for how we
		//   connect ancestors)

		// Add to blockIndex with status STORED only.
		err = bc.addBlockToBlockIndex(desoBlock, StatusBlockStored)
		if err != nil {
			return false, errors.Wrap(err, "processBlockPoS: Problem adding block to block index: ")
		}
		newBlockNode, exists := bc.blockIndex[*blockHash]
		if !exists {
			return false, errors.New("processBlockPoS: Block not found in block index after adding it. " +
				"This should never happen.")
		}
		// Store the block in badger
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
			if innerErr := PutBlockWithTxn(txn, bc.snapshot, desoBlock); innerErr != nil {
				return errors.Wrapf(err, "ProcessBlock: Problem calling PutBlock")
			}
			// Store the new block's node in our node index in the db under the
			//   <height uin32, blockHash BlockHash> -> <node info>
			// index.
			if innerErr := PutHeightHashToNodeInfoWithTxn(txn, bc.snapshot, newBlockNode, false /*bitcoinNodes*/); innerErr != nil {
				return errors.Wrapf(err, "ProcessBlock: Problem calling PutHeightHashToNodeInfo before validation")
			}

			// Notice we don't call PutBestHash or PutUtxoOperationsForBlockWithTxn because we're not
			// affecting those right now.

			return nil
		})
		if err != nil {
			return false, errors.Wrapf(err, "runCommitRuleOnBestChain: Problem putting block in db: ")
		}

		// FIXME: If we get here, it means we stored an orphan block. We could at this point send a signal
		// back to the server to try and actively fetch its parent from someone. That would look something
		// like the following. Consult with @tholonius
		//
		// if bc.eventManager != nil {
		// 	bc.eventManager.blockConnected(&BlockEvent{
		// 		Block:    block,
		// 		UtxoView: utxoView,
		// 		UtxoOps:  utxoOpsForBlock,
		// 	})
		// }

		// In this case there is no error. We got a block that seemed ostensibly valid, it just
		// didn't connect to anything.
		return false, nil
	}
	if lineageErr != nil {
		return false, errors.Wrapf(err, "procesBlockPoS unrecognized error: ")
	}

	// If we get to this point, we know we have a block that connects to the committed tip
	// through some contiguous chain. However, we don't know if all the blocks on the chain
	// have been validated yet.

	// Iterate through all the blocks from the committed tip to the current block. For each
	// block that is stored but not validated, call ProcessBlockPoS on it recursively.
	for _, ancestor := range lineageFromCommittedTip {
		if !IsBlockValidated(ancestor) {
			// FIXME: What view do we pass to this call?
			blk, err := GetBlock(ancestor.Hash, bc.db, bc.snapshot)
			if err != nil {
				return false, errors.Wrapf(err, "processBlockPoS: Problem getting block %v", ancestor.Hash)
			}
			didConnect, err := bc.processBlockPoS(blk, currentView, verifySignatures)
			if err != nil {
				return false, errors.Wrapf(err, "processBlockPoS: Problem processing ancestor "+
					"block: %v for tip block %v", ancestor.Hash, blockHash)
			}
			if !didConnect {
				// This should never happen with a valid block because it should be able to connect
				// to the committed tip. So return an error.
				return false, fmt.Errorf("processBlockPoS: Ancestor block %v did not connect to committed tip", ancestor.Hash)
			}
		}
	}

	// At this point, we know that all the ancestors of this block have been successfully
	// validated. That means we can now proceed with attempting to validate THIS block.

	// Do all the sanity checks on the block.
	// TODO: Check if err is for view > latest committed block view and <= latest uncommitted block.
	// If so, we need to perform the rest of the validations and then add to our block index.
	if err = bc.validateDeSoBlockPoS(desoBlock); err != nil {
		return false, errors.Wrap(err, "processBlockPoS: block validation failed: ")
	}

	// We know this utxoView will be valid because we checked that all ancestor blocks have
	// been validated.
	utxoView, err := bc.getUtxoViewAtBlockHash(*desoBlock.Header.PrevBlockHash)
	if err != nil {
		return false, errors.Wrap(err, "processBlockPoS: Problem initializing UtxoView: ")
	}
	txHashes := collections.Transform(desoBlock.Txns, func(txn *MsgDeSoTxn) *BlockHash {
		return txn.Hash()
	})
	_, err = utxoView.ConnectBlock(desoBlock, txHashes, true /*verifySignatures*/, bc.eventManager, desoBlock.Header.Height)
	if err != nil {
		return false, errors.Wrapf(err, "processBlockPoS: Problem connecting block to view: ")
	}

	validatorsByStake, err := utxoView.GetAllSnapshotValidatorSetEntriesByStake()
	if err != nil {
		return false, errors.Wrap(err, "processBlockPoS: Problem getting validator set: ")
	}
	// TODO(diamondhands): I don't think the TODO below makes sense given the changes but take a look.
	// TODO: If block belongs in the next epoch or it's from an epoch far ahead in the future, we may not be able to validate its QC at all.
	// the validator set for that epoch may be entirely different.
	// A couple of options on how to handle:
	//   - Add utility to UtxoView to fetch the validator set given an arbitrary block height. If we can't fetch the
	//     validator set for the block, then we reject it (even if it later turns out to be a valid block)
	//   - Add block to the block index before QC validation such that even if we aren't able to fetch the validator
	//     set for the block, we can at least store it locally.
	// Validate QC
	if err = bc.validateQC(desoBlock, validatorsByStake); err != nil {
		return false, errors.Wrap(err, "processBlockPoS: QC validation failed: ")
	}

	// If the block isn't in our blockIndex yet, add it now.
	err = bc.addBlockToBlockIndex(desoBlock, StatusBlockStored|StatusHeaderValidated|StatusBlockValidated)
	if err != nil {
		return false, errors.Wrap(err, "processBlockPoS: Problem adding block to block index: ")
	}

	newBlockNode, exists := bc.blockIndex[*blockHash]
	if !exists {
		return false, errors.New("processBlockPoS: Block not found in block index after adding it. " +
			"This should never happen.")
	}

	// Try to apply the incoming block as the new tip. This function will
	// first perform any required reorgs and then determine if the incoming block
	// extends the chain tip. If it does, it will apply the block to the best chain
	// and appliedNewTip will be true and we can continue to running the commit rule.
	err = bc.tryUpdateBestChain(newBlockNode, currentView, lineageFromCommittedTip)
	if err != nil {
		return false, errors.Wrap(err, "processBlockPoS: Problem applying new tip: ")
	}

	// At this point, the new block has been validated and applied as the new tip. We can now
	// update badger in a single transaction to write all of the new state to disk. Note that
	// this update appends the new block to the bestChain, but it does not update the committed
	// status of anything. We do that in a second atomic update below.
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
		if innerErr := PutBlockWithTxn(txn, bc.snapshot, desoBlock); innerErr != nil {
			return errors.Wrapf(err, "ProcessBlock: Problem calling PutBlock")
		}

		// Store the new block's node in our node index in the db under the
		//   <height uin32, blockHash BlockHash> -> <node info>
		// index.
		if innerErr := PutHeightHashToNodeInfoWithTxn(txn, bc.snapshot, newBlockNode, false /*bitcoinNodes*/); innerErr != nil {
			return errors.Wrapf(err, "ProcessBlock: Problem calling PutHeightHashToNodeInfo before validation")
		}

		// Set the best node hash to this one. Notice that the "best hash" marks the tip of the best *uncommitted*
		// chain. To get the best committed chain, you have to walk back from this hash to the first committed
		// block when loading it up.
		if innerErr := PutBestHashWithTxn(txn, bc.snapshot, newBlockNode.Hash, ChainTypeDeSoBlock); innerErr != nil {
			return errors.Wrapf(innerErr, "ProcessBlock: Problem calling PutBestHash after validation")
		}
		// Notice we don't write UTXO operations for this block because it is not committed yet.
		// We called ConnectBlock() previously only for validation purposes.
		return nil
	})
	if err != nil {
		return false, errors.Wrapf(err, "runCommitRuleOnBestChain: Problem putting block in db: ")
	}

	// FIXME: Do we want to pass back an event here? We were doing so before. Consult with @tholonius
	// Below is how you'd do it:
	// if bc.eventManager != nil {
	// 	bc.eventManager.blockConnected(&BlockEvent{
	// 		Block:    block,
	// 		UtxoView: utxoView,
	// 		UtxoOps:  utxoOpsForBlock,
	// 	})
	// }

	// Commit blocks if possible.
	if err = bc.runCommitRuleOnBestChain(); err != nil {
		return false, errors.Wrap(err, "processBlockPoS: error committing grandparents: ")
	}

	return true, nil
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
		if IsBlockCommitted(currentBlock) {
			return nil, RuleErrorDoesNotExtendCommittedTip
		}
		ancestors = append(ancestors, currentBlock)
		currentHash = currentBlock.Header.PrevBlockHash
	}
	collections.Reverse(ancestors)
	return ancestors, nil
}

// addBlockToBlockIndex adds the block to the block index and uncommitted blocks map.
func (bc *Blockchain) addBlockToBlockIndex(desoBlock *MsgDeSoBlock, blockStatus BlockStatus) error {
	hash, err := desoBlock.Hash()
	if err != nil {
		return errors.Wrapf(err, "addBlockToBlockIndex: Problem hashing block %v", desoBlock)
	}
	// Need to get parent block node from block index
	prevBlock := bc.blockIndex[*desoBlock.Header.PrevBlockHash]
	bc.blockIndex[*hash] = NewPoSBlockNode(prevBlock, hash, uint32(desoBlock.Header.Height), desoBlock.Header, blockStatus)

	return nil
}

// tryUpdateBestChain attempts to add the BlockNode passed in to the best chain. It assumes the BlockNode
// has already been added to the blockIndex and stored in the DB.
//
// FIXME: Do we need the bestHeaderChain and the bestHeaderChainMap anymore? I think we need it for initial
// sync but not sure. Maybe we can delete it? This is a question to revisit when redoing server.go
func (bc *Blockchain) tryUpdateBestChain(
	blockNode *BlockNode, currentView uint64, lineageFromCommittedTip []*BlockNode) (_err error) {

	// In the happy path, the block's parent will be the last block in the best chain.
	uncommittedTip := bc.GetBestChainTip()
	if uncommittedTip.Hash.IsEqual(blockNode.Parent.Hash) {
		bc.addBlockToBestChain(blockNode)
		return nil
	}

	// If we get here, then a reorg is required.

	// Delete all the blocks from the committed tip to the uncommitted tip.
	committedTip, idx := bc.getHighestCommittedBlock()
	if committedTip == nil || idx == -1 {
		// This is an edge case we'll never hit in practice since all the PoW blocks
		// are committed.
		return errors.New("tryApplyNewTip: No committed blocks found")
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
	return nil
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
	// FIXME(diamondhands): I didn't review this too closely yet. Let's make sure
	// we're on the same page on ProcessBlock first. This part shouldn't be hard
	// once the meat of ProcessBlockPoS is done.
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
	if IsBlockCommitted(grandParent) {
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
	// FIXME(diamondhands): I didn't review this too closely yet. Let's make sure
	// we're on the same page on ProcessBlock first. This part shouldn't be hard
	// once the meat of ProcessBlockPoS is done.
	//
	// Notice the blockIndex should always have the block we're looking for, and the
	// block should always be persisted to Badger by the time we hit commitBlock (yay).

	// Block must be in the best chain. we grab the block node from there.
	blockNode, exists := bc.bestChainMap[*blockHash]
	if !exists {
		return errors.Errorf("commitBlock: Block %v not found in best chain map", blockHash.String())
	}
	block, err := GetBlock(blockHash, bc.db, bc.snapshot)
	if err != nil {
		return errors.Wrapf(err, "commitBlock: Problem getting block from db %v", blockHash.String())
	}
	// Connect a view up to the parent of the block we are committing.
	utxoView, err := bc.getUtxoViewAtBlockHash(*block.Header.PrevBlockHash)
	if err != nil {
		return errors.Wrapf(err, "runCommitRuleOnBestChain: Problem initializing UtxoView: ")
	}
	// Get the full uncommitted block from the uncommitted blocks map
	// FIXME: This is using blockHash when it should use a parent hash or something.
	// It was like this when I got here.
	grandParentBlockNode, exists := bc.blockIndex[*blockHash]
	if !exists {
		return errors.Errorf("runCommitRuleOnBestChain: Block %v not found in uncommitted blocks map", blockHash.String())
	}
	grandParentBlock, err := GetBlock(grandParentBlockNode.Hash, bc.db, bc.snapshot)
	if err != nil {
		return errors.Wrapf(err, "commitBlock: Problem getting block from db %v", blockHash.String())
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
	// FIXME: I don't think you need to modify the status twice here. It shoudl be the
	// same object getting updated
	bc.bestChainMap[*blockNode.Hash].Status |= StatusBlockCommitted
	bc.blockIndex[*blockNode.Hash].Status |= StatusBlockCommitted
	for _, node := range bc.bestChain {
		if node.Hash.IsEqual(blockNode.Hash) {
			node.Status |= StatusBlockCommitted
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
	if IsBlockCommitted(currentBlock) {
		highestCommittedBlock, _ := bc.getHighestCommittedBlock()
		if highestCommittedBlock == nil {
			return nil, errors.Errorf("getUtxoViewAtBlockHash: No committed blocks found")
		}
		if !highestCommittedBlock.Hash.IsEqual(&blockHash) {
			return nil, errors.Errorf("getUtxoViewAtBlockHash: Block %v is committed but not the committed tip", blockHash)
		}
	}
	for !IsBlockCommitted(currentBlock) {
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
	// FIXME: Delete all references to uncommitedBlocks
	for ii := len(uncommittedAncestors) - 1; ii >= 0; ii-- {
		// We need to get these blocks from the uncommitted blocks map
		// fullBlock, exists := bc.uncommittedBlocksMap[*uncommittedAncestors[ii].Hash]
		// if !exists {
		// 	return nil, errors.Errorf("GetUncommittedTipView: Block %v not found in block index", uncommittedAncestors[ii].Hash)
		// }
		// txnHashes := collections.Transform(fullBlock.Txns, func(txn *MsgDeSoTxn) *BlockHash {
		// 	return txn.Hash()
		// })
		// _, err = utxoView.ConnectBlock(fullBlock, txnHashes, false, nil, fullBlock.Header.Height)
		// if err != nil {
		// 	hash, _ := fullBlock.Hash()
		// 	return nil, errors.Wrapf(err, "GetUncommittedTipView: Problem connecting block hash %v", hash.String())
		// }
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
		if IsBlockCommitted(bc.bestChain[ii]) {
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
