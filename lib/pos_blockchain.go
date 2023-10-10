package lib

import (
	"github.com/deso-protocol/core/collections"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"time"
)

// processBlockPoS runs the Fast-Hotstuff block connect and commit rule as follows:
//  1. Determine if we're missing a parent block of this block and any of its parents from the block index.
//     If so, return the hash of the missing block and add this block to the orphans list.
//  2. Validate on an incoming block, its header, its block height, the leader, and its QCs (vote or timeout)
//  3. Store the block in the block index and uncommitted blocks map.
//  4. Resolves forks within the last two blocks
//  5. Connect the block to the blockchain's tip
//  6. Run the commit rule - If applicable, flushes the incoming block's grandparent to the DB
//  7. Prune in-memory struct holding uncommitted block.
//  8. Update the currentView to this new block's view + 1
func (bc *Blockchain) processBlockPoS(desoBlock *MsgDeSoBlock, verifySignatures bool) (_success bool, _isOrphan bool, _missingBlockHashes []*BlockHash, _err error) {
	// TODO: Implement me
	// 1. Determine if we're missing a parent block of this block and any of its parents from the block index.
	// If so, process the orphan, but don't add to the block index or uncommitted block map.
	missingBlockHash, err := bc.validateAncestorsExist(desoBlock)
	if err != nil {
		return false, false, nil, err
	}
	if missingBlockHash != nil {
		missingBlockHashes := []*BlockHash{missingBlockHash}
		var blockHash *BlockHash
		blockHash, err = desoBlock.Header.Hash()
		// If we fail to get the block hash, this block isn't valid at all, so we
		// don't need to worry about adding it to the orphan list or block index.
		if err != nil {
			return false, true, missingBlockHashes, err
		}
		// ProcessOrphanBlock validates the block and adds it to the orphan list.
		// TODO: update _validateOrphanBlock to perform additional validation required.
		if err = bc.ProcessOrphanBlock(desoBlock, blockHash); err != nil {
			return false, true, missingBlockHashes, err
		}
		return false, true, missingBlockHashes, nil
	}

	// 2. Start with all sanity checks of the block.
	// TODO: Check if err is for view > latest committed block view and <= latest uncommitted block.
	// If so, we need to perform the rest of the validations and then add to our block index.
	if err = bc.validateDeSoBlockPoS(desoBlock); err != nil {

	}
	// TODO: Get validator set for current block height. Alternatively, we could do this in
	// validateQC, but we may need the validator set elsewhere in this function anyway.
	var validatorSet []*ValidatorEntry
	// 1e. Validate QC
	if err = bc.validateQC(desoBlock, validatorSet); err != nil {
		return false, false, nil, err
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
		// If we have a ValidatorsTimeoutAggregateQC set on the block, it means the nodes decided
		// to skip a view by sending TimeoutMessages to the leader, so we process
		// the block accordingly.
		// 1f. If timeout QC, validate that block hash isn't too far back from the latest.
		if err := bc.validateTimeoutQC(desoBlock, validatorSet); err != nil {
			return false, false, nil, err
		}
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
	if err := bc.addBlockToBlockIndex(desoBlock); err != nil {
		return false, false, nil, err
	}

	// 4. Handle reorgs if necessary
	if bc.shouldReorg(desoBlock) {
		if err = bc.handleReorg(desoBlock); err != nil {
			return false, false, nil, err
		}
	}

	// Happy path
	// 5. Add block to best chain.
	if err = bc.addBlockToBestChain(desoBlock); err != nil {
		return false, false, nil, err
	}

	// 6. Commit grandparent if possible.
	if err = bc.commitGrandparents(desoBlock); err != nil {
		return false, false, nil, err
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
// it checks that the view is less than or equal to the latest uncommitted block.
// If not, we return an error indicating that we'll want to add this block as an
// orphan. Then it will check if that the view is exactly one greater than the
// latest uncommitted block if we have an regular vote QC. If this block has a
// timeout QC, it will check that the view is at least greater than the latest
// uncommitted block's view + 1.
func (bc *Blockchain) validateBlockView(desoBlock *MsgDeSoBlock) error {
	// TODO: Implement me
	return errors.New("IMPLEMENT ME")
}

// validateBlockLeader validates that the proposer is the expected proposer for the
// block height + view number pair.
func (bc *Blockchain) validateBlockLeader(desoBlock *MsgDeSoBlock) error {
	// TODO: Implement me
	return errors.New("IMPLEMENT ME")
}

// validateQC validates that the QC of this block is valid, meaning a super majority
// of the validator set has voted (or timed out). Assumes ValidatorEntry list is sorted.
func (bc *Blockchain) validateQC(desoBlock *MsgDeSoBlock, validatorSet []*ValidatorEntry) error {
	// TODO: Implement me
	return errors.New("IMPLEMENT ME")
}

// validateTimeoutQC validates that the parent block hash is not too far back from the latest.
// Specifically, it checks that the parent block hash is at least the latest committed block.
func (bc *Blockchain) validateTimeoutQC(desoBlock *MsgDeSoBlock, validatorSet []*ValidatorEntry) error {
	// TODO: Implement me
	return errors.New("IMPLEMENT ME")
}

// validateAncestorsExist checks that all ancestors of this block exist in the block index.
// If an ancestor is not found, we'll return the block hash of the missing ancestor so the
// caller can request this block.
func (bc *Blockchain) validateAncestorsExist(desoBlock *MsgDeSoBlock) (_missingBlockHash *BlockHash, _err error) {
	// Notes: starting from the block passed in, we'll look for the parent in the block index.
	// 1. If the parent does not appear in the block index, we'll return the parent's hash.
	// 2. If the parent exists in the block index AND is in the best chain, we can safely assume
	//    that all ancestors exist in the block index.
	// 3. If the parent exists in the block index but is not in the best chain, we repeat from
	//    step 1 with the parent as the block passed in.
	// TODO: Implement me
	return nil, errors.New("IMPLEMENT ME")
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
// this block has a higher QC than our current tip and extends from either the committed
// tip OR any uncommitted safe block in our block index.
func (bc *Blockchain) shouldReorg(desoBlock *MsgDeSoBlock) bool {
	return false
}

// handleReorg handles a reorg to the block provided. It does not check whether or not we should
// perform a reorg, so this should be called after shouldReorg. It will do the following:
// 1. Update the bestChain and bestChainMap by removing blocks that are not uncommitted ancestor of this block.
// 2. Update the bestChain and bestChainMap by adding blocks that are uncommitted ancestors of this block.
// Note: addBlockToBestChain will be called after this to handle adding THIS block to the best chain.
func (bc *Blockchain) handleReorg(desoBlock *MsgDeSoBlock) error {
	// TODO: Implement me.
	return errors.New("IMPLEMENT ME")
}

// addBlockToBestChain adds the block to the best chain.
func (bc *Blockchain) addBlockToBestChain(desoBlock *MsgDeSoBlock) error {
	// TODO: Implement me.
	return errors.New("IMPLEMENT ME")
}

// pruneUncommittedBlocks prunes the in-memory struct holding uncommitted blocks.
func (bc *Blockchain) pruneUncommittedBlocks(desoBlock *MsgDeSoBlock) error {
	// TODO: Implement me.
	return errors.New("IMPLEMENT ME")
}

// commitGrandparents commits the grandparent of the block if possible.
// Specifically, this updates the CommittedBlockStatus of its grandparent
// and flushes the view after connecting the grandparent block to the DB.
func (bc *Blockchain) commitGrandparents(desoBlock *MsgDeSoBlock) error {
	// TODO: Implement me.
	return errors.New("IMPLEMENT ME")
}

// updateCurrentView updates the current view to the block's view + 1.
func (bc *Blockchain) updateCurrentView(desoBlock *MsgDeSoBlock) {
	// TODO: Implement me.
	panic(errors.New("IMPLEMENT ME"))
}

func (bc *Blockchain) GetUncommittedTipView() (*UtxoView, error) {
	// Connect the uncommitted blocks to the tip so that we can validate subsequent blocks
	highestCommittedBlock, committedBlockIndex := bc.getHighestCommittedBlock()
	if highestCommittedBlock == nil {
		// This is an edge case we'll never hit in practice since all the PoW blocks
		// are committed.
		return nil, errors.New("GetUncommittedTipView: No committed blocks found")
	}
	utxoView, err := NewUtxoView(bc.db, bc.params, bc.postgres, bc.snapshot)
	if err != nil {
		return nil, errors.Wrapf(err, "GetUncommittedTipView: Problem initializing UtxoView")
	}
	if committedBlockIndex == len(bc.bestChain)-1 {
		return utxoView, nil
	}
	for ii := committedBlockIndex + 1; ii < len(bc.bestChain); ii++ {
		// We need to get these blocks from the uncommitted blocks map
		fullBlock, exists := bc.uncommittedBlocksMap[*bc.bestChain[ii].Hash]
		if !exists {
			return nil, errors.Errorf("GetUncommittedTipView: Block %v not found in block index", bc.bestChain[ii].Hash)
		}
		_, err = utxoView.ConnectBlock(fullBlock, collections.Transform(fullBlock.Txns, func(txn *MsgDeSoTxn) *BlockHash {
			return txn.Hash()
		}), false, nil, fullBlock.Header.Height)
		if err != nil {
			hash, _ := fullBlock.Hash()
			return nil, errors.Wrapf(err, "GetUncommittedTipView: Problem connecting block hash %v", hash.String())
		}
	}
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
	return nil, 0
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
	RuleErrorNilMerkleRoot                  RuleError = "RuleErrorNilMerkleRoot"
	RuleErrorInvalidMerkleRoot              RuleError = "RuleErrorInvalidMerkleRoot"
	RuleErrorNoTxnsWithMerkleRoot           RuleError = "RuleErrorNoTxnsWithMerkleRoot"
	RuleErrorInvalidProposerVotingPublicKey RuleError = "RuleErrorInvalidProposerVotingPublicKey"
	RuleErrorInvalidProposerPublicKey       RuleError = "RuleErrorInvalidProposerPublicKey"
	RuleErrorInvalidRandomSeedHash          RuleError = "RuleErrorInvalidRandomSeedHash"

	RuleErrorInvalidPoSBlockHeight       RuleError = "RuleErrorInvalidPoSBlockHeight"
	RuleErrorPoSBlockBeforeCutoverHeight RuleError = "RuleErrorPoSBlockBeforeCutoverHeight"
)
