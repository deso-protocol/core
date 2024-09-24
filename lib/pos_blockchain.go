package lib

import (
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/consensus"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

// processHeaderPoS validates and stores an incoming block header to build
// the PoS version of the header chain. It requires callers to call it with
// headers in order of increasing block height. If called with an orphan header,
// it still gracefully handles it by returning early and not storing the header
// in the block index.
//
// The PoS header chain uses a simplified version of the Fast-HotStuff consensus
// rules. It's used during syncing to build a chain of block headers with the
// minimum set of validations needed to build a template of what the full PoS
// blockchain will look like.
//
// The PoS header chain uses block integrity checks to perform block validations,
// and to connect blocks based on their PrevBlockHash. It does not run the commit
// rule. It does not fully validate QCs or block proposers, or perform any validations
// that require on-chain state.
//
// processHeaderPoS algorithm:
//  1. Exit early if the header has already been indexed in the block index.
//  2. Do nothing if the header is an orphan.
//  3. Validate the header and verify that its parent is also valid.
//  4. Add the block header to the block index with status
//     StatusHeaderValidated or StatusHeaderValidateFailed.
//  5. Exit early if the's view is less than the current header chain's tip.
//  6. Reorg the best header chain if the header's view is higher than the current tip.
func (bc *Blockchain) processHeaderPoS(header *MsgDeSoHeader, verifySignatures bool) (
	_isMainChain bool, _isOrphan bool, _err error,
) {
	if !bc.params.IsPoSBlockHeight(header.Height) {
		return false, false, errors.Errorf(
			"processHeaderPoS: Header height %d is less than the ProofOfStake2ConsensusCutoverBlockHeight %d",
			header.Height, bc.params.GetFirstPoSBlockHeight(),
		)
	}

	headerHash, err := header.Hash()
	if err != nil {
		return false, false, errors.Wrapf(err, "processHeaderPoS: Problem hashing header")
	}

	// If the incoming header is already part of the best header chain, then we can exit early.
	// The header is not part of a fork, and is already an ancestor of the current header chain tip.
	if _, isInBestHeaderChain := bc.bestHeaderChain.GetBlockByHashAndHeight(headerHash, header.Height); isInBestHeaderChain {
		return true, false, nil
	}

	// If the incoming header is part of a reorg that uncommits the committed tip from the best chain,
	// then we exit early. Such headers are invalid and should not be synced.
	committedBlockchainTip, _ := bc.GetCommittedTip()
	if committedBlockchainTip != nil && committedBlockchainTip.Header.Height >= header.Height {
		return false, false, errors.New("processHeaderPoS: Header conflicts with committed tip")
	}

	// Validate the header and index it in the block index.
	blockNode, isOrphan, err := bc.validateAndIndexHeaderPoS(header, headerHash, verifySignatures)
	if err != nil {
		return false, false, errors.Wrapf(err, "processHeaderPoS: Problem validating and indexing header: ")
	}

	// Now that we know we have a valid header, we check the block index for it any orphan children for it
	// and heal the parent pointers for all of them.
	bc.healPointersForOrphanChildren(blockNode)

	// Exit early if the header is an orphan.
	if isOrphan {
		return false, true, nil
	}

	// Exit early if the header's view is less than the current header chain's tip. The header is not
	// the new tip for the best header chain.
	currentTip := bc.headerTip()
	if header.ProposedInView <= currentTip.Header.ProposedInView {
		return false, false, nil
	}

	// The header is not an orphan and has a higher view than the current tip. We reorg the header chain
	// and apply the incoming header as the new tip.
	_, blocksToDetach, blocksToAttach := GetReorgBlocks(currentTip, blockNode)
	bc.bestHeaderChain.Chain, bc.bestHeaderChain.ChainMap = updateBestChainInMemory(
		bc.bestHeaderChain.Chain,
		bc.bestHeaderChain.ChainMap,
		blocksToDetach,
		blocksToAttach,
	)

	// Success. The header is at the tip of the best header chain.
	return true, false, nil
}

// healPointersForOrphanChildren fixes an inconsistency in the block index that may have
// occurred as a result of a node restart. In cases where we have an orphan node that we store in the
// DB, then on restart, that node's parent will not be in the block index. When processing the parent
// later on, we not only need to store the parent in the block index but also need to update the
// pointer from the orphan block's BlockNode to the parent. We do that dynamically here as we
// process headers.
func (bc *Blockchain) healPointersForOrphanChildren(blockNode *BlockNode) {
	// Fetch all potential children of this blockNode from the block index.
	blockNodesAtNextHeight := bc.blockIndex.GetBlockNodesByHeight(blockNode.Header.Height + 1)
	exists := len(blockNodesAtNextHeight) > 0
	if !exists {
		// No children of this blockNode exist in the block index. Exit early.
		return
	}

	// Iterate through all block nodes at the next block height and update their parent pointers.
	for _, blockNodeAtNextHeight := range blockNodesAtNextHeight {
		// Check if it's a child of the parent block node.
		if !blockNodeAtNextHeight.Header.PrevBlockHash.IsEqual(blockNode.Hash) {
			continue
		}

		// Check if it has its parent pointer set. If it does, then we exit early.
		if blockNodeAtNextHeight.Parent != nil {
			continue
		}

		// If the parent block node is not set, then we set it to the parent block node.
		blockNodeAtNextHeight.Parent = blockNode
	}
}

func (bc *Blockchain) validateAndIndexHeaderPoS(header *MsgDeSoHeader, headerHash *BlockHash, verifySignatures bool) (
	_headerBlockNode *BlockNode, _isOrphan bool, _err error,
) {
	// Look up the header in the block index to check if it has already been validated and indexed.
	blockNode, blockNodeExists := bc.blockIndex.GetBlockNodeByHashAndHeight(headerHash, header.Height)
	// ------------------------------------ Base Cases ----------------------------------- //

	// The header is already validated. Exit early.
	if blockNodeExists && blockNode.IsHeaderValidated() {
		return blockNode, false, nil
	}

	// The header has already failed validations. Exit early.
	if blockNodeExists && blockNode.IsHeaderValidateFailed() {
		return nil, false, errors.New("validateAndIndexHeaderPoS: Header already failed validation")
	}

	// The header has an invalid PrevBlockHash field. Exit early.
	if header.PrevBlockHash == nil {
		return nil, false, errors.New("validateAndIndexHeaderPoS: PrevBlockHash is nil")
	}

	// The header is an orphan. No need to store it in the block index. Exit early.
	// TODO: validate that height - 1 > 0
	parentBlockNode, parentBlockNodeExists := bc.blockIndex.GetBlockNodeByHashAndHeight(header.PrevBlockHash, header.Height-1)
	if !parentBlockNodeExists {
		return nil, true, nil
	}

	// Sanity-check that the parent block is an ancestor of the current block.
	if blockNodeExists && (parentBlockNode.Height+1 != blockNode.Height) {
		return nil, false, errors.New("validateAndIndexHeaderPoS: Parent header has " +
			"greater or equal height compared to the current header.")
	}

	// ---------------------------------- Recursive Case ---------------------------------- //

	// Recursively call validateAndIndexHeaderPoS on the header's ancestors. It's possible for
	// headers to be added to the block index out of order by processBlockPoS. In those cases,
	// it's possible for ancestors of this header to exist in the block index but not have their
	// header validation statuses set yet. We set them here recursively.
	//
	// This is safe and efficient as long as validateAndIndexHeaderPoS is only called on non-orphan
	// headers. This guarantees that the recursive case for each header can only be hit once.
	parentBlockNode, isParentAnOrphan, err := bc.validateAndIndexHeaderPoS(
		parentBlockNode.Header, header.PrevBlockHash, verifySignatures)
	if err != nil {
		return nil, false, err
	}

	// Gracefully handle the case where the parent is still an orphan. This should never happen.
	if isParentAnOrphan {
		return nil, true, nil
	}
	// Verify that the parent has not previously failed validation. If it has, then the incoming header
	// is also not valid.
	if parentBlockNode.IsHeaderValidateFailed() {
		return nil, false, bc.storeValidateFailedHeaderInBlockIndexWithWrapperError(
			header, errors.New("validateAndIndexHeaderPoS: Parent header failed validations"),
		)
	}

	// Verify that the header is properly formed.
	if err := bc.isValidBlockHeaderPoS(header); err != nil {
		return nil, false, bc.storeValidateFailedHeaderInBlockIndexWithWrapperError(
			header, errors.New("validateAndIndexHeaderPoS: Header failed validations"),
		)
	}

	if verifySignatures {
		// Validate the header's random seed signature.
		isValidRandomSeedSignature, err := bc.hasValidProposerRandomSeedSignaturePoS(header)
		if err != nil {
			return nil, false, errors.Wrap(err, "validateAndIndexHeaderPoS: Problem validating random seed signature")
		}
		if !isValidRandomSeedSignature {
			return nil, false, bc.storeValidateFailedHeaderInBlockIndexWithWrapperError(
				header, errors.New("validateAndIndexHeaderPoS: Header has invalid random seed signature"),
			)
		}
	}

	// Store it as HeaderValidated now that it has passed all validations.
	blockNode, err = bc.storeValidatedHeaderInBlockIndex(header)
	if err != nil {
		return nil, false, errors.Wrapf(err, "validateAndIndexHeaderPoS: Problem adding header to block index: ")
	}

	// Happy path. The header is not an orphan and is valid.
	return blockNode, false, nil
}

// ProcessBlockPoS simply acquires the chain lock and calls processBlockPoS.
func (bc *Blockchain) ProcessBlockPoS(block *MsgDeSoBlock, currentView uint64, verifySignatures bool) (
	_success bool,
	_isOrphan bool,
	_missingBlockHashes []*BlockHash,
	_err error,
) {
	// Grab the chain lock
	bc.ChainLock.Lock()
	defer bc.ChainLock.Unlock()

	// Perform a simple nil-check. If the block is nil then we return an error. Nothing we can do here.
	if block == nil {
		return false, false, nil, fmt.Errorf("ProcessBlockPoS: Block is nil")
	}

	return bc.processBlockPoS(block, currentView, verifySignatures)
}

// processBlockPoS runs the Fast-HotStuff block connect and commit rule as follows:
//  1. Determine if we're missing the parent block of this block.
//     If so, return the hash of the missing block and add this block to the orphans list.
//  2. Validate the incoming block, its header, its block height, the leader, and its QCs (vote or timeout)
//  3. Store the block in the block index and save to DB.
//  4. Process the block's header. This may reorg the header chain and apply the block as the new header chain tip.
//  5. Try to apply the incoming block as the tip (performing reorgs as necessary). If it can't be applied, exit here.
//  6. Run the commit rule - If applicable, flushes the incoming block's grandparent to the DB
//  7. Notify listeners via the EventManager of which blocks have been removed and added.
func (bc *Blockchain) processBlockPoS(block *MsgDeSoBlock, currentView uint64, verifySignatures bool) (
	_success bool,
	_isOrphan bool,
	_missingBlockHashes []*BlockHash,
	_err error,
) {
	// If the incoming block's height is under the PoS cutover fork height, then we can't process it. Exit early.
	if !bc.params.IsPoSBlockHeight(block.Header.Height) {
		return false, false, nil, errors.Errorf(
			"processHeaderPoS: Header height %d is less than the ProofOfStake2ConsensusCutoverBlockHeight %d",
			block.Header.Height, bc.params.GetFirstPoSBlockHeight(),
		)
	}

	// If we can't hash the block, we can never store in the block index and we should throw it out immediately.
	if _, err := block.Hash(); err != nil {
		return false, false, nil, errors.Wrapf(err, "processBlockPoS: Problem hashing block")
	}

	// In hypersync archival mode, we may receive blocks that have already been processed and committed during state
	// synchronization. However, we may want to store these blocks in the db for archival purposes. We check if the
	// block we're dealing with is an archival block. If it is, we store it and return early.
	if success, err := bc.checkAndStoreArchivalBlock(block); err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem checking and storing archival block")
	} else if success {
		return true, false, nil, nil
	}

	// Get all the blocks between the current block and the committed tip. If the block
	// is an orphan, then we store it after performing basic validations.
	// If the block extends from any committed block other than the committed tip,
	// then we throw it away.
	lineageFromCommittedTip, missingBlockHashes, err := bc.getStoredLineageFromCommittedTip(block.Header)
	if errors.Is(err, RuleErrorDoesNotExtendCommittedTip) ||
		errors.Is(err, RuleErrorParentBlockHasViewGreaterOrEqualToChildBlock) ||
		errors.Is(err, RuleErrorParentBlockHeightNotSequentialWithChildBlockHeight) ||
		errors.Is(err, RuleErrorAncestorBlockValidationFailed) {
		// In this case, the block extends a committed block that is NOT the tip
		// block. We will never accept this block. To prevent spam, we do not
		// store this block as validate failed. We just throw it away.
		return false, false, nil, errors.Wrap(err, "processBlockPoS: ")
	}
	if errors.Is(err, RuleErrorMissingAncestorBlock) {
		// In this case, the block is an orphan that does not extend from any blocks
		// on our best chain. Try to process the orphan by running basic validations.
		// If it passes basic integrity checks, we'll store it with the hope that we
		// will eventually get a parent that connects to our best chain.
		return false, true, missingBlockHashes, bc.processOrphanBlockPoS(block)
	}

	if err != nil {
		return false, false, nil, errors.Wrap(err,
			"processBlockPoS: Unexpected problem getting lineage from committed tip: ")
	}

	// We expect the utxoView for the parent block to be valid because we check that all ancestor blocks have
	// been validated.
	parentUtxoViewAndUtxoOps, err := bc.getUtxoViewAndUtxoOpsAtBlockHash(*block.Header.PrevBlockHash, block.Header.Height-1)
	if err != nil {
		// This should never happen. If the parent is validated and extends from the tip, then we should
		// be able to build a UtxoView for it. This failure can only happen due to transient or badger issues.
		// We return that validation didn't fail and the error.
		return false, false, nil, errors.Wrap(err, "validateLeaderAndQC: Problem getting UtxoView")
	}
	parentUtxoView := parentUtxoViewAndUtxoOps.UtxoView
	// First, we perform a validation of the leader and the QC to prevent spam.
	// If the block fails this check, we throw it away.
	passedSpamPreventionCheck, err := bc.validateLeaderAndQC(block, parentUtxoView, verifySignatures)
	if err != nil {
		// If we hit an error, we can't store it since we're not sure if it passed the spam prevention check.
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem validating leader and QC")
	}
	if !passedSpamPreventionCheck {
		// If the block fails the spam prevention check, we throw it away.
		return false, false, nil, errors.Wrapf(RuleErrorFailedSpamPreventionsCheck, "processBlockPoS: Block failed spam prevention check: ")
	}

	// Validate the block and store it in the block index. The block is guaranteed to not be an orphan.
	blockNode, err := bc.validateAndIndexBlockPoS(block, parentUtxoView, verifySignatures)
	if err != nil {
		return false, false, nil, errors.Wrap(err,
			"processBlockPoS: Problem validating block: ")
	}
	if !blockNode.IsValidated() {
		return false, false, nil, errors.New(
			"processBlockPoS: Block not validated after performing all validations.")
	}

	// At this point, we know that the block has passed all validations. The block may or may
	// not be connected to the chain, but it has been accepted because it is known to be valid.
	// We trigger a block accepted event to notify listeners.
	if bc.eventManager != nil {
		bc.eventManager.blockAccepted(&BlockEvent{Block: block})
	}

	// 4. Process the block's header and update the header chain. We call processHeaderPoS
	// here after verifying that the block is not an orphan and has passed all validations,
	// but directly before applying the block as the new tip. Any failure when validating the
	// header and applying it to the header chain will result in the two chains being out of
	// sync. The header chain is less critical and mutations to it are reversible. So we attempt
	// to mutate it first before attempting to mutate the block chain.
	if _, _, err = bc.processHeaderPoS(block.Header, verifySignatures); err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem processing header")
	}

	// 5. Try to apply the incoming block as the new tip. This function will
	// first perform any required reorgs and then determine if the incoming block
	// extends the chain tip. If it does, it will apply the block to the best chain
	// and appliedNewTip will be true and we can continue to running the commit rule.
	appliedNewTip, connectedBlockHashes, disconnectedBlockHashes, err := bc.tryApplyNewTip(
		blockNode, currentView, lineageFromCommittedTip,
	)
	if err != nil {
		return false, false, nil, errors.Wrap(err, "processBlockPoS: Problem applying new tip: ")
	}

	// 6. Commit grandparent if possible. Only need to do this if we applied a new tip.
	if appliedNewTip {
		if err = bc.runCommitRuleOnBestChain(verifySignatures); err != nil {
			return false, false, nil, errors.Wrap(err,
				"processBlockPoS: error running commit rule: ")
		}
	}

	// 7. Notify listeners via the EventManager of which blocks have been removed and added.
	for ii := len(disconnectedBlockHashes) - 1; ii >= 0; ii-- {
		disconnectedBlock := bc.GetBlock(&disconnectedBlockHashes[ii])
		if disconnectedBlock == nil {
			glog.Errorf("processBlockPoS: Problem getting disconnected block %v", disconnectedBlockHashes[ii])
			continue
		}
		if bc.eventManager != nil {
			bc.eventManager.blockDisconnected(&BlockEvent{Block: disconnectedBlock})
		}
	}
	for ii := 0; ii < len(connectedBlockHashes); ii++ {
		connectedBlock := bc.GetBlock(&connectedBlockHashes[ii])
		if connectedBlock == nil {
			glog.Errorf("processBlockPoS: Problem getting connected block %v", connectedBlockHashes[ii])
			continue
		}
		if bc.eventManager != nil {
			bc.eventManager.blockConnected(&BlockEvent{Block: connectedBlock})
		}
	}

	// Now that we've processed this block, we check for any blocks that were previously
	// stored as orphans, which are children of this block. We can process them now.
	blockNodesAtNextHeight := bc.blockIndex.GetBlockNodesByHeight(uint64(blockNode.Height) + 1)
	for _, blockNodeAtNextHeight := range blockNodesAtNextHeight {
		if blockNodeAtNextHeight.Header.PrevBlockHash.IsEqual(blockNode.Hash) &&
			blockNodeAtNextHeight.IsStored() &&
			!blockNodeAtNextHeight.IsValidated() &&
			!blockNodeAtNextHeight.IsValidateFailed() {
			var orphanBlock *MsgDeSoBlock
			orphanBlock, err = GetBlock(blockNodeAtNextHeight.Hash, bc.db, bc.snapshot)
			if err != nil {
				glog.Errorf("processBlockPoS: Problem getting orphan block %v", blockNodeAtNextHeight.Hash)
				continue
			}
			var appliedNewTipOrphan bool
			if appliedNewTipOrphan, _, _, err = bc.processBlockPoS(
				orphanBlock, currentView, verifySignatures); err != nil {
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
// As a spam-prevention measure, we will not store a block if it fails the QC or leader check
// and simply throw it away. If it fails the other integrity checks, we'll store it
// as validate failed.
func (bc *Blockchain) processOrphanBlockPoS(block *MsgDeSoBlock) error {
	// Construct a UtxoView, so we can perform the QC and leader checks.
	utxoView := bc.GetCommittedTipView()

	epochEntry, err := utxoView.GetCurrentEpochEntry()
	if err != nil {
		// We can't validate the QC without getting the current epoch entry.
		return errors.Wrap(err, "processOrphanBlockPoS: Problem getting current epoch entry")
	}

	// If the block is in a previous or future epoch, we need to compute the
	// proper validator set for the block. We do this by computing the prev/next
	// epoch entry and then fetching the validator set at the snapshot of the
	// epoch number of the prev/next epoch entry.
	if !epochEntry.ContainsBlockHeight(block.Header.Height) {
		// Get the epoch entry based on the block height. The logic is the same
		// regardless of whether the block is in a previous or future epoch.
		// Note that the InitialView cannot be properly computed.
		usePrevEpoch := block.Header.Height < epochEntry.InitialBlockHeight
		// If it's in a previous epoch, we compute the prev epoch entry.
		if usePrevEpoch {
			epochEntry, err = utxoView.simulatePrevEpochEntry(epochEntry.EpochNumber,
				epochEntry.InitialBlockHeight)
			if err != nil {
				return errors.Wrap(err, "processOrphanBlockPoS: Problem computing prev epoch entry")
			}
		} else {
			// Okay now we know that this block must be in a future epoch. We do our best to compute
			// the next epoch entry and check if it is in that epoch. If it's in a future epoch, we just throw it away.
			// We supply 0 for the view and 0 for the block timestamp as we don't know what those values should be, and
			// we will ignore these values.
			epochEntry, err = utxoView.simulateNextEpochEntry(epochEntry.EpochNumber, epochEntry.FinalBlockHeight)
			if err != nil {
				return errors.Wrap(err, "processOrphanBlockPoS: Problem computing next epoch entry")
			}
		}
		if !epochEntry.ContainsBlockHeight(block.Header.Height) {
			// We will throw away this block as we know it's not in either
			// the next or the previous epoch.
			errSuffix := "future"
			if usePrevEpoch {
				errSuffix = "past"
			}
			return fmt.Errorf("processOrphanBlockPoS: Block height %d is too far in the %v",
				block.Header.Height, errSuffix)
		}
	}

	var epochEntrySnapshotAtEpochNumber uint64
	epochEntrySnapshotAtEpochNumber, err = utxoView.ComputeSnapshotEpochNumberForEpoch(epochEntry.EpochNumber)
	if err != nil {
		return errors.Wrapf(err,
			"processOrphanBlockPoS: Problem getting snapshot at epoch number for poch entry at epoch #%d",
			epochEntry.EpochNumber)
	}
	// Okay now that we've gotten the SnapshotAtEpochNumber for the prev/next epoch, we can make sure that the
	// proposer of the block is within the set of potential block proposers for the prev/next epoch based on
	// the VotingPublicKey.
	// First, we get the snapshot validator entry based on the BLS public key in the header.
	snapshotBLSPublicKeyPKIDEntry, err := utxoView.GetSnapshotValidatorBLSPublicKeyPKIDPairEntry(
		block.Header.ProposerVotingPublicKey, epochEntrySnapshotAtEpochNumber)
	if err != nil {
		return errors.Wrapf(err,
			"processOrphanBlockPoS: Problem getting snapshot validator entry for block proposer %v",
			block.Header.ProposerVotingPublicKey)
	}
	// If no snapshot BLSPublicKeyPKIDEntry exists, we'll never accept this block as
	// its block proposer is not in the validator set as we did not snapshot its BLS Public key.
	// This is a spam prevention measure, so we just throw away the block.
	if snapshotBLSPublicKeyPKIDEntry == nil {
		return nil
	}
	// Fetch the snapshot leader PKIDs
	snapshotLeaderPKIDs, err := utxoView.GetSnapshotLeaderScheduleAtEpochNumber(epochEntrySnapshotAtEpochNumber)
	if err != nil {
		return errors.Wrapf(err,
			"processOrphanBlockPoS: Problem getting snapshot leader schedule at snapshot at epoch number %d",
			epochEntrySnapshotAtEpochNumber)
	}
	// Get the PKID for the block proposer from the snapshot validator entry.
	blockProposerPKID := snapshotBLSPublicKeyPKIDEntry.PKID
	// TODO: Replace w/ collections.Any for simplicity. There is an issue with this version
	// of Go's compiler that is preventing us from using collections.Any here.
	// We can now check if the block proposer is in the set of snapshot leader PKIDs.
	blockProposerSeen := false
	for _, snapshotLeaderPKID := range snapshotLeaderPKIDs {
		if snapshotLeaderPKID.Eq(blockProposerPKID) {
			blockProposerSeen = true
			break
		}
	}
	if !blockProposerSeen {
		// We'll never accept this block as its block proposer is not in the set of
		// potential leaders. As a spam-prevention measure, we simply return nil and throw it away.
		return nil
	}
	validatorsByStake, err := utxoView.GetAllSnapshotValidatorSetEntriesByStakeAtEpochNumber(
		epochEntrySnapshotAtEpochNumber)
	if err != nil {
		return errors.Wrapf(err,
			"processOrphanBlockPoS: Problem getting validator set at snapshot at epoch number %d",
			epochEntrySnapshotAtEpochNumber)
	}

	// Okay now we have the validator set ordered by stake, we can validate the QC.
	if err = bc.isValidPoSQuorumCertificate(block, validatorsByStake); err != nil {
		// If we hit an error, we know that the QC is invalid, and we'll never accept this block,
		// As a spam-prevention measure, we just throw away this block and don't store it.
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "processOrphanBlockPoS: Problem getting snapshot global params")
	}
	// All blocks should pass the basic integrity validations, which ensure the block
	// is not malformed. If the block is malformed, we should store it as ValidateFailed.
	if err = bc.isProperlyFormedBlockPoS(block); err != nil {
		if _, innerErr := bc.storeValidateFailedBlockInBlockIndex(block); innerErr != nil {
			return errors.Wrapf(innerErr,
				"processOrphanBlockPoS: Problem adding validate failed block to block index: %v", err)
		}
		return nil
	}
	// Add to blockIndexByHash with status STORED only as we are not sure if it's valid yet.
	_, err = bc.storeBlockInBlockIndex(block)
	return errors.Wrap(err, "processBlockPoS: Problem adding block to block index: ")
}

// checkAndStoreArchivalBlock is a helper function that takes in a block and checks if it's an archival block.
// If it is, it stores the block in the db and returns true. If it's not, it returns false, or false and an error.
func (bc *Blockchain) checkAndStoreArchivalBlock(block *MsgDeSoBlock) (_success bool, _err error) {
	// First, get the block hash and lookup the block index.
	blockHash, err := block.Hash()
	if err != nil {
		return false, errors.Wrap(err, "checkAndStoreArchivalBlock: Problem hashing block")
	}
	blockNode, exists := bc.blockIndex.GetBlockNodeByHashAndHeight(blockHash, block.Header.Height)
	// If the blockNode doesn't exist, or the block is not committed, or it's already stored, then we're not dealing
	// with an archival block. Archival blocks must have an existing blockNode, be committed, and not be stored.
	if !exists || !blockNode.IsCommitted() || blockNode.IsStored() {
		return false, nil
	}

	// If we get to this point, we're dealing with an archival block, so we'll attempt to store it.
	// This means, this block node is already marked as COMMITTED and VALIDATED, and we just need to store it.
	_, err = bc.storeBlockInBlockIndex(block)
	if err != nil {
		return false, errors.Wrap(err, "checkAndStoreArchivalBlock: Problem storing block in block index")
	}
	return true, nil
}

// storeValidateFailedBlockWithWrappedError is a helper function that takes in a block and an error and
// stores the block in the block index with status VALIDATE_FAILED. It returns the resulting BlockNode.
func (bc *Blockchain) storeValidateFailedBlockWithWrappedError(block *MsgDeSoBlock, outerErr error) (
	*BlockNode, error) {
	blockNode, innerErr := bc.storeValidateFailedBlockInBlockIndex(block)
	if innerErr != nil {
		return nil, errors.Wrapf(innerErr,
			"storeValidateFailedBlockWithWrappedError: Problem adding validate failed block to block index: %v",
			outerErr)
	}
	return blockNode, nil
}

func (bc *Blockchain) validateLeaderAndQC(
	block *MsgDeSoBlock,
	parentUtxoView *UtxoView,
	verifySignatures bool,
) (_passedSpamPreventionCheck bool, _err error) {
	currentEpochEntry, err := parentUtxoView.GetCurrentEpochEntry()
	if err != nil {
		return false, errors.Wrap(err,
			"validateLeaderAndQC: Problem getting current epoch entry")
	}
	// If after constructing a UtxoView based on the parent block, we find that the current block's height
	// isn't in the current epoch, then block's stated height is wrong. The block is guaranteed to be invalid.
	if !currentEpochEntry.ContainsBlockHeight(block.Header.Height) {
		return false, nil
	}

	if verifySignatures {
		snapshotAtEpochNumber, err := parentUtxoView.ComputeSnapshotEpochNumberForEpoch(currentEpochEntry.EpochNumber)
		if err != nil {
			return false, errors.Wrapf(err,
				"validateLeaderAndQC: Problem getting snapshot epoch number for epoch #%d",
				currentEpochEntry.EpochNumber)
		}
		isValidPartialSig, err := parentUtxoView.hasValidProposerPartialSignaturePoS(block, snapshotAtEpochNumber)
		if err != nil {
			return false, errors.Wrap(err,
				"validateLeaderAndQC: Problem validating proposer partial sig")
		}
		if !isValidPartialSig {
			return false, nil
		}
		// 2. Validate QC
		validatorsByStake, err := parentUtxoView.GetAllSnapshotValidatorSetEntriesByStake()
		if err != nil {
			// This should never happen. If the parent is validated and extends from the tip, then we should
			// be able to fetch the validator set at its block height for it. This failure can only happen due
			// to transient badger issues. We return false for failed spam prevention check and the error.
			return false, errors.Wrap(err, "validateLeaderAndQC: Problem getting validator set")
		}

		// Validate the block's QC. If it's invalid, we return true for failed spam prevention check.
		if err = bc.isValidPoSQuorumCertificate(block, validatorsByStake); err != nil {
			return false, nil
		}
	}

	isBlockProposerValid, err := parentUtxoView.hasValidBlockProposerPoS(block)
	if err != nil {
		return false, errors.Wrapf(err,
			"validateAndIndexBlockPoS: Problem validating block proposer")
	}
	// If the block proposer is invalid, we return true for failed spam prevention check.
	if !isBlockProposerValid {
		return false, nil
	}
	return true, nil
}

// validateAndIndexBlockPoS performs all validation checks, except the QC and leader check to prevent spam,
// for a given block and adds it to the block index with the appropriate status. It assumes that the block
// passed in has passed the spam prevention check.
//  1. If the block is already VALIDATE_FAILED, we return the BlockNode as-is without perform further validations and
//     throw an error.
//  2. If the block is already VALIDATED, we return the BlockNode as-is without performing further validations and no
//     error.
//  3. We check if its parent is VALIDATE_FAILED, if so we add the block to the block index with status VALIDATE_FAILED
//     and throw an error.
//  4. If its parent is NOT VALIDATED and NOT VALIDATE_FAILED, we recursively call this function on its parent.
//  5. If after calling this function on its parent, the parent is VALIDATE_FAILED, we add the block to the block index
//     with status VALIDATE_FAILED and throw an error.
//  6. If after calling this function on its parent, the parent is VALIDATED, we perform all other validations on the
//     block.
//
// The recursive function's invariant is described as follows:
//   - Base case: If block is VALIDATED or VALIDATE_FAILED, return the BlockNode as-is. If the block is STORED and
//     has a timestamp too far in the future, we also return the BlockNode as-is.
//   - Recursive case: If the block is not VALIDATED or VALIDATE_FAILED in the blockIndexByHash, we will perform all
//     validations and add the block to the block index with the appropriate status (VALIDATED OR VALIDATE_FAILED) and
//     return the new BlockNode.
//   - Error case: Something goes wrong that doesn't result in the block being marked VALIDATE or VALIDATE_FAILED. In
//     this case, we will add the block to the block index with status STORED and return the BlockNode.
func (bc *Blockchain) validateAndIndexBlockPoS(block *MsgDeSoBlock, parentUtxoView *UtxoView, verifySignatures bool) (
	*BlockNode, error) {
	blockHash, err := block.Header.Hash()
	if err != nil {
		return nil, errors.Wrapf(err, "validateAndIndexBlockPoS: Problem hashing block %v", block)
	}

	// Base case - Check if the block is validated or validate failed. If so, we can return early.
	// TODO: validate height doesn't overflow uint32
	blockNode, exists := bc.blockIndex.GetBlockNodeByHashAndHeight(blockHash, block.Header.Height)
	if exists && (blockNode.IsValidateFailed() || blockNode.IsValidated()) {
		return blockNode, nil
	}

	// Base case - Check if the block has already been stored and fails the timestamp drift check.
	// If it fails the check, then we leave it as stored and return early.
	if exists && blockNode.IsStored() {
		// If the block is too far in the future, we leave it as STORED and return early.
		failsTimestampDriftCheck, err := bc.isBlockTimestampTooFarInFuturePoS(block.Header)
		if err != nil {
			return blockNode, errors.Wrap(err, "validateAndIndexBlockPoS: Problem checking block timestamp")
		}
		if failsTimestampDriftCheck {
			return blockNode, nil
		}
	}

	// Run the validation for the parent and update the block index with the parent's status. We first
	// check if the parent has a cached status. If so, we use the cached status. Otherwise, we run
	// the full validation algorithm on it, then index it and use the result.
	parentBlockNode, err := bc.validatePreviouslyIndexedBlockPoS(block.Header.PrevBlockHash, block.Header.Height-1, verifySignatures)
	if err != nil {
		return blockNode, errors.Wrapf(err, "validateAndIndexBlockPoS: Problem validating previously indexed block: ")
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
		return bc.storeBlockInBlockIndex(block)
	}

	// Validate the block's random seed signature
	if verifySignatures {
		isValidRandomSeedSignature, err := bc.hasValidProposerRandomSeedSignaturePoS(block.Header)
		if err != nil {
			var innerErr error
			blockNode, innerErr = bc.storeBlockInBlockIndex(block)
			if innerErr != nil {
				return nil, errors.Wrapf(innerErr, "validateAndIndexBlockPoS: Problem adding block to block index: %v", err)
			}
			return blockNode, errors.Wrap(err, "validateAndIndexBlockPoS: Problem validating random seed signature")
		}
		if !isValidRandomSeedSignature {
			return bc.storeValidateFailedBlockWithWrappedError(block, errors.New("invalid random seed signature"))
		}
	}

	// Make sure the block isn't too big.
	serializedBlock, err := block.ToBytes(false)
	if err != nil {
		return bc.storeValidateFailedBlockWithWrappedError(
			block, errors.Wrap(err, "validateAndIndexBlockPoS: Problem serializing block"))
	}
	if uint64(len(serializedBlock)) > parentUtxoView.GetCurrentGlobalParamsEntry().MaxBlockSizeBytesPoS {
		return bc.storeValidateFailedBlockWithWrappedError(block, RuleErrorBlockTooBig)
	}

	// Check if the block is properly formed and passes all basic validations.
	if err = bc.isValidBlockPoS(block); err != nil {
		return bc.storeValidateFailedBlockWithWrappedError(block, err)
	}

	// Connect this block to the parent block's UtxoView.
	txHashes := collections.Transform(block.Txns, func(txn *MsgDeSoTxn) *BlockHash {
		return txn.Hash()
	})

	// If we fail to connect the block, then it means the block is invalid. We should store it as ValidateFailed.
	if _, err = parentUtxoView.ConnectBlock(block, txHashes, verifySignatures, nil, block.Header.Height); err != nil {
		// If it doesn't connect, we want to mark it as ValidateFailed.
		return bc.storeValidateFailedBlockWithWrappedError(block, err)
	}

	// If the block is too far in the future, we leave it as STORED and return early.
	failsTimestampDriftCheck, err := bc.isBlockTimestampTooFarInFuturePoS(block.Header)
	if err != nil {
		return blockNode, errors.Wrap(err, "validateAndIndexBlockPoS: Problem checking block timestamp")
	}
	if failsTimestampDriftCheck {
		return bc.storeBlockInBlockIndex(block)
	}

	// We can now add this block to the block index since we have performed all basic validations.
	blockNode, err = bc.storeValidatedBlockInBlockIndex(block)
	if err != nil {
		return blockNode, errors.Wrap(err, "validateAndIndexBlockPoS: Problem adding block to block index: ")
	}
	return blockNode, nil
}

// validatePreviouslyIndexedBlockPoS is a helper function that takes in a block hash for a previously
// cached block, and runs the validateAndIndexBlockPoS algorithm on it. It returns the resulting BlockNode.
func (bc *Blockchain) validatePreviouslyIndexedBlockPoS(
	blockHash *BlockHash,
	blockHeight uint64,
	verifySignatures bool,
) (*BlockNode, error) {
	// Check if the block is already in the block index. If so, we check its current status first.
	blockNode, exists := bc.blockIndex.GetBlockNodeByHashAndHeight(blockHash, blockHeight)
	if !exists {
		// We should never really hit this if the block has already been cached in the block index first.
		// We check here anyway to be safe.
		return nil, errors.New(
			"validatePreviouslyIndexedBlockPoS: Block not found in block index. This should never happen.")
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
	// Build utxoView for the block's parent.
	parentUtxoViewAndUtxoOps, err := bc.getUtxoViewAndUtxoOpsAtBlockHash(*block.Header.PrevBlockHash, block.Header.Height-1)
	if err != nil {
		// This should never happen. If the parent is validated and extends from the tip, then we should
		// be able to build a UtxoView for it. This failure can only happen due to transient or badger issues.
		return nil, errors.Wrap(err, "validatePreviouslyIndexedBlockPoS: Problem getting UtxoView")
	}

	parentUtxoView := parentUtxoViewAndUtxoOps.UtxoView
	// If the block isn't validated or validate failed, we need to run the anti-spam checks on it.
	passedSpamPreventionCheck, err := bc.validateLeaderAndQC(block, parentUtxoView, verifySignatures)
	if err != nil {
		// If we hit an error, that means there was an intermittent issue when trying to
		// validate the QC or the leader.
		return nil, errors.Wrap(err, "validatePreviouslyIndexedBlockPoS: Problem validating leader and QC")
	}
	if !passedSpamPreventionCheck {
		// If the QC or Leader check failed, we'll never accept this block, but we've already stored it,
		// so we need to mark it as ValidateFailed.
		blockNode, err = bc.storeValidateFailedBlockInBlockIndex(block)
		if err != nil {
			return nil, errors.Wrap(err,
				"validatePreviouslyIndexedBlockPoS: Problem adding validate failed block to block index")
		}
		return blockNode, nil
	}

	// We run the full validation algorithm on the block.
	return bc.validateAndIndexBlockPoS(block, parentUtxoView, verifySignatures)
}

// isValidBlockPoS performs all basic block integrity checks. Any error
// resulting from this function implies that the block is invalid.
func (bc *Blockchain) isValidBlockPoS(block *MsgDeSoBlock) error {
	// Surface Level validation of the block
	if err := bc.isProperlyFormedBlockPoS(block); err != nil {
		return err
	}
	if err := bc.isBlockTimestampValidRelativeToParentPoS(block.Header); err != nil {
		return err
	}
	// Validate block height
	if err := bc.hasValidBlockHeightPoS(block.Header); err != nil {
		return err
	}
	// Validate view
	if err := bc.hasValidBlockViewPoS(block.Header); err != nil {
		return err
	}
	return nil
}

// isValidBlockHeaderPoS performs all basic block header integrity checks. Any
// error resulting from this function implies that the block header is invalid.
func (bc *Blockchain) isValidBlockHeaderPoS(header *MsgDeSoHeader) error {
	// Surface Level validation of the block header
	if err := bc.isProperlyFormedBlockHeaderPoS(header); err != nil {
		return err
	}
	if err := bc.isBlockTimestampValidRelativeToParentPoS(header); err != nil {
		return err
	}
	// Validate block height
	if err := bc.hasValidBlockHeightPoS(header); err != nil {
		return err
	}
	// Validate view
	if err := bc.hasValidBlockViewPoS(header); err != nil {
		return err
	}
	return nil
}

// isBlockTimestampValidRelativeToParentPoS validates that the block's timestamp is
// greater than its parent's timestamp.
func (bc *Blockchain) isBlockTimestampValidRelativeToParentPoS(header *MsgDeSoHeader) error {
	// Validate that the timestamp is not less than its parent.
	parentBlockNode, exists := bc.blockIndex.GetBlockNodeByHashAndHeight(header.PrevBlockHash, header.Height-1)
	if !exists {
		// Note: this should never happen as we only call this function after
		// we've validated that all ancestors exist in the block index.
		return RuleErrorMissingParentBlock
	}
	if header.TstampNanoSecs < parentBlockNode.Header.TstampNanoSecs {
		return RuleErrorPoSBlockTstampNanoSecsTooOld
	}
	return nil
}

// isBlockTimestampTooFarInFuturePoS validates that the block's timestamp is not too far in the future based
// on the configured block timestamp drift.
//
// We use the snapshotted global params to validate that the block's timestamp isn't too far ahead in the
// future. We use the snapshotted global params specifically so that the drift timestamp check behaves
// consistently even for orphan blocks that are 1 epoch in the future..
func (bc *Blockchain) isBlockTimestampTooFarInFuturePoS(header *MsgDeSoHeader) (bool, error) {
	// If the block's timestamp is lower than the current time, then there's no reason to check for
	// timestamp drift. The check is guaranteed to pass.
	currentTstampNanoSecs := time.Now().UnixNano()
	if header.TstampNanoSecs <= currentTstampNanoSecs {
		return false, nil
	}

	// We use GetCommittedTipView here, which generates a UtxoView at the current committed tip. We can use the view
	// to fetch the snapshot global params for the previous epoch, current epoch, and next epoch. As long as
	// the block's height is within 3600 blocks of the committed tip, this will always work. In practice,
	// the incoming block never be more than 3600 blocks behind or ahead of the tip, while also failing the
	// above header.TstampNanoSecs <= currentTstampNanoSecs check.
	utxoView := bc.GetCommittedTipView()

	simulatedEpochEntryForBlock, err := utxoView.SimulateAdjacentEpochEntryForBlockHeight(header.Height)
	if err != nil {
		return false, errors.Wrapf(err, "isBlockTimestampTooFarInFuturePoS: Problem simulating epoch entry")
	}

	snapshotEpochNumber, err := utxoView.ComputeSnapshotEpochNumberForEpoch(simulatedEpochEntryForBlock.EpochNumber)
	if err != nil {
		return false, errors.Wrapf(err, "isBlockTimestampTooFarInFuturePoS: Problem getting snapshot epoch number for epoch #%d",
			simulatedEpochEntryForBlock.EpochNumber)
	}

	snapshotGlobalParams, err := utxoView.GetSnapshotGlobalParamsEntryByEpochNumber(snapshotEpochNumber)
	if err != nil {
		return false, errors.Wrapf(err, "isBlockTimestampTooFarInFuturePoS: Problem getting snapshot global params")
	}

	return header.TstampNanoSecs > time.Now().UnixNano()+snapshotGlobalParams.BlockTimestampDriftNanoSecs, nil
}

// isProperlyFormedBlockPoS validates the block at a surface level and makes
// sure that all fields are populated in a valid manner. It does not verify
// signatures nor validate the blockchain state resulting from the block.
func (bc *Blockchain) isProperlyFormedBlockPoS(block *MsgDeSoBlock) error {
	// First, make sure we have a non-nil block
	if block == nil {
		return RuleErrorNilBlock
	}

	// Make sure the header is properly formed by itself
	if err := bc.isProperlyFormedBlockHeaderPoS(block.Header); err != nil {
		return err
	}

	// If the header is properly formed, we can check the rest of the block.

	// All blocks must have at least one txn
	if len(block.Txns) == 0 {
		return RuleErrorBlockWithNoTxns
	}

	// Make sure that the first txn in each block is a block reward txn.
	if block.Txns[0].TxnMeta.GetTxnType() != TxnTypeBlockReward {
		return RuleErrorBlockDoesNotStartWithRewardTxn
	}

	// We always need to check the merkle root.
	if block.Header.TransactionMerkleRoot == nil {
		return RuleErrorNilMerkleRoot
	}
	computedMerkleRoot, _, err := ComputeMerkleRoot(block.Txns)
	if err != nil {
		return errors.Wrapf(err, "isProperlyFormedBlockPoS: Problem computing merkle root")
	}
	if !block.Header.TransactionMerkleRoot.IsEqual(computedMerkleRoot) {
		return RuleErrorInvalidMerkleRoot
	}

	return nil
}

// isProperlyFormedBlockHeaderPoS validates the block header based on the header's
// contents alone, and makes sure that all fields are populated in a valid manner.
// It does not verify signatures in the header, nor cross-validate the block with
// past blocks in the block index.
func (bc *Blockchain) isProperlyFormedBlockHeaderPoS(header *MsgDeSoHeader) error {
	// First make sure we have a non-nil header
	if header == nil {
		return RuleErrorNilBlockHeader
	}

	// Make sure we have a prevBlockHash
	if header.PrevBlockHash == nil {
		return RuleErrorNilPrevBlockHash
	}

	// Header validation
	if header.Version != HeaderVersion2 {
		return RuleErrorInvalidPoSBlockHeaderVersion
	}

	// Require header to have either vote or timeout QC
	isTimeoutQCEmpty := header.ValidatorsTimeoutAggregateQC.isEmpty()
	isVoteQCEmpty := header.ValidatorsVoteQC.isEmpty()
	if isTimeoutQCEmpty && isVoteQCEmpty {
		return RuleErrorNoTimeoutOrVoteQC
	}

	if !isTimeoutQCEmpty && !isVoteQCEmpty {
		return RuleErrorBothTimeoutAndVoteQC
	}

	if header.ProposerVotingPublicKey.IsEmpty() {
		return RuleErrorInvalidProposerVotingPublicKey
	}

	if header.ProposerRandomSeedSignature.IsEmpty() {
		return RuleErrorInvalidProposerRandomSeedSignature
	}

	if header.TransactionMerkleRoot == nil {
		return RuleErrorNilMerkleRoot
	}

	// If a block has a vote QC, then the Header's proposed in view must be exactly one
	// greater than the QC's proposed in view.
	if !isVoteQCEmpty && header.ProposedInView != header.ValidatorsVoteQC.ProposedInView+1 {
		return RuleErrorPoSVoteBlockViewNotOneGreaterThanValidatorsVoteQCView
	}

	// If a block has a timeout QC, then the Header's proposed in view be must exactly one
	// greater than the QC's timed out view.
	if !isTimeoutQCEmpty && header.ProposedInView != header.ValidatorsTimeoutAggregateQC.TimedOutView+1 {
		return RuleErrorPoSTimeoutBlockViewNotOneGreaterThanValidatorsTimeoutQCView
	}

	return nil
}

// hasValidBlockHeightPoS validates the block height for a given block header. First,
// it checks that we've passed the PoS cutover fork height. Then it checks
// that this block height is exactly one greater than its parent's block height.
func (bc *Blockchain) hasValidBlockHeightPoS(header *MsgDeSoHeader) error {
	blockHeight := header.Height
	if !bc.params.IsPoSBlockHeight(blockHeight) {
		return RuleErrorPoSBlockBeforeCutoverHeight
	}
	// Validate that the block height is exactly one greater than its parent.
	parentBlockNode, exists := bc.blockIndex.GetBlockNodeByHashAndHeight(header.PrevBlockHash, header.Height-1)
	if !exists {
		// Note: this should never happen as we only call this function after
		// we've validated that all ancestors exist in the block index.
		return RuleErrorMissingParentBlock
	}
	if header.Height != parentBlockNode.Header.Height+1 {
		return RuleErrorInvalidPoSBlockHeight
	}
	return nil
}

// hasValidBlockViewPoS validates the view for a given block header
func (bc *Blockchain) hasValidBlockViewPoS(header *MsgDeSoHeader) error {
	// Validate that the view is greater than the latest uncommitted block.
	parentBlockNode, exists := bc.blockIndex.GetBlockNodeByHashAndHeight(header.PrevBlockHash, header.Height-1)
	if !exists {
		// Note: this should never happen as we only call this function after
		// we've validated that all ancestors exist in the block index.
		return RuleErrorMissingParentBlock
	}
	// If the parent block was a PoW block, we can't validate this block's view
	// in comparison.
	if !blockNodeProofOfStakeCutoverMigrationTriggered(parentBlockNode.Height) {
		return nil
	}
	// If our current block has a vote QC, then we need to validate that the
	// view is exactly one greater than the latest uncommitted block.
	if header.ValidatorsTimeoutAggregateQC.isEmpty() {
		if header.ProposedInView != parentBlockNode.Header.ProposedInView+1 {
			return RuleErrorPoSVoteBlockViewNotOneGreaterThanParent
		}
	} else {
		// If our current block has a timeout QC, then we need to validate that the
		// view is strictly greater than the latest uncommitted block's view.
		if header.ProposedInView <= parentBlockNode.Header.ProposedInView {
			return RuleErrorPoSTimeoutBlockViewNotGreaterThanParent
		}
	}
	return nil
}

func (bc *Blockchain) hasValidProposerRandomSeedSignaturePoS(header *MsgDeSoHeader) (bool, error) {
	// Validate that the leader proposed a valid random seed signature.
	parentBlock, exists := bc.blockIndex.GetBlockNodeByHashAndHeight(header.PrevBlockHash, header.Height-1)
	if !exists {
		// Note: this should never happen as we only call this function after
		// we've validated that all ancestors exist in the block index.
		return false, RuleErrorMissingParentBlock
	}

	prevRandomSeedHash, err := HashRandomSeedSignature(parentBlock.Header.ProposerRandomSeedSignature)
	if err != nil {
		return false, errors.Wrapf(err,
			"hasValidProposerRandomSeedSignaturePoS: Problem converting prev random seed hash to RandomSeedHash")
	}
	isVerified, err := verifySignatureOnRandomSeedHash(
		header.ProposerVotingPublicKey, header.ProposerRandomSeedSignature, prevRandomSeedHash)
	if err != nil {
		return false, errors.Wrapf(err,
			"hasValidProposerRandomSeedSignaturePoS: Problem verifying proposer random seed signature")
	}
	return isVerified, nil
}

func (bav *UtxoView) hasValidProposerPartialSignaturePoS(block *MsgDeSoBlock, snapshotAtEpochNumber uint64) (
	bool, error) {
	votingPublicKey := block.Header.ProposerVotingPublicKey
	proposerPartialSig := block.Header.ProposerVotePartialSignature
	// If the proposer partial sig is nil, we can't validate it. That's an error.
	if proposerPartialSig.IsEmpty() {
		return false, nil
	}
	// Get the snapshot validator entry for the proposer.
	snapshotBlockProposerValidatorEntry, err := bav.GetSnapshotValidatorEntryByBLSPublicKey(
		votingPublicKey, snapshotAtEpochNumber)
	if err != nil {
		return false, errors.Wrapf(err, "hasValidProposerPartialSignaturePoS: Problem getting snapshot validator entry")
	}

	// If the snapshot validator entry is nil or deleted, we didn't snapshot
	// the validator at this epoch, so we will never accept this block.
	if snapshotBlockProposerValidatorEntry == nil || snapshotBlockProposerValidatorEntry.isDeleted {
		return false, nil
	}
	// If the voting public key from the block's header doesn't match the
	// snapshotted voting public key, we will never accept this block.
	if !snapshotBlockProposerValidatorEntry.VotingPublicKey.Eq(votingPublicKey) {
		return false, nil
	}
	// Get the block's hash
	blockHash, err := block.Header.Hash()
	if err != nil {
		return false, errors.Wrapf(err, "hasValidProposerPartialSignaturePoS: Problem hashing block")
	}
	// Now that we have the snapshot validator entry and validated that the
	// voting public key from this block's header matches the snapshotted
	// voting public key, we can validate the partial sig.
	votePayload := consensus.GetVoteSignaturePayload(block.Header.ProposedInView, blockHash)
	isVerified, err := votingPublicKey.Verify(proposerPartialSig, votePayload[:])
	if err != nil {
		return false, errors.Wrapf(err, "hasValidProposerPartialSignaturePoS: Problem verifying partial sig")
	}
	return isVerified, nil
}

// hasValidBlockProposerPoS validates that the proposer is the expected proposer for the
// block height + view number pair. It returns a bool indicating whether
// we confirmed that the leader is valid. If we receive an error, we are unsure
// if the leader is invalid or not, so we return false.
func (bav *UtxoView) hasValidBlockProposerPoS(block *MsgDeSoBlock) (_isValidBlockProposer bool, _err error) {
	currentEpochEntry, err := bav.GetCurrentEpochEntry()
	if err != nil {
		return false, errors.Wrapf(err, "hasValidBlockProposerPoS: Problem getting current epoch entry")
	}
	leaders, err := bav.GetCurrentSnapshotLeaderSchedule()
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
	// - [currentEpoch.InitialLeaderIndexOffset + (block.View - currentEpoch.InitialView) - (block.Height - currentEpoch.InitialHeight)] % len(leaders)
	// - The pseudo-random offset for the leader schedule is currentEpoch.InitialLeaderIndexOffset.
	// - The number of views that have elapsed since the start of the epoch is block.View - currentEpoch.InitialView.
	// - The number of blocks that have been added to the chain since the start of the epoch is block.Height - currentEpoch.InitialHeight.
	// - The difference between the above two numbers is the number of timeouts that have occurred in this epoch.
	//
	// For each timeout, we skip one leader in the in the schedule. If we have more timeouts than leaders in
	// the schedule, we start from the top of the schedule again, which is why we take the modulo of the length
	// of the leader schedule.
	//
	// A quick example:
	// - Say we have 3 leaders in the schedule
	// - The initial leader index offset is 3
	// - The epoch started at height 10 and view 11
	// - The current block is at height 15 and view 17
	// - Then the number of timeouts that have occurred is 3 + (17 - 11) - (15 - 10) = 4.
	// - The leader index is 4 % 3 = 1.
	// - This means this block should be proposed by the 2nd leader in the schedule, which is at index 1.
	leaderIdxUint64 := (currentEpochEntry.InitialLeaderIndexOffset + viewDiff - heightDiff) % uint64(len(leaders))
	if leaderIdxUint64 > math.MaxUint16 {
		return false, nil
	}
	leaderIdx := uint16(leaderIdxUint64)
	leaderEntry, err := bav.GetSnapshotLeaderScheduleValidator(leaderIdx)
	if err != nil {
		return false, errors.Wrapf(err, "hasValidBlockProposerPoS: Problem getting leader schedule validator")
	}
	snapshotAtEpochNumber, err := bav.ComputeSnapshotEpochNumberForEpoch(currentEpochEntry.EpochNumber)
	if err != nil {
		return false, errors.Wrapf(err,
			"hasValidBlockProposerPoS: Problem getting snapshot epoch number for epoch #%d",
			currentEpochEntry.EpochNumber)
	}
	leaderEntryFromVotingPublicKey, err := bav.GetSnapshotValidatorEntryByBLSPublicKey(
		block.Header.ProposerVotingPublicKey,
		snapshotAtEpochNumber)
	if err != nil {
		return false, errors.Wrapf(err, "hasValidBlockProposerPoS: Problem getting leader validator entry")
	}
	// If no leader is found from the voting public key, we'll never accept this block.
	if leaderEntryFromVotingPublicKey == nil {
		return false, nil
	}

	// Dump some debug info on the current block's proposer and the current view's leader.
	glog.V(2).Infof(
		"hasValidBlockProposerPoS: Printing block proposer debug info: "+
			"\n  Epoch Num: %d, Block View: %d, Block Height: %d, Epoch Initial View: %d, Epoch Initial Block Height: %d, Epoch Initial Leader Index Offset: %d"+
			"\n  Leader Idx: %d, Num Leaders: %d"+
			"\n  Expected Leader PKID: %v, Expected Leader Voting PK: %v"+
			"\n  Expected Leader PKID from BLS Key Lookup: %v, Expected Leader Voting PK from BLS Key Lookup: %v"+
			"\n  Block Proposer Voting PK: %v",
		currentEpochEntry.EpochNumber,
		block.Header.ProposedInView,
		block.Header.Height,
		currentEpochEntry.InitialView,
		currentEpochEntry.InitialBlockHeight,
		currentEpochEntry.InitialLeaderIndexOffset,
		leaderIdx,
		len(leaders),
		PkToString(leaderEntry.ValidatorPKID.ToBytes(), bav.Params),
		leaderEntry.VotingPublicKey.ToAbbreviatedString(),
		PkToString(leaderEntryFromVotingPublicKey.ValidatorPKID.ToBytes(), bav.Params),
		leaderEntryFromVotingPublicKey.VotingPublicKey.ToAbbreviatedString(),
		block.Header.ProposerVotingPublicKey.ToAbbreviatedString(),
	)

	if !leaderEntry.VotingPublicKey.Eq(block.Header.ProposerVotingPublicKey) ||
		!leaderEntry.ValidatorPKID.Eq(leaderEntryFromVotingPublicKey.ValidatorPKID) {
		return false, nil
	}
	return true, nil
}

// isValidPoSQuorumCertificate validates that the QC of this block is valid, meaning a super majority
// of the validator set has voted (or timed out). It special cases the first block after the PoS cutover
// by overriding the validator set used to validate the high QC in the first block after the PoS cutover.
func (bc *Blockchain) isValidPoSQuorumCertificate(block *MsgDeSoBlock, validatorSet []*ValidatorEntry) error {
	highQCValidators := toConsensusValidators(validatorSet)
	aggregateQCValidators := highQCValidators

	voteQC := block.Header.ValidatorsVoteQC
	timeoutAggregateQC := block.Header.ValidatorsTimeoutAggregateQC

	// If the block is the first block after the PoS cutover and has a timeout aggregate QC, then the
	// highQC must be a synthetic QC. We need to override the validator set used to validate the high QC.
	if block.Header.Height == bc.params.GetFirstPoSBlockHeight() && !timeoutAggregateQC.isEmpty() {
		genesisQC, err := bc.GetProofOfStakeGenesisQuorumCertificate()
		if err != nil {
			return errors.Wrapf(err, "isValidPoSQuorumCertificate: Problem getting PoS genesis QC")
		}

		// Only override the validator set if the high QC is the genesis QC. Otherwise, we should use the
		// true validator set at the current epoch.
		if consensus.IsEqualQC(genesisQC, timeoutAggregateQC.GetHighQC()) {
			posCutoverValidator, err := BuildProofOfStakeCutoverValidator()
			if err != nil {
				return errors.Wrapf(err, "isValidPoSQuorumCertificate: Problem building PoS cutover validator")
			}
			highQCValidators = []consensus.Validator{posCutoverValidator}
		}
	}

	// Validate the timeout aggregate QC.
	if !timeoutAggregateQC.isEmpty() {
		if !consensus.IsValidSuperMajorityAggregateQuorumCertificate(timeoutAggregateQC, aggregateQCValidators, highQCValidators) {
			return RuleErrorInvalidTimeoutQC
		}
		return nil
	}

	// Validate the vote QC.
	if !consensus.IsValidSuperMajorityQuorumCertificate(voteQC, highQCValidators) {
		return RuleErrorInvalidVoteQC
	}

	return nil
}

// getStoredLineageFromCommittedTip returns the ancestors of the block provided up to, but not
// including the committed tip. The first block in the returned slice is the first uncommitted
// ancestor. if a valid lineage is returned, it means that we have all of the blocks in the
// lineage stored and that we are able to build the state of the chain up to the parent of the
// given header.
func (bc *Blockchain) getStoredLineageFromCommittedTip(header *MsgDeSoHeader) (
	_lineageFromCommittedTip []*BlockNode,
	_missingBlockHashes []*BlockHash,
	_err error,
) {
	highestCommittedBlock, idx := bc.GetCommittedTip()
	if idx == -1 || highestCommittedBlock == nil {
		return nil, nil, errors.New("getStoredLineageFromCommittedTip: No committed blocks found")
	}
	currentHash := header.PrevBlockHash.NewBlockHash()
	currentHeight := header.Height - 1
	ancestors := []*BlockNode{}
	prevHeight := header.Height
	prevView := header.GetView()
	for {
		// TODO: is currentHeight correct here?
		currentBlock, exists := bc.blockIndex.GetBlockNodeByHashAndHeight(currentHash, currentHeight)
		if !exists {
			return nil, []*BlockHash{currentHash}, RuleErrorMissingAncestorBlock
		}
		if currentBlock.Hash.IsEqual(highestCommittedBlock.Hash) {
			break
		}
		if currentBlock.IsCommitted() {
			return nil, nil, RuleErrorDoesNotExtendCommittedTip
		}
		if currentBlock.IsValidateFailed() {
			return nil, nil, RuleErrorAncestorBlockValidationFailed
		}
		if uint64(currentBlock.Header.Height)+1 != prevHeight {
			return nil, nil, RuleErrorParentBlockHeightNotSequentialWithChildBlockHeight
		}
		if currentBlock.Header.GetView() >= prevView {
			return nil, nil, RuleErrorParentBlockHasViewGreaterOrEqualToChildBlock
		}

		// If the current block is not marked as ValidateFailed but is also not Stored, it
		// means we have never seen the block before. We have it in the block index because
		// we previously saw its header. We need to request the block again from a peer and
		// consider it to be missing.
		if !currentBlock.IsStored() {
			return nil, []*BlockHash{currentHash}, RuleErrorMissingAncestorBlock
		}

		ancestors = append(ancestors, currentBlock)
		currentHash = currentBlock.Header.PrevBlockHash
		prevHeight = currentBlock.Header.Height
		prevView = currentBlock.Header.GetView()
	}
	return collections.Reverse(ancestors), nil, nil
}

// getOrCreateBlockNodeFromBlockIndex returns the block node from the block index if it exists.
// Otherwise, it creates a new block node and adds it to the blockIndexByHash and blockIndexByHeight.
func (bc *Blockchain) getOrCreateBlockNodeFromBlockIndex(block *MsgDeSoBlock) (*BlockNode, error) {
	hash, err := block.Header.Hash()
	if err != nil {
		return nil, errors.Wrapf(err, "getOrCreateBlockNodeFromBlockIndex: Problem hashing block %v", block)
	}
	blockNode, _ := bc.blockIndex.GetBlockNodeByHashAndHeight(hash, block.Header.Height)
	prevBlockNode, _ := bc.blockIndex.GetBlockNodeByHashAndHeight(block.Header.PrevBlockHash, block.Header.Height-1)
	if blockNode != nil {
		// If the block node already exists, we should set its parent if it doesn't have one already.
		if blockNode.Parent == nil {
			blockNode.Parent = prevBlockNode
		}
		return blockNode, nil
	}
	newBlockNode := NewBlockNode(prevBlockNode, hash, uint32(block.Header.Height), nil, nil, block.Header, StatusNone)
	bc.addNewBlockNodeToBlockIndex(newBlockNode)
	return newBlockNode, nil
}

// storeBlockInBlockIndex upserts the blocks into the in-memory block index & badger and updates its status to
// StatusBlockStored. It also writes the block to the block index in badger
func (bc *Blockchain) storeValidatedHeaderInBlockIndex(header *MsgDeSoHeader) (*BlockNode, error) {
	blockNode, err := bc.getOrCreateBlockNodeFromBlockIndex(&MsgDeSoBlock{Header: header})
	if err != nil {
		return nil, errors.Wrapf(err, "storeValidatedHeaderInBlockIndex: Problem getting or creating block node")
	}
	// If the block is validated, then this is a no-op.
	if blockNode.IsHeaderValidated() {
		return blockNode, nil
	}
	// We should throw an error if the BlockNode has failed header validation
	if blockNode.IsHeaderValidateFailed() {
		return nil, errors.New(
			"storeValidatedHeaderInBlockIndex: can't set block node to header validated after it's already been set to validate failed",
		)
	}
	blockNode.Status |= StatusHeaderValidated
	return blockNode, nil
}

func (bc *Blockchain) storeValidateFailedHeaderInBlockIndexWithWrapperError(header *MsgDeSoHeader, wrapperError error) error {
	if _, innerErr := bc.storeValidateFailedHeaderInBlockIndex(header); innerErr != nil {
		return errors.Wrapf(innerErr, "%v", wrapperError)
	}
	return wrapperError
}

// storeValidateFailedHeaderInBlockIndex stores the header in the block index only and sets its status to
// StatusHeaderValidateFailed. It does not write the header to the DB.
func (bc *Blockchain) storeValidateFailedHeaderInBlockIndex(header *MsgDeSoHeader) (*BlockNode, error) {
	blockNode, err := bc.getOrCreateBlockNodeFromBlockIndex(&MsgDeSoBlock{Header: header})
	if err != nil {
		return nil, errors.Wrapf(err, "storeValidateFailedHeaderInBlockIndex: Problem getting or creating block node")
	}
	// If the block has the header validate failed status, then this is a no-op.
	if blockNode.IsHeaderValidateFailed() {
		return blockNode, nil
	}
	// We should throw an error if the BlockNode has already been validated.
	if blockNode.IsHeaderValidated() {
		return nil, errors.New(
			"storeValidatedHeaderInBlockIndex: can't set block node to header validate failed after it's already been set to validated",
		)
	}
	blockNode.Status |= StatusHeaderValidateFailed
	return blockNode, nil
}

// storeBlockInBlockIndex upserts the blocks into the in-memory block index & badger and updates its status to
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

// storeValidatedBlockInBlockIndex upserts the blocks into the in-memory block index & badger and updates its
// status to StatusBlockValidated. If it does not have the status StatusBlockStored already, we add that as we
// will store the block in the DB after updating its status.  It also writes the block to the block index in
// badger by calling upsertBlockAndBlockNodeToDB.
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
	// If the BlockNode is not already processed, we should set its status to processed.
	// This ensures that bc.IsFullyStored will return true for this block.
	if !blockNode.IsProcessed() {
		blockNode.Status |= StatusBlockProcessed
	}
	// If the DB update fails, then we should return an error.
	if err = bc.upsertBlockAndBlockNodeToDB(block, blockNode, true); err != nil {
		return nil, errors.Wrapf(err, "storeValidatedBlockInBlockIndex: Problem upserting block and block node to DB")
	}
	return blockNode, nil
}

// storeValidateFailedBlockInBlockIndex upserts the blocks into the in-memory block index & badger and updates its
// status to StatusBlockValidateFailed. If it does not have the status StatusBlockStored already, we add that as we
// will store the block in the DB after updating its status.  It also writes the block to the block index in badger
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
		return nil, errors.New(
			"storeValidateFailedBlockInBlockIndex: can't set BlockNode to validate failed after it's already validated")
	}
	blockNode.Status |= StatusBlockValidateFailed
	// If the BlockNode is not already stored, we should set it to stored.
	if !blockNode.IsStored() {
		blockNode.Status |= StatusBlockStored
	}
	// If the DB update fails, then we should return an error.
	if err = bc.upsertBlockAndBlockNodeToDB(block, blockNode, false); err != nil {
		return nil, errors.Wrapf(err,
			"storeValidateFailedBlockInBlockIndex: Problem upserting block and block node to DB")
	}
	return blockNode, nil
}

// upsertBlockAndBlockNodeToDB writes the BlockNode to the blockIndexByHash in badger and writes the full block
// to the db under the <blockHash> -> <serialized block> index.
func (bc *Blockchain) upsertBlockAndBlockNodeToDB(block *MsgDeSoBlock, blockNode *BlockNode, storeFullBlock bool,
) error {
	// Store the block in badger
	err := bc.db.Update(func(txn *badger.Txn) error {
		if storeFullBlock {
			if innerErr := PutBlockHashToBlockWithTxn(txn, bc.snapshot, block, bc.eventManager); innerErr != nil {
				return errors.Wrapf(innerErr, "upsertBlockAndBlockNodeToDB: Problem calling PutBlockHashToBlockWithTxn")
			}
		}

		// TODO: if storeFullBlock = false, then we should probably remove the block from the DB? This can
		// happen if we had a block stored in the DB but then determined that it would have failed validation.
		// We would need to evict the block from the DB in that case.

		// Store the new block's node in our node index in the db under the
		//   <height uin32, blockHash BlockHash> -> <node info>
		// index.
		if innerErr := bc.upsertBlockNodeToDBWithTxn(txn, blockNode); innerErr != nil {
			return errors.Wrapf(innerErr, "upsertBlockAndBlockNodeToDB: ")
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

// upsertBlockNodeToDB is a simpler wrapper that calls upsertBlockNodeToDBWithTxn with a new transaction.
func (bc *Blockchain) upsertBlockNodeToDB(blockNode *BlockNode) error {
	return bc.db.Update(func(txn *badger.Txn) error {
		return bc.upsertBlockNodeToDBWithTxn(txn, blockNode)
	})
}

// upsertBlockNodeToDBWithTxn writes the BlockNode to the blockIndexByHash in badger.
func (bc *Blockchain) upsertBlockNodeToDBWithTxn(txn *badger.Txn, blockNode *BlockNode) error {
	// Store the new block's node in our node index in the db under the
	//   <height uin32, blockHash BlockHash> -> <node info>
	// index.
	err := PutHeightHashToNodeInfoWithTxn(txn, bc.snapshot, blockNode, false /*bitcoinNodes*/, bc.eventManager)
	if err != nil {
		return errors.Wrapf(err,
			"upsertBlockNodeToDBWithTxn: Problem calling PutHeightHashToNodeInfo before validation")
	}

	return nil
}

// tryApplyNewTip attempts to apply the new tip to the best chain. It will do the following:
//  1. Check if we should perform a reorg. If so, it will handle the reorg. If reorging causes an error,
//     return false and error.
//  2. Check if the incoming block extends the chain tip after reorg. If not, return false and nil
//  3. If the incoming block extends the chain tip, we can apply it by calling addBlockToBestChain. Return true and nil.
func (bc *Blockchain) tryApplyNewTip(blockNode *BlockNode, currentView uint64, lineageFromCommittedTip []*BlockNode) (
	_appliedNewTip bool,
	_connectedBlockHashes []BlockHash,
	_disconnectedBlocksHashes []BlockHash,
	_err error,
) {

	// Check if the incoming block extends the chain tip. If so, we don't need to reorg
	// and can just add this block to the best chain.
	chainTip := bc.BlockTip()
	if chainTip.Hash.IsEqual(blockNode.Header.PrevBlockHash) {
		bc.addTipBlockToBestChain(blockNode)
		return true, []BlockHash{*blockNode.Hash}, nil, nil
	}
	// Check if we should perform a reorg here.
	// If we shouldn't reorg AND the incoming block doesn't extend the chain tip, we know that
	// the incoming block will not get applied as the new tip.
	if !bc.shouldReorg(blockNode, currentView) {
		return false, nil, nil, nil
	}

	// We need to track the hashes of the blocks that we connected and disconnected during the reorg.
	connectedBlockHashes := []BlockHash{}
	disconnectedBlockHashes := []BlockHash{}

	// We need to perform a reorg here. For simplicity, we remove all uncommitted blocks and then re-add them.
	for !bc.blockTip().IsCommitted() {
		disconnectedBlockNode := bc.removeTipBlockFromBestChain()
		disconnectedBlockHashes = append(disconnectedBlockHashes, *disconnectedBlockNode.Hash)
	}
	// Add the ancestors of the new tip to the best chain.
	for _, ancestor := range lineageFromCommittedTip {
		bc.addTipBlockToBestChain(ancestor)
		connectedBlockHashes = append(connectedBlockHashes, *ancestor.Hash)
	}
	// Add the new tip to the best chain.
	bc.addTipBlockToBestChain(blockNode)
	connectedBlockHashes = append(connectedBlockHashes, *blockNode.Hash)

	// We need to dedupe the added and removed block hashes because we may have removed a
	// block and added it back during the reorg.
	uniqueConnectedBlockHashes, uniqueDisconnectedBlockHashes := collections.RemoveDuplicates(
		connectedBlockHashes,
		disconnectedBlockHashes,
	)
	return true, uniqueConnectedBlockHashes, uniqueDisconnectedBlockHashes, nil
}

// shouldReorg determines if we should reorg to the block provided. We should reorg if
// this block is proposed in a view greater than or equal to the currentView. Other
// functions have validated that this block is not extending from a committed block
// that is not the latest committed block, so there is no need to validate that here.
func (bc *Blockchain) shouldReorg(blockNode *BlockNode, currentView uint64) bool {
	chainTip := bc.BlockTip()
	// If this block extends from the chain tip, there's no need to reorg.
	if chainTip.Hash.IsEqual(blockNode.Header.PrevBlockHash) {
		return false
	}
	// If the block is proposed in a view less than the current view, there's no need to reorg.
	return blockNode.Header.ProposedInView >= currentView
}

// addTipBlockToBestChain adds the block as the new tip of the best chain.
func (bc *Blockchain) addTipBlockToBestChain(blockNode *BlockNode) {
	bc.bestChain.PushNewTip(blockNode)
}

// removeTipBlockFromBestChain removes the current tip from the best chain. It
// naively removes the tip regardless of the tip's status (committed or not).
// This function is a general purpose helper function that bundles mutations to
// the bestChain slice and bestChainMap map.
func (bc *Blockchain) removeTipBlockFromBestChain() *BlockNode {
	// Remove the last block from the best chain.
	lastBlock := bc.bestChain.Chain[len(bc.bestChain.Chain)-1]
	bc.bestChain.ChainMap.Delete(*lastBlock.Hash)
	bc.bestChain.Chain = bc.bestChain.Chain[:len(bc.bestChain.Chain)-1]
	return lastBlock
}

// runCommitRuleOnBestChain commits the grandparent of the block if possible.
// Specifically, this updates the CommittedBlockStatus of its grandparent
// and flushes the view after connecting the grandparent block to the DB.
func (bc *Blockchain) runCommitRuleOnBestChain(verifySignatures bool) error {
	currentBlock := bc.BlockTip()
	// If we can commit the grandparent, commit it.
	// Otherwise, we can't commit it and return nil.
	blockToCommit, canCommit := bc.canCommitGrandparent(currentBlock)
	if !canCommit {
		return nil
	}
	// Find all uncommitted ancestors of block to commit
	_, idx := bc.GetCommittedTip()
	if idx == -1 {
		// This is an edge case we'll never hit in practice since all the PoW blocks
		// are committed.
		return errors.New("runCommitRuleOnBestChain: No committed blocks found")
	}
	uncommittedAncestors := []*BlockNode{}
	for ii := idx + 1; ii < len(bc.bestChain.Chain); ii++ {
		uncommittedAncestors = append(uncommittedAncestors, bc.bestChain.Chain[ii])
		if bc.bestChain.Chain[ii].Hash.IsEqual(blockToCommit) {
			break
		}
	}
	for ii := 0; ii < len(uncommittedAncestors); ii++ {
		if err := bc.commitBlockPoS(uncommittedAncestors[ii].Hash, uint64(uncommittedAncestors[ii].Height), verifySignatures); err != nil {
			return errors.Wrapf(err,
				"runCommitRuleOnBestChain: Problem committing block %v", uncommittedAncestors[ii].Hash.String())
		}
	}
	return nil
}

// canCommitGrandparent determines if the grandparent of the current block can be committed.
// The grandparent can be committed if there exists a direct parent-child relationship
// between the grandparent and parent of the new block, meaning the grandparent and parent
// are proposed in consecutive views, and the "parent" is an ancestor of the incoming block
// (not necessarily consecutive views). Additionally, the grandparent must not already be committed.
func (bc *Blockchain) canCommitGrandparent(currentBlock *BlockNode) (_grandparentBlockHash *BlockHash, _canCommit bool,
) {
	// TODO: Is it sufficient that the current block's header points to the parent
	// or does it need to have something to do with the QC?
	parent, exists := bc.bestChain.GetBlockByHashAndHeight(currentBlock.Header.PrevBlockHash, uint64(currentBlock.Height-1))
	if !exists {
		glog.Errorf("canCommitGrandparent: Parent block %v not found in best chain map", currentBlock.Header.PrevBlockHash.String())
		return nil, false
	}
	grandParent, exists := bc.bestChain.GetBlockByHashAndHeight(parent.Header.PrevBlockHash, uint64(parent.Height-1))
	if !exists {
		glog.Errorf("canCommitGrandparent: Grandparent block %v not found in best chain map", parent.Header.PrevBlockHash.String())
		return nil, false
	}
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
func (bc *Blockchain) commitBlockPoS(blockHash *BlockHash, blockHeight uint64, verifySignatures bool) error {
	// block must be in the best chain. we grab the block node from there.
	blockNode, exists := bc.bestChain.GetBlockByHashAndHeight(blockHash, blockHeight)
	if !exists {
		return errors.Errorf("commitBlockPoS: Block %v not found in best chain map", blockHash.String())
	}
	// TODO: Do we want other validation in here?
	if blockNode.IsCommitted() {
		// Can't commit a block that's already committed.
		return errors.Errorf("commitBlockPoS: Block %v is already committed", blockHash.String())
	}
	// Connect a view up to block we are committing.
	utxoViewAndUtxoOps, err := bc.getUtxoViewAndUtxoOpsAtBlockHash(*blockHash, uint64(blockNode.Height))
	if err != nil {
		return errors.Wrapf(err, "commitBlockPoS: Problem initializing UtxoView: ")
	}
	utxoView := utxoViewAndUtxoOps.UtxoView
	utxoOps := utxoViewAndUtxoOps.UtxoOps
	block := utxoViewAndUtxoOps.Block
	// Put the block in the db
	// Note: we're skipping postgres.
	blockNode.Status |= StatusBlockCommitted
	err = bc.db.Update(func(txn *badger.Txn) error {
		if bc.snapshot != nil {
			bc.snapshot.PrepareAncestralRecordsFlush()
			glog.V(2).Infof("commitBlockPoS: Preparing snapshot flush")
		}

		// We generally expect DBSetWithTxn to handle emitting state syncer operations
		// for all KVs. However, blocks are a special case as we insert them into the
		// DB to store them before they're committed. State syncer may delete blocks
		// based on the BlockNode status, so we explicitly emit a state syncer operation
		// for the full block even though we are not inserting it into the DB here.
		if bc.eventManager != nil {
			blockBytes, err := block.ToBytes(false)
			if err != nil {
				glog.Errorf("commitBlockPoS: Problem serializing block %v: %v", blockHash, err)
			} else {
				bc.eventManager.stateSyncerOperation(&StateSyncerOperationEvent{
					StateChangeEntry: &StateChangeEntry{
						OperationType: DbOperationTypeUpsert,
						KeyBytes:      BlockHashToBlockKey(blockHash),
						EncoderBytes:  blockBytes,
						IsReverted:    false,
					},
					FlushId:      uuid.Nil,
					IsMempoolTxn: false,
				})
			}
		}

		// Store the new block's node in our node index in the db under the
		//   <height uin32, blockHash BlockHash> -> <node info>
		// index.
		if innerErr := PutHeightHashToNodeInfoWithTxn(
			txn, bc.snapshot, blockNode, false /*bitcoinNodes*/, bc.eventManager); innerErr != nil {
			return errors.Wrapf(innerErr, "commitBlockPoS: Problem calling PutHeightHashToNodeInfo before validation")
		}

		// Set the best node hash to this one. Note the header chain should already
		// be fully aware of this block so we shouldn't update it here.
		if innerErr := PutBestHashWithTxn(
			txn, bc.snapshot, blockNode.Hash, ChainTypeDeSoBlock, bc.eventManager); innerErr != nil {
			return errors.Wrapf(innerErr, "commitBlockPoS: Problem calling PutBestHash after validation")
		}
		// Write the utxo operations for this block to the db, so we can have the
		// ability to roll it back in the future.
		if innerErr := PutUtxoOperationsForBlockWithTxn(
			txn, bc.snapshot, uint64(blockNode.Height), blockNode.Hash, utxoOps, bc.eventManager,
		); innerErr != nil {
			return errors.Wrapf(innerErr, "commitBlockPoS: Problem writing utxo operations to db on simple add to tip")
		}
		if innerErr := utxoView.FlushToDBWithoutAncestralRecordsFlushWithTxn(
			txn, uint64(blockNode.Height)); innerErr != nil {
			return errors.Wrapf(innerErr, "commitBlockPoS: Problem flushing UtxoView to db")
		}
		// We can exit early if we're not using a snapshot.
		if bc.snapshot == nil {
			return nil
		}
		if innerErr := bc.snapshot.FlushAncestralRecordsWithTxn(txn); innerErr != nil {
			return errors.Wrapf(innerErr, "commitBlockPoS: Problem flushing ancestral records")
		}
		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "commitBlockPoS: Problem putting block in db: ")
	}

	if bc.snapshot != nil {
		bc.snapshot.FinishProcessBlock(blockNode)
	}
	if bc.eventManager != nil {
		bc.eventManager.blockCommitted(&BlockEvent{
			Block:    block,
			UtxoView: utxoView,
			UtxoOps:  utxoOps,
		})
		// TODO: check w/ Z if this is right....
		// Signal the state syncer that we've flushed to the DB so state syncer
		// will pick up the latest changes after committing this block.
		if !bc.eventManager.isMempoolManager {
			bc.eventManager.stateSyncerFlushed(&StateSyncerFlushedEvent{
				FlushId:   uuid.Nil,
				Succeeded: true,
			})
		}
	}
	currentEpochNumber, err := utxoView.GetCurrentEpochNumber()
	if err != nil {
		return errors.Wrapf(err, "commitBlockPoS: Problem getting current epoch number")
	}
	snapshotEpochNumber, err := utxoView.GetCurrentSnapshotEpochNumber()
	if err != nil {
		return errors.Wrapf(err, "commitBlockPoS: Problem getting current snapshot epoch number")
	}
	bc.snapshotCache.LoadCacheAtSnapshotAtEpochNumber(
		snapshotEpochNumber, currentEpochNumber, bc.db, bc.snapshot, bc.params)
	// TODO: What else do we need to do in here?
	return nil
}

// GetUncommittedBlocks is a helper that the state syncer uses to fetch all uncommitted
// block nodes, so it can flush them just like we would with mempool transactions. It returns
// all uncommitted block nodes from the specified tip to the last uncommitted block.
func (bc *Blockchain) GetUncommittedBlocks(tipHash *BlockHash) ([]*BlockNode, error) {
	if tipHash == nil {
		tipHash = bc.BlockTip().Hash
	}
	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()
	tipBlock, exists, err := bc.bestChain.GetBlockByHash(tipHash)
	if err != nil {
		return nil, errors.Wrapf(err, "GetUncommittedBlocks: Problem getting block %v", tipHash.String())
	}
	if !exists {
		return nil, errors.Errorf("GetUncommittedBlocks: Block %v not found in best chain map", tipHash.String())
	}
	// If the tip block is committed, we can't get uncommitted blocks from it so we return an empty slice.
	if tipBlock.IsCommitted() {
		return []*BlockNode{}, nil
	}
	var uncommittedBlockNodes []*BlockNode
	currentBlock := tipBlock
	for !currentBlock.IsCommitted() {
		uncommittedBlockNodes = append(uncommittedBlockNodes, currentBlock)
		currentParentHash := currentBlock.Header.PrevBlockHash
		if currentParentHash == nil {
			return nil, errors.Errorf("GetUncommittedBlocks: Block %v has nil PrevBlockHash", currentBlock.Hash)
		}
		currentBlock, _ = bc.blockIndex.GetBlockNodeByHashAndHeight(currentParentHash, currentBlock.Header.Height-1)
		if currentBlock == nil {
			return nil, errors.Errorf("GetUncommittedBlocks: Block %v not found in block index", currentParentHash)
		}
	}
	return collections.Reverse(uncommittedBlockNodes), nil
}

// GetCommittedTipView builds a UtxoView to the committed tip.
func (bc *Blockchain) GetCommittedTipView() *UtxoView {
	return NewUtxoViewWithSnapshotCache(bc.db, bc.params, bc.postgres, bc.snapshot, nil, bc.snapshotCache)
}

// BlockViewAndUtxoOps is a struct that contains a UtxoView and the UtxoOperations
// and a block that were used to build the UtxoView. This struct is only
// used for Blockchain's blockViewCache, which is used to speed up repeated access
// to a utxo view at an uncommitted block. Simply having a utxo view was insufficient
// for all performance enhancements as the utxo operations are needed when committing
// a block and the block is needed for the state syncer.
type BlockViewAndUtxoOps struct {
	UtxoView *UtxoView
	UtxoOps  [][]*UtxoOperation
	Block    *MsgDeSoBlock
}

func (viewAndUtxoOps *BlockViewAndUtxoOps) Copy() *BlockViewAndUtxoOps {
	copiedView := viewAndUtxoOps.UtxoView.CopyUtxoView()
	return &BlockViewAndUtxoOps{
		UtxoView: copiedView,
		UtxoOps:  viewAndUtxoOps.UtxoOps,
		Block:    viewAndUtxoOps.Block,
	}
}

// GetUncommittedTipView builds a UtxoView to the uncommitted tip.
func (bc *Blockchain) GetUncommittedTipView() (*UtxoView, error) {
	// Connect the uncommitted blocks to the tip so that we can validate subsequent blocks
	blockTip := bc.BlockTip()
	blockViewAndUtxoOps, err := bc.getUtxoViewAndUtxoOpsAtBlockHash(*blockTip.Hash, uint64(blockTip.Height))
	if err != nil {
		return nil, errors.Wrapf(err, "GetUncommittedTipView: Problem getting UtxoView at block hash")
	}
	return blockViewAndUtxoOps.UtxoView, nil
}

func (bc *Blockchain) getCachedBlockViewAndUtxoOps(blockHash BlockHash) (*BlockViewAndUtxoOps, error, bool) {
	if viewAndUtxoOpsAtHashItem, exists := bc.blockViewCache.Lookup(blockHash); exists {
		viewAndUtxoOpsAtHash, ok := viewAndUtxoOpsAtHashItem.(*BlockViewAndUtxoOps)
		if !ok {
			glog.Errorf("getCachedBlockViewAndUtxoOps: Problem casting to BlockViewAndUtxoOps")
			return nil, fmt.Errorf("getCachedBlockViewAndUtxoOps: Problem casting to BlockViewAndUtxoOps"), false
		}
		return viewAndUtxoOpsAtHash, nil, true
	}
	return nil, nil, false
}

// getUtxoViewAndUtxoOpsAtBlockHash builds a UtxoView to the block provided and returns a BlockViewAndUtxoOps
// struct containing UtxoView, the UtxoOperations that resulted from connecting the block, and the full
// block (MsgDeSoBlock) for convenience that came from connecting the block. It does this by identifying
// all uncommitted ancestors of this block. Then it checks the block view cache to see if we have already
// computed this view. If not, connecting the uncommitted ancestor blocks and saving to the cache. The
// returned UtxoOps and FullBlock should NOT be modified.
func (bc *Blockchain) getUtxoViewAndUtxoOpsAtBlockHash(blockHash BlockHash, blockHeight uint64) (
	*BlockViewAndUtxoOps, error) {
	// Always fetch the lineage from the committed tip to the block provided first to
	// ensure that a valid UtxoView is returned.
	uncommittedAncestors := []*BlockNode{}
	currentBlock, _ := bc.blockIndex.GetBlockNodeByHashAndHeight(&blockHash, blockHeight)
	if currentBlock == nil {
		return nil, errors.Errorf("getUtxoViewAndUtxoOpsAtBlockHash: Block %v not found in block index", blockHash)
	}

	highestCommittedBlock, _ := bc.GetCommittedTip()
	if highestCommittedBlock == nil {
		return nil, errors.Errorf("getUtxoViewAndUtxoOpsAtBlockHash: No committed blocks found")
	}
	// If the provided block is committed, we need to make sure it's the committed tip.
	// Otherwise, we return an error.
	if currentBlock.IsCommitted() {
		if !highestCommittedBlock.Hash.IsEqual(&blockHash) {
			return nil, errors.Errorf(
				"getUtxoViewAndUtxoOpsAtBlockHash: Block %v is committed but not the committed tip", blockHash)
		}
	}
	for !currentBlock.IsCommitted() {
		uncommittedAncestors = append(uncommittedAncestors, currentBlock)
		currentParentHash := currentBlock.Header.PrevBlockHash
		if currentParentHash == nil {
			return nil, errors.Errorf("getUtxoViewAndUtxoOpsAtBlockHash: Block %v has nil PrevBlockHash", currentBlock.Hash)
		}
		currentBlock, _ = bc.blockIndex.GetBlockNodeByHashAndHeight(currentParentHash, currentBlock.Header.Height-1)
		if currentBlock == nil {
			return nil, errors.Errorf("getUtxoViewAndUtxoOpsAtBlockHash: Block %v not found in block index", currentParentHash)
		}
		if currentBlock.IsCommitted() && !currentBlock.Hash.IsEqual(highestCommittedBlock.Hash) {
			return nil, errors.Errorf(
				"getUtxoViewAndUtxoOpsAtBlockHash: extends from a committed block that isn't the committed tip")
		}
		if currentBlock.IsCommitted() && !currentBlock.Hash.IsEqual(highestCommittedBlock.Hash) {
			return nil, errors.Errorf(
				"getUtxoViewAndUtxoOpsAtBlockHash: extends from a committed block that isn't the committed tip")
		}
	}
	viewAndUtxoOpsAtHash, err, exists := bc.getCachedBlockViewAndUtxoOps(blockHash)
	if err != nil {
		return nil, errors.Wrapf(err, "getUtxoViewAndUtxoOpsAtBlockHash: Problem getting cached BlockViewAndUtxoOps")
	}
	if exists {
		viewAndUtxoOpsCopy := viewAndUtxoOpsAtHash.Copy()
		return viewAndUtxoOpsCopy, nil
	}
	// Connect the uncommitted blocks to the tip so that we can validate subsequent blocks
	utxoView := NewUtxoViewWithSnapshotCache(bc.db, bc.params, bc.postgres, bc.snapshot, bc.eventManager,
		bc.snapshotCache)
	// TODO: there's another performance enhancement we can make here. If we have a view in the
	// cache for one of the ancestors, we can skip fetching the block and connecting it by taking
	// a copy of it and replacing the existing view.
	var utxoOps [][]*UtxoOperation
	var fullBlock *MsgDeSoBlock
	for ii := len(uncommittedAncestors) - 1; ii >= 0; ii-- {
		// We need to get these blocks from badger
		fullBlock, err = GetBlock(uncommittedAncestors[ii].Hash, bc.db, bc.snapshot)
		if err != nil {
			return nil, errors.Wrapf(err,
				"GetUncommittedTipView: Error fetching Block %v not found in block index",
				uncommittedAncestors[ii].Hash.String())
		}
		txnHashes := collections.Transform(fullBlock.Txns, func(txn *MsgDeSoTxn) *BlockHash {
			return txn.Hash()
		})
		utxoOps, err = utxoView.ConnectBlock(fullBlock, txnHashes, false, nil, fullBlock.Header.Height)
		if err != nil {
			hash, _ := fullBlock.Hash()
			return nil, errors.Wrapf(err, "GetUncommittedTipView: Problem connecting block hash %v", hash.String())
		}
	}
	// Update the TipHash saved on the UtxoView to the blockHash provided.
	utxoView.TipHash = &blockHash
	// Save a copy of the UtxoView to the cache.
	copiedView := utxoView.CopyUtxoView()
	bc.blockViewCache.Add(blockHash, &BlockViewAndUtxoOps{
		UtxoView: copiedView,
		UtxoOps:  utxoOps,
		Block:    fullBlock,
	})
	return &BlockViewAndUtxoOps{
		UtxoView: utxoView,
		UtxoOps:  utxoOps,
		Block:    fullBlock,
	}, nil
}

// GetCommittedTip returns the highest committed block and its index in the best chain.
func (bc *Blockchain) GetCommittedTip() (*BlockNode, int) {
	for ii := len(bc.bestChain.Chain) - 1; ii >= 0; ii-- {
		if bc.bestChain.Chain[ii].IsCommitted() {
			return bc.bestChain.Chain[ii], ii
		}
	}
	return nil, -1
}

// GetSafeBlocks returns all headers of blocks from which the chain can safely extend.
// A safe block is defined as a block that has been validated and all of its
// ancestors have been validated and extending from this block would not
// change any committed blocks. This means we return the committed tip and
// all blocks from the committed tip that have been validated.
//
// This function is not thread-safe. The caller needs to hold the chain lock before
// calling this function.
func (bc *Blockchain) GetSafeBlocks() ([]*MsgDeSoHeader, error) {
	safeBlocks, err := bc.getSafeBlockNodes()
	if err != nil {
		return nil, errors.Wrapf(err, "GetSafeBlocks: Problem getting safe block nodes")
	}
	headers := []*MsgDeSoHeader{}
	for _, blockNode := range safeBlocks {
		headers = append(headers, blockNode.Header)
	}
	return headers, nil
}

func (bc *Blockchain) getSafeBlockNodes() ([]*BlockNode, error) {
	// First get committed tip.
	committedTip, idx := bc.GetCommittedTip()
	if idx == -1 || committedTip == nil {
		return nil, errors.New("getSafeBlockNodes: No committed blocks found")
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

func (bc *Blockchain) GetProofOfStakeGenesisQuorumCertificate() (*QuorumCertificate, error) {
	finalPoWBlock, err := bc.GetFinalCommittedPoWBlock()
	if err != nil {
		return nil, err
	}

	aggregatedSignature, signersList, err := BuildQuorumCertificateAsProofOfStakeCutoverValidator(finalPoWBlock.Header.Height, finalPoWBlock.Hash)
	if err != nil {
		return nil, err
	}

	qc := &QuorumCertificate{
		BlockHash:      finalPoWBlock.Hash,
		ProposedInView: finalPoWBlock.Header.GetView(),
		ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
			Signature:   aggregatedSignature,
			SignersList: signersList,
		},
	}

	return qc, nil
}

func (bc *Blockchain) GetFinalCommittedPoWBlock() (*BlockNode, error) {
	// Fetch the block node for the cutover block
	blockNodes := bc.blockIndex.GetBlockNodesByHeight(bc.params.GetFinalPoWBlockHeight())
	if len(blockNodes) == 0 {
		return nil, errors.Errorf("Error fetching cutover block nodes before height %d", bc.params.GetFinalPoWBlockHeight())
	}

	// Fetch the block node with the committed status
	for _, blockNode := range blockNodes {
		if blockNode.IsCommitted() {
			return blockNode, nil
		}
	}

	return nil, errors.Errorf("Error fetching committed cutover block node with height %d", bc.params.GetFinalPoWBlockHeight())
}

const (
	RuleErrorNilBlock                                           RuleError = "RuleErrorNilBlock"
	RuleErrorNilBlockHeader                                     RuleError = "RuleErrorNilBlockHeader"
	RuleErrorNilPrevBlockHash                                   RuleError = "RuleErrorNilPrevBlockHash"
	RuleErrorPoSBlockTstampNanoSecsTooOld                       RuleError = "RuleErrorPoSBlockTstampNanoSecsTooOld"
	RuleErrorPoSBlockTstampNanoSecsInFuture                     RuleError = "RuleErrorPoSBlockTstampNanoSecsInFuture"
	RuleErrorInvalidPoSBlockHeaderVersion                       RuleError = "RuleErrorInvalidPoSBlockHeaderVersion"
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
	RuleErrorFailedSpamPreventionsCheck                         RuleError = "RuleErrorFailedSpamPreventionsCheck"

	RuleErrorNilMerkleRoot                      RuleError = "RuleErrorNilMerkleRoot"
	RuleErrorInvalidMerkleRoot                  RuleError = "RuleErrorInvalidMerkleRoot"
	RuleErrorInvalidProposerVotingPublicKey     RuleError = "RuleErrorInvalidProposerVotingPublicKey"
	RuleErrorInvalidProposerRandomSeedSignature RuleError = "RuleErrorInvalidProposerRandomSeedSignature"

	RuleErrorInvalidPoSBlockHeight       RuleError = "RuleErrorInvalidPoSBlockHeight"
	RuleErrorPoSBlockBeforeCutoverHeight RuleError = "RuleErrorPoSBlockBeforeCutoverHeight"

	RuleErrorPoSVoteBlockViewNotOneGreaterThanParent                     RuleError = "RuleErrorPoSVoteBlockViewNotOneGreaterThanParent"
	RuleErrorPoSVoteBlockViewNotOneGreaterThanValidatorsVoteQCView       RuleError = "RuleErrorPoSVoteBlockViewNotOneGreaterThanValidatorsVoteQCView"
	RuleErrorPoSTimeoutBlockViewNotGreaterThanParent                     RuleError = "RuleErrorPoSTimeoutBlockViewNotGreaterThanParent"
	RuleErrorPoSTimeoutBlockViewNotOneGreaterThanValidatorsTimeoutQCView RuleError = "RuleErrorPoSTimeoutBlockViewNotOneGreaterThanValidatorsTimeoutQCView"

	RuleErrorInvalidVoteQC    RuleError = "RuleErrorInvalidVoteQC"
	RuleErrorInvalidTimeoutQC RuleError = "RuleErrorInvalidTimeoutQC"
)
