package lib

import (
	"testing"
	"time"

	chainlib "github.com/btcsuite/btcd/blockchain"
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/require"
)

const (
	_statusValidated    = StatusHeaderValidated | StatusBlockProcessed | StatusBlockStored | StatusBlockValidated
	_statusFailed       = StatusHeaderValidated | StatusBlockProcessed | StatusBlockStored | StatusBlockValidateFailed
	_statusHeaderOnly   = StatusHeaderValidated
	_uncommittedBacklog = 2
)

// _putTestBlockNode builds a block node that is a plausible child of the provided parent and
// persists it to the block index in badger. It deliberately writes straight to the DB rather than
// going through the block index cache, so that tests can assert on what was actually persisted.
func _putTestBlockNode(
	t *testing.T, db *badger.DB, parent *BlockNode, status BlockStatus) *BlockNode {

	height := parent.Height + 1
	hash := NewBlockHash(RandomBytes(32))
	// DifficultyTarget and CumWork are only serialized below the PoS cutover height, but the test
	// chain sits below it, so both have to be populated for the node to round-trip through badger.
	// The header is a version 1 header for the same reason. The sweep never reads either; they only
	// have to survive a round trip.
	blockNode := NewBlockNode(hash, height, parent.DifficultyTarget, parent.CumWork, &MsgDeSoHeader{
		Version:        HeaderVersion1,
		PrevBlockHash:  parent.Hash,
		TstampNanoSecs: time.Now().UnixNano(),
		Height:         uint64(height),
	}, status)
	require.NoError(t, PutHeightHashToNodeInfo(db, nil, blockNode, false /*bitcoinNodes*/, nil))
	return blockNode
}

// _readBlockNodeFromDB re-reads a block node straight out of badger, bypassing the block index's
// in-memory cache entirely. This is the only read that proves a status change was persisted.
func _readBlockNodeFromDB(t *testing.T, db *badger.DB, blockNode *BlockNode) *BlockNode {
	fromDB := GetHeightHashToNodeInfo(db, nil, blockNode.Height, blockNode.Hash, false /*bitcoinNodes*/)
	require.NotNil(t, fromDB, "expected block node at height %d to be in the DB", blockNode.Height)
	return fromDB
}

// _buildUncommittedBacklog reproduces the geometry of the incident this change exists for: a
// committed tip with a run of validated-but-uncommitted blocks above it, and a block that failed
// validation sitting past the end of that run rather than directly on top of the committed tip.
// It returns the validated backlog and the failed block at its far end.
func _buildUncommittedBacklog(
	t *testing.T, bc *Blockchain, db *badger.DB) (_backlog []*BlockNode, _failed *BlockNode) {

	committedTip, exists := bc.GetCommittedTip()
	require.True(t, exists, "test setup must leave a committed tip for the sweep to start from")
	require.True(t, committedTip.IsCommitted())

	// The block tip still equals the committed tip at this point, which is exactly the condition
	// that makes the block tip useless as a bound for the sweep. Assert it so that this test keeps
	// meaning what it is supposed to mean.
	blockTip := bc.blockIndex.GetTip()
	require.NotNil(t, blockTip)
	require.Equal(t, committedTip.Height, blockTip.Height,
		"the block tip must not yet reflect the uncommitted backlog")

	backlog := []*BlockNode{}
	parent := committedTip
	for i := 0; i < _uncommittedBacklog; i++ {
		parent = _putTestBlockNode(t, db, parent, _statusValidated)
		backlog = append(backlog, parent)
	}

	// The block that lost the race, at committedTip.Height + _uncommittedBacklog + 1. This is above
	// the block tip, which is the whole point.
	failed := _putTestBlockNode(t, db, parent, _statusFailed)
	require.Greater(t, failed.Height, blockTip.Height+1,
		"the failed block must sit past a naive block-tip-based bound")

	return backlog, failed
}

// TestForgetValidateFailedBlocks verifies the sweep against the real geometry: the failed block is
// several heights above the committed tip, past the end of a run of uncommitted validated blocks.
func TestForgetValidateFailedBlocks(t *testing.T) {
	bc, _, db := NewTestBlockchain(t)

	committedTip, exists := bc.GetCommittedTip()
	require.True(t, exists)
	committedTipStatusBefore := committedTip.Status

	backlog, failedNode := _buildUncommittedBacklog(t, bc, db)

	// A losing sibling alongside the first validated block in the backlog. Failed blocks can sit at
	// validated heights too, not only past the end of the run, so the sweep must catch these.
	failedSibling := _putTestBlockNode(t, db, committedTip, _statusFailed)
	require.Equal(t, backlog[0].Height, failedSibling.Height)

	// A stored-but-unvalidated sibling: a block we received but have not yet formed an opinion on.
	// It is neither validated nor failed, so the sweep must leave it exactly as it is — forgetting
	// it would be wrong (nothing to forget) and marking it would be worse.
	storedOnly := _putTestBlockNode(t, db, committedTip,
		StatusHeaderValidated|StatusBlockProcessed|StatusBlockStored)

	// The run of blocks poisoned by the rejection. validateAndIndexBlockPoS marks any block whose
	// parent is ValidateFailed as ValidateFailed too, so in production a single lost race leaves a
	// contiguous chain of rejected blocks at heights where nothing is validated. All of them have to
	// be forgotten, not just the first.
	poisoned := []*BlockNode{}
	parent := failedNode
	for i := 0; i < 4; i++ {
		parent = _putTestBlockNode(t, db, parent, _statusFailed)
		poisoned = append(poisoned, parent)
	}

	// Past the end of the poisoned run, a height holding only a header we have never had the block
	// for, and a failed block beyond it. The walk must stop at the header-only height. This is the
	// bound that keeps the sweep cheap on a blocksync node, where header-only nodes stretch millions
	// of blocks past the block tip.
	headerOnly := _putTestBlockNode(t, db, parent, _statusHeaderOnly)
	unreachable := _putTestBlockNode(t, db, headerOnly, _statusFailed)

	require.NoError(t, bc.forgetValidateFailedBlocks())

	// The failed block past the end of the backlog must be reset to header-only and persisted.
	forgotten := _readBlockNodeFromDB(t, db, failedNode)
	require.False(t, forgotten.IsValidateFailed(), "ValidateFailed must be cleared")
	require.False(t, forgotten.IsStored(), "must be un-Stored so GetBlockNodesToFetch re-requests it")
	require.False(t, forgotten.IsProcessed(), "must be un-Processed so it is validated again")
	require.False(t, forgotten.IsValidated())
	require.True(t, forgotten.IsHeaderValidated(), "header-level status must survive")
	require.Equal(t, BlockStatus(_statusHeaderOnly), forgotten.Status,
		"exactly the header bits and nothing else should remain")

	// The losing sibling at a validated height must be forgotten too.
	forgottenSibling := _readBlockNodeFromDB(t, db, failedSibling)
	require.Equal(t, BlockStatus(_statusHeaderOnly), forgottenSibling.Status)

	// The stored-but-unvalidated sibling must be untouched.
	require.Equal(t, storedOnly.Status, _readBlockNodeFromDB(t, db, storedOnly).Status,
		"a block we have no verdict on must not be modified")

	// Every validated block in the backlog must be untouched.
	for _, blockNode := range backlog {
		stillValidated := _readBlockNodeFromDB(t, db, blockNode)
		require.Equal(t, BlockStatus(_statusValidated), stillValidated.Status,
			"a validated block at height %d must not be modified", blockNode.Height)
	}

	// Every block poisoned by the rejection must be forgotten too, all the way down the run.
	for _, blockNode := range poisoned {
		forgottenDescendant := _readBlockNodeFromDB(t, db, blockNode)
		require.Equal(t, BlockStatus(_statusHeaderOnly), forgottenDescendant.Status,
			"a block rejected for building on a rejected block must be forgotten (height %d)",
			blockNode.Height)
	}

	// The walk must have stopped at the header-only height, leaving what is beyond it alone.
	require.Equal(t, BlockStatus(_statusHeaderOnly), _readBlockNodeFromDB(t, db, headerOnly).Status)
	require.True(t, _readBlockNodeFromDB(t, db, unreachable).IsValidateFailed(),
		"sweep must stop at the first height we neither validated nor rejected")

	// The committed tip must be untouched.
	committedTipAfter, exists := bc.GetCommittedTip()
	require.True(t, exists)
	require.Equal(t, committedTipStatusBefore, committedTipAfter.Status)
	require.True(t, committedTipAfter.IsCommitted())
}

// TestForgetValidateFailedBlocksAcrossRestart is the test that actually matters. It builds the
// backlog, then builds a brand new Blockchain over the same badger DB the way a process restart
// would, and asserts the marker is gone. Without the sweep wired into NewBlockchain, or without
// persisting the cleared status, or with a bound that cannot see past the committed tip, this fails.
func TestForgetValidateFailedBlocksAcrossRestart(t *testing.T) {
	bc, params, db := NewTestBlockchain(t)

	_, failedNode := _buildUncommittedBacklog(t, bc, db)

	// Sanity check that the marker really is on disk before the restart, so that a green test
	// cannot be an artifact of the marker never having been written in the first place.
	before := _readBlockNodeFromDB(t, db, failedNode)
	require.True(t, before.IsValidateFailed(), "marker must be persisted before the restart")
	require.True(t, before.IsStored())

	// A hypothetical child of the failed block, used to probe what the retry machinery would do
	// with it. Before the restart the failed ancestor poisons the lineage outright.
	childHeader := &MsgDeSoHeader{
		Version:       HeaderVersion1,
		PrevBlockHash: failedNode.Hash,
		Height:        uint64(failedNode.Height) + 1,
	}
	_, _, lineageErr := bc.getStoredLineageFromCommittedTip(childHeader)
	require.Equal(t, RuleErrorAncestorBlockValidationFailed, lineageErr,
		"before the restart, a descendant of the failed block must be rejected outright")

	// Restart: a fresh Blockchain over the same DB, exactly as NewTestBlockchain builds one.
	restarted, err := NewBlockchain([]string{blockSignerPk}, 0, 0, params,
		chainlib.NewMedianTime(), db, nil, nil, nil, false, nil, MinBlockIndexSize)
	require.NoError(t, err)
	require.NotNil(t, restarted)

	after := _readBlockNodeFromDB(t, db, failedNode)
	require.False(t, after.IsValidateFailed(), "restart must forget the failed validation")
	require.False(t, after.IsStored(), "restart must leave the block ready to be re-fetched")
	require.Equal(t, BlockStatus(_statusHeaderOnly), after.Status)

	// And the restarted chain must agree, rather than serving a stale cached node.
	fromIndex, indexExists := restarted.blockIndex.GetBlockNodeByHashAndHeight(
		failedNode.Hash, uint64(failedNode.Height))
	require.True(t, indexExists)
	require.False(t, fromIndex.IsValidateFailed())

	// The behavioral payoff: the same descendant probe now reports the forgotten block as a
	// missing ancestor to be fetched, rather than a failed one. This is the state transition the
	// whole change exists to produce — it is what makes the node re-request and re-validate the
	// block instead of staying wedged.
	_, missingHashes, lineageErr := restarted.getStoredLineageFromCommittedTip(childHeader)
	require.Equal(t, RuleErrorMissingAncestorBlock, lineageErr,
		"after the restart, the forgotten block must read as missing, not failed")
	require.Len(t, missingHashes, 1)
	require.True(t, missingHashes[0].IsEqual(failedNode.Hash),
		"the forgotten block itself must be what gets re-requested")
}
