package lib

import (
	"testing"

	"github.com/deso-protocol/core/consensus"
	"github.com/stretchr/testify/require"
)

// This is a private regression reproducer for the QC/parent binding review.
// It deliberately constructs a block that extends one sibling while carrying
// a valid vote QC for another sibling at the same view.
func TestSecurityReviewVoteQCMustCertifyParent(t *testing.T) {
	testMeta := NewTestPoSBlockchainWithValidators(t)
	commonAncestorHash := testMeta.chain.BlockTip().Hash

	var parent *MsgDeSoBlock
	parent = _generateRealBlock(testMeta, 12, 12, 1001, commonAncestorHash, false)
	parentHash, err := parent.Hash()
	require.NoError(t, err)
	success, isOrphan, missing, err := testMeta.chain.ProcessBlockPoS(parent, 12, true)
	require.NoError(t, err)
	require.True(t, success)
	require.False(t, isOrphan)
	require.Empty(t, missing)

	var sibling *MsgDeSoBlock
	sibling = _generateRealBlock(testMeta, 12, 12, 1002, commonAncestorHash, false)
	siblingHash, err := sibling.Hash()
	require.NoError(t, err)
	require.False(t, siblingHash.IsEqual(parentHash))

	var child *MsgDeSoBlock
	child = _generateRealBlock(testMeta, 13, 13, 1003, parentHash, false)
	child.Header.ValidatorsVoteQC = _getVoteQC(
		testMeta,
		child.Header.Height,
		siblingHash,
		sibling.Header.ProposedInView,
	)
	updateProposerVotePartialSignatureForBlock(testMeta, child)

	require.Equal(
		t,
		RuleErrorPoSVoteQCBlockHashDoesNotMatchPrevBlockHash,
		testMeta.chain.isProperlyFormedBlockHeaderPoS(child.Header),
	)
	success, isOrphan, missing, err = testMeta.chain.ProcessBlockPoS(child, 13, true)
	require.Error(t, err)
	require.False(t, success)
	require.False(t, isOrphan)
	require.Empty(t, missing)
}

// This checks the earliest point at which the finality attack is stopped. The
// receiver sees Y, while E carries a valid QC for parallel sibling P. E must be
// rejected before another mismatched-QC child can cause Y to be committed.
func TestSecurityReviewMismatchedQCRejectedBeforeCommit(t *testing.T) {
	testMeta := NewTestPoSBlockchainWithValidators(t)
	commonAncestorHash := testMeta.chain.BlockTip().Hash

	var certifiedP *MsgDeSoBlock
	certifiedP = _generateRealBlock(testMeta, 12, 12, 2001, commonAncestorHash, false)
	certifiedPHash, err := certifiedP.Hash()
	require.NoError(t, err)
	success, _, _, err := testMeta.chain.ProcessBlockPoS(certifiedP, 12, true)
	require.NoError(t, err)
	require.True(t, success)

	var uncertifiedY *MsgDeSoBlock
	uncertifiedY = _generateRealBlock(testMeta, 12, 12, 2003, commonAncestorHash, false)
	uncertifiedYHash, err := uncertifiedY.Hash()
	require.NoError(t, err)
	require.False(t, uncertifiedYHash.IsEqual(certifiedPHash))
	success, _, _, err = testMeta.chain.ProcessBlockPoS(uncertifiedY, 12, true)
	require.NoError(t, err)
	require.True(t, success)

	var uncertifiedE *MsgDeSoBlock
	uncertifiedE = _generateRealBlock(testMeta, 13, 13, 2004, uncertifiedYHash, false)
	uncertifiedE.Header.ValidatorsVoteQC = _getVoteQC(
		testMeta,
		uncertifiedE.Header.Height,
		certifiedPHash,
		certifiedP.Header.ProposedInView,
	)
	updateProposerVotePartialSignatureForBlock(testMeta, uncertifiedE)
	require.Equal(
		t,
		RuleErrorPoSVoteQCBlockHashDoesNotMatchPrevBlockHash,
		testMeta.chain.isProperlyFormedBlockHeaderPoS(uncertifiedE.Header),
	)
	success, _, _, err = testMeta.chain.ProcessBlockPoS(uncertifiedE, 13, true)
	require.Error(t, err)
	require.False(t, success)

	uncertifiedYNode, exists := testMeta.chain.blockIndex.GetBlockNodeByHashAndHeight(
		uncertifiedYHash,
		uncertifiedY.Header.Height,
	)
	require.True(t, exists)
	require.False(t, uncertifiedYNode.IsCommitted())
	require.False(t, uncertifiedE.Header.ValidatorsVoteQC.BlockHash.IsEqual(uncertifiedYHash))
}

func TestSecurityReviewTimeoutHighQCMustCertifyParent(t *testing.T) {
	testMeta := NewTestPoSBlockchainWithValidators(t)
	commonAncestorHash := testMeta.chain.BlockTip().Hash

	var parent *MsgDeSoBlock
	parent = _generateRealBlock(testMeta, 12, 12, 3001, commonAncestorHash, false)
	parentHash, err := parent.Hash()
	require.NoError(t, err)
	success, _, _, err := testMeta.chain.ProcessBlockPoS(parent, 12, true)
	require.NoError(t, err)
	require.True(t, success)

	var sibling *MsgDeSoBlock
	sibling = _generateRealBlock(testMeta, 12, 12, 3002, commonAncestorHash, false)
	siblingHash, err := sibling.Hash()
	require.NoError(t, err)

	var timeoutChild *MsgDeSoBlock
	timeoutChild = _generateRealBlock(testMeta, 13, 14, 3003, parentHash, true)
	require.True(
		t,
		timeoutChild.Header.ValidatorsTimeoutAggregateQC.ValidatorsHighQC.BlockHash.IsEqual(parentHash),
	)
	require.NoError(t, testMeta.chain.isProperlyFormedBlockHeaderPoS(timeoutChild.Header))

	// Replace the high QC with an independently valid QC for a sibling in the
	// same view. Timeout signatures remain valid because they sign the timeout
	// view and high-QC view; the high QC itself authenticates the sibling hash.
	timeoutChild.Header.ValidatorsTimeoutAggregateQC.ValidatorsHighQC = _getVoteQC(
		testMeta,
		timeoutChild.Header.Height,
		siblingHash,
		sibling.Header.ProposedInView,
	)
	updateProposerVotePartialSignatureForBlock(testMeta, timeoutChild)

	parentViewAndOps, err := testMeta.chain.GetUtxoViewAndUtxoOpsAtBlockHash(*parentHash, parent.Header.Height)
	require.NoError(t, err)
	validators, err := parentViewAndOps.UtxoView.GetAllSnapshotValidatorSetEntriesByStake()
	require.NoError(t, err)
	require.True(t, consensus.IsValidSuperMajorityAggregateQuorumCertificate(
		timeoutChild.Header.ValidatorsTimeoutAggregateQC,
		toConsensusValidators(validators),
		toConsensusValidators(validators),
	))
	require.Equal(
		t,
		RuleErrorPoSTimeoutHighQCBlockHashDoesNotMatchPrevBlockHash,
		testMeta.chain.isProperlyFormedBlockHeaderPoS(timeoutChild.Header),
	)

	success, _, _, err = testMeta.chain.ProcessBlockPoS(timeoutChild, 14, true)
	require.Error(t, err)
	require.False(t, success)
}
