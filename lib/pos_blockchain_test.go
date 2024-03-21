package lib

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"

	"crypto/sha256"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/deso-protocol/core/consensus"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

// TestIsProperlyFormedBlockPoSAndIsBlockTimestampValidRelativeToParentPoS tests that
// isProperlyFormedBlockPoS and isBlockTimestampValidRelativeToParentPoS work as expected.
// It first creates a valid block and ensures that the validation passes.
// Then it modifies that block to trigger each validation error and ensures that
// we hit the expected error.
func TestIsProperlyFormedBlockPoSAndIsBlockTimestampValidRelativeToParentPoS(t *testing.T) {
	bc, params, _ := NewTestBlockchain(t)
	// TODO: update for PoS
	mempool, miner := NewTestMiner(t, bc, params, true)

	// Mine a few blocks to give the senderPkString some money.
	var err error
	for ii := 0; ii < 10; ii++ {
		_, err = miner.MineAndProcessSingleBlock(0, mempool)
		require.NoError(t, err)
	}
	// Create a block with a valid header.
	randomPayload := RandomBytes(256)
	require.NoError(t, err)
	randomBLSPrivateKey := _generateRandomBLSPrivateKey(t)
	signature, err := randomBLSPrivateKey.Sign(randomPayload)
	require.NoError(t, err)
	txns := []*MsgDeSoTxn{
		{
			TxnMeta: &BlockRewardMetadataa{},
		},
	}
	merkleRoot, _, err := ComputeMerkleRoot(txns)
	require.NoError(t, err)
	block := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			Version:        2,
			TstampNanoSecs: bc.BlockTip().Header.TstampNanoSecs + 10,
			Height:         2,
			ProposedInView: 3,
			PrevBlockHash:  bc.BlockTip().Hash,
			ValidatorsTimeoutAggregateQC: &TimeoutAggregateQuorumCertificate{
				TimedOutView: 2,
				ValidatorsHighQC: &QuorumCertificate{
					BlockHash:      bc.BlockTip().Hash,
					ProposedInView: 1,
					ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
						Signature:   signature,
						SignersList: bitset.NewBitset(),
					},
				},
				ValidatorsTimeoutHighQCViews: []uint64{28934},
				ValidatorsTimeoutAggregatedSignature: &AggregatedBLSSignature{
					Signature:   signature,
					SignersList: bitset.NewBitset(),
				},
			},
			ProposerRandomSeedSignature: signature,
			ProposerVotingPublicKey:     randomBLSPrivateKey.PublicKey(),
			TransactionMerkleRoot:       merkleRoot,
		},
		Txns: txns,
	}

	// Validate the block with a valid timeout QC and header.
	err = bc.isProperlyFormedBlockPoS(block)
	// There should be no error.
	require.Nil(t, err)

	// Timeout QC must have at least one transaction and that transaction must be a block reward txn.
	block.Txns = nil
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorBlockWithNoTxns)

	block.Txns = []*MsgDeSoTxn{
		{
			TxnMeta: &BasicTransferMetadata{},
		},
	}
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorBlockDoesNotStartWithRewardTxn)
	// Revert txns to be valid.
	block.Txns = []*MsgDeSoTxn{
		{
			TxnMeta: &BlockRewardMetadataa{},
		},
	}

	// Header's Proposed in view must be exactly one greater than the timeout QC's timed out view
	block.Header.ProposedInView = 2
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorPoSTimeoutBlockViewNotOneGreaterThanValidatorsTimeoutQCView)

	// Revert proposed in view
	block.Header.ProposedInView = 3

	// Timeout QC also must have a merkle root
	block.Header.TransactionMerkleRoot = nil
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorNilMerkleRoot)

	// Make sure block can't have both timeout and vote QC.
	validatorVoteQC := &QuorumCertificate{
		BlockHash:      bc.BlockTip().Hash,
		ProposedInView: 2,
		ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
			Signature:   signature,
			SignersList: bitset.NewBitset(),
		},
	}
	block.Header.ValidatorsVoteQC = validatorVoteQC
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorBothTimeoutAndVoteQC)

	// Make sure block has either timeout or vote QC.
	block.Header.ValidatorsTimeoutAggregateQC = nil
	block.Header.ValidatorsVoteQC = nil
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorNoTimeoutOrVoteQC)

	// Reset validator vote QC.
	block.Header.ValidatorsVoteQC = validatorVoteQC

	// Validate the block with a valid vote QC and header. Vote QCs must have at least 1 transaction
	// and first transaction must be a block reward.
	block.Txns = []*MsgDeSoTxn{
		// The validation just checks the length of transactions.
		// Connecting the block elsewhere will ensure that the transactions themselves are valid.
		{
			TxnMeta: &BlockRewardMetadataa{},
		},
	}
	merkleRoot, _, err = ComputeMerkleRoot(block.Txns)
	require.NoError(t, err)
	block.Header.TransactionMerkleRoot = merkleRoot
	// There should be no error.
	err = bc.isProperlyFormedBlockPoS(block)
	require.Nil(t, err)

	// Vote QC must have Header's Proposed in view exactly one greater than vote QC's proposed in view.
	block.Header.ProposedInView = 2
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorPoSVoteBlockViewNotOneGreaterThanValidatorsVoteQCView)

	// Revert proposed in view
	block.Header.ProposedInView = 3

	// Block must have non-nil Merkle root if we have non-zero transactions
	block.Header.TransactionMerkleRoot = nil
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorNilMerkleRoot)

	// Block must have a matching merkle root
	block.Header.TransactionMerkleRoot = &ZeroBlockHash
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorInvalidMerkleRoot)

	// Reset transactions
	block.Txns = []*MsgDeSoTxn{
		{
			TxnMeta: &BlockRewardMetadataa{},
		},
	}

	// Block must have valid proposer voting public key
	block.Header.ProposerVotingPublicKey = nil
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorInvalidProposerVotingPublicKey)

	block.Header.ProposerVotingPublicKey = &bls.PublicKey{}
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorInvalidProposerVotingPublicKey)

	// Reset proposer voting public key
	block.Header.ProposerVotingPublicKey = randomBLSPrivateKey.PublicKey()

	// Block must have valid proposer random seed hash
	block.Header.ProposerRandomSeedSignature = nil
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorInvalidProposerRandomSeedSignature)

	block.Header.ProposerRandomSeedSignature = &bls.Signature{}
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorInvalidProposerRandomSeedSignature)

	block.Header.ProposerRandomSeedSignature = signature

	// Timestamp validations
	// Block timestamp must be greater than the previous block timestamp
	block.Header.TstampNanoSecs = bc.BlockTip().Header.GetTstampSecs() - 1
	err = bc.isBlockTimestampValidRelativeToParentPoS(block.Header)
	require.Equal(t, err, RuleErrorPoSBlockTstampNanoSecsTooOld)

	// Revert the Header's timestamp
	block.Header.TstampNanoSecs = bc.BlockTip().Header.TstampNanoSecs + 10

	//  Block Header version must be 2
	block.Header.Version = 1
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorInvalidPoSBlockHeaderVersion)

	// Revert block header version
	block.Header.Version = 2

	// Nil prev block hash not allowed
	block.Header.PrevBlockHash = nil
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorNilPrevBlockHash)

	// Parent must exist in the block index.
	block.Header.PrevBlockHash = NewBlockHash(RandomBytes(32))
	err = bc.isBlockTimestampValidRelativeToParentPoS(block.Header)
	require.Equal(t, err, RuleErrorMissingParentBlock)

	// Nil block header not allowed
	block.Header = nil
	err = bc.isProperlyFormedBlockPoS(block)
	require.Equal(t, err, RuleErrorNilBlockHeader)
}

// TestHasValidBlockHeight tests that hasValidBlockHeightPoS works as expected.
// It ensures that the block does not have a height before the PoS cut over height,
// that the block's height is one greater than its parent, and that the block's parent
// exists.
func TestHasValidBlockHeight(t *testing.T) {
	bc, _, _ := NewTestBlockchain(t)
	hash := NewBlockHash(RandomBytes(32))
	nowTimestamp := time.Now().UnixNano()
	genesisBlock := NewBlockNode(nil, hash, 1, nil, nil, &MsgDeSoHeader{
		Version:                      2,
		TstampNanoSecs:               nowTimestamp - time.Minute.Nanoseconds(),
		Height:                       1,
		ProposedInView:               1,
		ValidatorsVoteQC:             nil,
		ValidatorsTimeoutAggregateQC: nil,
	}, StatusBlockStored|StatusBlockValidated)
	bc.bestChain = []*BlockNode{genesisBlock}
	bc.blockIndexByHash[*genesisBlock.Hash] = genesisBlock
	// Create a block with a valid header.
	randomPayload := RandomBytes(256)
	randomBLSPrivateKey := _generateRandomBLSPrivateKey(t)
	signature, err := randomBLSPrivateKey.Sign(randomPayload)
	require.NoError(t, err)
	block := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			PrevBlockHash:  genesisBlock.Hash,
			Version:        2,
			TstampNanoSecs: time.Now().UnixNano() - 10,
			Height:         2,
			ProposedInView: 1,
			ValidatorsTimeoutAggregateQC: &TimeoutAggregateQuorumCertificate{
				TimedOutView: 2,
				ValidatorsHighQC: &QuorumCertificate{
					BlockHash:      bc.BlockTip().Hash,
					ProposedInView: bc.BlockTip().Header.ProposedInView,
					ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
						Signature:   signature,
						SignersList: bitset.NewBitset(),
					},
				},
				ValidatorsTimeoutHighQCViews: []uint64{28934},
				ValidatorsTimeoutAggregatedSignature: &AggregatedBLSSignature{
					Signature:   signature,
					SignersList: bitset.NewBitset(),
				},
			},
		},
		Txns: nil,
	}

	// validate that we've cutover to PoS
	bc.params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 3
	err = bc.hasValidBlockHeightPoS(block.Header)
	require.Equal(t, err, RuleErrorPoSBlockBeforeCutoverHeight)

	// Update the fork height
	bc.params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 0

	err = bc.hasValidBlockHeightPoS(block.Header)
	require.Nil(t, err)

	block.Header.Height = 1
	err = bc.hasValidBlockHeightPoS(block.Header)
	require.Equal(t, err, RuleErrorInvalidPoSBlockHeight)

	block.Header.Height = 2
	bc.blockIndexByHash = map[BlockHash]*BlockNode{}
	err = bc.hasValidBlockHeightPoS(block.Header)
	require.Equal(t, err, RuleErrorMissingParentBlock)
}

// TestUpsertBlockAndBlockNodeToDB tests that upsertBlockAndBlockNodeToDB works as expected.
// It is tested by calling the wrapper functions storeBlockInBlockIndex and storeValidatedBlockInBlockIndex.
func TestUpsertBlockAndBlockNodeToDB(t *testing.T) {
	bc, _, _ := NewTestBlockchain(t)
	GlobalDeSoParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 0
	resetGlobalDeSoParams := func() {
		GlobalDeSoParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = math.MaxUint32
	}
	t.Cleanup(resetGlobalDeSoParams)
	hash1 := NewBlockHash(RandomBytes(32))
	hash2 := NewBlockHash(RandomBytes(32))
	genesisNode := NewBlockNode(nil, hash1, 1, nil, nil, &MsgDeSoHeader{
		Version:        2,
		Height:         1,
		ProposedInView: 1,
	}, StatusBlockStored|StatusBlockValidated)
	block2 := NewBlockNode(genesisNode, hash2, 2, nil, nil, &MsgDeSoHeader{
		Version:                      2,
		Height:                       2,
		ProposedInView:               2,
		ValidatorsVoteQC:             nil,
		ValidatorsTimeoutAggregateQC: nil,
	}, StatusBlockStored|StatusBlockValidated)
	bc.blockIndexByHash = map[BlockHash]*BlockNode{
		*hash1: genesisNode,
		*hash2: block2,
	}
	randomPayload := RandomBytes(256)
	randomBLSPrivateKey := _generateRandomBLSPrivateKey(t)
	signature, err := randomBLSPrivateKey.Sign(randomPayload)
	voteQC := &QuorumCertificate{
		BlockHash:      bc.BlockTip().Hash,
		ProposedInView: 1,
		ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
			Signature:   signature,
			SignersList: bitset.NewBitset(),
		},
	}
	require.NoError(t, err)
	blsPrivKey := _generateRandomBLSPrivateKey(t)
	block := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			PrevBlockHash:                hash2,
			Version:                      2,
			TstampNanoSecs:               time.Now().UnixNano() - 10,
			Height:                       2,
			ProposedInView:               1,
			ProposerVotingPublicKey:      blsPrivKey.PublicKey(),
			ProposerRandomSeedSignature:  signature,
			ProposerVotePartialSignature: signature,
			ValidatorsTimeoutAggregateQC: &TimeoutAggregateQuorumCertificate{
				TimedOutView:                 2,
				ValidatorsHighQC:             voteQC,
				ValidatorsTimeoutHighQCViews: []uint64{28934},
				ValidatorsTimeoutAggregatedSignature: &AggregatedBLSSignature{
					Signature:   signature,
					SignersList: bitset.NewBitset(),
				},
			},
		},
		Txns: []*MsgDeSoTxn{
			{
				TxnMeta: &BlockRewardMetadataa{},
			},
		},
	}
	blockNode, err := bc.storeBlockInBlockIndex(block)
	require.NoError(t, err)
	newHash, err := block.Hash()
	require.NoError(t, err)
	// Check the block index by hash
	blockNodeFromIndex, exists := bc.blockIndexByHash[*newHash]
	require.True(t, exists)
	require.True(t, blockNodeFromIndex.Hash.IsEqual(blockNode.Hash))
	require.Equal(t, blockNodeFromIndex.Height, uint32(2))
	require.True(t, blockNodeFromIndex.IsStored())
	require.False(t, blockNodeFromIndex.IsValidated())
	// Check the block index by height
	byHeightBlockNodes, exists := bc.blockIndexByHeight[2]
	require.True(t, exists)
	require.Len(t, byHeightBlockNodes, 1)
	require.True(t, byHeightBlockNodes[*newHash].Hash.IsEqual(newHash))
	require.True(t, bc.hasBlockNodesIndexedAtHeight(2))
	require.Len(t, bc.getAllBlockNodesIndexedAtHeight(2), 1)
	// Check the DB for the block
	uncommittedBlock, err := GetBlock(newHash, bc.db, bc.snapshot)
	require.NoError(t, err)
	uncommittedBytes, err := uncommittedBlock.ToBytes(false)
	require.NoError(t, err)
	origBlockBytes, err := block.ToBytes(false)
	require.NoError(t, err)
	require.True(t, bytes.Equal(uncommittedBytes, origBlockBytes))
	// Okay now we update the status of the block to include validated.
	blockNode, err = bc.storeValidatedBlockInBlockIndex(block)
	require.NoError(t, err)
	blockNodeFromIndex, exists = bc.blockIndexByHash[*newHash]
	require.True(t, exists)
	require.True(t, blockNodeFromIndex.Hash.IsEqual(blockNode.Hash))
	require.Equal(t, blockNodeFromIndex.Height, uint32(2))
	require.True(t, blockNodeFromIndex.IsStored())
	require.True(t, blockNodeFromIndex.IsValidated())
	// Check the block index by height.
	byHeightBlockNodes, exists = bc.blockIndexByHeight[2]
	require.True(t, exists)
	require.Len(t, byHeightBlockNodes, 1)
	require.True(t, byHeightBlockNodes[*newHash].Hash.IsEqual(newHash))
	require.True(t, byHeightBlockNodes[*newHash].IsValidated())
	require.True(t, bc.hasBlockNodesIndexedAtHeight(2))
	require.Len(t, bc.getAllBlockNodesIndexedAtHeight(2), 1)

	// Okay now we'll put in another block at the same height.
	// Update the random seed hash so we have a new hash for the block.
	randomSig, err := (&bls.Signature{}).FromBytes(RandomBytes(32))
	block.Header.ProposerRandomSeedSignature = randomSig
	updatedBlockHash, err := block.Hash()
	require.NoError(t, err)
	require.False(t, updatedBlockHash.IsEqual(newHash))

	// Okay now put this new block in there.
	blockNode, err = bc.storeBlockInBlockIndex(block)
	require.NoError(t, err)
	// Make sure the blockIndexByHash is correct.
	updatedBlockNode, exists := bc.blockIndexByHash[*updatedBlockHash]
	require.True(t, exists)
	require.True(t, updatedBlockNode.Hash.IsEqual(updatedBlockHash))
	require.Equal(t, updatedBlockNode.Height, uint32(2))
	require.True(t, updatedBlockNode.IsStored())
	require.False(t, updatedBlockNode.IsValidated())
	// Make sure the blockIndexByHeight is correct
	byHeightBlockNodes, exists = bc.blockIndexByHeight[2]
	require.True(t, exists)
	require.Len(t, byHeightBlockNodes, 2)
	require.True(t, byHeightBlockNodes[*newHash].Hash.IsEqual(newHash))
	require.True(t, byHeightBlockNodes[*updatedBlockHash].Hash.IsEqual(updatedBlockHash))
	require.True(t, bc.hasBlockNodesIndexedAtHeight(2))
	require.Len(t, bc.getAllBlockNodesIndexedAtHeight(2), 2)

	// If we're missing a field in the header, we should get an error
	// as we can't compute the hash.
	block.Header.ProposerVotingPublicKey = nil
	_, err = bc.storeBlockInBlockIndex(block)
	require.Error(t, err)
}

// TestHasValidBlockView tests that hasValidBlockViewPoS works as expected.
// If the block has a vote QC, it ensures that the block's view is exactly
// one greater than its parent's view.
// If the block has a timeout QC, it ensures that the block's view is
// greater than its parent's view.
func TestHasValidBlockViewPoS(t *testing.T) {
	setBalanceModelBlockHeights(t)
	setPoSBlockHeights(t, 1, 1)
	bc, _, _ := NewTestBlockchain(t)
	hash1 := NewBlockHash(RandomBytes(32))
	hash2 := NewBlockHash(RandomBytes(32))
	genesisNode := NewBlockNode(nil, hash1, 1, nil, nil, &MsgDeSoHeader{
		Version:        2,
		Height:         1,
		ProposedInView: 1,
	}, StatusBlockStored|StatusBlockValidated)
	block2 := NewBlockNode(genesisNode, hash2, 2, nil, nil, &MsgDeSoHeader{
		Version:                      2,
		Height:                       2,
		ProposedInView:               2,
		ValidatorsVoteQC:             nil,
		ValidatorsTimeoutAggregateQC: nil,
	}, StatusBlockStored|StatusBlockValidated)
	bc.bestChain = []*BlockNode{
		genesisNode,
		block2,
	}
	bc.blockIndexByHash = map[BlockHash]*BlockNode{
		*hash1: genesisNode,
		*hash2: block2,
	}
	randomPayload := RandomBytes(256)
	randomBLSPrivateKey := _generateRandomBLSPrivateKey(t)
	signature, err := randomBLSPrivateKey.Sign(randomPayload)
	voteQC := &QuorumCertificate{
		BlockHash:      bc.BlockTip().Hash,
		ProposedInView: 1,
		ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
			Signature:   signature,
			SignersList: bitset.NewBitset(),
		},
	}
	require.NoError(t, err)
	block := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			PrevBlockHash:  hash2,
			Version:        2,
			TstampNanoSecs: time.Now().UnixNano() - 10,
			Height:         2,
			ProposedInView: 1,
			ValidatorsTimeoutAggregateQC: &TimeoutAggregateQuorumCertificate{
				TimedOutView:                 2,
				ValidatorsHighQC:             voteQC,
				ValidatorsTimeoutHighQCViews: []uint64{28934},
				ValidatorsTimeoutAggregatedSignature: &AggregatedBLSSignature{
					Signature:   signature,
					SignersList: bitset.NewBitset(),
				},
			},
		},
		Txns: nil,
	}

	block.Header.ProposedInView = 2

	// Blocks with timeout QCs must have a view strictly greater than the parent.
	err = bc.hasValidBlockViewPoS(block.Header)
	require.Equal(t, err, RuleErrorPoSTimeoutBlockViewNotGreaterThanParent)

	// Any arbitrary number GREATER than the parent's view is valid.
	block.Header.ProposedInView = 10
	err = bc.hasValidBlockViewPoS(block.Header)
	require.Nil(t, err)

	// Now we set the timeout QC to nil and provide a vote QC, with height = 2
	block.Header.ValidatorsTimeoutAggregateQC = nil
	block.Header.ValidatorsVoteQC = voteQC
	block.Header.ProposedInView = 2
	err = bc.hasValidBlockViewPoS(block.Header)
	require.Equal(t, err, RuleErrorPoSVoteBlockViewNotOneGreaterThanParent)

	// An arbitrary number greater than its parents should fail.
	block.Header.ProposedInView = 10
	err = bc.hasValidBlockViewPoS(block.Header)
	require.Equal(t, err, RuleErrorPoSVoteBlockViewNotOneGreaterThanParent)

	// Exactly one great w/ vote QC should pass.
	block.Header.ProposedInView = 3
	err = bc.hasValidBlockViewPoS(block.Header)
	require.Nil(t, err)
}

// TestHasValidBlockProposerPoS tests that hasValidBlockProposerPoS works as expected.
// It registers 7 validators and stakes to themselves and then makes sure we can
// validate the block proposer for a valid block and makes sure we hit the appropriate
// RuleError if the block proposer is invalid for any reason.
func TestHasValidBlockProposerPoS(t *testing.T) {
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)
	// Initialize PoS fork heights.
	setPoSBlockHeights(t, 11, 12)

	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForEpochCompleteTest(t)

	_registerOrTransferWithTestMeta(testMeta, "m0", senderPkString, m0Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m1", senderPkString, m1Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m2", senderPkString, m2Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m3", senderPkString, m3Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m4", senderPkString, m4Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m5", senderPkString, m5Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m6", senderPkString, m6Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 1e3)

	m0PKID := *DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m0PkBytes).PKID
	m1PKID := *DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m1PkBytes).PKID
	m2PKID := *DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m2PkBytes).PKID
	m3PKID := *DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m3PkBytes).PKID
	m4PKID := *DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m4PkBytes).PKID
	m5PKID := *DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m5PkBytes).PKID
	m6PKID := *DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m6PkBytes).PKID

	validatorPKIDs := []PKID{m0PKID, m1PKID, m2PKID, m3PKID, m4PKID, m5PKID, m6PKID}
	_ = validatorPKIDs
	blockHeight := uint64(testMeta.chain.blockTip().Height) + 1
	incrBlockHeight := func() uint64 {
		blockHeight += 1
		return blockHeight
	}
	viewNumber := uint64(0)
	incrViewNumber := func() uint64 {
		viewNumber += 1
		return viewNumber
	}

	// Seed a CurrentEpochEntry.
	tmpUtxoView := _newUtxoView(testMeta)
	tmpUtxoView._setCurrentEpochEntry(&EpochEntry{EpochNumber: 0, FinalBlockHeight: blockHeight + 1})
	require.NoError(t, tmpUtxoView.FlushToDb(blockHeight))

	// For these tests, we set each epoch duration to only one block.
	testMeta.params.DefaultEpochDurationNumBlocks = uint64(1)

	{

		// We need to reset the UniversalUtxoView since the RegisterAsValidator and Stake
		// txn test helper utils use and flush the UniversalUtxoView. Otherwise, the
		// updated GlobalParamsEntry will be overwritten by the default one cached in
		// the UniversalUtxoView when it is flushed.
		testMeta.mempool.universalUtxoView._ResetViewMappingsAfterFlush()
	}

	// All validators register + stake to themselves.
	_registerValidatorAndStake(testMeta, m0Pub, m0Priv, 0, 100, false)
	_registerValidatorAndStake(testMeta, m1Pub, m1Priv, 0, 200, false)
	_registerValidatorAndStake(testMeta, m2Pub, m2Priv, 0, 300, false)
	_registerValidatorAndStake(testMeta, m3Pub, m3Priv, 0, 400, false)
	_registerValidatorAndStake(testMeta, m4Pub, m4Priv, 0, 500, false)
	_registerValidatorAndStake(testMeta, m5Pub, m5Priv, 0, 600, false)
	_registerValidatorAndStake(testMeta, m6Pub, m6Priv, 0, 700, false)

	// Get current epoch number
	utxoView := _newUtxoView(testMeta)
	currentEpochNumber, err := utxoView.GetCurrentEpochNumber()
	require.NoError(t, err)

	// Run the epoch complete hook
	_runOnEpochCompleteHook(testMeta, incrBlockHeight(), incrViewNumber())

	// Get leader schedule from DB
	leaderSchedule, err := DBSeekSnapshotLeaderSchedule(testMeta.db, currentEpochNumber)
	require.NoError(t, err)
	require.Equal(t, len(leaderSchedule), len(validatorPKIDs))
	// Make sure all the validators are in the leader schedule.
	for _, pkid := range leaderSchedule {
		require.Contains(t, validatorPKIDs, *pkid)
	}

	utxoView = _newUtxoView(testMeta)
	leaders, err := utxoView.GetCurrentSnapshotLeaderSchedule()
	require.NoError(t, err)
	require.Equal(t, len(leaders), len(validatorPKIDs))
	// Make sure all the validators are in the leader schedule.
	for _, pkid := range leaders {
		require.Contains(t, validatorPKIDs, *pkid)
	}

	utxoView = _newUtxoView(testMeta)
	// Get all the validator entries
	m0ValidatorEntry, err := utxoView.GetValidatorByPKID(&m0PKID)
	require.NoError(t, err)
	m1ValidatorEntry, err := utxoView.GetValidatorByPKID(&m1PKID)
	require.NoError(t, err)
	m2ValidatorEntry, err := utxoView.GetValidatorByPKID(&m2PKID)
	require.NoError(t, err)
	m3ValidatorEntry, err := utxoView.GetValidatorByPKID(&m3PKID)
	require.NoError(t, err)
	m4ValidatorEntry, err := utxoView.GetValidatorByPKID(&m4PKID)
	require.NoError(t, err)
	m5ValidatorEntry, err := utxoView.GetValidatorByPKID(&m5PKID)
	require.NoError(t, err)
	m6ValidatorEntry, err := utxoView.GetValidatorByPKID(&m6PKID)
	require.NoError(t, err)
	validatorPKIDToValidatorEntryMap := map[PKID]*ValidatorEntry{
		m0PKID: m0ValidatorEntry,
		m1PKID: m1ValidatorEntry,
		m2PKID: m2ValidatorEntry,
		m3PKID: m3ValidatorEntry,
		m4PKID: m4ValidatorEntry,
		m5PKID: m5ValidatorEntry,
		m6PKID: m6ValidatorEntry,
	}
	// Mark chain tip as committed.
	testMeta.chain.BlockTip().Status |= StatusBlockCommitted
	var isBlockProposerValid bool
	{
		// First block, we should have the first leader.
		leader0PKID := leaderSchedule[0]
		leader0Entry := validatorPKIDToValidatorEntryMap[*leader0PKID]
		dummyBlock := &MsgDeSoBlock{
			Header: &MsgDeSoHeader{
				PrevBlockHash:           testMeta.chain.BlockTip().Hash,
				ProposedInView:          viewNumber + 1,
				Height:                  blockHeight + 1,
				ProposerVotingPublicKey: leader0Entry.VotingPublicKey,
			},
		}
		isBlockProposerValid, err = utxoView.hasValidBlockProposerPoS(dummyBlock)
		require.NoError(t, err)
		require.True(t, isBlockProposerValid)

		// If we have a different proposer public key, we will have an error
		leader1Entry := validatorPKIDToValidatorEntryMap[*leaderSchedule[1]]
		dummyBlock.Header.ProposerVotingPublicKey = leader1Entry.VotingPublicKey.Copy()
		isBlockProposerValid, err = utxoView.hasValidBlockProposerPoS(dummyBlock)
		require.NoError(t, err)
		require.False(t, isBlockProposerValid)

		// If we advance the view, we know that leader 0 timed out, so
		// we move to leader 1.
		dummyBlock.Header.ProposedInView = viewNumber + 2
		dummyBlock.Header.ProposerVotingPublicKey = leader1Entry.VotingPublicKey
		isBlockProposerValid, err = utxoView.hasValidBlockProposerPoS(dummyBlock)
		require.NoError(t, err)
		require.True(t, isBlockProposerValid)

		// If we have 4 timeouts, we know that leaders 0, 1, 2, and 3 timed out,
		// so we move to leader 4.
		dummyBlock.Header.ProposedInView = viewNumber + 5
		leader4Entry := validatorPKIDToValidatorEntryMap[*leaderSchedule[4]]
		dummyBlock.Header.ProposerVotingPublicKey = leader4Entry.VotingPublicKey
		isBlockProposerValid, err = utxoView.hasValidBlockProposerPoS(dummyBlock)
		require.NoError(t, err)
		require.True(t, isBlockProposerValid)

		// If we have 7 timeouts, we know everybody timed out, so we go back to leader 0.
		dummyBlock.Header.ProposedInView = viewNumber + 8
		dummyBlock.Header.ProposerVotingPublicKey = leader0Entry.VotingPublicKey
		isBlockProposerValid, err = utxoView.hasValidBlockProposerPoS(dummyBlock)
		require.NoError(t, err)
		require.True(t, isBlockProposerValid)

		// If the block view is less than the epoch's initial view, this is an error.
		dummyBlock.Header.ProposedInView = viewNumber
		isBlockProposerValid, err = utxoView.hasValidBlockProposerPoS(dummyBlock)
		require.NoError(t, err)
		require.False(t, isBlockProposerValid)

		// If the block height is less than epoch's initial block height, this is an error.
		dummyBlock.Header.ProposedInView = viewNumber + 1
		dummyBlock.Header.Height = blockHeight
		isBlockProposerValid, err = utxoView.hasValidBlockProposerPoS(dummyBlock)
		require.NoError(t, err)
		require.False(t, isBlockProposerValid)

		// If the difference between the block's view and epoch's initial view is less than
		// the difference between the block's height and the epoch's initial height, this is an error.
		// This would imply that we've had more blocks than views, which is not possible.
		dummyBlock.Header.ProposedInView = viewNumber + 1
		dummyBlock.Header.Height = blockHeight + 2
		isBlockProposerValid, err = utxoView.hasValidBlockProposerPoS(dummyBlock)
		require.NoError(t, err)
		require.False(t, isBlockProposerValid)
	}

}

// TestGetLineageFromCommittedTip tests that getLineageFromCommittedTip works as expected.
// It makes sure the happy path works as well as makes sure we hit the appropriate RuleError
// if a block is invalid for any reason. Invalid reasons include extending from a committed
// block that is not the committed tip, extending from a block that has status StatusBlockValidateFailed,
// extending from a block that doesn't have a sequential block height or a monotonically increasing view.
func TestGetLineageFromCommittedTip(t *testing.T) {
	setBalanceModelBlockHeights(t)
	bc, _, _ := NewTestBlockchain(t)
	GlobalDeSoParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 0
	resetGlobalDeSoParams := func() {
		GlobalDeSoParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = math.MaxUint32
	}
	t.Cleanup(resetGlobalDeSoParams)
	hash1 := NewBlockHash(RandomBytes(32))
	genesisNode := NewBlockNode(nil, hash1, 1, nil, nil, &MsgDeSoHeader{
		Version:        2,
		Height:         1,
		ProposedInView: 1,
	}, StatusBlockStored|StatusBlockValidated|StatusBlockCommitted)
	bc.bestChain = []*BlockNode{genesisNode}
	bc.blockIndexByHash = map[BlockHash]*BlockNode{
		*hash1: genesisNode,
	}
	block := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			Version:        HeaderVersion2,
			PrevBlockHash:  hash1,
			ProposedInView: 3,
			Height:         3,
		},
	}
	// If parent is committed tip, we'll have 0 ancestors.
	ancestors, err := bc.getLineageFromCommittedTip(block.Header)
	require.NoError(t, err)
	require.Len(t, ancestors, 0)

	// If parent block is not in block index, we should get an error
	block.Header.PrevBlockHash = NewBlockHash(RandomBytes(32))
	ancestors, err = bc.getLineageFromCommittedTip(block.Header)
	require.Error(t, err)
	require.Equal(t, err, RuleErrorMissingAncestorBlock)
	require.Nil(t, ancestors)

	// If this block extends from a committed block that is not the tip, we should get an error.
	block.Header.PrevBlockHash = hash1
	// add another block to the best chain.
	hash2 := NewBlockHash(RandomBytes(32))
	block2 := NewBlockNode(genesisNode, hash2, 2, nil, nil, &MsgDeSoHeader{
		Version:        2,
		Height:         2,
		ProposedInView: 2,
		PrevBlockHash:  hash1,
	}, StatusBlockStored|StatusBlockValidated|StatusBlockCommitted)
	bc.bestChain = append(bc.bestChain, block2)
	bc.blockIndexByHash[*hash2] = block2
	ancestors, err = bc.getLineageFromCommittedTip(block.Header)
	require.Error(t, err)
	require.Equal(t, err, RuleErrorDoesNotExtendCommittedTip)

	// update block to be uncommitted
	block2.Status = StatusBlockStored | StatusBlockValidated
	// set new block's parent as block 2.
	block.Header.PrevBlockHash = hash2
	ancestors, err = bc.getLineageFromCommittedTip(block.Header)
	require.NoError(t, err)
	require.Len(t, ancestors, 1)

	// Testing error cases
	// Set block 2 to be ValidateFailed
	block2.Status = StatusBlockStored | StatusBlockValidateFailed
	ancestors, err = bc.getLineageFromCommittedTip(block.Header)
	require.Error(t, err)
	require.Equal(t, err, RuleErrorAncestorBlockValidationFailed)

	// Revert block 2 status.
	block2.Status = StatusBlockStored | StatusBlockValidated
	// Set block's height to be <= block2's height
	block.Header.Height = 2
	ancestors, err = bc.getLineageFromCommittedTip(block.Header)
	require.Error(t, err)
	require.Equal(t, err, RuleErrorParentBlockHeightNotSequentialWithChildBlockHeight)
	// Revert block 2's height and set block's view to be <= block2's view
	block.Header.Height = 3
	block.Header.ProposedInView = 2
	ancestors, err = bc.getLineageFromCommittedTip(block.Header)
	require.Error(t, err)
	require.Equal(t, err, RuleErrorParentBlockHasViewGreaterOrEqualToChildBlock)
}

// TestIsValidPoSQuorumCertificate tests that isValidPoSQuorumCertificate works as expected.
// It tests the following cases:
// 1. Empty vote & timeout QC - INVALID
// 2. Valid vote QC w/ super-majority - VALID
// 3. Empty validator set - INVALID
// 4. Vote QC w/ malformed validator entries - INVALID
// 5. Malformed vote QC - INVALID
// 6. Valid vote QC w/o super-majority - INVALID
// 7. Vote QC w/ mismatched signer's list and signature - INVALID
// 8. Valid timeout QC w/ super-majority - VALID
// 9. Malformed timeout QC - Invalid
// 10. Timeout QC w/ malformed validator entries - INVALID
// 11. Valid timeout QC w/o super-majority - INVALID
// 12. Timeout QC w/ mismatched signer's list and signature - INVALID
func TestIsValidPoSQuorumCertificate(t *testing.T) {
	bc, _, _ := NewTestBlockchain(t)
	hash1 := NewBlockHash(RandomBytes(32))
	// Mock validator entries
	m1PKID := DBGetPKIDEntryForPublicKey(bc.db, nil, m1PkBytes).PKID
	m1VotingPrivateKey := _generateRandomBLSPrivateKey(t)
	validator1Entry := &ValidatorEntry{
		ValidatorPKID:         m1PKID,
		VotingPublicKey:       m1VotingPrivateKey.PublicKey(),
		TotalStakeAmountNanos: uint256.NewInt().SetUint64(3),
	}
	m2PKID := DBGetPKIDEntryForPublicKey(bc.db, nil, m2PkBytes).PKID
	m2VotingPrivateKey := _generateRandomBLSPrivateKey(t)
	validator2Entry := &ValidatorEntry{
		ValidatorPKID:         m2PKID,
		VotingPublicKey:       m2VotingPrivateKey.PublicKey(),
		TotalStakeAmountNanos: uint256.NewInt().SetUint64(2),
	}
	m3PKID := DBGetPKIDEntryForPublicKey(bc.db, nil, m3PkBytes).PKID
	m3VotingPrivateKey := _generateRandomBLSPrivateKey(t)
	validator3Entry := &ValidatorEntry{
		ValidatorPKID:         m3PKID,
		VotingPublicKey:       m3VotingPrivateKey.PublicKey(),
		TotalStakeAmountNanos: uint256.NewInt().SetUint64(1),
	}

	validatorSet := []*ValidatorEntry{validator1Entry, validator2Entry, validator3Entry}

	desoBlock := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			Height:         5,
			ProposedInView: 6,
		},
	}
	// Empty QC for both vote and timeout should fail
	err := bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
	require.Error(t, err)
	require.Equal(t, err, RuleErrorInvalidVoteQC)

	// Valid vote QC should pass with supermajority
	votePayload := consensus.GetVoteSignaturePayload(6, hash1)
	vote1Signature, err := m1VotingPrivateKey.Sign(votePayload[:])
	require.NoError(t, err)
	vote2Signature, err := m2VotingPrivateKey.Sign(votePayload[:])
	require.NoError(t, err)
	aggregateSig, err := bls.AggregateSignatures([]*bls.Signature{vote1Signature, vote2Signature})
	require.NoError(t, err)
	signersList1And2 := bitset.NewBitset().FromBytes([]byte{0x3}) // 0b0011, which represents validators 1 and 2,
	voteQC := &QuorumCertificate{
		BlockHash:      hash1,
		ProposedInView: 6,
		ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
			SignersList: signersList1And2,
			Signature:   aggregateSig,
		},
	}
	desoBlock.Header.ValidatorsVoteQC = voteQC
	err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
	require.NoError(t, err)

	// Empty validator set should fail
	err = bc.isValidPoSQuorumCertificate(desoBlock, []*ValidatorEntry{})
	require.Error(t, err)
	require.Equal(t, err, RuleErrorInvalidVoteQC)

	// Malformed validators should fail
	{
		// Zero stake amount
		validatorSet[0].TotalStakeAmountNanos = uint256.NewInt().SetUint64(0)
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil stake amount
		validatorSet[0].TotalStakeAmountNanos = nil
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Reset stake amount
		validatorSet[0].TotalStakeAmountNanos = uint256.NewInt().SetUint64(3)
		// Nil voting public key
		validatorSet[0].VotingPublicKey = nil
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Reset voting public key
		validatorSet[0].VotingPublicKey = m1VotingPrivateKey.PublicKey()
		// Nil validator entry
		err = bc.isValidPoSQuorumCertificate(desoBlock, append(validatorSet, nil))
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)
	}

	{
		// Malformed vote QC should fail
		// Nil vote QC
		desoBlock.Header.ValidatorsVoteQC = nil
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// View is 0
		desoBlock.Header.ValidatorsVoteQC = voteQC
		voteQC.ProposedInView = 0
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil block hash
		voteQC.ProposedInView = 6
		voteQC.BlockHash = nil
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil signers list
		voteQC.ValidatorsVoteAggregatedSignature.SignersList = nil
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil Signature
		voteQC.ValidatorsVoteAggregatedSignature.SignersList = signersList1And2
		voteQC.ValidatorsVoteAggregatedSignature.Signature = nil
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil aggregate signature
		voteQC.BlockHash = hash1
		voteQC.ValidatorsVoteAggregatedSignature = nil
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)
		// Reset the ValidatorsVoteAggregatedSignature
		voteQC.ValidatorsVoteAggregatedSignature = &AggregatedBLSSignature{
			SignersList: signersList1And2,
			Signature:   aggregateSig,
		}
	}

	{
		// No supermajority in vote QC
		voteQC.ValidatorsVoteAggregatedSignature.SignersList = bitset.NewBitset().FromBytes([]byte{0x1}) // 0b0001, which represents validator 1
		voteQC.ValidatorsVoteAggregatedSignature.Signature = vote1Signature
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)
	}
	{
		// Only having signature for validator 1 should fail even if signers list has validator 2
		voteQC.ValidatorsVoteAggregatedSignature.SignersList = bitset.NewBitset().FromBytes([]byte{0x3}) // 0b0010, which represents validator 1 and 2
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Having 1 and 3 in signers list, but including signature for 2 should fail
		voteQC.ValidatorsVoteAggregatedSignature.SignersList = bitset.NewBitset().Set(0, true).Set(2, true) // represents validator 1 and 3
		voteQC.ValidatorsVoteAggregatedSignature.Signature = aggregateSig
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Reset the signers list and signature
		voteQC.ValidatorsVoteAggregatedSignature.SignersList = signersList1And2
		voteQC.ValidatorsVoteAggregatedSignature.Signature = aggregateSig
	}

	// Timeout QC tests
	// Let's start with a valid timeout QC
	timeout1Payload := consensus.GetTimeoutSignaturePayload(8, 6)
	timeout1Signature, err := m1VotingPrivateKey.Sign(timeout1Payload[:])
	require.NoError(t, err)
	timeout2Payload := consensus.GetTimeoutSignaturePayload(8, 5)
	timeout2Signature, err := m2VotingPrivateKey.Sign(timeout2Payload[:])

	timeoutAggSig, err := bls.AggregateSignatures([]*bls.Signature{timeout1Signature, timeout2Signature})
	require.NoError(t, err)
	timeoutQC := &TimeoutAggregateQuorumCertificate{
		TimedOutView:                 8,
		ValidatorsHighQC:             voteQC,
		ValidatorsTimeoutHighQCViews: []uint64{6, 5},
		ValidatorsTimeoutAggregatedSignature: &AggregatedBLSSignature{
			SignersList: signersList1And2,
			Signature:   timeoutAggSig,
		},
	}
	// Set the vote qc to nil
	desoBlock.Header.ValidatorsVoteQC = nil
	// Set the timeout qc to the timeout qc constructed above
	desoBlock.Header.ValidatorsTimeoutAggregateQC = timeoutQC
	err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
	require.NoError(t, err)

	{
		// Malformed timeout QC tests
		// NOTE: these actually trigger RuleErrorInvalidVoteQC because the
		// timeout QC is interpreted as empty
		// View = 0
		timeoutQC.TimedOutView = 0
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil high QC
		timeoutQC.TimedOutView = 8
		timeoutQC.ValidatorsHighQC = nil
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// High QC has view of 0
		timeoutQC.ValidatorsHighQC = voteQC
		timeoutQC.ValidatorsHighQC.ProposedInView = 0
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// No high QC views
		timeoutQC.ValidatorsHighQC.ProposedInView = 6
		timeoutQC.ValidatorsTimeoutHighQCViews = []uint64{}
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil high QC block hash
		timeoutQC.ValidatorsTimeoutHighQCViews = []uint64{6, 5}
		timeoutQC.ValidatorsHighQC.BlockHash = nil
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil high QC signers list
		timeoutQC.ValidatorsHighQC.BlockHash = hash1
		timeoutQC.ValidatorsHighQC.ValidatorsVoteAggregatedSignature.SignersList = nil
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil high QC signature
		timeoutQC.ValidatorsHighQC.ValidatorsVoteAggregatedSignature.SignersList = signersList1And2
		timeoutQC.ValidatorsHighQC.ValidatorsVoteAggregatedSignature.Signature = nil
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil High QC Aggregated signature
		timeoutQC.ValidatorsHighQC.ValidatorsVoteAggregatedSignature = nil
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Revert high qc aggregated signature
		timeoutQC.ValidatorsHighQC.ValidatorsVoteAggregatedSignature = &AggregatedBLSSignature{
			SignersList: signersList1And2,
			Signature:   aggregateSig,
		}

		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.NoError(t, err)
	}
	{
		// Timed out view is not exactly one greater than high QC view
		timeoutQC.ValidatorsHighQC.ProposedInView = 7
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)
	}
	{
		// Invalid validator set tests
		// Zero stake amount
		validatorSet[0].TotalStakeAmountNanos = uint256.NewInt().SetUint64(0)
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)

		// Nil stake amount
		validatorSet[0].TotalStakeAmountNanos = nil
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)

		// Reset stake amount
		validatorSet[0].TotalStakeAmountNanos = uint256.NewInt().SetUint64(3)
		// Nil voting public key
		validatorSet[0].VotingPublicKey = nil
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)

		// Reset voting public key
		validatorSet[0].VotingPublicKey = m1VotingPrivateKey.PublicKey()
		// Nil validator entry
		err = bc.isValidPoSQuorumCertificate(desoBlock, append(validatorSet, nil))
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)
	}

	{
		// No supermajority test
		timeoutQC.ValidatorsTimeoutAggregatedSignature.SignersList = bitset.NewBitset().FromBytes([]byte{0x1}) // 0b0001, which represents validator 1
		timeoutQC.ValidatorsTimeoutAggregatedSignature.Signature = timeout1Signature
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)
	}

	{
		// Only having signature for validator 1 should fail even if signers list has validator 2
		timeoutQC.ValidatorsTimeoutAggregatedSignature.SignersList = bitset.NewBitset().FromBytes([]byte{0x3}) // 0b0010, which represents validator 1 and 2
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)

		// Having 1 and 3 in signers list, but including signature for 2 should fail
		timeoutQC.ValidatorsTimeoutAggregatedSignature.SignersList = bitset.NewBitset().Set(0, true).Set(2, true) // represents validator 1 and 3
		timeoutQC.ValidatorsTimeoutAggregatedSignature.Signature = timeoutAggSig
		err = bc.isValidPoSQuorumCertificate(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)
	}
}

// TestShouldReorg tests that shouldReorg works as expected.
// It tests the following cases:
// 1. Parent is chain tip. No reorg required.
// 2. Parent is not chain tip, but currentView is greater than the block's view. No reorg required.
// 3. Parent is not chain tip and current view is less than or equal to block's view. Reorg required.
func TestShouldReorg(t *testing.T) {
	bc, _, _ := NewTestBlockchain(t)
	hash1 := NewBlockHash(RandomBytes(32))
	hash2 := NewBlockHash(RandomBytes(32))
	hash3 := NewBlockHash(RandomBytes(32))
	bc.bestChain = []*BlockNode{
		{
			Hash:   hash1,
			Status: StatusBlockStored | StatusBlockValidated | StatusBlockCommitted,
		},
		{
			Hash:   hash3,
			Status: StatusBlockStored | StatusBlockValidated,
		},
	}

	newBlock := &BlockNode{
		Header: &MsgDeSoHeader{
			ProposedInView: 2,
			PrevBlockHash:  bc.bestChain[1].Hash,
		},
	}

	// Parent is chain tip. No reorg required.
	require.False(t, bc.shouldReorg(newBlock, 2))

	// Parent is not chain tip, but currentView is greater than
	// the block's view.
	newBlock.Header.PrevBlockHash = hash1
	require.False(t, bc.shouldReorg(newBlock, 3))

	// Parent is not chain tip. Reorg required.
	// Other checks have already been completed to ensure
	// that hash2 exists in the blockIndexByHash
	newBlock.Header.PrevBlockHash = hash2
	require.True(t, bc.shouldReorg(newBlock, 2))
}

// TestTryApplyNewTip tests that tryApplyNewTip works as expected.
// It tests the following cases:
// 1. Simple reorg. Just replacing the uncommitted tip.
// 2. Create a longer chain and reorg to it.
// 3. Make sure no reorg when current view is greater than block's view
// 4. Super happy path of simply extending current uncommitted tip.
func TestTryApplyNewTip(t *testing.T) {
	setBalanceModelBlockHeights(t)
	bc, _, _ := NewTestBlockchain(t)
	GlobalDeSoParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 0
	resetGlobalDeSoParams := func() {
		GlobalDeSoParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = math.MaxUint32
	}
	t.Cleanup(resetGlobalDeSoParams)
	hash1 := NewBlockHash(RandomBytes(32))
	bn1 := &BlockNode{
		Hash:   hash1,
		Status: StatusBlockStored | StatusBlockValidated | StatusBlockCommitted,
		Height: 2,
		Header: &MsgDeSoHeader{
			Height:         2,
			ProposedInView: 2,
		},
	}
	hash2 := NewBlockHash(RandomBytes(32))
	bn2 := &BlockNode{
		Hash:   hash2,
		Status: StatusBlockStored | StatusBlockValidated,
		Height: 3,
		Header: &MsgDeSoHeader{
			PrevBlockHash:  hash1,
			Height:         3,
			ProposedInView: 3,
		},
	}
	hash3 := NewBlockHash(RandomBytes(32))
	bn3 := &BlockNode{
		Hash:   hash3,
		Status: StatusBlockStored | StatusBlockValidated,
		Height: 4,
		Header: &MsgDeSoHeader{
			PrevBlockHash:  hash2,
			Height:         4,
			ProposedInView: 4,
		},
	}
	bc.addTipBlockToBestChain(bn1)
	bc.addTipBlockToBestChain(bn2)
	bc.addTipBlockToBestChain(bn3)
	bc.blockIndexByHash[*hash1] = bn1
	bc.blockIndexByHash[*hash2] = bn2
	bc.blockIndexByHash[*hash3] = bn3

	// Simple reorg. Just replacing the uncommitted tip.
	newBlock := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			PrevBlockHash:  hash2,
			ProposedInView: 10,
			Height:         4,
		},
	}
	newBlockHash, err := newBlock.Hash()
	require.NoError(t, err)

	ancestors, err := bc.getLineageFromCommittedTip(newBlock.Header)
	require.NoError(t, err)
	checkBestChainForHash := func(hash *BlockHash) bool {
		return collections.Any(bc.bestChain, func(bn *BlockNode) bool {
			return bn.Hash.IsEqual(hash)
		})
	}

	// Try to apply newBlock as tip. This should succeed.
	newBlockNode := &BlockNode{
		Header: newBlock.Header,
		Hash:   newBlockHash,
	}
	appliedNewTip, connectedBlockHashes, disconnectedBlockHashes, err := bc.tryApplyNewTip(newBlockNode, 9, ancestors)
	require.NoError(t, err)
	require.True(t, appliedNewTip)
	// hash 3 should no longer be in the best chain or best chain map
	_, hash3ExistsInBestChainMap := bc.bestChainMap[*hash3]
	require.False(t, hash3ExistsInBestChainMap)
	require.False(t, checkBestChainForHash(hash3))
	require.Len(t, connectedBlockHashes, 1)
	require.Len(t, disconnectedBlockHashes, 1)

	// newBlock should be in the best chain and the best chain map and should be the tip.
	_, newBlockExistsInBestChainMap := bc.bestChainMap[*newBlockHash]
	require.True(t, newBlockExistsInBestChainMap)
	require.True(t, checkBestChainForHash(newBlockHash))
	require.True(t, bc.BlockTip().Hash.IsEqual(newBlockHash))

	// Make sure block 2 and block 1 are still in the best chain.
	_, hash2ExistsInBestChainMap := bc.bestChainMap[*hash2]
	require.True(t, hash2ExistsInBestChainMap)
	require.True(t, checkBestChainForHash(hash2))

	_, hash1ExistsInBestChainMap := bc.bestChainMap[*hash1]
	require.True(t, hash1ExistsInBestChainMap)
	require.True(t, checkBestChainForHash(hash1))

	// Remove newBlock from the best chain and block index to reset the state.
	bc.bestChain = bc.bestChain[:len(bc.bestChain)-1]
	delete(bc.bestChainMap, *newBlockHash)
	// Add block 3 back
	bc.addTipBlockToBestChain(bn3)

	// Add a series of blocks that are not part of the best chain
	// to the block index and reorg to them
	hash4 := NewBlockHash(RandomBytes(32))
	bn4 := &BlockNode{
		Hash:   hash4,
		Status: StatusBlockStored | StatusBlockValidated,
		Height: 5,
		Header: &MsgDeSoHeader{
			PrevBlockHash:  hash1,
			ProposedInView: 5,
			Height:         5,
		},
	}

	hash5 := NewBlockHash(RandomBytes(32))
	bn5 := &BlockNode{
		Hash:   hash5,
		Status: StatusBlockStored | StatusBlockValidated,
		Height: 6,
		Header: &MsgDeSoHeader{
			PrevBlockHash:  hash4,
			ProposedInView: 6,
			Height:         6,
		},
	}
	bc.blockIndexByHash[*hash4] = bn4
	bc.blockIndexByHash[*hash5] = bn5

	// Set new block's parent to hash5
	newBlockNode.Header.PrevBlockHash = hash5
	newBlockNode.Header.ProposedInView = 7
	newBlockNode.Header.Height = 7
	newBlockNode.Height = 7
	require.NoError(t, err)
	ancestors, err = bc.getLineageFromCommittedTip(newBlock.Header)
	require.NoError(t, err)

	// Try to apply newBlock as tip.
	appliedNewTip, connectedBlockHashes, disconnectedBlockHashes, err = bc.tryApplyNewTip(newBlockNode, 6, ancestors)
	require.NoError(t, err)
	require.True(t, appliedNewTip)
	// newBlockHash should be tip.
	require.True(t, bc.BlockTip().Hash.IsEqual(newBlockHash))
	// hash 3 should no longer be in the best chain or best chain map
	_, hash3ExistsInBestChainMap = bc.bestChainMap[*hash3]
	require.False(t, hash3ExistsInBestChainMap)
	require.False(t, checkBestChainForHash(hash3))
	// hash 2 should no longer be in the best chain or best chain map
	_, hash2ExistsInBestChainMap = bc.bestChainMap[*hash2]
	require.False(t, hash2ExistsInBestChainMap)
	require.False(t, checkBestChainForHash(hash2))
	// hash 4 should be in the best chain and the best chain map
	_, hash4ExistsInBestChainMap := bc.bestChainMap[*hash4]
	require.True(t, hash4ExistsInBestChainMap)
	require.True(t, checkBestChainForHash(hash4))
	// hash 5 should be in the best chain and the best chain map
	_, hash5ExistsInBestChainMap := bc.bestChainMap[*hash5]
	require.True(t, hash5ExistsInBestChainMap)
	require.True(t, checkBestChainForHash(hash5))

	// We have added three blocks and removed two blocks
	require.Len(t, connectedBlockHashes, 3)
	require.Len(t, disconnectedBlockHashes, 2)

	// Reset the state of the best chain.
	delete(bc.bestChainMap, *hash4)
	delete(bc.bestChainMap, *hash5)
	delete(bc.bestChainMap, *newBlockHash)
	bc.bestChain = bc.bestChain[:len(bc.bestChain)-3]

	// Add block 2 and 3 back.
	bc.addTipBlockToBestChain(bn2)
	bc.addTipBlockToBestChain(bn3)

	// No reorg tests
	// currentView > newBlock.View
	newBlockNode.Header.ProposedInView = 8

	// we should not apply the new tip if it doesn't extend the current tip.
	appliedNewTip, connectedBlockHashes, disconnectedBlockHashes, err = bc.tryApplyNewTip(newBlockNode, 9, ancestors)
	require.False(t, appliedNewTip)
	require.NoError(t, err)

	// No blocks have been removed or added.
	require.Len(t, connectedBlockHashes, 0)
	require.Len(t, disconnectedBlockHashes, 0)

	// Super Happy path: no reorg, just extending tip.
	newBlockNode.Header.ProposedInView = 10
	newBlockNode.Header.PrevBlockHash = hash3
	newBlockNode.Header.Height = 5
	newBlockNode.Height = 5
	require.NoError(t, err)
	ancestors, err = bc.getLineageFromCommittedTip(newBlock.Header)
	require.NoError(t, err)
	appliedNewTip, connectedBlockHashes, disconnectedBlockHashes, err = bc.tryApplyNewTip(newBlockNode, 6, ancestors)
	require.True(t, appliedNewTip)
	require.NoError(t, err)
	// newBlockHash should be tip.
	require.True(t, bc.BlockTip().Hash.IsEqual(newBlockHash))

	// One block has been added to the best chain.
	require.Len(t, connectedBlockHashes, 1)
	require.Len(t, disconnectedBlockHashes, 0)
}

// TestCanCommitGrandparent tests the canCommitGrandparent function
// by checking the commit rule. It ensures that the commit rule
// will be run when there is a direct parent-child relationship
// between the incoming block and its parent (no skipping views)
// and then we can commit the incoming block's grandparent.
func TestCanCommitGrandparent(t *testing.T) {
	setBalanceModelBlockHeights(t)
	bc, _, _ := NewTestBlockchain(t)
	GlobalDeSoParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 0
	resetGlobalDeSoParams := func() {
		GlobalDeSoParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = math.MaxUint32
	}
	t.Cleanup(resetGlobalDeSoParams)
	hash1 := NewBlockHash(RandomBytes(32))
	bn1 := &BlockNode{
		Hash:   hash1,
		Status: StatusBlockStored | StatusBlockValidated,
		Height: 2,
		Header: &MsgDeSoHeader{
			ProposedInView: 1,
		},
	}
	hash2 := NewBlockHash(RandomBytes(32))
	bn2 := &BlockNode{
		Hash:   hash2,
		Status: StatusBlockStored | StatusBlockValidated,
		Height: 3,
		Header: &MsgDeSoHeader{
			ProposedInView: 2,
			PrevBlockHash:  hash1,
		},
	}
	bc.bestChainMap[*hash1] = bn1
	bc.bestChainMap[*hash2] = bn2

	// define incoming block
	hash3 := NewBlockHash(RandomBytes(32))
	bn3 := &BlockNode{
		Hash:   hash3,
		Status: StatusBlockStored | StatusBlockValidated,
		Height: 4,
		Header: &MsgDeSoHeader{
			ProposedInView: 10,
			PrevBlockHash:  hash2,
		},
	}

	// If we are adding bn3 to the chain, it is an descendant of bn2
	// and bn2 and bn3 possess a direct parent-child relationship
	// (meaning they are in consecutive views). So we should be able
	// to commit bn1.
	grandparentHash, canCommit := bc.canCommitGrandparent(bn3)
	require.True(t, hash1.IsEqual(grandparentHash))
	require.True(t, canCommit)

	// Update bn1 to be committed. We no longer can run the commit since bn1 is already
	// committed. We expect committedBlockSeen to be true.
	bn1.Status |= StatusBlockCommitted
	grandparentHash, canCommit = bc.canCommitGrandparent(bn3)
	require.Nil(t, grandparentHash)
	require.False(t, canCommit)

	// revert bn1's committed status.
	bn1.Status = StatusBlockStored | StatusBlockValidated
	// Increase bn2's proposed in view, so that it is no longer a direct child of bn3.
	// We should no longer be able to commit bn1.
	bn2.Header.ProposedInView = 3
	grandparentHash, canCommit = bc.canCommitGrandparent(bn3)
	require.Nil(t, grandparentHash)
	require.False(t, canCommit)

	// TODO: What other cases do we really need tested here?
}

// TestRunCommitRuleOnBestChain tests the runCommitRuleOnBestChain function
// to verify that it properly assesses the commit rule and that the commit logic
// behaves as expected.
// It tests the following cases:
// 1. Adding a single block (block1) to the best chain does not result in any new blocks being committed.
// 2. Adding a second block (block2) w/ parent (block1) to the best chain does not result in any new blocks being committed.
// 3. Adding a third block (block3) w/ parent (block2) and block3's view = block2's view + 1 to the best chain results in block1 being committed.
// 4. Adding a fourth block (block4) w/ parent (block3) and block4's view > block3's view + 1 to the best chain results in block2 being committed.
// 5. Adding a fifth block (block5) w/ parent (block4) and block5's view = block4's view + 1 to the best chain does not result in block3 being committed.
// 6. Adding a sixth block (block6) w/ parent (block5) and block6's view = block5's view + 1 to the best chain results in block3 and block4 being committed.
func TestRunCommitRuleOnBestChain(t *testing.T) {
	testMeta := NewTestPoSBlockchainWithValidators(t)

	// Create a single block and add it to the best chain.
	blockTemplate1 := _generateBlockAndAddToBestChain(testMeta, 12, 12, 887)
	// Okay now try to run the commit rule. Nothing will happen.
	// We expect the block to be uncommitted.
	err := testMeta.chain.runCommitRuleOnBestChain(true)
	require.NoError(t, err)

	blockHash1, err := blockTemplate1.Hash()
	require.NoError(t, err)
	// Okay so let's make sure the block is uncommitted.
	_verifyCommitRuleHelper(testMeta, []*BlockHash{}, []*BlockHash{blockHash1}, nil)

	// Add one more block to best chain. Should still not trigger commit rule
	blockTemplate2 := _generateBlockAndAddToBestChain(testMeta, 13, 13, 813)

	// Run commit rule again. Nothing should happen.
	// We expect both block 1 and block 2 to be uncommitted.
	err = testMeta.chain.runCommitRuleOnBestChain(true)
	require.NoError(t, err)

	blockHash2, err := blockTemplate2.Hash()
	require.NoError(t, err)
	// Okay so let's make sure blocks 1 and 2 are uncommitted.
	_verifyCommitRuleHelper(testMeta, []*BlockHash{}, []*BlockHash{blockHash1, blockHash2}, nil)

	// Okay add one MORE block to the best chain. This should trigger the commit rule.
	blockTemplate3 := _generateBlockAndAddToBestChain(testMeta, 14, 14, 513)

	// Run the commit rule again. This time we expect block 1 to be committed.
	err = testMeta.chain.runCommitRuleOnBestChain(true)
	require.NoError(t, err)

	blockHash3, err := blockTemplate3.Hash()
	require.NoError(t, err)

	// Okay so let's make sure that block 1 is committed and blocks 2 and 3 are not.
	_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1}, []*BlockHash{blockHash2, blockHash3}, blockHash1)

	// Add one more block to the best chain, but have the view be further in the future.
	// this should trigger a commit on block 2.
	blockTemplate4 := _generateBlockAndAddToBestChain(testMeta, 14, 20, 429)
	err = testMeta.chain.runCommitRuleOnBestChain(true)
	require.NoError(t, err)

	blockHash4, err := blockTemplate4.Hash()
	require.NoError(t, err)

	// Blocks 1 and 2 should be committed, blocks 3 and 4 are not.
	_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1, blockHash2}, []*BlockHash{blockHash3, blockHash4}, blockHash2)

	// Okay so add block 5 to the best chain. This should NOT trigger a commit on block 3
	// as block 4 is not a direct child of block 3 based on its view.
	blockTemplate5 := _generateBlockAndAddToBestChain(testMeta, 15, 21, 654)
	err = testMeta.chain.runCommitRuleOnBestChain(true)
	require.NoError(t, err)

	blockHash5, err := blockTemplate5.Hash()
	require.NoError(t, err)

	// Blocks 1 and 2 are committed, blocks 3, 4, and 5 are not.
	_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1, blockHash2}, []*BlockHash{blockHash3, blockHash4, blockHash5}, blockHash2)

	// If we now add a block that is a descendent of block 5, we should be able to commit
	// blocks 3 and 4 as block 4 and 5 possess a direct parent child relationship and
	// we have a descendent of block 5.
	blockTemplate6 := _generateBlockAndAddToBestChain(testMeta, 16, 22, 912)
	require.NoError(t, err)
	err = testMeta.chain.runCommitRuleOnBestChain(true)
	require.NoError(t, err)

	blockHash6, err := blockTemplate6.Hash()
	require.NoError(t, err)

	// Blocks 1, 2, 3, and 4 are committed, blocks 5 and 6 are not.
	_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1, blockHash2, blockHash3, blockHash4}, []*BlockHash{blockHash5, blockHash6}, blockHash4)
}

// _verifyCommitRuleHelper is a helper function that verifies the state of the blockchain
// by checking the best chain, best chain map, and DB to make sure that the expected blocks
// are committed or uncommitted and that the TipHash is correct.
func _verifyCommitRuleHelper(testMeta *TestMeta, committedBlocks []*BlockHash, uncommittedBlocks []*BlockHash, bestHash *BlockHash) {
	if bestHash != nil {
		// Verify the best hash in the db.
		dbBestHash := DbGetBestHash(testMeta.chain.db, testMeta.chain.snapshot, ChainTypeDeSoBlock)
		require.True(testMeta.t, bestHash.IsEqual(dbBestHash))
	}
	for _, committedHash := range committedBlocks {
		// Okay so let's make sure the block is committed.
		blockNode, exists := testMeta.chain.bestChainMap[*committedHash]
		require.True(testMeta.t, exists)
		require.True(testMeta.t, blockNode.IsCommitted())

		// Block should be in DB.
		fullBlock, err := GetBlock(blockNode.Hash, testMeta.chain.db, testMeta.chain.snapshot)
		require.NoError(testMeta.t, err)
		require.NotNil(testMeta.t, fullBlock)
		// Height Hash To Node Info should be in DB.
		heightHashToNodeInfo := GetHeightHashToNodeInfo(testMeta.chain.db, testMeta.chain.snapshot, blockNode.Height, blockNode.Hash, false)
		require.NoError(testMeta.t, err)
		require.NotNil(testMeta.t, heightHashToNodeInfo)
		// Make sure this info matches the block node.
		serializedDBBlockNode, err := SerializeBlockNode(heightHashToNodeInfo)
		require.NoError(testMeta.t, err)
		serializedBlockNode, err := SerializeBlockNode(blockNode)
		require.NoError(testMeta.t, err)
		require.True(testMeta.t, bytes.Equal(serializedDBBlockNode, serializedBlockNode))
		utxoOps, err := GetUtxoOperationsForBlock(testMeta.chain.db, testMeta.chain.snapshot, blockNode.Hash)
		require.NoError(testMeta.t, err)
		// We have 1 utxo op slice for each transaction PLUS 1 for expired nonces.
		require.Len(testMeta.t, utxoOps, len(fullBlock.Txns)+1)
	}
	for _, uncommittedBlockHash := range uncommittedBlocks {
		// Okay so let's make sure the block is uncommitted.
		blockNode, exists := testMeta.chain.bestChainMap[*uncommittedBlockHash]
		require.True(testMeta.t, exists)
		require.False(testMeta.t, blockNode.IsCommitted())
		// TODO: Verify DB results?? Kinda silly to make sure everything is missing.
	}
	utxoView, err := testMeta.chain.GetUncommittedTipView()
	require.NoError(testMeta.t, err)
	currentEpoch, err := utxoView.GetCurrentEpochEntry()
	require.NoError(testMeta.t, err)
	currentEpochNumber := currentEpoch.EpochNumber
	prevEpoch, err := utxoView.simulatePrevEpochEntry(currentEpochNumber, currentEpoch.InitialBlockHeight)
	require.NoError(testMeta.t, err)
	prevEpochNumber := prevEpoch.EpochNumber
	for pubKeyString := range testMeta.pubKeyToBLSKeyMap {
		publicKeyBytes := MustBase58CheckDecode(pubKeyString)
		validatorEntry, err := utxoView.GetValidatorByPublicKey(NewPublicKey(publicKeyBytes))
		require.NoError(testMeta.t, err)
		// Validator should be active in either the last epoch or the current epoch
		// since the epoch turns over at every other block.
		require.True(testMeta.t, validatorEntry.LastActiveAtEpochNumber == prevEpochNumber ||
			validatorEntry.LastActiveAtEpochNumber == currentEpochNumber)
	}
}

// _verifyRandomSeedHashHelper is a helper function that verifies the random seed hash is set
// after connecting a new tip block.
func _verifyRandomSeedHashHelper(testMeta *TestMeta, tipBlock *MsgDeSoBlock) {
	// Get the utxo view for the tip block.
	utxoView, err := testMeta.chain.GetUncommittedTipView()
	require.NoError(testMeta.t, err)
	// Verify that the random seed hash is set.
	randomSeedHash, err := utxoView.GetCurrentRandomSeedHash()
	require.NoError(testMeta.t, err)

	// Verify that the random seed hash is set based on the random seed signature on the block.
	expectedRandomSeedHash, err := HashRandomSeedSignature(tipBlock.Header.ProposerRandomSeedSignature)
	require.NoError(testMeta.t, err)
	require.True(testMeta.t, expectedRandomSeedHash.Eq(randomSeedHash))
}

func TestProcessHeaderPoS(t *testing.T) {
	// Initialize the chain and test metadata.
	testMeta := NewTestPoSBlockchainWithValidators(t)

	// Capture the starting block height, view, and block hash for the best chain and best header chain.
	initialBlockHeight := testMeta.chain.BlockTip().Height
	initialView := testMeta.chain.BlockTip().Header.ProposedInView
	initialBlockHash := testMeta.chain.BlockTip().Hash

	initialHeaderHeight := testMeta.chain.HeaderTip().Height
	initialHeaderView := testMeta.chain.HeaderTip().Header.ProposedInView
	initialHeaderHash := testMeta.chain.HeaderTip().Hash

	require.Equal(t, initialBlockHeight, initialHeaderHeight)
	require.Equal(t, initialView, initialHeaderView)
	require.True(t, initialBlockHash.IsEqual(initialHeaderHash))

	// Run the ProcessBlockPoS tests end to end. ProcessHeaderPoS is called within ProcessBlockPoS.
	// The header chain should progress identically to the block chain, and it should reorg when then
	// block chain reorgs.
	testProcessBlockPoS(t, testMeta)

	// Capture the final block height, view, and block hash for the best chain and best header chain.
	finalBlockHeight := testMeta.chain.BlockTip().Height
	finalView := testMeta.chain.BlockTip().Header.ProposedInView
	finalBlockHash := testMeta.chain.BlockTip().Hash

	finalHeaderHeight := testMeta.chain.HeaderTip().Height
	finalHeaderView := testMeta.chain.HeaderTip().Header.ProposedInView
	finalHeaderHash := testMeta.chain.HeaderTip().Hash

	require.Equal(t, finalBlockHeight, finalHeaderHeight)
	require.Equal(t, finalView, finalHeaderView)
	require.True(t, finalBlockHash.IsEqual(finalHeaderHash))

	// Verify that the header chain has advanced from the initial state.
	require.Greater(t, finalBlockHeight, initialBlockHeight)
	require.Greater(t, finalView, initialView)
	require.False(t, finalBlockHash.IsEqual(initialBlockHash))
}

func TestProcessBlockPoS(t *testing.T) {
	testProcessBlockPoS(t, NewTestPoSBlockchainWithValidators(t))
}

// Test the following series of blocks to make sure that ProcessBlockPoS properly handles all cases as expected during the steady state
// 1. Process a bad block. The block could be bad for any reason, we don't really care the reason, we just want to see it get rejected.
// 2. Process three good blocks in a row, which tests the commit rule
// 3. Process a timeout block that reorgs the previous tip
// 4. Process a regular block that reorgs from the previous tip
// 5. Process an orphan, which tests the block's storage and the return value of missingBlockHashes
func testProcessBlockPoS(t *testing.T, testMeta *TestMeta) {
	{
		// Create a bad block and try to process it.
		dummyBlock := _generateDummyBlock(testMeta, 12, 12, 887)
		success, isOrphan, missingBlockHashes, err := testMeta.chain.ProcessBlockPoS(dummyBlock, 12, true)
		require.False(t, success)
		require.False(t, isOrphan)
		require.Len(t, missingBlockHashes, 0)
		require.Error(t, err)
	}

	var blockHash1 *BlockHash
	{
		var realBlock *MsgDeSoBlock
		realBlock = _generateRealBlock(testMeta, 12, 12, 889, testMeta.chain.BlockTip().Hash, false)
		success, isOrphan, missingBlockHashes, err := testMeta.chain.ProcessBlockPoS(realBlock, 12, true)
		require.True(t, success)
		require.False(t, isOrphan)
		require.Len(t, missingBlockHashes, 0)
		require.NoError(t, err)

		// Okay now we can check the best chain.
		// We expect the block to be uncommitted.
		blockHash1, err = realBlock.Hash()
		require.NoError(t, err)
		_verifyCommitRuleHelper(testMeta, []*BlockHash{}, []*BlockHash{blockHash1}, nil)
		_verifyRandomSeedHashHelper(testMeta, realBlock)
	}

	var blockHash2, blockHash3, futureBlockHash *BlockHash
	{
		// Now let's try adding two more blocks on top of this one to make sure commit rule works properly.
		var realBlock2 *MsgDeSoBlock
		realBlock2 = _generateRealBlock(testMeta, 13, 13, 950, blockHash1, false)
		success, _, _, err := testMeta.chain.ProcessBlockPoS(realBlock2, 13, true)
		require.True(t, success)
		blockHash2, err = realBlock2.Hash()
		require.NoError(t, err)

		var realBlock3 *MsgDeSoBlock
		realBlock3 = _generateRealBlock(testMeta, 14, 14, 378, blockHash2, false)

		success, _, _, err = testMeta.chain.ProcessBlockPoS(realBlock3, 14, true)
		require.True(t, success)
		// Okay now we expect blockHash1 to be committed, but blockHash2 and 3 to not be committed.
		blockHash3, err = realBlock3.Hash()
		require.NoError(t, err)

		_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1}, []*BlockHash{blockHash2, blockHash3}, blockHash1)
		_verifyRandomSeedHashHelper(testMeta, realBlock3)

		// Now let's try adding a block that has a timestamp too far in the future, and make sure it's stored.
		var futureBlock *MsgDeSoBlock
		futureBlock = _generateRealBlockWithTimestampOffset(testMeta, 15, 15, 870, blockHash3, false, time.Hour)

		success, isOrphan, missingBlockHashes, err := testMeta.chain.ProcessBlockPoS(futureBlock, 15, true)
		require.False(t, success)
		require.False(t, isOrphan)
		require.Len(t, missingBlockHashes, 0)
		require.Error(t, err)

		futureBlockHash, err = futureBlock.Hash()
		require.NoError(t, err)

		futureBlockNode, exists := testMeta.chain.blockIndexByHash[*futureBlockHash]
		require.True(t, exists)
		require.False(t, futureBlockNode.IsCommitted())
		require.True(t, futureBlockNode.IsStored())
		require.False(t, futureBlockNode.IsValidated())
		require.False(t, futureBlockNode.IsValidateFailed())
	}

	var timeoutBlockHash *BlockHash
	{
		// Okay let's timeout view 15
		var timeoutBlock *MsgDeSoBlock
		timeoutBlock = _generateRealBlock(testMeta, 15, 16, 381, blockHash3, true)
		success, _, _, err := testMeta.chain.ProcessBlockPoS(timeoutBlock, 15, true)
		fmt.Println(err)
		require.True(t, success)
		timeoutBlockHash, err = timeoutBlock.Hash()
		require.NoError(t, err)

		_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1, blockHash2}, []*BlockHash{blockHash3, timeoutBlockHash}, blockHash2)
	}

	var reorgBlockHash *BlockHash
	{
		// Okay let's introduce a reorg. New block at view 15 with block 3 as its parent.
		var reorgBlock *MsgDeSoBlock
		reorgBlock = _generateRealBlock(testMeta, 15, 15, 373, blockHash3, false)
		success, _, _, err := testMeta.chain.ProcessBlockPoS(reorgBlock, 15, true)
		require.True(t, success)
		reorgBlockHash, err = reorgBlock.Hash()
		require.NoError(t, err)
		// We expect blockHash1 and blockHash2 to be committed, but blockHash3 and reorgBlockHash to not be committed.
		// Timeout block will no longer be in best chain, and will still be in an uncommitted state in the block index
		_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1, blockHash2}, []*BlockHash{blockHash3, reorgBlockHash}, blockHash2)
		_verifyRandomSeedHashHelper(testMeta, reorgBlock)
		_, exists := testMeta.chain.bestChainMap[*timeoutBlockHash]
		require.False(t, exists)

		timeoutBlockNode, exists := testMeta.chain.blockIndexByHash[*timeoutBlockHash]
		require.True(t, exists)
		require.False(t, timeoutBlockNode.IsCommitted())
	}
	var dummyParentBlockHash, orphanBlockHash *BlockHash
	{
		// Let's process an orphan block.
		var dummyParentBlock *MsgDeSoBlock
		var err error
		dummyParentBlock = _generateRealBlock(testMeta, 16, 16, 272, reorgBlockHash, false)
		dummyParentBlockHash, err = dummyParentBlock.Hash()
		require.NoError(t, err)
		var orphanBlock *MsgDeSoBlock
		orphanBlock = _generateRealBlock(testMeta, 17, 17, 9273, reorgBlockHash, false)
		updateRandomSeedSignature(testMeta, orphanBlock, dummyParentBlock.Header.ProposerRandomSeedSignature)
		// Set the prev block hash manually on orphan block
		orphanBlock.Header.PrevBlockHash = dummyParentBlockHash
		// Create a QC on the dummy parent block
		orphanBlock.Header.ValidatorsVoteQC = _getVoteQC(testMeta, orphanBlock.Header.Height, dummyParentBlockHash, 16)
		updateProposerVotePartialSignatureForBlock(testMeta, orphanBlock)
		orphanBlockHash, err = orphanBlock.Hash()
		require.NoError(t, err)
		success, isOrphan, missingBlockHashes, err := testMeta.chain.ProcessBlockPoS(orphanBlock, 17, true)
		require.False(t, success)
		require.True(t, isOrphan)
		require.Len(t, missingBlockHashes, 1)
		require.True(t, missingBlockHashes[0].IsEqual(dummyParentBlockHash))
		require.NoError(t, err)
		orphanBlockInIndex := testMeta.chain.blockIndexByHash[*orphanBlockHash]
		require.NotNil(t, orphanBlockInIndex)
		require.True(t, orphanBlockInIndex.IsStored())
		require.False(t, orphanBlockInIndex.IsValidated())

		// Okay now if we process the parent block, the orphan should get updated to be validated.
		success, isOrphan, missingBlockHashes, err = testMeta.chain.ProcessBlockPoS(dummyParentBlock, 16, true)
		require.True(t, success)
		require.False(t, isOrphan)
		require.Len(t, missingBlockHashes, 0)
		require.NoError(t, err)

		orphanBlockInIndex = testMeta.chain.blockIndexByHash[*orphanBlockHash]
		require.NotNil(t, orphanBlockInIndex)
		require.True(t, orphanBlockInIndex.IsStored())
		require.True(t, orphanBlockInIndex.IsValidated())
		_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1, blockHash2, blockHash3, reorgBlockHash},
			[]*BlockHash{dummyParentBlockHash, orphanBlockHash}, reorgBlockHash)
	}
	{
		// Let's process a block that is an orphan, but is malformed.
		randomHash := NewBlockHash(RandomBytes(32))
		var malformedOrphanBlock *MsgDeSoBlock
		malformedOrphanBlock = _generateRealBlock(testMeta, 18, 18, 9273, testMeta.chain.BlockTip().Hash, false)
		malformedOrphanBlock.Header.PrevBlockHash = randomHash
		// Resign the block.
		updateProposerVotePartialSignatureForBlock(testMeta, malformedOrphanBlock)
		malformedOrphanBlockHash, err := malformedOrphanBlock.Hash()
		require.NoError(t, err)
		success, isOrphan, missingBlockHashes, err := testMeta.chain.ProcessBlockPoS(malformedOrphanBlock, 18, true)
		require.False(t, success)
		require.True(t, isOrphan)
		require.Len(t, missingBlockHashes, 1)
		require.True(t, missingBlockHashes[0].IsEqual(randomHash))
		require.NoError(t, err)

		malformedOrphanBlockInIndex := testMeta.chain.blockIndexByHash[*malformedOrphanBlockHash]
		require.True(t, malformedOrphanBlockInIndex.IsValidateFailed())
		require.True(t, malformedOrphanBlockInIndex.IsStored())

		// If a block can't be hashed, we expect to get an error.
		success, isOrphan, missingBlockHashes, err = testMeta.chain.ProcessBlockPoS(malformedOrphanBlock, 18, true)
		require.False(t, success)
		require.False(t, isOrphan)
		require.Len(t, missingBlockHashes, 0)
		require.Error(t, err)
	}
	var blockWithFailingTxnHash *BlockHash
	{
		var blockWithFailingTxn *MsgDeSoBlock
		blockWithFailingTxn = _generateRealBlockWithFailingTxn(testMeta, 18, 18, 123722, orphanBlockHash, false, 1, 0)
		success, _, _, err := testMeta.chain.ProcessBlockPoS(blockWithFailingTxn, 18, true)
		require.True(t, success)
		blockWithFailingTxnHash, err = blockWithFailingTxn.Hash()
		require.NoError(t, err)
		_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1, blockHash2, blockHash3, reorgBlockHash, dummyParentBlockHash},
			[]*BlockHash{orphanBlockHash, blockWithFailingTxnHash}, dummyParentBlockHash)
	}
}

// TestGetSafeBlocks tests the GetSafeBlocks function to make sure it returns the correct blocks.
// It adds three blocks as Validated and Stored to the block index, each referencing the previous
// block as its parent and adds one block as Stored with the same height as the third block, but not validated.
// Also, we add a block with a block height in the future to make sure it is not returned.
// First, we expect that all three Validated & Stored blocks are returned as safe blocks and
// the Stored block is not returned.
// Next, we update the previously stored block to be validated and expect it to be returned.
func TestGetSafeBlocks(t *testing.T) {
	testMeta := NewTestPoSBlockchainWithValidators(t)
	committedHash := testMeta.chain.BlockTip().Hash
	var block1 *MsgDeSoBlock
	block1 = _generateRealBlock(testMeta, uint64(testMeta.savedHeight), uint64(testMeta.savedHeight), 1723, committedHash, false)
	block1Hash, err := block1.Hash()
	require.NoError(t, err)
	// Add block 1 w/ stored and validated
	bn1, err := testMeta.chain.storeValidatedBlockInBlockIndex(block1)
	require.NoError(t, err)
	require.True(t, bn1.Hash.IsEqual(block1Hash))
	// Create block 2 w/ block 1 as parent and add it to the block index w/ stored & validated
	var block2 *MsgDeSoBlock
	block2 = _generateRealBlock(testMeta, uint64(testMeta.savedHeight+1), uint64(testMeta.savedHeight+1), 1293, block1Hash, false)
	block2Hash, err := block2.Hash()
	require.NoError(t, err)
	bn2, err := testMeta.chain.storeValidatedBlockInBlockIndex(block2)
	require.NoError(t, err)
	require.True(t, bn2.Hash.IsEqual(block2Hash))
	// Add block 3 only as stored and validated
	var block3 *MsgDeSoBlock
	block3 = _generateRealBlock(testMeta, uint64(testMeta.savedHeight+2), uint64(testMeta.savedHeight+2), 1372, block2Hash, false)
	bn3, err := testMeta.chain.storeValidatedBlockInBlockIndex(block3)
	require.NoError(t, err)
	block3Hash, err := block3.Hash()
	require.NoError(t, err)
	require.True(t, bn3.Hash.IsEqual(block3Hash))
	// Add block 3' only as stored
	var block3Prime *MsgDeSoBlock
	block3Prime = _generateRealBlock(testMeta, uint64(testMeta.savedHeight+2), uint64(testMeta.savedHeight+3), 137175, block2Hash, false)
	bn3Prime, err := testMeta.chain.storeBlockInBlockIndex(block3Prime)
	require.NoError(t, err)
	block3PrimeHash, err := block3Prime.Hash()
	require.NoError(t, err)
	require.True(t, bn3Prime.Hash.IsEqual(block3PrimeHash))
	// Add block 5 as Stored & Validated (this could never really happen, but it illustrates a point!)
	var block5 *MsgDeSoBlock
	block5 = _generateRealBlock(testMeta, uint64(testMeta.savedHeight+4), uint64(testMeta.savedHeight+4), 1237, block3Hash, false)
	block5.Header.Height = uint64(testMeta.savedHeight + 5)
	block5Hash, err := block5.Hash()
	require.NoError(t, err)
	_, err = testMeta.chain.storeValidatedBlockInBlockIndex(block5)
	require.NoError(t, err)
	// Okay let's get the safe blocks.
	safeBlocks, err := testMeta.chain.GetSafeBlocks()
	require.NoError(t, err)
	require.Len(t, safeBlocks, 4)
	_checkSafeBlocksForBlockHash := func(blockHash *BlockHash, safeBlockSlice []*MsgDeSoHeader) bool {
		return collections.Any(safeBlockSlice, func(header *MsgDeSoHeader) bool {
			headerHash, err := header.Hash()
			require.NoError(t, err)
			return headerHash.IsEqual(blockHash)
		})
	}
	require.True(t, _checkSafeBlocksForBlockHash(committedHash, safeBlocks))
	require.True(t, _checkSafeBlocksForBlockHash(block1Hash, safeBlocks))
	require.True(t, _checkSafeBlocksForBlockHash(block2Hash, safeBlocks))
	require.True(t, _checkSafeBlocksForBlockHash(block3Hash, safeBlocks))
	require.False(t, _checkSafeBlocksForBlockHash(block3PrimeHash, safeBlocks))
	require.False(t, _checkSafeBlocksForBlockHash(block5Hash, safeBlocks))

	// Update block 3 prime to be validated and it should now be a safe block.
	bn3Prime, err = testMeta.chain.storeValidatedBlockInBlockIndex(block3Prime)
	require.NoError(t, err)
	require.True(t, bn3Prime.IsValidated())
	safeBlocks, err = testMeta.chain.GetSafeBlocks()
	require.NoError(t, err)
	require.Len(t, safeBlocks, 5)
	require.True(t, _checkSafeBlocksForBlockHash(block3PrimeHash, safeBlocks))
}

// TestProcessOrphanBlockPoS tests the ProcessOrphanBlockPoS function to make sure it properly handles
// marking orphan blocks as Validate Failed if they are truly invalid. Note that orphan blocks will
// never be marked Validated.
func TestProcessOrphanBlockPoS(t *testing.T) {
	testMeta := NewTestPoSBlockchainWithValidators(t)

	// Generate a real block and make sure it doesn't hit any errors.
	{
		var realBlock *MsgDeSoBlock
		realBlock = _generateRealBlock(testMeta, 12, 12, 889, testMeta.chain.BlockTip().Hash, false)
		// Give the block a random parent, so it is truly an orphan.
		realBlock.Header.PrevBlockHash = NewBlockHash(RandomBytes(32))
		updateProposerVotePartialSignatureForBlock(testMeta, realBlock)
		err := testMeta.chain.processOrphanBlockPoS(realBlock)
		require.NoError(t, err)
		// Get the block node from the block index.
		blockHash, err := realBlock.Hash()
		require.NoError(t, err)
		blockNode, exists := testMeta.chain.blockIndexByHash[*blockHash]
		require.True(t, exists)
		require.True(t, blockNode.IsStored())
		require.False(t, blockNode.IsValidateFailed())
		require.False(t, blockNode.IsValidated())
	}
	// Generate a real block and make some modification to the block to make it malformed.
	{
		var realBlock *MsgDeSoBlock
		realBlock = _generateRealBlock(testMeta, 12, 12, 8172, testMeta.chain.BlockTip().Hash, false)
		// Give the block a random parent, so it is truly an orphan.
		realBlock.Header.PrevBlockHash = NewBlockHash(RandomBytes(32))
		// Set the header version to 1
		realBlock.Header.Version = 1
		updateProposerVotePartialSignatureForBlock(testMeta, realBlock)
		// There should be no error, but the block should be marked as ValidateFailed.
		err := testMeta.chain.processOrphanBlockPoS(realBlock)
		require.NoError(t, err)
		// Get the block node from the block index.
		blockHash, err := realBlock.Hash()
		require.NoError(t, err)
		blockNode, exists := testMeta.chain.blockIndexByHash[*blockHash]
		require.True(t, exists)
		require.True(t, blockNode.IsStored())
		require.True(t, blockNode.IsValidateFailed())
		require.False(t, blockNode.IsValidated())
	}
	// Generate a real block in this epoch and change the block proposer. This should fail the spam prevention check
	// and the block will not be in the block index.
	{
		var realBlock *MsgDeSoBlock
		realBlock = _generateRealBlock(testMeta, 12, 12, 1273, testMeta.chain.BlockTip().Hash, false)
		// Give the block a random parent, so it is truly an orphan.
		realBlock.Header.PrevBlockHash = NewBlockHash(RandomBytes(32))
		// Just make sure we're in the same epoch.
		utxoView := _newUtxoView(testMeta)
		currentEpochEntry, err := utxoView.GetCurrentEpochEntry()
		require.NoError(t, err)
		require.True(t, currentEpochEntry.ContainsBlockHeight(12))
		// Change the block proposer to some any other validator's public key.
		realBlock.Header.ProposerVotingPublicKey = _generateRandomBLSPrivateKey(t).PublicKey()
		updateProposerVotePartialSignatureForBlock(testMeta, realBlock)
		// There should be no error, but the block should be marked as ValidateFailed.
		err = testMeta.chain.processOrphanBlockPoS(realBlock)
		require.NoError(t, err)
		// Get the block node from the block index.
		blockHash, err := realBlock.Hash()
		require.NoError(t, err)
		_, exists := testMeta.chain.blockIndexByHash[*blockHash]
		require.False(t, exists)
	}

	// Generate a real block in this epoch and update the QC to not have a supermajority.
	// This fails the spam prevention check and the block will not be in the block index.
	{
		var realBlock *MsgDeSoBlock
		realBlock = _generateRealBlock(testMeta, 12, 12, 543, testMeta.chain.BlockTip().Hash, false)
		// Give the block a random parent, so it is truly an orphan.
		realBlock.Header.PrevBlockHash = NewBlockHash(RandomBytes(32))
		// Just make sure we're in the same epoch.
		utxoView := _newUtxoView(testMeta)
		currentEpochEntry, err := utxoView.GetCurrentEpochEntry()
		require.NoError(t, err)
		require.True(t, currentEpochEntry.ContainsBlockHeight(12))
		// Update the QC to not have a supermajority.
		// Get all the bls keys for the validators that aren't the leader.
		signersList := bitset.NewBitset()
		var signatures []*bls.Signature
		require.NoError(testMeta.t, err)
		votePayload := consensus.GetVoteSignaturePayload(11, testMeta.chain.BlockTip().Hash)
		allSnapshotValidators, err := utxoView.GetAllSnapshotValidatorSetEntriesByStake()
		require.NoError(t, err)
		// Only have m0 sign it. m0 has significantly less than 2/3 of the stake.
		m0PKID := utxoView.GetPKIDForPublicKey(m0PkBytes).PKID
		for ii, validatorEntry := range allSnapshotValidators {
			if !validatorEntry.ValidatorPKID.Eq(m0PKID) {
				continue
			}
			validatorPublicKeyBytes := utxoView.GetPublicKeyForPKID(validatorEntry.ValidatorPKID)
			validatorPublicKey := Base58CheckEncode(validatorPublicKeyBytes, false, testMeta.chain.params)
			validatorBLSPrivateKey := testMeta.pubKeyToBLSKeyMap[validatorPublicKey]
			sig, err := validatorBLSPrivateKey.Sign(votePayload[:])
			require.NoError(testMeta.t, err)
			signatures = append(signatures, sig)
			signersList = signersList.Set(ii, true)
		}
		// Create the aggregated signature.
		aggregatedSignature, err := bls.AggregateSignatures(signatures)
		require.NoError(testMeta.t, err)
		realBlock.Header.ValidatorsVoteQC.ValidatorsVoteAggregatedSignature = &AggregatedBLSSignature{
			SignersList: signersList,
			Signature:   aggregatedSignature,
		}
		updateProposerVotePartialSignatureForBlock(testMeta, realBlock)
		// There should be no error, but the block should be marked as ValidateFailed.
		err = testMeta.chain.processOrphanBlockPoS(realBlock)
		require.NoError(t, err)
		// Get the block node from the block index.
		blockHash, err := realBlock.Hash()
		require.NoError(t, err)
		_, exists := testMeta.chain.blockIndexByHash[*blockHash]
		require.False(t, exists)
	}
	{
		// Generate a real block in the next epoch and it should pass validation and be stored.
		utxoView := _newUtxoView(testMeta)
		currentEpochEntry, err := utxoView.GetCurrentEpochEntry()
		require.NoError(t, err)
		var nextEpochBlock *MsgDeSoBlock
		nextEpochBlock = _generateRealBlock(testMeta, currentEpochEntry.FinalBlockHeight+1, currentEpochEntry.FinalBlockHeight+1, 23, testMeta.chain.BlockTip().Hash, false)
		// Give the block a random parent, so it is truly an orphan.
		nextEpochBlock.Header.PrevBlockHash = NewBlockHash(RandomBytes(32))
		updateProposerVotePartialSignatureForBlock(testMeta, nextEpochBlock)
		err = testMeta.chain.processOrphanBlockPoS(nextEpochBlock)
		require.NoError(t, err)
		// Get the block node from the block index.
		blockHash, err := nextEpochBlock.Hash()
		require.NoError(t, err)
		blockNode, exists := testMeta.chain.blockIndexByHash[*blockHash]
		require.True(t, exists)
		require.True(t, blockNode.IsStored())
		require.False(t, blockNode.IsValidateFailed())
		require.False(t, blockNode.IsValidated())
	}
	{
		// Generate a real block in the next epoch and make the block proposer any public key not in
		// the validator set. This should fail the spam prevention check and the block will not be in the block index.
		utxoView := _newUtxoView(testMeta)
		currentEpochEntry, err := utxoView.GetCurrentEpochEntry()
		require.NoError(t, err)
		var nextEpochBlock *MsgDeSoBlock
		nextEpochBlock = _generateRealBlock(testMeta, currentEpochEntry.FinalBlockHeight+1, currentEpochEntry.FinalBlockHeight+1, 17283, testMeta.chain.BlockTip().Hash, false)
		// Give the block a random parent, so it is truly an orphan.
		nextEpochBlock.Header.PrevBlockHash = NewBlockHash(RandomBytes(32))
		// Change the block proposer to a random BLS public key.
		nextEpochBlock.Header.ProposerVotingPublicKey = _generateRandomBLSPrivateKey(t).PublicKey()
		updateProposerVotePartialSignatureForBlock(testMeta, nextEpochBlock)
		// There should be no error, but the block should be marked as ValidateFailed.
		err = testMeta.chain.processOrphanBlockPoS(nextEpochBlock)
		require.NoError(t, err)
		// Get the block node from the block index.
		blockHash, err := nextEpochBlock.Hash()
		require.NoError(t, err)
		_, exists := testMeta.chain.blockIndexByHash[*blockHash]
		require.False(t, exists)
	}
	{
		// Generate a real block in the next epoch and update the QC to not have a supermajority.
		utxoView := _newUtxoView(testMeta)
		currentEpochEntry, err := utxoView.GetCurrentEpochEntry()
		require.NoError(t, err)
		var nextEpochBlock *MsgDeSoBlock
		nextEpochBlock = _generateRealBlock(testMeta, currentEpochEntry.FinalBlockHeight+1, currentEpochEntry.FinalBlockHeight+1, 3178, testMeta.chain.BlockTip().Hash, false)
		// Give the block a random parent, so it is truly an orphan.
		nextEpochBlock.Header.PrevBlockHash = NewBlockHash(RandomBytes(32))
		updateProposerVotePartialSignatureForBlock(testMeta, nextEpochBlock)
		// Update the QC to not have a supermajority.
		err = testMeta.chain.processOrphanBlockPoS(nextEpochBlock)
		require.NoError(t, err)
		// Update the QC to not have a supermajority.
		// Get all the bls keys for the validators that aren't the leader.
		signersList := bitset.NewBitset()
		var signatures []*bls.Signature
		require.NoError(testMeta.t, err)
		votePayload := consensus.GetVoteSignaturePayload(currentEpochEntry.FinalBlockHeight, testMeta.chain.BlockTip().Hash)
		allSnapshotValidators, err := utxoView.GetAllSnapshotValidatorSetEntriesByStake()
		require.NoError(t, err)
		// Only have m0 sign it. m0 has significantly less than 2/3 of the stake.
		m0PKID := utxoView.GetPKIDForPublicKey(m0PkBytes).PKID
		for ii, validatorEntry := range allSnapshotValidators {
			if !validatorEntry.ValidatorPKID.Eq(m0PKID) {
				continue
			}
			validatorPublicKeyBytes := utxoView.GetPublicKeyForPKID(validatorEntry.ValidatorPKID)
			validatorPublicKey := Base58CheckEncode(validatorPublicKeyBytes, false, testMeta.chain.params)
			validatorBLSPrivateKey := testMeta.pubKeyToBLSKeyMap[validatorPublicKey]
			sig, err := validatorBLSPrivateKey.Sign(votePayload[:])
			require.NoError(testMeta.t, err)
			signatures = append(signatures, sig)
			signersList = signersList.Set(ii, true)
		}
		// Create the aggregated signature.
		aggregatedSignature, err := bls.AggregateSignatures(signatures)
		require.NoError(testMeta.t, err)
		nextEpochBlock.Header.ValidatorsVoteQC.ValidatorsVoteAggregatedSignature = &AggregatedBLSSignature{
			SignersList: signersList,
			Signature:   aggregatedSignature,
		}
		updateProposerVotePartialSignatureForBlock(testMeta, nextEpochBlock)
		err = testMeta.chain.processOrphanBlockPoS(nextEpochBlock)
		require.NoError(t, err)
		// Get the block node from the block index.
		blockHash, err := nextEpochBlock.Hash()
		require.NoError(t, err)
		_, exists := testMeta.chain.blockIndexByHash[*blockHash]
		require.False(t, exists)
	}
	{
		// Generate a block that is two epochs in the future. We won't even store this.
		utxoView := _newUtxoView(testMeta)
		currentEpochEntry, err := utxoView.GetCurrentEpochEntry()
		require.NoError(t, err)
		nextEpochEntry, err := utxoView.computeNextEpochEntry(currentEpochEntry.EpochNumber, currentEpochEntry.FinalBlockHeight, currentEpochEntry.FinalBlockHeight, 1)
		require.NoError(t, err)
		var twoEpochsInFutureBlock *MsgDeSoBlock
		twoEpochsInFutureBlock = _generateRealBlock(testMeta, nextEpochEntry.FinalBlockHeight+1, nextEpochEntry.FinalBlockHeight+1, 17283, testMeta.chain.BlockTip().Hash, false)
		// Give the block a random parent, so it is truly an orphan.
		twoEpochsInFutureBlock.Header.PrevBlockHash = NewBlockHash(RandomBytes(32))
		updateProposerVotePartialSignatureForBlock(testMeta, twoEpochsInFutureBlock)
		// We should get an error that this block is too far in the future.
		err = testMeta.chain.processOrphanBlockPoS(twoEpochsInFutureBlock)
		require.Error(t, err)
		// The block shouldn't be in the block index.
		blockHash, err := twoEpochsInFutureBlock.Hash()
		require.NoError(t, err)
		_, exists := testMeta.chain.blockIndexByHash[*blockHash]
		require.False(t, exists)
	}
	{
		// Generate a block that is in the previous epoch. We should store this.
		utxoView := _newUtxoView(testMeta)
		currentEpochEntry, err := utxoView.GetCurrentEpochEntry()
		require.NoError(t, err)
		prevEpochEntry, err := utxoView.simulatePrevEpochEntry(currentEpochEntry.EpochNumber, currentEpochEntry.FinalBlockHeight)
		require.NoError(t, err)
		var prevEpochBlock *MsgDeSoBlock
		prevEpochBlock = _generateRealBlock(testMeta, prevEpochEntry.FinalBlockHeight, prevEpochEntry.FinalBlockHeight, 17283, testMeta.chain.BlockTip().Hash, false)
		err = testMeta.chain.processOrphanBlockPoS(prevEpochBlock)
		require.NoError(t, err)
		// The block should be in the block index.
		blockHash, err := prevEpochBlock.Hash()
		require.NoError(t, err)
		blockNode, exists := testMeta.chain.blockIndexByHash[*blockHash]
		require.True(t, exists)
		require.True(t, blockNode.IsStored())
		require.False(t, blockNode.IsValidateFailed())
		require.False(t, blockNode.IsValidated())
	}
}

func TestHasValidProposerPartialSignaturePoS(t *testing.T) {
	testMeta := NewTestPoSBlockchainWithValidators(t)
	// Generate a real block and make sure it doesn't hit any errors.
	var realBlock *MsgDeSoBlock
	realBlock = _generateRealBlock(testMeta, 12, 12, 889, testMeta.chain.BlockTip().Hash, false)
	utxoView := _newUtxoView(testMeta)
	snapshotEpochNumber, err := utxoView.GetCurrentSnapshotEpochNumber()
	require.NoError(t, err)
	isValid, err := utxoView.hasValidProposerPartialSignaturePoS(realBlock, snapshotEpochNumber)
	require.NoError(t, err)
	require.True(t, isValid)

	// If the block proposer's voting public key doesn't match the signature, it should fail.
	realVotingPublicKey := realBlock.Header.ProposerVotingPublicKey
	{
		realBlock.Header.ProposerVotingPublicKey = _generateRandomBLSPrivateKey(t).PublicKey()
		isValid, err = utxoView.hasValidProposerPartialSignaturePoS(realBlock, snapshotEpochNumber)
		require.NoError(t, err)
		require.False(t, isValid)
		// Reset the proposer voting public key
		realBlock.Header.ProposerVotingPublicKey = realVotingPublicKey
	}

	// Signature on incorrect payload should fail.
	{
		incorrectPayload := consensus.GetVoteSignaturePayload(13, testMeta.chain.BlockTip().Hash)
		realBlock.Header.ProposerVotePartialSignature, err =
			testMeta.blsPubKeyToBLSKeyMap[realBlock.Header.ProposerVotingPublicKey.ToString()].Sign(incorrectPayload[:])
		isValid, err = utxoView.hasValidProposerPartialSignaturePoS(realBlock, snapshotEpochNumber)
		require.NoError(t, err)
		require.False(t, isValid)
	}

	// Signature on correct payload from wrong public key should fail.
	{
		var realBlockHash *BlockHash
		realBlockHash, err = realBlock.Hash()
		require.NoError(t, err)
		correctPayload := consensus.GetVoteSignaturePayload(12, realBlockHash)
		wrongPrivateKey := _generateRandomBLSPrivateKey(t)
		realBlock.Header.ProposerVotePartialSignature, err = wrongPrivateKey.Sign(correctPayload[:])
		isValid, err = utxoView.hasValidProposerPartialSignaturePoS(realBlock, snapshotEpochNumber)
		require.NoError(t, err)
		require.False(t, isValid)
	}
}

func TestHasValidProposerRandomSeedSignaturePoS(t *testing.T) {
	testMeta := NewTestPoSBlockchainWithValidators(t)
	// Generate a real block and process it so we have a PoS block on the best chain.
	var realBlock *MsgDeSoBlock
	realBlock = _generateRealBlock(testMeta, 12, 12, 889, testMeta.chain.BlockTip().Hash, false)
	// The first PoS block passes the validation.
	isValid, err := testMeta.chain.hasValidProposerRandomSeedSignaturePoS(realBlock.Header)
	require.NoError(t, err)
	require.True(t, isValid)
	_, _, _, err = testMeta.chain.ProcessBlockPoS(realBlock, 12, true)
	require.NoError(t, err)
	realBlockHash, err := realBlock.Hash()
	require.NoError(t, err)
	realBlockNode, exists := testMeta.chain.blockIndexByHash[*realBlockHash]
	require.True(t, exists)
	require.True(t, realBlockNode.IsStored())
	require.False(t, realBlockNode.IsValidateFailed())
	require.True(t, realBlockNode.IsValidated())
	require.NotNil(t, realBlockNode.Header.ProposerRandomSeedSignature)

	// A valid child block with a valid proposer random seed signature will pass validations.
	var childBlock *MsgDeSoBlock
	childBlock = _generateRealBlock(testMeta, 13, 13, 273, realBlockNode.Hash, false)
	{
		isValid, err = testMeta.chain.hasValidProposerRandomSeedSignaturePoS(childBlock.Header)
		require.NoError(t, err)
		require.True(t, isValid)
	}

	// Modifying the random seed signature on the parent to make the child fail.
	{
		realBlockNode.Header.ProposerRandomSeedSignature, err = (&bls.Signature{}).FromBytes(RandomBytes(32))
		require.NoError(t, err)
		isValid, err = testMeta.chain.hasValidProposerRandomSeedSignaturePoS(childBlock.Header)
		require.NoError(t, err)
		require.False(t, isValid)
	}

	// Signing the previous block's random seed signature with the wrong key should fail.
	{
		wrongProposerPrivateKey := _generateRandomBLSPrivateKey(t)
		prevBlockRandomSeedHashBytes := sha256.Sum256(realBlockNode.Header.ProposerRandomSeedSignature.ToBytes())
		childBlock.Header.ProposerRandomSeedSignature, err = wrongProposerPrivateKey.Sign(prevBlockRandomSeedHashBytes[:])
		require.NoError(t, err)
		isValid, err = testMeta.chain.hasValidProposerRandomSeedSignaturePoS(childBlock.Header)
		require.NoError(t, err)
		require.False(t, isValid)
	}
}

// _generateRealBlock generates a BlockTemplate with real data by adding 50 test transactions to the
// PosMempool, generating a RandomSeedHash, updating the latestBlockView in the PosBlockProducer, and calling _getFullRealBlockTemplate.
// It can be used to generate a block w/ either a vote or timeout QC.
func _generateRealBlock(testMeta *TestMeta, blockHeight uint64, view uint64, seed int64, prevBlockHash *BlockHash, isTimeout bool) BlockTemplate {
	return _generateRealBlockWithFailingTxn(testMeta, blockHeight, view, seed, prevBlockHash, isTimeout, 0, 0)
}

func _generateRealBlockWithTimestampOffset(
	testMeta *TestMeta,
	blockHeight uint64,
	view uint64,
	seed int64,
	prevBlockHash *BlockHash,
	isTimeout bool,
	blockTimestampOffset time.Duration,
) BlockTemplate {
	return _generateRealBlockWithFailingTxn(testMeta, blockHeight, view, seed, prevBlockHash, isTimeout, 0, blockTimestampOffset)
}

func _generateRealBlockWithFailingTxn(testMeta *TestMeta, blockHeight uint64, view uint64, seed int64,
	prevBlockHash *BlockHash, isTimeout bool, numFailingTxns uint64, blockTimestampOffset time.Duration) BlockTemplate {
	globalParams := _testGetDefaultGlobalParams()
	randSource := rand.New(rand.NewSource(seed))
	passingTxns := []*MsgDeSoTxn{}
	totalUtilityFee := uint64(0)
	passingTransactions := 50
	feeMin := globalParams.MinimumNetworkFeeNanosPerKB
	feeMax := uint64(2000)
	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	for ii := 0; ii < passingTransactions; ii++ {
		txn := _generateTestTxn(testMeta.t, randSource, feeMin, feeMax, m0PubBytes, m0Priv, blockHeight+100, 20)
		passingTxns = append(passingTxns, txn)
		_, utilityFee := computeBMF(txn.TxnFeeNanos)
		totalUtilityFee += utilityFee
		_wrappedPosMempoolAddTransaction(testMeta.t, testMeta.posMempool, txn)
	}

	failingTxns := []*MsgDeSoTxn{}
	for jj := 0; jj < int(numFailingTxns); jj++ {
		// make a like on a non-existent post
		txn, _, _, _, err := testMeta.chain.CreateLikeTxn(
			m0PubBytes, ZeroBlockHash, false, feeMax, nil, []*DeSoOutput{})
		failingTxns = append(failingTxns, txn)
		require.NoError(testMeta.t, err)
		_signTxn(testMeta.t, txn, m0Priv)
		_wrappedPosMempoolAddTransaction(testMeta.t, testMeta.posMempool, txn)
	}

	// TODO: Get real seed signature.
	prevBlock, exists := testMeta.chain.blockIndexByHash[*prevBlockHash]
	require.True(testMeta.t, exists)
	// Always update the testMeta latestBlockView
	latestBlockView, err := testMeta.chain.getUtxoViewAtBlockHash(*prevBlockHash)
	require.NoError(testMeta.t, err)
	latestBlockHeight := testMeta.chain.blockIndexByHash[*prevBlockHash].Height
	testMeta.posMempool.UpdateLatestBlock(latestBlockView, uint64(latestBlockHeight))
	seedSignature := getRandomSeedSignature(testMeta, blockHeight, view, prevBlock.Header.ProposerRandomSeedSignature)
	fullBlockTemplate := _getFullRealBlockTemplate(testMeta, blockHeight, view, seedSignature, isTimeout, blockTimestampOffset)
	// Remove the transactions from this block from the mempool.
	// This prevents nonce reuse issues when trying to make reorg blocks.
	for _, txn := range passingTxns {
		testMeta.posMempool.RemoveTransaction(txn.Hash())
	}
	for _, txn := range failingTxns {
		testMeta.posMempool.RemoveTransaction(txn.Hash())
	}
	return fullBlockTemplate
}

// _generateDummyBlock generates a BlockTemplate with dummy data by adding 50 test transactions to the
// PosMempool, generating a RandomSeedHash, updating the latestBlockView in the PosBlockProducer, and calling _getFullDummyBlockTemplate.
// It then adds this dummy block to the block index.
func _generateDummyBlock(testMeta *TestMeta, blockHeight uint64, view uint64, seed int64) BlockTemplate {
	globalParams := _testGetDefaultGlobalParams()
	randSource := rand.New(rand.NewSource(seed))
	passingTxns := []*MsgDeSoTxn{}
	totalUtilityFee := uint64(0)
	passingTransactions := 50
	feeMin := globalParams.MinimumNetworkFeeNanosPerKB
	feeMax := uint64(2000)
	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	for ii := 0; ii < passingTransactions; ii++ {
		txn := _generateTestTxn(testMeta.t, randSource, feeMin, feeMax, m0PubBytes, m0Priv, blockHeight+100, 20)
		passingTxns = append(passingTxns, txn)
		_, utilityFee := computeBMF(txn.TxnFeeNanos)
		totalUtilityFee += utilityFee
		_wrappedPosMempoolAddTransaction(testMeta.t, testMeta.posMempool, txn)
	}

	seedSignature := &bls.Signature{}
	_, err := seedSignature.FromBytes(Sha256DoubleHash([]byte("seed")).ToBytes())
	require.NoError(testMeta.t, err)

	blockTemplate := _getFullDummyBlockTemplate(testMeta, testMeta.posMempool.readOnlyLatestBlockView, blockHeight, view, seedSignature)
	require.NotNil(testMeta.t, blockTemplate)
	// This is a hack to get the block to connect. We just give the block reward to m0.
	blockTemplate.Txns[0].TxOutputs[0].PublicKey = m0PubBytes
	// Make sure ToBytes works.
	var msgDesoBlock *MsgDeSoBlock
	msgDesoBlock = blockTemplate
	_, err = msgDesoBlock.ToBytes(false)
	require.NoError(testMeta.t, err)
	newBlockHash, err := msgDesoBlock.Hash()
	require.NoError(testMeta.t, err)

	// Add block to block index.
	blockNode, err := testMeta.chain.storeBlockInBlockIndex(msgDesoBlock)
	require.NoError(testMeta.t, err)
	require.True(testMeta.t, blockNode.IsStored())
	_, exists := testMeta.chain.blockIndexByHash[*newBlockHash]
	require.True(testMeta.t, exists)
	// Remove the transactions from this block from the mempool.
	// This prevents nonce reuse issues when trying to make failing blocks.
	for _, txn := range passingTxns {
		testMeta.posMempool.RemoveTransaction(txn.Hash())
	}
	return blockTemplate
}

// _generateBlockAndAddToBestChain generates a BlockTemplate by calling _generateRealBlock and then adds it to the
// best chain. Finally it updates the PosMempool's latest block view.
func _generateBlockAndAddToBestChain(testMeta *TestMeta, blockHeight uint64, view uint64, seed int64) *MsgDeSoBlock {
	blockTemplate := _generateRealBlock(testMeta, blockHeight, view, seed, testMeta.chain.BlockTip().Hash, false)
	var msgDesoBlock *MsgDeSoBlock
	msgDesoBlock = blockTemplate
	newBlockHash, err := msgDesoBlock.Hash()
	require.NoError(testMeta.t, err)
	// Add block to block index.
	blockNode, err := testMeta.chain.storeValidatedBlockInBlockIndex(msgDesoBlock)
	require.NoError(testMeta.t, err)
	require.True(testMeta.t, blockNode.IsStored())
	require.True(testMeta.t, blockNode.IsValidated())
	newBlockNode, exists := testMeta.chain.blockIndexByHash[*newBlockHash]
	require.True(testMeta.t, exists)
	testMeta.chain.addTipBlockToBestChain(newBlockNode)
	// Update the latest block view
	latestBlockView, err := testMeta.chain.GetUncommittedTipView()
	require.NoError(testMeta.t, err)
	testMeta.posMempool.UpdateLatestBlock(latestBlockView, blockTemplate.Header.Height)

	return blockTemplate
}

func getLeaderForBlockHeightAndView(testMeta *TestMeta, blockHeight uint64, view uint64) (string, []byte) {
	testMeta.posMempool.Lock()
	defer testMeta.posMempool.Unlock()
	latestBlockView := testMeta.posMempool.readOnlyLatestBlockView
	currentEpochEntry, err := latestBlockView.GetCurrentEpochEntry()
	require.NoError(testMeta.t, err)
	leaders, err := latestBlockView.GetCurrentSnapshotLeaderSchedule()
	require.NoError(testMeta.t, err)
	require.GreaterOrEqual(testMeta.t, view, currentEpochEntry.InitialView)
	viewDiff := view - currentEpochEntry.InitialView
	require.GreaterOrEqual(testMeta.t, blockHeight, currentEpochEntry.InitialBlockHeight)
	heightDiff := blockHeight - currentEpochEntry.InitialBlockHeight
	require.GreaterOrEqual(testMeta.t, viewDiff, heightDiff)
	leaderIdx := (viewDiff - heightDiff) % uint64(len(leaders))
	require.Greater(testMeta.t, len(leaders), int(leaderIdx))
	leader := leaders[leaderIdx]
	leaderPublicKeyBytes := latestBlockView.GetPublicKeyForPKID(leader)
	return Base58CheckEncode(leaderPublicKeyBytes, false, testMeta.chain.params), leaderPublicKeyBytes
}

func getRandomSeedSignature(testMeta *TestMeta, height uint64, view uint64, prevRandomSeedSignature *bls.Signature) *bls.Signature {
	leaderPublicKey, _ := getLeaderForBlockHeightAndView(testMeta, height, view)
	leaderBLSPrivKey := testMeta.pubKeyToBLSKeyMap[leaderPublicKey]
	prevRandomSeedHashSHA256 := sha3.Sum256(prevRandomSeedSignature.ToBytes())
	newRandomSeedSignature, err := leaderBLSPrivKey.Sign(prevRandomSeedHashSHA256[:])
	require.NoError(testMeta.t, err)
	return newRandomSeedSignature
}

func updateRandomSeedSignature(testMeta *TestMeta, block *MsgDeSoBlock, prevRandomSeedSignature *bls.Signature) {
	block.Header.ProposerRandomSeedSignature = getRandomSeedSignature(testMeta, block.Header.Height, block.Header.ProposedInView, prevRandomSeedSignature)
}

func updateProposerVotePartialSignatureForBlock(testMeta *TestMeta, block *MsgDeSoBlock) {
	blockHash, err := block.Hash()
	require.NoError(testMeta.t, err)
	leaderPublicKey, _ := getLeaderForBlockHeightAndView(testMeta, block.Header.Height, block.Header.ProposedInView)
	leaderBlsPrivKey := testMeta.pubKeyToBLSKeyMap[leaderPublicKey]
	partialSigPayload := consensus.GetVoteSignaturePayload(block.Header.ProposedInView, blockHash)
	sig, err := leaderBlsPrivKey.Sign(partialSigPayload[:])
	require.NoError(testMeta.t, err)
	block.Header.ProposerVotePartialSignature = sig
}

func _getVoteQC(testMeta *TestMeta, blockHeight uint64, qcBlockHash *BlockHash, qcView uint64) *QuorumCertificate {
	var validators []consensus.Validator
	var signersList *bitset.Bitset
	var aggregatedSignature *bls.Signature
	votePayload := consensus.GetVoteSignaturePayload(qcView, qcBlockHash)
	testMeta.posMempool.Lock()
	defer testMeta.posMempool.Unlock()
	latestBlockView := testMeta.posMempool.readOnlyLatestBlockView
	allSnapshotValidators, err := latestBlockView.GetAllSnapshotValidatorSetEntriesByStake()
	require.NoError(testMeta.t, err)
	validators = toConsensusValidators(allSnapshotValidators)

	// Get all the bls keys for the validators that aren't the leader.
	signersList = bitset.NewBitset()
	var signatures []*bls.Signature
	require.NoError(testMeta.t, err)
	for ii, validatorEntry := range allSnapshotValidators {
		validatorPublicKeyBytes := latestBlockView.GetPublicKeyForPKID(validatorEntry.ValidatorPKID)
		validatorPublicKey := Base58CheckEncode(validatorPublicKeyBytes, false, testMeta.chain.params)
		validatorBLSPrivateKey := testMeta.pubKeyToBLSKeyMap[validatorPublicKey]
		sig, err := validatorBLSPrivateKey.Sign(votePayload[:])
		require.NoError(testMeta.t, err)
		signatures = append(signatures, sig)
		signersList = signersList.Set(ii, true)
	}

	// Create the aggregated signature.
	aggregatedSignature, err = bls.AggregateSignatures(signatures)
	require.NoError(testMeta.t, err)

	// Create the vote QC.
	voteQC := &QuorumCertificate{
		BlockHash:      qcBlockHash,
		ProposedInView: qcView,
		ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
			SignersList: signersList,
			Signature:   aggregatedSignature,
		},
	}

	isValid := consensus.IsValidSuperMajorityQuorumCertificate(voteQC, validators)
	require.True(testMeta.t, isValid)
	return voteQC
}

// _getFullRealBlockTemplate is a helper function that generates a block template with a valid vote or timeout QC,
// does all the required signing by validators, and generates the proper ProposerVotePartialSignature.
func _getFullRealBlockTemplate(
	testMeta *TestMeta,
	blockHeight uint64,
	view uint64,
	seedSignature *bls.Signature,
	isTimeout bool,
	blockTimestampOffset time.Duration,
) BlockTemplate {
	blockTemplate, err := testMeta.posBlockProducer.createBlockTemplate(
		testMeta.posMempool.readOnlyLatestBlockView, blockHeight, view, seedSignature)
	require.NoError(testMeta.t, err)
	require.NotNil(testMeta.t, blockTemplate)

	// Figure out who the leader is supposed to be.
	leaderPublicKey, leaderPublicKeyBytes := getLeaderForBlockHeightAndView(testMeta, blockHeight, view)
	// Get leader voting private key.
	leaderVotingPrivateKey := testMeta.pubKeyToBLSKeyMap[leaderPublicKey]
	// Get hash of last block
	chainTip := testMeta.chain.blockIndexByHash[*blockTemplate.Header.PrevBlockHash]
	chainTipHash := chainTip.Hash
	// Get the vote signature payload
	// Hack to get view numbers working properly w/ PoW blocks.
	qcView := chainTip.Header.ProposedInView
	if qcView == 0 {
		qcView = view - 1
	}

	// Create the vote QC.
	voteQC := _getVoteQC(testMeta, blockHeight, chainTipHash, qcView)
	if !isTimeout {
		blockTemplate.Header.ValidatorsVoteQC = voteQC
	} else {
		var validatorsTimeoutHighQCViews []uint64
		timeoutSignersList := bitset.NewBitset()
		timeoutSigs := []*bls.Signature{}
		// TODO: Get the latest vote QC. If the current tip isn't a vote QC, then
		// we need to go further back.
		prevQC := testMeta.chain.blockTip().Header.ValidatorsVoteQC
		ii := 0
		for _, blsPrivKey := range testMeta.pubKeyToBLSKeyMap {
			// Add timeout high qc view. Just assume it's the view after the vote QC for simplicity.
			validatorsTimeoutHighQCViews = append(validatorsTimeoutHighQCViews, prevQC.GetView())
			// Add timeout aggregated signature.
			newPayload := consensus.GetTimeoutSignaturePayload(view-1, prevQC.GetView())
			sig, err := blsPrivKey.Sign(newPayload[:])
			require.NoError(testMeta.t, err)
			timeoutSigs = append(timeoutSigs, sig)
			timeoutSignersList.Set(ii, true)
			ii++
		}
		timeoutAggregatedSignature, err := bls.AggregateSignatures(timeoutSigs)
		require.NoError(testMeta.t, err)
		timeoutQC := &TimeoutAggregateQuorumCertificate{
			TimedOutView:                 view - 1,
			ValidatorsHighQC:             prevQC,
			ValidatorsTimeoutHighQCViews: validatorsTimeoutHighQCViews,
			ValidatorsTimeoutAggregatedSignature: &AggregatedBLSSignature{
				SignersList: timeoutSignersList,
				Signature:   timeoutAggregatedSignature,
			},
		}
		blockTemplate.Header.ValidatorsTimeoutAggregateQC = timeoutQC
	}
	blockTemplate.Header.ProposerVotingPublicKey = leaderVotingPrivateKey.PublicKey()
	// Ugh we need to adjust the timestamp.
	blockTemplate.Header.TstampNanoSecs = time.Now().UnixNano() + blockTimestampOffset.Nanoseconds()
	if chainTip.Header.TstampNanoSecs > blockTemplate.Header.TstampNanoSecs {
		blockTemplate.Header.TstampNanoSecs = chainTip.Header.TstampNanoSecs + 1
	}
	var proposerVotePartialSignature *bls.Signature
	// Just hack it so the leader gets the block reward.
	blockTemplate.Txns[0].TxOutputs[0].PublicKey = leaderPublicKeyBytes
	// Fix the merkle root.
	merkleRoot, _, err := ComputeMerkleRoot(blockTemplate.Txns)
	require.NoError(testMeta.t, err)
	blockTemplate.Header.TransactionMerkleRoot = merkleRoot
	var msgDesoBlock *MsgDeSoBlock
	msgDesoBlock = blockTemplate
	newBlockHash, err := msgDesoBlock.Hash()
	require.NoError(testMeta.t, err)
	newBlockVotePayload := consensus.GetVoteSignaturePayload(view, newBlockHash)
	proposerVotePartialSignature, err = leaderVotingPrivateKey.Sign(newBlockVotePayload[:])
	require.NoError(testMeta.t, err)
	blockTemplate.Header.ProposerVotePartialSignature = proposerVotePartialSignature
	return blockTemplate
}

// _getFullDummyBlockTemplate is a helper function that generates a block template with a dummy ValidatorsVoteQC.
func _getFullDummyBlockTemplate(testMeta *TestMeta, latestBlockView *UtxoView, blockHeight uint64, view uint64, seedSignature *bls.Signature) BlockTemplate {
	blockTemplate, err := testMeta.posBlockProducer.createBlockTemplate(latestBlockView, blockHeight, view, seedSignature)
	require.NoError(testMeta.t, err)
	require.NotNil(testMeta.t, blockTemplate)
	// Add a dummy vote QC
	proposerVotingPublicKey := _generateRandomBLSPrivateKey(testMeta.t)
	dummySig, err := proposerVotingPublicKey.Sign(RandomBytes(32))
	chainTip := testMeta.chain.BlockTip()
	blockTemplate.Header.ValidatorsVoteQC = &QuorumCertificate{
		BlockHash:      chainTip.Hash,
		ProposedInView: chainTip.Header.ProposedInView,
		ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
			SignersList: bitset.NewBitset().Set(0, true),
			Signature:   dummySig,
		},
	}
	blockTemplate.Header.ProposerVotePartialSignature = dummySig
	return blockTemplate
}

// _generateRandomBLSPrivateKey generates a random BLS private key for use in tests.
func _generateRandomBLSPrivateKey(t *testing.T) *bls.PrivateKey {
	privateKey, err := bls.NewPrivateKey()
	require.NoError(t, err)
	return privateKey
}

// NewTestPoSBlockchainWithValidators creates a new low-difficulty Blockchain
// with 7 validators registered and staked for use in tests.
// Below is a description of the stake distribution.
// - m0 has 100 nanos staked
// - m1 has 200 nanos staked
// - m2 has 300 nanos staked
// - m3 has 400 nanos staked
// - m4 has 500 nanos staked
// - m5 has 600 nanos staked
// - m6 has 700 nanos staked
// After the validators have registered and staked, a block is mined and
// the PoW Mempool and Miner are stoppped. Then we run the end-of-epoch hook
// and the end-of-epoch hook is run to set the leader schedule.
// Finally, we create a new PoSMempool, PoSBlockProducer, and set the
// PoS Cutover height to 12.
func NewTestPoSBlockchainWithValidators(t *testing.T) *TestMeta {
	setBalanceModelBlockHeights(t)
	// Set the PoS Setup Height to block 11 and cutover to 12.
	setPoSBlockHeights(t, 11, 12)
	// Set Epoch length to 2 block for testing.
	DeSoTestnetParams.DefaultEpochDurationNumBlocks = 2
	t.Cleanup(func() {
		DeSoTestnetParams.DefaultEpochDurationNumBlocks = 3600
		GlobalDeSoParams = DeSoTestnetParams
	})

	chain, params, db := NewLowDifficultyBlockchain(t)
	oldPool, miner := NewTestMiner(t, chain, params, true)
	// Mine a few blocks to give the senderPkString some money.
	for ii := 0; ii < 10; ii++ {
		_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, oldPool)
		require.NoError(t, err)
	}

	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	publicKeys := []string{m0Pub, m1Pub, m2Pub, m3Pub, m4Pub, m5Pub, m6Pub}
	for _, publicKey := range publicKeys {
		_, _, _ = _doBasicTransferWithViewFlush(
			t, chain, db, params, senderPkString, publicKey,
			senderPrivString, 1e9, 1000)
	}
	testMeta := &TestMeta{
		t:                t,
		chain:            chain,
		db:               db,
		params:           params,
		posMempool:       nil,
		posBlockProducer: nil,
		// TODO: what else do we need here?
		feeRateNanosPerKb: 1000,
		savedHeight:       11,
		mempool:           oldPool,
	}
	// validate and stake to the public keys
	_registerValidatorAndStake(testMeta, m0Pub, m0Priv, 0, 100, false)
	_registerValidatorAndStake(testMeta, m1Pub, m1Priv, 0, 200, false)
	_registerValidatorAndStake(testMeta, m2Pub, m2Priv, 0, 300, false)
	_registerValidatorAndStake(testMeta, m3Pub, m3Priv, 0, 400, false)
	_registerValidatorAndStake(testMeta, m4Pub, m4Priv, 0, 500, false)
	_registerValidatorAndStake(testMeta, m5Pub, m5Priv, 0, 600, false)
	_registerValidatorAndStake(testMeta, m6Pub, m6Priv, 0, 700, false)
	// Mine a block with these transactions.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, oldPool)
	require.NoError(t, err)
	oldPool.Stop()
	miner.Stop()
	latestBlockView, err := NewUtxoView(db, params, nil, nil, nil)
	require.NoError(t, err)

	maxMempoolPosSizeBytes := uint64(1024 * 1024 * 1000)
	mempoolBackupIntervalMillis := uint64(30000)
	mempool := NewPosMempool()
	require.NoError(t, mempool.Init(
		params, _testGetDefaultGlobalParams(), latestBlockView, 11, _dbDirSetup(t), false, maxMempoolPosSizeBytes,
		mempoolBackupIntervalMillis, 1, nil, 1, 10000, 100, 100,
	))
	require.NoError(t, mempool.Start())
	require.True(t, mempool.IsRunning())
	priv := _generateRandomBLSPrivateKey(t)
	m0Pk := NewPublicKey(m0PubBytes)
	posBlockProducer := NewPosBlockProducer(mempool, params, m0Pk, priv.PublicKey(), time.Now().UnixNano())
	// TODO: do we need to update the encoder migration stuff for global params. Probably.
	testMeta.mempool = nil
	testMeta.posMempool = mempool
	testMeta.posBlockProducer = posBlockProducer
	testMeta.savedHeight = 12
	//:= &TestMeta{
	//	t:                t,
	//	chain:            chain,
	//	db:               db,
	//	params:           params,
	//	posMempool:       mempool,
	//	posBlockProducer: posBlockProducer,
	//	// TODO: what else do we need here?
	//	feeRateNanosPerKb: 1000,
	//	savedHeight:       10,
	//	//miner:                  nil,
	//	//txnOps:                 nil,
	//	//txns:                   nil,
	//	//expectedSenderBalances: nil,
	//	//savedHeight:            0,
	//	//feeRateNanosPerKb:      0,
	//}
	t.Cleanup(func() {
		mempool.Stop()
	})
	return testMeta
}
