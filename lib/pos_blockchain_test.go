//go:build relic

package lib

import (
	"bytes"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/deso-protocol/core/consensus"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"math"
	"math/rand"
	"strconv"
	"testing"
	"time"
)

func TestValidateBlockIntegrity(t *testing.T) {
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
	randomSeedHashBytes := RandomBytes(32)
	randomSeedHash := &RandomSeedHash{}
	_, err = randomSeedHash.FromBytes(randomSeedHashBytes)
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
			TstampNanoSecs: bc.GetBestChainTip().Header.TstampNanoSecs + 10,
			Height:         2,
			ProposedInView: 2,
			PrevBlockHash:  bc.GetBestChainTip().Hash,
			ValidatorsTimeoutAggregateQC: &TimeoutAggregateQuorumCertificate{
				TimedOutView: 2,
				ValidatorsHighQC: &QuorumCertificate{
					BlockHash:      bc.GetBestChainTip().Hash,
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
			ProposerRandomSeedHash:  randomSeedHash,
			ProposerPublicKey:       NewPublicKey(RandomBytes(33)),
			ProposerVotingPublicKey: randomBLSPrivateKey.PublicKey(),
			TransactionMerkleRoot:   merkleRoot,
		},
		Txns: txns,
	}

	// Validate the block with a valid timeout QC and header.
	err = bc.validateBlockIntegrity(block)
	// There should be no error.
	require.Nil(t, err)

	// Timeout QC should have exactly 1 transaction and that transaction is a block reward.
	block.Txns = nil
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorBlockWithNoTxns)

	block.Txns = []*MsgDeSoTxn{
		{
			TxnMeta: &BasicTransferMetadata{},
		},
	}
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorBlockDoesNotStartWithRewardTxn)
	// Revert txns to be valid.
	block.Txns = []*MsgDeSoTxn{
		{
			TxnMeta: &BlockRewardMetadataa{},
		},
	}

	// Timeout QC also must have a merkle root
	block.Header.TransactionMerkleRoot = nil
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorNilMerkleRoot)

	block.Header.TransactionMerkleRoot = &ZeroBlockHash
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorInvalidMerkleRoot)

	// Make sure block can't have both timeout and vote QC.
	validatorVoteQC := &QuorumCertificate{
		BlockHash:      bc.GetBestChainTip().Hash,
		ProposedInView: 1,
		ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
			Signature:   signature,
			SignersList: bitset.NewBitset(),
		},
	}
	block.Header.ValidatorsVoteQC = validatorVoteQC
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorBothTimeoutAndVoteQC)

	// Make sure block has either timeout or vote QC.
	block.Header.ValidatorsTimeoutAggregateQC = nil
	block.Header.ValidatorsVoteQC = nil
	err = bc.validateBlockIntegrity(block)
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
	err = bc.validateBlockIntegrity(block)
	require.Nil(t, err)

	// Block must have non-nil Merkle root if we have non-zero transactions
	block.Header.TransactionMerkleRoot = nil
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorNilMerkleRoot)

	// Block must have a matching merkle root
	block.Header.TransactionMerkleRoot = &ZeroBlockHash
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorInvalidMerkleRoot)

	// Reset transactions
	block.Txns = []*MsgDeSoTxn{
		{
			TxnMeta: &BlockRewardMetadataa{},
		},
	}

	// Block must have valid proposer voting public key
	block.Header.ProposerVotingPublicKey = nil
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorInvalidProposerVotingPublicKey)

	block.Header.ProposerVotingPublicKey = &bls.PublicKey{}
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorInvalidProposerVotingPublicKey)

	// Reset proposer voting public key
	block.Header.ProposerVotingPublicKey = randomBLSPrivateKey.PublicKey()

	// Block must have valid proposer public key
	block.Header.ProposerPublicKey = nil
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorInvalidProposerPublicKey)

	block.Header.ProposerPublicKey = &ZeroPublicKey
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorInvalidProposerPublicKey)

	block.Header.ProposerPublicKey = NewPublicKey(RandomBytes(33))

	// Block must have valid proposer random seed hash
	block.Header.ProposerRandomSeedHash = nil
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorInvalidRandomSeedHash)

	block.Header.ProposerRandomSeedHash = &RandomSeedHash{}
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorInvalidRandomSeedHash)

	block.Header.ProposerRandomSeedHash = randomSeedHash

	// Timestamp validations
	// Block timestamp must be greater than the previous block timestamp
	block.Header.TstampNanoSecs = bc.GetBestChainTip().Header.GetTstampSecs() - 1
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorPoSBlockTstampNanoSecsTooOld)

	// Block timestamps can't be in the future.
	block.Header.TstampNanoSecs = uint64(time.Now().UnixNano() + (11 * time.Minute).Nanoseconds())
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorPoSBlockTstampNanoSecsInFuture)

	// Revert the Header's timestamp
	block.Header.TstampNanoSecs = bc.GetBestChainTip().Header.TstampNanoSecs + 10

	//  Block Header version must be 2
	block.Header.Version = 1
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorInvalidPoSBlockHeaderVersion)

	// Revert block header version
	block.Header.Version = 2

	// Nil prev block hash not allowed
	block.Header.PrevBlockHash = nil
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorNilPrevBlockHash)

	// Parent must exist in the block index.
	block.Header.PrevBlockHash = NewBlockHash(RandomBytes(32))
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorMissingParentBlock)

	// Nil block header not allowed
	block.Header = nil
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorNilBlockHeader)
}

func TestValidateBlockHeight(t *testing.T) {
	bc, _, _ := NewTestBlockchain(t)
	hash := NewBlockHash(RandomBytes(32))
	nowTimestamp := uint64(time.Now().UnixNano())
	genesisBlock := NewBlockNode(nil, hash, 1, nil, nil, &MsgDeSoHeader{
		Version:                      2,
		TstampNanoSecs:               nowTimestamp - uint64(time.Minute.Nanoseconds()),
		Height:                       1,
		ProposedInView:               1,
		ValidatorsVoteQC:             nil,
		ValidatorsTimeoutAggregateQC: nil,
	}, StatusBlockStored|StatusBlockValidated)
	bc.bestChain = []*BlockNode{genesisBlock}
	bc.blockIndex[*genesisBlock.Hash] = genesisBlock
	// Create a block with a valid header.
	randomPayload := RandomBytes(256)
	randomBLSPrivateKey := _generateRandomBLSPrivateKey(t)
	signature, err := randomBLSPrivateKey.Sign(randomPayload)
	require.NoError(t, err)
	block := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			PrevBlockHash:  genesisBlock.Hash,
			Version:        2,
			TstampNanoSecs: uint64(time.Now().UnixNano()) - 10,
			Height:         2,
			ProposedInView: 1,
			ValidatorsTimeoutAggregateQC: &TimeoutAggregateQuorumCertificate{
				TimedOutView: 2,
				ValidatorsHighQC: &QuorumCertificate{
					BlockHash:      bc.GetBestChainTip().Hash,
					ProposedInView: bc.GetBestChainTip().Header.ProposedInView,
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
	err = bc.validateBlockHeight(block)
	require.Equal(t, err, RuleErrorPoSBlockBeforeCutoverHeight)

	// Update the fork height
	bc.params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 0

	err = bc.validateBlockHeight(block)
	require.Nil(t, err)

	block.Header.Height = 1
	err = bc.validateBlockHeight(block)
	require.Equal(t, err, RuleErrorInvalidPoSBlockHeight)

	block.Header.Height = 2
	bc.blockIndex = map[BlockHash]*BlockNode{}
	err = bc.validateBlockHeight(block)
	require.Equal(t, err, RuleErrorMissingParentBlock)
}

func TestUpsertBlockAndBlockNodeToDB(t *testing.T) {
	bc, _, _ := NewTestBlockchain(t)
	GlobalDeSoParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 0
	resetGlobalDeSoParams := func() {
		GlobalDeSoParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = math.MaxUint32
	}
	t.Cleanup(resetGlobalDeSoParams)
	hash := NewBlockHash(RandomBytes(32))
	genesisBlockNode := NewBlockNode(nil, hash, 1, nil, nil, &MsgDeSoHeader{
		Version:                      2,
		Height:                       1,
		ProposedInView:               1,
		ValidatorsVoteQC:             nil,
		ValidatorsTimeoutAggregateQC: nil,
	}, StatusBlockStored|StatusBlockValidated)
	_ = genesisBlockNode
	derefedHash := *hash
	bc.blockIndex = map[BlockHash]*BlockNode{
		derefedHash: genesisBlockNode,
	}
	proposerVotingPublicKey := _generateRandomBLSPrivateKey(t)
	dummySig, err := proposerVotingPublicKey.Sign(RandomBytes(32))
	require.NoError(t, err)
	block := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			Version:                 2,
			PrevBlockHash:           hash,
			TstampNanoSecs:          uint64(time.Now().UnixNano()),
			Height:                  2,
			ProposerPublicKey:       NewPublicKey(RandomBytes(33)),
			ProposerVotingPublicKey: proposerVotingPublicKey.PublicKey(),
			ProposerRandomSeedHash:  &RandomSeedHash{},
			ProposedInView:          1,
			ValidatorsTimeoutAggregateQC: &TimeoutAggregateQuorumCertificate{
				TimedOutView: 2,
				ValidatorsHighQC: &QuorumCertificate{
					BlockHash:      NewBlockHash(RandomBytes(32)),
					ProposedInView: 1,
					ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
						SignersList: bitset.NewBitset(),
						Signature:   dummySig,
					},
				},
				ValidatorsTimeoutHighQCViews: []uint64{28934},
				ValidatorsTimeoutAggregatedSignature: &AggregatedBLSSignature{
					SignersList: bitset.NewBitset(),
					Signature:   dummySig,
				},
			},
			ProposerVotePartialSignature: dummySig,
			TxnConnectStatusByIndexHash:  NewBlockHash(bitset.NewBitset().ToBytes()),
		},
		Txns: []*MsgDeSoTxn{
			{
				TxnMeta: &BlockRewardMetadataa{},
			},
		},
		TxnConnectStatusByIndex: bitset.NewBitset(),
	}
	err = bc.storeCommittedBlockInBlockIndex(block)
	require.Nil(t, err)
	newHash, err := block.Hash()
	require.NoError(t, err)
	// Check the block index
	blockNode, exists := bc.blockIndex[*newHash]
	require.True(t, exists)
	require.True(t, bytes.Equal(blockNode.Hash[:], newHash[:]))
	require.True(t, blockNode.IsStored())

	// Check the DB for the block.
	uncommittedBlock, err := GetBlock(newHash, bc.db, bc.snapshot)
	require.NoError(t, err)
	uncommittedBytes, err := uncommittedBlock.ToBytes(false)
	require.NoError(t, err)
	origBlockBytes, err := block.ToBytes(false)
	require.NoError(t, err)
	require.True(t, bytes.Equal(uncommittedBytes, origBlockBytes))
}

func TestValidateBlockView(t *testing.T) {
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
	bc.blockIndex = map[BlockHash]*BlockNode{
		*hash1: genesisNode,
		*hash2: block2,
	}
	randomPayload := RandomBytes(256)
	randomBLSPrivateKey := _generateRandomBLSPrivateKey(t)
	signature, err := randomBLSPrivateKey.Sign(randomPayload)
	voteQC := &QuorumCertificate{
		BlockHash:      bc.GetBestChainTip().Hash,
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
			TstampNanoSecs: uint64(time.Now().UnixNano()) - 10,
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
	err = bc.validateBlockView(block)
	require.Equal(t, err, RuleErrorPoSTimeoutBlockViewNotGreaterThanParent)

	// Any arbitrary number GREATER than the parent's view is valid.
	block.Header.ProposedInView = 10
	err = bc.validateBlockView(block)
	require.Nil(t, err)

	// Now we set the timeout QC to nil and provide a vote QC, with height = 2
	block.Header.ValidatorsTimeoutAggregateQC = nil
	block.Header.ValidatorsVoteQC = voteQC
	block.Header.ProposedInView = 2
	err = bc.validateBlockView(block)
	require.Equal(t, err, RuleErrorPoSVoteBlockViewNotOneGreaterThanParent)

	// An arbitrary number greater than its parents should fail.
	block.Header.ProposedInView = 10
	err = bc.validateBlockView(block)
	require.Equal(t, err, RuleErrorPoSVoteBlockViewNotOneGreaterThanParent)

	// Exactly one great w/ vote QC should pass.
	block.Header.ProposedInView = 3
	err = bc.validateBlockView(block)
	require.Nil(t, err)
}

func TestAddBlockToBlockIndexAndUncommittedBlocks(t *testing.T) {
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
	bc.blockIndex = map[BlockHash]*BlockNode{
		*hash1: genesisNode,
		*hash2: block2,
	}
	randomPayload := RandomBytes(256)
	randomBLSPrivateKey := _generateRandomBLSPrivateKey(t)
	signature, err := randomBLSPrivateKey.Sign(randomPayload)
	voteQC := &QuorumCertificate{
		BlockHash:      bc.GetBestChainTip().Hash,
		ProposedInView: 1,
		ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
			Signature:   signature,
			SignersList: bitset.NewBitset(),
		},
	}
	require.NoError(t, err)
	randomSeedHash := &RandomSeedHash{}
	_, err = randomSeedHash.FromBytes(RandomBytes(32))
	require.NoError(t, err)
	blsPrivKey := _generateRandomBLSPrivateKey(t)
	block := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			PrevBlockHash:                hash2,
			Version:                      2,
			TstampNanoSecs:               uint64(time.Now().UnixNano()) - 10,
			Height:                       2,
			ProposedInView:               1,
			ProposerPublicKey:            NewPublicKey(RandomBytes(33)),
			ProposerVotingPublicKey:      blsPrivKey.PublicKey(),
			ProposerRandomSeedHash:       randomSeedHash,
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
			TxnConnectStatusByIndexHash: NewBlockHash(bitset.NewBitset().ToBytes()),
		},
		Txns: []*MsgDeSoTxn{
			{
				TxnMeta: &BlockRewardMetadataa{},
			},
		},
		TxnConnectStatusByIndex: bitset.NewBitset(),
	}

	err = bc.storeBlockInBlockIndex(block)
	require.NoError(t, err)
	newHash, err := block.Hash()
	require.NoError(t, err)
	// Check the block index
	blockNode, exists := bc.blockIndex[*newHash]
	require.True(t, exists)
	require.True(t, bytes.Equal(blockNode.Hash[:], newHash[:]))
	require.Equal(t, blockNode.Height, uint32(2))
	require.True(t, blockNode.IsStored())
	// Check the DB for the block
	uncommittedBlock, err := GetBlock(newHash, bc.db, bc.snapshot)
	require.NoError(t, err)
	uncommittedBytes, err := uncommittedBlock.ToBytes(false)
	require.NoError(t, err)
	origBlockBytes, err := block.ToBytes(false)
	require.NoError(t, err)
	require.True(t, bytes.Equal(uncommittedBytes, origBlockBytes))

	// If we're missing a field in the header, we should get an error
	// as we can't compute the hash.
	block.Header.ProposerPublicKey = nil
	err = bc.storeBlockInBlockIndex(block)
	require.Error(t, err)
}

func TestValidateBlockLeader(t *testing.T) {
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

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
	leaders, err := utxoView.GetSnapshotLeaderSchedule()
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
	{
		// First block, we should have the first leader.
		leader0PKID := leaderSchedule[0]
		leader0Entry := validatorPKIDToValidatorEntryMap[*leader0PKID]
		leader0PublicKey := utxoView.GetPublicKeyForPKID(leader0PKID)
		dummyBlock := &MsgDeSoBlock{
			Header: &MsgDeSoHeader{
				ProposedInView:          viewNumber + 1,
				Height:                  blockHeight + 1,
				ProposerPublicKey:       NewPublicKey(leader0PublicKey),
				ProposerVotingPublicKey: leader0Entry.VotingPublicKey,
			},
		}
		err = testMeta.chain.validateBlockLeader(dummyBlock)
		require.NoError(t, err)

		// If we have a different proposer public key, we will have an error
		leader1PublicKey := utxoView.GetPublicKeyForPKID(leaderSchedule[1])
		leader1Entry := validatorPKIDToValidatorEntryMap[*leaderSchedule[1]]
		dummyBlock.Header.ProposerPublicKey = NewPublicKey(leader1PublicKey)
		err = testMeta.chain.validateBlockLeader(dummyBlock)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorLeaderForBlockDoesNotMatchSchedule)

		// If we have a different proposer voting public key, we will have an error
		dummyBlock.Header.ProposerPublicKey = NewPublicKey(leader0PublicKey)
		dummyBlock.Header.ProposerVotingPublicKey = leader1Entry.VotingPublicKey
		err = testMeta.chain.validateBlockLeader(dummyBlock)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorLeaderForBlockDoesNotMatchSchedule)

		// If we advance the view, we know that leader 0 timed out, so
		// we move to leader 1.
		dummyBlock.Header.ProposedInView = viewNumber + 2
		dummyBlock.Header.ProposerPublicKey = NewPublicKey(leader1PublicKey)
		dummyBlock.Header.ProposerVotingPublicKey = leader1Entry.VotingPublicKey
		err = testMeta.chain.validateBlockLeader(dummyBlock)
		require.NoError(t, err)

		// If we have 4 timeouts, we know that leaders 0, 1, 2, and 3 timed out,
		// so we move to leader 4.
		dummyBlock.Header.ProposedInView = viewNumber + 5
		leader4PublicKey := utxoView.GetPublicKeyForPKID(leaderSchedule[4])
		leader4Entry := validatorPKIDToValidatorEntryMap[*leaderSchedule[4]]
		dummyBlock.Header.ProposerPublicKey = NewPublicKey(leader4PublicKey)
		dummyBlock.Header.ProposerVotingPublicKey = leader4Entry.VotingPublicKey
		err = testMeta.chain.validateBlockLeader(dummyBlock)
		require.NoError(t, err)

		// If we have 7 timeouts, we know everybody timed out, so we go back to leader 0.
		dummyBlock.Header.ProposedInView = viewNumber + 8
		dummyBlock.Header.ProposerPublicKey = NewPublicKey(leader0PublicKey)
		dummyBlock.Header.ProposerVotingPublicKey = leader0Entry.VotingPublicKey
		err = testMeta.chain.validateBlockLeader(dummyBlock)
		require.NoError(t, err)

		// If the block view is less than the epoch's initial view, this is an error.
		dummyBlock.Header.ProposedInView = viewNumber
		err = testMeta.chain.validateBlockLeader(dummyBlock)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorBlockViewLessThanInitialViewForEpoch)

		// If the block height is less than epoch's initial block height, this is an error.
		dummyBlock.Header.ProposedInView = viewNumber + 1
		dummyBlock.Header.Height = blockHeight
		err = testMeta.chain.validateBlockLeader(dummyBlock)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorBlockHeightLessThanInitialHeightForEpoch)

		// If the difference between the block's view and epoch's initial view is less than
		// the difference between the block's height and the epoch's initial height, this is an error.
		// This would imply that we've had more blocks than views, which is not possible.
		dummyBlock.Header.ProposedInView = viewNumber + 1
		dummyBlock.Header.Height = blockHeight + 2
		err = testMeta.chain.validateBlockLeader(dummyBlock)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorBlockDiffLessThanHeightDiff)
	}

}

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
	bc.blockIndex = map[BlockHash]*BlockNode{
		*hash1: genesisNode,
	}
	block := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			PrevBlockHash: hash1,
		},
	}
	// If parent is committed tip, we'll have 0 ancestors.
	ancestors, err := bc.getLineageFromCommittedTip(block)
	require.NoError(t, err)
	require.Len(t, ancestors, 0)

	// If parent block is not in block index, we should get an error
	block.Header.PrevBlockHash = NewBlockHash(RandomBytes(32))
	ancestors, err = bc.getLineageFromCommittedTip(block)
	require.Error(t, err)
	require.Equal(t, err, RuleErrorMissingAncestorBlock)
	require.Nil(t, ancestors)

	// If this block extends from a committed block that is not the tip, we should get an error.
	block.Header.PrevBlockHash = hash1
	// add another block to the best chain.
	hash2 := NewBlockHash(RandomBytes(32))
	block2 := NewBlockNode(genesisNode, hash2, 2, nil, nil, &MsgDeSoHeader{
		Version:       2,
		Height:        2,
		PrevBlockHash: hash1,
	}, StatusBlockStored|StatusBlockValidated|StatusBlockCommitted)
	bc.bestChain = append(bc.bestChain, block2)
	bc.blockIndex[*hash2] = block2
	ancestors, err = bc.getLineageFromCommittedTip(block)
	require.Error(t, err)
	require.Equal(t, err, RuleErrorDoesNotExtendCommittedTip)

	// update block to be uncommitted
	block2.Status = StatusBlockStored | StatusBlockValidated
	// set new block's parent as block 2.
	block.Header.PrevBlockHash = hash2
	ancestors, err = bc.getLineageFromCommittedTip(block)
	require.NoError(t, err)
	require.Len(t, ancestors, 1)
}

func TestValidateQC(t *testing.T) {
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
	err := bc.validateQC(desoBlock, validatorSet)
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
	err = bc.validateQC(desoBlock, validatorSet)
	require.NoError(t, err)

	// Empty validator set should fail
	err = bc.validateQC(desoBlock, []*ValidatorEntry{})
	require.Error(t, err)
	require.Equal(t, err, RuleErrorInvalidVoteQC)

	// Malformed validators should fail
	{
		// Zero stake amount
		validatorSet[0].TotalStakeAmountNanos = uint256.NewInt().SetUint64(0)
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil stake amount
		validatorSet[0].TotalStakeAmountNanos = nil
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Reset stake amount
		validatorSet[0].TotalStakeAmountNanos = uint256.NewInt().SetUint64(3)
		// Nil voting public key
		validatorSet[0].VotingPublicKey = nil
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Reset voting public key
		validatorSet[0].VotingPublicKey = m1VotingPrivateKey.PublicKey()
		// Nil validator entry
		err = bc.validateQC(desoBlock, append(validatorSet, nil))
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)
	}

	{
		// Malformed vote QC should fail
		// Nil vote QC
		desoBlock.Header.ValidatorsVoteQC = nil
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// View is 0
		desoBlock.Header.ValidatorsVoteQC = voteQC
		voteQC.ProposedInView = 0
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil block hash
		voteQC.ProposedInView = 6
		voteQC.BlockHash = nil
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil signers list
		voteQC.ValidatorsVoteAggregatedSignature.SignersList = nil
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil Signature
		voteQC.ValidatorsVoteAggregatedSignature.SignersList = signersList1And2
		voteQC.ValidatorsVoteAggregatedSignature.Signature = nil
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil aggregate signature
		voteQC.BlockHash = hash1
		voteQC.ValidatorsVoteAggregatedSignature = nil
		err = bc.validateQC(desoBlock, validatorSet)
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
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)
	}
	{
		// Only having signature for validator 1 should fail even if signers list has validator 2
		voteQC.ValidatorsVoteAggregatedSignature.SignersList = bitset.NewBitset().FromBytes([]byte{0x3}) // 0b0010, which represents validator 1 and 2
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Having 1 and 3 in signers list, but including signature for 2 should fail
		voteQC.ValidatorsVoteAggregatedSignature.SignersList = bitset.NewBitset().Set(0, true).Set(2, true) // represents validator 1 and 3
		voteQC.ValidatorsVoteAggregatedSignature.Signature = aggregateSig
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Reset the signers list and signature
		voteQC.ValidatorsVoteAggregatedSignature.SignersList = signersList1And2
		voteQC.ValidatorsVoteAggregatedSignature.Signature = aggregateSig
	}

	// Timeout QC tests
	// Let's start with a valid timeout QC
	timeout1Payload := consensus.GetTimeoutSignaturePayload(6, 5)
	timeout1Signature, err := m1VotingPrivateKey.Sign(timeout1Payload[:])
	require.NoError(t, err)
	timeout2Payload := consensus.GetTimeoutSignaturePayload(6, 4)
	timeout2Signature, err := m2VotingPrivateKey.Sign(timeout2Payload[:])

	timeoutAggSig, err := bls.AggregateSignatures([]*bls.Signature{timeout1Signature, timeout2Signature})
	require.NoError(t, err)
	timeoutQC := &TimeoutAggregateQuorumCertificate{
		TimedOutView:                 6,
		ValidatorsHighQC:             voteQC,
		ValidatorsTimeoutHighQCViews: []uint64{5, 4},
		ValidatorsTimeoutAggregatedSignature: &AggregatedBLSSignature{
			SignersList: signersList1And2,
			Signature:   timeoutAggSig,
		},
	}
	// Set the vote qc to nil
	desoBlock.Header.ValidatorsVoteQC = nil
	// Set the timeout qc to the timeout qc constructed above
	desoBlock.Header.ValidatorsTimeoutAggregateQC = timeoutQC
	err = bc.validateQC(desoBlock, validatorSet)
	require.NoError(t, err)

	{
		// Malformed timeout QC tests
		// NOTE: these actually trigger RuleErrorInvalidVoteQC because the
		// timeout QC is interpreted as empty
		// View = 0
		timeoutQC.TimedOutView = 0
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil high QC
		timeoutQC.TimedOutView = 6
		timeoutQC.ValidatorsHighQC = nil
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// High QC has view of 0
		timeoutQC.ValidatorsHighQC = voteQC
		timeoutQC.ValidatorsHighQC.ProposedInView = 0
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// No high QC views
		timeoutQC.ValidatorsHighQC.ProposedInView = 6
		timeoutQC.ValidatorsTimeoutHighQCViews = []uint64{}
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil high QC block hash
		timeoutQC.ValidatorsTimeoutHighQCViews = []uint64{5, 4}
		timeoutQC.ValidatorsHighQC.BlockHash = nil
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil high QC signers list
		timeoutQC.ValidatorsHighQC.BlockHash = hash1
		timeoutQC.ValidatorsHighQC.ValidatorsVoteAggregatedSignature.SignersList = nil
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil high QC signature
		timeoutQC.ValidatorsHighQC.ValidatorsVoteAggregatedSignature.SignersList = signersList1And2
		timeoutQC.ValidatorsHighQC.ValidatorsVoteAggregatedSignature.Signature = nil
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Nil High QC Aggregated signature
		timeoutQC.ValidatorsHighQC.ValidatorsVoteAggregatedSignature = nil
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidVoteQC)

		// Revert high qc aggregated signature
		timeoutQC.ValidatorsHighQC.ValidatorsVoteAggregatedSignature = &AggregatedBLSSignature{
			SignersList: signersList1And2,
			Signature:   timeoutAggSig,
		}
	}
	{
		// Invalid validator set tests
		// Zero stake amount
		validatorSet[0].TotalStakeAmountNanos = uint256.NewInt().SetUint64(0)
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)

		// Nil stake amount
		validatorSet[0].TotalStakeAmountNanos = nil
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)

		// Reset stake amount
		validatorSet[0].TotalStakeAmountNanos = uint256.NewInt().SetUint64(3)
		// Nil voting public key
		validatorSet[0].VotingPublicKey = nil
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)

		// Reset voting public key
		validatorSet[0].VotingPublicKey = m1VotingPrivateKey.PublicKey()
		// Nil validator entry
		err = bc.validateQC(desoBlock, append(validatorSet, nil))
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)
	}

	{
		// No supermajority test
		timeoutQC.ValidatorsTimeoutAggregatedSignature.SignersList = bitset.NewBitset().FromBytes([]byte{0x1}) // 0b0001, which represents validator 1
		timeoutQC.ValidatorsTimeoutAggregatedSignature.Signature = timeout1Signature
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)
	}

	{
		// Only having signature for validator 1 should fail even if signers list has validator 2
		timeoutQC.ValidatorsTimeoutAggregatedSignature.SignersList = bitset.NewBitset().FromBytes([]byte{0x3}) // 0b0010, which represents validator 1 and 2
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)

		// Having 1 and 3 in signers list, but including signature for 2 should fail
		timeoutQC.ValidatorsTimeoutAggregatedSignature.SignersList = bitset.NewBitset().Set(0, true).Set(2, true) // represents validator 1 and 3
		timeoutQC.ValidatorsTimeoutAggregatedSignature.Signature = timeoutAggSig
		err = bc.validateQC(desoBlock, validatorSet)
		require.Error(t, err)
		require.Equal(t, err, RuleErrorInvalidTimeoutQC)
	}
}

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
	// that hash2 exists in the blockIndex
	newBlock.Header.PrevBlockHash = hash2
	require.True(t, bc.shouldReorg(newBlock, 2))
}

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
	}
	hash2 := NewBlockHash(RandomBytes(32))
	bn2 := &BlockNode{
		Hash:   hash2,
		Status: StatusBlockStored | StatusBlockValidated,
		Height: 3,
		Header: &MsgDeSoHeader{
			PrevBlockHash: hash1,
		},
	}
	hash3 := NewBlockHash(RandomBytes(32))
	bn3 := &BlockNode{
		Hash:   hash3,
		Status: StatusBlockStored | StatusBlockValidated,
		Height: 4,
		Header: &MsgDeSoHeader{
			PrevBlockHash: hash2,
		},
	}
	bc.addBlockToBestChain(bn1)
	bc.addBlockToBestChain(bn2)
	bc.addBlockToBestChain(bn3)
	bc.blockIndex[*hash1] = bn1
	bc.blockIndex[*hash2] = bn2
	bc.blockIndex[*hash3] = bn3

	// Simple reorg. Just replacing the uncommitted tip.
	newBlock := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			PrevBlockHash:  hash2,
			ProposedInView: 10,
		},
	}
	newBlockHash, err := newBlock.Hash()
	require.NoError(t, err)

	ancestors, err := bc.getLineageFromCommittedTip(newBlock)
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
	appliedNewTip, err := bc.tryApplyNewTip(newBlockNode, 9, ancestors)
	require.NoError(t, err)
	require.True(t, appliedNewTip)
	// hash 3 should no longer be in the best chain or best chain map
	_, hash3ExistsInBestChainMap := bc.bestChainMap[*hash3]
	require.False(t, hash3ExistsInBestChainMap)
	require.False(t, checkBestChainForHash(hash3))

	// newBlock should be in the best chain and the best chain map and should be the tip.
	_, newBlockExistsInBestChainMap := bc.bestChainMap[*newBlockHash]
	require.True(t, newBlockExistsInBestChainMap)
	require.True(t, checkBestChainForHash(newBlockHash))
	require.True(t, bc.GetBestChainTip().Hash.IsEqual(newBlockHash))

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
	bc.addBlockToBestChain(bn3)

	// Add a series of blocks that are not part of the best chain
	// to the block index and reorg to them
	hash4 := NewBlockHash(RandomBytes(32))
	bn4 := &BlockNode{
		Hash:   hash4,
		Status: StatusBlockStored | StatusBlockValidated,
		Height: 5,
		Header: &MsgDeSoHeader{
			PrevBlockHash: hash1,
		},
	}

	hash5 := NewBlockHash(RandomBytes(32))
	bn5 := &BlockNode{
		Hash:   hash5,
		Status: StatusBlockStored | StatusBlockValidated,
		Height: 6,
		Header: &MsgDeSoHeader{
			PrevBlockHash: hash4,
		},
	}
	bc.blockIndex[*hash4] = bn4
	bc.blockIndex[*hash5] = bn5

	// Set new block's parent to hash5
	newBlockNode.Header.PrevBlockHash = hash5
	require.NoError(t, err)
	ancestors, err = bc.getLineageFromCommittedTip(newBlock)
	require.NoError(t, err)

	// Try to apply newBlock as tip.
	appliedNewTip, err = bc.tryApplyNewTip(newBlockNode, 9, ancestors)
	require.NoError(t, err)
	require.True(t, appliedNewTip)
	// newBlockHash should be tip.
	require.True(t, bc.GetBestChainTip().Hash.IsEqual(newBlockHash))
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

	// Reset the state of the best chain.
	delete(bc.bestChainMap, *hash4)
	delete(bc.bestChainMap, *hash5)
	delete(bc.bestChainMap, *newBlockHash)
	bc.bestChain = bc.bestChain[:len(bc.bestChain)-3]

	// Add block 2 and 3 back.
	bc.addBlockToBestChain(bn2)
	bc.addBlockToBestChain(bn3)

	// No reorg tests
	// currentView > newBlock.View
	newBlockNode.Header.ProposedInView = 8

	// we should not apply the new tip if it doesn't extend the current tip.
	appliedNewTip, err = bc.tryApplyNewTip(newBlockNode, 9, ancestors)
	require.False(t, appliedNewTip)
	require.NoError(t, err)

	// Super Happy path: no reorg, just extending tip.
	newBlockNode.Header.ProposedInView = 10
	newBlockNode.Header.PrevBlockHash = hash3
	require.NoError(t, err)
	ancestors, err = bc.getLineageFromCommittedTip(newBlock)
	require.NoError(t, err)
	appliedNewTip, err = bc.tryApplyNewTip(newBlockNode, 9, ancestors)
	require.True(t, appliedNewTip)
	require.NoError(t, err)
	// newBlockHash should be tip.
	require.True(t, bc.GetBestChainTip().Hash.IsEqual(newBlockHash))
}

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

func TestRunCommitRuleOnBestChain(t *testing.T) {
	testMeta := NewTestPoSBlockchain(t)

	// Create a single block and add it to the best chain.
	blockTemplate1 := _generateBlockAndAddToBestChain(testMeta, 11, 11, 887)
	// Okay now try to run the commit rule. Nothing will happen.
	// We expect the block to be uncommitted.
	err := testMeta.chain.runCommitRuleOnBestChain()
	require.NoError(t, err)

	blockHash1, err := blockTemplate1.Hash()
	require.NoError(t, err)
	// Okay so let's make sure the block is uncommitted.
	_verifyCommitRuleHelper(testMeta, []*BlockHash{}, []*BlockHash{blockHash1}, nil)

	// Add one more block to best chain. Should still not trigger commit rule
	blockTemplate2 := _generateBlockAndAddToBestChain(testMeta, 12, 12, 813)

	// Run commit rule again. Nothing should happen.
	// We expect both block 1 and block 2 to be uncommitted.
	err = testMeta.chain.runCommitRuleOnBestChain()
	require.NoError(t, err)

	blockHash2, err := blockTemplate2.Hash()
	require.NoError(t, err)
	// Okay so let's make sure blocks 1 and 2 are uncommitted.
	_verifyCommitRuleHelper(testMeta, []*BlockHash{}, []*BlockHash{blockHash1, blockHash2}, nil)

	// Okay add one MORE block to the best chain. This should trigger the commit rule.
	blockTemplate3 := _generateBlockAndAddToBestChain(testMeta, 13, 13, 513)

	// Run the commit rule again. This time we expect block 1 to be committed.
	err = testMeta.chain.runCommitRuleOnBestChain()
	require.NoError(t, err)

	blockHash3, err := blockTemplate3.Hash()
	require.NoError(t, err)

	// Okay so let's make sure that block 1 is committed and blocks 2 and 3 are not.
	_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1}, []*BlockHash{blockHash2, blockHash3}, blockHash1)

	// Add one more block to the best chain, but have the view be further in the future.
	// this should trigger a commit on block 2.
	blockTemplate4 := _generateBlockAndAddToBestChain(testMeta, 14, 20, 429)
	err = testMeta.chain.runCommitRuleOnBestChain()
	require.NoError(t, err)

	blockHash4, err := blockTemplate4.Hash()
	require.NoError(t, err)

	// Blocks 1 and 2 should be committed, blocks 3 and 4 are not.
	_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1, blockHash2}, []*BlockHash{blockHash3, blockHash4}, blockHash2)

	// Okay so add block 5 to the best chain. This should NOT trigger a commit on block 3
	// as block 4 is not a direct child of block 3 based on its view.
	blockTemplate5 := _generateBlockAndAddToBestChain(testMeta, 15, 21, 654)
	err = testMeta.chain.runCommitRuleOnBestChain()
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
	err = testMeta.chain.runCommitRuleOnBestChain()
	require.NoError(t, err)

	blockHash6, err := blockTemplate6.Hash()
	require.NoError(t, err)

	// Blocks 1, 2, 3, and 4 are committed, blocks 5 and 6 are not.
	_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1, blockHash2, blockHash3, blockHash4}, []*BlockHash{blockHash5, blockHash6}, blockHash4)
}

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
}

// Test the following series of blocks to make sure that ProcessBlockPoS properly handles all cases as expected during the steady state
// 1. Process a bad block. The block could be bad for any reason, we don't really care the reason, we just want to // see it get rejected.
// 2. Process three good blocks in a row, which tests the commit rule
// 3. Process a timeout block that reorgs the previous tip
// 4. Process a regular block that reorgs from the previous tip
// 5. Process an orphan, which tests the block's storage and the return value of missingBlockHashes
func TestProcessBlockPoS(t *testing.T) {
	testMeta := NewTestPoSBlockchainWithValidators(t)

	{
		// Create a bad block and try to process it.
		dummyBlock := _generateDummyBlock(testMeta, 12, 12, 887)
		success, isOrphan, missingBlockHashes, err := testMeta.chain.processBlockPoS(dummyBlock, 12, true)
		require.False(t, success)
		require.False(t, isOrphan)
		require.Len(t, missingBlockHashes, 0)
		require.Error(t, err)
	}

	var blockHash1 *BlockHash
	{
		var realBlock *MsgDeSoBlock
		realBlock = _generateRealBlock(testMeta, 12, 12, 889, testMeta.chain.GetBestChainTip().Hash)
		success, isOrphan, missingBlockHashes, err := testMeta.chain.processBlockPoS(realBlock, 12, true)
		require.True(t, success)
		require.False(t, isOrphan)
		require.Len(t, missingBlockHashes, 0)
		require.NoError(t, err)

		// Okay now we can check the best chain.
		// We expect the block to be uncommitted.
		blockHash1, err = realBlock.Hash()
		require.NoError(t, err)
		_verifyCommitRuleHelper(testMeta, []*BlockHash{}, []*BlockHash{blockHash1}, nil)
	}

	var blockHash2, blockHash3 *BlockHash
	{
		// Now let's try adding two more blocks on top of this one to make sure commit rule works properly.
		var realBlock2 *MsgDeSoBlock
		realBlock2 = _generateRealBlock(testMeta, 13, 13, 950, blockHash1)
		success, _, _, err := testMeta.chain.processBlockPoS(realBlock2, 13, true)
		require.True(t, success)
		blockHash2, err = realBlock2.Hash()
		require.NoError(t, err)

		var realBlock3 *MsgDeSoBlock
		realBlock3 = _generateRealBlock(testMeta, 14, 14, 378, blockHash2)

		success, _, _, err = testMeta.chain.processBlockPoS(realBlock3, 14, true)
		require.True(t, success)
		// Okay now we expect blockHash1 to be committed, but blockHash2 and 3 to not be committed.
		blockHash3, err = realBlock3.Hash()
		require.NoError(t, err)

		_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1}, []*BlockHash{blockHash2, blockHash3}, blockHash1)
	}

	var timeoutBlockHash *BlockHash
	{
		// Okay let's timeout view 15
		var timeoutBlock *MsgDeSoBlock
		timeoutBlock = _generateRealTimeout(testMeta, 15, 15, 381, blockHash3)
		success, _, _, err := testMeta.chain.processBlockPoS(timeoutBlock, 15, true)
		require.True(t, success)
		timeoutBlockHash, err = timeoutBlock.Hash()
		require.NoError(t, err)

		_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1, blockHash2}, []*BlockHash{blockHash3, timeoutBlockHash}, blockHash2)
	}

	var reorgBlockHash *BlockHash
	{
		// Okay let's introduce a reorg. New block at view 15 with block 3 as its parent.
		var reorgBlock *MsgDeSoBlock
		reorgBlock = _generateRealBlock(testMeta, 15, 15, 373, blockHash3)
		success, _, _, err := testMeta.chain.processBlockPoS(reorgBlock, 15, true)
		require.True(t, success)
		reorgBlockHash, err = reorgBlock.Hash()
		require.NoError(t, err)
	}

	{
		// We expect blockHash1 and blockHash2 to be committed, but blockHash3 and reorgBlockHash to not be committed.
		// Timeout block will no longer be in best chain, and will still be in an uncommitted state in the block index
		_verifyCommitRuleHelper(testMeta, []*BlockHash{blockHash1, blockHash2}, []*BlockHash{blockHash3, reorgBlockHash}, blockHash2)
		_, exists := testMeta.chain.bestChainMap[*timeoutBlockHash]
		require.False(t, exists)

		timeoutBlockNode, exists := testMeta.chain.blockIndex[*timeoutBlockHash]
		require.True(t, exists)
		require.False(t, IsBlockCommitted(timeoutBlockNode))

		// Let's process an orphan block.
		var dummyParentBlock *MsgDeSoBlock
		dummyParentBlock = _generateRealBlock(testMeta, 16, 16, 272, reorgBlockHash)
		dummyParentBlockHash, err := dummyParentBlock.Hash()
		require.NoError(t, err)
		var orphanBlock *MsgDeSoBlock
		orphanBlock = _generateRealBlock(testMeta, 17, 17, 9273, reorgBlockHash)
		// Set the prev block hash manually on orphan block
		orphanBlock.Header.PrevBlockHash = dummyParentBlockHash
		orphanBlockHash, err := orphanBlock.Hash()
		_ = orphanBlockHash
		require.NoError(t, err)
		success, isOrphan, missingBlockHashes, err := testMeta.chain.processBlockPoS(orphanBlock, 17, true)
		require.False(t, success)
		require.True(t, isOrphan)
		require.Len(t, missingBlockHashes, 1)
		require.True(t, missingBlockHashes[0].IsEqual(dummyParentBlockHash))
		require.NoError(t, err)
		// TODO: decide what we're doing with orphans.
		//require.Equal(t, testMeta.chain.orphanList.Len(), 1)
		//require.True(t, testMeta.chain.orphanList.Front().Value.(*OrphanBlock).Hash.IsEqual(orphanBlockHash))
	}
}

func _generateRealBlock(testMeta *TestMeta, blockHeight uint64, view uint64, seed int64, prevBlockHash *BlockHash) BlockTemplate {
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

	seedHash := &RandomSeedHash{}
	_, err := seedHash.FromBytes(Sha256DoubleHash([]byte(strconv.FormatInt(seed, 10))).ToBytes())
	require.NoError(testMeta.t, err)
	// Always update the testMeta latestBlockView
	latestBlockView, err := testMeta.chain.getUtxoViewAtBlockHash(*prevBlockHash)
	require.NoError(testMeta.t, err)
	latestBlockHeight := testMeta.chain.blockIndex[*prevBlockHash].Height
	testMeta.posMempool.UpdateLatestBlock(latestBlockView, uint64(latestBlockHeight))
	return _getFullRealBlockTemplate(testMeta, testMeta.posMempool.readOnlyLatestBlockView, blockHeight, view, seedHash, false)
}

func _generateRealTimeout(testMeta *TestMeta, blockHeight uint64, view uint64, seed int64, prevBlockHash *BlockHash) BlockTemplate {
	seedHash := &RandomSeedHash{}
	_, err := seedHash.FromBytes(Sha256DoubleHash([]byte(strconv.FormatInt(seed, 10))).ToBytes())
	require.NoError(testMeta.t, err)
	// Always update the testMeta latestBlockView
	latestBlockView, err := testMeta.chain.getUtxoViewAtBlockHash(*prevBlockHash)
	require.NoError(testMeta.t, err)
	testMeta.posMempool.UpdateLatestBlock(latestBlockView, uint64(testMeta.chain.GetBestChainTip().Height))
	return _getFullRealBlockTemplate(testMeta, testMeta.posMempool.readOnlyLatestBlockView, blockHeight, view, seedHash, true)
}

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

	seedHash := &RandomSeedHash{}
	_, err := seedHash.FromBytes(Sha256DoubleHash([]byte("seed")).ToBytes())
	require.NoError(testMeta.t, err)

	blockTemplate := _getFullDummyBlockTemplate(testMeta, testMeta.posMempool.readOnlyLatestBlockView, blockHeight, view, seedHash)
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

	// Add block to block index and best chain
	err = testMeta.chain.storeValidatedBlockInBlockIndex(msgDesoBlock)
	require.NoError(testMeta.t, err)
	_, exists := testMeta.chain.blockIndex[*newBlockHash]
	require.True(testMeta.t, exists)
	return blockTemplate
}

func _generateBlockAndAddToBestChain(testMeta *TestMeta, blockHeight uint64, view uint64, seed int64) *MsgDeSoBlock {
	blockTemplate := _generateDummyBlock(testMeta, blockHeight, view, seed)
	var msgDesoBlock *MsgDeSoBlock
	msgDesoBlock = blockTemplate
	newBlockHash, err := msgDesoBlock.Hash()
	require.NoError(testMeta.t, err)
	newBlockNode, exists := testMeta.chain.blockIndex[*newBlockHash]
	require.True(testMeta.t, exists)
	testMeta.chain.addBlockToBestChain(newBlockNode)
	// Update the latest block view
	latestBlockView, err := testMeta.chain.GetUncommittedTipView()
	require.NoError(testMeta.t, err)
	testMeta.posMempool.UpdateLatestBlock(latestBlockView, blockTemplate.Header.Height)

	return blockTemplate
}

func _getFullRealBlockTemplate(testMeta *TestMeta, latestBlockView *UtxoView, blockHeight uint64, view uint64, seedHash *RandomSeedHash, isTimeout bool) BlockTemplate {
	blockTemplate, err := testMeta.posBlockProducer.createBlockTemplate(latestBlockView, blockHeight, view, seedHash)
	require.NoError(testMeta.t, err)
	require.NotNil(testMeta.t, blockTemplate)
	blockTemplate.Header.TxnConnectStatusByIndexHash = HashBitset(blockTemplate.TxnConnectStatusByIndex)

	// Figure out who the leader is supposed to be.
	currentEpochEntry, err := latestBlockView.GetCurrentEpochEntry()
	require.NoError(testMeta.t, err)
	leaders, err := latestBlockView.GetSnapshotLeaderSchedule()
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
	leaderPublicKey := Base58CheckEncode(leaderPublicKeyBytes, false, testMeta.chain.params)
	// Get leader voting private key.
	leaderVotingPrivateKey := testMeta.pubKeyToBLSKeyMap[leaderPublicKey]
	// Get hash of last block
	chainTip := testMeta.chain.blockIndex[*blockTemplate.Header.PrevBlockHash]
	chainTipHash := chainTip.Hash
	// Get the vote signature payload
	// Hack to get view numbers working properly w/ PoW blocks.
	qcView := chainTip.Header.ProposedInView
	if qcView == 0 {
		qcView = view - 1
	}
	votePayload := consensus.GetVoteSignaturePayload(qcView, chainTipHash)
	allSnapshotValidators, err := latestBlockView.GetAllSnapshotValidatorSetEntriesByStake()
	require.NoError(testMeta.t, err)
	// QC stuff.

	// Get all the bls keys for the validators that aren't the leader.
	signersList := bitset.NewBitset()
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
	aggregatedSignature, err := bls.AggregateSignatures(signatures)
	require.NoError(testMeta.t, err)
	// Create the vote QC.
	voteQC := &QuorumCertificate{
		BlockHash:      chainTipHash,
		ProposedInView: qcView,
		ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
			SignersList: signersList,
			Signature:   aggregatedSignature,
		},
	}

	isValid := consensus.IsValidSuperMajorityQuorumCertificate(voteQC, toConsensusValidators(allSnapshotValidators))
	require.True(testMeta.t, isValid)
	if !isTimeout {
		blockTemplate.Header.ValidatorsVoteQC = voteQC
	} else {
		var validatorsTimeoutHighQCViews []uint64
		timeoutSignersList := bitset.NewBitset()
		timeoutSigs := []*bls.Signature{}
		ii := 0
		for _, blsPrivKey := range testMeta.pubKeyToBLSKeyMap {
			// Add timeout high qc view. Just assume it's the view after the vote QC for simplicity.
			validatorsTimeoutHighQCViews = append(validatorsTimeoutHighQCViews, voteQC.ProposedInView+1)
			// Add timeout aggregated signature.
			newPayload := consensus.GetTimeoutSignaturePayload(view, voteQC.ProposedInView+1)
			sig, err := blsPrivKey.Sign(newPayload[:])
			require.NoError(testMeta.t, err)
			timeoutSigs = append(timeoutSigs, sig)
			timeoutSignersList.Set(ii, true)
			ii++
		}
		timeoutAggregatedSignature, err := bls.AggregateSignatures(timeoutSigs)
		require.NoError(testMeta.t, err)
		timeoutQC := &TimeoutAggregateQuorumCertificate{
			TimedOutView:                 view,
			ValidatorsHighQC:             voteQC,
			ValidatorsTimeoutHighQCViews: validatorsTimeoutHighQCViews,
			ValidatorsTimeoutAggregatedSignature: &AggregatedBLSSignature{
				SignersList: timeoutSignersList,
				Signature:   timeoutAggregatedSignature,
			},
		}
		blockTemplate.Header.ValidatorsTimeoutAggregateQC = timeoutQC
	}
	blockTemplate.Header.ProposerPublicKey = NewPublicKey(leaderPublicKeyBytes)
	blockTemplate.Header.ProposerVotingPublicKey = leaderVotingPrivateKey.PublicKey()
	// Ugh we need to adjust the timestamp.
	blockTemplate.Header.TstampNanoSecs = uint64(time.Now().UnixNano())
	if chainTip.Header.TstampNanoSecs > blockTemplate.Header.TstampNanoSecs {
		blockTemplate.Header.TstampNanoSecs = chainTip.Header.TstampNanoSecs + 1
	}
	require.Less(testMeta.t, blockTemplate.Header.TstampNanoSecs, uint64(time.Now().UnixNano())+testMeta.chain.params.DefaultBlockTimestampDriftNanoSecs)
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
	if !isTimeout {
		newBlockVotePayload := consensus.GetVoteSignaturePayload(view, newBlockHash)
		proposerVotePartialSignature, err = leaderVotingPrivateKey.Sign(newBlockVotePayload[:])
		require.NoError(testMeta.t, err)
	} else {
		newTimeoutPayload := consensus.GetTimeoutSignaturePayload(view, view+1)
		proposerVotePartialSignature, err = leaderVotingPrivateKey.Sign(newTimeoutPayload[:])
		require.NoError(testMeta.t, err)
	}

	blockTemplate.Header.ProposerVotePartialSignature = proposerVotePartialSignature
	return blockTemplate
}

func _getFullDummyBlockTemplate(testMeta *TestMeta, latestBlockView *UtxoView, blockHeight uint64, view uint64, seedHash *RandomSeedHash) BlockTemplate {
	blockTemplate, err := testMeta.posBlockProducer.createBlockTemplate(latestBlockView, blockHeight, view, seedHash)
	require.NoError(testMeta.t, err)
	require.NotNil(testMeta.t, blockTemplate)
	blockTemplate.Header.TxnConnectStatusByIndexHash = HashBitset(blockTemplate.TxnConnectStatusByIndex)
	// Add a dummy vote QC
	proposerVotingPublicKey := _generateRandomBLSPrivateKey(testMeta.t)
	dummySig, err := proposerVotingPublicKey.Sign(RandomBytes(32))
	chainTip := testMeta.chain.GetBestChainTip()
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

func _generateRandomBLSPrivateKey(t *testing.T) *bls.PrivateKey {
	privateKey, err := bls.NewPrivateKey()
	require.NoError(t, err)
	return privateKey
}

func NewTestPoSBlockchainWithValidators(t *testing.T) *TestMeta {
	setBalanceModelBlockHeights(t)
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
	latestBlockView, err := NewUtxoView(db, params, nil, nil)
	require.NoError(t, err)
	// Set the PoS Setup Height to block 11.
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = 11
	GlobalDeSoParams.ForkHeights.ProofOfStake1StateSetupBlockHeight = 11
	// Run the on epoch complete hook to set the leader schedule.
	err = latestBlockView.RunEpochCompleteHook(11, 11, uint64(time.Now().UnixNano()))
	require.NoError(t, err)
	err = latestBlockView.FlushToDb(11)
	require.NoError(t, err)
	maxMempoolPosSizeBytes := uint64(500)
	mempoolBackupIntervalMillis := uint64(30000)
	mempool := NewPosMempool(params, _testGetDefaultGlobalParams(), latestBlockView, 11, _dbDirSetup(t), false, maxMempoolPosSizeBytes, mempoolBackupIntervalMillis)
	require.NoError(t, mempool.Start())
	require.True(t, mempool.IsRunning())
	priv := _generateRandomBLSPrivateKey(t)
	m0Pk := NewPublicKey(m0PubBytes)
	posBlockProducer := NewPosBlockProducer(mempool, params, m0Pk, priv.PublicKey())
	params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 12
	GlobalDeSoParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 12
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
		GlobalDeSoParams.ForkHeights.ProofOfStake1StateSetupBlockHeight = math.MaxUint32
		GlobalDeSoParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = math.MaxUint32
	})
	return testMeta
}

func NewTestPoSBlockchain(t *testing.T) *TestMeta {
	setBalanceModelBlockHeights(t)
	chain, params, db := NewLowDifficultyBlockchain(t)
	params.ForkHeights.BalanceModelBlockHeight = 1
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
	oldPool.Stop()
	miner.Stop()
	latestBlockView, err := NewUtxoView(db, params, nil, nil)
	require.NoError(t, err)
	maxMempoolPosSizeBytes := uint64(500)
	mempoolBackupIntervalMillis := uint64(30000)
	mempool := NewPosMempool(params, _testGetDefaultGlobalParams(), latestBlockView, 10, _dbDirSetup(t), false, maxMempoolPosSizeBytes, mempoolBackupIntervalMillis)
	require.NoError(t, mempool.Start())
	require.True(t, mempool.IsRunning())
	priv := _generateRandomBLSPrivateKey(t)
	m0Pk := NewPublicKey(m0PubBytes)
	posBlockProducer := NewPosBlockProducer(mempool, params, m0Pk, priv.PublicKey())
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = 9
	params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 11
	GlobalDeSoParams.ForkHeights.ProofOfStake1StateSetupBlockHeight = 9
	GlobalDeSoParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 11
	testMeta := &TestMeta{
		t:                t,
		chain:            chain,
		db:               db,
		params:           params,
		posMempool:       mempool,
		posBlockProducer: posBlockProducer,
		// TODO: what else do we need here?
		feeRateNanosPerKb: 1000,
		savedHeight:       10,
		//miner:                  nil,
		//txnOps:                 nil,
		//txns:                   nil,
		//expectedSenderBalances: nil,
		//savedHeight:            0,
		//feeRateNanosPerKb:      0,
	}
	t.Cleanup(func() {
		mempool.Stop()
		GlobalDeSoParams.ForkHeights.ProofOfStake1StateSetupBlockHeight = math.MaxUint32
		GlobalDeSoParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = math.MaxUint32
	})
	return testMeta
}
