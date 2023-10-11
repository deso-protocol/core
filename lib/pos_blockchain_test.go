//go:build relic

package lib

import (
	"bytes"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/stretchr/testify/require"
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
		},
		Txns: nil,
	}

	// Validate the block with a valid timeout QC and header.
	err = bc.validateBlockIntegrity(block)
	// There should be no error.
	require.Nil(t, err)

	// Timeout QC shouldn't have any transactions
	block.Txns = []*MsgDeSoTxn{
		{ // The validation just checks the length of transactions.
			// Connecting the block elsewhere will ensure that the transactions themselves are valid.
			TxInputs: nil,
		},
	}
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorTimeoutQCWithTransactions)

	// Timeout QC shouldn't have a merkle root
	block.Txns = nil
	block.Header.TransactionMerkleRoot = &ZeroBlockHash
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorNoTxnsWithMerkleRoot)

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

	// Validate the block with a valid vote QC and header. Vote QCs must have at least 1 transaction.
	txn := _assembleBasicTransferTxnFullySigned(t, bc, 100, 1000,
		senderPkString, recipientPkString, senderPrivString, nil)
	block.Txns = []*MsgDeSoTxn{
		// The validation just checks the length of transactions.
		// Connecting the block elsewhere will ensure that the transactions themselves are valid.
		txn,
	}
	merkleRoot, _, err := ComputeMerkleRoot(block.Txns)
	require.NoError(t, err)
	block.Header.TransactionMerkleRoot = merkleRoot
	// There should be no error.
	err = bc.validateBlockIntegrity(block)
	require.Nil(t, err)

	// Block must have non-nil Merkle root iff we have non-zero transactions
	block.Header.TransactionMerkleRoot = nil
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorNilMerkleRoot)

	// Block must have a matching merkle root
	block.Header.TransactionMerkleRoot = &ZeroBlockHash
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorInvalidMerkleRoot)

	// Vote QC with no transactions and no merkle root is valid
	block.Header.TransactionMerkleRoot = nil
	block.Txns = nil
	err = bc.validateBlockIntegrity(block)
	require.Nil(t, err)

	// Vote QC with no transactions but includes a merkle is invalid
	block.Header.TransactionMerkleRoot = merkleRoot
	err = bc.validateBlockIntegrity(block)
	require.Equal(t, err, RuleErrorNoTxnsWithMerkleRoot)

	// Reset transactions
	block.Txns = []*MsgDeSoTxn{txn}

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
	genesisBlock := NewPoSBlockNode(nil, hash, 1, &MsgDeSoHeader{
		Version:                      2,
		TstampNanoSecs:               nowTimestamp - uint64(time.Minute.Nanoseconds()),
		Height:                       1,
		ProposedInView:               1,
		ValidatorsVoteQC:             nil,
		ValidatorsTimeoutAggregateQC: nil,
	}, StatusBlockValidated, UNCOMMITTED)
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

func TestAddBlockToBlockIndex(t *testing.T) {
	bc, _, _ := NewTestBlockchain(t)
	hash := NewBlockHash(RandomBytes(32))
	genesisBlockNode := NewPoSBlockNode(nil, hash, 1, &MsgDeSoHeader{
		Version:                      2,
		Height:                       1,
		ProposedInView:               1,
		ValidatorsVoteQC:             nil,
		ValidatorsTimeoutAggregateQC: nil,
	}, StatusBlockValidated, COMMITTED)
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
		},
		Txns: nil,
	}
	err = bc.addBlockToBlockIndex(block)
	require.Nil(t, err)
	newHash, err := block.Hash()
	require.NoError(t, err)
	// Check the block index
	blockNode, exists := bc.blockIndex[*newHash]
	require.True(t, exists)
	require.True(t, bytes.Equal(blockNode.Hash[:], newHash[:]))

	// Check the uncommitted blocks map
	uncommittedBlock, uncommittedExists := bc.uncommittedBlocksMap[*newHash]
	require.True(t, uncommittedExists)
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
	genesisNode := NewPoSBlockNode(nil, hash1, 1, &MsgDeSoHeader{
		Version:        2,
		Height:         1,
		ProposedInView: 1,
	}, StatusBlockValidated, COMMITTED)
	block2 := NewPoSBlockNode(genesisNode, hash2, 2, &MsgDeSoHeader{
		Version:                      2,
		Height:                       2,
		ProposedInView:               2,
		ValidatorsVoteQC:             nil,
		ValidatorsTimeoutAggregateQC: nil,
	}, StatusBlockValidated, UNCOMMITTED)
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
	hash1 := NewBlockHash(RandomBytes(32))
	hash2 := NewBlockHash(RandomBytes(32))
	genesisNode := NewPoSBlockNode(nil, hash1, 1, &MsgDeSoHeader{
		Version:        2,
		Height:         1,
		ProposedInView: 1,
	}, StatusBlockValidated, COMMITTED)
	block2 := NewPoSBlockNode(genesisNode, hash2, 2, &MsgDeSoHeader{
		Version:                      2,
		Height:                       2,
		ProposedInView:               2,
		ValidatorsVoteQC:             nil,
		ValidatorsTimeoutAggregateQC: nil,
	}, StatusBlockValidated, UNCOMMITTED)
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
		},
		Txns: nil,
	}

	err = bc.addBlockToBlockIndex(block)
	require.NoError(t, err)
	newHash, err := block.Hash()
	require.NoError(t, err)
	// Check the block index
	blockNode, exists := bc.blockIndex[*newHash]
	require.True(t, exists)
	require.True(t, bytes.Equal(blockNode.Hash[:], newHash[:]))
	require.Equal(t, blockNode.Height, uint32(2))
	// Check the uncommitted blocks map
	uncommittedBlock, uncommittedExists := bc.uncommittedBlocksMap[*newHash]
	require.True(t, uncommittedExists)
	uncommittedBytes, err := uncommittedBlock.ToBytes(false)
	require.NoError(t, err)
	origBlockBytes, err := block.ToBytes(false)
	require.NoError(t, err)
	require.True(t, bytes.Equal(uncommittedBytes, origBlockBytes))

	// If we're missing a field in the header, we should get an error
	// as we can't compute the hash.
	block.Header.ProposerPublicKey = nil
	err = bc.addBlockToBlockIndex(block)
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

func TestValidateAncestorsExist(t *testing.T) {
	bc, _, _ := NewTestBlockchain(t)
	hash1 := NewBlockHash(RandomBytes(32))
	hash2 := NewBlockHash(RandomBytes(32))
	genesisNode := NewPoSBlockNode(nil, hash1, 1, &MsgDeSoHeader{
		Version:        2,
		Height:         1,
		ProposedInView: 1,
	}, StatusBlockValidated, COMMITTED)
	block2 := NewPoSBlockNode(genesisNode, hash2, 2, &MsgDeSoHeader{
		Version:                      2,
		Height:                       2,
		ProposedInView:               2,
		ValidatorsVoteQC:             nil,
		ValidatorsTimeoutAggregateQC: nil,
	}, StatusBlockValidated, UNCOMMITTED)
	bc.blockIndex = map[BlockHash]*BlockNode{
		*hash1: genesisNode,
		*hash2: block2,
	}
	bc.bestChainMap = map[BlockHash]*BlockNode{
		*hash1: genesisNode,
		*hash2: block2,
	}

	block := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			PrevBlockHash: hash2,
		},
	}
	// If block is in best chain, we should a nil value for missing block hash and no error
	missingBlockHash := bc.validateAncestorsExist(*block.Header.PrevBlockHash)
	require.Nil(t, missingBlockHash)

	// If parent block is not in block index, we should get the parent block hash back
	block.Header.PrevBlockHash = NewBlockHash(RandomBytes(32))
	missingBlockHash = bc.validateAncestorsExist(*block.Header.PrevBlockHash)
	require.True(t, missingBlockHash.IsEqual(block.Header.PrevBlockHash))

	// If parent block is in block index, but not in best chain, we check its grandparents.

	// 1. Grandparent exists in best chain
	hash3 := NewBlockHash(RandomBytes(32))
	block3 := NewPoSBlockNode(nil, hash3, 3, &MsgDeSoHeader{
		Version:       2,
		PrevBlockHash: hash1,
	}, StatusBlockValidated, UNCOMMITTED)
	bc.blockIndex[*hash3] = block3
	block.Header.PrevBlockHash = hash3
	missingBlockHash = bc.validateAncestorsExist(*block.Header.PrevBlockHash)
	require.Nil(t, missingBlockHash)

	// 2. Grandparent doesn't exist in best chain.
	block3.Header.PrevBlockHash = NewBlockHash(RandomBytes(32))
	bc.blockIndex[*hash3] = block3
	missingBlockHash = bc.validateAncestorsExist(*block.Header.PrevBlockHash)
	require.True(t, missingBlockHash.IsEqual(block3.Header.PrevBlockHash))
}

func _generateRandomBLSPrivateKey(t *testing.T) *bls.PrivateKey {
	privateKey, err := bls.NewPrivateKey()
	require.NoError(t, err)
	return privateKey
}
