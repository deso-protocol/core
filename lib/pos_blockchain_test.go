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
	t.Skipf("TODO: Implement")
}

func _generateRandomBLSPrivateKey(t *testing.T) *bls.PrivateKey {
	privateKey, err := bls.NewPrivateKey()
	require.NoError(t, err)
	return privateKey
}
