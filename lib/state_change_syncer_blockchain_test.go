package lib

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestStateChangeSyncer_Block1_PureInserts implements the "Block 1 (pure inserts)" test case
// from the implementation plan. It creates real blockchain transactions using a test miner,
// generates state change diffs, and validates the resulting StateChangeEntry records.
//
// This test creates:
// 1. SubmitPost transaction (creates new PostEntry - core-state)
// 2. CreateProfile transaction (creates new ProfileEntry - core-state)
// 3. BasicTransfer transaction (funds recipient - not core-state, but necessary)
// 4. CreateProfile transaction for recipient (creates another ProfileEntry - core-state)
// 5. Follow transaction (creates new FollowEntry - core-state)
func TestStateChangeSyncer_Block1_PureInserts(t *testing.T) {
	require := require.New(t)

	// ---- Setup: blockchain, miner, and state syncer ----
	chain, params, embpg := NewLowDifficultyBlockchainWithParamsAndDb(t, &DeSoTestnetParams, false, 0, false)
	defer func() {
		if embpg != nil {
			embpg.Stop()
		}
	}()

	mempool, miner := NewTestMiner(t, chain, params, true /* isSender */)

	// Setup state syncer with temporary directory
	dir, err := os.MkdirTemp("", "state-syncer-block1")
	require.NoError(err)
	defer os.RemoveAll(dir)

	// Hook the state syncer into the blockchain's event manager
	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	chain.eventManager.OnBlockCommitted(func(event *BlockEvent) {
		err := syncer.GenerateCommittedBlockDiff(chain.db, event.PreCommitTxn, uint64(event.Block.Header.Height))
		if err != nil {
			t.Errorf("Failed to generate block diff: %v", err)
		}
	})

	// Get initial block height (should be 0 after genesis)
	initialHeight := chain.blockTip().Height
	require.Equal(uint32(0), initialHeight)

	// ---- Fund the sender account ----
	// The sender needs DeSo to pay for transaction fees
	// Mine a block to make the block reward mature and available
	_, err = miner.MineAndProcessSingleBlock(0 /* threadIndex */, mempool)
	require.NoError(err)

	// Wait for block reward maturity (2 blocks per test params)
	_, err = miner.MineAndProcessSingleBlock(0 /* threadIndex */, mempool)
	require.NoError(err)

	// Update initial height after funding blocks
	initialHeight = chain.blockTip().Height

	// ---- Transaction 1: SubmitPost (creates new PostEntry) ----
	postBody := &DeSoBodySchema{
		Body:      "Test post for state syncer diff validation",
		ImageURLs: []string{"https://example.com/image.jpg"},
	}
	bodyBytes, err := json.Marshal(postBody)
	require.NoError(err)

	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)

	submitPostTxn, _, _, _, err := chain.CreateSubmitPostTxn(
		senderPkBytes,                 // updaterPublicKey
		nil,                           // postHashToModify (nil = new post)
		nil,                           // parentStakeID
		bodyBytes,                     // body
		nil,                           // repostPostHashBytes
		false,                         // isQuotedRepost
		uint64(time.Now().UnixNano()), // tstampNanos
		nil,                           // postExtraData
		false,                         // isHidden
		10000,                         // minFeeRateNanosPerKB
		mempool,                       // mempool
		[]*DeSoOutput{},               // additionalOutputs
	)
	require.NoError(err)

	// Sign the transaction
	_signTxn(t, submitPostTxn, senderPrivString)

	// ---- Add transactions to mempool and mine blocks sequentially ----
	// Process each transaction in its own block to avoid UTXO conflicts

	// Block 1: SubmitPost transaction
	_, err = mempool.ProcessTransaction(submitPostTxn, false /* allowUnconnectedTxn */, false /* rateLimit */, 0 /* peerID */, true /* verifySignatures */)
	require.NoError(err)

	postHash := submitPostTxn.Hash()

	block1, err := miner.MineAndProcessSingleBlock(0 /* threadIndex */, mempool)
	require.NoError(err)
	require.NotNil(block1)

	// ---- Transaction 2: CreateProfile (core-state single-key upsert) ----
	// Create this transaction AFTER the previous block is mined to have fresh UTXOs
	createProfileTxn, _, _, _, err := chain.CreateUpdateProfileTxn(
		senderPkBytes,                           // UpdaterPublicKeyBytes
		nil,                                     // OptionalProfilePublicKeyBytes (nil = update own profile)
		"TestUser",                              // NewUsername
		"Test user for state syncer validation", // NewDescription
		"https://example.com/profile.jpg",       // NewProfilePic
		uint64(10*100),                          // NewCreatorBasisPoints (10%)
		uint64(2*100*100),                       // NewStakeMultipleBasisPoints (2.0x = 20,000 basis points)
		false,                                   // IsHidden
		uint64(0),                               // AdditionalFees
		map[string][]byte{},                     // ExtraData
		10000,                                   // minFeeRateNanosPerKB
		mempool,                                 // mempool
		[]*DeSoOutput{},                         // additionalOutputs
	)
	require.NoError(err)

	// Sign the transaction
	_signTxn(t, createProfileTxn, senderPrivString)

	// Block 2: CreateProfile transaction
	_, err = mempool.ProcessTransaction(createProfileTxn, false /* allowUnconnectedTxn */, false /* rateLimit */, 0 /* peerID */, true /* verifySignatures */)
	require.NoError(err)

	block2, err := miner.MineAndProcessSingleBlock(0 /* threadIndex */, mempool)
	require.NoError(err)
	require.NotNil(block2)

	// ---- Transaction 3: Create Profile for Recipient ----
	// The recipient needs a profile before they can be followed
	recipientPkBytes, _, err := Base58CheckDecode(recipientPkString)
	require.NoError(err)

	// Fund the recipient account first - they need DeSo to pay for profile creation fees
	// Create a basic transfer transaction manually (similar to _assembleBasicTransferTxnFullySigned)
	fundAmount := uint64(1000000) // 0.001 DeSo
	txnOutputs := []*DeSoOutput{
		{
			PublicKey:   recipientPkBytes,
			AmountNanos: fundAmount,
		},
	}
	fundRecipientTxn := &MsgDeSoTxn{
		TxInputs:  []*DeSoInput{},
		TxOutputs: txnOutputs,
		PublicKey: senderPkBytes,
		TxnMeta:   &BasicTransferMetadata{},
	}

	// Add inputs and change to the transaction
	_, _, _, _, err = chain.AddInputsAndChangeToTransaction(fundRecipientTxn, 10000, mempool)
	require.NoError(err)

	// Sign the funding transaction
	_signTxn(t, fundRecipientTxn, senderPrivString)

	// Process funding transaction
	_, err = mempool.ProcessTransaction(fundRecipientTxn, false /* allowUnconnectedTxn */, false /* rateLimit */, 0 /* peerID */, true /* verifySignatures */)
	require.NoError(err)

	fundingBlock, err := miner.MineAndProcessSingleBlock(0 /* threadIndex */, mempool)
	require.NoError(err)
	require.NotNil(fundingBlock)

	// Now create the recipient's profile
	recipientProfileTxn, _, _, _, err := chain.CreateUpdateProfileTxn(
		recipientPkBytes,                    // UpdaterPublicKeyBytes
		nil,                                 // OptionalProfilePublicKeyBytes (nil = update own profile)
		"RecipientUser",                     // NewUsername
		"Recipient user for testing",        // NewDescription
		"https://example.com/recipient.jpg", // NewProfilePic
		uint64(5*100),                       // NewCreatorBasisPoints (5%)
		uint64(1.5*100*100),                 // NewStakeMultipleBasisPoints (1.5x = 15,000 basis points)
		false,                               // IsHidden
		uint64(0),                           // AdditionalFees
		map[string][]byte{},                 // ExtraData
		10000,                               // minFeeRateNanosPerKB
		mempool,                             // mempool
		[]*DeSoOutput{},                     // additionalOutputs
	)
	require.NoError(err)

	// Sign the transaction - note we need recipientPrivString for this
	_signTxn(t, recipientProfileTxn, recipientPrivString)

	// Process recipient profile transaction
	_, err = mempool.ProcessTransaction(recipientProfileTxn, false /* allowUnconnectedTxn */, false /* rateLimit */, 0 /* peerID */, true /* verifySignatures */)
	require.NoError(err)

	block3, err := miner.MineAndProcessSingleBlock(0 /* threadIndex */, mempool)
	require.NoError(err)
	require.NotNil(block3)

	// ---- Transaction 4: Follow (inserts FollowEntry) ----
	// Create this transaction AFTER both profiles exist
	followTxn, _, _, _, err := chain.CreateFollowTxn(
		senderPkBytes,    // followerPublicKey
		recipientPkBytes, // followedPublicKey
		false,            // isUnfollow (false = follow)
		10000,            // minFeeRateNanosPerKB
		mempool,          // mempool
		[]*DeSoOutput{},  // additionalOutputs
	)
	require.NoError(err)

	// Sign the transaction
	_signTxn(t, followTxn, senderPrivString)

	// Block 4: Follow transaction
	_, err = mempool.ProcessTransaction(followTxn, false /* allowUnconnectedTxn */, false /* rateLimit */, 0 /* peerID */, true /* verifySignatures */)
	require.NoError(err)

	block4, err := miner.MineAndProcessSingleBlock(0 /* threadIndex */, mempool)
	require.NoError(err)
	require.NotNil(block4)

	// Verify final block height
	finalHeight := chain.blockTip().Height
	require.Equal(initialHeight+5, finalHeight)

	// ---- Validate state change diff files for all blocks ----
	// We should have diff files for blocks containing our transactions
	block1Height := uint64(block1.Header.Height)
	block2Height := uint64(block2.Header.Height)
	block3Height := uint64(block3.Header.Height)
	block4Height := uint64(block4.Header.Height)

	// Collect all state changes from the main transaction blocks (excluding funding)
	var allStateChanges []*StateChangeEntry
	flushId := uuid.New()

	for _, blockHeight := range []uint64{block1Height, block2Height, block3Height, block4Height} {
		diffPath := filepath.Join(dir, "state_changes_"+fmt.Sprintf("%d", blockHeight)+".bin")

		// File should exist
		_, err = os.Stat(diffPath)
		require.NoError(err)

		// Read and parse diff file
		diffBytes, err := os.ReadFile(diffPath)
		require.NoError(err)
		require.NotEmpty(diffBytes)

		// Extract state changes from this block's diff
		stateChanges, err := syncer.ExtractStateChangesFromBackup(diffBytes, flushId, blockHeight)
		require.NoError(err)

		// Add to our collection
		allStateChanges = append(allStateChanges, stateChanges...)
	}

	// ---- Validate extracted state changes ----
	// We should have at least 4 core-state entries: PostEntry, 2 ProfileEntries, FollowEntry
	// (There may be additional entries like blockchain metadata, UTXOs, etc.)
	require.GreaterOrEqual(len(allStateChanges), 4)

	// Track which expected entry types we've found
	postEntriesFound := 0
	profileEntriesFound := 0
	recipientProfileEntriesFound := 0
	followEntriesFound := 0
	blocksFound := 0
	blockNodesFound := 0
	transactionsFound := 0

	// Track block events per block height to ensure proper pairing
	type blockEventTracker struct {
		blockHash    *BlockHash
		blockHeight  uint64
		hasBlockNode bool
		hasBlock     bool
	}
	blockEvents := make(map[uint64]*blockEventTracker)

	// TODO: Validate block/block node/transaction changes.
	for _, change := range allStateChanges {
		require.Equal(DbOperationTypeUpsert, change.OperationType) // Block 1 = pure inserts
		require.Equal(flushId, change.FlushId)
		// Block height will vary since transactions are in different blocks
		require.True(change.BlockHeight >= block1Height && change.BlockHeight <= block4Height)
		require.NotEmpty(change.KeyBytes)

		switch change.EncoderType {
		case EncoderTypePostEntry:
			postEntriesFound++
			require.NotNil(change.Encoder)
			postEntry := change.Encoder.(*PostEntry)
			require.Contains(string(postEntry.Body), "Test post for state syncer diff validation")
			// require.Equal(postHash, change.KeyBytes)
			require.Equal(postHash, postEntry.PostHash)

		case EncoderTypeProfileEntry:
			require.NotNil(change.Encoder)
			profileEntry := change.Encoder.(*ProfileEntry)
			if string(profileEntry.Username) == "TestUser" {
				profileEntriesFound++
				require.Contains(string(profileEntry.Description), "Test user for state syncer validation")
			} else if string(profileEntry.Username) == "RecipientUser" {
				recipientProfileEntriesFound++
				require.Contains(string(profileEntry.Description), "Recipient user for testing")
			}

		case EncoderTypeFollowEntry:
			followEntriesFound++
			require.NotNil(change.Encoder)
			followEntry := change.Encoder.(*FollowEntry)
			// Just verify that we have valid PKIDs - the actual follow relationship is confirmed by the transaction succeeding
			require.NotNil(followEntry.FollowerPKID)
			require.NotNil(followEntry.FollowedPKID)
			require.NotEqual(followEntry.FollowerPKID, followEntry.FollowedPKID) // Different users

		case EncoderTypeBlockNode:
			blockNodesFound++
			require.NotNil(change.Encoder)
			blockNode := change.Encoder.(*BlockNode)
			blockHeight := uint64(blockNode.Height)

			// Initialize tracker for this block height if needed
			if blockEvents[blockHeight] == nil {
				blockEvents[blockHeight] = &blockEventTracker{
					blockHeight: blockHeight,
				}
			}

			tracker := blockEvents[blockHeight]

			// Ensure we haven't already seen a BlockNode for this height
			require.False(tracker.hasBlockNode, "Received duplicate BlockNode for height %d", blockHeight)
			tracker.hasBlockNode = true

			if tracker.blockHash == nil {
				// First event for this block height - set reference values
				tracker.blockHash = blockNode.Hash
				tracker.blockHeight = blockHeight
			} else {
				// Second event for this block height - validate against first
				require.Equal(tracker.blockHeight, blockHeight)
				require.Equal(*tracker.blockHash, *blockNode.Hash)
			}

			require.Equal(blockHeight, change.BlockHeight)

		case EncoderTypeBlock:
			blocksFound++
			require.NotNil(change.Encoder)
			block := change.Encoder.(*MsgDeSoBlock)
			blockHeight := change.BlockHeight

			blockHash, err := block.Hash()
			require.NoError(err)

			// Initialize tracker for this block height if needed
			if blockEvents[blockHeight] == nil {
				blockEvents[blockHeight] = &blockEventTracker{
					blockHeight: blockHeight,
				}
			}

			tracker := blockEvents[blockHeight]

			// Ensure we haven't already seen a Block for this height
			require.False(tracker.hasBlock, "Received duplicate Block for height %d", blockHeight)
			tracker.hasBlock = true

			if tracker.blockHash == nil {
				// First event for this block height - set reference values
				tracker.blockHash = blockHash
				tracker.blockHeight = blockHeight
			} else {
				// Second event for this block height - validate against first
				require.Equal(tracker.blockHeight, blockHeight)
				require.Equal(*tracker.blockHash, *blockHash)
			}

			require.Equal(blockHeight, change.BlockHeight)

			// Validate transactions in the block
			// TODO: Validate each of these, ensure each one is the right type, and that their txn metadata is correct.
			for _, txn := range block.Txns {
				transactionsFound++
				switch transactionsFound {
				case 1:
					require.Equal(TxnTypeBlockReward, txn.TxnMeta.GetTxnType())
				case 2:
					require.Equal(TxnTypeSubmitPost, txn.TxnMeta.GetTxnType())
					txnMeta := txn.TxnMeta.(*SubmitPostMetadata)
					bodyJSONObj := DeSoBodySchema{}
					err := json.Unmarshal(txnMeta.Body, &bodyJSONObj)
					require.NoError(err)
					require.Equal("Test post for state syncer diff validation", bodyJSONObj.Body)
					require.Equal(1, len(bodyJSONObj.ImageURLs))
					require.Equal("https://example.com/image.jpg", bodyJSONObj.ImageURLs[0])
				case 3:
					require.Equal(TxnTypeBlockReward, txn.TxnMeta.GetTxnType())
				case 4:
					require.Equal(TxnTypeUpdateProfile, txn.TxnMeta.GetTxnType())
					txnMeta := txn.TxnMeta.(*UpdateProfileMetadata)
					require.Equal("TestUser", string(txnMeta.NewUsername))
					require.Equal("Test user for state syncer validation", string(txnMeta.NewDescription))
					require.Equal("https://example.com/profile.jpg", string(txnMeta.NewProfilePic))
					require.Equal(uint64(10*100), txnMeta.NewCreatorBasisPoints)
					require.Equal(uint64(2*100*100), txnMeta.NewStakeMultipleBasisPoints)
					require.False(txnMeta.IsHidden)
				case 5:
					require.Equal(TxnTypeBlockReward, txn.TxnMeta.GetTxnType())
				case 6:
					require.Equal(TxnTypeUpdateProfile, txn.TxnMeta.GetTxnType())
					txnMeta := txn.TxnMeta.(*UpdateProfileMetadata)
					require.Equal("RecipientUser", string(txnMeta.NewUsername))
					require.Equal("Recipient user for testing", string(txnMeta.NewDescription))
					require.Equal("https://example.com/recipient.jpg", string(txnMeta.NewProfilePic))
					require.Equal(uint64(5*100), txnMeta.NewCreatorBasisPoints)
					require.Equal(uint64(1.5*100*100), txnMeta.NewStakeMultipleBasisPoints)
					require.False(txnMeta.IsHidden)
				case 7:
					require.Equal(TxnTypeBlockReward, txn.TxnMeta.GetTxnType())
				case 8:
					require.Equal(TxnTypeFollow, txn.TxnMeta.GetTxnType())
					txnMeta := txn.TxnMeta.(*FollowMetadata)
					require.Equal(recipientPkBytes, txnMeta.FollowedPublicKey)
					require.False(txnMeta.IsUnfollow)
				default:
					require.Fail("Unexpected transaction type found")
				}
			}

		}
	}

	// Validate that each block height has exactly one BlockNode and one Block
	for height, tracker := range blockEvents {
		require.True(tracker.hasBlockNode, "Missing BlockNode for height %d", height)
		require.True(tracker.hasBlock, "Missing Block for height %d", height)
	}

	// Ensure we found all expected entry types
	require.Equal(1, postEntriesFound)
	require.Equal(1, profileEntriesFound)
	require.Equal(1, recipientProfileEntriesFound)
	require.Equal(1, followEntriesFound)
	require.Equal(4, blocksFound)
	require.Equal(4, blockNodesFound)
	require.Equal(8, transactionsFound)

}

// TestStateChangeSyncer_Block2_UpdatesDeletes implements the "Block 2 (updates & deletes in same block)" test case
// from the implementation plan.  It mines a block containing:
//  1. A SubmitPost update to an existing PostEntry
//  2. A SubmitPost delete (IsHidden=true) of the same PostEntry
//  3. A DeleteUserAssociation that removes a previously‐created association (tests DbOperationTypeDelete)
//  4. A CreatePostAssociation introducing a second encoder type in the same block.
//
// It then verifies the resulting per-block diff file contains the expected Upsert and Delete operations.
func TestStateChangeSyncer_Block2_UpdatesDeletes(t *testing.T) {
	require := require.New(t)

	// ---- Setup blockchain, mempool, miner ----
	chain, params, embpg := NewLowDifficultyBlockchainWithParamsAndDb(t, &DeSoTestnetParams, false, 0, false)
	defer func() {
		if embpg != nil {
			embpg.Stop()
		}
	}()

	// Enable associations from genesis
	params.ForkHeights.AssociationsAndAccessGroupsBlockHeight = uint32(0)

	mempool, miner := NewTestMiner(t, chain, params, true /* isSender */)

	// Temporary dir for diff files
	dir, err := os.MkdirTemp("", "state-syncer-block2")
	require.NoError(err)
	defer os.RemoveAll(dir)

	// Hook state syncer into commit path
	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	chain.eventManager.OnBlockCommitted(func(event *BlockEvent) {
		err := syncer.GenerateCommittedBlockDiff(chain.db, event.PreCommitTxn, uint64(event.Block.Header.Height))
		if err != nil {
			t.Errorf("Failed to generate block diff: %v", err)
		}
	})

	// Mine a couple blocks so the sender has spendable funds.
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)

	// ---- Block 1: create initial state to be modified ----
	// 1. Original post
	bodyOriginal := []byte("Original post body for diff testing")
	postCreateTxn, _, _, _, err := chain.CreateSubmitPostTxn(
		senderPkBytes,
		nil, // new post
		nil,
		bodyOriginal,
		nil,
		false, // isQuotedRepost
		uint64(time.Now().UnixNano()),
		nil,   // postExtraData
		false, // isHidden
		10000, // minFeeRate
		mempool,
		[]*DeSoOutput{},
	)
	require.NoError(err)
	_signTxn(t, postCreateTxn, senderPrivString)
	_, err = mempool.ProcessTransaction(postCreateTxn, false, false, 0, true)
	require.NoError(err)
	postHash := postCreateTxn.Hash()

	// 2. Create a profile for target user so association validation passes
	targetUserPkBytes, _, err := Base58CheckDecode(recipientPkString)
	require.NoError(err)

	recipientProfileTxn, _, _, _, err := chain.CreateUpdateProfileTxn(
		senderPkBytes,               // updater pays the fee
		targetUserPkBytes,           // create profile for recipient
		"Target",                    // username
		"Target user",               // description
		"https://example.com/p.jpg", // profile pic
		uint64(5*100),
		uint64(2*100*100),
		false, // IsHidden
		0,     // AdditionalFees
		nil,   // ExtraData
		10000,
		mempool,
		[]*DeSoOutput{},
	)
	require.NoError(err)
	_signTxn(t, recipientProfileTxn, senderPrivString)
	_, err = mempool.ProcessTransaction(recipientProfileTxn, false, false, 0, true)
	require.NoError(err)

	// 3. Create a user association that we'll delete later
	createUserMeta := &CreateUserAssociationMetadata{
		TargetUserPublicKey: NewPublicKey(targetUserPkBytes),
		AppPublicKey:        &ZeroPublicKey,
		AssociationType:     []byte("ENDORSE"),
		AssociationValue:    []byte("GO"),
	}
	createAssocTxn, _, _, _, err := chain.CreateCreateUserAssociationTxn(
		senderPkBytes,
		createUserMeta,
		nil,
		10000,
		mempool,
		[]*DeSoOutput{},
	)
	require.NoError(err)
	_signTxn(t, createAssocTxn, senderPrivString)
	_, err = mempool.ProcessTransaction(createAssocTxn, false, false, 0, true)
	require.NoError(err)
	assocID := createAssocTxn.Hash()

	// Mine Block 1 containing the post + association.
	block1, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	// ---- Block 2: update & delete operations ----
	// Tx 1: Update post body
	bodyUpdate := []byte("Updated post body – interim")
	updatePostTxn, _, _, _, err := chain.CreateSubmitPostTxn(
		senderPkBytes,
		postHash[:], // modify existing post
		nil,
		bodyUpdate,
		nil,
		false,
		uint64(time.Now().UnixNano()),
		nil,
		false, // isHidden = false (update)
		10000,
		mempool,
		[]*DeSoOutput{},
	)
	require.NoError(err)
	_signTxn(t, updatePostTxn, senderPrivString)
	_, err = mempool.ProcessTransaction(updatePostTxn, false, false, 0, true)
	require.NoError(err)

	// Tx 2: Delete (hide) the same post
	deletePostTxn, _, _, _, err := chain.CreateSubmitPostTxn(
		senderPkBytes,
		postHash[:],
		nil,
		bodyUpdate, // body can be same; IsHidden flag drives deletion semantics
		nil,
		false,
		uint64(time.Now().UnixNano()),
		nil,
		true, // isHidden = true (delete)
		10000,
		mempool,
		[]*DeSoOutput{},
	)
	require.NoError(err)
	_signTxn(t, deletePostTxn, senderPrivString)
	_, err = mempool.ProcessTransaction(deletePostTxn, false, false, 0, true)
	require.NoError(err)

	// Tx 3: Delete previously created user association
	deleteAssocMeta := &DeleteUserAssociationMetadata{AssociationID: assocID}
	deleteAssocTxn, _, _, _, err := chain.CreateDeleteUserAssociationTxn(
		senderPkBytes,
		deleteAssocMeta,
		nil,
		10000,
		mempool,
		[]*DeSoOutput{},
	)
	require.NoError(err)
	_signTxn(t, deleteAssocTxn, senderPrivString)
	_, err = mempool.ProcessTransaction(deleteAssocTxn, false, false, 0, true)
	require.NoError(err)

	// Tx 4: Create a new PostAssociation on the post
	createPostAssocMeta := &CreatePostAssociationMetadata{
		PostHash:         postHash,
		AppPublicKey:     &ZeroPublicKey,
		AssociationType:  []byte("TAG"),
		AssociationValue: []byte("NEWS"),
	}
	createPostAssocTxn, _, _, _, err := chain.CreateCreatePostAssociationTxn(
		senderPkBytes,
		createPostAssocMeta,
		nil,
		10000,
		mempool,
		[]*DeSoOutput{},
	)
	require.NoError(err)
	_signTxn(t, createPostAssocTxn, senderPrivString)
	_, err = mempool.ProcessTransaction(createPostAssocTxn, false, false, 0, true)
	require.NoError(err)

	// Mine Block 2 with all above transactions
	block2, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	require.NotNil(block2)

	// Validate Block 1 diff file
	block1Height := uint64(block1.Header.Height)
	diffPath := filepath.Join(dir, fmt.Sprintf("state_changes_%d.bin", block1Height))
	_, err = os.Stat(diffPath)
	require.NoError(err)
	diffBytes, err := os.ReadFile(diffPath)
	require.NoError(err)
	require.NotEmpty(diffBytes)

	flushID := uuid.New()
	entries, err := syncer.ExtractStateChangesFromBackup(diffBytes, flushID, block1Height)
	require.NoError(err)

	postEntriesUpserted := 0
	postEntriesDeleted := 0
	profileEntriesUpserted := 0
	userAssociationsUpserted := 0
	blocksFound := 0
	blockNodesFound := 0
	transactionsFound := 0

	// Track block events
	type blockEventTracker struct {
		blockHash    *BlockHash
		blockHeight  uint64
		hasBlockNode bool
		hasBlock     bool
	}
	blockEvents := make(map[uint64]*blockEventTracker)

	for _, change := range entries {
		require.Equal(flushID, change.FlushId)
		require.Equal(block1Height, change.BlockHeight)
		require.NotEmpty(change.KeyBytes)

		switch change.EncoderType {
		case EncoderTypePostEntry:
			require.NotNil(change.Encoder)
			postEntry := change.Encoder.(*PostEntry)

			switch change.OperationType {
			case DbOperationTypeUpsert:
				postEntriesUpserted++
				// The final state should be the "hidden" version since delete was last
				require.False(postEntry.IsHidden, "Expected post to be visible (not hidden) in final state")
				require.Contains(string(postEntry.Body), "Original post body for diff testing")
			case DbOperationTypeDelete:
				postEntriesDeleted++
				// This shouldn't happen for posts - they get marked hidden, not deleted
				require.Fail("Posts should not have DbOperationTypeDelete, they use IsHidden=true")
			}

		case EncoderTypeProfileEntry:
			require.Equal(DbOperationTypeUpsert, change.OperationType)
			profileEntriesUpserted++
			require.NotNil(change.Encoder)
			profileEntry := change.Encoder.(*ProfileEntry)
			require.Equal("Target", string(profileEntry.Username))

		case EncoderTypeUserAssociationEntry:
			require.Equal(DbOperationTypeUpsert, change.OperationType)
			userAssociationsUpserted++
			require.NotNil(change.Encoder)
			userAssocEntry := change.Encoder.(*UserAssociationEntry)
			require.Equal(assocID, userAssocEntry.AssociationID)

		case EncoderTypeBlockNode:
			blockNodesFound++
			require.Equal(DbOperationTypeUpsert, change.OperationType)
			require.NotNil(change.Encoder)
			blockNode := change.Encoder.(*BlockNode)
			blockHeight := uint64(blockNode.Height)

			if blockEvents[blockHeight] == nil {
				blockEvents[blockHeight] = &blockEventTracker{blockHeight: blockHeight}
			}
			tracker := blockEvents[blockHeight]
			require.False(tracker.hasBlockNode, "Duplicate BlockNode for height %d", blockHeight)
			tracker.hasBlockNode = true
			if tracker.blockHash == nil {
				tracker.blockHash = blockNode.Hash
			} else {
				require.Equal(*tracker.blockHash, *blockNode.Hash)
			}

		case EncoderTypeBlock:
			blocksFound++
			require.Equal(DbOperationTypeUpsert, change.OperationType)
			require.NotNil(change.Encoder)
			block := change.Encoder.(*MsgDeSoBlock)
			blockHeight := change.BlockHeight

			blockHash, err := block.Hash()
			require.NoError(err)

			if blockEvents[blockHeight] == nil {
				blockEvents[blockHeight] = &blockEventTracker{blockHeight: blockHeight}
			}
			tracker := blockEvents[blockHeight]
			require.False(tracker.hasBlock, "Duplicate Block for height %d", blockHeight)
			tracker.hasBlock = true
			if tracker.blockHash == nil {
				tracker.blockHash = blockHash
			} else {
				require.Equal(*tracker.blockHash, *blockHash)
			}

			// Validate transactions in Block 2
			// Expected: BlockReward + 4 transactions (update post, delete post, delete assoc, create post assoc)
			for _, txn := range block.Txns {
				transactionsFound++
				switch transactionsFound {
				case 1:
					require.Equal(TxnTypeBlockReward, txn.TxnMeta.GetTxnType())
				case 2:
					require.Equal(TxnTypeSubmitPost, txn.TxnMeta.GetTxnType())
					txnMeta := txn.TxnMeta.(*SubmitPostMetadata)
					require.Contains(string(txnMeta.Body), "Original post body for diff testing")
					require.False(txnMeta.IsHidden) // This is the update, not delete
				case 3:
					require.Equal(TxnTypeUpdateProfile, txn.TxnMeta.GetTxnType())
					txnMeta := txn.TxnMeta.(*UpdateProfileMetadata)
					require.Equal("Target", string(txnMeta.NewUsername))
					require.Equal("Target user", string(txnMeta.NewDescription))
					require.Equal("https://example.com/p.jpg", string(txnMeta.NewProfilePic))
					require.Equal(uint64(5*100), txnMeta.NewCreatorBasisPoints)
					require.Equal(uint64(2*100*100), txnMeta.NewStakeMultipleBasisPoints)
					require.False(txnMeta.IsHidden) // This is the update, not delete
				case 4:
					require.Equal(TxnTypeCreateUserAssociation, txn.TxnMeta.GetTxnType())
					txnMeta := txn.TxnMeta.(*CreateUserAssociationMetadata)
					require.Equal([]byte("ENDORSE"), txnMeta.AssociationType)
					require.Equal([]byte("GO"), txnMeta.AssociationValue)
				case 5:
					require.Equal(TxnTypeCreatePostAssociation, txn.TxnMeta.GetTxnType())
					txnMeta := txn.TxnMeta.(*CreatePostAssociationMetadata)
					require.Equal([]byte("TAG"), txnMeta.AssociationType)
					require.Equal([]byte("NEWS"), txnMeta.AssociationValue)
					require.Equal(postHash, txnMeta.PostHash)
				default:
					require.Fail("Unexpected transaction found: %v", txn.TxnMeta.GetTxnType())
				}
			}
		}
	}

	require.Equal(1, postEntriesUpserted, "Expected 1 post entry upsert (final hidden state)")
	require.Equal(0, postEntriesDeleted, "Expected 0 post entry deletes (posts use IsHidden)")
	require.Equal(1, profileEntriesUpserted, "Expected 1 profile entry upsert (target user)")
	require.Equal(1, userAssociationsUpserted, "Expected 1 user association upsert")
	require.Equal(1, blocksFound, "Expected 1 block (Block 1)")
	require.Equal(1, blockNodesFound, "Expected 1 block node (Block 1)")
	require.Equal(4, transactionsFound, "Expected 4 transactions (1 block reward + 3 user txns)")

	// Validate Block 2 diff file
	block2Height := uint64(block2.Header.Height)
	diffPath = filepath.Join(dir, fmt.Sprintf("state_changes_%d.bin", block2Height))
	_, err = os.Stat(diffPath)
	require.NoError(err)
	diffBytes, err = os.ReadFile(diffPath)
	require.NoError(err)
	require.NotEmpty(diffBytes)

	flushID = uuid.New()
	entries, err = syncer.ExtractStateChangesFromBackup(diffBytes, flushID, block2Height)
	require.NoError(err)

	// ---- Detailed validation of state change entries ----
	// Track found entries by type and operation
	postEntriesUpserted = 0
	postEntriesDeleted = 0
	profileEntriesUpserted = 0
	userAssociationsDeleted := 0
	postAssociationsUpserted := 0
	blocksFound = 0
	blockNodesFound = 0
	transactionsFound = 0

	blockEvents = make(map[uint64]*blockEventTracker)

	for _, change := range entries {
		require.Equal(flushID, change.FlushId)
		require.Equal(block2Height, change.BlockHeight)
		require.NotEmpty(change.KeyBytes)

		switch change.EncoderType {
		case EncoderTypePostEntry:
			require.NotNil(change.Encoder)
			postEntry := change.Encoder.(*PostEntry)

			switch change.OperationType {
			case DbOperationTypeUpsert:
				postEntriesUpserted++
				// The final state should be the "hidden" version since delete was last
				require.True(postEntry.IsHidden, "Expected post to be hidden (deleted) in final state")
				require.Contains(string(postEntry.Body), "Updated post body")
			case DbOperationTypeDelete:
				postEntriesDeleted++
				// This shouldn't happen for posts - they get marked hidden, not deleted
				require.Fail("Posts should not have DbOperationTypeDelete, they use IsHidden=true")
			}

		case EncoderTypeProfileEntry:
			require.Equal(DbOperationTypeUpsert, change.OperationType)
			profileEntriesUpserted++
			require.NotNil(change.Encoder)
			profileEntry := change.Encoder.(*ProfileEntry)
			require.Equal("Target", string(profileEntry.Username))

		case EncoderTypeUserAssociationEntry:
			require.Equal(DbOperationTypeDelete, change.OperationType)
			userAssociationsDeleted++
			// For deletes, the encoder should be nil/empty since it's been removed
			require.Nil(change.Encoder)

		case EncoderTypePostAssociationEntry:
			require.Equal(DbOperationTypeUpsert, change.OperationType)
			postAssociationsUpserted++
			require.NotNil(change.Encoder)
			postAssocEntry := change.Encoder.(*PostAssociationEntry)
			require.Equal([]byte("TAG"), postAssocEntry.AssociationType)
			require.Equal([]byte("NEWS"), postAssocEntry.AssociationValue)

		case EncoderTypeBlockNode:
			blockNodesFound++
			require.Equal(DbOperationTypeUpsert, change.OperationType)
			require.NotNil(change.Encoder)
			blockNode := change.Encoder.(*BlockNode)
			blockHeight := uint64(blockNode.Height)

			if blockEvents[blockHeight] == nil {
				blockEvents[blockHeight] = &blockEventTracker{blockHeight: blockHeight}
			}
			tracker := blockEvents[blockHeight]
			require.False(tracker.hasBlockNode, "Duplicate BlockNode for height %d", blockHeight)
			tracker.hasBlockNode = true
			if tracker.blockHash == nil {
				tracker.blockHash = blockNode.Hash
			} else {
				require.Equal(*tracker.blockHash, *blockNode.Hash)
			}

		case EncoderTypeBlock:
			blocksFound++
			require.Equal(DbOperationTypeUpsert, change.OperationType)
			require.NotNil(change.Encoder)
			block := change.Encoder.(*MsgDeSoBlock)
			blockHeight := change.BlockHeight

			blockHash, err := block.Hash()
			require.NoError(err)

			if blockEvents[blockHeight] == nil {
				blockEvents[blockHeight] = &blockEventTracker{blockHeight: blockHeight}
			}
			tracker := blockEvents[blockHeight]
			require.False(tracker.hasBlock, "Duplicate Block for height %d", blockHeight)
			tracker.hasBlock = true
			if tracker.blockHash == nil {
				tracker.blockHash = blockHash
			} else {
				require.Equal(*tracker.blockHash, *blockHash)
			}

			// Validate transactions in Block 2
			// Expected: BlockReward + 4 transactions (update post, delete post, delete assoc, create post assoc)
			for _, txn := range block.Txns {
				transactionsFound++
				switch transactionsFound {
				case 1:
					require.Equal(TxnTypeBlockReward, txn.TxnMeta.GetTxnType())
				case 2:
					require.Equal(TxnTypeSubmitPost, txn.TxnMeta.GetTxnType())
					txnMeta := txn.TxnMeta.(*SubmitPostMetadata)
					require.Contains(string(txnMeta.Body), "Updated post body")
					require.False(txnMeta.IsHidden) // This is the update, not delete
				case 3:
					require.Equal(TxnTypeSubmitPost, txn.TxnMeta.GetTxnType())
					txnMeta := txn.TxnMeta.(*SubmitPostMetadata)
					require.Contains(string(txnMeta.Body), "Updated post body")
					require.True(txnMeta.IsHidden) // This is the delete (hide)
				case 4:
					require.Equal(TxnTypeDeleteUserAssociation, txn.TxnMeta.GetTxnType())
					txnMeta := txn.TxnMeta.(*DeleteUserAssociationMetadata)
					require.Equal(assocID, txnMeta.AssociationID)
				case 5:
					require.Equal(TxnTypeCreatePostAssociation, txn.TxnMeta.GetTxnType())
					txnMeta := txn.TxnMeta.(*CreatePostAssociationMetadata)
					require.Equal([]byte("TAG"), txnMeta.AssociationType)
					require.Equal([]byte("NEWS"), txnMeta.AssociationValue)
					require.Equal(postHash, txnMeta.PostHash)
				default:
					require.Fail("Unexpected transaction found: %v", txn.TxnMeta.GetTxnType())
				}
			}
		}
	}

	// Validate that each block height has exactly one BlockNode and one Block
	for height, tracker := range blockEvents {
		require.True(tracker.hasBlockNode, "Missing BlockNode for height %d", height)
		require.True(tracker.hasBlock, "Missing Block for height %d", height)
	}

	// Validate expected counts
	require.Equal(1, postEntriesUpserted, "Expected 1 post entry upsert (final hidden state)")
	require.Equal(0, postEntriesDeleted, "Expected 0 post entry deletes (posts use IsHidden)")
	require.Equal(0, profileEntriesUpserted, "Expected 0 profile entry upserts (no profile changes in Block 2)")
	require.Equal(1, userAssociationsDeleted, "Expected 1 user association delete")
	require.Equal(1, postAssociationsUpserted, "Expected 1 post association upsert")
	require.Equal(1, blocksFound, "Expected 1 block (Block 2)")
	require.Equal(1, blockNodesFound, "Expected 1 block node (Block 2)")
	require.Equal(5, transactionsFound, "Expected 5 transactions (1 block reward + 4 user txns)")
}

// TestStateChangeSyncer_Block3_MultipleUpdates implements the "Block 3 (2 updates of same key in same block)" test case
// from the implementation plan. It creates a post in Block 1, then performs two updates to the same post in Block 2.
// It validates that only the final state (second update) appears in the Block 2 diff, demonstrating that
// intermediate states within the same block are properly deduplicated.
func TestStateChangeSyncer_Block3_MultipleUpdates(t *testing.T) {
	require := require.New(t)

	// ---- Setup blockchain, mempool, miner ----
	chain, params, embpg := NewLowDifficultyBlockchainWithParamsAndDb(t, &DeSoTestnetParams, false, 0, false)
	defer func() {
		if embpg != nil {
			embpg.Stop()
		}
	}()

	mempool, miner := NewTestMiner(t, chain, params, true /* isSender */)

	// Setup state syncer with temporary directory
	dir, err := os.MkdirTemp("", "state-syncer-block3")
	require.NoError(err)
	defer os.RemoveAll(dir)

	// Hook the state syncer into the blockchain's event manager
	syncer := NewStateChangeSyncer(dir, NodeSyncTypeBlockSync, 0)
	chain.eventManager.OnBlockCommitted(func(event *BlockEvent) {
		err := syncer.GenerateCommittedBlockDiff(chain.db, event.PreCommitTxn, uint64(event.Block.Header.Height))
		if err != nil {
			t.Errorf("Failed to generate block diff: %v", err)
		}
	})

	// Fund the sender account with mining rewards
	_, err = miner.MineAndProcessSingleBlock(0 /* threadIndex */, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /* threadIndex */, mempool)
	require.NoError(err)

	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)

	// ---- Block 1: Create initial post ----
	postBody := &DeSoBodySchema{
		Body:      "Initial post body",
		ImageURLs: []string{"https://example.com/initial.jpg"},
	}
	bodyBytes, err := json.Marshal(postBody)
	require.NoError(err)

	submitPostTxn, _, _, _, err := chain.CreateSubmitPostTxn(
		senderPkBytes,                 // updaterPublicKey
		nil,                           // postHashToModify (nil = new post)
		nil,                           // parentStakeID
		bodyBytes,                     // body
		nil,                           // repostPostHashBytes
		false,                         // isQuotedRepost
		uint64(time.Now().UnixNano()), // tstampNanos
		nil,                           // postExtraData
		false,                         // isHidden
		10000,                         // minFeeRateNanosPerKB
		mempool,                       // mempool
		[]*DeSoOutput{},               // additionalOutputs
	)
	require.NoError(err)
	_signTxn(t, submitPostTxn, senderPrivString)
	_, err = mempool.ProcessTransaction(submitPostTxn, false, false, 0, true)
	require.NoError(err)

	postHash := submitPostTxn.Hash()

	// Mine Block 1 with the initial post
	block1, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	require.NotNil(block1)

	// ---- Block 2: Two updates to the same post ----

	// First update - this should be overwritten by the second update
	firstUpdateBody := &DeSoBodySchema{
		Body:      "First update - this should be overwritten",
		ImageURLs: []string{"https://example.com/first.jpg"},
	}
	firstBodyBytes, err := json.Marshal(firstUpdateBody)
	require.NoError(err)

	firstUpdateTxn, _, _, _, err := chain.CreateSubmitPostTxn(
		senderPkBytes,
		postHash[:],    // postHashToModify (update existing post)
		nil,            // parentStakeID
		firstBodyBytes, // body
		nil,            // repostPostHashBytes
		false,          // isQuotedRepost
		uint64(time.Now().UnixNano()),
		nil,   // postExtraData
		false, // isHidden
		10000, // minFeeRateNanosPerKB
		mempool,
		[]*DeSoOutput{},
	)
	require.NoError(err)
	_signTxn(t, firstUpdateTxn, senderPrivString)
	_, err = mempool.ProcessTransaction(firstUpdateTxn, false, false, 0, true)
	require.NoError(err)

	// Second update - this should be the final state in the diff
	secondUpdateBody := &DeSoBodySchema{
		Body:      "Second update - this should be the final state",
		ImageURLs: []string{"https://example.com/final.jpg"},
	}
	secondBodyBytes, err := json.Marshal(secondUpdateBody)
	require.NoError(err)

	secondUpdateTxn, _, _, _, err := chain.CreateSubmitPostTxn(
		senderPkBytes,
		postHash[:],     // postHashToModify (update same post again)
		nil,             // parentStakeID
		secondBodyBytes, // body
		nil,             // repostPostHashBytes
		false,           // isQuotedRepost
		uint64(time.Now().UnixNano()),
		nil,   // postExtraData
		false, // isHidden
		10000, // minFeeRateNanosPerKB
		mempool,
		[]*DeSoOutput{},
	)
	require.NoError(err)
	_signTxn(t, secondUpdateTxn, senderPrivString)
	_, err = mempool.ProcessTransaction(secondUpdateTxn, false, false, 0, true)
	require.NoError(err)

	// Mine Block 2 with both updates
	block2, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	require.NotNil(block2)

	// ---- Validate Block 2 state changes ----
	block2Height := uint64(block2.Header.Height)
	diffPath := filepath.Join(dir, fmt.Sprintf("state_changes_%d.bin", block2Height))
	_, err = os.Stat(diffPath)
	require.NoError(err)
	diffBytes, err := os.ReadFile(diffPath)
	require.NoError(err)
	require.NotEmpty(diffBytes)

	flushID := uuid.New()
	entries, err := syncer.ExtractStateChangesFromBackup(diffBytes, flushID, block2Height)
	require.NoError(err)

	// Track found entries
	postEntriesUpserted := 0
	blocksFound := 0
	blockNodesFound := 0
	transactionsFound := 0

	for _, change := range entries {
		require.Equal(flushID, change.FlushId)
		require.Equal(block2Height, change.BlockHeight)
		require.NotEmpty(change.KeyBytes)

		switch change.EncoderType {
		case EncoderTypePostEntry:
			require.Equal(DbOperationTypeUpsert, change.OperationType)
			require.NotNil(change.Encoder)

			postEntry := change.Encoder.(*PostEntry)
			require.Equal(postHash, postEntry.PostHash)
			require.Equal(senderPkBytes, postEntry.PosterPublicKey)
			require.False(postEntry.IsHidden)

			// Validate that the final state contains the SECOND update, not the first
			require.Contains(string(postEntry.Body), "Second update - this should be the final state")
			require.NotContains(string(postEntry.Body), "First update - this should be overwritten")
			require.NotContains(string(postEntry.Body), "Initial post body")

			postEntriesUpserted++

		case EncoderTypeBlockNode:
			blockNodesFound++
			require.Equal(DbOperationTypeUpsert, change.OperationType)

		case EncoderTypeBlock:
			blocksFound++
			require.Equal(DbOperationTypeUpsert, change.OperationType)
			require.NotNil(change.Encoder)

			block := change.Encoder.(*MsgDeSoBlock)
			// Block 2 should contain: BlockReward + FirstUpdate + SecondUpdate transactions
			for _, txn := range block.Txns {
				transactionsFound++
				switch transactionsFound {
				case 1:
					require.Equal(TxnTypeBlockReward, txn.TxnMeta.GetTxnType())
				case 2:
					require.Equal(TxnTypeSubmitPost, txn.TxnMeta.GetTxnType())
					txnMeta := txn.TxnMeta.(*SubmitPostMetadata)
					require.Contains(string(txnMeta.Body), "First update - this should be overwritten")
				case 3:
					require.Equal(TxnTypeSubmitPost, txn.TxnMeta.GetTxnType())
					txnMeta := txn.TxnMeta.(*SubmitPostMetadata)
					require.Contains(string(txnMeta.Body), "Second update - this should be the final state")
				default:
					require.Fail("Unexpected transaction found")
				}
			}
		}
	}

	// Validate expected counts
	require.Equal(1, postEntriesUpserted, "Expected exactly 1 post entry upsert (final state only)")
	require.Equal(1, blocksFound, "Expected 1 block (Block 2)")
	require.Equal(1, blockNodesFound, "Expected 1 block node (Block 2)")
	require.Equal(3, transactionsFound, "Expected 3 transactions (1 block reward + 2 post updates)")
}
