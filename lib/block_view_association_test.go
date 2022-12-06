package lib

import (
	"errors"
	"github.com/stretchr/testify/require"
	"math"
	"sort"
	"testing"
)

func TestAssociations(t *testing.T) {
	// Run all tests twice: once flushing all txns to the
	// db, and once just keeping all txns in the mempool.
	_testAssociations(t, true)
	_testAssociations(t, false)
}

func _testAssociations(t *testing.T, flushToDB bool) {
	// -----------------------
	// Initialization
	// -----------------------
	var createUserAssociationMetadata *CreateUserAssociationMetadata
	var deleteUserAssociationMetadata *DeleteUserAssociationMetadata
	var associationID *BlockHash
	var userAssociationEntry *UserAssociationEntry
	var userAssociationEntries []*UserAssociationEntry
	var createPostAssociationMetadata *CreatePostAssociationMetadata
	var deletePostAssociationMetadata *DeletePostAssociationMetadata
	var postAssociationEntry *PostAssociationEntry
	var postAssociationEntries []*PostAssociationEntry
	var submitPostMetadata *SubmitPostMetadata
	var postHash *BlockHash
	var err error

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true)
	params.ForkHeights.AssociationsBlockHeight = uint32(0)

	utxoView := func() *UtxoView {
		newUtxoView, err := mempool.GetAugmentedUniversalView()
		require.NoError(t, err)
		return newUtxoView
	}

	// Mine a few blocks to give the senderPkString some money.
	for ii := 0; ii < 10; ii++ {
		_, err = miner.MineAndProcessSingleBlock(0, mempool)
		require.NoError(t, err)
	}

	// We build the testMeta obj after mining blocks so that we save the correct block height.
	testMeta := &TestMeta{
		t:                 t,
		chain:             chain,
		params:            params,
		db:                db,
		mempool:           mempool,
		miner:             miner,
		savedHeight:       chain.blockTip().Height + 1,
		feeRateNanosPerKb: uint64(101),
	}

	_registerOrTransferWithTestMeta(testMeta, "m0", senderPkString, m0Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m1", senderPkString, m1Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m2", senderPkString, m2Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m3", senderPkString, m3Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m4", senderPkString, m4Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 1e3)

	m0PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m0PkBytes).PKID
	m1PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m1PkBytes).PKID
	m2PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m2PkBytes).PKID
	m3PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m3PkBytes).PKID
	m4PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m4PkBytes).PKID
	_, _, _, _, _ = m0PKID, m1PKID, m2PKID, m3PKID, m4PKID

	{
		// Param Updater set min fee rate to 101 nanos per KB
		params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			paramUpdaterPub,
			paramUpdaterPriv,
			-1,
			int64(testMeta.feeRateNanosPerKb),
			-1,
			-1,
			-1,
		)
	}

	// -------------------------------
	// UserAssociation: validations
	// -------------------------------
	{
		// RuleErrorAssociationBeforeBlockHeight
		params.ForkHeights.AssociationsBlockHeight = math.MaxUint32
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "SQL",
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationBeforeBlockHeight)
		params.ForkHeights.AssociationsBlockHeight = uint32(0)
	}
	{
		// RuleErrorUserAssociationInvalidTargetUser
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  "ENDORSEMENT",
			AssociationValue: "SQL",
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorUserAssociationInvalidTargetUser)
	}
	{
		// RuleErrorAssociationInvalidApp
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "SQL",
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidApp)
	}
	{
		// RuleErrorAssociationInvalidType: AssociationType is empty
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     "",
			AssociationValue:    "SQL",
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidType)
	}
	{
		// RuleErrorAssociationInvalidType: AssociationType is too long
		var associationType []byte
		for ii := 0; ii < MaxAssociationTypeCharLength+1; ii++ {
			associationType = append(associationType, []byte(" ")...)
		}
		require.Equal(t, len(associationType), MaxAssociationTypeCharLength+1)

		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     string(associationType),
			AssociationValue:    "SQL",
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidType)
	}
	{
		// RuleErrorAssociationInvalidType: AssociationType uses reserved prefix
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     AssociationTypeReservedPrefix + "ENDORSEMENT",
			AssociationValue:    "SQL",
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidType)
	}
	{
		// RuleErrorAssociationTypeInvalidValue: AssociationValue is empty
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "",
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidValue)
	}
	{
		// RuleErrorAssociationInvalidValue: AssociationValue is too long
		var associationValue []byte
		for ii := 0; ii < MaxAssociationValueCharLength+1; ii++ {
			associationValue = append(associationValue, []byte(" ")...)
		}
		require.Equal(t, len(associationValue), MaxAssociationValueCharLength+1)

		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    string(associationValue),
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidValue)
	}
	{
		// RuleErrorAssociationInvalidID
		deleteUserAssociationMetadata = &DeleteUserAssociationMetadata{
			AssociationID: nil,
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: deleteUserAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidID)
	}
	{
		// RuleErrorAssociationNotFound
		deleteUserAssociationMetadata = &DeleteUserAssociationMetadata{
			AssociationID: NewBlockHash(RandomBytes(HashSizeBytes)),
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: deleteUserAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationNotFound)
	}
	// ---------------------------------
	// UserAssociation: happy paths
	// ---------------------------------
	{
		// CreateUserAssociation
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "SQL",
		}
		txnMsg := MsgDeSoTxn{
			TxnMeta: createUserAssociationMetadata,
			ExtraData: map[string][]byte{
				"UserAssociationKey1": []byte("UserAssociationValue1"),
			},
		}
		_submitAssociationTxnHappyPath(testMeta, m0Pub, m0Priv, txnMsg, flushToDB)

		userAssociationEntry, err = utxoView().GetUserAssociationByAttributes(
			m0PkBytes, createUserAssociationMetadata,
		)
		require.NoError(t, err)
		require.NotNil(t, userAssociationEntry)
		require.NotNil(t, userAssociationEntry.AssociationID)
		require.Equal(t, userAssociationEntry.TransactorPKID, m0PKID)
		require.Equal(t, userAssociationEntry.TargetUserPKID, m1PKID)
		require.Equal(t, userAssociationEntry.AssociationType, "ENDORSEMENT")
		require.Equal(t, userAssociationEntry.AssociationValue, "SQL")
		require.Equal(
			t, string(userAssociationEntry.ExtraData["UserAssociationKey1"]), "UserAssociationValue1",
		)
		require.NotNil(t, userAssociationEntry.BlockHeight)
		associationID = userAssociationEntry.AssociationID
	}
	{
		// RuleErrorAssociationInvalidTransactor: m1 trying to delete m0's association
		deleteUserAssociationMetadata = &DeleteUserAssociationMetadata{
			AssociationID: associationID,
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m1Pub, m1Priv, MsgDeSoTxn{TxnMeta: deleteUserAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidTransactor)
	}
	{
		// Test overwriting UserAssociation: new ExtraData field
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "SQL",
		}
		txnMsg := MsgDeSoTxn{
			TxnMeta: createUserAssociationMetadata,
			ExtraData: map[string][]byte{
				"UserAssociationKey2": []byte("UserAssociationValue2"),
			},
		}
		_submitAssociationTxnHappyPath(testMeta, m0Pub, m0Priv, txnMsg, flushToDB)

		userAssociationEntry, err = utxoView().GetUserAssociationByAttributes(
			m0PkBytes, createUserAssociationMetadata,
		)
		require.NoError(t, err)
		require.NotNil(t, userAssociationEntry)
		require.NotEqual(t, userAssociationEntry.AssociationID, associationID)
		require.Equal(
			t, string(userAssociationEntry.ExtraData["UserAssociationKey1"]), "UserAssociationValue1",
		)
		require.Equal(
			t, string(userAssociationEntry.ExtraData["UserAssociationKey2"]), "UserAssociationValue2",
		)
	}
	{
		// Test overwriting UserAssociation: updated ExtraData field
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "SQL",
		}
		txnMsg := MsgDeSoTxn{
			TxnMeta: createUserAssociationMetadata,
			ExtraData: map[string][]byte{
				"UserAssociationKey2": []byte("UserAssociationValue2-Updated"),
			},
		}
		_submitAssociationTxnHappyPath(testMeta, m0Pub, m0Priv, txnMsg, flushToDB)

		userAssociationEntry, err = utxoView().GetUserAssociationByAttributes(
			m0PkBytes, createUserAssociationMetadata,
		)
		require.NoError(t, err)
		require.NotNil(t, userAssociationEntry)
		require.NotEqual(t, userAssociationEntry.AssociationID, associationID)
		require.Equal(
			t, string(userAssociationEntry.ExtraData["UserAssociationKey1"]), "UserAssociationValue1",
		)
		require.Equal(
			t, string(userAssociationEntry.ExtraData["UserAssociationKey2"]), "UserAssociationValue2-Updated",
		)
	}
	{
		// DeleteUserAssociation
		deleteUserAssociationMetadata = &DeleteUserAssociationMetadata{
			AssociationID: userAssociationEntry.AssociationID,
		}
		_submitAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: deleteUserAssociationMetadata}, flushToDB,
		)

		userAssociationEntry, err = utxoView().GetUserAssociationByID(deleteUserAssociationMetadata.AssociationID)
		require.NoError(t, err)
		require.Nil(t, userAssociationEntry)
	}
	// -------------------------------
	// PostAssociation: validations
	// -------------------------------
	{
		// Create post
		submitPostMetadata = &SubmitPostMetadata{
			Body: []byte("Hello, world! --m1"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m1Pub, m1Priv, MsgDeSoTxn{TxnMeta: submitPostMetadata}, flushToDB,
		)

		require.Equal(t, testMeta.txns[len(testMeta.txns)-1].TxnMeta.GetTxnType(), TxnTypeSubmitPost)
		postHash = testMeta.txns[len(testMeta.txns)-1].Hash()
		postEntry := utxoView().GetPostEntryForPostHash(postHash)
		require.NotNil(t, postEntry)
		require.Equal(t, postEntry.Body, submitPostMetadata.Body)
	}
	{
		// RuleErrorAssociationBeforeBlockHeight
		params.ForkHeights.AssociationsBlockHeight = math.MaxUint32
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  "REACTION",
			AssociationValue: "HEART",
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationBeforeBlockHeight)
		params.ForkHeights.AssociationsBlockHeight = uint32(0)
	}
	{
		// RuleErrorPostAssociationInvalidPost
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         NewBlockHash(RandomBytes(HashSizeBytes)),
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  "REACTION",
			AssociationValue: "HEART",
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorPostAssociationInvalidPost)
	}
	{
		// RuleErrorAssociationInvalidApp
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AssociationType:  "REACTION",
			AssociationValue: "HEART",
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidApp)
	}
	{
		// RuleErrorAssociationInvalidType: AssociationType is empty
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  "",
			AssociationValue: "HEART",
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidType)
	}
	{
		// RuleErrorAssociationInvalidType: AssociationType is too long
		var associationType []byte
		for ii := 0; ii < MaxAssociationTypeCharLength+1; ii++ {
			associationType = append(associationType, []byte(" ")...)
		}
		require.Equal(t, len(associationType), MaxAssociationTypeCharLength+1)

		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  string(associationType),
			AssociationValue: "HEART",
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidType)
	}
	{
		// RuleErrorAssociationInvalidType: AssociationType uses reserved prefix
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  AssociationTypeReservedPrefix + "REACTION",
			AssociationValue: "HEART",
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidType)
	}
	{
		// RuleErrorAssociationTypeInvalidValue: AssociationValue is empty
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  "REACTION",
			AssociationValue: "",
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidValue)
	}
	{
		// RuleErrorAssociationInvalidValue: AssociationValue is too long
		var associationValue []byte
		for ii := 0; ii < MaxAssociationValueCharLength+1; ii++ {
			associationValue = append(associationValue, []byte(" ")...)
		}
		require.Equal(t, len(associationValue), MaxAssociationValueCharLength+1)

		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  "REACTION",
			AssociationValue: string(associationValue),
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidValue)
	}
	{
		// RuleErrorAssociationInvalidID
		deletePostAssociationMetadata = &DeletePostAssociationMetadata{
			AssociationID: nil,
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: deletePostAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidID)
	}
	{
		// RuleErrorAssociationNotFound
		deletePostAssociationMetadata = &DeletePostAssociationMetadata{
			AssociationID: NewBlockHash(RandomBytes(HashSizeBytes)),
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: deletePostAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationNotFound)
	}
	// ---------------------------------
	// PostAssociation: happy paths
	// ---------------------------------
	{
		// CreatePostAssociation
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  "REACTION",
			AssociationValue: "HEART",
		}
		txnMsg := MsgDeSoTxn{
			TxnMeta: createPostAssociationMetadata,
			ExtraData: map[string][]byte{
				"PostAssociationKey1": []byte("PostAssociationValue1"),
			},
		}
		_submitAssociationTxnHappyPath(testMeta, m0Pub, m0Priv, txnMsg, flushToDB)

		postAssociationEntry, err = utxoView().GetPostAssociationByAttributes(
			m0PkBytes, createPostAssociationMetadata,
		)
		require.NoError(t, err)
		require.NotNil(t, postAssociationEntry)
		require.NotNil(t, postAssociationEntry.AssociationID)
		require.Equal(t, postAssociationEntry.TransactorPKID, m0PKID)
		require.Equal(t, postAssociationEntry.PostHash, postHash)
		require.Equal(t, postAssociationEntry.AssociationType, "REACTION")
		require.Equal(t, postAssociationEntry.AssociationValue, "HEART")
		require.Equal(
			t, string(postAssociationEntry.ExtraData["PostAssociationKey1"]), "PostAssociationValue1",
		)
		require.NotNil(t, postAssociationEntry.BlockHeight)
		associationID = postAssociationEntry.AssociationID
	}
	{
		// RuleErrorAssociationInvalidTransactor: m1 trying to delete m0's association
		deletePostAssociationMetadata = &DeletePostAssociationMetadata{
			AssociationID: associationID,
		}
		_, _, _, err = _submitAssociationTxnSadPath(
			testMeta, m1Pub, m1Priv, MsgDeSoTxn{TxnMeta: deletePostAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidTransactor)
	}
	{
		// Test overwriting PostAssociation: new ExtraData field
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  "REACTION",
			AssociationValue: "HEART",
		}
		txnMsg := MsgDeSoTxn{
			TxnMeta: createPostAssociationMetadata,
			ExtraData: map[string][]byte{
				"PostAssociationKey2": []byte("PostAssociationValue2"),
			},
		}
		_submitAssociationTxnHappyPath(testMeta, m0Pub, m0Priv, txnMsg, flushToDB)

		postAssociationEntry, err = utxoView().GetPostAssociationByAttributes(
			m0PkBytes, createPostAssociationMetadata,
		)
		require.NoError(t, err)
		require.NotNil(t, postAssociationEntry)
		require.NotEqual(t, postAssociationEntry.AssociationID, associationID)
		require.Equal(
			t, string(postAssociationEntry.ExtraData["PostAssociationKey1"]), "PostAssociationValue1",
		)
		require.Equal(
			t, string(postAssociationEntry.ExtraData["PostAssociationKey2"]), "PostAssociationValue2",
		)
	}
	{
		// Test overwriting PostAssociation: updated ExtraData field
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  "REACTION",
			AssociationValue: "HEART",
		}
		txnMsg := MsgDeSoTxn{
			TxnMeta: createPostAssociationMetadata,
			ExtraData: map[string][]byte{
				"PostAssociationKey2": []byte("PostAssociationValue2-Updated"),
			},
		}
		_submitAssociationTxnHappyPath(testMeta, m0Pub, m0Priv, txnMsg, flushToDB)

		postAssociationEntry, err = utxoView().GetPostAssociationByAttributes(
			m0PkBytes, createPostAssociationMetadata,
		)
		require.NoError(t, err)
		require.NotNil(t, postAssociationEntry)
		require.NotEqual(t, postAssociationEntry.AssociationID, associationID)
		require.Equal(
			t, string(postAssociationEntry.ExtraData["PostAssociationKey1"]), "PostAssociationValue1",
		)
		require.Equal(
			t, string(postAssociationEntry.ExtraData["PostAssociationKey2"]), "PostAssociationValue2-Updated",
		)
	}
	{
		// DeletePostAssociation
		deletePostAssociationMetadata = &DeletePostAssociationMetadata{
			AssociationID: postAssociationEntry.AssociationID,
		}
		_submitAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: deletePostAssociationMetadata}, flushToDB,
		)

		postAssociationEntry, err = utxoView().GetPostAssociationByID(deletePostAssociationMetadata.AssociationID)
		require.NoError(t, err)
		require.Nil(t, postAssociationEntry)
	}
	// ---------------------------------
	// UserAssociation: query API
	// ---------------------------------
	{
		// Create test user associations

		// m0 -> m1, ENDORSEMENT: SQL scoped to m4's app
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        NewPublicKey(m4PkBytes),
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "SQL",
		}
		_submitAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// m2 -> m1, ENDORSEMENT: JavaScript
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "JavaScript",
		}
		_submitAssociationTxnHappyPath(
			testMeta, m2Pub, m2Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// m1 -> m2, ENDORSEMENT: SQL
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m2PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     "endorsement",
			AssociationValue:    "SQL",
		}
		_submitAssociationTxnHappyPath(
			testMeta, m1Pub, m1Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// m0 -> m3, ENDORSEMENT: JAVA
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m3PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "JAVA",
		}
		_submitAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// m1 -> m3, ENDORSEMENT: C
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m3PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "C",
		}
		_submitAssociationTxnHappyPath(
			testMeta, m1Pub, m1Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// m2 -> m3, ENDORSEMENT: C++
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m3PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "C++",
		}
		_submitAssociationTxnHappyPath(
			testMeta, m2Pub, m2Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// m4 -> m3, ENDORSEMENT: C#
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m3PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "C#",
		}
		_submitAssociationTxnHappyPath(
			testMeta, m4Pub, m4Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// m0 -> m1, MEMBERSHIP: Acme University Alumni
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     "MEMBERSHIP",
			AssociationValue:    "Acme University Alumni",
		}
		_submitAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// Query for all endorsements of m0 (none exist)
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TargetUserPKID:  m0PKID,
			AssociationType: "ENDORSEMENT",
		})
		require.NoError(t, err)
		require.Empty(t, userAssociationEntries)

		// Query for all endorsements of m1
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TargetUserPKID:  m1PKID,
			AssociationType: "ENDORSEMENT",
		})
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 2)
		sort.Slice(userAssociationEntries, func(ii, jj int) bool {
			return userAssociationEntries[ii].AssociationValue < userAssociationEntries[jj].AssociationValue
		})
		require.Equal(t, userAssociationEntries[0].AssociationValue, "JavaScript")
		require.Equal(t, userAssociationEntries[1].AssociationValue, "SQL")

		// Query for m0's global SQL endorsements of m1 (none exist)
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TransactorPKID:   m0PKID,
			TargetUserPKID:   m1PKID,
			AppPKID:          &ZeroPKID,
			AssociationType:  "ENDORSEMENT",
			AssociationValue: "SQL",
		})
		require.NoError(t, err)
		require.Empty(t, userAssociationEntries)

		// Query for m0's SQL endorsements of m1 scoped to m4's app
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TransactorPKID:   m0PKID,
			TargetUserPKID:   m1PKID,
			AppPKID:          m4PKID,
			AssociationType:  "ENDORSEMENT",
			AssociationValue: "SQL",
		})
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 1)

		// Query for all endorsements of m1 by m2
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TransactorPKID:  m2PKID,
			TargetUserPKID:  m1PKID,
			AssociationType: "ENDORSEMENT",
		})
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 1)
		require.Equal(t, userAssociationEntries[0].AssociationValue, "JavaScript")

		// Query for all ENDORSEMENT: SQL by m0
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TransactorPKID:   m0PKID,
			AssociationType:  "ENDORSEMENT",
			AssociationValue: "SQL",
		})
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 1)
		require.Equal(t, userAssociationEntries[0].TargetUserPKID, m1PKID)

		// Query for all endorse* by m0
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TransactorPKID:        m0PKID,
			AssociationTypePrefix: "endorse",
		})
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 2)
		sort.Slice(userAssociationEntries, func(ii, jj int) bool {
			return userAssociationEntries[ii].AssociationValue < userAssociationEntries[jj].AssociationValue
		})
		require.Equal(t, userAssociationEntries[0].AssociationValue, "JAVA")
		require.Equal(t, userAssociationEntries[1].AssociationValue, "SQL")

		// Query for all Acme University Alumni members as defined by m0
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TransactorPKID:   m0PKID,
			AssociationType:  "MEMBERSHIP",
			AssociationValue: "Acme University Alumni",
		})
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 1)
		require.Equal(t, userAssociationEntries[0].TargetUserPKID, m1PKID)

		// Query for all Acme University * members as defined by m0
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TransactorPKID:         m0PKID,
			AssociationType:        "MEMBERSHIP",
			AssociationValuePrefix: "Acme University",
		})
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 1)
		require.Equal(t, userAssociationEntries[0].TargetUserPKID, m1PKID)

		// Query for all C* endorsements of m3
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TargetUserPKID:         m3PKID,
			AssociationType:        "ENDORSEMENT",
			AssociationValuePrefix: "C",
		})
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 3)
		sort.Slice(userAssociationEntries, func(ii, jj int) bool {
			return userAssociationEntries[ii].AssociationValue < userAssociationEntries[jj].AssociationValue
		})
		require.Equal(t, userAssociationEntries[0].AssociationValue, "C")
		require.Equal(t, userAssociationEntries[1].AssociationValue, "C#")
		require.Equal(t, userAssociationEntries[2].AssociationValue, "C++")

		// Failed query: no params specified
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")
		require.Nil(t, userAssociationEntries)

		// Failed query: AssociationType and AssociationTypePrefix specified
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TargetUserPKID:        m3PKID,
			AssociationType:       "ENDORSEMENT",
			AssociationTypePrefix: "ENDORSE",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")

		// Failed query: AssociationValue and AssociationValuePrefix specified
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TargetUserPKID:         m3PKID,
			AssociationType:        "ENDORSEMENT",
			AssociationValue:       "C#",
			AssociationValuePrefix: "C",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")

		// Failed query if Badger: no Transactor or TargetUser specified
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			AssociationType:  "ENDORSEMENT",
			AssociationValue: "C#",
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, userAssociationEntries, 1)
			require.Equal(t, userAssociationEntries[0].TargetUserPKID, m3PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}

		// Failed query if Badger: empty AssociationType and non-empty AssociationValue
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TransactorPKID:   m4PKID,
			AssociationValue: "C#",
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, userAssociationEntries, 1)
			require.Equal(t, userAssociationEntries[0].TargetUserPKID, m3PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}

		// Failed query if Badger: non-empty AssociationTypePrefix and non-empty AssociationValue
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TransactorPKID:        m4PKID,
			AssociationTypePrefix: "ENDORSE",
			AssociationValue:      "C#",
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, userAssociationEntries, 1)
			require.Equal(t, userAssociationEntries[0].TargetUserPKID, m3PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}

		// Failed query if Badger: empty AssociationValue and non-empty AppPKID
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(&UserAssociationQuery{
			TransactorPKID:  m0PKID,
			TargetUserPKID:  m1PKID,
			AppPKID:         m4PKID,
			AssociationType: "ENDORSEMENT",
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, userAssociationEntries, 1)
			require.Equal(t, userAssociationEntries[0].AssociationValue, "SQL")
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}
	}
	// ---------------------------------
	// PostAssociation: query API
	// ---------------------------------
	{
		// Create test posts
		require.NotNil(t, utxoView().GetPostEntryForPostHash(postHash))

		submitPostMetadata = &SubmitPostMetadata{
			Body: []byte("Hello, world! --m2"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m2Pub, m2Priv, MsgDeSoTxn{TxnMeta: submitPostMetadata}, flushToDB,
		)
		require.Equal(t, testMeta.txns[len(testMeta.txns)-1].TxnMeta.GetTxnType(), TxnTypeSubmitPost)
		postHash2 := testMeta.txns[len(testMeta.txns)-1].Hash()
		require.NotNil(t, utxoView().GetPostEntryForPostHash(postHash2))

		submitPostMetadata = &SubmitPostMetadata{
			Body: []byte("Hello, world! --m3"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m3Pub, m3Priv, MsgDeSoTxn{TxnMeta: submitPostMetadata}, flushToDB,
		)
		require.Equal(t, testMeta.txns[len(testMeta.txns)-1].TxnMeta.GetTxnType(), TxnTypeSubmitPost)
		postHash3 := testMeta.txns[len(testMeta.txns)-1].Hash()
		require.NotNil(t, utxoView().GetPostEntryForPostHash(postHash3))

		// Create test post associations

		// m0 -> m1's post, REACTION: HEART scoped to m3's app
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     NewPublicKey(m3PkBytes),
			AssociationType:  "REACTION",
			AssociationValue: "HEART",
		}
		_submitAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)

		// m2 -> m1's post, REACTION: DOWN_VOTE
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  "REACTION",
			AssociationValue: "DOWN_VOTE",
		}
		_submitAssociationTxnHappyPath(
			testMeta, m2Pub, m2Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)

		// m0 -> m1's post, TAG: r/funny
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  "TAG",
			AssociationValue: "r/funny",
		}
		_submitAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)

		// m0 -> m2's post, TAG: r/funny
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash2,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  "TAG",
			AssociationValue: "r/funny",
		}
		_submitAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)

		// m1 -> m2's post, TAG: r/new
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash2,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  "TAG",
			AssociationValue: "r/new",
		}
		_submitAssociationTxnHappyPath(
			testMeta, m1Pub, m1Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)

		// m3 -> m2's post, TAG: NSFW
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash2,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  "TAG",
			AssociationValue: "NSFW",
		}
		_submitAssociationTxnHappyPath(
			testMeta, m3Pub, m3Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)

		// Query for all reactions on m1's post
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			PostHash:        postHash,
			AssociationType: "REACTION",
		})
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 2)
		sort.Slice(postAssociationEntries, func(ii, jj int) bool {
			return postAssociationEntries[ii].AssociationValue < postAssociationEntries[jj].AssociationValue
		})
		require.Equal(t, postAssociationEntries[0].AssociationValue, "DOWN_VOTE")
		require.Equal(t, postAssociationEntries[1].AssociationValue, "HEART")

		// Query for all REACT* on m1's post
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			PostHash:              postHash,
			AssociationTypePrefix: "REACT",
		})
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 2)
		sort.Slice(postAssociationEntries, func(ii, jj int) bool {
			return postAssociationEntries[ii].AssociationValue < postAssociationEntries[jj].AssociationValue
		})
		require.Equal(t, postAssociationEntries[0].AssociationValue, "DOWN_VOTE")
		require.Equal(t, postAssociationEntries[1].AssociationValue, "HEART")

		// Query for all down votes on m1's post
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			PostHash:         postHash,
			AssociationType:  "REACTION",
			AssociationValue: "DOWN_VOTE",
		})
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)
		require.Equal(t, postAssociationEntries[0].TransactorPKID, m2PKID)

		// Query for all m0's reactions
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			TransactorPKID:  m0PKID,
			AssociationType: "REACTION",
		})
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)
		require.Equal(t, postAssociationEntries[0].AssociationValue, "HEART")
		require.Equal(t, postAssociationEntries[0].PostHash, postHash)

		// Query for all m0's REACTION*
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			TransactorPKID:        m0PKID,
			AssociationTypePrefix: "reaction",
		})
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)
		require.Equal(t, postAssociationEntries[0].AssociationValue, "HEART")
		require.Equal(t, postAssociationEntries[0].PostHash, postHash)

		// Query for m0's global HEARTs on m1's POST (none exist)
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			TransactorPKID:   m0PKID,
			PostHash:         postHash,
			AppPKID:          &ZeroPKID,
			AssociationType:  "REACTION",
			AssociationValue: "HEART",
		})
		require.NoError(t, err)
		require.Empty(t, postAssociationEntries)

		// Query for m0's HEARTs on m1's POST scoped to m3's app
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			TransactorPKID:   m0PKID,
			PostHash:         postHash,
			AppPKID:          m3PKID,
			AssociationType:  "REACTION",
			AssociationValue: "HEART",
		})
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)

		// Query for all r/* tags on m2's post
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			PostHash:               postHash2,
			AssociationType:        "tag",
			AssociationValuePrefix: "r/",
		})
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 2)
		sort.Slice(postAssociationEntries, func(ii, jj int) bool {
			return postAssociationEntries[ii].AssociationValue < postAssociationEntries[jj].AssociationValue
		})
		require.Equal(t, postAssociationEntries[0].AssociationValue, "r/funny")
		require.Equal(t, postAssociationEntries[1].AssociationValue, "r/new")

		// Query for all NSFW tags on m2's post
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			PostHash:         postHash2,
			AssociationType:  "tag",
			AssociationValue: "NSFW",
		})
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)
		require.Equal(t, postAssociationEntries[0].TransactorPKID, m3PKID)

		// Query for all NSF* tags by m3
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			TransactorPKID:         m3PKID,
			AssociationType:        "tag",
			AssociationValuePrefix: "NSF",
		})
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)
		require.Equal(t, postAssociationEntries[0].PostHash, postHash2)

		// Query by all params
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			TransactorPKID:   m3PKID,
			PostHash:         postHash2,
			AssociationType:  "TAG",
			AssociationValue: "NSFW",
		})
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)
		require.Equal(t, postAssociationEntries[0].TransactorPKID, m3PKID)

		// Query for all tags
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			AssociationType: "TAG",
		})
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 4)
		sort.Slice(postAssociationEntries, func(ii, jj int) bool {
			return postAssociationEntries[ii].AssociationValue < postAssociationEntries[jj].AssociationValue
		})
		require.Equal(t, postAssociationEntries[0].AssociationValue, "NSFW")
		require.Equal(t, postAssociationEntries[1].AssociationValue, "r/funny")
		require.Equal(t, postAssociationEntries[2].AssociationValue, "r/funny")
		require.Equal(t, postAssociationEntries[3].AssociationValue, "r/new")

		// Query for all tag*s
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			AssociationTypePrefix: "TAG",
		})
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 4)
		sort.Slice(postAssociationEntries, func(ii, jj int) bool {
			return postAssociationEntries[ii].AssociationValue < postAssociationEntries[jj].AssociationValue
		})
		require.Equal(t, postAssociationEntries[0].AssociationValue, "NSFW")
		require.Equal(t, postAssociationEntries[1].AssociationValue, "r/funny")
		require.Equal(t, postAssociationEntries[2].AssociationValue, "r/funny")
		require.Equal(t, postAssociationEntries[3].AssociationValue, "r/new")

		// Query for all r/* tags
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			AssociationType:        "tag",
			AssociationValuePrefix: "r/",
		})
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 3)
		sort.Slice(postAssociationEntries, func(ii, jj int) bool {
			return postAssociationEntries[ii].AssociationValue < postAssociationEntries[jj].AssociationValue
		})
		require.Equal(t, postAssociationEntries[0].AssociationValue, "r/funny")
		require.Equal(t, postAssociationEntries[1].AssociationValue, "r/funny")
		require.Equal(t, postAssociationEntries[2].AssociationValue, "r/new")

		// Query for all r/new tags
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			AssociationType:  "tag",
			AssociationValue: "r/new",
		})
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)
		require.Equal(t, postAssociationEntries[0].TransactorPKID, m1PKID)

		// Failed query: no params specified
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")
		require.Nil(t, postAssociationEntries)

		// Failed query: AssociationType and AssociationTypePrefix specified
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			AssociationType:       "tag",
			AssociationTypePrefix: "tag",
			AssociationValue:      "r/new",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")

		// Failed query: AssociationValue and AssociationValuePrefix specified
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			AssociationType:        "tag",
			AssociationValue:       "r/new",
			AssociationValuePrefix: "r/",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")

		// Failed query if Badger: non-empty Transactor, non-empty AssociationTypePrefix, non-empty AssociationValue
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			TransactorPKID:        m3PKID,
			AssociationTypePrefix: "TAG",
			AssociationValue:      "NSFW",
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].PostHash, postHash2)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}

		// Failed query if Badger: non-empty Transactor, non-empty AssociationTypePrefix, non-empty PostHash
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			TransactorPKID:        m3PKID,
			PostHash:              postHash2,
			AssociationTypePrefix: "TAG",
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].AssociationValue, "NSFW")
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}

		// Failed query if Badger: non-empty Transactor, non-empty AssociationType, non-empty AssociationValuePrefix, non-emptyPostHash
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			TransactorPKID:         m3PKID,
			PostHash:               postHash2,
			AssociationType:        "TAG",
			AssociationValuePrefix: "NSF",
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].AssociationValue, "NSFW")
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}

		// Failed query if Badger: non-empty Transactor, non-empty AssociationType, empty AssociationValue, non-empty PostHash
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			TransactorPKID:  m3PKID,
			PostHash:        postHash2,
			AssociationType: "TAG",
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].AssociationValue, "NSFW")
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}

		// Failed query if Badger: non-empty Transactor, empty AssociationType, non-empty AssociationValue
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			TransactorPKID:   m3PKID,
			AssociationValue: "NSFW",
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].PostHash, postHash2)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}

		// Failed query if Badger: non-empty Transactor, empty AssociationType, non-empty PostHash
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			TransactorPKID: m3PKID,
			PostHash:       postHash2,
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].AssociationValue, "NSFW")
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}

		// Failed query if Badger: empty Transactor, non-empty PostHash, non-empty AssociationTypePrefix, non-empty AssociationValue
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			PostHash:              postHash2,
			AssociationTypePrefix: "TAG",
			AssociationValue:      "NSFW",
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].TransactorPKID, m3PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}

		// Failed query if Badger: empty Transactor, non-empty PostHash, empty AssociationType, non-empty AssociationValue
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			PostHash:         postHash2,
			AssociationValue: "NSFW",
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].TransactorPKID, m3PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}

		// Failed query if Badger: empty Transactor, empty PostHash, empty AssociationType, non-empty AssociationValue
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			AssociationValue: "NSFW",
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].TransactorPKID, m3PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}

		// Failed query if Badger: empty Transactor, empty PostHash, non-empty AssociationTypePrefix, non-empty AssociationValue
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			AssociationTypePrefix: "TAG",
			AssociationValue:      "NSFW",
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].TransactorPKID, m3PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}

		// Failed query if Badger: empty TransactorPKID and non-empty AppPKID
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(&PostAssociationQuery{
			PostHash:         postHash,
			AppPKID:          m3PKID,
			AssociationType:  "REACTION",
			AssociationValue: "HEART",
		})
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, userAssociationEntries, 1)
			require.Equal(t, userAssociationEntries[0].TransactorPKID, m0PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
		}
	}

	// Flush mempool to the db and test rollbacks.
	mempool.universalUtxoView.FlushToDb(0)
	_executeAllTestRollbackAndFlush(testMeta)
}

func _submitAssociationTxnHappyPath(
	testMeta *TestMeta,
	TransactorPublicKeyBase58Check string,
	TransactorPrivateKeyBase58Check string,
	inputTxn MsgDeSoTxn,
	flushToDB bool,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances,
		_getBalance(testMeta.t, testMeta.chain, testMeta.mempool, TransactorPublicKeyBase58Check),
	)

	currentOps, currentTxn, _, err := _submitAssociationTxnSadPath(
		testMeta,
		TransactorPublicKeyBase58Check,
		TransactorPrivateKeyBase58Check,
		inputTxn,
		flushToDB,
	)

	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _submitAssociationTxnSadPath(
	testMeta *TestMeta,
	TransactorPublicKeyBase58Check string,
	TransactorPrivateKeyBase58Check string,
	inputTxn MsgDeSoTxn,
	flushToDB bool,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	updaterPkBytes, _, err := Base58CheckDecode(TransactorPublicKeyBase58Check)
	require.NoError(testMeta.t, err)

	// Create the transaction.
	var txn *MsgDeSoTxn
	var totalInputMake, changeAmountMake, feesMake uint64

	switch inputTxn.TxnMeta.GetTxnType() {
	case TxnTypeCreateUserAssociation:
		txn, totalInputMake, changeAmountMake, feesMake, err = testMeta.chain.CreateCreateUserAssociationTxn(
			updaterPkBytes,
			inputTxn.TxnMeta.(*CreateUserAssociationMetadata),
			inputTxn.ExtraData,
			testMeta.feeRateNanosPerKb,
			testMeta.mempool,
			[]*DeSoOutput{},
		)
	case TxnTypeDeleteUserAssociation:
		txn, totalInputMake, changeAmountMake, feesMake, err = testMeta.chain.CreateDeleteUserAssociationTxn(
			updaterPkBytes,
			inputTxn.TxnMeta.(*DeleteUserAssociationMetadata),
			inputTxn.ExtraData,
			testMeta.feeRateNanosPerKb,
			testMeta.mempool,
			[]*DeSoOutput{},
		)
	case TxnTypeCreatePostAssociation:
		txn, totalInputMake, changeAmountMake, feesMake, err = testMeta.chain.CreateCreatePostAssociationTxn(
			updaterPkBytes,
			inputTxn.TxnMeta.(*CreatePostAssociationMetadata),
			inputTxn.ExtraData,
			testMeta.feeRateNanosPerKb,
			testMeta.mempool,
			[]*DeSoOutput{},
		)
	case TxnTypeDeletePostAssociation:
		txn, totalInputMake, changeAmountMake, feesMake, err = testMeta.chain.CreateDeletePostAssociationTxn(
			updaterPkBytes,
			inputTxn.TxnMeta.(*DeletePostAssociationMetadata),
			inputTxn.ExtraData,
			testMeta.feeRateNanosPerKb,
			testMeta.mempool,
			[]*DeSoOutput{},
		)
	case TxnTypeSubmitPost:
		// SubmitPost is not technically an association txn type, but we include it
		// here so that we can reuse this helper function to create SubmitPost txns
		// with and without flushing the mempool.
		txn, totalInputMake, changeAmountMake, feesMake, err = testMeta.chain.CreateSubmitPostTxn(
			updaterPkBytes,
			[]byte{},
			[]byte{},
			inputTxn.TxnMeta.(*SubmitPostMetadata).Body,
			[]byte{},
			false,
			uint64(1668027603792),
			make(map[string][]byte),
			false,
			testMeta.feeRateNanosPerKb,
			testMeta.mempool,
			[]*DeSoOutput{},
		)
	default:
		err = errors.New("invalid txn type")
	}
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(testMeta.t, totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(testMeta.t, txn, TransactorPrivateKeyBase58Check)

	// Connect the transaction.
	utxoOps, totalInput, totalOutput, fees, err := testMeta.mempool.universalUtxoView.ConnectTransaction(
		txn,
		txn.Hash(),
		getTxnSize(*txn),
		testMeta.savedHeight,
		true,
		false,
	)
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(testMeta.t, totalInput, totalOutput+fees)
	require.Equal(testMeta.t, totalInput, totalInputMake)

	var operationType OperationType
	switch inputTxn.TxnMeta.GetTxnType() {
	case TxnTypeCreateUserAssociation:
		operationType = OperationTypeCreateUserAssociation
	case TxnTypeDeleteUserAssociation:
		operationType = OperationTypeDeleteUserAssociation
	case TxnTypeCreatePostAssociation:
		operationType = OperationTypeCreatePostAssociation
	case TxnTypeDeletePostAssociation:
		operationType = OperationTypeDeletePostAssociation
	case TxnTypeSubmitPost:
		operationType = OperationTypeSubmitPost
	default:
		return nil, nil, 0, errors.New("invalid txn type")
	}
	require.Equal(testMeta.t, operationType, utxoOps[len(utxoOps)-1].Type)

	if flushToDB {
		require.NoError(testMeta.t, testMeta.mempool.universalUtxoView.FlushToDb(0))
	}
	require.NoError(testMeta.t, testMeta.mempool.RegenerateReadOnlyView())
	return utxoOps, txn, testMeta.savedHeight, nil
}
