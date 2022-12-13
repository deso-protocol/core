package lib

import (
	"bytes"
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
	var userAssociationQuery *UserAssociationQuery
	var postAssociationQuery *PostAssociationQuery
	var count uint64
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
			AssociationType:     []byte("ENDORSEMENT"),
			AssociationValue:    []byte("SQL"),
		}
		_, _, _, err = _submitAssociationTxn(
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
			AssociationType:  []byte("ENDORSEMENT"),
			AssociationValue: []byte("SQL"),
		}
		_, _, _, err = _submitAssociationTxn(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorUserAssociationInvalidTargetUser)
	}
	{
		// RuleErrorAssociationInvalidApp
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AssociationType:     []byte("ENDORSEMENT"),
			AssociationValue:    []byte("SQL"),
		}
		_, _, _, err = _submitAssociationTxn(
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
			AssociationType:     []byte{},
			AssociationValue:    []byte("SQL"),
		}
		_, _, _, err = _submitAssociationTxn(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidType)
	}
	{
		// RuleErrorAssociationInvalidType: AssociationType is too long
		var associationType []byte
		for ii := 0; ii < MaxAssociationTypeByteLength+1; ii++ {
			associationType = append(associationType, []byte(" ")...)
		}
		require.Equal(t, len(associationType), MaxAssociationTypeByteLength+1)

		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     associationType,
			AssociationValue:    []byte("SQL"),
		}
		_, _, _, err = _submitAssociationTxn(
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
			AssociationType:     []byte(AssociationTypeReservedPrefix + "ENDORSEMENT"),
			AssociationValue:    []byte("SQL"),
		}
		_, _, _, err = _submitAssociationTxn(
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
			AssociationType:     []byte("ENDORSEMENT"),
			AssociationValue:    []byte{},
		}
		_, _, _, err = _submitAssociationTxn(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidValue)
	}
	{
		// RuleErrorAssociationInvalidValue: AssociationValue is too long
		var associationValue []byte
		for ii := 0; ii < MaxAssociationValueByteLength+1; ii++ {
			associationValue = append(associationValue, []byte(" ")...)
		}
		require.Equal(t, len(associationValue), MaxAssociationValueByteLength+1)

		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     []byte("ENDORSEMENT"),
			AssociationValue:    associationValue,
		}
		_, _, _, err = _submitAssociationTxn(
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
		_, _, _, err = _submitAssociationTxn(
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
		_, _, _, err = _submitAssociationTxn(
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
			AssociationType:     []byte("ENDORSEMENT"),
			AssociationValue:    []byte("SQL"),
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
		require.Equal(t, userAssociationEntry.AssociationType, []byte("ENDORSEMENT"))
		require.Equal(t, userAssociationEntry.AssociationValue, []byte("SQL"))
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
		_, _, _, err = _submitAssociationTxn(
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
			AssociationType:     []byte("ENDORSEMENT"),
			AssociationValue:    []byte("SQL"),
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
			AssociationType:     []byte("ENDORSEMENT"),
			AssociationValue:    []byte("SQL"),
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
			AssociationType:  []byte("REACTION"),
			AssociationValue: []byte("HEART"),
		}
		_, _, _, err = _submitAssociationTxn(
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
			AssociationType:  []byte("REACTION"),
			AssociationValue: []byte("HEART"),
		}
		_, _, _, err = _submitAssociationTxn(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorPostAssociationInvalidPost)
	}
	{
		// RuleErrorAssociationInvalidApp
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AssociationType:  []byte("REACTION"),
			AssociationValue: []byte("HEART"),
		}
		_, _, _, err = _submitAssociationTxn(
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
			AssociationType:  []byte{},
			AssociationValue: []byte("HEART"),
		}
		_, _, _, err = _submitAssociationTxn(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidType)
	}
	{
		// RuleErrorAssociationInvalidType: AssociationType is too long
		var associationType []byte
		for ii := 0; ii < MaxAssociationTypeByteLength+1; ii++ {
			associationType = append(associationType, []byte(" ")...)
		}
		require.Equal(t, len(associationType), MaxAssociationTypeByteLength+1)

		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  associationType,
			AssociationValue: []byte("HEART"),
		}
		_, _, _, err = _submitAssociationTxn(
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
			AssociationType:  []byte(AssociationTypeReservedPrefix + "REACTION"),
			AssociationValue: []byte("HEART"),
		}
		_, _, _, err = _submitAssociationTxn(
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
			AssociationType:  []byte("REACTION"),
			AssociationValue: []byte{},
		}
		_, _, _, err = _submitAssociationTxn(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidValue)
	}
	{
		// RuleErrorAssociationInvalidValue: AssociationValue is too long
		var associationValue []byte
		for ii := 0; ii < MaxAssociationValueByteLength+1; ii++ {
			associationValue = append(associationValue, []byte(" ")...)
		}
		require.Equal(t, len(associationValue), MaxAssociationValueByteLength+1)

		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  []byte("REACTION"),
			AssociationValue: associationValue,
		}
		_, _, _, err = _submitAssociationTxn(
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
		_, _, _, err = _submitAssociationTxn(
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
		_, _, _, err = _submitAssociationTxn(
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
			AssociationType:  []byte("REACTION"),
			AssociationValue: []byte("HEART"),
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
		require.Equal(t, postAssociationEntry.AssociationType, []byte("REACTION"))
		require.Equal(t, postAssociationEntry.AssociationValue, []byte("HEART"))
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
		_, _, _, err = _submitAssociationTxn(
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
			AssociationType:  []byte("REACTION"),
			AssociationValue: []byte("HEART"),
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
			AssociationType:  []byte("REACTION"),
			AssociationValue: []byte("HEART"),
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
			AssociationType:     []byte("ENDORSEMENT"),
			AssociationValue:    []byte("SQL"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// m2 -> m1, ENDORSEMENT: JavaScript
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     []byte("ENDORSEMENT"),
			AssociationValue:    []byte("JavaScript"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m2Pub, m2Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// m1 -> m2, ENDORSEMENT: SQL
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m2PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     []byte("endorsement"),
			AssociationValue:    []byte("SQL"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m1Pub, m1Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// m0 -> m3, ENDORSEMENT: JAVA
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m3PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     []byte("ENDORSEMENT"),
			AssociationValue:    []byte("JAVA"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// m1 -> m3, ENDORSEMENT: C
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m3PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     []byte("ENDORSEMENT"),
			AssociationValue:    []byte("C"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m1Pub, m1Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// m2 -> m3, ENDORSEMENT: C++
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m3PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     []byte("ENDORSEMENT"),
			AssociationValue:    []byte("C++"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m2Pub, m2Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// m4 -> m3, ENDORSEMENT: C#
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m3PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     []byte("ENDORSEMENT"),
			AssociationValue:    []byte("C#"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m4Pub, m4Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// m0 -> m1, MEMBERSHIP: Acme University Alumni
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AppPublicKey:        &ZeroPublicKey,
			AssociationType:     []byte("MEMBERSHIP"),
			AssociationValue:    []byte("Acme University Alumni"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata}, flushToDB,
		)

		// Query for all endorsements of m0 (none exist)
		userAssociationQuery = &UserAssociationQuery{
			TargetUserPKID:  m0PKID,
			AssociationType: []byte("ENDORSEMENT"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Empty(t, userAssociationEntries)

		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Zero(t, count)

		// Query for all endorsements of m1
		userAssociationQuery = &UserAssociationQuery{
			TargetUserPKID:  m1PKID,
			AssociationType: []byte("ENDORSEMENT"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 2)
		sort.Slice(userAssociationEntries, func(ii, jj int) bool {
			return bytes.Compare(userAssociationEntries[ii].AssociationValue, userAssociationEntries[jj].AssociationValue) < 0
		})
		require.Equal(t, userAssociationEntries[0].AssociationValue, []byte("JavaScript"))
		require.Equal(t, userAssociationEntries[1].AssociationValue, []byte("SQL"))

		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(2))

		// Query for m0's global SQL endorsements of m1 (none exist)
		userAssociationQuery = &UserAssociationQuery{
			TransactorPKID:   m0PKID,
			TargetUserPKID:   m1PKID,
			AppPKID:          &ZeroPKID,
			AssociationType:  []byte("ENDORSEMENT"),
			AssociationValue: []byte("SQL"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Empty(t, userAssociationEntries)

		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Zero(t, count)

		// Query for m0's SQL endorsements of m1 scoped to m4's app
		userAssociationQuery = &UserAssociationQuery{
			TransactorPKID:   m0PKID,
			TargetUserPKID:   m1PKID,
			AppPKID:          m4PKID,
			AssociationType:  []byte("ENDORSEMENT"),
			AssociationValue: []byte("SQL"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 1)

		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(1))

		// Query for all endorsements of m1 by m2
		userAssociationQuery = &UserAssociationQuery{
			TransactorPKID:  m2PKID,
			TargetUserPKID:  m1PKID,
			AssociationType: []byte("ENDORSEMENT"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 1)
		require.Equal(t, userAssociationEntries[0].AssociationValue, []byte("JavaScript"))

		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(1))

		// Query for all ENDORSEMENT: SQL by m0
		userAssociationQuery = &UserAssociationQuery{
			TransactorPKID:   m0PKID,
			AssociationType:  []byte("ENDORSEMENT"),
			AssociationValue: []byte("SQL"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 1)
		require.Equal(t, userAssociationEntries[0].TargetUserPKID, m1PKID)

		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(1))

		// Query for all endorse* by m0
		userAssociationQuery = &UserAssociationQuery{
			TransactorPKID:        m0PKID,
			AssociationTypePrefix: []byte("endorse"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 2)
		sort.Slice(userAssociationEntries, func(ii, jj int) bool {
			return bytes.Compare(userAssociationEntries[ii].AssociationValue, userAssociationEntries[jj].AssociationValue) < 0
		})
		require.Equal(t, userAssociationEntries[0].AssociationValue, []byte("JAVA"))
		require.Equal(t, userAssociationEntries[1].AssociationValue, []byte("SQL"))

		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(2))

		// Query for all Acme University Alumni members as defined by m0
		userAssociationQuery = &UserAssociationQuery{
			TransactorPKID:   m0PKID,
			AssociationType:  []byte("MEMBERSHIP"),
			AssociationValue: []byte("Acme University Alumni"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 1)
		require.Equal(t, userAssociationEntries[0].TargetUserPKID, m1PKID)

		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(1))

		// Query for all Acme University * members as defined by m0
		userAssociationQuery = &UserAssociationQuery{
			TransactorPKID:         m0PKID,
			AssociationType:        []byte("MEMBERSHIP"),
			AssociationValuePrefix: []byte("Acme University"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 1)
		require.Equal(t, userAssociationEntries[0].TargetUserPKID, m1PKID)

		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(1))

		// Query for all C* endorsements of m3
		userAssociationQuery = &UserAssociationQuery{
			TargetUserPKID:         m3PKID,
			AssociationType:        []byte("ENDORSEMENT"),
			AssociationValuePrefix: []byte("C"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 3)
		sort.Slice(userAssociationEntries, func(ii, jj int) bool {
			return bytes.Compare(userAssociationEntries[ii].AssociationValue, userAssociationEntries[jj].AssociationValue) < 0
		})
		require.Equal(t, userAssociationEntries[0].AssociationValue, []byte("C"))
		require.Equal(t, userAssociationEntries[1].AssociationValue, []byte("C#"))
		require.Equal(t, userAssociationEntries[2].AssociationValue, []byte("C++"))

		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(3))

		// Failed query: no params specified
		userAssociationQuery = &UserAssociationQuery{}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")
		require.Nil(t, userAssociationEntries)

		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")
		require.Zero(t, count)

		// Failed query: AssociationType and AssociationTypePrefix specified
		userAssociationQuery = &UserAssociationQuery{
			TargetUserPKID:        m3PKID,
			AssociationType:       []byte("ENDORSEMENT"),
			AssociationTypePrefix: []byte("ENDORSE"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")
		require.Nil(t, userAssociationEntries)

		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")
		require.Zero(t, count)

		// Failed query: AssociationValue and AssociationValuePrefix specified
		userAssociationQuery = &UserAssociationQuery{
			TargetUserPKID:         m3PKID,
			AssociationType:        []byte("ENDORSEMENT"),
			AssociationValue:       []byte("C#"),
			AssociationValuePrefix: []byte("C"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")
		require.Nil(t, userAssociationEntries)

		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")
		require.Zero(t, count)

		// Failed query if Badger: no Transactor or TargetUser specified
		userAssociationQuery = &UserAssociationQuery{
			AssociationType:  []byte("ENDORSEMENT"),
			AssociationValue: []byte("C#"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, userAssociationEntries, 1)
			require.Equal(t, userAssociationEntries[0].TargetUserPKID, m3PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, userAssociationEntries)
		}
		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
		}

		// Failed query if Badger: empty AssociationType and non-empty AssociationValue
		userAssociationQuery = &UserAssociationQuery{
			TransactorPKID:   m4PKID,
			AssociationValue: []byte("C#"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, userAssociationEntries, 1)
			require.Equal(t, userAssociationEntries[0].TargetUserPKID, m3PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, userAssociationEntries)
		}
		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
		}

		// Failed query if Badger: non-empty AssociationTypePrefix and non-empty AssociationValue
		userAssociationQuery = &UserAssociationQuery{
			TransactorPKID:        m4PKID,
			AssociationTypePrefix: []byte("ENDORSE"),
			AssociationValue:      []byte("C#"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, userAssociationEntries, 1)
			require.Equal(t, userAssociationEntries[0].TargetUserPKID, m3PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, userAssociationEntries)
		}
		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
		}

		// Failed query if Badger: empty AssociationValue and non-empty AppPKID
		userAssociationQuery = &UserAssociationQuery{
			TransactorPKID:  m0PKID,
			TargetUserPKID:  m1PKID,
			AppPKID:         m4PKID,
			AssociationType: []byte("ENDORSEMENT"),
		}
		userAssociationEntries, err = utxoView().GetUserAssociationsByAttributes(userAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, userAssociationEntries, 1)
			require.Equal(t, userAssociationEntries[0].AssociationValue, []byte("SQL"))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, userAssociationEntries)
		}
		count, err = utxoView().CountUserAssociationsByAttributes(userAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
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
			AssociationType:  []byte("REACTION"),
			AssociationValue: []byte("HEART"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)

		// m2 -> m1's post, REACTION: DOWN_VOTE
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  []byte("REACTION"),
			AssociationValue: []byte("DOWN_VOTE"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m2Pub, m2Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)

		// m0 -> m1's post, TAG: r/funny
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  []byte("TAG"),
			AssociationValue: []byte("r/funny"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)

		// m0 -> m2's post, TAG: r/funny
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash2,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  []byte("TAG"),
			AssociationValue: []byte("r/funny"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)

		// m1 -> m2's post, TAG: r/new
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash2,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  []byte("TAG"),
			AssociationValue: []byte("r/new"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m1Pub, m1Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)

		// m3 -> m2's post, TAG: NSFW
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash2,
			AppPublicKey:     &ZeroPublicKey,
			AssociationType:  []byte("TAG"),
			AssociationValue: []byte("NSFW"),
		}
		_submitAssociationTxnHappyPath(
			testMeta, m3Pub, m3Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata}, flushToDB,
		)

		// Query for all reactions on m1's post
		postAssociationQuery = &PostAssociationQuery{
			PostHash:        postHash,
			AssociationType: []byte("REACTION"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 2)
		sort.Slice(postAssociationEntries, func(ii, jj int) bool {
			return bytes.Compare(postAssociationEntries[ii].AssociationValue, postAssociationEntries[jj].AssociationValue) < 0
		})
		require.Equal(t, postAssociationEntries[0].AssociationValue, []byte("DOWN_VOTE"))
		require.Equal(t, postAssociationEntries[1].AssociationValue, []byte("HEART"))

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(2))

		// Query for all REACT* on m1's post
		postAssociationQuery = &PostAssociationQuery{
			PostHash:              postHash,
			AssociationTypePrefix: []byte("REACT"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 2)
		sort.Slice(postAssociationEntries, func(ii, jj int) bool {
			return bytes.Compare(postAssociationEntries[ii].AssociationValue, postAssociationEntries[jj].AssociationValue) < 0
		})
		require.Equal(t, postAssociationEntries[0].AssociationValue, []byte("DOWN_VOTE"))
		require.Equal(t, postAssociationEntries[1].AssociationValue, []byte("HEART"))

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(2))

		// Query for all down votes on m1's post
		postAssociationQuery = &PostAssociationQuery{
			PostHash:         postHash,
			AssociationType:  []byte("REACTION"),
			AssociationValue: []byte("DOWN_VOTE"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)
		require.Equal(t, postAssociationEntries[0].TransactorPKID, m2PKID)

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(1))

		// Query for all m0's reactions
		postAssociationQuery = &PostAssociationQuery{
			TransactorPKID:  m0PKID,
			AssociationType: []byte("REACTION"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)
		require.Equal(t, postAssociationEntries[0].AssociationValue, []byte("HEART"))
		require.Equal(t, postAssociationEntries[0].PostHash, postHash)

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(1))

		// Query for all m0's REACTION*
		postAssociationQuery = &PostAssociationQuery{
			TransactorPKID:        m0PKID,
			AssociationTypePrefix: []byte("reaction"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)
		require.Equal(t, postAssociationEntries[0].AssociationValue, []byte("HEART"))
		require.Equal(t, postAssociationEntries[0].PostHash, postHash)

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(1))

		// Query for m0's global HEARTs on m1's POST (none exist)
		postAssociationQuery = &PostAssociationQuery{
			TransactorPKID:   m0PKID,
			PostHash:         postHash,
			AppPKID:          &ZeroPKID,
			AssociationType:  []byte("REACTION"),
			AssociationValue: []byte("HEART"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Empty(t, postAssociationEntries)

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Zero(t, count)

		// Query for m0's HEARTs on m1's POST scoped to m3's app
		postAssociationQuery = &PostAssociationQuery{
			TransactorPKID:   m0PKID,
			PostHash:         postHash,
			AppPKID:          m3PKID,
			AssociationType:  []byte("REACTION"),
			AssociationValue: []byte("HEART"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(1))

		// Query for all r/* tags on m2's post
		postAssociationQuery = &PostAssociationQuery{
			PostHash:               postHash2,
			AssociationType:        []byte("tag"),
			AssociationValuePrefix: []byte("r/"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 2)
		sort.Slice(postAssociationEntries, func(ii, jj int) bool {
			return bytes.Compare(postAssociationEntries[ii].AssociationValue, postAssociationEntries[jj].AssociationValue) < 0
		})
		require.Equal(t, postAssociationEntries[0].AssociationValue, []byte("r/funny"))
		require.Equal(t, postAssociationEntries[1].AssociationValue, []byte("r/new"))

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(2))

		// Query for all NSFW tags on m2's post
		postAssociationQuery = &PostAssociationQuery{
			PostHash:         postHash2,
			AssociationType:  []byte("tag"),
			AssociationValue: []byte("NSFW"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)
		require.Equal(t, postAssociationEntries[0].TransactorPKID, m3PKID)

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(1))

		// Query for all NSF* tags by m3
		postAssociationQuery = &PostAssociationQuery{
			TransactorPKID:         m3PKID,
			AssociationType:        []byte("tag"),
			AssociationValuePrefix: []byte("NSF"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)
		require.Equal(t, postAssociationEntries[0].PostHash, postHash2)

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(1))

		// Query by all params
		postAssociationQuery = &PostAssociationQuery{
			TransactorPKID:   m3PKID,
			PostHash:         postHash2,
			AssociationType:  []byte("TAG"),
			AssociationValue: []byte("NSFW"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)
		require.Equal(t, postAssociationEntries[0].TransactorPKID, m3PKID)

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(1))

		// Query for all tags
		postAssociationQuery = &PostAssociationQuery{
			AssociationType: []byte("TAG"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 4)
		sort.Slice(postAssociationEntries, func(ii, jj int) bool {
			return bytes.Compare(postAssociationEntries[ii].AssociationValue, postAssociationEntries[jj].AssociationValue) < 0
		})
		require.Equal(t, postAssociationEntries[0].AssociationValue, []byte("NSFW"))
		require.Equal(t, postAssociationEntries[1].AssociationValue, []byte("r/funny"))
		require.Equal(t, postAssociationEntries[2].AssociationValue, []byte("r/funny"))
		require.Equal(t, postAssociationEntries[3].AssociationValue, []byte("r/new"))

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(4))

		// Query for all tag*s
		postAssociationQuery = &PostAssociationQuery{
			AssociationTypePrefix: []byte("TAG"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 4)
		sort.Slice(postAssociationEntries, func(ii, jj int) bool {
			return bytes.Compare(postAssociationEntries[ii].AssociationValue, postAssociationEntries[jj].AssociationValue) < 0
		})
		require.Equal(t, postAssociationEntries[0].AssociationValue, []byte("NSFW"))
		require.Equal(t, postAssociationEntries[1].AssociationValue, []byte("r/funny"))
		require.Equal(t, postAssociationEntries[2].AssociationValue, []byte("r/funny"))
		require.Equal(t, postAssociationEntries[3].AssociationValue, []byte("r/new"))

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(4))

		// Query for all r/* tags
		postAssociationQuery = &PostAssociationQuery{
			AssociationType:        []byte("tag"),
			AssociationValuePrefix: []byte("r/"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 3)
		sort.Slice(postAssociationEntries, func(ii, jj int) bool {
			return bytes.Compare(postAssociationEntries[ii].AssociationValue, postAssociationEntries[jj].AssociationValue) < 0
		})
		require.Equal(t, postAssociationEntries[0].AssociationValue, []byte("r/funny"))
		require.Equal(t, postAssociationEntries[1].AssociationValue, []byte("r/funny"))
		require.Equal(t, postAssociationEntries[2].AssociationValue, []byte("r/new"))

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(3))

		// Query for all r/new tags
		postAssociationQuery = &PostAssociationQuery{
			AssociationType:  []byte("tag"),
			AssociationValue: []byte("r/new"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Len(t, postAssociationEntries, 1)
		require.Equal(t, postAssociationEntries[0].TransactorPKID, m1PKID)

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.NoError(t, err)
		require.Equal(t, count, uint64(1))

		// Failed query: no params specified
		postAssociationQuery = &PostAssociationQuery{}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")
		require.Nil(t, postAssociationEntries)

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")
		require.Zero(t, count)

		// Failed query: AssociationType and AssociationTypePrefix specified
		postAssociationQuery = &PostAssociationQuery{
			AssociationType:       []byte("tag"),
			AssociationTypePrefix: []byte("tag"),
			AssociationValue:      []byte("r/new"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")
		require.Nil(t, postAssociationEntries)

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")
		require.Zero(t, count)

		// Failed query: AssociationValue and AssociationValuePrefix specified
		postAssociationQuery = &PostAssociationQuery{
			AssociationType:        []byte("tag"),
			AssociationValue:       []byte("r/new"),
			AssociationValuePrefix: []byte("r/"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")
		require.Nil(t, postAssociationEntries)

		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid query params")
		require.Zero(t, count)

		// Failed query if Badger: non-empty Transactor, non-empty AssociationTypePrefix, non-empty AssociationValue
		postAssociationQuery = &PostAssociationQuery{
			TransactorPKID:        m3PKID,
			AssociationTypePrefix: []byte("TAG"),
			AssociationValue:      []byte("NSFW"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].PostHash, postHash2)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, postAssociationEntries)
		}
		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
		}

		// Failed query if Badger: non-empty Transactor, non-empty AssociationTypePrefix, non-empty PostHash
		postAssociationQuery = &PostAssociationQuery{
			TransactorPKID:        m3PKID,
			PostHash:              postHash2,
			AssociationTypePrefix: []byte("TAG"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].AssociationValue, []byte("NSFW"))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, postAssociationEntries)
		}
		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
		}

		// Failed query if Badger: non-empty Transactor, non-empty AssociationType, non-empty AssociationValuePrefix, non-emptyPostHash
		postAssociationQuery = &PostAssociationQuery{
			TransactorPKID:         m3PKID,
			PostHash:               postHash2,
			AssociationType:        []byte("TAG"),
			AssociationValuePrefix: []byte("NSF"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].AssociationValue, []byte("NSFW"))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, postAssociationEntries)
		}
		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
		}

		// Failed query if Badger: non-empty Transactor, non-empty AssociationType, empty AssociationValue, non-empty PostHash
		postAssociationQuery = &PostAssociationQuery{
			TransactorPKID:  m3PKID,
			PostHash:        postHash2,
			AssociationType: []byte("TAG"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].AssociationValue, []byte("NSFW"))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, postAssociationEntries)
		}
		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
		}

		// Failed query if Badger: non-empty Transactor, empty AssociationType, non-empty AssociationValue
		postAssociationQuery = &PostAssociationQuery{
			TransactorPKID:   m3PKID,
			AssociationValue: []byte("NSFW"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].PostHash, postHash2)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, postAssociationEntries)
		}
		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
		}

		// Failed query if Badger: non-empty Transactor, empty AssociationType, non-empty PostHash
		postAssociationQuery = &PostAssociationQuery{
			TransactorPKID: m3PKID,
			PostHash:       postHash2,
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].AssociationValue, []byte("NSFW"))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, postAssociationEntries)
		}
		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
		}

		// Failed query if Badger: empty Transactor, non-empty PostHash, non-empty AssociationTypePrefix, non-empty AssociationValue
		postAssociationQuery = &PostAssociationQuery{
			PostHash:              postHash2,
			AssociationTypePrefix: []byte("TAG"),
			AssociationValue:      []byte("NSFW"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].TransactorPKID, m3PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, postAssociationEntries)
		}
		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
		}

		// Failed query if Badger: empty Transactor, non-empty PostHash, empty AssociationType, non-empty AssociationValue
		postAssociationQuery = &PostAssociationQuery{
			PostHash:         postHash2,
			AssociationValue: []byte("NSFW"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].TransactorPKID, m3PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, postAssociationEntries)
		}
		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
		}

		// Failed query if Badger: empty Transactor, empty PostHash, empty AssociationType, non-empty AssociationValue
		postAssociationQuery = &PostAssociationQuery{
			AssociationValue: []byte("NSFW"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].TransactorPKID, m3PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, postAssociationEntries)
		}
		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
		}

		// Failed query if Badger: empty Transactor, empty PostHash, non-empty AssociationTypePrefix, non-empty AssociationValue
		postAssociationQuery = &PostAssociationQuery{
			AssociationTypePrefix: []byte("TAG"),
			AssociationValue:      []byte("NSFW"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, postAssociationEntries, 1)
			require.Equal(t, postAssociationEntries[0].TransactorPKID, m3PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, postAssociationEntries)
		}
		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
		}

		// Failed query if Badger: empty TransactorPKID and non-empty AppPKID
		postAssociationQuery = &PostAssociationQuery{
			PostHash:         postHash,
			AppPKID:          m3PKID,
			AssociationType:  []byte("REACTION"),
			AssociationValue: []byte("HEART"),
		}
		postAssociationEntries, err = utxoView().GetPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Len(t, userAssociationEntries, 1)
			require.Equal(t, userAssociationEntries[0].TransactorPKID, m0PKID)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Nil(t, postAssociationEntries)
		}
		count, err = utxoView().CountPostAssociationsByAttributes(postAssociationQuery)
		if chain.postgres != nil {
			require.NoError(t, err)
			require.Equal(t, count, uint64(1))
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid query params")
			require.Zero(t, count)
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

	currentOps, currentTxn, _, err := _submitAssociationTxn(
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

func _submitAssociationTxn(
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
