package lib

import (
	"errors"
	"github.com/stretchr/testify/require"
	"math"
	"sort"
	"testing"
)

func TestAssociations(t *testing.T) {
	// -----------------------
	// Initialization
	// -----------------------
	var createUserAssociationMetadata *CreateUserAssociationMetadata
	var deleteUserAssociationMetadata *DeleteUserAssociationMetadata
	var userAssociationEntry *UserAssociationEntry
	var userAssociationEntries []*UserAssociationEntry
	var createPostAssociationMetadata *CreatePostAssociationMetadata
	var deletePostAssociationMetadata *DeletePostAssociationMetadata
	var postAssociationEntry *PostAssociationEntry
	// var postAssociationEntries []*PostAssociationEntry
	var postHash *BlockHash
	var err error

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true)
	params.ForkHeights.AssociationsBlockHeight = uint32(0)

	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
	require.NoError(t, err)
	_ = utxoView

	// Mine a few blocks to give the senderPkString some money.
	for ii := 0; ii < 10; ii++ {
		_, err = miner.MineAndProcessSingleBlock(0, mempool)
		require.NoError(t, err)
	}

	// We take the block tip to be the blockchain height rather than the header chain height.
	savedHeight := chain.blockTip().Height + 1

	// We build the testMeta obj after mining blocks so that we save the correct block height.
	testMeta := &TestMeta{
		t:                 t,
		chain:             chain,
		params:            params,
		db:                db,
		mempool:           mempool,
		miner:             miner,
		savedHeight:       savedHeight,
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
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "SQL",
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationBeforeBlockHeight)
		params.ForkHeights.AssociationsBlockHeight = uint32(0)
	}
	{
		// RuleErrorAssociationInvalidType: AssociationType is empty
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AssociationType:     "",
			AssociationValue:    "SQL",
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata},
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
			AssociationType:     string(associationType),
			AssociationValue:    "SQL",
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidType)
	}
	{
		// RuleErrorAssociationInvalidType: AssociationType uses reserved prefix
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AssociationType:     AssociationTypeReservedPrefix + "ENDORSEMENT",
			AssociationValue:    "SQL",
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidType)
	}
	{
		// RuleErrorAssociationTypeInvalidValue: AssociationValue is empty
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "",
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata},
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
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    string(associationValue),
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidValue)
	}
	{
		// RuleErrorAssociationInvalidID
		deleteUserAssociationMetadata = &DeleteUserAssociationMetadata{
			AssociationID: nil,
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: deleteUserAssociationMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidID)
	}
	{
		// RuleErrorAssociationNotFound
		deleteUserAssociationMetadata = &DeleteUserAssociationMetadata{
			AssociationID: NewBlockHash(RandomBytes(HashSizeBytes)),
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: deleteUserAssociationMetadata},
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
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "SQL",
		}
		_doAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata},
		)

		userAssociationEntry, err = utxoView.GetUserAssociationByAttributes(
			m0PkBytes, createUserAssociationMetadata,
		)
		require.NoError(t, err)
		require.NotNil(t, userAssociationEntry)
		require.NotNil(t, userAssociationEntry.AssociationID)
		require.Equal(t, userAssociationEntry.TransactorPKID, m0PKID)
		require.Equal(t, userAssociationEntry.TargetUserPKID, m1PKID)
		require.Equal(t, userAssociationEntry.AssociationType, "ENDORSEMENT")
		require.Equal(t, userAssociationEntry.AssociationValue, "SQL")
		require.NotNil(t, userAssociationEntry.BlockHeight)
	}
	{
		// DeleteUserAssociation
		deleteUserAssociationMetadata = &DeleteUserAssociationMetadata{
			AssociationID: userAssociationEntry.AssociationID,
		}
		_doAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: deleteUserAssociationMetadata},
		)

		userAssociationEntry, err = utxoView.GetUserAssociationByID(deleteUserAssociationMetadata.AssociationID)
		require.NoError(t, err)
		require.Nil(t, userAssociationEntry)
	}
	// -------------------------------
	// PostAssociation: validations
	// -------------------------------
	{
		// Create post
		_submitPostWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			[]byte{},
			[]byte{},
			&DeSoBodySchema{Body: "Hello, world!"},
			[]byte{},
			uint64(1668027603792),
			false,
		)
		require.Equal(t, testMeta.txns[len(testMeta.txns)-1].TxnMeta.GetTxnType(), TxnTypeSubmitPost)
		postHash = testMeta.txns[len(testMeta.txns)-1].Hash()
		require.NotNil(t, utxoView.GetPostEntryForPostHash(postHash))
	}
	{
		// RuleErrorAssociationBeforeBlockHeight
		params.ForkHeights.AssociationsBlockHeight = math.MaxUint32
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AssociationType:  "REACTION",
			AssociationValue: "HEART",
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationBeforeBlockHeight)
		params.ForkHeights.AssociationsBlockHeight = uint32(0)
	}
	{
		// RuleErrorPostAssociationInvalidPost
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         NewBlockHash(RandomBytes(HashSizeBytes)),
			AssociationType:  "REACTION",
			AssociationValue: "HEART",
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorPostAssociationInvalidPost)
	}
	{
		// RuleErrorAssociationInvalidType: AssociationType is empty
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AssociationType:  "",
			AssociationValue: "HEART",
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata},
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
			AssociationType:  string(associationType),
			AssociationValue: "HEART",
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidType)
	}
	{
		// RuleErrorAssociationInvalidType: AssociationType uses reserved prefix
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AssociationType:  AssociationTypeReservedPrefix + "REACTION",
			AssociationValue: "HEART",
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidType)
	}
	{
		// RuleErrorAssociationTypeInvalidValue: AssociationValue is empty
		createPostAssociationMetadata = &CreatePostAssociationMetadata{
			PostHash:         postHash,
			AssociationType:  "REACTION",
			AssociationValue: "",
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata},
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
			AssociationType:  "REACTION",
			AssociationValue: string(associationValue),
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidValue)
	}
	{
		// RuleErrorAssociationInvalidID
		deletePostAssociationMetadata = &DeletePostAssociationMetadata{
			AssociationID: nil,
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: deletePostAssociationMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAssociationInvalidID)
	}
	{
		// RuleErrorAssociationNotFound
		deletePostAssociationMetadata = &DeletePostAssociationMetadata{
			AssociationID: NewBlockHash(RandomBytes(HashSizeBytes)),
		}
		_, _, _, err = _doAssociationTxnSadPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: deletePostAssociationMetadata},
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
			AssociationType:  "REACTION",
			AssociationValue: "HEART",
		}
		_doAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createPostAssociationMetadata},
		)

		postAssociationEntry, err = utxoView.GetPostAssociationByAttributes(
			m0PkBytes, createPostAssociationMetadata,
		)
		require.NoError(t, err)
		require.NotNil(t, postAssociationEntry)
		require.NotNil(t, postAssociationEntry.AssociationID)
		require.Equal(t, postAssociationEntry.TransactorPKID, m0PKID)
		require.Equal(t, postAssociationEntry.PostHash, postHash)
		require.Equal(t, postAssociationEntry.AssociationType, "REACTION")
		require.Equal(t, postAssociationEntry.AssociationValue, "HEART")
		require.NotNil(t, postAssociationEntry.BlockHeight)
	}
	{
		// DeletePostAssociation
		deletePostAssociationMetadata = &DeletePostAssociationMetadata{
			AssociationID: postAssociationEntry.AssociationID,
		}
		_doAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: deletePostAssociationMetadata},
		)

		postAssociationEntry, err = utxoView.GetPostAssociationByID(deletePostAssociationMetadata.AssociationID)
		require.NoError(t, err)
		require.Nil(t, postAssociationEntry)
	}
	// ---------------------------------
	// UserAssociation: query API
	// ---------------------------------
	{
		// Create test user associations

		// m0 -> m1, ENDORSEMENT: SQL
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "SQL",
		}
		_doAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata},
		)

		// m1 -> m2, ENDORSEMENT: SQL
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m2PkBytes),
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "SQL",
		}
		_doAssociationTxnHappyPath(
			testMeta, m1Pub, m1Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata},
		)

		// m0 -> m3, ENDORSEMENT: JAVA
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m3PkBytes),
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "JAVA",
		}
		_doAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata},
		)

		// m1 -> m3, ENDORSEMENT: C
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m3PkBytes),
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "C",
		}
		_doAssociationTxnHappyPath(
			testMeta, m1Pub, m1Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata},
		)

		// m2 -> m3, ENDORSEMENT: C++
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m3PkBytes),
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "C++",
		}
		_doAssociationTxnHappyPath(
			testMeta, m2Pub, m2Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata},
		)

		// m4 -> m3, ENDORSMENT: C#
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m3PkBytes),
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "C#",
		}
		_doAssociationTxnHappyPath(
			testMeta, m4Pub, m4Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata},
		)

		// m0 -> m1, MEMBERSHIP: Acme University Alumni
		createUserAssociationMetadata = &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AssociationType:     "MEMBERSHIP",
			AssociationValue:    "Acme University Alumni",
		}
		_doAssociationTxnHappyPath(
			testMeta, m0Pub, m0Priv, MsgDeSoTxn{TxnMeta: createUserAssociationMetadata},
		)

		// Query for all endorsements of m1
		userAssociationEntries, err = utxoView.GetUserAssociationsByAttributes(nil, &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m1PkBytes),
			AssociationType:     "ENDORSEMENT",
		})
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 1)
		require.Equal(t, userAssociationEntries[0].AssociationValue, "SQL")

		// Query for all Acme University Alumni members as defined by m0
		userAssociationEntries, err = utxoView.GetUserAssociationsByAttributes(m0PkBytes, &CreateUserAssociationMetadata{
			AssociationType:  "MEMBERSHIP",
			AssociationValue: "Acme University Alumni",
		})
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 1)
		require.Equal(t, userAssociationEntries[0].TargetUserPKID, m1PKID)

		// Query for all Acme University * members as defined by m0
		userAssociationEntries, err = utxoView.GetUserAssociationsByAttributes(m0PkBytes, &CreateUserAssociationMetadata{
			AssociationType:  "MEMBERSHIP",
			AssociationValue: "Acme University *",
		})
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 1)
		require.Equal(t, userAssociationEntries[0].TargetUserPKID, m1PKID)

		// Query for all C* endorsements of m3
		userAssociationEntries, err = utxoView.GetUserAssociationsByAttributes(nil, &CreateUserAssociationMetadata{
			TargetUserPublicKey: NewPublicKey(m3PkBytes),
			AssociationType:     "ENDORSEMENT",
			AssociationValue:    "C*",
		})
		require.NoError(t, err)
		require.Len(t, userAssociationEntries, 3)
		sort.Slice(userAssociationEntries, func(ii, jj int) bool {
			return userAssociationEntries[ii].AssociationValue < userAssociationEntries[jj].AssociationValue
		})
		require.Equal(t, userAssociationEntries[0].AssociationValue, "C")
		require.Equal(t, userAssociationEntries[1].AssociationValue, "C#")
		require.Equal(t, userAssociationEntries[2].AssociationValue, "C++")
	}

	_executeAllTestRollbackAndFlush(testMeta)
}

func _doAssociationTxnHappyPath(
	testMeta *TestMeta,
	TransactorPublicKeyBase58Check string,
	TransactorPrivateKeyBase58Check string,
	inputTxn MsgDeSoTxn,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances,
		_getBalance(testMeta.t, testMeta.chain, nil, TransactorPublicKeyBase58Check),
	)

	currentOps, currentTxn, _, err := _doAssociationTxnSadPath(
		testMeta,
		TransactorPublicKeyBase58Check,
		TransactorPrivateKeyBase58Check,
		inputTxn,
	)

	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _doAssociationTxnSadPath(
	testMeta *TestMeta,
	TransactorPublicKeyBase58Check string,
	TransactorPrivateKeyBase58Check string,
	inputTxn MsgDeSoTxn,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	updaterPkBytes, _, err := Base58CheckDecode(TransactorPublicKeyBase58Check)
	require.NoError(testMeta.t, err)

	utxoView, err := NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot,
	)
	require.NoError(testMeta.t, err)

	// Create the transaction.
	var txn *MsgDeSoTxn
	var totalInputMake, changeAmountMake, feesMake uint64

	switch inputTxn.TxnMeta.GetTxnType() {
	case TxnTypeCreateUserAssociation:
		txn, totalInputMake, changeAmountMake, feesMake, err = testMeta.chain.CreateCreateUserAssociationTxn(
			updaterPkBytes,
			inputTxn.TxnMeta.(*CreateUserAssociationMetadata),
			testMeta.feeRateNanosPerKb,
			nil,
			[]*DeSoOutput{},
		)
	case TxnTypeDeleteUserAssociation:
		txn, totalInputMake, changeAmountMake, feesMake, err = testMeta.chain.CreateDeleteUserAssociationTxn(
			updaterPkBytes,
			inputTxn.TxnMeta.(*DeleteUserAssociationMetadata),
			testMeta.feeRateNanosPerKb,
			nil,
			[]*DeSoOutput{},
		)
	case TxnTypeCreatePostAssociation:
		txn, totalInputMake, changeAmountMake, feesMake, err = testMeta.chain.CreateCreatePostAssociationTxn(
			updaterPkBytes,
			inputTxn.TxnMeta.(*CreatePostAssociationMetadata),
			testMeta.feeRateNanosPerKb,
			nil,
			[]*DeSoOutput{},
		)
	case TxnTypeDeletePostAssociation:
		txn, totalInputMake, changeAmountMake, feesMake, err = testMeta.chain.CreateDeletePostAssociationTxn(
			updaterPkBytes,
			inputTxn.TxnMeta.(*DeletePostAssociationMetadata),
			testMeta.feeRateNanosPerKb,
			nil,
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
	utxoOps, totalInput, totalOutput, fees, err := utxoView.ConnectTransaction(
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
	default:
		return nil, nil, 0, errors.New("invalid txn type")
	}
	require.Equal(testMeta.t, operationType, utxoOps[len(utxoOps)-1].Type)

	require.NoError(testMeta.t, utxoView.FlushToDb(0))
	return utxoOps, txn, testMeta.savedHeight, nil
}
