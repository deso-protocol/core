package lib

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"reflect"
	"testing"
)

func _daoCoinTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	TransactorPublicKeyBase58Check string,
	TransactorPrivateKeyBase58Check string,
	metadata DAOCoinMetadata,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(TransactorPublicKeyBase58Check)
	require.NoError(err)

	profilePkBytes := metadata.ProfilePublicKey
	assert.Len(profilePkBytes, btcec.PubKeyBytesLenCompressed)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateDAOCoinTxn(
		updaterPkBytes,
		&metadata,
		feeRateNanosPerKB,
		nil, /*mempool*/
		[]*DeSoOutput{})

	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, TransactorPrivateKeyBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeDAOCoin operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeDAOCoin, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _daoCoinTxnWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	TransactorPublicKeyBase58Check string,
	TransactorPrivateKeyBase58Check string,
	metadata DAOCoinMetadata) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, TransactorPublicKeyBase58Check))

	currentOps, currentTxn, _, err := _daoCoinTxn(testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB, TransactorPublicKeyBase58Check, TransactorPrivateKeyBase58Check, metadata)

	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _daoCoinTransferTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	TransactorPublicKeyBase58Check string,
	TransactorPrivateKeyBase58Check string,
	metadata DAOCoinTransferMetadata,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(TransactorPublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateDAOCoinTransferTxn(
		updaterPkBytes,
		&metadata,
		feeRateNanosPerKB,
		nil, /*mempool*/
		[]*DeSoOutput{})

	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, TransactorPrivateKeyBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeDAOCoinTransfer operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeDAOCoinTransfer, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _daoCoinTransferTxnWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	TransactorPublicKeyBase58Check string,
	TransactorPrivateKeyBase58Check string,
	metadata DAOCoinTransferMetadata) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, TransactorPublicKeyBase58Check))

	currentOps, currentTxn, _, err := _daoCoinTransferTxn(testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB, TransactorPublicKeyBase58Check, TransactorPrivateKeyBase58Check, metadata)

	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func TestDAOCoinBasic(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	DAOCoinBlockHeight = uint32(0)

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true

	// Mine a few blocks to give the senderPkString some money.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	// We take the block tip to be the blockchain height rather than the
	// header chain height.
	savedHeight := chain.blockTip().Height + 1
	// We build the testMeta obj after mining blocks so that we save the correct block height.
	testMeta := &TestMeta{
		t:           t,
		chain:       chain,
		params:      params,
		db:          db,
		mempool:     mempool,
		miner:       miner,
		savedHeight: savedHeight,
	}

	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 70)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 420)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 140)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 210)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 100)

	m0PKID := DBGetPKIDEntryForPublicKey(db, m0PkBytes)
	m1PKID := DBGetPKIDEntryForPublicKey(db, m1PkBytes)
	m2PKID := DBGetPKIDEntryForPublicKey(db, m2PkBytes)
	// M0 can't mint without a profile
	{
		_, _, _, err := _daoCoinTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeMint,
			CoinsToMintNanos: 100,
		})

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinOperationOnNonexistentProfile)
	}

	// Create a profile for m0
	{
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}
	oneMCoins := 1000000 * NanosPerUnit
	hundredKCoins := 100000 * NanosPerUnit
	tenKCoins := 10000 * NanosPerUnit
	oneKCoins := 1000 * NanosPerUnit

	// M1 can't mint for M0
	{
		_, _, _, err := _daoCoinTxn(t, chain, db, params, 10, m1Pub, m1Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeMint,
			CoinsToMintNanos: 100,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorOnlyProfileOwnerCanMintDAOCoin)
	}

	// M1 can't disable minting for M0
	{
		_, _, _, err := _daoCoinTxn(t, chain, db, params, 10, m1Pub, m1Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeDisableMinting,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorOnlyProfileOwnerCanDisableMintingDAOCoin)
	}

	// Can't mint 0 DAO coins
	{
		_, _, _, err := _daoCoinTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeMint,
			CoinsToMintNanos: 0,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinMustMintNonZeroDAOCoin)
	}

	// Mint 1M DAO coins
	{
		_daoCoinTxnWithTestMeta(testMeta, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeMint,
			CoinsToMintNanos: oneMCoins,
		},
		)
		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m0PKID.PKID, m0PKID.PKID, true)
		require.Equal(daoBalanceEntry.BalanceNanos, oneMCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos, oneMCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(1))
		require.False(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// Burn 100K DAO coins
	{
		_daoCoinTxnWithTestMeta(testMeta, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeBurn,
			CoinsToBurnNanos: hundredKCoins,
		})

		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m0PKID.PKID, m0PKID.PKID, true)
		require.Equal(daoBalanceEntry.BalanceNanos, oneMCoins-hundredKCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos, oneMCoins-hundredKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(1))
		require.False(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// M0 transfers 10K DAO coins to m1
	{
		_daoCoinTransferTxnWithTestMeta(testMeta, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			ReceiverPublicKey:      m1PkBytes,
			DAOCoinToTransferNanos: tenKCoins,
		})

		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m0PKID.PKID, m0PKID.PKID, true)
		require.Equal(daoBalanceEntry.BalanceNanos, oneMCoins-hundredKCoins-tenKCoins)

		m1DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m1PKID.PKID, m0PKID.PKID, true)
		require.Equal(m1DAOBalanceEntry.BalanceNanos, tenKCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos, oneMCoins-hundredKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
		require.False(profileEntry.DAOCoinEntry.MintingDisabled)

	}

	// m1 burns 1k DAO coins
	{
		_daoCoinTxnWithTestMeta(testMeta, 10, m1Pub, m1Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeBurn,
			CoinsToBurnNanos: oneKCoins,
		})

		m1DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m1PKID.PKID, m0PKID.PKID, true)
		require.Equal(m1DAOBalanceEntry.BalanceNanos, tenKCoins-oneKCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos, oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
		require.False(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// M0 disables minting
	{
		_daoCoinTxnWithTestMeta(testMeta, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeDisableMinting,
		})

		profileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos, oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// M0 can't mint any new coins
	{
		_, _, _, err := _daoCoinTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeMint,
			CoinsToMintNanos: 100,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinCannotMintIfMintingIsDisabled)
	}

	// M0 can't disable minting again
	// Can't mint 0 DAO coins
	{
		_, _, _, err := _daoCoinTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeDisableMinting,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinCannotDisableMintingIfAlreadyDisabled)
	}

	// Can't transfer more coins than you have.
	{
		_, _, _, err := _daoCoinTransferTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			DAOCoinToTransferNanos: oneMCoins,
			ReceiverPublicKey:      m2PkBytes,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinTransferInsufficientCoins)
	}

	// Can't transfer zero coins
	{
		_, _, _, err := _daoCoinTransferTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			DAOCoinToTransferNanos: 0,
			ReceiverPublicKey:      m2PkBytes,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCOinTransferMustTransferNonZeroDAOCoins)
	}

	// Can't transfer to yourself
	{
		_, _, _, err := _daoCoinTransferTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			DAOCoinToTransferNanos: oneKCoins,
			ReceiverPublicKey:      m0PkBytes,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinTransferCannotTransferToSelf)
	}

	// Can't transfer if there is no balance entry
	{
		_, _, _, err := _daoCoinTransferTxn(t, chain, db, params, 10, m2Pub, m2Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			DAOCoinToTransferNanos: 1,
			ReceiverPublicKey:      m0PkBytes,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinTransferBalanceEntryDoesNotExist)
	}

	// Can't transfer DAO coins of non-existent profile
	{
		_, _, _, err := _daoCoinTransferTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m2PkBytes,
			DAOCoinToTransferNanos: oneMCoins,
			ReceiverPublicKey:      m2PkBytes,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinTransferOnNonexistentProfile)
	}

	// Can't transfer if receiver pub key is not of correct length
	{
		_, _, _, err := _daoCoinTransferTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			DAOCoinToTransferNanos: oneMCoins,
			ReceiverPublicKey:      m2PkBytes[:10],
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinTransferInvalidReceiverPubKeySize)
	}

	// Can't transfer if profile pub key is not of correct length
	{
		_, _, _, err := _daoCoinTransferTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes[:10],
			DAOCoinToTransferNanos: oneMCoins,
			ReceiverPublicKey:      m2PkBytes,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinTransferInvalidProfilePubKeySize)
	}

	// Can't burn more than you own
	{
		_, _, _, err := _daoCoinTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeBurn,
			CoinsToBurnNanos: oneMCoins,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinBurnInsufficientCoins)
	}

	// Let's have m1 burn all their coins. See number of holders go down.
	{
		_daoCoinTransferTxnWithTestMeta(testMeta, 10, m1Pub, m1Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			ReceiverPublicKey:      m0PkBytes,
			DAOCoinToTransferNanos: tenKCoins - oneKCoins,
		})

		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m0PKID.PKID, m0PKID.PKID, true)
		require.Equal(daoBalanceEntry.BalanceNanos, oneMCoins-hundredKCoins-oneKCoins)

		m1DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m1PKID.PKID, m0PKID.PKID, true)
		// M1's balance entry is deleted because they have nothing
		require.Nil(m1DAOBalanceEntry)

		profileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos, oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(1))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// Have m0 transfer some coins to m2
	{
		_daoCoinTransferTxnWithTestMeta(testMeta, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			ReceiverPublicKey:      m2PkBytes,
			DAOCoinToTransferNanos: tenKCoins,
		})

		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m0PKID.PKID, m0PKID.PKID, true)
		require.Equal(daoBalanceEntry.BalanceNanos, oneMCoins-hundredKCoins-tenKCoins-oneKCoins)

		m2DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m2PKID.PKID, m0PKID.PKID, true)
		require.Equal(m2DAOBalanceEntry.BalanceNanos, tenKCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos, oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// Create a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

	// Swap m0 and m3 identities
	{
		_swapIdentityWithTestMeta(testMeta, 10, paramUpdaterPub, paramUpdaterPriv, m0PkBytes, m3PkBytes)

		m3PKID := DBGetPKIDEntryForPublicKey(db, m3PkBytes)
		require.True(reflect.DeepEqual(m3PKID.PKID, m0PKID.PKID))

		// Okay so we provied that M3PKID now points to where M0PKID used to point. Let's update M0PKID to be correct.
		m0PKID = DBGetPKIDEntryForPublicKey(db, m0PkBytes)
		require.False(reflect.DeepEqual(m0PKID.PKID, m3PKID.PKID))

		// Make sure M3's DAO Coin Entry is what M0's was prior to the swap
		m3ProfileEntry := DBGetProfileEntryForPKID(db, m3PKID.PKID)
		require.NotNil(m3ProfileEntry)
		require.Equal(m3ProfileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
		require.Equal(m3ProfileEntry.DAOCoinEntry.CoinsInCirculationNanos, oneMCoins-hundredKCoins-oneKCoins)
		require.True(m3ProfileEntry.DAOCoinEntry.MintingDisabled)

		// M0 shouldn't have a profile entry since M3 didn't have one before
		m0ProfileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Nil(m0ProfileEntry)

		// M0 shouldn't own any M3 DAO Coin
		m0DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(db, m0PKID.PKID, m3PKID.PKID, true)
		require.Nil(m0DAOBalanceEntry)

		// M3's DAO Balance entry should be what M0's was prior to the swap
		m3DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(db, m3PKID.PKID, m3PKID.PKID, true)
		require.Equal(m3DAOBalanceEntry.BalanceNanos, oneMCoins-hundredKCoins-tenKCoins-oneKCoins)
	}

	m3PKID := DBGetPKIDEntryForPublicKey(db, m3PkBytes)
	// Have m3 transfer the rest of their coins to m2
	{
		_daoCoinTransferTxnWithTestMeta(testMeta, 10, m3Pub, m3Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m3PkBytes,
			ReceiverPublicKey:      m2PkBytes,
			DAOCoinToTransferNanos: oneMCoins - hundredKCoins - tenKCoins - oneKCoins,
		})

		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m3PKID.PKID, m3PKID.PKID, true)
		require.Nil(daoBalanceEntry)

		m2DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m2PKID.PKID, m3PKID.PKID, true)
		require.Equal(m2DAOBalanceEntry.BalanceNanos, oneMCoins-hundredKCoins-oneKCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m3PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos, oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(1))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// Have m2 burn all their M3 DAO coin
	{
		_daoCoinTxnWithTestMeta(testMeta, 10, m2Pub, m2Priv, DAOCoinMetadata{
			ProfilePublicKey: m3PkBytes,
			OperationType:    DAOCoinOperationTypeBurn,
			CoinsToBurnNanos: oneMCoins - hundredKCoins - oneKCoins,
		})

		m2DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m2PKID.PKID, m3PKID.PKID, true)
		require.Nil(m2DAOBalanceEntry)

		profileEntry := DBGetProfileEntryForPKID(db, m3PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos, uint64(0))
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(0))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}
