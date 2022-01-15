package lib

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
	"github.com/holiman/uint256"
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

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true
	params.ForkHeights.DAOCoinBlockHeight = uint32(0)

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
	m4PKID := DBGetPKIDEntryForPublicKey(db, m4PkBytes)
	// M0 can't mint without a profile
	{
		_, _, _, err = _daoCoinTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeMint,
			CoinsToMintNanos: *uint256.NewInt().SetUint64(100),
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
	hundredCoins := 100 * NanosPerUnit

	// M1 can't mint for M0
	{
		_, _, _, err = _daoCoinTxn(t, chain, db, params, 10, m1Pub, m1Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeMint,
			CoinsToMintNanos: *uint256.NewInt().SetUint64(100),
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorOnlyProfileOwnerCanMintDAOCoin)
	}

	// M1 can't disable minting for M0
	{
		_, _, _, err = _daoCoinTxn(t, chain, db, params, 10, m1Pub, m1Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeDisableMinting,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorOnlyProfileOwnerCanDisableMintingDAOCoin)
	}

	// Can't mint 0 DAO coins
	{
		_, _, _, err = _daoCoinTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeMint,
			CoinsToMintNanos: *uint256.NewInt().SetUint64(0),
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinMustMintNonZeroDAOCoin)
	}

	// Mint 1M DAO coins
	// M0 DAO cap table before:
	//		M0: 0
	// M0 DAO cap table after:
	//		M0: 1M
	{
		_daoCoinTxnWithTestMeta(testMeta, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeMint,
			CoinsToMintNanos: *uint256.NewInt().SetUint64(oneMCoins),
		},
		)
		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m0PKID.PKID, m0PKID.PKID, true)
		require.Equal(daoBalanceEntry.BalanceNanos.Uint64(), oneMCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(1))
		require.False(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// Burn 100K DAO coins
	// M0 DAO cap table before:
	//		M0: 1M
	// M0 DAO cap table after:
	//		M0: 1M - 100K
	{
		_daoCoinTxnWithTestMeta(testMeta, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeBurn,
			CoinsToBurnNanos: *uint256.NewInt().SetUint64(hundredKCoins),
		})

		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m0PKID.PKID, m0PKID.PKID, true)
		require.Equal(daoBalanceEntry.BalanceNanos.Uint64(), oneMCoins-hundredKCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(1))
		require.False(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// M1 can't burn coins
	{
		_, _, _, err = _daoCoinTxn(t, chain, db, params, 10, m1Pub, m1Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeBurn,
			CoinsToBurnNanos: *uint256.NewInt().SetUint64(100),
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinBurnerBalanceEntryDoesNotExist)
	}

	// M0 transfers 10K DAO coins to m1
	// M0 DAO cap table before:
	//		M0: 1M - 100K
	// M0 DAO cap table after:
	//		M0: 1M - 100K - 10K
	//		M1: 10K
	{
		_daoCoinTransferTxnWithTestMeta(testMeta, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			ReceiverPublicKey:      m1PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(tenKCoins),
		})

		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m0PKID.PKID, m0PKID.PKID, true)
		require.Equal(daoBalanceEntry.BalanceNanos.Uint64(), oneMCoins-hundredKCoins-tenKCoins)

		m1DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m1PKID.PKID, m0PKID.PKID, true)
		require.Equal(m1DAOBalanceEntry.BalanceNanos.Uint64(), tenKCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
		require.False(profileEntry.DAOCoinEntry.MintingDisabled)

	}

	// M0 burns 10K coin and immediately mints 10K more. M0 runs a weird DAO
	// M0 DAO cap table before:
	//		M0: 1M - 100K - 10K
	//		M1: 10K
	// M0 DAO cap table after:
	//		M0: 1M - 100K - 10K
	//		M1: 10K
	{
		_daoCoinTxnWithTestMeta(testMeta, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeBurn,
			CoinsToBurnNanos: *uint256.NewInt().SetUint64(tenKCoins),
		})

		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m0PKID.PKID, m0PKID.PKID, true)
		require.Equal(daoBalanceEntry.BalanceNanos.Uint64(), oneMCoins-hundredKCoins-tenKCoins-tenKCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins-tenKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
		require.False(profileEntry.DAOCoinEntry.MintingDisabled)

		_daoCoinTxnWithTestMeta(testMeta, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeMint,
			CoinsToMintNanos: *uint256.NewInt().SetUint64(tenKCoins),
		})
		daoBalanceEntry = DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m0PKID.PKID, m0PKID.PKID, true)
		require.Equal(daoBalanceEntry.BalanceNanos.Uint64(), oneMCoins-hundredKCoins-tenKCoins)

		profileEntry = DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
		require.False(profileEntry.DAOCoinEntry.MintingDisabled)

	}

	// m1 burns 1k DAO coins
	// M0 DAO cap table before:
	//		M0: 1M - 100K - 10K
	//		M1: 10K
	// M0 DAO cap table after:
	//		M0: 1M - 100K - 10K
	//		M1: 10K - 1K
	{
		_daoCoinTxnWithTestMeta(testMeta, 10, m1Pub, m1Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeBurn,
			CoinsToBurnNanos: *uint256.NewInt().SetUint64(oneKCoins),
		})

		m1DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m1PKID.PKID, m0PKID.PKID, true)
		require.Equal(m1DAOBalanceEntry.BalanceNanos.Uint64(), tenKCoins-oneKCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins-oneKCoins)
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
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// M0 can't mint any new coins
	{
		_, _, _, err = _daoCoinTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeMint,
			CoinsToMintNanos: *uint256.NewInt().SetUint64(100),
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinCannotMintIfMintingIsDisabled)
	}

	// M0 can't disable minting again
	{
		_, _, _, err = _daoCoinTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeDisableMinting,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinCannotDisableMintingIfAlreadyDisabled)
	}

	// Can't transfer more coins than you have.
	{
		_, _, _, err = _daoCoinTransferTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(oneMCoins),
			ReceiverPublicKey:      m2PkBytes,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCoinTransferInsufficientCoins)
	}

	// Can't transfer to yourself
	{
		_, _, _, err = _daoCoinTransferTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(oneKCoins),
			ReceiverPublicKey:      m0PkBytes,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCoinTransferCannotTransferToSelf)
	}

	// Can't transfer if there is no balance entry
	{
		_, _, _, err = _daoCoinTransferTxn(t, chain, db, params, 10, m2Pub, m2Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(1),
			ReceiverPublicKey:      m0PkBytes,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCoinTransferBalanceEntryDoesNotExist)
	}

	// Can't transfer DAO coins of non-existent profile
	{
		_, _, _, err = _daoCoinTransferTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m2PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(oneMCoins),
			ReceiverPublicKey:      m2PkBytes,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCoinTransferOnNonexistentProfile)
	}

	// Can't transfer if receiver pub key is not of correct length
	{
		_, _, _, err = _daoCoinTransferTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(oneMCoins),
			ReceiverPublicKey:      m2PkBytes[:10],
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCoinTransferInvalidReceiverPubKeySize)
	}

	// Can't transfer if profile pub key is not of correct length
	{
		_, _, _, err = _daoCoinTransferTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes[:10],
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(oneMCoins),
			ReceiverPublicKey:      m2PkBytes,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCoinTransferInvalidProfilePubKeySize)
	}

	// Can't burn more than you own
	{
		_, _, _, err = _daoCoinTxn(t, chain, db, params, 10, m0Pub, m0Priv, DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeBurn,
			CoinsToBurnNanos: *uint256.NewInt().SetUint64(oneMCoins),
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinBurnInsufficientCoins)
	}

	// Let's have m1 transfer all their coins. See number of holders go down.
	// M0 DAO cap table before:
	//		M0: 1M - 100K - 10K
	//		M1: 10K - 1K
	// M0 DAO cap table after:
	//		M0: 1M - 100K - 10K + (10K - 1K) = 1M - 100K - 1K
	//		M1: 0
	{
		_daoCoinTransferTxnWithTestMeta(testMeta, 10, m1Pub, m1Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			ReceiverPublicKey:      m0PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(tenKCoins - oneKCoins),
		})

		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m0PKID.PKID, m0PKID.PKID, true)
		require.Equal(daoBalanceEntry.BalanceNanos.Uint64(), oneMCoins-hundredKCoins-oneKCoins)

		m1DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m1PKID.PKID, m0PKID.PKID, true)
		// M1's balance entry is deleted because they have nothing
		require.Nil(m1DAOBalanceEntry)

		profileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(1))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// Have m0 transfer some coins to m2
	// M0 DAO cap table before:
	//		M0: 1M - 100K - 1K
	// M0 DAO cap table after:
	//		M0: 1M - 100K - 10K - 1K
	//		M2: 10K
	{
		_daoCoinTransferTxnWithTestMeta(testMeta, 10, m0Pub, m0Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			ReceiverPublicKey:      m2PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(tenKCoins),
		})

		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m0PKID.PKID, m0PKID.PKID, true)
		require.Equal(daoBalanceEntry.BalanceNanos.Uint64(), oneMCoins-hundredKCoins-tenKCoins-oneKCoins)

		m2DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m2PKID.PKID, m0PKID.PKID, true)
		require.Equal(m2DAOBalanceEntry.BalanceNanos.Uint64(), tenKCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// Create a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

	// Swap m0 and m3 identities
	// M0 DAO cap table before:
	//		M0: 1M - 100K - 10K - 1K
	//		M2: 10K
	// M3 DAO cap table after:
	//		M3: 1M - 100K - 10K - 1K
	//		M2: 10K
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
		require.Equal(m3ProfileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins-oneKCoins)
		require.True(m3ProfileEntry.DAOCoinEntry.MintingDisabled)

		// M0 shouldn't have a profile entry since M3 didn't have one before
		m0ProfileEntry := DBGetProfileEntryForPKID(db, m0PKID.PKID)
		require.Nil(m0ProfileEntry)

		// M0 shouldn't own any M3 DAO Coin
		m0DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(db, m0PKID.PKID, m3PKID.PKID, true)
		require.Nil(m0DAOBalanceEntry)

		// M3's DAO Balance entry should be what M0's was prior to the swap
		m3DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(db, m3PKID.PKID, m3PKID.PKID, true)
		require.Equal(m3DAOBalanceEntry.BalanceNanos.Uint64(), oneMCoins-hundredKCoins-tenKCoins-oneKCoins)
	}
	m3PKID := DBGetPKIDEntryForPublicKey(db, m3PkBytes)
	m0PKID = DBGetPKIDEntryForPublicKey(db, m0PkBytes)

	// So now let's have M3 update the restriction status to be Profile owner only. Now either the recipient or sender
	// must be the profile owner.
	{
		_daoCoinTxnWithTestMeta(testMeta, 10, m3Pub, m3Priv, DAOCoinMetadata{
			ProfilePublicKey:          m3PkBytes,
			OperationType:             DAOCoinOperationTypeUpdateTransferRestrictionStatus,
			TransferRestrictionStatus: TransferRestrictionStatusProfileOwnerOnly,
		})

		m3ProfileEntry := DBGetProfileEntryForPKID(db, m3PKID.PKID)
		require.Equal(m3ProfileEntry.DAOCoinEntry.TransferRestrictionStatus, TransferRestrictionStatusProfileOwnerOnly)
	}

	// M1 can't update the TransferRestrictionStatus
	{
		_, _, _, err = _daoCoinTxn(t, chain, db, params, 10, m1Pub, m1Priv, DAOCoinMetadata{
			ProfilePublicKey:          m3PkBytes,
			OperationType:             DAOCoinOperationTypeUpdateTransferRestrictionStatus,
			TransferRestrictionStatus: TransferRestrictionStatusPermanentlyUnrestricted,
		})

		require.Error(err)
		require.Contains(err.Error(), RuleErrorOnlyProfileOwnerCanUpdateTransferRestrictionStatus)
	}

	// m2 tries to transfer their coins to m1, but can't because must transfer to/from the profile owner.
	{
		_, _, _, err = _daoCoinTransferTxn(t, chain, db, params, 10, m2Pub, m2Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m3PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(1),
			ReceiverPublicKey:      m1PkBytes,
		})
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinTransferProfileOwnerOnlyViolation)
	}

	// M2 can transfer 1K to M3!
	// M3 DAO cap table before:
	//		M3: 1M - 100K - 10K - 1K
	//		M2: 10K
	// M3 DAO cap table after:
	//		M3: 1M - 100K - 10K - 1K + 1K = 1M - 100K - 10K
	//		M2: 10K - 1K
	{
		_daoCoinTransferTxnWithTestMeta(testMeta, 10, m2Pub, m2Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m3PkBytes,
			ReceiverPublicKey:      m3PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(oneKCoins),
		})

		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m3PKID.PKID, m3PKID.PKID, true)
		require.Equal(daoBalanceEntry.BalanceNanos.Uint64(), oneMCoins-hundredKCoins-tenKCoins)

		m2DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m2PKID.PKID, m3PKID.PKID, true)
		require.Equal(m2DAOBalanceEntry.BalanceNanos.Uint64(), tenKCoins-oneKCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m3PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// M3 transfers 1K to M1
	// M3 DAO cap table before:
	//		M3: 1M - 100K - 10K
	//		M2: 10K - 1K
	// M3 DAO cap table after:
	//		M3: 1M - 100K - 10K - 1K
	//		M2: 10K - 1K
	//		M1: 1K
	{
		_daoCoinTransferTxnWithTestMeta(testMeta, 10, m3Pub, m3Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m3PkBytes,
			ReceiverPublicKey:      m1PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(oneKCoins),
		})

		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m3PKID.PKID, m3PKID.PKID, true)
		require.Equal(daoBalanceEntry.BalanceNanos.Uint64(), oneMCoins-hundredKCoins-tenKCoins-oneKCoins)

		m1DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m1PKID.PKID, m3PKID.PKID, true)
		require.Equal(m1DAOBalanceEntry.BalanceNanos.Uint64(), oneKCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m3PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(3))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// Okay so now M3 wants to allow anybody who holds their DAO coin to transfer amongst themselves
	{
		_daoCoinTxnWithTestMeta(testMeta, 10, m3Pub, m3Priv, DAOCoinMetadata{
			ProfilePublicKey:          m3PkBytes,
			OperationType:             DAOCoinOperationTypeUpdateTransferRestrictionStatus,
			TransferRestrictionStatus: TransferRestrictionStatusDAOMembersOnly,
		})

		m3ProfileEntry := DBGetProfileEntryForPKID(db, m3PKID.PKID)
		require.Equal(m3ProfileEntry.DAOCoinEntry.TransferRestrictionStatus, TransferRestrictionStatusDAOMembersOnly)
	}

	// M1 can't transfer to M4 because they're not a DAO member yet.
	{
		_, _, _, err = _daoCoinTransferTxn(t, chain, db, params, 10, m1Pub, m1Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m3PkBytes,
			ReceiverPublicKey:      m4PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(100),
		})

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinTransferDAOMemberOnlyViolation)
	}

	// M1 can 100 transfer to M2 tho, no problem - because M2 is already a DAO HODLer
	// M3 DAO cap table before:
	//		M3: 1M - 100K - 10K - 1K
	//		M2: 10K - 1K
	//		M1: 1K
	// M3 DAO cap table after:
	//		M3: 1M - 100K - 10K - 1K
	//		M2: 10K - 1K + 100
	//		M1: 1K - 100
	{
		_daoCoinTransferTxnWithTestMeta(testMeta, 10, m1Pub, m1Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m3PkBytes,
			ReceiverPublicKey:      m2PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(hundredCoins),
		})

		m1DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m1PKID.PKID, m3PKID.PKID, true)
		require.Equal(m1DAOBalanceEntry.BalanceNanos.Uint64(), oneKCoins-hundredCoins)

		m2DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m2PKID.PKID, m3PKID.PKID, true)
		require.Equal(m2DAOBalanceEntry.BalanceNanos.Uint64(), tenKCoins-oneKCoins+hundredCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m3PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(3))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// M3 can transfer to whomever they want, even if they're not a DAO member yet. M3 transfers 100 to M4, so M1 can
	// transfer some later.
	// M3 DAO cap table before:
	//		M3: 1M - 100K - 10K - 1K
	//		M2: 10K - 1K + 100
	//		M1: 1K - 100
	// M3 DAO cap table after:
	//		M3: 1M - 100K - 10K - 1K - 100
	//		M2: 10K - 1K + 100
	//		M1: 1K - 100
	//		M4: 100
	{
		_daoCoinTransferTxnWithTestMeta(testMeta, 10, m3Pub, m3Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m3PkBytes,
			ReceiverPublicKey:      m4PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(hundredCoins),
		})

		m3DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m3PKID.PKID, m3PKID.PKID, true)
		require.Equal(m3DAOBalanceEntry.BalanceNanos.Uint64(), oneMCoins-hundredKCoins-tenKCoins-oneKCoins-hundredCoins)

		m4DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m4PKID.PKID, m3PKID.PKID, true)
		require.Equal(m4DAOBalanceEntry.BalanceNanos.Uint64(), hundredCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m3PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(4))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// M1 can now 100 transfer to M4
	// M3 DAO cap table before:
	//		M3: 1M - 100K - 10K - 1K - 100
	//		M2: 10K - 1K + 100
	//		M1: 1K - 100
	//		M4: 100
	// M3 DAO cap table after:
	//		M3: 1M - 100K - 10K - 1K - 100
	//		M2: 10K - 1K + 100
	//		M1: 1K - 100 - 100
	//		M4: 100 + 100
	{
		_daoCoinTransferTxnWithTestMeta(testMeta, 10, m1Pub, m1Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m3PkBytes,
			ReceiverPublicKey:      m4PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(hundredCoins),
		})

		m1DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m1PKID.PKID, m3PKID.PKID, true)
		require.Equal(m1DAOBalanceEntry.BalanceNanos.Uint64(), oneKCoins-hundredCoins-hundredCoins)

		m4DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m4PKID.PKID, m3PKID.PKID, true)
		require.Equal(m4DAOBalanceEntry.BalanceNanos.Uint64(), hundredCoins+hundredCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m3PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(4))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// M1 can't send anything to M0 right now, because M0 owns 0 M3 DAO coin.
	{
		_, _, _, err = _daoCoinTransferTxn(t, chain, db, params, 10, m1Pub, m1Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m3PkBytes,
			ReceiverPublicKey:      m0PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(100),
		})

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinTransferDAOMemberOnlyViolation)
	}

	// M3 permanently unrestricts transfers so all DAO holders can transfer willy-nilly
	{
		_daoCoinTxnWithTestMeta(testMeta, 10, m3Pub, m3Priv, DAOCoinMetadata{
			ProfilePublicKey:          m3PkBytes,
			OperationType:             DAOCoinOperationTypeUpdateTransferRestrictionStatus,
			TransferRestrictionStatus: TransferRestrictionStatusPermanentlyUnrestricted,
		})

		profileEntry := DBGetProfileEntryForPKID(db, m3PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.TransferRestrictionStatus,
			TransferRestrictionStatusPermanentlyUnrestricted)
	}
	// M3 can't restrict the transfers at all anymore
	{
		_, _, _, err = _daoCoinTxn(t, chain, db, params, 10, m3Pub, m3Priv, DAOCoinMetadata{
			ProfilePublicKey:          m3PkBytes,
			OperationType:             DAOCoinOperationTypeUpdateTransferRestrictionStatus,
			TransferRestrictionStatus: TransferRestrictionStatusProfileOwnerOnly,
		})

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinCannotUpdateRestrictionStatusIfStatusIsPermanentlyUnrestricted)
	}

	// M1 can send M0 now to get them back in the game. M1 sends them 100 coins
	// M1 can now 100 transfer to M4
	// M3 DAO cap table before:
	//		M3: 1M - 100K - 10K - 1K - 100
	//		M2: 10K - 1K + 100
	//		M1: 1K - 100
	//		M4: 100
	// M3 DAO cap table after:
	//		M3: 1M - 100K - 10K - 1K - 100
	//		M2: 10K - 1K + 100
	//		M1: 1K - 100 - 100 - 100
	//		M4: 100 + 100
	//		M0: 100
	{
		_daoCoinTransferTxnWithTestMeta(testMeta, 10, m1Pub, m1Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m3PkBytes,
			ReceiverPublicKey:      m0PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(hundredCoins),
		})

		m1DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m1PKID.PKID, m3PKID.PKID, true)
		require.Equal(m1DAOBalanceEntry.BalanceNanos.Uint64(), oneKCoins-hundredCoins-hundredCoins-hundredCoins)

		m0DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m0PKID.PKID, m3PKID.PKID, true)
		require.Equal(m0DAOBalanceEntry.BalanceNanos.Uint64(), hundredCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m3PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(5))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// Have m3 transfer the rest of their coins to m2
	// M3 DAO cap table before:
	//		M3: 1M - 100K - 10K - 1K - 100
	//		M2: 10K - 1K + 100
	//		M1: 1K - 100 - 100 - 100
	//		M4: 100 + 100
	//		M0: 100
	// M3 DAO cap table after:
	//		M2: 10K - 1K + 100 + (1M - 100K - 10K - 1K - 100) = 1M - 100K - 1K - 1K
	//		M1: 1K - 100 - 100 - 100
	//		M4: 100 + 100
	//		M0: 100
	{
		_daoCoinTransferTxnWithTestMeta(testMeta, 10, m3Pub, m3Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m3PkBytes,
			ReceiverPublicKey:      m2PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(oneMCoins - hundredKCoins - tenKCoins - oneKCoins - hundredCoins),
		})

		daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m3PKID.PKID, m3PKID.PKID, true)
		require.Nil(daoBalanceEntry)

		m2DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m2PKID.PKID, m3PKID.PKID, true)
		require.Equal(m2DAOBalanceEntry.BalanceNanos.Uint64(), oneMCoins-hundredKCoins-oneKCoins-oneKCoins)

		profileEntry := DBGetProfileEntryForPKID(db, m3PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneMCoins-hundredKCoins-oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(4))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// Have m2 burn all their M3 DAO coin
	// M3 DAO cap table before:
	//		M2: 1M - 100K - 1K - 1K
	//		M1: 1K - 100 - 100 - 100
	//		M4: 100 + 100
	//		M0: 100
	// M3 DAO cap table after:
	//		M2: 0
	//		M1: 1K - 100 - 100 - 100
	//		M4: 100 + 100
	//		M0: 100
	{
		_daoCoinTxnWithTestMeta(testMeta, 10, m2Pub, m2Priv, DAOCoinMetadata{
			ProfilePublicKey: m3PkBytes,
			OperationType:    DAOCoinOperationTypeBurn,
			CoinsToBurnNanos: *uint256.NewInt().SetUint64(oneMCoins - hundredKCoins - oneKCoins - oneKCoins),
		})

		m2DAOBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
			db, m2PKID.PKID, m3PKID.PKID, true)
		require.Nil(m2DAOBalanceEntry)

		profileEntry := DBGetProfileEntryForPKID(db, m3PKID.PKID)
		require.Equal(profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Uint64(), oneKCoins)
		require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(3))
		require.True(profileEntry.DAOCoinEntry.MintingDisabled)
	}

	// Create a profile for m2
	{
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m2Pub,         /*updaterPkBase58Check*/
			m2Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Have m2 try to mint an amount that would exceed the maximum allowed.
	// This should fail.
	{
		// Mint the max - 1k
		// M2 DAO cap table before:
		// - nobody has any
		// M2 DAO cap table after:
		// - M2: max-1k
		maxMinus1k := uint256.NewInt().Sub(MaxUint256, uint256.NewInt().SetUint64(1000))
		{
			_daoCoinTxnWithTestMeta(testMeta, 10, m2Pub, m2Priv, DAOCoinMetadata{
				ProfilePublicKey: m2PkBytes,
				OperationType:    DAOCoinOperationTypeMint,
				CoinsToMintNanos: *maxMinus1k,
			})
			daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
				db, m2PKID.PKID, m2PKID.PKID, true)
			require.Equal(&daoBalanceEntry.BalanceNanos, maxMinus1k)

			profileEntry := DBGetProfileEntryForPKID(db, m2PKID.PKID)
			require.Equal(&profileEntry.DAOCoinEntry.CoinsInCirculationNanos, maxMinus1k)
			require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(1))
			require.False(profileEntry.DAOCoinEntry.MintingDisabled)
		}

		// Minting 1,001 coins should fail
		{
			_, _, _, err = _daoCoinTxn(t, chain, db, params, 10, m2Pub, m2Priv, DAOCoinMetadata{
				ProfilePublicKey: m2PkBytes,
				OperationType:    DAOCoinOperationTypeMint,
				CoinsToMintNanos: *uint256.NewInt().SetUint64(1001),
			})
			require.Error(err)
			require.Contains(err.Error(), RuleErrorOverflowWhileMintingDAOCoins)
		}

		// Have M2 send half of the coins to M1
		// M2 DAO cap table before:
		// - M2: max-1k
		// M2 DAO cap table after:
		// - M1: (max-1k) / 2
		// - M2: (max-1k) / 2 + 1
		maxMinus1kDiv2 := uint256.NewInt().Div(maxMinus1k, uint256.NewInt().SetUint64(2))
		maxMinus1kDiv2PlusOne := uint256.NewInt().Add(
			maxMinus1kDiv2,
			uint256.NewInt().SetUint64(1))
		{
			_daoCoinTransferTxnWithTestMeta(testMeta, 10, m2Pub, m2Priv, DAOCoinTransferMetadata{
				ProfilePublicKey:       m2PkBytes,
				ReceiverPublicKey:      m1PkBytes,
				DAOCoinToTransferNanos: *maxMinus1kDiv2,
			})

			{
				daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
					db, m1PKID.PKID, m2PKID.PKID, true)
				require.Equal(maxMinus1kDiv2, &daoBalanceEntry.BalanceNanos)
			}
			{
				daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
					db, m2PKID.PKID, m2PKID.PKID, true)
				require.Equal(maxMinus1kDiv2PlusOne, &daoBalanceEntry.BalanceNanos)
			}

			profileEntry := DBGetProfileEntryForPKID(db, m2PKID.PKID)
			require.Equal(&profileEntry.DAOCoinEntry.CoinsInCirculationNanos, maxMinus1k)
			require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
			require.False(profileEntry.DAOCoinEntry.MintingDisabled)
		}

		// Minting 1,001 coins should STILL fail
		{
			_, _, _, err = _daoCoinTxn(t, chain, db, params, 10, m2Pub, m2Priv, DAOCoinMetadata{
				ProfilePublicKey: m2PkBytes,
				OperationType:    DAOCoinOperationTypeMint,
				CoinsToMintNanos: *uint256.NewInt().SetUint64(1001),
			})
			require.Error(err)
			require.Contains(err.Error(), RuleErrorOverflowWhileMintingDAOCoins)
		}

		// Mintng 1k coins should pass, and take us to the max supply
		// M2 DAO cap table before:
		// - M1: (max-1k)/2
		// - M2: (max-1k)/2 + 1
		// M2 DAO cap table after:
		// - M1: (max-1k)/2
		// - M2: (max-1k)/2 + 1k + 1
		maxMinus1kDiv2Plus1kPlusOne := uint256.NewInt().Add(
			maxMinus1kDiv2, uint256.NewInt().SetUint64(1001))
		{
			_daoCoinTxnWithTestMeta(testMeta, 10, m2Pub, m2Priv, DAOCoinMetadata{
				ProfilePublicKey: m2PkBytes,
				OperationType:    DAOCoinOperationTypeMint,
				CoinsToMintNanos: *uint256.NewInt().SetUint64(1000),
			})

			{
				daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
					db, m1PKID.PKID, m2PKID.PKID, true)
				require.Equal(maxMinus1kDiv2, &daoBalanceEntry.BalanceNanos)
			}
			{
				daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
					db, m2PKID.PKID, m2PKID.PKID, true)
				require.Equal(maxMinus1kDiv2Plus1kPlusOne, &daoBalanceEntry.BalanceNanos)
			}

			profileEntry := DBGetProfileEntryForPKID(db, m2PKID.PKID)
			require.Equal(MaxUint256, &profileEntry.DAOCoinEntry.CoinsInCirculationNanos)
			require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
			require.False(profileEntry.DAOCoinEntry.MintingDisabled)
		}

		// Burning 2k should work
		// M2 DAO cap table before:
		// - M1: (max-1k)/2
		// - M2: (max-1k)/2 + 1k + 1
		// M2 DAO cap table after:
		// - M1: (max-1k)/2 - 2k
		// - M2: (max-1k)/2 + 1k + 1
		maxMinus1kDiv2Minus2k := uint256.NewInt().Sub(
			maxMinus1kDiv2, uint256.NewInt().SetUint64(2000))
		maxMinus1kDiv2Minus1kPlus1 := uint256.NewInt().Add(
			maxMinus1kDiv2Minus2k,
			maxMinus1kDiv2Plus1kPlusOne)
		{
			_daoCoinTxnWithTestMeta(testMeta, 10, m1Pub, m1Priv, DAOCoinMetadata{
				ProfilePublicKey: m2PkBytes,
				OperationType:    DAOCoinOperationTypeBurn,
				CoinsToBurnNanos: *uint256.NewInt().SetUint64(2000),
			})

			{
				daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
					db, m1PKID.PKID, m2PKID.PKID, true)
				require.Equal(maxMinus1kDiv2Minus2k, &daoBalanceEntry.BalanceNanos)
			}
			{
				daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
					db, m2PKID.PKID, m2PKID.PKID, true)
				require.Equal(maxMinus1kDiv2Plus1kPlusOne, &daoBalanceEntry.BalanceNanos)
			}

			profileEntry := DBGetProfileEntryForPKID(db, m2PKID.PKID)
			require.Equal(maxMinus1kDiv2Minus1kPlus1, &profileEntry.DAOCoinEntry.CoinsInCirculationNanos)
			require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
			require.False(profileEntry.DAOCoinEntry.MintingDisabled)
		}

		// Minting 1k should work
		// M2 DAO cap table before:
		// - M1: (max-1k)/2 - 2k
		// - M2: (max-1k)/2 + 1k + 1
		// M2 DAO cap table after:
		// - M1: (max-1k)/2 - 2k
		// - M2: (max-1k)/2 + 2k + 1
		maxMinus1kDiv2Plus2k := uint256.NewInt().Add(
			maxMinus1kDiv2, uint256.NewInt().SetUint64(2000))
		maxMinus1kDiv2Plus2kPlus1 := uint256.NewInt().Add(
			maxMinus1kDiv2Plus2k, uint256.NewInt().SetUint64(1))
		{
			_daoCoinTxnWithTestMeta(testMeta, 10, m2Pub, m2Priv, DAOCoinMetadata{
				ProfilePublicKey: m2PkBytes,
				OperationType:    DAOCoinOperationTypeMint,
				CoinsToMintNanos: *uint256.NewInt().SetUint64(1000),
			})

			{
				daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
					db, m1PKID.PKID, m2PKID.PKID, true)
				require.Equal(maxMinus1kDiv2Minus2k, &daoBalanceEntry.BalanceNanos)
			}
			{
				daoBalanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDs(
					db, m2PKID.PKID, m2PKID.PKID, true)
				require.Equal(maxMinus1kDiv2Plus2kPlus1, &daoBalanceEntry.BalanceNanos)
			}

			profileEntry := DBGetProfileEntryForPKID(db, m2PKID.PKID)
			require.Equal(maxMinus1k, &profileEntry.DAOCoinEntry.CoinsInCirculationNanos)
			require.Equal(profileEntry.DAOCoinEntry.NumberOfHolders, uint64(2))
			require.False(profileEntry.DAOCoinEntry.MintingDisabled)
		}

		// Minting 1,001 coins should STILL fail
		{
			_, _, _, err = _daoCoinTxn(t, chain, db, params, 10, m2Pub, m2Priv, DAOCoinMetadata{
				ProfilePublicKey: m2PkBytes,
				OperationType:    DAOCoinOperationTypeMint,
				CoinsToMintNanos: *uint256.NewInt().SetUint64(1001),
			})
			require.Error(err)
			require.Contains(err.Error(), RuleErrorOverflowWhileMintingDAOCoins)
		}
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}
