package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestValidatorRegistration(t *testing.T) {
	_testValidatorRegistration(t, false)
	_testValidatorRegistration(t, true)
	_testValidatorRegistrationWithDerivedKey(t)
}

func _testValidatorRegistration(t *testing.T, flushToDB bool) {
	// Local variables
	var registerMetadata *RegisterAsValidatorMetadata
	var validatorEntry *ValidatorEntry
	var validatorEntries []*ValidatorEntry
	var globalStakeAmountNanos *uint256.Int
	var err error

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	utxoView := func() *UtxoView {
		newUtxoView, err := mempool.GetAugmentedUniversalView()
		require.NoError(t, err)
		return newUtxoView
	}
	_ = utxoView

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
	{
		// RuleErrorProofOfStakeTxnBeforeBlockHeight
		params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = math.MaxUint32
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("https://example.com")},
			DisableDelegatedStake: false,
		}
		_, _, _, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorProofofStakeTxnBeforeBlockHeight)

		params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = uint32(0)
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	}
	{
		// RuleErrorValidatorNoDomains
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               [][]byte{},
			DisableDelegatedStake: false,
		}
		_, _, _, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorNoDomains)
	}
	{
		// RuleErrorValidatorTooManyDomains
		var domains [][]byte
		for ii := 0; ii <= MaxValidatorNumDomains+1; ii++ {
			domains = append(domains, []byte(fmt.Sprintf("https://example.com/%d", ii)))
		}
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               domains,
			DisableDelegatedStake: false,
		}
		_, _, _, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorTooManyDomains)
	}
	{
		// RuleErrorValidatorInvalidDomain
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("InvalidURL")},
			DisableDelegatedStake: false,
		}
		_, _, _, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorInvalidDomain)
	}
	{
		// RuleErrorValidatorDuplicateDomains
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("https://example.com"), []byte("https://example.com")},
			DisableDelegatedStake: false,
		}
		_, _, _, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorDuplicateDomains)
	}
	{
		// Happy path: register a validator
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("https://example.com")},
			DisableDelegatedStake: false,
		}
		extraData := map[string][]byte{"TestKey": []byte("TestValue1")}
		_, _, _, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerMetadata, extraData, flushToDB,
		)
		require.NoError(t, err)
	}
	{
		// Query: retrieve ValidatorEntry by PKID
		validatorEntry, err = utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.ValidatorPKID, m0PKID)
		require.Len(t, validatorEntry.Domains, 1)
		require.Equal(t, string(validatorEntry.Domains[0]), "https://example.com")
		require.False(t, validatorEntry.DisableDelegatedStake)
		require.Equal(t, string(validatorEntry.ExtraData["TestKey"]), "TestValue1")
	}
	{
		// Query: retrieve top ValidatorEntries by stake
		validatorEntries, err = utxoView().GetTopValidatorsByStake(0)
		require.NoError(t, err)
		require.Empty(t, validatorEntries)

		validatorEntries, err = utxoView().GetTopValidatorsByStake(2)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 1)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m0PKID)
	}
	{
		// Query: retrieve GlobalStakeAmountNanos
		globalStakeAmountNanos, err = utxoView().GetGlobalStakeAmountNanos()
		require.NoError(t, err)
		require.Equal(t, globalStakeAmountNanos, uint256.NewInt())
	}
	{
		// Happy path: update a validator
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("https://example1.com"), []byte("https://example2.com")},
			DisableDelegatedStake: false,
		}
		extraData := map[string][]byte{"TestKey": []byte("TestValue2")}
		_, _, _, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerMetadata, extraData, flushToDB,
		)
		require.NoError(t, err)
	}
	{
		// Query: retrieve ValidatorEntry by PKID, make sure it has been updated
		validatorEntry, err = utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.ValidatorPKID, m0PKID)
		require.Len(t, validatorEntry.Domains, 2)
		require.Equal(t, string(validatorEntry.Domains[0]), "https://example1.com")
		require.Equal(t, string(validatorEntry.Domains[1]), "https://example2.com")
		require.False(t, validatorEntry.DisableDelegatedStake)
		require.Equal(t, string(validatorEntry.ExtraData["TestKey"]), "TestValue2")
	}
	{
		// Sad path: unregister validator that doesn't exist
		_, _, _, err = _submitUnregisterAsValidatorTxn(testMeta, m1Pub, m1Priv, flushToDB)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorNotFound)
	}
	{
		// Happy path: unregister validator
		_, _, _, err = _submitUnregisterAsValidatorTxn(testMeta, m0Pub, m0Priv, flushToDB)
		require.NoError(t, err)
	}
	{
		// Sad path: unregister validator that doesn't exist
		_, _, _, err = _submitUnregisterAsValidatorTxn(testMeta, m0Pub, m0Priv, flushToDB)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorNotFound)
	}
	{
		// Query: retrieve ValidatorEntry by PKID
		validatorEntry, err = utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Nil(t, validatorEntry)
	}
	{
		// Query: retrieve top ValidatorEntries by stake
		validatorEntries, err = utxoView().GetTopValidatorsByStake(1)
		require.NoError(t, err)
		require.Empty(t, validatorEntries)
	}
	{
		// Query: retrieve GlobalStakeAmountNanos
		globalStakeAmountNanos, err = utxoView().GetGlobalStakeAmountNanos()
		require.NoError(t, err)
		require.Equal(t, globalStakeAmountNanos, uint256.NewInt())
	}

	// Flush mempool to the db and test rollbacks.
	require.NoError(t, mempool.universalUtxoView.FlushToDb(0))
	_executeAllTestRollbackAndFlush(testMeta)
}

func _submitRegisterAsValidatorTxn(
	testMeta *TestMeta,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	metadata *RegisterAsValidatorMetadata,
	extraData map[string][]byte,
	flushToDB bool,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	// Record transactor's prevBalance.
	prevBalance := _getBalance(testMeta.t, testMeta.chain, testMeta.mempool, transactorPublicKeyBase58Check)

	// Convert PublicKeyBase58Check to PkBytes.
	updaterPkBytes, _, err := Base58CheckDecode(transactorPublicKeyBase58Check)
	require.NoError(testMeta.t, err)

	// Create the transaction.
	txn, totalInputMake, changeAmountMake, feesMake, err := testMeta.chain.CreateRegisterAsValidatorTxn(
		updaterPkBytes,
		metadata,
		extraData,
		testMeta.feeRateNanosPerKb,
		testMeta.mempool,
		[]*DeSoOutput{},
	)
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(testMeta.t, totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(testMeta.t, txn, transactorPrivateKeyBase58Check)

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
	require.Equal(testMeta.t, OperationTypeRegisterAsValidator, utxoOps[len(utxoOps)-1].Type)
	if flushToDB {
		require.NoError(testMeta.t, testMeta.mempool.universalUtxoView.FlushToDb(0))
	}
	require.NoError(testMeta.t, testMeta.mempool.RegenerateReadOnlyView())

	// Record the txn.
	testMeta.expectedSenderBalances = append(testMeta.expectedSenderBalances, prevBalance)
	testMeta.txnOps = append(testMeta.txnOps, utxoOps)
	testMeta.txns = append(testMeta.txns, txn)
	return utxoOps, txn, testMeta.savedHeight, nil
}

func _submitUnregisterAsValidatorTxn(
	testMeta *TestMeta,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	flushToDB bool,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	// Record transactor's prevBalance.
	prevBalance := _getBalance(testMeta.t, testMeta.chain, testMeta.mempool, transactorPublicKeyBase58Check)

	// Convert PublicKeyBase58Check to PkBytes.
	updaterPkBytes, _, err := Base58CheckDecode(transactorPublicKeyBase58Check)
	require.NoError(testMeta.t, err)

	// Create the transaction.
	txn, totalInputMake, changeAmountMake, feesMake, err := testMeta.chain.CreateUnregisterAsValidatorTxn(
		updaterPkBytes,
		&UnregisterAsValidatorMetadata{},
		nil,
		testMeta.feeRateNanosPerKb,
		testMeta.mempool,
		[]*DeSoOutput{},
	)
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(testMeta.t, totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(testMeta.t, txn, transactorPrivateKeyBase58Check)

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
	require.Equal(testMeta.t, OperationTypeUnregisterAsValidator, utxoOps[len(utxoOps)-1].Type)
	if flushToDB {
		require.NoError(testMeta.t, testMeta.mempool.universalUtxoView.FlushToDb(0))
	}
	require.NoError(testMeta.t, testMeta.mempool.RegenerateReadOnlyView())

	// Record the txn.
	testMeta.expectedSenderBalances = append(testMeta.expectedSenderBalances, prevBalance)
	testMeta.txnOps = append(testMeta.txnOps, utxoOps)
	testMeta.txns = append(testMeta.txns, txn)
	return utxoOps, txn, testMeta.savedHeight, nil
}

func _testValidatorRegistrationWithDerivedKey(t *testing.T) {
	var err error

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize fork heights.
	params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeyEthSignatureCompatibilityBlockHeight = uint32(0)
	params.ForkHeights.ExtraDataOnEntriesBlockHeight = uint32(0)
	params.ForkHeights.AssociationsAndAccessGroupsBlockHeight = uint32(0)
	params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = uint32(0)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

	// Mine a few blocks to give the senderPkString some money.
	for ii := 0; ii < 10; ii++ {
		_, err = miner.MineAndProcessSingleBlock(0, mempool)
		require.NoError(t, err)
	}

	// We build the testMeta obj after mining blocks so that we save the correct block height.
	blockHeight := uint64(chain.blockTip().Height) + 1
	testMeta := &TestMeta{
		t:                 t,
		chain:             chain,
		params:            params,
		db:                db,
		mempool:           mempool,
		miner:             miner,
		savedHeight:       uint32(blockHeight),
		feeRateNanosPerKb: uint64(101),
	}

	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 1e3)

	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(t, err)
	senderPrivBytes, _, err := Base58CheckDecode(senderPrivString)
	require.NoError(t, err)
	senderPrivKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), senderPrivBytes)

	createDerivedKey := func(txnType TxnType, count uint64) error {
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(t, err)

		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
				txnType:                    count,
			},
		}

		derivedKeyMetadata, derivedKeyAuthPriv := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(
			t, senderPrivKey, blockHeight+5, txnSpendingLimit, false, blockHeight,
		)
		derivedKeyAuthPrivBase58Check := Base58CheckEncode(derivedKeyAuthPriv.Serialize(), true, params)

		prevBalance := _getBalance(testMeta.t, testMeta.chain, testMeta.mempool, senderPkString)

		utxoOps, txn, _, err := _doAuthorizeTxnWithExtraDataAndSpendingLimits(
			t,
			chain,
			db,
			params,
			utxoView,
			testMeta.feeRateNanosPerKb,
			senderPkBytes,
			derivedKeyMetadata.DerivedPublicKey,
			derivedKeyAuthPrivBase58Check,
			derivedKeyMetadata.ExpirationBlock,
			derivedKeyMetadata.AccessSignature,
			false,
			nil,
			nil,
			txnSpendingLimit,
		)
		if err != nil {
			return err
		}
		require.NoError(t, utxoView.FlushToDb(0))
		testMeta.expectedSenderBalances = append(testMeta.expectedSenderBalances, prevBalance)
		testMeta.txnOps = append(testMeta.txnOps, utxoOps)
		testMeta.txns = append(testMeta.txns, txn)

		return utxoView.ValidateDerivedKey(
			senderPkBytes, derivedKeyMetadata.DerivedPublicKey, blockHeight,
		)
	}

	{
		// Create RegisterAsValidator derived key.
		err = createDerivedKey(TxnTypeRegisterAsValidator, 1)
		require.NoError(t, err)
	}

	// Flush mempool to the db and test rollbacks.
	require.NoError(t, mempool.universalUtxoView.FlushToDb(0))
	_executeAllTestRollbackAndFlush(testMeta)
}
