package lib

import (
	"errors"
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

func TestGetTopValidatorsByStake(t *testing.T) {
	_testGetTopValidatorsByStake(t, false)
	_testGetTopValidatorsByStake(t, true)
}

func _testValidatorRegistration(t *testing.T, flushToDB bool) {
	// Local variables
	var registerMetadata *RegisterAsValidatorMetadata
	var validatorEntry *ValidatorEntry
	var validatorEntries []*ValidatorEntry
	var globalStakeAmountNanos *uint256.Int
	var err error

	// Initialize fork heights.
	setBalanceModelBlockHeights()
	defer resetBalanceModelBlockHeights()

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
	blockHeight := uint64(chain.blockTip().Height + 1)
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
		// ParamUpdater set min fee rate
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

		params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = uint32(1)
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
	require.NoError(t, mempool.universalUtxoView.FlushToDb(blockHeight))
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
		require.NoError(testMeta.t, testMeta.mempool.universalUtxoView.FlushToDb(uint64(testMeta.savedHeight)))
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
		require.NoError(testMeta.t, testMeta.mempool.universalUtxoView.FlushToDb(uint64(testMeta.savedHeight)))
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

	// Initialize balance model fork heights.
	setBalanceModelBlockHeights()
	defer resetBalanceModelBlockHeights()

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize fork heights.
	params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = uint32(1)
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
	senderPKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, senderPkBytes).PKID

	_submitAuthorizeDerivedKeyTxn := func(txnType TxnType, count uint64) (string, error) {
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
			testMeta,
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
			return "", err
		}
		require.NoError(t, utxoView.FlushToDb(blockHeight))
		testMeta.expectedSenderBalances = append(testMeta.expectedSenderBalances, prevBalance)
		testMeta.txnOps = append(testMeta.txnOps, utxoOps)
		testMeta.txns = append(testMeta.txns, txn)

		err = utxoView.ValidateDerivedKey(
			senderPkBytes, derivedKeyMetadata.DerivedPublicKey, blockHeight,
		)
		require.NoError(t, err)
		return derivedKeyAuthPrivBase58Check, nil
	}

	_submitValidatorTxnWithDerivedKey := func(
		transactorPkBytes []byte, derivedKeyPrivBase58Check string, inputTxn MsgDeSoTxn,
	) error {
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(t, err)
		var txn *MsgDeSoTxn

		switch inputTxn.TxnMeta.GetTxnType() {
		// Construct txn.
		case TxnTypeRegisterAsValidator:
			txn, _, _, _, err = testMeta.chain.CreateRegisterAsValidatorTxn(
				transactorPkBytes,
				inputTxn.TxnMeta.(*RegisterAsValidatorMetadata),
				make(map[string][]byte),
				testMeta.feeRateNanosPerKb,
				mempool,
				[]*DeSoOutput{},
			)
		case TxnTypeUnregisterAsValidator:
			txn, _, _, _, err = testMeta.chain.CreateUnregisterAsValidatorTxn(
				transactorPkBytes,
				inputTxn.TxnMeta.(*UnregisterAsValidatorMetadata),
				make(map[string][]byte),
				testMeta.feeRateNanosPerKb,
				mempool,
				[]*DeSoOutput{},
			)
		default:
			return errors.New("invalid txn type")
		}
		if err != nil {
			return err
		}
		// Sign txn.
		_signTxnWithDerivedKeyAndType(t, txn, derivedKeyPrivBase58Check, 1)
		// Store the original transactor balance.
		transactorPublicKeyBase58Check := Base58CheckEncode(transactorPkBytes, false, params)
		prevBalance := _getBalance(testMeta.t, testMeta.chain, testMeta.mempool, transactorPublicKeyBase58Check)
		// Connect txn.
		utxoOps, _, _, _, err := utxoView.ConnectTransaction(
			txn,
			txn.Hash(),
			getTxnSize(*txn),
			testMeta.savedHeight,
			true,
			false,
		)
		if err != nil {
			return err
		}
		// Flush UTXO view to the db.
		require.NoError(t, utxoView.FlushToDb(blockHeight))
		// Track txn for rolling back.
		testMeta.expectedSenderBalances = append(testMeta.expectedSenderBalances, prevBalance)
		testMeta.txnOps = append(testMeta.txnOps, utxoOps)
		testMeta.txns = append(testMeta.txns, txn)
		return nil
	}

	{
		// ParamUpdater set min fee rate
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
		// Submit a RegisterAsValidator txn using a DerivedKey.

		// Create a DerivedKey that can perform one RegisterAsValidator txn.
		derivedKeyPriv, err := _submitAuthorizeDerivedKeyTxn(TxnTypeRegisterAsValidator, 1)
		require.NoError(t, err)

		// Perform a RegisterAsValidator txn. No error expected.
		registerAsValidatorMetadata := &RegisterAsValidatorMetadata{
			Domains: [][]byte{[]byte("https://example.com")},
		}
		err = _submitValidatorTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: registerAsValidatorMetadata},
		)
		require.NoError(t, err)

		// Validate the ValidatorEntry exists.
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(t, err)
		validatorEntry, err := utxoView.GetValidatorByPKID(senderPKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Len(t, validatorEntry.Domains, 1)
		require.Equal(t, validatorEntry.Domains[0], []byte("https://example.com"))

		// Perform a second RegisterAsValidator txn. Error expected.
		err = _submitValidatorTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: registerAsValidatorMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "No more transactions of type REGISTER_AS_VALIDATOR are allowed on this Derived Key")

		// Perform an UnregisterAsValidator txn. Error expected.
		unregisterAsValidatorMetadata := &UnregisterAsValidatorMetadata{}
		err = _submitValidatorTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unregisterAsValidatorMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "No more transactions of type UNREGISTER_AS_VALIDATOR are allowed on this Derived Key")
	}
	{
		// Submit an UnregisterAsValidator txn using a DerivedKey.

		// Create a DerivedKey that can perform one UnregisterAsValidator txn.
		derivedKeyPriv, err := _submitAuthorizeDerivedKeyTxn(TxnTypeUnregisterAsValidator, 1)
		require.NoError(t, err)

		// Perform an UnregisterAsValidator txn. No error expected.
		unregisterAsValidatorMetadata := &UnregisterAsValidatorMetadata{}
		err = _submitValidatorTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unregisterAsValidatorMetadata},
		)
		require.NoError(t, err)

		// Validate the ValidatorEntry no longer exists.
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(t, err)
		validatorEntry, err := utxoView.GetValidatorByPKID(senderPKID)
		require.NoError(t, err)
		require.Nil(t, validatorEntry)

		// Perform a second UnregisterAsValidator txn. Error expected. Validator not found.
		err = _submitValidatorTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unregisterAsValidatorMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorNotFound)

		// Perform a RegisterAsValidator txn. Error expected.
		registerAsValidatorMetadata := &RegisterAsValidatorMetadata{
			Domains: [][]byte{[]byte("https://example.com")},
		}
		err = _submitValidatorTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: registerAsValidatorMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "No more transactions of type REGISTER_AS_VALIDATOR are allowed on this Derived Key")

	}

	// Flush mempool to the db and test rollbacks.
	require.NoError(t, mempool.universalUtxoView.FlushToDb(blockHeight))
	_executeAllTestRollbackAndFlush(testMeta)
}

func _testGetTopValidatorsByStake(t *testing.T, flushToDB bool) {
	var validatorEntries []*ValidatorEntry
	var err error

	// Initialize balance model fork heights.
	setBalanceModelBlockHeights()
	defer resetBalanceModelBlockHeights()

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize PoS fork height.
	params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = uint32(1)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

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
		// ParamUpdater set min fee rate
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
		// m0 registers as a validator.
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains: [][]byte{[]byte("https://m0.com")},
		}
		_, _, _, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB,
		)
		require.NoError(t, err)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopValidatorsByStake(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 1)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt())
	}
	{
		// m1 registers as a validator.
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains: [][]byte{[]byte("https://m1.com")},
		}
		_, _, _, err = _submitRegisterAsValidatorTxn(
			testMeta, m1Pub, m1Priv, registerMetadata, nil, flushToDB,
		)
		require.NoError(t, err)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopValidatorsByStake(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 2)
	}
	{
		// m2 registers as a validator.
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains: [][]byte{[]byte("https://m2.com")},
		}
		_, _, _, err = _submitRegisterAsValidatorTxn(
			testMeta, m2Pub, m2Priv, registerMetadata, nil, flushToDB,
		)
		require.NoError(t, err)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopValidatorsByStake(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 3)
	}
	{
		// m3 stakes 100 DESO nanos with m0.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(100),
		}
		_, err = _submitStakeTxn(testMeta, m3Pub, m3Priv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// m3 stakes 200 DESO nanos with m1.
		stakeMetadata = &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(200),
		}
		_, err = _submitStakeTxn(testMeta, m3Pub, m3Priv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// m3 stakes 300 DESO nanos with m2.
		stakeMetadata = &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m2PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(300),
		}
		_, err = _submitStakeTxn(testMeta, m3Pub, m3Priv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopValidatorsByStake(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 3)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m2PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt().SetUint64(300))
		require.Equal(t, validatorEntries[1].ValidatorPKID, m1PKID)
		require.Equal(t, validatorEntries[1].TotalStakeAmountNanos, uint256.NewInt().SetUint64(200))
		require.Equal(t, validatorEntries[2].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[2].TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))
	}
	{
		// m3 unstakes from m1.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(150),
		}
		_, err = _submitUnstakeTxn(testMeta, m3Pub, m3Priv, unstakeMetadata, nil, flushToDB)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopValidatorsByStake(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 3)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m2PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt().SetUint64(300))
		require.Equal(t, validatorEntries[1].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[1].TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))
		require.Equal(t, validatorEntries[2].ValidatorPKID, m1PKID)
		require.Equal(t, validatorEntries[2].TotalStakeAmountNanos, uint256.NewInt().SetUint64(50))
	}
	{
		// m3 unstakes more from m1.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(50),
		}
		_, err = _submitUnstakeTxn(testMeta, m3Pub, m3Priv, unstakeMetadata, nil, flushToDB)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopValidatorsByStake(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 3)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m2PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt().SetUint64(300))
		require.Equal(t, validatorEntries[1].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[1].TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))
		require.Equal(t, validatorEntries[2].ValidatorPKID, m1PKID)
		require.Equal(t, validatorEntries[2].TotalStakeAmountNanos, uint256.NewInt().SetUint64(0))
	}
	{
		// m2 unregisters as validator.
		_, _, _, err = _submitUnregisterAsValidatorTxn(testMeta, m2Pub, m2Priv, flushToDB)
		require.NoError(t, err)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopValidatorsByStake(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 2)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))
		require.Equal(t, validatorEntries[1].ValidatorPKID, m1PKID)
		require.Equal(t, validatorEntries[1].TotalStakeAmountNanos, uint256.NewInt().SetUint64(0))
	}
	{
		// m4 stakes with m1.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(150),
		}
		_, err = _submitStakeTxn(testMeta, m4Pub, m4Priv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopValidatorsByStake(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 2)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m1PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt().SetUint64(150))
		require.Equal(t, validatorEntries[1].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[1].TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))
	}
	{
		// m4 stakes more with m1.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(100),
		}
		_, err = _submitStakeTxn(testMeta, m4Pub, m4Priv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopValidatorsByStake(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 2)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m1PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt().SetUint64(250))
		require.Equal(t, validatorEntries[1].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[1].TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))
	}
	{
		// Verify top validators with LIMIT.
		validatorEntries, err = utxoView().GetTopValidatorsByStake(1)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 1)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m1PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt().SetUint64(250))
	}

	// Flush mempool to the db and test rollbacks.
	require.NoError(t, mempool.universalUtxoView.FlushToDb(blockHeight))
	_executeAllTestRollbackAndFlush(testMeta)
}
