package lib

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestValidatorRegistration(t *testing.T) {
	_testValidatorRegistration(t, true)
	_testValidatorRegistration(t, false)
}

func _testValidatorRegistration(t *testing.T, flushToDB bool) {
	var registerMetadata *RegisterAsValidatorMetadata
	var err error

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)
	params.ForkHeights.AssociationsAndAccessGroupsBlockHeight = uint32(0)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

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
		// Happy path: validator is registered
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("https://example.com")},
			DisableDelegatedStake: false,
		}
		_, _, _, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB,
		)
		require.NoError(t, err)
	}
}

func _submitRegisterAsValidatorTxn(
	testMeta *TestMeta,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	metadata *RegisterAsValidatorMetadata,
	extraData map[string][]byte,
	flushToDB bool,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
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
	return utxoOps, txn, testMeta.savedHeight, nil
}

func _submitUnregisterAsValidatorTxn(
	testMeta *TestMeta,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	flushToDB bool,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
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
	return utxoOps, txn, testMeta.savedHeight, nil
}
