package lib

import (
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/deso-protocol/core/bls"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestValidatorRegistration(t *testing.T) {
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	t.Run("flushToDB=false", func(t *testing.T) {
		_testValidatorRegistration(t, false)
	})
	t.Run("flushToDB=true", func(t *testing.T) {
		_testValidatorRegistration(t, true)
	})
}

func _testValidatorRegistration(t *testing.T, flushToDB bool) {
	// Local variables
	var registerMetadata *RegisterAsValidatorMetadata
	var validatorEntry *ValidatorEntry
	var blsPublicKeyPKIDPairEntry *BLSPublicKeyPKIDPairEntry
	var prevBLSPublicKey *bls.PublicKey
	var prevBLSPrivateKey *bls.PrivateKey
	var validatorEntries []*ValidatorEntry
	var err error

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 1e3)

	m0PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m0PkBytes).PKID

	{
		// ParamUpdater set MinFeeRateNanos.
		params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true
		_updateGlobalParamsEntryWithExtraData(
			testMeta,
			testMeta.feeRateNanosPerKb,
			paramUpdaterPub,
			paramUpdaterPriv,
			map[string][]byte{},
		)
	}
	{
		// RuleErrorProofOfStakeTxnBeforeBlockHeight
		params.ForkHeights.ProofOfStake1StateSetupBlockHeight = math.MaxUint32
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("https://example.com")},
			DisableDelegatedStake: false,
			VotingPublicKey:       votingPublicKey,
			VotingAuthorization:   votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorProofofStakeTxnBeforeBlockHeight)

		params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	}
	{
		// RuleErrorValidatorInvalidCommissionBasisPoints
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:                             [][]byte{[]byte("https://example.com")},
			DisableDelegatedStake:               true,
			DelegatedStakeCommissionBasisPoints: MaxDelegatedStakeCommissionBasisPoints + 1,
			VotingPublicKey:                     votingPublicKey,
			VotingAuthorization:                 votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorInvalidCommissionBasisPoints)
	}
	{
		// RuleErrorValidatorNoDomains
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               [][]byte{},
			DisableDelegatedStake: false,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB)
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
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorTooManyDomains)
	}
	{
		// RuleErrorValidatorInvalidDomain
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("InvalidURL")},
			DisableDelegatedStake: false,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorInvalidDomain)
	}
	{
		// RuleErrorValidatorDuplicateDomains
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("https://example.com"), []byte("https://example.com")},
			DisableDelegatedStake: false,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorDuplicateDomains)
	}
	{
		// RuleErrorValidatorMissingVotingPublicKey
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains: [][]byte{[]byte("https://example.com")},
		}
		_, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorMissingVotingPublicKey)
	}
	{
		// RuleErrorValidatorMissingVotingAuthorization
		votingPublicKey, _ := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:         [][]byte{[]byte("https://example.com")},
			VotingPublicKey: votingPublicKey,
		}
		_, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorMissingVotingAuthorization)
	}
	{
		// RuleErrorValidatorInvalidVotingAuthorization: invalid TransactorPkBytes
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m1PkBytes)
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte("https://example.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorInvalidVotingAuthorization)
	}
	{
		// RuleErrorValidatorInvalidVotingAuthorization: invalid VotingPublicKey
		votingPublicKey, _ := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		_, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte("https://example.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorInvalidVotingAuthorization)
	}
	{
		// Happy path: register a validator
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("https://example.com")},
			DisableDelegatedStake: false,
			VotingPublicKey:       votingPublicKey,
			VotingAuthorization:   votingAuthorization,
		}
		extraData := map[string][]byte{"TestKey": []byte("TestValue1")}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, extraData, flushToDB)
		require.NoError(t, err)
		prevBLSPublicKey = votingPublicKey.Copy()
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

		// Query: retrieve the BLSPublicKeyPKIDPairEntry for the validator's VotingPublicKey
		blsPublicKeyPKIDPairEntry, err = utxoView().GetBLSPublicKeyPKIDPairEntry(validatorEntry.VotingPublicKey)
		require.NoError(t, err)
		require.True(t, blsPublicKeyPKIDPairEntry.BLSPublicKey.Eq(validatorEntry.VotingPublicKey))
		require.True(t, blsPublicKeyPKIDPairEntry.PKID.Eq(validatorEntry.ValidatorPKID))
	}
	{
		// Query: retrieve top active ValidatorEntries by stake.
		// Should be empty since m0's TotalStakeAmountNanos is zero.
		validatorEntries, err = utxoView().GetTopActiveValidatorsByStakeAmount(1)
		require.NoError(t, err)
		require.Empty(t, validatorEntries)
	}
	{
		// Happy path: update a validator
		votingPrivateKey, votingPublicKey, votingAuthorization := _generateVotingPrivateKeyPublicKeyAndAuthorization(t, m0PkBytes)
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("https://example1.com"), []byte("https://example2.com")},
			DisableDelegatedStake: false,
			VotingPublicKey:       votingPublicKey,
			VotingAuthorization:   votingAuthorization,
		}
		extraData := map[string][]byte{"TestKey": []byte("TestValue2")}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, extraData, flushToDB)
		require.NoError(t, err)
		prevBLSPublicKey = votingPublicKey.Copy()
		prevBLSPrivateKey = votingPrivateKey
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

		// Query: retrieve the BLSPublicKeyPKIDPairEntry for the validator's VotingPublicKey
		// make sure it has been updated.
		blsPublicKeyPKIDPairEntry, err = utxoView().GetBLSPublicKeyPKIDPairEntry(validatorEntry.VotingPublicKey)
		require.NoError(t, err)
		require.True(t, blsPublicKeyPKIDPairEntry.BLSPublicKey.Eq(validatorEntry.VotingPublicKey))
		require.True(t, blsPublicKeyPKIDPairEntry.PKID.Eq(validatorEntry.ValidatorPKID))
	}
	{
		// Sad path: register validator with same VotingPublicKey as m0
		var votingAuthorization *bls.Signature
		votingAuthorization, err = prevBLSPrivateKey.Sign(CreateValidatorVotingAuthorizationPayload(m1PkBytes))
		require.NoError(t, err)
		registerMetadata = &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("https://example.com")},
			DisableDelegatedStake: false,
			VotingPublicKey:       prevBLSPublicKey,
			VotingAuthorization:   votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m1Pub, m1Priv, registerMetadata, nil, flushToDB)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorVotingPublicKeyDuplicate)
	}
	{
		// Sad path: unregister validator that doesn't exist
		_, err = _submitUnregisterAsValidatorTxn(testMeta, m1Pub, m1Priv, flushToDB)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorNotFound)
	}
	{
		// Happy path: unregister validator
		_, err = _submitUnregisterAsValidatorTxn(testMeta, m0Pub, m0Priv, flushToDB)
		require.NoError(t, err)
	}
	{
		// Sad path: unregister validator that doesn't exist
		_, err = _submitUnregisterAsValidatorTxn(testMeta, m0Pub, m0Priv, flushToDB)
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
		// Query: retrieve the BLSPublicKeyPKIDPairEntry for the validator's VotingPublicKey
		blsPublicKeyPKIDPairEntry, err = utxoView().GetBLSPublicKeyPKIDPairEntry(prevBLSPublicKey)
		require.NoError(t, err)
		require.Nil(t, blsPublicKeyPKIDPairEntry)
	}
	{
		// Query: retrieve top active ValidatorEntries by stake
		validatorEntries, err = utxoView().GetTopActiveValidatorsByStakeAmount(1)
		require.NoError(t, err)
		require.Empty(t, validatorEntries)
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
) (_fees uint64, _err error) {
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
		return 0, err
	}
	require.Equal(testMeta.t, totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(testMeta.t, txn, transactorPrivateKeyBase58Check)

	// Connect the transaction.
	utxoOps, totalInput, totalOutput, fees, err := testMeta.mempool.universalUtxoView.ConnectTransaction(
		txn, txn.Hash(), testMeta.savedHeight, 0, true, false)
	if err != nil {
		return 0, err
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
	return fees, nil
}

func _submitUnregisterAsValidatorTxn(
	testMeta *TestMeta,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	flushToDB bool,
) (_fees uint64, _err error) {
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
		return 0, err
	}
	require.Equal(testMeta.t, totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(testMeta.t, txn, transactorPrivateKeyBase58Check)

	// Connect the transaction.
	utxoOps, totalInput, totalOutput, fees, err := testMeta.mempool.universalUtxoView.ConnectTransaction(
		txn, txn.Hash(), testMeta.savedHeight, 0, true, false)
	if err != nil {
		return 0, err
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
	return fees, nil
}

func TestValidatorRegistrationWithDerivedKey(t *testing.T) {
	var err error

	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize PoS fork height.
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
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
	senderPrivKey, _ := btcec.PrivKeyFromBytes(senderPrivBytes)
	senderPKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, senderPkBytes).PKID

	newUtxoView := func() *UtxoView {
		utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
		return utxoView
	}

	_submitAuthorizeDerivedKeyTxn := func(txnType TxnType, count uint64) (string, error) {
		utxoView := newUtxoView()

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
		utxoView := newUtxoView()
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
			txn, txn.Hash(), testMeta.savedHeight, 0, true, false)
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
		// ParamUpdater set MinFeeRateNanos.
		params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true
		_updateGlobalParamsEntryWithExtraData(
			testMeta,
			testMeta.feeRateNanosPerKb,
			paramUpdaterPub,
			paramUpdaterPriv,
			map[string][]byte{},
		)
	}
	{
		// Submit a RegisterAsValidator txn using a DerivedKey.

		// Create a DerivedKey that can perform one RegisterAsValidator txn.
		derivedKeyPriv, err := _submitAuthorizeDerivedKeyTxn(TxnTypeRegisterAsValidator, 1)
		require.NoError(t, err)

		// Create a VotingPublicKey and VotingAuthorization.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, senderPkBytes)

		// Perform a RegisterAsValidator txn. No error expected.
		registerAsValidatorMetadata := &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte("https://example.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		err = _submitValidatorTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: registerAsValidatorMetadata},
		)
		require.NoError(t, err)

		// Validate the ValidatorEntry exists.
		utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
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
		utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
		validatorEntry, err := utxoView.GetValidatorByPKID(senderPKID)
		require.NoError(t, err)
		require.Nil(t, validatorEntry)

		// Perform a second UnregisterAsValidator txn. Error expected. Validator not found.
		err = _submitValidatorTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unregisterAsValidatorMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorNotFound)

		// Create a VotingPublicKey and VotingAuthorization.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, senderPkBytes)

		// Perform a RegisterAsValidator txn. Error expected.
		registerAsValidatorMetadata := &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte("https://example.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
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

func TestGetTopActiveValidatorsByStakeAmount(t *testing.T) {
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	t.Run("flushToDB=false", func(t *testing.T) {
		_testGetTopActiveValidatorsByStakeAmount(t, false)
	})
	t.Run("flushToDB=true", func(t *testing.T) {
		_testGetTopActiveValidatorsByStakeAmount(t, true)
	})
}

func _testGetTopActiveValidatorsByStakeAmount(t *testing.T, flushToDB bool) {
	var validatorEntries []*ValidatorEntry
	var err error

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize PoS fork height.
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
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

	{
		// ParamUpdater set MinFeeRateNanos.
		params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true
		_updateGlobalParamsEntryWithExtraData(
			testMeta,
			testMeta.feeRateNanosPerKb,
			paramUpdaterPub,
			paramUpdaterPriv,
			map[string][]byte{},
		)
	}
	{
		// m0 registers as a validator.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte("https://m0.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB)
		require.NoError(t, err)

		// Verify top validators is empty since m0's TotalStakeAmountNanos is zero.
		validatorEntries, err = utxoView().GetTopActiveValidatorsByStakeAmount(10)
		require.NoError(t, err)
		require.Empty(t, validatorEntries)
	}
	{
		// m1 registers as a validator.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m1PkBytes)
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte("https://m1.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m1Pub, m1Priv, registerMetadata, nil, flushToDB)
		require.NoError(t, err)

		// Verify top validators is empty since both validators' TotalStakeAmountNanos are zero.
		validatorEntries, err = utxoView().GetTopActiveValidatorsByStakeAmount(10)
		require.NoError(t, err)
		require.Empty(t, validatorEntries)
	}
	{
		// m2 registers as a validator.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m2PkBytes)
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte("https://m2.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m2Pub, m2Priv, registerMetadata, nil, flushToDB)
		require.NoError(t, err)

		// Verify top validators is empty since all three validators' TotalStakeAmountNanos are zero.
		validatorEntries, err = utxoView().GetTopActiveValidatorsByStakeAmount(10)
		require.NoError(t, err)
		require.Empty(t, validatorEntries)
	}
	{
		// m3 stakes 100 DESO nanos with m0.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt(100),
		}
		_, err = _submitStakeTxn(testMeta, m3Pub, m3Priv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// m3 stakes 200 DESO nanos with m1.
		stakeMetadata = &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt(200),
		}
		_, err = _submitStakeTxn(testMeta, m3Pub, m3Priv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// m3 stakes 300 DESO nanos with m2.
		stakeMetadata = &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m2PkBytes),
			StakeAmountNanos:   uint256.NewInt(300),
		}
		_, err = _submitStakeTxn(testMeta, m3Pub, m3Priv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopActiveValidatorsByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 3)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m2PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt(300))
		require.Equal(t, validatorEntries[1].ValidatorPKID, m1PKID)
		require.Equal(t, validatorEntries[1].TotalStakeAmountNanos, uint256.NewInt(200))
		require.Equal(t, validatorEntries[2].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[2].TotalStakeAmountNanos, uint256.NewInt(100))
	}
	{
		// m3 unstakes from m1.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt(150),
		}
		_, err = _submitUnstakeTxn(testMeta, m3Pub, m3Priv, unstakeMetadata, nil, flushToDB)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopActiveValidatorsByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 3)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m2PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt(300))
		require.Equal(t, validatorEntries[1].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[1].TotalStakeAmountNanos, uint256.NewInt(100))
		require.Equal(t, validatorEntries[2].ValidatorPKID, m1PKID)
		require.Equal(t, validatorEntries[2].TotalStakeAmountNanos, uint256.NewInt(50))
	}
	{
		// m3 unstakes more from m1.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt(50),
		}
		_, err = _submitUnstakeTxn(testMeta, m3Pub, m3Priv, unstakeMetadata, nil, flushToDB)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopActiveValidatorsByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 2)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m2PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt(300))
		require.Equal(t, validatorEntries[1].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[1].TotalStakeAmountNanos, uint256.NewInt(100))
	}
	{
		// m2 unregisters as validator.
		_, err = _submitUnregisterAsValidatorTxn(testMeta, m2Pub, m2Priv, flushToDB)
		require.NoError(t, err)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopActiveValidatorsByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 1)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt(100))
	}
	{
		// m4 stakes with m1.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt(150),
		}
		_, err = _submitStakeTxn(testMeta, m4Pub, m4Priv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopActiveValidatorsByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 2)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m1PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt(150))
		require.Equal(t, validatorEntries[1].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[1].TotalStakeAmountNanos, uint256.NewInt(100))
	}
	{
		// m4 stakes more with m1.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt(100),
		}
		_, err = _submitStakeTxn(testMeta, m4Pub, m4Priv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// Verify top validators.
		validatorEntries, err = utxoView().GetTopActiveValidatorsByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 2)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m1PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt(250))
		require.Equal(t, validatorEntries[1].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[1].TotalStakeAmountNanos, uint256.NewInt(100))
	}
	{
		// Verify top validators with LIMIT.
		validatorEntries, err = utxoView().GetTopActiveValidatorsByStakeAmount(1)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 1)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m1PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt(250))
	}

	// Flush mempool to the db and test rollbacks.
	require.NoError(t, mempool.universalUtxoView.FlushToDb(blockHeight))
	_executeAllTestRollbackAndFlush(testMeta)
}

func TestGetTopActiveValidatorsByStakeMergingDbAndUtxoView(t *testing.T) {
	// For this test, we manually place ValidatorEntries in the database and
	// UtxoView to test merging the two to determine the TopValidatorsByStake.

	// Initialize test chain and UtxoView.
	chain, params, db := NewLowDifficultyBlockchain(t)
	utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
	blockHeight := uint64(chain.blockTip().Height + 1)

	// m0 will be stored in the db with Stake=100.
	m0PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m0PkBytes).PKID
	// m1 will be stored in the db with Stake=400 and Status=Jailed.
	m1PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m1PkBytes).PKID
	// m2 will be stored in the db and UtxoView with Stake=300.
	m2PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m2PkBytes).PKID
	// m3 will be stored in the db and UtxoView with Stake=600 and isDeleted=true.
	m3PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m3PkBytes).PKID
	// m4 will be stored in the UtxoView only with Stake=50.
	m4PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m4PkBytes).PKID
	// m5 will be stored in the UtxoView only with Stake=500 and Status=Jailed.
	m5PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m5PkBytes).PKID

	// Store m0's ValidatorEntry in the db with TotalStake = 100 nanos.
	votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
	validatorEntry := &ValidatorEntry{
		ValidatorPKID:         m0PKID,
		TotalStakeAmountNanos: uint256.NewInt(100),
		VotingPublicKey:       votingPublicKey,
		VotingAuthorization:   votingAuthorization,
	}
	utxoView._setValidatorEntryMappings(validatorEntry)
	require.NoError(t, utxoView.FlushToDb(blockHeight))

	// Verify m0 is stored in the db.
	var err error
	validatorEntry, err = DBGetValidatorByPKID(db, chain.snapshot, m0PKID)
	require.NoError(t, err)
	require.NotNil(t, validatorEntry)
	require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt(100))

	// Verify m0 is not stored in the UtxoView.
	require.Empty(t, utxoView.ValidatorPKIDToValidatorEntry)

	// Store m1's jailed ValidatorEntry in the db with TotalStake = 400 nanos.
	votingPublicKey, votingAuthorization = _generateVotingPublicKeyAndAuthorization(t, m1PkBytes)
	validatorEntry = &ValidatorEntry{
		ValidatorPKID:         m1PKID,
		TotalStakeAmountNanos: uint256.NewInt(400),
		VotingPublicKey:       votingPublicKey,
		VotingAuthorization:   votingAuthorization,
		JailedAtEpochNumber:   1,
	}
	utxoView._setValidatorEntryMappings(validatorEntry)
	require.NoError(t, utxoView.FlushToDb(blockHeight))

	// Verify m1 is stored in the db.
	validatorEntry, err = DBGetValidatorByPKID(db, chain.snapshot, m1PKID)
	require.NoError(t, err)
	require.NotNil(t, validatorEntry)
	require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt(400))
	require.Equal(t, validatorEntry.Status(), ValidatorStatusJailed)

	// Store m2's ValidatorEntry in the db with TotalStake = 300 nanos.
	votingPublicKey, votingAuthorization = _generateVotingPublicKeyAndAuthorization(t, m2PkBytes)
	m2ValidatorEntry := &ValidatorEntry{
		ValidatorPKID:         m2PKID,
		TotalStakeAmountNanos: uint256.NewInt(300),
		VotingPublicKey:       votingPublicKey,
		VotingAuthorization:   votingAuthorization,
	}
	utxoView._setValidatorEntryMappings(m2ValidatorEntry)
	require.NoError(t, utxoView.FlushToDb(blockHeight))

	// Verify m2 is stored in the db.
	validatorEntry, err = DBGetValidatorByPKID(db, chain.snapshot, m2PKID)
	require.NoError(t, err)
	require.NotNil(t, validatorEntry)
	require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt(300))

	// Store m3's ValidatorEntry in the db with TotalStake = 600 nanos.
	votingPublicKey, votingAuthorization = _generateVotingPublicKeyAndAuthorization(t, m3PkBytes)
	m3ValidatorEntry := &ValidatorEntry{
		ValidatorPKID:         m3PKID,
		TotalStakeAmountNanos: uint256.NewInt(600),
		VotingPublicKey:       votingPublicKey,
		VotingAuthorization:   votingAuthorization,
	}
	utxoView._setValidatorEntryMappings(m3ValidatorEntry)
	require.NoError(t, utxoView.FlushToDb(blockHeight))

	// Verify m3 is stored in the db.
	validatorEntry, err = DBGetValidatorByPKID(db, chain.snapshot, m3PKID)
	require.NoError(t, err)
	require.NotNil(t, validatorEntry)
	require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt(600))

	// Fetch m2 so it is also cached in the UtxoView.
	validatorEntry, err = utxoView.GetValidatorByPKID(m2PKID)
	require.NoError(t, err)
	require.NotNil(t, validatorEntry)

	// Verify m2 is also stored in the UtxoView.
	require.Len(t, utxoView.ValidatorPKIDToValidatorEntry, 1)
	require.Equal(t, utxoView.ValidatorPKIDToValidatorEntry[*m2ValidatorEntry.ValidatorPKID].ValidatorPKID, m2PKID)
	require.Equal(
		t,
		utxoView.ValidatorPKIDToValidatorEntry[*m2ValidatorEntry.ValidatorPKID].TotalStakeAmountNanos,
		uint256.NewInt(300),
	)

	// Store m3's ValidatorEntry in the UtxoView with isDeleted=true.
	utxoView._deleteValidatorEntryMappings(m3ValidatorEntry)

	// Verify m3 is stored in the UtxoView with isDeleted=true.
	require.Equal(t, utxoView.ValidatorPKIDToValidatorEntry[*m3ValidatorEntry.ValidatorPKID].ValidatorPKID, m3PKID)
	require.True(t, utxoView.ValidatorPKIDToValidatorEntry[*m3ValidatorEntry.ValidatorPKID].isDeleted)

	// Store m4's ValidatorEntry in the UtxoView with TotalStake = 50 nanos.
	votingPublicKey, votingAuthorization = _generateVotingPublicKeyAndAuthorization(t, m4PkBytes)
	m4ValidatorEntry := &ValidatorEntry{
		ValidatorPKID:         m4PKID,
		TotalStakeAmountNanos: uint256.NewInt(50),
		VotingPublicKey:       votingPublicKey,
		VotingAuthorization:   votingAuthorization,
	}
	utxoView._setValidatorEntryMappings(m4ValidatorEntry)

	// Verify m4 is not stored in the db.
	validatorEntry, err = DBGetValidatorByPKID(db, chain.snapshot, m4PKID)
	require.NoError(t, err)
	require.Nil(t, validatorEntry)

	// Verify m4 is stored in the UtxoView.
	require.Len(t, utxoView.ValidatorPKIDToValidatorEntry, 3)
	require.Equal(t, utxoView.ValidatorPKIDToValidatorEntry[*m4ValidatorEntry.ValidatorPKID].ValidatorPKID, m4PKID)
	require.Equal(
		t,
		utxoView.ValidatorPKIDToValidatorEntry[*m4ValidatorEntry.ValidatorPKID].TotalStakeAmountNanos,
		uint256.NewInt(50),
	)

	// Store m5's jailed ValidatorEntry in the UtxoView with TotalStake = 500 nanos.
	votingPublicKey, votingAuthorization = _generateVotingPublicKeyAndAuthorization(t, m5PkBytes)
	m5ValidatorEntry := &ValidatorEntry{
		ValidatorPKID:         m5PKID,
		TotalStakeAmountNanos: uint256.NewInt(500),
		VotingPublicKey:       votingPublicKey,
		VotingAuthorization:   votingAuthorization,
		JailedAtEpochNumber:   1,
	}
	utxoView._setValidatorEntryMappings(m5ValidatorEntry)

	// Verify m5 is not stored in the db.
	validatorEntry, err = DBGetValidatorByPKID(db, chain.snapshot, m5PKID)
	require.NoError(t, err)
	require.Nil(t, validatorEntry)

	// Verify m5 is stored in the UtxoView.
	require.Len(t, utxoView.ValidatorPKIDToValidatorEntry, 4)
	require.Equal(t, utxoView.ValidatorPKIDToValidatorEntry[*m5ValidatorEntry.ValidatorPKID].ValidatorPKID, m5PKID)
	require.Equal(
		t,
		utxoView.ValidatorPKIDToValidatorEntry[*m5ValidatorEntry.ValidatorPKID].TotalStakeAmountNanos,
		uint256.NewInt(500),
	)
	require.Equal(
		t, utxoView.ValidatorPKIDToValidatorEntry[*m5ValidatorEntry.ValidatorPKID].Status(), ValidatorStatusJailed,
	)

	// Fetch TopActiveValidatorsByStake merging ValidatorEntries from the db and UtxoView.
	validatorEntries, err := utxoView.GetTopActiveValidatorsByStakeAmount(6)
	require.NoError(t, err)
	require.Len(t, validatorEntries, 3)
	require.Equal(t, validatorEntries[0].ValidatorPKID, m2PKID)
	require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt(300))
	require.Equal(t, validatorEntries[1].ValidatorPKID, m0PKID)
	require.Equal(t, validatorEntries[1].TotalStakeAmountNanos, uint256.NewInt(100))
	require.Equal(t, validatorEntries[2].ValidatorPKID, m4PKID)
	require.Equal(t, validatorEntries[2].TotalStakeAmountNanos, uint256.NewInt(50))
}

func TestUpdatingValidatorDisableDelegatedStake(t *testing.T) {
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	t.Run("flushToDB=false", func(t *testing.T) {
		_testUpdatingValidatorDisableDelegatedStake(t, false)
	})
	t.Run("flushToDB=true", func(t *testing.T) {
		_testUpdatingValidatorDisableDelegatedStake(t, true)
	})
}

func _testUpdatingValidatorDisableDelegatedStake(t *testing.T, flushToDB bool) {
	var validatorEntry *ValidatorEntry
	var stakeEntries []*StakeEntry
	var err error

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize PoS fork height.
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 1e3)

	m0PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m0PkBytes).PKID

	{
		// ParamUpdater set MinFeeRateNanos.
		params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true
		_updateGlobalParamsEntryWithExtraData(
			testMeta,
			testMeta.feeRateNanosPerKb,
			paramUpdaterPub,
			paramUpdaterPriv,
			map[string][]byte{},
		)
	}
	{
		// m0 registers as a validator with DisableDelegatedStake = FALSE.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("https://m0.com")},
			DisableDelegatedStake: false,
			VotingPublicKey:       votingPublicKey,
			VotingAuthorization:   votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB)
		require.NoError(t, err)

		validatorEntry, err = utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.False(t, validatorEntry.DisableDelegatedStake)

		stakeEntries, err = utxoView().GetStakeEntriesForValidatorPKID(m0PKID)
		require.NoError(t, err)
		require.Empty(t, stakeEntries)
	}
	{
		// m0 updates DisableDelegatedStake = TRUE.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("https://m0.com")},
			DisableDelegatedStake: true,
			VotingPublicKey:       votingPublicKey,
			VotingAuthorization:   votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB)
		require.NoError(t, err)

		validatorEntry, err = utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.True(t, validatorEntry.DisableDelegatedStake)
	}
	{
		// m0 stakes with himself. This is allowed even though DisableDelegatedStake = TRUE.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt(100),
		}
		_, err = _submitStakeTxn(
			testMeta, m0Pub, m0Priv, stakeMetadata, nil, flushToDB,
		)
		require.NoError(t, err)

		stakeEntries, err = utxoView().GetStakeEntriesForValidatorPKID(m0PKID)
		require.NoError(t, err)
		require.Len(t, stakeEntries, 1)
		require.Equal(t, stakeEntries[0].StakerPKID, m0PKID)
	}
	{
		// m1 tries to stake with m0. Errors.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt(100),
		}
		_, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidStakeValidatorDisabledDelegatedStake)
	}
	{
		// m0 updates DisableDelegatedStake = FALSE.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("https://m0.com")},
			DisableDelegatedStake: false,
			VotingPublicKey:       votingPublicKey,
			VotingAuthorization:   votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB)
		require.NoError(t, err)

		validatorEntry, err = utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.False(t, validatorEntry.DisableDelegatedStake)
	}
	{
		// m1 stakes with m0. Succeeds.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt(100),
		}
		_, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.NoError(t, err)

		stakeEntries, err = utxoView().GetStakeEntriesForValidatorPKID(m0PKID)
		require.NoError(t, err)
		require.Len(t, stakeEntries, 2)
	}
	{
		// m0 tries to update DisableDelegateStake = TRUE. Errors.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains:               [][]byte{[]byte("https://m0.com")},
			DisableDelegatedStake: true,
			VotingPublicKey:       votingPublicKey,
			VotingAuthorization:   votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorDisablingExistingDelegatedStakers)
	}

	// Flush mempool to the db and test rollbacks.
	require.NoError(t, mempool.universalUtxoView.FlushToDb(blockHeight))
	_executeAllTestRollbackAndFlush(testMeta)
}

func TestUnregisterAsValidator(t *testing.T) {
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	t.Run("flushToDB=false", func(t *testing.T) {
		_testUnregisterAsValidator(t, false)
	})
	t.Run("flushToDB=true", func(t *testing.T) {
		_testUnregisterAsValidator(t, true)
	})
}

func _testUnregisterAsValidator(t *testing.T, flushToDB bool) {
	var validatorEntry *ValidatorEntry
	var stakeEntry *StakeEntry
	var lockedStakeEntry *LockedStakeEntry
	_ = lockedStakeEntry
	var err error

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize PoS fork height.
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 1e3)

	m0PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m0PkBytes).PKID
	m1PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m1PkBytes).PKID

	currentEpochNumber, err := utxoView().GetCurrentEpochNumber()
	require.NoError(t, err)

	{
		// ParamUpdater set MinFeeRateNanos.
		params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true
		_updateGlobalParamsEntryWithExtraData(
			testMeta,
			testMeta.feeRateNanosPerKb,
			paramUpdaterPub,
			paramUpdaterPriv,
			map[string][]byte{},
		)
	}
	{
		// m0 registers as a validator.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte("https://m0.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB)
		require.NoError(t, err)

		validatorEntry, err = utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
	}
	{
		// m0 stakes with himself.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt(600),
		}
		_, err = _submitStakeTxn(
			testMeta, m0Pub, m0Priv, stakeMetadata, nil, flushToDB,
		)
		require.NoError(t, err)

		stakeEntry, err = utxoView().GetStakeEntry(m0PKID, m0PKID)
		require.NoError(t, err)
		require.NotNil(t, stakeEntry)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt(600))
	}
	{
		// m1 stakes with m0.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt(400),
		}
		_, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.NoError(t, err)

		stakeEntry, err = utxoView().GetStakeEntry(m0PKID, m1PKID)
		require.NoError(t, err)
		require.NotNil(t, stakeEntry)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt(400))
	}
	{
		// m1 partially unstakes with m0.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt(100),
		}
		_, err = _submitUnstakeTxn(
			testMeta, m1Pub, m1Priv, unstakeMetadata, nil, flushToDB,
		)

		// m1's StakeEntry is updated.
		stakeEntry, err = utxoView().GetStakeEntry(m0PKID, m1PKID)
		require.NoError(t, err)
		require.NotNil(t, stakeEntry)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt(300))

		// m1 has a LockedStakeEntry created.
		lockedStakeEntry, err = utxoView().GetLockedStakeEntry(m0PKID, m1PKID, currentEpochNumber)
		require.NoError(t, err)
		require.NotNil(t, lockedStakeEntry)
		require.Equal(t, lockedStakeEntry.LockedAmountNanos, uint256.NewInt(100))
	}
	{
		// m0 unregisters as a validator.
		_, err = _submitUnregisterAsValidatorTxn(testMeta, m0Pub, m0Priv, flushToDB)
		require.NoError(t, err)

		// m0's ValidatorEntry is deleted.
		validatorEntry, err = utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Nil(t, validatorEntry)

		// m0 is unstaked.
		// m0's StakeEntry is deleted.
		stakeEntry, err = utxoView().GetStakeEntry(m0PKID, m0PKID)
		require.NoError(t, err)
		require.Nil(t, stakeEntry)
		// m0's has a LockedStakeEntry created.
		lockedStakeEntry, err = utxoView().GetLockedStakeEntry(m0PKID, m0PKID, currentEpochNumber)
		require.NoError(t, err)
		require.NotNil(t, lockedStakeEntry)
		require.Equal(t, lockedStakeEntry.LockedAmountNanos, uint256.NewInt(600))

		// m1 is unstaked.
		// m1's StakeEntry is deleted.
		stakeEntry, err = utxoView().GetStakeEntry(m0PKID, m1PKID)
		require.NoError(t, err)
		require.Nil(t, stakeEntry)
		// m1's LockedStakeEntry is updated.
		lockedStakeEntry, err = utxoView().GetLockedStakeEntry(m0PKID, m1PKID, currentEpochNumber)
		require.NoError(t, err)
		require.NotNil(t, lockedStakeEntry)
		require.Equal(t, lockedStakeEntry.LockedAmountNanos, uint256.NewInt(400))
	}

	// Flush mempool to the db and test rollbacks.
	require.NoError(t, mempool.universalUtxoView.FlushToDb(blockHeight))
	_executeAllTestRollbackAndFlush(testMeta)
}

func TestUnjailValidator(t *testing.T) {
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	t.Run("flushToDB=false", func(t *testing.T) {
		_testUnjailValidator(t, false)
	})
	t.Run("flushToDB=true", func(t *testing.T) {
		_testUnjailValidator(t, true)
	})
}

func _testUnjailValidator(t *testing.T, flushToDB bool) {
	var validatorEntry *ValidatorEntry
	var err error

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize PoS fork height.
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	chain.snapshot = nil

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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 1e3)

	m0PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m0PkBytes).PKID
	m1PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m1PkBytes).PKID

	// Seed a CurrentEpochEntry.
	epochUtxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
	epochUtxoView._setCurrentEpochEntry(&EpochEntry{EpochNumber: 1, FinalBlockHeight: blockHeight + 10})
	require.NoError(t, epochUtxoView.FlushToDb(blockHeight))
	currentEpochNumber, err := utxoView().GetCurrentEpochNumber()
	require.NoError(t, err)

	{
		// ParamUpdater set MinFeeRateNanos and ValidatorJailEpochDuration=3.
		params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true
		_updateGlobalParamsEntryWithExtraData(
			testMeta,
			testMeta.feeRateNanosPerKb,
			paramUpdaterPub,
			paramUpdaterPriv,
			map[string][]byte{ValidatorJailEpochDurationKey: UintToBuf(3)},
		)
	}
	{
		// m0 registers as a validator.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte("https://example.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		extraData := map[string][]byte{"TestKey": []byte("TestValue1")}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, extraData, flushToDB)
		require.NoError(t, err)

		validatorEntry, err = utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.ExtraData["TestKey"], []byte("TestValue1"))
	}
	{
		// RuleErrorUnjailingNonjailedValidator
		_, err = _submitUnjailValidatorTxn(testMeta, m0Pub, m0Priv, nil, flushToDB)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorUnjailingNonjailedValidator)
	}
	{
		// m0 is jailed. Since this update takes place outside a transaction,
		// we cannot test rollbacks. We will run into an error where m0 is
		// trying to unjail himself, but he was never jailed.

		// Jail m0.
		tmpUtxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
		require.NoError(t, tmpUtxoView.JailValidator(validatorEntry))
		require.NoError(t, tmpUtxoView.FlushToDb(blockHeight))

		// Delete m0's ValidatorEntry from the UtxoView so that it is read from the db.
		delete(mempool.universalUtxoView.ValidatorPKIDToValidatorEntry, *validatorEntry.ValidatorPKID)
		delete(mempool.readOnlyUtxoView.ValidatorPKIDToValidatorEntry, *validatorEntry.ValidatorPKID)

		// Verify m0 is jailed.
		validatorEntry, err = utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.Status(), ValidatorStatusJailed)
	}
	{
		// m1 stakes with m0. Succeeds. You can stake to a jailed validator.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt(100),
		}
		_, err = _submitStakeTxn(testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		stakeEntry, err := utxoView().GetStakeEntry(m0PKID, m1PKID)
		require.NoError(t, err)
		require.NotNil(t, stakeEntry)
	}
	{
		// m1 unstakes from m0. Succeeds. You can unstake from a jailed validator.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt(100),
		}
		_, err = _submitUnstakeTxn(testMeta, m1Pub, m1Priv, unstakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		stakeEntry, err := utxoView().GetStakeEntry(m0PKID, m1PKID)
		require.NoError(t, err)
		require.Nil(t, stakeEntry)

		lockedStakeEntry, err := utxoView().GetLockedStakeEntry(m0PKID, m1PKID, currentEpochNumber)
		require.NoError(t, err)
		require.NotNil(t, lockedStakeEntry)
	}
	{
		// RuleErrorValidatorNotFound
		_, err = _submitUnjailValidatorTxn(testMeta, m1Pub, m1Priv, nil, flushToDB)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorValidatorNotFound)
	}
	{
		// RuleErrorUnjailingValidatorTooEarly
		_, err = _submitUnjailValidatorTxn(testMeta, m0Pub, m0Priv, nil, flushToDB)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorUnjailingValidatorTooEarly)
	}
	{
		// Simulate three epochs passing by seeding a new CurrentEpochEntry.

		// Delete the CurrentEpochEntry from the UtxoView.
		mempool.universalUtxoView.CurrentEpochEntry = nil
		mempool.readOnlyUtxoView.CurrentEpochEntry = nil

		// Store a new CurrentEpochEntry in the db.
		epochUtxoView = NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
		epochUtxoView._setCurrentEpochEntry(
			&EpochEntry{EpochNumber: currentEpochNumber + 3, FinalBlockHeight: blockHeight + 10},
		)

		// Store a SnapshotGlobalParamsEntry in the db.
		epochUtxoView._setSnapshotGlobalParamsEntry(&GlobalParamsEntry{}, currentEpochNumber+1)
		require.NoError(t, epochUtxoView.FlushToDb(blockHeight))

		// Verify CurrentEpochNumber.
		currentEpochNumber, err = utxoView().GetCurrentEpochNumber()
		require.NoError(t, err)
		require.Equal(t, currentEpochNumber, uint64(4))
	}
	{
		// RuleErrorProofofStakeTxnBeforeBlockHeight
		params.ForkHeights.ProofOfStake1StateSetupBlockHeight = math.MaxUint32
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

		_, err = _submitUnjailValidatorTxn(testMeta, m0Pub, m0Priv, nil, flushToDB)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorProofofStakeTxnBeforeBlockHeight)

		params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	}
	{
		// m0 unjails himself.
		validatorEntry, err = utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.Status(), ValidatorStatusJailed)
		require.Equal(t, validatorEntry.LastActiveAtEpochNumber, uint64(1))

		extraData := map[string][]byte{"TestKey": []byte("TestValue2")}
		_, err = _submitUnjailValidatorTxn(testMeta, m0Pub, m0Priv, extraData, flushToDB)
		require.NoError(t, err)

		validatorEntry, err = utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.Status(), ValidatorStatusActive)
		require.Equal(t, validatorEntry.LastActiveAtEpochNumber, uint64(4))
		require.Equal(t, validatorEntry.ExtraData["TestKey"], []byte("TestValue2"))
	}
}

func TestUnjailValidatorWithDerivedKey(t *testing.T) {
	var validatorEntry *ValidatorEntry
	var derivedKeyPriv string
	var err error

	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize PoS fork height.
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
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
	senderPrivKey, _ := btcec.PrivKeyFromBytes(senderPrivBytes)
	senderPKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, senderPkBytes).PKID

	newUtxoView := func() *UtxoView {
		utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
		return utxoView
	}

	_submitAuthorizeDerivedKeyUnjailValidatorTxn := func(count uint64) (string, error) {
		utxoView := newUtxoView()

		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
				TxnTypeUnjailValidator:     count,
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

	_submitUnjailValidatorTxnWithDerivedKey := func(transactorPkBytes []byte, derivedKeyPrivBase58Check string) error {
		utxoView := newUtxoView()
		// Construct txn.
		txn, _, _, _, err := testMeta.chain.CreateUnjailValidatorTxn(
			transactorPkBytes,
			&UnjailValidatorMetadata{},
			make(map[string][]byte),
			testMeta.feeRateNanosPerKb,
			mempool,
			[]*DeSoOutput{},
		)
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
			txn, txn.Hash(), testMeta.savedHeight, 0, true, false)
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

	// Seed a CurrentEpochEntry.
	epochUtxoView := newUtxoView()
	epochUtxoView._setCurrentEpochEntry(&EpochEntry{EpochNumber: 1, FinalBlockHeight: blockHeight + 10})
	require.NoError(t, epochUtxoView.FlushToDb(blockHeight))
	currentEpochNumber, err := newUtxoView().GetCurrentEpochNumber()
	require.NoError(t, err)

	{
		// ParamUpdater set MinFeeRateNanos.
		params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true
		_updateGlobalParamsEntryWithExtraData(
			testMeta,
			testMeta.feeRateNanosPerKb,
			paramUpdaterPub,
			paramUpdaterPriv,
			map[string][]byte{},
		)
	}
	{
		// sender registers as a validator.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, senderPkBytes)
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte("https://example.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, senderPkString, senderPrivString, registerMetadata, nil, true)
		require.NoError(t, err)

		validatorEntry, err = newUtxoView().GetValidatorByPKID(senderPKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
	}
	{
		// sender is jailed. Since this update takes place outside a transaction,
		// we cannot test rollbacks. We will run into an error where sender is
		// trying to unjail himself, but he was never jailed.

		// Jail the sender.
		tmpUtxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
		require.NoError(t, tmpUtxoView.JailValidator(validatorEntry))
		require.NoError(t, tmpUtxoView.FlushToDb(blockHeight))

		// Delete sender's ValidatorEntry from the UtxoView so that it is read from the db.
		delete(mempool.universalUtxoView.ValidatorPKIDToValidatorEntry, *validatorEntry.ValidatorPKID)
		delete(mempool.readOnlyUtxoView.ValidatorPKIDToValidatorEntry, *validatorEntry.ValidatorPKID)

		// Verify sender is jailed.
		validatorEntry, err = newUtxoView().GetValidatorByPKID(senderPKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.Status(), ValidatorStatusJailed)
	}
	{
		// sender creates a DerivedKey that can perform one UnjailValidator txn.
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyUnjailValidatorTxn(1)
		require.NoError(t, err)
	}
	{
		// RuleErrorUnjailingValidatorTooEarly
		err = _submitUnjailValidatorTxnWithDerivedKey(senderPkBytes, derivedKeyPriv)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorUnjailingValidatorTooEarly)
	}
	{
		// Simulate three epochs passing by seeding a new CurrentEpochEntry.

		// Delete the CurrentEpochEntry from the UtxoView.
		mempool.universalUtxoView.CurrentEpochEntry = nil
		mempool.readOnlyUtxoView.CurrentEpochEntry = nil

		// Store a new CurrentEpochEntry in the db.
		epochUtxoView = NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
		epochUtxoView._setCurrentEpochEntry(
			&EpochEntry{EpochNumber: currentEpochNumber + 3, FinalBlockHeight: blockHeight + 10},
		)

		// Store a SnapshotGlobalParamsEntry in the db.
		epochUtxoView._setSnapshotGlobalParamsEntry(&GlobalParamsEntry{}, currentEpochNumber+1)
		require.NoError(t, epochUtxoView.FlushToDb(blockHeight))

		// Verify CurrentEpochNumber.
		currentEpochNumber, err = newUtxoView().GetCurrentEpochNumber()
		require.NoError(t, err)
		require.Equal(t, currentEpochNumber, uint64(4))
	}
	{
		// sender unjails himself using a DerivedKey.
		validatorEntry, err = newUtxoView().GetValidatorByPKID(senderPKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.Status(), ValidatorStatusJailed)
		require.Equal(t, validatorEntry.LastActiveAtEpochNumber, uint64(1))

		err = _submitUnjailValidatorTxnWithDerivedKey(senderPkBytes, derivedKeyPriv)
		require.NoError(t, err)

		validatorEntry, err = newUtxoView().GetValidatorByPKID(senderPKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.Status(), ValidatorStatusActive)
		require.Equal(t, validatorEntry.LastActiveAtEpochNumber, uint64(4))
	}
}

func _submitUnjailValidatorTxn(
	testMeta *TestMeta,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	extraData map[string][]byte,
	flushToDB bool,
) (_fees uint64, _err error) {
	// Record transactor's prevBalance.
	prevBalance := _getBalance(testMeta.t, testMeta.chain, testMeta.mempool, transactorPublicKeyBase58Check)

	// Convert PublicKeyBase58Check to PkBytes.
	updaterPkBytes, _, err := Base58CheckDecode(transactorPublicKeyBase58Check)
	require.NoError(testMeta.t, err)

	// Create the transaction.
	txn, totalInputMake, changeAmountMake, feesMake, err := testMeta.chain.CreateUnjailValidatorTxn(
		updaterPkBytes,
		&UnjailValidatorMetadata{},
		extraData,
		testMeta.feeRateNanosPerKb,
		testMeta.mempool,
		[]*DeSoOutput{},
	)
	if err != nil {
		return 0, err
	}
	require.Equal(testMeta.t, totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(testMeta.t, txn, transactorPrivateKeyBase58Check)

	// Connect the transaction.
	utxoOps, totalInput, totalOutput, fees, err := testMeta.mempool.universalUtxoView.ConnectTransaction(
		txn, txn.Hash(), testMeta.savedHeight, 0, true, false)
	if err != nil {
		return 0, err
	}
	require.Equal(testMeta.t, totalInput, totalOutput+fees)
	require.Equal(testMeta.t, totalInput, totalInputMake)
	require.Equal(testMeta.t, OperationTypeUnjailValidator, utxoOps[len(utxoOps)-1].Type)
	if flushToDB {
		require.NoError(testMeta.t, testMeta.mempool.universalUtxoView.FlushToDb(uint64(testMeta.savedHeight)))
	}
	require.NoError(testMeta.t, testMeta.mempool.RegenerateReadOnlyView())

	// Record the txn.
	testMeta.expectedSenderBalances = append(testMeta.expectedSenderBalances, prevBalance)
	testMeta.txnOps = append(testMeta.txnOps, utxoOps)
	testMeta.txns = append(testMeta.txns, txn)
	return fees, nil
}

func _generateVotingPublicKeyAndAuthorization(t *testing.T, transactorPkBytes []byte) (*bls.PublicKey, *bls.Signature) {
	blsPrivateKey, err := bls.NewPrivateKey()
	require.NoError(t, err)
	votingPublicKey := blsPrivateKey.PublicKey()
	votingAuthorizationPayload := CreateValidatorVotingAuthorizationPayload(transactorPkBytes)
	votingAuthorization, err := blsPrivateKey.Sign(votingAuthorizationPayload)
	require.NoError(t, err)
	return votingPublicKey, votingAuthorization
}

func _generateVotingPrivateKeyPublicKeyAndAuthorization(t *testing.T, transactorPkBytes []byte) (*bls.PrivateKey, *bls.PublicKey, *bls.Signature) {
	blsPrivateKey, err := bls.NewPrivateKey()
	require.NoError(t, err)
	votingPublicKey := blsPrivateKey.PublicKey()
	votingAuthorizationPayload := CreateValidatorVotingAuthorizationPayload(transactorPkBytes)
	votingAuthorization, err := blsPrivateKey.Sign(votingAuthorizationPayload)
	require.NoError(t, err)
	return blsPrivateKey, votingPublicKey, votingAuthorization
}
