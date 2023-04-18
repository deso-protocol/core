package lib

import (
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestStaking(t *testing.T) {
	_testStaking(t, false)
	_testStaking(t, true)
}

func _testStaking(t *testing.T, flushToDB bool) {
	// Local variables
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
		// m0 registers as a validator.
		params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = uint32(1)
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

		registerAsValidatorMetadata := &RegisterAsValidatorMetadata{
			Domains: [][]byte{[]byte("https://example.com")},
		}
		_, _, _, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerAsValidatorMetadata, nil, flushToDB,
		)
		require.NoError(t, err)

		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Len(t, validatorEntry.Domains, 1)
		require.Equal(t, validatorEntry.Domains[0], []byte("https://example.com"))
		require.True(t, validatorEntry.TotalStakeAmountNanos.IsZero())
	}
	//
	// STAKING
	//
	{
		// RuleErrorProofOfStakeTxnBeforeBlockHeight
		params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = math.MaxUint32
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(100),
		}
		_, _, _, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorProofofStakeTxnBeforeBlockHeight)

		params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = uint32(1)
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	}
	{
		// RuleErrorInvalidValidatorPKID
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m2PkBytes),
			StakeAmountNanos:   uint256.NewInt(),
		}
		_, _, _, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidValidatorPKID)
	}
	{
		// RuleErrorInvalidStakeAmountNanos
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt(),
		}
		_, _, _, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidStakeAmountNanos)
	}
	{
		// RuleErrorInvalidStakeInsufficientBalance
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   MaxUint256,
		}
		_, _, _, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidStakeInsufficientBalance)
	}
	{
		// m1 stakes with m0.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(100),
		}
		extraData := map[string][]byte{"TestKey": []byte("TestValue")}
		_, _, _, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, extraData, flushToDB,
		)
		require.NoError(t, err)

		// Verify StakeEntry.StakeAmountNanos.
		stakeEntry, err := utxoView().GetStakeEntry(m0PKID, m1PKID)
		require.NoError(t, err)
		require.NotNil(t, stakeEntry)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt().SetUint64(100))
		require.Equal(t, stakeEntry.ExtraData["TestKey"], []byte("TestValue"))

		// Verify ValidatorEntry.TotalStakeAmountNanos.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))

		// Verify GlobalStakeAmountNanos.
		globalStakeAmountNanos, err := utxoView().GetGlobalStakeAmountNanos()
		require.NoError(t, err)
		require.Equal(t, globalStakeAmountNanos, uint256.NewInt().SetUint64(100))

		// TODO: Verify m1's DESO balance decreases.
	}
	{
		// m1 stakes more with m0.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(50),
		}
		extraData := map[string][]byte{"TestKey": []byte("TestValue2")}
		_, _, _, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, extraData, flushToDB,
		)
		require.NoError(t, err)

		// Verify StakeEntry.StakeAmountNanos.
		stakeEntry, err := utxoView().GetStakeEntry(m0PKID, m1PKID)
		require.NoError(t, err)
		require.NotNil(t, stakeEntry)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt().SetUint64(150))
		require.Equal(t, stakeEntry.ExtraData["TestKey"], []byte("TestValue2"))

		// Verify ValidatorEntry.TotalStakeAmountNanos.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(150))

		// Verify GlobalStakeAmountNanos.
		globalStakeAmountNanos, err := utxoView().GetGlobalStakeAmountNanos()
		require.NoError(t, err)
		require.Equal(t, globalStakeAmountNanos, uint256.NewInt().SetUint64(150))

		// TODO: Verify m1's DESO balance decreases.
	}
	//
	// UNSTAKING
	//
	{
		// RuleErrorProofOfStakeTxnBeforeBlockHeight
		params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = math.MaxUint32
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(40),
		}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, m1Pub, m1Priv, unstakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorProofofStakeTxnBeforeBlockHeight)

		params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = uint32(1)
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	}
	{
		// RuleErrorInvalidValidatorPKID
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m2PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(40),
		}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, m1Pub, m1Priv, unstakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidValidatorPKID)
	}
	{
		// RuleErrorInvalidUnstakeNoStakeFound
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(40),
		}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, m2Pub, m2Priv, unstakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnstakeNoStakeFound)
	}
	{
		// RuleErrorInvalidUnstakeAmountNanos
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt(),
		}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, m1Pub, m1Priv, unstakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnstakeAmountNanos)
	}
	{
		// RuleErrorInvalidUnstakeInsufficientStakeFound
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: MaxUint256,
		}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, m1Pub, m1Priv, unstakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnstakeInsufficientStakeFound)
	}
	{
		// m1 unstakes from m0.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(40),
		}
		extraData := map[string][]byte{"TestKey": []byte("TestValue")}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, m1Pub, m1Priv, unstakeMetadata, extraData, flushToDB,
		)
		require.NoError(t, err)

		// Verify StakeEntry.StakeAmountNanos.
		stakeEntry, err := utxoView().GetStakeEntry(m0PKID, m1PKID)
		require.NoError(t, err)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt().SetUint64(110))

		// Verify ValidatorEntry.TotalStakeAmountNanos.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(110))

		// Verify GlobalStakeAmountNanos.
		globalStakeAmountNanos, err := utxoView().GetGlobalStakeAmountNanos()
		require.NoError(t, err)
		require.Equal(t, globalStakeAmountNanos, uint256.NewInt().SetUint64(110))

		// Verify LockedStakeEntry.UnstakeAmountNanos.
		currentEpochNumber := uint64(0) // TODO: set this
		lockedStakeEntry, err := utxoView().GetLockedStakeEntry(m0PKID, m1PKID, currentEpochNumber)
		require.NoError(t, err)
		require.Equal(t, lockedStakeEntry.LockedAmountNanos, uint256.NewInt().SetUint64(40))
		require.Equal(t, lockedStakeEntry.ExtraData["TestKey"], []byte("TestValue"))
	}
	{
		// m1 unstakes more from m0.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(30),
		}
		extraData := map[string][]byte{"TestKey": []byte("TestValue2")}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, m1Pub, m1Priv, unstakeMetadata, extraData, flushToDB,
		)
		require.NoError(t, err)

		// Verify StakeEntry.StakeAmountNanos.
		stakeEntry, err := utxoView().GetStakeEntry(m0PKID, m1PKID)
		require.NoError(t, err)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt().SetUint64(80))

		// Verify ValidatorEntry.TotalStakeAmountNanos.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(80))

		// Verify GlobalStakeAmountNanos.
		globalStakeAmountNanos, err := utxoView().GetGlobalStakeAmountNanos()
		require.NoError(t, err)
		require.Equal(t, globalStakeAmountNanos, uint256.NewInt().SetUint64(80))

		// Verify LockedStakeEntry.UnstakeAmountNanos.
		currentEpochNumber := uint64(0) // TODO: set this
		lockedStakeEntry, err := utxoView().GetLockedStakeEntry(m0PKID, m1PKID, currentEpochNumber)
		require.NoError(t, err)
		require.Equal(t, lockedStakeEntry.LockedAmountNanos, uint256.NewInt().SetUint64(70))
		require.Equal(t, lockedStakeEntry.ExtraData["TestKey"], []byte("TestValue2"))
	}
	{
		// m1 unstakes the rest of their stake with m0.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(80),
		}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, m1Pub, m1Priv, unstakeMetadata, nil, flushToDB,
		)
		require.NoError(t, err)

		// Verify StakeEntry.isDeleted.
		stakeEntry, err := utxoView().GetStakeEntry(m0PKID, m1PKID)
		require.NoError(t, err)
		require.Nil(t, stakeEntry)

		// Verify ValidatorEntry.TotalStakeAmountNanos.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt())

		// Verify GlobalStakeAmountNanos.
		globalStakeAmountNanos, err := utxoView().GetGlobalStakeAmountNanos()
		require.NoError(t, err)
		require.Equal(t, globalStakeAmountNanos, uint256.NewInt())

		// Verify LockedStakeEntry.UnstakeAmountNanos.
		currentEpochNumber := uint64(0) // TODO: set this
		lockedStakeEntry, err := utxoView().GetLockedStakeEntry(m0PKID, m1PKID, currentEpochNumber)
		require.NoError(t, err)
		require.Equal(t, lockedStakeEntry.LockedAmountNanos, uint256.NewInt().SetUint64(150))
		require.Equal(t, lockedStakeEntry.ExtraData["TestKey"], []byte("TestValue2"))
	}
	//
	// UNLOCK STAKE
	//
	{
		// RuleErrorProofOfStakeTxnBeforeBlockHeight
		params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = math.MaxUint32
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   0,
			EndEpochNumber:     0,
		}
		_, _, _, err = _submitUnlockStakeTxn(
			testMeta, m1Pub, m1Priv, unlockStakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorProofofStakeTxnBeforeBlockHeight)

		params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = uint32(1)
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	}
	{
		// RuleErrorInvalidValidatorPKID
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m2PkBytes),
			StartEpochNumber:   0,
			EndEpochNumber:     0,
		}
		_, _, _, err = _submitUnlockStakeTxn(
			testMeta, m1Pub, m1Priv, unlockStakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidValidatorPKID)
	}
	{
		// RuleErrorInvalidUnlockStakeEpochRange
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   1,
			EndEpochNumber:     0,
		}
		_, _, _, err = _submitUnlockStakeTxn(
			testMeta, m1Pub, m1Priv, unlockStakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnlockStakeEpochRange)
	}
	{
		// m1 unlocks stake that was assigned to m0.
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   0,
			EndEpochNumber:     0,
		}
		_, _, _, err = _submitUnlockStakeTxn(
			testMeta, m1Pub, m1Priv, unlockStakeMetadata, nil, flushToDB,
		)
		require.NoError(t, err)

		// Verify StakeEntry.isDeleted.
		stakeEntry, err := utxoView().GetStakeEntry(m0PKID, m1PKID)
		require.NoError(t, err)
		require.Nil(t, stakeEntry)

		// Verify ValidatorEntry.TotalStakeAmountNanos.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt())

		// Verify GlobalStakeAmountNanos.
		globalStakeAmountNanos, err := utxoView().GetGlobalStakeAmountNanos()
		require.NoError(t, err)
		require.Equal(t, globalStakeAmountNanos, uint256.NewInt())

		// Verify LockedStakeEntry.isDeleted.
		currentEpochNumber := uint64(0) // TODO: set this
		lockedStakeEntry, err := utxoView().GetLockedStakeEntry(m0PKID, m1PKID, currentEpochNumber)
		require.NoError(t, err)
		require.Nil(t, lockedStakeEntry)

		// TODO: Verify m1's DESO balance increases.
	}
	{
		// RuleErrorInvalidUnlockStakeNoUnlockableStakeFound
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   0,
			EndEpochNumber:     0,
		}
		_, _, _, err = _submitUnlockStakeTxn(
			testMeta, m1Pub, m1Priv, unlockStakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnlockStakeNoUnlockableStakeFound)
	}

	// Flush mempool to the db and test rollbacks.
	require.NoError(t, mempool.universalUtxoView.FlushToDb(blockHeight))
	_executeAllTestRollbackAndFlush(testMeta)
}

func _submitStakeTxn(
	testMeta *TestMeta,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	metadata *StakeMetadata,
	extraData map[string][]byte,
	flushToDB bool,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	// Record transactor's prevBalance.
	prevBalance := _getBalance(testMeta.t, testMeta.chain, testMeta.mempool, transactorPublicKeyBase58Check)

	// Convert PublicKeyBase58Check to PkBytes.
	updaterPkBytes, _, err := Base58CheckDecode(transactorPublicKeyBase58Check)
	require.NoError(testMeta.t, err)

	// Create the transaction.
	txn, totalInputMake, changeAmountMake, feesMake, err := testMeta.chain.CreateStakeTxn(
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
	require.Equal(testMeta.t, OperationTypeStake, utxoOps[len(utxoOps)-1].Type)
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

func _submitUnstakeTxn(
	testMeta *TestMeta,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	metadata *UnstakeMetadata,
	extraData map[string][]byte,
	flushToDB bool,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	// Record transactor's prevBalance.
	prevBalance := _getBalance(testMeta.t, testMeta.chain, testMeta.mempool, transactorPublicKeyBase58Check)

	// Convert PublicKeyBase58Check to PkBytes.
	updaterPkBytes, _, err := Base58CheckDecode(transactorPublicKeyBase58Check)
	require.NoError(testMeta.t, err)

	// Create the transaction.
	txn, totalInputMake, changeAmountMake, feesMake, err := testMeta.chain.CreateUnstakeTxn(
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
	require.Equal(testMeta.t, OperationTypeUnstake, utxoOps[len(utxoOps)-1].Type)
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

func _submitUnlockStakeTxn(
	testMeta *TestMeta,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	metadata *UnlockStakeMetadata,
	extraData map[string][]byte,
	flushToDB bool,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	// Record transactor's prevBalance.
	prevBalance := _getBalance(testMeta.t, testMeta.chain, testMeta.mempool, transactorPublicKeyBase58Check)

	// Convert PublicKeyBase58Check to PkBytes.
	updaterPkBytes, _, err := Base58CheckDecode(transactorPublicKeyBase58Check)
	require.NoError(testMeta.t, err)

	// Create the transaction.
	txn, totalInputMake, changeAmountMake, feesMake, err := testMeta.chain.CreateUnlockStakeTxn(
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
	require.Equal(testMeta.t, OperationTypeUnlockStake, utxoOps[len(utxoOps)-1].Type)
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
