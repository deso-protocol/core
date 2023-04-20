package lib

import (
	"errors"
	"github.com/btcsuite/btcd/btcec"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestStaking(t *testing.T) {
	_testStaking(t, false)
	_testStaking(t, true)
	_testStakingWithDerivedKey(t)
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
			StakeAmountNanos:   nil,
		}
		_, _, _, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidStakeAmountNanos)
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
			UnstakeAmountNanos: nil,
		}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, m1Pub, m1Priv, unstakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnstakeAmountNanos)
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

	// TODO: Flush mempool to the db and test rollbacks.
	//require.NoError(t, mempool.universalUtxoView.FlushToDb(blockHeight))
	//_executeAllTestRollbackAndFlush(testMeta)
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

func _testStakingWithDerivedKey(t *testing.T) {
	var derivedKeyPriv string
	var err error

	// Initialize balance model fork heights.
	setBalanceModelBlockHeights()
	defer resetBalanceModelBlockHeights()

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize fork heights.
	params.ForkHeights.DeSoUnlimitedDerivedKeysBlockHeight = uint32(0)
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

	_registerOrTransferWithTestMeta(testMeta, "m0", senderPkString, m0Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m1", senderPkString, m1Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 1e3)

	m0PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m0PkBytes).PKID
	m1PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m1PkBytes).PKID
	m2PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m2PkBytes).PKID

	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(t, err)
	senderPrivBytes, _, err := Base58CheckDecode(senderPrivString)
	require.NoError(t, err)
	senderPrivKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), senderPrivBytes)
	senderPKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, senderPkBytes).PKID

	newUtxoView := func() *UtxoView {
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(t, err)
		return utxoView
	}

	_submitAuthorizeDerivedKeyTxn := func(txnSpendingLimit *TransactionSpendingLimit) (string, error) {
		utxoView := newUtxoView()
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

	_submitStakeTxnWithDerivedKey := func(
		transactorPkBytes []byte, derivedKeyPrivBase58Check string, inputTxn MsgDeSoTxn,
	) error {
		utxoView := newUtxoView()
		var txn *MsgDeSoTxn

		switch inputTxn.TxnMeta.GetTxnType() {
		// Construct txn.
		case TxnTypeStake:
			txn, _, _, _, err = testMeta.chain.CreateStakeTxn(
				transactorPkBytes,
				inputTxn.TxnMeta.(*StakeMetadata),
				make(map[string][]byte),
				testMeta.feeRateNanosPerKb,
				mempool,
				[]*DeSoOutput{},
			)
		case TxnTypeUnstake:
			txn, _, _, _, err = testMeta.chain.CreateUnstakeTxn(
				transactorPkBytes,
				inputTxn.TxnMeta.(*UnstakeMetadata),
				make(map[string][]byte),
				testMeta.feeRateNanosPerKb,
				mempool,
				[]*DeSoOutput{},
			)
		case TxnTypeUnlockStake:
			txn, _, _, _, err = testMeta.chain.CreateUnlockStakeTxn(
				transactorPkBytes,
				inputTxn.TxnMeta.(*UnlockStakeMetadata),
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
		_signTxnWithDerivedKey(t, txn, derivedKeyPrivBase58Check)
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
		// m0 registers as a validator.
		registerAsValidatorMetadata := &RegisterAsValidatorMetadata{
			Domains: [][]byte{[]byte("https://example1.com")},
		}
		_, _, _, err = _submitRegisterAsValidatorTxn(
			testMeta, m0Pub, m0Priv, registerAsValidatorMetadata, nil, true,
		)
		require.NoError(t, err)
	}
	{
		// m1 registers as a validator.
		registerAsValidatorMetadata := &RegisterAsValidatorMetadata{
			Domains: [][]byte{[]byte("https://example2.com")},
		}
		_, _, _, err = _submitRegisterAsValidatorTxn(
			testMeta, m1Pub, m1Priv, registerAsValidatorMetadata, nil, true,
		)
		require.NoError(t, err)
	}
	{
		// RuleErrorTransactionSpendingLimitInvalidStaker
		// sender tries to create a DerivedKey that would allow
		// m1 to stake 100 $DESO nanos with m0. Errors.
		stakeLimitKey := MakeStakeLimitKey(m0PKID, m1PKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			StakeLimitMap: map[StakeLimitKey]uint64{stakeLimitKey: 100},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.Error(t, err)
	}
	{
		// RuleErrorTransactionSpendingLimitInvalidValidator
		// sender tries to create a DerivedKey to stake with m2. Validator doesn't exist. Errors.
		stakeLimitKey := MakeStakeLimitKey(m2PKID, senderPKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			StakeLimitMap: map[StakeLimitKey]uint64{stakeLimitKey: 100},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.Error(t, err)
	}
	{
		// RuleErrorTransactionSpendingLimitInvalidStaker
		// sender tries to create a DerivedKey that would allow
		// m1 to unstake 100 $DESO nanos from m0. Errors.
		stakeLimitKey := MakeStakeLimitKey(m0PKID, m1PKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			UnstakeLimitMap: map[StakeLimitKey]uint64{stakeLimitKey: 100},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.Error(t, err)
	}
	{
		// RuleErrorTransactionSpendingLimitInvalidValidator
		// sender tries to create a DerivedKey to unstake from m2. Validator doesn't exist. Errors.
		stakeLimitKey := MakeStakeLimitKey(m2PKID, senderPKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			UnstakeLimitMap: map[StakeLimitKey]uint64{stakeLimitKey: 100},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.Error(t, err)
	}
	{
		// RuleErrorTransactionSpendingLimitInvalidStaker
		// sender tries to create a DerivedKey that would allow
		// m1 to unlock stake from m0. Errors.
		stakeLimitKey := MakeStakeLimitKey(m0PKID, m1PKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			UnlockStakeLimitMap: map[StakeLimitKey]uint64{stakeLimitKey: 100},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.Error(t, err)
	}
	{
		// RuleErrorTransactionSpendingLimitInvalidValidator
		// sender tries to create a DerivedKey to stake with m2. Validator doesn't exist. Errors.
		stakeLimitKey := MakeStakeLimitKey(m2PKID, senderPKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			UnlockStakeLimitMap: map[StakeLimitKey]uint64{stakeLimitKey: 100},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.Error(t, err)
	}
	{
		// sender stakes with m0 using a DerivedKey.

		// sender creates a DerivedKey to stake up to 100 $DESO nanos with m0.
		stakeLimitKey := MakeStakeLimitKey(m0PKID, senderPKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			StakeLimitMap: map[StakeLimitKey]uint64{stakeLimitKey: 100},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.NoError(t, err)

		// sender tries to stake 100 $DESO nanos with m1 using the DerivedKey. Errors.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(100),
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: stakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorStakeTransactionSpendingLimitNotFound)

		// sender tries to stake 200 $DESO nanos with m0 using the DerivedKey. Errors.
		stakeMetadata = &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(200),
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: stakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorStakeTransactionSpendingLimitExceeded)

		// sender stakes 100 $DESO nanos with m0 using the DerivedKey. Succeeds.
		stakeMetadata = &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(100),
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: stakeMetadata},
		)
		require.NoError(t, err)

		// StakeEntry was created.
		stakeEntry, err := newUtxoView().GetStakeEntry(m0PKID, senderPKID)
		require.NoError(t, err)
		require.NotNil(t, stakeEntry)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt().SetUint64(100))

		// TODO: verify sender's DESO balance is reduced by 100 $DESO nanos.
	}
	{
		// sender unstakes from m0 using a DerivedKey.

		// sender creates a DerivedKey to unstake up to 50 $DESO nanos from m0.
		stakeLimitKey := MakeStakeLimitKey(m0PKID, senderPKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			UnstakeLimitMap: map[StakeLimitKey]uint64{stakeLimitKey: 50},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.NoError(t, err)

		// sender tries to unstake 50 $DESO nanos from m1 using the DerivedKey. Errors.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(50),
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unstakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnstakeNoStakeFound)

		// sender stakes 50 $DESO nanos with m1.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(50),
		}
		_, _, _, err = _submitStakeTxn(
			testMeta, senderPkString, senderPrivString, stakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender tries to unstake 50 $DESO nanos from m1 using the DerivedKey. Errors.
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(50),
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unstakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorUnstakeTransactionSpendingLimitNotFound)

		// sender tries to unstake 200 $DESO nanos from m0 using the DerivedKey. Errors.
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(200),
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unstakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnstakeInsufficientStakeFound)

		// sender tries to unstake 100 $DESO nanos from m0 using the DerivedKey. Errors.
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(100),
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unstakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorUnstakeTransactionSpendingLimitExceeded)

		// sender unstakes 50 $DESO nanos from m0 using the DerivedKey. Succeeds.
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(50),
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unstakeMetadata},
		)
		require.NoError(t, err)

		// StakeEntry was updated.
		stakeEntry, err := newUtxoView().GetStakeEntry(m0PKID, senderPKID)
		require.NoError(t, err)
		require.NotNil(t, stakeEntry)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt().SetUint64(50))

		// LockedStakeEntry was created.
		epochNumber := uint64(0) // TODO: Get epoch number from the db.
		lockedStakeEntry, err := newUtxoView().GetLockedStakeEntry(m0PKID, senderPKID, epochNumber)
		require.NoError(t, err)
		require.NotNil(t, lockedStakeEntry)
		require.Equal(t, lockedStakeEntry.LockedAmountNanos, uint256.NewInt().SetUint64(50))
	}
	{
		// sender unlocks stake using a DerivedKey.

		// sender creates a DerivedKey to perform 1 unlock stake operation with m0.
		stakeLimitKey := MakeStakeLimitKey(m0PKID, senderPKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			UnlockStakeLimitMap: map[StakeLimitKey]uint64{stakeLimitKey: 1},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.NoError(t, err)

		// sender tries to unlock all stake from m1 using the DerivedKey. Errors.
		epochNumber := uint64(0) // TODO: Get epoch number from the db.
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StartEpochNumber:   epochNumber,
			EndEpochNumber:     epochNumber,
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnlockStakeNoUnlockableStakeFound)

		// sender unstakes 50 $DESO nanos from m1.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(50),
		}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, senderPkString, senderPrivString, unstakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender tries to unlock all stake from m1 using the DerivedKey. Errors.
		unlockStakeMetadata = &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StartEpochNumber:   epochNumber,
			EndEpochNumber:     epochNumber,
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorUnlockStakeTransactionSpendingLimitNotFound)

		// sender unlocks all stake from m0 using the DerivedKey. Succeeds.
		unlockStakeMetadata = &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   epochNumber,
			EndEpochNumber:     epochNumber,
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.NoError(t, err)

		// LockedStakeEntry was deleted.
		lockedStakeEntry, err := newUtxoView().GetLockedStakeEntry(m0PKID, senderPKID, epochNumber)
		require.NoError(t, err)
		require.Nil(t, lockedStakeEntry)

		// TODO: verify sender's DESO balance was increased by 50 DESO nanos.

		// sender stakes + unstakes 50 $DESO nanos with m0.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(50),
		}
		_, _, _, err = _submitStakeTxn(
			testMeta, senderPkString, senderPrivString, stakeMetadata, nil, true,
		)
		require.NoError(t, err)
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(50),
		}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, senderPkString, senderPrivString, unstakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender tries to unlock all stake from m0 using the DerivedKey. Errors.
		unlockStakeMetadata = &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   epochNumber,
			EndEpochNumber:     epochNumber,
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorUnlockStakeTransactionSpendingLimitNotFound)
	}
	{
		// sender stakes, unstakes, and unlocks stake using a DerivedKey scoped to any validator.

		// sender creates a DerivedKey that can stake, unstake, and unlock stake with any validator.
		stakeLimitKey := MakeStakeLimitKey(&ZeroPKID, senderPKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			StakeLimitMap:       map[StakeLimitKey]uint64{stakeLimitKey: 50},
			UnstakeLimitMap:     map[StakeLimitKey]uint64{stakeLimitKey: 50},
			UnlockStakeLimitMap: map[StakeLimitKey]uint64{stakeLimitKey: 2},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.NoError(t, err)

		// sender stakes with m0 using the DerivedKey.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(25),
		}
		_, _, _, err = _submitStakeTxn(
			testMeta, senderPkString, senderPrivString, stakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender stakes with m1 using the DerivedKey.
		stakeMetadata = &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(25),
		}
		_, _, _, err = _submitStakeTxn(
			testMeta, senderPkString, senderPrivString, stakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender unstakes from m0 using the DerivedKey.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(25),
		}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, senderPkString, senderPrivString, unstakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender unstakes from m1 using the DerivedKey.
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(25),
		}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, senderPkString, senderPrivString, unstakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender unlocks stake from m0 using the DerivedKey.
		epochNumber := uint64(0) // TODO: get current epoch number from db.
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   epochNumber,
			EndEpochNumber:     epochNumber,
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.NoError(t, err)

		// sender unlocks stake from m1 using the DerivedKey.
		unlockStakeMetadata = &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StartEpochNumber:   epochNumber,
			EndEpochNumber:     epochNumber,
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.NoError(t, err)
	}
	{
		// sender stakes, unstakes, and unlocks stake using an IsUnlimited DerivedKey.

		// sender creates an IsUnlimited DerivedKey.
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: 0,
			IsUnlimited:     true,
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.NoError(t, err)

		// sender stakes with m0 using the DerivedKey.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(25),
		}
		_, _, _, err = _submitStakeTxn(
			testMeta, senderPkString, senderPrivString, stakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender stakes with m1 using the DerivedKey.
		stakeMetadata = &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(25),
		}
		_, _, _, err = _submitStakeTxn(
			testMeta, senderPkString, senderPrivString, stakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender unstakes from m0 using the DerivedKey.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(25),
		}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, senderPkString, senderPrivString, unstakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender unstakes from m1 using the DerivedKey.
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(25),
		}
		_, _, _, err = _submitUnstakeTxn(
			testMeta, senderPkString, senderPrivString, unstakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender unlocks stake from m0 using the DerivedKey.
		epochNumber := uint64(0) // TODO: get current epoch number from db.
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   epochNumber,
			EndEpochNumber:     epochNumber,
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.NoError(t, err)

		// sender unlocks stake from m1 using the DerivedKey.
		unlockStakeMetadata = &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StartEpochNumber:   epochNumber,
			EndEpochNumber:     epochNumber,
		}
		err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.NoError(t, err)
	}
	{
		// Test TransactionSpendingLimit.ToMetamaskString() scoped to one validator.
		stakeLimitKey1 := MakeStakeLimitKey(m0PKID, senderPKID)
		stakeLimitKey2 := MakeStakeLimitKey(m1PKID, senderPKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			StakeLimitMap: map[StakeLimitKey]uint64{
				stakeLimitKey1: uint64(1.5 * float64(NanosPerUnit)),
				stakeLimitKey2: uint64(2.0 * float64(NanosPerUnit)),
			},
			UnstakeLimitMap: map[StakeLimitKey]uint64{
				stakeLimitKey1: uint64(3.25 * float64(NanosPerUnit)),
			},
			UnlockStakeLimitMap: map[StakeLimitKey]uint64{stakeLimitKey1: 2, stakeLimitKey2: 3},
		}
		metamaskStr := txnSpendingLimit.ToMetamaskString(params)
		require.Equal(t, metamaskStr,
			"Spending limits on the derived key:\n"+
				"\tTotal $DESO Limit: 1.0 $DESO\n"+
				"\tTransaction Count Limit: \n"+
				"\t\tAUTHORIZE_DERIVED_KEY: 1\n"+
				"\tStaking Restrictions:\n"+
				"\t\t[\n"+
				"\t\t\tValidator PKID: "+m0Pub+"\n"+
				"\t\t\tStaker PKID: "+senderPkString+"\n"+
				"\t\t\tStaking Limit: 1.50 $DESO\n"+
				"\t\t]\n"+
				"\t\t[\n"+
				"\t\t\tValidator PKID: "+m1Pub+"\n"+
				"\t\t\tStaker PKID: "+senderPkString+"\n"+
				"\t\t\tStaking Limit: 2.00 $DESO\n"+
				"\t\t]\n"+
				"\tUnstaking Restrictions:\n"+
				"\t\t[\n"+
				"\t\t\tValidator PKID: "+m0Pub+"\n"+
				"\t\t\tStaker PKID: "+senderPkString+"\n"+
				"\t\t\tUnstaking Limit: 3.25 $DESO\n"+
				"\t\t]\n"+
				"\tUnlocking Stake Restrictions:\n"+
				"\t\t[\n"+
				"\t\t\tValidator PKID: "+m0Pub+"\n"+
				"\t\t\tStaker PKID: "+senderPkString+"\n"+
				"\t\t\tTransaction Count: 2\n"+
				"\t\t]\n"+
				"\t\t[\n"+
				"\t\t\tValidator PKID: "+m1Pub+"\n"+
				"\t\t\tStaker PKID: "+senderPkString+"\n"+
				"\t\t\tTransaction Count: 3\n"+
				"\t\t]\n",
		)
	}
	{
		// Test TransactionSpendingLimit.ToMetamaskString() scoped to any validator.
		stakeLimitKey := MakeStakeLimitKey(&ZeroPKID, senderPKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			StakeLimitMap:       map[StakeLimitKey]uint64{stakeLimitKey: uint64(0.65 * float64(NanosPerUnit))},
			UnstakeLimitMap:     map[StakeLimitKey]uint64{stakeLimitKey: uint64(2.1 * float64(NanosPerUnit))},
			UnlockStakeLimitMap: map[StakeLimitKey]uint64{stakeLimitKey: 1},
		}
		metamaskStr := txnSpendingLimit.ToMetamaskString(params)
		require.Equal(t, metamaskStr,
			"Spending limits on the derived key:\n"+
				"\tTotal $DESO Limit: 1.0 $DESO\n"+
				"\tTransaction Count Limit: \n"+
				"\t\tAUTHORIZE_DERIVED_KEY: 1\n"+
				"\tStaking Restrictions:\n"+
				"\t\t[\n"+
				"\t\t\tValidator PKID: Any\n"+
				"\t\t\tStaker PKID: "+senderPkString+"\n"+
				"\t\t\tStaking Limit: 0.65 $DESO\n"+
				"\t\t]\n"+
				"\tUnstaking Restrictions:\n"+
				"\t\t[\n"+
				"\t\t\tValidator PKID: Any\n"+
				"\t\t\tStaker PKID: "+senderPkString+"\n"+
				"\t\t\tUnstaking Limit: 2.10 $DESO\n"+
				"\t\t]\n"+
				"\tUnlocking Stake Restrictions:\n"+
				"\t\t[\n"+
				"\t\t\tValidator PKID: Any\n"+
				"\t\t\tStaker PKID: "+senderPkString+"\n"+
				"\t\t\tTransaction Count: 1\n"+
				"\t\t]\n",
		)
	}

	// TODO: Flush mempool to the db and test rollbacks.
	//require.NoError(t, mempool.universalUtxoView.FlushToDb(blockHeight))
	//_executeAllTestRollbackAndFlush(testMeta)
}
