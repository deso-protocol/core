//go:build relic

package lib

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestStaking(t *testing.T) {
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	t.Run("flushToDB=false", func(t *testing.T) {
		_testStaking(t, false)
	})
	t.Run("flushToDB=true", func(t *testing.T) {
		_testStaking(t, true)
	})
}

func _testStaking(t *testing.T, flushToDB bool) {
	// Local variables
	var err error

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)
	chain.snapshot = nil

	// For these tests, we set StakeLockupEpochDuration to zero.
	// We test the lockup logic in a separate test.
	params.DefaultStakeLockupEpochDuration = 0

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

	// Helper utils
	utxoView := func() *UtxoView {
		newUtxoView, err := mempool.GetAugmentedUniversalView()
		require.NoError(t, err)
		return newUtxoView
	}

	getDESOBalanceNanos := func(publicKeyBytes []byte) uint64 {
		desoBalanceNanos, err := utxoView().GetDeSoBalanceNanosForPublicKey(publicKeyBytes)
		require.NoError(t, err)
		return desoBalanceNanos
	}

	// Seed a CurrentEpochEntry.
	epochUtxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
	require.NoError(t, err)
	epochUtxoView._setCurrentEpochEntry(&EpochEntry{EpochNumber: 1, FinalBlockHeight: blockHeight + 10})
	require.NoError(t, epochUtxoView.FlushToDb(blockHeight))
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
		params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerAsValidatorMetadata := &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte("https://example.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerAsValidatorMetadata, nil, flushToDB)
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
		params.ForkHeights.ProofOfStake1StateSetupBlockHeight = math.MaxUint32
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			RewardMethod:       StakingRewardMethodPayToBalance,
			StakeAmountNanos:   uint256.NewInt().SetUint64(100),
		}
		_, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorProofofStakeTxnBeforeBlockHeight)

		params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	}
	{
		// RuleErrorInvalidValidatorPKID
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m2PkBytes),
			RewardMethod:       StakingRewardMethodPayToBalance,
			StakeAmountNanos:   uint256.NewInt(),
		}
		_, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidValidatorPKID)
	}
	{
		// RuleErrorInvalidStakingRewardMethod
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			RewardMethod:       99,
			StakeAmountNanos:   uint256.NewInt().SetUint64(1),
		}
		_, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidStakingRewardMethod)
	}
	{
		// RuleErrorInvalidStakeAmountNanos
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			RewardMethod:       StakingRewardMethodPayToBalance,
			StakeAmountNanos:   nil,
		}
		_, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidStakeAmountNanos)
	}
	{
		// RuleErrorInvalidStakeAmountNanos
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			RewardMethod:       StakingRewardMethodPayToBalance,
			StakeAmountNanos:   uint256.NewInt(),
		}
		_, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidStakeAmountNanos)
	}
	{
		// RuleErrorInvalidStakeAmountNanos
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			RewardMethod:       StakingRewardMethodPayToBalance,
			StakeAmountNanos:   MaxUint256,
		}
		_, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidStakeAmountNanos)
	}
	{
		// RuleErrorInvalidStakeInsufficientBalance
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			RewardMethod:       StakingRewardMethodPayToBalance,
			StakeAmountNanos:   uint256.NewInt().SetUint64(math.MaxUint64),
		}
		_, err = _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidStakeInsufficientBalance)
	}
	{
		// m1 stakes with m0.
		m1OldDESOBalanceNanos := getDESOBalanceNanos(m1PkBytes)
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			RewardMethod:       StakingRewardMethodPayToBalance,
			StakeAmountNanos:   uint256.NewInt().SetUint64(100),
		}
		extraData := map[string][]byte{"TestKey": []byte("TestValue")}
		feeNanos, err := _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, extraData, flushToDB,
		)
		require.NoError(t, err)

		// Verify StakeEntry.StakeAmountNanos.
		stakeEntry, err := utxoView().GetStakeEntry(m0PKID, m1PKID)
		require.NoError(t, err)
		require.NotNil(t, stakeEntry)
		require.Equal(t, stakeEntry.RewardMethod, StakingRewardMethodPayToBalance)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt().SetUint64(100))
		require.Equal(t, stakeEntry.ExtraData["TestKey"], []byte("TestValue"))

		// Verify ValidatorEntry.TotalStakeAmountNanos.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))

		// Verify m1's DESO balance decreases by StakeAmountNanos (net of fees).
		m1NewDESOBalanceNanos := getDESOBalanceNanos(m1PkBytes)
		require.Equal(t, m1OldDESOBalanceNanos-feeNanos-stakeMetadata.StakeAmountNanos.Uint64(), m1NewDESOBalanceNanos)
	}
	{
		// m1 stakes more with m0.
		m1OldDESOBalanceNanos := getDESOBalanceNanos(m1PkBytes)
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			RewardMethod:       StakingRewardMethodPayToBalance,
			StakeAmountNanos:   uint256.NewInt().SetUint64(50),
		}
		extraData := map[string][]byte{"TestKey": []byte("TestValue2")}
		feeNanos, err := _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, extraData, flushToDB,
		)
		require.NoError(t, err)

		// Verify StakeEntry.StakeAmountNanos.
		stakeEntry, err := utxoView().GetStakeEntry(m0PKID, m1PKID)
		require.NoError(t, err)
		require.NotNil(t, stakeEntry)
		require.Equal(t, stakeEntry.RewardMethod, StakingRewardMethodPayToBalance)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt().SetUint64(150))
		require.Equal(t, stakeEntry.ExtraData["TestKey"], []byte("TestValue2"))

		// Verify ValidatorEntry.TotalStakeAmountNanos.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(150))

		// Verify m1's DESO balance decreases by StakeAmountNanos (net of fees).
		m1NewDESOBalanceNanos := getDESOBalanceNanos(m1PkBytes)
		require.Equal(t, m1OldDESOBalanceNanos-feeNanos-stakeMetadata.StakeAmountNanos.Uint64(), m1NewDESOBalanceNanos)
	}
	{
		// m1 changes the RewardMethod value on their stake with m0.
		m1OldDESOBalanceNanos := getDESOBalanceNanos(m1PkBytes)
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			RewardMethod:       StakingRewardMethodRestake,
			StakeAmountNanos:   uint256.NewInt(),
		}
		extraData := map[string][]byte{"TestKey": []byte("TestValue2")}
		feeNanos, err := _submitStakeTxn(
			testMeta, m1Pub, m1Priv, stakeMetadata, extraData, flushToDB,
		)
		require.NoError(t, err)

		// Verify the StakeEntry.StakeAmountNanos does not change.
		stakeEntry, err := utxoView().GetStakeEntry(m0PKID, m1PKID)
		require.NoError(t, err)
		require.NotNil(t, stakeEntry)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt().SetUint64(150))
		require.Equal(t, stakeEntry.ExtraData["TestKey"], []byte("TestValue2"))

		// Verify the StakeEntry.RewardMethod has changed to StakingRewardMethodRestake.
		require.Equal(t, stakeEntry.RewardMethod, StakingRewardMethodRestake)

		// Verify the ValidatorEntry.TotalStakeAmountNanos does not change.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(150))

		// Verify m1's DESO balance decreases by StakeAmountNanos (net of fees).
		m1NewDESOBalanceNanos := getDESOBalanceNanos(m1PkBytes)
		require.Equal(t, m1OldDESOBalanceNanos-feeNanos-stakeMetadata.StakeAmountNanos.Uint64(), m1NewDESOBalanceNanos)
	}
	//
	// UNSTAKING
	//
	{
		// RuleErrorProofOfStakeTxnBeforeBlockHeight
		params.ForkHeights.ProofOfStake1StateSetupBlockHeight = math.MaxUint32
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(40),
		}
		_, err = _submitUnstakeTxn(
			testMeta, m1Pub, m1Priv, unstakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorProofofStakeTxnBeforeBlockHeight)

		params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	}
	{
		// RuleErrorInvalidValidatorPKID
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m2PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(40),
		}
		_, err = _submitUnstakeTxn(
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
		_, err = _submitUnstakeTxn(
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
		_, err = _submitUnstakeTxn(
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
		_, err = _submitUnstakeTxn(
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
		_, err = _submitUnstakeTxn(
			testMeta, m1Pub, m1Priv, unstakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnstakeInsufficientStakeFound)
	}
	{
		// m1 unstakes from m0.
		m1OldDESOBalanceNanos := getDESOBalanceNanos(m1PkBytes)
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(40),
		}
		extraData := map[string][]byte{"TestKey": []byte("TestValue")}
		feeNanos, err := _submitUnstakeTxn(
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

		// Verify LockedStakeEntry.UnstakeAmountNanos.
		lockedStakeEntry, err := utxoView().GetLockedStakeEntry(m0PKID, m1PKID, currentEpochNumber)
		require.NoError(t, err)
		require.Equal(t, lockedStakeEntry.LockedAmountNanos, uint256.NewInt().SetUint64(40))
		require.Equal(t, lockedStakeEntry.ExtraData["TestKey"], []byte("TestValue"))

		// Verify m1's balance stays the same (net of fees).
		m1NewDESOBalanceNanos := getDESOBalanceNanos(m1PkBytes)
		require.Equal(t, m1OldDESOBalanceNanos-feeNanos, m1NewDESOBalanceNanos)
	}
	{
		// m1 unstakes more from m0.
		m1OldDESOBalanceNanos := getDESOBalanceNanos(m1PkBytes)
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(30),
		}
		extraData := map[string][]byte{"TestKey": []byte("TestValue2")}
		feeNanos, err := _submitUnstakeTxn(
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

		// Verify LockedStakeEntry.UnstakeAmountNanos.
		lockedStakeEntry, err := utxoView().GetLockedStakeEntry(m0PKID, m1PKID, currentEpochNumber)
		require.NoError(t, err)
		require.Equal(t, lockedStakeEntry.LockedAmountNanos, uint256.NewInt().SetUint64(70))
		require.Equal(t, lockedStakeEntry.ExtraData["TestKey"], []byte("TestValue2"))

		// Verify m1's balance stays the same (net of fees).
		m1NewDESOBalanceNanos := getDESOBalanceNanos(m1PkBytes)
		require.Equal(t, m1OldDESOBalanceNanos-feeNanos, m1NewDESOBalanceNanos)
	}
	{
		// m1 unstakes the rest of their stake with m0.
		m1OldDESOBalanceNanos := getDESOBalanceNanos(m1PkBytes)
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(80),
		}
		feeNanos, err := _submitUnstakeTxn(
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

		// Verify LockedStakeEntry.UnstakeAmountNanos.
		lockedStakeEntry, err := utxoView().GetLockedStakeEntry(m0PKID, m1PKID, currentEpochNumber)
		require.NoError(t, err)
		require.Equal(t, lockedStakeEntry.LockedAmountNanos, uint256.NewInt().SetUint64(150))
		require.Equal(t, lockedStakeEntry.ExtraData["TestKey"], []byte("TestValue2"))

		// Verify m1's balance stays the same (net of fees).
		m1NewDESOBalanceNanos := getDESOBalanceNanos(m1PkBytes)
		require.Equal(t, m1OldDESOBalanceNanos-feeNanos, m1NewDESOBalanceNanos)
	}
	//
	// UNLOCK STAKE
	//
	{
		// RuleErrorProofOfStakeTxnBeforeBlockHeight
		params.ForkHeights.ProofOfStake1StateSetupBlockHeight = math.MaxUint32
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   currentEpochNumber,
			EndEpochNumber:     currentEpochNumber,
		}
		_, err = _submitUnlockStakeTxn(
			testMeta, m1Pub, m1Priv, unlockStakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorProofofStakeTxnBeforeBlockHeight)

		params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
		GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
		GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	}
	{
		// RuleErrorInvalidValidatorPKID
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m2PkBytes),
			StartEpochNumber:   currentEpochNumber,
			EndEpochNumber:     currentEpochNumber,
		}
		_, err = _submitUnlockStakeTxn(
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
		_, err = _submitUnlockStakeTxn(
			testMeta, m1Pub, m1Priv, unlockStakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnlockStakeEpochRange)
	}
	{
		// RuleErrorInvalidUnlockStakeNoUnlockableStakeFound
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   0,
			EndEpochNumber:     0,
		}
		_, err = _submitUnlockStakeTxn(
			testMeta, m1Pub, m1Priv, unlockStakeMetadata, nil, flushToDB,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnlockStakeNoUnlockableStakeFound)
	}
	{
		// m1 unlocks stake that was assigned to m0.
		lockedStakeEntries, err := utxoView().GetLockedStakeEntriesInRange(
			m0PKID, m1PKID, currentEpochNumber, currentEpochNumber,
		)
		require.NoError(t, err)
		require.Equal(t, len(lockedStakeEntries), 1)
		require.Equal(t, lockedStakeEntries[0].LockedAmountNanos, uint256.NewInt().SetUint64(150))

		m1OldDESOBalanceNanos := getDESOBalanceNanos(m1PkBytes)
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   currentEpochNumber,
			EndEpochNumber:     currentEpochNumber,
		}
		feeNanos, err := _submitUnlockStakeTxn(
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

		// Verify LockedStakeEntry.isDeleted.
		lockedStakeEntry, err := utxoView().GetLockedStakeEntry(m0PKID, m1PKID, currentEpochNumber)
		require.NoError(t, err)
		require.Nil(t, lockedStakeEntry)

		// Verify m1's DESO balance increases by LockedAmountNanos (net of fees).
		m1NewDESOBalanceNanos := getDESOBalanceNanos(m1PkBytes)
		require.Equal(t, m1OldDESOBalanceNanos-feeNanos+uint64(150), m1NewDESOBalanceNanos)
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
) (_fees uint64, _err error) {
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
		return 0, err
	}
	require.Equal(testMeta.t, totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(testMeta.t, txn, transactorPrivateKeyBase58Check)

	// Connect the transaction.
	utxoOps, totalInput, totalOutput, fees, err := testMeta.mempool.universalUtxoView.ConnectTransaction(txn, txn.Hash(), testMeta.savedHeight, 0, true, false)
	if err != nil {
		return 0, err
	}
	require.Equal(testMeta.t, totalInput, totalOutput+fees)
	require.Equal(testMeta.t, totalInput, totalInputMake+metadata.StakeAmountNanos.Uint64())
	require.Equal(testMeta.t, OperationTypeStake, utxoOps[len(utxoOps)-1].Type)
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

func _submitUnstakeTxn(
	testMeta *TestMeta,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	metadata *UnstakeMetadata,
	extraData map[string][]byte,
	flushToDB bool,
) (_fees uint64, _err error) {
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
		return 0, err
	}
	require.Equal(testMeta.t, totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(testMeta.t, txn, transactorPrivateKeyBase58Check)

	// Connect the transaction.
	utxoOps, totalInput, totalOutput, fees, err := testMeta.mempool.universalUtxoView.ConnectTransaction(txn, txn.Hash(), testMeta.savedHeight, 0, true, false)
	if err != nil {
		return 0, err
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
	return fees, nil
}

func _submitUnlockStakeTxn(
	testMeta *TestMeta,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	metadata *UnlockStakeMetadata,
	extraData map[string][]byte,
	flushToDB bool,
) (_fees uint64, _err error) {
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
		return 0, err
	}
	require.Equal(testMeta.t, totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(testMeta.t, txn, transactorPrivateKeyBase58Check)

	// Connect the transaction.
	utxoOps, totalInput, totalOutput, fees, err := testMeta.mempool.universalUtxoView.ConnectTransaction(txn, txn.Hash(), testMeta.savedHeight, 0, true, false)
	if err != nil {
		return 0, err
	}
	require.Equal(testMeta.t, totalInput, totalOutput+fees)
	// TotalInput = TotalInputMake + TotalUnlockedAmountNanos
	require.True(testMeta.t, totalInput > totalInputMake)
	require.Equal(testMeta.t, OperationTypeUnlockStake, utxoOps[len(utxoOps)-1].Type)
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

func TestStakingWithDerivedKey(t *testing.T) {
	var derivedKeyPriv string
	var err error

	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize PoS fork heights.
	params.ForkHeights.DeSoUnlimitedDerivedKeysBlockHeight = uint32(0)
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	chain.snapshot = nil

	// For these tests, we set StakeLockupEpochDuration to zero.
	// We test the lockup logic in a separate test.
	params.DefaultStakeLockupEpochDuration = 0

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
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
		require.NoError(t, err)
		return utxoView
	}

	getDESOBalanceNanos := func(publicKeyBytes []byte) uint64 {
		desoBalanceNanos, err := newUtxoView().GetDeSoBalanceNanosForPublicKey(publicKeyBytes)
		require.NoError(t, err)
		return desoBalanceNanos
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
	) (_fees uint64, _err error) {
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
			return 0, errors.New("invalid txn type")
		}
		if err != nil {
			return 0, err
		}
		// Sign txn.
		_signTxnWithDerivedKeyAndType(t, txn, derivedKeyPrivBase58Check, 1)
		// Store the original transactor balance.
		transactorPublicKeyBase58Check := Base58CheckEncode(transactorPkBytes, false, params)
		prevBalance := _getBalance(testMeta.t, testMeta.chain, testMeta.mempool, transactorPublicKeyBase58Check)
		// Connect txn.
		utxoOps, _, _, fees, err := utxoView.ConnectTransaction(txn, txn.Hash(), testMeta.savedHeight, 0, true, false)
		if err != nil {
			return 0, err
		}
		// Flush UTXO view to the db.
		require.NoError(t, utxoView.FlushToDb(blockHeight))
		// Track txn for rolling back.
		testMeta.expectedSenderBalances = append(testMeta.expectedSenderBalances, prevBalance)
		testMeta.txnOps = append(testMeta.txnOps, utxoOps)
		testMeta.txns = append(testMeta.txns, txn)
		return fees, nil
	}

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
		// m0 registers as a validator.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerAsValidatorMetadata := &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte("https://example1.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerAsValidatorMetadata, nil, true)
		require.NoError(t, err)
	}
	{
		// m1 registers as a validator.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m1PkBytes)
		registerAsValidatorMetadata := &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte("https://example2.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m1Pub, m1Priv, registerAsValidatorMetadata, nil, true)
		require.NoError(t, err)
	}
	{
		// RuleErrorTransactionSpendingLimitInvalidValidator
		// sender tries to create a DerivedKey to stake with m2. Validator doesn't exist. Errors.
		stakeLimitKey := MakeStakeLimitKey(m2PKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			StakeLimitMap: map[StakeLimitKey]*uint256.Int{stakeLimitKey: uint256.NewInt().SetUint64(100)},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.Error(t, err)
	}
	{
		// RuleErrorTransactionSpendingLimitInvalidValidator
		// sender tries to create a DerivedKey to unstake from m2. Validator doesn't exist. Errors.
		stakeLimitKey := MakeStakeLimitKey(m2PKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			UnstakeLimitMap: map[StakeLimitKey]*uint256.Int{stakeLimitKey: uint256.NewInt().SetUint64(100)},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.Error(t, err)
	}
	{
		// RuleErrorTransactionSpendingLimitInvalidValidator
		// sender tries to create a DerivedKey to stake with m2. Validator doesn't exist. Errors.
		stakeLimitKey := MakeStakeLimitKey(m2PKID)
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
		stakeLimitKey := MakeStakeLimitKey(m0PKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			StakeLimitMap: map[StakeLimitKey]*uint256.Int{stakeLimitKey: uint256.NewInt().SetUint64(100)},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.NoError(t, err)

		// sender tries to stake 100 $DESO nanos with m1 using the DerivedKey. Errors.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(100),
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: stakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorStakeTransactionSpendingLimitNotFound)

		// sender tries to stake 200 $DESO nanos with m0 using the DerivedKey. Errors.
		stakeMetadata = &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(200),
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: stakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorStakeTransactionSpendingLimitExceeded)

		// sender stakes 100 $DESO nanos with m0 using the DerivedKey. Succeeds.
		senderOldDESOBalanceNanos := getDESOBalanceNanos(senderPkBytes)
		stakeMetadata = &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(100),
		}
		feeNanos, err := _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: stakeMetadata},
		)
		require.NoError(t, err)

		// StakeEntry was created.
		stakeEntry, err := newUtxoView().GetStakeEntry(m0PKID, senderPKID)
		require.NoError(t, err)
		require.NotNil(t, stakeEntry)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt().SetUint64(100))

		// Verify sender's DESO balance is reduced by StakeAmountNanos (net of fees).
		senderNewDESOBalanceNanos := getDESOBalanceNanos(senderPkBytes)
		require.Equal(t, senderOldDESOBalanceNanos-feeNanos-stakeMetadata.StakeAmountNanos.Uint64(), senderNewDESOBalanceNanos)
	}
	{
		// sender unstakes from m0 using a DerivedKey.

		// sender creates a DerivedKey to unstake up to 50 $DESO nanos from m0.
		stakeLimitKey := MakeStakeLimitKey(m0PKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			UnstakeLimitMap: map[StakeLimitKey]*uint256.Int{stakeLimitKey: uint256.NewInt().SetUint64(50)},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.NoError(t, err)

		// sender tries to unstake 50 $DESO nanos from m1 using the DerivedKey. Errors.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(50),
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unstakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnstakeNoStakeFound)

		// sender stakes 50 $DESO nanos with m1.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(50),
		}
		_, err = _submitStakeTxn(
			testMeta, senderPkString, senderPrivString, stakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender tries to unstake 50 $DESO nanos from m1 using the DerivedKey. Errors.
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(50),
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unstakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorUnstakeTransactionSpendingLimitNotFound)

		// sender tries to unstake 200 $DESO nanos from m0 using the DerivedKey. Errors.
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(200),
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unstakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnstakeInsufficientStakeFound)

		// sender tries to unstake 100 $DESO nanos from m0 using the DerivedKey. Errors.
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(100),
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unstakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorUnstakeTransactionSpendingLimitExceeded)

		// sender unstakes 50 $DESO nanos from m0 using the DerivedKey. Succeeds.
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(50),
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unstakeMetadata},
		)
		require.NoError(t, err)

		// StakeEntry was updated.
		stakeEntry, err := newUtxoView().GetStakeEntry(m0PKID, senderPKID)
		require.NoError(t, err)
		require.NotNil(t, stakeEntry)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt().SetUint64(50))

		// LockedStakeEntry was created.
		lockedStakeEntry, err := newUtxoView().GetLockedStakeEntry(m0PKID, senderPKID, currentEpochNumber)
		require.NoError(t, err)
		require.NotNil(t, lockedStakeEntry)
		require.Equal(t, lockedStakeEntry.LockedAmountNanos, uint256.NewInt().SetUint64(50))
	}
	{
		// sender unlocks stake using a DerivedKey.

		// sender creates a DerivedKey to perform 1 unlock stake operation with m0.
		stakeLimitKey := MakeStakeLimitKey(m0PKID)
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
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StartEpochNumber:   currentEpochNumber,
			EndEpochNumber:     currentEpochNumber,
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnlockStakeNoUnlockableStakeFound)

		// sender unstakes 50 $DESO nanos from m1.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(50),
		}
		_, err = _submitUnstakeTxn(
			testMeta, senderPkString, senderPrivString, unstakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender tries to unlock all stake from m1 using the DerivedKey. Errors.
		unlockStakeMetadata = &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StartEpochNumber:   currentEpochNumber,
			EndEpochNumber:     currentEpochNumber,
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorUnlockStakeTransactionSpendingLimitNotFound)

		// sender unlocks all stake from m0 using the DerivedKey. Succeeds.
		senderOldDESOBalanceNanos := getDESOBalanceNanos(senderPkBytes)
		unlockStakeMetadata = &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   currentEpochNumber,
			EndEpochNumber:     currentEpochNumber,
		}
		feeNanos, err := _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.NoError(t, err)

		// LockedStakeEntry was deleted.
		lockedStakeEntry, err := newUtxoView().GetLockedStakeEntry(m0PKID, senderPKID, currentEpochNumber)
		require.NoError(t, err)
		require.Nil(t, lockedStakeEntry)

		// Verify sender's DESO balance was increased by 50 DESO nanos (net of fees).
		senderNewDESOBalanceNanos := getDESOBalanceNanos(senderPkBytes)
		require.Equal(t, senderOldDESOBalanceNanos-feeNanos+uint64(50), senderNewDESOBalanceNanos)

		// sender stakes + unstakes 50 $DESO nanos with m0.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(50),
		}
		_, err = _submitStakeTxn(
			testMeta, senderPkString, senderPrivString, stakeMetadata, nil, true,
		)
		require.NoError(t, err)
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(50),
		}
		_, err = _submitUnstakeTxn(
			testMeta, senderPkString, senderPrivString, unstakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender tries to unlock all stake from m0 using the DerivedKey. Errors.
		unlockStakeMetadata = &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   currentEpochNumber,
			EndEpochNumber:     currentEpochNumber,
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorUnlockStakeTransactionSpendingLimitNotFound)
	}
	{
		// sender stakes, unstakes, and unlocks stake using a DerivedKey scoped to any validator.

		// sender creates a DerivedKey that can stake, unstake, and unlock stake with any validator.
		stakeLimitKey := MakeStakeLimitKey(&ZeroPKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			StakeLimitMap:       map[StakeLimitKey]*uint256.Int{stakeLimitKey: uint256.NewInt().SetUint64(50)},
			UnstakeLimitMap:     map[StakeLimitKey]*uint256.Int{stakeLimitKey: uint256.NewInt().SetUint64(50)},
			UnlockStakeLimitMap: map[StakeLimitKey]uint64{stakeLimitKey: 2},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.NoError(t, err)

		// sender stakes with m0 using the DerivedKey.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(25),
		}
		_, err = _submitStakeTxn(
			testMeta, senderPkString, senderPrivString, stakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender stakes with m1 using the DerivedKey.
		stakeMetadata = &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(25),
		}
		_, err = _submitStakeTxn(
			testMeta, senderPkString, senderPrivString, stakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender unstakes from m0 using the DerivedKey.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(25),
		}
		_, err = _submitUnstakeTxn(
			testMeta, senderPkString, senderPrivString, unstakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender unstakes from m1 using the DerivedKey.
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(25),
		}
		_, err = _submitUnstakeTxn(
			testMeta, senderPkString, senderPrivString, unstakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender unlocks stake from m0 using the DerivedKey.
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   currentEpochNumber,
			EndEpochNumber:     currentEpochNumber,
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.NoError(t, err)

		// sender unlocks stake from m1 using the DerivedKey.
		unlockStakeMetadata = &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StartEpochNumber:   currentEpochNumber,
			EndEpochNumber:     currentEpochNumber,
		}
		_, err = _submitStakeTxnWithDerivedKey(
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
		_, err = _submitStakeTxn(
			testMeta, senderPkString, senderPrivString, stakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender stakes with m1 using the DerivedKey.
		stakeMetadata = &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(25),
		}
		_, err = _submitStakeTxn(
			testMeta, senderPkString, senderPrivString, stakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender unstakes from m0 using the DerivedKey.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(25),
		}
		_, err = _submitUnstakeTxn(
			testMeta, senderPkString, senderPrivString, unstakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender unstakes from m1 using the DerivedKey.
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(25),
		}
		_, err = _submitUnstakeTxn(
			testMeta, senderPkString, senderPrivString, unstakeMetadata, nil, true,
		)
		require.NoError(t, err)

		// sender unlocks stake from m0 using the DerivedKey.
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   currentEpochNumber,
			EndEpochNumber:     currentEpochNumber,
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.NoError(t, err)

		// sender unlocks stake from m1 using the DerivedKey.
		unlockStakeMetadata = &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StartEpochNumber:   currentEpochNumber,
			EndEpochNumber:     currentEpochNumber,
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.NoError(t, err)
	}
	{
		// sender exhausts a TransactionSpendingLimit scoped to a single validator.
		// We fall back to check if there is a TransactionSpendingLimit scoped to
		// any validator to cover their staking + unstaking + unlocking stake txns.

		// sender creates a DerivedKey to stake, unstake, and unlock stake with m1 or any validator.
		scopedStakeLimitKey := MakeStakeLimitKey(m1PKID)
		globalStakeLimitKey := MakeStakeLimitKey(&ZeroPKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			StakeLimitMap: map[StakeLimitKey]*uint256.Int{
				scopedStakeLimitKey: uint256.NewInt().SetUint64(100),
				globalStakeLimitKey: uint256.NewInt().SetUint64(200),
			},
			UnstakeLimitMap: map[StakeLimitKey]*uint256.Int{
				scopedStakeLimitKey: uint256.NewInt().SetUint64(100),
				globalStakeLimitKey: uint256.NewInt().SetUint64(200),
			},
			UnlockStakeLimitMap: map[StakeLimitKey]uint64{scopedStakeLimitKey: 1, globalStakeLimitKey: 1},
		}
		derivedKeyPriv, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.NoError(t, err)

		// sender stakes with m1 using the global TransactionSpendingLimit.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(200),
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: stakeMetadata},
		)
		require.NoError(t, err)

		// sender unstakes from m1 using the global TransactionSpendingLimit.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(200),
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unstakeMetadata},
		)
		require.NoError(t, err)

		// sender unlocks stake from m1 using the scoped TransactionSpendingLimit.
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StartEpochNumber:   currentEpochNumber,
			EndEpochNumber:     currentEpochNumber,
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.NoError(t, err)

		// sender stakes with m1 using the scoped TransactionSpendingLimit.
		stakeMetadata = &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(100),
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: stakeMetadata},
		)
		require.NoError(t, err)

		// sender unstakes from m1 using the scoped TransactionSpendingLimit.
		unstakeMetadata = &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(100),
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unstakeMetadata},
		)
		require.NoError(t, err)

		// sender unlocks stake from m1 using the global TransactionSpendingLimit.
		unlockStakeMetadata = &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m1PkBytes),
			StartEpochNumber:   currentEpochNumber,
			EndEpochNumber:     currentEpochNumber,
		}
		_, err = _submitStakeTxnWithDerivedKey(
			senderPkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: unlockStakeMetadata},
		)
		require.NoError(t, err)
	}
	{
		// Test TransactionSpendingLimit.ToMetamaskString() scoped to one validator.
		stakeLimitKey1 := MakeStakeLimitKey(m0PKID)
		stakeLimitKey2 := MakeStakeLimitKey(m1PKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			StakeLimitMap: map[StakeLimitKey]*uint256.Int{
				stakeLimitKey1: uint256.NewInt().SetUint64(uint64(1.5 * float64(NanosPerUnit))),
				stakeLimitKey2: uint256.NewInt().SetUint64(uint64(2.0 * float64(NanosPerUnit))),
			},
			UnstakeLimitMap: map[StakeLimitKey]*uint256.Int{
				stakeLimitKey1: uint256.NewInt().SetUint64(uint64(3.25 * float64(NanosPerUnit))),
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
				"\t\t\tStaking Limit: 1.50 $DESO\n"+
				"\t\t]\n"+
				"\t\t[\n"+
				"\t\t\tValidator PKID: "+m1Pub+"\n"+
				"\t\t\tStaking Limit: 2.00 $DESO\n"+
				"\t\t]\n"+
				"\tUnstaking Restrictions:\n"+
				"\t\t[\n"+
				"\t\t\tValidator PKID: "+m0Pub+"\n"+
				"\t\t\tUnstaking Limit: 3.25 $DESO\n"+
				"\t\t]\n"+
				"\tUnlocking Stake Restrictions:\n"+
				"\t\t[\n"+
				"\t\t\tValidator PKID: "+m0Pub+"\n"+
				"\t\t\tTransaction Count: 2\n"+
				"\t\t]\n"+
				"\t\t[\n"+
				"\t\t\tValidator PKID: "+m1Pub+"\n"+
				"\t\t\tTransaction Count: 3\n"+
				"\t\t]\n",
		)
	}
	{
		// Test TransactionSpendingLimit.ToMetamaskString() scoped to any validator.
		stakeLimitKey := MakeStakeLimitKey(&ZeroPKID)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			StakeLimitMap: map[StakeLimitKey]*uint256.Int{
				stakeLimitKey: uint256.NewInt().SetUint64(uint64(0.65 * float64(NanosPerUnit))),
			},
			UnstakeLimitMap: map[StakeLimitKey]*uint256.Int{
				stakeLimitKey: uint256.NewInt().SetUint64(uint64(2.1 * float64(NanosPerUnit))),
			},
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
				"\t\t\tStaking Limit: 0.65 $DESO\n"+
				"\t\t]\n"+
				"\tUnstaking Restrictions:\n"+
				"\t\t[\n"+
				"\t\t\tValidator PKID: Any\n"+
				"\t\t\tUnstaking Limit: 2.10 $DESO\n"+
				"\t\t]\n"+
				"\tUnlocking Stake Restrictions:\n"+
				"\t\t[\n"+
				"\t\t\tValidator PKID: Any\n"+
				"\t\t\tTransaction Count: 1\n"+
				"\t\t]\n",
		)
	}

	// Flush mempool to the db and test rollbacks.
	require.NoError(t, mempool.universalUtxoView.FlushToDb(blockHeight))
	_executeAllTestRollbackAndFlush(testMeta)
}

func TestGetTopStakesByStakeAmount(t *testing.T) {
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	t.Run("flushToDB=false", func(t *testing.T) {
		_testGetTopStakesByStakeAmount(t, false)
	})
	t.Run("flushToDB=true", func(t *testing.T) {
		_testGetTopStakesByStakeAmount(t, true)
	})
}

func _testGetTopStakesByStakeAmount(t *testing.T, flushToDB bool) {
	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize PoS fork height.
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

	// Mine a few blocks to give the senderPkString some money.
	for ii := 0; ii < 10; ii++ {
		_, err := miner.MineAndProcessSingleBlock(0, mempool)
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

	// Helper utils
	utxoView := func() *UtxoView {
		newUtxoView, err := mempool.GetAugmentedUniversalView()
		require.NoError(t, err)
		return newUtxoView
	}

	constructAndSubmitRegisterValidatorTxn := func(validatorPk string, validatorPriv string, validatorPkBytes []byte, domain string) {
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, validatorPkBytes)
		registerAsValidatorMetadata := &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte(domain)},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		_, err := _submitRegisterAsValidatorTxn(testMeta, validatorPk, validatorPriv, registerAsValidatorMetadata, nil, flushToDB)
		require.NoError(t, err)
	}

	constructAndSubmitStakeTxn := func(stakerPk string, stakerPriv string, validatorPkBytes []byte, amountNanos uint64) {
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(validatorPkBytes),
			RewardMethod:       StakingRewardMethodPayToBalance,
			StakeAmountNanos:   uint256.NewInt().SetUint64(amountNanos),
		}
		_, err := _submitStakeTxn(testMeta, stakerPk, stakerPriv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)
	}

	{
		// m0 and m1 register as validators.
		constructAndSubmitRegisterValidatorTxn(m0Pub, m0Priv, m0PkBytes, "https://example.com")
		constructAndSubmitRegisterValidatorTxn(m1Pub, m1Priv, m1PkBytes, "https://example2.com")
	}

	// Cache the validator set for easy access.
	validatorPKIDs := []*PKID{m0PKID, m1PKID}

	{
		// m0 stakes 100 nanos to themselves.
		constructAndSubmitStakeTxn(m0Pub, m0Priv, m0PkBytes, 100)
		// m0 stakes 200 nanos to m1.
		constructAndSubmitStakeTxn(m0Pub, m0Priv, m1PkBytes, 200)

		// m1 stakes 110 nanos to m0.
		constructAndSubmitStakeTxn(m1Pub, m1Priv, m0PkBytes, 110)
		// m1 stakes 210 nanos to themselves.
		constructAndSubmitStakeTxn(m1Pub, m1Priv, m1PkBytes, 210)

		// m2 stakes 120 nanos to m0.
		constructAndSubmitStakeTxn(m2Pub, m2Priv, m0PkBytes, 120)
		// m2 stakes 220 nanos to m1.
		constructAndSubmitStakeTxn(m2Pub, m2Priv, m1PkBytes, 220)

		// m3 stakes 130 nanos to m0.
		constructAndSubmitStakeTxn(m3Pub, m3Priv, m0PkBytes, 130)
		// m3 stakes 230 nanos to m1.
		constructAndSubmitStakeTxn(m3Pub, m3Priv, m1PkBytes, 230)

		// m4 stakes 100 nanos to m0.
		constructAndSubmitStakeTxn(m4Pub, m4Priv, m0PkBytes, 100)
		// m4 stakes 200 nanos to m1.
		constructAndSubmitStakeTxn(m4Pub, m4Priv, m1PkBytes, 200)
	}

	{
		// Verify when query limit 3 is lower than number of stake entries 10.

		topStakeEntries, err := utxoView().GetTopStakesForValidatorsByStakeAmount(validatorPKIDs, 3)
		require.NoError(t, err)
		require.Equal(t, 3, len(topStakeEntries))
	}

	{
		// Verify when query limit 1000 is higher than number of stake entries 10.

		topStakeEntries, err := utxoView().GetTopStakesForValidatorsByStakeAmount(validatorPKIDs, 1000)
		require.NoError(t, err)
		require.Equal(t, 10, len(topStakeEntries))
	}

	{
		// Verify ordering of top 5 stake entries, which includes breaking ties.

		topStakeEntries, err := utxoView().GetTopStakesForValidatorsByStakeAmount(validatorPKIDs, 6)
		require.NoError(t, err)
		require.Equal(t, 6, len(topStakeEntries))

		require.Equal(t, uint64(230), topStakeEntries[0].StakeAmountNanos.Uint64())
		require.True(t, bytes.Equal(m1PKID.ToBytes(), topStakeEntries[0].ValidatorPKID.ToBytes()))
		require.True(t, bytes.Equal(m3PKID.ToBytes(), topStakeEntries[0].StakerPKID.ToBytes()))

		require.Equal(t, uint64(220), topStakeEntries[1].StakeAmountNanos.Uint64())
		require.True(t, bytes.Equal(m1PKID.ToBytes(), topStakeEntries[1].ValidatorPKID.ToBytes()))
		require.True(t, bytes.Equal(m2PKID.ToBytes(), topStakeEntries[1].StakerPKID.ToBytes()))

		require.Equal(t, uint64(210), topStakeEntries[2].StakeAmountNanos.Uint64())
		require.True(t, bytes.Equal(m1PKID.ToBytes(), topStakeEntries[2].ValidatorPKID.ToBytes()))
		require.True(t, bytes.Equal(m1PKID.ToBytes(), topStakeEntries[2].StakerPKID.ToBytes()))

		require.Equal(t, uint64(200), topStakeEntries[3].StakeAmountNanos.Uint64())
		require.True(t, bytes.Equal(m1PKID.ToBytes(), topStakeEntries[3].ValidatorPKID.ToBytes()))
		require.True(t, bytes.Equal(m0PKID.ToBytes(), topStakeEntries[3].StakerPKID.ToBytes()))

		require.Equal(t, uint64(200), topStakeEntries[4].StakeAmountNanos.Uint64())
		require.True(t, bytes.Equal(m1PKID.ToBytes(), topStakeEntries[4].ValidatorPKID.ToBytes()))
		require.True(t, bytes.Equal(m4PKID.ToBytes(), topStakeEntries[4].StakerPKID.ToBytes()))

		require.Equal(t, uint64(130), topStakeEntries[5].StakeAmountNanos.Uint64())
		require.True(t, bytes.Equal(m0PKID.ToBytes(), topStakeEntries[5].ValidatorPKID.ToBytes()))
		require.True(t, bytes.Equal(m3PKID.ToBytes(), topStakeEntries[5].StakerPKID.ToBytes()))
	}
}

func TestGetLockedStakeEntriesInRange(t *testing.T) {
	// For this test, we manually place LockedStakeEntries in the database and
	// UtxoView to test merging the two to GetLockedStakeEntriesInRange.

	// Initialize test chain and UtxoView.
	chain, params, db := NewLowDifficultyBlockchain(t)
	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
	require.NoError(t, err)
	blockHeight := uint64(chain.blockTip().Height + 1)

	m0PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m0PkBytes).PKID
	m1PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m1PkBytes).PKID

	// Set a LockedStakeEntry in the db.
	lockedStakeEntry := &LockedStakeEntry{
		ValidatorPKID:       m0PKID,
		StakerPKID:          m0PKID,
		LockedAtEpochNumber: 1,
	}
	utxoView._setLockedStakeEntryMappings(lockedStakeEntry)
	require.NoError(t, utxoView.FlushToDb(blockHeight))

	// Verify LockedStakeEntry is in the db.
	lockedStakeEntry, err = DBGetLockedStakeEntry(db, chain.snapshot, m0PKID, m0PKID, 1)
	require.NoError(t, err)
	require.NotNil(t, lockedStakeEntry)

	// Verify LockedStakeEntry is not in the UtxoView.
	require.Empty(t, utxoView.LockedStakeMapKeyToLockedStakeEntry)

	// Set another LockedStakeEntry in the db.
	lockedStakeEntry = &LockedStakeEntry{
		ValidatorPKID:       m0PKID,
		StakerPKID:          m0PKID,
		LockedAtEpochNumber: 2,
	}
	utxoView._setLockedStakeEntryMappings(lockedStakeEntry)
	require.NoError(t, utxoView.FlushToDb(blockHeight))

	// Fetch the LockedStakeEntry, so it is also cached in the UtxoView.
	lockedStakeEntry, err = utxoView.GetLockedStakeEntry(m0PKID, m0PKID, 2)
	require.NoError(t, err)
	require.NotNil(t, lockedStakeEntry)

	// Verify the LockedStakeEntry is in the db.
	lockedStakeEntry, err = DBGetLockedStakeEntry(db, chain.snapshot, m0PKID, m0PKID, 2)
	require.NoError(t, err)
	require.NotNil(t, lockedStakeEntry)

	// Verify the LockedStakeEntry is also in the UtxoView.
	require.Len(t, utxoView.LockedStakeMapKeyToLockedStakeEntry, 1)
	require.NotNil(t, utxoView.LockedStakeMapKeyToLockedStakeEntry[lockedStakeEntry.ToMapKey()])

	// Set another LockedStakeEntry in the UtxoView.
	utxoViewLockedStakeEntry := &LockedStakeEntry{
		ValidatorPKID:       m0PKID,
		StakerPKID:          m0PKID,
		LockedAtEpochNumber: 3,
	}
	utxoView._setLockedStakeEntryMappings(utxoViewLockedStakeEntry)

	// Verify the LockedStakeEntry is not in the db.
	lockedStakeEntry, err = DBGetLockedStakeEntry(db, chain.snapshot, m0PKID, m0PKID, 3)
	require.NoError(t, err)
	require.Nil(t, lockedStakeEntry)

	// Verify the LockedStakeEntry is in the UtxoView.
	require.Len(t, utxoView.LockedStakeMapKeyToLockedStakeEntry, 2)
	require.NotNil(t, utxoView.LockedStakeMapKeyToLockedStakeEntry[utxoViewLockedStakeEntry.ToMapKey()])

	// Verify GetLockedStakeEntriesInRange.
	lockedStakeEntries, err := utxoView.GetLockedStakeEntriesInRange(m0PKID, m0PKID, 1, 3)
	require.NoError(t, err)
	require.Len(t, lockedStakeEntries, 3)
	require.Equal(t, lockedStakeEntries[0].LockedAtEpochNumber, uint64(1))
	require.Equal(t, lockedStakeEntries[1].LockedAtEpochNumber, uint64(2))
	require.Equal(t, lockedStakeEntries[2].LockedAtEpochNumber, uint64(3))

	// A few more edge case tests for GetLockedStakeEntriesInRange.
	lockedStakeEntries, err = utxoView.GetLockedStakeEntriesInRange(m0PKID, m0PKID, 0, 4)
	require.NoError(t, err)
	require.Len(t, lockedStakeEntries, 3)

	// Nil ValidatorPKID.
	lockedStakeEntries, err = utxoView.GetLockedStakeEntriesInRange(nil, m0PKID, 1, 3)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil ValidatorPKID provided as input")

	// Nil StakerPKID.
	lockedStakeEntries, err = utxoView.GetLockedStakeEntriesInRange(m0PKID, nil, 1, 3)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil StakerPKID provided as input")

	// StartEpochNumber > EndEpochNumber.
	lockedStakeEntries, err = utxoView.GetLockedStakeEntriesInRange(m0PKID, m0PKID, 3, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid LockedAtEpochNumber range provided as input")

	// None found for this ValidatorPKID.
	lockedStakeEntries, err = utxoView.GetLockedStakeEntriesInRange(m1PKID, m0PKID, 1, 3)
	require.NoError(t, err)
	require.Empty(t, lockedStakeEntries)

	// None found for this StakerPKID.
	lockedStakeEntries, err = utxoView.GetLockedStakeEntriesInRange(m0PKID, m1PKID, 1, 3)
	require.NoError(t, err)
	require.Empty(t, lockedStakeEntries)

	// None found for this LockedAtEpochNumber range.
	lockedStakeEntries, err = utxoView.GetLockedStakeEntriesInRange(m0PKID, m0PKID, 5, 6)
	require.NoError(t, err)
	require.Empty(t, lockedStakeEntries)
}

func TestStakeLockupEpochDuration(t *testing.T) {
	var err error

	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize fork heights.
	params.ForkHeights.DeSoUnlimitedDerivedKeysBlockHeight = uint32(0)
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	chain.snapshot = nil

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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 1e3)

	m0PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m0PkBytes).PKID

	newUtxoView := func() *UtxoView {
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
		require.NoError(t, err)
		return utxoView
	}

	// Seed a CurrentEpochEntry.
	epochUtxoView := newUtxoView()
	epochUtxoView._setCurrentEpochEntry(&EpochEntry{EpochNumber: 1, FinalBlockHeight: blockHeight + 10})
	require.NoError(t, epochUtxoView.FlushToDb(blockHeight))
	currentEpochNumber, err := newUtxoView().GetCurrentEpochNumber()
	require.NoError(t, err)

	{
		// ParamUpdater set MinFeeRateNanos and StakeLockupEpochDuration=3.
		params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true
		_updateGlobalParamsEntryWithExtraData(
			testMeta,
			testMeta.feeRateNanosPerKb,
			paramUpdaterPub,
			paramUpdaterPriv,
			map[string][]byte{StakeLockupEpochDurationKey: UintToBuf(3)},
		)
	}
	{
		// m0 registers as a validator.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, m0PkBytes)
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte("https://m1.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, nil, true)
		require.NoError(t, err)

		validatorEntry, err := newUtxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
	}
	{
		// m0 stakes with himself.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(100),
		}
		_, err = _submitStakeTxn(testMeta, m0Pub, m0Priv, stakeMetadata, nil, true)
		require.NoError(t, err)

		stakeEntry, err := newUtxoView().GetStakeEntry(m0PKID, m0PKID)
		require.NoError(t, err)
		require.NotNil(t, stakeEntry)
		require.Equal(t, stakeEntry.StakeAmountNanos, uint256.NewInt().SetUint64(100))
	}
	{
		// m0 unstakes from himself.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(100),
		}
		_, err = _submitUnstakeTxn(testMeta, m0Pub, m0Priv, unstakeMetadata, nil, true)
		require.NoError(t, err)

		stakeEntry, err := newUtxoView().GetStakeEntry(m0PKID, m0PKID)
		require.NoError(t, err)
		require.Nil(t, stakeEntry)

		lockedStakeEntry, err := newUtxoView().GetLockedStakeEntry(m0PKID, m0PKID, currentEpochNumber)
		require.NoError(t, err)
		require.NotNil(t, lockedStakeEntry)
		require.Equal(t, lockedStakeEntry.LockedAmountNanos, uint256.NewInt().SetUint64(100))
	}
	{
		// RuleErrorInvalidUnlockStakeMustWaitLockupDuration
		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   currentEpochNumber,
			EndEpochNumber:     currentEpochNumber,
		}
		_, err = _submitUnlockStakeTxn(testMeta, m0Pub, m0Priv, unlockStakeMetadata, nil, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorInvalidUnlockStakeMustWaitLockupDuration)
	}
	{
		// Simulate three epochs passing by seeding a new CurrentEpochEntry.
		// Note that we can't test the disconnect logic after these tests
		// since we have updated the CurrentEpochNumber.
		epochUtxoView = newUtxoView()
		epochUtxoView._setCurrentEpochEntry(
			&EpochEntry{EpochNumber: currentEpochNumber + 3, FinalBlockHeight: blockHeight + 10},
		)
		// Also store a SnapshotGlobalParamsEntry in the db.
		epochUtxoView._setSnapshotGlobalParamsEntry(&GlobalParamsEntry{}, currentEpochNumber+1)
		require.NoError(t, epochUtxoView.FlushToDb(blockHeight))
		currentEpochNumber, err = newUtxoView().GetCurrentEpochNumber()
		require.NoError(t, err)
	}
	{
		// m0 unlocks his stake.
		oldDesoBalanceNanos, err := newUtxoView().GetDeSoBalanceNanosForPublicKey(m0PkBytes)
		require.NoError(t, err)

		unlockStakeMetadata := &UnlockStakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StartEpochNumber:   currentEpochNumber - 3,
			EndEpochNumber:     currentEpochNumber - 3,
		}
		feeNanos, err := _submitUnlockStakeTxn(testMeta, m0Pub, m0Priv, unlockStakeMetadata, nil, true)
		require.NoError(t, err)

		lockedStakeEntry, err := newUtxoView().GetLockedStakeEntry(m0PKID, m0PKID, currentEpochNumber-2)
		require.NoError(t, err)
		require.Nil(t, lockedStakeEntry)

		newDesoBalanceNanos, err := newUtxoView().GetDeSoBalanceNanosForPublicKey(m0PkBytes)
		require.NoError(t, err)
		require.Equal(t, oldDesoBalanceNanos-feeNanos+uint64(100), newDesoBalanceNanos)
	}
}

func TestStakingToJailedValidator(t *testing.T) {
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	t.Run("flushToDB=false", func(t *testing.T) {
		testStakingToJailedValidator(t, false)
	})
	t.Run("flushToDB=true", func(t *testing.T) {
		testStakingToJailedValidator(t, true)
	})
}

func testStakingToJailedValidator(t *testing.T, flushToDB bool) {
	var err error

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize PoS fork heights.
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	chain.snapshot = nil

	// For these tests, we set ValidatorJailEpochDuration to 0.
	params.DefaultValidatorJailEpochDuration = 0

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

	// Helper utils
	utxoView := func() *UtxoView {
		newUtxoView, err := mempool.GetAugmentedUniversalView()
		require.NoError(t, err)
		return newUtxoView
	}

	jailValidator := func(validatorPKID *PKID) {
		// Retrieve current ValidatorEntry.
		validatorEntry, err := utxoView().GetValidatorByPKID(validatorPKID)
		require.NoError(t, err)

		// Jail the validator.
		tmpUtxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
		require.NoError(t, err)
		require.NoError(t, tmpUtxoView.JailValidator(validatorEntry))
		require.NoError(t, tmpUtxoView.FlushToDb(blockHeight))

		// Delete the ValidatorEntry and GlobalActiveStakeAmountNanos
		// from the UtxoView so that they are next read from the db.
		delete(mempool.universalUtxoView.ValidatorPKIDToValidatorEntry, *validatorPKID)
		delete(mempool.readOnlyUtxoView.ValidatorPKIDToValidatorEntry, *validatorPKID)
	}

	// Seed a CurrentEpochEntry.
	epochUtxoView := utxoView()
	epochUtxoView._setCurrentEpochEntry(&EpochEntry{EpochNumber: 1, FinalBlockHeight: blockHeight + 10})
	require.NoError(t, epochUtxoView.FlushToDb(blockHeight))

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
			Domains:             [][]byte{[]byte("https://m0.example.com")},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, m0Pub, m0Priv, registerMetadata, nil, flushToDB)
		require.NoError(t, err)
	}
	{
		// m1 stakes with m0. m0 is active.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(150),
		}
		_, err = _submitStakeTxn(testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// m0 TotalStakeAmountNanos increases.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(150))
	}
	{
		// m1 unstakes some from m0. m0 is active.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(50),
		}
		_, err = _submitUnstakeTxn(testMeta, m1Pub, m1Priv, unstakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// m0 TotalStakeAmountNanos decreases.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))
	}
	{
		// Jail m0. Since this update takes place outside a transaction,
		// we cannot test rollbacks. We will run into an error where m0
		// is trying to unjail himself, but he was never jailed.
		jailValidator(m0PKID)

		// Verify m0 is jailed.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.Status(), ValidatorStatusJailed)

		// m0 TotalStakeAmountNanos stays the same.
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))
	}
	{
		// m1 stakes more with m0. m0 is jailed.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(50),
		}
		_, err = _submitStakeTxn(testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// m0 TotalStakeAmountNanos increases.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(150))
	}
	{
		// m1 unstakes some from m0. m0 is jailed.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(50),
		}
		_, err = _submitUnstakeTxn(testMeta, m1Pub, m1Priv, unstakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// m0 TotalStakeAmountNanos decreases.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))
	}
	{
		// m0 unjails himself.
		_, err = _submitUnjailValidatorTxn(testMeta, m0Pub, m0Priv, nil, flushToDB)
		require.NoError(t, err)

		// m0 TotalStakeAmountNanos stays the same.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))
	}
	{
		// m1 stakes more with m0. m0 is active.
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(50),
		}
		_, err = _submitStakeTxn(testMeta, m1Pub, m1Priv, stakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// m0 TotalStakeAmountNanos increases.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(150))
	}
	{
		// m1 unstakes some from m0. m0 is active.
		unstakeMetadata := &UnstakeMetadata{
			ValidatorPublicKey: NewPublicKey(m0PkBytes),
			UnstakeAmountNanos: uint256.NewInt().SetUint64(50),
		}
		_, err = _submitUnstakeTxn(testMeta, m1Pub, m1Priv, unstakeMetadata, nil, flushToDB)
		require.NoError(t, err)

		// m0 TotalStakeAmountNanos decreases.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))
	}
	{
		// Jail m0 again. Since this update takes place outside a transaction,
		// we cannot test rollbacks. We will run into an error where m0 is
		// trying to unjail himself, but he was never jailed.
		jailValidator(m0PKID)

		// m0 TotalStakeAmountNanos stays the same.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))
	}
	{
		// m0 unregisters as a validator.
		_, err = _submitUnregisterAsValidatorTxn(testMeta, m0Pub, m0Priv, flushToDB)
		require.NoError(t, err)

		// m0's ValidatorEntry is deleted.
		validatorEntry, err := utxoView().GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Nil(t, validatorEntry)
	}
}
