//go:build relic

package lib

import (
	"fmt"
	"testing"

	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestIsLastBlockInCurrentEpoch(t *testing.T) {
	var isLastBlockInCurrentEpoch bool

	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)

	// Initialize PoS fork heights.
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
	require.NoError(t, err)

	// The BlockHeight is before the PoS snapshotting fork height.
	isLastBlockInCurrentEpoch, err = utxoView.IsLastBlockInCurrentEpoch(0)
	require.NoError(t, err)
	require.False(t, isLastBlockInCurrentEpoch)

	// The BlockHeight is equal to the PoS snapshotting fork height.
	isLastBlockInCurrentEpoch, err = utxoView.IsLastBlockInCurrentEpoch(1)
	require.NoError(t, err)
	require.True(t, isLastBlockInCurrentEpoch)

	// Seed a CurrentEpochEntry.
	utxoView._setCurrentEpochEntry(&EpochEntry{EpochNumber: 1, FinalBlockHeight: 5})
	require.NoError(t, utxoView.FlushToDb(1))

	// The CurrentBlockHeight != CurrentEpochEntry.FinalBlockHeight.
	isLastBlockInCurrentEpoch, err = utxoView.IsLastBlockInCurrentEpoch(4)
	require.NoError(t, err)
	require.False(t, isLastBlockInCurrentEpoch)

	// The CurrentBlockHeight == CurrentEpochEntry.FinalBlockHeight.
	isLastBlockInCurrentEpoch, err = utxoView.IsLastBlockInCurrentEpoch(5)
	require.NoError(t, err)
	require.True(t, isLastBlockInCurrentEpoch)
}

func TestRunEpochCompleteHook(t *testing.T) {

	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForEpochCompleteTest(t)

	_registerOrTransferWithTestMeta(testMeta, "m0", senderPkString, m0Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m1", senderPkString, m1Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m2", senderPkString, m2Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m3", senderPkString, m3Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m4", senderPkString, m4Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m5", senderPkString, m5Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m6", senderPkString, m6Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 1e3)

	m0PKID := DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m0PkBytes).PKID
	m1PKID := DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m1PkBytes).PKID
	m2PKID := DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m2PkBytes).PKID
	m3PKID := DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m3PkBytes).PKID
	m4PKID := DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m4PkBytes).PKID
	m5PKID := DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m5PkBytes).PKID
	m6PKID := DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m6PkBytes).PKID

	validatorPKIDs := []*PKID{m0PKID, m1PKID, m2PKID, m3PKID, m4PKID, m5PKID, m6PKID}

	blockHeight := uint64(testMeta.chain.blockTip().Height) + 1
	incrBlockHeight := func() uint64 {
		blockHeight += 1
		return blockHeight
	}

	// Seed a CurrentEpochEntry.
	tmpUtxoView := _newUtxoView(testMeta)
	tmpUtxoView._setCurrentEpochEntry(&EpochEntry{EpochNumber: 0, FinalBlockHeight: blockHeight + 1})
	require.NoError(t, tmpUtxoView.FlushToDb(blockHeight))

	// For these tests, we set each epoch duration to only one block.
	testMeta.params.DefaultEpochDurationNumBlocks = uint64(1)

	// We set the default staking rewards APY to 10%
	testMeta.params.DefaultStakingRewardsAPYBasisPoints = uint64(1000)

	{
		// ParamUpdater set MinFeeRateNanos, ValidatorJailEpochDuration,
		// and JailInactiveValidatorGracePeriodEpochs.
		testMeta.params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true
		require.Zero(t, _newUtxoView(testMeta).GlobalParamsEntry.MinimumNetworkFeeNanosPerKB)
		require.Zero(t, _newUtxoView(testMeta).GlobalParamsEntry.ValidatorJailEpochDuration)

		_updateGlobalParamsEntryWithExtraData(
			testMeta,
			testMeta.feeRateNanosPerKb,
			paramUpdaterPub,
			paramUpdaterPriv,
			map[string][]byte{
				ValidatorJailEpochDurationKey:             UintToBuf(4),
				JailInactiveValidatorGracePeriodEpochsKey: UintToBuf(10),
			},
		)

		require.Equal(t, _newUtxoView(testMeta).GlobalParamsEntry.MinimumNetworkFeeNanosPerKB, testMeta.feeRateNanosPerKb)
		require.Equal(t, _newUtxoView(testMeta).GlobalParamsEntry.ValidatorJailEpochDuration, uint64(4))

		// We need to reset the UniversalUtxoView since the RegisterAsValidator and Stake
		// txn test helper utils use and flush the UniversalUtxoView. Otherwise, the
		// updated GlobalParamsEntry will be overwritten by the default one cached in
		// the UniversalUtxoView when it is flushed.
		testMeta.mempool.universalUtxoView._ResetViewMappingsAfterFlush()
	}
	{
		// Test the state of the snapshots prior to running our first OnEpochCompleteHook.

		// Test CurrentEpochNumber.
		currentEpochNumber, err := _newUtxoView(testMeta).GetCurrentEpochNumber()
		require.NoError(t, err)
		require.Equal(t, currentEpochNumber, uint64(0))

		// Test SnapshotGlobalParamsEntry is non-nil and contains the default values.
		snapshotGlobalParamsEntry, err := _newUtxoView(testMeta).GetSnapshotGlobalParamsEntry()
		require.NoError(t, err)
		require.NotNil(t, snapshotGlobalParamsEntry)
		require.Equal(t, snapshotGlobalParamsEntry.ValidatorJailEpochDuration, uint64(3))

		_assertEmptyValidatorSnapshots(testMeta)

		_assertEmptyStakeSnapshots(testMeta)
	}
	{
		// Test RunOnEpochCompleteHook() with no validators or stakers.
		_runOnEpochCompleteHook(testMeta, incrBlockHeight())
	}
	{
		// Test the state of the snapshots after running our first OnEpochCompleteHook
		// but with no existing validators or stakers.

		// Test CurrentEpochNumber.
		currentEpochNumber, err := _newUtxoView(testMeta).GetCurrentEpochNumber()
		require.NoError(t, err)
		require.Equal(t, currentEpochNumber, uint64(1))

		// Test SnapshotGlobalParamsEntry is nil.
		snapshotGlobalParamsEntry, err := _newUtxoView(testMeta).GetSnapshotGlobalParamsEntry()
		require.NoError(t, err)
		require.NotNil(t, snapshotGlobalParamsEntry)
		require.Equal(t, _newUtxoView(testMeta).GlobalParamsEntry.MinimumNetworkFeeNanosPerKB, testMeta.feeRateNanosPerKb)
		require.Equal(t, snapshotGlobalParamsEntry.ValidatorJailEpochDuration, uint64(4))

		_assertEmptyValidatorSnapshots(testMeta)

		_assertEmptyStakeSnapshots(testMeta)
	}
	{
		// All validators register + stake to themselves.
		_registerValidatorAndStake(testMeta, m0Pub, m0Priv, 100, false)
		_registerValidatorAndStake(testMeta, m1Pub, m1Priv, 200, false)
		_registerValidatorAndStake(testMeta, m2Pub, m2Priv, 300, false)
		_registerValidatorAndStake(testMeta, m3Pub, m3Priv, 400, false)
		_registerValidatorAndStake(testMeta, m4Pub, m4Priv, 500, false)
		_registerValidatorAndStake(testMeta, m5Pub, m5Priv, 600, false)
		_registerValidatorAndStake(testMeta, m6Pub, m6Priv, 700, false)

		validatorEntries, err := _newUtxoView(testMeta).GetTopActiveValidatorsByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 7)

		stakeEntries, err := _newUtxoView(testMeta).GetTopStakesByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, stakeEntries, 7)
	}
	{
		// Test RunOnEpochCompleteHook().
		_runOnEpochCompleteHook(testMeta, incrBlockHeight())
	}
	{
		// Test CurrentEpochNumber.
		currentEpochNumber, err := _newUtxoView(testMeta).GetCurrentEpochNumber()
		require.NoError(t, err)
		require.Equal(t, currentEpochNumber, uint64(2))

		// Test SnapshotGlobalParamsEntry is populated.
		snapshotGlobalParamsEntry, err := _newUtxoView(testMeta).GetSnapshotGlobalParamsEntry()
		require.NoError(t, err)
		require.NotNil(t, snapshotGlobalParamsEntry)
		require.Equal(t, snapshotGlobalParamsEntry.MinimumNetworkFeeNanosPerKB, testMeta.feeRateNanosPerKb)
		require.Equal(t, snapshotGlobalParamsEntry.ValidatorJailEpochDuration, uint64(4))

		_assertEmptyValidatorSnapshots(testMeta)

		_assertEmptyStakeSnapshots(testMeta)
	}
	{
		// Test RunOnEpochCompleteHook().
		_runOnEpochCompleteHook(testMeta, incrBlockHeight())
	}
	{
		// Test CurrentEpochNumber.
		currentEpochNumber, err := _newUtxoView(testMeta).GetCurrentEpochNumber()
		require.NoError(t, err)
		require.Equal(t, currentEpochNumber, uint64(3))

		// Test SnapshotGlobalParamsEntry is populated.
		snapshotGlobalParamsEntry, err := _newUtxoView(testMeta).GetSnapshotGlobalParamsEntry()
		require.NoError(t, err)
		require.NotNil(t, snapshotGlobalParamsEntry)
		require.Equal(t, snapshotGlobalParamsEntry.MinimumNetworkFeeNanosPerKB, testMeta.feeRateNanosPerKb)
		require.Equal(t, snapshotGlobalParamsEntry.ValidatorJailEpochDuration, uint64(4))

		// Test SnapshotValidatorByPKID is populated.
		for _, pkid := range validatorPKIDs {
			snapshotValidatorSetEntry, err := _newUtxoView(testMeta).GetSnapshotValidatorSetEntryByPKID(pkid)
			require.NoError(t, err)
			require.NotNil(t, snapshotValidatorSetEntry)
		}

		// Test GetSnapshotValidatorSetByStakeAmount is populated.
		validatorEntries, err := _newUtxoView(testMeta).GetSnapshotValidatorSetByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 7)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m6PKID)
		require.Equal(t, validatorEntries[6].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt().SetUint64(700))
		require.Equal(t, validatorEntries[6].TotalStakeAmountNanos, uint256.NewInt().SetUint64(100))

		// Test SnapshotValidatorSetTotalStakeAmountNanos is populated.
		snapshotValidatorSetTotalStakeAmountNanos, err := _newUtxoView(testMeta).GetSnapshotValidatorSetTotalStakeAmountNanos()
		require.NoError(t, err)
		require.Equal(t, snapshotValidatorSetTotalStakeAmountNanos, uint256.NewInt().SetUint64(2800))

		// Test SnapshotLeaderSchedule is populated.
		for index := range validatorPKIDs {
			snapshotLeaderScheduleValidator, err := _newUtxoView(testMeta).GetSnapshotLeaderScheduleValidator(uint16(index))
			require.NoError(t, err)
			require.NotNil(t, snapshotLeaderScheduleValidator)
		}

		// Test GetSnapshotStakesToRewardByStakeAmount is populated.
		snapshotStakeEntries, err := _newUtxoView(testMeta).GetSnapshotStakesToRewardByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, snapshotStakeEntries, 7)
		require.Equal(t, snapshotStakeEntries[0].StakerPKID, m6PKID)
		require.Equal(t, snapshotStakeEntries[6].StakerPKID, m0PKID)
		require.Equal(t, snapshotStakeEntries[0].StakeAmountNanos, uint256.NewInt().SetUint64(700))
		require.Equal(t, snapshotStakeEntries[6].StakeAmountNanos, uint256.NewInt().SetUint64(100))
	}
	{
		// Test snapshotting changing stake.

		// m5 has 600 staked.
		validatorEntry, err := _newUtxoView(testMeta).GetValidatorByPKID(m5PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos.Uint64(), uint64(600))

		// m5 stakes another 200.
		_registerValidatorAndStake(testMeta, m5Pub, m5Priv, 200, false)

		// m5 has 800 staked.
		validatorEntry, err = _newUtxoView(testMeta).GetValidatorByPKID(m5PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos.Uint64(), uint64(800))

		// Run OnEpochCompleteHook().
		_runOnEpochCompleteHook(testMeta, incrBlockHeight())

		// Snapshot m5 still has 600 staked.
		validatorEntry, err = _newUtxoView(testMeta).GetSnapshotValidatorSetEntryByPKID(m5PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos.Uint64(), uint64(600))

		snapshotStakeEntries, err := _newUtxoView(testMeta).GetSnapshotStakesToRewardByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, snapshotStakeEntries, 7)
		require.Equal(t, snapshotStakeEntries[1].StakerPKID, m5PKID)
		require.Equal(t, snapshotStakeEntries[1].StakeAmountNanos, uint256.NewInt().SetUint64(600))

		// Run OnEpochCompleteHook().
		_runOnEpochCompleteHook(testMeta, incrBlockHeight())

		// Snapshot m5 now has 800 staked.
		validatorEntry, err = _newUtxoView(testMeta).GetSnapshotValidatorSetEntryByPKID(m5PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos.Uint64(), uint64(800))

		snapshotStakeEntries, err = _newUtxoView(testMeta).GetSnapshotStakesToRewardByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, snapshotStakeEntries, 7)
		require.Equal(t, snapshotStakeEntries[0].StakerPKID, m5PKID)
		require.Equal(t, snapshotStakeEntries[0].StakeAmountNanos, uint256.NewInt().SetUint64(800))
	}
	{
		// Test snapshotting changing GlobalParams.

		// Update StakeLockupEpochDuration from default of 3 to 2.
		snapshotGlobalsParamsEntry, err := _newUtxoView(testMeta).GetSnapshotGlobalParamsEntry()
		require.NoError(t, err)
		require.Equal(t, snapshotGlobalsParamsEntry.StakeLockupEpochDuration, uint64(3))

		_updateGlobalParamsEntryWithExtraData(
			testMeta,
			testMeta.feeRateNanosPerKb,
			paramUpdaterPub,
			paramUpdaterPriv,
			map[string][]byte{StakeLockupEpochDurationKey: UintToBuf(2)},
		)

		require.Equal(t, _newUtxoView(testMeta).GlobalParamsEntry.StakeLockupEpochDuration, uint64(2))

		// Run OnEpochCompleteHook().
		_runOnEpochCompleteHook(testMeta, incrBlockHeight())

		// Snapshot StakeLockupEpochDuration is still 3.
		snapshotGlobalsParamsEntry, err = _newUtxoView(testMeta).GetSnapshotGlobalParamsEntry()
		require.NoError(t, err)
		require.Equal(t, snapshotGlobalsParamsEntry.StakeLockupEpochDuration, uint64(3))

		// Run OnEpochCompleteHook().
		_runOnEpochCompleteHook(testMeta, incrBlockHeight())

		// Snapshot StakeLockupEpochDuration is updated to 2.
		snapshotGlobalsParamsEntry, err = _newUtxoView(testMeta).GetSnapshotGlobalParamsEntry()
		require.NoError(t, err)
		require.Equal(t, snapshotGlobalsParamsEntry.StakeLockupEpochDuration, uint64(2))
	}
	{
		// Test snapshotting changing validator set.

		// m0 unregisters as a validator.
		snapshotValidatorSet, err := _newUtxoView(testMeta).GetSnapshotValidatorSetByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, snapshotValidatorSet, 7)

		_, err = _submitUnregisterAsValidatorTxn(testMeta, m0Pub, m0Priv, true)
		require.NoError(t, err)

		// Run OnEpochCompleteHook().
		_runOnEpochCompleteHook(testMeta, incrBlockHeight())

		// m0 is still in the snapshot validator set.
		snapshotValidatorSet, err = _newUtxoView(testMeta).GetSnapshotValidatorSetByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, snapshotValidatorSet, 7)

		snapshotStakeEntries, err := _newUtxoView(testMeta).GetSnapshotStakesToRewardByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, snapshotStakeEntries, 7)

		// Run OnEpochCompleteHook().
		_runOnEpochCompleteHook(testMeta, incrBlockHeight())

		// m0 is dropped from the snapshot validator set.
		snapshotValidatorSet, err = _newUtxoView(testMeta).GetSnapshotValidatorSetByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, snapshotValidatorSet, 6)

		snapshotStakeEntries, err = _newUtxoView(testMeta).GetSnapshotStakesToRewardByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, snapshotStakeEntries, 6)
	}
	{
		// Run OnEpochCompleteHook().
		_runOnEpochCompleteHook(testMeta, incrBlockHeight())
	}
	{
		// Run OnEpochCompleteHook()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight())
	}
	{
		// Test jailing inactive validators.
		//
		// The CurrentEpochNumber is 9. All validators were last active in epoch 1
		// which is the epoch in which they registered.
		//
		// The JailInactiveValidatorGracePeriodEpochs is 10 epochs. So all
		// validators should be jailed after epoch 11, at the start of epoch 12.
		//
		// The SnapshotLookbackNumEpochs is 2, so all registered snapshot validators
		// should be considered jailed after epoch 13, at the start of epoch 14.

		// Define helper utils.
		getCurrentEpochNumber := func() int {
			currentEpochNumber, err := _newUtxoView(testMeta).GetCurrentEpochNumber()
			require.NoError(t, err)
			return int(currentEpochNumber)
		}

		getNumCurrentActiveValidators := func() int {
			validatorEntries, err := _newUtxoView(testMeta).GetTopActiveValidatorsByStakeAmount(10)
			require.NoError(t, err)
			return len(validatorEntries)
		}

		getNumSnapshotValidatorSet := func() int {
			snapshotValidatorSet, err := _newUtxoView(testMeta).GetSnapshotValidatorSetByStakeAmount(10)
			require.NoError(t, err)
			return len(snapshotValidatorSet)
		}

		getCurrentValidator := func(validatorPKID *PKID) *ValidatorEntry {
			validatorEntry, err := _newUtxoView(testMeta).GetValidatorByPKID(validatorPKID)
			require.NoError(t, err)
			return validatorEntry
		}

		getNumStakes := func() int {
			stakeEntries, err := _newUtxoView(testMeta).GetTopStakesByStakeAmount(10)
			require.NoError(t, err)
			return len(stakeEntries)
		}

		getNumSnapshotStakes := func() int {
			snapshotStakeEntries, err := _newUtxoView(testMeta).GetSnapshotStakesToRewardByStakeAmount(10)
			require.NoError(t, err)
			return len(snapshotStakeEntries)
		}

		// In epoch 11, all registered validators have Status = Active.
		require.Equal(t, getCurrentEpochNumber(), 11)
		require.Equal(t, getNumCurrentActiveValidators(), 6)
		require.Equal(t, getNumSnapshotValidatorSet(), 6)
		require.Equal(t, getNumStakes(), 6)
		require.Equal(t, getNumSnapshotStakes(), 6)

		// Run OnEpochCompleteHook().
		_runOnEpochCompleteHook(testMeta, incrBlockHeight())

		// In epoch 12, all current registered validators have Status = Jailed.
		// In snapshot 10, all snapshot validators have Status = Active.
		require.Equal(t, getCurrentEpochNumber(), 12)
		require.Empty(t, getNumCurrentActiveValidators())
		require.Equal(t, getNumSnapshotValidatorSet(), 6)
		require.Equal(t, getNumStakes(), 6)
		require.Equal(t, getNumSnapshotStakes(), 6)

		require.Equal(t, getCurrentValidator(m6PKID).Status(), ValidatorStatusJailed)
		require.Equal(t, getCurrentValidator(m6PKID).JailedAtEpochNumber, uint64(11))

		// Run OnEpochCompleteHook().
		_runOnEpochCompleteHook(testMeta, incrBlockHeight())

		// In epoch 13, all current registered validators have Status = Jailed.
		// In snapshot 11, the validator set is empty because all validators have Status = Jailed.
		require.Equal(t, getCurrentEpochNumber(), 13)
		require.Empty(t, getNumCurrentActiveValidators())
		require.Empty(t, getNumSnapshotValidatorSet())
		require.Equal(t, getNumStakes(), 6)
		require.Empty(t, getNumSnapshotStakes())

		// Run OnEpochCompleteHook().
		_runOnEpochCompleteHook(testMeta, incrBlockHeight())

		// In epoch 14, all current registered validators have Status = Jailed.
		// In snapshot 12, the validator set is empty because all validators have Status = Jailed.

		require.Equal(t, getCurrentEpochNumber(), 14)
		require.Empty(t, getNumCurrentActiveValidators())
		require.Empty(t, getNumSnapshotValidatorSet())
		require.Equal(t, getNumStakes(), 6)
		require.Empty(t, getNumSnapshotStakes())
	}
}

func _setUpMinerAndTestMetaForEpochCompleteTest(t *testing.T) *TestMeta {
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize PoS fork heights.
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(1)
	params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = uint32(1)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

	// Mine a few blocks to give the senderPkString some money.
	for ii := 0; ii < 10; ii++ {
		_, err := miner.MineAndProcessSingleBlock(0, mempool)
		require.NoError(t, err)
	}

	// We build the testMeta obj after mining blocks so that we save the correct block height.
	blockHeight := uint64(chain.blockTip().Height) + 1

	return &TestMeta{
		t:                 t,
		chain:             chain,
		params:            params,
		db:                db,
		mempool:           mempool,
		miner:             miner,
		savedHeight:       uint32(blockHeight),
		feeRateNanosPerKb: uint64(101),
	}
}

func _registerValidatorAndStake(testMeta *TestMeta, publicKey string, privateKey string, stakeAmountNanos uint64, restakeRewards bool) {
	// Convert PublicKeyBase58Check to PublicKeyBytes.
	pkBytes, _, err := Base58CheckDecode(publicKey)
	require.NoError(testMeta.t, err)

	// Validator registers.
	votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(testMeta.t, pkBytes)
	registerMetadata := &RegisterAsValidatorMetadata{
		Domains:             [][]byte{[]byte(fmt.Sprintf("https://%s.com", publicKey))},
		VotingPublicKey:     votingPublicKey,
		VotingAuthorization: votingAuthorization,
	}
	_, err = _submitRegisterAsValidatorTxn(testMeta, publicKey, privateKey, registerMetadata, nil, true)
	require.NoError(testMeta.t, err)

	rewardMethod := StakingRewardMethodPayToBalance
	if restakeRewards {
		rewardMethod = StakingRewardMethodRestake
	}

	stakeMetadata := &StakeMetadata{
		ValidatorPublicKey: NewPublicKey(pkBytes),
		RewardMethod:       rewardMethod,
		StakeAmountNanos:   uint256.NewInt().SetUint64(stakeAmountNanos),
	}
	_, err = _submitStakeTxn(testMeta, publicKey, privateKey, stakeMetadata, nil, true)
	require.NoError(testMeta.t, err)
}

func _newUtxoView(testMeta *TestMeta) *UtxoView {
	newUtxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(testMeta.t, err)
	return newUtxoView
}

func _runOnEpochCompleteHook(testMeta *TestMeta, blockHeight uint64) {
	tmpUtxoView := _newUtxoView(testMeta)
	// Set blockTimestampNanoSecs to 1 year * block height. Every time the block height increments,
	// the timestamp increases by 1 year
	blockTimestampNanoSecs := blockHeight * 365 * 24 * 3600 * 1e9
	require.NoError(testMeta.t, tmpUtxoView.RunEpochCompleteHook(blockHeight, blockTimestampNanoSecs))
	require.NoError(testMeta.t, tmpUtxoView.FlushToDb(blockHeight))
}

func _assertEmptyValidatorSnapshots(testMeta *TestMeta) {
	// Test GetSnapshotValidatorSetByStakeAmount is empty.
	validatorEntries, err := _newUtxoView(testMeta).GetSnapshotValidatorSetByStakeAmount(100)
	require.NoError(testMeta.t, err)
	require.Empty(testMeta.t, validatorEntries)

	// Test SnapshotValidatorSetTotalStakeAmountNanos is zero.
	snapshotValidatorSetTotalStakeAmountNanos, err := _newUtxoView(testMeta).GetSnapshotValidatorSetTotalStakeAmountNanos()
	require.NoError(testMeta.t, err)
	require.True(testMeta.t, snapshotValidatorSetTotalStakeAmountNanos.IsZero())

	// Test SnapshotLeaderSchedule is nil.
	for index := range validatorEntries {
		snapshotLeaderScheduleValidator, err := _newUtxoView(testMeta).GetSnapshotLeaderScheduleValidator(uint16(index))
		require.NoError(testMeta.t, err)
		require.Nil(testMeta.t, snapshotLeaderScheduleValidator)
	}
}

func _assertEmptyStakeSnapshots(testMeta *TestMeta) {
	// Test GetSnapshotStakesToRewardByStakeAmount is empty.
	stakeEntries, err := _newUtxoView(testMeta).GetSnapshotStakesToRewardByStakeAmount(100)
	require.NoError(testMeta.t, err)
	require.Empty(testMeta.t, stakeEntries)
}
