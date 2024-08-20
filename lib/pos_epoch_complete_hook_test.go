package lib

import (
	"fmt"
	"sort"
	"testing"

	"github.com/deso-protocol/core/bls"

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

	utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)

	// The BlockHeight is before the PoS snapshotting fork height.
	var err error
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
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)
	// Initialize PoS fork heights.
	setPoSBlockHeights(t, 11, 11)
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
		// Update the saved height in the testMeta so that the calls to construct transactions use the
		// correct block height.
		testMeta.savedHeight = uint32(blockHeight)
		// Put a dummy block in the chain so that the tip is updated. This
		// make the calls to update global params work since they use the chain's tip as the block height.
		testMeta.chain.addTipBlockToBestChain(&BlockNode{Height: uint32(blockHeight), Hash: NewBlockHash([]byte{byte(blockHeight)})})
		return blockHeight
	}
	viewNumber := uint64(0)
	incrViewNumber := func() uint64 {
		viewNumber += 1
		return viewNumber
	}

	// Seed a CurrentEpochEntry.
	tmpUtxoView := _newUtxoView(testMeta)
	tmpUtxoView._setCurrentEpochEntry(&EpochEntry{EpochNumber: 0, FinalBlockHeight: blockHeight + 1})
	require.NoError(t, tmpUtxoView.FlushToDb(blockHeight))

	// For these tests, we set each epoch duration to only one block.
	testMeta.params.DefaultEpochDurationNumBlocks = uint64(1)

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
		snapshotGlobalParamsEntry, err := _newUtxoView(testMeta).GetCurrentSnapshotGlobalParamsEntry()
		require.NoError(t, err)
		require.NotNil(t, snapshotGlobalParamsEntry)
		require.Equal(t, snapshotGlobalParamsEntry.ValidatorJailEpochDuration, uint64(3))

		_assertEmptyValidatorSnapshots(testMeta)

		_assertEmptyStakeSnapshots(testMeta)
	}
	{
		// Test RunOnEpochCompleteHook() with no validators or stakers.
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)
	}
	{
		// Test the state of the snapshots after running our first OnEpochCompleteHook
		// but with no existing validators or stakers.

		// Test CurrentEpochNumber.
		currentEpochNumber, err := _newUtxoView(testMeta).GetCurrentEpochNumber()
		require.NoError(t, err)
		require.Equal(t, currentEpochNumber, uint64(1))

		// Test CurrentEpochEntry
		currentEpoch, err := _newUtxoView(testMeta).GetCurrentEpochEntry()
		require.NoError(t, err)
		require.NotNil(t, currentEpoch)
		require.Equal(t, currentEpoch.InitialBlockHeight, uint64(13))
		require.Equal(t, currentEpoch.InitialView, uint64(2))

		// Test SnapshotGlobalParamsEntry is nil.
		snapshotGlobalParamsEntry, err := _newUtxoView(testMeta).GetCurrentSnapshotGlobalParamsEntry()
		require.NoError(t, err)
		require.NotNil(t, snapshotGlobalParamsEntry)
		require.Equal(t, _newUtxoView(testMeta).GlobalParamsEntry.MinimumNetworkFeeNanosPerKB, testMeta.feeRateNanosPerKb)
		require.Equal(t, snapshotGlobalParamsEntry.ValidatorJailEpochDuration, uint64(4))

		_assertEmptyValidatorSnapshots(testMeta)

		_assertEmptyStakeSnapshots(testMeta)
	}
	{
		// All validators register + stake to themselves.
		_registerValidatorAndStake(testMeta, m0Pub, m0Priv, 0, 100, false)
		_registerValidatorAndStake(testMeta, m1Pub, m1Priv, 0, 200, false)
		_registerValidatorAndStake(testMeta, m2Pub, m2Priv, 0, 300, false)
		_registerValidatorAndStake(testMeta, m3Pub, m3Priv, 0, 400, false)
		_registerValidatorAndStake(testMeta, m4Pub, m4Priv, 0, 500, false)
		_registerValidatorAndStake(testMeta, m5Pub, m5Priv, 0, 600, false)
		_registerValidatorAndStake(testMeta, m6Pub, m6Priv, 0, 700, false)

		validatorEntries, err := _newUtxoView(testMeta).GetTopActiveValidatorsByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 7)

		stakeEntries, err := _newUtxoView(testMeta).GetTopStakesForValidatorsByStakeAmount(validatorPKIDs, 10)
		require.NoError(t, err)
		require.Len(t, stakeEntries, 7)
	}
	{
		// Test RunOnEpochCompleteHook().
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)
	}
	{
		// Test CurrentEpochNumber.
		currentEpochNumber, err := _newUtxoView(testMeta).GetCurrentEpochNumber()
		require.NoError(t, err)
		require.Equal(t, currentEpochNumber, uint64(2))

		// Test CurrentEpochEntry
		currentEpoch, err := _newUtxoView(testMeta).GetCurrentEpochEntry()
		require.NoError(t, err)
		require.NotNil(t, currentEpoch)
		require.Equal(t, currentEpoch.InitialBlockHeight, uint64(14))
		require.Equal(t, currentEpoch.InitialView, uint64(3))
		require.Equal(t, currentEpoch.FinalBlockHeight, uint64(14))
		require.Equal(t, currentEpoch.InitialLeaderIndexOffset, uint64(0))

		// Test SnapshotGlobalParamsEntry is populated.
		snapshotGlobalParamsEntry, err := _newUtxoView(testMeta).GetCurrentSnapshotGlobalParamsEntry()
		require.NoError(t, err)
		require.NotNil(t, snapshotGlobalParamsEntry)
		require.Equal(t, snapshotGlobalParamsEntry.MinimumNetworkFeeNanosPerKB, testMeta.feeRateNanosPerKb)
		require.Equal(t, snapshotGlobalParamsEntry.ValidatorJailEpochDuration, uint64(4))

		_assertEmptyValidatorSnapshots(testMeta)

		_assertEmptyStakeSnapshots(testMeta)
	}
	{
		// Test RunOnEpochCompleteHook().

		// Increment the view number twice to simulate one timeout
		incrViewNumber()
		incrViewNumber()

		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-2)
	}
	{
		// Test CurrentEpochNumber.
		currentEpochNumber, err := _newUtxoView(testMeta).GetCurrentEpochNumber()
		require.NoError(t, err)
		require.Equal(t, currentEpochNumber, uint64(3))

		// Test CurrentEpochEntry
		currentEpoch, err := _newUtxoView(testMeta).GetCurrentEpochEntry()
		require.NoError(t, err)
		require.NotNil(t, currentEpoch)
		require.Equal(t, currentEpoch.InitialBlockHeight, uint64(15))
		require.Equal(t, currentEpoch.InitialView, uint64(5))
		require.Equal(t, currentEpoch.FinalBlockHeight, uint64(15))
		// InitialLeaderIndexOffset is non-zero because the final two views of the previous epoch were not consecutive.
		//
		// InitialLeaderIndexOffset = hashUint64ToUint64(currentEpochFinalView) % uint64(len(nextSnapshotLeaderSchedule))
		//                          = hashUint64ToUint64(4) % 7
		//                          = 0xeb667cfa9fe822a % 7
		//                          = 5
		require.Equal(t, currentEpoch.InitialLeaderIndexOffset, uint64(5))

		// Test SnapshotGlobalParamsEntry is populated.
		snapshotGlobalParamsEntry, err := _newUtxoView(testMeta).GetCurrentSnapshotGlobalParamsEntry()
		require.NoError(t, err)
		require.NotNil(t, snapshotGlobalParamsEntry)
		require.Equal(t, snapshotGlobalParamsEntry.MinimumNetworkFeeNanosPerKB, testMeta.feeRateNanosPerKb)
		require.Equal(t, snapshotGlobalParamsEntry.ValidatorJailEpochDuration, uint64(4))

		// Test SnapshotValidatorByPKID is populated.
		for _, pkid := range validatorPKIDs {
			snapshotValidatorSetEntry, err := _newUtxoView(testMeta).GetCurrentSnapshotValidatorSetEntryByPKID(pkid)
			require.NoError(t, err)
			require.NotNil(t, snapshotValidatorSetEntry)
			// Make sure BLS public key -> PKID mapping is populated.
			blsPublicKeyPKIDEntry, err := _newUtxoView(testMeta).GetCurrentSnapshotValidatorBLSPublicKeyPKIDPairEntry(snapshotValidatorSetEntry.VotingPublicKey)
			require.NoError(t, err)
			require.NotNil(t, blsPublicKeyPKIDEntry)
			require.True(t, blsPublicKeyPKIDEntry.PKID.Eq(pkid))
		}

		// Test GetSnapshotValidatorSetByStakeAmount is populated.
		validatorEntries, err := _newUtxoView(testMeta).GetSnapshotValidatorSetByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 7)
		require.Equal(t, validatorEntries[0].ValidatorPKID, m6PKID)
		require.Equal(t, validatorEntries[6].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt(700))
		require.Equal(t, validatorEntries[6].TotalStakeAmountNanos, uint256.NewInt(100))

		// Test SnapshotLeaderSchedule is populated.
		for index := range validatorPKIDs {
			snapshotLeaderScheduleValidator, err := _newUtxoView(testMeta).GetSnapshotLeaderScheduleValidator(uint16(index))
			require.NoError(t, err)
			require.NotNil(t, snapshotLeaderScheduleValidator)
		}

		// Test GetSnapshotStakesToRewardByStakeAmount is populated.
		stakeEntries, err := _newUtxoView(testMeta).GetAllSnapshotStakesToReward()
		require.NoError(t, err)
		_sortStakeEntriesByStakeAmount(stakeEntries)
		require.Len(t, stakeEntries, 7)
		require.Equal(t, stakeEntries[0].StakerPKID, m6PKID)
		require.Equal(t, stakeEntries[6].StakerPKID, m0PKID)
		require.Equal(t, stakeEntries[0].StakeAmountNanos, uint256.NewInt(700))
		require.Equal(t, stakeEntries[6].StakeAmountNanos, uint256.NewInt(100))
	}
	{
		// Test snapshotting changing stake.

		// m5 has 600 staked.
		validatorEntry, err := _newUtxoView(testMeta).GetValidatorByPKID(m5PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos.Uint64(), uint64(600))

		// m5 stakes another 200.
		_registerValidatorAndStake(testMeta, m5Pub, m5Priv, 0, 200, false)

		// m5 has 800 staked.
		validatorEntry, err = _newUtxoView(testMeta).GetValidatorByPKID(m5PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos.Uint64(), uint64(800))

		// Run OnEpochCompleteHook().
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)

		// Snapshot m5 still has 600 staked.
		validatorEntry, err = _newUtxoView(testMeta).GetCurrentSnapshotValidatorSetEntryByPKID(m5PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos.Uint64(), uint64(600))

		stakeEntries, err := _newUtxoView(testMeta).GetAllSnapshotStakesToReward()
		require.NoError(t, err)
		_sortStakeEntriesByStakeAmount(stakeEntries)
		require.Len(t, stakeEntries, 7)
		require.Equal(t, stakeEntries[1].StakerPKID, m5PKID)
		require.Equal(t, stakeEntries[1].StakeAmountNanos, uint256.NewInt(600))

		// Run OnEpochCompleteHook().
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)

		// Snapshot m5 now has 800 staked.
		validatorEntry, err = _newUtxoView(testMeta).GetCurrentSnapshotValidatorSetEntryByPKID(m5PKID)
		require.NoError(t, err)
		require.NotNil(t, validatorEntry)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos.Uint64(), uint64(800))

		stakeEntries, err = _newUtxoView(testMeta).GetAllSnapshotStakesToReward()
		require.NoError(t, err)
		_sortStakeEntriesByStakeAmount(stakeEntries)
		require.Len(t, stakeEntries, 7)
		require.Equal(t, stakeEntries[0].StakerPKID, m5PKID)
		require.Equal(t, stakeEntries[0].StakeAmountNanos, uint256.NewInt(800))
	}
	{
		// Test snapshotting changing GlobalParams.

		// Update StakeLockupEpochDuration from default of 3 to 2.
		snapshotGlobalsParamsEntry, err := _newUtxoView(testMeta).GetCurrentSnapshotGlobalParamsEntry()
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
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)

		// Snapshot StakeLockupEpochDuration is still 3.
		snapshotGlobalsParamsEntry, err = _newUtxoView(testMeta).GetCurrentSnapshotGlobalParamsEntry()
		require.NoError(t, err)
		require.Equal(t, snapshotGlobalsParamsEntry.StakeLockupEpochDuration, uint64(3))

		// Run OnEpochCompleteHook().
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)

		// Snapshot StakeLockupEpochDuration is updated to 2.
		snapshotGlobalsParamsEntry, err = _newUtxoView(testMeta).GetCurrentSnapshotGlobalParamsEntry()
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
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)

		// m0 is still in the snapshot validator set.
		snapshotValidatorSet, err = _newUtxoView(testMeta).GetSnapshotValidatorSetByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, snapshotValidatorSet, 7)

		snapshotStakeEntries, err := _newUtxoView(testMeta).GetAllSnapshotStakesToReward()
		require.NoError(t, err)
		require.Len(t, snapshotStakeEntries, 7)

		// Run OnEpochCompleteHook().
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)

		// m0 is dropped from the snapshot validator set.
		snapshotValidatorSet, err = _newUtxoView(testMeta).GetSnapshotValidatorSetByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, snapshotValidatorSet, 6)

		snapshotStakeEntries, err = _newUtxoView(testMeta).GetAllSnapshotStakesToReward()
		require.NoError(t, err)
		require.Len(t, snapshotStakeEntries, 6)
	}
	{
		// Run OnEpochCompleteHook().
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)
	}
	{
		// Run OnEpochCompleteHook()
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)
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
			stakeEntries, err := _newUtxoView(testMeta).GetTopStakesForValidatorsByStakeAmount(validatorPKIDs, 10)
			require.NoError(t, err)
			return len(stakeEntries)
		}

		getNumSnapshotStakes := func() int {
			snapshotStakeEntries, err := _newUtxoView(testMeta).GetAllSnapshotStakesToReward()
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
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)

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
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)

		// In epoch 13, all current registered validators have Status = Jailed.
		// In snapshot 11, the validator set is empty because all validators have Status = Jailed.
		require.Equal(t, getCurrentEpochNumber(), 13)
		require.Empty(t, getNumCurrentActiveValidators())
		require.Empty(t, getNumSnapshotValidatorSet())
		require.Equal(t, getNumStakes(), 6)
		require.Empty(t, getNumSnapshotStakes())

		// Run OnEpochCompleteHook().
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)

		// In epoch 14, all current registered validators have Status = Jailed.
		// In snapshot 12, the validator set is empty because all validators have Status = Jailed.

		require.Equal(t, getCurrentEpochNumber(), 14)
		require.Empty(t, getNumCurrentActiveValidators())
		require.Empty(t, getNumSnapshotValidatorSet())
		require.Equal(t, getNumStakes(), 6)
		require.Empty(t, getNumSnapshotStakes())
	}
}

func TestStakingRewardDistribution(t *testing.T) {
	DeSoTestnetParams.DefaultEpochDurationNumBlocks = uint64(1)
	GlobalDeSoParams.DefaultEpochDurationNumBlocks = uint64(1)
	resetDefaultEpochDurationNumBlocks := func() {
		DeSoTestnetParams.DefaultEpochDurationNumBlocks = uint64(3600)
		GlobalDeSoParams.DefaultEpochDurationNumBlocks = uint64(3600)
	}
	defer resetDefaultEpochDurationNumBlocks()
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)
	// Initialize PoS fork heights.
	setPoSBlockHeights(t, 11, 11)
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForEpochCompleteTest(t)

	_registerOrTransferWithTestMeta(testMeta, "m0", senderPkString, m0Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m1", senderPkString, m1Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m2", senderPkString, m2Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m3", senderPkString, m3Pub, senderPrivString, 1e3)

	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 1e3)

	m0PKID := DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m0PkBytes).PKID
	m1PKID := DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m1PkBytes).PKID
	m2PKID := DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m2PkBytes).PKID
	m3PKID := DBGetPKIDEntryForPublicKey(testMeta.db, testMeta.chain.snapshot, m3PkBytes).PKID

	blockHeight := uint64(testMeta.chain.blockTip().Height) + 1
	incrBlockHeight := func() uint64 {
		blockHeight += 1
		return blockHeight
	}
	viewNumber := uint64(0)
	incrViewNumber := func() uint64 {
		viewNumber += 1
		return viewNumber
	}

	// Seed a CurrentEpochEntry.
	tmpUtxoView := _newUtxoView(testMeta)
	tmpUtxoView._setCurrentEpochEntry(&EpochEntry{EpochNumber: 2, FinalBlockHeight: blockHeight + 1})
	require.NoError(t, tmpUtxoView.FlushToDb(blockHeight))

	// For these tests, we set each epoch duration to only one block.
	testMeta.params.DefaultEpochDurationNumBlocks = uint64(1)

	// We set the default staking rewards APY to 10%
	testMeta.params.DefaultStakingRewardsAPYBasisPoints = uint64(1000)

	// Two validators register + stake to themselves.
	_registerValidatorAndStake(testMeta, m0Pub, m0Priv, 2000, 400, true)  // 20% commission rate, 400 nano stake
	_registerValidatorAndStake(testMeta, m1Pub, m1Priv, 2000, 200, false) // 20% commission rate, 200 nano stake

	// Cache the validator PKIDs.
	validatorPKIDs := []*PKID{m0PKID, m1PKID}

	// Two stakers delegate their stake to the validators.
	_stakeToValidator(testMeta, m2Pub, m2Priv, m0Pub, 100, true) // 100 nano stake
	_stakeToValidator(testMeta, m3Pub, m3Priv, m1Pub, 50, false) // 50 nano stake

	{
		// Verify the validators and their total stakes.
		validatorEntries, err := _newUtxoView(testMeta).GetTopActiveValidatorsByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 2)

		// Validator m0 has 500 nanos staked in total: 400 staked by itself and 100 delegated by m2.
		require.Equal(t, validatorEntries[0].ValidatorPKID, m0PKID)
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos, uint256.NewInt(500))

		// Validator m1 has 250 nanos staked in total: 200 staked by itself and 50 delegated by m3.
		require.Equal(t, validatorEntries[1].ValidatorPKID, m1PKID)
		require.Equal(t, validatorEntries[1].TotalStakeAmountNanos, uint256.NewInt(250))
	}

	{
		// Verify the stakers' stakes.
		stakeEntries, err := _newUtxoView(testMeta).GetTopStakesForValidatorsByStakeAmount(validatorPKIDs, 10)
		require.NoError(t, err)
		require.Len(t, stakeEntries, 4)

		require.Equal(t, stakeEntries[0].StakerPKID, m0PKID)
		require.Equal(t, stakeEntries[0].StakeAmountNanos, uint256.NewInt(400))
		require.Equal(t, stakeEntries[1].StakerPKID, m1PKID)
		require.Equal(t, stakeEntries[1].StakeAmountNanos, uint256.NewInt(200))
		require.Equal(t, stakeEntries[2].StakerPKID, m2PKID)
		require.Equal(t, stakeEntries[2].StakeAmountNanos, uint256.NewInt(100))
		require.Equal(t, stakeEntries[3].StakerPKID, m3PKID)
		require.Equal(t, stakeEntries[3].StakeAmountNanos, uint256.NewInt(50))
	}

	{
		// Run OnEpochCompleteHook().
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)
	}

	{
		// Run OnEpochCompleteHook().
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)
	}

	{
		// Test that the stakes are unchanged.
		stakeEntries, err := _newUtxoView(testMeta).GetTopStakesForValidatorsByStakeAmount(validatorPKIDs, 10)
		require.NoError(t, err)
		require.Len(t, stakeEntries, 4)
		require.Equal(t, stakeEntries[0].StakerPKID, m0PKID)
		require.Equal(t, stakeEntries[0].StakeAmountNanos, uint256.NewInt(400))
		require.Equal(t, stakeEntries[1].StakerPKID, m1PKID)
		require.Equal(t, stakeEntries[1].StakeAmountNanos, uint256.NewInt(200))
		require.Equal(t, stakeEntries[2].StakerPKID, m2PKID)
		require.Equal(t, stakeEntries[2].StakeAmountNanos, uint256.NewInt(100))
		require.Equal(t, stakeEntries[3].StakerPKID, m3PKID)
		require.Equal(t, stakeEntries[3].StakeAmountNanos, uint256.NewInt(50))

		// Test that DESO wallet balances are unchanged.
		m0Balance, err := _newUtxoView(testMeta).GetDeSoBalanceNanosForPublicKey(m0PkBytes)
		require.NoError(t, err)
		require.Equal(t, m0Balance, uint64(546))
		m1Balance, err := _newUtxoView(testMeta).GetDeSoBalanceNanosForPublicKey(m1PkBytes)
		require.NoError(t, err)
		require.Equal(t, m1Balance, uint64(746))
		m2Balance, err := _newUtxoView(testMeta).GetDeSoBalanceNanosForPublicKey(m2PkBytes)
		require.NoError(t, err)
		require.Equal(t, m2Balance, uint64(882))
		m3Balance, err := _newUtxoView(testMeta).GetDeSoBalanceNanosForPublicKey(m3PkBytes)
		require.NoError(t, err)
		require.Equal(t, m3Balance, uint64(932))

		// Test that snapshot stakes have been created.
		snapshotStakeEntries, err := _newUtxoView(testMeta).GetAllSnapshotStakesToReward()
		require.NoError(t, err)
		_sortStakeEntriesByStakeAmount(snapshotStakeEntries)
		require.Len(t, snapshotStakeEntries, 4)
		require.Equal(t, snapshotStakeEntries[0].StakerPKID, m0PKID)
		require.Equal(t, snapshotStakeEntries[0].StakeAmountNanos, uint256.NewInt(400))
		require.Equal(t, snapshotStakeEntries[1].StakerPKID, m1PKID)
		require.Equal(t, snapshotStakeEntries[1].StakeAmountNanos, uint256.NewInt(200))
		require.Equal(t, snapshotStakeEntries[2].StakerPKID, m2PKID)
		require.Equal(t, snapshotStakeEntries[2].StakeAmountNanos, uint256.NewInt(100))
		require.Equal(t, snapshotStakeEntries[3].StakerPKID, m3PKID)
		require.Equal(t, snapshotStakeEntries[3].StakeAmountNanos, uint256.NewInt(50))
	}

	{
		// Run OnEpochCompleteHook().
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)
	}

	{
		// This is the first epoch where staking rewards have been distributed. The nominal interest
		// rate for staking rewards is 10% APY. Exactly 1 year's worth of time has passed since the
		// previous epoch.

		// Test that the number of stakes is unchanged.
		stakeEntries, err := _newUtxoView(testMeta).GetTopStakesForValidatorsByStakeAmount(validatorPKIDs, 10)
		require.NoError(t, err)
		require.Len(t, stakeEntries, 4)

		// Test reward computation and restaking for m0:
		// - m0's original stake was 400 nanos
		// - m0 had 100 nanos delegated to it
		// - m0's commission rate is 20%
		// - all rewards for m0 will be restaked
		//
		// Reward Computations:
		// - m0's reward from its own stake is: 400 * [e^0.1 - 1] = 42 nanos
		// - m0's reward from delegated stake is: 100 * [e^0.1 - 1] * 0.2 = 2 nanos
		//
		// Final stake amount:
		// - m0's final stake is: 400 + 42 + 2 = 444 nanos
		require.Equal(t, stakeEntries[0].StakerPKID, m0PKID)
		require.Equal(t, stakeEntries[0].StakeAmountNanos, uint256.NewInt(444))

		// Test that m0's DESO wallet balance is unchanged.
		m0Balance, err := _newUtxoView(testMeta).GetDeSoBalanceNanosForPublicKey(m0PkBytes)
		require.NoError(t, err)
		require.Equal(t, m0Balance, uint64(546))

		// Test reward computation for m1:
		// - m1's original stake was 200 nanos
		// - m1 had 50 nanos delegated to it
		// - m1's original DESO wallet balance was 746 nanos
		// - m1's commission rate is 10%
		// - all rewards for m1 will be paid out to its DESO wallet
		//
		// Reward Computations:
		// - m1's reward from its own stake is: 200 * [e^0.1 - 1] = 21 nanos
		// - m1's reward from delegated stake is: 50 * [e^0.1 - 1] * 0.2 = 1 nano
		//
		// Final DESO wallet balance:
		// - m1's final DESO wallet balance is: 746 + 21 + 1 = 768 nanos
		m1Balance, err := _newUtxoView(testMeta).GetDeSoBalanceNanosForPublicKey(m1PkBytes)
		require.NoError(t, err)
		require.Equal(t, m1Balance, uint64(768))

		// Test that m1's stake is unchanged.
		require.Equal(t, stakeEntries[1].StakerPKID, m1PKID)
		require.Equal(t, stakeEntries[1].StakeAmountNanos, uint256.NewInt(200))

		// Test reward computation and restaking for m2:
		// - m2's original stake was 100 nanos
		// - m2's validator m0 has a commission rate of 20%
		// - m2's rewards will be restaked
		//
		// Reward Computations:
		// - m2's total reward for its stake is: 100 * [e^0.1 - 1] = 10 nanos
		// - m2's reward lost to m0's commission is: 10 nanos * 0.2 = 2 nanos
		//
		// Final stake amount:
		// - m2's final stake is: 100 + 10 - 2 = 108 nanos
		require.Equal(t, stakeEntries[2].StakerPKID, m2PKID)
		require.Equal(t, stakeEntries[2].StakeAmountNanos, uint256.NewInt(108))

		// Test that m2's DESO wallet balance is unchanged.
		m2Balance, err := _newUtxoView(testMeta).GetDeSoBalanceNanosForPublicKey(m2PkBytes)
		require.NoError(t, err)
		require.Equal(t, m2Balance, uint64(882))

		// Test reward computation for m3:
		// - m3's original stake was 50 nanos
		// - m3's validator m1 has a commission rate of 20%
		// - m3's original DESO wallet balance was 932 nanos
		// - m3's rewards will be paid out to its DESO wallet
		//
		// Reward Computations:
		// - m3's total reward for its stake is 50 * [e^0.1 - 1] = 5 nanos
		// - m3's reward lost to m1's commission is: 5 nanos * 0.2 = 1 nano
		//
		// Final DESO wallet balance:
		// - m3's final DESO wallet balance is: 932 + 5 - 1 = 936 nanos
		m3Balance, err := _newUtxoView(testMeta).GetDeSoBalanceNanosForPublicKey(m3PkBytes)
		require.NoError(t, err)
		require.Equal(t, m3Balance, uint64(936))

		// Test that m3's stake is unchanged.
		require.Equal(t, stakeEntries[3].StakerPKID, m3PKID)
		require.Equal(t, stakeEntries[3].StakeAmountNanos, uint256.NewInt(50))

		// Make sure the validator's total stake amount is correct.
		// M0's total stake amount nanos should be the sum of M0 and M2's stakes (444 + 108)
		validatorEntry, err := _newUtxoView(testMeta).GetValidatorByPKID(m0PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos.Uint64(), uint64(444+108))

		// M1's total stake amount nanos should be the sum of M1 and M3's stakes (200 + 50)
		validatorEntry, err = _newUtxoView(testMeta).GetValidatorByPKID(m1PKID)
		require.NoError(t, err)
		require.Equal(t, validatorEntry.TotalStakeAmountNanos.Uint64(), uint64(200+50))
	}

	{
		// Test that snapshot stakes have not changed.
		snapshotStakeEntries, err := _newUtxoView(testMeta).GetAllSnapshotStakesToReward()
		require.NoError(t, err)
		_sortStakeEntriesByStakeAmount(snapshotStakeEntries)
		require.Len(t, snapshotStakeEntries, 4)
		require.Equal(t, snapshotStakeEntries[0].StakerPKID, m0PKID)
		require.Equal(t, snapshotStakeEntries[0].StakeAmountNanos, uint256.NewInt(400))
		require.Equal(t, snapshotStakeEntries[1].StakerPKID, m1PKID)
		require.Equal(t, snapshotStakeEntries[1].StakeAmountNanos, uint256.NewInt(200))
		require.Equal(t, snapshotStakeEntries[2].StakerPKID, m2PKID)
		require.Equal(t, snapshotStakeEntries[2].StakeAmountNanos, uint256.NewInt(100))
		require.Equal(t, snapshotStakeEntries[3].StakerPKID, m3PKID)
		require.Equal(t, snapshotStakeEntries[3].StakeAmountNanos, uint256.NewInt(50))
	}

	{
		// Run OnEpochCompleteHook().
		incrViewNumber()
		_runOnEpochCompleteHook(testMeta, incrBlockHeight(), viewNumber, viewNumber-1)
	}

	{
		// Test that the current epoch's snapshot stakes now reflect the rewards that were
		// restaked at the end of epoch n-2.

		snapshotStakeEntries, err := _newUtxoView(testMeta).GetAllSnapshotStakesToReward()
		require.NoError(t, err)
		_sortStakeEntriesByStakeAmount(snapshotStakeEntries)
		require.Len(t, snapshotStakeEntries, 4)
		require.Equal(t, snapshotStakeEntries[0].StakerPKID, m0PKID)
		require.Equal(t, snapshotStakeEntries[0].StakeAmountNanos, uint256.NewInt(444))
		require.Equal(t, snapshotStakeEntries[1].StakerPKID, m1PKID)
		require.Equal(t, snapshotStakeEntries[1].StakeAmountNanos, uint256.NewInt(200))
		require.Equal(t, snapshotStakeEntries[2].StakerPKID, m2PKID)
		require.Equal(t, snapshotStakeEntries[2].StakeAmountNanos, uint256.NewInt(108))
		require.Equal(t, snapshotStakeEntries[3].StakerPKID, m3PKID)
		require.Equal(t, snapshotStakeEntries[3].StakeAmountNanos, uint256.NewInt(50))
	}

}

func _setUpMinerAndTestMetaForEpochCompleteTest(t *testing.T) *TestMeta {
	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

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

func _registerValidatorAndStake(
	testMeta *TestMeta,
	publicKey string,
	privateKey string,
	commissionBasisPoints uint64,
	stakeAmountNanos uint64,
	restakeRewards bool,
) {
	// Convert PublicKeyBase58Check to PublicKeyBytes.
	pkBytes, _, err := Base58CheckDecode(publicKey)
	require.NoError(testMeta.t, err)

	// Validator registers.
	votingPrivateKey, votingPublicKey, votingAuthorization := _generateVotingPrivateKeyPublicKeyAndAuthorization(testMeta.t, pkBytes)
	if testMeta.pubKeyToBLSKeyMap == nil {
		testMeta.pubKeyToBLSKeyMap = make(map[string]*bls.PrivateKey)
	}
	if testMeta.blsPubKeyToBLSKeyMap == nil {
		testMeta.blsPubKeyToBLSKeyMap = make(map[string]*bls.PrivateKey)
	}
	// Stash the voting private key in testmeta for convenience
	testMeta.pubKeyToBLSKeyMap[publicKey] = votingPrivateKey
	testMeta.blsPubKeyToBLSKeyMap[votingPublicKey.ToString()] = votingPrivateKey
	registerMetadata := &RegisterAsValidatorMetadata{
		Domains:                             [][]byte{[]byte(fmt.Sprintf("%s.com:18000", publicKey))},
		VotingPublicKey:                     votingPublicKey,
		DelegatedStakeCommissionBasisPoints: commissionBasisPoints,
		VotingAuthorization:                 votingAuthorization,
	}
	_, err = _submitRegisterAsValidatorTxn(testMeta, publicKey, privateKey, registerMetadata, nil, true)
	require.NoError(testMeta.t, err)

	_stakeToValidator(testMeta, publicKey, privateKey, publicKey, stakeAmountNanos, restakeRewards)
}

func _stakeToValidator(
	testMeta *TestMeta,
	stakerPubKey string,
	stakerPrivKey string,
	validatorPubKey string,
	stakeAmountNanos uint64,
	restakeRewards bool,
) {
	// Convert ValidatorPublicKeyBase58Check to ValidatorPublicKeyBytes.
	validatorPkBytes, _, err := Base58CheckDecode(validatorPubKey)
	require.NoError(testMeta.t, err)

	rewardMethod := StakingRewardMethodPayToBalance
	if restakeRewards {
		rewardMethod = StakingRewardMethodRestake
	}

	stakeMetadata := &StakeMetadata{
		ValidatorPublicKey: NewPublicKey(validatorPkBytes),
		RewardMethod:       rewardMethod,
		StakeAmountNanos:   uint256.NewInt(stakeAmountNanos),
	}
	_, err = _submitStakeTxn(testMeta, stakerPubKey, stakerPrivKey, stakeMetadata, nil, true)
	require.NoError(testMeta.t, err)
}

func _newUtxoView(testMeta *TestMeta) *UtxoView {
	newUtxoView := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, testMeta.chain.eventManager)
	return newUtxoView
}

func _runOnEpochCompleteHook(testMeta *TestMeta, blockHeight uint64, viewNumber uint64, previousViewNumber uint64) {
	tmpUtxoView := _newUtxoView(testMeta)
	// Set blockTimestampNanoSecs to 1 year * block height. Every time the block height increments,
	// the timestamp increases by 1 year
	blockTimestampNanoSecs := int64(blockHeight) * 365 * 24 * 3600 * 1e9
	_, err := tmpUtxoView.RunEpochCompleteHook(blockHeight, viewNumber, previousViewNumber, blockTimestampNanoSecs)
	require.NoError(testMeta.t, err)
	require.NoError(testMeta.t, tmpUtxoView.FlushToDb(blockHeight))
}

func _assertEmptyValidatorSnapshots(testMeta *TestMeta) {
	// Test GetSnapshotValidatorSetByStakeAmount is empty.
	validatorEntries, err := _newUtxoView(testMeta).GetSnapshotValidatorSetByStakeAmount(100)
	require.NoError(testMeta.t, err)
	require.Empty(testMeta.t, validatorEntries)

	// Test SnapshotLeaderSchedule is nil.
	for index := range validatorEntries {
		snapshotLeaderScheduleValidator, err := _newUtxoView(testMeta).GetSnapshotLeaderScheduleValidator(uint16(index))
		require.NoError(testMeta.t, err)
		require.Nil(testMeta.t, snapshotLeaderScheduleValidator)
	}
}

func _assertEmptyStakeSnapshots(testMeta *TestMeta) {
	// Test GetSnapshotStakesToRewardByStakeAmount is empty.
	stakeEntries, err := _newUtxoView(testMeta).GetAllSnapshotStakesToReward()
	require.NoError(testMeta.t, err)
	require.Empty(testMeta.t, stakeEntries)
}

func _sortStakeEntriesByStakeAmount(stakeEntries []*StakeEntry) {
	sort.Slice(stakeEntries, func(ii, jj int) bool {
		return stakeEntries[ii].StakeAmountNanos.Cmp(stakeEntries[jj].StakeAmountNanos) > 0
	})
}
