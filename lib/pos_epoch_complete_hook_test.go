//go:build relic

package lib

import (
	"fmt"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIsLastBlockInCurrentEpoch(t *testing.T) {
	var isLastBlockInCurrentEpoch bool

	// Initialize balance model fork heights.
	setBalanceModelBlockHeights()
	defer resetBalanceModelBlockHeights()

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)

	// Initialize fork heights.
	params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = uint32(1)
	params.ForkHeights.ProofOfStakeBlockHeight = uint32(1)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
	require.NoError(t, err)

	// The BlockHeight is before the PoS fork height.
	isLastBlockInCurrentEpoch, err = utxoView.IsLastBlockInCurrentEpoch(0)
	require.NoError(t, err)
	require.False(t, isLastBlockInCurrentEpoch)

	// The CurrentEpochEntry is nil.
	isLastBlockInCurrentEpoch, err = utxoView.IsLastBlockInCurrentEpoch(1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "CurrentEpochEntry is nil, this should never happen")
	require.False(t, isLastBlockInCurrentEpoch)

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
	setBalanceModelBlockHeights()
	defer resetBalanceModelBlockHeights()

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize fork heights.
	params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = uint32(1)
	params.ForkHeights.ProofOfStakeBlockHeight = uint32(1)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
	require.NoError(t, err)

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
	_registerOrTransferWithTestMeta(testMeta, "m5", senderPkString, m5Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "m6", senderPkString, m6Pub, senderPrivString, 1e3)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 1e3)

	m0PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m0PkBytes).PKID
	m1PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m1PkBytes).PKID
	m2PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m2PkBytes).PKID
	m3PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m3PkBytes).PKID
	m4PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m4PkBytes).PKID
	m5PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m5PkBytes).PKID
	m6PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m6PkBytes).PKID
	_, _, _, _, _, _, _ = m0PKID, m1PKID, m2PKID, m3PKID, m4PKID, m5PKID, m6PKID

	// Seed a CurrentEpochEntry.
	utxoView._setCurrentEpochEntry(&EpochEntry{EpochNumber: 1, FinalBlockHeight: blockHeight})
	require.NoError(t, utxoView.FlushToDb(blockHeight))

	// Helper utils
	_registerAndStake := func(publicKey string, privateKey string, stakeAmountNanos uint64) {
		// Convert PublicKeyBase58Check to PublicKeyBytes.
		pkBytes, _, err := Base58CheckDecode(publicKey)
		require.NoError(t, err)

		// Validator registers.
		votingPublicKey, votingSignature := _generateVotingPublicKeyAndSignature(t, pkBytes, blockHeight)
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains:                  [][]byte{[]byte(fmt.Sprintf("https://%s.com", publicKey))},
			VotingPublicKey:          votingPublicKey,
			VotingPublicKeySignature: votingSignature,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, publicKey, privateKey, registerMetadata, nil, true)
		require.NoError(t, err)

		// Validator stakes to himself.
		if stakeAmountNanos == 0 {
			return
		}
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(pkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(stakeAmountNanos),
		}
		_, err = _submitStakeTxn(testMeta, publicKey, privateKey, stakeMetadata, nil, true)
		require.NoError(t, err)
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
		// All validators register + stake to themselves.
		_registerAndStake(m0Pub, m0Priv, 100)
		_registerAndStake(m1Pub, m1Priv, 200)
		_registerAndStake(m2Pub, m2Priv, 300)
		_registerAndStake(m3Pub, m3Priv, 400)
		_registerAndStake(m4Pub, m4Priv, 500)
		_registerAndStake(m5Pub, m5Priv, 600)
		_registerAndStake(m6Pub, m6Priv, 700)

		validatorEntries, err := utxoView.GetTopActiveValidatorsByStake(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 7)
	}
	{
		// Test SnapshotGlobalParamsEntry is nil.
		snapshotGlobalParamsEntry, err := utxoView.GetSnapshotGlobalParamsEntry(1)
		require.NoError(t, err)
		require.Nil(t, snapshotGlobalParamsEntry)

		// Test SnapshotValidatorByPKID is nil.
		for _, pkid := range []*PKID{m0PKID, m1PKID, m2PKID, m3PKID, m4PKID, m5PKID, m6PKID} {
			snapshotValidatorEntry, err := utxoView.GetSnapshotValidatorByPKID(pkid, 1)
			require.NoError(t, err)
			require.Nil(t, snapshotValidatorEntry)
		}

		// Test SnapshotTopActiveValidatorsByStake is empty.
		// TODO

		// Test SnapshotGlobalActiveStakeAmountNanos is nil.
		snapshotGlobalActiveStakeAmountNanos, err := utxoView.GetSnapshotGlobalActiveStakeAmountNanos(1)
		require.NoError(t, err)
		require.Nil(t, snapshotGlobalActiveStakeAmountNanos)

		// Test SnapshotLeaderSchedule is nil.
		// TODO
	}
	{
		// Test RunOnEpochCompleteHook().
		require.NoError(t, utxoView.FlushToDb(blockHeight))
		require.NoError(t, utxoView.RunEpochCompleteHook(blockHeight))
		require.NoError(t, utxoView.FlushToDb(blockHeight))
	}
	{
		// Test SnapshotGlobalParamsEntry is populated.
		snapshotGlobalParamsEntry, err := utxoView.GetSnapshotGlobalParamsEntry(1)
		require.NoError(t, err)
		require.NotNil(t, snapshotGlobalParamsEntry)
		//require.Equal(t, snapshotGlobalParamsEntry.MinimumNetworkFeeNanosPerKB, testMeta.feeRateNanosPerKb)

		// Test SnapshotValidatorByPKID is populated.
		for _, pkid := range []*PKID{m0PKID, m1PKID, m2PKID, m3PKID, m4PKID, m5PKID, m6PKID} {
			snapshotValidatorEntry, err := utxoView.GetSnapshotValidatorByPKID(pkid, 1)
			require.NoError(t, err)
			require.NotNil(t, snapshotValidatorEntry)
		}

		// Test SnapshotTopActiveValidatorsByStake is populated.
		// TODO

		// Test SnapshotGlobalActiveStakeAmountNanos is populated.
		snapshotGlobalActiveStakeAmountNanos, err := utxoView.GetSnapshotGlobalActiveStakeAmountNanos(1)
		require.NoError(t, err)
		require.Equal(t, snapshotGlobalActiveStakeAmountNanos, uint256.NewInt().SetUint64(2800))

		// Test SnapshotLeaderSchedule is populated.
		// TODO
	}
}
