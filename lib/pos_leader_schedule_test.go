package lib

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestGenerateLeaderSchedule(t *testing.T) {
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
		_, err := miner.MineAndProcessSingleBlock(0, mempool)
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

	// Helper utils
	newUtxoView := func() *UtxoView {
		utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
		return utxoView
	}

	registerValidator := func(publicKey string, privateKey string, stakeAmountNanos uint64) {
		// Convert PublicKeyBase58Check to PublicKeyBytes.
		pkBytes, _, err := Base58CheckDecode(publicKey)
		require.NoError(t, err)

		// Validator registers.
		votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, pkBytes)
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains:             [][]byte{[]byte(fmt.Sprintf("%s.com:18000", publicKey))},
			VotingPublicKey:     votingPublicKey,
			VotingAuthorization: votingAuthorization,
		}
		_, err = _submitRegisterAsValidatorTxn(testMeta, publicKey, privateKey, registerMetadata, nil, true)
		require.NoError(t, err)

		// Validator stakes to himself.
		if stakeAmountNanos == 0 {
			return
		}
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(pkBytes),
			StakeAmountNanos:   uint256.NewInt(0).SetUint64(stakeAmountNanos),
		}
		_, err = _submitStakeTxn(testMeta, publicKey, privateKey, stakeMetadata, nil, true)
		require.NoError(t, err)
	}

	setCurrentRandomSeedHash := func(seed string) {
		randomSHA256 := sha256.Sum256([]byte(seed))
		randomSeedHash, err := (&RandomSeedHash{}).FromBytes(randomSHA256[:])
		require.NoError(t, err)
		tmpUtxoView := newUtxoView()
		tmpUtxoView._setCurrentRandomSeedHash(randomSeedHash)
		require.NoError(t, tmpUtxoView.FlushToDb(blockHeight))
	}

	getValidatorSet := func() []*ValidatorEntry {
		utxoView := newUtxoView()
		leaderScheduleMaxNumValidators := utxoView.GetCurrentGlobalParamsEntry().LeaderScheduleMaxNumValidators
		maxValidatorSetSize := utxoView.GetCurrentGlobalParamsEntry().ValidatorSetMaxNumValidators
		maxValidatorsToFetch := leaderScheduleMaxNumValidators
		if maxValidatorsToFetch < maxValidatorSetSize {
			maxValidatorsToFetch = maxValidatorSetSize
		}
		maxValidatorSet, err := utxoView.GetTopActiveValidatorsByStakeAmount(maxValidatorsToFetch)
		require.NoError(t, err)
		return maxValidatorSet
	}

	testGenerateLeaderSchedule := func(expectedOrder []*PKID) {
		// We test that GenerateLeaderSchedule() is idempotent by running it 10 times.
		// Given the same CurrentRandomSeedHash and the same stake-weighted validators,
		// we verify that we generate the same leader schedule each time.
		for ii := 0; ii < 10; ii++ {
			maxValidatorSet := getValidatorSet()
			leaderSchedule, err := newUtxoView().GenerateLeaderSchedule(maxValidatorSet)
			require.NoError(t, err)
			require.Len(t, leaderSchedule, len(expectedOrder))

			for index, pkid := range leaderSchedule {
				require.Equal(t, pkid, expectedOrder[index])
			}
		}
	}

	// Seed a CurrentEpochEntry.
	tmpUtxoView := newUtxoView()
	tmpUtxoView._setCurrentEpochEntry(&EpochEntry{EpochNumber: 1, FinalBlockHeight: blockHeight + 10})
	require.NoError(t, tmpUtxoView.FlushToDb(blockHeight))

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
		// Test GenerateLeaderSchedule() edge case: no registered validators.
		leaderSchedule, err := newUtxoView().GenerateLeaderSchedule(nil)
		require.NoError(t, err)
		require.Empty(t, leaderSchedule)
	}
	{
		// m0 registers as validator.
		registerValidator(m0Pub, m0Priv, 0)
	}
	{
		// Test GenerateLeaderSchedule() edge case: one registered validator with zero stake.
		leaderSchedule, err := newUtxoView().GenerateLeaderSchedule([]*ValidatorEntry{})
		require.NoError(t, err)
		require.Empty(t, leaderSchedule)
	}
	{
		// m0 stakes to himself.
		registerValidator(m0Pub, m0Priv, 10)
	}
	{
		// Test GenerateLeaderSchedule() edge case: one registered validator with non-zero stake.
		leaderSchedule, err := newUtxoView().GenerateLeaderSchedule(getValidatorSet())
		require.NoError(t, err)
		require.Len(t, leaderSchedule, 1)
		require.Equal(t, leaderSchedule[0], m0PKID)
	}
	{
		// m1 registers and stakes to himself.
		registerValidator(m1Pub, m1Priv, 20)
	}
	{
		// Test GenerateLeaderSchedule() edge case: two registered validators with non-zero stake.
		leaderSchedule, err := newUtxoView().GenerateLeaderSchedule(getValidatorSet())
		require.NoError(t, err)
		require.Len(t, leaderSchedule, 2)
		require.Equal(t, leaderSchedule[0], m1PKID)
		require.Equal(t, leaderSchedule[1], m0PKID)
	}
	{
		// All remaining validators register and stake to themselves.
		registerValidator(m2Pub, m2Priv, 30)
		registerValidator(m3Pub, m3Priv, 40)
		registerValidator(m4Pub, m4Priv, 500)
		registerValidator(m5Pub, m5Priv, 600)
		registerValidator(m6Pub, m6Priv, 700)
	}
	{
		// Verify GetTopActiveValidatorsByStakeAmount.
		validatorEntries, err := newUtxoView().GetTopActiveValidatorsByStakeAmount(10)
		require.NoError(t, err)
		require.Len(t, validatorEntries, 7)
		require.True(t, validatorEntries[0].ValidatorPKID.Eq(m6PKID))
		require.True(t, validatorEntries[1].ValidatorPKID.Eq(m5PKID))
		require.True(t, validatorEntries[2].ValidatorPKID.Eq(m4PKID))
		require.True(t, validatorEntries[3].ValidatorPKID.Eq(m3PKID))
		require.True(t, validatorEntries[4].ValidatorPKID.Eq(m2PKID))
		require.True(t, validatorEntries[5].ValidatorPKID.Eq(m1PKID))
		require.True(t, validatorEntries[6].ValidatorPKID.Eq(m0PKID))
		require.Equal(t, validatorEntries[0].TotalStakeAmountNanos.Uint64(), uint64(700))
		require.Equal(t, validatorEntries[1].TotalStakeAmountNanos.Uint64(), uint64(600))
		require.Equal(t, validatorEntries[2].TotalStakeAmountNanos.Uint64(), uint64(500))
		require.Equal(t, validatorEntries[3].TotalStakeAmountNanos.Uint64(), uint64(40))
		require.Equal(t, validatorEntries[4].TotalStakeAmountNanos.Uint64(), uint64(30))
		require.Equal(t, validatorEntries[5].TotalStakeAmountNanos.Uint64(), uint64(20))
		require.Equal(t, validatorEntries[6].TotalStakeAmountNanos.Uint64(), uint64(10))
	}
	{
		// Test GenerateLeaderSchedule().
		testGenerateLeaderSchedule([]*PKID{m6PKID, m5PKID, m4PKID, m2PKID, m3PKID, m1PKID, m0PKID})
	}
	{
		// Seed a new CurrentRandomSeedHash.
		setCurrentRandomSeedHash("3b4b028b-6a7c-4b38-bea3-a5f59b34e02d")
		// Test GenerateLeaderSchedule().
		testGenerateLeaderSchedule([]*PKID{m6PKID, m5PKID, m3PKID, m4PKID, m2PKID, m0PKID, m1PKID})
	}
	{
		// Seed a new CurrentRandomSeedHash.
		setCurrentRandomSeedHash("b4b38eaf-216d-4132-8725-a481baaf87cc")
		// Test GenerateLeaderSchedule().
		testGenerateLeaderSchedule([]*PKID{m4PKID, m5PKID, m6PKID, m3PKID, m1PKID, m2PKID, m0PKID})
	}
	{
		// Seed a new CurrentRandomSeedHash.
		setCurrentRandomSeedHash("7c87f290-d9ec-4cb4-ad47-c64c8ca46f0e")
		// Test GenerateLeaderSchedule().
		testGenerateLeaderSchedule([]*PKID{m6PKID, m2PKID, m4PKID, m5PKID, m3PKID, m1PKID, m0PKID})
	}
	{
		// Seed a new CurrentRandomSeedHash.
		setCurrentRandomSeedHash("0999a3ce-15e4-455a-b061-6081b88b237d")
		// Test GenerateLeaderSchedule().
		testGenerateLeaderSchedule([]*PKID{m6PKID, m5PKID, m4PKID, m2PKID, m1PKID, m0PKID, m3PKID})
	}
	{
		// Seed a new CurrentRandomSeedHash.
		setCurrentRandomSeedHash("dbfffc42-3c40-49c4-a3df-cfbd2606cce2")
		// Test GenerateLeaderSchedule().
		testGenerateLeaderSchedule([]*PKID{m6PKID, m5PKID, m4PKID, m3PKID, m0PKID, m2PKID, m1PKID})
	}
	{
		// Seed a new CurrentRandomSeedHash.
		setCurrentRandomSeedHash("ceea0ad8-7277-4468-a0a1-8bacb78b01ca")
		// Test GenerateLeaderSchedule().
		testGenerateLeaderSchedule([]*PKID{m3PKID, m5PKID, m6PKID, m4PKID, m2PKID, m1PKID, m0PKID})
	}
	{
		// Test changing LeaderScheduleMaxNumValidators.
		params.DefaultLeaderScheduleMaxNumValidators = 5
		leaderSchedule, err := newUtxoView().GenerateLeaderSchedule(getValidatorSet())
		require.NoError(t, err)
		require.Len(t, leaderSchedule, 5)
	}

	// Test rollbacks.
	_executeAllTestRollbackAndFlush(testMeta)
}
