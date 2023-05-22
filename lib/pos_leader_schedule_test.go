//go:build relic

package lib

import (
	"crypto/sha256"
	"fmt"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGenerateLeaderSchedule(t *testing.T) {
	// Initialize fork heights.
	setBalanceModelBlockHeights()
	defer resetBalanceModelBlockHeights()

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize PoS txn types block height.
	params.ForkHeights.ProofOfStakeNewTxnTypesBlockHeight = uint32(1)
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
	type TestValidator struct {
		PublicKey  string
		PrivateKey string
		PKID       *PKID
	}

	testValidators := []*TestValidator{
		{PublicKey: m0Pub, PrivateKey: m0Priv, PKID: m0PKID}, // Stake = 100
		{PublicKey: m1Pub, PrivateKey: m1Priv, PKID: m1PKID}, // Stake = 200
		{PublicKey: m2Pub, PrivateKey: m2Priv, PKID: m2PKID}, // Stake = 300
		{PublicKey: m3Pub, PrivateKey: m3Priv, PKID: m3PKID}, // Stake = 400
		{PublicKey: m4Pub, PrivateKey: m4Priv, PKID: m4PKID}, // Stake = 500
		{PublicKey: m5Pub, PrivateKey: m5Priv, PKID: m5PKID}, // Stake = 600
		{PublicKey: m6Pub, PrivateKey: m6Priv, PKID: m6PKID}, // Stake = 700
	}

	newUtxoView := func() *UtxoView {
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(t, err)
		return utxoView
	}

	registerValidator := func(testValidator *TestValidator) {
		validatorPkBytes, _, err := Base58CheckDecode(testValidator.PublicKey)
		require.NoError(t, err)

		// Validator registers.
		votingPublicKey, votingSignature := _generateVotingPublicKeyAndSignature(t, validatorPkBytes, blockHeight)
		registerMetadata := &RegisterAsValidatorMetadata{
			Domains:                  [][]byte{[]byte(fmt.Sprintf("https://%s.com", testValidator.PublicKey))},
			VotingPublicKey:          votingPublicKey,
			VotingPublicKeySignature: votingSignature,
		}
		_, err = _submitRegisterAsValidatorTxn(
			testMeta, testValidator.PublicKey, testValidator.PrivateKey, registerMetadata, nil, true,
		)
		require.NoError(t, err)
	}

	stakeValidator := func(testValidator *TestValidator, stakeAmountNanos uint64) {
		validatorPkBytes, _, err := Base58CheckDecode(testValidator.PublicKey)
		require.NoError(t, err)
		stakeMetadata := &StakeMetadata{
			ValidatorPublicKey: NewPublicKey(validatorPkBytes),
			StakeAmountNanos:   uint256.NewInt().SetUint64(stakeAmountNanos),
		}
		_, err = _submitStakeTxn(testMeta, testValidator.PublicKey, testValidator.PrivateKey, stakeMetadata, nil, true)
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

	// Seed a CurrentEpochEntry.
	tmpUtxoView := newUtxoView()
	tmpUtxoView._setCurrentEpochEntry(&EpochEntry{EpochNumber: 1, FinalBlockHeight: blockHeight + 10})
	require.NoError(t, tmpUtxoView.FlushToDb(blockHeight))

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
		// Test GenerateLeaderSchedule() edge case: no registered validators.
		leaderSchedule, err := newUtxoView().GenerateLeaderSchedule()
		require.NoError(t, err)
		require.Empty(t, leaderSchedule)
	}
	{
		// m0 registers as validator.
		registerValidator(testValidators[0])
	}
	{
		// Test GenerateLeaderSchedule() edge case: one registered validator with zero stake.
		leaderSchedule, err := newUtxoView().GenerateLeaderSchedule()
		require.NoError(t, err)
		require.Empty(t, leaderSchedule)
	}
	{
		// m0 stakes to himself.
		stakeValidator(testValidators[0], 100)
	}
	{
		// Test GenerateLeaderSchedule() edge case: one registered validator with non-zero stake.
		leaderSchedule, err := newUtxoView().GenerateLeaderSchedule()
		require.NoError(t, err)
		require.Len(t, leaderSchedule, 1)
		require.Equal(t, leaderSchedule[0].ValidatorPKID, testValidators[0].PKID)
	}
	{
		// m1 registers and stakes to himself.
		registerValidator(testValidators[1])
		stakeValidator(testValidators[1], 200)
	}
	{
		// Test GenerateLeaderSchedule() edge case: two registered validators with non-zero stake.
		leaderSchedule, err := newUtxoView().GenerateLeaderSchedule()
		require.NoError(t, err)
		require.Len(t, leaderSchedule, 2)
		require.Equal(t, leaderSchedule[0].ValidatorPKID, testValidators[0].PKID)
		require.Equal(t, leaderSchedule[1].ValidatorPKID, testValidators[1].PKID)
	}
	{
		// All remaining validators register and stake to themselves.
		for index, testValidator := range testValidators {
			registerValidator(testValidator)
			if index > 1 {
				stakeValidator(testValidator, uint64((index+1)*100))
			}
		}
	}
	{
		// Verify GetTopActiveValidatorsByStake.
		validatorEntries, err := newUtxoView().GetTopActiveValidatorsByStake(10)
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
		require.Equal(t, validatorEntries[3].TotalStakeAmountNanos.Uint64(), uint64(400))
		require.Equal(t, validatorEntries[4].TotalStakeAmountNanos.Uint64(), uint64(300))
		require.Equal(t, validatorEntries[5].TotalStakeAmountNanos.Uint64(), uint64(200))
		require.Equal(t, validatorEntries[6].TotalStakeAmountNanos.Uint64(), uint64(100))
	}
	{
		// Test GenerateLeaderSchedule().
		leaderSchedule, err := newUtxoView().GenerateLeaderSchedule()
		require.NoError(t, err)
		require.Len(t, leaderSchedule, 7)
		require.Equal(t, leaderSchedule[0].ValidatorPKID, testValidators[3].PKID)
		require.Equal(t, leaderSchedule[1].ValidatorPKID, testValidators[2].PKID)
		require.Equal(t, leaderSchedule[2].ValidatorPKID, testValidators[1].PKID)
		require.Equal(t, leaderSchedule[3].ValidatorPKID, testValidators[0].PKID)
		require.Equal(t, leaderSchedule[4].ValidatorPKID, testValidators[6].PKID)
		require.Equal(t, leaderSchedule[5].ValidatorPKID, testValidators[5].PKID)
		require.Equal(t, leaderSchedule[6].ValidatorPKID, testValidators[4].PKID)
	}
	{
		// Seed a new CurrentRandomSeedHash.
		setCurrentRandomSeedHash("3b4b028b-6a7c-4b38-bea3-a5f59b34e02d")

		// Test GenerateLeaderSchedule().
		leaderSchedule, err := newUtxoView().GenerateLeaderSchedule()
		require.NoError(t, err)
		require.Len(t, leaderSchedule, 7)
		require.Equal(t, leaderSchedule[0].ValidatorPKID, testValidators[6].PKID)
		require.Equal(t, leaderSchedule[1].ValidatorPKID, testValidators[5].PKID)
		require.Equal(t, leaderSchedule[2].ValidatorPKID, testValidators[4].PKID)
		require.Equal(t, leaderSchedule[3].ValidatorPKID, testValidators[3].PKID)
		require.Equal(t, leaderSchedule[4].ValidatorPKID, testValidators[2].PKID)
		require.Equal(t, leaderSchedule[5].ValidatorPKID, testValidators[1].PKID)
		require.Equal(t, leaderSchedule[6].ValidatorPKID, testValidators[0].PKID)
	}
	{
		// Seed a new CurrentRandomSeedHash.
		setCurrentRandomSeedHash("b4b38eaf-216d-4132-8725-a481baaf87cc")

		// Test GenerateLeaderSchedule().
		leaderSchedule, err := newUtxoView().GenerateLeaderSchedule()
		require.NoError(t, err)
		require.Len(t, leaderSchedule, 7)
		require.Equal(t, leaderSchedule[0].ValidatorPKID, testValidators[6].PKID)
		require.Equal(t, leaderSchedule[1].ValidatorPKID, testValidators[5].PKID)
		require.Equal(t, leaderSchedule[2].ValidatorPKID, testValidators[4].PKID)
		require.Equal(t, leaderSchedule[3].ValidatorPKID, testValidators[3].PKID)
		require.Equal(t, leaderSchedule[4].ValidatorPKID, testValidators[2].PKID)
		require.Equal(t, leaderSchedule[5].ValidatorPKID, testValidators[1].PKID)
		require.Equal(t, leaderSchedule[6].ValidatorPKID, testValidators[0].PKID)
	}
	{
		// Seed a new CurrentRandomSeedHash.
		setCurrentRandomSeedHash("7c87f290-d9ec-4cb4-ad47-c64c8ca46f0e")

		// Test GenerateLeaderSchedule().
		leaderSchedule, err := newUtxoView().GenerateLeaderSchedule()
		require.NoError(t, err)
		require.Len(t, leaderSchedule, 7)
		require.Equal(t, leaderSchedule[0].ValidatorPKID, testValidators[3].PKID)
		require.Equal(t, leaderSchedule[1].ValidatorPKID, testValidators[2].PKID)
		require.Equal(t, leaderSchedule[2].ValidatorPKID, testValidators[1].PKID)
		require.Equal(t, leaderSchedule[3].ValidatorPKID, testValidators[0].PKID)
		require.Equal(t, leaderSchedule[4].ValidatorPKID, testValidators[4].PKID)
		require.Equal(t, leaderSchedule[5].ValidatorPKID, testValidators[6].PKID)
		require.Equal(t, leaderSchedule[6].ValidatorPKID, testValidators[5].PKID)
	}
	{
		// Seed a new CurrentRandomSeedHash.
		setCurrentRandomSeedHash("0999a3ce-15e4-455a-b061-6081b88b237d")

		// Test GenerateLeaderSchedule().
		leaderSchedule, err := newUtxoView().GenerateLeaderSchedule()
		require.NoError(t, err)
		require.Len(t, leaderSchedule, 7)
		require.Equal(t, leaderSchedule[0].ValidatorPKID, testValidators[5].PKID)
		require.Equal(t, leaderSchedule[1].ValidatorPKID, testValidators[4].PKID)
		require.Equal(t, leaderSchedule[2].ValidatorPKID, testValidators[3].PKID)
		require.Equal(t, leaderSchedule[3].ValidatorPKID, testValidators[2].PKID)
		require.Equal(t, leaderSchedule[4].ValidatorPKID, testValidators[1].PKID)
		require.Equal(t, leaderSchedule[5].ValidatorPKID, testValidators[0].PKID)
		require.Equal(t, leaderSchedule[6].ValidatorPKID, testValidators[6].PKID)
	}

	// Test rollbacks.
	_executeAllTestRollbackAndFlush(testMeta)
}
