package lib

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCoinLockupTxnRuleErrors(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Attempt to perform a lockup of amount zero.
	// (This should fail -- RuleErrorCoinLockupOfAmountZero)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			m0Pub,
			0,
			uint256.NewInt(),
			0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupOfAmountZero)
	}

	// Attempt to perform a lockup on a non-existent profile.
	// (This should fail -- RuleErrorCoinLockupOnNonExistentProfile)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			m2Pub,
			0,
			uint256.NewInt().SetUint64(1),
			0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupOnNonExistentProfile)
	}

	// Attempt to perform an excessive DESO lockup (more than 2**64 DESO).
	// (This should fail -- RuleErrorCoinLockupExcessiveDeSoLockup)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
			0,
			MaxUint256,
			0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupExcessiveDeSoLockup)
	}

	// Attempt to perform a lockup with zero lockup duration.
	// (This should fail -- RuleErrorCoinLockupInvalidLockupDuration)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
			0,
			uint256.NewInt().SetUint64(1),
			0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupInvalidLockupDuration)
	}

	// Attempt to perform a lockup with negative lockup duration.
	// (This should fail -- RuleErrorCoinLockupInvalidLockupDuration)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
			0,
			uint256.NewInt().SetUint64(1),
			1)
		require.Contains(t, err.Error(), RuleErrorCoinLockupInvalidLockupDuration)
	}

	// Attempt to perform a lockup in excess of the user's DESO balance.
	// (This should fail -- RuleErrorCoinLockupInsufficientDeSo)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
			1,
			uint256.NewInt().SetUint64(1e10),
			0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupInsufficientDeSo)
	}

	// Attempt to perform a lockup in excess of the user's coin balance.
	// (This should fail -- RuleErrorCoinLockupInsufficientCoins)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			m0Pub,
			1,
			uint256.NewInt().SetUint64(1e10),
			0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupInsufficientCoins)
	}

	// NOTE: The only other rule errors for coin lockup txns are related to yield curve overflows.
	//       This is tested separately and more comprehensively in a different test.

	// Attempt to perform a valid and simple coin lockup transaction.
	// This should succeed :)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			m0Pub,
			1000,
			uint256.NewInt().SetUint64(1000),
			0)
		require.NoError(t, err)
	}
}

func TestUpdateCoinLockupParamsTxnRuleErrors(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Attempt to create a lockup yield point with negative duration.
	// (This should fail -- RuleErrorUpdateCoinLockupParamsNegativeDuration)
	{
		_, _, _, err := _updateCoinLockupParams(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			int64(-1),
			0,
			false,
			false,
			TransferRestrictionStatusUnrestricted,
		)
		require.Contains(t, err.Error(), RuleErrorUpdateCoinLockupParamsNegativeDuration)
	}

	// Attempt to delete a non-existent yield curve point.
	// (This should fail -- RuleErrorUpdateCoinLockupParamsDeletingNonExistentPoint)
	{
		_, _, _, err := _updateCoinLockupParams(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			int64(1e9),
			0,
			true,
			false,
			TransferRestrictionStatusUnrestricted,
		)
		require.Contains(t, err.Error(), RuleErrorUpdateCoinLockupParamsDeletingNonExistentPoint)
	}

	// Attempt to update the transfer restrictions of a non-existent profile.
	// (This should fail -- RuleErrorUpdateCoinLockupParamsUpdatingNonExistentProfile)
	{
		_, _, _, err := _updateCoinLockupParams(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			int64(1e9),
			0,
			false,
			true,
			TransferRestrictionStatusUnrestricted,
		)
		require.Contains(t, err.Error(), RuleErrorUpdateCoinLockupParamsUpdatingNonExistentProfile)
	}

	// Attempt to update PermanentlyUnrestricted transfer restrictions.
	// (This should fail -- RuleErrorUpdateCoinLockupParamsUpdatingPermanentTransferRestriction)
	{
		// First update transfer restrictions to TransferRestrictionStatusPermanentlyUnrestricted.
		// This should be a valid transaction.
		_updateCoinLockupParamsWithTestMeta(testMeta,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			0,
			0,
			false,
			true,
			TransferRestrictionStatusPermanentlyUnrestricted,
		)

		// Now attempt to further update the transfer restrictions.
		// (This should fail -- RuleErrorUpdateCoinLockupParamsUpdatingPermanentTransferRestriction)
		_, _, _, err := _updateCoinLockupParams(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			0,
			0,
			false,
			true,
			TransferRestrictionStatusUnrestricted,
		)
		require.Contains(t, err.Error(), RuleErrorUpdateCoinLockupParamsUpdatingPermanentTransferRestriction)
	}

	// Attempt to update transfer restrictions to an invalid transfer restriction status.
	// (This should fail -- RuleErrorUpdateCoinLockupParamsInvalidRestrictions)
	{
		_, _, _, err := _updateCoinLockupParams(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			int64(1e9),
			0,
			false,
			true,
			TransferRestrictionStatus(uint8(255)),
		)
		require.Contains(t, err.Error(), RuleErrorUpdateCoinLockupParamsInvalidRestrictions)
	}

	// Attempt to perform a valid and simple update coin lockup param transaction.
	// This should succeed :)
	{
		_, _, _, err := _updateCoinLockupParams(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			365*25*60*60*1e9,
			500,
			false,
			true,
			TransferRestrictionStatusProfileOwnerOnly,
		)
		require.NoError(t, err)
	}
}

func TestCoinLockupTransferTxnRuleErrors(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Attempt to perform a lockup transfer of zero coins.
	// (This should fail -- RuleErrorCoinLockupTransferOfAmountZero)
	{
		_, _, _, err := _coinLockupTransfer(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			NewPublicKey(m3PkBytes),
			NewPublicKey(m0PkBytes),
			0,
			uint256.NewInt())
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferOfAmountZero)
	}

	// Attempt to perform a locked DESO transfer in excess of 2**64.
	// (This should fail -- RuleErrorCoinLockupTransferOfDeSoCausesOverflow)
	{
		_, _, _, err := _coinLockupTransfer(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			NewPublicKey(m3PkBytes),
			&ZeroPublicKey,
			0,
			MaxUint256)
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferOfDeSoCausesOverflow)
	}

	// Attempt to perform a coin lockup transfer on coins from a non-existent profile.
	// (This should fail -- RuleErrorCoinLockupTransferOnNonExistentProfile)
	{
		_, _, _, err := _coinLockupTransfer(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			NewPublicKey(m3PkBytes),
			NewPublicKey(m3PkBytes),
			0,
			MaxUint256)
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferOnNonExistentProfile)
	}

	// Attempt to perform a coin lockup transfer where the sender is the receiver.
	// (This should fail -- RuleErrorCoinLockupTransferSenderEqualsReceiver)
	{
		_, _, _, err := _coinLockupTransfer(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			NewPublicKey(m0PkBytes),
			NewPublicKey(m0PkBytes),
			0,
			MaxUint256)
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferSenderEqualsReceiver)
	}

	// Attempt to perform an excessive coin lockup transfer.
	// (This should fail -- RuleErrorCoinLockupTransferInsufficientBalance)
	{
		_, _, _, err := _coinLockupTransfer(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			NewPublicKey(m3PkBytes),
			NewPublicKey(m0PkBytes),
			0,
			MaxUint256)
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferInsufficientBalance)
	}

	// Attempt to violate profile owner only transfer restrictions.
	// (This should fail -- RuleErrorCoinLockupTransferRestrictedToProfileOwner)
	{
		// Set M0 locked transfer restrictions to profile owner only.
		_updateCoinLockupParamsWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			0,
			0,
			false,
			true,
			TransferRestrictionStatusProfileOwnerOnly,
		)

		// Lockup 1000 M0 coins.
		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			m0Pub,
			1,
			uint256.NewInt().SetUint64(1e6),
			0,
		)

		// Send 1000 locked M0 coins to M2.
		_coinLockupTransferWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			NewPublicKey(m2PkBytes),
			NewPublicKey(m0PkBytes),
			1,
			uint256.NewInt().SetUint64(1e6),
		)

		// Attempt to have M2 send locked M0 coins to M3.
		// (This should fail -- RuleErrorCoinLockupTransferRestrictedToProfileOwner)
		_, _, _, err := _coinLockupTransfer(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			NewPublicKey(m3PkBytes),
			NewPublicKey(m0PkBytes),
			1,
			uint256.NewInt().SetUint64(1))
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferRestrictedToProfileOwner)
	}

	// Attempt to violate DAO member only transfer restrictions.
	// (This should fail -- RuleErrorCoinLockupTransferRestrictedToDAOMembers)
	{
		// Set M0 locked transfer restrictions to dao members owner only.
		_updateCoinLockupParamsWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			0,
			0,
			false,
			true,
			TransferRestrictionStatusDAOMembersOnly,
		)

		// Attempt to have M2 send locked M0 coins to M3.
		// (This should fail -- RuleErrorCoinLockupTransferRestrictedToDAOMembers)
		_, _, _, err := _coinLockupTransfer(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			NewPublicKey(m3PkBytes),
			NewPublicKey(m0PkBytes),
			1,
			uint256.NewInt().SetUint64(1))
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferRestrictedToDAOMembers)
	}

	// NOTE: There's one more rule error: RuleErrorCoinLockupTransferBalanceOverflowAtReceiver
	//       This one is particularly challenging to trigger as it's yield based.
	//       For this reason we deal with it in other more specified yield focused tests.
}

func TestCoinUnlockTxnRuleErrors(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Attempt to unlock coins associated with a non-existent profile.
	// (This should fail -- RuleErrorCoinUnlockOnNonExistentProfile)
	{
		_, _, _, err := _coinUnlockWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			m2Pub,
			0)
		require.Contains(t, err.Error(), RuleErrorCoinUnlockOnNonExistentProfile)
	}

	// Attempt to unlock locked coins which do not exist.
	// (This should fail -- RuleErrorCoinUnlockNoUnlockableCoinsFound)
	{
		_, _, _, err := _coinUnlockWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			m0Pub,
			0)
		require.Contains(t, err.Error(), RuleErrorCoinUnlockNoUnlockableCoinsFound)
	}

	// TODO: Cause unlockable balance overflow test. Tricky as it relies on yield.
}

//----------------------------------------------------------
// (Testing) Lockup Setup Helper Functions
//----------------------------------------------------------

// _setUpProfilesAndMintM0M1DAOCoins is a simple helper function that takes as input
// a TestMeta struct with the following fields:
//
// miner - 10 blocks worth of DESO mined in their balance. Assumed to be senderPkString.
// (no other state)
//
// After running the _setUpProfilesAndMintM0M1DAOCoins, the following state is expected:
//
// miner - ~10 blocks worth of DESO mined in their balance
// m0Pub - ~10,000 nDESO, m0 profile, and 1,000,000 m0 DAO coins minted and held
// m1Pub - ~10,000 nDESO, m1 profile, and 1,000,000,000 m1 DAO coins minted and held
// m2Pub - 10,000 nDESO
// m3Pub - 10,000 nDESO
// m4Pub - 10,000 nDESO
// paramUpdaterPub - 10,000 nDESO
func _setUpProfilesAndMintM0M1DAOCoins(testMeta *TestMeta) {
	// Create on-chain public keys with DESO sent from miner
	_registerOrTransferWithTestMeta(testMeta, "m0", senderPkString, m0Pub, senderPrivString, 10000)
	_registerOrTransferWithTestMeta(testMeta, "m1", senderPkString, m1Pub, senderPrivString, 10000)
	_registerOrTransferWithTestMeta(testMeta, "m2", senderPkString, m2Pub, senderPrivString, 10000)
	_registerOrTransferWithTestMeta(testMeta, "m3", senderPkString, m3Pub, senderPrivString, 10000)
	_registerOrTransferWithTestMeta(testMeta, "m4", senderPkString, m4Pub, senderPrivString, 10000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 10000)

	// Create on-chain profile for m0
	{
		_updateProfileWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			[]byte{},
			"m0",
			"i am the m0",
			shortPic,
			10*100,
			1.25*100*100,
			false,
		)
	}

	// Create on-chain profile for m1
	{
		_updateProfileWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			[]byte{},
			"m1",
			"i am the m1",
			shortPic,
			10*100,
			1.25*100*100,
			false,
		)
	}

	// Create 1,000,000 m0 dao coins held by m0
	{
		_daoCoinTxnWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			DAOCoinMetadata{
				ProfilePublicKey:          m0PkBytes,
				OperationType:             DAOCoinOperationTypeMint,
				CoinsToMintNanos:          *uint256.NewInt().SetUint64(1e6),
				CoinsToBurnNanos:          uint256.Int{},
				TransferRestrictionStatus: 0,
			})
	}

	// Create 1,000,000,000 m1 dao coins held by m1
	{
		_daoCoinTxnWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			DAOCoinMetadata{
				ProfilePublicKey:          m1PkBytes,
				OperationType:             DAOCoinOperationTypeMint,
				CoinsToMintNanos:          *uint256.NewInt().SetUint64(1e9),
				CoinsToBurnNanos:          uint256.Int{},
				TransferRestrictionStatus: 0,
			})
	}
}

func _setUpMinerAndTestMetaForTimestampBasedLockupTests(t *testing.T) *TestMeta {
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Ensure DAO coins are enabled (a pre-requisite for lockups)
	params.ForkHeights.DAOCoinBlockHeight = uint32(0)

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

//----------------------------------------------------------
// (Testing) Lockup Transaction Connection Helper Functions
//----------------------------------------------------------

func _coinLockupWithTestMetaAndConnectTimestamp(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	profilePublicKeyBase58Check string,
	unlockTimestampNanoSecs int64,
	lockupAmountBaseUnits *uint256.Int,
	connectTimestamp int64) {

	testMeta.expectedSenderBalances =
		append(testMeta.expectedSenderBalances,
			_getBalance(testMeta.t, testMeta.chain, nil, transactorPublicKeyBase58Check))

	currentOps, currentTxn, _, err := _coinLockupWithConnectTimestamp(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB, transactorPublicKeyBase58Check, transactorPrivateKeyBase58Check,
		profilePublicKeyBase58Check, unlockTimestampNanoSecs, lockupAmountBaseUnits, connectTimestamp)
	require.NoError(testMeta.t, err)

	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _coinLockupWithConnectTimestamp(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	profilePublicKeyBase58Check string,
	unlockTimestampNanoSecs int64,
	lockupAmountBaseUnits *uint256.Int,
	connectTimestamp int64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	transactorPkBytes, _, err := Base58CheckDecode(transactorPublicKeyBase58Check)
	require.NoError(err)

	profilePkBytes, _, err := Base58CheckDecode(profilePublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
	require.NoError(err)

	// Create the coin lockup transaction.
	txn, totalInputMake, _, feesMake, err := chain.CreateCoinLockupTxn(
		transactorPkBytes, profilePkBytes, unlockTimestampNanoSecs,
		lockupAmountBaseUnits, feeRateNanosPerKB, nil, []*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInputMake, feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, transactorPrivateKeyBase58Check)

	// Connect the transaction.
	txHash := txn.Hash()
	blockHeight := chain.BlockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(
			txn, txHash, getTxnSize(*txn), blockHeight, connectTimestamp, true, false)
	if err != nil {
		return nil, nil, 0, err
	}

	// Ensure that DESO is flowing in the correct amount.
	require.Equal(totalInput, totalOutput+fees)

	// Check that UtxoOps following connection have the correct type
	require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
	if NewPublicKey(profilePkBytes).IsZeroPublicKey() {
		require.Equal(OperationTypeSpendBalance, utxoOps[1].Type)
		require.Equal(OperationTypeCoinLockup, utxoOps[2].Type)
	} else {
		require.Equal(OperationTypeCoinLockup, utxoOps[1].Type)
	}

	// Ensure the transaction can be flushed without issue before returning
	require.NoError(utxoView.FlushToDb(uint64(blockHeight)))
	return utxoOps, txn, blockHeight, nil
}

func _updateCoinLockupParamsWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	lockupYieldDurationNanoSecs int64,
	lockupYieldAPYBasisPoints uint64,
	removeYieldCurvePoint bool,
	newLockupTransferRestrictions bool,
	lockupTransferRestrictionStatus TransferRestrictionStatus) {

	testMeta.expectedSenderBalances =
		append(testMeta.expectedSenderBalances,
			_getBalance(testMeta.t, testMeta.chain, nil, transactorPublicKeyBase58Check))

	currentOps, currentTxn, _, err := _updateCoinLockupParams(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB, transactorPublicKeyBase58Check, transactorPrivateKeyBase58Check,
		lockupYieldDurationNanoSecs, lockupYieldAPYBasisPoints, removeYieldCurvePoint,
		newLockupTransferRestrictions, lockupTransferRestrictionStatus)
	require.NoError(testMeta.t, err)

	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _updateCoinLockupParams(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	lockupYieldDurationNanoSecs int64,
	lockupYieldAPYBasisPoints uint64,
	removeYieldCurvePoint bool,
	newLockupTransferRestrictions bool,
	lockupTransferRestrictionStatus TransferRestrictionStatus) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	transactorPkBytes, _, err := Base58CheckDecode(transactorPublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
	require.NoError(err)

	// Create the update coin lockup params transaction.
	txn, totalInputMake, _, feesMake, err := chain.CreateUpdateCoinLockupParamsTxn(
		transactorPkBytes, lockupYieldDurationNanoSecs, lockupYieldAPYBasisPoints, removeYieldCurvePoint,
		newLockupTransferRestrictions, lockupTransferRestrictionStatus, feeRateNanosPerKB, nil, []*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInputMake, feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, transactorPrivateKeyBase58Check)

	// Connect the transaction.
	txHash := txn.Hash()
	blockHeight := chain.BlockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(
			txn, txHash, getTxnSize(*txn), blockHeight, 0, true, false)
	if err != nil {
		return nil, nil, 0, err
	}

	// Ensure that DESO is flowing in the correct amount.
	require.Equal(totalInput, totalOutput+fees)

	// Check that UtxoOps following connection have the correct type
	require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
	require.Equal(OperationTypeUpdateCoinLockupParams, utxoOps[1].Type)

	// Ensure the transaction can be flushed without issue before returning
	require.NoError(utxoView.FlushToDb(uint64(blockHeight)))
	return utxoOps, txn, blockHeight, nil
}

func _coinLockupTransferWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	recipientPublicKey *PublicKey,
	profilePublicKey *PublicKey,
	unlockTimestampNanoSecs int64,
	lockedCoinsToTransferBaseUnits *uint256.Int) {

	testMeta.expectedSenderBalances =
		append(testMeta.expectedSenderBalances,
			_getBalance(testMeta.t, testMeta.chain, nil, transactorPublicKeyBase58Check))

	currentOps, currentTxn, _, err := _coinLockupTransfer(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB, transactorPublicKeyBase58Check, transactorPrivateKeyBase58Check,
		recipientPublicKey, profilePublicKey, unlockTimestampNanoSecs, lockedCoinsToTransferBaseUnits)
	require.NoError(testMeta.t, err)

	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _coinLockupTransfer(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	recipientPublicKey *PublicKey,
	profilePublicKey *PublicKey,
	unlockTimestampNanoSecs int64,
	lockedCoinsToTransferBaseUnits *uint256.Int) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	transactorPkBytes, _, err := Base58CheckDecode(transactorPublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
	require.NoError(err)

	// Create the update coin lockup params transaction.
	txn, totalInputMake, _, feesMake, err := chain.CreateCoinLockupTransferTxn(
		transactorPkBytes, recipientPublicKey.ToBytes(), profilePublicKey.ToBytes(), unlockTimestampNanoSecs,
		lockedCoinsToTransferBaseUnits, feeRateNanosPerKB, nil, []*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInputMake, feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, transactorPrivateKeyBase58Check)

	// Connect the transaction.
	txHash := txn.Hash()
	blockHeight := chain.BlockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(
			txn, txHash, getTxnSize(*txn), blockHeight, 0, true, false)
	if err != nil {
		return nil, nil, 0, err
	}

	// Ensure that DESO is flowing in the correct amount.
	require.Equal(totalInput, totalOutput+fees)

	// Check that UtxoOps following connection have the correct type
	require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
	require.Equal(OperationTypeCoinLockupTransfer, utxoOps[1].Type)

	// Ensure the transaction can be flushed without issue before returning
	require.NoError(utxoView.FlushToDb(uint64(blockHeight)))
	return utxoOps, txn, blockHeight, nil
}

func _coinUnlockWithTestMetaAndConnectTimestamp(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	profilePublicKeyBase58Check string,
	connectTimestamp int64) {

	testMeta.expectedSenderBalances =
		append(testMeta.expectedSenderBalances,
			_getBalance(testMeta.t, testMeta.chain, nil, transactorPublicKeyBase58Check))

	currentOps, currentTxn, _, err := _coinUnlockWithConnectTimestamp(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB, transactorPublicKeyBase58Check, transactorPrivateKeyBase58Check,
		profilePublicKeyBase58Check, connectTimestamp)
	require.NoError(testMeta.t, err)

	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _coinUnlockWithConnectTimestamp(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	profilePublicKeyBase58Check string,
	connectTimestamp int64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	transactorPkBytes, _, err := Base58CheckDecode(transactorPublicKeyBase58Check)
	require.NoError(err)

	profilePkBytes, _, err := Base58CheckDecode(profilePublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
	require.NoError(err)

	// Create the coin unlock transaction.
	txn, totalInputMake, _, feesMake, err := chain.CreateCoinUnlockTxn(
		transactorPkBytes, profilePkBytes, feeRateNanosPerKB, nil, []*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInputMake, feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, transactorPrivateKeyBase58Check)

	// Connect the transaction.
	txHash := txn.Hash()
	blockHeight := chain.BlockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(
			txn, txHash, getTxnSize(*txn), blockHeight, connectTimestamp, true, false)
	if err != nil {
		return nil, nil, 0, err
	}

	// Ensure that DESO is flowing in the correct amount.
	require.Equal(totalInput, totalOutput+fees)

	// Check that UtxoOps following connection have the correct type
	require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
	if NewPublicKey(profilePkBytes).IsZeroPublicKey() {
		require.Equal(OperationTypeAddBalance, utxoOps[1].Type)
		require.Equal(OperationTypeCoinUnlock, utxoOps[2].Type)
	} else {
		require.Equal(OperationTypeCoinUnlock, utxoOps[1].Type)
	}

	// Ensure the transaction can be flushed without issue before returning
	require.NoError(utxoView.FlushToDb(uint64(blockHeight)))
	return utxoOps, txn, blockHeight, nil
}
