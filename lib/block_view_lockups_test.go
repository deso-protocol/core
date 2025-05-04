package lib

import (
	"testing"

	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/deso-protocol/uint256"
	"github.com/dgraph-io/badger/v3"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoinLockupsForkHeight(t *testing.T) {
	// Test and ensure lockup transactions cannot trigger without:
	//    (a) LockupsBlockHeight Fork

	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Ensure DAO coins and balance models are enabled (a pre-requisite for lockups)
	params.ForkHeights.DAOCoinBlockHeight = uint32(1)
	params.ForkHeights.BalanceModelBlockHeight = uint32(1)

	// Initialize PoS fork heights.
	params.ForkHeights.LockupsBlockHeight = uint32(25)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

	// Mine a few blocks to give the senderPkString some money.
	for ii := 0; ii < 10; ii++ {
		_, err := miner.MineAndProcessSingleBlock(0, mempool)
		require.NoError(t, err)
	}

	// We build the testMeta obj after mining blocks so that we save the correct block height.
	blockHeight := uint64(chain.blockTip().Height) + 1

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	feeRateNanosPerKb := uint64(101)
	_setUpProfilesAndMintM0M1DAOCoins(&TestMeta{
		t:                 t,
		chain:             chain,
		params:            params,
		db:                db,
		mempool:           mempool,
		miner:             miner,
		savedHeight:       uint32(blockHeight),
		feeRateNanosPerKb: uint64(101),
	})

	// Simulate blocks being mined up and to the fork and ensure lockup transactions cannot be triggered early.
	for ii := 0; ; ii++ {
		_, err := miner.MineAndProcessSingleBlock(0, mempool)
		require.NoError(t, err)
		currentBlockHeight := uint64(chain.blockTip().Height) + 1
		if currentBlockHeight == uint64(params.ForkHeights.LockupsBlockHeight) {
			break
		}

		_, _, _, err1 := _coinLockupWithConnectTimestamp(
			t, chain, db, params, feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			m0Pub,
			m0Pub,
			1000,
			1000,
			uint256.NewInt(100),
			0)
		_, _, _, err2 := _updateCoinLockupParams(
			t, chain, db, params,
			feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			365*25*60*60*1e9,
			500,
			false,
			true,
			TransferRestrictionStatusProfileOwnerOnly,
		)
		_, _, _, err3 := _coinLockupTransfer(
			t, chain, db, params,
			feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			NewPublicKey(m3PkBytes),
			NewPublicKey(m0PkBytes),
			1000,
			uint256.NewInt(1))
		_, _, _, err4 := _coinUnlockWithConnectTimestamp(
			t, chain, db, params,
			feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			m0Pub,
			0)

		if currentBlockHeight < uint64(params.ForkHeights.LockupsBlockHeight) {
			require.Contains(t, err1.Error(), RuleErrorLockupTxnBeforeBlockHeight)
			require.Contains(t, err2.Error(), RuleErrorLockupTxnBeforeBlockHeight)
			require.Contains(t, err3.Error(), RuleErrorLockupTxnBeforeBlockHeight)
			require.Contains(t, err4.Error(), RuleErrorLockupTxnBeforeBlockHeight)
		}
	}
}

func TestCalculateLockupYield(t *testing.T) {
	var yield *uint256.Int
	var err error

	// Ensure that a lockup with zero duration has zero yield.
	yield, err = CalculateLockupYield(
		MaxUint256,
		uint256.NewInt(0),
		uint256.NewInt(1))
	require.NoError(t, err)
	require.Equal(t, *yield, *uint256.NewInt(0))

	// Ensure that a lockup with zero apyYieldBasisPoints has zero yield.
	yield, err = CalculateLockupYield(
		MaxUint256,
		uint256.NewInt(1),
		uint256.NewInt(0))
	require.NoError(t, err)
	require.Equal(t, *yield, *uint256.NewInt(0))

	// Ensure that when principal is MaxUint256 and the apy yield is 2bp,
	// the operation fails due to lack of precision.
	_, err = CalculateLockupYield(
		MaxUint256,
		uint256.NewInt(2),
		uint256.NewInt(1))
	require.Contains(t, err.Error(), RuleErrorCoinLockupCoinYieldOverflow)

	// Ensure that when principal is MaxUint256 and the duration is 2ns,
	// the operation fails due to lack of precision.
	_, err = CalculateLockupYield(
		MaxUint256,
		uint256.NewInt(1),
		uint256.NewInt(2))
	require.Contains(t, err.Error(), RuleErrorCoinLockupCoinYieldOverflow)

	// Ensure that the CalculateLockupYield operation acts as a floor of
	// the true infinite precision CalculateLockupYield operation.
	//
	// To do this, we note that the operation is numerically as follows:
	// (principal * yield_bp * duration_ns) / (365 * 24 * 60 * 60 * 1e9 * 10000)
	//
	// Numerically we start by computing the denominator and numerator separately.
	// To test that division rounding is functioning correctly, we set the following values:
	// principal = 365 * 24 * 10000
	// yield_bp  = 60 * 60
	// duration  = 1e9
	//
	// In theory, this should return a yield of 1 without any overflow in the operation.
	// We test this below:
	yield, err = CalculateLockupYield(
		uint256.NewInt(365*24*10000),
		uint256.NewInt(60*60),
		uint256.NewInt(1e9))
	require.NoError(t, err)
	require.Equal(t, *yield, *uint256.NewInt(1))

	// Knowing this, we can now check to ensure the edges of the CalculateLockupYield
	// operation are behaving correctly and never minting more coins than expected.
	// We start by reducing the numerator. Any decrease to the numerator should return a yield of zero.
	// To test this, we set duration = 1e9 - 1.
	// (This decreases only the largest factor, leading to the smallest decrease possible in the numerator)
	yield, err = CalculateLockupYield(
		uint256.NewInt(365*24*10000),
		uint256.NewInt(60*60),
		uint256.NewInt(1e9-1))
	require.NoError(t, err)
	require.Equal(t, *yield, *uint256.NewInt(0))

	// If we only slightly increase the numerator, we should expect to see the yield remain the same.
	// To test this, we set duration = 1e9 + 1
	// (This increases only the largest factor, leading to the smallest increase possible in the numerator)
	yield, err = CalculateLockupYield(
		uint256.NewInt(365*24*10000),
		uint256.NewInt(60*60),
		uint256.NewInt(1e9+1))
	require.NoError(t, err)
	require.Equal(t, *yield, *uint256.NewInt(1))

	// We should only see an increase to the output yield if the numerator is scaled by a constant.
	// To do this, we can iterate through various constants and see if the output yield matches.
	// These operations are quick and cheap, so we test all values between 0 and 100000.
	// We also ensure that slight deviations do not alter the output.
	for ii := uint64(0); ii < 100000; ii++ {
		yield, err = CalculateLockupYield(
			uint256.NewInt(ii*365*24*10000),
			uint256.NewInt(60*60),
			uint256.NewInt(1e9))
		require.NoError(t, err)
		require.Equal(t, *yield, *uint256.NewInt(ii))

		// Slight increase to the numerator. Ensure we don't create more yield than expected.
		yield, err = CalculateLockupYield(
			uint256.NewInt(ii*365*24*10000),
			uint256.NewInt(60*60),
			uint256.NewInt(1e9+1))
		require.NoError(t, err)
		require.Equal(t, *yield, *uint256.NewInt(ii))

		// Slight decrease to the numerator. Ensure we create strictly less yield.
		expectedValue := ii - 1
		if ii == 0 {
			expectedValue = 0
		}
		yield, err = CalculateLockupYield(
			uint256.NewInt(ii*365*24*10000),
			uint256.NewInt(60*60),
			uint256.NewInt(1e9-1))
		require.NoError(t, err)
		require.Equal(t, *yield, *uint256.NewInt(expectedValue))
	}
}

func TestCoinLockupTxnRuleErrors(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Attempt to perform a lockup of amount zero.
	// (This should fail -- RuleErrorCoinLockupOfAmountZero)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			0, 0, uint256.NewInt(0), 0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupOfAmountZero)
	}

	// Attempt to perform a lockup on a non-existent profile.
	// (This should fail -- RuleErrorCoinLockupOnNonExistentProfile)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m2Pub, m0Pub,
			0, 0, uint256.NewInt(1), 0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupOnNonExistentProfile)
	}

	// Attempt to perform a lockup with the zero public key as the profile.
	// (This should fail -- RuleErrorCoinLockupCannotLockupZeroKey)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params), m0Pub,
			0, 0, uint256.NewInt(1), 0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupCannotLockupZeroKey)
	}

	// Attempt to perform a lockup with zero lockup duration.
	// (This should fail -- RuleErrorCoinLockupInvalidLockupDuration)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			0, 0, uint256.NewInt(1), 0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupInvalidLockupDuration)
	}

	// Attempt to perform a lockup with negative lockup duration.
	// (This should fail -- RuleErrorCoinLockupInvalidLockupDuration)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			0, 0, uint256.NewInt(1), 1)
		require.Contains(t, err.Error(), RuleErrorCoinLockupInvalidLockupDuration)
	}

	// Attempt to perform a vested lockup with a logically invalid vesting schedule (vest goes into the past).
	// (This should fail -- RuleErrorCoinLockupInvalidLockupDuration)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, 900, uint256.NewInt(1), 950)
		require.Contains(t, err.Error(), RuleErrorCoinLockupInvalidVestingEndTimestamp)
	}

	// Attempt to perform an unvested lockup with the ZeroPublicKey as the recipient.
	// (This should fail -- RuleErrorCoinLockupZeroPublicKeyAsRecipient)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
			1000, 1000, uint256.NewInt(1), 950)
		require.Contains(t, err.Error(), RuleErrorCoinLockupZeroPublicKeyAsRecipient)
	}

	// Attempt to perform a lockup in excess of the user's coin balance.
	// (This should fail -- RuleErrorCoinLockupInsufficientCoins)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1, 1, uint256.NewInt(1e10), 0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupInsufficientCoins)
	}

	// Set m0 locked transfer restrictions to profile owner only and send m1, m2 unlocked m0 tokens.
	// We do this to test transfer restriction status on lockups.
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
	_daoCoinTransferTxnWithTestMeta(testMeta, testMeta.feeRateNanosPerKb, m0Pub, m0Priv, DAOCoinTransferMetadata{
		ProfilePublicKey:       m0PkBytes,
		DAOCoinToTransferNanos: *uint256.NewInt(1000),
		ReceiverPublicKey:      m1PkBytes,
	})
	_daoCoinTransferTxnWithTestMeta(testMeta, testMeta.feeRateNanosPerKb, m0Pub, m0Priv, DAOCoinTransferMetadata{
		ProfilePublicKey:       m0PkBytes,
		DAOCoinToTransferNanos: *uint256.NewInt(1000),
		ReceiverPublicKey:      m2PkBytes,
	})

	// Attempt to perform a m0 lockup where the transactor is not m0.
	// (This should fail -- RuleErrorCoinLockupRestrictedToProfileOwner)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m0Pub, m0Pub,
			1000, 1000, uint256.NewInt(1000), 0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferRestrictedToProfileOwner)
	}

	// Update transfer restrictions to DAO members only.
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

	// Attempt to perform a m0 lockup where the receiver m3 is not in the DAO.
	// (This should fail -- RuleErrorCoinLockupRestrictedToDAOMembers)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m0Pub, m3Pub,
			1000, 1000, uint256.NewInt(1000), 0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferRestrictedToDAOMembers)
	}

	// Try the same m0 lockup but where DAO member m2 is the recipient.
	// This should succeed :)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m0Pub, m2Pub,
			1000, 1000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Restore default transfer restrictions.
	_updateCoinLockupParamsWithTestMeta(
		testMeta,
		testMeta.feeRateNanosPerKb,
		m0Pub,
		m0Priv,
		0,
		0,
		false,
		true,
		TransferRestrictionStatusUnrestricted,
	)

	// NOTE: The only other rule errors for coin lockup txns are related to yield curve overflows.
	//       This is tested separately and more comprehensively in a different test.

	// Attempt to perform a valid and simple coin lockup transaction.
	// This should succeed :)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, 1000, uint256.NewInt(1000), 0)
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
			uint256.NewInt(0))
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferOfAmountZero)
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

	// Attempt to perform a coin lockup transfer where the receiver is the ZeroPublicKey.
	// (This should fail -- RuleErrorCoinLockupTransferSenderEqualsReceiver)
	{
		_, _, _, err := _coinLockupTransfer(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			&ZeroPublicKey,
			NewPublicKey(m0PkBytes),
			0,
			MaxUint256)
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferToZeroPublicKey)
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
			testMeta, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1, 1, uint256.NewInt(1e6), 0)

		// Send 1000 locked M0 coins to M2.
		_coinLockupTransferWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			NewPublicKey(m2PkBytes),
			NewPublicKey(m0PkBytes),
			1,
			uint256.NewInt(1e6),
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
			uint256.NewInt(1))
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
			uint256.NewInt(1))
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

	// Attempt to unlock coins with the zero public key as the profile.
	// (This should fail -- RuleErrorCoinUnlockCannotUnlockZeroPublicKey)
	{
		_, _, _, err := _coinUnlockWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
			0)
		require.Contains(t, err.Error(), RuleErrorCoinUnlockCannotUnlockZeroPublicKey)
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

	// NOTE: We test overflow errors based on unlocks in tests below.
	//       In general, they're tricky to trigger. Because of this we have special tests for overflows.
}

func TestLockupBasedOverflowsOnProfiles(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Create an on-chain profile for m2
	{
		_updateProfileWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			[]byte{},
			"m2",
			"i am the m2",
			shortPic,
			10*100,
			1.25*100*100,
			false,
		)
	}

	// Create MaxUint256 m2 DAO coins held by m2
	{
		_daoCoinTxnWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			DAOCoinMetadata{
				ProfilePublicKey:          m2PkBytes,
				OperationType:             DAOCoinOperationTypeMint,
				CoinsToMintNanos:          *MaxUint256,
				CoinsToBurnNanos:          uint256.Int{},
				TransferRestrictionStatus: 0,
			})
	}

	// Try and lockup MaxUint256 m2 coins and ensure CoinsInCirculation and NumberOfHolders decreases
	{
		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta, testMeta.feeRateNanosPerKb,
			m2Pub, m2Priv, m2Pub, m2Pub,
			1000, 1000, MaxUint256, 0)

		// Ensure CoinsInCirculationNanos and NumberOfHolders are now zero
		utxoView := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		profileEntry := utxoView.GetProfileEntryForPublicKey(m2PkBytes)
		require.Equal(t, *uint256.NewInt(0), profileEntry.DAOCoinEntry.CoinsInCirculationNanos)
		require.Equal(t, uint64(0), profileEntry.DAOCoinEntry.NumberOfHolders)
	}

	// Create MaxUint256 m2 DAO coins held by m2. This should succeed as we locked all tokens previously.
	{
		_daoCoinTxnWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			DAOCoinMetadata{
				ProfilePublicKey:          m2PkBytes,
				OperationType:             DAOCoinOperationTypeMint,
				CoinsToMintNanos:          *MaxUint256,
				CoinsToBurnNanos:          uint256.Int{},
				TransferRestrictionStatus: 0,
			})
	}

	// Try and do a subsequent lockup of one base unit of m2 coin at the same timestamp as above.
	// (This should fail -- RuleErrorCoinLockupYieldCausesOverflowInLockedBalanceEntry)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m2Pub, m2Priv, m2Pub, m2Pub,
			1000, 1000, uint256.NewInt(1), 0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupYieldCausesOverflowInLockedBalanceEntry)
	}

	// Try and do a MaxUint256 lockup for one year at 1% yield.
	// (This should fail in CalculateLockupYield -- RuleErrorCoinLockupCoinYieldOverflow)
	{
		_updateCoinLockupParamsWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			365*24*60*60*1e9,
			100,
			false,
			false,
			TransferRestrictionStatusUnrestricted,
		)

		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m2Pub, m2Priv, m2Pub, m2Pub,
			365*24*60*60*1e9, 365*24*60*60*1e9, MaxUint256, 0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupCoinYieldOverflow)
	}

	// Try and do a MaxUint256 lockup with 1bp yield and 1ns duration.
	// NOTE: This fails because principal + interest > MaxUint256, but the
	//       CalculateLockupYield operation does not overflow (unlike the above check).
	// (This should fail -- RuleErrorCoinLockupYieldCausesOverflow)
	{
		_updateCoinLockupParamsWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			1,
			1,
			false,
			false,
			TransferRestrictionStatusUnrestricted,
		)

		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m2Pub, m2Priv, m2Pub, m2Pub,
			1, 1, MaxUint256, 0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupYieldCausesOverflow)

		// Remove the yield curve point.
		_updateCoinLockupParamsWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			1,
			1,
			true,
			false,
			TransferRestrictionStatusUnrestricted,
		)
	}

	// Try and perform a lockup transfer to someone with an existing MaxUint256 balance.
	// (This should fail -- RuleErrorCoinLockupTransferBalanceOverflowAtReceiver)
	{
		// Transfer MaxUint256 locked m2 tokens to m3. These were locked in an above test.
		_coinLockupTransferWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			NewPublicKey(m3PkBytes),
			NewPublicKey(m2PkBytes),
			1000,
			MaxUint256,
		)

		// Lockup MaxUint256 m2 tokens.
		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta, testMeta.feeRateNanosPerKb, m2Pub, m2Priv, m2Pub, m2Pub,
			1000, 1000, MaxUint256, 0)

		// Try and perform another transfer. This should fail.
		_, _, _, err := _coinLockupTransfer(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			NewPublicKey(m3PkBytes),
			NewPublicKey(m2PkBytes),
			1000,
			MaxUint256,
		)
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferBalanceOverflowAtReceiver)
	}

	// Try and perform a lockup unlock on multiple locked balance entries such that the unlock balance overflows.
	// (This should fail -- RuleErrorCoinUnlockUnlockableCoinsOverflow)
	{
		// Mint MaxUint256 m2 tokens.
		_daoCoinTxnWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			DAOCoinMetadata{
				ProfilePublicKey:          m2PkBytes,
				OperationType:             DAOCoinOperationTypeMint,
				CoinsToMintNanos:          *MaxUint256,
				CoinsToBurnNanos:          uint256.Int{},
				TransferRestrictionStatus: 0,
			})

		// Lockup MaxUint256 m2 tokens at a different timestamp.
		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta, testMeta.feeRateNanosPerKb,
			m2Pub, m2Priv, m2Pub, m2Pub,
			1001, 1001, MaxUint256, 0)

		// Try and unlock all locked balance entries simultaneously.
		// This should cause an overflow.
		_, _, _, err := _coinUnlockWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			m2Pub,
			1002)
		require.Contains(t, err.Error(), RuleErrorCoinUnlockUnlockableCoinsOverflow)
	}

	// Try and perform a lockup unlock such that the transactor's balance entry overflows.
	// (This should fail -- RuleErrorCoinUnlockCausesBalanceOverflow)
	{
		// Mint MaxUint256 m2 tokens.
		_daoCoinTxnWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			DAOCoinMetadata{
				ProfilePublicKey:          m2PkBytes,
				OperationType:             DAOCoinOperationTypeMint,
				CoinsToMintNanos:          *uint256.NewInt(1),
				CoinsToBurnNanos:          uint256.Int{},
				TransferRestrictionStatus: 0,
			})

		// Try and unlock one of the MaxUint256 locked balance entries.
		// This should cause an overflow in the balance entry.
		_, _, _, err := _coinUnlockWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			m2Pub,
			1001)
		require.Contains(t, err.Error(), RuleErrorCoinUnlockCausesBalanceOverflow)
	}

	// Try and perform a lockup unlock such that the CoinsInCirculation overflows.
	// (This should fail -- RuleErrorCoinLockupCausesCoinsInCirculationOverflow)
	{
		_, _, _, err := _coinUnlockWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m3Pub,
			m3Priv,
			m2Pub,
			1001)
		require.Contains(t, err.Error(), RuleErrorCoinUnlockCausesCoinsInCirculationOverflow)
	}
}

func TestLockupStandardProfileFlows(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Have m1 create a yield curve which consists of:
	// 1 year  @  5% yield
	// 2 years @ 10% yield
	// Remove the yield curve point.
	{
		_updateCoinLockupParamsWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			365*24*60*60*1e9,
			500,
			false,
			false,
			TransferRestrictionStatusUnrestricted,
		)
		_updateCoinLockupParamsWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			2*365*24*60*60*1e9,
			1000,
			false,
			true,
			TransferRestrictionStatusProfileOwnerOnly,
		)
	}

	// Have m1 lockup 10000 m1 DAO tokens for half of a year.
	// We set the connecting block timestamp to 1 year from UNIX start to give it a non-zero value.
	// We expect this to create a locked balance entry with 10000 base units locked inside.
	{
		// Get the PKID associated with m1.
		utxoView := NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID

		// Get the original BalanceEntry for the associated DAO coins.
		originalBalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			m1PkBytes, m1PkBytes, true)

		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m1Pub, m1Pub,
			365*24*60*60*1e9+365*12*60*60*1e9,
			365*24*60*60*1e9+365*12*60*60*1e9,
			uint256.NewInt(10000),
			365*24*60*60*1e9)

		// Check to ensure the resulting locked balance entry has 10000 base units.
		utxoView = NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		lockedBalanceEntry, err :=
			utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
				m1PKID,
				m1PKID,
				365*24*60*60*1e9+365*12*60*60*1e9,
				365*24*60*60*1e9+365*12*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt(10000), lockedBalanceEntry.BalanceBaseUnits)

		// Check to ensure that the BalanceEntry has decreased by exactly 10000.
		newBalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			m1PkBytes, m1PkBytes, true)
		require.True(t, originalBalanceEntry.BalanceNanos.Gt(&newBalanceEntry.BalanceNanos))
		require.Equal(t,
			*uint256.NewInt(0).Sub(&originalBalanceEntry.BalanceNanos, &newBalanceEntry.BalanceNanos),
			*uint256.NewInt(10000))
	}

	// Have m1 lockup 10000 m1 DAO tokens for one year.
	// We set the connecting block timestamp to 1 year from UNIX start to give it a non-zero value.
	// We expect this to create a locked balance entry with 10500 base units locked inside.
	{
		// Get the PKID associated with m1.
		utxoView := NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID

		// Get the original BalanceEntry for the associated DAO coins.
		originalBalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			m1PkBytes, m1PkBytes, true)

		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m1Pub, m1Pub,
			2*365*24*60*60*1e9,
			2*365*24*60*60*1e9,
			uint256.NewInt(10000),
			365*24*60*60*1e9)

		// Check to ensure the resulting locked balance entry has 10500 base units.
		utxoView = NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		lockedBalanceEntry, err :=
			utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
				m1PKID,
				m1PKID,
				2*365*24*60*60*1e9,
				2*365*24*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt(10500), lockedBalanceEntry.BalanceBaseUnits)

		// Check to ensure that the BalanceEntry has decreased by exactly 10000.
		newBalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			m1PkBytes, m1PkBytes, true)
		require.True(t, originalBalanceEntry.BalanceNanos.Gt(&newBalanceEntry.BalanceNanos))
		require.Equal(t,
			*uint256.NewInt(0).Sub(&originalBalanceEntry.BalanceNanos, &newBalanceEntry.BalanceNanos),
			*uint256.NewInt(10000))
	}

	// Have m1 lockup 10000 m1 DAO tokens for one and a half year.
	// We set the connecting block timestamp to 1 year from UNIX start to give it a non-zero value.
	// We expect this to create a locked balance entry with 10500 base units locked inside.
	// NOTE: This is testing the interpolation algorithm for lockups in the middle of two yield curve points.
	{
		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m1Pub, m1Pub,
			2*365*24*60*60*1e9+365*12*60*60*1e9,
			2*365*24*60*60*1e9+365*12*60*60*1e9,
			uint256.NewInt(10000),
			365*24*60*60*1e9)

		// Check to ensure the resulting locked balance entry has 10500 base units.
		utxoView := NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID
		lockedBalanceEntry, err :=
			utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
				m1PKID,
				m1PKID,
				2*365*24*60*60*1e9+365*12*60*60*1e9,
				2*365*24*60*60*1e9+365*12*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt(10500), lockedBalanceEntry.BalanceBaseUnits)
	}

	// Have m1 lockup 10000 m1 DAO tokens for two years.
	// We set the connecting block timestamp to 1 year from UNIX start to give it a non-zero value.
	// We expect this to create a locked balance entry with 12000 base units locked inside.
	{
		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m1Pub, m1Pub,
			3*365*24*60*60*1e9,
			3*365*24*60*60*1e9,
			uint256.NewInt(10000),
			365*24*60*60*1e9)

		// Check to ensure the resulting locked balance entry has 12000 base units.
		utxoView := NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID
		lockedBalanceEntry, err :=
			utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
				m1PKID,
				m1PKID,
				3*365*24*60*60*1e9,
				3*365*24*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt(12000), lockedBalanceEntry.BalanceBaseUnits)
	}

	// Have m1 distribute 1 year locked tokens.
	{
		_coinLockupTransferWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			NewPublicKey(m2PkBytes),
			NewPublicKey(m1PkBytes),
			2*365*24*60*60*1e9,
			uint256.NewInt(500),
		)
		_coinLockupTransferWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			NewPublicKey(m3PkBytes),
			NewPublicKey(m1PkBytes),
			2*365*24*60*60*1e9,
			uint256.NewInt(500),
		)
		_coinLockupTransferWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			NewPublicKey(m4PkBytes),
			NewPublicKey(m1PkBytes),
			2*365*24*60*60*1e9,
			uint256.NewInt(500),
		)

		// Check to ensure the resulting locked balance entry for m1 has 9000 base units.
		utxoView := NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID
		lockedBalanceEntry, err :=
			utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
				m1PKID,
				m1PKID,
				2*365*24*60*60*1e9,
				2*365*24*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt(9000), lockedBalanceEntry.BalanceBaseUnits)
	}

	// Check to make sure locked tokens are not liquid.
	{
		_, _, _, err := _coinLockupTransfer(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			NewPublicKey(m3PkBytes),
			NewPublicKey(m1PkBytes),
			2*365*24*60*60*1e9,
			uint256.NewInt(500),
		)
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferRestrictedToProfileOwner)
	}

	// Check to make sure tokens can be unlocked following a year.
	// Ensure that the associated balance entry increases by 500 on unlock.
	// 500 base units of m1 DAO coins was given by m2 during the distribution phase.
	{
		// Get the original BalanceEntry for the associated DAO coins.
		utxoView := NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		originalBalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			m2PkBytes, m1PkBytes, true)

		_coinUnlockWithTestMetaAndConnectTimestamp(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			m1Pub,
			2*365*24*60*60*1e9+1,
		)

		// Get the updated BalanceEntry for the associated DAO coins.
		utxoView = NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		newBalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			m2PkBytes, m1PkBytes, true)
		require.True(t, newBalanceEntry.BalanceNanos.Gt(&originalBalanceEntry.BalanceNanos))
		require.Equal(t, *uint256.NewInt(500), *uint256.NewInt(0).Sub(
			&newBalanceEntry.BalanceNanos, &originalBalanceEntry.BalanceNanos))
	}
}

func TestLockupWithDerivedKey(t *testing.T) {
	var derivedKeyPriv string
	var derivedKeyPub string

	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)
	blockHeight := uint64(testMeta.chain.BlockTip().Height) + 1

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	utxoView := NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m0PKID := utxoView.GetPKIDForPublicKey(m0PkBytes).PKID
	m1PKID := utxoView.GetPKIDForPublicKey(m1PkBytes).PKID
	//m2PKID := utxoView.GetPKIDForPublicKey(m2PkBytes).PKID

	senderPrivBytes, _, err := Base58CheckDecode(m0Priv)
	require.NoError(t, err)
	m0PrivKey, _ := btcec.PrivKeyFromBytes(senderPrivBytes)

	// Setup helper functions for creating m0 derived keys
	newUtxoView := func() *UtxoView {
		utxoView := NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		return utxoView
	}
	_submitAuthorizeDerivedKeyTxn := func(txnSpendingLimit *TransactionSpendingLimit) (string, string, error) {
		utxoView := newUtxoView()
		derivedKeyMetadata, derivedKeyAuthPriv := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(
			t, m0PrivKey, blockHeight+5, txnSpendingLimit, false, blockHeight,
		)
		derivedKeyAuthPrivBase58Check := Base58CheckEncode(derivedKeyAuthPriv.Serialize(), true, testMeta.params)

		prevBalance := _getBalance(testMeta.t, testMeta.chain, testMeta.mempool, m0Pub)

		utxoOps, txn, _, err := _doAuthorizeTxnWithExtraDataAndSpendingLimits(
			testMeta,
			utxoView,
			testMeta.feeRateNanosPerKb,
			m0PkBytes,
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
			return "", "", err
		}
		require.NoError(t, utxoView.FlushToDb(blockHeight))
		testMeta.expectedSenderBalances = append(testMeta.expectedSenderBalances, prevBalance)
		testMeta.txnOps = append(testMeta.txnOps, utxoOps)
		testMeta.txns = append(testMeta.txns, txn)

		err = utxoView.ValidateDerivedKey(
			m0PkBytes, derivedKeyMetadata.DerivedPublicKey, blockHeight,
		)
		require.NoError(t, err)
		return derivedKeyAuthPrivBase58Check,
			Base58CheckEncode(derivedKeyMetadata.DerivedPublicKey, false, testMeta.params), nil
	}
	_submitLockupTxnWithDerivedKeyAndTimestamp := func(
		transactorPkBytes []byte, derivedKeyPrivBase58Check string, inputTxn MsgDeSoTxn, blockTimestamp int64,
	) (_fees uint64, _err error) {
		utxoView := newUtxoView()
		var txn *MsgDeSoTxn

		switch inputTxn.TxnMeta.GetTxnType() {
		// Construct txn.
		case TxnTypeCoinLockup:
			txMeta := inputTxn.TxnMeta.(*CoinLockupMetadata)
			txn, _, _, _, err = testMeta.chain.CreateCoinLockupTxn(
				transactorPkBytes,
				txMeta.ProfilePublicKey.ToBytes(),
				txMeta.RecipientPublicKey.ToBytes(),
				txMeta.UnlockTimestampNanoSecs,
				txMeta.VestingEndTimestampNanoSecs,
				txMeta.LockupAmountBaseUnits,
				nil, testMeta.feeRateNanosPerKb, nil, []*DeSoOutput{})
			require.NoError(t, err)
		case TxnTypeUpdateCoinLockupParams:
			txMeta := inputTxn.TxnMeta.(*UpdateCoinLockupParamsMetadata)
			txn, _, _, _, err = testMeta.chain.CreateUpdateCoinLockupParamsTxn(
				transactorPkBytes,
				txMeta.LockupYieldDurationNanoSecs,
				txMeta.LockupYieldAPYBasisPoints,
				txMeta.RemoveYieldCurvePoint,
				txMeta.NewLockupTransferRestrictions,
				txMeta.LockupTransferRestrictionStatus,
				nil, testMeta.feeRateNanosPerKb, nil, []*DeSoOutput{})
			require.NoError(t, err)
		case TxnTypeCoinLockupTransfer:
			txMeta := inputTxn.TxnMeta.(*CoinLockupTransferMetadata)
			txn, _, _, _, err = testMeta.chain.CreateCoinLockupTransferTxn(
				transactorPkBytes,
				txMeta.RecipientPublicKey.ToBytes(),
				txMeta.ProfilePublicKey.ToBytes(),
				txMeta.UnlockTimestampNanoSecs,
				txMeta.LockedCoinsToTransferBaseUnits,
				nil, testMeta.feeRateNanosPerKb, nil, []*DeSoOutput{})
			require.NoError(t, err)
		case TxnTypeCoinUnlock:
			txMeta := inputTxn.TxnMeta.(*CoinUnlockMetadata)
			txn, _, _, _, err = testMeta.chain.CreateCoinUnlockTxn(
				transactorPkBytes,
				txMeta.ProfilePublicKey.ToBytes(),
				nil, testMeta.feeRateNanosPerKb, nil, []*DeSoOutput{})
			require.NoError(t, err)
		default:
			return 0, errors.New("invalid txn type")
		}
		if err != nil {
			return 0, err
		}
		// Sign txn.
		_signTxnWithDerivedKeyAndType(t, txn, derivedKeyPrivBase58Check, 1)

		// Store the original transactor balance.
		transactorPublicKeyBase58Check := Base58CheckEncode(transactorPkBytes, false, testMeta.params)
		prevBalance := _getBalance(testMeta.t, testMeta.chain, testMeta.mempool, transactorPublicKeyBase58Check)
		// Connect txn.
		utxoOps, _, _, fees, err := utxoView.ConnectTransaction(txn, txn.Hash(),
			testMeta.savedHeight, blockTimestamp, true, false)
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

	{
		// Error creating spending limit: cannot specify a lockup profile PKID if scope type is Any
		lockupLimitKey := MakeLockupLimitKey(*m0PKID, LockupLimitScopeTypeAnyCoins, AnyLockupOperation)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				// NOTE: We must include TxnTypeAuthorizeDerivedKey as the helper function
				//       _doAuthorizeTxnWithExtraDataAndSpendingLimits signs with the derived key,
				//       NOT the owner key. This transaction will decrement this one type AuthorizeDerivedKey limit.
				TxnTypeAuthorizeDerivedKey: 1,
			},
			LockupLimitMap: map[LockupLimitKey]uint64{lockupLimitKey: uint64(1)},
		}
		derivedKeyPriv, derivedKeyPub, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.Error(t, err)
	}

	{
		// Try and create an UpdateCoinLockupParams transaction that does nothing.
		// (This should fail -- RueErrorDerivedKeyUpdateCoinLockupParamsISNoOp)

		// Create the derived key
		lockupLimitKey := MakeLockupLimitKey(*m0PKID, LockupLimitScopeTypeScopedCoins, AnyLockupOperation)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				// NOTE: We must include TxnTypeAuthorizeDerivedKey as the helper function
				//       _doAuthorizeTxnWithExtraDataAndSpendingLimits signs with the derived key,
				//       NOT the owner key. This transaction will decrement this one type AuthorizeDerivedKey limit.
				TxnTypeAuthorizeDerivedKey: 1,
			},
			LockupLimitMap: map[LockupLimitKey]uint64{lockupLimitKey: uint64(1)},
		}
		derivedKeyPriv, derivedKeyPub, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.NoError(t, err)
		utxoView := NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		derivedPubKeyBytes, _, err := Base58CheckDecode(derivedKeyPub)
		require.NoError(t, err)
		derivedKeyEntry := utxoView.GetDerivedKeyMappingForOwner(m0PkBytes, derivedPubKeyBytes)
		require.Equal(t, uint64(1), derivedKeyEntry.TransactionSpendingLimitTracker.LockupLimitMap[lockupLimitKey])

		// Submit the no-op transaction
		updateCoinLockupParamsMetadata := &UpdateCoinLockupParamsMetadata{
			LockupYieldDurationNanoSecs:     0,
			LockupYieldAPYBasisPoints:       0,
			RemoveYieldCurvePoint:           false,
			NewLockupTransferRestrictions:   false,
			LockupTransferRestrictionStatus: TransferRestrictionStatusUnrestricted,
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: updateCoinLockupParamsMetadata}, 0,
		)
		require.Contains(t, err.Error(), RuleErrorDerivedKeyUpdateCoinLockupParamsIsNoOp)
	}

	// Testing (specific profile PKID || specific operation) limits
	{
		// Try and lockup tokens out-of-scope with the transactor's PKID. This should fail.
		// To do this, we will try and have m0's derived key lockup m0's DeSo tokens while
		// only allowing the DeSo token to do lockups on m1's PKID.
		// This tests incorrect profile scope combined with the correct operation.
		//
		// Then, we will try and have m0 perform an unlock on locked m1 tokens.
		// This tests correct profile scope combined with incorrect operation.
		//
		// After this, we try and have m0 lockup m1 tokens.
		// This should succeed as it's the correct profile scope and correct operation.

		// Create the derived key
		lockupLimitKey := MakeLockupLimitKey(*m1PKID, LockupLimitScopeTypeScopedCoins, CoinLockupOperation)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				// NOTE: We must include TxnTypeAuthorizeDerivedKey as the helper function
				//       _doAuthorizeTxnWithExtraDataAndSpendingLimits signs with the derived key,
				//       NOT the owner key. This transaction will decrement this one type AuthorizeDerivedKey limit.
				TxnTypeAuthorizeDerivedKey: 1,
			},
			LockupLimitMap: map[LockupLimitKey]uint64{lockupLimitKey: uint64(1)},
		}
		derivedKeyPriv, derivedKeyPub, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.NoError(t, err)

		// Have m0 try and lockup m0 tokens. (Incorrect profile + correct operation)
		coinLockupMetadata := &CoinLockupMetadata{
			ProfilePublicKey:            NewPublicKey(m0PkBytes),
			RecipientPublicKey:          NewPublicKey(m0PkBytes),
			UnlockTimestampNanoSecs:     365 * 24 * 60 * 60 * 1e9,
			VestingEndTimestampNanoSecs: 365 * 24 * 60 * 60 * 1e9,
			LockupAmountBaseUnits:       uint256.NewInt(1000),
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinLockupMetadata}, 0,
		)
		require.Contains(t, err.Error(), RuleErrorDerivedKeyCoinLockupOperationNotAuthorized)

		// Have m1 transfer over 1,000 LOCKED m1 tokens for m0 to unlock. (Correct profile + incorrect operation)
		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m1Pub, m1Pub,
			365*24*60*60*1e9,
			365*24*60*60*1e9,
			uint256.NewInt(1000),
			0)
		_coinLockupTransferWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			NewPublicKey(m0PkBytes),
			NewPublicKey(m1PkBytes),
			365*24*60*60*1e9,
			uint256.NewInt(1000),
		)
		coinUnlockMetadata := &CoinUnlockMetadata{ProfilePublicKey: NewPublicKey(m1PkBytes)}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinUnlockMetadata}, 365*24*60*60*1e9+1,
		)
		require.Contains(t, err.Error(), RuleErrorDerivedKeyCoinLockupOperationNotAuthorized)

		// Have m1 transfer over 1,000 unlocked m1 tokens to m0 and have m0 lock them up.
		// (Correct profile + correct operation)
		_daoCoinTransferTxnWithTestMeta(testMeta, testMeta.feeRateNanosPerKb, m1Pub, m1Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m1PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt(1000),
			ReceiverPublicKey:      m0PkBytes,
		})
		coinLockupMetadata = &CoinLockupMetadata{
			ProfilePublicKey:            NewPublicKey(m1PkBytes),
			RecipientPublicKey:          NewPublicKey(m1PkBytes),
			UnlockTimestampNanoSecs:     365 * 24 * 60 * 60 * 1e9,
			VestingEndTimestampNanoSecs: 365 * 24 * 60 * 60 * 1e9,
			LockupAmountBaseUnits:       uint256.NewInt(1000),
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinLockupMetadata}, 0,
		)
		require.NoError(t, err)

		// Ensure the operation cannot be performed again as the transaction limit was set to 1.
		_daoCoinTransferTxnWithTestMeta(testMeta, testMeta.feeRateNanosPerKb, m1Pub, m1Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m1PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt(1000),
			ReceiverPublicKey:      m0PkBytes,
		})
		coinLockupMetadata = &CoinLockupMetadata{
			ProfilePublicKey:            NewPublicKey(m1PkBytes),
			RecipientPublicKey:          NewPublicKey(m1PkBytes),
			UnlockTimestampNanoSecs:     365 * 24 * 60 * 60 * 1e9,
			VestingEndTimestampNanoSecs: 365 * 24 * 60 * 60 * 1e9,
			LockupAmountBaseUnits:       uint256.NewInt(1000),
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinLockupMetadata}, 0,
		)
		require.Contains(t, err.Error(), RuleErrorDerivedKeyCoinLockupOperationNotAuthorized)
	}

	// Test (specific profile PKID || any operation) limits
	{
		// Create the derived key
		lockupLimitKey := MakeLockupLimitKey(*m0PKID, LockupLimitScopeTypeScopedCoins, AnyLockupOperation)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				// NOTE: We must include TxnTypeAuthorizeDerivedKey as the helper function
				//       _doAuthorizeTxnWithExtraDataAndSpendingLimits signs with the derived key,
				//       NOT the owner key. This transaction will decrement this one type AuthorizeDerivedKey limit.
				TxnTypeAuthorizeDerivedKey: 1,
			},
			LockupLimitMap: map[LockupLimitKey]uint64{lockupLimitKey: uint64(2)},
		}
		derivedKeyPriv, derivedKeyPub, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.NoError(t, err)

		// Have m1 transfer 1000 unlocked m1 coins to m0
		_daoCoinTransferTxnWithTestMeta(testMeta, testMeta.feeRateNanosPerKb, m1Pub, m1Priv, DAOCoinTransferMetadata{
			ProfilePublicKey:       m1PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt(1000),
			ReceiverPublicKey:      m0PkBytes,
		})

		// Try to submit a transaction locking up 1000 m1 coins with m0's derived key.
		// This should fail. (Incorrect Profile PKID + Correct Operation)
		coinLockupMetadata := &CoinLockupMetadata{
			ProfilePublicKey:            NewPublicKey(m1PkBytes),
			RecipientPublicKey:          NewPublicKey(m1PkBytes),
			UnlockTimestampNanoSecs:     365 * 24 * 60 * 60 * 1e9,
			VestingEndTimestampNanoSecs: 365 * 24 * 60 * 60 * 1e9,
			LockupAmountBaseUnits:       uint256.NewInt(1000),
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinLockupMetadata}, 0,
		)
		require.Contains(t, err.Error(), RuleErrorDerivedKeyCoinLockupOperationNotAuthorized)

		// Try to submit a transaction locking up 1000 m0 coins with m0's derived key.
		// This should succeed. (Correct Profile PKID + Correct Operation)
		coinLockupMetadata = &CoinLockupMetadata{
			ProfilePublicKey:            NewPublicKey(m0PkBytes),
			RecipientPublicKey:          NewPublicKey(m0PkBytes),
			UnlockTimestampNanoSecs:     365 * 24 * 60 * 60 * 1e9,
			VestingEndTimestampNanoSecs: 365 * 24 * 60 * 60 * 1e9,
			LockupAmountBaseUnits:       uint256.NewInt(1000),
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinLockupMetadata}, 0,
		)
		require.NoError(t, err)

		// Try to submit a transaction unlocking 1000 m0 coins with m0's derived key.
		// This should succeed. (Correct Profile PKID + Correct Operation)
		// This tests that AnyLockupOperation is truly ANY lockup operation.
		coinUnlockMetadata := &CoinUnlockMetadata{ProfilePublicKey: NewPublicKey(m0PkBytes)}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinUnlockMetadata}, 365*24*60*60*1e9+1,
		)
		require.NoError(t, err)

		// Try to submit a subsequent lockup transaction. This should fail as we've exhausted the derived key.
		coinLockupMetadata = &CoinLockupMetadata{
			ProfilePublicKey:            NewPublicKey(m0PkBytes),
			RecipientPublicKey:          NewPublicKey(m0PkBytes),
			UnlockTimestampNanoSecs:     365 * 24 * 60 * 60 * 1e9,
			VestingEndTimestampNanoSecs: 365 * 24 * 60 * 60 * 1e9,
			LockupAmountBaseUnits:       uint256.NewInt(1000),
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinLockupMetadata}, 365*24*60*60*1e9+1,
		)
		require.Contains(t, err.Error(), RuleErrorDerivedKeyCoinLockupOperationNotAuthorized)
	}

	// Test (any creator PKID || specific operation) limits
	{
		// To test this, we create a derived key that can unlock ANY locked coins ONCE.
		// We have m1 send locked tokens to m0, and ensure m0's derived key can unlock them properly.

		// Create the derived key
		lockupLimitKey := MakeLockupLimitKey(ZeroPKID, LockupLimitScopeTypeAnyCoins, CoinLockupUnlockOperation)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				// NOTE: We must include TxnTypeAuthorizeDerivedKey as the helper function
				//       _doAuthorizeTxnWithExtraDataAndSpendingLimits signs with the derived key,
				//       NOT the owner key. This transaction will decrement this one type AuthorizeDerivedKey limit.
				TxnTypeAuthorizeDerivedKey: 1,
			},
			LockupLimitMap: map[LockupLimitKey]uint64{lockupLimitKey: uint64(1)},
		}
		derivedKeyPriv, derivedKeyPub, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.NoError(t, err)

		// Have m0 lockup 1000 m0 tokens to be unlocked one year into the future.
		// This should fail. (Correct PKID + Incorrect Operation Type)
		coinLockupMetadata := &CoinLockupMetadata{
			ProfilePublicKey:            NewPublicKey(m0PkBytes),
			RecipientPublicKey:          NewPublicKey(m0PkBytes),
			UnlockTimestampNanoSecs:     365 * 24 * 60 * 60 * 1e9,
			VestingEndTimestampNanoSecs: 365 * 24 * 60 * 60 * 1e9,
			LockupAmountBaseUnits:       uint256.NewInt(1000),
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinLockupMetadata}, 0,
		)
		require.Contains(t, err.Error(), RuleErrorDerivedKeyCoinLockupOperationNotAuthorized)

		// Have m1 transfer over 1,000 LOCKED m1 tokens for m0 to unlock.
		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m1Pub, m1Pub,
			365*24*60*60*1e9,
			365*24*60*60*1e9,
			uint256.NewInt(1000),
			0)
		_coinLockupTransferWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			NewPublicKey(m0PkBytes),
			NewPublicKey(m1PkBytes),
			365*24*60*60*1e9,
			uint256.NewInt(1000),
		)

		// Have m0 unlock the 1,000 locked m1 tokens.
		// This should succeed. (Correct PKID + Correct Operation)
		coinUnlockMetadata := &CoinUnlockMetadata{ProfilePublicKey: NewPublicKey(m1PkBytes)}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinUnlockMetadata}, 365*24*60*60*1e9+1,
		)
		require.NoError(t, err)

		// Try to submit a subsequent lockup transaction. This should fail as we've exhausted the derived key.
		coinLockupMetadata = &CoinLockupMetadata{
			ProfilePublicKey:            NewPublicKey(m0PkBytes),
			RecipientPublicKey:          NewPublicKey(m0PkBytes),
			UnlockTimestampNanoSecs:     365 * 24 * 60 * 60 * 1e9,
			VestingEndTimestampNanoSecs: 365 * 24 * 60 * 60 * 1e9,
			LockupAmountBaseUnits:       uint256.NewInt(1000),
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinLockupMetadata}, 365*24*60*60*1e9+1,
		)
		require.Contains(t, err.Error(), RuleErrorDerivedKeyCoinLockupOperationNotAuthorized)
	}

	// Test (any creator PKID || any operation) limits
	{
		// To test (any creator PKID || any operation) we attempt to do the following from a derived key:
		//   - 2x Update the owner's yield curve
		//   - 1x Update Lockup Transfer Restrictions
		//   - 2x Lockup the owner's tokens
		//   - 2x Transfer the owner's locked tokens
		//   - 2x Unlock the transfers locked tokens

		// Create the derived key
		lockupLimitKey := MakeLockupLimitKey(ZeroPKID, LockupLimitScopeTypeAnyCoins, AnyLockupOperation)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				// NOTE: We must include TxnTypeAuthorizeDerivedKey as the helper function
				//       _doAuthorizeTxnWithExtraDataAndSpendingLimits signs with the derived key,
				//       NOT the owner key. This transaction will decrement this one type AuthorizeDerivedKey limit.
				TxnTypeAuthorizeDerivedKey: 1,
			},
			LockupLimitMap: map[LockupLimitKey]uint64{lockupLimitKey: uint64(9)},
		}
		derivedKeyPriv, derivedKeyPub, err = _submitAuthorizeDerivedKeyTxn(txnSpendingLimit)
		require.NoError(t, err)

		// Perform the first update to the yield curve
		// NOTE: This will count as two operations against the limit as it's both
		//       updating the yield curve AND updating transfer restrictions.
		updateCoinLockupParamsMetadata := &UpdateCoinLockupParamsMetadata{
			LockupYieldDurationNanoSecs:     365 * 24 * 60 * 60 * 1e9,
			LockupYieldAPYBasisPoints:       1000,
			RemoveYieldCurvePoint:           false,
			NewLockupTransferRestrictions:   true,
			LockupTransferRestrictionStatus: TransferRestrictionStatusProfileOwnerOnly,
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: updateCoinLockupParamsMetadata}, 0,
		)
		require.NoError(t, err)
		utxoView := NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		profileEntry := utxoView.GetProfileEntryForPKID(m0PKID)
		require.Equal(t, TransferRestrictionStatusProfileOwnerOnly, profileEntry.DAOCoinEntry.LockupTransferRestrictionStatus)
		leftYCP, rightYCP, err := utxoView.GetLocalYieldCurvePoints(m0PKID, 365*24*60*60*1e9)
		require.NoError(t, err)
		require.True(t, leftYCP == nil)
		require.Equal(t, int64(365*24*60*60*1e9), rightYCP.LockupDurationNanoSecs)
		require.Equal(t, uint64(1000), rightYCP.LockupYieldAPYBasisPoints)

		// Perform the second update to the yield curve (a delete operation)
		updateCoinLockupParamsMetadata = &UpdateCoinLockupParamsMetadata{
			LockupYieldDurationNanoSecs:     365 * 24 * 60 * 60 * 1e9,
			LockupYieldAPYBasisPoints:       1000,
			RemoveYieldCurvePoint:           true,
			NewLockupTransferRestrictions:   false,
			LockupTransferRestrictionStatus: TransferRestrictionStatusDAOMembersOnly,
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: updateCoinLockupParamsMetadata}, 0,
		)
		require.NoError(t, err)
		utxoView = NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		profileEntry = utxoView.GetProfileEntryForPKID(m0PKID)
		require.Equal(t, TransferRestrictionStatusProfileOwnerOnly, profileEntry.DAOCoinEntry.LockupTransferRestrictionStatus)
		leftYCP, rightYCP, err = utxoView.GetLocalYieldCurvePoints(m0PKID, 365*24*60*60*1e9)
		require.NoError(t, err)
		require.True(t, leftYCP == nil)
		require.True(t, rightYCP == nil)

		// Perform the first lockup operation of 1000 m0 coins at 1yr
		coinLockupMetadata := &CoinLockupMetadata{
			ProfilePublicKey:            NewPublicKey(m0PkBytes),
			RecipientPublicKey:          NewPublicKey(m0PkBytes),
			UnlockTimestampNanoSecs:     365 * 24 * 60 * 60 * 1e9,
			VestingEndTimestampNanoSecs: 365 * 24 * 60 * 60 * 1e9,
			LockupAmountBaseUnits:       uint256.NewInt(1000),
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinLockupMetadata}, 0,
		)
		require.NoError(t, err)
		utxoView = NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		lockedBalanceEntry, err :=
			utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
				m0PKID,
				m0PKID,
				365*24*60*60*1e9,
				365*24*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt(1000), lockedBalanceEntry.BalanceBaseUnits)
		require.Equal(t, int64(365*24*60*60*1e9), lockedBalanceEntry.UnlockTimestampNanoSecs)

		// Perform the second lockup operation of 1000 m0 coins at 2yrs
		coinLockupMetadata = &CoinLockupMetadata{
			ProfilePublicKey:            NewPublicKey(m0PkBytes),
			RecipientPublicKey:          NewPublicKey(m0PkBytes),
			UnlockTimestampNanoSecs:     2 * 365 * 24 * 60 * 60 * 1e9,
			VestingEndTimestampNanoSecs: 2 * 365 * 24 * 60 * 60 * 1e9,
			LockupAmountBaseUnits:       uint256.NewInt(1000),
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinLockupMetadata}, 0,
		)
		require.NoError(t, err)
		utxoView = NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		lockedBalanceEntry, err =
			utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
				m0PKID,
				m0PKID,
				2*365*24*60*60*1e9,
				2*365*24*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt(1000), lockedBalanceEntry.BalanceBaseUnits)
		require.Equal(t, int64(2*365*24*60*60*1e9), lockedBalanceEntry.UnlockTimestampNanoSecs)

		// Perform the first transfer operation to m1 of 500 locked m0 coins @ 1yr
		coinLockupTransferMetadata := &CoinLockupTransferMetadata{
			RecipientPublicKey:             NewPublicKey(m1PkBytes),
			ProfilePublicKey:               NewPublicKey(m0PkBytes),
			UnlockTimestampNanoSecs:        365 * 24 * 60 * 60 * 1e9,
			LockedCoinsToTransferBaseUnits: uint256.NewInt(500),
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinLockupTransferMetadata}, 0,
		)
		require.NoError(t, err)
		utxoView = NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		lockedBalanceEntry, err =
			utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
				m1PKID,
				m0PKID,
				365*24*60*60*1e9,
				365*24*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt(500), lockedBalanceEntry.BalanceBaseUnits)
		require.Equal(t, int64(365*24*60*60*1e9), lockedBalanceEntry.UnlockTimestampNanoSecs)

		// Perform the second transfer operation to m1 of 500 locked m0 coins @ 2yrs
		coinLockupTransferMetadata = &CoinLockupTransferMetadata{
			RecipientPublicKey:             NewPublicKey(m1PkBytes),
			ProfilePublicKey:               NewPublicKey(m0PkBytes),
			UnlockTimestampNanoSecs:        2 * 365 * 24 * 60 * 60 * 1e9,
			LockedCoinsToTransferBaseUnits: uint256.NewInt(500),
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinLockupTransferMetadata}, 0,
		)
		require.NoError(t, err)
		utxoView = NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		lockedBalanceEntry, err =
			utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
				m1PKID,
				m0PKID,
				2*365*24*60*60*1e9,
				2*365*24*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt(500), lockedBalanceEntry.BalanceBaseUnits)
		require.Equal(t, int64(2*365*24*60*60*1e9), lockedBalanceEntry.UnlockTimestampNanoSecs)

		// Perform the first unlock operation of 500 m1 tokens @ 1yr
		utxoView = NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		balanceEntry, _, _ := utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes)
		startingBalance := balanceEntry.BalanceNanos
		coinUnlockMetadata := &CoinUnlockMetadata{ProfilePublicKey: NewPublicKey(m0PkBytes)}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinUnlockMetadata}, 365*24*60*60*1e9+1,
		)
		require.NoError(t, err)
		utxoView = NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		balanceEntry, _, _ = utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes)
		require.True(t, balanceEntry.BalanceNanos.Gt(&startingBalance))
		require.Equal(t, *uint256.NewInt(500),
			*uint256.NewInt(0).Sub(&balanceEntry.BalanceNanos, &startingBalance))
		lockedBalanceEntry, err =
			utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
				m0PKID,
				m0PKID,
				365*24*60*60*1e9,
				365*24*60*60*1e9)
		require.NoError(t, err)
		require.True(t, lockedBalanceEntry == nil)

		// Perform the second unlock operation of 500 m1 tokens @ 2yrs
		utxoView = NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinUnlockMetadata}, 2*365*24*60*60*1e9+1,
		)
		require.NoError(t, err)
		utxoView = NewUtxoView(
			testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		balanceEntry, _, _ = utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes)
		require.True(t, balanceEntry.BalanceNanos.Gt(&startingBalance))
		require.Equal(t, *uint256.NewInt(1000),
			*uint256.NewInt(0).Sub(&balanceEntry.BalanceNanos, &startingBalance))
		lockedBalanceEntry, err =
			utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
				m0PKID,
				m0PKID,
				2*365*24*60*60*1e9,
				2*365*24*60*60*1e9)
		require.NoError(t, err)
		require.True(t, lockedBalanceEntry == nil)

		// Now we try and perform another operation. This should fail as we've depleted our lockup operations limit.
		coinLockupMetadata = &CoinLockupMetadata{
			ProfilePublicKey:            NewPublicKey(m0PkBytes),
			RecipientPublicKey:          NewPublicKey(m0PkBytes),
			UnlockTimestampNanoSecs:     3 * 365 * 24 * 60 * 60 * 1e9,
			VestingEndTimestampNanoSecs: 3 * 365 * 24 * 60 * 60 * 1e9,
			LockupAmountBaseUnits:       uint256.NewInt(1000),
		}
		_, err = _submitLockupTxnWithDerivedKeyAndTimestamp(
			m0PkBytes, derivedKeyPriv, MsgDeSoTxn{TxnMeta: coinLockupMetadata}, 2*365*24*60*60*1e9+2,
		)
		require.Contains(t, err.Error(), RuleErrorDerivedKeyCoinLockupOperationNotAuthorized)
	}
}

func TestLockupDisconnects(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Ensure that paramUpdater is set in the testMeta
	testMeta.params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

	//
	// Test Coin Lockup for Profiles
	//
	utxoOps1, txn1, _, err := _coinLockupWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
		m0Pub, m0Priv, m0Pub, m0Pub,
		2*365*24*60*60*1e9,
		2*365*24*60*60*1e9,
		uint256.NewInt(1000),
		365*24*60*60*1e9)
	require.NoError(t, err)
	utxoOps2, txn2, _, err := _coinLockupWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
		m0Pub, m0Priv, m0Pub, m0Pub,
		2*365*24*60*60*1e9,
		2*365*24*60*60*1e9,
		uint256.NewInt(1000),
		365*24*60*60*1e9)
	require.NoError(t, err)
	txHash := txn2.Hash()
	blockHeight := testMeta.chain.BlockTip().Height + 1
	utxoView := NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	err = utxoView.DisconnectTransaction(txn2, txHash, utxoOps2, blockHeight)
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))
	require.NoError(t, err)
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m0PKID := utxoView.GetPKIDForPublicKey(m0PkBytes).PKID
	lockedBalanceEntry, err :=
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m0PKID,
			m0PKID,
			2*365*24*60*60*1e9,
			2*365*24*60*60*1e9)
	require.NoError(t, err)
	require.Equal(t, *uint256.NewInt(1000), lockedBalanceEntry.BalanceBaseUnits)
	balanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes, true)
	require.Equal(t, *uint256.NewInt(999000), balanceEntry.BalanceNanos)
	err = utxoView.DisconnectTransaction(txn1, txn1.Hash(), utxoOps1, blockHeight)
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))
	require.NoError(t, err)
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	lockedBalanceEntry, err =
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m0PKID,
			m0PKID,
			2*365*24*60*60*1e9,
			2*365*24*60*60*1e9)
	require.True(t, lockedBalanceEntry == nil)
	balanceEntry, _, _ = utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes, true)
	require.Equal(t, *uint256.NewInt(1000000), balanceEntry.BalanceNanos)

	//
	// Test Update Coin Lockup Params for Profiles
	//

	// Test adding a lockup curve point and modifying lockup transfer restrictions.
	// Ensure upon disconnect the original point and restrictions remain.
	_, _, _, err = _updateCoinLockupParams(
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		m1Pub,
		m1Priv,
		365*24*60*60*1e9,
		1000,
		false,
		true,
		TransferRestrictionStatusProfileOwnerOnly,
	)
	require.NoError(t, err)
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	utxoOps, txn, _, err := _updateCoinLockupParams(
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		m1Pub,
		m1Priv,
		365*24*60*60*1e9,
		2500,
		false,
		true,
		TransferRestrictionStatusPermanentlyUnrestricted,
	)
	require.NoError(t, err)
	txHash = txn.Hash()
	blockHeight = testMeta.chain.BlockTip().Height + 1
	err = utxoView.DisconnectTransaction(txn, txHash, utxoOps, blockHeight)
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))
	require.NoError(t, err)
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m1PKID := utxoView.GetPKIDForPublicKey(m1PkBytes).PKID
	leftYieldCurvePoint, rightYieldCurvePoint, err :=
		utxoView.GetLocalYieldCurvePoints(m1PKID, 365*24*60*60*1e9)
	require.NoError(t, err)
	require.True(t, leftYieldCurvePoint == nil)
	require.Equal(t, rightYieldCurvePoint.LockupYieldAPYBasisPoints, uint64(1000))
	require.Equal(t, rightYieldCurvePoint.LockupDurationNanoSecs, int64(365*24*60*60*1e9))
	profileEntry := utxoView.GetProfileEntryForPKID(m1PKID)
	require.Equal(t, profileEntry.DAOCoinEntry.LockupTransferRestrictionStatus, TransferRestrictionStatusProfileOwnerOnly)

	// Test Deleting a Yield Curve Point and Reverting Said Transaction
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	utxoOps, txn, _, err = _updateCoinLockupParams(
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		m1Pub,
		m1Priv,
		365*24*60*60*1e9,
		0,
		true,
		false,
		TransferRestrictionStatusUnrestricted,
	)
	require.NoError(t, err)
	leftYieldCurvePoint, rightYieldCurvePoint, err =
		utxoView.GetLocalYieldCurvePoints(m1PKID, 365*24*60*60*1e9)
	require.NoError(t, err)
	require.True(t, leftYieldCurvePoint == nil)
	require.True(t, rightYieldCurvePoint == nil)
	txHash = txn.Hash()
	blockHeight = testMeta.chain.BlockTip().Height + 1
	err = utxoView.DisconnectTransaction(txn, txHash, utxoOps, blockHeight)
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))
	require.NoError(t, err)
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	leftYieldCurvePoint, rightYieldCurvePoint, err =
		utxoView.GetLocalYieldCurvePoints(m1PKID, 365*24*60*60*1e9)
	require.NoError(t, err)
	require.True(t, leftYieldCurvePoint == nil)
	require.Equal(t, rightYieldCurvePoint.LockupYieldAPYBasisPoints, uint64(1000))
	require.Equal(t, rightYieldCurvePoint.LockupDurationNanoSecs, int64(365*24*60*60*1e9))
	profileEntry = utxoView.GetProfileEntryForPKID(m1PKID)
	require.Equal(t, profileEntry.DAOCoinEntry.LockupTransferRestrictionStatus, TransferRestrictionStatusProfileOwnerOnly)

	//
	// Test Coin Lockup Transfers
	//

	// Create an on-chain profile for m3 with MaxUint256 Locked Tokens
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	_updateProfileWithTestMeta(
		testMeta,
		testMeta.feeRateNanosPerKb,
		m3Pub,
		m3Priv,
		[]byte{},
		"m3",
		"i am the m3",
		shortPic,
		10*100,
		1.25*100*100,
		false,
	)
	_daoCoinTxnWithTestMeta(
		testMeta,
		testMeta.feeRateNanosPerKb,
		m3Pub,
		m3Priv,
		DAOCoinMetadata{
			ProfilePublicKey:          m3PkBytes,
			OperationType:             DAOCoinOperationTypeMint,
			CoinsToMintNanos:          *MaxUint256,
			CoinsToBurnNanos:          uint256.Int{},
			TransferRestrictionStatus: 0,
		})
	_coinLockupWithTestMetaAndConnectTimestamp(
		testMeta, testMeta.feeRateNanosPerKb,
		m3Pub, m3Priv, m3Pub, m3Pub,
		1000, 1000, MaxUint256, 0)
	utxoOps, txn, _, err = _coinLockupTransfer(
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		m3Pub,
		m3Priv,
		NewPublicKey(m4PkBytes),
		NewPublicKey(m3PkBytes),
		1000,
		MaxUint256)
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m3PKID := utxoView.GetPKIDForPublicKey(m3PkBytes).PKID
	m4PKID := utxoView.GetPKIDForPublicKey(m4PkBytes).PKID
	m3BalanceEntry, err :=
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m3PKID,
			m3PKID,
			1000,
			1000)
	m4BalanceEntry, err :=
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m4PKID,
			m3PKID,
			1000,
			1000)
	require.True(t, nil == m3BalanceEntry)
	require.Equal(t, *MaxUint256, m4BalanceEntry.BalanceBaseUnits)
	txHash = txn.Hash()
	blockHeight = testMeta.chain.BlockTip().Height + 1
	err = utxoView.DisconnectTransaction(txn, txHash, utxoOps, blockHeight)
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))
	require.NoError(t, err)
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m3PKID = utxoView.GetPKIDForPublicKey(m3PkBytes).PKID
	m4PKID = utxoView.GetPKIDForPublicKey(m4PkBytes).PKID
	m3BalanceEntry, err =
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m3PKID,
			m3PKID,
			1000,
			1000)
	m4BalanceEntry, err =
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m4PKID,
			m3PKID,
			1000,
			1000)
	require.True(t, nil == m4BalanceEntry)
	require.Equal(t, *MaxUint256, m3BalanceEntry.BalanceBaseUnits)

	//
	// Test Coin Unlocks for Profiles
	//

	// Create an on-chain profile for m4 with MaxUint256 Locked Tokens
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	_updateProfileWithTestMeta(
		testMeta,
		testMeta.feeRateNanosPerKb,
		m4Pub,
		m4Priv,
		[]byte{},
		"m4",
		"i am the m4",
		shortPic,
		10*100,
		1.25*100*100,
		false,
	)
	_daoCoinTxnWithTestMeta(
		testMeta,
		testMeta.feeRateNanosPerKb,
		m4Pub,
		m4Priv,
		DAOCoinMetadata{
			ProfilePublicKey:          m4PkBytes,
			OperationType:             DAOCoinOperationTypeMint,
			CoinsToMintNanos:          *MaxUint256,
			CoinsToBurnNanos:          uint256.Int{},
			TransferRestrictionStatus: 0,
		})
	_coinLockupWithTestMetaAndConnectTimestamp(
		testMeta, testMeta.feeRateNanosPerKb,
		m4Pub, m4Priv, m4Pub, m4Pub,
		1000, 1000, MaxUint256, 0)

	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m4LockedBalanceEntry, err :=
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m4PKID,
			m4PKID,
			1000,
			1000)
	m4be, _, _ := utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m4PkBytes, m4PkBytes)
	require.NoError(t, err)
	require.Equal(t, *MaxUint256, m4LockedBalanceEntry.BalanceBaseUnits)
	require.Equal(t, *uint256.NewInt(0), m4be.BalanceNanos)

	utxoOps, txn, _, err = _coinUnlockWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		m4Pub,
		m4Priv,
		m4Pub,
		1001)

	// Ensure unlock functioned properly
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m4LockedBalanceEntry, err =
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m4PKID,
			m4PKID,
			1000,
			1000)
	require.NoError(t, err)
	m4be, _, _ = utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m4PkBytes, m4PkBytes)
	require.True(t, nil == m4LockedBalanceEntry)
	require.Equal(t, *MaxUint256, m4be.BalanceNanos)

	// Execute the disconnect and ensure it functions correctly
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	txHash = txn.Hash()
	blockHeight = testMeta.chain.BlockTip().Height + 1
	err = utxoView.DisconnectTransaction(txn, txHash, utxoOps, blockHeight)
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))
	require.NoError(t, err)
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m4LockedBalanceEntry, err =
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m4PKID,
			m4PKID,
			1000,
			1000)
	require.NoError(t, err)
	m4be, _, _ = utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m4PkBytes, m4PkBytes)
	require.Equal(t, *uint256.NewInt(0), m4be.BalanceNanos)
	require.Equal(t, *MaxUint256, m4LockedBalanceEntry.BalanceBaseUnits)
}

func TestLockupBlockConnectsAndDisconnects(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Get chain tip header timestamp
	tipTimestamp := int64(testMeta.chain.blockTip().Header.TstampNanoSecs)

	// Validate the starting state
	utxoView := NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m0PKID := utxoView.GetPKIDForPublicKey(m0PkBytes).PKID
	m3PKID := utxoView.GetPKIDForPublicKey(m3PkBytes).PKID
	m0Profile := utxoView.GetProfileEntryForPKID(m0PKID)
	require.Equal(t, TransferRestrictionStatusUnrestricted, m0Profile.DAOCoinEntry.LockupTransferRestrictionStatus)
	m0LeftYieldCurvePoint, m0RightYieldCurvePoint, err := utxoView.GetLocalYieldCurvePoints(m0PKID, 365*24*60*60*1e9+1)
	require.NoError(t, err)
	require.True(t, m0RightYieldCurvePoint == nil)
	require.True(t, m0LeftYieldCurvePoint == nil)
	m0BalanceEntry, _, _ := utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes)
	m3BalanceEntry, _, _ := utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m3PkBytes, m0PkBytes)
	require.Equal(t, *uint256.NewInt(1000000), m0BalanceEntry.BalanceNanos)
	require.Equal(t, *uint256.NewInt(0), m3BalanceEntry.BalanceNanos)
	m0LockedBalanceEntry, err :=
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m0PKID,
			m0PKID,
			tipTimestamp+2e9,
			tipTimestamp+2e9)
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry == nil)
	m3LockedBalanceEntry, err :=
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m3PKID,
			m0PKID,
			tipTimestamp+2e9,
			tipTimestamp+2e9)
	require.NoError(t, err)
	require.True(t, m3LockedBalanceEntry == nil)

	//
	// Construct a block and test connect with a yield curve update, lockup, and transfer.
	//

	// Construct transactions
	updateTxn, _, _, _, err := testMeta.chain.CreateUpdateCoinLockupParamsTxn(
		m0PkBytes, 365*24*60*60*1e9, 1000, false,
		true, TransferRestrictionStatusProfileOwnerOnly,
		nil, testMeta.feeRateNanosPerKb, nil, []*DeSoOutput{})
	require.NoError(t, err)
	_signTxn(t, updateTxn, m0Priv)
	lockupTxn, _, _, _, err := testMeta.chain.CreateCoinLockupTxn(
		m0PkBytes, m0PkBytes, m0PkBytes, tipTimestamp+2e9, tipTimestamp+2e9,
		uint256.NewInt(1000), nil, testMeta.feeRateNanosPerKb, nil, []*DeSoOutput{})
	require.NoError(t, err)
	_signTxn(t, lockupTxn, m0Priv)
	transferTxn, _, _, _, err := testMeta.chain.CreateCoinLockupTransferTxn(
		m0PkBytes, m3PkBytes, m0PkBytes, tipTimestamp+2e9,
		uint256.NewInt(1000), nil, testMeta.feeRateNanosPerKb, nil, []*DeSoOutput{})
	require.NoError(t, err)
	_signTxn(t, transferTxn, m0Priv)

	// Construct and attach the first block
	senderPkBytes, _, _ := Base58CheckDecode(senderPkString)
	blk1, _, _, err := testMeta.miner.BlockProducer._getBlockTemplate(senderPkBytes)
	require.NoError(t, err)
	blk1.Txns = append(blk1.Txns, updateTxn)
	blk1.Txns = append(blk1.Txns, lockupTxn)
	blk1.Txns = append(blk1.Txns, transferTxn)
	blk1Root, _, err := ComputeMerkleRoot(blk1.Txns)
	require.NoError(t, err)
	blk1.Header.TransactionMerkleRoot = blk1Root
	blk1.Header.TstampNanoSecs = tipTimestamp + 1e9

	// Mine the first block to ensure the difficulty is sufficient for ProcessBlock
	// NOTE: 10000 iterations is presumed sufficient for testing as seen in TestBasicTransfer.
	_, bestNonce, err := FindLowestHash(blk1.Header, 10000)
	require.NoError(t, err)
	blk1.Header.Nonce = bestNonce

	// Process the first block
	err = testMeta.miner.BlockProducer.SignBlock(blk1)
	require.NoError(t, err)
	_, _, _, err = testMeta.chain.ProcessBlock(blk1, false)
	require.NoError(t, err)

	// Validate state update
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m0PKID = utxoView.GetPKIDForPublicKey(m0PkBytes).PKID
	m3PKID = utxoView.GetPKIDForPublicKey(m3PkBytes).PKID
	m0Profile = utxoView.GetProfileEntryForPKID(m0PKID)
	require.Equal(t, TransferRestrictionStatusProfileOwnerOnly, m0Profile.DAOCoinEntry.LockupTransferRestrictionStatus)
	m0LeftYieldCurvePoint, m0RightYieldCurvePoint, err = utxoView.GetLocalYieldCurvePoints(m0PKID, 365*24*60*60*1e9+1)
	require.NoError(t, err)
	require.True(t, m0RightYieldCurvePoint == nil)
	require.Equal(t, int64(365*24*60*60*1e9), m0LeftYieldCurvePoint.LockupDurationNanoSecs)
	require.Equal(t, uint64(1000), m0LeftYieldCurvePoint.LockupYieldAPYBasisPoints)
	m0BalanceEntry, _, _ = utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes)
	m3BalanceEntry, _, _ = utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m3PkBytes, m0PkBytes)
	require.Equal(t, *uint256.NewInt(999000), m0BalanceEntry.BalanceNanos)
	require.Equal(t, *uint256.NewInt(0), m3BalanceEntry.BalanceNanos)
	m0LockedBalanceEntry, err =
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m0PKID,
			m0PKID,
			tipTimestamp+2e9,
			tipTimestamp+2e9)
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry == nil)
	m3LockedBalanceEntry, err =
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m3PKID,
			m0PKID,
			tipTimestamp+2e9,
			tipTimestamp+2e9)
	require.NoError(t, err)
	require.Equal(t, *uint256.NewInt(1000), m3LockedBalanceEntry.BalanceBaseUnits)

	//
	// Construct a subsequent second block and test unlock.
	//

	// Construct transactions
	unlockTxn, _, _, _, err := testMeta.chain.CreateCoinUnlockTxn(
		m3PkBytes, m0PkBytes, nil, testMeta.feeRateNanosPerKb, nil, []*DeSoOutput{})
	require.NoError(t, err)
	_signTxn(t, unlockTxn, m3Priv)

	// Construct the second block
	blk2, _, _, err := testMeta.miner.BlockProducer._getBlockTemplate(senderPkBytes)
	require.NoError(t, err)
	blk2.Txns = append(blk2.Txns, unlockTxn)
	blk2Root, _, err := ComputeMerkleRoot(blk2.Txns)
	require.NoError(t, err)
	blk2.Header.TransactionMerkleRoot = blk2Root
	blk2.Header.TstampNanoSecs = tipTimestamp + 3e9

	// Mine the second block to ensure the difficulty is sufficient for ProcessBlock
	// NOTE: 10000 iterations is presumed sufficient for testing as seen in TestBasicTransfer.
	_, bestNonce, err = FindLowestHash(blk2.Header, 10000)
	require.NoError(t, err)
	blk2.Header.Nonce = bestNonce

	// Process the second block
	err = testMeta.miner.BlockProducer.SignBlock(blk2)
	require.NoError(t, err)
	_, _, _, err = testMeta.chain.ProcessBlock(blk2, false)
	require.NoError(t, err)

	// Validate state update
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m0BalanceEntry, _, _ = utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes)
	m3BalanceEntry, _, _ = utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m3PkBytes, m0PkBytes)
	require.Equal(t, *uint256.NewInt(999000), m0BalanceEntry.BalanceNanos)
	require.Equal(t, *uint256.NewInt(1000), m3BalanceEntry.BalanceNanos)
	m0LockedBalanceEntry, err =
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m0PKID,
			m0PKID,
			tipTimestamp+2e9,
			tipTimestamp+2e9)
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry == nil)
	m3LockedBalanceEntry, err =
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m3PKID,
			m0PKID,
			tipTimestamp+2e9,
			tipTimestamp+2e9)
	require.NoError(t, err)
	require.True(t, m3LockedBalanceEntry == nil)

	//
	// Disconnect the second block and ensure state is reverted.
	//

	// Disconnect the second block
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	blk2Hash, err := blk2.Hash()
	require.NoError(t, err)
	utxoOps, err := GetUtxoOperationsForBlock(testMeta.db, nil, blk2Hash)
	require.NoError(t, err)
	txHashes, err := ComputeTransactionHashes(blk2.Txns)
	require.NoError(t, err)
	err = utxoView.DisconnectBlock(blk2, txHashes, utxoOps, blk2.Header.Height)
	require.NoError(t, err)
	require.NoError(t, utxoView.FlushToDb(blk2.Header.Height))

	// Update the tip
	testMeta.chain.blockIndex.tip = testMeta.chain.blockIndex.tip.GetParent(testMeta.chain.blockIndex)

	// Validate the state update
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m0PKID = utxoView.GetPKIDForPublicKey(m0PkBytes).PKID
	m3PKID = utxoView.GetPKIDForPublicKey(m3PkBytes).PKID
	m0Profile = utxoView.GetProfileEntryForPKID(m0PKID)
	require.Equal(t, TransferRestrictionStatusProfileOwnerOnly, m0Profile.DAOCoinEntry.LockupTransferRestrictionStatus)
	m0LeftYieldCurvePoint, m0RightYieldCurvePoint, err = utxoView.GetLocalYieldCurvePoints(m0PKID, 365*24*60*60*1e9+1)
	require.NoError(t, err)
	require.True(t, m0RightYieldCurvePoint == nil)
	require.Equal(t, int64(365*24*60*60*1e9), m0LeftYieldCurvePoint.LockupDurationNanoSecs)
	require.Equal(t, uint64(1000), m0LeftYieldCurvePoint.LockupYieldAPYBasisPoints)
	m0BalanceEntry, _, _ = utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes)
	m3BalanceEntry, _, _ = utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m3PkBytes, m0PkBytes)
	require.Equal(t, *uint256.NewInt(999000), m0BalanceEntry.BalanceNanos)
	require.Equal(t, *uint256.NewInt(0), m3BalanceEntry.BalanceNanos)
	m0LockedBalanceEntry, err =
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m0PKID,
			m0PKID,
			tipTimestamp+2e9,
			tipTimestamp+2e9)
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry == nil)
	m3LockedBalanceEntry, err =
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m3PKID,
			m0PKID,
			tipTimestamp+2e9,
			tipTimestamp+2e9)
	require.NoError(t, err)
	require.Equal(t, *uint256.NewInt(1000), m3LockedBalanceEntry.BalanceBaseUnits)

	//
	// Disconnect the first block and ensure state is reverted.
	//

	// Disconnect the first block
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	blk1Hash, err := blk1.Hash()
	require.NoError(t, err)
	utxoView.TipHash = blk1Hash
	require.NoError(t, err)
	utxoOps, err = GetUtxoOperationsForBlock(testMeta.db, nil, blk1Hash)
	require.NoError(t, err)
	txHashes, err = ComputeTransactionHashes(blk1.Txns)
	require.NoError(t, err)
	err = utxoView.DisconnectBlock(blk1, txHashes, utxoOps, blk1.Header.Height)
	require.NoError(t, err)
	require.NoError(t, utxoView.FlushToDb(blk1.Header.Height))

	// Update the tip
	testMeta.chain.blockIndex.setTip(testMeta.chain.blockIndex.tip.GetParent(testMeta.chain.blockIndex))

	// Verify we return back to the initial state
	utxoView = NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m0Profile = utxoView.GetProfileEntryForPKID(m0PKID)
	require.Equal(t, TransferRestrictionStatusUnrestricted, m0Profile.DAOCoinEntry.LockupTransferRestrictionStatus)
	m0LeftYieldCurvePoint, m0RightYieldCurvePoint, err = utxoView.GetLocalYieldCurvePoints(m0PKID, 365*24*60*60*1e9+1)
	require.NoError(t, err)
	require.True(t, m0RightYieldCurvePoint == nil)
	require.True(t, m0LeftYieldCurvePoint == nil)
	m0BalanceEntry, _, _ = utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes)
	m3BalanceEntry, _, _ = utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m3PkBytes, m0PkBytes)
	require.Equal(t, *uint256.NewInt(1000000), m0BalanceEntry.BalanceNanos)
	require.Equal(t, *uint256.NewInt(0), m3BalanceEntry.BalanceNanos)
	m0LockedBalanceEntry, err =
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m0PKID,
			m0PKID,
			tipTimestamp+2e9,
			tipTimestamp+2e9)
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry == nil)
	m3LockedBalanceEntry, err =
		utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecsVestingEndTimestampNanoSecs(
			m3PKID,
			m0PKID,
			tipTimestamp+2e9,
			tipTimestamp+2e9)
	require.NoError(t, err)
	require.True(t, m3LockedBalanceEntry == nil)
}

func TestCoinLockupIndirectRecipients(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Attempt to create an indirect recipient of an unvested lockup by having m0 lockup and give to m3.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m3Pub,
			1000, 1000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Verify that m3 received the lockup (not m0) and that m0 was credited properly.
	utxoView := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m3PKIDEntry := utxoView.GetPKIDForPublicKey(m3PkBytes)
	m3PKID := m3PKIDEntry.PKID
	m0PKIDEntry := utxoView.GetPKIDForPublicKey(m0PkBytes)
	m0PKID := m0PKIDEntry.PKID

	// Check m3 LockedBalanceEntry
	m3LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m3PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 1000,
	})
	require.NoError(t, err)
	require.True(t, m3LockedBalanceEntry != nil)
	require.True(t, m3LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(1000)))

	// Check the m0 LockedBalanceEntry as non-existent
	m0LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 1000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry == nil)

	// Attempt to create an indirect recipient of a vested lockup by having m0 lockup and give to m3.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m3Pub,
			1050, 1100, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Check m3 LockedBalanceEntry
	m3LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m3PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1050,
		VestingEndTimestampNanoSecs: 1100,
	})
	require.NoError(t, err)
	require.True(t, m3LockedBalanceEntry != nil)
	require.True(t, m3LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(1000)))

	// Check the m0 LockedBalanceEntry as non-existent
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1050,
		VestingEndTimestampNanoSecs: 1100,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry == nil)
}

func TestSimpleVestedLockup(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Perform a simple vested lockup in the future over 1000ns.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Get the original m0 balance entry base units.
	utxoView := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m0PKIDEntry := utxoView.GetPKIDForPublicKey(m0PkBytes)
	m0PKID := m0PKIDEntry.PKID
	originalBalanceEntry, _, _ :=
		utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes, true)

	// Perform a simple unlock halfway through the vest. Ensure the payout is 500 base units.
	{
		_, _, _, err := _coinUnlockWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			m0Pub,
			1500,
		)
		require.NoError(t, err)
	}

	// Verify that the locked balance entry was credited.
	utxoView = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)

	// Check m0 LockedBalanceEntry
	m0LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry == nil)
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1500,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(500)))

	// Get the updated m0 balance entry base units and ensure it's been credited 500 base units.
	utxoView = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	updatedBalanceEntry, _, _ :=
		utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes, true)
	require.True(t, uint256.NewInt(500).Eq(
		uint256.NewInt(0).Sub(
			&updatedBalanceEntry.BalanceNanos,
			&originalBalanceEntry.BalanceNanos)))
	originalBalanceEntry = updatedBalanceEntry

	// Perform another simple unlock halfway through the remaining vest. Ensure the payout is 250 base units.
	{
		_, _, _, err := _coinUnlockWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			m0Pub,
			1750,
		)
		require.NoError(t, err)
	}

	// Verify that the locked balance entry was credited.
	utxoView = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)

	// Check m0 LockedBalanceEntry
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1500,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry == nil)
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1750,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(250)))

	// Get the updated m0 balance entry base units and ensure it's been credited 250 base units.
	utxoView = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	updatedBalanceEntry, _, _ =
		utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes, true)
	require.True(t, uint256.NewInt(250).Eq(
		uint256.NewInt(0).Sub(
			&updatedBalanceEntry.BalanceNanos,
			&originalBalanceEntry.BalanceNanos)))
	originalBalanceEntry = updatedBalanceEntry

	// Try and unlock the remaining amount.
	{
		_, _, _, err := _coinUnlockWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			m0Pub,
			2000,
		)
		require.NoError(t, err)
	}

	// Verify that the locked balance entry was credited.
	utxoView = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)

	// Check m0 LockedBalanceEntry
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1750,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry == nil)
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     2000,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry == nil)

	// Get the updated m0 balance entry base units and ensure it's been credited 250 base units.
	utxoView = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	updatedBalanceEntry, _, _ =
		utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes, true)
	require.True(t, uint256.NewInt(250).Eq(
		uint256.NewInt(0).Sub(
			&updatedBalanceEntry.BalanceNanos,
			&originalBalanceEntry.BalanceNanos)))
	originalBalanceEntry = updatedBalanceEntry

	// Check that we're back to where we started (1e6 base units)
	require.True(t, uint256.NewInt(1e6).Eq(&updatedBalanceEntry.BalanceNanos))
}

func TestNoOverlapVestedLockupConsolidation(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Perform a simple vested lockup in the future over 1000ns.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Perform a second simple vested lockup in the future that causes a left overhang.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			3000, 4000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Verify that the left overhang was computed correctly.
	utxoView :=
		NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)

	// Check m0 LockedBalanceEntry
	m0PKIDEntry := utxoView.GetPKIDForPublicKey(m0PkBytes)
	m0PKID := m0PKIDEntry.PKID
	m0LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(1000)))
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     3000,
		VestingEndTimestampNanoSecs: 4000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(1000)))
}

func TestPerfectOverlapVestedLockupConsolidation(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Perform a simple vested lockup in the future over 1000ns.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Perform a second simple vested lockup in the future that causes a left overhang.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Verify that the left overhang was computed correctly.
	utxoView :=
		NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)

	// Check m0 LockedBalanceEntry
	m0PKIDEntry := utxoView.GetPKIDForPublicKey(m0PkBytes)
	m0PKID := m0PKIDEntry.PKID
	m0LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(2000)))
}

func TestLeftOverhangVestedLockupConsolidation(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// First we test the following vested lockup consolidation type:
	// existing lockup:       --------------------------------
	// proposed lockup:                    -------------------
	// overhang:              ^            ^
	//
	// In theory the below operation should generate just two locked balance entries.

	// Perform a simple vested lockup in the future over 1000ns.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Perform a second simple vested lockup in the future that causes a left overhang.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1500, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Verify that the left overhang was computed correctly.
	utxoView :=
		NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)

	// Check m0 LockedBalanceEntry
	m0PKIDEntry := utxoView.GetPKIDForPublicKey(m0PkBytes)
	m0PKID := m0PKIDEntry.PKID
	m0LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 1499,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(500)))
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1500,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(1500)))

	// Now we test the opposite vested lockup consolidation type:
	// existing lockup:                    -------------------
	// proposed lockup:       --------------------------------
	// overhang:              ^            ^
	//
	// In theory the below operation should generate just two locked balance entries.

	// Perform a simple vested lockup in the future over 1000ns.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m1Pub, m1Pub,
			1500, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Perform a second simple vested lockup in the future that causes a left overhang.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m1Pub, m1Pub,
			1000, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Check m0 LockedBalanceEntry
	m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
	m1PKID := m1PKIDEntry.PKID
	m1LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m1PKID,
		ProfilePKID:                 *m1PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 1499,
	})
	require.NoError(t, err)
	require.True(t, m1LockedBalanceEntry != nil)
	require.True(t, m1LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(500)))
	m1LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m1PKID,
		ProfilePKID:                 *m1PKID,
		UnlockTimestampNanoSecs:     1500,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m1LockedBalanceEntry != nil)
	require.True(t, m1LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(1500)))
}

func TestRightOverhangVestedLockupConsolidation(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// First we test the following vested lockup consolidation type:
	// existing lockup:       --------------------------------
	// proposed lockup:       -------------------
	// overhang:                                ^            ^
	//
	// In theory the below operation should generate just two locked balance entries.

	// Perform a simple vested lockup in the future over 1000ns.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Perform a second simple vested lockup in the future that causes a left overhang.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, 1499, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Verify that the left overhang was computed correctly.
	utxoView :=
		NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)

	// Check m0 LockedBalanceEntry
	m0PKIDEntry := utxoView.GetPKIDForPublicKey(m0PkBytes)
	m0PKID := m0PKIDEntry.PKID
	m0LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 1499,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(1499)))
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1500,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(501)))

	// Now we test the opposite vested lockup consolidation type:
	// existing lockup:       -------------------
	// proposed lockup:       --------------------------------
	// overhang:                                 ^            ^
	//
	// In theory the below operation should generate just two locked balance entries.

	// Perform a simple vested lockup in the future over 1000ns.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m1Pub, m1Pub,
			1000, 1499, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Perform a second simple vested lockup in the future that causes a left overhang.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m1Pub, m1Pub,
			1000, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Check m1 LockedBalanceEntry
	m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
	m1PKID := m1PKIDEntry.PKID
	m1LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m1PKID,
		ProfilePKID:                 *m1PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 1499,
	})
	require.NoError(t, err)
	require.True(t, m1LockedBalanceEntry != nil)
	require.True(t, m1LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(1500)))
	m1LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m1PKID,
		ProfilePKID:                 *m1PKID,
		UnlockTimestampNanoSecs:     1500,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m1LockedBalanceEntry != nil)
	require.True(t, m1LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(500)))
}

func TestExternalThreeWayLockupConsolidation(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// First we test the following vested lockup consolidation type:
	// existing lockup:         --------------------------------
	// proposed lockup:   -------------------
	//
	// In theory the below operation should generate three locked balance entries.

	// Perform a simple vested lockup in the future over 1000ns.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1250, 1750, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Perform a second simple vested lockup in the future that causes a three-way split.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, 1500, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Validate that the split was performed correctly.
	utxoView :=
		NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)

	// Check m0 LockedBalanceEntry
	m0PKIDEntry := utxoView.GetPKIDForPublicKey(m0PkBytes)
	m0PKID := m0PKIDEntry.PKID
	m0LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 1249,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(500)))
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1501,
		VestingEndTimestampNanoSecs: 1750,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(500)))
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1250,
		VestingEndTimestampNanoSecs: 1500,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(1000)))
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1250,
		VestingEndTimestampNanoSecs: 1750,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry == nil)

	// Now we test the opposite vested lockup consolidation type:
	// existing lockup:     ------------------
	// proposed lockup:              ---------------------------------
	//
	// In theory the below operation should generate three locked balance entries.

	// Perform a simple vested lockup in the future over 1000ns.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m1Pub, m1Pub,
			1000, 1500, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Perform a second simple vested lockup in the future that causes a three-way split.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m1Pub, m1Pub,
			1250, 1750, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Check m1 LockedBalanceEntry
	m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
	m1PKID := m1PKIDEntry.PKID
	m1LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m1PKID,
		ProfilePKID:                 *m1PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 1249,
	})
	require.NoError(t, err)
	require.True(t, m1LockedBalanceEntry != nil)
	require.True(t, m1LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(500)))
	m1LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m1PKID,
		ProfilePKID:                 *m1PKID,
		UnlockTimestampNanoSecs:     1250,
		VestingEndTimestampNanoSecs: 1500,
	})
	require.NoError(t, err)
	require.True(t, m1LockedBalanceEntry != nil)
	require.True(t, m1LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(1002)))
	m1LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m1PKID,
		ProfilePKID:                 *m1PKID,
		UnlockTimestampNanoSecs:     1501,
		VestingEndTimestampNanoSecs: 1750,
	})
	require.NoError(t, err)
	require.True(t, m1LockedBalanceEntry != nil)
	require.True(t, m1LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(498)))
}

func TestInternalThreeWayLockupConsolidation(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// First we test the following vested lockup consolidation type:
	// existing lockup:       --------------------------------
	// proposed lockup:              -------------------
	//
	// In theory the below operation should generate three locked balance entries.

	// Perform a simple vested lockup in the future over 1000ns.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Perform a second simple vested lockup in the future that causes a three-way split.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1250, 1750, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Validate that the split was performed correctly.
	utxoView :=
		NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)

	// Check m0 LockedBalanceEntry
	m0PKIDEntry := utxoView.GetPKIDForPublicKey(m0PkBytes)
	m0PKID := m0PKIDEntry.PKID
	m0LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 1249,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(250)))
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1250,
		VestingEndTimestampNanoSecs: 1750,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(1500)))
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1751,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(250)))

	// Now we test the opposite vested lockup consolidation type:
	// existing lockup:             ------------------
	// proposed lockup:        ---------------------------------
	//
	// In theory the below operation should generate three locked balance entries.

	// Perform a simple vested lockup in the future over 500ns.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m1Pub, m1Pub,
			1250, 1750, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Perform a second simple vested lockup in the future that causes a three-way split.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m1Pub, m1Priv, m1Pub, m1Pub,
			1000, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Check m1 LockedBalanceEntry
	m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
	m1PKID := m1PKIDEntry.PKID
	m1LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m1PKID,
		ProfilePKID:                 *m1PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 1249,
	})
	require.NoError(t, err)
	require.True(t, m1LockedBalanceEntry != nil)
	require.True(t, m1LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(250)))
	m1LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m1PKID,
		ProfilePKID:                 *m1PKID,
		UnlockTimestampNanoSecs:     1250,
		VestingEndTimestampNanoSecs: 1750,
	})
	require.NoError(t, err)
	require.True(t, m1LockedBalanceEntry != nil)
	require.True(t, m1LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(1501)))
	m1LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m1PKID,
		ProfilePKID:                 *m1PKID,
		UnlockTimestampNanoSecs:     1751,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m1LockedBalanceEntry != nil)
	require.True(t, m1LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(249)))
}

func TestSimpleJointExistingVestedLockups(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// First we test the following vested lockup consolidation type:
	// existing lockups:       <------------><------------->
	// proposed lockup:        <--------------------------->
	//
	// In theory the below operation should generate two locked balance entries.

	// Perform a simple vested lockup in the future over 500ns.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, 1500, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Perform a second simple vested lockup in the future that does not overlap but is continuous.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1501, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Perform a third simple vested lockup that overlaps both.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Validate that the split was performed correctly.
	utxoView :=
		NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)

	// Check m0 LockedBalanceEntry
	m0PKIDEntry := utxoView.GetPKIDForPublicKey(m0PkBytes)
	m0PKID := m0PKIDEntry.PKID
	m0LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 1500,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(1501)))
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1501,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(1499)))
}

func TestSimpleDisjointExistingVestedLockups(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// First we test the following vested lockup consolidation type:
	// existing lockups:       ------------       -------------
	// proposed lockup:              -------------------
	//
	// In theory the below operation should generate five locked balance entries.

	// Perform a simple vested lockup in the future over 250ns.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, 2000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Perform a second simple vested lockup in the future that does not overlap.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			3000, 4000, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Perform a third simple vested lockup in the future that triggers a five way split.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1500, 3500, uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Validate that the split was performed correctly.
	utxoView :=
		NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)

	// Check m0 LockedBalanceEntry
	m0PKIDEntry := utxoView.GetPKIDForPublicKey(m0PkBytes)
	m0PKID := m0PKIDEntry.PKID
	m0LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1000,
		VestingEndTimestampNanoSecs: 1499,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(500)))
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     1500,
		VestingEndTimestampNanoSecs: 2000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(750)))
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     2001,
		VestingEndTimestampNanoSecs: 2999,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(499)))
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     3000,
		VestingEndTimestampNanoSecs: 3500,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(751)))
	m0LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
		HODLerPKID:                  *m0PKID,
		ProfilePKID:                 *m0PKID,
		UnlockTimestampNanoSecs:     3501,
		VestingEndTimestampNanoSecs: 4000,
	})
	require.NoError(t, err)
	require.True(t, m0LockedBalanceEntry != nil)
	require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(500)))
}

func TestVestingIntersectionLimit(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Validate the default value of the MaximumVestedIntersectionsPerLockupTransaction parameter.
	utxoView :=
		NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	require.Equal(t, utxoView.GetCurrentGlobalParamsEntry().MaximumVestedIntersectionsPerLockupTransaction, 1000)

	// Generate consecutive vested locked balance entries equal to this limit.
	for ii := 0; ii < utxoView.GetCurrentGlobalParamsEntry().MaximumVestedIntersectionsPerLockupTransaction; ii++ {
		{
			_, _, _, err := _coinLockupWithConnectTimestamp(
				t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
				m0Pub, m0Priv, m0Pub, m0Pub,
				int64(ii*1000)+1, int64(ii*1000)+1000, uint256.NewInt(1000), 0)
			require.NoError(t, err)
		}
	}

	// Create 1,000,000,000 m0 dao coins held by m0.
	// We require this otherwise we will hit downstream (correct) RuleErrorCoinLockupInsufficientCoins errors.
	{
		_daoCoinTxnWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			DAOCoinMetadata{
				ProfilePublicKey:          m0PkBytes,
				OperationType:             DAOCoinOperationTypeMint,
				CoinsToMintNanos:          *uint256.NewInt(1e9),
				CoinsToBurnNanos:          uint256.Int{},
				TransferRestrictionStatus: 0,
			})
	}

	// Ensure we can consolidate on top of all these locked balance entries.
	maxIntersections := utxoView.GetCurrentGlobalParamsEntry().MaximumVestedIntersectionsPerLockupTransaction
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1, int64((maxIntersections-1)*1000)+1000,
			uint256.NewInt(uint64(maxIntersections)*1000), 0)
		require.NoError(t, err)
	}

	// Validate the consolidation.
	m0PKIDEntry := utxoView.GetPKIDForPublicKey(m0PkBytes)
	m0PKID := m0PKIDEntry.PKID
	utxoView =
		NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	for ii := 0; ii < utxoView.GetCurrentGlobalParamsEntry().MaximumVestedIntersectionsPerLockupTransaction; ii++ {
		m0LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForLockedBalanceEntryKey(LockedBalanceEntryKey{
			HODLerPKID:                  *m0PKID,
			ProfilePKID:                 *m0PKID,
			UnlockTimestampNanoSecs:     int64(ii*1000) + 1,
			VestingEndTimestampNanoSecs: int64(ii*1000) + 1000,
		})
		require.NoError(t, err)
		require.True(t, m0LockedBalanceEntry != nil)
		require.True(t, m0LockedBalanceEntry.BalanceBaseUnits.Eq(uint256.NewInt(2000)))
	}

	// Now add another vested lockup, pushing us over the limit.
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			int64(maxIntersections*1000)+1,
			int64(maxIntersections*1000)+1000,
			uint256.NewInt(1000), 0)
		require.NoError(t, err)
	}

	// Now try to consolidate on top of all previous entries.
	// (This should fail -- RuleErrorCoinLockupViolatesVestingIntersectionLimit)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1, int64((maxIntersections)*1000)+1000,
			uint256.NewInt(uint64(maxIntersections)*1000), 0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupViolatesVestingIntersectionLimit)
	}

	// Now we try to consolidate on top of all previous entries with offset bounds to ensure db reads are
	// functioning properly.
	// (This should fail -- RuleErrorCoinLockupViolatesVestingIntersectionLimit)
	{
		_, _, _, err := _coinLockupWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub, m0Priv, m0Pub, m0Pub,
			1000, int64((maxIntersections)*1000)+1,
			uint256.NewInt(uint64(maxIntersections)*1000), 0)
		require.Contains(t, err.Error(), RuleErrorCoinLockupViolatesVestingIntersectionLimit)
	}

	// Now we try to unlock all previous entries just to ensure GetUnlockableLockedBalanceEntries is functioning.
	utxoView =
		NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	startingBalanceEntry, _, _ := utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes)
	require.True(t, startingBalanceEntry != nil)
	{
		_, _, _, err := _coinUnlockWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			m0Pub,
			int64(maxIntersections*1000)+1001,
		)
		require.NoError(t, err)
	}
	utxoView =
		NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	finalBalanceEntry, _, _ := utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes)
	require.True(t, finalBalanceEntry != nil)
	require.True(t,
		uint256.NewInt(0).Sub(&finalBalanceEntry.BalanceNanos, &startingBalanceEntry.BalanceNanos).Eq(
			uint256.NewInt(uint64(maxIntersections)*2000+1000)))

	// Now just to be extra sure, check to make sure there's no more unlockable locked balance entries.
	unvestedUnlockable, vestedUnlockable, err :=
		utxoView.GetUnlockableLockedBalanceEntries(m0PKID, m0PKID, int64(maxIntersections*1000)+1001)
	require.NoError(t, err)
	require.True(t, len(unvestedUnlockable) == 0)
	require.True(t, len(vestedUnlockable) == 0)
}

func TestRealWorldLockupsUseCase(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// We'll assume the following:
	// -- Weekly Deposits
	// -- Unlock starts the 1st day of the month 1 years in the future
	// -- Unlocks end 1st day of the month 5 years in the future
	// -- We'll simulate this for 5 years (it becomes repetitive after this)
	//
	// Since we're doing months as the granularity, the most we can intersect
	// at any given time using this strategy is 48 which is below the intersection limit
	// for vested lockups. Hence, we should not expect that error to trigger here.
	//
	// Note that this will simulate 3,650/7 lockups. At 1,000 DAO coin base units per day locked up,
	// this means we require ~500k m0 DAO coin base units to correctly simulate. Additionally,
	// it would require (ballpark) ~500k nDESO to process the transaction properly.

	// Mint more m0 DAO coins to ensure we have enough.
	{
		_daoCoinTxnWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			DAOCoinMetadata{
				ProfilePublicKey:          m0PkBytes,
				OperationType:             DAOCoinOperationTypeMint,
				CoinsToMintNanos:          *uint256.NewInt(1e7),
				CoinsToBurnNanos:          uint256.Int{},
				TransferRestrictionStatus: 0,
			})
	}

	// Have the miner send m0 sufficient DESO over to cover all transaction fees.
	_registerOrTransferWithTestMeta(testMeta, "m0", senderPkString, m0Pub, senderPrivString, 1e7)

	// Construct a time simplification function.
	simplifyTime := func(t time.Time) time.Time {
		return time.Date(t.Year(), t.Month(), 1, 14, 0, 0, 0, time.UTC)
	}

	// We'll start the simulation at 9am January 1st, 2024.
	startTime := time.Date(2024, time.January, 1, 14, 0, 0, 0, time.UTC)

	// We iterate for 10 years.
	totalLocked := uint256.NewInt(0)
	for ii := 0; ii < 365*5; ii++ {
		// Check if it's time for a deposit.
		if ii%7 != 0 {
			continue
		}

		// We simulate the block connect time as well for fun.
		blockConnectTime := startTime.AddDate(0, 0, ii)

		// Find the lockup start time in 1 year.
		nextLockupStartTime := startTime.AddDate(1, 0, ii)

		// Find the lockup end time in 5 years.
		nextLockupEndTime := startTime.AddDate(5, 0, ii)

		// Simplify both to increase lockup overlap probabilities.
		nextLockupStartTime = simplifyTime(nextLockupStartTime)
		nextLockupEndTime = simplifyTime(nextLockupEndTime)

		// Construct and execute the lockup.
		{
			// NOTE: Subtracting 1 nanosecond from the end time is important and prevents
			// annoying "empty balance" errors from consolidation in the future.
			_, _, _, err := _coinLockupWithConnectTimestamp(
				t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
				m0Pub, m0Priv, m0Pub, m0Pub,
				nextLockupStartTime.UnixNano(),
				nextLockupEndTime.UnixNano()-1,
				uint256.NewInt(1000),
				blockConnectTime.UnixNano())
			require.NoError(t, err)
		}

		// Add to total locked.
		totalLocked = uint256.NewInt(0).Add(
			totalLocked, uint256.NewInt(1000))
	}

	// Verify the locked balance entries in the db.
	utxoView :=
		NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	m0PKIDEntry := utxoView.GetPKIDForPublicKey(m0PkBytes)
	m0PKID := m0PKIDEntry.PKID
	lockedBalanceEntries, err := utxoView.GetAllLockedBalanceEntriesForHodlerPKID(m0PKID)
	require.NoError(t, err)

	// Verify the lockedBalanceEntries locked the correct amount and that the entries are consecutive.
	totalLockedFound := uint256.NewInt(0)
	for ii, lockedBalanceEntry := range lockedBalanceEntries {
		// Add to the balance found.
		totalLockedFound = uint256.NewInt(0).Add(
			totalLockedFound, &lockedBalanceEntry.BalanceBaseUnits)

		// Check if we're consecutive.
		if ii != len(lockedBalanceEntries)-1 {
			require.Equal(t,
				lockedBalanceEntry.VestingEndTimestampNanoSecs+1,
				lockedBalanceEntries[ii+1].UnlockTimestampNanoSecs)
		}
	}
	require.True(t, totalLockedFound.Eq(totalLocked))
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
	_registerOrTransferWithTestMeta(testMeta, "m0", senderPkString, m0Pub, senderPrivString, 100000)
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
				CoinsToMintNanos:          *uint256.NewInt(1e6),
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
				CoinsToMintNanos:          *uint256.NewInt(1e9),
				CoinsToBurnNanos:          uint256.Int{},
				TransferRestrictionStatus: 0,
			})
	}
}

func _setUpMinerAndTestMetaForTimestampBasedLockupTests(t *testing.T) *TestMeta {
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	// Initialize pos fork heights.
	setPoSBlockHeights(t, 11, 100)

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Ensure DAO coins are enabled (a pre-requisite for lockups)
	params.ForkHeights.DAOCoinBlockHeight = uint32(0)

	// Initialize lockups block height.
	params.ForkHeights.LockupsBlockHeight = uint32(11)
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(11)
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
	recipientPublicKeyBase58Check string,
	unlockTimestampNanoSecs int64,
	vestingEndTimestampNanoSecs int64,
	lockupAmountBaseUnits *uint256.Int,
	connectTimestamp int64) {

	testMeta.expectedSenderBalances =
		append(testMeta.expectedSenderBalances,
			_getBalance(testMeta.t, testMeta.chain, nil, transactorPublicKeyBase58Check))

	currentOps, currentTxn, _, err := _coinLockupWithConnectTimestamp(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params, feeRateNanosPerKB,
		transactorPublicKeyBase58Check,
		transactorPrivateKeyBase58Check,
		profilePublicKeyBase58Check,
		recipientPublicKeyBase58Check,
		unlockTimestampNanoSecs,
		vestingEndTimestampNanoSecs,
		lockupAmountBaseUnits,
		connectTimestamp)
	require.NoError(testMeta.t, err)

	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _coinLockupWithConnectTimestamp(
	t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams, feeRateNanosPerKB uint64,
	transactorPublicKeyBase58Check string,
	transactorPrivateKeyBase58Check string,
	profilePublicKeyBase58Check string,
	recipientPublicKeyBase58Check string,
	unlockTimestampNanoSecs int64,
	vestingEndTimestampNanoSecs int64,
	lockupAmountBaseUnits *uint256.Int,
	connectTimestamp int64,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	transactorPkBytes, _, err := Base58CheckDecode(transactorPublicKeyBase58Check)
	require.NoError(err)

	profilePkBytes, _, err := Base58CheckDecode(profilePublicKeyBase58Check)
	require.NoError(err)

	recipientPkBytes, _, err := Base58CheckDecode(recipientPublicKeyBase58Check)
	require.NoError(err)

	utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, nil)

	// Create the coin lockup transaction.
	txn, totalInputMake, _, feesMake, err := chain.CreateCoinLockupTxn(
		transactorPkBytes,
		profilePkBytes,
		recipientPkBytes,
		unlockTimestampNanoSecs,
		vestingEndTimestampNanoSecs,
		lockupAmountBaseUnits,
		nil,
		feeRateNanosPerKB,
		nil, []*DeSoOutput{})
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
			txn, txHash, blockHeight, connectTimestamp, true, false)
	if err != nil {
		return nil, nil, 0, err
	}

	// Ensure that DESO is flowing in the correct amount.
	require.Equal(totalInput, totalOutput+fees)

	// Check that UtxoOps following connection have the correct type
	require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
	require.Equal(OperationTypeCoinLockup, utxoOps[1].Type)

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

	utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, nil)

	// Create the update coin lockup params transaction.
	txn, totalInputMake, _, feesMake, err := chain.CreateUpdateCoinLockupParamsTxn(
		transactorPkBytes, lockupYieldDurationNanoSecs, lockupYieldAPYBasisPoints, removeYieldCurvePoint,
		newLockupTransferRestrictions, lockupTransferRestrictionStatus, nil, feeRateNanosPerKB, nil, []*DeSoOutput{})
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
			txn, txHash, blockHeight, 0, true, false)
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

	utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, nil)

	// Create the update coin lockup params transaction.
	txn, totalInputMake, _, feesMake, err := chain.CreateCoinLockupTransferTxn(
		transactorPkBytes, recipientPublicKey.ToBytes(), profilePublicKey.ToBytes(), unlockTimestampNanoSecs,
		lockedCoinsToTransferBaseUnits, nil, feeRateNanosPerKB, nil, []*DeSoOutput{})
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
			txn, txHash, blockHeight, 0, true, false)
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

	utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, nil)

	// Create the coin unlock transaction.
	txn, totalInputMake, _, feesMake, err := chain.CreateCoinUnlockTxn(
		transactorPkBytes, profilePkBytes, nil, feeRateNanosPerKB, nil, []*DeSoOutput{})
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
			txn, txHash, blockHeight, connectTimestamp, true, false)
	if err != nil {
		return nil, nil, 0, err
	}

	// Ensure that DESO is flowing in the correct amount.
	require.Equal(totalInput, totalOutput+fees)

	// Check that UtxoOps following connection have the correct type
	require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
	require.Equal(OperationTypeCoinUnlock, utxoOps[1].Type)

	// Ensure the transaction can be flushed without issue before returning
	require.NoError(utxoView.FlushToDb(uint64(blockHeight)))
	return utxoOps, txn, blockHeight, nil
}
