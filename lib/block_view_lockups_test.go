package lib

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestForkHeightAndInitialState(t *testing.T) {
	// TODO: Create test for forks.

	// TODO: Create test for initial creator state.

	// TODO: Create test for initial deso state.
}

func TestCalculateLockupYield(t *testing.T) {
	var yield *uint256.Int
	var err error

	// Ensure that a lockup with zero duration has zero yield.
	yield, err = CalculateLockupYield(
		MaxUint256,
		uint256.NewInt(),
		uint256.NewInt().SetUint64(1))
	require.NoError(t, err)
	require.Equal(t, *yield, *uint256.NewInt())

	// Ensure that a lockup with zero apyYieldBasisPoints has zero yield.
	yield, err = CalculateLockupYield(
		MaxUint256,
		uint256.NewInt().SetUint64(1),
		uint256.NewInt())
	require.NoError(t, err)
	require.Equal(t, *yield, *uint256.NewInt())

	// Ensure that when principal is MaxUint256 and the apy yield is 2bp,
	// the operation fails due to lack of precision.
	_, err = CalculateLockupYield(
		MaxUint256,
		uint256.NewInt().SetUint64(2),
		uint256.NewInt().SetUint64(1))
	require.Contains(t, err.Error(), RuleErrorCoinLockupCoinYieldOverflow)

	// Ensure that when principal is MaxUint256 and the duration is 2ns,
	// the operation fails due to lack of precision.
	_, err = CalculateLockupYield(
		MaxUint256,
		uint256.NewInt().SetUint64(1),
		uint256.NewInt().SetUint64(2))
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
		uint256.NewInt().SetUint64(365*24*10000),
		uint256.NewInt().SetUint64(60*60),
		uint256.NewInt().SetUint64(1e9))
	require.NoError(t, err)
	require.Equal(t, *yield, *uint256.NewInt().SetUint64(1))

	// Knowing this, we can now check to ensure the edges of the CalculateLockupYield
	// operation are behaving correctly and never minting more coins than expected.
	// We start by reducing the numerator. Any decrease to the numerator should return a yield of zero.
	// To test this, we set duration = 1e9 - 1.
	// (This decreases only the largest factor, leading to the smallest decrease possible in the numerator)
	yield, err = CalculateLockupYield(
		uint256.NewInt().SetUint64(365*24*10000),
		uint256.NewInt().SetUint64(60*60),
		uint256.NewInt().SetUint64(1e9-1))
	require.NoError(t, err)
	require.Equal(t, *yield, *uint256.NewInt().SetUint64(0))

	// If we only slightly increase the numerator, we should expect to see the yield remain the same.
	// To test this, we set duration = 1e9 + 1
	// (This increases only the largest factor, leading to the smallest increase possible in the numerator)
	yield, err = CalculateLockupYield(
		uint256.NewInt().SetUint64(365*24*10000),
		uint256.NewInt().SetUint64(60*60),
		uint256.NewInt().SetUint64(1e9+1))
	require.NoError(t, err)
	require.Equal(t, *yield, *uint256.NewInt().SetUint64(1))

	// We should only see an increase to the output yield if the numerator is scaled by a constant.
	// To do this, we can iterate through various constants and see if the output yield matches.
	// These operations are quick and cheap, so we test all values between 0 and 100000.
	// We also ensure that slight deviations do not alter the output.
	for ii := uint64(0); ii < 100000; ii++ {
		yield, err = CalculateLockupYield(
			uint256.NewInt().SetUint64(ii*365*24*10000),
			uint256.NewInt().SetUint64(60*60),
			uint256.NewInt().SetUint64(1e9))
		require.NoError(t, err)
		require.Equal(t, *yield, *uint256.NewInt().SetUint64(ii))

		// Slight increase to the numerator. Ensure we don't create more yield than expected.
		yield, err = CalculateLockupYield(
			uint256.NewInt().SetUint64(ii*365*24*10000),
			uint256.NewInt().SetUint64(60*60),
			uint256.NewInt().SetUint64(1e9+1))
		require.NoError(t, err)
		require.Equal(t, *yield, *uint256.NewInt().SetUint64(ii))

		// Slight decrease to the numerator. Ensure we create strictly less yield.
		expectedValue := ii - 1
		if ii == 0 {
			expectedValue = 0
		}
		yield, err = CalculateLockupYield(
			uint256.NewInt().SetUint64(ii*365*24*10000),
			uint256.NewInt().SetUint64(60*60),
			uint256.NewInt().SetUint64(1e9-1))
		require.NoError(t, err)
		require.Equal(t, *yield, *uint256.NewInt().SetUint64(expectedValue))
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
	// NOTE: This also checks that DESO lockups do not require an associated profile.
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
			testMeta,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			m2Pub,
			1000,
			MaxUint256,
			0)

		// Ensure CoinsInCirculationNanos and NumberOfHolders are now zero
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		profileEntry := utxoView.GetProfileEntryForPublicKey(m2PkBytes)
		require.Equal(t, *uint256.NewInt(), profileEntry.DAOCoinEntry.CoinsInCirculationNanos)
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
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			m2Pub,
			1000,
			uint256.NewInt().SetUint64(1),
			0)
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
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			m2Pub,
			365*24*60*60*1e9,
			MaxUint256,
			0)
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
			t, testMeta.chain, testMeta.db, testMeta.params,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			m2Pub,
			1,
			MaxUint256,
			0)
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
			testMeta,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			m2Pub,
			1000,
			MaxUint256,
			0,
		)

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
			testMeta,
			testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			m2Pub,
			1001,
			MaxUint256,
			0,
		)

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
				CoinsToMintNanos:          *uint256.NewInt().SetUint64(1),
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
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID

		// Get the original BalanceEntry for the associated DAO coins.
		originalBalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			m1PkBytes, m1PkBytes, true)

		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			m1Pub,
			365*24*60*60*1e9+365*12*60*60*1e9,
			uint256.NewInt().SetUint64(10000),
			365*24*60*60*1e9,
		)

		// Check to ensure the resulting locked balance entry has 10000 base units.
		utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		lockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
			m1PKID, m1PKID, 365*24*60*60*1e9+365*12*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt().SetUint64(10000), lockedBalanceEntry.BalanceBaseUnits)

		// Check to ensure that the BalanceEntry has decreased by exactly 10000.
		newBalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			m1PkBytes, m1PkBytes, true)
		require.True(t, originalBalanceEntry.BalanceNanos.Gt(&newBalanceEntry.BalanceNanos))
		require.Equal(t,
			*uint256.NewInt().Sub(&originalBalanceEntry.BalanceNanos, &newBalanceEntry.BalanceNanos),
			*uint256.NewInt().SetUint64(10000))
	}

	// Have m1 lockup 10000 m1 DAO tokens for one year.
	// We set the connecting block timestamp to 1 year from UNIX start to give it a non-zero value.
	// We expect this to create a locked balance entry with 10500 base units locked inside.
	{
		// Get the PKID associated with m1.
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID

		// Get the original BalanceEntry for the associated DAO coins.
		originalBalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			m1PkBytes, m1PkBytes, true)

		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			m1Pub,
			2*365*24*60*60*1e9,
			uint256.NewInt().SetUint64(10000),
			365*24*60*60*1e9,
		)

		// Check to ensure the resulting locked balance entry has 10500 base units.
		utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		lockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
			m1PKID, m1PKID, 2*365*24*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt().SetUint64(10500), lockedBalanceEntry.BalanceBaseUnits)

		// Check to ensure that the BalanceEntry has decreased by exactly 10000.
		newBalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			m1PkBytes, m1PkBytes, true)
		require.True(t, originalBalanceEntry.BalanceNanos.Gt(&newBalanceEntry.BalanceNanos))
		require.Equal(t,
			*uint256.NewInt().Sub(&originalBalanceEntry.BalanceNanos, &newBalanceEntry.BalanceNanos),
			*uint256.NewInt().SetUint64(10000))
	}

	// Have m1 lockup 10000 m1 DAO tokens for one and a half year.
	// We set the connecting block timestamp to 1 year from UNIX start to give it a non-zero value.
	// We expect this to create a locked balance entry with 10500 base units locked inside.
	// NOTE: This is testing the interpolation algorithm for lockups in the middle of two yield curve points.
	{
		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			m1Pub,
			2*365*24*60*60*1e9+365*12*60*60*1e9,
			uint256.NewInt().SetUint64(10000),
			365*24*60*60*1e9,
		)

		// Check to ensure the resulting locked balance entry has 10500 base units.
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID
		lockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
			m1PKID, m1PKID, 2*365*24*60*60*1e9+365*12*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt().SetUint64(10500), lockedBalanceEntry.BalanceBaseUnits)
	}

	// Have m1 lockup 10000 m1 DAO tokens for two years.
	// We set the connecting block timestamp to 1 year from UNIX start to give it a non-zero value.
	// We expect this to create a locked balance entry with 12000 base units locked inside.
	{
		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			m1Pub,
			3*365*24*60*60*1e9,
			uint256.NewInt().SetUint64(10000),
			365*24*60*60*1e9,
		)

		// Check to ensure the resulting locked balance entry has 12000 base units.
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID
		lockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
			m1PKID, m1PKID, 3*365*24*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt().SetUint64(12000), lockedBalanceEntry.BalanceBaseUnits)
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
			uint256.NewInt().SetUint64(500),
		)
		_coinLockupTransferWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			NewPublicKey(m3PkBytes),
			NewPublicKey(m1PkBytes),
			2*365*24*60*60*1e9,
			uint256.NewInt().SetUint64(500),
		)
		_coinLockupTransferWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			NewPublicKey(m4PkBytes),
			NewPublicKey(m1PkBytes),
			2*365*24*60*60*1e9,
			uint256.NewInt().SetUint64(500),
		)

		// Check to ensure the resulting locked balance entry for m1 has 9000 base units.
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID
		lockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
			m1PKID, m1PKID, 2*365*24*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt().SetUint64(9000), lockedBalanceEntry.BalanceBaseUnits)
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
			uint256.NewInt().SetUint64(500),
		)
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferRestrictedToProfileOwner)
	}

	// Check to make sure tokens can be unlocked following a year.
	// Ensure that the associated balance entry increases by 500 on unlock.
	// 500 base units of m1 DAO coins was given by m2 during the distribution phase.
	{
		// Get the original BalanceEntry for the associated DAO coins.
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		originalBalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			m2PkBytes, m1PkBytes, true)

		_, _, _, err = _coinUnlockWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			m1Pub,
			2*365*24*60*60*1e9+1,
		)
		require.NoError(t, err)

		// Get the updated BalanceEntry for the associated DAO coins.
		utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		newBalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			m2PkBytes, m1PkBytes, true)
		require.True(t, newBalanceEntry.BalanceNanos.Gt(&originalBalanceEntry.BalanceNanos))
		require.Equal(t, *uint256.NewInt().SetUint64(500), *uint256.NewInt().Sub(
			&newBalanceEntry.BalanceNanos, &originalBalanceEntry.BalanceNanos))
	}
}

func TestLockupStandardDeSoFlows(t *testing.T) {
	// Initialize test chain, miner, and testMeta
	testMeta := _setUpMinerAndTestMetaForTimestampBasedLockupTests(t)

	// Initialize m0, m1, m2, m3, m4, and paramUpdater
	_setUpProfilesAndMintM0M1DAOCoins(testMeta)

	// Ensure that paramUpdater is set in the testMeta
	testMeta.params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

	// Have paramUpdater create a yield curve which consists of:
	// 1 year  @  5% yield
	// 2 years @ 10% yield
	// Remove the yield curve point.
	{
		_updateCoinLockupParamsWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			paramUpdaterPub,
			paramUpdaterPriv,
			365*24*60*60*1e9,
			500,
			false,
			false,
			TransferRestrictionStatusUnrestricted,
		)
		_updateCoinLockupParamsWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			paramUpdaterPub,
			paramUpdaterPriv,
			2*365*24*60*60*1e9,
			1000,
			false,
			true,
			TransferRestrictionStatusProfileOwnerOnly,
		)
	}

	// Have m1 lockup 500 nDESO for half of a year.
	// We set the connecting block timestamp to 1 year from UNIX start to give it a non-zero value.
	// We expect this to create a locked balance entry with 500 base units locked inside.
	{
		// Get m1's DESO balance.
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1OriginalBalance, err := utxoView.GetDeSoBalanceNanosForPublicKey(m1PkBytes)
		require.NoError(t, err)

		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
			365*24*60*60*1e9+365*12*60*60*1e9,
			uint256.NewInt().SetUint64(500),
			365*24*60*60*1e9,
		)

		// Check to ensure the resulting locked balance entry has 525 base units.
		utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID
		lockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
			m1PKID, ZeroPKID.NewPKID(), 365*24*60*60*1e9+365*12*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt().SetUint64(500), lockedBalanceEntry.BalanceBaseUnits)

		// Check that m1's DESO balance has decreased by more than 500 nDESO (some extra was spent on fees).
		m1NewBalance, err := utxoView.GetDeSoBalanceNanosForPublicKey(m1PkBytes)
		require.NoError(t, err)
		require.Greater(t, m1OriginalBalance, m1NewBalance)
		require.Greater(t, m1OriginalBalance-m1NewBalance, uint64(500))
	}

	// Have m1 lockup 500 nDESO for one year.
	// We set the connecting block timestamp to 1 year from UNIX start to give it a non-zero value.
	// We expect this to create a locked balance entry with 525 base units locked inside.
	{
		// Get m1's DESO balance.
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1OriginalBalance, err := utxoView.GetDeSoBalanceNanosForPublicKey(m1PkBytes)
		require.NoError(t, err)

		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
			2*365*24*60*60*1e9,
			uint256.NewInt().SetUint64(500),
			365*24*60*60*1e9,
		)

		// Check to ensure the resulting locked balance entry has 525 base units.
		utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID
		lockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
			m1PKID, ZeroPKID.NewPKID(), 2*365*24*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt().SetUint64(525), lockedBalanceEntry.BalanceBaseUnits)

		// Check that m1's DESO balance has decreased by more than 500 nDESO (some extra was spent on fees).
		m1NewBalance, err := utxoView.GetDeSoBalanceNanosForPublicKey(m1PkBytes)
		require.NoError(t, err)
		require.Greater(t, m1OriginalBalance, m1NewBalance)
		require.Greater(t, m1OriginalBalance-m1NewBalance, uint64(500))
	}

	// Have m1 lockup 500 nDESO for one and a half years.
	// We set the connecting block timestamp to 1 year from UNIX start to give it a non-zero value.
	// We expect this to create a locked balance entry with 525 base units locked inside.
	{
		// Get m1's DESO balance.
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1OriginalBalance, err := utxoView.GetDeSoBalanceNanosForPublicKey(m1PkBytes)
		require.NoError(t, err)

		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
			2*365*24*60*60*1e9+365*12*60*60*1e9,
			uint256.NewInt().SetUint64(500),
			365*24*60*60*1e9,
		)

		// Check to ensure the resulting locked balance entry has 525 base units.
		utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID
		lockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
			m1PKID, ZeroPKID.NewPKID(), 2*365*24*60*60*1e9+365*12*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt().SetUint64(525), lockedBalanceEntry.BalanceBaseUnits)

		// Check that m1's DESO balance has decreased by more than 500 nDESO (some extra was spent on fees).
		m1NewBalance, err := utxoView.GetDeSoBalanceNanosForPublicKey(m1PkBytes)
		require.NoError(t, err)
		require.Greater(t, m1OriginalBalance, m1NewBalance)
		require.Greater(t, m1OriginalBalance-m1NewBalance, uint64(500))
	}

	// Have m1 lockup 500 nDESO for two years.
	// We set the connecting block timestamp to 1 year from UNIX start to give it a non-zero value.
	// We expect this to create a locked balance entry with 600 base units locked inside.
	{
		// Get m1's DESO balance.
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1OriginalBalance, err := utxoView.GetDeSoBalanceNanosForPublicKey(m1PkBytes)
		require.NoError(t, err)

		_coinLockupWithTestMetaAndConnectTimestamp(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
			3*365*24*60*60*1e9,
			uint256.NewInt().SetUint64(500),
			365*24*60*60*1e9,
		)

		// Check to ensure the resulting locked balance entry has 525 base units.
		utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID
		lockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
			m1PKID, ZeroPKID.NewPKID(), 3*365*24*60*60*1e9)
		require.NoError(t, err)
		require.Equal(t, *uint256.NewInt().SetUint64(600), lockedBalanceEntry.BalanceBaseUnits)

		// Check that m1's DESO balance has decreased by more than 500 nDESO (some extra was spent on fees).
		m1NewBalance, err := utxoView.GetDeSoBalanceNanosForPublicKey(m1PkBytes)
		require.NoError(t, err)
		require.Greater(t, m1OriginalBalance, m1NewBalance)
		require.Greater(t, m1OriginalBalance-m1NewBalance, uint64(500))
	}

	// Check to make sure locked DESO is not liquid.
	{
		_, _, _, err := _coinLockupTransfer(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			NewPublicKey(m3PkBytes),
			&ZeroPublicKey,
			2*365*24*60*60*1e9,
			uint256.NewInt().SetUint64(100),
		)
		require.Contains(t, err.Error(), RuleErrorCoinLockupTransferRestrictedToProfileOwner)
	}

	// Check to make sure tokens can be unlocked following a year.
	// Ensure that the associated balance entry increases by less than 1025 on unlock.
	// One locked balance entry exists at half a year and has 500 nDESO, the other at one year
	// and has 525 nDESO.
	{
		// Get m1's DESO balance.
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1OriginalBalance, err := utxoView.GetDeSoBalanceNanosForPublicKey(m1PkBytes)
		require.NoError(t, err)

		_, _, _, err = _coinUnlockWithConnectTimestamp(
			t, testMeta.chain, testMeta.db, testMeta.params, testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
			2*365*24*60*60*1e9+1,
		)
		require.NoError(t, err)

		// Check to ensure the resulting locked balance entry is deleted.
		utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)
		m1PKIDEntry := utxoView.GetPKIDForPublicKey(m1PkBytes)
		m1PKID := m1PKIDEntry.PKID
		lockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
			m1PKID, ZeroPKID.NewPKID(), 2*365*24*60*60*1e9)
		require.True(t, lockedBalanceEntry == nil)

		// Check that m1's DESO balance has increased by less than 1025 nDESO (some extra was spent on fees).
		m1NewBalance, err := utxoView.GetDeSoBalanceNanosForPublicKey(m1PkBytes)
		require.NoError(t, err)
		require.Greater(t, m1NewBalance, m1OriginalBalance)
		require.Less(t, m1NewBalance-m1OriginalBalance, uint64(1025))
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
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		m0Pub,
		m0Priv,
		m0Pub,
		2*365*24*60*60*1e9,
		uint256.NewInt().SetUint64(1000),
		365*24*60*60*1e9)
	require.NoError(t, err)
	utxoOps2, txn2, _, err := _coinLockupWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		m0Pub,
		m0Priv,
		m0Pub,
		2*365*24*60*60*1e9,
		uint256.NewInt().SetUint64(1000),
		365*24*60*60*1e9)
	require.NoError(t, err)
	txHash := txn2.Hash()
	blockHeight := testMeta.chain.BlockTip().Height + 1
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	err = utxoView.DisconnectTransaction(txn2, txHash, utxoOps2, blockHeight)
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))
	require.NoError(t, err)
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	m0PKID := utxoView.GetPKIDForPublicKey(m0PkBytes).PKID
	lockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
		m0PKID, m0PKID, 2*365*24*60*60*1e9)
	require.NoError(t, err)
	require.Equal(t, *uint256.NewInt().SetUint64(1000), lockedBalanceEntry.BalanceBaseUnits)
	balanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes, true)
	require.Equal(t, *uint256.NewInt().SetUint64(999000), balanceEntry.BalanceNanos)
	err = utxoView.DisconnectTransaction(txn1, txn1.Hash(), utxoOps1, blockHeight)
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))
	require.NoError(t, err)
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	lockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
		m0PKID, m0PKID, 2*365*24*60*60*1e9)
	require.True(t, lockedBalanceEntry == nil)
	balanceEntry, _, _ = utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, m0PkBytes, true)
	require.Equal(t, *uint256.NewInt().SetUint64(1000000), balanceEntry.BalanceNanos)

	//
	// Test Coin Lockup for DESO
	//

	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	originalBalance, err := utxoView.GetSpendableDeSoBalanceNanosForPublicKey(
		m2PkBytes, testMeta.chain.BlockTip().Height)
	require.NoError(t, err)
	utxoOps1, txn1, _, err = _coinLockupWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		m2Pub,
		m2Priv,
		Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
		2*365*24*60*60*1e9,
		uint256.NewInt().SetUint64(500),
		365*24*60*60*1e9)
	require.NoError(t, err)
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	intermediateBalance, err := utxoView.GetSpendableDeSoBalanceNanosForPublicKey(
		m2PkBytes, testMeta.chain.BlockTip().Height)
	require.NoError(t, err)
	utxoOps2, txn2, _, err = _coinLockupWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		m2Pub,
		m2Priv,
		Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
		2*365*24*60*60*1e9,
		uint256.NewInt().SetUint64(500),
		365*24*60*60*1e9)
	require.NoError(t, err)
	txHash = txn2.Hash()
	blockHeight = testMeta.chain.BlockTip().Height + 1
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	err = utxoView.DisconnectTransaction(txn2, txHash, utxoOps2, blockHeight)
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))
	require.NoError(t, err)
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	m2PKID := utxoView.GetPKIDForPublicKey(m2PkBytes).PKID
	lockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
		m2PKID, &ZeroPKID, 2*365*24*60*60*1e9)
	require.NoError(t, err)
	require.Equal(t, *uint256.NewInt().SetUint64(500), lockedBalanceEntry.BalanceBaseUnits)
	currentBalance, err := utxoView.GetSpendableDeSoBalanceNanosForPublicKey(
		m2PkBytes, testMeta.chain.BlockTip().Height)
	require.NoError(t, err)
	require.Equal(t, currentBalance, intermediateBalance)
	err = utxoView.DisconnectTransaction(txn1, txn1.Hash(), utxoOps1, blockHeight)
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))
	require.NoError(t, err)
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	lockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
		m2PKID, &ZeroPKID, 2*365*24*60*60*1e9)
	require.True(t, lockedBalanceEntry == nil)
	currentBalance, err = utxoView.GetSpendableDeSoBalanceNanosForPublicKey(
		m2PkBytes, testMeta.chain.BlockTip().Height)
	require.NoError(t, err)
	require.Equal(t, currentBalance, originalBalance)

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
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
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
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
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
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
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
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	leftYieldCurvePoint, rightYieldCurvePoint, err =
		utxoView.GetLocalYieldCurvePoints(m1PKID, 365*24*60*60*1e9)
	require.NoError(t, err)
	require.True(t, leftYieldCurvePoint == nil)
	require.Equal(t, rightYieldCurvePoint.LockupYieldAPYBasisPoints, uint64(1000))
	require.Equal(t, rightYieldCurvePoint.LockupDurationNanoSecs, int64(365*24*60*60*1e9))
	profileEntry = utxoView.GetProfileEntryForPKID(m1PKID)
	require.Equal(t, profileEntry.DAOCoinEntry.LockupTransferRestrictionStatus, TransferRestrictionStatusProfileOwnerOnly)

	//
	// Test Update Coin Lockup Params for DESO
	//

	// Test adding a lockup curve point and modifying lockup transfer restrictions.
	// Ensure upon disconnect the original point and restrictions remain.
	_, _, _, err = _updateCoinLockupParams(
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		paramUpdaterPub,
		paramUpdaterPriv,
		365*24*60*60*1e9,
		1000,
		false,
		true,
		TransferRestrictionStatusProfileOwnerOnly,
	)
	require.NoError(t, err)
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	utxoOps, txn, _, err = _updateCoinLockupParams(
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		paramUpdaterPub,
		paramUpdaterPriv,
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
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	leftYieldCurvePoint, rightYieldCurvePoint, err =
		utxoView.GetLocalYieldCurvePoints(&ZeroPKID, 365*24*60*60*1e9)
	require.NoError(t, err)
	require.True(t, leftYieldCurvePoint == nil)
	require.Equal(t, rightYieldCurvePoint.LockupYieldAPYBasisPoints, uint64(1000))
	require.Equal(t, rightYieldCurvePoint.LockupDurationNanoSecs, int64(365*24*60*60*1e9))
	require.Equal(t, utxoView.GlobalParamsEntry.LockedDESOTransferRestrictions, TransferRestrictionStatusProfileOwnerOnly)

	// Test Deleting a Yield Curve Point and Reverting Said Transaction
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	utxoOps, txn, _, err = _updateCoinLockupParams(
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		paramUpdaterPub,
		paramUpdaterPriv,
		365*24*60*60*1e9,
		0,
		true,
		false,
		TransferRestrictionStatusUnrestricted,
	)
	require.NoError(t, err)
	leftYieldCurvePoint, rightYieldCurvePoint, err =
		utxoView.GetLocalYieldCurvePoints(&ZeroPKID, 365*24*60*60*1e9)
	require.NoError(t, err)
	require.True(t, leftYieldCurvePoint == nil)
	require.True(t, rightYieldCurvePoint == nil)
	txHash = txn.Hash()
	blockHeight = testMeta.chain.BlockTip().Height + 1
	err = utxoView.DisconnectTransaction(txn, txHash, utxoOps, blockHeight)
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))
	require.NoError(t, err)
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	leftYieldCurvePoint, rightYieldCurvePoint, err =
		utxoView.GetLocalYieldCurvePoints(&ZeroPKID, 365*24*60*60*1e9)
	require.NoError(t, err)
	require.True(t, leftYieldCurvePoint == nil)
	require.Equal(t, rightYieldCurvePoint.LockupYieldAPYBasisPoints, uint64(1000))
	require.Equal(t, rightYieldCurvePoint.LockupDurationNanoSecs, int64(365*24*60*60*1e9))
	require.Equal(t, utxoView.GlobalParamsEntry.LockedDESOTransferRestrictions, TransferRestrictionStatusProfileOwnerOnly)

	//
	// Test Coin Lockup Transfers
	//

	// Create an on-chain profile for m3 with MaxUint256 Locked Tokens
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
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
		testMeta,
		testMeta.feeRateNanosPerKb,
		m3Pub,
		m3Priv,
		m3Pub,
		1000,
		MaxUint256,
		0)
	utxoOps, txn, _, err = _coinLockupTransfer(
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		m3Pub,
		m3Priv,
		NewPublicKey(m4PkBytes),
		NewPublicKey(m3PkBytes),
		1000,
		MaxUint256)
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	m3PKID := utxoView.GetPKIDForPublicKey(m3PkBytes).PKID
	m4PKID := utxoView.GetPKIDForPublicKey(m4PkBytes).PKID
	m3BalanceEntry, err := utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(m3PKID, m3PKID, 1000)
	m4BalanceEntry, err := utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(m4PKID, m3PKID, 1000)
	require.True(t, nil == m3BalanceEntry)
	require.Equal(t, *MaxUint256, m4BalanceEntry.BalanceBaseUnits)
	txHash = txn.Hash()
	blockHeight = testMeta.chain.BlockTip().Height + 1
	err = utxoView.DisconnectTransaction(txn, txHash, utxoOps, blockHeight)
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))
	require.NoError(t, err)
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	m3PKID = utxoView.GetPKIDForPublicKey(m3PkBytes).PKID
	m4PKID = utxoView.GetPKIDForPublicKey(m4PkBytes).PKID
	m3BalanceEntry, err = utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(m3PKID, m3PKID, 1000)
	m4BalanceEntry, err = utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(m4PKID, m3PKID, 1000)
	require.True(t, nil == m4BalanceEntry)
	require.Equal(t, *MaxUint256, m3BalanceEntry.BalanceBaseUnits)

	//
	// Test Coin Unlocks for Profiles
	//

	// Create an on-chain profile for m4 with MaxUint256 Locked Tokens
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
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
		testMeta,
		testMeta.feeRateNanosPerKb,
		m4Pub,
		m4Priv,
		m4Pub,
		1000,
		MaxUint256,
		0)

	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	m4LockedBalanceEntry, err := utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
		m4PKID, m4PKID, 1000)
	m4be, _, _ := utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m4PkBytes, m4PkBytes)
	require.NoError(t, err)
	require.Equal(t, *MaxUint256, m4LockedBalanceEntry.BalanceBaseUnits)
	require.Equal(t, *uint256.NewInt(), m4be.BalanceNanos)

	utxoOps, txn, _, err = _coinUnlockWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		m4Pub,
		m4Priv,
		m4Pub,
		1001)

	// Ensure unlock functioned properly
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	m4LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
		m4PKID, m4PKID, 1000)
	require.NoError(t, err)
	m4be, _, _ = utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m4PkBytes, m4PkBytes)
	require.True(t, nil == m4LockedBalanceEntry)
	require.Equal(t, *MaxUint256, m4be.BalanceNanos)

	// Execute the disconnect and ensure it functions correctly
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	txHash = txn.Hash()
	blockHeight = testMeta.chain.BlockTip().Height + 1
	err = utxoView.DisconnectTransaction(txn, txHash, utxoOps, blockHeight)
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))
	require.NoError(t, err)
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	m4LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
		m4PKID, m4PKID, 1000)
	require.NoError(t, err)
	m4be, _, _ = utxoView.GetDAOCoinBalanceEntryForHODLerPubKeyAndCreatorPubKey(m4PkBytes, m4PkBytes)
	require.Equal(t, *uint256.NewInt(), m4be.BalanceNanos)
	require.Equal(t, *MaxUint256, m4LockedBalanceEntry.BalanceBaseUnits)

	//
	// Test Coin Unlocks for DESO
	//

	// Lockup 500 nDESO with m4. Check to ensure balances are accurately updated.
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	startingBalance, err := utxoView.GetSpendableDeSoBalanceNanosForPublicKey(
		m4PkBytes, testMeta.chain.BlockTip().Height)
	require.NoError(t, err)
	_coinLockupWithTestMetaAndConnectTimestamp(
		testMeta,
		testMeta.feeRateNanosPerKb,
		m4Pub,
		m4Priv,
		Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
		1000,
		uint256.NewInt().SetUint64(500),
		0)

	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	m4LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
		m4PKID, &ZeroPKID, 1000)
	preUnlockBalance, err := utxoView.GetSpendableDeSoBalanceNanosForPublicKey(
		m4PkBytes, testMeta.chain.BlockTip().Height)
	require.NoError(t, err)
	require.Equal(t, *uint256.NewInt().SetUint64(500), m4LockedBalanceEntry.BalanceBaseUnits)
	require.Greater(t, startingBalance, preUnlockBalance)
	require.Greater(t, startingBalance-preUnlockBalance, uint64(500))

	utxoOps, txn, _, err = _coinUnlockWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		m4Pub,
		m4Priv,
		Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params),
		1001)

	// Ensure unlock functioned properly
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	m4LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
		m4PKID, &ZeroPKID, 1000)
	currentBalance, err = utxoView.GetSpendableDeSoBalanceNanosForPublicKey(
		m4PkBytes, testMeta.chain.BlockTip().Height)
	require.NoError(t, err)
	require.True(t, m4LockedBalanceEntry == nil)
	require.Greater(t, startingBalance, currentBalance)
	require.Less(t, startingBalance-currentBalance, uint64(500))

	// Execute the disconnect and ensure it functions correctly
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	txHash = txn.Hash()
	blockHeight = testMeta.chain.BlockTip().Height + 1
	err = utxoView.DisconnectTransaction(txn, txHash, utxoOps, blockHeight)
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))
	require.NoError(t, err)
	utxoView, err = NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	m4LockedBalanceEntry, err = utxoView.GetLockedBalanceEntryForHODLerPKIDProfilePKIDUnlockTimestampNanoSecs(
		m4PKID, &ZeroPKID, 1000)
	currentBalance, err = utxoView.GetSpendableDeSoBalanceNanosForPublicKey(
		m4PkBytes, testMeta.chain.BlockTip().Height)
	require.NoError(t, err)
	require.Equal(t, *uint256.NewInt().SetUint64(500), m4LockedBalanceEntry.BalanceBaseUnits)
	require.Equal(t, preUnlockBalance, currentBalance)
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
