package block_view

import (
	"github.com/deso-protocol/core/lib"
	"github.com/deso-protocol/core/network"
	"github.com/deso-protocol/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSwapIdentityNOOPCreatorCoinBuySimple(t *testing.T) {

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      network.TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                network.CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                network.CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1172373183,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           4827626815,
		},
		// Have m1 sell half of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                network.CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4123456789,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
			m3DeSoBalance:           6000000000,
		},
		// Swap m0 and m3
		// State after swapping:
		// m0Pk: m3 profile
		// m3Pk: m0 profile (the one with the profile)
		{
			TxnType:       network.TxnTypeSwapIdentity,
			FromPublicKey: m0PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m3Pub,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             0, // Should go to zero because it belongs to m3 now
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m3CCBalance:             3367151687,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
			m3DeSoBalance:           6000000000,
		},
		// Swap m3 and m1
		// State after swapping:
		// m0Pk: m3 profile
		// m1Pk: m0 profile (the one with the profile)
		// m3Pk: m1 profile
		{
			TxnType:       network.TxnTypeSwapIdentity,
			FromPublicKey: m3PkBytes,
			ToPublicKey:   m1PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m1Pub,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             0, // m0 still has zero because they got a dummy profile
			m0HasPurchased:          false,
			m1CCBalance:             3367151687, // This becomes what m3 had a moment ago.
			m1HasPurchased:          false,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m3CCBalance:             4000655948, // This becomes what m1 had a moment ago.
			m3HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
			m3DeSoBalance:           6000000000,
		},
		// Swap m0 and m1. Should restore m0's profile to it.
		// State after swapping:
		// m0Pk: m0 profile (the one with the profile)
		// m1Pk: m3 profile
		// m3Pk: m1 profile
		{
			TxnType:       network.TxnTypeSwapIdentity,
			FromPublicKey: m0PkBytes,
			ToPublicKey:   m1PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m0Pub,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687, // m0 should be back to normal
			m0HasPurchased:          false,
			m1CCBalance:             0, // m1 is the zero now since it took the empty profile from m0
			m1HasPurchased:          false,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m3CCBalance:             4000655948, // This is still what m1 started with.
			m3HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
			m3DeSoBalance:           6000000000,
		},
		// Swap m1 and m3. Should restore everything back to normal.
		// State after swapping:
		// m0Pk: m0 profile
		// m1Pk: m1 profile (the one with the profile)
		// m3Pk: m3 profile
		{
			TxnType:       network.TxnTypeSwapIdentity,
			FromPublicKey: m1PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m0Pub,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m3CCBalance:             0, // This goes back to zero as we started with.
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
			m3DeSoBalance:           6000000000,
		},
		// Have m2 sell all of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                network.CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       1977342329,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 7367807635,
			DeSoLockedNanos:         399958612,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           5243756077,
		},
		// Have m1 buy more, m0 should receive 25% of the minted coins as a founders reward
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                network.CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13613944261,
			DeSoLockedNanos:         2523203055,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             4928685843,
			m0HasPurchased:          false,
			m1CCBalance:             8685258418,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4232379830,
			m2DeSoBalance:           5243756077,
		},

		// Have m1 sell the rest of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                network.CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       8685258418,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4928685843,
			DeSoLockedNanos:         119727407,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             4928685843,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
		},

		// Have m0 sell all of their stake except leave 1 DeSo locked
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                network.CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4925685829,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 3000014,
			DeSoLockedNanos:         1,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             3000014,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6119715429,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
		},

		{
			// Have m0 sell all of their remaining stake except for 1 CreatorCoin nano
			// This will trigger an autosell.
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                network.CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       3000013,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6119715427,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
		},

		// Have m1 buy a little more, m0 should receieve some
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                network.CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 12852863707,
			DeSoLockedNanos:         2123244443,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             3213215926,
			m0HasPurchased:          false,
			m1CCBalance:             9639647781,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6119715427,
			m1DeSoBalance:           4512158337,
			m2DeSoBalance:           5243756077,
		},

		// Have m1 sell their creator coins. m0 should be the only one left with coins.
		// Meaning m0 is effectively being left with their founders reward, even after all
		// their supporters have sold.
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                network.CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       9639647781,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 3213215926,
			DeSoLockedNanos:         33175681,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             3213215926,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6119715427,
			m1DeSoBalance:           6602018090,
			m2DeSoBalance:           5243756077,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestSwapIdentityCreatorCoinBuySimple(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      network.TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                network.CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                network.CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1172373183,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           4827626815,
		},
		// Have m1 sell half of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                network.CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4123456789,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
		},

		// Swap m0 and m3
		{
			TxnType:       network.TxnTypeSwapIdentity,
			FromPublicKey: m0PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m3Pub,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             0, // Should go to zero because it belongs to m3 now
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m3CCBalance:             3367151687,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
		},

		// Have m2 sell all of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                network.CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       1977342329,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 7367807635,
			DeSoLockedNanos:         399958612,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             3367151687,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           5243756077,
		},
		// Have m1 buy more, m3 should receieve a founders reward
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                network.CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13613944261,
			DeSoLockedNanos:         2523203055,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             8685258418,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             4928685843,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4232379830,
			m2DeSoBalance:           5243756077,
		},

		// Have m1 sell the rest of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                network.CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       8685258418,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4928685843,
			DeSoLockedNanos:         119727407,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             4928685843,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
		},

		// Have m3 sell all of their stake except leave 1 DeSo locked
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m3Pub,
			UpdaterPrivateKeyBase58Check: m3Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                network.CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4925685829,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 3000014,
			DeSoLockedNanos:         1,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             3000014,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
			m3DeSoBalance:           6119715431,
		},

		{
			// Have m3 sell all of their remaining stake except for 1 CreatorCoin nano
			// This should trigger the CreatorCoinAutoSellThresholdNanos threshold leaving
			// m3 with no CreatorCoins.
			UpdaterPublicKeyBase58Check:  m3Pub,
			UpdaterPrivateKeyBase58Check: m3Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                network.CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       3000013,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
			m3DeSoBalance:           6119715429,
		},

		// Have m1 buy a little more, m3 should receieve a founders reward
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                network.CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 12852863707,
			DeSoLockedNanos:         2123244443,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9639647781,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             3213215926,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4512158337,
			m2DeSoBalance:           5243756077,
			m3DeSoBalance:           6119715429,
		},

		// Have m1 sell their creator coins except CreatorCoinAutoSellThresholdNanos - 1. This should
		// cause an auto sell and m1 back to zero.
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                network.CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       9639647781 - types.DeSoMainnetParams.CreatorCoinAutoSellThresholdNanos + 1,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 3213215926,
			DeSoLockedNanos:         33175681,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             3213215926,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6602018090,
			m2DeSoBalance:           5243756077,
			m3DeSoBalance:           6119715429,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestSwapIdentityFailureCases(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	// Set up a blockchain
	chain, params, db := lib.NewLowDifficultyBlockchain()
	mempool, miner := lib.NewTestMiner(t, chain, params, true /*isSender*/)
	feeRateNanosPerKB := uint64(11)
	_, _ = mempool, miner

	// Send money to people from moneyPk
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, lib.moneyPkString, paramUpdaterPub,
		lib.moneyPrivString, 6*types.NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, lib.moneyPkString, m0Pub,
		lib.moneyPrivString, 6*types.NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, lib.moneyPkString, m1Pub,
		lib.moneyPrivString, 6*types.NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, lib.moneyPkString, m2Pub,
		lib.moneyPrivString, 6*types.NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	// Create a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

	// Swapping identities with a key that is not paramUpdater should fail.
	_, _, _, err := _swapIdentity(
		t, chain, db, params, feeRateNanosPerKB,
		m0Pub,
		m0Priv,
		m1PkBytes, m2PkBytes)
	require.Error(err)
	require.Contains(err.Error(), types.RuleErrorSwapIdentityIsParamUpdaterOnly)

	// Swapping identities with a key that is not paramUpdater should fail.
	// - Case where the transactor is the from public key
	_, _, _, err = _swapIdentity(
		t, chain, db, params, feeRateNanosPerKB,
		m0Pub,
		m0Priv,
		m0PkBytes, m2PkBytes)
	require.Error(err)
	require.Contains(err.Error(), types.RuleErrorSwapIdentityIsParamUpdaterOnly)

	// Swapping identities with a key that is not paramUpdater should fail.
	// - Case where the transactor is the to public key
	_, _, _, err = _swapIdentity(
		t, chain, db, params, feeRateNanosPerKB,
		m0Pub,
		m0Priv,
		m2PkBytes, m0PkBytes)
	require.Error(err)
	require.Contains(err.Error(), types.RuleErrorSwapIdentityIsParamUpdaterOnly)
}

func TestSwapIdentityMain(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0 so we can check creator coin balances easily.
		{
			TxnType:                      network.TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Swap m1 and m2, which don't have profiles yet. This should work.
		{
			TxnType:       network.TxnTypeSwapIdentity,
			FromPublicKey: m1PkBytes,
			ToPublicKey:   m2PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m0Pub,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      0,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             0,
			m5HasPurchased:          false,
			m6CCBalance:             0,
			m6HasPurchased:          false,
			m0DeSoBalance:           5999999998, // m0 lost 2 nanos in fees when creating her profile
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           6000000000,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           6000000000,
			m6DeSoBalance:           6000000000,

			// Profiles should not exist for either of these keys
			ProfilesToCheckPublicKeysBase58Check: []string{m1Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"", ""},
		},
		// Create a profile for m3
		{
			TxnType:                      network.TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m3Pub,
			UpdaterPrivateKeyBase58Check: m3Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			ProfileUsername:              "m3",
			ProfileDescription:           "i am m3",
			ProfilePic:                   "m3 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      0,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             0,
			m5HasPurchased:          false,
			m6CCBalance:             0,
			m6HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999998,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           6000000000,
			m6DeSoBalance:           6000000000,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic"},
		},
		// Have m5 buy coins for m3
		{
			UpdaterPublicKeyBase58Check:  m5Pub,
			UpdaterPrivateKeyBase58Check: m5Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                network.CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             2708037578,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             8124112737,
			m5HasPurchased:          true,
			m6CCBalance:             0,
			m6HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999998,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876542,
			m6DeSoBalance:           6000000000,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic"},
		},
		// Swap m2 and m3. Everything should stay the same except m2 should be the
		// creator everyone owns a piece of
		{
			TxnType:       network.TxnTypeSwapIdentity,
			FromPublicKey: m2PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m2Pub,

			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             2708037578, // The CC balance moves from m3 to m2
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             8124112737,
			m5HasPurchased:          true,
			m6CCBalance:             0,
			m6HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999998,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876542,
			m6DeSoBalance:           6000000000,

			// Profile check. Note m2 is the public key that owns the profile now.
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m2Pub, m3Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", ""},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", ""},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", ""},
		},
		// Create a profile for m3 again. This should work, since m3 lost its
		// profile to m2 easrlier
		{
			TxnType:                      network.TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m3Pub,
			UpdaterPrivateKeyBase58Check: m3Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			ProfileUsername:              "the_real_m3",
			ProfileDescription:           "i am the real m3",
			ProfilePic:                   "the real m3 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			// The CC balances are zero because we're checking against m3
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      0,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             0,
			m5HasPurchased:          false,
			m6CCBalance:             0,
			m6HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876542,
			m6DeSoBalance:           6000000000,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m2Pub, m3Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic"},
		},
		// Have m6 buy some coins in m3
		{
			UpdaterPublicKeyBase58Check:  m6Pub,
			UpdaterPrivateKeyBase58Check: m6Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                network.CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2000000001,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// The CC balances are zero because we're checking against m3
			CoinsInCirculationNanos: 12598787739,
			DeSoLockedNanos:         1999800000,
			CoinWatermarkNanos:      12598787739,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             3149696934, // m3 has some of its own coins as a founder reward
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             0,
			m5HasPurchased:          false,
			m6CCBalance:             9449090805, // m6 now owns some m3
			m6HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876542,
			m6DeSoBalance:           3999999997,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m2Pub, m3Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic"},
		},
		// Have m6 buy a tiny amount of m2.
		// This should fail the AutoSellThreshold test if you set it to 2 DeSoToSellNanos
		{
			UpdaterPublicKeyBase58Check:  m6Pub,
			UpdaterPrivateKeyBase58Check: m6Priv,
			ProfilePublicKeyBase58Check:  m2Pub,
			OperationType:                network.CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              10,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			CoinsInCirculationNanos: 10832150340,
			DeSoLockedNanos:         1270996352,
			CoinWatermarkNanos:      10832150340,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             2708037584, // The CC balance moves from m3 to m2
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             8124112737,
			m5HasPurchased:          true,
			m6CCBalance:             19,
			m6HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876542,
			m6DeSoBalance:           3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m2Pub, m3Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic"},
		},
		// Swap m2 and m3 again.
		{
			TxnType:       network.TxnTypeSwapIdentity,
			FromPublicKey: m2PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m2Pub,

			CoinsInCirculationNanos: 12598787739,
			DeSoLockedNanos:         1999800000,
			CoinWatermarkNanos:      12598787739,
			// This was previously the m3 cap table, but now it's the m2 cap table.
			m0CCBalance:    0,
			m0HasPurchased: false,
			m1CCBalance:    0,
			m1HasPurchased: false,
			m2CCBalance:    3149696934,
			m2HasPurchased: false,
			m3CCBalance:    0,
			m3HasPurchased: false,
			m4CCBalance:    0,
			m4HasPurchased: false,
			m5CCBalance:    0,
			m5HasPurchased: false,
			m6CCBalance:    9449090805, // m6 now owns some m2
			m6HasPurchased: true,
			m0DeSoBalance:  5999999998,
			m1DeSoBalance:  6000000000,
			m2DeSoBalance:  6000000000,
			m3DeSoBalance:  5999999996,
			m4DeSoBalance:  6000000000,
			m5DeSoBalance:  4728876542,
			m6DeSoBalance:  3999999985,

			// Profile check. Note m2 is the public key that owns the profile now.
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic"},
		},
		// Have m5 buy a small amount of m3 and check the cap table
		// If you set the DeSoToSellNanos to 2, this will also fail the autosell threshold.
		{
			UpdaterPublicKeyBase58Check:  m5Pub,
			UpdaterPrivateKeyBase58Check: m5Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                network.CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              10,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			CoinsInCirculationNanos: 10832150365,
			DeSoLockedNanos:         1270996361,
			CoinWatermarkNanos:      10832150365,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0, // The CC balance moves from m3 to m2
			m2HasPurchased:          false,
			m3CCBalance:             2708037590,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             8124112756,
			m5HasPurchased:          true,
			m6CCBalance:             19,
			m6HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876530,
			m6DeSoBalance:           3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic"},
		},
		// Swap m3 for m4 and check the m4 cap table. It should be identical to
		// the m3 cap table from before.
		{
			TxnType:       network.TxnTypeSwapIdentity,
			FromPublicKey: m3PkBytes,
			ToPublicKey:   m4PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m4Pub,

			CoinsInCirculationNanos: 10832150365,
			DeSoLockedNanos:         1270996361,
			CoinWatermarkNanos:      10832150365,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             2708037590, // The m3 balance has moved to m4 now
			m4HasPurchased:          false,
			m5CCBalance:             8124112756,
			m5HasPurchased:          true,
			m6CCBalance:             19,
			m6HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876530,
			m6DeSoBalance:           3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m4Pub, m2Pub, m3Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3", ""},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3", ""},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic", ""},
		},
		// Swap m2 for m3 and check the m3 cap table. It should be identical to
		// the m2 cap table from before.
		{
			TxnType:       network.TxnTypeSwapIdentity,
			FromPublicKey: m2PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m3Pub,

			CoinsInCirculationNanos: 12598787739,
			DeSoLockedNanos:         1999800000,
			CoinWatermarkNanos:      12598787739,
			// This was previously the m2 cap table, but now it's the m3 cap table.
			m0CCBalance:    0,
			m0HasPurchased: false,
			m1CCBalance:    0,
			m1HasPurchased: false,
			m2CCBalance:    0,
			m2HasPurchased: false,
			m3CCBalance:    3149696934,
			m3HasPurchased: false,
			m4CCBalance:    0,
			m4HasPurchased: false,
			m5CCBalance:    0,
			m6CCBalance:    9449090805,
			m6HasPurchased: true,
			m0DeSoBalance:  5999999998,
			m1DeSoBalance:  6000000000,
			m2DeSoBalance:  6000000000,
			m3DeSoBalance:  5999999996,
			m4DeSoBalance:  6000000000,
			m5DeSoBalance:  4728876530,
			m6DeSoBalance:  3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m4Pub, m3Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3", ""},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3", ""},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic", ""},
		},
		// Swap m4 and m3 and check the m4 cap table. It should be identical to the above.
		{
			TxnType:                     network.TxnTypeSwapIdentity,
			FromPublicKey:               m3PkBytes,
			ToPublicKey:                 m4PkBytes,
			ProfilePublicKeyBase58Check: m4Pub,

			CoinsInCirculationNanos: 12598787739,
			DeSoLockedNanos:         1999800000,
			CoinWatermarkNanos:      12598787739,
			// This was previously the m2 cap table, but now it's the m3 cap table.
			m0CCBalance:    0,
			m0HasPurchased: false,
			m1CCBalance:    0,
			m1HasPurchased: false,
			m2CCBalance:    0,
			m2HasPurchased: false,
			m3CCBalance:    0,
			m3HasPurchased: false,
			m4CCBalance:    3149696934,
			m4HasPurchased: false,
			m5CCBalance:    0,
			m5HasPurchased: false,
			m6CCBalance:    9449090805,
			m6HasPurchased: true,
			m0DeSoBalance:  5999999998,
			m1DeSoBalance:  6000000000,
			m2DeSoBalance:  6000000000,
			m3DeSoBalance:  5999999996,
			m4DeSoBalance:  6000000000,
			m5DeSoBalance:  4728876530,
			m6DeSoBalance:  3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub, m4Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3", ""},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3", ""},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic", ""},
		},
		// Do a small m3 buy and check that the cap table lines up.
		{
			UpdaterPublicKeyBase58Check:  m5Pub,
			UpdaterPrivateKeyBase58Check: m5Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                network.CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              10,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			CoinsInCirculationNanos: 10832150390,
			DeSoLockedNanos:         1270996370,
			CoinWatermarkNanos:      10832150390,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             2708037596,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             8124112775,
			m5HasPurchased:          true,
			m6CCBalance:             19,
			m6HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876518,
			m6DeSoBalance:           3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub, m4Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3", ""},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3", ""},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic", ""},
		},
		// Create a profile for m2
		{
			TxnType:                      network.TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m2Pub,
			ProfileUsername:              "the_new_m2",
			ProfileDescription:           "i am the new m2",
			ProfilePic:                   "the new m2 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			// The CC balances are zero because we're checking against m3
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      0,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             0,
			m5HasPurchased:          false,
			m6CCBalance:             0,
			m6HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           5999999998,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876518,
			m6DeSoBalance:           3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub, m4Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3", "the_new_m2"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3", "i am the new m2"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic", "the new m2 profile pic"},
		},
		// Swap m2 and m4 and verify that m4 now has the zeros
		{
			TxnType:                     network.TxnTypeSwapIdentity,
			FromPublicKey:               m2PkBytes,
			ToPublicKey:                 m4PkBytes,
			ProfilePublicKeyBase58Check: m4Pub,

			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      0,
			// This was previously the m2 cap table, but now it's the m3 cap table.
			m0CCBalance:    0,
			m0HasPurchased: false,
			m1CCBalance:    0,
			m1HasPurchased: false,
			m2CCBalance:    0,
			m2HasPurchased: false,
			m3CCBalance:    0,
			m3HasPurchased: false,
			m4CCBalance:    0,
			m4HasPurchased: false,
			m5CCBalance:    0,
			m5HasPurchased: false,
			m6CCBalance:    0,
			m6HasPurchased: false,
			m0DeSoBalance:  5999999998,
			m1DeSoBalance:  6000000000,
			m2DeSoBalance:  5999999998,
			m3DeSoBalance:  5999999996,
			m4DeSoBalance:  6000000000,
			m5DeSoBalance:  4728876518,
			m6DeSoBalance:  3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub, m2Pub, m4Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3", "the_new_m2"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3", "i am the new m2"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic", "the new m2 profile pic"},
		},
		// Do a small m2 buy and make sure that the m4 cap table is what we have
		// Setting DeSoToSellNanos to zero will cause an RuleErrorCreatorCoinBuyMustSatisfyAutoSellThresholdNanos
		// rule exception.
		{
			UpdaterPublicKeyBase58Check:  m5Pub,
			UpdaterPrivateKeyBase58Check: m5Priv,
			ProfilePublicKeyBase58Check:  m2Pub,
			OperationType:                network.CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              10,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			CoinsInCirculationNanos: 12598787757,
			DeSoLockedNanos:         1999800009,
			CoinWatermarkNanos:      12598787757,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             3149696938,
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             14,
			m5HasPurchased:          true,
			m6CCBalance:             9449090805,
			m6HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           5999999998,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876506,
			m6DeSoBalance:           3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub, m2Pub, m4Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3", "the_new_m2"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3", "i am the new m2"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic", "the new m2 profile pic"},
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestSwapIdentityWithFollows(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m1
		{
			TxnType:                      network.TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m1Pub,
			ProfileUsername:              "m1",
			ProfileDescription:           "i am m1",
			ProfilePic:                   "m1 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m0 follow m1
		{
			TxnType:                      network.TxnTypeFollow,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			FollowedPublicKey:            m1PkBytes,
			IsUnfollow:                   false,
			ProfilePublicKeyBase58Check:  m1Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m1Pub, m0Pub},
			ProfilesToCheckUsernames:             []string{"m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", ""},

			// These are our follow checks
			FollowPublicKeysToCheck: []string{m0Pub, m1Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{m1Pub: true},
				{},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{},
				{m0Pub: true},
			},
		},
		// Swap m0 and m1
		{
			TxnType:                     network.TxnTypeSwapIdentity,
			FromPublicKey:               m0PkBytes,
			ToPublicKey:                 m1PkBytes,
			ProfilePublicKeyBase58Check: m0Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m1Pub},
			ProfilesToCheckUsernames:             []string{"m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", ""},

			// Follow checks
			// The whole thing should be reversed now. Instead of m1 following
			// m0, it should be m0 following m1.
			FollowPublicKeysToCheck: []string{m0Pub, m1Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{},
				{m0Pub: true},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{m1Pub: true},
				{},
			},
		},
		// Swap m1 and m2. m2 should now be the one following m0
		{
			TxnType:                     network.TxnTypeSwapIdentity,
			FromPublicKey:               m1PkBytes,
			ToPublicKey:                 m2PkBytes,
			ProfilePublicKeyBase58Check: m0Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m1Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m1", "", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", "", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", "", ""},

			// Follow checks
			// The whole thing should be reversed now. Instead of m1 following
			// m0, it should be m0 following m1.
			FollowPublicKeysToCheck: []string{m0Pub, m1Pub, m2Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{},
				{},
				{m0Pub: true},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{m2Pub: true},
				{},
				{},
			},
		},
		// Give m1 a new profile
		{
			TxnType:                      network.TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m1Pub,
			ProfileUsername:              "new_m1",
			ProfileDescription:           "i am new m1",
			ProfilePic:                   "new m1 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m1Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m1", "new_m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", "i am new m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", "new m1 profile pic", ""},
		},
		// Have m2 follow m1
		{
			TxnType:                      network.TxnTypeFollow,
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			FollowedPublicKey:            m1PkBytes,
			IsUnfollow:                   false,
			ProfilePublicKeyBase58Check:  m1Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m1Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m1", "new_m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", "i am new m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", "new m1 profile pic", ""},

			// Follow checks
			// The whole thing should be reversed now. Instead of m1 following
			// m0, it should be m0 following m1.
			FollowPublicKeysToCheck: []string{m0Pub, m1Pub, m2Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{},
				{},
				{m0Pub: true, m1Pub: true},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{m2Pub: true},
				{m2Pub: true},
				{},
			},
		},
		// Have m0 follow m1
		{
			TxnType:                      network.TxnTypeFollow,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			FollowedPublicKey:            m1PkBytes,
			IsUnfollow:                   false,
			ProfilePublicKeyBase58Check:  m1Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m1Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m1", "new_m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", "i am new m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", "new m1 profile pic", ""},

			// Follow checks
			// The whole thing should be reversed now. Instead of m1 following
			// m0, it should be m0 following m1.
			FollowPublicKeysToCheck: []string{m0Pub, m1Pub, m2Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{m1Pub: true},
				{},
				{m0Pub: true, m1Pub: true},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{m2Pub: true},
				{m2Pub: true, m0Pub: true},
				{},
			},
		},
		// Have m1 follow m0
		{
			TxnType:                      network.TxnTypeFollow,
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			FollowedPublicKey:            m0PkBytes,
			IsUnfollow:                   false,
			ProfilePublicKeyBase58Check:  m1Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m1Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m1", "new_m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", "i am new m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", "new m1 profile pic", ""},

			// Follow checks
			// The whole thing should be reversed now. Instead of m1 following
			// m0, it should be m0 following m1.
			FollowPublicKeysToCheck: []string{m0Pub, m1Pub, m2Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{m1Pub: true},
				{m0Pub: true},
				{m0Pub: true, m1Pub: true},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{m2Pub: true, m1Pub: true},
				{m2Pub: true, m0Pub: true},
				{},
			},
		},
		// Swap m1 and m2. m2 should now inherit m1's follows
		// This is a tricky one...
		{
			TxnType:                     network.TxnTypeSwapIdentity,
			FromPublicKey:               m1PkBytes,
			ToPublicKey:                 m2PkBytes,
			ProfilePublicKeyBase58Check: m0Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m2Pub, m1Pub},
			ProfilesToCheckUsernames:             []string{"m1", "new_m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", "i am new m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", "new m1 profile pic", ""},

			// Follow checks
			// The whole thing should be reversed now. Instead of m1 following
			// m0, it should be m0 following m1.
			FollowPublicKeysToCheck: []string{m0Pub, m1Pub, m2Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{m2Pub: true},
				{m0Pub: true, m2Pub: true},
				{m0Pub: true},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{m1Pub: true, m2Pub: true},
				{},
				{m1Pub: true, m0Pub: true},
			},
		},
		// Swap m2 and m0.
		{
			TxnType:                     network.TxnTypeSwapIdentity,
			FromPublicKey:               m2PkBytes,
			ToPublicKey:                 m0PkBytes,
			ProfilePublicKeyBase58Check: m0Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m2Pub, m0Pub, m1Pub},
			ProfilesToCheckUsernames:             []string{"m1", "new_m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", "i am new m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", "new m1 profile pic", ""},

			// Follow checks
			// The whole thing should be reversed now. Instead of m1 following
			// m0, it should be m0 following m1.
			FollowPublicKeysToCheck: []string{m2Pub, m1Pub, m0Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{m0Pub: true},
				{m2Pub: true, m0Pub: true},
				{m2Pub: true},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{m1Pub: true, m0Pub: true},
				{},
				{m1Pub: true, m2Pub: true},
			},
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}
