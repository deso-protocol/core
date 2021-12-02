package lib

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCreatorCoinTransferSimple_CreatorCoinFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
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
			OperationType:                CreatorCoinOperationTypeBuy,
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
		// Have m1 transfer some creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   1000000,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8123112737,
			m1HasPurchased:          true,
			m2CCBalance:             1000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 transfer some more creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   20000000,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8103112737,
			m1HasPurchased:          true,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876538,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 transfer some more creator coins to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   8000000000,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10708037578,
			m0HasPurchased:          false,
			m1CCBalance:             103112737,
			m1HasPurchased:          true,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876536,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 transfer the rest of her creator coins to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   103112737,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10811150315,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 transfer all coins back to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   10811150315,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             10832150315,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999996,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 transfer all coins back to m1. Weeeeee!!!
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m1Pub,
			CreatorCoinToTransferNanos:   10832150315,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             10832150315,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999996,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           5999999998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false /*desoFounderReward*/)
}

func TestCreatorCoinTransferSimple_DeSoFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// [0] Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
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
		// [1] Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0, // Founder reward is given in DeSo here.
			m0HasPurchased:          false,
			m1CCBalance:             9841661798,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// [2] Have m1 transfer some creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   1000000,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9840661798,
			m1HasPurchased:          true,
			m2CCBalance:             1000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           6000000000,
		},
		// [3] Have m1 transfer some more creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   20000000,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9820661798,
			m1HasPurchased:          true,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876538,
			m2DeSoBalance:           6000000000,
		},
		// [4] Have m1 transfer some more creator coins to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   8000000000,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             8000000000,
			m0HasPurchased:          false,
			m1CCBalance:             1820661798,
			m1HasPurchased:          true,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876536,
			m2DeSoBalance:           6000000000,
		},
		// [5] Have m1 transfer the rest of her creator coins to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   1820661798,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             9820661798,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           6000000000,
		},
		// [6] Have m0 transfer all coins back to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   9820661798,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             9841661798,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749081,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           6000000000,
		},
		// [7] Have m2 transfer all coins back to m1. Weeeeee!!!
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m1Pub,
			CreatorCoinToTransferNanos:   9841661798,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9841661798,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749081,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           5999999998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, true /*desoFounderReward*/)
}

func TestCreatorCoinTransferWithSwapIdentity(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
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
			OperationType:                CreatorCoinOperationTypeBuy,
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
			OperationType:                CreatorCoinOperationTypeBuy,
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
		// Have m1 transfer 1e9 creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   1000000000,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             7124112737,
			m1HasPurchased:          true,
			m2CCBalance:             2977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           4827626815,
		},
		// Swap m0 and m3
		{
			TxnType:       TxnTypeSwapIdentity,
			FromPublicKey: m0PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m3Pub,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             7124112737,
			m1HasPurchased:          true,
			m2CCBalance:             2977342329,
			m2HasPurchased:          true,
			m3CCBalance:             3367151687,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           4827626815,
		},
		// Have m2 transfer 2e9 creator coins (now attached to m3Pub's profile) to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   2000000000,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             2000000000,
			m0HasPurchased:          false,
			m1CCBalance:             7124112737,
			m1HasPurchased:          true,
			m2CCBalance:             977342329,
			m2HasPurchased:          true,
			m3CCBalance:             3367151687,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           4827626813,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinTransferWithSmallBalancesLeftOver(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
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
			OperationType:                CreatorCoinOperationTypeBuy,
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
		// Have m1 all but one nano of their creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   8124112736,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             8124112737,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 transfer all but the min threshold back to m1 (threshold assumed to be 10 nanos).
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m1Pub,
			CreatorCoinToTransferNanos:   8124112727,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112727,
			m1HasPurchased:          false,
			m2CCBalance:             10,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           5999999998,
		},
		// Have m2 transfer their remaining 10 nanos back to m1.
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m1Pub,
			CreatorCoinToTransferNanos:   10,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           5999999996,
		},
		// Have m1 transfer all but 5 nanos back to m0.
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   8124112732,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10832150315,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876538,
			m2DeSoBalance:           5999999996,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinTransferWithMaxTransfers(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
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
			OperationType:                CreatorCoinOperationTypeBuy,
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
		// Have m1 send all of their creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   8124112737,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             8124112737,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 buy some more of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13647653882,
			DeSoLockedNanos:         2541992686,
			CoinWatermarkNanos:      13647653882,
			m0CCBalance:             3411913469,
			m0HasPurchased:          false,
			m1CCBalance:             2111627676,
			m1HasPurchased:          true,
			m2CCBalance:             8124112737,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           3457753082,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 transfer all their m0 coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   2111627676,

			// These are the expectations
			CoinsInCirculationNanos: 13647653882,
			DeSoLockedNanos:         2541992686,
			CoinWatermarkNanos:      13647653882,
			m0CCBalance:             3411913469,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             10235740413,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           3457753080,
			m2DeSoBalance:           5999999998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinTransferBelowMinThreshold(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	// Set up a blockchain
	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	feeRateNanosPerKB := uint64(11)
	_, _ = mempool, miner

	// Send money to people from moneyPk
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m0Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m1Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m2Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m3Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m4Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m5Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m6Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	_, _, _, err := _updateProfile(
		t, chain, db, params,
		feeRateNanosPerKB /*feerate*/, m0Pub, m0Priv, m0PkBytes, "m0",
		"i am m0", "m0 profile pic", 2500, /*CreatorBasisPoints*/
		12500 /*stakeMultipleBasisPoints*/, false /*isHidden*/)
	require.NoError(err)

	// m1 buys some m0 creator coin.
	_, _, _, err = _creatorCoinTxn(
		t, chain, db, params, feeRateNanosPerKB,
		m1Pub, m1Priv,
		m0Pub,                       /*profile*/
		CreatorCoinOperationTypeBuy, /*buy/sell*/
		1000000000,                  /*DeSoToSellNanos*/
		0,                           /*CreatorCoinToSellNanos*/
		0,                           /*DeSoToAddNanos*/
		0,                           /*MinDeSoExpectedNanos*/
		0 /*MinCreatorCoinExpectedNanos*/)
	require.NoError(err)

	_, _, _, err = _doCreatorCoinTransferTxn(
		t, chain, db, params, feeRateNanosPerKB,
		m1Pub, m1Priv, m0Pub, m2Pub,
		mempool.bc.params.CreatorCoinAutoSellThresholdNanos-1)
	require.Contains(err.Error(), RuleErrorCreatorCoinTransferMustBeGreaterThanMinThreshold)
}
