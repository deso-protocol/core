package lib

import (
	"bytes"
	"github.com/dgraph-io/badger/v3"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestDAOCoinLimitOrder(t *testing.T) {
	// -----------------------
	// Initialization
	// -----------------------

	// Test constants
	const feeRateNanosPerKb = uint64(10)

	// Initialize test chain and miner.
	require := require.New(t)
	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true)

	params.ForkHeights.DAOCoinBlockHeight = uint32(0)
	params.ForkHeights.DAOCoinLimitOrderBlockHeight = uint32(0)

	// Supports both BadgerDB and Postgres testing.
	dbAdapter := DbAdapter{
		badgerDb:   db,
		postgresDb: chain.postgres,
	}

	// Mine a few blocks to give the senderPkString some money.
	_, err := miner.MineAndProcessSingleBlock(0, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0, mempool)
	require.NoError(err)

	// We take the block tip to be the blockchain height rather than the header chain height.
	savedHeight := chain.blockTip().Height + 1

	// We build the testMeta obj after mining blocks so that we save the correct block height.
	testMeta := &TestMeta{
		t:           t,
		chain:       chain,
		params:      params,
		db:          db,
		mempool:     mempool,
		miner:       miner,
		savedHeight: savedHeight,
	}

	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 7000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 4000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 140)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 210)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 100)

	m0PKID := DBGetPKIDEntryForPublicKey(db, m0PkBytes)
	m1PKID := DBGetPKIDEntryForPublicKey(db, m1PkBytes)
	m2PKID := DBGetPKIDEntryForPublicKey(db, m2PkBytes)
	m4PKID := DBGetPKIDEntryForPublicKey(db, m4PkBytes)
	_, _, _, _ = m0PKID, m1PKID, m2PKID, m4PKID // TODO: delete

	// -----------------------
	// Helpers
	// -----------------------

	// Helper function to convert PublicKeys to PKIDs without initializing a new UTXOView.
	toPKID := func(inputPK *PublicKey) *PKID {
		if bytes.Equal(inputPK.ToBytes(), ZeroPublicKey.ToBytes()) {
			return &ZeroPKID
		}

		if bytes.Equal(inputPK.ToBytes(), m0PkBytes) {
			return m0PKID.PKID
		}

		if bytes.Equal(inputPK.ToBytes(), m1PkBytes) {
			return m1PKID.PKID
		}

		return nil
	}

	// -----------------------
	// Tests
	// -----------------------

	// Store how many $DESO and DAO coin units will be transferred.
	daoCoinQuantityChange := uint256.NewInt().SetUint64(100)
	desoQuantityChange := uint256.NewInt().SetUint64(10)

	// Construct metadata for a m0 limit order:
	//   * Buying: 	 DAO coin
	//   * Selling:  $DESO
	//   * Price: 	 0.1 $DESO / DAO coin
	//   * Quantity: 100 DAO coins
	metadataM0 := DAOCoinLimitOrderMetadata{
		BuyingDAOCoinCreatorPublicKey:             NewPublicKey(m0PkBytes),
		SellingDAOCoinCreatorPublicKey:            &ZeroPublicKey,
		ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(0.1),
		QuantityToBuyInBaseUnits:                  daoCoinQuantityChange,
	}

	// RuleErrorDAOCoinLimitOrderCannotBuyAndSellSameCoin
	{
		originalValue := metadataM0.BuyingDAOCoinCreatorPublicKey
		metadataM0.BuyingDAOCoinCreatorPublicKey = metadataM0.SellingDAOCoinCreatorPublicKey

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderCannotBuyAndSellSameCoin)
		metadataM0.BuyingDAOCoinCreatorPublicKey = originalValue
	}

	// RuleErrorDAOCoinLimitOrderBuyingDAOCoinCreatorMissingProfile
	{
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderBuyingDAOCoinCreatorMissingProfile)
	}

	// Create a profile for m0.
	{
		_updateProfileWithTestMeta(
			testMeta,
			feeRateNanosPerKb, /*feeRateNanosPerKB*/
			m0Pub,             /*updaterPkBase58Check*/
			m0Priv,            /*updaterPrivBase58Check*/
			[]byte{},          /*profilePubKey*/
			"m0",              /*newUsername*/
			"i am the m0",     /*newDescription*/
			shortPic,          /*newProfilePic*/
			10*100,            /*newCreatorBasisPoints*/
			1.25*100*100,      /*newStakeMultipleBasisPoints*/
			false,             /*isHidden*/
		)
	}

	// RuleErrorDAOCoinLimitOrderInvalidExchangeRate: zero
	{
		originalValue := metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = uint256.NewInt()

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInvalidExchangeRate)
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = originalValue
	}

	// RuleErrorDAOCoinLimitOrderInvalidQuantity: zero
	{
		originalValue := metadataM0.QuantityToBuyInBaseUnits
		metadataM0.QuantityToBuyInBaseUnits = uint256.NewInt()

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInvalidQuantity)
		metadataM0.QuantityToBuyInBaseUnits = originalValue
	}

	// RuleErrorDAOCoinLimitOrderTotalCostOverflowsUint256
	{
		originalPrice := metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy
		originalQuantity := metadataM0.QuantityToBuyInBaseUnits
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = MaxUint256.Clone()
		metadataM0.QuantityToBuyInBaseUnits = MaxUint256.Clone()

		// Perform txn.
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderTotalCostOverflowsUint256)

		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = originalPrice
		metadataM0.QuantityToBuyInBaseUnits = originalQuantity
	}

	// RuleErrorDAOCoinLimitOrderTotalCostOverflowsUint64
	{
		originalPrice := metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy
		originalQuantity := metadataM0.QuantityToBuyInBaseUnits
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = uint256.NewInt().SetUint64(math.MaxUint64)
		metadataM0.QuantityToBuyInBaseUnits = uint256.NewInt().SetUint64(math.MaxUint64)

		// Perform txn.
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderTotalCostIsLessThanOneNano)

		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = originalPrice
		metadataM0.QuantityToBuyInBaseUnits = originalQuantity
	}

	// RuleErrorDAOCoinLimitOrderTotalCostIsLessThanOneNano
	{
		originalPrice := metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy
		originalQuantity := metadataM0.QuantityToBuyInBaseUnits
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = uint256.NewInt().SetUint64(1)
		metadataM0.QuantityToBuyInBaseUnits = uint256.NewInt().SetUint64(1)

		// Perform txn.
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderTotalCostIsLessThanOneNano)

		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = originalPrice
		metadataM0.QuantityToBuyInBaseUnits = originalQuantity
	}

	// RuleErrorDAOCoinLimitOrderInsufficientDAOCoinsToOpenOrder
	{
		originalPrice := metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy
		originalQuantity := metadataM0.QuantityToBuyInBaseUnits
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(1.0)
		metadataM0.QuantityToBuyInBaseUnits = uint256.NewInt().SetUint64(math.MaxUint64)

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInsufficientDAOCoinsToOpenOrder)
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = originalPrice
		metadataM0.QuantityToBuyInBaseUnits = originalQuantity
	}

	// m0 submits limit order buying 100 DAO coin units @ 0.1 $DESO / DAO coin.
	// Happy path: update quantity and resubmit. m0's order should be stored.
	{
		// Confirm no existing limit orders.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Empty(orderEntries)

		// Perform txn.
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		// Confirm 1 existing limit order, and it's from m0.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight, toPKID)))
	}

	// Test db_adapter.GetAllDAOCoinLimitOrdersForThisDAOCoinPair()
	{
		// Confirm 1 existing limit order, and it's from m0.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(
			toPKID(metadataM0.BuyingDAOCoinCreatorPublicKey),
			toPKID(metadataM0.SellingDAOCoinCreatorPublicKey))

		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight, toPKID)))
	}

	// Test db_adapter.GetAllDAOCoinLimitOrdersForThisTransactor()
	{
		// Confirm 1 existing limit order, and it's from m0.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrdersForThisTransactor(m0PKID.PKID)
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight, toPKID)))
	}

	// Test db_adapter.GetAllDAOCoinLimitOrdersForThisTransactorAtThisPrice()
	{
		// Confirm 1 existing limit order, and it's from m0.
		// Note that the blockHeight param is ignored.
		orderEntry := metadataM0.ToEntry(m0PKID.PKID, 0, toPKID)
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrdersForThisTransactorAtThisPrice(orderEntry)
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(orderEntry))
	}

	// Construct metadata for a m1 limit order:
	//   * Buying: 	 $DESO
	//   * Selling:  DAO coins
	//   * Price: 	 10 DAO coins / $DESO
	//   * Quantity: 10 $DESO
	metadataM1 := DAOCoinLimitOrderMetadata{
		BuyingDAOCoinCreatorPublicKey:             metadataM0.SellingDAOCoinCreatorPublicKey,
		SellingDAOCoinCreatorPublicKey:            metadataM0.BuyingDAOCoinCreatorPublicKey,
		ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(10.0),
		QuantityToBuyInBaseUnits:                  desoQuantityChange,
	}

	// RuleErrorDAOCoinLimitOrderInsufficientDAOCoinsToOpenOrder
	{
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM1)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInsufficientDAOCoinsToOpenOrder)
	}

	// Mint DAO coins and transfer to m1.
	{
		daoCoinMintMetadata := DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeMint,
			CoinsToMintNanos: *uint256.NewInt().SetUint64(1e4),
		}

		_daoCoinTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, daoCoinMintMetadata)

		daoCoinTransferMetadata := DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(3000),
			ReceiverPublicKey:      m1PkBytes,
		}

		_daoCoinTransferTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, daoCoinTransferMetadata)
	}

	// m1 submits limit order for 10 $DESO @ 10 DAO coin / $DESO.
	// Orders fulfilled for transferring 100 DAO coins <--> 10 $DESO.
	// Submit matching order and confirm matching happy path.
	{
		// Confirm 1 existing limit order, and it's from m0.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight, toPKID)))

		// Confirm 1 matching limit orders exists.
		orderEntryM1 := metadataM1.ToEntry(m1PKID.PKID, testMeta.savedHeight, toPKID)
		orderEntries, err = dbAdapter.GetMatchingDAOCoinLimitOrders(orderEntryM1, nil)

		require.NoError(err)
		require.Equal(len(orderEntries), 1)

		// Store original $DESO balances to check diffs.
		originalM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
		originalM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)

		// Store original DAO coin balances to check diffs.
		originalM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
		originalM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)

		// Perform txn.
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)

		// Both orders are deleted from the order book.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Empty(orderEntries)

		// Calculate updated $DESO balances.
		updatedM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
		updatedM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)

		// Calculate updated DAO coin balances.
		updatedM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
		updatedM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)

		// Calculate total cost of order to compare to changes in $DESO.
		totalOrderCost256, err := orderEntryM1.BaseUnitsToSellUint256()
		totalOrderCost := totalOrderCost256.Uint64()
		require.NoError(err)

		// m0's BID order is fulfilled so his DESO balance decreases and his DAO coin balance increases.
		require.Equal(
			originalM0DESOBalance-totalOrderCost,
			updatedM0DESOBalance)

		require.Equal(
			*uint256.NewInt().Add(&originalM0DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
			updatedM0DAOCoinBalance.BalanceNanos)

		// m1's ASK order is fulfilled so his DESO balance increases and his DAO coin balance decreases.
		require.Equal(
			originalM1DESOBalance+totalOrderCost-uint64(3), // TODO: calculate gas fee instead of hard-coding.
			updatedM1DESOBalance)

		require.Equal(
			*uint256.NewInt().Sub(&originalM1DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
			updatedM1DAOCoinBalance.BalanceNanos)
	}

	//// Scenario: partially fulfilled orders sorting by best price
	//// m1 submits ASK order for 200 DAO coin nanos @ 11 DAO coin / $DESO.
	//// m1 submits ASK order for 100 DAO coin nanos @ 12 DAO coin / $DESO.
	//// m1 submits ASK order for 100 DAO coin nanos @ 12 DAO coin / $DESO.
	//// Quantity is updated instead of creating a new limit order.
	//// m0 submits BID order for 300 DAO coin nanos @ 1/8 $DESO / DAO coin.
	//// m0's order is fully fulfilled.
	//// m1's orders are partially fulfilled for:
	////   * 200 DAO coin nanos @ 11 DAO coin / $DESO and
	////   * 100 DAO coin nano @ 12 DAO coin $DESO
	//{
	//	// Confirm no existing limit orders.
	//	orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Empty(orderEntries)
	//
	//	// m1 submits ASK order for 200 DAO coin nanos @ 11 DAO coin / $DESO.
	//	err = metadataM1.UpdatePrice(NewFloat().SetUint64(11))
	//	metadataM1.QuantityNanos = uint256.NewInt().SetUint64(200)
	//	require.NoError(err)
	//	invertedScaledPrice11, err := metadataM1.ToEntry(m1PKID.PKID, savedHeight).InvertedScaledPrice()
	//	require.NoError(err)
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)
	//
	//	// m1 submits ASK order for 100 DAO coin nanos @ 12 DAO coin / $DESO.
	//	err = metadataM1.UpdatePrice(NewFloat().SetUint64(12))
	//	metadataM1.QuantityNanos = uint256.NewInt().SetUint64(100)
	//	require.NoError(err)
	//	invertedScaledPrice12, err := metadataM1.ToEntry(m1PKID.PKID, savedHeight).InvertedScaledPrice()
	//	require.NoError(err)
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)
	//
	//	// Confirm 2 existing limit orders.
	//	orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 2)
	//	require.True(orderEntries[1].Eq(metadataM1.ToEntry(m1PKID.PKID, testMeta.savedHeight)))
	//
	//	// m1 submits ASK order for 100 DAO coin nano @ 12 DAO coin / $DESO.
	//	// Quantity is updated and only one order persists.
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)
	//
	//	// Confirm 2 existing limit order, second has updated quantity of 200.
	//	orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 2)
	//	metadataM1.QuantityNanos = uint256.NewInt().SetUint64(200)
	//	require.True(orderEntries[1].Eq(metadataM1.ToEntry(m1PKID.PKID, testMeta.savedHeight)))
	//
	//	// Store original $DESO balances to check diffs.
	//	originalM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
	//	originalM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)
	//
	//	// Store original DAO coin balances to check diffs.
	//	originalM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
	//	originalM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)
	//
	//	// Construct metadata for m0's BID order.
	//	err = metadataM0.UpdatePrice(NewFloat().SetFloat64(0.125)) // 1.0 / 8.0 = 0.125
	//	require.NoError(err)
	//	metadataM0.QuantityNanos = uint256.NewInt().SetUint64(300)
	//
	//	// Confirm matching limit orders exist.
	//	orderEntries, err = dbAdapter.GetMatchingDAOCoinLimitOrders(
	//		metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight), nil)
	//
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 2)
	//
	//	// m0 submits BID order for 300 DAO coin nanos @ 1/8 $DESO / DAO coin.
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)
	//
	//	// The correct orders are removed from the order book.
	//	// m0's BID order for 300 DAO coin nanos @ 1/8 $DESO / DAO coin is fulfilled.
	//	// m1's ASK order for 200 DAO coin nanos @ 12 DAO coin / $DESO is fulfilled.
	//	// m1's ASK order for 200 DAO coin nanos @ 11 DAO coin / $DESO is partially fulfilled w/ 100 DAO coin nanos remaining.
	//	orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 1)
	//	err = metadataM1.UpdatePrice(NewFloat().SetUint64(11))
	//	require.NoError(err)
	//	metadataM1.QuantityNanos = uint256.NewInt().SetUint64(100)
	//	require.True(orderEntries[0].Eq(metadataM1.ToEntry(m1PKID.PKID, testMeta.savedHeight)))
	//
	//	// Calculate updated $DESO balances.
	//	updatedM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
	//	updatedM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)
	//
	//	// Calculate updated DAO coin balances.
	//	updatedM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
	//	updatedM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)
	//
	//	// Orders partially fulfilled for:
	//	//   * 200 DAO coin nanos @ 12 DAO coin / $DESO
	//	//   * 100 DAO coin nanos @ 11 DAO coin / $DESO
	//	daoCoinQuantityNanosChange = uint256.NewInt().SetUint64(300)
	//
	//	// Calculate total cost of order to compare to changes in $DESO.
	//	// 200 DAO coin nanos @ 12 DAO coin / $DESO
	//	subOrderCost1, err := (&DAOCoinLimitOrderEntry{}).CostUint64(
	//		invertedScaledPrice12, uint256.NewInt().SetUint64(200))
	//
	//	require.NoError(err)
	//
	//	// 100 DAO coin nanos @ 11 DAO coin / $DESO
	//	subOrderCost2, err := (&DAOCoinLimitOrderEntry{}).CostUint64(
	//		invertedScaledPrice11, uint256.NewInt().SetUint64(100))
	//
	//	require.NoError(err)
	//	totalOrderCost := subOrderCost1 + subOrderCost2
	//
	//	// m0's BID order is fulfilled so his $DESO balance decreases and his DAO coin balance increases.
	//	// TODO: should be equal
	//	require.NotEqual(
	//		originalM0DESOBalance-totalOrderCost-uint64(2), // TODO: calculate gas fee instead of hard-coding.
	//		updatedM0DESOBalance)
	//
	//	require.Equal(
	//		*uint256.NewInt().Add(&originalM0DAOCoinBalance.BalanceNanos, daoCoinQuantityNanosChange),
	//		updatedM0DAOCoinBalance.BalanceNanos)
	//
	//	// m1's ASK orders are fulfilled so his $DESO balance increases and his DAO coin balance decreases.
	//	require.Equal(
	//		originalM1DESOBalance+totalOrderCost,
	//		updatedM1DESOBalance)
	//
	//	require.Equal(
	//		*uint256.NewInt().Sub(&originalM1DAOCoinBalance.BalanceNanos, daoCoinQuantityNanosChange),
	//		updatedM1DAOCoinBalance.BalanceNanos)
	//}
	//
	//// Scenario: cancel all of an open ASK order.
	//// m1 tries to cancel ASK order for 100 DAO coin nanos @ 12 DAO coins / $DESO. None exist.
	//// m1 cancels ASK order for 100 DAO coin nanos @ 11 DAO coins / $DESO.
	//{
	//	// Confirm 1 existing limit order from m1 for 100 DAO coin nanos @ 11 DAO coins / $DESO.
	//	err := metadataM1.UpdatePrice(NewFloat().SetUint64(11))
	//	require.NoError(err)
	//	orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 1)
	//	require.True(orderEntries[0].Eq(metadataM1.ToEntry(m1PKID.PKID, testMeta.savedHeight)))
	//
	//	// m1 tries to cancel ASK order for 100 DAO coin nanos @ 12 DAO coins / $DESO. None exist.
	//	err = metadataM1.UpdatePrice(NewFloat().SetUint64(12))
	//	require.NoError(err)
	//	metadataM1.CancelExistingOrder = true
	//
	//	_, _, _, err = _doDAOCoinLimitOrderTxn(
	//		t, chain, db, params, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)
	//
	//	require.Error(err)
	//	require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderToCancelNotFound)
	//
	//	// m1 cancels ASK order for 100 DAO coin nanos @ 11 DAO coins / $DESO.
	//	err = metadataM1.UpdatePrice(NewFloat().SetUint64(11))
	//	require.NoError(err)
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)
	//
	//	// Confirm no existing limit orders.
	//	orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Empty(orderEntries)
	//
	//	// Reset metadataM1.
	//	metadataM1.CancelExistingOrder = false
	//}
	//
	//// Scenario: submit and subsequently cancel part of open BID order.
	//// m0 submits BID order for 200 DAO coin nanos @ 0.1 $DESO / DAO coin.
	//// m0 cancels BID order for 100 DAO coin nanos @ 0.1 $DESO / DAO coin.
	//{
	//	// Confirm no existing limit orders.
	//	orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Empty(orderEntries)
	//
	//	// m0 submits BID order for 200 DAO coin nanos @ 0.1 $DESO / DAO coin.
	//	err = metadataM0.UpdatePrice(NewFloat().SetFloat64(0.1))
	//	require.NoError(err)
	//	metadataM0.QuantityNanos = uint256.NewInt().SetUint64(200)
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)
	//
	//	// Confirm 1 existing limit order from m0.
	//	orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 1)
	//	require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight)))
	//
	//	// m0 cancels BID order for 100 DAO coin nanos @ 0.1 $DESO / DAO coin.
	//	metadataM0.QuantityNanos = uint256.NewInt().SetUint64(100)
	//	metadataM0.CancelExistingOrder = true
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)
	//
	//	// Confirm 1 existing limit order from m0 with updated quantity of 100.
	//	orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 1)
	//	require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight)))
	//
	//	// Reset metadataM0.
	//	metadataM0.CancelExistingOrder = false
	//}
	//
	//// Scenario: m0 and m1 both submit open BID orders for the same price.
	//{
	//	// Confirm 1 existing limit order from m0.
	//	// BID order for 100 DAO coin nanos @ 0.1 $DESO / DAO coin
	//	orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 1)
	//	require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight)))
	//
	//	// m1 submits BID order for 200 DAO coins @ 0.1 $DESO / DAO coin.
	//	err = metadataM1.UpdatePrice(NewFloat().SetFloat64(0.1))
	//	require.NoError(err)
	//	metadataM1.QuantityNanos = uint256.NewInt().SetUint64(200)
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)
	//
	//	// Confirm 2 existing limit orders @ 0.1 $DESO / DAO coin.
	//	// 1 from m0 with quantity 100.
	//	// 1 from m1 with quantity 200.
	//	orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 2)
	//
	//	// m1's order is listed first bc his m1PKID < m0PKID and the key
	//	// is identicial for both of these orders other than the PKID.
	//	require.True(orderEntries[0].Eq(metadataM1.ToEntry(m1PKID.PKID, savedHeight)))
	//	require.True(orderEntries[1].Eq(metadataM0.ToEntry(m0PKID.PKID, savedHeight)))
	//}

	// TODO: add validation, no DAO coins in circulation for this profile
	// TODO: maybe test trying to buy more DAO coins than were minted.
	// TODO: partially fulfilled orders
	// TODO: two bid orders, different prices, choose high priced one
	// TODO: two ask orders, different prices, choose lower priced one
	// TODO: what if someone submits order that matches their own order? Probably fine. Just match them.
	// TODO: test disconnect logic

	//_rollBackTestMetaTxnsAndFlush(testMeta)
	//_applyTestMetaTxnsToMempool(testMeta)
	//_applyTestMetaTxnsToViewAndFlush(testMeta)
	//_disconnectTestMetaTxnsFromViewAndFlush(testMeta)

	if chain.postgres == nil {
		// TODO: this step currently only works with Badger.
		//_connectBlockThenDisconnectBlockAndFlush(testMeta)
	}
}

//
// ----- HELPERS
//

// No error expected.
func _doDAOCoinLimitOrderTxnWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	TransactorPublicKeyBase58Check string,
	TransactorPrivateKeyBase58Check string,
	metadata DAOCoinLimitOrderMetadata) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, TransactorPublicKeyBase58Check))

	currentOps, currentTxn, _, err := _doDAOCoinLimitOrderTxn(testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB, TransactorPublicKeyBase58Check, TransactorPrivateKeyBase58Check, metadata)

	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

// Error expected.
func _doDAOCoinLimitOrderTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	TransactorPublicKeyBase58Check string,
	TransactorPrivateKeyBase58Check string,
	metadata DAOCoinLimitOrderMetadata,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	require := require.New(t)

	updaterPkBytes, _, err := Base58CheckDecode(TransactorPublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, chain.postgres)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateDAOCoinLimitOrderTxn(
		updaterPkBytes,
		&metadata,
		feeRateNanosPerKB,
		nil,
		[]*DeSoOutput{})

	if err != nil {
		return nil, nil, 0, err
	}

	// There is some spend amount that may go to matching ASK orders.
	// That is why these are not always exactly equal.
	require.True(totalInputMake >= changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, TransactorPrivateKeyBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeDAOCoin operation at the end.
	// TODO: update utxo comparison logic to account for outputs to matching orders
	//require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	//for ii := 0; ii < len(txn.TxInputs); ii++ {
	//	require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	//}
	require.Equal(OperationTypeDAOCoinLimitOrder, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func CalculateScaledExchangeRate(price float64) *uint256.Int {
	scaledPriceInt, _ := Mul(NewFloat().SetFloat64(price), NewFloat().SetInt(OneUQ128x128.ToBig())).Int(nil)
	scaledPriceUint256, _ := uint256.FromBig(scaledPriceInt)
	return scaledPriceUint256
}

func (order *DAOCoinLimitOrderEntry) Eq(other *DAOCoinLimitOrderEntry) (bool, error) {
	// Convert both order entries to bytes and compare bytes.
	orderBytes, err := order.ToBytes()
	if err != nil {
		return false, err
	}

	otherBytes, err := other.ToBytes()
	if err != nil {
		return false, err
	}

	return bytes.Equal(orderBytes, otherBytes), nil
}

func (txnData *DAOCoinLimitOrderMetadata) ToEntry(
	transactorPKID *PKID, blockHeight uint32, toPKID func(*PublicKey) *PKID) *DAOCoinLimitOrderEntry {

	return &DAOCoinLimitOrderEntry{
		TransactorPKID:                            transactorPKID,
		BuyingDAOCoinCreatorPKID:                  toPKID(txnData.BuyingDAOCoinCreatorPublicKey),
		SellingDAOCoinCreatorPKID:                 toPKID(txnData.BuyingDAOCoinCreatorPublicKey),
		ScaledExchangeRateCoinsToSellPerCoinToBuy: txnData.ScaledExchangeRateCoinsToSellPerCoinToBuy,
		QuantityToBuyInBaseUnits:                  txnData.QuantityToBuyInBaseUnits,
		BlockHeight:                               blockHeight,
	}
}
