package lib

import (
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

	// Make m3 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true
	params.ForkHeights.DAOCoinBlockHeight = uint32(0)
	params.ForkHeights.DAOCoinLimitOrderBlockHeight = uint32(0)

	// Supports both BadgerDB and Postgres testing.
	dbAdapter := DbAdapter{
		badgerDb:   db,
		postgresDb: chain.postgres,
	}

	_ = dbAdapter // TODO: delete

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

	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 700)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 420)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 140)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 210)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 100)

	m0PKID := DBGetPKIDEntryForPublicKey(db, m0PkBytes)
	m1PKID := DBGetPKIDEntryForPublicKey(db, m1PkBytes)
	m2PKID := DBGetPKIDEntryForPublicKey(db, m2PkBytes)
	m4PKID := DBGetPKIDEntryForPublicKey(db, m4PkBytes)
	_, _, _ = m1PKID, m2PKID, m4PKID // TODO: delete

	// -----------------------
	// Tests
	// -----------------------

	// Construct metadata for a m0 limit order buying DAO coins
	// minted by m0 in exchange for $DESO.
	metadataM0 := DAOCoinLimitOrderMetadata{
		BuyingDAOCoinCreatorPKID:  m0PKID.PKID,
		SellingDAOCoinCreatorPKID: ZeroPKID.NewPKID(),
		PriceNanos:                uint256.NewInt().SetUint64(10),
		QuantityNanos:             uint256.NewInt().SetUint64(100),
	}

	// RuleErrorDAOCoinLimitOrderCannotBuyAndSellSameCoin
	{
		originalValue := metadataM0.BuyingDAOCoinCreatorPKID
		metadataM0.BuyingDAOCoinCreatorPKID = metadataM0.SellingDAOCoinCreatorPKID

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderCannotBuyAndSellSameCoin)
		metadataM0.BuyingDAOCoinCreatorPKID = originalValue
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

	// RuleErrorDAOCoinLimitOrderInvalidPrice: zero
	{
		originalValue := metadataM0.PriceNanos
		metadataM0.PriceNanos = uint256.NewInt()

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInvalidPrice)
		metadataM0.PriceNanos = originalValue
	}

	// RuleErrorDAOCoinLimitOrderInvalidQuantity: zero
	{
		originalValue := metadataM0.QuantityNanos
		metadataM0.QuantityNanos = uint256.NewInt().SetUint64(0)

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInvalidQuantity)
		metadataM0.QuantityNanos = originalValue
	}

	// RuleErrorDAOCoinLimitOrderInvalidTotalCost: uint256 overflow
	{
		originalPrice := metadataM0.PriceNanos
		originalQuantity := metadataM0.QuantityNanos
		metadataM0.PriceNanos = uint256.NewInt().SetUint64(2)
		metadataM0.QuantityNanos = MaxUint256.Clone()

		// Perform txn.
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInvalidTotalCost)

		metadataM0.PriceNanos = originalPrice
		metadataM0.QuantityNanos = originalQuantity
	}

	// RuleErrorDAOCoinLimitOrderInvalidTotalCost: non-uint64 value
	{
		originalPrice := metadataM0.PriceNanos
		originalQuantity := metadataM0.QuantityNanos

		metadataM0.PriceNanos = uint256.NewInt().SetUint64(2)
		metadataM0.QuantityNanos = uint256.NewInt().SetUint64(math.MaxUint64)

		// Perform txn.
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInvalidTotalCost)

		metadataM0.PriceNanos = originalPrice
		metadataM0.QuantityNanos = originalQuantity
	}

	// RuleErrorDAOCoinLimitOrderInsufficientDESOCoinsToOpenOrder
	{
		originalPrice := metadataM0.PriceNanos
		originalQuantity := metadataM0.QuantityNanos

		metadataM0.PriceNanos = uint256.NewInt().SetUint64(1)
		metadataM0.QuantityNanos = uint256.NewInt().SetUint64(math.MaxUint64)

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInsufficientDESOToOpenOrder)
		metadataM0.PriceNanos = originalPrice
		metadataM0.QuantityNanos = originalQuantity
	}

	// Store how many DAO coin nanos will be transferred.
	daoCoinQuantityNanosChange := uint256.NewInt().SetUint64(2)

	// m0 submits limit order buying 2 DAO coin nanos @ 10 $DESO nanos / DAO coin nano.
	// Happy path: update quantity and resubmit. m0's order should be stored.
	{
		// Confirm no existing limit orders.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Empty(orderEntries)

		// Perform txn.
		metadataM0.QuantityNanos = daoCoinQuantityNanosChange
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		// Confirm 1 existing limit order, and it's from m0.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight)))
	}

	// Test db_adapter.GetAllDAOCoinLimitOrdersForThisTransactor()
	{
		// Confirm 1 existing limit order, and it's from m0.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrdersForThisTransactor(m0PKID.PKID)
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight)))
	}

	// Test db_adapter.GetAllDAOCoinLimitOrdersForThisTransactorAtThisPrice()
	{
		// Confirm 1 existing limit order, and it's from m0.
		// Note that the blockHeight param is ignored.
		orderEntry := metadataM0.ToEntry(m0PKID.PKID, 0)
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrdersForThisTransactorAtThisPrice(orderEntry)
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight)))
	}

	// Construct metadata for a m1 limit order selling
	// 2 DAO coins minted by m0 in exchange for $DESO.
	metadataM1 := *metadataM0.Copy()
	metadataM1.BuyingDAOCoinCreatorPKID = metadataM0.SellingDAOCoinCreatorPKID
	metadataM1.SellingDAOCoinCreatorPKID = metadataM0.BuyingDAOCoinCreatorPKID

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
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(100),
			ReceiverPublicKey:      m1PkBytes,
		}

		_daoCoinTransferTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, daoCoinTransferMetadata)
	}

	//// m1 submits ASK order for 2 DAO coins @ 10/1e9 $DESO.
	//// Orders fulfilled for 2 DAO coins @ 10/1e9 $DESO.
	//// Submit matching order and confirm matching happy path.
	//{
	//	// Confirm 1 existing limit order, and it's from m0.
	//	orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 1)
	//	require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight)))
	//
	//	// Store original $DESO balances to check diffs.
	//	originalM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
	//	originalM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)
	//
	//	// Store original DAO coin balances to check diffs.
	//	originalM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
	//	originalM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)
	//
	//	// Perform txn.
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)
	//
	//	// Calculate updated $DESO balances.
	//	updatedM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
	//	updatedM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)
	//
	//	// Calculate updated DAO coin balances.
	//	updatedM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
	//	updatedM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)
	//
	//	// Calculate total cost of order to compare to changes in $DESO.
	//	totalOrderCost, err := _getTotalCostFromQuantityAndPriceNanosPerDenominatedCoin(
	//		metadataM0.Quantity,
	//		metadataM1.PriceNanosPerDenominatedCoin)
	//
	//	require.NoError(err)
	//
	//	// m0's BID order is fulfilled so his DESO balance decreases and his DAO coin balance increases.
	//	require.Equal(
	//		originalM0DESOBalance-totalOrderCost.Uint64(),
	//		updatedM0DESOBalance)
	//
	//	require.Equal(
	//		*uint256.NewInt().Add(&originalM0DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
	//		updatedM0DAOCoinBalance.BalanceNanos)
	//
	//	// m1's ASK order is fulfilled so his DESO balance increases and his DAO coin balance decreases.
	//	require.Equal(
	//		originalM1DESOBalance+totalOrderCost.Uint64()-uint64(3), // TODO: calculate gas fee instead of hard-coding.
	//		updatedM1DESOBalance)
	//
	//	require.Equal(
	//		*uint256.NewInt().Sub(&originalM1DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
	//		updatedM1DAOCoinBalance.BalanceNanos)
	//
	//	// Both orders are deleted from the order book.
	//	orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Empty(orderEntries)
	//}
	//
	//// Scenario: partially fulfilled orders sorting by best price
	//// m1 submits ASK order for 1 DAO coin @ 12/1e9 $DESO.
	//// m1 submits ASK order for 1 DAO coin @ 12/1e9 $DESO.
	//// Quantity is updated instead of creating a new limit order.
	//// m1 submits ASK order for 2 DAO coins @ 11/1e9 $DESO.
	//// m0 submits BID order for 3 DAO coins @ 15/1e9 $DESO.
	//// Orders partially fulfilled for 2 DAO coins @ 11/1e9 $DESO and 1 DAO coin @ 12/1e9 $DESO.
	//{
	//	// Confirm no existing limit orders.
	//	orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Empty(orderEntries)
	//
	//	// m1 submits ASK order for 1 DAO coin @ 12/1e9 $DESO.
	//	metadataM1.PriceNanosPerDenominatedCoin = uint256.NewInt().SetUint64(NanosPerUnit / 12)
	//	metadataM1.Quantity = uint256.NewInt().SetUint64(1)
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)
	//
	//	// Confirm 1 existing limit order, and it's from m1.
	//	orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 1)
	//	require.True(orderEntries[0].Eq(metadataM1.ToEntry(m1PKID.PKID, testMeta.savedHeight)))
	//
	//	// m1 submits ASK order for 1 DAO coin @ 12/1e9 $DESO.
	//	// Quantity is updated and only one order persists.
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)
	//
	//	// Confirm 1 existing limit order, and it's m1's with an updated quantity of 2.
	//	orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 1)
	//	metadataM1.Quantity = uint256.NewInt().SetUint64(2)
	//	require.True(orderEntries[0].Eq(metadataM1.ToEntry(m1PKID.PKID, testMeta.savedHeight)))
	//
	//	// m1 submits ASK order for 2 DAO coins @ 11/1e9 $DESO.
	//	metadataM1.PriceNanosPerDenominatedCoin = uint256.NewInt().SetUint64(NanosPerUnit / 11)
	//	metadataM1.Quantity = uint256.NewInt().SetUint64(2)
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)
	//
	//	// Confirm 2 existing limit orders.
	//	orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 2)
	//
	//	// m0 submits BID order for 3 DAO coins @ 15/1e9 $DESO.
	//	// Store original $DESO balances to check diffs.
	//	originalM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
	//	originalM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)
	//
	//	// Store original DAO coin balances to check diffs.
	//	originalM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
	//	originalM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)
	//
	//	// Construct metadata for m0's BID order.
	//	metadataM0.PriceNanosPerDenominatedCoin = uint256.NewInt().SetUint64(NanosPerUnit / 15)
	//	metadataM0.Quantity = uint256.NewInt().SetUint64(3)
	//
	//	// Confirm matching limit orders exist.
	//	orderEntries, err = dbAdapter.GetMatchingDAOCoinLimitOrders(
	//		metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight), nil)
	//
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 2)
	//
	//	// Perform txn.
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)
	//
	//	// Calculate updated $DESO balances.
	//	updatedM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
	//	updatedM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)
	//
	//	// Calculate updated DAO coin balances.
	//	updatedM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
	//	updatedM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)
	//
	//	// Orders partially fulfilled for 2 DAO coins @ 11/1e9 $DESO and 1 DAO coin @ 12/1e9 $DESO.
	//	daoCoinQuantityChange = uint256.NewInt().SetUint64(3)
	//
	//	// Calculate total cost of order to compare to changes in $DESO.
	//	// 2 DAO coins @ 11/1e9 $DESO
	//	subOrderCost1, err := _getTotalCostFromQuantityAndPriceNanosPerDenominatedCoin(
	//		uint256.NewInt().SetUint64(2),
	//		uint256.NewInt().SetUint64(NanosPerUnit/11))
	//
	//	require.NoError(err)
	//
	//	// 1 DAO coin @ 12/1e9 $DESO
	//	subOrderCost2, err := _getTotalCostFromQuantityAndPriceNanosPerDenominatedCoin(
	//		uint256.NewInt().SetUint64(1),
	//		uint256.NewInt().SetUint64(NanosPerUnit/12))
	//
	//	require.NoError(err)
	//	totalOrderCost := uint256.NewInt().Add(subOrderCost1, subOrderCost2)
	//
	//	// m0's BID order is fulfilled so his DESO balance decreases and his DAO coin balance increases.
	//	require.Equal(
	//		originalM0DESOBalance-totalOrderCost.Uint64()-uint64(2), // TODO: calculate gas fee instead of hard-coding.
	//		updatedM0DESOBalance)
	//
	//	require.Equal(
	//		*uint256.NewInt().Add(&originalM0DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
	//		updatedM0DAOCoinBalance.BalanceNanos)
	//
	//	// m1's ASK orders are fulfilled so his DESO balance increases and his DAO coin balance decreases.
	//	require.Equal(
	//		originalM1DESOBalance+totalOrderCost.Uint64(),
	//		updatedM1DESOBalance)
	//
	//	require.Equal(
	//		*uint256.NewInt().Sub(&originalM1DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
	//		updatedM1DAOCoinBalance.BalanceNanos)
	//
	//	// The correct orders are removed from the order book.
	//	// m0's BID order for 3 DAO coins @ 15/1e9 $DESO is fulfilled.
	//	// m1's ASK order for 2 DAO coins @ 11/1e9 $DESO is fulfilled.
	//	// m1's ASK order for 2 DAO coins @ 12/1e9 $DESO is partially fulfilled w/ 1 DAO coin remaining.
	//	orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 1)
	//	metadataM1.PriceNanosPerDenominatedCoin = uint256.NewInt().SetUint64(NanosPerUnit / 12)
	//	metadataM1.Quantity = uint256.NewInt().SetUint64(1)
	//	require.True(orderEntries[0].Eq(metadataM1.ToEntry(m1PKID.PKID, testMeta.savedHeight)))
	//}
	//
	//// Scenario: cancel all of an open ASK order.
	//// m1 tries to cancel ASK order for 1 DAO coin @ 11/1e9 $DESO. None exist.
	//// m1 cancels ASK order for 1 DAO coin @ 12/1e9 $DESO.
	//{
	//	// Confirm 1 existing limit order from m1.
	//	orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 1)
	//	require.True(orderEntries[0].Eq(metadataM1.ToEntry(m1PKID.PKID, testMeta.savedHeight)))
	//
	//	// m1 tries to cancel ASK order for 1 DAO coin @ 11/1e9 $DESO. None exist.
	//	metadataM1.PriceNanosPerDenominatedCoin = uint256.NewInt().SetUint64(NanosPerUnit / 11)
	//	metadataM1.CancelExistingOrder = true
	//
	//	_, _, _, err = _doDAOCoinLimitOrderTxn(
	//		t, chain, db, params, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)
	//
	//	require.Error(err)
	//	require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderToCancelNotFound)
	//
	//	// m1 cancels ASK order for 1 DAO coin @ 12/1e9 $DESO.
	//	metadataM1.PriceNanosPerDenominatedCoin = uint256.NewInt().SetUint64(NanosPerUnit / 12)
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
	//// m0 submits BID order for 2 DAO coins @ 10/1e9 $DESO.
	//// m0 cancels BID order for 1 DAO coin @ 10/1e9 $DESO.
	//{
	//	// Confirm no existing limit orders.
	//	orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Empty(orderEntries)
	//
	//	// m0 submits BID order for 2 DAO coins @ 10/1e9 $DESO.
	//	metadataM0.PriceNanosPerDenominatedCoin = uint256.NewInt().SetUint64(NanosPerUnit / 10)
	//	metadataM0.Quantity = uint256.NewInt().SetUint64(2)
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)
	//
	//	// Confirm 1 existing limit order from m0.
	//	orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 1)
	//	require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight)))
	//
	//	// m0 cancels BID order for 1 DAO coin @ 10/1e9 $DESO.
	//	metadataM0.Quantity = uint256.NewInt().SetUint64(1)
	//	metadataM0.CancelExistingOrder = true
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)
	//
	//	// Confirm 1 existing limit order from m0 with updated quantity of 1.
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
	//	// Confirm 1 existing limit order from m0 with quantity 1.
	//	orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	require.Equal(len(orderEntries), 1)
	//	require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight)))
	//
	//	// m1 submits BID order for 2 DAO coins @ 10/1e9 $DESO.
	//	metadataM1.PriceNanosPerDenominatedCoin = uint256.NewInt().SetUint64(NanosPerUnit / 10)
	//	metadataM1.Quantity = uint256.NewInt().SetUint64(2)
	//	_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)
	//
	//	// Confirm 2 existing limit orders @ 10/1e9 $DESO.
	//	// 1 from m0 with quantity 1.
	//	// 1 from m1 with quantity 2.
	//	orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
	//	require.NoError(err)
	//	// TODO: make these tests pass
	//	// require.Equal(len(orderEntries), 2)
	//	// require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight)))
	//	// require.True(orderEntries[1].Eq(metadataM1.ToEntry(m1PKID.PKID, testMeta.savedHeight)))
	//}

	// TODO: add validation, no DAO coins in circulation for this profile
	// TODO: maybe test trying to buy more DAO coins than were minted.
	// TODO: partially fulfilled orders
	// TODO: two bid orders, different prices, choose high priced one
	// TODO: two ask orders, different prices, choose lower priced one
	// TODO: what if someone submits order that matches their own order? Probably fine. Just match them.
	// TODO: test disconnect logic

	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)

	if chain.postgres == nil {
		// TODO: this step currently only works with Badger.
		_connectBlockThenDisconnectBlockAndFlush(testMeta)
	}
}

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
