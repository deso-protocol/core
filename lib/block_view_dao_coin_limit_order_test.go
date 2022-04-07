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

	utxoView, err := NewUtxoView(db, params, chain.postgres)
	require.NoError(err)
	dbAdapter := utxoView.GetDbAdapter()

	// Mine a few blocks to give the senderPkString some money.
	_, err = miner.MineAndProcessSingleBlock(0, mempool)
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

	// Helper function to convert PublicKeys to PKIDs.
	toPKID := func(inputPK *PublicKey) *PKID {
		return DBGetPKIDEntryForPublicKey(db, inputPK.ToBytes()).PKID
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
		QuantityToFillInBaseUnits:                 daoCoinQuantityChange,
		OperationType:                             DAOCoinLimitOrderOperationTypeBID,
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

	// RuleErrorDAOCoinLimitOrderInvalidOperationType
	{
		originalValue := metadataM0.OperationType
		metadataM0.OperationType = 99

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInvalidOperationType)
		metadataM0.OperationType = originalValue
	}

	// RuleErrorDAOCoinLimitOrderBuyingDAOCoinCreatorMissingProfile
	{
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderBuyingDAOCoinCreatorMissingProfile)
	}

	// RuleErrorDAOCoinLimitOrderSellingDAOCoinCreatorMissingProfile
	{
		originalBuyingCoin := metadataM0.BuyingDAOCoinCreatorPublicKey
		originalSellingCoin := metadataM0.SellingDAOCoinCreatorPublicKey
		metadataM0.BuyingDAOCoinCreatorPublicKey = originalSellingCoin
		metadataM0.SellingDAOCoinCreatorPublicKey = originalBuyingCoin

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderSellingDAOCoinCreatorMissingProfile)
		metadataM0.BuyingDAOCoinCreatorPublicKey = originalBuyingCoin
		metadataM0.SellingDAOCoinCreatorPublicKey = originalSellingCoin
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
		originalValue := metadataM0.QuantityToFillInBaseUnits
		metadataM0.QuantityToFillInBaseUnits = uint256.NewInt()

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInvalidQuantity)
		metadataM0.QuantityToFillInBaseUnits = originalValue
	}

	// RuleErrorDAOCoinLimitOrderTotalCostOverflowsUint256
	{
		originalPrice := metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy
		originalQuantity := metadataM0.QuantityToFillInBaseUnits
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = MaxUint256.Clone()
		metadataM0.QuantityToFillInBaseUnits = MaxUint256.Clone()

		// Perform txn.
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderTotalCostOverflowsUint256)

		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = originalPrice
		metadataM0.QuantityToFillInBaseUnits = originalQuantity
	}

	// RuleErrorDAOCoinLimitOrderTotalCostOverflowsUint64
	{
		originalPrice := metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy
		originalQuantity := metadataM0.QuantityToFillInBaseUnits
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = uint256.NewInt().SetUint64(math.MaxUint64)
		metadataM0.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(math.MaxUint64)

		// Perform txn.
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderTotalCostIsLessThanOneNano)

		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = originalPrice
		metadataM0.QuantityToFillInBaseUnits = originalQuantity
	}

	// RuleErrorDAOCoinLimitOrderTotalCostIsLessThanOneNano
	{
		originalPrice := metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy
		originalQuantity := metadataM0.QuantityToFillInBaseUnits
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = uint256.NewInt().SetUint64(1)
		metadataM0.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(1)

		// Perform txn.
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderTotalCostIsLessThanOneNano)

		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = originalPrice
		metadataM0.QuantityToFillInBaseUnits = originalQuantity
	}

	// RuleErrorDAOCoinLimitOrderInsufficientDESOToOpenOrder
	{
		originalPrice := metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy
		originalQuantity := metadataM0.QuantityToFillInBaseUnits
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(1.0)
		metadataM0.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(math.MaxUint64)

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInsufficientDESOToOpenOrder)
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = originalPrice
		metadataM0.QuantityToFillInBaseUnits = originalQuantity
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
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, savedHeight, toPKID)))
	}

	// Test GetAllDAOCoinLimitOrdersForThisDAOCoinPair()
	{
		// Test database query.
		// Confirm 1 existing limit order, and it's from m0.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(
			toPKID(metadataM0.BuyingDAOCoinCreatorPublicKey),
			toPKID(metadataM0.SellingDAOCoinCreatorPublicKey))

		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, savedHeight, toPKID)))

		// Test UTXO view query.
		// Confirm 1 existing limit order, and it's from m0.
		orderEntries, err = utxoView._getAllDAOCoinLimitOrdersForThisDAOCoinPair(
			toPKID(metadataM0.BuyingDAOCoinCreatorPublicKey),
			toPKID(metadataM0.SellingDAOCoinCreatorPublicKey))

		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, savedHeight, toPKID)))
	}

	// Test GetAllDAOCoinLimitOrdersForThisTransactor()
	{
		// Test database query.
		// Confirm 1 existing limit order, and it's from m0.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrdersForThisTransactor(m0PKID.PKID)
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, savedHeight, toPKID)))

		// Test UTXO view query.
		// Confirm 1 existing limit order, and it's from m0.
		orderEntries, err = utxoView._getAllDAOCoinLimitOrdersForThisTransactor(m0PKID.PKID)
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, savedHeight, toPKID)))
	}

	// Test GetAllDAOCoinLimitOrdersForThisTransactorAtThisPrice()
	{
		// Test database query.
		// Confirm 1 existing limit order, and it's from m0.
		orderEntry := metadataM0.ToEntry(m0PKID.PKID, savedHeight, toPKID)
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrdersForThisTransactorAtThisPrice(orderEntry)
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(orderEntry))

		// Test UTXO view query.
		// Confirm 1 existing limit order, and it's from m0.
		orderEntries, err = utxoView._getAllDAOCoinLimitOrdersForThisTransactorAtThisPrice(orderEntry)
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
		QuantityToFillInBaseUnits:                 desoQuantityChange,
		OperationType:                             DAOCoinLimitOrderOperationTypeBID,
	}

	// RuleErrorDAOCoinLimitOrderInsufficientDAOCoinsToOpenOrder
	{
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)

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
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, savedHeight, toPKID)))

		// Confirm 1 matching limit orders exists.
		orderEntryM1 := metadataM1.ToEntry(m1PKID.PKID, savedHeight, toPKID)
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

		// m0's order buying DAO coins is fulfilled so:
		//   * His DESO balance decreases and
		//   * His DAO coin balance increases.
		require.Equal(
			originalM0DESOBalance-desoQuantityChange.Uint64(),
			updatedM0DESOBalance)

		require.Equal(
			*uint256.NewInt().Add(&originalM0DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
			updatedM0DAOCoinBalance.BalanceNanos)

		// m1's order is fulfilled buying $DESO so:
		//   * His $DESO balance increases and
		//   * His DAO coin balance decreases.
		require.Equal(
			originalM1DESOBalance+desoQuantityChange.Uint64()-uint64(3), // TODO: calculate gas fee instead of hard-coding.
			updatedM1DESOBalance)

		require.Equal(
			*uint256.NewInt().Sub(&originalM1DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
			updatedM1DAOCoinBalance.BalanceNanos)
	}

	// Scenario: partially fulfilled orders sorting by best price
	// m1 submits order buying 20 $DESO nanos @ 11 DAO coin / $DESO.
	// m1 submits order buying 5 $DESO nanos @ 12 DAO coin / $DESO.
	// m1 submits order buying 5 $DESO nanos @ 12 DAO coin / $DESO.
	// Quantity is updated instead of creating a new limit order.
	// m0 submits order buying 240 DAO coin nanos @ 1/8 $DESO / DAO coin.
	// m0's order is fully fulfilled.
	// m1's orders are partially fulfilled for:
	//   * 10 $DESO @ 12 DAO coin / $DESO (fully fulfilled) and
	//   * 10 $DESO @ 11 DAO coin / $DESO (partially fulfilled).
	{
		// Confirm no existing limit orders.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Empty(orderEntries)

		// m1 submits order buying 20 $DESO @ 11 DAO coin / $DESO.
		metadataM1.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(11.0)
		metadataM1.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(20)
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)

		// m1 submits order buying 5 $DESO nanos @ 12 DAO coin / $DESO.
		metadataM1.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(12.0)
		metadataM1.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(5)
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)

		// Confirm 2 existing limit orders.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 2)
		require.True(orderEntries[1].Eq(metadataM1.ToEntry(m1PKID.PKID, savedHeight, toPKID)))

		// m1 submits order buying 5 $DESO nanos @ 12 DAO coin / $DESO.
		// Quantity is updated and only one order persists.
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)

		// Confirm 2 existing limit order, second has updated quantity of 10.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 2)
		metadataM1.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(10)
		require.True(orderEntries[1].Eq(metadataM1.ToEntry(m1PKID.PKID, savedHeight, toPKID)))

		// Store original $DESO balances to check diffs.
		originalM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
		originalM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)

		// Store original DAO coin balances to check diffs.
		originalM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
		originalM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)

		// Construct metadata for m0's order buying 240 DAO coin nanos @ 1/8 $DESO / DAO coin.
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(0.125) // 1.0 / 8.0 = 0.125
		metadataM0.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(240)

		// Confirm matching limit orders exist.
		orderEntries, err = dbAdapter.GetMatchingDAOCoinLimitOrders(
			metadataM0.ToEntry(m0PKID.PKID, savedHeight, toPKID), nil)

		require.NoError(err)
		require.Equal(len(orderEntries), 2)

		// m0 submits order buying 240 DAO coin nanos @ 1/8 $DESO / DAO coin.
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		// The correct orders are removed from the order book.
		// m1's order for 10 $DESO nanos @ 12 DAO coin / $DESO is fulfilled.
		// m1's order for 20 $DESO nanos @ 11 DAO coin / $DESO is partially fulfilled with 10 $DESO nanos remaining.
		// m0's order for 240 DAO coin nanos @ 1/8 $DESO / DAO coin is fulfilled.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		metadataM1.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(11.0)
		metadataM1.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(10)
		require.True(orderEntries[0].Eq(metadataM1.ToEntry(m1PKID.PKID, savedHeight, toPKID)))

		// Calculate updated $DESO balances.
		updatedM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
		updatedM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)

		// Calculate updated DAO coin balances.
		updatedM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
		updatedM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)

		// Calculate changes in $DESO and DAO coins.
		daoCoinQuantityChange = uint256.NewInt().SetUint64(240)
		desoQuantityChange := uint256.NewInt().SetUint64(20)

		// m0's order to buy DAO coins is fulfilled so:
		//   * His $DESO balance decreases and
		//   * His DAO coin balance increases.
		// TODO: these should be equal.
		require.Equal(
			originalM0DESOBalance-desoQuantityChange.Uint64()-uint64(2), // TODO: calculate gas fee instead of hard-coding.
			updatedM0DESOBalance)

		require.Equal(
			*uint256.NewInt().Add(&originalM0DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
			updatedM0DAOCoinBalance.BalanceNanos)

		// m1's orders to buy $DESO are fulfilled so:
		//   * His $DESO balance increases and
		//   * His DAO coin balance decreases.
		require.Equal(
			originalM1DESOBalance+desoQuantityChange.Uint64(), updatedM1DESOBalance)

		require.Equal(
			*uint256.NewInt().Sub(&originalM1DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
			updatedM1DAOCoinBalance.BalanceNanos)
	}

	// Scenario: cancel all of an open order.
	// m1 tries to cancel order buying 10 $DESO nanos @ 12 DAO coin / $DESO. None exist.
	// m1 cancels order buying 10 DAO coin nanos @ 11 DAO coins / $DESO.
	{
		// Confirm 1 existing limit order from m1 for 10 $DESO nanos @ 11 DAO coin / $DESO.
		metadataM1.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(11.0)
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM1.ToEntry(m1PKID.PKID, savedHeight, toPKID)))

		// m1 tries to cancel order buying 10 $DESO nanos @ 12 DAO coin / $DESO. None exist.
		metadataM1.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(12.0)
		metadataM1.CancelExistingOrder = true

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderToCancelNotFound)

		// m1 cancels order buying 10 DAO coin nanos @ 11 DAO coins / $DESO.
		metadataM1.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(11.0)
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)

		// Confirm no existing limit orders.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Empty(orderEntries)

		// Reset metadataM1.
		metadataM1.CancelExistingOrder = false
	}

	// Scenario: submit and subsequently cancel part of open order. This cancels the whole order.
	// Note: we thought about cancelling only part of the open order, but came to the conclusion
	// that it is easier and cleaner if we just cancel the entire order regardless of what
	// quantity the transactor specifies.
	// m0 submits order buying 200 DAO coin nanos @ 0.1 $DESO / DAO coin.
	// m0 cancels order buying 100 DAO coin nanos @ 0.1 $DESO / DAO coin.
	{
		// Confirm no existing limit orders.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Empty(orderEntries)

		// m0 submits order buying 200 DAO coin nanos @ 0.1 $DESO / DAO coin.
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(0.1)
		metadataM0.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(200)
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		// Confirm 1 existing limit order from m0.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, savedHeight, toPKID)))

		// m0 cancels order buying 100 DAO coin nanos @ 0.1 $DESO / DAO coin.
		metadataM0.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(100)
		metadataM0.CancelExistingOrder = true
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		// Confirm 1 existing limit order from m0 with updated quantity of 100.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 0)

		// Reset metadataM0.
		metadataM0.CancelExistingOrder = false
	}

	// Scenario: user sells DAO coins for $DESO, but is able to find a good matching
	// order such that they receive/buy the same amount of $DESO by selling a lower
	// quantity of DAO coins than they intended. This is expected behavior.
	{
		// Confirm no existing orders.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 0)

		// m0 submits order buying 100 DAO coin units @ 10 $DESO / DAO coin.
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(10.0)
		metadataM0.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(100)
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		// Confirm order is stored.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, savedHeight, toPKID)))

		// Store original $DESO balances to check diffs.
		originalM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
		originalM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)

		// Store original DAO coin balances to check diffs.
		originalM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
		originalM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)

		// m1 submits order selling 50 DAO coin units @ 5 $DESO / DAO coin.
		metadataM1.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(0.2)
		metadataM1.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(250)
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)

		// m0's order is partially fulfilled with 75 coins remaining. m1's order is fully
		// fulfilled. Note that he gets his full amount of $DESO but sells only 25 of the
		// 50 DAO coin units he intended to. This is expected behavior at the moment. We
		// specify a buying quantity but allow the selling quantity to vary depending on
		// the best offer(s) available.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		metadataM0.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(75)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, savedHeight, toPKID)))

		// Calculate updated $DESO balances.
		updatedM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
		updatedM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)

		// Calculate updated DAO coin balances.
		updatedM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
		updatedM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)

		// Calculate changes in $DESO and DAO coins.
		daoCoinQuantityChange = uint256.NewInt().SetUint64(25)
		desoQuantityChange := uint256.NewInt().SetUint64(250)

		// m0's order buying DAO coins is partially fulfilled so:
		//   * His $DESO balance decreases and
		//   * His DAO coin balance increases.
		require.Equal(
			originalM0DESOBalance-desoQuantityChange.Uint64(),
			updatedM0DESOBalance)

		require.Equal(
			*uint256.NewInt().Add(&originalM0DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
			updatedM0DAOCoinBalance.BalanceNanos)

		// m1's order selling DAO coins is fulfilled so:
		//   * His $DESO balance increases and
		//   * His DAO coin balance decreases.
		// TODO: these should be equal.
		require.NotEqual(
			originalM1DESOBalance+desoQuantityChange.Uint64()-uint64(2), updatedM1DESOBalance) // TODO: calculate gas fee instead of hard-coding.

		require.Equal(
			*uint256.NewInt().Sub(&originalM1DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
			updatedM1DAOCoinBalance.BalanceNanos)

		// m0 cancels the remainder of his order.
		metadataM0.CancelExistingOrder = true
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)
		metadataM0.CancelExistingOrder = false

		// Confirm no existing limit orders.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Empty(orderEntries)
	}

	// Scenario: m0 and m1 both submit identical orders. Both orders are stored.
	{
		// Confirm no existing limit orders.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Empty(orderEntries)

		// m0 submits order buying 100 DAO coins @ 0.1 $DESO / DAO coin.
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(0.1)
		metadataM0.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(100)
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		// Confirm 1 existing limit order from m0.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, savedHeight, toPKID)))

		// m1 submits order buying 100 DAO coins @ 0.1 $DESO / DAO coin.
		metadataM1.BuyingDAOCoinCreatorPublicKey = metadataM0.BuyingDAOCoinCreatorPublicKey
		metadataM1.SellingDAOCoinCreatorPublicKey = metadataM0.SellingDAOCoinCreatorPublicKey
		metadataM1.ScaledExchangeRateCoinsToSellPerCoinToBuy = metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy
		metadataM1.QuantityToFillInBaseUnits = metadataM0.QuantityToFillInBaseUnits
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)

		// Confirm 2 existing limit orders @ 0.1 $DESO / DAO coin.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 2)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, savedHeight, toPKID)))
		require.True(orderEntries[1].Eq(metadataM1.ToEntry(m1PKID.PKID, savedHeight, toPKID)))
	}

	// Scenario: non-matching order.
	{
		// m0 cancels their order.
		metadataM0.CancelExistingOrder = true
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)
		metadataM0.CancelExistingOrder = false

		// Confirm 1 existing order from m1.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM1.ToEntry(m1PKID.PKID, savedHeight, toPKID)))

		// m0 submits order for a worse exchange rate than m1 is willing to accept.
		// Doesn't match m1's order. Stored instead.
		metadataM0.BuyingDAOCoinCreatorPublicKey = metadataM1.SellingDAOCoinCreatorPublicKey
		metadataM0.SellingDAOCoinCreatorPublicKey = metadataM1.BuyingDAOCoinCreatorPublicKey
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(9)
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		// Confirm 2 existing orders.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 2)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, savedHeight, toPKID)))
		require.True(orderEntries[1].Eq(metadataM1.ToEntry(m1PKID.PKID, savedHeight, toPKID)))

		// m1 submits order matching their own order. Fails.
		metadataM1.BuyingDAOCoinCreatorPublicKey = metadataM0.BuyingDAOCoinCreatorPublicKey
		metadataM1.SellingDAOCoinCreatorPublicKey = metadataM0.SellingDAOCoinCreatorPublicKey
		metadataM1.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(10.0)
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderMatchingOwnOrder)

		// Confirm 2 existing orders.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 2)
	}

	// Cancel order with insufficient funds to cover the order.
	{
		m0BalanceEntry := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
		// Just a reminder of m0's current balance of their own DAO Coins
		require.Equal(m0BalanceEntry.BalanceNanos.Uint64(), uint64(7365))
		// M0 transfers away some of their DAO coin such that they no longer have 100 nanos (to cover their order).
		_daoCoinTransferTxnWithTestMeta(
			testMeta,
			feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			DAOCoinTransferMetadata{
				ProfilePublicKey:       m0PkBytes,
				ReceiverPublicKey:      m2PkBytes,
				DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(m0BalanceEntry.BalanceNanos.Uint64() - 1),
			},
		)

		metadataM0.CancelExistingOrder = true
		_doDAOCoinLimitOrderTxnWithTestMeta(
			testMeta,
			feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			metadataM0,
		)

		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Len(orderEntries, 1)
		require.True(orderEntries[0].TransactorPKID.Eq(m1PKID.PKID))

		// Before we transfer the DAO coins back to m0, let's create an order for m2 that is slightly better
		// than m0's order. We'll have m1 submit an order that matches this later.
		metadataM2 := DAOCoinLimitOrderMetadata{
			BuyingDAOCoinCreatorPublicKey:             metadataM0.BuyingDAOCoinCreatorPublicKey,
			SellingDAOCoinCreatorPublicKey:            metadataM0.SellingDAOCoinCreatorPublicKey,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(9.5),
			QuantityToFillInBaseUnits:                 metadataM0.QuantityToFillInBaseUnits,
			OperationType:                             DAOCoinLimitOrderOperationTypeBID,
		}

		_doDAOCoinLimitOrderTxnWithTestMeta(
			testMeta,
			feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			metadataM2,
		)

		// Okay let's transfer the DAO coins back to m0 and recreate the order
		_daoCoinTransferTxnWithTestMeta(
			testMeta,
			feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			DAOCoinTransferMetadata{
				ProfilePublicKey:       m0PkBytes,
				ReceiverPublicKey:      m0PkBytes,
				DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(7339),
			},
		)
		metadataM0.CancelExistingOrder = false
		_doDAOCoinLimitOrderTxnWithTestMeta(
			testMeta,
			feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			metadataM0,
		)
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Len(orderEntries, 3)
	}

	// M1 submits an order that would match both m0 and m2's order. We expect to see m2's order cancelled
	// and m0's order filled as m2 doesn't have sufficient DAO coins to cover the order they placed.
	{
		metadataM1.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(float64(1) / float64(8))
		metadataM1.SellingDAOCoinCreatorPublicKey = metadataM0.BuyingDAOCoinCreatorPublicKey
		metadataM1.BuyingDAOCoinCreatorPublicKey = metadataM0.SellingDAOCoinCreatorPublicKey

		// 27
		_doDAOCoinLimitOrderTxnWithTestMeta(
			testMeta,
			feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			metadataM1,
		)

		m2Orders, err := dbAdapter.GetAllDAOCoinLimitOrdersForThisTransactor(m2PKID.PKID)
		require.NoError(err)
		require.Len(m2Orders, 0)
	}

	// Let's start fresh and mint some DAO coins for M1
	{
		// 28
		_updateProfileWithTestMeta(
			testMeta,
			feeRateNanosPerKb, /*feeRateNanosPerKB*/
			m1Pub,             /*updaterPkBase58Check*/
			m1Priv,            /*updaterPrivBase58Check*/
			[]byte{},          /*profilePubKey*/
			"m1",              /*newUsername*/
			"i am the m1",     /*newDescription*/
			shortPic,          /*newProfilePic*/
			10*100,            /*newCreatorBasisPoints*/
			1.25*100*100,      /*newStakeMultipleBasisPoints*/
			false,             /*isHidden*/
		)

		// Mint 100k nanos for M1 DAO coin
		daoCoinMintMetadata := DAOCoinMetadata{
			ProfilePublicKey: m1PkBytes,
			OperationType:    DAOCoinOperationTypeMint,
			CoinsToMintNanos: *uint256.NewInt().SetUint64(1e5),
		}

		// 29
		_daoCoinTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, daoCoinMintMetadata)

		// Transfer 10K nanos to M2
		daoCoinTransferMetadata := DAOCoinTransferMetadata{
			ProfilePublicKey:       m1PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(1e4),
			ReceiverPublicKey:      m2PkBytes,
		}

		// 30
		_daoCoinTransferTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, daoCoinTransferMetadata)
	}

	// M1 and M2 submit orders to SELL M1 DAO Coin
	{
		// Sell DAO @ 5 DAO / DESO, up to 10 DESO. Max DAO = 50
		m1OrderMetadata := DAOCoinLimitOrderMetadata{
			SellingDAOCoinCreatorPublicKey:            NewPublicKey(m1PkBytes),
			BuyingDAOCoinCreatorPublicKey:             &ZeroPublicKey,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(5),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(10),
			OperationType:                             DAOCoinLimitOrderOperationTypeBID,
		}

		// 31
		_doDAOCoinLimitOrderTxnWithTestMeta(
			testMeta,
			feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			m1OrderMetadata,
		)

		// Sell DAO @ 2 DAO / DESO, up to 5 DESO. Max DAO = 10
		m2OrderMetadata := DAOCoinLimitOrderMetadata{
			SellingDAOCoinCreatorPublicKey:            NewPublicKey(m1PkBytes),
			BuyingDAOCoinCreatorPublicKey:             &ZeroPublicKey,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(2),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(5),
			OperationType:                             DAOCoinLimitOrderOperationTypeBID,
		}

		// 32
		_doDAOCoinLimitOrderTxnWithTestMeta(
			testMeta,
			feeRateNanosPerKb,
			m2Pub,
			m2Priv,
			m2OrderMetadata,
		)

		orders, err := dbAdapter.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(&ZeroPKID, m1PKID.PKID)
		require.NoError(err)
		require.Len(orders, 2)
	}

	// M0 submits order to buy M1 DAO Coin that matches
	{
		m0DESOBalanceBefore := _getBalance(t, chain, mempool, m0Pub)
		m1DESOBalanceBefore := _getBalance(t, chain, mempool, m1Pub)
		m2DESOBalanceBefore := _getBalance(t, chain, mempool, m2Pub)
		m1BalanceEntryBefore := dbAdapter.GetBalanceEntry(m1PKID.PKID, m1PKID.PKID, true)
		m2BalanceEntryBefore := dbAdapter.GetBalanceEntry(m2PKID.PKID, m1PKID.PKID, true)

		// Sell DESO @ 1 DESO / DAO for up to 100 DAO coins. Max DESO: 100 DESO
		m0OrderMetadata := DAOCoinLimitOrderMetadata{
			SellingDAOCoinCreatorPublicKey:            &ZeroPublicKey,
			BuyingDAOCoinCreatorPublicKey:             NewPublicKey(m1PkBytes),
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(1),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(300),
			OperationType:                             DAOCoinLimitOrderOperationTypeBID,
		}

		// 33
		_doDAOCoinLimitOrderTxnWithTestMeta(
			testMeta,
			feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			m0OrderMetadata,
		)

		orders, err := dbAdapter.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(&ZeroPKID, m1PKID.PKID)
		require.NoError(err)
		require.Len(orders, 0)

		orders, err = dbAdapter.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(m1PKID.PKID, &ZeroPKID)
		require.NoError(err)
		require.Len(orders, 1)
		require.True(orders[0].QuantityToFillInBaseUnits.Eq(uint256.NewInt().SetUint64(240)))

		// Get balance entries for all users.
		m0BalanceEntryAfter := dbAdapter.GetBalanceEntry(m0PKID.PKID, m1PKID.PKID, true)
		m1BalanceEntryAfter := dbAdapter.GetBalanceEntry(m1PKID.PKID, m1PKID.PKID, true)
		m2BalanceEntryAfter := dbAdapter.GetBalanceEntry(m2PKID.PKID, m1PKID.PKID, true)

		m2Decrease, err := SafeUint256().Sub(&m2BalanceEntryBefore.BalanceNanos, &m2BalanceEntryAfter.BalanceNanos)
		require.NoError(err)
		require.True(m2Decrease.Eq(uint256.NewInt().SetUint64(10)))

		m1Decrease, err := SafeUint256().Sub(&m1BalanceEntryBefore.BalanceNanos, &m1BalanceEntryAfter.BalanceNanos)
		require.NoError(err)
		require.True(m1Decrease.Eq(uint256.NewInt().SetUint64(50)))

		require.True(m0BalanceEntryAfter.BalanceNanos.Eq(uint256.NewInt().SetUint64(60)))

		m0DESOBalanceAfter := _getBalance(t, chain, mempool, m0Pub)
		m1DESOBalanceAfter := _getBalance(t, chain, mempool, m1Pub)
		m2DESOBalanceAfter := _getBalance(t, chain, mempool, m2Pub)

		require.Equal(m0DESOBalanceBefore-15-3, m0DESOBalanceAfter) // Fee is 3 nanos
		require.Equal(m1DESOBalanceBefore+10, m1DESOBalanceAfter)
		require.Equal(m2DESOBalanceBefore+5, m2DESOBalanceAfter)
	}

	{
		// Current Order Book:
		//   Transactor: m0
		//   Buying:     m0 DAO coin
		//   Selling:    $DESO
		//   Price:      0.1 $DESO / DAO coin
		//   Quantity:   100 DAO coin units
		//
		//   Transactor: m0
		//   Buying:     $DESO
		//   Selling:    m0 DAO coin
		//   Price:      9 DAO coins / $DESO
		//   Quantity:   89 $DESO nanos
		//
		//   Transactor: m1
		//   Buying:     m0 DAO coin
		//   Selling:    $DESO
		//   Price:      0.1 $DESO / DAO coin
		//   Quantity:   100 DAO coin units
		//
		//   Transactor: m0
		//   Buying:     m1 DAO coin
		//   Selling:    $DESO
		//   Price:      1 $DESO / DAO coin
		//   Quantity:   240 DAO coin units

		// Test get all DAO coin limit orders.
		orderEntries, err := utxoView._getAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 4)

		// Test get all DAO coin limit orders for this DAO coin pair.
		orderEntries, err = utxoView._getAllDAOCoinLimitOrdersForThisDAOCoinPair(m0PKID.PKID, &ZeroPKID)
		require.NoError(err)
		require.Equal(len(orderEntries), 2)

		// Test get all DAO coin limit orders for this transactor.
		// Target order:
		//   Transactor: m1
		//   Buying:     m0 DAO coin
		//   Selling:    $DESO
		//   Price:      0.1 $DESO / DAO coin
		//   Quantity:   100 DAO coin units
		orderEntries, err = utxoView._getAllDAOCoinLimitOrdersForThisTransactor(m1PKID.PKID)
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.Equal(orderEntries[0].ScaledExchangeRateCoinsToSellPerCoinToBuy, CalculateScaledExchangeRate(0.1))

		// Test get all DAO coin limit orders for this transactor at this price.
		// Target order:
		//   Transactor: m0
		//   Buying:     $DESO
		//   Selling:    m0 DAO coin
		//   Price:      9 DAO coins / $DESO
		//   Quantity:   89 $DESO nanos
		queryEntry := &DAOCoinLimitOrderEntry{
			TransactorPKID:                            m0PKID.PKID,
			BuyingDAOCoinCreatorPKID:                  &ZeroPKID,
			SellingDAOCoinCreatorPKID:                 m0PKID.PKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(9.0),
			QuantityToFillInBaseUnits:                 uint256.NewInt(), // ignored
		}

		orderEntries, err = utxoView._getAllDAOCoinLimitOrdersForThisTransactorAtThisPrice(queryEntry)
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.Equal(orderEntries[0].QuantityToFillInBaseUnits, uint256.NewInt().SetUint64(89))

		// Test get matching DAO coin limit orders.
		// Target order:
		//   Transactor: m0
		//   Buying:     m1 DAO coin
		//   Selling:    $DESO
		//   Price:      1 $DESO / DAO coin
		//   Quantity:   240 DAO coin units
		queryEntry = &DAOCoinLimitOrderEntry{
			TransactorPKID:                            m1PKID.PKID,
			BuyingDAOCoinCreatorPKID:                  &ZeroPKID,
			SellingDAOCoinCreatorPKID:                 m1PKID.PKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(0.9),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(100),
		}

		orderEntries, err = utxoView._getNextLimitOrdersToFill(queryEntry, nil)
		require.NoError(err)
		require.Empty(orderEntries)

		queryEntry.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(1.1)
		orderEntries, err = utxoView._getNextLimitOrdersToFill(queryEntry, nil)
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.Equal(orderEntries[0].ScaledExchangeRateCoinsToSellPerCoinToBuy, CalculateScaledExchangeRate(1.0))
		require.Equal(orderEntries[0].QuantityToFillInBaseUnits, uint256.NewInt().SetUint64(240))

		// m0 submits another order slightly better than previous.
		//   Transactor: m0
		//   Buying:     m1 DAO coin
		//   Selling:    $DESO
		//   Price:      1.05 $DESO / DAO coin
		//   Quantity:   110 DAO coin units
		metadataM0.BuyingDAOCoinCreatorPublicKey = NewPublicKey(m1PkBytes)
		metadataM0.SellingDAOCoinCreatorPublicKey = &ZeroPublicKey
		metadataM0.ScaledExchangeRateCoinsToSellPerCoinToBuy = CalculateScaledExchangeRate(1.05)
		metadataM0.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(110)
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)
		orderEntries, err = utxoView._getAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 5)

		// Test get matching DAO coin limit orders.
		// Query with identical order as before. Should match m0's new + better order.
		// Target order:
		//   Transactor: m0
		//   Buying:     m1 DAO coin
		//   Selling:    $DESO
		//   Price:      1.05 $DESO / DAO coin
		//   Quantity:   110 DAO coin units
		orderEntries, err = utxoView._getNextLimitOrdersToFill(queryEntry, nil)
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.Equal(orderEntries[0].ScaledExchangeRateCoinsToSellPerCoinToBuy, CalculateScaledExchangeRate(1.05))
		require.Equal(orderEntries[0].QuantityToFillInBaseUnits, uint256.NewInt().SetUint64(110))

		// Test get matching DAO coin limit orders.
		// Query with identical order as before but higher quantity.
		// Should match both of m0's orders with better listed first.
		queryEntry.QuantityToFillInBaseUnits = uint256.NewInt().SetUint64(150)
		orderEntries, err = utxoView._getNextLimitOrdersToFill(queryEntry, nil)
		require.NoError(err)
		require.Equal(len(orderEntries), 2)
		require.Equal(orderEntries[0].ScaledExchangeRateCoinsToSellPerCoinToBuy, CalculateScaledExchangeRate(1.05))
		require.Equal(orderEntries[0].QuantityToFillInBaseUnits, uint256.NewInt().SetUint64(110))
		require.Equal(orderEntries[1].ScaledExchangeRateCoinsToSellPerCoinToBuy, CalculateScaledExchangeRate(1.0))
		require.Equal(orderEntries[1].QuantityToFillInBaseUnits, uint256.NewInt().SetUint64(240))
	}

	// Test CalculateDAOCoinsTransferredInLimitOrderMatch()
	{
		// Scenario 1: one ASK, one BID, exactly matching orders
		// m0 sells 1000 DAO coin base units @ 0.1 $DESO / DAO coin.
		m0Order := &DAOCoinLimitOrderEntry{
			TransactorPKID:                            m0PKID.PKID,
			BuyingDAOCoinCreatorPKID:                  &ZeroPKID,
			SellingDAOCoinCreatorPKID:                 m0PKID.PKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(10.0),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(1000),
			OperationType:                             DAOCoinLimitOrderOperationTypeASK,
		}

		// m1 buys 1000 DAO coin base units @ 0.1 $DESO / DAO coin.
		m1Order := &DAOCoinLimitOrderEntry{
			TransactorPKID:                            m1PKID.PKID,
			BuyingDAOCoinCreatorPKID:                  m0PKID.PKID,
			SellingDAOCoinCreatorPKID:                 &ZeroPKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(0.1),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(1000),
			OperationType:                             DAOCoinLimitOrderOperationTypeBID,
		}

		// m0 = transactor, m1 = matching order
		updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			err := utxoView._calculateDAOCoinsTransferredInLimitOrderMatch(m0Order, m1Order)
		require.NoError(err)
		require.Equal(updatedTransactorQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(updatedMatchingQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(transactorBuyingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(100))
		require.Equal(transactorSellingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(1000))

		// m1 = transactor, m0 = matching order
		updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			err = utxoView._calculateDAOCoinsTransferredInLimitOrderMatch(m1Order, m0Order)
		require.NoError(err)
		require.Equal(updatedTransactorQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(updatedMatchingQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(transactorBuyingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(1000))
		require.Equal(transactorSellingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(100))

		// Scenario 2: one BID, one ASK, matching orders w/ mismatched prices
		// m0 buys 1000 DAO coin base units @ 10 $DESO / DAO coin.
		m0Order = &DAOCoinLimitOrderEntry{
			TransactorPKID:                            m0PKID.PKID,
			BuyingDAOCoinCreatorPKID:                  m0PKID.PKID,
			SellingDAOCoinCreatorPKID:                 &ZeroPKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(10.0),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(1000),
			OperationType:                             DAOCoinLimitOrderOperationTypeBID,
		}

		// m1 sells 500 DAO coin base units @ 5 $DESO / DAO coin.
		m1Order = &DAOCoinLimitOrderEntry{
			TransactorPKID:                            m1PKID.PKID,
			BuyingDAOCoinCreatorPKID:                  &ZeroPKID,
			SellingDAOCoinCreatorPKID:                 m0PKID.PKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(0.2),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(500),
			OperationType:                             DAOCoinLimitOrderOperationTypeASK,
		}

		// m0 = transactor, m1 = matching order
		// m0 buys 500 DAO coin base units @ 5 $DESO / DAO coin.
		updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			err = utxoView._calculateDAOCoinsTransferredInLimitOrderMatch(m0Order, m1Order)
		require.NoError(err)
		require.Equal(updatedTransactorQuantityToFillInBaseUnits, uint256.NewInt().SetUint64(500))
		require.Equal(updatedMatchingQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(transactorBuyingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(500))
		require.Equal(transactorSellingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(2500))

		// m1 = transactor, m0 = matching order
		// m1 sells 500 DAO coin base units @ 10 $DESO / DAO coin.
		updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			err = utxoView._calculateDAOCoinsTransferredInLimitOrderMatch(m1Order, m0Order)
		require.NoError(err)
		require.Equal(updatedTransactorQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(updatedMatchingQuantityToFillInBaseUnits, uint256.NewInt().SetUint64(500))
		require.Equal(transactorBuyingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(5000))
		require.Equal(transactorSellingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(500))

		// Scenario 3: m0 and m1 both submit BIDs that should match
		// m0 buys 100 DAO coin base units @ 10 $DESO / DAO coin.
		m0Order = &DAOCoinLimitOrderEntry{
			TransactorPKID:                            m0PKID.PKID,
			BuyingDAOCoinCreatorPKID:                  m0PKID.PKID,
			SellingDAOCoinCreatorPKID:                 &ZeroPKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(10.0),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(100),
			OperationType:                             DAOCoinLimitOrderOperationTypeBID,
		}

		// m1 buys 1000 $DESO @ 0.1 DAO coin / $DESO.
		m1Order = &DAOCoinLimitOrderEntry{
			TransactorPKID:                            m1PKID.PKID,
			BuyingDAOCoinCreatorPKID:                  &ZeroPKID,
			SellingDAOCoinCreatorPKID:                 m0PKID.PKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(0.1),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(1000),
			OperationType:                             DAOCoinLimitOrderOperationTypeBID,
		}

		// m0 = transactor, m1 = matching order
		// m0 buys 100 DAO coin base units @ 10 $DESO / DAO coin.
		updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			err = utxoView._calculateDAOCoinsTransferredInLimitOrderMatch(m0Order, m1Order)
		require.NoError(err)
		require.Equal(updatedTransactorQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(updatedMatchingQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(transactorBuyingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(100))
		require.Equal(transactorSellingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(1000))

		// m1 = transactor, m0 = matching order
		// m1 buys 1000 $DESO @ 0.1 DAO coin / $DESO.
		updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			err = utxoView._calculateDAOCoinsTransferredInLimitOrderMatch(m1Order, m0Order)
		require.NoError(err)
		require.Equal(updatedTransactorQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(updatedMatchingQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(transactorBuyingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(1000))
		require.Equal(transactorSellingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(100))

		// Scenario 4: m0 and m1 both submit BIDs that match
		// 			   m1 gets a better price than expected
		// m0 buys 100 DAO coin base units @ 10 $DESO / DAO coin.
		m0Order = &DAOCoinLimitOrderEntry{
			TransactorPKID:                            m0PKID.PKID,
			BuyingDAOCoinCreatorPKID:                  m0PKID.PKID,
			SellingDAOCoinCreatorPKID:                 &ZeroPKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(10.0),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(100),
			OperationType:                             DAOCoinLimitOrderOperationTypeBID,
		}

		// m1 buys 250 $DESO @ 0.2 DAO coin / $DESO.
		m1Order = &DAOCoinLimitOrderEntry{
			TransactorPKID:                            m1PKID.PKID,
			BuyingDAOCoinCreatorPKID:                  &ZeroPKID,
			SellingDAOCoinCreatorPKID:                 m0PKID.PKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(0.2),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(250),
			OperationType:                             DAOCoinLimitOrderOperationTypeBID,
		}

		// m0 = transactor, m1 = matching order
		// m0 buys 50 DAO coin base units @ 5 $DESO / DAO coin.
		updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			err = utxoView._calculateDAOCoinsTransferredInLimitOrderMatch(m0Order, m1Order)
		require.NoError(err)
		require.Equal(updatedTransactorQuantityToFillInBaseUnits, uint256.NewInt().SetUint64(50))
		require.Equal(updatedMatchingQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(transactorBuyingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(50))
		require.Equal(transactorSellingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(250))

		// m1 = transactor, m0 = matching order
		// m1 buys 250 $DESO @ 0.1 DAO coins / $DESO.
		updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			err = utxoView._calculateDAOCoinsTransferredInLimitOrderMatch(m1Order, m0Order)
		require.NoError(err)
		require.Equal(updatedTransactorQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(updatedMatchingQuantityToFillInBaseUnits, uint256.NewInt().SetUint64(75))
		require.Equal(transactorBuyingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(250))
		require.Equal(transactorSellingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(25))

		// Scenario 5: m0 and m1 both submit ASKs that should match
		// m0 sells 1000 $DESO @ 10 $DESO / DAO coin.
		m0Order = &DAOCoinLimitOrderEntry{
			TransactorPKID:                            m0PKID.PKID,
			BuyingDAOCoinCreatorPKID:                  m0PKID.PKID,
			SellingDAOCoinCreatorPKID:                 &ZeroPKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(10.0),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(1000),
			OperationType:                             DAOCoinLimitOrderOperationTypeASK,
		}

		// m1 sells 100 DAO coin base units @ 0.1 DAO coin / $DESO.
		m1Order = &DAOCoinLimitOrderEntry{
			TransactorPKID:                            m1PKID.PKID,
			BuyingDAOCoinCreatorPKID:                  &ZeroPKID,
			SellingDAOCoinCreatorPKID:                 m0PKID.PKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(0.1),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(100),
			OperationType:                             DAOCoinLimitOrderOperationTypeASK,
		}

		// m0 = transactor, m1 = matching order
		// m0 sells 1000 $DESO @ 10 $DESO / DAO coin.
		updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			err = utxoView._calculateDAOCoinsTransferredInLimitOrderMatch(m0Order, m1Order)
		require.NoError(err)
		require.Equal(updatedTransactorQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(updatedMatchingQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(transactorBuyingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(100))
		require.Equal(transactorSellingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(1000))

		// m1 = transactor, m0 = matching order
		// m1 sells 100 DAO coin base units @ 0.1 DAO coin / $DESO.
		updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			err = utxoView._calculateDAOCoinsTransferredInLimitOrderMatch(m1Order, m0Order)
		require.NoError(err)
		require.Equal(updatedTransactorQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(updatedMatchingQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(transactorBuyingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(1000))
		require.Equal(transactorSellingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(100))

		// Scenario 6: m0 and m1 both submit ASKs that match
		// 			   m1 gets a better price than expected
		// m0 sells 1000 $DESO @ 10 $DESO / DAO coin.
		m0Order = &DAOCoinLimitOrderEntry{
			TransactorPKID:                            m0PKID.PKID,
			BuyingDAOCoinCreatorPKID:                  m0PKID.PKID,
			SellingDAOCoinCreatorPKID:                 &ZeroPKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(10.0),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(1000),
			OperationType:                             DAOCoinLimitOrderOperationTypeASK,
		}

		// m1 sells 50 DAO coin units for 0.2 DAO coin / $DESO.
		m1Order = &DAOCoinLimitOrderEntry{
			TransactorPKID:                            m1PKID.PKID,
			BuyingDAOCoinCreatorPKID:                  &ZeroPKID,
			SellingDAOCoinCreatorPKID:                 m0PKID.PKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: CalculateScaledExchangeRate(0.2),
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(50),
			OperationType:                             DAOCoinLimitOrderOperationTypeASK,
		}

		// m0 = transactor, m1 = matching order
		// m0 sells 250 $DESO @ 5 $DESO / DAO coin.
		updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			err = utxoView._calculateDAOCoinsTransferredInLimitOrderMatch(m0Order, m1Order)
		require.NoError(err)
		require.Equal(updatedTransactorQuantityToFillInBaseUnits, uint256.NewInt().SetUint64(750))
		require.Equal(updatedMatchingQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(transactorBuyingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(50))
		require.Equal(transactorSellingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(250))

		// m1 = transactor, m0 = matching order
		// m1 sells 50 DAO coin units for 0.1 DAO coin / $DESO.
		updatedTransactorQuantityToFillInBaseUnits,
			updatedMatchingQuantityToFillInBaseUnits,
			transactorBuyingCoinBaseUnitsTransferred,
			transactorSellingCoinBaseUnitsTransferred,
			err = utxoView._calculateDAOCoinsTransferredInLimitOrderMatch(m1Order, m0Order)
		require.NoError(err)
		require.Equal(updatedTransactorQuantityToFillInBaseUnits, uint256.NewInt())
		require.Equal(updatedMatchingQuantityToFillInBaseUnits, uint256.NewInt().SetUint64(500))
		require.Equal(transactorBuyingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(500))
		require.Equal(transactorSellingCoinBaseUnitsTransferred, uint256.NewInt().SetUint64(50))
	}

	// TODO: add validation, no DAO coins in circulation for this profile
	// TODO: maybe test trying to buy more DAO coins than were minted.
	// TODO: test transfer restriction status

	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
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

	// There is some spend amount that may go to matching orders.
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

	// Convert *DAOCoinLimitOrderMetadata to *DAOCoinLimitOrderEntry.
	return &DAOCoinLimitOrderEntry{
		TransactorPKID:                            transactorPKID,
		BuyingDAOCoinCreatorPKID:                  toPKID(txnData.BuyingDAOCoinCreatorPublicKey),
		SellingDAOCoinCreatorPKID:                 toPKID(txnData.SellingDAOCoinCreatorPublicKey),
		ScaledExchangeRateCoinsToSellPerCoinToBuy: txnData.ScaledExchangeRateCoinsToSellPerCoinToBuy,
		QuantityToFillInBaseUnits:                 txnData.QuantityToFillInBaseUnits,
		OperationType:                             txnData.OperationType,
		BlockHeight:                               blockHeight,
	}
}
