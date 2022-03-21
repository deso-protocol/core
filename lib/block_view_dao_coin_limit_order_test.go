package lib

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"testing"
)

// Scenarios
//
// Scenario: fulfilled orders, matching price and quantity
// m0 submits BID order for 2 DAO coins @ 10/1e9 $DESO.
// m1 submits ASK order for 2 DAO coins @ 10/1e9 $DESO.
// Orders fulfilled for 2 DAO coins @ 10/1e9 $DESO.
//
// Scenario: partially fulfilled orders sorting by best price
// m1 submits ASK order for 1 DAO coin @ 12/1e9 $DESO.
// m1 submits ASK order for 1 DAO coin @ 12/1e9 $DESO.
// Quantity is updated and only one order persists.
// m1 submits ASK order for 2 DAO coins @ 11/1e9 $DESO.
// m0 submits BID order for 3 DAO coins @ 15/1e9 $DESO.
// Orders partially fulfilled for 2 DAO coins @ 11/1e9 $DESO and 1 DAO coin @ 12/1e9 $DESO.
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
	_, _ = m2PKID, m4PKID

	// -----------------------
	// Tests
	// -----------------------

	// Construct metadata for a m0 ASK order denominated in
	// $DESO and selling DAO coins minted by m0.
	metadataM0 := DAOCoinLimitOrderMetadata{
		DenominatedCoinType:          DAOCoinLimitOrderEntryDenominatedCoinTypeDESO,
		DenominatedCoinCreatorPKID:   &ZeroPKID,
		DAOCoinCreatorPKID:           m0PKID.PKID,
		OperationType:                DAOCoinLimitOrderEntryOrderTypeBid,
		PriceNanosPerDenominatedCoin: uint256.NewInt().SetUint64(NanosPerUnit / 10),
		Quantity:                     uint256.NewInt().SetUint64(100),
	}

	// RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType: DAO coin
	{
		originalValue := metadataM0.DenominatedCoinType
		metadataM0.DenominatedCoinType = DAOCoinLimitOrderEntryDenominatedCoinTypeDAOCoin

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType)
		metadataM0.DenominatedCoinType = originalValue
	}

	// RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType: nonexistent
	{
		originalValue := metadataM0.DenominatedCoinType
		metadataM0.DenominatedCoinType = 99

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderUnsupportedDenominatedCoinType)
		metadataM0.DenominatedCoinType = originalValue
	}

	// RuleErrorDAOCoinLimitOrderInvalidDenominatedCoinCreatorPKID: non-zero PKID
	{
		originalValue := metadataM0.DenominatedCoinCreatorPKID
		metadataM0.DenominatedCoinCreatorPKID = m0PKID.PKID

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInvalidDenominatedCoinCreatorPKID)
		metadataM0.DenominatedCoinCreatorPKID = originalValue
	}

	// RuleErrorDAOCoinLimitOrderDAOCoinCreatorMissingProfile
	{
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderDAOCoinCreatorMissingProfile)
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

	// RuleErrorDAOCoinLimitOrderUnsupportedOperationType: nonexistent
	{
		originalValue := metadataM0.OperationType
		metadataM0.OperationType = 99

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderUnsupportedOperationType)
		metadataM0.OperationType = originalValue
	}

	// RuleErrorDAOCoinLimitOrderInvalidPrice: zero
	{
		originalValue := metadataM0.PriceNanosPerDenominatedCoin
		metadataM0.PriceNanosPerDenominatedCoin = uint256.NewInt()

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInvalidPrice)
		metadataM0.PriceNanosPerDenominatedCoin = originalValue
	}

	// RuleErrorDAOCoinLimitOrderInvalidQuantity: zero
	{
		originalValue := metadataM0.Quantity
		metadataM0.Quantity = uint256.NewInt().SetUint64(0)

		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInvalidQuantity)
		metadataM0.Quantity = originalValue
	}

	// RuleErrorDAOCoinLimitOrderInsufficientDESOToOpenBidOrder
	{
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInsufficientDESOToOpenBidOrder)
	}

	// Store how many DAO coins will be transferred.
	daoCoinQuantityChange := uint256.NewInt().SetUint64(2)

	// Update quantity and resubmit. m0's BID order should be stored.
	{
		// Confirm no existing limit orders.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Empty(orderEntries)

		// Perform txn.
		metadataM0.Quantity = daoCoinQuantityChange
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		// Confirm 1 existing limit order, and it's from m0.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight)))
	}

	// Construct metadata for a m1 BID order denominated in
	// $DESO and buying DAO coins minted by m0.
	metadataM1 := *metadataM0.Copy()
	metadataM1.OperationType = DAOCoinLimitOrderEntryOrderTypeAsk
	metadataM1.Quantity = daoCoinQuantityChange

	// RuleErrorDAOCoinLimitOrderInsufficientDAOCoinsToOpenAskOrder
	{
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, feeRateNanosPerKb, m0Pub, m0Priv, metadataM1)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInsufficientDAOCoinsToOpenAskOrder)
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

	// Submit matching order and confirm matching happy path.
	{
		// Confirm 1 existing limit order, and it's from m0.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight)))

		// Store original $DESO balances to check diffs.
		originalM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
		originalM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)

		// Store original DAO coin balances to check diffs.
		originalM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
		originalM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)

		// Perform txn.
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)

		// Calculate updated $DESO balances.
		updatedM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
		updatedM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)

		// Calculate updated DAO coin balances.
		updatedM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
		updatedM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)

		// Calculate total cost of order to compare to changes in $DESO.
		totalOrderCost, err := _getTotalCostFromQuantityAndPriceNanosPerDenominatedCoin(
			metadataM0.Quantity,
			metadataM1.PriceNanosPerDenominatedCoin)

		require.NoError(err)

		// m0's BID order is fulfilled so his DESO balance decreases and his DAO coin balance increases.
		require.Equal(
			originalM0DESOBalance-totalOrderCost.Uint64(),
			updatedM0DESOBalance)

		require.Equal(
			*uint256.NewInt().Add(&originalM0DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
			updatedM0DAOCoinBalance.BalanceNanos)

		// m1's ASK order is fulfilled so his DESO balance increases and his DAO coin balance decreases.
		require.Equal(
			originalM1DESOBalance+totalOrderCost.Uint64()-uint64(3), // TODO: calculate gas fee instead of hard-coding.
			updatedM1DESOBalance)

		require.Equal(
			*uint256.NewInt().Sub(&originalM1DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
			updatedM1DAOCoinBalance.BalanceNanos)

		// Both orders are deleted from the order book.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Empty(orderEntries)
	}

	// Scenario: partially fulfilled orders sorting by best price
	// m1 submits ASK order for 1 DAO coin @ 12/1e9 $DESO.
	// m1 submits ASK order for 1 DAO coin @ 12/1e9 $DESO.
	// Quantity is updated instead of creating a new limit order.
	// m1 submits ASK order for 2 DAO coins @ 11/1e9 $DESO.
	// m0 submits BID order for 3 DAO coins @ 15/1e9 $DESO.
	// Orders partially fulfilled for 2 DAO coins @ 11/1e9 $DESO and 1 DAO coin @ 12/1e9 $DESO.
	{
		// Confirm no existing limit orders.
		orderEntries, err := dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Empty(orderEntries)

		// m1 submits ASK order for 1 DAO coin @ 12/1e9 $DESO.
		metadataM1.PriceNanosPerDenominatedCoin = uint256.NewInt().SetUint64(NanosPerUnit / 12)
		metadataM1.Quantity = uint256.NewInt().SetUint64(1)
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)

		// Confirm 1 existing limit order, and it's from m1.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		require.True(orderEntries[0].Eq(metadataM1.ToEntry(m1PKID.PKID, testMeta.savedHeight)))

		// m1 submits ASK order for 1 DAO coin @ 12/1e9 $DESO.
		// Quantity is updated and only one order persists.
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)

		// Confirm 1 existing limit order, and it's m1's with an updated quantity of 2.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		metadataM1.Quantity = uint256.NewInt().SetUint64(2)
		require.True(orderEntries[0].Eq(metadataM1.ToEntry(m1PKID.PKID, testMeta.savedHeight)))

		// m1 submits ASK order for 2 DAO coins @ 11/1e9 $DESO.
		metadataM1.PriceNanosPerDenominatedCoin = uint256.NewInt().SetUint64(NanosPerUnit / 11)
		metadataM1.Quantity = uint256.NewInt().SetUint64(2)
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m1Pub, m1Priv, metadataM1)

		// Confirm 2 existing limit orders.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 2)

		// m0 submits BID order for 3 DAO coins @ 15/1e9 $DESO.
		// Store original $DESO balances to check diffs.
		originalM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
		originalM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)

		// Store original DAO coin balances to check diffs.
		originalM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
		originalM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)

		// Construct metadata for m0's BID order.
		metadataM0.PriceNanosPerDenominatedCoin = uint256.NewInt().SetUint64(NanosPerUnit / 15)
		metadataM0.Quantity = uint256.NewInt().SetUint64(3)

		// Confirm matching limit orders exist.
		orderEntries, err = dbAdapter.GetMatchingDAOCoinLimitOrders(
			metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight), nil)

		require.NoError(err)
		require.Equal(len(orderEntries), 2)

		// Perform txn.
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, feeRateNanosPerKb, m0Pub, m0Priv, metadataM0)

		// Calculate updated $DESO balances.
		updatedM0DESOBalance := _getBalance(t, chain, mempool, m0Pub)
		updatedM1DESOBalance := _getBalance(t, chain, mempool, m1Pub)

		// Calculate updated DAO coin balances.
		updatedM0DAOCoinBalance := dbAdapter.GetBalanceEntry(m0PKID.PKID, m0PKID.PKID, true)
		updatedM1DAOCoinBalance := dbAdapter.GetBalanceEntry(m1PKID.PKID, m0PKID.PKID, true)

		// Orders partially fulfilled for 2 DAO coins @ 11/1e9 $DESO and 1 DAO coin @ 12/1e9 $DESO.
		daoCoinQuantityChange = uint256.NewInt().SetUint64(3)

		// Calculate total cost of order to compare to changes in $DESO.
		// 2 DAO coins @ 11/1e9 $DESO
		subOrderCost1, err := _getTotalCostFromQuantityAndPriceNanosPerDenominatedCoin(
			uint256.NewInt().SetUint64(2),
			uint256.NewInt().SetUint64(NanosPerUnit/11))

		require.NoError(err)

		// 1 DAO coin @ 12/1e9 $DESO
		subOrderCost2, err := _getTotalCostFromQuantityAndPriceNanosPerDenominatedCoin(
			uint256.NewInt().SetUint64(1),
			uint256.NewInt().SetUint64(NanosPerUnit/12))

		require.NoError(err)
		totalOrderCost := uint256.NewInt().Add(subOrderCost1, subOrderCost2)

		// m0's BID order is fulfilled so his DESO balance decreases and his DAO coin balance increases.
		require.Equal(
			originalM0DESOBalance-totalOrderCost.Uint64()-uint64(2), // TODO: calculate gas fee instead of hard-coding.
			updatedM0DESOBalance)

		require.Equal(
			*uint256.NewInt().Add(&originalM0DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
			updatedM0DAOCoinBalance.BalanceNanos)

		// m1's ASK orders are fulfilled so his DESO balance increases and his DAO coin balance decreases.
		require.Equal(
			originalM1DESOBalance+totalOrderCost.Uint64(),
			updatedM1DESOBalance)

		require.Equal(
			*uint256.NewInt().Sub(&originalM1DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
			updatedM1DAOCoinBalance.BalanceNanos)

		// The correct orders are removed from the order book.
		// m0's BID order for 3 DAO coins @ 15/1e9 $DESO is fulfilled.
		// m1's ASK order for 2 DAO coins @ 11/1e9 $DESO is fulfilled.
		// m1's ASK order for 2 DAO coins @ 12/1e9 $DESO is partially fulfilled w/ 1 DAO coin remaining.
		orderEntries, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Equal(len(orderEntries), 1)
		metadataM1.PriceNanosPerDenominatedCoin = uint256.NewInt().SetUint64(NanosPerUnit / 12)
		metadataM1.Quantity = uint256.NewInt().SetUint64(1)
		require.True(orderEntries[0].Eq(metadataM1.ToEntry(m1PKID.PKID, testMeta.savedHeight)))
	}

	// TODO: add validation, no DAO coins in circulation for this profile
	// TODO: maybe test trying to buy more DAO coins than were minted.
	// TODO: partially fulfilled orders
	// TODO: two bid orders, different prices, choose high priced one
	// TODO: two ask orders, different prices, choose lower priced one
	// TODO: what if someone submits order that matches their own order.

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
