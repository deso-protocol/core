package lib

import (
	"bytes"
	"github.com/dgraph-io/badger/v3"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDAOCoinLimitOrder(t *testing.T) {
	const FEE_RATE_NANOS_PER_KB = 10
	require := require.New(t)

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true)
	// Make m3 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true
	params.ForkHeights.DAOCoinBlockHeight = uint32(0)
	params.ForkHeights.DAOCoinLimitOrderBlockHeight = uint32(0)

	// Mine a few blocks to give the senderPkString some money.
	_, err := miner.MineAndProcessSingleBlock(0, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0, mempool)
	require.NoError(err)

	// We take the block tip to be the blockchain height rather than the
	// header chain height.
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

	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 70)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 420)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 140)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 210)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 100)

	m0PKID := DBGetPKIDEntryForPublicKey(db, m0PkBytes)
	m1PKID := DBGetPKIDEntryForPublicKey(db, m1PkBytes)
	m2PKID := DBGetPKIDEntryForPublicKey(db, m2PkBytes)
	m4PKID := DBGetPKIDEntryForPublicKey(db, m4PkBytes)

	_, _, _, _ = m0PKID, m1PKID, m2PKID, m4PKID

	metadataM0 := DAOCoinLimitOrderMetadata{
		DenominatedCoinType:          DAOCoinLimitOrderEntryDenominatedCoinTypeDESO,
		DenominatedCoinCreatorPKID:   &ZeroPKID,
		DAOCoinCreatorPKID:           m0PKID.PKID,
		OperationType:                DAOCoinLimitOrderEntryOrderTypeBid,
		PriceNanosPerDenominatedCoin: uint256.NewInt().SetUint64(10),
		Quantity:                     uint256.NewInt().SetUint64(100),
	}

	// RuleErrorDAOCoinLimitOrderDAOCoinCreatorMissingProfile
	{
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, FEE_RATE_NANOS_PER_KB, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderDAOCoinCreatorMissingProfile)
	}

	// Create a profile for m0.
	{
		_updateProfileWithTestMeta(
			testMeta,
			FEE_RATE_NANOS_PER_KB, /*feeRateNanosPerKB*/
			m0Pub,                 /*updaterPkBase58Check*/
			m0Priv,                /*updaterPrivBase58Check*/
			[]byte{},              /*profilePubKey*/
			"m0",                  /*newUsername*/
			"i am the m0",         /*newDescription*/
			shortPic,              /*newProfilePic*/
			10*100,                /*newCreatorBasisPoints*/
			1.25*100*100,          /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// RuleErrorDAOCoinLimitOrderInsufficientDESOToOpenBidOrder
	{
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, FEE_RATE_NANOS_PER_KB, m0Pub, m0Priv, metadataM0)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorDAOCoinLimitOrderInsufficientDESOToOpenBidOrder)
	}

	// Update quantity and resubmit. Should go through.
	{
		metadataM0.Quantity = uint256.NewInt().SetUint64(2)
		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, FEE_RATE_NANOS_PER_KB, m0Pub, m0Priv, metadataM0)

		queryEntry := metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight)
		resultEntry := DBGetDAOCoinLimitOrder(db, queryEntry, false)

		require.NotNil(resultEntry)
		queryEntryBytes, err := queryEntry.ToBytes()
		require.NoError(err)

		resultEntryBytes, err := resultEntry.ToBytes()
		require.NoError(err)

		require.True(bytes.Equal(queryEntryBytes, resultEntryBytes))
	}

	// Mint DAO coins and transfer to M1.
	{
		daoCoinMintMetadata := DAOCoinMetadata{
			ProfilePublicKey: m0PkBytes,
			OperationType:    DAOCoinOperationTypeMint,
			CoinsToMintNanos: *uint256.NewInt().SetUint64(1e4),
		}

		_daoCoinTxnWithTestMeta(testMeta, FEE_RATE_NANOS_PER_KB, m0Pub, m0Priv, daoCoinMintMetadata)

		daoCoinTransferMetadata := DAOCoinTransferMetadata{
			ProfilePublicKey:       m0PkBytes,
			DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(2),
			ReceiverPublicKey:      m1PkBytes,
		}

		_daoCoinTransferTxnWithTestMeta(testMeta, FEE_RATE_NANOS_PER_KB, m0Pub, m0Priv, daoCoinTransferMetadata)
	}

	// Submit matching order and confirm matching happy path.
	{
		originalM0DAOCoinBalance := DbGetBalanceEntry(db, m0PKID.PKID, m0PKID.PKID, true)
		originalM1DAOCoinBalance := DbGetBalanceEntry(db, m1PKID.PKID, m0PKID.PKID, true)
		daoCoinQuantityChange := uint256.NewInt().SetUint64(2)

		metadataM1 := DAOCoinLimitOrderMetadata{
			DenominatedCoinType:          DAOCoinLimitOrderEntryDenominatedCoinTypeDESO,
			DenominatedCoinCreatorPKID:   &ZeroPKID,
			DAOCoinCreatorPKID:           m0PKID.PKID,
			OperationType:                DAOCoinLimitOrderEntryOrderTypeAsk,
			PriceNanosPerDenominatedCoin: uint256.NewInt().SetUint64(10),
			Quantity:                     daoCoinQuantityChange,
		}

		_doDAOCoinLimitOrderTxnWithTestMeta(testMeta, FEE_RATE_NANOS_PER_KB, m1Pub, m1Priv, metadataM1)

		updatedM0DAOCoinBalance := DbGetBalanceEntry(db, m0PKID.PKID, m0PKID.PKID, true)
		updatedM1DAOCoinBalance := DbGetBalanceEntry(db, m1PKID.PKID, m0PKID.PKID, true)

		// M0's BID order is fulfilled so his DAO coin balance increases.
		require.Equal(
			*uint256.NewInt().Add(&originalM0DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
			updatedM0DAOCoinBalance.BalanceNanos)

		// M1's ASK order is fulfilled so his DAO coin balance decreases.
		require.Equal(
			*uint256.NewInt().Sub(&originalM1DAOCoinBalance.BalanceNanos, daoCoinQuantityChange),
			updatedM1DAOCoinBalance.BalanceNanos)

		// Both orders are deleted from the order book.
		askOrderEntry := DBGetDAOCoinLimitOrder(db, metadataM0.ToEntry(m0PKID.PKID, testMeta.savedHeight), false)
		require.Nil(askOrderEntry)

		bidOrderEntry := DBGetDAOCoinLimitOrder(db, metadataM1.ToEntry(m1PKID.PKID, testMeta.savedHeight), false)
		require.Nil(bidOrderEntry)
	}

	// TODO: add validation, no DAO coins in circulation for this profile
	// TODO: maybe test trying to buy more DAO coins than were minted.
	// TODO: partially fulfilled orders
	// TODO: two bid orders, different prices, choose high priced one
	// TODO: two ask orders, different prices, choose lower priced one
	// TODO: what if someone submits order that matches their own order.
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

	utxoView, err := NewUtxoView(db, params, nil)
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

	require.Equal(totalInputMake, changeAmountMake+feesMake)

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
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeDAOCoinLimitOrder, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}
