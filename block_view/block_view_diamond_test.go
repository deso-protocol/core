package block_view

import (
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/deso-protocol/core/network"
	"github.com/deso-protocol/core/types"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDeSoDiamonds(t *testing.T) {
	types.DeSoDiamondsBlockHeight = 0
	diamondValueMap := lib.GetDeSoNanosDiamondLevelMapAtBlockHeight(0)

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := lib.NewLowDifficultyBlockchain()
	mempool, miner := lib.NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3, m4 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true
	params.ParamUpdaterPublicKeys[MakePkMapKey(m4PkBytes)] = true

	// Mine a few blocks to give the senderPkString some money.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	// We build the testMeta obj after mining blocks so that we save the correct block height.
	testMeta := &TestMeta{
		t:           t,
		chain:       chain,
		params:      params,
		db:          db,
		mempool:     mempool,
		miner:       miner,
		savedHeight: chain.blockTip().Height + 1,
	}

	// Fund all the keys.
	_registerOrTransferWithTestMeta(testMeta, "", lib.senderPkString, m0Pub, lib.senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", lib.senderPkString, m1Pub, lib.senderPrivString, 1000000000)
	_registerOrTransferWithTestMeta(testMeta, "", lib.senderPkString, m2Pub, lib.senderPrivString, 1000000000)

	// Get PKIDs for looking up diamond entries.
	m0PkBytes, _, err := types.Base58CheckDecode(m0Pub)
	require.NoError(err)
	m0PKID := db.DBGetPKIDEntryForPublicKey(db, m0PkBytes)

	m1PkBytes, _, err := types.Base58CheckDecode(m1Pub)
	require.NoError(err)
	m1PKID := db.DBGetPKIDEntryForPublicKey(db, m1PkBytes)

	m2PkBytes, _, err := types.Base58CheckDecode(m2Pub)
	require.NoError(err)
	m2PKID := db.DBGetPKIDEntryForPublicKey(db, m2PkBytes)
	_ = m2PKID

	validateDiamondEntry := func(
		senderPKID *types.PKID, receiverPKID *types.PKID, diamondPostHash *types.BlockHash, diamondLevel int64) {

		diamondEntry := db.DbGetDiamondMappings(db, receiverPKID, senderPKID, diamondPostHash)

		if diamondEntry == nil && diamondLevel > 0 {
			t.Errorf("validateDiamondEntry: couldn't find diamond entry for diamondLevel %d", diamondLevel)
		} else if diamondEntry == nil && diamondLevel == 0 {
			// If diamondLevel is set to zero, we are checking that diamondEntry is nil.
			return
		}

		require.Equal(diamondEntry.DiamondLevel, diamondLevel)
	}

	// Create a post for testing.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,       /*feeRateNanosPerKB*/
			m0Pub,    /*updaterPkBase58Check*/
			m0Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&network.DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-1].Hash()
	_ = post1Hash

	// Have m1 give the post a diamond.
	{
		// Balances before.
		m0BalBeforeNFT := lib._getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999), m0BalBeforeNFT)
		m1BalBeforeNFT := lib._getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 0)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 1)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 1)

		// Balances after.
		m0BalAfterNFT := lib._getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[1]), m0BalAfterNFT)
		m1BalAfterNFT := lib._getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[1]-2), m1BalAfterNFT)
	}

	// Upgrade the post from 1 -> 2 diamonds.
	{
		// Balances before.
		m0BalBeforeNFT := lib._getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[1]), m0BalBeforeNFT)
		m1BalBeforeNFT := lib._getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[1]-2), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 1)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 2)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 2)

		// Balances after.
		m0BalAfterNFT := lib._getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[2]), m0BalAfterNFT)
		m1BalAfterNFT := lib._getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[2]-4), m1BalAfterNFT)
	}

	// Upgrade the post from 2 -> 3 diamonds.
	{
		// Balances before.
		m0BalBeforeNFT := lib._getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[2]), m0BalBeforeNFT)
		m1BalBeforeNFT := lib._getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[2]-4), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 2)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 3)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 3)

		// Balances after.
		m0BalAfterNFT := lib._getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[3]), m0BalAfterNFT)
		m1BalAfterNFT := lib._getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[3]-6), m1BalAfterNFT)
	}

	// Upgrade the post from 3 -> 4 diamonds.
	{
		// Balances before.
		m0BalBeforeNFT := lib._getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[3]), m0BalBeforeNFT)
		m1BalBeforeNFT := lib._getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[3]-6), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 3)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 4)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 4)

		// Balances after.
		m0BalAfterNFT := lib._getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[4]), m0BalAfterNFT)
		m1BalAfterNFT := lib._getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[4]-8), m1BalAfterNFT)
	}

	// Upgrade the post from 4 -> 5 diamonds.
	{
		// Balances before.
		m0BalBeforeNFT := lib._getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[4]), m0BalBeforeNFT)
		m1BalBeforeNFT := lib._getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[4]-8), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 4)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 5)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 5)

		// Balances after.
		m0BalAfterNFT := lib._getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[5]), m0BalAfterNFT)
		m1BalAfterNFT := lib._getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[5]-10), m1BalAfterNFT)
	}

	// Have m2 give the post 5 diamonds right off the bat.
	{
		// Balances before.
		m0BalBeforeNFT := lib._getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[5]), m0BalBeforeNFT)
		m2BalBeforeNFT := lib._getBalance(t, chain, nil, m2Pub)
		require.Equal(uint64(1e9), m2BalBeforeNFT)

		validateDiamondEntry(m2PKID.PKID, m0PKID.PKID, post1Hash, 0)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m2Pub, m2Priv, post1Hash, 5)
		validateDiamondEntry(m2PKID.PKID, m0PKID.PKID, post1Hash, 5)

		// Balances after.
		m0BalAfterNFT := lib._getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[5]+diamondValueMap[5]), m0BalAfterNFT)
		m2BalAfterNFT := lib._getBalance(t, chain, nil, m2Pub)
		require.Equal(uint64(1e9-diamondValueMap[5]-2), m2BalAfterNFT)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestDeSoDiamondErrorCases(t *testing.T) {
	types.DeSoDiamondsBlockHeight = 0
	diamondValueMap := lib.GetDeSoNanosDiamondLevelMapAtBlockHeight(0)

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := lib.NewLowDifficultyBlockchain()
	mempool, miner := lib.NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3, m4 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true
	params.ParamUpdaterPublicKeys[MakePkMapKey(m4PkBytes)] = true

	// Mine a few blocks to give the senderPkString some money.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	// We build the testMeta obj after mining blocks so that we save the correct block height.
	testMeta := &TestMeta{
		t:           t,
		chain:       chain,
		params:      params,
		db:          db,
		mempool:     mempool,
		miner:       miner,
		savedHeight: chain.blockTip().Height + 1,
	}

	// Fund all the keys.
	_registerOrTransferWithTestMeta(testMeta, "", lib.senderPkString, m0Pub, lib.senderPrivString, 1000000000)
	_registerOrTransferWithTestMeta(testMeta, "", lib.senderPkString, m1Pub, lib.senderPrivString, 1000000000)

	// Since the "CreateBasicTransferTxnWithDiamonds()" function in blockchain.go won't let us
	// trigger most errors that we want to check, we create another version of the function here
	// that allows us to put together whatever type of broken txn we want.
	_giveCustomDeSoDiamondTxn := func(
		senderPkBase58Check string, senderPrivBase58Check string, receiverPkBase58Check string,
		diamondPostHashBytes []byte, diamondLevel int64, amountNanos uint64) (_err error) {

		senderPkBytes, _, err := types.Base58CheckDecode(senderPkBase58Check)
		require.NoError(err)

		receiverPkBytes, _, err := types.Base58CheckDecode(receiverPkBase58Check)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		// Build the basic transfer txn.
		txn := &network.MsgDeSoTxn{
			PublicKey: senderPkBytes,
			TxnMeta:   &network.BasicTransferMetadata{},
			TxOutputs: []*network.DeSoOutput{
				{
					PublicKey:   receiverPkBytes,
					AmountNanos: amountNanos,
				},
			},
			// TxInputs and TxOutputs will be set below.
			// This function does not compute a signature.
		}

		// Make a map for the diamond extra data and add it.
		diamondsExtraData := make(map[string][]byte)
		diamondsExtraData[types.DiamondLevelKey] = network.IntToBuf(diamondLevel)
		diamondsExtraData[types.DiamondPostHashKey] = diamondPostHashBytes
		txn.ExtraData = diamondsExtraData

		// We don't need to make any tweaks to the amount because it's basically
		// a standard "pay per kilobyte" transaction.
		totalInput, _, _, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, mempool)
		if err != nil {
			return errors.Wrapf(
				err, "giveCustomDeSoDiamondTxn: Problem adding inputs: ")
		}

		// We want our transaction to have at least one input, even if it all
		// goes to change. This ensures that the transaction will not be "replayable."
		if len(txn.TxInputs) == 0 {
			return fmt.Errorf(
				"giveCustomDeSoDiamondTxn: BasicTransfer txn must have at" +
					" least one input but had zero inputs instead. Try increasing the fee rate.")
		}

		// Sign the transaction now that its inputs are set up.
		lib._signTxn(t, txn, senderPrivBase58Check)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		utxoOps, totalInput, totalOutput, fees, err :=
			utxoView.ConnectTransaction(
				txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		if err != nil {
			return err
		}
		require.Equal(t, totalInput, totalOutput+fees)

		// We should have one SPEND UtxoOperation for each input, one ADD operation
		// for each output, and one OperationTypeDeSoDiamond operation at the end.
		require.Equal(t, len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(t, OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		require.Equal(OperationTypeDeSoDiamond, utxoOps[len(utxoOps)-1].Type)

		require.NoError(utxoView.FlushToDb())

		return nil
	}

	// Error case: PostHash with bad length.
	{
		err := _giveCustomDeSoDiamondTxn(
			m0Pub,
			m0Priv,
			m1Pub,
			db.RandomBytes(types.HashSizeBytes-1),
			1,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), types.RuleErrorBasicTransferDiamondInvalidLengthForPostHashBytes)
	}

	// Error case: non-existent post.
	{
		err := _giveCustomDeSoDiamondTxn(
			m0Pub,
			m0Priv,
			m1Pub,
			db.RandomBytes(types.HashSizeBytes),
			1,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), types.RuleErrorBasicTransferDiamondPostEntryDoesNotExist)
	}

	// Create a post for testing.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,       /*feeRateNanosPerKB*/
			m0Pub,    /*updaterPkBase58Check*/
			m0Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&network.DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-1].Hash()
	_ = post1Hash

	// Error case: cannot diamond yourself.
	{
		err := _giveCustomDeSoDiamondTxn(
			m0Pub,
			m0Priv,
			m1Pub,
			post1Hash[:],
			1,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), types.RuleErrorBasicTransferDiamondCannotTransferToSelf)
	}

	// Error case: don't include diamond level.
	{
		_, _, _, err := _giveDeSoDiamonds(
			t, chain, db, params,
			10,
			m1Pub,
			m1Priv,
			post1Hash,
			1,
			true, /*deleteDiamondLevel*/
		)
		require.Error(err)
		require.Contains(err.Error(), types.RuleErrorBasicTransferHasDiamondPostHashWithoutDiamondLevel)
	}

	// Error case: invalid diamond level.
	{
		err := _giveCustomDeSoDiamondTxn(
			m1Pub,
			m1Priv,
			m0Pub,
			post1Hash[:],
			-1,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), types.RuleErrorBasicTransferHasInvalidDiamondLevel)
	}

	// Error case: insufficient deso.
	{
		err := _giveCustomDeSoDiamondTxn(
			m1Pub,
			m1Priv,
			m0Pub,
			post1Hash[:],
			2,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), types.RuleErrorBasicTransferInsufficientDeSoForDiamondLevel)
	}
}
