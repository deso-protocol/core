package lib

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAtomicTxns(t *testing.T) {
	t.Run("TestAtomicTxns/FlushToDB=false", func(t *testing.T) {
		testAtomicTxns(t, false)
	})
	t.Run("TestAtomicTxns/FlushToDB=true", func(t *testing.T) {
		testAtomicTxns(t, true)
	})
}

func testAtomicTxns(t *testing.T, flushToDB bool) {
	setBalanceModelBlockHeights(t)

	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Mine a few blocks to give the senderPkString some money.
	for ii := 0; ii < 10; ii++ {
		_, err := miner.MineAndProcessSingleBlock(0, mempool)
		require.NoError(t, err)
	}

	testMeta := &TestMeta{
		t:                 t,
		chain:             chain,
		params:            params,
		db:                db,
		mempool:           mempool,
		miner:             miner,
		savedHeight:       chain.blockTip().Height + 1,
		feeRateNanosPerKb: uint64(101),
	}

	txns := []*MsgDeSoTxn{}
	for _, user := range []struct {
		recipientUsername  string
		recipientPublicKey string
		amount             uint64
	}{
		{
			recipientUsername:  "m0",
			recipientPublicKey: m0Pub,
			amount:             1e4,
		},
		{
			recipientUsername:  "m1",
			recipientPublicKey: m1Pub,
			amount:             1e6,
		},
	} {
		txns = append(txns, _assembleBasicTransferTxnFullySigned(
			t, chain, user.amount, 101, senderPkString, user.recipientPublicKey, senderPrivString, mempool))
	}

	atomicTxn, totalInput, totalOutput, fees, err := chain.CreateAtomicTxns(
		txns, testMeta.feeRateNanosPerKb, mempool)
	_, _, _ = totalInput, totalOutput, fees
	require.NoError(t, err)
	_submitAtomicTxnHappyPath(testMeta, atomicTxn, flushToDB)
	{

		bodyObj := &DeSoBodySchema{Body: "m0 post"}
		body, err := json.Marshal(bodyObj)
		require.NoError(t, err)
		m0PostTxn, _, _, _, err := chain.CreateSubmitPostTxn(
			m0PkBytes, nil, nil, body, nil, false, 100, nil, false, 101, mempool, nil)
		require.NoError(t, err)
		_signTxn(t, m0PostTxn, m0Priv)

		m1LikeTxn, _, _, _, err := chain.CreateLikeTxn(
			m1PkBytes, *m0PostTxn.Hash(), false, 101, mempool, nil)
		require.NoError(t, err)
		_signTxn(t, m1LikeTxn, m1Priv)
		// If m1's txn is first, this will fail.
		atomicTxn, totalInput, totalOutput, fees, err = chain.CreateAtomicTxns(
			[]*MsgDeSoTxn{m1LikeTxn, m0PostTxn}, testMeta.feeRateNanosPerKb, mempool)
		_, _, _ = totalInput, totalOutput, fees
		require.NoError(t, err)
		_, _, _, err = _submitAtomicTxn(testMeta, atomicTxn, flushToDB)
		require.Error(t, err)

		// If m0's txn is first, this will succeed.
		atomicTxn, totalInput, totalOutput, fees, err = chain.CreateAtomicTxns(
			[]*MsgDeSoTxn{m0PostTxn, m1LikeTxn}, testMeta.feeRateNanosPerKb, mempool)
		_, _, _ = totalInput, totalOutput, fees
		require.NoError(t, err)
		_submitAtomicTxnHappyPath(testMeta, atomicTxn, flushToDB)
	}

	// Flush mempool to the db and test rollbacks.
	require.NoError(t, mempool.universalUtxoView.FlushToDb(uint64(testMeta.savedHeight+1)))
	_executeAllTestRollbackAndFlush(testMeta)
	// TODO: more testing plz.
}

func _submitAtomicTxn(
	testMeta *TestMeta,
	txn *MsgDeSoTxn,
	flushToDB bool,
) ([]*UtxoOperation, *MsgDeSoTxn, uint32, error) {
	utxoOps, _, _, _, err := testMeta.mempool.universalUtxoView.ConnectTransaction(
		txn, txn.Hash(), getTxnSize(*txn), testMeta.savedHeight, 0, true, false)
	if err != nil {
		return nil, nil, 0, err
	}

	if flushToDB {
		require.NoError(testMeta.t, testMeta.mempool.universalUtxoView.FlushToDb(uint64(testMeta.savedHeight+1)))
	}

	require.NoError(testMeta.t, testMeta.mempool.RegenerateReadOnlyView())
	return utxoOps, txn, testMeta.savedHeight, nil
}

func _submitAtomicTxnHappyPath(
	testMeta *TestMeta,
	txn *MsgDeSoTxn,
	flushToDB bool,
) {
	if txn.TxnMeta.GetTxnType() != TxnTypeAtomicTxns {
		testMeta.t.Fatal("Expected atomic swap txn")
	}

	var totalBalance uint64
	for _, innerTxn := range txn.TxnMeta.(*AtomicTxnsMetadata).Txns {
		totalBalance += _getBalance(
			testMeta.t, testMeta.chain, testMeta.mempool,
			Base58CheckEncode(innerTxn.PublicKey, false, testMeta.params))
	}
	testMeta.expectedSenderBalances = append(testMeta.expectedSenderBalances, totalBalance)

	currentOps, currentTxn, _, err := _submitAtomicTxn(testMeta, txn, flushToDB)
	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}
