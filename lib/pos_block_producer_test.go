package lib

import (
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
)

func TestGetBlockTransactions(t *testing.T) {
	require := require.New(t)
	seed := int64(381)
	rand := rand.New(rand.NewSource(seed))
	passingTransactions := 50
	failingTransactions := 30
	invalidTransactions := 10
	m1InitialBalance := uint64(20000)

	globalParams := _testGetDefaultGlobalParams()
	feeMin := globalParams.MinimumNetworkFeeNanosPerKB
	feeMax := uint64(2000)

	chain, params, db := NewLowDifficultyBlockchain(t)
	params.ForkHeights.BalanceModelBlockHeight = 1
	params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 1
	oldPool, miner := NewTestMiner(t, chain, params, true)
	// Mine a few blocks to give the senderPkString some money.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, oldPool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, oldPool)
	require.NoError(err)

	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	m0PublicKeyBase58Check := Base58CheckEncode(m0PubBytes, false, params)
	m1PubBytes, _, _ := Base58CheckDecode(m1Pub)
	m1PublicKeyBase58Check := Base58CheckEncode(m1PubBytes, false, params)

	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, senderPkString, m0PublicKeyBase58Check,
		senderPrivString, 200000, 11)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, senderPkString, m1PublicKeyBase58Check,
		senderPrivString, m1InitialBalance, 11)

	latestBlockView, err := NewUtxoView(db, params, nil, nil)
	require.NoError(err)
	dir := _dbDirSetup(t)

	mempool := NewPosMempool(params, globalParams, latestBlockView, 2, dir, false)
	require.NoError(mempool.Start())
	defer mempool.Stop()
	require.True(mempool.IsRunning())

	// First test happy path with a bunch of passing transactions.
	passingTxns := []*MsgDeSoTxn{}
	totalUtilityFee := uint64(0)
	for ii := 0; ii < passingTransactions; ii++ {
		txn := _generateTestTxn(t, rand, feeMin, feeMax, m0PubBytes, m0Priv, 100, 20)
		passingTxns = append(passingTxns, txn)
		_, utilityFee := computeBMF(txn.TxnFeeNanos)
		totalUtilityFee += utilityFee
		_wrappedPosMempoolAddTransaction(t, mempool, txn)
	}

	pbp := NewPosBlockProducer(mempool, params)
	latestBlockViewCopy, err := latestBlockView.CopyUtxoView()
	require.NoError(err)
	txns, txnConnectStatus, txnTimestamps, maxUtilityFee, err := pbp.getBlockTransactions(latestBlockView, 3, 10000)
	require.NoError(err)
	require.Equal(latestBlockViewCopy, latestBlockView)
	require.Equal(len(passingTxns), len(txns))
	require.Equal(len(passingTxns), txnConnectStatus.Size())
	require.Equal(len(passingTxns), len(txnTimestamps))
	require.Equal(maxUtilityFee, totalUtilityFee)
	for ii := range txns {
		require.True(txnConnectStatus.Get(ii))
	}

	// Now test the case where we have a bunch of transactions that don't pass.
	// A failing transaction will try to send an excessive balance in a basic transfer.
	failingTxns := []*MsgDeSoTxn{}
	for ii := 0; ii < failingTransactions; ii++ {
		failingTxn := _generateTestTxn(t, rand, feeMin, feeMax, m0PubBytes, m0Priv, 100, 20)
		failingTxn.TxOutputs = append(failingTxn.TxOutputs, &DeSoOutput{
			PublicKey:   m1PubBytes,
			AmountNanos: 1e10,
		})
		_signTxn(t, failingTxn, m0Priv)
		effectiveFee := failingTxn.TxnFeeNanos * globalParams.FailingTransactionBMFRateBasisPoints / 10000
		_, utilityFee := computeBMF(effectiveFee)
		totalUtilityFee += utilityFee
		failingTxns = append(failingTxns, failingTxn)
		_wrappedPosMempoolAddTransaction(t, mempool, failingTxn)
	}

	latestBlockViewCopy, err = latestBlockView.CopyUtxoView()
	require.NoError(err)
	txns, txnConnectStatus, txnTimestamps, maxUtilityFee, err = pbp.getBlockTransactions(latestBlockView, 3, 50000)
	require.NoError(err)
	require.Equal(latestBlockViewCopy, latestBlockView)
	require.Equal(len(passingTxns)+len(failingTxns), len(txns))
	require.Equal(len(passingTxns)+len(failingTxns), len(txnTimestamps))
	require.Equal(maxUtilityFee, totalUtilityFee)
	totalConnected := 0
	for ii := range txns {
		if txnConnectStatus.Get(ii) {
			totalConnected++
		} else {
			require.Equal(1, len(txns[ii].TxOutputs))
		}
	}
	require.Equal(len(passingTxns), totalConnected)

	// We will now test some invalid transactions, which make it in the mempool, yet will not connect to utxo view,
	// nor as failing transactions. To do this, we will create a couple transactions with high spends compared to their
	// fees. The spend will be high enough so that the public key won't have enough balance to cover the fees of
	// the remaining transactions.
	invalidTxns := []*MsgDeSoTxn{}
	for ii := 0; ii < invalidTransactions; ii++ {
		invalidTxn := _generateTestTxn(t, rand, feeMin, feeMax, m1PubBytes, m1Priv, 100, 20)
		if m1InitialBalance < invalidTxn.TxnFeeNanos+1 {
			t.Fatalf("m1InitialBalance (%d) must be greater than txn fee (%d) + 1", m1InitialBalance, invalidTxn.TxnFeeNanos+1)
		}
		invalidTxn.TxOutputs = append(invalidTxn.TxOutputs, &DeSoOutput{
			PublicKey:   m2PkBytes,
			AmountNanos: m1InitialBalance - invalidTxn.TxnFeeNanos - 1,
		})
		_signTxn(t, invalidTxn, m1Priv)
		invalidTxns = append(invalidTxns, invalidTxn)
		_wrappedPosMempoolAddTransaction(t, mempool, invalidTxn)
	}
	latestBlockViewCopy, err = latestBlockView.CopyUtxoView()
	require.NoError(err)
	txns, txnConnectStatus, txnTimestamps, maxUtilityFee, err = pbp.getBlockTransactions(latestBlockView, 3, 50000)
	// Only a single of the invalid transactions made by m1 should have been added.
	require.NoError(err)
	require.Equal(latestBlockViewCopy, latestBlockView)
	require.Equal(len(passingTxns)+len(failingTxns)+1, len(txns))
	require.Equal(len(passingTxns)+len(failingTxns)+1, len(txnTimestamps))
	totalConnected = 0
	for ii := range txns {
		if txnConnectStatus.Get(ii) {
			totalConnected++
		} else {
			require.Equal(1, len(txns[ii].TxOutputs))
		}
	}
	require.Equal(len(passingTxns)+1, totalConnected)
}
