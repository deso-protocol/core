package lib

import (
	"bytes"
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/require"
	"math/rand"
	"os"
	"testing"
)

func TestPosMempoolStart(t *testing.T) {
	require := require.New(t)

	params := DeSoTestnetParams
	globalParams := _testGetDefaultGlobalParams()

	dir, err := os.MkdirTemp("", "badgerdb-mempool")
	require.NoError(err)
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	defer os.RemoveAll(dir)

	mempool := NewPosMempool(&params, globalParams, nil, 0, dir)
	require.NoError(mempool.Start())
	require.Equal(PosMempoolStatusRunning, mempool.status)
	mempool.Stop()
}

func TestPosMempoolRestartWithTransactions(t *testing.T) {
	require := require.New(t)
	seed := int64(991)
	rand := rand.New(rand.NewSource(seed))

	globalParams := _testGetDefaultGlobalParams()
	feeMin := globalParams.MinimumNetworkFeeNanosPerKB
	feeMax := uint64(10000)

	params, db := _blockchainSetup(t)
	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	m1PubBytes, _, _ := Base58CheckDecode(m1Pub)

	latestBlockView, err := NewUtxoView(db, params, nil, nil)
	require.NoError(err)

	dir, err := os.MkdirTemp("", "badgerdb-mempool")
	require.NoError(err)
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	defer os.RemoveAll(dir)

	mempool := NewPosMempool(params, globalParams, latestBlockView, 2, dir)
	require.NoError(mempool.Start())
	require.Equal(PosMempoolStatusRunning, mempool.status)

	txn1 := _generateTestTxn(t, rand, feeMin, feeMax, m0PubBytes, m0Priv, 100, 0)
	txn2 := _generateTestTxn(t, rand, feeMin, feeMax, m1PubBytes, m1Priv, 100, 0)
	require.NoError(mempool.AddTransaction(txn1))
	require.NoError(mempool.AddTransaction(txn2))

	poolTxns := mempool.GetTransactions()
	require.Equal(2, len(poolTxns))
	mempool.Stop()

	newPool := NewPosMempool(params, globalParams, latestBlockView, 2, dir)
	require.NoError(newPool.Start())
	require.Equal(PosMempoolStatusRunning, newPool.status)
	newPoolTxns := newPool.GetTransactions()
	require.Equal(2, len(newPoolTxns))
	newPool.Stop()
}

func TestPosMempoolPrune(t *testing.T) {
	require := require.New(t)
	seed := int64(993)
	rand := rand.New(rand.NewSource(seed))

	globalParams := _testGetDefaultGlobalParams()
	feeMin := globalParams.MinimumNetworkFeeNanosPerKB
	feeMax := uint64(2000)

	params, db := _blockchainSetup(t)
	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	m1PubBytes, _, _ := Base58CheckDecode(m1Pub)

	latestBlockView, err := NewUtxoView(db, params, nil, nil)
	require.NoError(err)

	dir, err := os.MkdirTemp("", "badgerdb-mempool")
	require.NoError(err)
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	defer os.RemoveAll(dir)

	params.MaxMempoolPosSizeBytes = 500
	mempool := NewPosMempool(params, globalParams, latestBlockView, 2, dir)
	require.NoError(mempool.Start())
	require.Equal(PosMempoolStatusRunning, mempool.status)

	var txns []*MsgDeSoTxn
	for ii := 0; ii < 10; ii++ {
		pk := m0PubBytes
		priv := m0Priv
		if ii%2 == 1 {
			pk = m1PubBytes
			priv = m1Priv
		}
		txn := _generateTestTxn(t, rand, feeMin, feeMax, pk, priv, 100, 25)
		txns = append(txns, txn)
		require.NoError(mempool.AddTransaction(txn))
	}

	fetchedTxns := mempool.GetTransactions()
	require.Equal(3, len(fetchedTxns))
	require.Equal(uint64(1974), fetchedTxns[0].TxnFeeNanos)
	require.Equal(uint64(1931), fetchedTxns[1].TxnFeeNanos)
	require.Equal(uint64(1776), fetchedTxns[2].TxnFeeNanos)
	require.Equal(uint64(1974), mempool.GetTransaction(fetchedTxns[0].Hash()).TxnFeeNanos)
	require.Equal(uint64(1931), mempool.GetTransaction(fetchedTxns[1].Hash()).TxnFeeNanos)
	require.Equal(uint64(1776), mempool.GetTransaction(fetchedTxns[2].Hash()).TxnFeeNanos)

	// Remove one transaction.
	require.NoError(mempool.RemoveTransaction(fetchedTxns[0].Hash()))
	mempool.Stop()

	newPool := NewPosMempool(params, globalParams, latestBlockView, 2, dir)
	require.NoError(newPool.Start())
	require.Equal(PosMempoolStatusRunning, newPool.status)
	require.Equal(2, len(newPool.GetTransactions()))

	// Remove the other transactions.
	require.NoError(newPool.RemoveTransaction(fetchedTxns[1].Hash()))
	require.NoError(newPool.RemoveTransaction(fetchedTxns[2].Hash()))
	// Remove the same transaction twice
	require.NoError(newPool.RemoveTransaction(fetchedTxns[1].Hash()))
	require.Equal(0, len(newPool.GetTransactions()))

	// Add the transactions back.
	for _, txn := range fetchedTxns {
		require.NoError(newPool.AddTransaction(txn))
	}
	require.Equal(3, len(newPool.GetTransactions()))

	// Iterate through the transactions.
	it := newPool.GetIterator()
	index := 0
	for it.Next() {
		tx, ok := it.Value()
		require.True(ok)
		require.True(bytes.Equal(tx.Hash().ToBytes(), fetchedTxns[index].Hash().ToBytes()))
		index++
	}
	newPool.Stop()
}

func TestPosMempoolUpdateGlobalParams(t *testing.T) {
	require := require.New(t)
	seed := int64(995)
	rand := rand.New(rand.NewSource(seed))

	globalParams := _testGetDefaultGlobalParams()
	feeMin := globalParams.MinimumNetworkFeeNanosPerKB
	feeMax := uint64(2000)

	params, db := _blockchainSetup(t)
	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	m1PubBytes, _, _ := Base58CheckDecode(m1Pub)

	latestBlockView, err := NewUtxoView(db, params, nil, nil)
	require.NoError(err)

	dir, err := os.MkdirTemp("", "badgerdb-mempool")
	require.NoError(err)
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	defer os.RemoveAll(dir)

	mempool := NewPosMempool(params, globalParams, latestBlockView, 2, dir)
	require.NoError(mempool.Start())
	require.Equal(PosMempoolStatusRunning, mempool.status)

	var txns []*MsgDeSoTxn
	for ii := 0; ii < 100; ii++ {
		pk := m0PubBytes
		priv := m0Priv
		if ii%2 == 1 {
			pk = m1PubBytes
			priv = m1Priv
		}
		txn := _generateTestTxn(t, rand, feeMin, feeMax, pk, priv, 100, 25)
		txns = append(txns, txn)
		require.NoError(mempool.AddTransaction(txn))
	}

	require.Equal(100, len(mempool.GetTransactions()))
	newGlobalParams := _testGetDefaultGlobalParams()
	newGlobalParams.MinimumNetworkFeeNanosPerKB = 20000
	mempool.UpdateGlobalParams(newGlobalParams)
	require.Equal(0, len(mempool.GetTransactions()))
	mempool.Stop()

	newPool := NewPosMempool(params, newGlobalParams, latestBlockView, 2, dir)
	require.NoError(newPool.Start())
	require.Equal(PosMempoolStatusRunning, newPool.status)
	newPoolTxns := newPool.GetTransactions()
	require.Equal(0, len(newPoolTxns))
	newPool.Stop()
}

func _blockchainSetup(t *testing.T) (_params *DeSoParams, _db *badger.DB) {
	require := require.New(t)

	chain, params, db := NewLowDifficultyBlockchain(t)
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
		senderPrivString, 200000, 11)

	return params, db
}

func _generateTestTxn(t *testing.T, rand *rand.Rand, feeMin uint64, feeMax uint64, pk []byte, priv string, expirationHeight uint64,
	extraDataBytes int32) *MsgDeSoTxn {

	extraData := make(map[string][]byte)
	extraData["key"] = RandomBytes(extraDataBytes)
	txn := &MsgDeSoTxn{
		TxnVersion:  DeSoTxnVersion1,
		PublicKey:   pk,
		TxnMeta:     &BasicTransferMetadata{},
		TxnFeeNanos: rand.Uint64()%(feeMax-feeMin) + feeMin,
		TxnNonce: &DeSoNonce{
			ExpirationBlockHeight: expirationHeight,
		},
		ExtraData: extraData,
	}
	_signTxn(t, txn, priv)
	return txn
}
