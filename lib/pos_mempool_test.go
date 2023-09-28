package lib

import (
	"bytes"
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/rand"
	"os"
	"testing"
)

func TestPosMempoolStart(t *testing.T) {
	require := require.New(t)

	params := DeSoTestnetParams
	globalParams := _testGetDefaultGlobalParams()
	dir := _dbDirSetup(t)

	mempool := NewPosMempool(&params, globalParams, nil, 0, dir)
	require.NoError(mempool.Start())
	require.True(mempool.IsRunning())
	mempool.Stop()
	require.False(mempool.IsRunning())
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
	dir := _dbDirSetup(t)

	mempool := NewPosMempool(params, globalParams, latestBlockView, 2, dir)
	require.NoError(mempool.Start())
	require.True(mempool.IsRunning())

	txn1 := _generateTestTxn(t, rand, feeMin, feeMax, m0PubBytes, m0Priv, 100, 0)
	txn2 := _generateTestTxn(t, rand, feeMin, feeMax, m1PubBytes, m1Priv, 100, 0)
	_wrappedPosMempoolAddTransaction(t, mempool, txn1)
	_wrappedPosMempoolAddTransaction(t, mempool, txn2)

	poolTxns := mempool.GetTransactions()
	require.Equal(2, len(poolTxns))
	mempool.Stop()
	require.False(mempool.IsRunning())

	newPool := NewPosMempool(params, globalParams, latestBlockView, 2, dir)
	require.NoError(newPool.Start())
	require.True(newPool.IsRunning())
	newPoolTxns := newPool.GetTransactions()
	require.Equal(2, len(newPoolTxns))
	require.Equal(len(newPool.GetTransactions()), len(newPool.nonceTracker.nonceMap))
	newPool.Stop()
	require.False(newPool.IsRunning())
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
	dir := _dbDirSetup(t)

	params.MaxMempoolPosSizeBytes = 500
	mempool := NewPosMempool(params, globalParams, latestBlockView, 2, dir)
	require.NoError(mempool.Start())
	require.True(mempool.IsRunning())

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
		_wrappedPosMempoolAddTransaction(t, mempool, txn)
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
	require.False(mempool.IsRunning())

	newPool := NewPosMempool(params, globalParams, latestBlockView, 2, dir)
	require.NoError(newPool.Start())
	require.True(newPool.IsRunning())
	require.Equal(2, len(newPool.GetTransactions()))

	// Remove the other transactions.
	require.NoError(newPool.RemoveTransaction(fetchedTxns[1].Hash()))
	require.NoError(newPool.RemoveTransaction(fetchedTxns[2].Hash()))
	// Remove the same transaction twice
	require.NoError(newPool.RemoveTransaction(fetchedTxns[1].Hash()))
	require.Equal(0, len(newPool.GetTransactions()))

	// Add the transactions back.
	for _, txn := range fetchedTxns {
		_wrappedPosMempoolAddTransaction(t, newPool, txn)
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
	require.Equal(len(newPool.GetTransactions()), len(newPool.nonceTracker.nonceMap))
	newPool.Stop()
	require.False(newPool.IsRunning())
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
	dir := _dbDirSetup(t)

	mempool := NewPosMempool(params, globalParams, latestBlockView, 2, dir)
	require.NoError(mempool.Start())
	require.True(mempool.IsRunning())

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
		_wrappedPosMempoolAddTransaction(t, mempool, txn)
	}

	require.Equal(100, len(mempool.GetTransactions()))
	newGlobalParams := _testGetDefaultGlobalParams()
	newGlobalParams.MinimumNetworkFeeNanosPerKB = 20000
	mempool.UpdateGlobalParams(newGlobalParams)
	require.Equal(0, len(mempool.GetTransactions()))
	mempool.Stop()
	require.False(mempool.IsRunning())

	newPool := NewPosMempool(params, newGlobalParams, latestBlockView, 2, dir)
	require.NoError(newPool.Start())
	require.True(newPool.IsRunning())
	newPoolTxns := newPool.GetTransactions()
	require.Equal(0, len(newPoolTxns))
	require.Equal(len(mempool.GetTransactions()), len(mempool.nonceTracker.nonceMap))
	newPool.Stop()
	require.False(newPool.IsRunning())
}

func TestPosMempoolReplaceWithHigherFee(t *testing.T) {
	require := require.New(t)
	seed := int64(1077)
	rand := rand.New(rand.NewSource(seed))

	globalParams := _testGetDefaultGlobalParams()
	feeMin := globalParams.MinimumNetworkFeeNanosPerKB
	feeMax := uint64(2000)

	params, db := _blockchainSetup(t)
	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	m1PubBytes, _, _ := Base58CheckDecode(m1Pub)

	latestBlockView, err := NewUtxoView(db, params, nil, nil)
	require.NoError(err)
	dir := _dbDirSetup(t)

	mempool := NewPosMempool(params, globalParams, latestBlockView, 2, dir)
	require.NoError(mempool.Start())
	require.True(mempool.IsRunning())

	txn1 := _generateTestTxn(t, rand, feeMin, feeMax, m0PubBytes, m0Priv, 100, 25)
	_wrappedPosMempoolAddTransaction(t, mempool, txn1)
	require.Equal(1, len(mempool.GetTransactions()))

	txns := mempool.GetTransactions()
	require.Equal(1, len(txns))
	txn1New := _generateTestTxn(t, rand, feeMin, feeMax, m0PubBytes, m0Priv, 100, 25)
	txn1New.TxnFeeNanos = txn1.TxnFeeNanos + 1000
	txn1New.TxnNonce.PartialID = txn1.TxnNonce.PartialID
	_signTxn(t, txn1New, m0Priv)
	_wrappedPosMempoolAddTransaction(t, mempool, txn1New)
	require.Equal(1, len(mempool.GetTransactions()))
	require.Equal(txn1New.TxnNonce, mempool.GetTransactions()[0].TxnNonce)

	txn2 := _generateTestTxn(t, rand, feeMin, feeMax, m1PubBytes, m1Priv, 100, 25)
	_wrappedPosMempoolAddTransaction(t, mempool, txn2)
	require.Equal(2, len(mempool.GetTransactions()))

	txns = mempool.GetTransactions()
	require.Equal(2, len(txns))
	txn2New := _generateTestTxn(t, rand, feeMin, feeMax, m1PubBytes, m1Priv, 100, 25)
	txn2New.TxnFeeNanos = txn2.TxnFeeNanos + 1000
	txn2New.TxnNonce.PartialID = txn2.TxnNonce.PartialID
	_signTxn(t, txn2New, m1Priv)
	_wrappedPosMempoolAddTransaction(t, mempool, txn2New)
	require.Equal(2, len(mempool.GetTransactions()))
	require.Equal(txn2New.TxnNonce, mempool.GetTransactions()[0].TxnNonce)
	require.Equal(txn1New.TxnNonce, mempool.GetTransactions()[1].TxnNonce)

	require.Equal(len(mempool.GetTransactions()), len(mempool.nonceTracker.nonceMap))
	mempool.Stop()
	require.False(mempool.IsRunning())
}

func _blockchainSetup(t *testing.T) (_params *DeSoParams, _db *badger.DB) {
	require := require.New(t)

	chain, params, db := NewLowDifficultyBlockchain(t)
	params.ForkHeights.BalanceModelBlockHeight = 1
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

func _dbDirSetup(t *testing.T) (_dir string) {
	require := require.New(t)

	dir, err := os.MkdirTemp("", "badgerdb-mempool")
	require.NoError(err)
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	t.Cleanup(func() {
		os.RemoveAll(dir)
	})
	return dir
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
			PartialID:             rand.Uint64() % 10000,
		},
		ExtraData: extraData,
	}
	_signTxn(t, txn, priv)
	return txn
}

func _wrappedPosMempoolAddTransaction(t *testing.T, mp *PosMempool, txn *MsgDeSoTxn) {
	require.NoError(t, mp.AddTransaction(txn))
	require.Equal(t, true, _checkPosMempoolIntegrity(t, mp))
}

func _wrappedPosMempoolRemoveTransaction(t *testing.T, mp *PosMempool, txnHash *BlockHash) {
	require.NoError(t, mp.RemoveTransaction(txnHash))
	require.Equal(t, true, _checkPosMempoolIntegrity(t, mp))
}

func _checkPosMempoolIntegrity(t *testing.T, mp *PosMempool) bool {
	if !mp.IsRunning() {
		return true
	}

	if len(mp.GetTransactions()) != len(mp.nonceTracker.nonceMap) {
		t.Errorf("PosMempool transactions and nonceTracker are out of sync")
		return false
	}

	balances := make(map[PublicKey]uint64)
	for _, txn := range mp.GetTransactions() {
		if txn.TxnNonce == nil {
			t.Errorf("PosMempool transaction has nil nonce")
			return false
		}
		pk := NewPublicKey(txn.PublicKey)
		if txnNt := mp.nonceTracker.GetTxnByPublicKeyNonce(*pk, *txn.TxnNonce); !assert.Equal(t, txn, txnNt.Tx) {
			t.Errorf("PosMempool nonceTracker and transactions are out of sync")
			return false
		}
		balances[*pk] += txn.TxnFeeNanos
	}

	if len(balances) > len(mp.ledger.balances) {
		t.Errorf("PosMempool ledger is out of sync length balances (%v) > ledger (%v)", len(balances), len(mp.ledger.balances))
		return false
	}
	activeBalances := 0
	for pk, ledgerBalance := range mp.ledger.balances {
		if ledgerBalance > 0 {
			activeBalances++
		} else {
			continue
		}
		if balance, exists := balances[pk]; !exists || ledgerBalance != balance {
			t.Errorf("PosMempool ledger is out of sync pk %v", PkToStringTestnet(pk.ToBytes()))
			return false
		}
	}
	if len(balances) != activeBalances {
		t.Errorf("PosMempool ledger is out of sync length")
		return false
	}
	return true
}
