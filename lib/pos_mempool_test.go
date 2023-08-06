package lib

import (
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

	eventManager := NewEventManager()

	mempool := NewPosMempool(&params, globalParams, nil, nil, dir, eventManager)
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
		senderPrivString, 20000, 11)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, senderPkString, m1PublicKeyBase58Check,
		senderPrivString, 20000, 11)

	latestBlockView, err := NewUtxoView(db, params, nil, nil)
	require.NoError(err)
	latestBlockNode := chain.blockTip()

	dir, err := os.MkdirTemp("", "badgerdb-mempool")
	require.NoError(err)
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	defer os.RemoveAll(dir)

	eventManager := NewEventManager()

	mempool := NewPosMempool(params, globalParams, latestBlockView, latestBlockNode, dir, eventManager)
	require.NoError(mempool.Start())
	require.Equal(PosMempoolStatusRunning, mempool.status)

	txn1 := &MsgDeSoTxn{
		TxnVersion:  DeSoTxnVersion1,
		PublicKey:   m0PubBytes,
		TxnMeta:     &BasicTransferMetadata{},
		TxnFeeNanos: rand.Uint64()%(feeMax-feeMin) + feeMin,
		TxnNonce: &DeSoNonce{
			ExpirationBlockHeight: 100,
		},
	}
	txn2 := &MsgDeSoTxn{
		TxnVersion:  DeSoTxnVersion1,
		PublicKey:   m1PubBytes,
		TxnMeta:     &BasicTransferMetadata{},
		TxnFeeNanos: rand.Uint64()%(feeMax-feeMin) + feeMin,
		TxnNonce: &DeSoNonce{
			ExpirationBlockHeight: 100,
		},
	}
	_signTxn(t, txn1, m0Priv)
	_signTxn(t, txn2, m1Priv)
	require.NoError(mempool.ProcessMsgDeSoTxn(txn1))
	require.NoError(mempool.ProcessMsgDeSoTxn(txn2))

	poolTxns := mempool.GetTransactions()
	require.Equal(2, len(poolTxns))
	mempool.Stop()

	newPool := NewPosMempool(params, globalParams, latestBlockView, latestBlockNode, dir, eventManager)
	require.NoError(newPool.Start())
	require.Equal(PosMempoolStatusRunning, newPool.status)
	newPoolTxns := newPool.GetTransactions()
	require.Equal(2, len(newPoolTxns))
	newPool.Stop()
}

// TODO: Add a test for pruning and a lot of transactions
// TODO: Add a test for removing transactions
