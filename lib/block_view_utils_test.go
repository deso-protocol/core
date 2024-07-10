package lib

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSafeUtxoView(t *testing.T) {
	setBalanceModelBlockHeights(t)
	setPoSBlockHeights(t, 1, 3)
	chain, params, db := NewLowDifficultyBlockchain(t)

	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(t, err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(t, err)
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

	safeUtxoView := NewSafeUtxoView(NewUtxoView(db, params, nil, nil, nil))

	safeUtxoView.primaryView.PublicKeyToDeSoBalanceNanos = nil

	// Construct a basic transfer
	txn := &MsgDeSoTxn{
		TxInputs:    []*DeSoInput{},
		TxOutputs:   []*DeSoOutput{},
		TxnFeeNanos: 50,
		PublicKey:   nil,
		TxnMeta:     &BasicTransferMetadata{},
		TxnNonce:    &DeSoNonce{ExpirationBlockHeight: 10, PartialID: 1000},
	}

	// Sign the txn
	txn.PublicKey = m0PkBytes
	_signTxn(t, txn, m0Priv)
	txnHash := txn.Hash()

	_, _, _, _, err = safeUtxoView.ConnectTransaction(
		txn,
		txnHash,
		3,
		1e9,
		false,
		false,
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Recovered from panic")

	safeUtxoView.primaryView.PublicKeyToDeSoBalanceNanos = make(map[PublicKey]uint64)
	safeUtxoView.backupView.PublicKeyToDeSoBalanceNanos = nil

	_, _, _, _, err = safeUtxoView.ConnectTransaction(
		txn,
		txnHash,
		3,
		1e9,
		false,
		false,
	)
	require.NoError(t, err)
}
