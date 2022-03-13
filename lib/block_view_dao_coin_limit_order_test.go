package lib

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDAOCoinLimitOrder(t *testing.T) {
	require := require.New(t)

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true)
	// Make m3 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true
	params.ForkHeights.DAOCoinBlockHeight = uint32(0)

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

	metadata := DAOCoinLimitOrderMetadata{
		DenominatedCoinType:        DAOCoinLimitOrderEntryDenominatedCoinTypeDESO,
		DenominatedCoinCreatorPKID: &ZeroPKID,
		DAOCoinCreatorPKID:         m0PKID.PKID,
		OperationType:              DAOCoinLimitOrderEntryOrderTypeBid,
		PriceNanos:                 *uint256.NewInt().SetUint64(10),
		Quantity:                   *uint256.NewInt().SetUint64(100),
	}

	{
		_, _, _, err = _doDAOCoinLimitOrderTxn(
			t, chain, db, params, 10, m0Pub, m0Priv, metadata)

		require.Error(err)
		//require.Contains(err.Error(), RuleErrorDAOCoinOperationOnNonexistentProfile)
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
