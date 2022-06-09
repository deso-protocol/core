package lib

import (
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "net/http/pprof"
	"testing"
)

func _strToPk(t *testing.T, pkStr string) []byte {
	require := require.New(t)

	pkBytes, _, err := Base58CheckDecode(pkStr)
	require.NoError(err)

	return pkBytes
}

func getTxnSize(txn MsgDeSoTxn) int64 {
	bytes, _ := txn.ToBytes(false)
	return int64(len(bytes))
}

var (
	// Set up some addresses
	m0Pub           = "tBCKY2X1Gbqn95tN1PfsCFLKX6x6h48g5LdHt9T95Wj9Rm6EVKLVpi"
	m0Priv          = "tbc2uXFwv3CJvr5HdLLKpAtLNCtBafvfxLBMbJFCNdLA61cLB7aLq"
	m0PkBytes, _, _ = Base58CheckDecode(m0Pub)

	m1Pub           = "tBCKYGWj36qERG57RKdrnCf6JQad1smGTzeLkj1bfN7UqKwY8SM57a"
	m1Priv          = "tbc2DtxgxPVB6T6sbFqhgNrPqwb7QUYG5ZS7aEXQ3ZxAyG88YAPVy"
	m1PkBytes, _, _ = Base58CheckDecode(m1Pub)

	m2Pub           = "tBCKVNYw7WgG59SGP8EdpR9nyywoMBYa3ChLG4UjCBhvFgd4e7oXNg"
	m2Priv          = "tbc37VGdu4RJ7uJcoGHrDJkr4FZPsVYbyo3dRxdhyQHPNp6jUjbK1"
	m2PkBytes, _, _ = Base58CheckDecode(m2Pub)

	m3Pub           = "tBCKWqMGE7xdz78juDSEsDFYt67CuL9VrTiv627Wj2sLwG6B2fcy7o"
	m3Priv          = "tbc2MkEWaCoVNh5rV4fyAdSmAkLQ9bZLqEMGSLYtoAAxgA1844Y67"
	m3PkBytes, _, _ = Base58CheckDecode(m3Pub)

	m4Pub           = "tBCKWu6nNQa3cUV8QLwRhX9r6NXcNpDuK7xtscwm27zXJ7MxdnmZ3g"
	m4Priv          = "tbc2GmpAmkm8CmMjS9NXiAFZHEDGqxSCCpkvkwnY8oqfZXAXnmtFV"
	m4PkBytes, _, _ = Base58CheckDecode(m4Pub)

	m5Pub           = "tBCKWWAqRR89yCLGEbw2QXK32XZkgEacnrZbdc1KrXk5NzeDvfTr4h"
	m5Priv          = "tbc2w7CpjUTcmtLdAPxb8BwYQ8W66Qn8hDcgLxyHGJWfbuT4RFtjz"
	m5PkBytes, _, _ = Base58CheckDecode(m5Pub)

	m6Pub           = "tBCKX5xzB91EPszJq6Ep4AHf7nKi9BXBFeb7o668N3bryz5deqvCBo"
	m6Priv          = "tbc2hN9pnZVnA8TCtV76tZKt5wfLsHyQ5jo9s7NxRswa1h5Y4Hbgg"
	m6PkBytes, _, _ = Base58CheckDecode(m6Pub)

	paramUpdaterPub           = "tBCKWVdVW6St5R8KkbQYd9uhvwmna4EVAeEKBXRsZLVrCM1JHkEU1G"
	paramUpdaterPriv          = "tbc1jF5hXKspbYUVqkSwyyrs9oSho8yA6vZURvBNLySVESFsRmaGf"
	paramUpdaterPkBytes, _, _ = Base58CheckDecode(paramUpdaterPub)
)

func _doBasicTransferWithViewFlush(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, pkSenderStr string, pkReceiverStr string, privStr string,
	amountNanos uint64, feeRateNanosPerKB uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32) {

	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	txn := _assembleBasicTransferTxnFullySigned(
		t, chain, amountNanos, feeRateNanosPerKB, pkSenderStr, pkReceiverStr, privStr, nil)

	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
	require.NoError(err)

	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	txHash := txn.Hash()
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	require.NoError(err)
	require.GreaterOrEqual(totalOutput, amountNanos)
	require.Equal(totalInput, totalOutput+fees)

	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs), len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	for ii := len(txn.TxInputs); ii < len(txn.TxInputs)+len(txn.TxOutputs); ii++ {
		require.Equal(OperationTypeAddUtxo, utxoOps[ii].Type)
	}

	require.NoError(utxoView.FlushToDb(0))

	return utxoOps, txn, blockHeight
}

func _registerOrTransferWithTestMeta(testMeta *TestMeta, username string,
	senderPk string, recipientPk string, senderPriv string, amountToSend uint64) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, senderPk))

	currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params, senderPk, recipientPk,
		senderPriv, amountToSend, 11 /*feerate*/)

	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _updateGlobalParamsEntry(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, usdCentsPerBitcoin int64, minimumNetworkFeesNanosPerKB int64,
	createProfileFeeNanos int64, createNFTFeeNanos int64, maxCopiesPerNFT int64, flushToDb bool) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateUpdateGlobalParamsTxn(
		updaterPkBytes,
		usdCentsPerBitcoin,
		createProfileFeeNanos,
		createNFTFeeNanos,
		maxCopiesPerNFT,
		minimumNetworkFeesNanosPerKB,
		nil,
		feeRateNanosPerKB,
		nil,
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, updaterPrivBase58Check)

	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)

	require.NoError(err)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypePrivateMessage operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(
		OperationTypeUpdateGlobalParams, utxoOps[len(utxoOps)-1].Type)
	if flushToDb {
		require.NoError(utxoView.FlushToDb(0))
	}
	return utxoOps, txn, blockHeight, nil
}

func _updateGlobalParamsEntryWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	updaterPkBase58Check string,
	updaterPrivBase58Check string,
	USDCentsPerBitcoinExchangeRate int64,
	minimumNetworkFeeNanosPerKb int64,
	createProfileFeeNanos int64,
	createNFTFeeNanos int64,
	maxCopiesPerNFT int64,
) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances,
		_getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))

	currentOps, currentTxn, _, err := _updateGlobalParamsEntry(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		int64(InitialUSDCentsPerBitcoinExchangeRate),
		minimumNetworkFeeNanosPerKb,
		createProfileFeeNanos,
		createNFTFeeNanos,
		maxCopiesPerNFT,
		true) /*flushToDB*/
	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

type TestMeta struct {
	t                      *testing.T
	chain                  *Blockchain
	db                     *badger.DB
	params                 *DeSoParams
	mempool                *DeSoMempool
	miner                  *DeSoMiner
	txnOps                 [][]*UtxoOperation
	txns                   []*MsgDeSoTxn
	expectedSenderBalances []uint64
	savedHeight            uint32
}

func _executeAllTestRollbackAndFlush(testMeta *TestMeta) {
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func _rollBackTestMetaTxnsAndFlush(testMeta *TestMeta) {
	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(testMeta.txnOps); ii++ {
		backwardIter := len(testMeta.txnOps) - 1 - ii
		currentOps := testMeta.txnOps[backwardIter]
		currentTxn := testMeta.txns[backwardIter]
		fmt.Printf(
			"Disconnecting transaction with type %v index %d (going backwards)\n",
			currentTxn.TxnMeta.GetTxnType(), backwardIter)

		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(testMeta.t, err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, testMeta.savedHeight)
		require.NoError(testMeta.t, err)

		require.NoError(testMeta.t, utxoView.FlushToDb(0))

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(
			testMeta.t,
			testMeta.expectedSenderBalances[backwardIter],
			_getBalance(testMeta.t, testMeta.chain, nil, PkToStringTestnet(currentTxn.PublicKey)),
		)
	}
}

func _applyTestMetaTxnsToMempool(testMeta *TestMeta) {
	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	for ii, tx := range testMeta.txns {
		require.Equal(
			testMeta.t,
			testMeta.expectedSenderBalances[ii],
			_getBalance(testMeta.t, testMeta.chain, testMeta.mempool, PkToStringTestnet(tx.PublicKey)))

		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		_, err := testMeta.mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(testMeta.t, err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}
}

func _applyTestMetaTxnsToViewAndFlush(testMeta *TestMeta) {
	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(testMeta.t, err)
	for ii, txn := range testMeta.txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := testMeta.chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.NoError(testMeta.t, err)
	}
	// Flush the utxoView after having added all the transactions.
	require.NoError(testMeta.t, utxoView.FlushToDb(0))
}

func _disconnectTestMetaTxnsFromViewAndFlush(testMeta *TestMeta) {
	// Disonnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(testMeta.t, err)
	for ii := 0; ii < len(testMeta.txnOps); ii++ {
		backwardIter := len(testMeta.txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := testMeta.txnOps[backwardIter]
		currentTxn := testMeta.txns[backwardIter]

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, testMeta.savedHeight)
		require.NoError(testMeta.t, err)
	}
	require.NoError(testMeta.t, utxoView.FlushToDb(0))
	require.Equal(
		testMeta.t,
		testMeta.expectedSenderBalances[0],
		_getBalance(testMeta.t, testMeta.chain, nil, senderPkString))
}

func _connectBlockThenDisconnectBlockAndFlush(testMeta *TestMeta) {
	// all those transactions in it.
	block, err := testMeta.miner.MineAndProcessSingleBlock(0 /*threadIndex*/, testMeta.mempool)
	require.NoError(testMeta.t, err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(testMeta.t, len(testMeta.txnOps)+1, len(block.Txns))

	// Roll back the block and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(testMeta.t, err)

		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := block.Header.Hash()
		require.NoError(testMeta.t, err)
		utxoOps, err := GetUtxoOperationsForBlock(testMeta.db, testMeta.chain.snapshot, hash)
		require.NoError(testMeta.t, err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(block.Txns)
		require.NoError(testMeta.t, err)
		require.NoError(testMeta.t, utxoView.DisconnectBlock(block, txHashes, utxoOps, 0))

		// Flushing the view after applying and rolling back should work.
		require.NoError(testMeta.t, utxoView.FlushToDb(0))
	}
}

func TestUpdateGlobalParams(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_, _ = mempool, miner

	// Set the founder equal to the moneyPk
	params.ParamUpdaterPublicKeys = make(map[PkMapKey]bool)
	params.ParamUpdaterPublicKeys[MakePkMapKey(MustBase58CheckDecode(moneyPkString))] = true

	// Send money to m0 from moneyPk
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m0Pub,
		moneyPrivString, 10*NanosPerUnit /*amount to send*/, 11 /*feerate*/)

	// Should fail when founder key is not equal to moneyPk
	{
		newUSDCentsPerBitcoin := int64(27000 * 100)
		newMinimumNetworkFeeNanosPerKB := int64(100)
		newCreateProfileFeeNanos := int64(200)
		newCreateNFTFeeNanos := int64(300)
		_, _, _, err := _updateGlobalParamsEntry(
			t, chain, db, params, 100, /*feeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			newUSDCentsPerBitcoin,
			newMinimumNetworkFeeNanosPerKB,
			newCreateProfileFeeNanos,
			newCreateNFTFeeNanos,
			-1, /*maxCopiesPerNFT*/
			false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorUserNotAuthorizedToUpdateGlobalParams)
	}

	// Should pass when founder key is equal to moneyPk
	var updateGlobalParamsTxn *MsgDeSoTxn
	var err error
	{
		newUSDCentsPerBitcoin := int64(270430 * 100)
		newMinimumNetworkFeeNanosPerKB := int64(191)
		newCreateProfileFeeNanos := int64(10015)
		newCreateNFTFeeNanos := int64(14983)
		newMaxCopiesPerNFT := int64(123)
		_, updateGlobalParamsTxn, _, err = _updateGlobalParamsEntry(
			t, chain, db, params, 200, /*feeRateNanosPerKB*/
			moneyPkString,
			moneyPrivString,
			newUSDCentsPerBitcoin,
			newMinimumNetworkFeeNanosPerKB,
			newCreateProfileFeeNanos,
			newCreateNFTFeeNanos,
			newMaxCopiesPerNFT,
			false)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		txnSize := getTxnSize(*updateGlobalParamsTxn)
		blockHeight := chain.blockTip().Height + 1
		utxoOps, totalInput, totalOutput, fees, err :=
			utxoView.ConnectTransaction(updateGlobalParamsTxn,
				updateGlobalParamsTxn.Hash(), txnSize, blockHeight, true, /*verifySignature*/
				false /*ignoreUtxos*/)
		require.NoError(err)
		_, _, _, _ = utxoOps, totalInput, totalOutput, fees
		require.NoError(utxoView.FlushToDb(0))

		// Verify that utxoView and db reflect the new global parmas entry.
		expectedGlobalParams := GlobalParamsEntry{
			USDCentsPerBitcoin:          uint64(newUSDCentsPerBitcoin),
			MinimumNetworkFeeNanosPerKB: uint64(newMinimumNetworkFeeNanosPerKB),
			CreateProfileFeeNanos:       uint64(newCreateProfileFeeNanos),
			CreateNFTFeeNanos:           uint64(newCreateNFTFeeNanos),
			MaxCopiesPerNFT:             123,
		}
		require.Equal(DbGetGlobalParamsEntry(utxoView.Handle, chain.snapshot), &expectedGlobalParams)

		require.Equal(utxoView.GlobalParamsEntry, &expectedGlobalParams)

		// Check the balance of the updater after this txn
		require.NotEqual(0, _getBalance(t, chain, nil, moneyPkString))
	}

	{

		// Save the prev global params entry so we can check it after disconnect.
		prevGlobalParams := DbGetGlobalParamsEntry(db, chain.snapshot)

		newUSDCentsPerBitcoin := int64(270434 * 100)
		newMinimumNetworkFeeNanosPerKB := int64(131)
		newCreateProfileFeeNanos := int64(102315)
		newCreateNFTFeeNanos := int64(3244099)
		newMaxCopiesPerNFT := int64(555)
		var utxoOps []*UtxoOperation
		utxoOps, updateGlobalParamsTxn, _, err = _updateGlobalParamsEntry(
			t, chain, db, params, 200, /*feeRateNanosPerKB*/
			moneyPkString,
			moneyPrivString,
			newUSDCentsPerBitcoin,
			newMinimumNetworkFeeNanosPerKB,
			newCreateProfileFeeNanos,
			newCreateNFTFeeNanos,
			newMaxCopiesPerNFT, /*maxCopiesPerNFT*/
			true)
		require.NoError(err)

		// Verify that the db reflects the new global params entry.
		expectedGlobalParams := &GlobalParamsEntry{
			USDCentsPerBitcoin:          uint64(newUSDCentsPerBitcoin),
			MinimumNetworkFeeNanosPerKB: uint64(newMinimumNetworkFeeNanosPerKB),
			CreateProfileFeeNanos:       uint64(newCreateProfileFeeNanos),
			CreateNFTFeeNanos:           uint64(newCreateNFTFeeNanos),
			MaxCopiesPerNFT:             uint64(newMaxCopiesPerNFT),
		}

		require.Equal(DbGetGlobalParamsEntry(db, chain.snapshot), expectedGlobalParams)

		// Now let's do a disconnect and make sure the values reflect the previous entry.
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		blockHeight := chain.blockTip().Height + 1
		utxoView.DisconnectTransaction(
			updateGlobalParamsTxn, updateGlobalParamsTxn.Hash(), utxoOps, blockHeight)

		require.NoError(utxoView.FlushToDb(0))

		require.Equal(DbGetGlobalParamsEntry(utxoView.Handle, chain.snapshot), prevGlobalParams)
		require.Equal(utxoView.GlobalParamsEntry, prevGlobalParams)

		// Check the balance of the updater after this txn
		require.NotEqual(0, _getBalance(t, chain, nil, moneyPkString))
	}
}

func TestBasicTransfer(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Mine two blocks to give the sender some DeSo.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)
	recipientPkBytes, _, err := Base58CheckDecode(recipientPkString)
	require.NoError(err)

	// A basic transfer whose input public keys differ from the
	// transaction-level public key should fail.
	{
		txn := &MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs: []*DeSoInput{},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPkBytes,
			TxnMeta:   &BasicTransferMetadata{},
		}

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, nil)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		// At this point the txn has inputs for senderPkString. Change
		// the public key to recipientPkString and sign it with the
		// recipientPrivString.
		txn.PublicKey = recipientPkBytes

		_signTxn(t, txn, recipientPrivString)
		utxoView, _ := NewUtxoView(db, params, nil, chain.snapshot)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
				true /*verifySignatures*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey)
	}

	// Just a basic transfer with a bad signature.
	{
		txn := &MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs: []*DeSoInput{},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPkBytes,
			TxnMeta:   &BasicTransferMetadata{},
		}

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, nil)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		// Sign the transaction with the recipient's key rather than the
		// sender's key.
		_signTxn(t, txn, recipientPrivString)
		utxoView, _ := NewUtxoView(db, params, nil, chain.snapshot)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
				true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidTransactionSignature)
	}

	// A block reward with a bad signature should fail.
	{
		txn := &MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs: []*DeSoInput{},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPkBytes,
			TxnMeta: &BlockRewardMetadataa{
				ExtraData: []byte{0x00, 0x01},
			},
		}
		_signTxn(t, txn, senderPrivString)
		utxoView, _ := NewUtxoView(db, params, nil, chain.snapshot)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
				true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardTxnNotAllowedToHaveSignature)
	}

	// A block reward with an input, even if it's signed legitimately,
	// should fail.
	{
		txn := &MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs: []*DeSoInput{},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPkBytes,
			TxnMeta: &BlockRewardMetadataa{
				ExtraData: []byte{0x00, 0x01},
			},
		}

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, nil)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		_signTxn(t, txn, senderPrivString)
		utxoView, _ := NewUtxoView(db, params, nil, chain.snapshot)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
				true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardTxnNotAllowedToHaveInputs)
	}

	// A block with too much block reward should fail.
	allowedBlockReward := CalcBlockRewardNanos(chain.blockTip().Height)
	assert.Equal(int64(allowedBlockReward), int64(1*NanosPerUnit))
	blockToMine, _, _, err := miner._getBlockToMine(0 /*threadIndex*/)
	require.NoError(err)
	{
		blockToMine.Txns[0].TxOutputs[0].AmountNanos = allowedBlockReward + 1
		// One iteration should be sufficient to find us a good block.
		_, bestNonce, err := FindLowestHash(blockToMine.Header, 10000)
		require.NoError(err)
		blockToMine.Header.Nonce = bestNonce

		txHashes, err := ComputeTransactionHashes(blockToMine.Txns)
		require.NoError(err)
		utxoView, _ := NewUtxoView(db, params, nil, chain.snapshot)
		_, err = utxoView.ConnectBlock(blockToMine, txHashes, true /*verifySignatures*/, nil, 0)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardExceedsMaxAllowed)
	}

	// A block with less than the max block reward should be OK.
	{
		blockToMine.Txns[0].TxOutputs[0].AmountNanos = allowedBlockReward - 1
		// One iteration should be sufficient to find us a good block.
		_, bestNonce, err := FindLowestHash(blockToMine.Header, 10000)
		require.NoError(err)
		blockToMine.Header.Nonce = bestNonce

		txHashes, err := ComputeTransactionHashes(blockToMine.Txns)
		require.NoError(err)
		utxoView, _ := NewUtxoView(db, params, nil, chain.snapshot)
		_, err = utxoView.ConnectBlock(blockToMine, txHashes, true /*verifySignatures*/, nil, 0)
		require.NoError(err)
	}
}
