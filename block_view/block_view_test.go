package block_view

import (
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/db"
	"github.com/deso-protocol/core/lib"
	"github.com/deso-protocol/core/network"
	"github.com/deso-protocol/core/types"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "net/http/pprof"
)

func _strToPk(t *testing.T, pkStr string) []byte {
	require := require.New(t)

	pkBytes, _, err := types.Base58CheckDecode(pkStr)
	require.NoError(err)

	return pkBytes
}

func getTxnSize(txn network.MsgDeSoTxn) int64 {
	bytes, _ := txn.ToBytes(false)
	return int64(len(bytes))
}

var (
	// Set up some addresses
	m0Pub           = "tBCKY2X1Gbqn95tN1PfsCFLKX6x6h48g5LdHt9T95Wj9Rm6EVKLVpi"
	m0Priv          = "tbc2uXFwv3CJvr5HdLLKpAtLNCtBafvfxLBMbJFCNdLA61cLB7aLq"
	m0PkBytes, _, _ = types.Base58CheckDecode(m0Pub)

	m1Pub           = "tBCKYGWj36qERG57RKdrnCf6JQad1smGTzeLkj1bfN7UqKwY8SM57a"
	m1Priv          = "tbc2DtxgxPVB6T6sbFqhgNrPqwb7QUYG5ZS7aEXQ3ZxAyG88YAPVy"
	m1PkBytes, _, _ = types.Base58CheckDecode(m1Pub)

	m2Pub           = "tBCKVNYw7WgG59SGP8EdpR9nyywoMBYa3ChLG4UjCBhvFgd4e7oXNg"
	m2Priv          = "tbc37VGdu4RJ7uJcoGHrDJkr4FZPsVYbyo3dRxdhyQHPNp6jUjbK1"
	m2PkBytes, _, _ = types.Base58CheckDecode(m2Pub)

	m3Pub           = "tBCKWqMGE7xdz78juDSEsDFYt67CuL9VrTiv627Wj2sLwG6B2fcy7o"
	m3Priv          = "tbc2MkEWaCoVNh5rV4fyAdSmAkLQ9bZLqEMGSLYtoAAxgA1844Y67"
	m3PkBytes, _, _ = types.Base58CheckDecode(m3Pub)

	m4Pub           = "tBCKWu6nNQa3cUV8QLwRhX9r6NXcNpDuK7xtscwm27zXJ7MxdnmZ3g"
	m4Priv          = "tbc2GmpAmkm8CmMjS9NXiAFZHEDGqxSCCpkvkwnY8oqfZXAXnmtFV"
	m4PkBytes, _, _ = types.Base58CheckDecode(m4Pub)

	m5Pub           = "tBCKWWAqRR89yCLGEbw2QXK32XZkgEacnrZbdc1KrXk5NzeDvfTr4h"
	m5Priv          = "tbc2w7CpjUTcmtLdAPxb8BwYQ8W66Qn8hDcgLxyHGJWfbuT4RFtjz"
	m5PkBytes, _, _ = types.Base58CheckDecode(m5Pub)

	m6Pub           = "tBCKX5xzB91EPszJq6Ep4AHf7nKi9BXBFeb7o668N3bryz5deqvCBo"
	m6Priv          = "tbc2hN9pnZVnA8TCtV76tZKt5wfLsHyQ5jo9s7NxRswa1h5Y4Hbgg"
	m6PkBytes, _, _ = types.Base58CheckDecode(m6Pub)

	paramUpdaterPub           = "tBCKWVdVW6St5R8KkbQYd9uhvwmna4EVAeEKBXRsZLVrCM1JHkEU1G"
	paramUpdaterPriv          = "tbc1jF5hXKspbYUVqkSwyyrs9oSho8yA6vZURvBNLySVESFsRmaGf"
	paramUpdaterPkBytes, _, _ = types.Base58CheckDecode(paramUpdaterPub)
)

func _doBasicTransferWithViewFlush(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, pkSenderStr string, pkReceiverStr string, privStr string,
	amountNanos uint64, feeRateNanosPerKB uint64) (
	_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32) {

	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	txn := lib._assembleBasicTransferTxnFullySigned(
		t, chain, amountNanos, feeRateNanosPerKB, pkSenderStr, pkReceiverStr, privStr, nil)

	utxoView, err := NewUtxoView(db, params, nil)
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

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight
}

func _registerOrTransferWithTestMeta(testMeta *TestMeta, username string,
	senderPk string, recipientPk string, senderPriv string, amountToSend uint64) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, lib._getBalance(testMeta.t, testMeta.chain, nil, senderPk))

	currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params, senderPk, recipientPk,
		senderPriv, amountToSend, 11 /*feerate*/)

	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _updateUSDCentsPerBitcoinExchangeRate(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, usdCentsPerBitcoin uint64) (
	_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := types.Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateUpdateBitcoinUSDExchangeRateTxn(
		updaterPkBytes,
		usdCentsPerBitcoin,
		feeRateNanosPerKB,
		nil,
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, updaterPrivBase58Check)

	utxoView, err := NewUtxoView(db, params, nil)
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
		OperationTypeUpdateBitcoinUSDExchangeRate, utxoOps[len(utxoOps)-1].Type)

	return utxoOps, txn, blockHeight, nil
}

func _updateGlobalParamsEntry(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, usdCentsPerBitcoin int64, minimumNetworkFeesNanosPerKB int64,
	createProfileFeeNanos int64, createNFTFeeNanos int64, maxCopiesPerNFT int64, flushToDb bool) (
	_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := types.Base58CheckDecode(updaterPkBase58Check)
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
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, updaterPrivBase58Check)

	utxoView, err := NewUtxoView(db, params, nil)
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
		require.NoError(utxoView.FlushToDb())
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
		lib._getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))

	currentOps, currentTxn, _, err := _updateGlobalParamsEntry(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		int64(types.InitialUSDCentsPerBitcoinExchangeRate),
		minimumNetworkFeeNanosPerKb,
		createProfileFeeNanos,
		createNFTFeeNanos,
		maxCopiesPerNFT,
		true) /*flushToDB*/
	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _submitPost(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, postHashToModify []byte,
	parentStakeID []byte,
	bodyObj *network.DeSoBodySchema,
	repostedPostHash []byte,
	tstampNanos uint64,
	isHidden bool) (
	_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := types.Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	body, err := json.Marshal(bodyObj)
	require.NoError(err)

	isQuotedRepost := false
	if len(repostedPostHash) > 0 && (bodyObj.Body != "" || len(bodyObj.ImageURLs) > 0 || len(bodyObj.VideoURLs) > 0) {
		isQuotedRepost = true
	}
	postExtraData := make(map[string][]byte)
	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateSubmitPostTxn(
		updaterPkBytes,
		postHashToModify,
		parentStakeID,
		body,
		repostedPostHash,
		isQuotedRepost,
		tstampNanos,
		postExtraData,
		isHidden,
		feeRateNanosPerKB,
		nil,
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, updaterPrivBase58Check)

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
	require.Equal(OperationTypeSubmitPost, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

type TestMeta struct {
	t                      *testing.T
	chain                  *lib.Blockchain
	db                     *badger.DB
	params                 *types.DeSoParams
	mempool                *lib.DeSoMempool
	miner                  *lib.DeSoMiner
	txnOps                 [][]*UtxoOperation
	txns                   []*network.MsgDeSoTxn
	expectedSenderBalances []uint64
	savedHeight            uint32
}

func _submitPostWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	updaterPkBase58Check string,
	updaterPrivBase58Check string,
	postHashToModify []byte,
	parentStakeID []byte,
	body *network.DeSoBodySchema,
	repostedPostHash []byte,
	tstampNanos uint64,
	isHidden bool) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, lib._getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))

	currentOps, currentTxn, _, err := _submitPost(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params, feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		postHashToModify,
		parentStakeID,
		body,
		repostedPostHash,
		tstampNanos,
		isHidden)

	require.NoError(testMeta.t, err)

	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _createNFT(t *testing.T, chain *lib.Blockchain, db *badger.DB, params *types.DeSoParams,
	feeRateNanosPerKB uint64, updaterPkBase58Check string, updaterPrivBase58Check string,
	nftPostHash *types.BlockHash, numCopies uint64, hasUnlockable bool, isForSale bool, minBidAmountNanos uint64,
	nftFee uint64, nftRoyaltyToCreatorBasisPoints uint64, nftRoyaltyToCoinBasisPoints uint64,
) (_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := types.Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateCreateNFTTxn(
		updaterPkBytes,
		nftPostHash,
		numCopies,
		hasUnlockable,
		isForSale,
		minBidAmountNanos,
		nftFee,
		nftRoyaltyToCreatorBasisPoints,
		nftRoyaltyToCoinBasisPoints,
		feeRateNanosPerKB,
		nil, []*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	// Note: the "nftFee" is the "spendAmount" and therefore must be added to feesMake.
	require.Equal(totalInputMake, changeAmountMake+feesMake+nftFee)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, updaterPrivBase58Check)

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
	// for each output, and one OperationTypeCreateNFT operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeCreateNFT, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _createNFTWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	updaterPkBase58Check string,
	updaterPrivBase58Check string,
	postHashToModify *types.BlockHash,
	numCopies uint64,
	hasUnlockable bool,
	isForSale bool,
	minBidAmountNanos uint64,
	nftFee uint64,
	nftRoyaltyToCreatorBasisPoints uint64,
	nftRoyaltyToCoinBasisPoints uint64,
) {
	// Sanity check: the number of NFT entries before should be 0.
	dbNFTEntries := db.DBGetNFTEntriesForPostHash(testMeta.db, postHashToModify)
	require.Equal(testMeta.t, 0, len(dbNFTEntries))

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, lib._getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))
	currentOps, currentTxn, _, err := _createNFT(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params, feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		postHashToModify,
		numCopies,
		hasUnlockable,
		isForSale,
		minBidAmountNanos,
		nftFee,
		nftRoyaltyToCreatorBasisPoints,
		nftRoyaltyToCoinBasisPoints,
	)
	require.NoError(testMeta.t, err)

	// Sanity check: the number of NFT entries after should be numCopies.
	dbNFTEntries = db.DBGetNFTEntriesForPostHash(testMeta.db, postHashToModify)
	require.Equal(testMeta.t, int(numCopies), len(dbNFTEntries))

	// Sanity check that the first entry has serial number 1.
	require.Equal(testMeta.t, uint64(1), dbNFTEntries[0].SerialNumber)

	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _giveDeSoDiamonds(t *testing.T, chain *lib.Blockchain, db *badger.DB, params *types.DeSoParams,
	feeRateNanosPerKB uint64, senderPkBase58Check string, senderPrivBase58Check string,
	diamondPostHash *types.BlockHash, diamondLevel int64, deleteDiamondLevel bool,
) (_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	senderPkBytes, _, err := types.Base58CheckDecode(senderPkBase58Check)
	require.NoError(t, err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(t, err)

	txn, totalInputMake, spendAmount, changeAmountMake, feesMake, err := chain.CreateBasicTransferTxnWithDiamonds(
		senderPkBytes,
		diamondPostHash,
		diamondLevel,
		feeRateNanosPerKB,
		nil,
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(t, totalInputMake, spendAmount+changeAmountMake+feesMake)

	// For testing purposes.
	if deleteDiamondLevel {
		delete(txn.ExtraData, types.DiamondLevelKey)
	}

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, senderPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(t, totalInput, totalOutput+fees)
	require.Equal(t, totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeDeSoDiamond operation at the end.
	require.Equal(t, len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(t, OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(t, OperationTypeDeSoDiamond, utxoOps[len(utxoOps)-1].Type)

	require.NoError(t, utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _giveDeSoDiamondsWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	senderPkBase58Check string,
	senderPrivBase58Check string,
	postHashToModify *types.BlockHash,
	diamondLevel int64,
) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, lib._getBalance(testMeta.t, testMeta.chain, nil, senderPkBase58Check))
	currentOps, currentTxn, _, err := _giveDeSoDiamonds(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params, feeRateNanosPerKB,
		senderPkBase58Check,
		senderPrivBase58Check,
		postHashToModify,
		diamondLevel,
		false,
	)
	require.NoError(testMeta.t, err)

	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _createNFTBid(t *testing.T, chain *lib.Blockchain, db *badger.DB, params *types.DeSoParams,
	feeRateNanosPerKB uint64, updaterPkBase58Check string, updaterPrivBase58Check string,
	nftPostHash *types.BlockHash, serialNumber uint64, bidAmountNanos uint64,
) (_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := types.Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateNFTBidTxn(
		updaterPkBytes,
		nftPostHash,
		serialNumber,
		bidAmountNanos,
		feeRateNanosPerKB,
		nil,
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, updaterPrivBase58Check)

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
	// for each output, and one OperationTypeNFTBid operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeNFTBid, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _createNFTBidWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	updaterPkBase58Check string,
	updaterPrivBase58Check string,
	postHash *types.BlockHash,
	serialNumber uint64,
	bidAmountNanos uint64,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, lib._getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))
	currentOps, currentTxn, _, err := _createNFTBid(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params, feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		postHash,
		serialNumber,
		bidAmountNanos,
	)
	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _acceptNFTBid(t *testing.T, chain *lib.Blockchain, db *badger.DB, params *types.DeSoParams,
	feeRateNanosPerKB uint64, updaterPkBase58Check string, updaterPrivBase58Check string, nftPostHash *types.BlockHash,
	serialNumber uint64, bidderPkBase58Check string, bidAmountNanos uint64, unencryptedUnlockableText string,
) (_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := types.Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	bidderPkBytes, _, err := types.Base58CheckDecode(bidderPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	bidderPKID := utxoView.GetPKIDForPublicKey(bidderPkBytes)
	require.NotNil(bidderPKID)
	require.False(bidderPKID.isDeleted)
	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateAcceptNFTBidTxn(
		updaterPkBytes,
		nftPostHash,
		serialNumber,
		bidderPKID.PKID,
		bidAmountNanos,
		[]byte(unencryptedUnlockableText),
		feeRateNanosPerKB,
		nil,
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, updaterPrivBase58Check)

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

	// We should have one SPEND UtxoOperation for each input, one SPEND
	// operation for each BidderInpout, one ADD operation
	// for each output, and one OperationTypeAcceptNFTBid operation at the end.
	numInputs := len(txn.TxInputs) + len(txn.TxnMeta.(*network.AcceptNFTBidMetadata).BidderInputs)
	numOps := len(utxoOps)
	for ii := 0; ii < numInputs; ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	for ii := numInputs; ii < numOps-1; ii++ {
		require.Equal(OperationTypeAddUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeAcceptNFTBid, utxoOps[numOps-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _acceptNFTBidWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	updaterPkBase58Check string,
	updaterPrivBase58Check string,
	postHash *types.BlockHash,
	serialNumber uint64,
	bidderPkBase58Check string,
	bidAmountNanos uint64,
	unencryptedUnlockableText string,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, lib._getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))
	currentOps, currentTxn, _, err := _acceptNFTBid(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params, feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		postHash,
		serialNumber,
		bidderPkBase58Check,
		bidAmountNanos,
		unencryptedUnlockableText,
	)
	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _updateNFT(t *testing.T, chain *lib.Blockchain, db *badger.DB, params *types.DeSoParams,
	feeRateNanosPerKB uint64, updaterPkBase58Check string, updaterPrivBase58Check string,
	nftPostHash *types.BlockHash, serialNumber uint64, isForSale bool, minBidAmountNanos uint64,
) (_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := types.Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateUpdateNFTTxn(
		updaterPkBytes,
		nftPostHash,
		serialNumber,
		isForSale,
		minBidAmountNanos,
		feeRateNanosPerKB,
		nil,
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, updaterPrivBase58Check)

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
	// for each output, and one OperationTypeUpdateNFT operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeUpdateNFT, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _updateNFTWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	updaterPkBase58Check string,
	updaterPrivBase58Check string,
	postHash *types.BlockHash,
	serialNumber uint64,
	isForSale bool,
	minBidAmountNanos uint64,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, lib._getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))
	currentOps, currentTxn, _, err := _updateNFT(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params, feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		postHash,
		serialNumber,
		isForSale,
		minBidAmountNanos,
	)
	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _transferNFT(t *testing.T, chain *lib.Blockchain, db *badger.DB, params *types.DeSoParams,
	feeRateNanosPerKB uint64, senderPk string, senderPriv string, receiverPk string,
	nftPostHash *types.BlockHash, serialNumber uint64, unlockableText string,
) (_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := types.Base58CheckDecode(senderPk)
	require.NoError(err)

	receiverPkBytes, _, err := types.Base58CheckDecode(receiverPk)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateNFTTransferTxn(
		senderPkBytes,
		receiverPkBytes,
		nftPostHash,
		serialNumber,
		[]byte(unlockableText),
		feeRateNanosPerKB,
		nil,
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, senderPriv)

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
	// for each output, and one OperationTypeNFTTransfer operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeNFTTransfer, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _transferNFTWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	senderPkBase58Check string,
	senderPrivBase58Check string,
	receiverPkBase58Check string,
	postHash *types.BlockHash,
	serialNumber uint64,
	unlockableText string,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, lib._getBalance(testMeta.t, testMeta.chain, nil, senderPkBase58Check))
	currentOps, currentTxn, _, err := _transferNFT(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params, feeRateNanosPerKB,
		senderPkBase58Check,
		senderPrivBase58Check,
		receiverPkBase58Check,
		postHash,
		serialNumber,
		unlockableText,
	)
	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _acceptNFTTransfer(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, nftPostHash *types.BlockHash, serialNumber uint64,
) (_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := types.Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateAcceptNFTTransferTxn(
		updaterPkBytes,
		nftPostHash,
		serialNumber,
		feeRateNanosPerKB,
		nil,
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, updaterPrivBase58Check)

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
	// for each output, and one OperationTypeNFTTransfer operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeAcceptNFTTransfer, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _acceptNFTTransferWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	updaterPkBase58Check string,
	updaterPrivBase58Check string,
	postHash *types.BlockHash,
	serialNumber uint64,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, lib._getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))
	currentOps, currentTxn, _, err := _acceptNFTTransfer(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params, feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		postHash,
		serialNumber,
	)
	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _burnNFT(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, nftPostHash *types.BlockHash, serialNumber uint64,
) (_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := types.Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateBurnNFTTxn(
		updaterPkBytes,
		nftPostHash,
		serialNumber,
		feeRateNanosPerKB,
		nil,
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, updaterPrivBase58Check)

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
	// for each output, and one OperationTypeNFTTransfer operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeBurnNFT, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _burnNFTWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	updaterPkBase58Check string,
	updaterPrivBase58Check string,
	postHash *types.BlockHash,
	serialNumber uint64,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, lib._getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))
	currentOps, currentTxn, _, err := _burnNFT(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params, feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		postHash,
		serialNumber,
	)
	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
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

		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, nil)
		require.NoError(testMeta.t, err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, testMeta.savedHeight)
		require.NoError(testMeta.t, err)

		require.NoError(testMeta.t, utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(
			testMeta.t,
			testMeta.expectedSenderBalances[backwardIter],
			lib._getBalance(testMeta.t, testMeta.chain, nil, types.PkToStringTestnet(currentTxn.PublicKey)),
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
			lib._getBalance(testMeta.t, testMeta.chain, testMeta.mempool, types.PkToStringTestnet(tx.PublicKey)))

		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		_, err := testMeta.mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(testMeta.t, err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}
}

func _applyTestMetaTxnsToViewAndFlush(testMeta *TestMeta) {
	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, nil)
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
	require.NoError(testMeta.t, utxoView.FlushToDb())
}

func _disconnectTestMetaTxnsFromViewAndFlush(testMeta *TestMeta) {
	// Disonnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, nil)
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
	require.NoError(testMeta.t, utxoView.FlushToDb())
	require.Equal(
		testMeta.t,
		testMeta.expectedSenderBalances[0],
		lib._getBalance(testMeta.t, testMeta.chain, nil, lib.senderPkString))
}

func _connectBlockThenDisconnectBlockAndFlush(testMeta *TestMeta) {
	// all those transactions in it.
	block, err := testMeta.miner.MineAndProcessSingleBlock(0 /*threadIndex*/, testMeta.mempool)
	require.NoError(testMeta.t, err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(testMeta.t, len(testMeta.txnOps)+1, len(block.Txns))

	// Roll back the block and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, nil)
		require.NoError(testMeta.t, err)

		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := block.Header.Hash()
		require.NoError(testMeta.t, err)
		utxoOps, err := db.GetUtxoOperationsForBlock(testMeta.db, hash)
		require.NoError(testMeta.t, err)

		// Compute the hashes for all the transactions.
		txHashes, err := lib.ComputeTransactionHashes(block.Txns)
		require.NoError(testMeta.t, err)
		require.NoError(testMeta.t, utxoView.DisconnectBlock(block, txHashes, utxoOps))

		// Flushing the view after applying and rolling back should work.
		require.NoError(testMeta.t, utxoView.FlushToDb())
	}
}

func _swapIdentity(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, fromPublicKey []byte, toPublicKey []byte) (
	_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := types.Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateSwapIdentityTxn(
		updaterPkBytes,
		fromPublicKey,
		toPublicKey,
		feeRateNanosPerKB,
		nil,
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, updaterPrivBase58Check)

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
	// for each output, and one OperationTypeSwapIdentity operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeSwapIdentity, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _updateProfile(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, profilePubKey []byte, newUsername string,
	newDescription string, newProfilePic string, newCreatorBasisPoints uint64,
	newStakeMultipleBasisPoints uint64, isHidden bool) (
	_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := types.Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateUpdateProfileTxn(
		updaterPkBytes,
		profilePubKey,
		newUsername,
		newDescription,
		newProfilePic,
		newCreatorBasisPoints,
		newStakeMultipleBasisPoints,
		isHidden,
		0,
		feeRateNanosPerKB,
		nil, /*mempool*/
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, updaterPrivBase58Check)

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
	// for each output, and one OperationTypeUpdateProfile operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeUpdateProfile, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _updateProfileWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	updaterPkBase58Check string,
	updaterPrivBase58Check string,
	profilePubKey []byte,
	newUsername string,
	newDescription string,
	newProfilePic string,
	newCreatorBasisPoints uint64,
	newStakeMultipleBasisPoints uint64,
	isHidden bool) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, lib._getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))

	currentOps, currentTxn, _, err := _updateProfile(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB, updaterPkBase58Check,
		updaterPrivBase58Check, profilePubKey, newUsername,
		newDescription, newProfilePic, newCreatorBasisPoints,
		newStakeMultipleBasisPoints, isHidden)

	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _getAuthorizeDerivedKeyMetadata(t *testing.T, ownerPrivateKey *btcec.PrivateKey,
	params *types.DeSoParams, expirationBlock uint64, isDeleted bool) (*network.AuthorizeDerivedKeyMetadata,
	*btcec.PrivateKey) {
	require := require.New(t)

	// Generate a random derived key pair
	derivedPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err, "_getAuthorizeDerivedKeyMetadata: Error generating a derived key pair")
	derivedPublicKey := derivedPrivateKey.PubKey().SerializeCompressed()

	// Create access signature
	expirationBlockByte := db.EncodeUint64(expirationBlock)
	accessBytes := append(derivedPublicKey, expirationBlockByte[:]...)
	accessSignature, err := ownerPrivateKey.Sign(types.Sha256DoubleHash(accessBytes)[:])
	require.NoError(err, "_getAuthorizeDerivedKeyMetadata: Error creating access signature")

	// Determine operation type
	var operationType network.AuthorizeDerivedKeyOperationType
	if isDeleted {
		operationType = network.AuthorizeDerivedKeyOperationNotValid
	} else {
		operationType = network.AuthorizeDerivedKeyOperationValid
	}

	return &network.AuthorizeDerivedKeyMetadata{
		derivedPublicKey,
		expirationBlock,
		operationType,
		accessSignature.Serialize(),
	}, derivedPrivateKey
}

// Create a new AuthorizeDerivedKey txn and connect it to the utxoView
func _doAuthorizeTxn(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, utxoView *UtxoView, feeRateNanosPerKB uint64, ownerPublicKey []byte,
	derivedPublicKey []byte, derivedPrivBase58Check string, expirationBlock uint64,
	accessSignature []byte, deleteKey bool) (_utxoOps []*UtxoOperation,
	_txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	txn, totalInput, changeAmount, fees, err := chain.CreateAuthorizeDerivedKeyTxn(
		ownerPublicKey,
		derivedPublicKey,
		expirationBlock,
		accessSignature,
		deleteKey,
		false,
		feeRateNanosPerKB,
		nil, /*mempool*/
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInput, changeAmount+fees)

	// Sign the transaction now that its inputs are set up.
	// We have to set the solution byte because we're signing
	// the transaction with derived key on behalf of the owner.
	lib._signTxnWithDerivedKey(t, txn, derivedPrivBase58Check)

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
	require.Equal(totalInput, totalInput)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeUpdateProfile operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeAuthorizeDerivedKey, utxoOps[len(utxoOps)-1].Type)

	return utxoOps, txn, blockHeight, nil
}

func _creatorCoinTxn(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, feeRateNanosPerKB uint64,
	UpdaterPublicKeyBase58Check string,
	UpdaterPrivateKeyBase58Check string,
	// See CreatorCoinMetadataa for an explanation of these fields.
	ProfilePublicKeyBase58Check string,
	OperationType network.CreatorCoinOperationType,
	DeSoToSellNanos uint64,
	CreatorCoinToSellNanos uint64,
	DeSoToAddNanos uint64,
	MinDeSoExpectedNanos uint64,
	MinCreatorCoinExpectedNanos uint64) (
	_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := types.Base58CheckDecode(UpdaterPublicKeyBase58Check)
	require.NoError(err)

	profilePkBytes, _, err := types.Base58CheckDecode(ProfilePublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateCreatorCoinTxn(
		updaterPkBytes,
		profilePkBytes,
		OperationType,
		DeSoToSellNanos,
		CreatorCoinToSellNanos,
		DeSoToAddNanos,
		MinDeSoExpectedNanos,
		MinCreatorCoinExpectedNanos,
		feeRateNanosPerKB,
		nil, /*mempool*/
		[]*network.DeSoOutput{})

	if err != nil {
		return nil, nil, 0, err
	}

	if OperationType == network.CreatorCoinOperationTypeBuy {
		require.Equal(int64(totalInputMake), int64(changeAmountMake+feesMake+DeSoToSellNanos))
	} else {
		require.Equal(int64(totalInputMake), int64(changeAmountMake+feesMake))
	}

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, UpdaterPrivateKeyBase58Check)

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
	require.GreaterOrEqual(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeCreatorCoin operation at the end.
	numInputs := len(txn.TxInputs)
	numOps := len(utxoOps)
	for ii := 0; ii < numInputs; ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	for ii := numInputs; ii < numOps-1; ii++ {
		require.Equal(OperationTypeAddUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeCreatorCoin, utxoOps[numOps-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _creatorCoinTxnWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	UpdaterPublicKeyBase58Check string,
	UpdaterPrivateKeyBase58Check string,
	// See CreatorCoinMetadataa for an explanation of these fields.
	ProfilePublicKeyBase58Check string,
	OperationType network.CreatorCoinOperationType,
	DeSoToSellNanos uint64,
	CreatorCoinToSellNanos uint64,
	DeSoToAddNanos uint64,
	MinDeSoExpectedNanos uint64,
	MinCreatorCoinExpectedNanos uint64) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, lib._getBalance(testMeta.t, testMeta.chain, nil, UpdaterPublicKeyBase58Check))

	currentOps, currentTxn, _, err := _creatorCoinTxn(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB, UpdaterPublicKeyBase58Check,
		UpdaterPrivateKeyBase58Check, ProfilePublicKeyBase58Check, OperationType,
		DeSoToSellNanos, CreatorCoinToSellNanos, DeSoToAddNanos,
		MinDeSoExpectedNanos, MinCreatorCoinExpectedNanos)

	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _doCreatorCoinTransferTxnWithDiamonds(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, feeRateNanosPerKB uint64,
	SenderPublicKeyBase58Check string,
	SenderPrivBase58Check string,
	ReceiverPublicKeyBase58Check string,
	DiamondPostHash *types.BlockHash,
	DiamondLevel int64) (
	_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := types.Base58CheckDecode(SenderPublicKeyBase58Check)
	require.NoError(err)

	receiverPkBytes, _, err := types.Base58CheckDecode(ReceiverPublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
		senderPkBytes,
		receiverPkBytes,
		DiamondPostHash,
		DiamondLevel,
		feeRateNanosPerKB, nil, []*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, SenderPrivBase58Check)

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
	require.GreaterOrEqual(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeCreatorCoinTransfer operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeCreatorCoinTransfer, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _doCreatorCoinTransferTxn(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, feeRateNanosPerKB uint64,
	UpdaterPublicKeyBase58Check string, UpdaterPrivateKeyBase58Check string,
	// See CreatorCoinTransferMetadataa for an explanation of these fields.
	ProfilePublicKeyBase58Check string,
	ReceiverPublicKeyBase58Check string,
	CreatorCoinToTransferNanos uint64) (
	_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := types.Base58CheckDecode(UpdaterPublicKeyBase58Check)
	require.NoError(err)

	profilePkBytes, _, err := types.Base58CheckDecode(ProfilePublicKeyBase58Check)
	require.NoError(err)

	receiverPkBytes, _, err := types.Base58CheckDecode(ReceiverPublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, _, _, err := chain.CreateCreatorCoinTransferTxn(
		updaterPkBytes,
		profilePkBytes,
		CreatorCoinToTransferNanos,
		receiverPkBytes,
		feeRateNanosPerKB,
		nil, /*mempool*/
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, UpdaterPrivateKeyBase58Check)

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
	// for each output, and one OperationTypeCreatorCoinTransfer operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeCreatorCoinTransfer, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _doSubmitPostTxn(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, feeRateNanosPerKB uint64,
	UpdaterPublicKeyBase58Check string, UpdaterPrivateKeyBase58Check string,
	postHashToModify []byte,
	parentPostHashBytes []byte,
	body string,
	extraData map[string][]byte,
	isHidden bool) (
	_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := types.Base58CheckDecode(UpdaterPublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, _, _, err := chain.CreateSubmitPostTxn(
		updaterPkBytes,
		postHashToModify,
		parentPostHashBytes,
		[]byte(body),
		nil,
		false,
		uint64(time.Now().UnixNano()),
		extraData,
		isHidden,
		feeRateNanosPerKB,
		nil, /*mempool*/
		[]*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, UpdaterPrivateKeyBase58Check)

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
	require.GreaterOrEqual(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeSubmitPost operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeSubmitPost, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _privateMessage(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, feeRateNanosPerKB uint64, senderPkBase58Check string,
	recipientPkBase58Check string,
	senderPrivBase58Check string, unencryptedMessageText string, tstampNanos uint64) (
	_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := types.Base58CheckDecode(senderPkBase58Check)
	require.NoError(err)

	recipientPkBytes, _, err := types.Base58CheckDecode(recipientPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreatePrivateMessageTxn(
		senderPkBytes, recipientPkBytes, unencryptedMessageText, "",
		tstampNanos, feeRateNanosPerKB, nil, []*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, senderPrivBase58Check)

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
	require.Equal(OperationTypePrivateMessage, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _doLikeTxn(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, feeRateNanosPerKB uint64, senderPkBase58Check string,
	likedPostHash types.BlockHash, senderPrivBase58Check string, isUnfollow bool) (
	_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := types.Base58CheckDecode(senderPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateLikeTxn(
		senderPkBytes, likedPostHash, isUnfollow, feeRateNanosPerKB, nil, []*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, senderPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true, /*verifySignature*/
			false /*ignoreUtxos*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeLike operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeLike, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _doFollowTxn(t *testing.T, chain *lib.Blockchain, db *badger.DB,
	params *types.DeSoParams, feeRateNanosPerKB uint64, senderPkBase58Check string,
	followedPkBase58Check string, senderPrivBase58Check string, isUnfollow bool) (
	_utxoOps []*UtxoOperation, _txn *network.MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := types.Base58CheckDecode(senderPkBase58Check)
	require.NoError(err)

	followedPkBytes, _, err := types.Base58CheckDecode(followedPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateFollowTxn(
		senderPkBytes, followedPkBytes, isUnfollow, feeRateNanosPerKB, nil, []*network.DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	lib._signTxn(t, txn, senderPrivBase58Check)

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
	// for each output, and one OperationTypeFollow operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeFollow, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

const (
	longPic       string = "data:image/jpeg;base64,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"
	shortPic      string = "data:image/jpeg;base64,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"
	otherShortPic string = "data:image/jpeg;base64,/9j/2wCEAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDIBCQkJDAsMGA0NGDIhHCEyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMv/AABEIAGQAZAMBIgACEQEDEQH/xAGiAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgsQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+gEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoLEQACAQIEBAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXxFxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo6ery8/T19vf4+fr/2gAMAwEAAhEDEQA/APf6KKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAoopGJVSQpYgcAd6AForyO++JmrHUJCgg05bZyj2dxHuckcEOeD/wB8fma7SDxpDH4Stte1OxurRJ3WNIVQyO5Y4UqBzhu2QDz0rSdKUEpPqZQrRnJxj08jqKKwbTxdp17p9/cwR3ZksB+/tGt2SdTjcAEbBJI6etXptasLU2KXU4gkvmCQRyAhmbaWwR2OAevpWZqaFFc5qfjfRtJv5bS5kuD5Gw3M8UDPFbb/ALvmOOFzViz8TQXfiSfQ2sryC5ihadZJkURyxhgu5SGJIJPcCgDbopnmx/N86/L97np9ar6hqVnpdjPe3twkNvAhkkdudq+uBzQBbopkM0c8SyROHRgCCD1p9ABRRRQAUjbtp2kBscZGRS0UAfP/AIkOqN4guzrccn29WAcW0a+XKv8AAU7gHpzkn7pzjFd34hsvEWo/DywXULaSbUlvbeaWOxTEiRrID9N4XqRgZ6V291o+n3t/a31zaxyXNoSYZGHKZ/n+PQ81exSV+rua1JwlFKMUn1fc8dvNEu7jQPE3m+H9WvVvmT+z2vYlkuxMImXe5z8qLwFPUZPFamt6UNU03wxqk3hm6uPsUyw3tvJbKZzCI2XG3PzLvIOPxr07FGKZkeb2R1HQb3WY7Xwvd3cerSQz2URRViRfLVDHMcny9u3pg8dKmvJ9Sk+IUtxbaPqcSHTH02O6EA8tZjJkPnP3B1z+lehYoxQB4gfCeq3Witaaf4fu7G8j0eaDUpJsAX05KlcHJ8w7lZg3vitbU9Ev/FDeJLj+wrqIz6PAlkt7EEYzp5nTk4YZ46dfevWcUYoA5/wetpHoax2miz6SqsN8M1uISz7RlsA8+mfaugoooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAP/9k="
)

const (
	BitcoinTestnetMnemonic       = "clump donkey smoke"
	BitcoinTestnetDerivationPath = "m/44'/1'/0'/"

	BitcoinTestnetBurnAddress = "ms9ybkD3E685i54ZqW8osN7qg3KnQXZabH"
	BitcoinTestnetBurnPub     = "02bcb72f2dcc0a21aaa31ba792c8bf4a13e3393d7d1b3073afbac613a06dd1d99f"
	BitcoinTestnetBurnPriv    = "cUFfryF4sMvdPzcXMXRVFfK4D5wZzsbZDEqGfBdb7o2MJfE9aoiN"

	BitcoinTestnetAddress1 = "mqsT6WSy5D1xa2GGxsVm1dPGrk7shccwk3"
	BitcoinTestnetPub1     = "02bce3413e2c2eb510208fefd883861f4d65ac494070a76a837196ea663c00f23c"
	BitcoinTestnetPriv1    = "cQ6NjLY85qGNpEr8rsHZRs4USVpYVLUzYiqufVTpw2gvQ3Hrcfdf"

	BitcoinTestnetAddress2 = "mzcT3DXVuEZho8FZS6428Tk8gbyDTeBRyF"
	BitcoinTestnetPub2     = "0368bb82e27246e4fc386eb641fee1ae7bc0b0e0684753a58c64370eab9573ce80"
	BitcoinTestnetPriv2    = "cR2cSmj3pZ51JGjVzmvHiJwAY1m7tb9x8FCesdSkqzBUHayzifM8"

	BitcoinTestnetAddress3 = "myewf7QQJbXhzdx8QUZuxbtqUuD71Dhwy2"
	BitcoinTestnetPub3     = "03da23d9ac943570a2ecf543733c3f39b8037144397b3bd2306e881539170e47d6"
	BitcoinTestnetPriv3    = "cU5PpBsfZbiHfFaCoBVDnCo8wYEUjkr4NxbhnRcSd5qPvG5ofKvN"

	TestDataDir = "../test_data"
)
