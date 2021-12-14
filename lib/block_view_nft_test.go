package lib

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math"
	"reflect"
	"testing"
)

func _createNFT(t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams,
	feeRateNanosPerKB uint64, updaterPkBase58Check string, updaterPrivBase58Check string,
	nftPostHash *BlockHash, numCopies uint64, hasUnlockable bool, isForSale bool, minBidAmountNanos uint64,
	nftFee uint64, nftRoyaltyToCreatorBasisPoints uint64, nftRoyaltyToCoinBasisPoints uint64,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(updaterPkBase58Check)
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
		nil, []*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	// Note: the "nftFee" is the "spendAmount" and therefore must be added to feesMake.
	require.Equal(totalInputMake, changeAmountMake+feesMake+nftFee)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, updaterPrivBase58Check)

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
	postHashToModify *BlockHash,
	numCopies uint64,
	hasUnlockable bool,
	isForSale bool,
	minBidAmountNanos uint64,
	nftFee uint64,
	nftRoyaltyToCreatorBasisPoints uint64,
	nftRoyaltyToCoinBasisPoints uint64,
) {
	// Sanity check: the number of NFT entries before should be 0.
	dbNFTEntries := DBGetNFTEntriesForPostHash(testMeta.db, postHashToModify)
	require.Equal(testMeta.t, 0, len(dbNFTEntries))

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))
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
	dbNFTEntries = DBGetNFTEntriesForPostHash(testMeta.db, postHashToModify)
	require.Equal(testMeta.t, int(numCopies), len(dbNFTEntries))

	// Sanity check that the first entry has serial number 1.
	require.Equal(testMeta.t, uint64(1), dbNFTEntries[0].SerialNumber)

	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _createNFTBid(t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams,
	feeRateNanosPerKB uint64, updaterPkBase58Check string, updaterPrivBase58Check string,
	nftPostHash *BlockHash, serialNumber uint64, bidAmountNanos uint64,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(updaterPkBase58Check)
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
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, updaterPrivBase58Check)

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
	postHash *BlockHash,
	serialNumber uint64,
	bidAmountNanos uint64,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))
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

func _acceptNFTBid(t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams,
	feeRateNanosPerKB uint64, updaterPkBase58Check string, updaterPrivBase58Check string, nftPostHash *BlockHash,
	serialNumber uint64, bidderPkBase58Check string, bidAmountNanos uint64, unencryptedUnlockableText string,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	bidderPkBytes, _, err := Base58CheckDecode(bidderPkBase58Check)
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
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, updaterPrivBase58Check)

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
	numInputs := len(txn.TxInputs) + len(txn.TxnMeta.(*AcceptNFTBidMetadata).BidderInputs)
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
	postHash *BlockHash,
	serialNumber uint64,
	bidderPkBase58Check string,
	bidAmountNanos uint64,
	unencryptedUnlockableText string,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))
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

func _updateNFT(t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams,
	feeRateNanosPerKB uint64, updaterPkBase58Check string, updaterPrivBase58Check string,
	nftPostHash *BlockHash, serialNumber uint64, isForSale bool, minBidAmountNanos uint64,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(updaterPkBase58Check)
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
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, updaterPrivBase58Check)

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
	postHash *BlockHash,
	serialNumber uint64,
	isForSale bool,
	minBidAmountNanos uint64,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))
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

func _transferNFT(t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams,
	feeRateNanosPerKB uint64, senderPk string, senderPriv string, receiverPk string,
	nftPostHash *BlockHash, serialNumber uint64, unlockableText string,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := Base58CheckDecode(senderPk)
	require.NoError(err)

	receiverPkBytes, _, err := Base58CheckDecode(receiverPk)
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
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, senderPriv)

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
	postHash *BlockHash,
	serialNumber uint64,
	unlockableText string,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, senderPkBase58Check))
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

func _acceptNFTTransfer(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, nftPostHash *BlockHash, serialNumber uint64,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateAcceptNFTTransferTxn(
		updaterPkBytes,
		nftPostHash,
		serialNumber,
		feeRateNanosPerKB,
		nil,
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, updaterPrivBase58Check)

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
	postHash *BlockHash,
	serialNumber uint64,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))
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

func _burnNFT(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, nftPostHash *BlockHash, serialNumber uint64,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateBurnNFTTxn(
		updaterPkBytes,
		nftPostHash,
		serialNumber,
		feeRateNanosPerKB,
		nil,
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, updaterPrivBase58Check)

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
	postHash *BlockHash,
	serialNumber uint64,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))
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

func TestNFTBasic(t *testing.T) {
	BrokenNFTBidsFixBlockHeight = uint32(0)

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 70)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 420)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 140)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 210)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)

	// Set max copies to a non-zero value to activate NFTs.
	{
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m4Pub,
			m4Priv,
			-1, -1, -1, -1,
			1000, /*maxCopiesPerNFT*/
		)
	}

	// Create a simple post.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-1].Hash()

	// Error case: can't make an NFT without a profile.
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			100,   /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCantCreateNFTWithoutProfileEntry)
	}

	// Create a profile so we can make an NFT.
	{
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Error case: m0 cannot turn a vanilla repost of their post into an NFT.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                /*feeRateNanosPerKB*/
			m0Pub,             /*updaterPkBase58Check*/
			m0Priv,            /*updaterPrivBase58Check*/
			[]byte{},          /*postHashToModify*/
			[]byte{},          /*parentStakeID*/
			&DeSoBodySchema{}, /*body*/
			post1Hash[:],      /*repostedPostHash*/
			1502947011*1e9,    /*tstampNanos*/
			false /*isHidden*/)

		vanillaRepostPostHash := testMeta.txns[len(testMeta.txns)-1].Hash()
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			vanillaRepostPostHash,
			100,   /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreateNFTOnVanillaRepost)
	}

	// Error case: m1 should not be able to turn m0's post into an NFT.
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			100,   /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreateNFTMustBeCalledByPoster)
	}

	// Error case: m0 should not be able to make more than MaxCopiesPerNFT.
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1001,  /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorTooManyNFTCopies)
	}

	// Error case: m0 should not be able to make an NFT with zero copies.
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			0,     /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTMustHaveNonZeroCopies)
	}

	// Error case: non-existent post.
	{

		fakePostHash := &BlockHash{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}

		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			fakePostHash,
			1,     /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreateNFTOnNonexistentPost)
	}

	// Finally, have m0 turn post1 into an NFT. Woohoo!
	{
		// Balance before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(28), m0BalBeforeNFT)

		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			5,     /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		// Balance after. Since the default NFT fee is 0, m0 is only charged the nanos per kb fee.
		m0BalAfterNFT := _getBalance(testMeta.t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(27), m0BalAfterNFT)
	}

	// Error case: cannot turn a post into an NFT twice.
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			5,     /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreateNFTOnPostThatAlreadyIsNFT)
	}

	// Error case: cannot modify a post after it is NFTed.
	{
		_, _, _, err := _submitPost(
			testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
			10,
			m0Pub,
			m0Priv,
			post1Hash[:],
			[]byte{},
			&DeSoBodySchema{Body: "modified m0 post"},
			[]byte{},
			1502947011*1e9,
			false)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostCannotUpdateNFT)
	}

	// Now let's try adding a fee to creating NFT copies. This fee exists since creating
	// n-copies of an NFT causes the chain to do n-times as much work.
	{
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			-1, -1, -1,
			1,  /*createNFTFeeNanos*/
			-1, /*maxCopiesPerNFT*/
		)
	}

	// Have m0 create another post for us to NFTify.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 2"}, /*body*/
			[]byte{},
			1502947012*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post2Hash := testMeta.txns[len(testMeta.txns)-1].Hash()

	// Error case: creating an NFT without paying the nftFee should fail.
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post2Hash,
			1000,  /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreateNFTWithInsufficientFunds)
	}

	// Creating an NFT with the correct NFT fee should succeed.
	// This time set HasUnlockable to 'true'.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		numCopies := uint64(10)
		nftFee := utxoView.GlobalParamsEntry.CreateNFTFeeNanos * numCopies

		m0BalBeforeNFT := _getBalance(testMeta.t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(26), m0BalBeforeNFT)

		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post2Hash,
			10,     /*NumCopies*/
			true,   /*HasUnlockable*/
			true,   /*IsForSale*/
			0,      /*MinBidAmountNanos*/
			nftFee, /*nftFee*/
			0,      /*nftRoyaltyToCreatorBasisPoints*/
			0,      /*nftRoyaltyToCoinBasisPoints*/
		)

		// Check that m0 was charged the correct nftFee.
		m0BalAfterNFT := _getBalance(testMeta.t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(25)-nftFee, m0BalAfterNFT)
	}

	//
	// Bidding on NFTs
	//

	// Error case: non-existent NFT.
	{
		fakePostHash := &BlockHash{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}

		_, _, _, err := _createNFTBid(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			fakePostHash,
			1,          /*SerialNumber*/
			1000000000, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidOnNonExistentPost)
	}

	// Have m0 create another post that has not been NFTed.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 3"}, /*body*/
			[]byte{},
			1502947013*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post3Hash := testMeta.txns[len(testMeta.txns)-1].Hash()

	// Error case: cannot bid on a post that is not an NFT.
	{
		_, _, _, err := _createNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post3Hash,
			1,          /*SerialNumber*/
			1000000000, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidOnPostThatIsNotAnNFT)
	}

	// Error case: Bidding on a serial number that does not exist should fail (post1 has 5 copies).
	{
		_, _, _, err = _createNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			6,          /*SerialNumber*/
			1000000000, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidOnInvalidSerialNumber)
	}

	// Error case: cannot make a bid with a sufficient deso balance to fill the bid.
	{
		_, _, _, err = _createNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			1,          /*SerialNumber*/
			1000000000, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInsufficientFundsForNFTBid)
	}

	// Error case: m0 cannot bid on its own NFT.
	{
		_, _, _, err := _createNFTBid(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1,          /*SerialNumber*/
			1000000000, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTOwnerCannotBidOnOwnedNFT)
	}

	// Have m1 and m2 bid on post #1 / serial #1.
	{
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1, /*SerialNumber*/
			1, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1, /*SerialNumber*/
			2, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(2, len(bidEntries))
	}

	// Error case: m1 should not be able to accept or update m0's NFTs.
	{
		_, _, _, err := _updateNFT(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			1,     /*SerialNumber*/
			false, /*IsForSale*/
			0,     /*MinBidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorUpdateNFTByNonOwner)

		// m1 trying to be sneaky by accepting their own bid.
		_, _, _, err = _acceptNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			1, /*SerialNumber*/
			m1Pub,
			1,  /*BidAmountNanos*/
			"", /*UnlockableText*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorAcceptNFTBidByNonOwner)
	}

	// Error case: accepting a bid that does not match the bid entry.
	{
		// m0 trying to be sneaky by setting m1's bid amount to 100x.
		_, _, _, err = _acceptNFTBid(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1, /*SerialNumber*/
			m1Pub,
			100, /*BidAmountNanos*/
			"",  /*UnlockableText*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorAcceptedNFTBidAmountDoesNotMatch)
	}

	// Error case: can't accept a non-existent bid.
	{
		// m3 has not bid on this NFT.
		_, _, _, err = _acceptNFTBid(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1, /*SerialNumber*/
			m3Pub,
			200, /*BidAmountNanos*/
			"",  /*UnlockableText*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCantAcceptNonExistentBid)
	}

	// Error case: can't accept or update a non-existent NFT.
	{
		_, _, _, err := _updateNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			666,   /*SerialNumber*/
			false, /*IsForSale*/
			0,     /*MinBidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCannotUpdateNonExistentNFT)

		_, _, _, err = _acceptNFTBid(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			666, /*SerialNumber*/
			m1Pub,
			1,  /*BidAmountNanos*/
			"", /*UnlockableText*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidOnNonExistentNFTEntry)
	}

	// Error case: can't submit an update txn that doesn't actually update anything.
	{
		// <post1, #1> is already for sale.
		_, _, _, err := _updateNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			0,    /*MinBidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTUpdateMustUpdateIsForSaleStatus)
	}

	// Finally, accept m2's bid on <post1, #1>.
	{
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1, /*SerialNumber*/
			m2Pub,
			2,  /*BidAmountNanos*/
			"", /*UnlockableText*/
		)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))
	}

	// Update <post1, #2>, so that it is no longer for sale.
	{
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			2,     /*SerialNumber*/
			false, /*IsForSale*/
			0,     /*MinBidAmountNanos*/
		)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 2)
		require.Equal(0, len(bidEntries))
	}

	// Error case: <post1, #1> and <post1, #2> are no longer for sale and should not allow bids.
	{
		_, _, _, err := _createNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			1,          /*SerialNumber*/
			1000000000, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidOnNFTThatIsNotForSale)

		_, _, _, err = _createNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			2,          /*SerialNumber*/
			1000000000, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidOnNFTThatIsNotForSale)
	}

	// Have m1, m2, and m3 bid on <post #2, #1> (which has an unlockable).
	{
		bidEntries := DBGetNFTBidEntries(db, post2Hash, 1)
		require.Equal(0, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post2Hash,
			1, /*SerialNumber*/
			5, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post2Hash, 1)
		require.Equal(1, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post2Hash,
			1,  /*SerialNumber*/
			10, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post2Hash, 1)
		require.Equal(2, len(bidEntries))

		// m1 updates their bid to outbid m2.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post2Hash,
			1,  /*SerialNumber*/
			11, /*BidAmountNanos*/
		)

		// The number of bid entries should not change since this is just an update.
		bidEntries = DBGetNFTBidEntries(db, post2Hash, 1)
		require.Equal(2, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post2Hash,
			1,  /*SerialNumber*/
			12, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post2Hash, 1)
		require.Equal(3, len(bidEntries))

		// m1 updates their bid to outbid m3.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post2Hash,
			1,  /*SerialNumber*/
			13, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post2Hash, 1)
		require.Equal(3, len(bidEntries))
	}

	// Error case: can't accept a bid for an unlockable NFT, without providing the unlockable.
	{
		_, _, _, err = _acceptNFTBid(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post2Hash,
			1, /*SerialNumber*/
			m3Pub,
			12, /*BidAmountNanos*/
			"", /*UnencryptedUnlockableText*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorUnlockableNFTMustProvideUnlockableText)
	}

	{
		unencryptedUnlockableText := "this is an unlockable string"

		// Accepting the bid with an unlockable string should work.
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post2Hash,
			1,                         /*SerialNumber*/
			m3Pub,                     /*bidderPkBase58Check*/
			12,                        /*BidAmountNanos*/
			unencryptedUnlockableText, /*UnencryptedUnlockableText*/
		)

		// Check and make sure the unlockable looks gucci.
		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, post2Hash, 1)
		require.Equal(nftEntry.IsForSale, false)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestNFTRoyaltiesAndSpendingOfBidderUTXOs(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 100)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 15000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)

	// Set max copies to a non-zero value to activate NFTs.
	{
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m4Pub,
			m4Priv,
			-1, -1, -1, -1,
			1000, /*maxCopiesPerNFT*/
		)
	}

	// Create a simple post.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-1].Hash()

	// Create a profile so me can make an NFT.
	{
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Make sure that m0 has coins in circulation so that creator coin royalties can be paid.
	{
		_creatorCoinTxnWithTestMeta(
			testMeta,
			10,     /*feeRateNanosPerKB*/
			m0Pub,  /*updaterPkBase58Check*/
			m0Priv, /*updaterPrivBase58Check*/
			m0Pub,  /*profilePubKeyBase58Check*/
			CreatorCoinOperationTypeBuy,
			29, /*DeSoToSellNanos*/
			0,  /*CreatorCoinToSellNanos*/
			0,  /*DeSoToAddNanos*/
			0,  /*MinDeSoExpectedNanos*/
			10, /*MinCreatorCoinExpectedNanos*/
		)

		m0Bal := _getBalance(testMeta.t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(30), m0Bal)
	}
	// Initial deso locked before royalties.
	m0InitialDeSoLocked, _ := _getCreatorCoinInfo(t, db, params, m0Pub)
	require.Equal(uint64(28), m0InitialDeSoLocked)

	// Error case: m0 should not be able to set >10000 basis points in royalties.
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			10,    /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			10000, /*nftRoyaltyToCreatorBasisPoints*/
			1,     /*nftRoyaltyToCoinBasisPoints*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTRoyaltyHasTooManyBasisPoints)

		_, _, _, err = _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			10,    /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			1,     /*nftRoyaltyToCreatorBasisPoints*/
			10000, /*nftRoyaltyToCoinBasisPoints*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTRoyaltyHasTooManyBasisPoints)
	}

	// Error case: royalty values big enough to overflow should fail.
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			10,               /*NumCopies*/
			false,            /*HasUnlockable*/
			true,             /*IsForSale*/
			0,                /*MinBidAmountNanos*/
			0,                /*nftFee*/
			math.MaxUint64-1, /*nftRoyaltyToCreatorBasisPoints*/
			2,                /*nftRoyaltyToCoinBasisPoints*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTRoyaltyOverflow)
	}

	// Create NFT: Let's have m0 create an NFT with 10% royalties for the creator and 20% for the coin.
	{
		// Balance before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(30), m0BalBeforeNFT)

		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			10,    /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			1000,  /*nftRoyaltyToCreatorBasisPoints*/
			2000,  /*nftRoyaltyToCoinBasisPoints*/
		)

		// Balance after. Since the default NFT fee is 0, m0 is only charged the nanos per kb fee.
		m0BalAfterNFT := _getBalance(testMeta.t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(29), m0BalAfterNFT)
	}

	// 1 nano bid: Have m1 make a bid on <post1, #1>, accept it and check the royalties.
	{
		bidAmountNanos := uint64(1)
		serialNumber := uint64(1)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			serialNumber,   /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))

		// Owner balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(29), m0BalBefore)

		// Bidder balance before.
		m1BalBefore := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(999), m1BalBefore)

		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			serialNumber, /*SerialNumber*/
			m1Pub,        /*bidderPkBase58Check*/
			bidAmountNanos,
			"", /*UnencryptedUnlockableText*/
		)

		// Check royalties. 10% for the creator, 10% for the coin.
		m0BalAfter := _getBalance(t, chain, nil, m0Pub)
		// In order to prevent money printing, <1 nano royalties are rounded down to zero.
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(uint64(0), expectedCreatorRoyalty)
		expectedCoinRoyalty := bidAmountNanos / 10
		require.Equal(uint64(0), expectedCoinRoyalty)
		bidAmountMinusRoyalties := bidAmountNanos - expectedCoinRoyalty - expectedCreatorRoyalty
		require.Equal(m0BalBefore-2+bidAmountMinusRoyalties+expectedCreatorRoyalty, m0BalAfter)
		require.Equal(uint64(28), m0BalAfter)
		// Make sure that the bidder's balance decreased by the bid amount.
		m1BalAfter := _getBalance(t, chain, nil, m1Pub)
		require.Equal(m1BalBefore-bidAmountNanos, m1BalAfter)
		require.Equal(uint64(998), m1BalAfter)
		// Creator coin: zero royalties should be paid.
		desoLocked, _ := _getCreatorCoinInfo(t, db, params, m0Pub)
		require.Equal(m0InitialDeSoLocked+expectedCoinRoyalty, desoLocked)
	}

	// 10 nano bid: Have m1 make a bid on <post1, #2>, accept it and check the royalties.
	{
		bidAmountNanos := uint64(10)
		serialNumber := uint64(2)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, serialNumber)
		require.Equal(0, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			serialNumber,   /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, serialNumber)
		require.Equal(1, len(bidEntries))

		// Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(28), m0BalBefore)

		// Bidder balance before.
		m1BalBefore := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(997), m1BalBefore)

		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			serialNumber, /*SerialNumber*/
			m1Pub,        /*bidderPkBase58Check*/
			bidAmountNanos,
			"", /*UnencryptedUnlockableText*/
		)

		// Check royalties. 10% for the creator, 20% for the coin.
		m0BalAfter := _getBalance(t, chain, nil, m0Pub)
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(uint64(1), expectedCreatorRoyalty)
		expectedCoinRoyalty := 2 * bidAmountNanos / 10
		require.Equal(uint64(2), expectedCoinRoyalty)
		bidAmountMinusRoyalties := bidAmountNanos - expectedCoinRoyalty - expectedCreatorRoyalty
		require.Equal(m0BalBefore-2+bidAmountMinusRoyalties+expectedCreatorRoyalty, m0BalAfter)
		require.Equal(uint64(34), m0BalAfter)
		// Make sure that the bidder's balance decreased by the bid amount.
		m1BalAfter := _getBalance(t, chain, nil, m1Pub)
		require.Equal(m1BalBefore-bidAmountNanos, m1BalAfter)
		require.Equal(uint64(987), m1BalAfter)
		// Creator coin.
		desoLocked, _ := _getCreatorCoinInfo(t, db, params, m0Pub)
		require.Equal(m0InitialDeSoLocked+expectedCoinRoyalty, desoLocked)
	}

	// 100 nano bid: Have m1 make a bid on <post1, #3>, accept it and check the royalties.
	{
		m0DeSoLocked, _ := _getCreatorCoinInfo(t, db, params, m0Pub)
		require.Equal(uint64(30), m0DeSoLocked)

		bidAmountNanos := uint64(100)
		serialNumber := uint64(3)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, serialNumber)
		require.Equal(0, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			serialNumber,   /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, serialNumber)
		require.Equal(1, len(bidEntries))

		// Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(34), m0BalBefore)

		// Bidder balance before.
		m1BalBefore := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(986), m1BalBefore)

		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			serialNumber, /*SerialNumber*/
			m1Pub,        /*bidderPkBase58Check*/
			bidAmountNanos,
			"", /*UnencryptedUnlockableText*/
		)

		// Check royalties. 10% for the creator, 20% for the coin.
		m0BalAfter := _getBalance(t, chain, nil, m0Pub)
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(uint64(10), expectedCreatorRoyalty)
		expectedCoinRoyalty := 2 * bidAmountNanos / 10
		require.Equal(uint64(20), expectedCoinRoyalty)
		bidAmountMinusRoyalties := bidAmountNanos - expectedCoinRoyalty - expectedCreatorRoyalty
		require.Equal(m0BalBefore-2+bidAmountMinusRoyalties+expectedCreatorRoyalty, m0BalAfter)
		require.Equal(uint64(112), m0BalAfter)
		// Make sure that the bidder's balance decreased by the bid amount.
		m1BalAfter := _getBalance(t, chain, nil, m1Pub)
		require.Equal(m1BalBefore-bidAmountNanos, m1BalAfter)
		require.Equal(uint64(886), m1BalAfter)
		// Creator coin.
		desoLocked, _ := _getCreatorCoinInfo(t, db, params, m0Pub)
		require.Equal(m0DeSoLocked+expectedCoinRoyalty, desoLocked)
	}

	// Put <post1, #1> up for sale again and make sure royalties still work.
	{
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			0,    /*MinBidAmountNanos*/
		)
	}

	// 10000 nano bid: Have m3 make a bid on <post1, #1>, accept it and check the royalties.
	{
		m0DeSoLocked, _ := _getCreatorCoinInfo(t, db, params, m0Pub)
		require.Equal(uint64(50), m0DeSoLocked)

		bidAmountNanos := uint64(10000)
		serialNumber := uint64(1)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, serialNumber)
		require.Equal(0, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			serialNumber,   /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, serialNumber)
		require.Equal(1, len(bidEntries))

		// Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(112), m0BalBefore)
		m1BalBefore := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(885), m1BalBefore)
		m3BalBefore := _getBalance(t, chain, nil, m3Pub)
		require.Equal(uint64(14999), m3BalBefore)

		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			serialNumber, /*SerialNumber*/
			m3Pub,        /*bidderPkBase58Check*/
			bidAmountNanos,
			"", /*UnencryptedUnlockableText*/
		)

		// Check royalties. 10% for the creator, 10% for the coin.
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(uint64(1000), expectedCreatorRoyalty)
		expectedCoinRoyalty := 2 * bidAmountNanos / 10
		require.Equal(uint64(2000), expectedCoinRoyalty)
		bidAmountMinusRoyalties := bidAmountNanos - expectedCoinRoyalty - expectedCreatorRoyalty

		m0BalAfter := _getBalance(t, chain, nil, m0Pub)
		require.Equal(m0BalBefore+expectedCreatorRoyalty, m0BalAfter)
		require.Equal(uint64(1112), m0BalAfter)

		m1BalAfter := _getBalance(t, chain, nil, m1Pub)
		require.Equal(m1BalBefore-2+bidAmountMinusRoyalties, m1BalAfter)
		require.Equal(uint64(7883), m1BalAfter)

		// Make sure m3's balance was decreased appropriately.
		m3BalAfter := _getBalance(t, chain, nil, m3Pub)
		require.Equal(m3BalBefore-bidAmountNanos, m3BalAfter)
		require.Equal(uint64(4999), m3BalAfter)

		// Creator coin.
		desoLocked, _ := _getCreatorCoinInfo(t, db, params, m0Pub)
		require.Equal(m0DeSoLocked+expectedCoinRoyalty, desoLocked)
	}

	// Error case: Let's make sure that no royalties are paid if there are no coins in circulation.
	{
		_, coinsInCirculationNanos := _getCreatorCoinInfo(t, db, params, m0Pub)
		require.Equal(uint64(30365901), coinsInCirculationNanos)

		// Sell all the coins.
		_creatorCoinTxnWithTestMeta(
			testMeta,
			10,     /*feeRateNanosPerKB*/
			m0Pub,  /*updaterPkBase58Check*/
			m0Priv, /*updaterPrivBase58Check*/
			m0Pub,  /*profilePubKeyBase58Check*/
			CreatorCoinOperationTypeSell,
			0,                       /*DeSoToSellNanos*/
			coinsInCirculationNanos, /*CreatorCoinToSellNanos*/
			0,                       /*DeSoToAddNanos*/
			0,                       /*MinDeSoExpectedNanos*/
			0,                       /*MinCreatorCoinExpectedNanos*/
		)

		// Create a bid on <post1, #9>, which is still for sale.
		bidAmountNanos := uint64(100)
		serialNumber := uint64(9)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, serialNumber)
		require.Equal(0, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			serialNumber,   /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, serialNumber)
		require.Equal(1, len(bidEntries))

		// Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(3160), m0BalBefore)

		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			serialNumber, /*SerialNumber*/
			m3Pub,        /*bidderPkBase58Check*/
			bidAmountNanos,
			"", /*UnencryptedUnlockableText*/
		)

		// Check royalties. 10% for the creator, 20% for the coin.
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(uint64(10), expectedCreatorRoyalty)
		expectedCoinRoyalty := 2 * bidAmountNanos / 10
		require.Equal(uint64(20), expectedCoinRoyalty)
		bidAmountMinusRoyalties := bidAmountNanos - expectedCoinRoyalty - expectedCreatorRoyalty

		m0BalAfter := _getBalance(t, chain, nil, m0Pub)
		require.Equal(m0BalBefore-2+bidAmountMinusRoyalties+expectedCreatorRoyalty, m0BalAfter)
		require.Equal(uint64(3238), m0BalAfter)

		// Creator coin --> Make sure no royalties were added.
		desoLocked, _ := _getCreatorCoinInfo(t, db, params, m0Pub)
		require.Equal(uint64(0), desoLocked)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestNFTSerialNumberZeroBid(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 100)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 15000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 15000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 15000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)

	// Set max copies to a non-zero value to activate NFTs.
	{
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m4Pub,
			m4Priv,
			-1, -1, -1, -1,
			1000, /*maxCopiesPerNFT*/
		)
	}

	// Create two posts for testing.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)

		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 2"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-2].Hash()
	post2Hash := testMeta.txns[len(testMeta.txns)-1].Hash()

	// Create a profile so me can make an NFT.
	{
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Create NFT: Let's have m0 create two NFTs for testing.
	{
		// Balance before.
		m0BalBeforeNFTs := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(59), m0BalBeforeNFTs)

		// Create an NFT with a ton of copies for testing accepting bids.
		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			100,   /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		// Create an NFT with one copy to test making a standing offer on an NFT that isn't for sale.
		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post2Hash,
			1,     /*NumCopies*/
			false, /*HasUnlockable*/
			false, /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		// Balance after. Since the default NFT fee is 0, m0 is only charged the nanos per kb fee.
		m0BalAfterNFTs := _getBalance(testMeta.t, testMeta.chain, nil, m0Pub)
		require.Equal(m0BalBeforeNFTs-uint64(2), m0BalAfterNFTs)
	}

	// <Post2, #1> (the only copy of this NFT) is not for sale.  Ensure that we can make a #0 bid.
	{
		bidEntries := DBGetNFTBidEntries(db, post2Hash, 0)
		require.Equal(0, len(bidEntries))

		// m1: This is a standing offer for the post 2 NFT that can be accepted at any time.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post2Hash,
			0,   /*SerialNumber*/
			100, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post2Hash, 0)
		require.Equal(1, len(bidEntries))
	}

	// Have m1,m2,m3 make some bids, including a bid on serial #0.
	{
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 0)
		require.Equal(0, len(bidEntries))

		// m1: This is a blanket bid on any serial number of post1.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			0,   /*SerialNumber*/
			100, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 0)
		require.Equal(1, len(bidEntries))

		// m1: This is a specific bid for serial #1 of post1.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1,    /*SerialNumber*/
			1000, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))

		// m2: Add a bid from m2 for fun.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1,   /*SerialNumber*/
			999, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(2, len(bidEntries))

		// m3: Add a blanket bid from m3 for fun.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			0,   /*SerialNumber*/
			999, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 0)
		require.Equal(2, len(bidEntries))
	}

	// Error case: m1 has two active bids. One for serial #1 for 1000 nanos, and one for
	// serial #0 for 100 nanos. m0 can accept the serial #0 bid on any serial number. In this
	// case they try and accept it for serial #2 while spoofing the 1000 nano bid amount from
	// the serial #1 bid.  This should obviously fail.
	//
	// In addition, m0 should not be able to accept the serial #0 bid on serial #1 since it is
	// trumped by the specific serial #1 bid placed by m1.
	{
		_, _, _, err = _acceptNFTBid(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			2, /*SerialNumber*/
			m1Pub,
			1000, /*BidAmountNanos*/
			"",   /*UnlockableText*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorAcceptedNFTBidAmountDoesNotMatch)

		_, _, _, err = _acceptNFTBid(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1, /*SerialNumber*/
			m1Pub,
			100, /*BidAmountNanos*/
			"",  /*UnlockableText*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorAcceptedNFTBidAmountDoesNotMatch)
	}

	// Accept some bids!
	{
		// Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(57), m0BalBefore)

		// This will accept m1's serial #0 bid.
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			2,     /*SerialNumber*/
			m1Pub, /*bidderPkBase58Check*/
			100,   /*bidAmountNanos*/
			"",    /*UnencryptedUnlockableText*/
		)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 0)
		require.Equal(1, len(bidEntries))

		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1,     /*SerialNumber*/
			m1Pub, /*bidderPkBase58Check*/
			1000,  /*bidAmountNanos*/
			"",    /*UnencryptedUnlockableText*/
		)
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// This will accept m3's serial #0 bid.
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			3,     /*SerialNumber*/
			m3Pub, /*bidderPkBase58Check*/
			999,   /*bidAmountNanos*/
			"",    /*UnencryptedUnlockableText*/
		)
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 0)
		require.Equal(0, len(bidEntries))

		// This NFT doesn't have royalties so m0's balance should be directly related to the bids accepted.
		m0BalAfter := _getBalance(t, chain, nil, m0Pub)
		require.Equal(m0BalBefore-6+100+1000+999, m0BalAfter)
		require.Equal(uint64(2150), m0BalAfter)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestNFTMinimumBidAmount(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 15000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 15000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 15000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 15000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)

	// Set max copies to a non-zero value to activate NFTs.
	{
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m4Pub,
			m4Priv,
			-1, -1, -1, -1,
			1000, /*maxCopiesPerNFT*/
		)
	}

	// Create a simple post.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-1].Hash()

	// Create a profile so me can make an NFT.
	{
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Create NFT with a minimum bid amount.
	{
		// Balance before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(14960), m0BalBeforeNFT)

		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			100,   /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			1111,  /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		// Balance after. Since the default NFT fee is 0, m0 is only charged the nanos per kb fee.
		m0BalAfterNFT := _getBalance(testMeta.t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(14959), m0BalAfterNFT)
	}

	// Error case: Attempt to make some bids below the minimum bid amount, they should error.
	{
		_, _, _, err := _createNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			1, /*SerialNumber*/
			0, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidLessThanMinBidAmountNanos)

		_, _, _, err = _createNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			1,    /*SerialNumber*/
			1110, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidLessThanMinBidAmountNanos)
	}

	// Have m1,m2,m3 make some legitimate bids, including a bid on serial #0.
	{
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// m1 --> <post1, #1>
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1,    /*SerialNumber*/
			1111, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))

		// m1 --> <post1, #0> (This bid can be any amount since it is a blanket bid)
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			0,  /*SerialNumber*/
			10, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 0)
		require.Equal(1, len(bidEntries))

		// m2: Add a bid from m2 for fun.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1,    /*SerialNumber*/
			1112, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(2, len(bidEntries))

		// m3: Add a blanket bid from m3 for fun.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			1,    /*SerialNumber*/
			1113, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(3, len(bidEntries))
	}

	// TODO: add test to withdraw bid with a 0 BidAmountNanos

	// Accept m3's bid on #1 and m1's blanked bid on #2, weeeee!
	{
		// Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(14959), m0BalBefore)

		// This will accept m3's serial #1 bid.
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1,     /*SerialNumber*/
			m3Pub, /*bidderPkBase58Check*/
			1113,  /*bidAmountNanos*/
			"",    /*UnencryptedUnlockableText*/
		)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// This will accept m1's serial #0 bid.
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			2,     /*SerialNumber*/
			m1Pub, /*bidderPkBase58Check*/
			10,    /*bidAmountNanos*/
			"",    /*UnencryptedUnlockableText*/
		)
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 0)
		require.Equal(0, len(bidEntries))

		// This NFT doesn't have royalties so m0's balance should be directly related to the bids accepted.
		m0BalAfter := _getBalance(t, chain, nil, m0Pub)
		require.Equal(m0BalBefore-4+1113+10, m0BalAfter)
		require.Equal(uint64(16078), m0BalAfter)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

// Test to make sure an NFT created with "IsForSale=false" does not accept bids.
func TestNFTCreatedIsNotForSale(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 15000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 15000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 15000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 15000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)

	// Set max copies to a non-zero value to activate NFTs.
	{
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m4Pub,
			m4Priv,
			-1, -1, -1, -1,
			1000, /*maxCopiesPerNFT*/
		)
	}

	// Create a simple post.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-1].Hash()

	// Create a profile so me can make an NFT.
	{
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Create NFT with IsForSale=false.
	{
		// Balance before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(14960), m0BalBeforeNFT)

		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			100,   /*NumCopies*/
			false, /*HasUnlockable*/
			false, /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		// Balance after. Since the default NFT fee is 0, m0 is only charged the nanos per kb fee.
		m0BalAfterNFT := _getBalance(testMeta.t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(14959), m0BalAfterNFT)
	}

	// Error case: Attempt to make some bids on an NFT that is not for sale, they should error.
	{
		_, _, _, err := _createNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			1,    /*SerialNumber*/
			1000, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidOnNFTThatIsNotForSale)

		// None of the serial numbers should accept bids.
		_, _, _, err = _createNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			99,   /*SerialNumber*/
			1000, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidOnNFTThatIsNotForSale)
	}

	// Update <post1, #1>, so that it is for sale.
	{
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			0,    /*MinBidAmountNanos*/
		)
	}

	// Now that <post1, #1> is for sale, creating a bid should work.
	{
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// m1 --> <post1, #1>
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1,    /*SerialNumber*/
			1111, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))
	}

	// Accept m1's bid on #1, weeeee!
	{
		// Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(14958), m0BalBefore)

		// This will accept m1's serial #1 bid.
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1,     /*SerialNumber*/
			m1Pub, /*bidderPkBase58Check*/
			1111,  /*bidAmountNanos*/
			"",    /*UnencryptedUnlockableText*/
		)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// This NFT doesn't have royalties so m0's balance should be directly related to the bids accepted.
		m0BalAfter := _getBalance(t, chain, nil, m0Pub)
		require.Equal(m0BalBefore-2+1111, m0BalAfter)
		require.Equal(uint64(16067), m0BalAfter)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestNFTMoreErrorCases(t *testing.T) {
	// Error cases tested:
	// - CreatorBasisPoints is greater than max value
	// - CoinBasisPoints is greater than max value
	// - Test than an NFT can only be minted once.
	// - Test that you cannot AcceptNFTBid if nft is not for sale.
	// - Test that min bid amount is behaving correctly.

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 70)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 420)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 2000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 210)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)

	// Set max copies to a non-zero value to activate NFTs.
	{
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m4Pub,
			m4Priv,
			-1, -1, -1, -1,
			1000, /*maxCopiesPerNFT*/
		)
	}

	// Create a simple post.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-1].Hash()

	// Create a profile so we can make an NFT.
	{
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Error case: CreatorBasisPoints / CoinBasisPoints greater than max.
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			100,   /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			10001, /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTRoyaltyHasTooManyBasisPoints)

		_, _, _, err = _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			100,   /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			10001, /*nftRoyaltyToCoinBasisPoints*/
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTRoyaltyHasTooManyBasisPoints)

		_, _, _, err = _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			100,   /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			5001,  /*nftRoyaltyToCreatorBasisPoints*/
			5001,  /*nftRoyaltyToCoinBasisPoints*/
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTRoyaltyHasTooManyBasisPoints)
	}

	// Finally, have m0 turn post1 into an NFT. Woohoo!
	{
		// Balance before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(30), m0BalBeforeNFT)

		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			5,       /*NumCopies*/
			false,   /*HasUnlockable*/
			false,   /*IsForSale*/
			1000000, /*MinBidAmountNanos*/
			0,       /*nftFee*/
			0,       /*nftRoyaltyToCreatorBasisPoints*/
			0,       /*nftRoyaltyToCoinBasisPoints*/
		)

		// Balance after. Since the default NFT fee is 0, m0 is only charged the nanos per kb fee.
		m0BalAfterNFT := _getBalance(testMeta.t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(29), m0BalAfterNFT)
	}

	// Error case: Cannot mint the NFT a second time.
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			5,       /*NumCopies*/
			false,   /*HasUnlockable*/
			false,   /*IsForSale*/
			1000000, /*MinBidAmountNanos*/
			0,       /*nftFee*/
			0,       /*nftRoyaltyToCreatorBasisPoints*/
			0,       /*nftRoyaltyToCoinBasisPoints*/
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreateNFTOnPostThatAlreadyIsNFT)

		// Should behave the same if we change the NFT metadata.
		_, _, _, err = _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			5,       /*NumCopies*/
			false,   /*HasUnlockable*/
			true,    /*IsForSale*/
			1000000, /*MinBidAmountNanos*/
			0,       /*nftFee*/
			0,       /*nftRoyaltyToCreatorBasisPoints*/
			0,       /*nftRoyaltyToCoinBasisPoints*/
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreateNFTOnPostThatAlreadyIsNFT)

		// Should behave the same if we change the NFT metadata.
		_, _, _, err = _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			5,     /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreateNFTOnPostThatAlreadyIsNFT)
	}

	// Have m1 make a standing offer on post1.
	{
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 0)
		require.Equal(0, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			0, /*SerialNumber*/
			5, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 0)
		require.Equal(1, len(bidEntries))
	}

	// Error case: cannot accept a bid if the NFT is not for sale.
	{
		_, _, _, err = _acceptNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			1, /*SerialNumber*/
			m1Pub,
			5,  /*BidAmountNanos*/
			"", /*UnlockableText*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidOnNFTThatIsNotForSale)
	}

	// Update <post1, #1>, so that it is on sale.
	{
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			1000, /*MinBidAmountNanos*/
		)
	}

	// Error case: make sure the min bid amount behaves correctly.
	{
		// You should not be able to create an NFT bid below the min bid amount.
		_, _, _, err := _createNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			1, /*SerialNumber*/
			1, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidLessThanMinBidAmountNanos)
	}

	// A bid above the min bid amount should succeed.
	{
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1,    /*SerialNumber*/
			1001, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))
	}

	// Accept m1's standing offer for the post. This should succeed despite the min bid amount.
	{
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1, /*SerialNumber*/
			m1Pub,
			5,  /*BidAmountNanos*/
			"", /*UnlockableText*/
		)

		// Make sure the entries in the DB were deleted.
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 0)
		require.Equal(0, len(bidEntries))
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestNFTBidsAreCanceledAfterAccept(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 2000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 2000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 2000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 2000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)

	// Set max copies to a non-zero value to activate NFTs.
	{
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m4Pub,
			m4Priv,
			-1, -1, -1, -1,
			1000, /*maxCopiesPerNFT*/
		)
	}

	// Create a simple post.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-1].Hash()

	// Create a profile so we can make an NFT.
	{
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Finally, have m0 turn post1 into an NFT. Woohoo!
	{
		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			5,     /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			10,    /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)
	}

	// Have m1, m2, and m3 all make some bids on the post.
	{
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1,  /*SerialNumber*/
			10, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1,  /*SerialNumber*/
			11, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(2, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1,  /*SerialNumber*/
			12, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(2, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			1,  /*SerialNumber*/
			13, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(3, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1,  /*SerialNumber*/
			14, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(3, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			1,  /*SerialNumber*/
			15, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(3, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1,  /*SerialNumber*/
			16, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(3, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			1,  /*SerialNumber*/
			17, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(3, len(bidEntries))
	}

	// Error case: cannot accept an old bid (m1 made a bid of 10 nanos, which was later updated).
	{
		_, _, _, err = _acceptNFTBid(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1, /*SerialNumber*/
			m1Pub,
			10, /*BidAmountNanos*/
			"", /*UnlockableText*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorAcceptedNFTBidAmountDoesNotMatch)
	}

	// Accept m2's bid on the post. Make sure all bids are deleted.
	{
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1, /*SerialNumber*/
			m2Pub,
			16, /*BidAmountNanos*/
			"", /*UnlockableText*/
		)

		// Make sure the entries in the DB were deleted.
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))
	}

	// Error case: accepting m1 or m3s bid should fail now.
	{
		_, _, _, err = _acceptNFTBid(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1, /*SerialNumber*/
			m1Pub,
			12, /*BidAmountNanos*/
			"", /*UnlockableText*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidOnNFTThatIsNotForSale)

		_, _, _, err = _acceptNFTBid(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1, /*SerialNumber*/
			m1Pub,
			17, /*BidAmountNanos*/
			"", /*UnlockableText*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidOnNFTThatIsNotForSale)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestNFTDifferentMinBidAmountSerialNumbers(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 2000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 2000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 2000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 2000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)

	// Set max copies to a non-zero value to activate NFTs.
	{
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m4Pub,
			m4Priv,
			-1, -1, -1, -1,
			1000, /*maxCopiesPerNFT*/
		)
	}

	// Create a simple post.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-1].Hash()

	// Create a profile so we can make an NFT.
	{
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Finally, have m0 turn post1 into an NFT. Woohoo!
	{
		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			5,     /*NumCopies*/
			false, /*HasUnlockable*/
			false, /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)
	}

	// Update the post 1 NFTs, so that they have different min bid amounts.
	{
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			100,  /*MinBidAmountNanos*/
		)

		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			2,    /*SerialNumber*/
			true, /*IsForSale*/
			300,  /*MinBidAmountNanos*/
		)

		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			3,    /*SerialNumber*/
			true, /*IsForSale*/
			500,  /*MinBidAmountNanos*/
		)

		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			4,    /*SerialNumber*/
			true, /*IsForSale*/
			400,  /*MinBidAmountNanos*/
		)

		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			5,    /*SerialNumber*/
			true, /*IsForSale*/
			200,  /*MinBidAmountNanos*/
		)
	}

	// Error case: check that all the serial numbers error below the min bid amount as expected.
	{
		_, _, _, err := _createNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			1,  /*SerialNumber*/
			99, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidLessThanMinBidAmountNanos)

		_, _, _, err = _createNFTBid(
			t, chain, db, params, 10,
			m2Pub,
			m2Priv,
			post1Hash,
			2,   /*SerialNumber*/
			299, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidLessThanMinBidAmountNanos)

		_, _, _, err = _createNFTBid(
			t, chain, db, params, 10,
			m3Pub,
			m3Priv,
			post1Hash,
			3,   /*SerialNumber*/
			499, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidLessThanMinBidAmountNanos)

		_, _, _, err = _createNFTBid(
			t, chain, db, params, 10,
			m2Pub,
			m2Priv,
			post1Hash,
			4,   /*SerialNumber*/
			399, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidLessThanMinBidAmountNanos)

		_, _, _, err = _createNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			5,   /*SerialNumber*/
			199, /*BidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTBidLessThanMinBidAmountNanos)
	}

	// Bids at the min bid amount nanos threshold should not error.
	{
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1,   /*SerialNumber*/
			100, /*BidAmountNanos*/
		)

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			2,   /*SerialNumber*/
			300, /*BidAmountNanos*/
		)

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			3,   /*SerialNumber*/
			500, /*BidAmountNanos*/
		)

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			4,   /*SerialNumber*/
			400, /*BidAmountNanos*/
		)

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			5,   /*SerialNumber*/
			200, /*BidAmountNanos*/
		)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestNFTMaxCopiesGlobalParam(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)

	// Set max copies to a non-zero value to activate NFTs.
	{
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m4Pub,
			m4Priv,
			-1, -1, -1, -1,
			1000, /*maxCopiesPerNFT*/
		)
	}

	// Create a couple posts to test NFT creation with.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)

		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 2"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)

		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 3"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-1].Hash()
	post2Hash := testMeta.txns[len(testMeta.txns)-2].Hash()
	post3Hash := testMeta.txns[len(testMeta.txns)-3].Hash()

	// Create a profile so me can make an NFT.
	{
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Error case: creating an NFT with 1001 copies should fail since the default max is 1000.
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1001,  /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorTooManyNFTCopies)
	}

	// Make post 1 an NFT with 1000 copies, the default MaxCopiesPerNFT.
	{
		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1000,  /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)
	}

	// Now let's try making the MaxCopiesPerNFT ridiculously small.
	{
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			-1, -1, -1, -1,
			1, /*maxCopiesPerNFT*/
		)
	}

	// Error case: now creating an NFT with 2 copies should fail.
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post2Hash,
			2,     /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorTooManyNFTCopies)
	}

	// Making an NFT with only 1 copy should succeed.
	{
		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post2Hash,
			1,     /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)
	}

	// Error case: setting MaxCopiesPerNFT to be >MaxMaxCopiesPerNFT or <MinMaxCopiesPerNFT should fail.
	{
		require.Equal(1, MinMaxCopiesPerNFT)
		require.Equal(10000, MaxMaxCopiesPerNFT)

		_, _, _, err := _updateGlobalParamsEntry(
			testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			-1, -1, -1, -1,
			MaxMaxCopiesPerNFT+1, /*maxCopiesPerNFT*/
			true)                 /*flushToDB*/
		require.Error(err)
		require.Contains(err.Error(), RuleErrorMaxCopiesPerNFTTooHigh)

		_, _, _, err = _updateGlobalParamsEntry(
			testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			-1, -1, -1, -1,
			MinMaxCopiesPerNFT-1, /*maxCopiesPerNFT*/
			true)                 /*flushToDB*/
		require.Error(err)
		require.Contains(err.Error(), RuleErrorMaxCopiesPerNFTTooLow)
	}

	// Now let's try making the MaxCopiesPerNFT ridiculously large.
	{
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			-1, -1, -1, -1,
			10000, /*maxCopiesPerNFT*/
		)
	}

	// Making an NFT with 10000 copies should now be possible!
	{
		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post3Hash,
			10000, /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)
	}

	// Now place some bids to make sure the NFTs were really minted.
	{
		// Post 1 should have 1000 copies.
		dbEntries := DBGetNFTEntriesForPostHash(db, post1Hash)
		require.Equal(1000, len(dbEntries))
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1000, /*SerialNumber*/
			1,    /*BidAmountNanos*/
		)

		// Post 2 should have 1 copy.
		dbEntries = DBGetNFTEntriesForPostHash(db, post2Hash)
		require.Equal(1, len(dbEntries))
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post2Hash,
			1, /*SerialNumber*/
			1, /*BidAmountNanos*/
		)

		// Post 3 should have 10000 copies.
		dbEntries = DBGetNFTEntriesForPostHash(db, post3Hash)
		require.Equal(10000, len(dbEntries))
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post3Hash,
			10000, /*SerialNumber*/
			1,     /*BidAmountNanos*/
		)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestNFTPreviousOwnersCantAcceptBids(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)

	// Set max copies to a non-zero value to activate NFTs.
	{
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m4Pub,
			m4Priv,
			-1, -1, -1, -1,
			1000, /*maxCopiesPerNFT*/
		)
	}

	// Create a post for testing.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-1].Hash()

	// NFT the post.
	{
		// You need a profile in order to create an NFT.
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)

		// We only need 1 copy for this test.
		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1,     /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		// Post 1 should have 1 copies.
		dbEntries := DBGetNFTEntriesForPostHash(db, post1Hash)
		require.Equal(1, len(dbEntries))
	}

	// Have m1 place a bid and m0 accept it.
	{
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1, /*SerialNumber*/
			1, /*BidAmountNanos*/
		)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))

		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1, /*SerialNumber*/
			m1Pub,
			1,  /*BidAmountNanos*/
			"", /*UnlockableText*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))
	}

	// Error case: m0 should not be able to put m1's NFT for sale.
	{
		_, _, _, err := _updateNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1,     /*SerialNumber*/
			false, /*IsForSale*/
			0,     /*MinBidAmountNanos*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorUpdateNFTByNonOwner)
	}

	// Have m1 place the NFT for sale and m2 bid on it.
	{
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			0,    /*MinBidAmountNanos*/
		)

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1, /*SerialNumber*/
			1, /*BidAmountNanos*/
		)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))
	}

	// Error case: m0 cannot accept the m2's bid on m1's behalf.
	{
		_, _, _, err = _acceptNFTBid(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1, /*SerialNumber*/
			m2Pub,
			1,  /*BidAmountNanos*/
			"", /*UnlockableText*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorAcceptNFTBidByNonOwner)
	}

	// Have m1 accept the bid, m2 put the NFT for sale, and m3 bid on the NFT.
	{
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1, /*SerialNumber*/
			m2Pub,
			1,  /*BidAmountNanos*/
			"", /*UnlockableText*/
		)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			0,    /*MinBidAmountNanos*/
		)

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			1, /*SerialNumber*/
			1, /*BidAmountNanos*/
		)
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))
	}

	// Error case: m0 and m1 cannot accept the m3's bid on m2's behalf.
	{
		_, _, _, err = _acceptNFTBid(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1, /*SerialNumber*/
			m3Pub,
			1,  /*BidAmountNanos*/
			"", /*UnlockableText*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorAcceptNFTBidByNonOwner)

		_, _, _, err = _acceptNFTBid(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			1, /*SerialNumber*/
			m3Pub,
			1,  /*BidAmountNanos*/
			"", /*UnlockableText*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorAcceptNFTBidByNonOwner)
	}

	// Have m2 accept the bid.
	{
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1, /*SerialNumber*/
			m3Pub,
			1,  /*BidAmountNanos*/
			"", /*UnlockableText*/
		)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestNFTTransfersAndBurns(t *testing.T) {
	BrokenNFTBidsFixBlockHeight = uint32(0)
	NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true

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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 1000)

	// Get PKIDs for checking nft ownership.
	m0PkBytes, _, err := Base58CheckDecode(m0Pub)
	require.NoError(err)
	m0PKID := DBGetPKIDEntryForPublicKey(db, m0PkBytes)
	_ = m0PKID

	m1PkBytes, _, err := Base58CheckDecode(m1Pub)
	require.NoError(err)
	m1PKID := DBGetPKIDEntryForPublicKey(db, m1PkBytes)
	_ = m1PKID

	m2PkBytes, _, err := Base58CheckDecode(m2Pub)
	require.NoError(err)
	m2PKID := DBGetPKIDEntryForPublicKey(db, m2PkBytes)
	_ = m2PKID

	m3PkBytes, _, err := Base58CheckDecode(m3Pub)
	require.NoError(err)
	m3PKID := DBGetPKIDEntryForPublicKey(db, m3PkBytes)
	_ = m3PKID

	// Set max copies to a non-zero value to activate NFTs.
	{
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			-1, -1, -1, -1,
			1000, /*maxCopiesPerNFT*/
		)
	}

	// Create two posts to NFTify (one will have unlockable, one will not).
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)

		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 2"}, /*body*/
			[]byte{},
			1502947012*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-2].Hash()
	post2Hash := testMeta.txns[len(testMeta.txns)-1].Hash()

	// Create a profile so we can make an NFT.
	{
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Have m0 turn both post1 and post2 into NFTs.
	{
		// Balance before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(959), m0BalBeforeNFT)

		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			5,     /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post2Hash,
			5,     /*NumCopies*/
			true,  /*HasUnlockable*/
			false, /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
		)

		// Balance after. Since the default NFT fee is 0, m0 is only charged the nanos per kb fee.
		m0BalAfterNFT := _getBalance(testMeta.t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(957), m0BalAfterNFT)
	}

	// Have m1 bid on and win post #1 / serial #5.
	{
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 5)
		require.Equal(0, len(bidEntries))

		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			5, /*SerialNumber*/
			1, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 5)
		require.Equal(1, len(bidEntries))

		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			5, /*SerialNumber*/
			m1Pub,
			1,  /*BidAmountNanos*/
			"", /*UnlockableText*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 5)
		require.Equal(0, len(bidEntries))
	}

	// Update <post1, #2>, so that it is no longer for sale.
	{
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			2,     /*SerialNumber*/
			false, /*IsForSale*/
			0,     /*MinBidAmountNanos*/
		)
	}

	// At this point, we have 10 NFTs in the following state:
	//   - m1 owns <post 1, #5> (no unlockable, not for sale; purchased from m0)
	//   - m0 owns:
	//     - <post 1, #1-4> (no unlockable, all for sale except #2)
	//     - <post 2, #1-5> (has unlockable, none for sale)

	// Now that we have some NFTs, let's try transferring them.

	// Error case: non-existent NFT.
	{
		_, _, _, err := _transferNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			m1Pub,
			post1Hash,
			6, /*Non-existent serial number.*/
			"",
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCannotTransferNonExistentNFT)
	}

	// Error case: transfer by non-owner.
	{
		_, _, _, err := _transferNFT(
			t, chain, db, params, 10,
			m3Pub,
			m3Priv,
			m2Pub,
			post1Hash,
			2,
			"",
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorNFTTransferByNonOwner)
	}

	// Error case: cannot transfer NFT that is for sale.
	{
		_, _, _, err := _transferNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			m1Pub,
			post1Hash,
			1,
			"",
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCannotTransferForSaleNFT)
	}

	// Error case: cannot transfer unlockable NFT without unlockable text.
	{
		_, _, _, err := _transferNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			m1Pub,
			post2Hash,
			1,
			"",
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCannotTransferUnlockableNFTWithoutUnlockable)
	}

	// Let's transfer some NFTs!
	{
		// m0 transfers <post 1, #2> (not for sale, no unlockable) to m2.
		_transferNFTWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			m2Pub,
			post1Hash,
			2,
			"",
		)

		// m1 transfers <post 1, #5> (not for sale, no unlockable) to m3.
		_transferNFTWithTestMeta(
			testMeta,
			10,
			m1Pub,
			m1Priv,
			m3Pub,
			post1Hash,
			5,
			"",
		)

		// m0 transfers <post 2, #1> (not for sale, has unlockable) to m1.
		unlockableText := "this is an encrypted unlockable string"
		_transferNFTWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			m1Pub,
			post2Hash,
			1,
			unlockableText,
		)

		// Check the state of the transferred NFTs.
		transferredNFT1 := DBGetNFTEntryByPostHashSerialNumber(db, post1Hash, 2)
		require.Equal(transferredNFT1.IsPending, true)
		require.True(reflect.DeepEqual(transferredNFT1.OwnerPKID, m2PKID.PKID))
		require.True(reflect.DeepEqual(transferredNFT1.LastOwnerPKID, m0PKID.PKID))

		transferredNFT2 := DBGetNFTEntryByPostHashSerialNumber(db, post1Hash, 5)
		require.Equal(transferredNFT2.IsPending, true)
		require.True(reflect.DeepEqual(transferredNFT2.OwnerPKID, m3PKID.PKID))
		require.True(reflect.DeepEqual(transferredNFT2.LastOwnerPKID, m1PKID.PKID))

		transferredNFT3 := DBGetNFTEntryByPostHashSerialNumber(db, post2Hash, 1)
		require.Equal(transferredNFT3.IsPending, true)
		require.True(reflect.DeepEqual(transferredNFT3.OwnerPKID, m1PKID.PKID))
		require.True(reflect.DeepEqual(transferredNFT3.LastOwnerPKID, m0PKID.PKID))
		require.True(reflect.DeepEqual(transferredNFT3.UnlockableText, []byte(unlockableText)))
	}

	// Now let's test out accepting NFT transfers.

	// Error case: non-existent NFT.
	{
		_, _, _, err := _acceptNFTTransfer(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			6, /*Non-existent serial number.*/
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCannotAcceptTransferOfNonExistentNFT)
	}

	// Error case: transfer by non-owner (m1 owns <post 2, #1>).
	{
		_, _, _, err := _acceptNFTTransfer(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post2Hash,
			1,
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorAcceptNFTTransferByNonOwner)
	}

	// Error case: cannot accept NFT transfer on non-pending NFT.
	{
		_, _, _, err := _acceptNFTTransfer(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post2Hash,
			4,
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorAcceptNFTTransferForNonPendingNFT)
	}

	// Let's accept some NFT transfers!
	{
		// m2 accepts <post 1, #2>
		_acceptNFTTransferWithTestMeta(
			testMeta,
			10,
			m2Pub,
			m2Priv,
			post1Hash,
			2,
		)

		// m1 accepts <post 2, #1>
		_acceptNFTTransferWithTestMeta(
			testMeta,
			10,
			m1Pub,
			m1Priv,
			post2Hash,
			1,
		)

		// Check the state of the accepted NFTs.
		acceptedNFT1 := DBGetNFTEntryByPostHashSerialNumber(db, post1Hash, 2)
		require.Equal(acceptedNFT1.IsPending, false)

		acceptedNFT2 := DBGetNFTEntryByPostHashSerialNumber(db, post2Hash, 1)
		require.Equal(acceptedNFT2.IsPending, false)
	}

	// Now let's test out burning NFTs.

	// Error case: non-existent NFT.
	{
		_, _, _, err := _burnNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			6, /*Non-existent serial number.*/
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCannotBurnNonExistentNFT)
	}

	// Error case: transfer by non-owner (m1 owns <post 2, #1>).
	{
		_, _, _, err := _burnNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post2Hash,
			1,
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorBurnNFTByNonOwner)
	}

	// Error case: cannot burn an NFT that is for sale (<post 1, #1> is still for sale).
	{
		_, _, _, err := _burnNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1,
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCannotBurnNFTThatIsForSale)
	}

	// Let's burn some NFTs!!
	{
		// m3 burns <post 1, #5> (not for sale, is pending, no unlockable)
		_burnNFTWithTestMeta(
			testMeta,
			10,
			m3Pub,
			m3Priv,
			post1Hash,
			5,
		)

		// m0 burns <post 2, #3> (not for sale, not pending, has unlockable)
		_burnNFTWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			post2Hash,
			3,
		)

		// Check the burned NFTs no longer exist.
		burnedNFT1 := DBGetNFTEntryByPostHashSerialNumber(db, post1Hash, 5)
		require.Nil(burnedNFT1)

		burnedNFT2 := DBGetNFTEntryByPostHashSerialNumber(db, post2Hash, 3)
		require.Nil(burnedNFT2)

		// Check that the post entries have the correct burn count.
		post1 := DBGetPostEntryByPostHash(db, post1Hash)
		require.Equal(uint64(1), post1.NumNFTCopiesBurned)

		post2 := DBGetPostEntryByPostHash(db, post2Hash)
		require.Equal(uint64(1), post2.NumNFTCopiesBurned)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}
