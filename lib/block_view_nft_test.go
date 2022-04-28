package lib

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math"
	"reflect"
	"testing"
)

func _createNFTWithAdditionalRoyalties(t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams,
	feeRateNanosPerKB uint64, updaterPkBase58Check string, updaterPrivBase58Check string,
	nftPostHash *BlockHash, numCopies uint64, hasUnlockable bool, isForSale bool, minBidAmountNanos uint64,
	nftFee uint64, nftRoyaltyToCreatorBasisPoints uint64, nftRoyaltyToCoinBasisPoints uint64, isBuyNow bool,
	buyNowPriceNanos uint64, additionalDESORoyaltiesMap map[PublicKey]uint64, additionalCoinRoyaltiesMap map[PublicKey]uint64,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	return _createNFTWithExtraData(t, chain, db, params, feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		nftPostHash,
		numCopies,
		hasUnlockable,
		isForSale,
		minBidAmountNanos,
		nftFee,
		nftRoyaltyToCreatorBasisPoints,
		nftRoyaltyToCoinBasisPoints,
		isBuyNow,
		buyNowPriceNanos,
		additionalDESORoyaltiesMap,
		additionalCoinRoyaltiesMap,
		nil)
}

func _createNFTWithExtraData(t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams,
	feeRateNanosPerKB uint64, updaterPkBase58Check string, updaterPrivBase58Check string,
	nftPostHash *BlockHash, numCopies uint64, hasUnlockable bool, isForSale bool, minBidAmountNanos uint64,
	nftFee uint64, nftRoyaltyToCreatorBasisPoints uint64, nftRoyaltyToCoinBasisPoints uint64, isBuyNow bool,
	buyNowPriceNanos uint64, additionalDESORoyaltiesMap map[PublicKey]uint64, additionalCoinRoyaltiesMap map[PublicKey]uint64,
	extraData map[string][]byte,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
		isBuyNow,
		buyNowPriceNanos,
		additionalDESORoyaltiesMap,
		additionalCoinRoyaltiesMap,
		extraData,
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

	require.NoError(utxoView.FlushToDb(0))

	return utxoOps, txn, blockHeight, nil
}

func _createNFT(t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams,
	feeRateNanosPerKB uint64, updaterPkBase58Check string, updaterPrivBase58Check string,
	nftPostHash *BlockHash, numCopies uint64, hasUnlockable bool, isForSale bool, minBidAmountNanos uint64,
	nftFee uint64, nftRoyaltyToCreatorBasisPoints uint64, nftRoyaltyToCoinBasisPoints uint64, isBuyNow bool,
	buyNowPriceNanos uint64,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	return _createNFTWithAdditionalRoyalties(t, chain, db, params, feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		nftPostHash,
		numCopies,
		hasUnlockable,
		isForSale,
		minBidAmountNanos,
		nftFee,
		nftRoyaltyToCreatorBasisPoints,
		nftRoyaltyToCoinBasisPoints,
		isBuyNow,
		buyNowPriceNanos,
		nil,
		nil)
}

func _createNFTWithAdditionalRoyaltiesWithTestMeta(
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
	isBuyNow bool,
	buyNowPriceNanos uint64,
	additionalDESORoyaltiesMap map[PublicKey]uint64,
	additionalCoinRoyaltiesMap map[PublicKey]uint64,
) {
	_createNFTWithAdditionalRoyaltiesAndExtraDataWithTestMeta(
		testMeta,
		feeRateNanosPerKB,
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
		isBuyNow,
		buyNowPriceNanos,
		additionalDESORoyaltiesMap,
		additionalCoinRoyaltiesMap,
		nil,
	)
}

func _createNFTWithAdditionalRoyaltiesAndExtraDataWithTestMeta(
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
	isBuyNow bool,
	buyNowPriceNanos uint64,
	additionalDESORoyaltiesMap map[PublicKey]uint64,
	additionalCoinRoyaltiesMap map[PublicKey]uint64,
	extraData map[string][]byte,
) {
	// Sanity check: the number of NFT entries before should be 0.
	dbNFTEntries := DBGetNFTEntriesForPostHash(testMeta.db, postHashToModify)
	require.Equal(testMeta.t, 0, len(dbNFTEntries))

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))
	currentOps, currentTxn, _, err := _createNFTWithExtraData(
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
		isBuyNow,
		buyNowPriceNanos,
		additionalDESORoyaltiesMap,
		additionalCoinRoyaltiesMap,
		extraData,
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
	isBuyNow bool,
	buyNowPriceNanos uint64,
) {
	_createNFTWithAdditionalRoyaltiesWithTestMeta(
		testMeta,
		feeRateNanosPerKB,
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
		isBuyNow,
		buyNowPriceNanos,
		nil,
		nil,
	)
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

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
	require.NoError(err)

	txn, totalInputMake, _, _, err := chain.CreateNFTBidTxn(
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
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeNFTBid, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb(0))

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

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
	// operation for each BidderInput, one ADD operation
	// for each output, and one OperationTypeAcceptNFTBid operation at the end.
	numTxnInputs := len(txn.TxInputs)
	numTxnOutputs := len(txn.TxOutputs)
	numBidderInputs := len(txn.TxnMeta.(*AcceptNFTBidMetadata).BidderInputs)
	numOps := len(utxoOps)
	ii := 0
	for ; ii < numTxnInputs; ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	for ; ii < numTxnInputs+numTxnOutputs; ii++ {
		require.Equal(OperationTypeAddUtxo, utxoOps[ii].Type)
	}
	for ; ii < numTxnInputs+numTxnOutputs+numBidderInputs; ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	for ; ii < numOps-1; ii++ {
		require.Equal(OperationTypeAddUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeAcceptNFTBid, utxoOps[numOps-1].Type)

	require.NoError(utxoView.FlushToDb(0))

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
	nftPostHash *BlockHash, serialNumber uint64, isForSale bool, minBidAmountNanos uint64, isBuyNow bool,
	buyNowPriceNanos uint64,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateUpdateNFTTxn(
		updaterPkBytes,
		nftPostHash,
		serialNumber,
		isForSale,
		minBidAmountNanos,
		isBuyNow,
		buyNowPriceNanos,
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

	require.NoError(utxoView.FlushToDb(0))

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
	isBuyNow bool,
	buyNowPriceNanos uint64,
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
		isBuyNow,
		buyNowPriceNanos,
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

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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

	require.NoError(utxoView.FlushToDb(0))

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

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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

	require.NoError(utxoView.FlushToDb(0))

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

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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

	require.NoError(utxoView.FlushToDb(0))

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

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3, m4 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true
	params.ParamUpdaterPublicKeys[MakePkMapKey(m4PkBytes)] = true
	params.ForkHeights.BrokenNFTBidsFixBlockHeight = uint32(0)
	params.ForkHeights.BuyNowAndNFTSplitsBlockHeight = uint32(0)
	params.ForkHeights.ExtraDataOnEntriesBlockHeight = uint32(0)

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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreateNFTOnNonexistentPost)
	}

	// Error case: can't set BuyNow to true with unlockable content
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			1,    /*NumCopies*/
			true, /*HasUnlockable*/
			true, /*IsForSale*/
			0,    /*MinBidAmountNanos*/
			0,    /*nftFee*/
			0,    /*nftRoyaltyToCreatorBasisPoints*/
			0,    /*nftRoyaltyToCoinBasisPoints*/
			true, /*IsBuyNow*/
			0,
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCannotHaveUnlockableAndBuyNowNFT)
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreateNFTWithInsufficientFunds)
	}

	// Creating an NFT with the correct NFT fee should succeed.
	// This time set HasUnlockable to 'true'.
	// Add some extra data to the NFT entries
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		numCopies := uint64(10)
		nftFee := utxoView.GlobalParamsEntry.CreateNFTFeeNanos * numCopies

		m0BalBeforeNFT := _getBalance(testMeta.t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(26), m0BalBeforeNFT)

		extraData := map[string][]byte{
			"rarity": []byte("high"),
		}
		_createNFTWithAdditionalRoyaltiesAndExtraDataWithTestMeta(
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
			false,
			0,
			nil,
			nil,
			extraData,
		)

		// Check that m0 was charged the correct nftFee.
		m0BalAfterNFT := _getBalance(testMeta.t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(25)-nftFee, m0BalAfterNFT)

		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post2Hash, 1)
		require.Len(nftEntry.ExtraData, 1)
		require.Equal(nftEntry.ExtraData["rarity"], []byte("high"))
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post2Hash, 1)
		require.Equal(nftEntry.IsForSale, false)
	}

	// Error case: can't update an NFT that has unlockable to be a Buy Now NFT
	{
		_, _, _, err = _updateNFT(t, chain, db, params, 10,
			m3Pub,
			m3Priv,
			post2Hash,
			1,
			true,
			12,
			true,
			0,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCannotHaveUnlockableAndBuyNowNFT)
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
	m0InitialDeSoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
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
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
		require.Equal(m0InitialDeSoLocked+expectedCoinRoyalty, desoLocked)
	}

	// 100 nano bid: Have m1 make a bid on <post1, #3>, accept it and check the royalties.
	{
		m0DeSoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
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
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
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
			false,
			0,
		)
	}

	// 10000 nano bid: Have m3 make a bid on <post1, #1>, accept it and check the royalties.
	{
		m0DeSoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
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
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
		require.Equal(m0DeSoLocked+expectedCoinRoyalty, desoLocked)
	}

	// Error case: Let's make sure that no royalties are paid if there are no coins in circulation.
	{
		_, coinsInCirculationNanos := _getCreatorCoinInfo(t, chain, params, m0Pub)
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
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true

	params.ForkHeights.BrokenNFTBidsFixBlockHeight = uint32(0)
	params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)

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
	m0PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m0PkBytes)
	_ = m0PKID

	m1PkBytes, _, err := Base58CheckDecode(m1Pub)
	require.NoError(err)
	m1PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m1PkBytes)
	_ = m1PKID

	m2PkBytes, _, err := Base58CheckDecode(m2Pub)
	require.NoError(err)
	m2PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m2PkBytes)
	_ = m2PKID

	m3PkBytes, _, err := Base58CheckDecode(m3Pub)
	require.NoError(err)
	m3PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m3PkBytes)
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
			false,
			0,
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
			false,
			0,
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
			false,
			0,
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
		transferredNFT1 := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 2)
		require.Equal(transferredNFT1.IsPending, true)
		require.True(reflect.DeepEqual(transferredNFT1.OwnerPKID, m2PKID.PKID))
		require.True(reflect.DeepEqual(transferredNFT1.LastOwnerPKID, m0PKID.PKID))

		transferredNFT2 := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 5)
		require.Equal(transferredNFT2.IsPending, true)
		require.True(reflect.DeepEqual(transferredNFT2.OwnerPKID, m3PKID.PKID))
		require.True(reflect.DeepEqual(transferredNFT2.LastOwnerPKID, m1PKID.PKID))

		transferredNFT3 := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post2Hash, 1)
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
		acceptedNFT1 := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 2)
		require.Equal(acceptedNFT1.IsPending, false)

		acceptedNFT2 := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post2Hash, 1)
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
		burnedNFT1 := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 5)
		require.Nil(burnedNFT1)

		burnedNFT2 := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post2Hash, 3)
		require.Nil(burnedNFT2)

		// Check that the post entries have the correct burn count.
		post1 := DBGetPostEntryByPostHash(db, chain.snapshot, post1Hash)
		require.Equal(uint64(1), post1.NumNFTCopiesBurned)

		post2 := DBGetPostEntryByPostHash(db, chain.snapshot, post2Hash)
		require.Equal(uint64(1), post2.NumNFTCopiesBurned)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestBidAmountZero(t *testing.T) {

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
			false,
			0,
		)

		// Post 1 should have 1 copies.
		dbEntries := DBGetNFTEntriesForPostHash(db, post1Hash)
		require.Equal(1, len(dbEntries))
	}

	// Case: User can submit a bid of amount 0 on an NFT with MinBidAmountNanos of 0. It doesn't do anything though.
	{
		// M1 places a pointless bid of 0.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1, /*SerialNumber*/
			0, /*BidAmountNanos*/
		)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

	}
	// Case: User submits bid and cancels it. Bid cannot be accepted. Users submits new bid. It can be accepted.
	// Have m1 place a bid and m0 accept it.
	{
		// Place a bid of 1 nano
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

		// Cancel bid.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1, /*SerialNumber*/
			0, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		{
			_, _, _, err = _acceptNFTBid(
				t, chain, db, params, 10,
				m0Pub,
				m0Priv,
				post1Hash,
				1, /*SerialNumber*/
				m1Pub,
				1,  /*BidAmountNanos*/
				"", /*UnlockableText*/
			)
			require.Error(err)
			require.Contains(err.Error(), RuleErrorCantAcceptNonExistentBid)
		}

		// Place a bid of 2 nanos
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1, /*SerialNumber*/
			2, /*BidAmountNanos*/
		)

		// Accept that bid
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1, /*SerialNumber*/
			m1Pub,
			2,  /*BidAmountNanos*/
			"", /*UnlockableText*/
		)

		// There are no bid entries after it has been accepted.
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 1)
		m1PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m1PkBytes)
		require.Equal(nftEntry.OwnerPKID, m1PKID.PKID)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)

}

func TestNFTBuyNow(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3, m4 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true
	params.ParamUpdaterPublicKeys[MakePkMapKey(m4PkBytes)] = true
	params.ForkHeights.BuyNowAndNFTSplitsBlockHeight = uint32(0)

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

		m0Bal := _getBalance(t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(930), m0Bal)
	}
	// Initial deso locked before royalties.
	m0InitialDeSoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
	require.Equal(uint64(28), m0InitialDeSoLocked)

	// Error case: Cannot create Buy Now NFT with unlockable content.
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			100,  /*NumCopies*/
			true, /*HasUnlockable*/
			true, /*IsForSale*/
			0,    /*MinBidAmountNanos*/
			0,    /*nftFee*/
			0,    /*nftRoyaltyToCreatorBasisPoints*/
			0,    /*nftRoyaltyToCoinBasisPoints*/
			true, /*IsBuyNow*/
			10,
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCannotHaveUnlockableAndBuyNowNFT)
	}

	// Error case: Cannot create Buy Now NFT with Buy Now price less than MinBidAmountNanos
	{
		_, _, _, err := _createNFT(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			100,   /*NumCopies*/
			false, /*HasUnlockable*/
			true,  /*IsForSale*/
			11,    /*MinBidAmountNanos*/
			0,     /*nftFee*/
			0,     /*nftRoyaltyToCreatorBasisPoints*/
			0,     /*nftRoyaltyToCoinBasisPoints*/
			true,  /*IsBuyNow*/
			10,
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCannotHaveBuyNowPriceBelowMinBidAmountNanos)
	}

	// Create NFT with a BuyNow price of 100 nanos and 10% coin + 10% creator royalties
	{
		// Balance before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(930), m0BalBeforeNFT)

		_createNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			100,    /*NumCopies*/
			false,  /*HasUnlockable*/
			true,   /*IsForSale*/
			0,      /*MinBidAmountNanos*/
			0,      /*nftFee*/
			10*100, /*nftRoyaltyToCreatorBasisPoints*/
			20*100, /*nftRoyaltyToCoinBasisPoints*/
			true,   /*IsBuyNow*/
			100,
		)

		// Balance after. Since the default NFT fee is 0, m0 is only charged the nanos per kb fee.
		m0BalAfterNFT := _getBalance(t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(928), m0BalAfterNFT)
	}

	// Have m1 buy serial #1.
	{
		bidAmountNanos := uint64(100)
		// Creator Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(928), m0BalBefore)

		// Bidder Balance before.
		m1BalBefore := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1000), m1BalBefore)

		// There are no bids before.
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// M1 purchases this NFT by submitting a bid greater than the MinBidAmountNanos on this Buy-Now NFT.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1,              /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 1)

		// M1 is now the owner of the NFT.
		m1PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m1PkBytes)
		require.Equal(nftEntry.OwnerPKID, m1PKID.PKID)

		// Balance after. M0's balance should increase by the bid amount (100) less coin royalties (20)
		m0BalAfter := _getBalance(t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(1008), m0BalAfter)

		// Balance after. m1 should pay for the bid amount + cover the transaction fee.
		m1BalAfter := _getBalance(t, testMeta.chain, nil, m1Pub)
		require.Equal(uint64(899), m1BalAfter)

		// Make sure royalties to creator and to coin are paid out correctly.
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(uint64(10), expectedCreatorRoyalty)
		expectedCoinRoyalty := 2 * bidAmountNanos / 10
		require.Equal(uint64(20), expectedCoinRoyalty)
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
		require.Equal(m0InitialDeSoLocked+expectedCoinRoyalty, desoLocked)
	}

	// Error case: Cannot Update an NFT to have a Buy Now price less than Min Bid Amount nanos
	{
		_, _, _, err := _updateNFT(
			t, chain, db, params, 10,
			m1Pub,
			m1Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			10,   /*MinBidAmountNanos*/
			true, /*IsBuyNow*/
			5,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCannotHaveBuyNowPriceBelowMinBidAmountNanos)
	}

	// Have m1 put the NFT up for sale again as a buy now NFT
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
			true, /*IsBuyNow*/
			150,
		)
	}

	// Have m2 purchase the NFT
	{
		bidAmountNanos := uint64(150)
		// Creator Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(1008), m0BalBefore)

		// Seller Balance before.
		m1BalBefore := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(897), m1BalBefore)

		// Bidder Balance before.
		m2BalBefore := _getBalance(t, chain, nil, m2Pub)
		require.Equal(uint64(1000), m2BalBefore)

		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// DESO locked before royalties.
		m0DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)

		// m1 --> <post1, #1>
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1,              /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)

		// No bids exist for this serial number anymore.
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 1)

		// M2 is now the owner.
		m2PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m2PkBytes)
		require.Equal(nftEntry.OwnerPKID, m2PKID.PKID)

		// Creator Balance after. M0's balance should increase by the creator royalties (15)
		m0BalAfter := _getBalance(t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(1023), m0BalAfter)
		require.Equal(m0BalAfter, m0BalBefore+15)

		// Seller Balance after. M1's balance should increase by the bid amount (150) less coin royalties (30) and creator royalties (15)
		m1BalAfter := _getBalance(t, testMeta.chain, nil, m1Pub)
		require.Equal(uint64(1002), m1BalAfter)
		require.Equal(m1BalAfter, m1BalBefore+bidAmountNanos-30-15)

		// Bidder Balance after. m2 should pay for the bid amount (150) + cover the transaction fee (1).
		m2BalAfter := _getBalance(t, testMeta.chain, nil, m2Pub)
		require.Equal(uint64(849), m2BalAfter)
		require.Equal(m2BalAfter, m2BalBefore-bidAmountNanos-1)

		// Make sure royalties to creator and to coin are paid out correctly.
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(uint64(15), expectedCreatorRoyalty)
		expectedCoinRoyalty := 2 * bidAmountNanos / 10
		require.Equal(uint64(30), expectedCoinRoyalty)
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
		require.Equal(m0DeSoLockedBefore+expectedCoinRoyalty, desoLocked)
	}

	// Have m2 put the NFT up for auction - making sure an NFT that was
	// buy-now can be auctioned off in the future.
	{
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1,     /*SerialNumber*/
			true,  /*IsForSale*/
			0,     /*MinBidAmountNanos*/
			false, /*IsBuyNow*/
			0,
		)
	}

	// Submit some bids
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
			1,  /*SerialNumber*/
			10, /*BidAmountNanos*/
		)

		// There is one bid now.
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))

		// m0: Add a bid from m0 for fun.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1, /*SerialNumber*/
			8, /*BidAmountNanos*/
		)

		// There are two bids now.
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(2, len(bidEntries))

		// m3: Add a bid from m3 for fun.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			1,  /*SerialNumber*/
			20, /*BidAmountNanos*/
		)

		// There are three bids now.
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(3, len(bidEntries))

		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 1)

		// m2 is still the owner of the NFT since this is not a buy now.
		m2PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m2PkBytes)
		require.Equal(nftEntry.OwnerPKID, m2PKID.PKID)
	}

	// Have m2 accept bid from m3
	{
		bidAmountNanos := uint64(20)
		// Creator Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(1022), m0BalBefore)

		// Bidder Balance before.
		m3BalBefore := _getBalance(t, chain, nil, m3Pub)
		require.Equal(uint64(999), m3BalBefore)

		// Seller Balance before.
		m2BalBefore := _getBalance(t, chain, nil, m2Pub)
		require.Equal(uint64(848), m2BalBefore)

		// DESO locked before royalties.
		m0DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)

		// M2 accepts M3's bid.
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1, /*SerialNumber*/
			m3Pub,
			bidAmountNanos, /*BidAmountNanos*/
			"",             /*UnlockableText*/
		)
		// All outstanding bids on serial #1 are cancelled.
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 1)

		// m3 is now the owner of the NFT.
		m3PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m3PkBytes)
		require.Equal(nftEntry.OwnerPKID, m3PKID.PKID)

		// Creator Balance after. M0's balance should increase by the creator royalties (2)
		m0BalAfter := _getBalance(t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(1024), m0BalAfter)
		require.Equal(m0BalAfter, m0BalBefore+2)

		// Bidder Balance after. M3's balance should decrease by the bid amount (20)
		m3BalAfter := _getBalance(t, testMeta.chain, nil, m3Pub)
		require.Equal(uint64(979), m3BalAfter)
		require.Equal(m3BalAfter, m3BalBefore-20)

		// Seller Balance after. m2's balance should increase by the bid amount (20) less creator royalties (2), coin royalties (4) and the transaction fee (2).
		m2BalAfter := _getBalance(t, testMeta.chain, nil, m2Pub)
		require.Equal(uint64(860), m2BalAfter)
		require.Equal(m2BalAfter, m2BalBefore+20-4-2-2)

		// Make sure royalties to creator and to coin are paid out correctly.
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(uint64(2), expectedCreatorRoyalty)
		expectedCoinRoyalty := 2 * bidAmountNanos / 10
		require.Equal(uint64(4), expectedCoinRoyalty)
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
		require.Equal(m0DeSoLockedBefore+expectedCoinRoyalty, desoLocked)
	}

	// Case: User puts NFT on sale as Buy Now NFT. Others bid. User
	// accepts a bid greater than min bid amount nanos
	{
		// M3 puts the NFT on sale a buy now NFT
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			5,    /*MinBidAmountNanos*/
			true, /*IsBuyNow*/
			100,
		)

		// There are no bids when it is first put on sale
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// m1 submits a bid below buy now price
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1,  /*SerialNumber*/
			10, /*BidAmountNanos*/
		)

		// There is 1 bid now.
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))

		// m2 submits a bid below buy now price
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1,  /*SerialNumber*/
			30, /*BidAmountNanos*/
		)

		// There are two bids now.
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(2, len(bidEntries))

		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 1)

		// m3 is still the owner of the NFT since no bid exceeded the buy now NFT price.
		m3PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m3PkBytes)
		require.Equal(nftEntry.OwnerPKID, m3PKID.PKID)
	}

	// Have m3 accept bid from m2
	{
		bidAmountNanos := uint64(30)
		// Creator Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(1024), m0BalBefore)

		// Bidder Balance before.
		m2BalBefore := _getBalance(t, chain, nil, m2Pub)
		require.Equal(uint64(859), m2BalBefore)

		// Seller Balance before.
		m3BalBefore := _getBalance(t, chain, nil, m3Pub)
		require.Equal(uint64(977), m3BalBefore)

		// DESO locked before royalties.
		m0DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)

		// M3 accepts M2's bid.
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			1, /*SerialNumber*/
			m2Pub,
			bidAmountNanos, /*BidAmountNanos*/
			"",             /*UnlockableText*/
		)
		// All outstanding bids on serial #1 are cancelled.
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 1)

		// m2 is now the owner of the NFT.
		m2PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m2PkBytes)
		require.Equal(nftEntry.OwnerPKID, m2PKID.PKID)

		// Creator Balance after. M0's balance should increase by the creator royalties (3)
		m0BalAfter := _getBalance(t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(1027), m0BalAfter)
		require.Equal(m0BalAfter, m0BalBefore+3)

		// Bidder Balance after. M2's balance should decrease by the bid amount (30)
		m2BalAfter := _getBalance(t, testMeta.chain, nil, m2Pub)
		require.Equal(uint64(829), m2BalAfter)
		require.Equal(m2BalAfter, m2BalBefore-30)

		// Seller Balance after. m3's balance should increase by the bid amount (30) less creator royalties (3), coin royalties (6) and the transaction fee (2).
		m3BalAfter := _getBalance(t, testMeta.chain, nil, m3Pub)
		require.Equal(uint64(996), m3BalAfter)
		require.Equal(m3BalAfter, m3BalBefore+30-6-3-2)

		// Make sure royalties to creator and to coin are paid out correctly.
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(uint64(3), expectedCreatorRoyalty)
		expectedCoinRoyalty := 2 * bidAmountNanos / 10
		require.Equal(uint64(6), expectedCoinRoyalty)
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
		require.Equal(m0DeSoLockedBefore+expectedCoinRoyalty, desoLocked)
	}

	// Case: User puts NFT on sale as Buy Now NFT and with min bid amount
	// nanos being 0. Users bid but one Bidder "buys now"
	{
		// M2 puts the NFT on sale a buy now NFT
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			20,   /*MinBidAmountNanos*/
			true, /*IsBuyNow*/
			100,
		)

		// There are no bids when it is first put on sale
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// m1 submits a bid below buy now price
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1,  /*SerialNumber*/
			40, /*BidAmountNanos*/
		)

		// There is 1 bid now.
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))

		// m3 submits a bid below buy now price
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			1,  /*SerialNumber*/
			50, /*BidAmountNanos*/
		)

		// There are two bids now.
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(2, len(bidEntries))

		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 1)

		// m2 is still the owner of the NFT since no bid exceeded the buy now NFT price.
		m2PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m2PkBytes)
		require.Equal(nftEntry.OwnerPKID, m2PKID.PKID)
	}

	// Have m0 buy the NFT now
	{
		bidAmountNanos := uint64(100)
		// Creator & Bidder Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(1027), m0BalBefore)

		// Seller Balance before.
		m2BalBefore := _getBalance(t, chain, nil, m2Pub)
		require.Equal(uint64(827), m2BalBefore)

		// DESO locked before royalties.
		m0DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)

		// Submit Buy Now bid
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1,              /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)
		// All outstanding bids on serial #1 are cancelled.
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 1)

		// m0 is now the owner of the NFT.
		m0PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m0PkBytes)
		require.Equal(nftEntry.OwnerPKID, m0PKID.PKID)

		// Creator & Buyer Balance after. M0's balance should increase by the creator royalties (10) minus the bid amount (100) and the transaction fee (3)
		m0BalAfter := _getBalance(t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(934), m0BalAfter)
		require.Equal(m0BalAfter, m0BalBefore+10-100-3)

		// Seller Balance after. m2's balance should increase by the bid amount (100) less creator royalties (10), coin royalties (20).
		m2BalAfter := _getBalance(t, testMeta.chain, nil, m2Pub)
		require.Equal(uint64(897), m2BalAfter)
		require.Equal(m2BalAfter, m2BalBefore+100-20-10)

		// Make sure royalties to creator and to coin are paid out correctly.
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(uint64(10), expectedCreatorRoyalty)
		expectedCoinRoyalty := 2 * bidAmountNanos / 10
		require.Equal(uint64(20), expectedCoinRoyalty)
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
		require.Equal(m0DeSoLockedBefore+expectedCoinRoyalty, desoLocked)
	}

	// Case User puts NFT on sale as Buy Now NFT. Bidder wins with amount greater than
	// Buy Now NFT price.
	{
		// M0 puts the NFT on sale a buy now NFT
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			10,   /*MinBidAmountNanos*/
			true, /*IsBuyNow*/
			50,
		)

		// There are no bids when it is first put on sale
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))
	}

	// Have m1 buy the NFT now for 60, 10 more than the buy now price. Tough cookies m1, but you're still paying 60.
	{
		bidAmountNanos := uint64(60)
		// Creator & Seller Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(932), m0BalBefore)

		// Buyer Balance before.
		m1BalBefore := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(999), m1BalBefore)

		// DESO locked before royalties.
		m0DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)

		// Submit Buy Now bid
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1,              /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)
		// All outstanding bids on serial #1 are cancelled.
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 1)

		// m1 is now the owner of the NFT.
		m1PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m1PkBytes)
		require.Equal(nftEntry.OwnerPKID, m1PKID.PKID)

		// Creator & Seller Balance after. M0's balance should increase by the bid amount (60) minus the creator coin royalties (12)
		m0BalAfter := _getBalance(t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(980), m0BalAfter)
		require.Equal(m0BalAfter, m0BalBefore+60-12)

		// Buyer's Balance after. m1's balance should decrease by the bid amount (60) plus transaction fee (1).
		m1BalAfter := _getBalance(t, testMeta.chain, nil, m1Pub)
		require.Equal(uint64(938), m1BalAfter)
		require.Equal(m1BalAfter, m1BalBefore-60-1)

		// Make sure royalties to creator and to coin are paid out correctly.
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(uint64(6), expectedCreatorRoyalty)
		expectedCoinRoyalty := 2 * bidAmountNanos / 10
		require.Equal(uint64(12), expectedCoinRoyalty)
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
		require.Equal(m0DeSoLockedBefore+expectedCoinRoyalty, desoLocked)
	}

	// Case: User Puts NFT on sale as Buy Now NFT with 0 as Buy now price. First bid wins.
	{
		// M1 puts the NFT on sale a buy now NFT
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			0,    /*MinBidAmountNanos*/
			true, /*IsBuyNow*/
			0,
		)

		// There are no bids when it is first put on sale
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// M2 submits a bid with an amount 0 which means cancel my bid. Even if the Buy Now price is 0, a user must bid
		// at least 1 nano in order to win.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1, /*SerialNumber*/
			0, /*BidAmountNanos*/
		)

		// There are still no bids
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

	}

	// Have m2 buy the NFT now for 5
	{
		bidAmountNanos := uint64(5)
		// Creator balance before
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(980), m0BalBefore)

		// Seller Balance before.
		m1BalBefore := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(936), m1BalBefore)

		// Buyer Balance before.
		m2BalBefore := _getBalance(t, chain, nil, m2Pub)
		require.Equal(uint64(896), m2BalBefore)

		// DESO locked before royalties.
		m0DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)

		// Submit Buy Now bid
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1,              /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)
		// All outstanding bids on serial #1 are cancelled.
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 1)

		// m1 is now the owner of the NFT.
		m2PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m2PkBytes)
		require.Equal(nftEntry.OwnerPKID, m2PKID.PKID)

		// Creator & Seller Balance after. M0's balance won't increase all, since the creator royalties are 0 (10% of 5 is less than 1).
		m0BalAfter := _getBalance(t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(980), m0BalAfter)
		require.Equal(m0BalAfter, m0BalBefore)

		// Seller's Balance after. m1's balance should increase by the bid amount (5) minus coin royalties (1). There are no creator royalties here.
		m1BalAfter := _getBalance(t, testMeta.chain, nil, m1Pub)
		require.Equal(uint64(940), m1BalAfter)
		require.Equal(m1BalAfter, m1BalBefore+5-1)

		// Buyer's Balance after. m2's balance should decrease by the bid amount (5) and the transaction fee (1).
		m2BalAfter := _getBalance(t, testMeta.chain, nil, m2Pub)
		require.Equal(uint64(890), m2BalAfter)
		require.Equal(m2BalAfter, m2BalBefore-5-1)

		// Make sure royalties to creator and to coin are paid out correctly.
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(uint64(0), expectedCreatorRoyalty)
		expectedCoinRoyalty := 2 * bidAmountNanos / 10
		require.Equal(uint64(1), expectedCoinRoyalty)
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
		require.Equal(m0DeSoLockedBefore+expectedCoinRoyalty, desoLocked)
	}

	// Case: NFT is transferred. Before being accepted, it can't be put on sale as a
	// buy now NFT. Once accepted, all is good.
	{
		params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)
		_transferNFTWithTestMeta(
			testMeta,
			10,
			m2Pub,
			m2Priv,
			m3Pub,
			post1Hash,
			1,
			"",
		)

		m3PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m3PkBytes)
		m2PKID := DBGetPKIDEntryForPublicKey(db, chain.snapshot, m2PkBytes)
		// Check the state of the transferred NFTs.
		transferredNFT := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 1)
		require.Equal(transferredNFT.IsPending, true)
		require.True(reflect.DeepEqual(transferredNFT.OwnerPKID, m3PKID.PKID))
		require.True(reflect.DeepEqual(transferredNFT.LastOwnerPKID, m2PKID.PKID))

		// The NFT is not for sale and is not buy now
		require.False(transferredNFT.IsBuyNow)
		require.False(transferredNFT.IsForSale)

		// You can't bid on a pending NFT. A Pending NFT can't be on sale.
		{
			_, _, _, err := _createNFTBid(
				t, chain, db, params, 10,
				m2Pub,
				m2Priv,
				post1Hash,
				1,  /*SerialNumber*/
				10, /*BidAmountNanos*/
			)
			require.Error(err)
			require.Contains(err.Error(), RuleErrorNFTBidOnNFTThatIsNotForSale)
		}

		// M3 accepts the transfer
		_acceptNFTTransferWithTestMeta(
			testMeta,
			10,
			m3Pub,
			m3Priv,
			post1Hash,
			1,
		)

		acceptedNFT := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 1)
		require.False(acceptedNFT.IsPending)
		require.False(acceptedNFT.IsBuyNow)
		require.False(acceptedNFT.IsForSale)

		// M3 puts it on sale as a buy now NFT
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			0,    /*MinBidAmountNanos*/
			true, /*IsBuyNow*/
			20,
		)

		// M3 can't transfer an NFT that is for sale
		{
			_, _, _, err := _transferNFT(
				t, chain, db, params, 10,
				m3Pub,
				m3Priv,
				m0Pub,
				post1Hash,
				1,
				"",
			)

			require.Error(err)
			require.Contains(err.Error(), RuleErrorCannotTransferForSaleNFT)
		}

		// M1 submits a bid less than Buy Now Price
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m1Pub,
			m1Priv,
			post1Hash,
			1,  /*SerialNumber*/
			10, /*BidAmountNanos*/
		)
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))

		// M0 submits a bid on serial number 0. Bidding on serial number zero does not trigger a buy now operation.
		_createNFTBidWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			post1Hash,
			0,
			101)

		// There is still 1 bid now.
		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))

		// Finally just have M2 buy this NFT.
		_createNFTBidWithTestMeta(
			testMeta,
			10,
			m2Pub,
			m2Priv,
			post1Hash,
			1,
			20,
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, chain.snapshot, post1Hash, 1)
		require.Equal(nftEntry.OwnerPKID, m2PKID.PKID)

	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestNFTSplits(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3, m4 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true
	params.ParamUpdaterPublicKeys[MakePkMapKey(m4PkBytes)] = true
	params.ForkHeights.BuyNowAndNFTSplitsBlockHeight = uint32(0)

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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m5Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m6Pub, senderPrivString, 1000)

	//m4PKID := DBGetPKIDEntryForPublicKey(db, m4PkBytes)
	//m5PKID := DBGetPKIDEntryForPublicKey(db, m5PkBytes)
	//m6PKID := DBGetPKIDEntryForPublicKey(db, m6PkBytes)

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
		// You need a profile in order to create an NFT. Create a profile for M0
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
		// You need a profile in order to receive royalties to your coin
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m1",          /*newUsername*/
			"i am the m1", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)

		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m2Pub,         /*updaterPkBase58Check*/
			m2Priv,        /*updaterPrivBase58Check*/
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

		m0Bal := _getBalance(t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(930), m0Bal)

		_creatorCoinTxnWithTestMeta(
			testMeta,
			10,     /*feeRateNanosPerKB*/
			m1Pub,  /*updaterPkBase58Check*/
			m1Priv, /*updaterPrivBase58Check*/
			m1Pub,  /*profilePubKeyBase58Check*/
			CreatorCoinOperationTypeBuy,
			29, /*DeSoToSellNanos*/
			0,  /*CreatorCoinToSellNanos*/
			0,  /*DeSoToAddNanos*/
			0,  /*MinDeSoExpectedNanos*/
			10, /*MinCreatorCoinExpectedNanos*/
		)

		m1Bal := _getBalance(t, testMeta.chain, nil, m1Pub)
		require.Equal(uint64(931), m1Bal)
	}
	// Initial deso locked before royalties.
	m0InitialDeSoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
	require.Equal(uint64(28), m0InitialDeSoLocked)

	m1InitialDeSoLocked, _ := _getCreatorCoinInfo(t, chain, params, m1Pub)
	require.Equal(uint64(28), m1InitialDeSoLocked)

	// Cannot give coin royalty if a public key does not have a profile
	{
		additionalCoinRoyaltyMap := make(map[PublicKey]uint64)
		additionalCoinRoyaltyMap[*NewPublicKey(m3PkBytes)] = 10 * 100
		_, _, _, err := _createNFTWithAdditionalRoyalties(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			100,
			false,
			false,
			0,
			0,
			10*100,
			20*100,
			false,
			0,
			nil,
			additionalCoinRoyaltyMap,
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorAdditionalCoinRoyaltyMustHaveProfile)
	}

	// Cannot overflow basis points
	{
		additionalCoinRoyaltyMap := make(map[PublicKey]uint64)
		additionalCoinRoyaltyMap[*NewPublicKey(m1PkBytes)] = math.MaxUint64
		additionalCoinRoyaltyMap[*NewPublicKey(m2PkBytes)] = 10
		_, _, _, err = _createNFTWithAdditionalRoyalties(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			100,
			false,
			false,
			0,
			0,
			10*100,
			20*100,
			false,
			0,
			nil,
			additionalCoinRoyaltyMap,
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorAdditionalCoinRoyaltyOverflow)
	}
	{

		additionalDESORoyaltyMap := make(map[PublicKey]uint64)
		additionalDESORoyaltyMap[*NewPublicKey(m2PkBytes)] = math.MaxUint64 - 1
		additionalDESORoyaltyMap[*NewPublicKey(m3PkBytes)] = 10
		_, _, _, err = _createNFTWithAdditionalRoyalties(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			100,
			false,
			false,
			0,
			0,
			10*100,
			20*100,
			false,
			0,
			additionalDESORoyaltyMap,
			nil,
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorAdditionalCoinRoyaltyOverflow)
	}
	// Cannot overflow basis points across poster's royalties and additional royalties
	{
		{
			additionalCoinRoyaltyMap := make(map[PublicKey]uint64)
			additionalCoinRoyaltyMap[*NewPublicKey(m2PkBytes)] = 10
			additionalDESORoyaltyMap := make(map[PublicKey]uint64)
			additionalDESORoyaltyMap[*NewPublicKey(m2PkBytes)] = math.MaxUint64 - 1
			_, _, _, err = _createNFTWithAdditionalRoyalties(
				t, chain, db, params, 10,
				m0Pub,
				m0Priv,
				post1Hash,
				100,
				false,
				false,
				0,
				0,
				0*100,
				0*100,
				false,
				0,
				additionalDESORoyaltyMap,
				additionalCoinRoyaltyMap,
			)

			require.Error(err)
			require.Contains(err.Error(), RuleErrorNFTRoyaltyOverflow)
		}
		{
			additionalCoinRoyaltyMap := make(map[PublicKey]uint64)
			additionalCoinRoyaltyMap[*NewPublicKey(m2PkBytes)] = 10
			additionalDESORoyaltyMap := make(map[PublicKey]uint64)
			additionalDESORoyaltyMap[*NewPublicKey(m2PkBytes)] = 10
			_, _, _, err = _createNFTWithAdditionalRoyalties(
				t, chain, db, params, 10,
				m0Pub,
				m0Priv,
				post1Hash,
				100,
				false,
				false,
				0,
				0,
				math.MaxUint64-10,
				0*100,
				false,
				0,
				additionalDESORoyaltyMap,
				additionalCoinRoyaltyMap,
			)

			require.Error(err)
			require.Contains(err.Error(), RuleErrorNFTRoyaltyOverflow)
		}
		{
			_, _, _, err = _createNFTWithAdditionalRoyalties(
				t, chain, db, params, 10,
				m0Pub,
				m0Priv,
				post1Hash,
				100,
				false,
				false,
				0,
				0,
				math.MaxUint64-10,
				11,
				false,
				0,
				nil,
				nil,
			)

			require.Error(err)
			require.Contains(err.Error(), RuleErrorNFTRoyaltyOverflow)
		}
	}
	// Cannot specify the creator as an additional coin royalty
	{
		additionalCoinRoyaltyMap := make(map[PublicKey]uint64)
		additionalCoinRoyaltyMap[*NewPublicKey(m0PkBytes)] = 10 * 100
		_, _, _, err := _createNFTWithAdditionalRoyalties(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			100,
			false,
			false,
			0,
			0,
			10*100,
			20*100,
			false,
			0,
			nil,
			additionalCoinRoyaltyMap,
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCannotSpecifyCreatorAsAdditionalRoyalty)
	}

	// Cannot specify the creator as an additional DESO royalty
	{
		additionalDESORoyaltyMap := make(map[PublicKey]uint64)
		additionalDESORoyaltyMap[*NewPublicKey(m0PkBytes)] = 10 * 100
		_, _, _, err := _createNFTWithAdditionalRoyalties(
			t, chain, db, params, 10,
			m0Pub,
			m0Priv,
			post1Hash,
			100,
			false,
			false,
			0,
			0,
			10*100,
			20*100,
			false,
			0,
			additionalDESORoyaltyMap,
			nil,
		)

		require.Error(err)
		require.Contains(err.Error(), RuleErrorCannotSpecifyCreatorAsAdditionalRoyalty)
	}

	// Cannot have too many basis points as royalty across all royalties specified.
	{
		{
			additionalDESORoyaltyMap := make(map[PublicKey]uint64)
			additionalDESORoyaltyMap[*NewPublicKey(m1PkBytes)] = 30 * 100
			additionalDESORoyaltyMap[*NewPublicKey(m2PkBytes)] = 50 * 100
			_, _, _, err := _createNFTWithAdditionalRoyalties(
				t, chain, db, params, 10,
				m0Pub,
				m0Priv,
				post1Hash,
				100,
				false,
				false,
				0,
				0,
				10*100,
				20*100,
				false,
				0,
				additionalDESORoyaltyMap,
				nil,
			)

			require.Error(err)
			require.Contains(err.Error(), RuleErrorNFTRoyaltyHasTooManyBasisPoints)
		}
		{
			additionalDESORoyaltyMap := make(map[PublicKey]uint64)
			additionalDESORoyaltyMap[*NewPublicKey(m1PkBytes)] = 30 * 100
			additionalDESORoyaltyMap[*NewPublicKey(m2PkBytes)] = 10 * 100
			additionalCoinRoyaltyMap := make(map[PublicKey]uint64)
			additionalCoinRoyaltyMap[*NewPublicKey(m1PkBytes)] = 50 * 100
			_, _, _, err := _createNFTWithAdditionalRoyalties(
				t, chain, db, params, 10,
				m0Pub,
				m0Priv,
				post1Hash,
				100,
				false,
				false,
				0,
				0,
				10*100,
				20*100,
				false,
				0,
				additionalDESORoyaltyMap,
				additionalCoinRoyaltyMap,
			)

			require.Error(err)
			require.Contains(err.Error(), RuleErrorNFTRoyaltyHasTooManyBasisPoints)
		}
	}

	// Create NFT with 10% royalty to creator, 20% to coin, 5% to m1's coin and 1% to m2
	{
		// Balance before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(930), m0BalBeforeNFT)

		additionalDESORoyaltyMap := make(map[PublicKey]uint64)
		additionalDESORoyaltyMap[*NewPublicKey(m2PkBytes)] = 100

		additionalCoinRoyaltyMap := make(map[PublicKey]uint64)
		additionalCoinRoyaltyMap[*NewPublicKey(m1PkBytes)] = 500

		_createNFTWithAdditionalRoyaltiesWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			100,    /*NumCopies*/
			false,  /*HasUnlockable*/
			true,   /*IsForSale*/
			0,      /*MinBidAmountNanos*/
			0,      /*nftFee*/
			10*100, /*nftRoyaltyToCreatorBasisPoints*/
			20*100, /*nftRoyaltyToCoinBasisPoints*/
			false,  /*IsBuyNow*/
			0,
			additionalDESORoyaltyMap,
			additionalCoinRoyaltyMap,
		)

		// Balance after. Since the default NFT fee is 0, m0 is only charged the nanos per kb fee.
		m0BalAfterNFT := _getBalance(t, testMeta.chain, nil, m0Pub)
		require.Equal(int64(928), int64(m0BalAfterNFT))
	}

	// Have m3 bid on serial #1. Have m0 accept bid.
	{
		bidAmountNanos := uint64(100)
		// Creator Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(int64(928), int64(m0BalBefore))

		// Bidder Balance before.
		m3BalBefore := _getBalance(t, chain, nil, m3Pub)
		require.Equal(int64(1000), int64(m3BalBefore))

		// Creator's DESO locked before
		m0DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)

		// M1's DESO locked before
		m1DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m1Pub)

		// M2's balance before
		m2BalBefore := _getBalance(t, chain, nil, m2Pub)
		require.Equal(int64(961), int64(m2BalBefore))

		// There are no bids before.
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// M3 bids 100 on this NFT.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			1,              /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)

		m3BalAfterBid := _getBalance(t, chain, nil, m3Pub)
		require.Equal(int64(999), int64(m3BalAfterBid))

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(1, len(bidEntries))

		//nftEntry := DBGetNFTEntryByPostHashSerialNumber(db, post1Hash, 1)
		_acceptNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1,     /*SerialNumber*/
			m3Pub, /*bidderPkBase58Check*/
			bidAmountNanos,
			"", /*UnencryptedUnlockableText*/
		)

		// Check royalties. 10% for the creator, 10% for the coin, 5% to m1's coin, and 1% to m2's wallet
		m0BalAfter := _getBalance(t, chain, nil, m0Pub)
		m2BalAfter := _getBalance(t, chain, nil, m2Pub)

		// Creator royalty = 10, coin royalty = 20, m1's coin royalty = 5, m2's royalty = 1
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(int64(10), int64(expectedCreatorRoyalty))
		expectedCoinRoyalty := bidAmountNanos / 5
		require.Equal(int64(20), int64(expectedCoinRoyalty))
		expectedM1CoinRoyalty := bidAmountNanos / 20
		require.Equal(int64(5), int64(expectedM1CoinRoyalty))
		expectedM2Royalty := bidAmountNanos / 100
		require.Equal(int64(1), int64(expectedM2Royalty))
		// Check creator's balance
		bidAmountMinusRoyalties := bidAmountNanos - expectedCoinRoyalty - expectedCreatorRoyalty - expectedM1CoinRoyalty - expectedM2Royalty
		require.Equal(m0BalBefore-2+bidAmountMinusRoyalties+expectedCreatorRoyalty, m0BalAfter)
		require.Equal(int64(1000), int64(m0BalAfter))
		// Check m2's balance
		require.Equal(m2BalBefore+expectedM2Royalty, m2BalAfter)
		require.Equal(int64(962), int64(m2BalAfter))
		// Make sure that the bidder's balance decreased by the bid amount.
		m3BalAfter := _getBalance(t, chain, nil, m3Pub)
		require.Equal(m3BalAfterBid-bidAmountNanos, m3BalAfter)
		require.Equal(int64(899), int64(m3BalAfter))

		// Check coin royalties
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
		require.Equal(m0DeSoLockedBefore+expectedCoinRoyalty, desoLocked)

		desoLockedM1, _ := _getCreatorCoinInfo(t, chain, params, m1Pub)
		require.Equal(m1DeSoLockedBefore+expectedM1CoinRoyalty, desoLockedM1)
	}

	// M3 puts it on sale and m2 buys it. Test that when additional royalty is paid to bidder that things work as
	// expected.
	{
		// m3 puts it on sale as buy now at 200 nanos
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			100,  /*MinBidAmountNanos*/
			true, /*IsBuyNow*/
			200,
		)

		// M2 bids 200 to buy the NFT outright.
		bidAmountNanos := uint64(200)
		// Creator Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(int64(1000), int64(m0BalBefore))

		// Bidder/m2 Balance before.
		m2BalBefore := _getBalance(t, chain, nil, m2Pub)
		require.Equal(int64(962), int64(m2BalBefore))

		// Seller balance before
		m3BalBefore := _getBalance(t, chain, nil, m3Pub)
		require.Equal(int64(897), int64(m3BalBefore))

		// Creator's DESO locked before
		m0DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)

		// M1's DESO locked before
		m1DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m1Pub)

		// There are no bids before.
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// M2 buys this NFT for 200.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1,              /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// Check royalties. 10% for the creator, 20% for the coin, 5% to m1's coin, and 1% to m2's wallet
		m0BalAfter := _getBalance(t, chain, nil, m0Pub)
		m2BalAfter := _getBalance(t, chain, nil, m2Pub)

		// Creator royalty = 20, coin royalty = 40, m1's coin royalty = 10, m2's royalty = 2
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(int64(20), int64(expectedCreatorRoyalty))
		expectedCoinRoyalty := bidAmountNanos / 5
		require.Equal(int64(40), int64(expectedCoinRoyalty))
		expectedM1CoinRoyalty := bidAmountNanos / 20
		require.Equal(int64(10), int64(expectedM1CoinRoyalty))
		expectedM2Royalty := bidAmountNanos / 100
		require.Equal(int64(2), int64(expectedM2Royalty))
		// Check creator's balance
		bidAmountMinusRoyalties := bidAmountNanos - expectedCoinRoyalty - expectedCreatorRoyalty - expectedM1CoinRoyalty - expectedM2Royalty
		require.Equal(m0BalBefore+expectedCreatorRoyalty, m0BalAfter)
		require.Equal(int64(1020), int64(m0BalAfter))
		// Check m2's balance - m2 is the buyer but also receives a royalty (and pays 2 nanos in fees for the bid)
		require.Equal(m2BalBefore+expectedM2Royalty-bidAmountNanos-2, m2BalAfter)
		require.Equal(int64(762), int64(m2BalAfter))
		// Make sure that the seller's balance decreased by the bid amount minus royalties.
		m3BalAfter := _getBalance(t, chain, nil, m3Pub)
		require.Equal(m3BalBefore+bidAmountMinusRoyalties, m3BalAfter)
		require.Equal(int64(1025), int64(m3BalAfter))

		// Check coin royalties
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
		require.Equal(m0DeSoLockedBefore+expectedCoinRoyalty, desoLocked)

		desoLockedM1, _ := _getCreatorCoinInfo(t, chain, params, m1Pub)
		require.Equal(m1DeSoLockedBefore+expectedM1CoinRoyalty, desoLockedM1)
	}

	// M2 puts it on sale and m0 buys it. test that creator buying it still works properly and
	// seller = additional DESO royalty works.
	{
		// m2 puts it on sale as buy now at 500 nanos
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post1Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			100,  /*MinBidAmountNanos*/
			true, /*IsBuyNow*/
			500,
		)

		// M0 bids 500 to buy the NFT outright.
		bidAmountNanos := uint64(500)
		// Creator/Bidder Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(int64(1020), int64(m0BalBefore))

		// Seller/m2 Balance before.
		m2BalBefore := _getBalance(t, chain, nil, m2Pub)
		require.Equal(int64(760), int64(m2BalBefore))

		// Creator's DESO locked before
		m0DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)

		// M1's DESO locked before
		m1DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m1Pub)

		// There are no bids before.
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// M0 buys this NFT for 500.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			1,              /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)

		bidEntries = DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// Check royalties. 10% for the creator, 20% for the coin, 5% to m1's coin, and 1% to m2's wallet
		m0BalAfter := _getBalance(t, chain, nil, m0Pub)
		m2BalAfter := _getBalance(t, chain, nil, m2Pub)

		// Creator royalty = 50, coin royalty = 100, m1's coin royalty = 25, m2's royalty = 5
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(int64(50), int64(expectedCreatorRoyalty))
		expectedCoinRoyalty := bidAmountNanos / 5
		require.Equal(int64(100), int64(expectedCoinRoyalty))
		expectedM1CoinRoyalty := bidAmountNanos / 20
		require.Equal(int64(25), int64(expectedM1CoinRoyalty))
		expectedM2Royalty := bidAmountNanos / 100
		require.Equal(int64(5), int64(expectedM2Royalty))
		// Check creator's balance
		bidAmountMinusRoyalties := bidAmountNanos - expectedCoinRoyalty - expectedCreatorRoyalty - expectedM1CoinRoyalty - expectedM2Royalty
		require.Equal(m0BalBefore+expectedCreatorRoyalty-bidAmountNanos-2, m0BalAfter)
		require.Equal(int64(568), int64(m0BalAfter))
		// Check m2's balance - m2 is the seller and also receives a royalty
		require.Equal(m2BalBefore+expectedM2Royalty+bidAmountMinusRoyalties, m2BalAfter)
		require.Equal(int64(1085), int64(m2BalAfter))

		// Check coin royalties
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
		require.Equal(m0DeSoLockedBefore+expectedCoinRoyalty, desoLocked)

		desoLockedM1, _ := _getCreatorCoinInfo(t, chain, params, m1Pub)
		require.Equal(m1DeSoLockedBefore+expectedM1CoinRoyalty, desoLockedM1)
	}

	// Create a new post for testing.
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

	// Create NFT with 10% royalty to creator, 20% to coin, 5% to m2's coin
	{
		// Balance before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(int64(567), int64(m0BalBeforeNFT))

		additionalCoinRoyaltyMap := make(map[PublicKey]uint64)
		additionalCoinRoyaltyMap[*NewPublicKey(m2PkBytes)] = 500

		_createNFTWithAdditionalRoyaltiesWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post2Hash,
			100,    /*NumCopies*/
			false,  /*HasUnlockable*/
			true,   /*IsForSale*/
			0,      /*MinBidAmountNanos*/
			0,      /*nftFee*/
			10*100, /*nftRoyaltyToCreatorBasisPoints*/
			20*100, /*nftRoyaltyToCoinBasisPoints*/
			true,   /*IsBuyNow*/
			100,
			nil,
			additionalCoinRoyaltyMap,
		)

		// Balance after. Since the default NFT fee is 0, m0 is only charged the nanos per kb fee.
		m0BalAfterNFT := _getBalance(t, testMeta.chain, nil, m0Pub)
		require.Equal(int64(565), int64(m0BalAfterNFT))
	}

	// Have m3 buy it "now"
	{
		// M3 bids 100 to buy the NFT outright.
		bidAmountNanos := uint64(100)
		// Creator Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(int64(565), int64(m0BalBefore))

		// Seller balance before
		m3BalBefore := _getBalance(t, chain, nil, m3Pub)
		require.Equal(int64(1025), int64(m3BalBefore))

		// Creator's DESO locked before
		m0DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)

		// M2's DESO locked before -- should be 0
		m2DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m2Pub)

		// There are no bids before.
		bidEntries := DBGetNFTBidEntries(db, post2Hash, 1)
		require.Equal(0, len(bidEntries))

		// M3 buys this NFT for 100.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m3Pub,
			m3Priv,
			post2Hash,
			1,              /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)

		// Check royalties. 10% for the creator, 20% for the coin, 5% to m2's coin
		m0BalAfter := _getBalance(t, chain, nil, m0Pub)
		m3BalAfter := _getBalance(t, chain, nil, m3Pub)

		// Creator royalty = 10, coin royalty = 20, m2's coin royalty = 5
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(int64(10), int64(expectedCreatorRoyalty))
		expectedCoinRoyalty := bidAmountNanos / 5
		require.Equal(int64(20), int64(expectedCoinRoyalty))
		expectedM2CoinRoyalty := bidAmountNanos / 20
		require.Equal(int64(5), int64(expectedM2CoinRoyalty))

		// Check creator's balance
		bidAmountMinusRoyalties := bidAmountNanos - expectedCoinRoyalty - expectedCreatorRoyalty - expectedM2CoinRoyalty
		require.Equal(m0BalBefore+expectedCreatorRoyalty+bidAmountMinusRoyalties, m0BalAfter)
		require.Equal(int64(640), int64(m0BalAfter))

		// Check bidder's balance
		require.Equal(m3BalBefore-bidAmountNanos-1, m3BalAfter)
		require.Equal(int64(924), int64(m3BalAfter))

		// Check coin royalties
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
		require.Equal(m0DeSoLockedBefore+expectedCoinRoyalty, desoLocked)

		// Because there is no DeSo locked in M2's coin, we don't add to their DESO locked.
		desoLockedM2, _ := _getCreatorCoinInfo(t, chain, params, m2Pub)
		require.Equal(m2DeSoLockedBefore, desoLockedM2)
	}

	// Have M2 buy some of their own coin so they can take advantage of the royalties
	{
		_creatorCoinTxnWithTestMeta(
			testMeta,
			10,     /*feeRateNanosPerKB*/
			m2Pub,  /*updaterPkBase58Check*/
			m2Priv, /*updaterPrivBase58Check*/
			m2Pub,  /*profilePubKeyBase58Check*/
			CreatorCoinOperationTypeBuy,
			29, /*DeSoToSellNanos*/
			0,  /*CreatorCoinToSellNanos*/
			0,  /*DeSoToAddNanos*/
			0,  /*MinDeSoExpectedNanos*/
			10, /*MinCreatorCoinExpectedNanos*/
		)

		m2Bal := _getBalance(t, testMeta.chain, nil, m2Pub)
		require.Equal(int64(1054), int64(m2Bal))
	}

	// Swap identity of m3 and m2.
	// m2 now owns the NFT that m3 had.
	// This will also cause m3's coin to wind up with m2's royalties.
	params.ParamUpdaterPublicKeys[MakePkMapKey(paramUpdaterPkBytes)] = true
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 100)
	_swapIdentityWithTestMeta(testMeta, 10, paramUpdaterPub, paramUpdaterPriv, m2PkBytes, m3PkBytes)

	// Now M2 (formerly m3) puts it on sale and m4 buys this NFT and watch M2 get some royalties
	{
		// m2 puts it on sale as buy now at 200 nanos
		_updateNFTWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m2Pub,
			m2Priv,
			post2Hash,
			1,    /*SerialNumber*/
			true, /*IsForSale*/
			100,  /*MinBidAmountNanos*/
			true, /*IsBuyNow*/
			200,
		)

		// M2 bids 200 to buy the NFT outright.
		bidAmountNanos := uint64(200)
		// Creator Balance before.
		m0BalBefore := _getBalance(t, chain, nil, m0Pub)
		require.Equal(int64(640), int64(m0BalBefore))

		// Seller Balance before.
		m2BalBefore := _getBalance(t, chain, nil, m2Pub)
		m3BalBefore := _getBalance(t, chain, nil, m3Pub)
		require.Equal(int64(1052), int64(m2BalBefore))
		require.Equal(int64(924), int64(m3BalBefore))

		// Bidder balance before
		m4BalBefore := _getBalance(t, chain, nil, m4Pub)
		require.Equal(int64(999), int64(m4BalBefore))

		// Creator's DESO locked before
		m0DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)

		// M2's DESO locked before
		m2DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m2Pub)
		m3DeSoLockedBefore, _ := _getCreatorCoinInfo(t, chain, params, m3Pub)

		// There are no bids before.
		bidEntries := DBGetNFTBidEntries(db, post1Hash, 1)
		require.Equal(0, len(bidEntries))

		// M4 buys this NFT for 100.
		_createNFTBidWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m4Pub,
			m4Priv,
			post2Hash,
			1,              /*SerialNumber*/
			bidAmountNanos, /*BidAmountNanos*/
		)

		// Check royalties. 10% for the creator, 20% for the coin, 5% to m2's coin
		m0BalAfter := _getBalance(t, chain, nil, m0Pub)
		m2BalAfter := _getBalance(t, chain, nil, m2Pub)
		m3BalAfter := _getBalance(t, chain, nil, m3Pub)
		m4BalAfter := _getBalance(t, chain, nil, m4Pub)

		// Creator royalty = 20, coin royalty = 40, m2's coin royalty = 10
		expectedCreatorRoyalty := bidAmountNanos / 10
		require.Equal(int64(20), int64(expectedCreatorRoyalty))
		expectedCoinRoyalty := bidAmountNanos / 5
		require.Equal(int64(40), int64(expectedCoinRoyalty))
		expectedM2CoinRoyalty := bidAmountNanos / 20
		require.Equal(int64(10), int64(expectedM2CoinRoyalty))

		// Check creator's balance
		bidAmountMinusRoyalties := bidAmountNanos - expectedCoinRoyalty - expectedCreatorRoyalty - expectedM2CoinRoyalty
		require.Equal(m0BalBefore+expectedCreatorRoyalty, m0BalAfter)
		require.Equal(int64(660), int64(m0BalAfter))

		// Check seller's balance
		require.Equal(m2BalBefore+bidAmountMinusRoyalties, m2BalAfter)
		require.Equal(int64(1182), int64(m2BalAfter))

		require.Equal(m3BalBefore, m3BalAfter)
		require.Equal(int64(924), int64(m3BalAfter))

		// Check bidder's balance
		require.Equal(m4BalBefore-bidAmountNanos-1, m4BalAfter)
		require.Equal(int64(798), int64(m4BalAfter))

		// Check coin royalties
		desoLocked, _ := _getCreatorCoinInfo(t, chain, params, m0Pub)
		require.Equal(m0DeSoLockedBefore+expectedCoinRoyalty, desoLocked)

		desoLockedM2, _ := _getCreatorCoinInfo(t, chain, params, m2Pub)
		require.Equal(m2DeSoLockedBefore, desoLockedM2)

		// Now that there is DESO locked in M2's coin, we can add the royalties to their coin
		desoLockedM3, _ := _getCreatorCoinInfo(t, chain, params, m3Pub)
		require.Equal(m3DeSoLockedBefore+expectedM2CoinRoyalty, desoLockedM3)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestNFTSplitsSerializers(t *testing.T) {
	require := require.New(t)

	mm := make(map[PublicKey]uint64)
	mm[*NewPublicKey(m0PkBytes)] = 123456
	mm[*NewPublicKey(m1PkBytes)] = 7890123
	mm[*NewPublicKey(m2PkBytes)] = 34834983
	bb, err := SerializePubKeyToUint64Map(mm)
	require.NoError(err)

	newMM, err := DeserializePubKeyToUint64Map(bb)
	require.NoError(err)

	require.Equal(mm, newMM)
}

// Set up this test to catch a very hardcore pkid/pubkey bug that only
// showed up in prod.
func TestNFTSplitsHardcorePKIDBug(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3, m4 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true
	params.ParamUpdaterPublicKeys[MakePkMapKey(m4PkBytes)] = true
	params.ForkHeights.BuyNowAndNFTSplitsBlockHeight = uint32(0)
	params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)

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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 10000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 10000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 10000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 10000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 10000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m5Pub, senderPrivString, 10000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m6Pub, senderPrivString, 10000)

	//m4PKID := DBGetPKIDEntryForPublicKey(db, m4PkBytes)
	//m5PKID := DBGetPKIDEntryForPublicKey(db, m5PkBytes)
	//m6PKID := DBGetPKIDEntryForPublicKey(db, m6PkBytes)

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

	_ = post1Hash
	// NFT the post.
	{
		// Create a profile for m0, m1, m2, m3, m4
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
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m1",          /*newUsername*/
			"i am the m1", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)

		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m2Pub,         /*updaterPkBase58Check*/
			m2Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m3Pub,         /*updaterPkBase58Check*/
			m3Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m3",          /*newUsername*/
			"i am the m3", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
		_updateProfileWithTestMeta(
			testMeta,
			10,            /*feeRateNanosPerKB*/
			m4Pub,         /*updaterPkBase58Check*/
			m4Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m4",          /*newUsername*/
			"i am the m4", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Make a really, really complicated NFT
	{
		// DESO royalties
		additionalDESORoyaltyMap := make(map[PublicKey]uint64)
		additionalDESORoyaltyMap[*NewPublicKey(m1PkBytes)] = 200
		additionalDESORoyaltyMap[*NewPublicKey(m2PkBytes)] = 300
		additionalDESORoyaltyMap[*NewPublicKey(m3PkBytes)] = 300
		additionalDESORoyaltyMap[*NewPublicKey(m4PkBytes)] = 400
		additionalDESORoyaltyMap[*NewPublicKey(m5PkBytes)] = 500

		// Creator royalties
		additionalCoinRoyaltyMap := make(map[PublicKey]uint64)
		additionalDESORoyaltyMap[*NewPublicKey(m1PkBytes)] = 200
		additionalDESORoyaltyMap[*NewPublicKey(m3PkBytes)] = 300
		additionalDESORoyaltyMap[*NewPublicKey(m4PkBytes)] = 300
		additionalDESORoyaltyMap[*NewPublicKey(m6PkBytes)] = 500

		_createNFTWithAdditionalRoyaltiesWithTestMeta(
			testMeta,
			10, /*FeeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			post1Hash,
			100,    /*NumCopies*/
			false,  /*HasUnlockable*/
			true,   /*IsForSale*/
			0,      /*MinBidAmountNanos*/
			0,      /*nftFee*/
			10*100, /*nftRoyaltyToCreatorBasisPoints*/
			20*100, /*nftRoyaltyToCoinBasisPoints*/
			false,  /*IsBuyNow*/
			0,
			additionalDESORoyaltyMap,
			additionalCoinRoyaltyMap,
		)
	}

	// Now do a bunch of buy and sell operations
	{
		serialNum := uint64(1)
		bidAmountNanos := uint64(100)
		// M1 bids for it and m0 accepts the bid
		_createNFTBidWithTestMeta(testMeta,
			10,
			m1Pub,
			m1Priv,
			post1Hash,
			serialNum,
			bidAmountNanos,
		)

		// M0 accepts this
		_acceptNFTBidWithTestMeta(testMeta,
			10,
			m0Pub,
			m0Priv,
			post1Hash,
			1,
			m1Pub,
			bidAmountNanos,
			"",
		)
	}

	// M1 puts it on sale as a buy now NFT
	{
		_updateNFTWithTestMeta(testMeta,
			10,
			m1Pub,
			m1Priv,
			post1Hash,
			1,
			true,
			0,
			true,
			100,
		)
	}

	// M2 buys it
	{
		_createNFTBidWithTestMeta(testMeta,
			10,
			m2Pub,
			m2Priv,
			post1Hash,
			1,
			100)
	}

	// M2 puts it on sale in an auction style
	{
		_updateNFTWithTestMeta(testMeta,
			10,
			m2Pub,
			m2Priv,
			post1Hash,
			1,
			true,
			100,
			false,
			0,
		)
	}

	// M0 and M3 bid on it
	{
		_createNFTBidWithTestMeta(testMeta,
			10,
			m0Pub,
			m0Priv,
			post1Hash,
			1,
			200,
		)

		_createNFTBidWithTestMeta(testMeta,
			10,
			m3Pub,
			m3Priv,
			post1Hash,
			1,
			250,
		)
	}

	// M2 accepts M3's bid
	{
		_acceptNFTBidWithTestMeta(testMeta,
			10,
			m2Pub,
			m2Priv,
			post1Hash,
			1,
			m3Pub,
			250,
			"",
		)
	}

	// M3 puts it on sale as a buy now NFT
	{
		_updateNFTWithTestMeta(testMeta,
			10,
			m3Pub,
			m3Priv,
			post1Hash,
			1,
			true,
			0,
			true,
			200,
		)
	}

	// M0 buys their NFT back
	{
		_createNFTBidWithTestMeta(testMeta,
			10,
			m0Pub,
			m0Priv,
			post1Hash,
			1,
			200,
		)
	}

	// M0 puts it on sale again
	{
		_updateNFTWithTestMeta(testMeta,
			10,
			m0Pub,
			m0Priv,
			post1Hash,
			1,
			true,
			10,
			true,
			200,
		)
	}

	// M3 buys it back again
	{
		_createNFTBidWithTestMeta(testMeta,
			10,
			m3Pub,
			m3Priv,
			post1Hash,
			1,
			200,
		)
	}

	// M3 puts it on sale and m2 buys it this time
	{
		_updateNFTWithTestMeta(testMeta,
			10,
			m3Pub,
			m3Priv,
			post1Hash,
			1,
			true,
			0,
			true,
			150,
		)

		_createNFTBidWithTestMeta(testMeta,
			10,
			m2Pub,
			m2Priv,
			post1Hash,
			1,
			150,
		)
	}

	// M2 transfers it to M1 and m1 Accepts
	{
		_transferNFTWithTestMeta(testMeta,
			10,
			m2Pub,
			m2Priv,
			m1Pub,
			post1Hash,
			1,
			"",
		)

		_acceptNFTTransferWithTestMeta(testMeta,
			10,
			m1Pub,
			m1Priv,
			post1Hash,
			1,
		)
	}

	// M1 puts it on sale as an auction
	{
		_updateNFTWithTestMeta(testMeta,
			10,
			m1Pub,
			m1Priv,
			post1Hash,
			1,
			true,
			100,
			false,
			0,
		)
	}

	// M4, M5, and M6 submit bids
	{
		_createNFTBidWithTestMeta(testMeta,
			10,
			m4Pub,
			m4Priv,
			post1Hash,
			1,
			100,
		)

		_createNFTBidWithTestMeta(testMeta,
			10,
			m5Pub,
			m5Priv,
			post1Hash,
			1,
			120,
		)

		_createNFTBidWithTestMeta(testMeta,
			10,
			m6Pub,
			m6Priv,
			post1Hash,
			1,
			110,
		)
	}

	// M1 accepts M5's bid
	{
		_acceptNFTBidWithTestMeta(testMeta,
			10,
			m1Pub,
			m1Priv,
			post1Hash,
			1,
			m5Pub,
			120,
			"",
		)
	}

	// M5 puts it on sale as a buy now NFT and M4 buys it
	{
		_updateNFTWithTestMeta(testMeta,
			10,
			m5Pub,
			m5Priv,
			post1Hash,
			1,
			true,
			0,
			true,
			100,
		)

		_createNFTBidWithTestMeta(testMeta,
			10,
			m4Pub,
			m4Priv,
			post1Hash,
			1,
			100,
		)
	}

	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}
