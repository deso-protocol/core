package lib

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
	"time"
)

const (
	BasicTransferRecipient = "RECIPIENT"
	BasicTransferAmount    = "AMOUNT"
)

type AuthorizeDerivedKeyTestData struct {
	userPrivateKey           string
	userPublicKey            []byte
	expectedConnectError     error
	transactionSpendingLimit TransactionSpendingLimit
	memo                     []byte
	derivedKeySignature      bool
	derivedPrivateKey        *btcec.PrivateKey
	operationType            AuthorizeDerivedKeyOperationType
	expirationBlock          uint64
	extraData                map[string][]byte
}

func (data *AuthorizeDerivedKeyTestData) IsDependency(other transactionTestInputSpace) bool {
	return false
}

func (data *AuthorizeDerivedKeyTestData) GetInputType() transactionTestInputType {
	return transactionTestInputTypeDerivedKey
}

// We create this inline function for attempting a basic transfer.
// This helps us test that the DeSoChain recognizes a derived key.
func _derivedKeyBasicTransfer(t *testing.T, db *badger.DB, chain *Blockchain, params *DeSoParams,
	senderPk []byte, recipientPk []byte, signerPriv string, utxoView *UtxoView,
	mempool *DeSoMempool, isSignerSender bool) ([]*UtxoOperation, *MsgDeSoTxn, error) {

	require := require.New(t)
	_ = require

	txn := &MsgDeSoTxn{
		// The inputs will be set below.
		TxInputs: []*DeSoInput{},
		TxOutputs: []*DeSoOutput{
			{
				PublicKey:   recipientPk,
				AmountNanos: 1,
			},
		},
		PublicKey: senderPk,
		TxnMeta:   &BasicTransferMetadata{},
		ExtraData: make(map[string][]byte),
	}

	totalInput, spendAmount, changeAmount, fees, err :=
		chain.AddInputsAndChangeToTransaction(txn, 10, mempool)
	require.NoError(err)
	require.Equal(totalInput, spendAmount+changeAmount+fees)
	require.Greater(totalInput, uint64(0))

	if isSignerSender {
		// Sign the transaction with the provided derived key
		_signTxn(t, txn, signerPriv)
	} else {
		// Sign the transaction with the provided derived key
		_signTxnWithDerivedKey(t, txn, signerPriv)
	}

	// Get utxoView if it doesn't exist
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUniversalView()
		require.NoError(err)
	}
	if utxoView == nil {
		utxoView, err = NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
	}

	txHash := txn.Hash()
	blockHeight := chain.blockTip().Height + 1
	utxoOps, _, _, _, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
			true /*verifySignature*/, false /*ignoreUtxos*/)
	return utxoOps, txn, err
}

// Verify that the balance and expiration block in the db match expectation.
func _derivedKeyVerifyTest(t *testing.T, db *badger.DB, chain *Blockchain, transactionSpendingLimit *TransactionSpendingLimit,
	derivedPublicKey []byte, expirationBlockExpected uint64, balanceExpected uint64,
	operationTypeExpected AuthorizeDerivedKeyOperationType, mempool *DeSoMempool) {

	require := require.New(t)
	_ = require

	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)

	// Verify that expiration block was persisted in the db or is in mempool utxoView
	var derivedKeyEntry *DerivedKeyEntry
	if mempool == nil {
		derivedKeyEntry = chain.NewDbAdapter().GetOwnerToDerivedKeyMapping(*NewPublicKey(senderPkBytes), *NewPublicKey(derivedPublicKey))
	} else {
		utxoView, err := mempool.GetAugmentedUniversalView()
		require.NoError(err)
		derivedKeyEntry = utxoView.GetDerivedKeyMappingForOwner(senderPkBytes, derivedPublicKey)
	}
	// If we removed the derivedKeyEntry from utxoView altogether, it'll be nil.
	// To pass the tests, we initialize it to a default struct.
	if derivedKeyEntry == nil || derivedKeyEntry.isDeleted {
		derivedKeyEntry = &DerivedKeyEntry{*NewPublicKey(senderPkBytes), *NewPublicKey(derivedPublicKey), 0, AuthorizeDerivedKeyOperationValid, nil, transactionSpendingLimit, nil, false}
	}
	require.Equal(derivedKeyEntry.ExpirationBlock, expirationBlockExpected)
	require.Equal(derivedKeyEntry.OperationType, operationTypeExpected)

	// Verify that the balance of recipient is equal to expected balance
	require.Equal(_getBalance(t, chain, mempool, recipientPkString), balanceExpected)
}

func _doTxn(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	TransactorPublicKeyBase58Check string,
	TransactorPrivKeyBase58Check string,
	isDerivedTransactor bool,
	txnType TxnType,
	txnMeta DeSoTxnMetadata,
	extraData map[string]interface{},
	blockHeight uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	return _doTxnWithBlockHeight(
		testMeta,
		feeRateNanosPerKB,
		TransactorPublicKeyBase58Check,
		TransactorPrivKeyBase58Check,
		isDerivedTransactor,
		txnType,
		txnMeta,
		extraData,
		blockHeight,
	)
}

func _doTxnWithBlockHeight(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	TransactorPublicKeyBase58Check string,
	TransactorPrivKeyBase58Check string,
	isDerivedTransactor bool,
	txnType TxnType,
	txnMeta DeSoTxnMetadata,
	extraData map[string]interface{},
	encoderBlockHeight uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	assert := assert.New(testMeta.t)
	require := require.New(testMeta.t)
	_ = assert
	_ = require

	transactorPublicKey, _, err := Base58CheckDecode(TransactorPublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(err)
	chain := testMeta.chain

	var txn *MsgDeSoTxn
	var totalInputMake uint64
	var changeAmountMake uint64
	var feesMake uint64
	var operationType OperationType
	var isBuyNowBid bool
	switch txnType {
	case TxnTypeCreatorCoin:
		realTxMeta := txnMeta.(*CreatorCoinMetadataa)
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateCreatorCoinTxn(
			transactorPublicKey,
			realTxMeta.ProfilePublicKey,
			realTxMeta.OperationType,
			realTxMeta.DeSoToSellNanos,
			realTxMeta.CreatorCoinToSellNanos,
			realTxMeta.DeSoToAddNanos,
			realTxMeta.MinDeSoExpectedNanos,
			realTxMeta.MinCreatorCoinExpectedNanos,
			feeRateNanosPerKB,
			nil,
			nil)
		require.NoError(err)
		operationType = OperationTypeCreatorCoin
	case TxnTypeCreatorCoinTransfer:
		realTxMeta := txnMeta.(*CreatorCoinTransferMetadataa)
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateCreatorCoinTransferTxn(
			transactorPublicKey,
			realTxMeta.ProfilePublicKey,
			realTxMeta.CreatorCoinToTransferNanos,
			realTxMeta.ReceiverPublicKey,
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeCreatorCoinTransfer
	case TxnTypeDAOCoin:
		realTxMeta := txnMeta.(*DAOCoinMetadata)
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateDAOCoinTxn(
			transactorPublicKey,
			realTxMeta,
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeDAOCoin
	case TxnTypeDAOCoinTransfer:
		realTxMeta := txnMeta.(*DAOCoinTransferMetadata)
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateDAOCoinTransferTxn(
			transactorPublicKey,
			realTxMeta,
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeDAOCoinTransfer
	case TxnTypeUpdateNFT:
		realTxMeta := txnMeta.(*UpdateNFTMetadata)
		var isBuyNow bool
		var buyNowPriceNanos uint64
		if buyNowVal, buyNowValExists := extraData[BuyNowPriceKey]; buyNowValExists {
			buyNowPriceNanos = buyNowVal.(uint64)
			isBuyNow = true
		}
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateUpdateNFTTxn(
			transactorPublicKey,
			realTxMeta.NFTPostHash,
			realTxMeta.SerialNumber,
			realTxMeta.IsForSale,
			realTxMeta.MinBidAmountNanos,
			isBuyNow,
			buyNowPriceNanos,
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeUpdateNFT
	case TxnTypeCreateNFT:
		realTxMeta := txnMeta.(*CreateNFTMetadata)
		var isBuyNow bool
		var buyNowPriceNanos uint64
		if buyNowVal, buyNowValExists := extraData[BuyNowPriceKey]; buyNowValExists {
			buyNowPriceNanos = buyNowVal.(uint64)
			isBuyNow = true
		}
		var additionalDESORoyaltyMap map[PublicKey]uint64
		if additionalDESORoyaltyMapVal, additionalDESORoyaltyMapValExists :=
			extraData[DESORoyaltiesMapKey]; additionalDESORoyaltyMapValExists {
			additionalDESORoyaltyMap = additionalDESORoyaltyMapVal.(map[PublicKey]uint64)
		}
		var additionalCoinRoyaltyMap map[PublicKey]uint64
		if additionalCoinRoyaltyMapVal, additionalCoinRoyaltyMapValExists :=
			extraData[CoinRoyaltiesMapKey]; additionalCoinRoyaltyMapValExists {
			additionalCoinRoyaltyMap = additionalCoinRoyaltyMapVal.(map[PublicKey]uint64)
		}
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateCreateNFTTxn(
			transactorPublicKey,
			realTxMeta.NFTPostHash,
			realTxMeta.NumCopies,
			realTxMeta.HasUnlockable,
			realTxMeta.IsForSale,
			realTxMeta.MinBidAmountNanos,
			utxoView.GlobalParamsEntry.CreateNFTFeeNanos*uint64(realTxMeta.NumCopies),
			realTxMeta.NFTRoyaltyToCreatorBasisPoints,
			realTxMeta.NFTRoyaltyToCoinBasisPoints,
			isBuyNow,
			buyNowPriceNanos,
			additionalDESORoyaltyMap,
			additionalCoinRoyaltyMap,
			nil,
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeCreateNFT
	case TxnTypeAcceptNFTBid:
		realTxMeta := txnMeta.(*AcceptNFTBidMetadata)
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateAcceptNFTBidTxn(
			transactorPublicKey,
			realTxMeta.NFTPostHash,
			realTxMeta.SerialNumber,
			realTxMeta.BidderPKID,
			realTxMeta.BidAmountNanos,
			realTxMeta.UnlockableText,
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeAcceptNFTBid
	case TxnTypeAcceptNFTTransfer:
		realTxMeta := txnMeta.(*AcceptNFTTransferMetadata)
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateAcceptNFTTransferTxn(
			transactorPublicKey,
			realTxMeta.NFTPostHash,
			realTxMeta.SerialNumber,
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeAcceptNFTTransfer
	case TxnTypeNFTBid:
		realTxMeta := txnMeta.(*NFTBidMetadata)
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateNFTBidTxn(
			transactorPublicKey,
			realTxMeta.NFTPostHash,
			realTxMeta.SerialNumber,
			realTxMeta.BidAmountNanos,
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeNFTBid
		nftKey := MakeNFTKey(realTxMeta.NFTPostHash, realTxMeta.SerialNumber)
		nftEntry := utxoView.GetNFTEntryForNFTKey(&nftKey)
		if nftEntry != nil && nftEntry.IsBuyNow && nftEntry.BuyNowPriceNanos <= realTxMeta.BidAmountNanos {
			isBuyNowBid = true
		}
	case TxnTypeNFTTransfer:
		realTxMeta := txnMeta.(*NFTTransferMetadata)
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateNFTTransferTxn(
			transactorPublicKey,
			realTxMeta.ReceiverPublicKey,
			realTxMeta.NFTPostHash,
			realTxMeta.SerialNumber,
			realTxMeta.UnlockableText,
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeNFTTransfer
	case TxnTypeBurnNFT:
		realTxMeta := txnMeta.(*BurnNFTMetadata)
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateBurnNFTTxn(
			transactorPublicKey,
			realTxMeta.NFTPostHash,
			realTxMeta.SerialNumber,
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeBurnNFT
	case TxnTypeAuthorizeDerivedKey:
		realTxMeta := txnMeta.(*AuthorizeDerivedKeyMetadata)
		var memo []byte
		if memoInterface, memoInterfaceExists := extraData[DerivedKeyMemoKey]; memoInterfaceExists {
			memo = memoInterface.([]byte)
		}
		var transactionSpendingLimit *TransactionSpendingLimit
		if tslInterface, tslInterfaceExists := extraData[TransactionSpendingLimitKey]; tslInterfaceExists {
			transactionSpendingLimit = tslInterface.(*TransactionSpendingLimit)
		}
		var deleteKey bool
		if realTxMeta.OperationType == AuthorizeDerivedKeyOperationNotValid {
			deleteKey = true
		}
		transactionSpendingLimitBytes, err := transactionSpendingLimit.ToBytes(encoderBlockHeight)
		require.NoError(err)
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateAuthorizeDerivedKeyTxn(
			transactorPublicKey,
			realTxMeta.DerivedPublicKey,
			realTxMeta.ExpirationBlock,
			realTxMeta.AccessSignature,
			deleteKey,
			false,
			nil,
			memo,
			hex.EncodeToString(transactionSpendingLimitBytes),
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeAuthorizeDerivedKey
	case TxnTypeUpdateProfile:
		realTxMeta := txnMeta.(*UpdateProfileMetadata)
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateUpdateProfileTxn(
			transactorPublicKey,
			realTxMeta.ProfilePublicKey,
			string(realTxMeta.NewUsername),
			string(realTxMeta.NewDescription),
			string(realTxMeta.NewProfilePic),
			realTxMeta.NewCreatorBasisPoints,
			realTxMeta.NewStakeMultipleBasisPoints,
			realTxMeta.IsHidden,
			0,
			nil,
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeUpdateProfile
	case TxnTypeSubmitPost:
		realTxMeta := txnMeta.(*SubmitPostMetadata)
		// TODO: fix to support reposts / quoted reposts / extra data
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateSubmitPostTxn(
			transactorPublicKey,
			realTxMeta.PostHashToModify,
			realTxMeta.ParentStakeID,
			realTxMeta.Body,
			nil,
			false,
			realTxMeta.TimestampNanos,
			nil,
			realTxMeta.IsHidden,
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeSubmitPost
	case TxnTypeUpdateGlobalParams:
		getGlobalParamValFromExtraData := func(key string) int64 {
			if val, exists := extraData[key]; exists {
				return val.(int64)
			}
			return int64(-1)
		}
		usdCentsPerBitcoin := getGlobalParamValFromExtraData(USDCentsPerBitcoinKey)
		createProfileFeeNanos := getGlobalParamValFromExtraData(CreateProfileFeeNanosKey)
		createNFTFeeNanos := getGlobalParamValFromExtraData(CreateNFTFeeNanosKey)
		maxCopiesPerNFT := getGlobalParamValFromExtraData(MaxCopiesPerNFTKey)
		minNetworkFeeNanosPerKB := getGlobalParamValFromExtraData(MinNetworkFeeNanosPerKBKey)
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateUpdateGlobalParamsTxn(
			transactorPublicKey,
			usdCentsPerBitcoin,
			createProfileFeeNanos,
			createNFTFeeNanos,
			maxCopiesPerNFT,
			minNetworkFeeNanosPerKB,
			nil,
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeUpdateGlobalParams
	case TxnTypeBasicTransfer:

		recipientPublicKey := extraData[BasicTransferRecipient].([]byte)
		amountNanos := extraData[BasicTransferAmount].(uint64)

		// Assemble the transaction so that inputs can be found and fees can
		// be computed.
		txn = &MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs: []*DeSoInput{},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   recipientPublicKey,
					AmountNanos: amountNanos,
				},
			},
			PublicKey: transactorPublicKey,
			TxnMeta:   &BasicTransferMetadata{},
			// We wait to compute the signature until we've added all the
			// inputs and change.
		}

		// Add inputs to the transaction and do signing, validation, and broadcast
		// depending on what the user requested.
		totalInputMake, _, changeAmountMake, feesMake, err = chain.AddInputsAndChangeToTransaction(
			txn, feeRateNanosPerKB, nil)
		require.NoError(err)
		operationType = OperationTypeSpendUtxo
	case TxnTypeDAOCoinLimitOrder:
		realTxMeta := txnMeta.(*DAOCoinLimitOrderMetadata)
		txn, totalInputMake, changeAmountMake, feesMake, err = chain.CreateDAOCoinLimitOrderTxn(
			transactorPublicKey,
			realTxMeta,
			feeRateNanosPerKB,
			nil,
			nil,
		)
		require.NoError(err)
		operationType = OperationTypeDAOCoinLimitOrder
	default:
		return nil, nil, 0, fmt.Errorf("Unsupported Txn Type")
	}
	_, _ = feesMake, changeAmountMake
	if err != nil {
		return nil, nil, 0, err
	}
	if isDerivedTransactor {
		_signTxnWithDerivedKey(testMeta.t, txn, TransactorPrivKeyBase58Check)
	} else {
		_signTxn(testMeta.t, txn, TransactorPrivKeyBase58Check)
	}

	txHash := txn.Hash()
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one operation that corresponds to the txn type at the end.
	// TODO: generalize?
	utxoOpExpectation := len(txn.TxInputs) + len(txn.TxOutputs) + 1
	if isDerivedTransactor && blockHeight >= testMeta.params.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight {
		// If we got an unlimited derived key, we will not have an additional spending limit utxoop.
		// ====== Access Group Fork ======
		// We will only have utxoop expectation if spending limit contains CC, DAO, or NFT spending limits.
		transactorPrivBytes, _, err := Base58CheckDecode(TransactorPrivKeyBase58Check)
		_, transactorPub := btcec.PrivKeyFromBytes(btcec.S256(), transactorPrivBytes)
		transactorPubBytes := transactorPub.SerializeCompressed()
		require.NoError(err)
		if !utxoView.GetDerivedKeyMappingForOwner(txn.PublicKey, transactorPubBytes).TransactionSpendingLimitTracker.IsUnlimited {
			utxoOpExpectation++
		}
	}
	if txnType == TxnTypeBasicTransfer {
		utxoOpExpectation--
	}
	// We add one op to account for NFT bids on buy now NFT.
	if isBuyNowBid {
		utxoOpExpectation++
	}
	require.Equal(utxoOpExpectation, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	if txnType != TxnTypeBasicTransfer {
		require.Equal(operationType, utxoOps[len(utxoOps)-1].Type)
	}

	require.NoError(utxoView.FlushToDb(encoderBlockHeight))

	return utxoOps, txn, blockHeight, nil
}

func _doTxnWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	TransactorPublicKeyBase58Check string,
	TransactorPrivateKeyBase58Check string,
	IsDerivedTransactor bool,
	TxnType TxnType,
	TxnMeta DeSoTxnMetadata,
	ExtraData map[string]interface{},
	encoderBlockHeight uint64) {

	_doTxnWithTestMetaWithBlockHeight(
		testMeta,
		feeRateNanosPerKB,
		TransactorPublicKeyBase58Check,
		TransactorPrivateKeyBase58Check,
		IsDerivedTransactor,
		TxnType,
		TxnMeta,
		ExtraData,
		encoderBlockHeight,
	)
}

func _doTxnWithTestMetaWithBlockHeight(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	TransactorPublicKeyBase58Check string,
	TransactorPrivateKeyBase58Check string,
	IsDerivedTransactor bool,
	TxnType TxnType,
	TxnMeta DeSoTxnMetadata,
	ExtraData map[string]interface{},
	encoderBlockHeight uint64) {
	testMeta.expectedSenderBalances = append(testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, TransactorPublicKeyBase58Check))

	currentOps, currentTxn, _, err := _doTxnWithBlockHeight(testMeta,
		feeRateNanosPerKB, TransactorPublicKeyBase58Check, TransactorPrivateKeyBase58Check, IsDerivedTransactor,
		TxnType, TxnMeta, ExtraData, encoderBlockHeight)
	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _doTxnWithTextMetaWithBlockHeightWithError(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	TransactorPublicKeyBase58Check string,
	TransactorPrivateKeyBase58Check string,
	IsDerivedTransactor bool,
	TxnType TxnType,
	TxnMeta DeSoTxnMetadata,
	ExtraData map[string]interface{},
	encoderBlockHeight uint64) error {

	initialBalance := _getBalance(testMeta.t, testMeta.chain, nil, TransactorPublicKeyBase58Check)

	currentOps, currentTxn, _, err := _doTxnWithBlockHeight(testMeta,
		feeRateNanosPerKB, TransactorPublicKeyBase58Check, TransactorPrivateKeyBase58Check, IsDerivedTransactor,
		TxnType, TxnMeta, ExtraData, encoderBlockHeight)
	if err != nil {
		return err
	}

	testMeta.expectedSenderBalances = append(testMeta.expectedSenderBalances, initialBalance)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
	return nil
}

func _getAuthorizeDerivedKeyMetadata(
	t *testing.T,
	ownerPrivateKey *btcec.PrivateKey,
	expirationBlock uint64,
	isDeleted bool) (*AuthorizeDerivedKeyMetadata, *btcec.PrivateKey) {
	require := require.New(t)

	// Generate a random derived key pair
	derivedPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err, "_getAuthorizeDerivedKeyMetadata: Error generating a derived key pair")
	derivedPublicKey := derivedPrivateKey.PubKey().SerializeCompressed()

	// Create access signature
	expirationBlockByte := EncodeUint64(expirationBlock)
	accessBytes := append(derivedPublicKey, expirationBlockByte[:]...)
	accessSignature, err := ownerPrivateKey.Sign(Sha256DoubleHash(accessBytes)[:])
	require.NoError(err, "_getAuthorizeDerivedKeyMetadata: Error creating access signature")

	// Determine operation type
	var operationType AuthorizeDerivedKeyOperationType
	if isDeleted {
		operationType = AuthorizeDerivedKeyOperationNotValid
	} else {
		operationType = AuthorizeDerivedKeyOperationValid
	}

	return &AuthorizeDerivedKeyMetadata{
		derivedPublicKey,
		expirationBlock,
		operationType,
		accessSignature.Serialize(),
	}, derivedPrivateKey
}

func _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(
	t *testing.T,
	ownerPrivateKey *btcec.PrivateKey,
	expirationBlock uint64,
	transactionSpendingLimit *TransactionSpendingLimit,
	isDeleted bool,
	blockHeight uint64) (*AuthorizeDerivedKeyMetadata, *btcec.PrivateKey) {
	require := require.New(t)

	// Generate a random derived key pair
	derivedPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err, "_getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit: Error generating a derived key pair")
	derivedPublicKey := derivedPrivateKey.PubKey().SerializeCompressed()

	// Determine operation type
	var operationType AuthorizeDerivedKeyOperationType
	if isDeleted {
		operationType = AuthorizeDerivedKeyOperationNotValid
	} else {
		operationType = AuthorizeDerivedKeyOperationValid
	}

	// We randomly use standard or the metamask derived key access signature.
	var accessBytes []byte
	accessBytesEncodingType := rand.Int() % 2
	if accessBytesEncodingType == 0 {
		// Create access signature
		expirationBlockByte := EncodeUint64(expirationBlock)
		accessBytes = append(derivedPublicKey, expirationBlockByte[:]...)

		var transactionSpendingLimitBytes []byte
		transactionSpendingLimitBytes, err = transactionSpendingLimit.ToBytes(blockHeight)
		require.NoError(err, "_getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit: Error in transaction spending limit to bytes")
		accessBytes = append(accessBytes, transactionSpendingLimitBytes[:]...)
	} else {
		accessBytes = AssembleAccessBytesWithMetamaskStrings(derivedPublicKey, expirationBlock,
			transactionSpendingLimit, &DeSoTestnetParams)
	}
	signature, err := ownerPrivateKey.Sign(Sha256DoubleHash(accessBytes)[:])
	accessSignature := signature.Serialize()
	require.NoError(err, "_getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit: Error creating access signature")

	return &AuthorizeDerivedKeyMetadata{
		derivedPublicKey,
		expirationBlock,
		operationType,
		accessSignature,
	}, derivedPrivateKey
}

func _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
	t *testing.T,
	ownerPrivateKey *btcec.PrivateKey,
	expirationBlock uint64,
	transactionSpendingLimit *TransactionSpendingLimit,
	derivedPrivateKey *btcec.PrivateKey,
	isDeleted bool,
	blockHeight uint64) (*AuthorizeDerivedKeyMetadata, *btcec.PrivateKey) {
	require := require.New(t)

	derivedPublicKey := derivedPrivateKey.PubKey().SerializeCompressed()

	// Create access signature
	expirationBlockByte := EncodeUint64(expirationBlock)
	accessBytes := append(derivedPublicKey, expirationBlockByte[:]...)

	transactionSpendingLimitBytes, err := transactionSpendingLimit.ToBytes(blockHeight)
	require.NoError(err, "_getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit: Error in transaction spending limit to bytes")
	accessBytes = append(accessBytes, transactionSpendingLimitBytes[:]...)

	accessSignature, err := ownerPrivateKey.Sign(Sha256DoubleHash(accessBytes)[:])
	require.NoError(err, "_getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit: Error creating access signature")

	// Determine operation type
	var operationType AuthorizeDerivedKeyOperationType
	if isDeleted {
		operationType = AuthorizeDerivedKeyOperationNotValid
	} else {
		operationType = AuthorizeDerivedKeyOperationValid
	}

	return &AuthorizeDerivedKeyMetadata{
		derivedPublicKey,
		expirationBlock,
		operationType,
		accessSignature.Serialize(),
	}, derivedPrivateKey
}

func _getAccessSignature(
	derivedPublicKey []byte,
	expirationBlock uint64,
	transactionSpendingLimit *TransactionSpendingLimit,
	ownerPrivateKey *btcec.PrivateKey,
	blockHeight uint64) ([]byte, error) {
	accessBytes := append(derivedPublicKey, EncodeUint64(expirationBlock)...)
	transactionSpendingLimitBytes, err := transactionSpendingLimit.ToBytes(blockHeight)
	if err != nil {
		return nil, err
	}
	accessBytes = append(accessBytes, transactionSpendingLimitBytes...)
	accessSignature, err := ownerPrivateKey.Sign(Sha256DoubleHash(accessBytes)[:])
	if err != nil {
		return nil, err
	}
	return accessSignature.Serialize(), nil
}

func _doAuthorizeTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, utxoView *UtxoView, feeRateNanosPerKB uint64, ownerPublicKey []byte,
	derivedPublicKey []byte, derivedPrivBase58Check string, expirationBlock uint64,
	accessSignature []byte, deleteKey bool,
	memo []byte, transactionSpendingLimit *TransactionSpendingLimit) (_utxoOps []*UtxoOperation,
	_txn *MsgDeSoTxn, _height uint32, _err error) {
	return _doAuthorizeTxnWithExtraDataAndSpendingLimits(t, chain, db, params, utxoView, feeRateNanosPerKB, ownerPublicKey,
		derivedPublicKey, derivedPrivBase58Check, expirationBlock, accessSignature, deleteKey,
		nil, memo, transactionSpendingLimit)
}

// Create a new AuthorizeDerivedKey txn and connect it to the utxoView
func _doAuthorizeTxnWithExtraDataAndSpendingLimits(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, utxoView *UtxoView, feeRateNanosPerKB uint64, ownerPublicKey []byte,
	derivedPublicKey []byte, derivedPrivBase58Check string, expirationBlock uint64,
	accessSignature []byte, deleteKey bool, extraData map[string][]byte,
	memo []byte, transactionSpendingLimit *TransactionSpendingLimit) (_utxoOps []*UtxoOperation,
	_txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	transactionSpendingLimitBytes, err := transactionSpendingLimit.ToBytes(uint64(blockHeight))
	require.NoError(err)
	txn, totalInput, changeAmount, fees, err := chain.CreateAuthorizeDerivedKeyTxn(
		ownerPublicKey,
		derivedPublicKey,
		expirationBlock,
		accessSignature,
		deleteKey,
		false,
		extraData,
		memo,
		hex.EncodeToString(transactionSpendingLimitBytes),
		feeRateNanosPerKB,
		nil, /*mempool*/
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInput, changeAmount+fees)

	// Sign the transaction now that its inputs are set up.
	// We have to set the solution byte because we're signing
	// the transaction with derived key on behalf of the owner.
	_signTxnWithDerivedKey(t, txn, derivedPrivBase58Check)

	txHash := txn.Hash()
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
	// for each output, (and 1 for the spending limit accounting if we're passed the block height)
	// and one OperationTypeUpdateProfile operation at the end.
	transactionSpendingLimitCount := 0
	if blockHeight >= params.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight {
		transactionSpendingLimitCount++
	}
	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeUpdateProfile operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+transactionSpendingLimitCount+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeAuthorizeDerivedKey, utxoOps[len(utxoOps)-1].Type)

	return utxoOps, txn, blockHeight, nil
}

func TestAuthorizeDerivedKeyBasic(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	dbAdapter := chain.NewDbAdapter()

	params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)
	params.ForkHeights.ExtraDataOnEntriesBlockHeight = uint32(0)

	// Mine two blocks to give the sender some DeSo.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)
	senderPrivBytes, _, err := Base58CheckDecode(senderPrivString)
	require.NoError(err)
	recipientPkBytes, _, err := Base58CheckDecode(recipientPkString)
	require.NoError(err)

	// Get AuthorizeDerivedKey txn metadata with expiration at block 6
	senderPriv, _ := btcec.PrivKeyFromBytes(btcec.S256(), senderPrivBytes)
	var transactionSpendingLimit *TransactionSpendingLimit
	authTxnMeta, derivedPriv := _getAuthorizeDerivedKeyMetadata(t, senderPriv, 6, false)
	derivedPrivBase58Check := Base58CheckEncode(derivedPriv.Serialize(), true, params)
	derivedPkBytes := derivedPriv.PubKey().SerializeCompressed()
	fmt.Println("Derived public key:", hex.EncodeToString(derivedPkBytes))

	// We will use these to keep track of added utxo ops and txns
	testUtxoOps := [][]*UtxoOperation{}
	testTxns := []*MsgDeSoTxn{}

	// Just for the sake of consistency, we run the _derivedKeyBasicTransfer on unauthorized
	// derived key. It should fail since blockchain hasn't seen this key yet.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key")
	}
	// Attempt sending an AuthorizeDerivedKey txn signed with an invalid private key.
	// This must fail because the txn has to be signed either by owner or derived key.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMeta.DerivedPublicKey,
			randomPrivBase58Check,
			authTxnMeta.ExpirationBlock,
			authTxnMeta.AccessSignature,
			false,
			nil,
			transactionSpendingLimit,
		)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn signed with an unauthorized private key.")
	}
	// Attempt sending an AuthorizeDerivedKey txn where access signature is signed with
	// an invalid private key. This must fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		expirationBlockByte := UintToBuf(authTxnMeta.ExpirationBlock)
		accessBytes := append(authTxnMeta.DerivedPublicKey, expirationBlockByte[:]...)
		accessSignatureRandom, err := randomPrivateKey.Sign(Sha256DoubleHash(accessBytes)[:])
		require.NoError(err)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMeta.DerivedPublicKey,
			derivedPrivBase58Check,
			authTxnMeta.ExpirationBlock,
			accessSignatureRandom.Serialize(),
			false,
			nil,
			transactionSpendingLimit,
		)
		require.Error(err)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn signed with an invalid access signature.")
	}
	// Check basic transfer signed with still unauthorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key")
	}
	// Now attempt to send the same transaction but signed with the correct derived key.
	// This must pass. The new derived key will be flushed to the db here.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)

		extraData := map[string][]byte{
			"test": []byte("result"),
		}
		utxoOps, txn, _, err := _doAuthorizeTxnWithExtraDataAndSpendingLimits(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMeta.DerivedPublicKey,
			derivedPrivBase58Check,
			authTxnMeta.ExpirationBlock,
			authTxnMeta.AccessSignature,
			false,
			extraData,
			nil,
			transactionSpendingLimit,
		)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))

		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// Verify that expiration block was persisted in the db
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 0, AuthorizeDerivedKeyOperationValid, nil)
		derivedKeyEntry := dbAdapter.GetOwnerToDerivedKeyMapping(*NewPublicKey(senderPkBytes), *NewPublicKey(authTxnMeta.DerivedPublicKey))
		require.Equal(derivedKeyEntry.ExtraData["test"], []byte("result"))
		fmt.Println("Passed connecting AuthorizeDerivedKey txn signed with an authorized private key. Flushed to Db.")
	}
	// Check basic transfer signed by the owner key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 1, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with owner key. Flushed to Db.")
	}
	// Check basic transfer signed with now authorized derived key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with authorized derived key. Flushed to Db.")
	}
	// Check basic transfer signed with a random key.
	// Should fail. Well... theoretically, it could pass in a distant future.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Fail basic transfer signed with random key.")
	}
	// Try disconnecting all transactions so that key is deauthorized.
	// Should succeed.
	{
		for iterIndex := range testTxns {
			testIndex := len(testTxns) - 1 - iterIndex
			currentTxn := testTxns[testIndex]
			currentUtxoOps := testUtxoOps[testIndex]
			fmt.Println("currentTxn.String()", currentTxn.String())

			// Disconnect the transaction
			utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(0), "SimpleDisconnect: Index: %v", testIndex)
		}

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txns. Flushed to Db.")
	}
	// After disconnecting, check basic transfer signed with unauthorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key after disconnecting")
	}
	// Connect all txns to a single UtxoView flushing only at the end.
	{
		// Create a new UtxoView
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		for testIndex, txn := range testTxns {
			fmt.Printf("Applying test index: %v\n", testIndex)
			blockHeight := chain.blockTip().Height + 1
			txnSize := getTxnSize(*txn)
			_, _, _, _, err :=
				utxoView.ConnectTransaction(
					txn, txn.Hash(), txnSize, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.NoError(err)
		}

		// Now flush at the end.
		require.NoError(utxoView.FlushToDb(0))

		// Verify that expiration block and balance was persisted in the db
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed re-connecting all txn to a single utxoView")
	}
	// Check basic transfer signed with a random key.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Fail basic transfer signed with random key.")
	}
	// Disconnect all txns on a single UtxoView flushing only at the end
	{
		// Create a new UtxoView
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		for iterIndex := range testTxns {
			testIndex := len(testTxns) - 1 - iterIndex
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			txn := testTxns[testIndex]
			require.NoError(utxoView.DisconnectTransaction(
				txn, txn.Hash(), testUtxoOps[testIndex], blockHeight))
		}

		// Now flush at the end.
		require.NoError(utxoView.FlushToDb(0))

		// Verify that expiration block and balance was persisted in the db
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txn on a single utxoView")
	}
	// Connect transactions to a single mempool, should pass.
	{
		for ii, currentTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				currentTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "mempool index %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}

		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool")
	}
	// Check basic transfer signed with a random key, when passing mempool.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, nil, mempool, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Fail basic transfer signed with random key with mempool.")
	}
	// Remove all the transactions from the mempool. Should pass.
	{
		for _, burnTxn := range testTxns {
			mempool.inefficientRemoveTransaction(burnTxn)
		}
		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed removing all txn from the mempool.")
	}
	// After disconnecting, check basic transfer signed with unauthorized derived key.
	// Should fail.
	{
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, nil, mempool, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Failed basic transfer signed with unauthorized derived key after disconnecting")
	}
	// Re-connect transactions to a single mempool, should pass.
	{
		for ii, currentTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				currentTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "mempool index %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}

		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool.")
	}
	// We will be adding some blocks so we define an array to keep track of them.
	testBlocks := []*MsgDeSoBlock{}
	// Mine a block with all the mempool transactions.
	{
		// All the txns should be in the mempool already so mining a block should put
		// all those transactions in it.
		addedBlock, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		testBlocks = append(testBlocks, addedBlock)
	}
	// Reset testUtxoOps and testTxns so we can test more transactions
	testUtxoOps = [][]*UtxoOperation{}
	testTxns = []*MsgDeSoTxn{}
	// Check basic transfer signed by the owner key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		fmt.Println("Passed basic transfer signed with owner key. Flushed to Db.")
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 3, AuthorizeDerivedKeyOperationValid, nil)
	}
	// Check basic transfer signed with authorized derived key. Now the auth txn is persisted in the db.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 4, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with authorized derived key. Flushed to Db.")
	}
	// Check basic transfer signed with a random key.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 4, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Fail basic transfer signed with random key.")
	}
	// Try disconnecting all transactions. Should succeed.
	{
		for iterIndex := range testTxns {
			testIndex := len(testTxns) - 1 - iterIndex
			currentTxn := testTxns[testIndex]
			currentUtxoOps := testUtxoOps[testIndex]
			fmt.Println("currentTxn.String()", currentTxn.String())

			// Disconnect the transaction
			utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(0), "SimpleDisconnect: Index: %v", testIndex)
		}

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txns. Flushed to Db.")
	}
	// Mine a few more blocks so that the authorization should expire
	{
		for i := uint64(chain.blockTip().Height); i < authTxnMeta.ExpirationBlock; i++ {
			addedBlock, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
			require.NoError(err)
			testBlocks = append(testBlocks, addedBlock)
		}
		fmt.Println("Added a few more blocks.")
	}
	// Check basic transfer signed by the owner key.
	// Should succeed.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)

		// We're not persisting in the db so balance should remain at 2.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with owner key.")
	}
	// Check basic transfer signed with expired authorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed a txn signed with an expired derived key.")
	}

	// Reset testUtxoOps and testTxns so we can test more transactions
	testUtxoOps = [][]*UtxoOperation{}
	testTxns = []*MsgDeSoTxn{}
	// Get another AuthorizeDerivedKey txn metadata with expiration at block 10
	// We will try to de-authorize this key with a txn before it expires.
	authTxnMetaDeAuth, derivedDeAuthPriv := _getAuthorizeDerivedKeyMetadata(t, senderPriv, 10, false)
	derivedPrivDeAuthBase58Check := Base58CheckEncode(derivedDeAuthPriv.Serialize(), true, params)
	derivedDeAuthPkBytes := derivedDeAuthPriv.PubKey().SerializeCompressed()
	fmt.Println("Derived public key:", hex.EncodeToString(derivedDeAuthPkBytes))
	// Send an authorize transaction signed with the correct derived key.
	// This must pass.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, _, err := _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			authTxnMetaDeAuth.ExpirationBlock,
			authTxnMetaDeAuth.AccessSignature,
			false,
			nil,
			transactionSpendingLimit,
		)
		require.NoError(err)
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// Verify that expiration block was persisted in the db
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, 0, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed connecting AuthorizeDerivedKey txn signed with an authorized private key.")
	}
	// Re-connect transactions to a single mempool, should pass.
	{
		for ii, currentTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				currentTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "mempool index %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}

		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool.")
	}
	// Mine a block so that mempool gets flushed to db
	{
		addedBlock, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		testBlocks = append(testBlocks, addedBlock)
		fmt.Println("Added a block.")
	}
	// Reset testUtxoOps and testTxns so we can test more transactions
	testUtxoOps = [][]*UtxoOperation{}
	testTxns = []*MsgDeSoTxn{}
	// Check basic transfer signed with new authorized derived key.
	// Sanity check. Should pass. We're not flushing to the db yet.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// We're persisting to the db so balance should change to 3.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with derived key.")
	}
	// Send a de-authorize transaction signed with a derived key.
	// Doesn't matter if it's signed by the owner or not, once a isDeleted
	// txn appears, the key should be forever expired. This must pass.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, _, err := _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			10,
			authTxnMetaDeAuth.AccessSignature,
			true,
			nil,
			transactionSpendingLimit,
		)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)
		// Verify the expiration block in the db
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed connecting AuthorizeDerivedKey txn with isDeleted signed with an authorized private key.")
	}
	// Check basic transfer signed with new authorized derived key.
	// Now that key has been de-authorized this must fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed basic transfer signed with de-authorized derived key.")
	}
	// Sanity check basic transfer signed by the owner key.
	// Should succeed.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// Balance should change to 4
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed basic transfer signed with owner key.")
	}
	// Send an authorize transaction signed with a derived key.
	// Since we've already deleted this derived key, this must fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			10,
			authTxnMetaDeAuth.AccessSignature,
			false,
			nil,
			transactionSpendingLimit,
		)
		require.Contains(err.Error(), RuleErrorAuthorizeDerivedKeyDeletedDerivedPublicKey)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn with de-authorized private key.")
	}
	// Try disconnecting all transactions. Should succeed.
	{
		for iterIndex := range testTxns {
			testIndex := len(testTxns) - 1 - iterIndex
			currentTxn := testTxns[testIndex]
			currentUtxoOps := testUtxoOps[testIndex]
			fmt.Println("currentTxn.String()", currentTxn.String())

			// Disconnect the transaction
			utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(0), "SimpleDisconnect: Index: %v", testIndex)
		}

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txns. Flushed to Db.")
	}
	// Connect transactions to a single mempool, should pass.
	{
		for ii, currentTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				currentTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "mempool index %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}

		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool")
	}
	// Check adding basic transfer to mempool signed with new authorized derived key.
	// Now that key has been de-authorized this must fail.
	{
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, nil, mempool, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, mempool)
		fmt.Println("Failed basic transfer signed with de-authorized derived key in mempool.")
	}
	// Attempt re-authorizing a previously de-authorized derived key.
	// Since we've already deleted this derived key, this must fail.
	{
		utxoView, err := mempool.GetAugmentedUniversalView()
		require.NoError(err)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			10,
			authTxnMetaDeAuth.AccessSignature,
			false,
			nil,
			transactionSpendingLimit,
		)
		require.Contains(err.Error(), RuleErrorAuthorizeDerivedKeyDeletedDerivedPublicKey)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, mempool)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn with de-authorized private key.")
	}
	// Mine a block so that mempool gets flushed to db
	{
		addedBlock, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		testBlocks = append(testBlocks, addedBlock)
		fmt.Println("Added a block.")
	}
	// Check adding basic transfer signed with new authorized derived key.
	// Now that key has been de-authorized this must fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed basic transfer signed with de-authorized derived key.")
	}
	// Attempt re-authorizing a previously de-authorized derived key.
	// Since we've already deleted this derived key, this must fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			10,
			authTxnMetaDeAuth.AccessSignature,
			false,
			nil,
			transactionSpendingLimit,
		)
		require.Contains(err.Error(), RuleErrorAuthorizeDerivedKeyDeletedDerivedPublicKey)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn with de-authorized private key.")
	}
	// Sanity check basic transfer signed by the owner key.
	// Should succeed.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)

		// Balance should change to 4
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed basic transfer signed with owner key.")
	}
	// Roll back the blocks and make sure we don't hit any errors.
	disconnectSingleBlock := func(blockToDisconnect *MsgDeSoBlock, utxoView *UtxoView) {
		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := blockToDisconnect.Header.Hash()
		require.NoError(err)
		utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
		require.NoError(err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(blockToDisconnect.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(blockToDisconnect, txHashes, utxoOps, 0))
	}
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)

		for iterIndex := range testBlocks {
			testIndex := len(testBlocks) - 1 - iterIndex
			testBlock := testBlocks[testIndex]
			disconnectSingleBlock(testBlock, utxoView)
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb(0))
		fmt.Println("Successfully rolled back the blocks.")
	}

	// After we rolled back the blocks, db should reset
	_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
		authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
	fmt.Println("Successfuly run TestAuthorizeDerivedKeyBasic()")
}

func TestAuthorizeDerivedKeyBasicWithTransactionLimits(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight = uint32(0)
	params.ForkHeights.DAOCoinLimitOrderBlockHeight = 0
	params.ForkHeights.DerivedKeyEthSignatureCompatibilityBlockHeight = 0
	params.ForkHeights.OrderBookDBFetchOptimizationBlockHeight = 0
	params.ForkHeights.ParamUpdaterRefactorBlockHeight = 0
	params.ForkHeights.DeSoUnlimitedDerivedKeysBlockHeight = 0
	// Setting DeSoAccessGroupsBlockHeight to 100 because flushToDb in this test uses hard-coded blockheight of 0, which
	// breaks the encoding.
	params.ForkHeights.AssociationsAndAccessGroupsBlockHeight = 100
	params.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	params.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	GlobalDeSoParams = *params

	// Mine two blocks to give the sender some DeSo.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)
	senderPrivBytes, _, err := Base58CheckDecode(senderPrivString)
	require.NoError(err)
	recipientPkBytes, _, err := Base58CheckDecode(recipientPkString)
	require.NoError(err)

	// Get AuthorizeDerivedKey txn metadata with expiration at block 6
	senderPriv, _ := btcec.PrivKeyFromBytes(btcec.S256(), senderPrivBytes)
	transactionCountLimitMap := make(map[TxnType]uint64)
	transactionCountLimitMap[TxnTypeAuthorizeDerivedKey] = 1
	transactionCountLimitMap[TxnTypeBasicTransfer] = 1
	transactionSpendingLimit := &TransactionSpendingLimit{
		GlobalDESOLimit:          NanosPerUnit, // 1 DESO limit
		TransactionCountLimitMap: transactionCountLimitMap,
	}
	blockHeight, err := GetBlockTipHeight(db, false)
	require.NoError(err)
	authTxnMeta, derivedPriv := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(
		t, senderPriv, 6, transactionSpendingLimit, false, blockHeight+1)
	derivedPrivBase58Check := Base58CheckEncode(derivedPriv.Serialize(), true, params)
	derivedPkBytes := derivedPriv.PubKey().SerializeCompressed()
	fmt.Println("Derived public key:", hex.EncodeToString(derivedPkBytes))

	// We will use these to keep track of added utxo ops and txns
	testUtxoOps := [][]*UtxoOperation{}
	testTxns := []*MsgDeSoTxn{}

	// Just for the sake of consistency, we run the _derivedKeyBasicTransfer on unauthorized
	// derived key. It should fail since blockchain hasn't seen this key yet.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key")
	}
	// Attempt sending an AuthorizeDerivedKey txn signed with an invalid private key.
	// This must fail because the txn has to be signed either by owner or derived key.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMeta.DerivedPublicKey,
			randomPrivBase58Check,
			authTxnMeta.ExpirationBlock,
			authTxnMeta.AccessSignature,
			false,
			nil,
			transactionSpendingLimit,
		)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn signed with an unauthorized private key.")
	}
	// Attempt sending an AuthorizeDerivedKey txn where access signature is signed with
	// an invalid private key. This must fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		expirationBlockByte := UintToBuf(authTxnMeta.ExpirationBlock)
		accessBytes := append(authTxnMeta.DerivedPublicKey, expirationBlockByte[:]...)
		accessSignatureRandom, err := randomPrivateKey.Sign(Sha256DoubleHash(accessBytes)[:])
		require.NoError(err)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMeta.DerivedPublicKey,
			derivedPrivBase58Check,
			authTxnMeta.ExpirationBlock,
			accessSignatureRandom.Serialize(),
			false,
			nil,
			transactionSpendingLimit,
		)
		require.Error(err)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn signed with an invalid access signature.")
	}
	// Check basic transfer signed with still unauthorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key")
	}
	// Now attempt to send the same transaction but signed with the correct derived key.
	// This must pass. The new derived key will be flushed to the db here.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, _, err := _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMeta.DerivedPublicKey,
			derivedPrivBase58Check,
			authTxnMeta.ExpirationBlock,
			authTxnMeta.AccessSignature,
			false,
			nil,
			transactionSpendingLimit,
		)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))

		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// Verify that expiration block was persisted in the db
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed connecting AuthorizeDerivedKey txn signed with an authorized private key. Flushed to Db.")
	}
	// Check basic transfer signed by the owner key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 1, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with owner key. Flushed to Db.")
	}
	// Check basic transfer signed with now authorized derived key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.NoError(err)
		testTxns = append(testTxns, txn)
		testUtxoOps = append(testUtxoOps, utxoOps)
		require.NoError(utxoView.FlushToDb(0))

		// Attempting the basic transfer again should error because the spending limit authorized only 1 transfer.
		utxoView, err = NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyTxnTypeNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with authorized derived key. Flushed to Db.")
	}
	// Check basic transfer signed with a random key.
	// Should fail. Well... theoretically, it could pass in a distant future.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Fail basic transfer signed with random key.")
	}
	// Try disconnecting all transactions so that key is deauthorized.
	// Should succeed.
	{
		for iterIndex := range testTxns {
			testIndex := len(testTxns) - 1 - iterIndex
			currentTxn := testTxns[testIndex]
			currentUtxoOps := testUtxoOps[testIndex]
			fmt.Println("currentTxn.String()", currentTxn.String())

			// Disconnect the transaction
			utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(0), "SimpleDisconnect: Index: %v", testIndex)
		}

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txns. Flushed to Db.")
	}
	// After disconnecting, check basic transfer signed with unauthorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key after disconnecting")
	}
	// Connect all txns to a single UtxoView flushing only at the end.
	{
		// Create a new UtxoView
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		for testIndex, txn := range testTxns {
			fmt.Printf("Applying test index: %v\n", testIndex)
			blockHeight := chain.blockTip().Height + 1
			txnSize := getTxnSize(*txn)
			_, _, _, _, err :=
				utxoView.ConnectTransaction(
					txn, txn.Hash(), txnSize, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.NoError(err)
		}

		// Now flush at the end.
		require.NoError(utxoView.FlushToDb(0))

		// Verify that expiration block and balance was persisted in the db
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed re-connecting all txn to a single utxoView")
	}
	// Check basic transfer signed with a random key.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Fail basic transfer signed with random key.")
	}
	// Disconnect all txns on a single UtxoView flushing only at the end
	{
		// Create a new UtxoView
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		for iterIndex := range testTxns {
			testIndex := len(testTxns) - 1 - iterIndex
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			txn := testTxns[testIndex]
			require.NoError(utxoView.DisconnectTransaction(
				txn, txn.Hash(), testUtxoOps[testIndex], blockHeight))
		}

		// Now flush at the end.
		require.NoError(utxoView.FlushToDb(0))

		// Verify that expiration block and balance was persisted in the db
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txn on a single utxoView")
	}
	// Connect transactions to a single mempool, should pass.
	{
		for ii, currentTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				currentTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "mempool index %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}

		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool")
	}
	// Check basic transfer signed with a random key, when passing mempool.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, nil, mempool, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Fail basic transfer signed with random key with mempool.")
	}
	// Remove all the transactions from the mempool. Should pass.
	{
		for _, burnTxn := range testTxns {
			mempool.inefficientRemoveTransaction(burnTxn)
		}
		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed removing all txn from the mempool.")
	}
	// After disconnecting, check basic transfer signed with unauthorized derived key.
	// Should fail.
	{
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, nil, mempool, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Failed basic transfer signed with unauthorized derived key after disconnecting")
	}
	// Re-connect transactions to a single mempool, should pass.
	{
		for ii, currentTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				currentTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "mempool index %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}

		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool.")
	}
	// We will be adding some blocks so we define an array to keep track of them.
	testBlocks := []*MsgDeSoBlock{}
	// Mine a block with all the mempool transactions.
	{
		// All the txns should be in the mempool already so mining a block should put
		// all those transactions in it.
		addedBlock, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		testBlocks = append(testBlocks, addedBlock)
	}
	// Reset testUtxoOps and testTxns so we can test more transactions
	testUtxoOps = [][]*UtxoOperation{}
	testTxns = []*MsgDeSoTxn{}
	// Check basic transfer signed by the owner key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		fmt.Println("Passed basic transfer signed with owner key. Flushed to Db.")
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 3, AuthorizeDerivedKeyOperationValid, nil)
	}
	// Check basic transfer signed with authorized derived key. Now the auth txn is persisted in the db.
	// Should succeed. Flush to db.
	{
		// We authorize an additional basic transfer before the derived key can do this.

		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		addlBasicTransferMap := make(map[TxnType]uint64)
		addlBasicTransferMap[TxnTypeBasicTransfer] = 1
		addlBasicTransferMap[TxnTypeAuthorizeDerivedKey] = 1
		oneMoreBasicTransferSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit:          NanosPerUnit,
			TransactionCountLimitMap: addlBasicTransferMap,
		}
		authorizeUTXOOps, authorizeTxn, _, err := _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMeta.DerivedPublicKey,
			derivedPrivBase58Check,
			authTxnMeta.ExpirationBlock,
			authTxnMeta.AccessSignature,
			false,
			nil,
			oneMoreBasicTransferSpendingLimit,
		)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, authorizeUTXOOps)
		testTxns = append(testTxns, authorizeTxn)

		utxoOps, txn, err := _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// Try sending another basic transfer from the derived key. Should fail because we only authorized 2 basic transfers in total.
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyTxnTypeNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 4, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with authorized derived key. Flushed to Db.")
	}
	// Check basic transfer signed with a random key.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 4, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Fail basic transfer signed with random key.")
	}
	// Try disconnecting all transactions. Should succeed.
	{
		for iterIndex := range testTxns {
			testIndex := len(testTxns) - 1 - iterIndex
			currentTxn := testTxns[testIndex]
			currentUtxoOps := testUtxoOps[testIndex]
			fmt.Println("currentTxn.String()", currentTxn.String())

			// Disconnect the transaction
			utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(0), "SimpleDisconnect: Index: %v", testIndex)
		}

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txns. Flushed to Db.")
	}
	// Mine a few more blocks so that the authorization should expire
	{
		for i := uint64(chain.blockTip().Height); i < authTxnMeta.ExpirationBlock; i++ {
			addedBlock, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
			require.NoError(err)
			testBlocks = append(testBlocks, addedBlock)
		}
		fmt.Println("Added a few more blocks.")
	}
	// Check basic transfer signed by the owner key.
	// Should succeed.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)

		// We're not persisting in the db so balance should remain at 2.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with owner key.")
	}
	// Check basic transfer signed with expired authorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed a txn signed with an expired derived key.")
	}

	// Reset testUtxoOps and testTxns so we can test more transactions
	testUtxoOps = [][]*UtxoOperation{}
	testTxns = []*MsgDeSoTxn{}
	// Get another AuthorizeDerivedKey txn metadata with expiration at block 10
	// We will try to de-authorize this key with a txn before it expires.
	blockHeight, err = GetBlockTipHeight(db, false)
	require.NoError(err)
	authTxnMetaDeAuth, derivedDeAuthPriv := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(
		t, senderPriv, 10, transactionSpendingLimit, false, blockHeight+1)
	derivedPrivDeAuthBase58Check := Base58CheckEncode(derivedDeAuthPriv.Serialize(), true, params)
	derivedDeAuthPkBytes := derivedDeAuthPriv.PubKey().SerializeCompressed()
	fmt.Println("Derived public key:", hex.EncodeToString(derivedDeAuthPkBytes))
	// Send an authorize transaction signed with the correct derived key.
	// This must pass.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, _, err := _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			authTxnMetaDeAuth.ExpirationBlock,
			authTxnMetaDeAuth.AccessSignature,
			false,
			nil,
			transactionSpendingLimit,
		)
		require.NoError(err)
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// Verify that expiration block was persisted in the db
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, 0, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed connecting AuthorizeDerivedKey txn signed with an authorized private key.")
	}
	// Re-connect transactions to a single mempool, should pass.
	{
		for ii, currentTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				currentTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "mempool index %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}

		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool.")
	}
	// Mine a block so that mempool gets flushed to db
	{
		addedBlock, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		testBlocks = append(testBlocks, addedBlock)
		fmt.Println("Added a block.")
	}
	// Reset testUtxoOps and testTxns so we can test more transactions
	testUtxoOps = [][]*UtxoOperation{}
	testTxns = []*MsgDeSoTxn{}
	// Check basic transfer signed with new authorized derived key.
	// Sanity check. Should pass. We're not flushing to the db yet.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// We're persisting to the db so balance should change to 3.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with derived key.")
	}
	// Send a de-authorize transaction signed with a derived key.
	// Doesn't matter if it's signed by the owner or not, once a isDeleted
	// txn appears, the key should be forever expired. This must pass.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, _, err := _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			10,
			authTxnMetaDeAuth.AccessSignature,
			true,
			nil,
			transactionSpendingLimit,
		)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)
		// Verify the expiration block in the db
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed connecting AuthorizeDerivedKey txn with isDeleted signed with an authorized private key.")
	}
	// Check basic transfer signed with new authorized derived key.
	// Now that key has been de-authorized this must fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed basic transfer signed with de-authorized derived key.")
	}
	// Sanity check basic transfer signed by the owner key.
	// Should succeed.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// Balance should change to 4
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed basic transfer signed with owner key.")
	}
	// Send an authorize transaction signed with a derived key.
	// Since we've already deleted this derived key, this must fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			10,
			authTxnMetaDeAuth.AccessSignature,
			false,
			nil,
			transactionSpendingLimit,
		)
		require.Contains(err.Error(), RuleErrorAuthorizeDerivedKeyDeletedDerivedPublicKey)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn with de-authorized private key.")
	}
	// Try disconnecting all transactions. Should succeed.
	{
		for iterIndex := range testTxns {
			testIndex := len(testTxns) - 1 - iterIndex
			currentTxn := testTxns[testIndex]
			currentUtxoOps := testUtxoOps[testIndex]
			fmt.Println("currentTxn.String()", currentTxn.String())

			// Disconnect the transaction
			utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(0), "SimpleDisconnect: Index: %v", testIndex)
		}

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txns. Flushed to Db.")
	}
	// Connect transactions to a single mempool, should pass.
	{
		for ii, currentTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				currentTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "mempool index %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}

		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool")
	}
	// Check adding basic transfer to mempool signed with new authorized derived key.
	// Now that key has been de-authorized this must fail.
	{
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, nil, mempool, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, mempool)
		fmt.Println("Failed basic transfer signed with de-authorized derived key in mempool.")
	}
	// Attempt re-authorizing a previously de-authorized derived key.
	// Since we've already deleted this derived key, this must fail.
	{
		utxoView, err := mempool.GetAugmentedUniversalView()
		require.NoError(err)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			10,
			authTxnMetaDeAuth.AccessSignature,
			false,
			nil,
			transactionSpendingLimit,
		)
		require.Contains(err.Error(), RuleErrorAuthorizeDerivedKeyDeletedDerivedPublicKey)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, mempool)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn with de-authorized private key.")
	}
	// Mine a block so that mempool gets flushed to db
	{
		addedBlock, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		testBlocks = append(testBlocks, addedBlock)
		fmt.Println("Added a block.")
	}
	// Check adding basic transfer signed with new authorized derived key.
	// Now that key has been de-authorized this must fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed basic transfer signed with de-authorized derived key.")
	}
	// Attempt re-authorizing a previously de-authorized derived key.
	// Since we've already deleted this derived key, this must fail.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			10,
			authTxnMetaDeAuth.AccessSignature,
			false,
			nil,
			transactionSpendingLimit,
		)
		require.Contains(err.Error(), RuleErrorAuthorizeDerivedKeyDeletedDerivedPublicKey)

		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn with de-authorized private key.")
	}
	// Sanity check basic transfer signed by the owner key.
	// Should succeed.
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)
		_, _, err = _derivedKeyBasicTransfer(t, db, chain, params, senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)

		// Balance should change to 4
		_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
			authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed basic transfer signed with owner key.")
	}
	// Roll back the blocks and make sure we don't hit any errors.
	disconnectSingleBlock := func(blockToDisconnect *MsgDeSoBlock, utxoView *UtxoView) {
		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := blockToDisconnect.Header.Hash()
		require.NoError(err)
		utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
		require.NoError(err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(blockToDisconnect.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(blockToDisconnect, txHashes, utxoOps, 0))
	}
	{
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(err)

		for iterIndex := range testBlocks {
			testIndex := len(testBlocks) - 1 - iterIndex
			testBlock := testBlocks[testIndex]
			disconnectSingleBlock(testBlock, utxoView)
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb(0))
		fmt.Println("Successfully rolled back the blocks.")
	}

	// After we rolled back the blocks, db should reset
	_derivedKeyVerifyTest(t, db, chain, transactionSpendingLimit,
		authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
	fmt.Println("Successfuly run TestAuthorizeDerivedKeyBasicWithTransactionLimits()")
}

func TestAuthorizedDerivedKeyWithTransactionLimitsHardcore(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	dbAdapter := chain.NewDbAdapter()

	// Set the block height for unlimited derived keys to 10. We will perform two sets of tests:
	// 	1) Before the unlimited derived keys block height for utxo_view and encoder migration.
	// 	2) Right at the unlimited derived keys block height.
	// 	3) After the block height.
	const (
		unlimitedDerivedKeysBlockHeight            = uint32(10)
		TestStageBeforeUnlimitedDerivedBlockHeight = "TestStageBeforeUnlimitedDerivedBlockHeight"
		TestStageAtUnlimitedDerivedBlockHeight     = "TestStageAtUnlimitedDerivedBlockHeight"
		TestStageAfterUnlimitedDerivedBlockHeight  = "TestStageAfterUnlimitedDerivedBlockHeight"
	)
	testStage := TestStageBeforeUnlimitedDerivedBlockHeight

	params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight = uint32(0)
	params.ForkHeights.DAOCoinBlockHeight = uint32(0)
	params.ForkHeights.DAOCoinLimitOrderBlockHeight = uint32(0)
	params.ForkHeights.OrderBookDBFetchOptimizationBlockHeight = uint32(0)
	params.ForkHeights.BuyNowAndNFTSplitsBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeyEthSignatureCompatibilityBlockHeight = uint32(0)
	params.ForkHeights.DeSoUnlimitedDerivedKeysBlockHeight = unlimitedDerivedKeysBlockHeight
	params.ForkHeights.AssociationsAndAccessGroupsBlockHeight = 100
	params.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	params.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	GlobalDeSoParams = *params

	params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

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
	// We take the block tip to be the blockchain height rather than the header chain height.
	testMeta := &TestMeta{
		t:           t,
		chain:       chain,
		params:      params,
		db:          db,
		mempool:     mempool,
		miner:       miner,
		savedHeight: chain.blockTip().Height + 1,
	}

	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 100)

	m0Balance := 1000
	m1Balance := 1000
	m2Balance := 1000
	m3Balance := 1000
	m4Balance := 1000
	paramUpdaterBalance := 1000
	expirationBlockHeight := uint64(100)

	_, _, _, _, _, _ = m0Balance, m1Balance, m2Balance, m3Balance, m4Balance, paramUpdaterBalance
	// Create profiles for M0 and M1
	// Create a profile for m0
	blockHeight, err := GetBlockTipHeight(db, false)
	require.NoError(err)
	{
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeUpdateProfile,
			&UpdateProfileMetadata{
				NewUsername:                 []byte("m0"),
				NewDescription:              []byte("i am the m0"),
				NewProfilePic:               []byte(shortPic),
				NewCreatorBasisPoints:       10 * 100,
				NewStakeMultipleBasisPoints: 1.25 * 100 * 100,
				IsHidden:                    false,
			},
			nil,
			blockHeight+1,
		)

		// Create a profile for m1
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m1Pub,
			m1Priv,
			false,
			TxnTypeUpdateProfile,
			&UpdateProfileMetadata{
				NewUsername:                 []byte("m1"),
				NewDescription:              []byte("i am the m1"),
				NewProfilePic:               []byte(shortPic),
				NewCreatorBasisPoints:       10 * 100,
				NewStakeMultipleBasisPoints: 1.25 * 100 * 100,
				IsHidden:                    false,
			},
			nil,
			blockHeight+1,
		)
	}

REPEAT:
	utxoView, err := mempool.GetAugmentedUniversalView()
	require.NoError(err)
	m1PrivKeyBytes, _, err := Base58CheckDecode(m1Priv)
	m1PrivateKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), m1PrivKeyBytes)
	m1PKID := utxoView.GetPKIDForPublicKey(m1PkBytes).PKID
	transactionSpendingLimit := &TransactionSpendingLimit{
		GlobalDESOLimit:              100,
		TransactionCountLimitMap:     make(map[TxnType]uint64),
		CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
		DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
		NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
	}
	transactionSpendingLimit.TransactionCountLimitMap[TxnTypeAuthorizeDerivedKey] = 1
	transactionSpendingLimit.TransactionCountLimitMap[TxnTypeBasicTransfer] = 1
	// Mint and update transfer restriction status
	//
	// We don't need to set TxnType-level quota for DAOCoin txns. Only
	// the granular quota matters.
	//transactionSpendingLimit.TransactionCountLimitMap[TxnTypeDAOCoin] = 1
	//transactionSpendingLimit.TransactionCountLimitMap[TxnTypeDAOCoinTransfer] = 1
	transactionSpendingLimit.DAOCoinOperationLimitMap[MakeDAOCoinOperationLimitKey(*m1PKID, MintDAOCoinOperation)] = 1
	transactionSpendingLimit.DAOCoinOperationLimitMap[MakeDAOCoinOperationLimitKey(*m1PKID, TransferDAOCoinOperation)] = 1
	blockHeight, err = GetBlockTipHeight(db, false)
	require.NoError(err)
	authTxnMeta, derivedPriv := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(
		t, m1PrivateKey, expirationBlockHeight, transactionSpendingLimit, false, blockHeight+1)
	derivedPrivBase58Check := Base58CheckEncode(derivedPriv.Serialize(), true, params)
	{
		extraData := make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = transactionSpendingLimit
		_doTxnWithTestMeta(
			testMeta,
			10,
			m1Pub,
			derivedPrivBase58Check,
			true,
			TxnTypeAuthorizeDerivedKey,
			authTxnMeta,
			extraData,
			blockHeight+1,
		)
	}

	// Derived key for M1 mints 100 M1 DAO coins
	{
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m1Pub,
			derivedPrivBase58Check,
			true,
			TxnTypeDAOCoin,
			&DAOCoinMetadata{
				ProfilePublicKey: m1PkBytes,
				OperationType:    DAOCoinOperationTypeMint,
				CoinsToMintNanos: *uint256.NewInt().SetUint64(100 * NanosPerUnit),
				CoinsToBurnNanos: *uint256.NewInt(),
			},
			nil,
			blockHeight+1,
		)

		// Attempting to mint DAO again should throw an error because we only authorized 1 mint.
		_, _, _, err = _doTxn(
			testMeta,
			10,
			m1Pub,
			derivedPrivBase58Check,
			true,
			TxnTypeDAOCoin,
			&DAOCoinMetadata{
				ProfilePublicKey: m1PkBytes,
				OperationType:    DAOCoinOperationTypeMint,
				CoinsToMintNanos: *uint256.NewInt().SetUint64(100 * NanosPerUnit),
				CoinsToBurnNanos: *uint256.NewInt(),
			},
			nil,
			blockHeight+1,
		)
		require.Contains(err.Error(), RuleErrorDerivedKeyDAOCoinOperationNotAuthorized)
	}

	// Derived key for M1 transfers 10 M1 DAO Coins to M0
	{
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m1Pub,
			derivedPrivBase58Check,
			true,
			TxnTypeDAOCoinTransfer,
			&DAOCoinTransferMetadata{
				ProfilePublicKey:       m1PkBytes,
				ReceiverPublicKey:      m0PkBytes,
				DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(10 * NanosPerUnit),
			},
			nil,
			blockHeight+1,
		)

		// Attempting to transfer DAO again should throw an error because we only authorized 1 transfer.
		_, _, _, err = _doTxn(
			testMeta,
			10,
			m1Pub,
			derivedPrivBase58Check,
			true,
			TxnTypeDAOCoinTransfer,
			&DAOCoinTransferMetadata{
				ProfilePublicKey:       m1PkBytes,
				ReceiverPublicKey:      m0PkBytes,
				DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(10 * NanosPerUnit),
			},
			nil,
			blockHeight+1,
		)
		require.Contains(err.Error(), RuleErrorDerivedKeyDAOCoinOperationNotAuthorized)
	}

	// Randomly try changing the spending limit on the derived key to an unlimited key.
	{
		// Get the mempool's utxoview and get the derived key bytes.
		utxoView, err := mempool.GetAugmentedUniversalView()
		require.NoError(err)
		derivedPrivBytes, _, err := Base58CheckDecode(derivedPrivBase58Check)
		_, derivedPub := btcec.PrivKeyFromBytes(btcec.S256(), derivedPrivBytes)
		derivedPubBytes := derivedPub.SerializeCompressed()
		require.NoError(err)

		// Persist the existing spending limit on the derived key.
		prevDerivedKeyEntry := utxoView.GetDerivedKeyMappingForOwner(m1PkBytes, derivedPubBytes)
		require.NotNil(prevDerivedKeyEntry)
		require.Equal(false, prevDerivedKeyEntry.isDeleted)
		prevTransactionSpendingLimit := &TransactionSpendingLimit{}
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		prevTransactionSpendingLimitBytes, err := prevDerivedKeyEntry.TransactionSpendingLimitTracker.ToBytes(blockHeight + 1)
		rr := bytes.NewReader(prevTransactionSpendingLimitBytes)
		err = prevTransactionSpendingLimit.FromBytes(blockHeight+1, rr)
		require.NoError(err)

		// Unlimited spending limit.
		transactionSpendingLimit = &TransactionSpendingLimit{
			GlobalDESOLimit:              0,
			TransactionCountLimitMap:     make(map[TxnType]uint64),
			CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
			DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
			NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
			IsUnlimited:                  true,
		}

		// Authorize the unlimited derived key
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		reauthTxnMeta, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
			t, m1PrivateKey, expirationBlockHeight, transactionSpendingLimit, derivedPriv, false, blockHeight+1)
		extraData := make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = transactionSpendingLimit
		// Use EncoderBlockHeight 1 to make sure we use the new spending limit encoding.
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMetaWithBlockHeight(
			testMeta,
			10,
			m1Pub,
			m1Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			reauthTxnMeta,
			extraData,
			blockHeight+1,
		)

		// Attempting to transfer should now pass because the key has unlimited permissions.
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		err = _doTxnWithTextMetaWithBlockHeightWithError(
			testMeta,
			10,
			m1Pub,
			derivedPrivBase58Check,
			true,
			TxnTypeDAOCoinTransfer,
			&DAOCoinTransferMetadata{
				ProfilePublicKey:       m1PkBytes,
				ReceiverPublicKey:      m0PkBytes,
				DAOCoinToTransferNanos: *uint256.NewInt().SetUint64(10 * NanosPerUnit),
			},
			nil,
			blockHeight+1,
		)
		if blockHeight+1 < uint64(unlimitedDerivedKeysBlockHeight) {
			require.Contains(err.Error(), RuleErrorDerivedKeyTxnSpendsMoreThanGlobalDESOLimit)
		} else {
			require.NoError(err)
		}

		// Now try to mint some DAO coins, it should pass too.
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		err = _doTxnWithTextMetaWithBlockHeightWithError(
			testMeta,
			10,
			m1Pub,
			derivedPrivBase58Check,
			true,
			TxnTypeDAOCoin,
			&DAOCoinMetadata{
				ProfilePublicKey: m1PkBytes,
				OperationType:    DAOCoinOperationTypeMint,
				CoinsToMintNanos: *uint256.NewInt().SetUint64(100 * NanosPerUnit),
				CoinsToBurnNanos: *uint256.NewInt(),
			},
			nil,
			blockHeight+1,
		)
		if blockHeight+1 < uint64(unlimitedDerivedKeysBlockHeight) {
			require.Contains(err.Error(), RuleErrorDerivedKeyTxnSpendsMoreThanGlobalDESOLimit)
		} else {
			require.NoError(err)
		}

		// Revert to the previous spending limit.
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		reauthTxnMeta, _ = _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
			t, m1PrivateKey, expirationBlockHeight, prevTransactionSpendingLimit, derivedPriv, false, blockHeight+1)
		extraData = make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = prevTransactionSpendingLimit
		// Use EncoderBlockHeight 1 to make sure we use the new spending limit encoding.
		_doTxnWithTestMetaWithBlockHeight(
			testMeta,
			10,
			m1Pub,
			m1Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			reauthTxnMeta,
			extraData,
			blockHeight+1,
		)
	}

	// Now the derived key can't do anything else for M1 DAO coin
	{
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_, _, _, err = _doTxn(
			testMeta,
			10,
			m1Pub,
			derivedPrivBase58Check,
			true,
			TxnTypeDAOCoin,
			&DAOCoinMetadata{
				ProfilePublicKey:          m1PkBytes,
				OperationType:             DAOCoinOperationTypeUpdateTransferRestrictionStatus,
				TransferRestrictionStatus: TransferRestrictionStatusProfileOwnerOnly,
			},
			nil,
			blockHeight+1,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyDAOCoinOperationNotAuthorized)
	}

	newTransactionSpendingLimit := &TransactionSpendingLimit{
		GlobalDESOLimit:              100,
		TransactionCountLimitMap:     make(map[TxnType]uint64),
		CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
		DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
		NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
	}
	newTransactionSpendingLimit.TransactionCountLimitMap[TxnTypeAuthorizeDerivedKey] = 1
	newTransactionSpendingLimit.TransactionCountLimitMap[TxnTypeBasicTransfer] = 1
	// Mint and update transfer restriction status
	// TxnType-level limits are not needed for DAOCoin operations because we defer to
	// granular limits.
	//newTransactionSpendingLimit.TransactionCountLimitMap[TxnTypeDAOCoin] = 10
	//newTransactionSpendingLimit.TransactionCountLimitMap[TxnTypeDAOCoinTransfer] = 10
	// This time we allow any operation 10x
	newTransactionSpendingLimit.DAOCoinOperationLimitMap[MakeDAOCoinOperationLimitKey(*m1PKID, AnyDAOCoinOperation)] = 10
	newTransactionSpendingLimit.DAOCoinOperationLimitMap[MakeDAOCoinOperationLimitKey(*m1PKID, UpdateTransferRestrictionStatusDAOCoinOperation)] = 0
	blockHeight, err = GetBlockTipHeight(db, false)
	require.NoError(err)
	newAuthTxnMeta, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
		t, m1PrivateKey, expirationBlockHeight, newTransactionSpendingLimit, derivedPriv, false, blockHeight+1)

	// Okay so let's update the derived key, but now let's let the derived key do any operation on our DAO coin
	{
		extraData := make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = newTransactionSpendingLimit
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m1Pub,
			derivedPrivBase58Check,
			true,
			TxnTypeAuthorizeDerivedKey,
			newAuthTxnMeta,
			extraData,
			blockHeight+1,
		)
	}

	// Updating the transfer restriction status should work
	if testStage == TestStageBeforeUnlimitedDerivedBlockHeight {
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m1Pub,
			derivedPrivBase58Check,
			true,
			TxnTypeDAOCoin,
			&DAOCoinMetadata{
				ProfilePublicKey:          m1PkBytes,
				OperationType:             DAOCoinOperationTypeUpdateTransferRestrictionStatus,
				TransferRestrictionStatus: TransferRestrictionStatusProfileOwnerOnly,
			},
			nil,
			blockHeight+1,
		)
	}

	// Burning some DAO coins should work
	{
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m1Pub,
			derivedPrivBase58Check,
			true,
			TxnTypeDAOCoin,
			&DAOCoinMetadata{
				ProfilePublicKey: m1PkBytes,
				OperationType:    DAOCoinOperationTypeBurn,
				CoinsToBurnNanos: *uint256.NewInt().SetUint64(10 * NanosPerUnit),
			},
			nil,
			blockHeight+1,
		)
	}

	m0TransactionSpendingLimit := &TransactionSpendingLimit{
		GlobalDESOLimit:              0,
		TransactionCountLimitMap:     make(map[TxnType]uint64),
		CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
		DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
		NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
	}

	m0PrivKeyBytes, _, err := Base58CheckDecode(m0Priv)
	m0PrivateKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), m0PrivKeyBytes)
	blockHeight, err = GetBlockTipHeight(db, false)
	require.NoError(err)
	m0AuthTxnMeta, derived0Priv := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(
		t, m0PrivateKey, expirationBlockHeight, m0TransactionSpendingLimit, false, blockHeight+1)
	derived0PrivBase58Check := Base58CheckEncode(derived0Priv.Serialize(), true, params)
	derived0PublicKeyBase58Check := Base58CheckEncode(m0AuthTxnMeta.DerivedPublicKey, false, params)
	// Okay let's have M0 authorize a derived key that doesn't allow anything to show errors
	{
		extraData := make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = m0TransactionSpendingLimit
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			m0AuthTxnMeta,
			extraData,
			blockHeight+1,
		)
	}

	{
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_, _, _, err = _doTxn(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeCreatorCoin,
			&CreatorCoinMetadataa{
				ProfilePublicKey: m1PkBytes,
				OperationType:    CreatorCoinOperationTypeBuy,
				DeSoToSellNanos:  10,
			},
			nil,
			blockHeight+1,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyTxnSpendsMoreThanGlobalDESOLimit)
	}

	// Okay so now we update the derived key to have enough DESO to do this, but don't give it the ability to perform
	// any creator coin transactions
	m0TransactionSpendingLimit.GlobalDESOLimit = 15
	blockHeight, err = GetBlockTipHeight(db, false)
	require.NoError(err)
	m0AuthTxnMetaWithSpendingLimitTxn, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
		t, m0PrivateKey, expirationBlockHeight, m0TransactionSpendingLimit, derived0Priv, false, blockHeight+1)

	{
		extraData := make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = m0TransactionSpendingLimit
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			m0AuthTxnMetaWithSpendingLimitTxn,
			extraData,
			blockHeight+1,
		)
	}

	{
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_, _, _, err = _doTxn(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeCreatorCoin,
			&CreatorCoinMetadataa{
				ProfilePublicKey: m1PkBytes,
				OperationType:    CreatorCoinOperationTypeBuy,
				DeSoToSellNanos:  10,
			},
			nil,
			blockHeight+1,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyCreatorCoinOperationNotAuthorized)
	}

	// Okay so now we update the derived key to have enough DESO to do this, but don't give it the ability to perform
	// any creator coin transactions
	m0TransactionSpendingLimit.TransactionCountLimitMap[TxnTypeCreatorCoin] = 1
	blockHeight, err = GetBlockTipHeight(db, false)
	require.NoError(err)
	m0AuthTxnMetaWithCCTxn, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
		t, m0PrivateKey, expirationBlockHeight, m0TransactionSpendingLimit, derived0Priv, false, blockHeight+1)

	{
		extraData := make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = m0TransactionSpendingLimit
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			m0AuthTxnMetaWithCCTxn,
			extraData,
			blockHeight+1,
		)
	}

	{
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_, _, _, err = _doTxn(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeCreatorCoin,
			&CreatorCoinMetadataa{
				ProfilePublicKey: m1PkBytes,
				OperationType:    CreatorCoinOperationTypeBuy,
				DeSoToSellNanos:  10,
			},
			nil,
			blockHeight+1,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyCreatorCoinOperationNotAuthorized)
	}

	// Randomly try changing the spending limit on the derived key to an unlimited key.
	{
		// Get the mempool's utxoview and get the derived key bytes.
		utxoView, err := mempool.GetAugmentedUniversalView()
		require.NoError(err)
		derivedPub := derived0Priv.PubKey()
		derivedPubBytes := derivedPub.SerializeCompressed()
		require.NoError(err)

		// Persist the existing spending limit on the derived key.
		prevDerivedKeyEntry := utxoView.GetDerivedKeyMappingForOwner(m0PkBytes, derivedPubBytes)
		require.NotNil(prevDerivedKeyEntry)
		require.Equal(false, prevDerivedKeyEntry.isDeleted)
		prevTransactionSpendingLimit := &TransactionSpendingLimit{}
		prevTransactionSpendingLimitBytes, err := prevDerivedKeyEntry.TransactionSpendingLimitTracker.ToBytes(1)
		rr := bytes.NewReader(prevTransactionSpendingLimitBytes)
		err = prevTransactionSpendingLimit.FromBytes(1, rr)
		require.NoError(err)

		// Unlimited spending limit.
		transactionSpendingLimit = &TransactionSpendingLimit{
			GlobalDESOLimit:              0,
			TransactionCountLimitMap:     make(map[TxnType]uint64),
			CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
			DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
			NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
			IsUnlimited:                  true,
		}

		// Authorize the unlimited derived key
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		reauthTxnMeta, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
			t, m0PrivateKey, expirationBlockHeight, transactionSpendingLimit, derived0Priv, false, blockHeight+1)
		extraData := make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = transactionSpendingLimit
		// Use EncoderBlockHeight 1 to make sure we use the new spending limit encoding.
		_doTxnWithTestMetaWithBlockHeight(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			reauthTxnMeta,
			extraData,
			blockHeight+1,
		)

		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		err = _doTxnWithTextMetaWithBlockHeightWithError(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeCreatorCoin,
			&CreatorCoinMetadataa{
				ProfilePublicKey: m1PkBytes,
				OperationType:    CreatorCoinOperationTypeBuy,
				DeSoToSellNanos:  10,
			},
			nil,
			blockHeight+1,
		)
		if blockHeight+1 < uint64(unlimitedDerivedKeysBlockHeight) {
			require.Contains(err.Error(), RuleErrorDerivedKeyTxnSpendsMoreThanGlobalDESOLimit)
		} else {
			require.NoError(err)
		}

		// Revert to the previous spending limit.
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		reauthTxnMeta, _ = _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
			t, m0PrivateKey, expirationBlockHeight, prevTransactionSpendingLimit, derived0Priv, false, blockHeight+1)
		extraData = make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = prevTransactionSpendingLimit
		// Use EncoderBlockHeight 1 to make sure we use the new spending limit encoding.
		_doTxnWithTestMetaWithBlockHeight(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			reauthTxnMeta,
			extraData,
			blockHeight+1,
		)
	}
	// Okay now let's just let this derived key do his single transaction, but then it won't be able to do anything else
	// Okay so now we update the derived key to have enough DESO to do this, but don't give it the ability to perform
	// any creator coin transactions
	m0TransactionSpendingLimit.CreatorCoinOperationLimitMap[MakeCreatorCoinOperationLimitKey(*m1PKID, BuyCreatorCoinOperation)] = 1
	m0TransactionSpendingLimit.TransactionCountLimitMap = map[TxnType]uint64{}
	blockHeight, err = GetBlockTipHeight(db, false)
	require.NoError(err)
	m0AuthTxnMetaWithCCOpTxn, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
		t, m0PrivateKey, expirationBlockHeight, m0TransactionSpendingLimit, derived0Priv, false, blockHeight+1)
	{
		extraData := make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = m0TransactionSpendingLimit
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			m0AuthTxnMetaWithCCOpTxn,
			extraData,
			blockHeight+1,
		)
	}

	// Derived Key tries to spend more than global deso limit
	{
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_, _, _, err = _doTxn(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeCreatorCoin,
			&CreatorCoinMetadataa{
				ProfilePublicKey: m1PkBytes,
				OperationType:    CreatorCoinOperationTypeBuy,
				DeSoToSellNanos:  25,
			},
			nil,
			blockHeight+1,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyTxnSpendsMoreThanGlobalDESOLimit)
	}

	{
		derivedKeyEntry := dbAdapter.GetOwnerToDerivedKeyMapping(*NewPublicKey(m0PkBytes), *NewPublicKey(m0AuthTxnMeta.DerivedPublicKey))
		require.Equal(derivedKeyEntry.TransactionSpendingLimitTracker.GlobalDESOLimit, uint64(15))
		require.Equal(derivedKeyEntry.TransactionSpendingLimitTracker.CreatorCoinOperationLimitMap[MakeCreatorCoinOperationLimitKey(*m1PKID, BuyCreatorCoinOperation)], uint64(1))
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeCreatorCoin,
			&CreatorCoinMetadataa{
				ProfilePublicKey: m1PkBytes,
				OperationType:    CreatorCoinOperationTypeBuy,
				DeSoToSellNanos:  10,
			},
			nil,
			blockHeight+1,
		)
		// Let's confirm that the global deso limit has been reduced on the tracker
		derivedKeyEntry = dbAdapter.GetOwnerToDerivedKeyMapping(*NewPublicKey(m0PkBytes), *NewPublicKey(m0AuthTxnMeta.DerivedPublicKey))
		require.Equal(derivedKeyEntry.TransactionSpendingLimitTracker.GlobalDESOLimit, uint64(4)) // 15 - (10 + 1) (CC buy + fee)
		require.Equal(derivedKeyEntry.TransactionSpendingLimitTracker.CreatorCoinOperationLimitMap[MakeCreatorCoinOperationLimitKey(*m1PKID, BuyCreatorCoinOperation)], uint64(0))
	}

	var post1Hash *BlockHash
	// Create a buy now NFT and test that the derived key can't spend greater than their global DESO limit to buy it.
	{
		var bodyBytes []byte
		bodyBytes, err = json.Marshal(&DeSoBodySchema{Body: "test NFT"})
		require.NoError(err)
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m1Pub,
			m1Priv,
			false,
			TxnTypeSubmitPost,
			&SubmitPostMetadata{
				Body:           bodyBytes,
				TimestampNanos: uint64(time.Now().UnixNano()),
			},
			nil,
			blockHeight+1,
		)
		post1Hash = testMeta.txns[len(testMeta.txns)-1].Hash()
	}

	{
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			paramUpdaterPub,
			paramUpdaterPriv,
			false,
			TxnTypeUpdateGlobalParams,
			&UpdateGlobalParamsMetadata{},
			map[string]interface{}{
				MaxCopiesPerNFTKey: int64(1000),
			},
			blockHeight+1,
		)
	}
	{
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		require.NotNil(post1Hash)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m1Pub,
			m1Priv,
			false,
			TxnTypeCreateNFT,
			&CreateNFTMetadata{
				NFTPostHash: post1Hash,
				NumCopies:   10,
				IsForSale:   true,
			},
			map[string]interface{}{
				BuyNowPriceKey: uint64(5),
			},
			blockHeight+1,
		)
	}

	// M0 allows the derived key to bid and sets global DESO limit to 4 nanos
	{
		nftBidSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: 4,
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeNFTBid: 1,
			},
			NFTOperationLimitMap: map[NFTOperationLimitKey]uint64{
				MakeNFTOperationLimitKey(*post1Hash, 1, NFTBidOperation): 1,
			},
		}
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		m0AuthTxnMetaWithNFTBidOpTxn, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
			t,
			m0PrivateKey,
			expirationBlockHeight,
			nftBidSpendingLimit,
			derived0Priv,
			false,
			blockHeight+1,
		)

		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			m0AuthTxnMetaWithNFTBidOpTxn,
			map[string]interface{}{
				TransactionSpendingLimitKey: nftBidSpendingLimit,
			},
			blockHeight+1,
		)
	}

	// Derived key tries to buy now, but fails
	{
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_, _, _, err = _doTxn(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeNFTBid,
			&NFTBidMetadata{
				NFTPostHash:    post1Hash,
				SerialNumber:   1,
				BidAmountNanos: 5,
			},
			nil,
			blockHeight+1,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyTxnSpendsMoreThanGlobalDESOLimit)
	}
	// M0 increases the global DESO limit to 6
	{
		globalDESOSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: 6,
		}
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		m0AuthTxnMetaWithGlobalDESOLimitTxn, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
			t, m0PrivateKey, expirationBlockHeight, globalDESOSpendingLimit, derived0Priv, false, blockHeight+1)

		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			m0AuthTxnMetaWithGlobalDESOLimitTxn,
			map[string]interface{}{
				TransactionSpendingLimitKey: globalDESOSpendingLimit,
			},
			blockHeight+1,
		)
	}
	// Derived key can buy
	{
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeNFTBid,
			&NFTBidMetadata{
				NFTPostHash:    post1Hash,
				SerialNumber:   1,
				BidAmountNanos: 5,
			},
			nil,
			blockHeight+1,
		)
		// Let's confirm that the global deso limit has been reduced on the tracker
		derivedKeyEntry := dbAdapter.GetOwnerToDerivedKeyMapping(*NewPublicKey(m0PkBytes), *NewPublicKey(m0AuthTxnMeta.DerivedPublicKey))
		require.Equal(derivedKeyEntry.TransactionSpendingLimitTracker.GlobalDESOLimit,
			uint64(0)) // 6 - (5 + 1) (Buy Now Price + fee)
		require.Equal(derivedKeyEntry.TransactionSpendingLimitTracker.
			NFTOperationLimitMap[MakeNFTOperationLimitKey(*post1Hash, 1, NFTBidOperation)],
			uint64(0))
	}

	// Derived Key can mint NFT - authorize NFT minting
	{
		globalDESOSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: 6,
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeSubmitPost: 1,
				TxnTypeCreateNFT:  1,
			},
		}
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		m0AuthTxnMetaWithGlobalDESOLimitTxn, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
			t, m0PrivateKey, expirationBlockHeight, globalDESOSpendingLimit, derived0Priv, false, blockHeight+1)

		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			m0AuthTxnMetaWithGlobalDESOLimitTxn,
			map[string]interface{}{
				TransactionSpendingLimitKey: globalDESOSpendingLimit,
			},
			blockHeight+1,
		)
	}

	// Derived Key can mint NFT
	{
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeSubmitPost,
			&SubmitPostMetadata{
				Body:           []byte("abbc"),
				TimestampNanos: uint64(time.Now().UnixNano()),
			},
			nil,
			blockHeight+1,
		)
		nftPostHash := testMeta.txns[len(testMeta.txns)-1].Hash()
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeCreateNFT,
			&CreateNFTMetadata{
				NFTPostHash: nftPostHash,
				NumCopies:   10,
				IsForSale:   true,
			},
			nil,
			blockHeight+1,
		)
	}

	// Send the derived key some money
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, derived0PublicKeyBase58Check, senderPrivString, 100)
	// Derived key can spend its own money
	{
		derivedKeyEntryBefore := dbAdapter.GetOwnerToDerivedKeyMapping(*NewPublicKey(m0PkBytes), *NewPublicKey(m0AuthTxnMeta.DerivedPublicKey))
		require.Equal(derivedKeyEntryBefore.TransactionSpendingLimitTracker.TransactionCountLimitMap[TxnTypeBasicTransfer], uint64(0))
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			derived0PublicKeyBase58Check,
			derived0PrivBase58Check,
			false,
			TxnTypeBasicTransfer,
			&BasicTransferMetadata{},
			map[string]interface{}{
				BasicTransferAmount:    uint64(10),
				BasicTransferRecipient: m0PkBytes,
			},
			blockHeight+1,
		)
		derivedKeyEntryAfter := dbAdapter.GetOwnerToDerivedKeyMapping(*NewPublicKey(m0PkBytes), *NewPublicKey(m0AuthTxnMeta.DerivedPublicKey))
		require.Equal(derivedKeyEntryBefore.TransactionSpendingLimitTracker.GlobalDESOLimit, derivedKeyEntryAfter.TransactionSpendingLimitTracker.GlobalDESOLimit)
	}

	// DAO Coin Limit Orders
	{
		// Can't submit order if not authorized
		exchangeRate, err := CalculateScaledExchangeRate(0.1)
		require.NoError(err)
		metadata := &DAOCoinLimitOrderMetadata{
			BuyingDAOCoinCreatorPublicKey:             NewPublicKey(m1PkBytes),
			SellingDAOCoinCreatorPublicKey:            &ZeroPublicKey,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: exchangeRate,
			QuantityToFillInBaseUnits:                 uint256.NewInt().SetUint64(100),
			OperationType:                             DAOCoinLimitOrderOperationTypeBID,
			FillType:                                  DAOCoinLimitOrderFillTypeGoodTillCancelled,
		}
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_, _, _, err = _doTxn(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeDAOCoinLimitOrder,
			metadata,
			nil,
			blockHeight+1,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyDAOCoinLimitOrderNotAuthorized)

		globalDESOSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: 6,
			DAOCoinLimitOrderLimitMap: map[DAOCoinLimitOrderLimitKey]uint64{
				MakeDAOCoinLimitOrderLimitKey(*m1PKID, ZeroPKID): 1,
			},
		}
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		m0AuthTxnMetaWithGlobalDESOLimitTxn, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
			t, m0PrivateKey, expirationBlockHeight, globalDESOSpendingLimit, derived0Priv, false, blockHeight+1)

		// Authorize derived key with a Limit Order spending limit of 1
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			m0AuthTxnMetaWithGlobalDESOLimitTxn,
			map[string]interface{}{
				TransactionSpendingLimitKey: globalDESOSpendingLimit,
			},
			blockHeight+1,
		)

		// Submitting a Limit Order with the buyer and seller reversed won't work.
		metadata.BuyingDAOCoinCreatorPublicKey = &ZeroPublicKey
		metadata.SellingDAOCoinCreatorPublicKey = NewPublicKey(m1PkBytes)
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_, _, _, err = _doTxn(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeDAOCoinLimitOrder,
			metadata,
			nil,
			blockHeight+1,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyDAOCoinLimitOrderNotAuthorized)

		// Submitting with the authorized buyer and seller should work
		metadata.SellingDAOCoinCreatorPublicKey = &ZeroPublicKey
		metadata.BuyingDAOCoinCreatorPublicKey = NewPublicKey(m1PkBytes)
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeDAOCoinLimitOrder,
			metadata,
			nil,
			blockHeight+1,
		)

		var orders []*DAOCoinLimitOrderEntry
		orders, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Len(orders, 1)
		require.Equal(*orders[0], DAOCoinLimitOrderEntry{
			OrderID:                   orders[0].OrderID,
			TransactorPKID:            utxoView.GetPKIDForPublicKey(m0PkBytes).PKID,
			BuyingDAOCoinCreatorPKID:  m1PKID,
			SellingDAOCoinCreatorPKID: &ZeroPKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: metadata.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			QuantityToFillInBaseUnits:                 metadata.QuantityToFillInBaseUnits,
			BlockHeight:                               testMeta.savedHeight,
			OperationType:                             DAOCoinLimitOrderOperationTypeBID,
			FillType:                                  DAOCoinLimitOrderFillTypeGoodTillCancelled,
		})

		// Cancelling an order should fail with an authorization failure error code if the derived key isn't authorized
		// to trade the buying and selling coins
		orderID := *orders[0].OrderID
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		_, _, _, err = _doTxn(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeDAOCoinLimitOrder,
			&DAOCoinLimitOrderMetadata{
				CancelOrderID: &orderID,
			},
			nil,
			blockHeight+1,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyDAOCoinLimitOrderNotAuthorized)

		// Re-authorize the derived key with a spending limit of 1 for the buying and selling coins
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		m0AuthTxnMetaWithGlobalDESOLimitTxn, _ = _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
			t,
			m0PrivateKey,
			expirationBlockHeight,
			globalDESOSpendingLimit,
			derived0Priv,
			false,
			blockHeight+1,
		)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			m0AuthTxnMetaWithGlobalDESOLimitTxn,
			map[string]interface{}{
				TransactionSpendingLimitKey: globalDESOSpendingLimit,
			},
			blockHeight+1,
		)

		// Cancelling an existing order using CancelOrderID should work if the derived key is authorized for the
		// buying and selling coins that make up the order
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeDAOCoinLimitOrder,
			&DAOCoinLimitOrderMetadata{
				CancelOrderID: &orderID,
			},
			nil,
			blockHeight+1,
		)
		orders, err = dbAdapter.GetAllDAOCoinLimitOrders()
		require.NoError(err)
		require.Len(orders, 0)

		// Cancelling a non-existent order should fail due to an order id lookup, irrespective of the status of the
		// derived key
		_, _, _, err = _doTxn(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeDAOCoinLimitOrder,
			&DAOCoinLimitOrderMetadata{
				CancelOrderID: &orderID,
			},
			nil,
			blockHeight+1,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyInvalidDAOCoinLimitOrderOrderID)
	}

	// M0 deauthorizes the derived key
	{
		emptyTransactionSpendingLimit := &TransactionSpendingLimit{}
		blockHeight, err = GetBlockTipHeight(db, false)
		require.NoError(err)
		accessSignature, err := _getAccessSignature(
			m0AuthTxnMeta.DerivedPublicKey, expirationBlockHeight, emptyTransactionSpendingLimit, m0PrivateKey, blockHeight+1)
		require.NoError(err)
		metadata := &AuthorizeDerivedKeyMetadata{
			DerivedPublicKey: m0AuthTxnMeta.DerivedPublicKey,
			ExpirationBlock:  expirationBlockHeight,
			OperationType:    AuthorizeDerivedKeyOperationNotValid,
			AccessSignature:  accessSignature,
		}
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			metadata,
			map[string]interface{}{
				TransactionSpendingLimitKey: emptyTransactionSpendingLimit,
			},
			blockHeight+1,
		)
	}

	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_, err = testMeta.miner.MineAndProcessSingleBlock(0 /*threadIndex*/, testMeta.mempool)
	require.NoError(err)

	testMeta.txnOps = [][]*UtxoOperation{}
	testMeta.txns = []*MsgDeSoTxn{}
	testMeta.expectedSenderBalances = []uint64{}
	if testStage == TestStageBeforeUnlimitedDerivedBlockHeight {
		// Mine block until we reach the unlimited spending limit block height.
		for chain.blockTip().Height+1 < unlimitedDerivedKeysBlockHeight {
			_, err = testMeta.miner.MineAndProcessSingleBlock(0 /*threadIndex*/, testMeta.mempool)
			require.NoError(err)
		}
		testStage = TestStageAtUnlimitedDerivedBlockHeight
	} else if testStage == TestStageAtUnlimitedDerivedBlockHeight {
		// Mine a block to be above the unlimited derived keys block height.
		_, err = testMeta.miner.MineAndProcessSingleBlock(0 /*threadIndex*/, testMeta.mempool)
		require.NoError(err)
		testStage = TestStageAfterUnlimitedDerivedBlockHeight
	}
	testMeta.savedHeight = chain.blockTip().Height + 1

	if testStage != TestStageAfterUnlimitedDerivedBlockHeight {
		goto REPEAT
	}
	_executeAllTestRollbackAndFlush(testMeta)
}

func TestAuthorizeDerivedKeyWithTransactionSpendingLimitsAccessGroups(t *testing.T) {
	require := require.New(t)

	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	m0PublicKey := NewPublicKey(m0PubBytes)
	m1PubBytes, _, _ := Base58CheckDecode(m1Pub)
	m1PublicKey := NewPublicKey(m1PubBytes)
	fundPublicKeysWithNanosMap := make(map[PublicKey]uint64)
	fundPublicKeysWithNanosMap[*m0PublicKey] = 1000
	initChainCallback := func(tm *transactionTestMeta) {
		_setTestDerivedKeyWithAccessGroupParams(tm)
	}
	tConfig := &transactionTestConfig{
		t:                          t,
		testBadger:                 true,
		testPostgres:               false,
		testPostgresPort:           5433,
		disableLogging:             true,
		initialBlocksMined:         4,
		fundPublicKeysWithNanosMap: fundPublicKeysWithNanosMap,
		initChainCallback:          initChainCallback,
	}
	// Test the following spending limits:
	// - spending limit for AccessGroupLimit
	// - spending limit for AccessGroupMemberLimit
	// - spending limit for AccessGroupLimit & AccessGroupMemberLimit
	// - spending limit for new message txns
	// - unlimited spending limit
	//
	// For each spending limit, we will submit a bunch of txns to make sure the limit works properly.
	// We will also try updating a spending limit.
	groupPriv1, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	groupPk1 := groupPriv1.PubKey().SerializeCompressed()
	_ = groupPk1
	derivedPriv1, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	groupKeyName1 := NewGroupKeyName([]byte("group 1"))
	groupKeyName2 := NewGroupKeyName([]byte("group 2"))
	groupKeyName3 := NewGroupKeyName([]byte("group 3"))
	tv1SpendingLimit := TransactionSpendingLimit{
		GlobalDESOLimit: 10,
		AccessGroupMap: map[AccessGroupLimitKey]uint64{
			{
				AccessGroupOwnerPublicKey: *m0PublicKey,
				AccessGroupKeyName:        *groupKeyName1,
				OperationType:             AccessGroupOperationTypeCreate,
			}: 10,
		},
	}
	tv1 := _createDerivedKeyTestVector("TEST 1: (PASS) Try connecting an authorize derived key transaction "+
		"test vector for m0PublicKey before the block height authorizing access group transaction", m0Priv, m0PubBytes,
		derivedPriv1, tv1SpendingLimit, []byte{}, false, AuthorizeDerivedKeyOperationValid, 100,
		nil, nil)
	derivedPriv2, err := btcec.NewPrivateKey(btcec.S256())
	tv2SpendingLimit := TransactionSpendingLimit{
		GlobalDESOLimit: 10,
		AccessGroupMemberMap: map[AccessGroupMemberLimitKey]uint64{
			{
				AccessGroupOwnerPublicKey: *m0PublicKey,
				AccessGroupKeyName:        *groupKeyName1,
				OperationType:             AccessGroupMemberOperationTypeAdd,
			}: 10,
		},
	}
	tv2 := _createDerivedKeyTestVector("TEST 2: (PASS) Try connecting an authorize derived key transaction "+
		"test vector for m0PublicKey before the block height authorizing access group member transaction", m0Priv, m0PubBytes,
		derivedPriv2, tv2SpendingLimit, []byte{}, false, AuthorizeDerivedKeyOperationValid, 100,
		nil, nil)
	derivedPriv3, err := btcec.NewPrivateKey(btcec.S256())
	tv3SpendingLimit := TransactionSpendingLimit{
		GlobalDESOLimit:      10,
		AccessGroupMap:       tv1SpendingLimit.AccessGroupMap,
		AccessGroupMemberMap: tv2SpendingLimit.AccessGroupMemberMap,
	}
	tv3 := _createDerivedKeyTestVector("TEST 3: (PASS) Try connecting an authorize derived key transaction "+
		"test vector for m0PublicKey before the block height authorizing access group and access group member transactions",
		m0Priv, m0PubBytes, derivedPriv3, tv3SpendingLimit, []byte{}, false, AuthorizeDerivedKeyOperationValid, 100,
		nil, nil)
	derivedPriv4, err := btcec.NewPrivateKey(btcec.S256())
	tv4SpendingLimit := TransactionSpendingLimit{
		GlobalDESOLimit: 10,
		TransactionCountLimitMap: map[TxnType]uint64{
			TxnTypeNewMessage: 10,
		},
	}
	tv4 := _createDerivedKeyTestVector("TEST 4: (PASS) Try connecting an authorize derived key transaction "+
		"test vector for m0PublicKey before the block height authorizing new message transactions", m0Priv, m0PubBytes,
		derivedPriv4, tv4SpendingLimit, []byte{}, false, AuthorizeDerivedKeyOperationValid, 100,
		nil, nil)

	derivedPriv4p5, err := btcec.NewPrivateKey(btcec.S256())
	tv4p5SpendingLimit := TransactionSpendingLimit{
		IsUnlimited: true,
	}
	tv4p5 := _createDerivedKeyTestVector("Test 4.5: (PASS) Try connecting an authorize derived key transaction "+
		"test vector for m0PublicKey before the block height authorizing unlimited transactions", m0Priv, m0PubBytes,
		derivedPriv4p5, tv4p5SpendingLimit, []byte{}, false, AuthorizeDerivedKeyOperationValid, 100,
		nil, nil)

	tvv1 := []*transactionTestVector{tv1, tv2, tv3, tv4, tv4p5}
	tvb1 := NewTransactionTestVectorBlock(tvv1, nil, nil)

	// Mine 2 blocks atop of this block so that we trigger the access group fork.
	tvb2 := NewTransactionTestVectorBlock([]*transactionTestVector{}, nil, nil)
	tvb3 := NewTransactionTestVectorBlock([]*transactionTestVector{}, nil, nil)

	// Make sure neither of access group nor access group member spending limits worked prior to the block height.

	tv5 := _createAccessGroupTestVector("TEST 5: (FAIL) Try connecting an access group transaction made by "+
		"m0 registering (m0, groupName1) signed by a derived key derivedPriv1", m0Priv, m0PubBytes, m0PubBytes, groupPk1,
		groupKeyName1.ToBytes(), AccessGroupOperationTypeCreate, nil, RuleErrorAccessGroupTransactionSpendingLimitInvalid)
	tv5.getDerivedPrivateKey = func(tv *transactionTestVector, tm *transactionTestMeta) (*btcec.PrivateKey, int) {
		// Use DeSo-DER signature scheme to prevent writing anything to transaction extra data.
		return derivedPriv1, 1
	}
	// Now create access group (m0, groupName1) using m0 main private key.
	tv6 := _createAccessGroupTestVector("TEST 6: (PASS) Try connecting access group transaction made by "+
		"m0 registering (m0, groupName1) signed by m0", m0Priv, m0PubBytes, m0PubBytes, groupPk1, groupKeyName1.ToBytes(),
		AccessGroupOperationTypeCreate, nil, nil)
	// Try adding members to (m0, groupName1) from a derived key.
	//  update spending limits after block height and re-send access group and access group member transactions.
	tv7Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: groupKeyName1.ToBytes(), EncryptedKey: []byte{}, ExtraData: nil},
	}
	tv7 := _createAccessGroupMembersTestVector("TEST 7: (FAIL) Try connecting an access group member transaction made by "+
		"m0 registering (m0, groupName1) signed by a derived key derivedPriv2", m0Priv, m0PubBytes, groupKeyName1.ToBytes(), tv7Members,
		AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupMemberSpendingLimitInvalid)
	tv7.getDerivedPrivateKey = func(tv *transactionTestVector, tm *transactionTestMeta) (*btcec.PrivateKey, int) {
		// Use DeSo-DER signature scheme to prevent writing anything to transaction extra data.
		return derivedPriv2, 1
	}

	// Try creating an access group or adding members from derivedPriv3.
	tv8 := _createAccessGroupTestVector("TEST 8: (FAIL) Try connecting an access group transaction made by "+
		"m0 registering (m0, groupName2) signed by a derived key derivedPriv3", m0Priv, m0PubBytes, m0PubBytes, groupPk1,
		groupKeyName2.ToBytes(), AccessGroupOperationTypeCreate, nil, RuleErrorAccessGroupTransactionSpendingLimitInvalid)
	tv8.getDerivedPrivateKey = func(tv *transactionTestVector, tm *transactionTestMeta) (*btcec.PrivateKey, int) {
		// Use DeSo-DER signature scheme to prevent writing anything to transaction extra data.
		return derivedPriv3, 1
	}
	// Try adding members to (m0, groupName1) from a derived key.
	tv9Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: groupKeyName1.ToBytes(), EncryptedKey: []byte{}, ExtraData: nil},
	}
	tv9 := _createAccessGroupMembersTestVector("TEST 9: (FAIL) Try connecting an access group member transaction made by "+
		"m0 registering (m0, groupName1) signed by a derived key derivedPriv3", m0Priv, m0PubBytes, groupKeyName1.ToBytes(), tv9Members,
		AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupMemberSpendingLimitInvalid)
	tv9.getDerivedPrivateKey = func(tv *transactionTestVector, tm *transactionTestMeta) (*btcec.PrivateKey, int) {
		// Use DeSo-DER signature scheme to prevent writing anything to transaction extra data.
		return derivedPriv3, 1
	}

	// Authorizing new message transaction before the fork height should work because we don't restrict it.
	tv10Message := _createMessageEntry(*m0PublicKey, *groupKeyName1, *m0PublicKey, *m1PublicKey, *BaseGroupKeyName(), *m1PublicKey, []byte{1}, 1, nil)
	tv10 := _createNewMessageTestVector("TEST 10: (PASS) Try connecting a new message transaction made by m0, sending "+
		"a DM message to m1 signed by a derived key derivedPriv4", m0Priv, m0PubBytes, tv10Message, NewMessageTypeDm, NewMessageOperationCreate,
		nil)
	tv10.getDerivedPrivateKey = func(tv *transactionTestVector, tm *transactionTestMeta) (*btcec.PrivateKey, int) {
		// Use DeSo-DER signature scheme to prevent writing anything to transaction extra data.
		return derivedPriv4, 1
	}

	// Creating an access group or adding members to an access group should work for unlimited derived key 4p5
	// Try creating an access group or adding members from derivedPriv4p5.
	tv11 := _createAccessGroupTestVector("TEST 11: (PASS) Try connecting an access group transaction made by "+
		"m0 registering (m0, groupName2) signed by a derived key derivedPriv4p5", m0Priv, m0PubBytes, m0PubBytes, groupPk1,
		groupKeyName2.ToBytes(), AccessGroupOperationTypeCreate, nil, nil)
	tv11.getDerivedPrivateKey = func(tv *transactionTestVector, tm *transactionTestMeta) (*btcec.PrivateKey, int) {
		// Use DeSo-DER signature scheme to prevent writing anything to transaction extra data.
		return derivedPriv4p5, 1
	}
	// Try adding members to (m0, groupName1) from a derivedPriv4p5
	tv12Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv12 := _createAccessGroupMembersTestVector("TEST 12: (PASS) Try connecting an access group member transaction made by "+
		"m0 adding member (m1, BaseKey) to group (m0, groupName1) signed by a derived key derivedPriv4p5", m0Priv, m0PubBytes,
		groupKeyName1.ToBytes(), tv12Members, AccessGroupMemberOperationTypeAdd, nil)
	tv12.getDerivedPrivateKey = func(tv *transactionTestVector, tm *transactionTestMeta) (*btcec.PrivateKey, int) {
		// Use DeSo-DER signature scheme to prevent writing anything to transaction extra data.
		return derivedPriv4p5, 1
	}

	// Try updating the spending limit for derivedPriv3 to unlimited and make sure it can add and update members.
	tv13SpendingLimit := TransactionSpendingLimit{
		IsUnlimited: true,
	}
	tv13 := _createDerivedKeyTestVector("TEST 13: (PASS) Try connecting a derived key transaction made by "+
		"m0 updating the spending limit for derivedPriv3 to unlimited", m0Priv, m0PubBytes, derivedPriv3,
		tv13SpendingLimit, []byte{}, false, AuthorizeDerivedKeyOperationValid, 100,
		nil, nil)

	// Now try creating an access group or adding members to an access group from derivedPriv3.
	// Create access group (m0, groupName3) from derivedPriv3.
	tv14 := _createAccessGroupTestVector("TEST 14: (PASS) Try connecting an access group transaction made by "+
		"m0 registering (m0, groupName2) signed by a derived key derivedPriv3", m0Priv, m0PubBytes, m0PubBytes, groupPk1,
		groupKeyName3.ToBytes(), AccessGroupOperationTypeCreate, nil, nil)
	tv14.getDerivedPrivateKey = func(tv *transactionTestVector, tm *transactionTestMeta) (*btcec.PrivateKey, int) {
		// Use DeSo-DER signature scheme to prevent writing anything to transaction extra data.
		return derivedPriv3, 1
	}
	// Try adding members to (m0, groupName1) from a derived key.
	tv15Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: groupKeyName1.ToBytes(), EncryptedKey: []byte{}, ExtraData: nil},
	}
	tv15 := _createAccessGroupMembersTestVector("TEST 15: (PASS) Try connecting an access group member transaction made by "+
		"m0 adding member (m0, groupName1) to group (m0, groupName3) signed by a derived key derivedPriv3", m0Priv, m0PubBytes,
		groupKeyName3.ToBytes(), tv15Members, AccessGroupMemberOperationTypeAdd, nil)
	tv15.getDerivedPrivateKey = tv14.getDerivedPrivateKey

	tvv4 := []*transactionTestVector{tv5, tv6, tv7, tv8, tv9, tv10, tv11, tv12, tv13, tv14, tv15}
	tvb4 := NewTransactionTestVectorBlock(tvv4, nil, nil)

	tvbb := []*transactionTestVectorBlock{tvb1, tvb2, tvb3, tvb4}
	tes := NewTransactionTestSuite(t, tvbb, tConfig)
	tes.Run()
}

func _getDerivedKeyMetadata(t *testing.T, ownerPrivateKeyString string, derivedPublicKey []byte, expirationBlock uint64,
	limit TransactionSpendingLimit, blockHeight uint64) *AuthorizeDerivedKeyMetadata {
	require := require.New(t)

	ownerPriv, _, err := Base58CheckDecode(ownerPrivateKeyString)
	require.NoError(err)
	ownerPrivKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), ownerPriv)
	spendingLimit := limit
	accessSignature, err := _getAccessSignature(
		derivedPublicKey, expirationBlock, &spendingLimit, ownerPrivKey, blockHeight)
	require.NoError(err)
	metadata := &AuthorizeDerivedKeyMetadata{
		DerivedPublicKey: derivedPublicKey,
		ExpirationBlock:  expirationBlock,
		OperationType:    AuthorizeDerivedKeyOperationNotValid,
		AccessSignature:  accessSignature,
	}
	return metadata
}

func _setTestDerivedKeyWithAccessGroupParams(tm *transactionTestMeta) {
	tm.params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)
	tm.params.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight = uint32(0)
	tm.params.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight = uint32(0)
	tm.params.ForkHeights.DAOCoinBlockHeight = uint32(0)
	tm.params.ForkHeights.DAOCoinLimitOrderBlockHeight = uint32(0)
	tm.params.ForkHeights.OrderBookDBFetchOptimizationBlockHeight = uint32(0)
	tm.params.ForkHeights.BuyNowAndNFTSplitsBlockHeight = uint32(0)
	tm.params.ForkHeights.DerivedKeyEthSignatureCompatibilityBlockHeight = uint32(0)
	tm.params.ForkHeights.DeSoUnlimitedDerivedKeysBlockHeight = 0
	// TODO: Note that there a laziness comment in the spending limit transaction creation code.
	tm.params.ForkHeights.AssociationsAndAccessGroupsBlockHeight = 7
	tm.params.EncoderMigrationHeights = GetEncoderMigrationHeights(&tm.params.ForkHeights)
	tm.params.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&tm.params.ForkHeights)
	tm.params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true
	GlobalDeSoParams = *tm.params
}

func _createDerivedKeyTestVector(id string, userPrivateKey string, userPublicKey []byte, derivedPrivateKey *btcec.PrivateKey,
	limit TransactionSpendingLimit, memo []byte, derivedKeySignature bool, operationType AuthorizeDerivedKeyOperationType,
	expirationBlock uint64, extraData map[string][]byte, expectedConnectError error) (_tv *transactionTestVector) {

	testData := &AuthorizeDerivedKeyTestData{
		userPrivateKey:           userPrivateKey,
		userPublicKey:            userPublicKey,
		expectedConnectError:     expectedConnectError,
		extraData:                extraData,
		transactionSpendingLimit: limit,
		memo:                     memo,
		operationType:            operationType,
		expirationBlock:          expirationBlock,
		derivedKeySignature:      derivedKeySignature,
		derivedPrivateKey:        derivedPrivateKey,
	}
	return &transactionTestVector{
		id:         transactionTestIdentifier(id),
		inputSpace: testData,
		getTransaction: func(tv *transactionTestVector, tm *transactionTestMeta) (*MsgDeSoTxn, error) {
			dataSpace := tv.inputSpace.(*AuthorizeDerivedKeyTestData)
			txn, err := _createSignedAuthorizeDerivedKeyTransaction(tm.t, tm.chain, tm.mempool, dataSpace)
			require.NoError(tm.t, err)
			return txn, dataSpace.expectedConnectError
		},
		verifyConnectUtxoViewEntry:    nil,
		verifyDisconnectUtxoViewEntry: nil,
		verifyDbEntry:                 nil,
	}
}

func _createSignedAuthorizeDerivedKeyTransaction(t *testing.T, chain *Blockchain, mempool *DeSoMempool,
	dataSpace *AuthorizeDerivedKeyTestData) (_txn *MsgDeSoTxn, _err error) {

	require := require.New(t)
	// Create the transaction.
	// TODO: This is a little lazy and will result in a disconnect error if the transaction is submitted in the
	// 	blockheight that's 1 lesser than the fork height.
	blockHeight := uint64(chain.blockTip().Height + 1)
	spendingLimitBytes, err := dataSpace.transactionSpendingLimit.ToBytes(blockHeight)
	require.NoError(err)
	spendingLimitsHex := hex.EncodeToString(spendingLimitBytes)
	derivedPk := dataSpace.derivedPrivateKey.PubKey().SerializeCompressed()
	derivedKeyMetadata := _getDerivedKeyMetadata(t, m0Priv, derivedPk, dataSpace.expirationBlock,
		dataSpace.transactionSpendingLimit, blockHeight)
	deleteKey := dataSpace.operationType == AuthorizeDerivedKeyOperationNotValid
	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateAuthorizeDerivedKeyTxn(
		dataSpace.userPublicKey, derivedPk, dataSpace.expirationBlock, derivedKeyMetadata.AccessSignature,
		deleteKey, dataSpace.derivedKeySignature, dataSpace.extraData, dataSpace.memo, spendingLimitsHex,
		10, mempool, []*DeSoOutput{})
	require.NoError(err)
	require.Equal(totalInputMake, changeAmountMake+feesMake)

	if dataSpace.derivedKeySignature {
		derivedPriv := Base58CheckEncode(dataSpace.derivedPrivateKey.Serialize(), true, chain.params)
		_signTxnWithDerivedKey(t, txn, derivedPriv)
	} else {
		_signTxn(t, txn, dataSpace.userPrivateKey)
	}
	return txn, nil
}
