package lib

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

const (
	BasicTransferRecipient = "RECIPIENT"
	BasicTransferAmount    = "AMOUNT"
)

func _doTxn(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	TransactorPublicKeyBase58Check string,
	TransactorPrivKeyBase58Check string,
	isDerivedTransactor bool,
	txnType TxnType,
	txnMeta DeSoTxnMetadata,
	extraData map[string]interface{}) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	assert := assert.New(testMeta.t)
	require := require.New(testMeta.t)
	_ = assert
	_ = require

	transactorPublicKey, _, err := Base58CheckDecode(TransactorPublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, nil, testMeta.chain.snapshot)
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
		transactionSpendingLimitBytes, err := transactionSpendingLimit.ToBytes()
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
		utxoOpExpectation++
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

	require.NoError(utxoView.FlushToDb(0))

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
	ExtraData map[string]interface{}) {
	testMeta.expectedSenderBalances = append(testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, TransactorPublicKeyBase58Check))

	currentOps, currentTxn, _, err := _doTxn(testMeta,
		feeRateNanosPerKB, TransactorPublicKeyBase58Check, TransactorPrivateKeyBase58Check, IsDerivedTransactor,
		TxnType, TxnMeta, ExtraData)

	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
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
	isDeleted bool) (*AuthorizeDerivedKeyMetadata, *btcec.PrivateKey) {
	require := require.New(t)

	// Generate a random derived key pair
	derivedPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err, "_getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit: Error generating a derived key pair")
	derivedPublicKey := derivedPrivateKey.PubKey().SerializeCompressed()

	// Create access signature
	expirationBlockByte := EncodeUint64(expirationBlock)
	accessBytes := append(derivedPublicKey, expirationBlockByte[:]...)

	var transactionSpendingLimitBytes []byte
	transactionSpendingLimitBytes, err = transactionSpendingLimit.ToBytes()
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

func _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
	t *testing.T,
	ownerPrivateKey *btcec.PrivateKey,
	expirationBlock uint64,
	transactionSpendingLimit *TransactionSpendingLimit,
	derivedPrivateKey *btcec.PrivateKey,
	isDeleted bool) (*AuthorizeDerivedKeyMetadata, *btcec.PrivateKey) {
	require := require.New(t)

	derivedPublicKey := derivedPrivateKey.PubKey().SerializeCompressed()

	// Create access signature
	expirationBlockByte := EncodeUint64(expirationBlock)
	accessBytes := append(derivedPublicKey, expirationBlockByte[:]...)

	transactionSpendingLimitBytes, err := transactionSpendingLimit.ToBytes()
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
	ownerPrivateKey *btcec.PrivateKey) ([]byte, error) {
	accessBytes := append(derivedPublicKey, EncodeUint64(expirationBlock)...)
	transactionSpendingLimitBytes, err := transactionSpendingLimit.ToBytes()
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

	transactionSpendingLimitBytes, err := transactionSpendingLimit.ToBytes()
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

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

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

	// We create this inline function for attempting a basic transfer.
	// This helps us test that the DeSoChain recognizes a derived key.
	_basicTransfer := func(senderPk []byte, recipientPk []byte, signerPriv string, utxoView *UtxoView,
		mempool *DeSoMempool, isSignerSender bool) ([]*UtxoOperation, *MsgDeSoTxn, error) {

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
			utxoView, err = NewUtxoView(db, params, nil, chain.snapshot)
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
	_verifyTestWithExtraData := func(derivedPublicKey []byte, expirationBlockExpected uint64,
		balanceExpected uint64, operationTypeExpected AuthorizeDerivedKeyOperationType, extraData map[string][]byte,
		mempool *DeSoMempool) {
		// Verify that expiration block was persisted in the db or is in mempool utxoView
		if mempool == nil {
			derivedKeyEntry := DBGetOwnerToDerivedKeyMapping(db, chain.snapshot, *NewPublicKey(senderPkBytes), *NewPublicKey(derivedPublicKey))
			// If we removed the derivedKeyEntry from utxoView altogether, it'll be nil.
			// To pass the tests, we initialize it to a default struct.
			if derivedKeyEntry == nil || derivedKeyEntry.isDeleted {
				derivedKeyEntry = &DerivedKeyEntry{*NewPublicKey(senderPkBytes), *NewPublicKey(derivedPublicKey), 0, AuthorizeDerivedKeyOperationValid, nil, transactionSpendingLimit, nil, false}
			}
			assert.Equal(derivedKeyEntry.ExpirationBlock, expirationBlockExpected)
			assert.Equal(derivedKeyEntry.OperationType, operationTypeExpected)
		} else {
			utxoView, err := mempool.GetAugmentedUniversalView()
			require.NoError(err)
			derivedKeyEntry := utxoView._getDerivedKeyMappingForOwner(senderPkBytes, derivedPublicKey)
			// If we removed the derivedKeyEntry from utxoView altogether, it'll be nil.
			// To pass the tests, we initialize it to a default struct.
			if derivedKeyEntry == nil || derivedKeyEntry.isDeleted {
				derivedKeyEntry = &DerivedKeyEntry{*NewPublicKey(senderPkBytes), *NewPublicKey(derivedPublicKey), 0, AuthorizeDerivedKeyOperationValid, nil, transactionSpendingLimit, nil, false}
			}
			assert.Equal(derivedKeyEntry.ExpirationBlock, expirationBlockExpected)
			assert.Equal(derivedKeyEntry.OperationType, operationTypeExpected)
		}

		// Verify that the balance of recipient is equal to expected balance
		assert.Equal(_getBalance(t, chain, mempool, recipientPkString), balanceExpected)
	}

	_verifyTest := func(derivedPublicKey []byte, expirationBlockExpected uint64,
		balanceExpected uint64, operationTypeExpected AuthorizeDerivedKeyOperationType, mempool *DeSoMempool) {
		_verifyTestWithExtraData(derivedPublicKey, expirationBlockExpected, balanceExpected,
			operationTypeExpected, nil, mempool)
	}

	// We will use these to keep track of added utxo ops and txns
	testUtxoOps := [][]*UtxoOperation{}
	testTxns := []*MsgDeSoTxn{}

	// Just for the sake of consistency, we run the _basicTransfer on unauthorized
	// derived key. It should fail since blockchain hasn't seen this key yet.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key")
	}
	// Attempt sending an AuthorizeDerivedKey txn signed with an invalid private key.
	// This must fail because the txn has to be signed either by owner or derived key.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn signed with an unauthorized private key.")
	}
	// Attempt sending an AuthorizeDerivedKey txn where access signature is signed with
	// an invalid private key. This must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn signed with an invalid access signature.")
	}
	// Check basic transfer signed with still unauthorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key")
	}
	// Now attempt to send the same transaction but signed with the correct derived key.
	// This must pass. The new derived key will be flushed to the db here.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
		_verifyTestWithExtraData(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 0, AuthorizeDerivedKeyOperationValid, extraData, nil)
		derivedKeyEntry := DBGetOwnerToDerivedKeyMapping(db, chain.snapshot, *NewPublicKey(senderPkBytes), *NewPublicKey(authTxnMeta.DerivedPublicKey))
		require.Equal(derivedKeyEntry.ExtraData["test"], []byte("result"))
		fmt.Println("Passed connecting AuthorizeDerivedKey txn signed with an authorized private key. Flushed to Db.")
	}
	// Check basic transfer signed by the owner key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 1, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with owner key. Flushed to Db.")
	}
	// Check basic transfer signed with now authorized derived key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with authorized derived key. Flushed to Db.")
	}
	// Check basic transfer signed with a random key.
	// Should fail. Well... theoretically, it could pass in a distant future.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
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
			utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(0), "SimpleDisconnect: Index: %v", testIndex)
		}

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txns. Flushed to Db.")
	}
	// After disconnecting, check basic transfer signed with unauthorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key after disconnecting")
	}
	// Connect all txns to a single UtxoView flushing only at the end.
	{
		// Create a new UtxoView
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed re-connecting all txn to a single utxoView")
	}
	// Check basic transfer signed with a random key.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Fail basic transfer signed with random key.")
	}
	// Disconnect all txns on a single UtxoView flushing only at the end
	{
		// Create a new UtxoView
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
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
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool")
	}
	// Check basic transfer signed with a random key, when passing mempool.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, nil, mempool, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Fail basic transfer signed with random key with mempool.")
	}
	// Remove all the transactions from the mempool. Should pass.
	{
		for _, burnTxn := range testTxns {
			mempool.inefficientRemoveTransaction(burnTxn)
		}
		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed removing all txn from the mempool.")
	}
	// After disconnecting, check basic transfer signed with unauthorized derived key.
	// Should fail.
	{
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, nil, mempool, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, mempool)
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
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
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
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		fmt.Println("Passed basic transfer signed with owner key. Flushed to Db.")
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 3, AuthorizeDerivedKeyOperationValid, nil)
	}
	// Check basic transfer signed with authorized derived key. Now the auth txn is persisted in the db.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 4, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with authorized derived key. Flushed to Db.")
	}
	// Check basic transfer signed with a random key.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 4, AuthorizeDerivedKeyOperationValid, nil)
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
			utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(0), "SimpleDisconnect: Index: %v", testIndex)
		}

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
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
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)

		// We're not persisting in the db so balance should remain at 2.
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with owner key.")
	}
	// Check basic transfer signed with expired authorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
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
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, 0, 2, AuthorizeDerivedKeyOperationValid, nil)
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
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
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
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// We're persisting to the db so balance should change to 3.
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with derived key.")
	}
	// Send a de-authorize transaction signed with a derived key.
	// Doesn't matter if it's signed by the owner or not, once a isDeleted
	// txn appears, the key should be forever expired. This must pass.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed connecting AuthorizeDerivedKey txn with isDeleted signed with an authorized private key.")
	}
	// Check basic transfer signed with new authorized derived key.
	// Now that key has been de-authorized this must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed basic transfer signed with de-authorized derived key.")
	}
	// Sanity check basic transfer signed by the owner key.
	// Should succeed.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// Balance should change to 4
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed basic transfer signed with owner key.")
	}
	// Send an authorize transaction signed with a derived key.
	// Since we've already deleted this derived key, this must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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

		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
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
			utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(0), "SimpleDisconnect: Index: %v", testIndex)
		}

		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
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
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool")
	}
	// Check adding basic transfer to mempool signed with new authorized derived key.
	// Now that key has been de-authorized this must fail.
	{
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, nil, mempool, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, mempool)
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

		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, mempool)
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
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed basic transfer signed with de-authorized derived key.")
	}
	// Attempt re-authorizing a previously de-authorized derived key.
	// Since we've already deleted this derived key, this must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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

		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn with de-authorized private key.")
	}
	// Sanity check basic transfer signed by the owner key.
	// Should succeed.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)

		// Balance should change to 4
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
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
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
	_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
	fmt.Println("Successfuly run TestAuthorizeDerivedKeyBasic()")
}

func TestAuthorizeDerivedKeyBasicWithTransactionLimits(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight = uint32(0)

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
	authTxnMeta, derivedPriv := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(
		t, senderPriv, 6, transactionSpendingLimit, false)
	derivedPrivBase58Check := Base58CheckEncode(derivedPriv.Serialize(), true, params)
	derivedPkBytes := derivedPriv.PubKey().SerializeCompressed()
	fmt.Println("Derived public key:", hex.EncodeToString(derivedPkBytes))

	// We create this inline function for attempting a basic transfer.
	// This helps us test that the DeSoChain recognizes a derived key.
	_basicTransfer := func(senderPk []byte, recipientPk []byte, signerPriv string, utxoView *UtxoView,
		mempool *DeSoMempool, isSignerSender bool) ([]*UtxoOperation, *MsgDeSoTxn, error) {

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
			utxoView, err = NewUtxoView(db, params, nil, chain.snapshot)
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
	_verifyTest := func(derivedPublicKey []byte, expirationBlockExpected uint64,
		balanceExpected uint64, operationTypeExpected AuthorizeDerivedKeyOperationType, mempool *DeSoMempool) {
		// Verify that expiration block was persisted in the db or is in mempool utxoView
		if mempool == nil {
			derivedKeyEntry := DBGetOwnerToDerivedKeyMapping(db, chain.snapshot, *NewPublicKey(senderPkBytes), *NewPublicKey(derivedPublicKey))
			// If we removed the derivedKeyEntry from utxoView altogether, it'll be nil.
			// To pass the tests, we initialize it to a default struct.
			if derivedKeyEntry == nil || derivedKeyEntry.isDeleted {
				derivedKeyEntry = &DerivedKeyEntry{
					*NewPublicKey(senderPkBytes), *NewPublicKey(derivedPublicKey), 0, AuthorizeDerivedKeyOperationValid, nil, transactionSpendingLimit, nil, false}
			}
			assert.Equal(derivedKeyEntry.ExpirationBlock, expirationBlockExpected)
			assert.Equal(derivedKeyEntry.OperationType, operationTypeExpected)
		} else {
			utxoView, err := mempool.GetAugmentedUniversalView()
			require.NoError(err)
			derivedKeyEntry := utxoView._getDerivedKeyMappingForOwner(senderPkBytes, derivedPublicKey)
			// If we removed the derivedKeyEntry from utxoView altogether, it'll be nil.
			// To pass the tests, we initialize it to a default struct.
			if derivedKeyEntry == nil || derivedKeyEntry.isDeleted {
				derivedKeyEntry = &DerivedKeyEntry{*NewPublicKey(senderPkBytes), *NewPublicKey(derivedPublicKey), 0, AuthorizeDerivedKeyOperationValid, nil, transactionSpendingLimit, nil, false}
			}
			assert.Equal(derivedKeyEntry.ExpirationBlock, expirationBlockExpected)
			assert.Equal(derivedKeyEntry.OperationType, operationTypeExpected)
		}

		// Verify that the balance of recipient is equal to expected balance
		assert.Equal(_getBalance(t, chain, mempool, recipientPkString), balanceExpected)
	}

	// We will use these to keep track of added utxo ops and txns
	testUtxoOps := [][]*UtxoOperation{}
	testTxns := []*MsgDeSoTxn{}

	// Just for the sake of consistency, we run the _basicTransfer on unauthorized
	// derived key. It should fail since blockchain hasn't seen this key yet.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key")
	}
	// Attempt sending an AuthorizeDerivedKey txn signed with an invalid private key.
	// This must fail because the txn has to be signed either by owner or derived key.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn signed with an unauthorized private key.")
	}
	// Attempt sending an AuthorizeDerivedKey txn where access signature is signed with
	// an invalid private key. This must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn signed with an invalid access signature.")
	}
	// Check basic transfer signed with still unauthorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key")
	}
	// Now attempt to send the same transaction but signed with the correct derived key.
	// This must pass. The new derived key will be flushed to the db here.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed connecting AuthorizeDerivedKey txn signed with an authorized private key. Flushed to Db.")
	}
	// Check basic transfer signed by the owner key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 1, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with owner key. Flushed to Db.")
	}
	// Check basic transfer signed with now authorized derived key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with authorized derived key. Flushed to Db.")
	}
	// Check basic transfer signed with a random key.
	// Should fail. Well... theoretically, it could pass in a distant future.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
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
			utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(0), "SimpleDisconnect: Index: %v", testIndex)
		}

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txns. Flushed to Db.")
	}
	// After disconnecting, check basic transfer signed with unauthorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key after disconnecting")
	}
	// Connect all txns to a single UtxoView flushing only at the end.
	{
		// Create a new UtxoView
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed re-connecting all txn to a single utxoView")
	}
	// Check basic transfer signed with a random key.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Fail basic transfer signed with random key.")
	}
	// Disconnect all txns on a single UtxoView flushing only at the end
	{
		// Create a new UtxoView
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
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
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool")
	}
	// Check basic transfer signed with a random key, when passing mempool.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, nil, mempool, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Fail basic transfer signed with random key with mempool.")
	}
	// Remove all the transactions from the mempool. Should pass.
	{
		for _, burnTxn := range testTxns {
			mempool.inefficientRemoveTransaction(burnTxn)
		}
		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed removing all txn from the mempool.")
	}
	// After disconnecting, check basic transfer signed with unauthorized derived key.
	// Should fail.
	{
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, nil, mempool, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, mempool)
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
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
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
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		fmt.Println("Passed basic transfer signed with owner key. Flushed to Db.")
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 3, AuthorizeDerivedKeyOperationValid, nil)
	}
	// Check basic transfer signed with authorized derived key. Now the auth txn is persisted in the db.
	// Should succeed. Flush to db.
	{
		// We authorize an additional basic transfer before the derived key can do this.

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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

		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 4, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with authorized derived key. Flushed to Db.")
	}
	// Check basic transfer signed with a random key.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 4, AuthorizeDerivedKeyOperationValid, nil)
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
			utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(0), "SimpleDisconnect: Index: %v", testIndex)
		}

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
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
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)

		// We're not persisting in the db so balance should remain at 2.
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with owner key.")
	}
	// Check basic transfer signed with expired authorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed a txn signed with an expired derived key.")
	}

	// Reset testUtxoOps and testTxns so we can test more transactions
	testUtxoOps = [][]*UtxoOperation{}
	testTxns = []*MsgDeSoTxn{}
	// Get another AuthorizeDerivedKey txn metadata with expiration at block 10
	// We will try to de-authorize this key with a txn before it expires.
	authTxnMetaDeAuth, derivedDeAuthPriv := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(t, senderPriv, 10, transactionSpendingLimit, false)
	derivedPrivDeAuthBase58Check := Base58CheckEncode(derivedDeAuthPriv.Serialize(), true, params)
	derivedDeAuthPkBytes := derivedDeAuthPriv.PubKey().SerializeCompressed()
	fmt.Println("Derived public key:", hex.EncodeToString(derivedDeAuthPkBytes))
	// Send an authorize transaction signed with the correct derived key.
	// This must pass.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, 0, 2, AuthorizeDerivedKeyOperationValid, nil)
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
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, mempool)
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
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// We're persisting to the db so balance should change to 3.
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with derived key.")
	}
	// Send a de-authorize transaction signed with a derived key.
	// Doesn't matter if it's signed by the owner or not, once a isDeleted
	// txn appears, the key should be forever expired. This must pass.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed connecting AuthorizeDerivedKey txn with isDeleted signed with an authorized private key.")
	}
	// Check basic transfer signed with new authorized derived key.
	// Now that key has been de-authorized this must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed basic transfer signed with de-authorized derived key.")
	}
	// Sanity check basic transfer signed by the owner key.
	// Should succeed.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb(0))
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// Balance should change to 4
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed basic transfer signed with owner key.")
	}
	// Send an authorize transaction signed with a derived key.
	// Since we've already deleted this derived key, this must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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

		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
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
			utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(0), "SimpleDisconnect: Index: %v", testIndex)
		}

		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 2, AuthorizeDerivedKeyOperationValid, nil)
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
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool")
	}
	// Check adding basic transfer to mempool signed with new authorized derived key.
	// Now that key has been de-authorized this must fail.
	{
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, nil, mempool, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, mempool)
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

		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, mempool)
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
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed basic transfer signed with de-authorized derived key.")
	}
	// Attempt re-authorizing a previously de-authorized derived key.
	// Since we've already deleted this derived key, this must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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

		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn with de-authorized private key.")
	}
	// Sanity check basic transfer signed by the owner key.
	// Should succeed.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)

		// Balance should change to 4
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
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
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
	_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
	fmt.Println("Successfuly run TestAuthorizeDerivedKeyBasicWithTransactionLimits()")
}

func TestAuthorizedDerivedKeyWithTransactionLimitsHardcore(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight = uint32(0)
	params.ForkHeights.DAOCoinBlockHeight = uint32(0)
	params.ForkHeights.DAOCoinLimitOrderBlockHeight = uint32(0)
	params.ForkHeights.OrderBookDBFetchOptimizationBlockHeight = uint32(0)
	params.ForkHeights.BuyNowAndNFTSplitsBlockHeight = uint32(0)

	params.ParamUpdaterPublicKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

	// Mine a few blocks to give the senderPkString some money.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
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

	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 100)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 100)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 100)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m3Pub, senderPrivString, 100)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m4Pub, senderPrivString, 100)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 100)

	m0Balance := 100
	m1Balance := 100
	m2Balance := 100
	m3Balance := 100
	m4Balance := 100
	paramUpdaterBalance := 100

	_, _, _, _, _, _ = m0Balance, m1Balance, m2Balance, m3Balance, m4Balance, paramUpdaterBalance
	// Create profiles for M0 and M1
	// Create a profile for m0
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
		)

		// Create a profile for m1
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
		)
	}

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
	authTxnMeta, derivedPriv := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(
		t, m1PrivateKey, 6, transactionSpendingLimit, false)
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
		)
	}

	// Derived key for M1 mints 100 M1 DAO coins
	{
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
		)
	}

	// Derived key for M1 transfers 10 M1 DAO Coins to M0
	{
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
		)
	}

	// Now the derived key can't do anything else for M1 DAO coin
	{
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
	newAuthTxnMeta, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(t, m1PrivateKey, 6, newTransactionSpendingLimit, derivedPriv, false)

	// Okay so let's update the derived key, but now let's let the derived key do any operation on our DAO coin
	{
		extraData := make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = newTransactionSpendingLimit
		_doTxnWithTestMeta(
			testMeta,
			10,
			m1Pub,
			derivedPrivBase58Check,
			true,
			TxnTypeAuthorizeDerivedKey,
			newAuthTxnMeta,
			extraData,
		)
	}

	// Updating the transfer restriction status should work
	{
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
		)
	}

	// Burning some DAO coins should work
	{
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
	m0AuthTxnMeta, derived0Priv := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(t, m0PrivateKey, 6, m0TransactionSpendingLimit, false)
	derived0PrivBase58Check := Base58CheckEncode(derived0Priv.Serialize(), true, params)
	derived0PublicKeyBase58Check := Base58CheckEncode(m0AuthTxnMeta.DerivedPublicKey, false, params)
	// Okay let's have M0 authorize a derived key that doesn't allow anything to show errors
	{
		extraData := make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = m0TransactionSpendingLimit
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			m0AuthTxnMeta,
			extraData,
		)
	}

	{
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
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyTxnSpendsMoreThanGlobalDESOLimit)
	}

	// Okay so now we update the derived key to have enough DESO to do this, but don't give it the ability to perform
	// any creator coin transactions
	m0TransactionSpendingLimit.GlobalDESOLimit = 15
	m0AuthTxnMetaWithSpendingLimitTxn, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
		t, m0PrivateKey, 6, m0TransactionSpendingLimit, derived0Priv, false)

	{
		extraData := make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = m0TransactionSpendingLimit
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			m0AuthTxnMetaWithSpendingLimitTxn,
			extraData,
		)
	}

	{
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
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyCreatorCoinOperationNotAuthorized)
	}

	// Okay so now we update the derived key to have enough DESO to do this, but don't give it the ability to perform
	// any creator coin transactions
	m0TransactionSpendingLimit.TransactionCountLimitMap[TxnTypeCreatorCoin] = 1
	m0AuthTxnMetaWithCCTxn, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(t, m0PrivateKey, 6, m0TransactionSpendingLimit, derived0Priv, false)

	{
		extraData := make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = m0TransactionSpendingLimit
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			m0AuthTxnMetaWithCCTxn,
			extraData,
		)
	}

	{
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
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyCreatorCoinOperationNotAuthorized)
	}

	// Okay now let's just let this derived key do his single transaction, but then it won't be able to do anything else
	// Okay so now we update the derived key to have enough DESO to do this, but don't give it the ability to perform
	// any creator coin transactions
	m0TransactionSpendingLimit.CreatorCoinOperationLimitMap[MakeCreatorCoinOperationLimitKey(*m1PKID, BuyCreatorCoinOperation)] = 1
	m0TransactionSpendingLimit.TransactionCountLimitMap = map[TxnType]uint64{}
	m0AuthTxnMetaWithCCOpTxn, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(t, m0PrivateKey, 6, m0TransactionSpendingLimit, derived0Priv, false)
	{
		extraData := make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = m0TransactionSpendingLimit
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			m0Priv,
			false,
			TxnTypeAuthorizeDerivedKey,
			m0AuthTxnMetaWithCCOpTxn,
			extraData,
		)
	}

	// Derived Key tries to spend more than global deso limit
	{
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
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyTxnSpendsMoreThanGlobalDESOLimit)
	}

	{
		derivedKeyEntry := DBGetOwnerToDerivedKeyMapping(db, chain.snapshot, *NewPublicKey(m0PkBytes), *NewPublicKey(m0AuthTxnMeta.DerivedPublicKey))
		require.Equal(derivedKeyEntry.TransactionSpendingLimitTracker.GlobalDESOLimit, uint64(15))
		require.Equal(derivedKeyEntry.TransactionSpendingLimitTracker.CreatorCoinOperationLimitMap[MakeCreatorCoinOperationLimitKey(*m1PKID, BuyCreatorCoinOperation)], uint64(1))
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
		)
		// Let's confirm that the global deso limit has been reduced on the tracker
		derivedKeyEntry = DBGetOwnerToDerivedKeyMapping(db, chain.snapshot, *NewPublicKey(m0PkBytes), *NewPublicKey(m0AuthTxnMeta.DerivedPublicKey))
		require.Equal(derivedKeyEntry.TransactionSpendingLimitTracker.GlobalDESOLimit, uint64(4)) // 15 - (10 + 1) (CC buy + fee)
		require.Equal(derivedKeyEntry.TransactionSpendingLimitTracker.CreatorCoinOperationLimitMap[MakeCreatorCoinOperationLimitKey(*m1PKID, BuyCreatorCoinOperation)], uint64(0))
	}

	var post1Hash *BlockHash
	// Create a buy now NFT and test that the derived key can't spend greater than their global DESO limit to buy it.
	{
		var bodyBytes []byte
		bodyBytes, err = json.Marshal(&DeSoBodySchema{Body: "test NFT"})
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
		)
		post1Hash = testMeta.txns[len(testMeta.txns)-1].Hash()
	}

	{
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
		)
	}
	{
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
		m0AuthTxnMetaWithNFTBidOpTxn, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
			t,
			m0PrivateKey,
			6,
			nftBidSpendingLimit,
			derived0Priv,
			false,
		)

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
		)
	}

	// Derived key tries to buy now, but fails
	{
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
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyTxnSpendsMoreThanGlobalDESOLimit)
	}
	// M0 increases the global DESO limit to 6
	{
		globalDESOSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: 6,
		}
		m0AuthTxnMetaWithGlobalDESOLimitTxn, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(t, m0PrivateKey, 6, globalDESOSpendingLimit, derived0Priv, false)

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
		)
	}
	// Derived key can buy
	{
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
		)
		// Let's confirm that the global deso limit has been reduced on the tracker
		derivedKeyEntry := DBGetOwnerToDerivedKeyMapping(db, chain.snapshot, *NewPublicKey(m0PkBytes), *NewPublicKey(m0AuthTxnMeta.DerivedPublicKey))
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
		m0AuthTxnMetaWithGlobalDESOLimitTxn, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(t, m0PrivateKey, 6, globalDESOSpendingLimit, derived0Priv, false)

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
		)
	}

	// Derived Key can mint NFT
	{
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
		)
	}

	// Send the derived key some money
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, derived0PublicKeyBase58Check, senderPrivString, 100)
	// Derived key can spend its own money
	{
		derivedKeyEntryBefore := DBGetOwnerToDerivedKeyMapping(db, chain.snapshot, *NewPublicKey(m0PkBytes), *NewPublicKey(m0AuthTxnMeta.DerivedPublicKey))
		require.Equal(derivedKeyEntryBefore.TransactionSpendingLimitTracker.TransactionCountLimitMap[TxnTypeBasicTransfer], uint64(0))
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
			})
		derivedKeyEntryAfter := DBGetOwnerToDerivedKeyMapping(db, chain.snapshot, *NewPublicKey(m0PkBytes), *NewPublicKey(m0AuthTxnMeta.DerivedPublicKey))
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
		_, _, _, err = _doTxn(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeDAOCoinLimitOrder,
			metadata,
			nil,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyDAOCoinLimitOrderNotAuthorized)

		globalDESOSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: 6,
			DAOCoinLimitOrderLimitMap: map[DAOCoinLimitOrderLimitKey]uint64{
				MakeDAOCoinLimitOrderLimitKey(*m1PKID, ZeroPKID): 1,
			},
		}
		m0AuthTxnMetaWithGlobalDESOLimitTxn, _ := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(t, m0PrivateKey, 6, globalDESOSpendingLimit, derived0Priv, false)

		// Authorize derived key with a Limit Order spending limit of 1
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
		)

		// Submitting a Limit Order with the buyer and seller reversed won't work.
		metadata.BuyingDAOCoinCreatorPublicKey = &ZeroPublicKey
		metadata.SellingDAOCoinCreatorPublicKey = NewPublicKey(m1PkBytes)
		_, _, _, err = _doTxn(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeDAOCoinLimitOrder,
			metadata,
			nil,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyDAOCoinLimitOrderNotAuthorized)

		// Submitting with the authorized buyer and seller should work
		metadata.SellingDAOCoinCreatorPublicKey = &ZeroPublicKey
		metadata.BuyingDAOCoinCreatorPublicKey = NewPublicKey(m1PkBytes)
		_doTxnWithTestMeta(
			testMeta,
			10,
			m0Pub,
			derived0PrivBase58Check,
			true,
			TxnTypeDAOCoinLimitOrder,
			metadata,
			nil,
		)

		var orders []*DAOCoinLimitOrderEntry
		orders, err = DBGetAllDAOCoinLimitOrders(db)
		require.NoError(err)
		require.Len(orders, 1)
		require.Equal(*orders[0], DAOCoinLimitOrderEntry{
			OrderID:                   orders[0].OrderID,
			TransactorPKID:            utxoView.GetPKIDForPublicKey(m0PkBytes).PKID,
			BuyingDAOCoinCreatorPKID:  m1PKID,
			SellingDAOCoinCreatorPKID: &ZeroPKID,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: metadata.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			QuantityToFillInBaseUnits:                 metadata.QuantityToFillInBaseUnits,
			BlockHeight:                               savedHeight,
			OperationType:                             DAOCoinLimitOrderOperationTypeBID,
			FillType:                                  DAOCoinLimitOrderFillTypeGoodTillCancelled,
		})

		// Cancelling an order should fail with an authorization failure error code if the derived key isn't authorized
		// to trade the buying and selling coins
		orderID := *orders[0].OrderID
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
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyDAOCoinLimitOrderNotAuthorized)

		// Re-authorize the derived key with a spending limit of 1 for the buying and selling coins
		m0AuthTxnMetaWithGlobalDESOLimitTxn, _ = _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimitAndDerivedPrivateKey(
			t,
			m0PrivateKey,
			6,
			globalDESOSpendingLimit,
			derived0Priv,
			false,
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
		)
		orders, err = DBGetAllDAOCoinLimitOrders(db)
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
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorDerivedKeyInvalidDAOCoinLimitOrderOrderID)
	}

	// M0 deauthorizes the derived key
	{
		emptyTransactionSpendingLimit := &TransactionSpendingLimit{}
		accessSignature, err := _getAccessSignature(m0AuthTxnMeta.DerivedPublicKey, 6, emptyTransactionSpendingLimit, m0PrivateKey)
		require.NoError(err)
		metadata := &AuthorizeDerivedKeyMetadata{
			DerivedPublicKey: m0AuthTxnMeta.DerivedPublicKey,
			ExpirationBlock:  6,
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
			})
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_executeAllTestRollbackAndFlush(testMeta)
}
