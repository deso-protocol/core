package lib

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"os"
	"reflect"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	merkletree "github.com/laser/go-merkle-tree"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "net/http/pprof"
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

func TestBalanceModel(t *testing.T) {
	BalanceModelBlockHeight = 0

	// Basic transfers.
	TestBasicTransfer(t)
	TestBasicTransferReorg(t)
	TestValidateBasicTransfer(t)

	// Diamonds.
	TestDeSoDiamonds(t)
	TestDeSoDiamondErrorCases(t)

	// Global params.
	TestUpdateGlobalParams(t)

	// Posts, profiles, likes, follows, messages.
	TestSubmitPost(t)
	TestUpdateProfile(t)
	TestSpamUpdateProfile(t)
	TestUpdateProfileChangeBack(t)
	TestLikeTxns(t)
	// TestFollowTxns(t)
	// TestPrivateMessage(t)
	//
	//	// Creator coins.
	//	TestCreatorCoinTransferSimple_DeSoFounderReward(t)
	//	TestCreatorCoinTransferWithSwapIdentity(t)
	//	TestCreatorCoinTransferWithSmallBalancesLeftOver(t)
	//	TestCreatorCoinTransferWithMaxTransfers(t)
	//	TestCreatorCoinTransferBelowMinThreshold(t)
	//	TestCreatorCoinBuySellSimple_DeSoFounderReward(t)
	//	TestCreatorCoinSelfBuying_DeSoAndCreatorCoinFounderReward(t)
	//	TestCreatorCoinTinyFounderRewardBuySellAmounts_DeSoFounderReward(t)
	//	TestCreatorCoinLargeFounderRewardBuySellAmounts(t)
	//	TestCreatorCoinAroundThresholdBuySellAmounts(t)
	//	TestSalomonSequence(t)
	//	TestCreatorCoinBigBuyAfterSmallBuy(t)
	//	TestCreatorCoinBigBigBuyBigSell(t)
	//
	//	// Swap identity.
	//	TestSwapIdentityNOOPCreatorCoinBuySimple(t)
	//	TestSwapIdentityCreatorCoinBuySimple(t)
	//	TestSwapIdentityFailureCases(t)
	// TestSwapIdentityMain(t)
	//	TestSwapIdentityWithFollows(t)
	//
	//	// NFTs.
	// TestNFTBasic(t)
	//	TestNFTRoyaltiesAndSpendingOfBidderUTXOs(t)
	//	TestNFTSerialNumberZeroBid(t)
	//	TestNFTMinimumBidAmount(t)
	//	TestNFTCreatedIsNotForSale(t)
	//	TestNFTMoreErrorCases(t)
	//	TestNFTBidsAreCanceledAfterAccept(t)
	//	TestNFTDifferentMinBidAmountSerialNumbers(t)
	//	TestNFTMaxCopiesGlobalParam(t)
	//	TestNFTPreviousOwnersCantAcceptBids(t)
	//	TestNFTTransfersAndBurns(t)
	//
	//	// Derived keys.
	//	TestAuthorizeDerivedKeyBasic(t)
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

		blockHeight := chain.blockTip().Height + 1

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
		utxoView, _ := NewUtxoView(db, params, nil)
		utxoView.GlobalParamsEntry.MinimumNetworkFeeNanosPerKB = 1
		txHash := txn.Hash()
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
				true /*verifySignatures*/, false /*ignoreUtxos*/)
		require.Error(err)
		if blockHeight < BalanceModelBlockHeight {
			require.Contains(err.Error(), RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey)
		} else {
			require.Contains(err.Error(), RuleErrorInsufficientBalance)
		}
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

		blockHeight := chain.blockTip().Height + 1
		if blockHeight < BalanceModelBlockHeight {
			totalInput, spendAmount, changeAmount, fees, err :=
				chain.AddInputsAndChangeToTransaction(txn, 10, nil)
			require.NoError(err)
			require.Equal(totalInput, spendAmount+changeAmount+fees)
			require.Greater(totalInput, uint64(0))
		} else {
			txn.TxnVersion = 1
		}

		// Sign the transaction with the recipient's key rather than the
		// sender's key.
		_signTxn(t, txn, recipientPrivString)
		utxoView, _ := NewUtxoView(db, params, nil)
		txHash := txn.Hash()
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

		blockHeight := chain.blockTip().Height + 1

		_signTxn(t, txn, senderPrivString)
		utxoView, _ := NewUtxoView(db, params, nil)
		txHash := txn.Hash()
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

		blockHeight := chain.blockTip().Height + 1

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, nil)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		_signTxn(t, txn, senderPrivString)
		utxoView, _ := NewUtxoView(db, params, nil)
		txHash := txn.Hash()
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
				true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		if blockHeight < BalanceModelBlockHeight {
			require.Contains(err.Error(), RuleErrorBlockRewardTxnNotAllowedToHaveInputs)
		} else {
			// AddInputsAndChange() does not add inputs in the balance model case so this
			// transaction fails with a different error.
			require.Contains(err.Error(), RuleErrorBlockRewardTxnNotAllowedToHaveSignature)
		}
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
		utxoView, _ := NewUtxoView(db, params, nil)
		_, err = utxoView.ConnectBlock(blockToMine, txHashes, true /*verifySignatures*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardExceedsMaxAllowed)
	}

	// A block with less than the max block reward should be OK.
	{
		utxoView, _ := NewUtxoView(db, params, nil)
		minerBalanceBefore, _ := utxoView.GetDeSoBalanceNanosForPublicKey(senderPkBytes)

		blockToMine.Txns[0].TxOutputs[0].AmountNanos = allowedBlockReward - 1
		// One iteration should be sufficient to find us a good block.
		_, bestNonce, err := FindLowestHash(blockToMine.Header, 10000)
		require.NoError(err)
		blockToMine.Header.Nonce = bestNonce

		txHashes, err := ComputeTransactionHashes(blockToMine.Txns)
		require.NoError(err)
		utxoView, _ = NewUtxoView(db, params, nil)
		_, err = utxoView.ConnectBlock(blockToMine, txHashes, true /*verifySignatures*/)
		require.NoError(err)

		minerBalanceAfter, _ := utxoView.GetDeSoBalanceNanosForPublicKey(senderPkBytes)

		// The miner starts with two DESO from two blocks being mined.
		require.Equal(uint64(2000000000), minerBalanceBefore)
		// Then mines another block reward worth .999999999 DESO.
		require.Equal(uint64(999999999), blockToMine.Txns[0].TxOutputs[0].AmountNanos)
		// Therefore the balance after mining should be 2.999999999 DESO.
		require.Equal(uint64(2999999999), minerBalanceAfter)

		err = utxoView.FlushToDb()
		require.NoError(err)
	}

	// A regular (non-BlockReward) basic transfer with sufficient balance should work.
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

		blockHeight := chain.blockTip().Height + 1

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, nil)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		_signTxn(t, txn, senderPrivString)
		utxoView, _ := NewUtxoView(db, params, nil)
		txHash := txn.Hash()
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
				true /*verifySignature*/, false /*ignoreUtxos*/)
		require.NoError(err)

		senderBalance, _ := utxoView.GetDeSoBalanceNanosForPublicKey(senderPkBytes)
		recipientBalance, _ := utxoView.GetDeSoBalanceNanosForPublicKey(recipientPkBytes)
		require.Equal(uint64(2999999997), senderBalance)
		require.Equal(uint64(1), recipientBalance)
	}
}

func _doBasicTransferWithViewFlush(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, pkSenderStr string, pkReceiverStr string, privStr string,
	amountNanos uint64, feeRateNanosPerKB uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32) {

	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	txn := _assembleBasicTransferTxnFullySigned(
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

	if blockHeight < BalanceModelBlockHeight {
		require.Equal(len(txn.TxInputs)+len(txn.TxOutputs), len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		for ii := len(txn.TxInputs); ii < len(txn.TxInputs)+len(txn.TxOutputs); ii++ {
			require.Equal(OperationTypeAddUtxo, utxoOps[ii].Type)
		}
	} else {
		require.Equal(0, len(txn.TxInputs))
		for ii := 0; ii < len(txn.TxOutputs); ii++ {
			require.Equal(OperationTypeAddBalance, utxoOps[ii].Type)
		}
		require.Equal(OperationTypeSpendBalance, utxoOps[len(txn.TxOutputs)].Type)
	}

	require.NoError(utxoView.FlushToDb())

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

func _updateUSDCentsPerBitcoinExchangeRate(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, usdCentsPerBitcoin uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateUpdateBitcoinUSDExchangeRateTxn(
		updaterPkBytes,
		usdCentsPerBitcoin,
		feeRateNanosPerKB,
		nil,
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, updaterPrivBase58Check)

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

	if blockHeight < BalanceModelBlockHeight {
		// We should have one SPEND UtxoOperation for each input, one ADD operation
		// for each output, and one OperationTypePrivateMessage operation at the end.
		require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		require.Equal(
			OperationTypeUpdateGlobalParams, utxoOps[len(utxoOps)-1].Type)
	} else {
		require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
		require.Equal(OperationTypeUpdateGlobalParams, utxoOps[1].Type)
	}
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

func _submitPost(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, postHashToModify []byte,
	parentStakeID []byte,
	bodyObj *DeSoBodySchema,
	repostedPostHash []byte,
	tstampNanos uint64,
	isHidden bool) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(updaterPkBase58Check)
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
	utxoView.GlobalParamsEntry.MinimumNetworkFeeNanosPerKB = 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	if blockHeight < BalanceModelBlockHeight {
		// We should have one SPEND UtxoOperation for each input, one ADD operation
		// for each output, and one OperationTypeSubmitPost operation at the end.
		require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
	} else {
		// Under the balance model, the UTXO ops should only include a spend and a submit post.
		require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
		require.Equal(OperationTypeSubmitPost, utxoOps[1].Type)
	}

	require.Equal(OperationTypeSubmitPost, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
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

func _submitPostWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	updaterPkBase58Check string,
	updaterPrivBase58Check string,
	postHashToModify []byte,
	parentStakeID []byte,
	body *DeSoBodySchema,
	repostedPostHash []byte,
	tstampNanos uint64,
	isHidden bool) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))

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

	blockHeight := chain.blockTip().Height + 1

	if blockHeight < BalanceModelBlockHeight {
		// Note: the "nftFee" is the "spendAmount" and therefore must be added to feesMake.
		require.Equal(totalInputMake, changeAmountMake+feesMake+nftFee)
	} else {
		// The balance model does not have "implicit" outputs  or "change" like the UTXO model.
		// Instead, all fees are explicitly baked into the "feesMake".
		require.Equal(totalInputMake, feesMake)
	}

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, updaterPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	if blockHeight < BalanceModelBlockHeight {
		// We should have one SPEND UtxoOperation for each input, one ADD operation
		// for each output, and one OperationTypeCreateNFT operation at the end.
		require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		require.Equal(OperationTypeCreateNFT, utxoOps[len(utxoOps)-1].Type)
	} else {
		require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
		require.Equal(OperationTypeCreateNFT, utxoOps[1].Type)
	}

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

func _giveDeSoDiamonds(t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams,
	feeRateNanosPerKB uint64, senderPkBase58Check string, senderPrivBase58Check string,
	diamondPostHash *BlockHash, diamondLevel int64, deleteDiamondLevel bool,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	senderPkBytes, _, err := Base58CheckDecode(senderPkBase58Check)
	require.NoError(t, err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(t, err)

	txn, totalInputMake, spendAmount, changeAmountMake, feesMake, err := chain.CreateBasicTransferTxnWithDiamonds(
		senderPkBytes,
		diamondPostHash,
		diamondLevel,
		feeRateNanosPerKB,
		nil,
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(t, totalInputMake, spendAmount+changeAmountMake+feesMake)

	// For testing purposes.
	if deleteDiamondLevel {
		delete(txn.ExtraData, DiamondLevelKey)
	}

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, senderPrivBase58Check)

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

	if blockHeight < BalanceModelBlockHeight {
		// We should have one SPEND UtxoOperation for each input, one ADD operation
		// for each output, and one OperationTypeDeSoDiamond operation at the end.
		require.Equal(t, len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(t, OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		require.Equal(t, OperationTypeDeSoDiamond, utxoOps[len(utxoOps)-1].Type)
	} else {
		require.Equal(t, OperationTypeAddBalance, utxoOps[0].Type)
		require.Equal(t, OperationTypeSpendBalance, utxoOps[1].Type)
		require.Equal(t, OperationTypeDeSoDiamond, utxoOps[2].Type)
	}

	require.NoError(t, utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _giveDeSoDiamondsWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	senderPkBase58Check string,
	senderPrivBase58Check string,
	postHashToModify *BlockHash,
	diamondLevel int64,
) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, senderPkBase58Check))
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

	if blockHeight < BalanceModelBlockHeight {
		// We should have one SPEND UtxoOperation for each input, one ADD operation
		// for each output, and one OperationTypeNFTBid operation at the end.
		require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		require.Equal(OperationTypeNFTBid, utxoOps[len(utxoOps)-1].Type)
	} else {
		require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
		require.Equal(OperationTypeNFTBid, utxoOps[1].Type)
	}

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

	if blockHeight < BalanceModelBlockHeight {
		// We should have one SPEND UtxoOperation for each input, one ADD operation
		// for each output, and one OperationTypeAcceptNFTBid operation at the end.
		numInputs := len(txn.TxInputs)
		numOps := len(utxoOps)
		for ii := 0; ii < numInputs; ii++ {
			require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		for ii := numInputs; ii < numOps-1; ii++ {
			require.Equal(OperationTypeAddUtxo, utxoOps[ii].Type)
		}
		require.Equal(OperationTypeAcceptNFTBid, utxoOps[numOps-1].Type)
	} else {
		require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
		require.Equal(OperationTypeAcceptNFTBid, utxoOps[1].Type)
	}

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

	if blockHeight < BalanceModelBlockHeight {
		// We should have one SPEND UtxoOperation for each input, one ADD operation
		// for each output, and one OperationTypeUpdateNFT operation at the end.
		require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		require.Equal(OperationTypeUpdateNFT, utxoOps[len(utxoOps)-1].Type)
	} else {
		require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
		require.Equal(OperationTypeUpdateNFT, utxoOps[1].Type)
	}

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
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, nil)
		require.NoError(testMeta.t, err)

		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := block.Header.Hash()
		require.NoError(testMeta.t, err)
		utxoOps, err := GetUtxoOperationsForBlock(testMeta.db, hash)
		require.NoError(testMeta.t, err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(block.Txns)
		require.NoError(testMeta.t, err)
		require.NoError(testMeta.t, utxoView.DisconnectBlock(block, txHashes, utxoOps))

		// Flushing the view after applying and rolling back should work.
		require.NoError(testMeta.t, utxoView.FlushToDb())
	}
}

func _swapIdentity(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, fromPublicKey []byte, toPublicKey []byte) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateSwapIdentityTxn(
		updaterPkBytes,
		fromPublicKey,
		toPublicKey,
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
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	if blockHeight < BalanceModelBlockHeight {
		// We should have one SPEND UtxoOperation for each input, one ADD operation
		// for each output, and one OperationTypeSwapIdentity operation at the end.
		require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		require.Equal(OperationTypeSwapIdentity, utxoOps[len(utxoOps)-1].Type)
	} else {
		require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
		require.Equal(OperationTypeSwapIdentity, utxoOps[1].Type)
	}

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _updateProfile(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, profilePubKey []byte, newUsername string,
	newDescription string, newProfilePic string, newCreatorBasisPoints uint64,
	newStakeMultipleBasisPoints uint64, isHidden bool, forceZeroAdditionalFee bool) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	if utxoView.GlobalParamsEntry.MinimumNetworkFeeNanosPerKB == 0 {
		utxoView.GlobalParamsEntry.MinimumNetworkFeeNanosPerKB = 1
	}

	additionalFees := utxoView.GlobalParamsEntry.CreateProfileFeeNanos
	if forceZeroAdditionalFee {
		additionalFees = 0
	}

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateUpdateProfileTxn(
		updaterPkBytes,
		profilePubKey,
		newUsername,
		newDescription,
		newProfilePic,
		newCreatorBasisPoints,
		newStakeMultipleBasisPoints,
		isHidden,
		additionalFees,
		feeRateNanosPerKB,
		nil, /*mempool*/
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
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	if blockHeight < BalanceModelBlockHeight {
		// We should have one SPEND UtxoOperation for each input, one ADD operation
		// for each output, and one OperationTypeUpdateProfile operation at the end.
		require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		require.Equal(OperationTypeUpdateProfile, utxoOps[len(utxoOps)-1].Type)
	} else {
		require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
		require.Equal(OperationTypeUpdateProfile, utxoOps[1].Type)
	}

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
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))

	currentOps, currentTxn, _, err := _updateProfile(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB, updaterPkBase58Check,
		updaterPrivBase58Check, profilePubKey, newUsername,
		newDescription, newProfilePic, newCreatorBasisPoints,
		newStakeMultipleBasisPoints, isHidden, false)

	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _getAuthorizeDerivedKeyMetadata(t *testing.T, ownerPrivateKey *btcec.PrivateKey,
	params *DeSoParams, expirationBlock uint64, isDeleted bool) (*AuthorizeDerivedKeyMetadata,
	*btcec.PrivateKey) {
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

// Create a new AuthorizeDerivedKey txn and connect it to the utxoView
func _doAuthorizeTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, utxoView *UtxoView, feeRateNanosPerKB uint64, ownerPublicKey []byte,
	derivedPublicKey []byte, derivedPrivBase58Check string, expirationBlock uint64,
	accessSignature []byte, deleteKey bool) (_utxoOps []*UtxoOperation,
	_txn *MsgDeSoTxn, _height uint32, _err error) {

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
	// for each output, and one OperationTypeUpdateProfile operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeAuthorizeDerivedKey, utxoOps[len(utxoOps)-1].Type)

	return utxoOps, txn, blockHeight, nil
}

func _creatorCoinTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	UpdaterPublicKeyBase58Check string,
	UpdaterPrivateKeyBase58Check string,
	// See CreatorCoinMetadataa for an explanation of these fields.
	ProfilePublicKeyBase58Check string,
	OperationType CreatorCoinOperationType,
	DeSoToSellNanos uint64,
	CreatorCoinToSellNanos uint64,
	DeSoToAddNanos uint64,
	MinDeSoExpectedNanos uint64,
	MinCreatorCoinExpectedNanos uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(UpdaterPublicKeyBase58Check)
	require.NoError(err)

	profilePkBytes, _, err := Base58CheckDecode(ProfilePublicKeyBase58Check)
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
		[]*DeSoOutput{})

	if err != nil {
		return nil, nil, 0, err
	}

	if OperationType == CreatorCoinOperationTypeBuy {
		require.Equal(int64(totalInputMake), int64(changeAmountMake+feesMake+DeSoToSellNanos))
	} else {
		require.Equal(int64(totalInputMake), int64(changeAmountMake+feesMake))
	}

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, UpdaterPrivateKeyBase58Check)

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
	OperationType CreatorCoinOperationType,
	DeSoToSellNanos uint64,
	CreatorCoinToSellNanos uint64,
	DeSoToAddNanos uint64,
	MinDeSoExpectedNanos uint64,
	MinCreatorCoinExpectedNanos uint64) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, UpdaterPublicKeyBase58Check))

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

func _doCreatorCoinTransferTxnWithDiamonds(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	SenderPublicKeyBase58Check string,
	SenderPrivBase58Check string,
	ReceiverPublicKeyBase58Check string,
	DiamondPostHash *BlockHash,
	DiamondLevel int64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := Base58CheckDecode(SenderPublicKeyBase58Check)
	require.NoError(err)

	receiverPkBytes, _, err := Base58CheckDecode(ReceiverPublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
		senderPkBytes,
		receiverPkBytes,
		DiamondPostHash,
		DiamondLevel,
		feeRateNanosPerKB, nil, []*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, SenderPrivBase58Check)

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

func _doCreatorCoinTransferTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	UpdaterPublicKeyBase58Check string, UpdaterPrivateKeyBase58Check string,
	// See CreatorCoinTransferMetadataa for an explanation of these fields.
	ProfilePublicKeyBase58Check string,
	ReceiverPublicKeyBase58Check string,
	CreatorCoinToTransferNanos uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(UpdaterPublicKeyBase58Check)
	require.NoError(err)

	profilePkBytes, _, err := Base58CheckDecode(ProfilePublicKeyBase58Check)
	require.NoError(err)

	receiverPkBytes, _, err := Base58CheckDecode(ReceiverPublicKeyBase58Check)
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
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, UpdaterPrivateKeyBase58Check)

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

func _doSubmitPostTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	UpdaterPublicKeyBase58Check string, UpdaterPrivateKeyBase58Check string,
	postHashToModify []byte,
	parentPostHashBytes []byte,
	body string,
	extraData map[string][]byte,
	isHidden bool) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(UpdaterPublicKeyBase58Check)
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
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, UpdaterPrivateKeyBase58Check)

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

func _privateMessage(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, senderPkBase58Check string,
	recipientPkBase58Check string,
	senderPrivBase58Check string, unencryptedMessageText string, tstampNanos uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := Base58CheckDecode(senderPkBase58Check)
	require.NoError(err)

	recipientPkBytes, _, err := Base58CheckDecode(recipientPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreatePrivateMessageTxn(
		senderPkBytes, recipientPkBytes, unencryptedMessageText, "",
		tstampNanos, feeRateNanosPerKB, nil, []*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, senderPrivBase58Check)

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

	if blockHeight < BalanceModelBlockHeight {
		// We should have one SPEND UtxoOperation for each input, one ADD operation
		// for each output, and one OperationTypePrivateMessage operation at the end.
		require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		require.Equal(OperationTypePrivateMessage, utxoOps[len(utxoOps)-1].Type)
	} else {
		require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
		require.Equal(OperationTypePrivateMessage, utxoOps[1].Type)
	}

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _doLikeTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, senderPkBase58Check string,
	likedPostHash BlockHash, senderPrivBase58Check string, isUnfollow bool) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := Base58CheckDecode(senderPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateLikeTxn(
		senderPkBytes, likedPostHash, isUnfollow, feeRateNanosPerKB, nil, []*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, senderPrivBase58Check)

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

	if blockHeight < BalanceModelBlockHeight {
		// We should have one SPEND UtxoOperation for each input, one ADD operation
		// for each output, and one OperationTypeLike operation at the end.
		require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		require.Equal(OperationTypeLike, utxoOps[len(utxoOps)-1].Type)
	} else {
		require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
		require.Equal(OperationTypeLike, utxoOps[1].Type)
	}

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _doFollowTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, senderPkBase58Check string,
	followedPkBase58Check string, senderPrivBase58Check string, isUnfollow bool) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := Base58CheckDecode(senderPkBase58Check)
	require.NoError(err)

	followedPkBytes, _, err := Base58CheckDecode(followedPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateFollowTxn(
		senderPkBytes, followedPkBytes, isUnfollow, feeRateNanosPerKB, nil, []*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, senderPrivBase58Check)

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

	if blockHeight < BalanceModelBlockHeight {
		// We should have one SPEND UtxoOperation for each input, one ADD operation
		// for each output, and one OperationTypeFollow operation at the end.
		require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		require.Equal(OperationTypeFollow, utxoOps[len(utxoOps)-1].Type)
	} else {
		require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
		require.Equal(OperationTypeFollow, utxoOps[1].Type)
	}

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func TestSubmitPost(t *testing.T) {
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

	// Setup some convenience functions for the test.
	txnOps := [][]*UtxoOperation{}
	txns := []*MsgDeSoTxn{}
	expectedSenderBalances := []uint64{}

	// We take the block tip to be the blockchain height rather than the
	// header chain height.
	savedHeight := chain.blockTip().Height + 1
	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPk))

		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, senderPk, recipientPk,
			senderPriv, 70 /*amount to send*/, 11 /*feerate*/)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// Fund all the keys.
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)

	checkPostsDeleted := func() {
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		corePosts, commentsByPostHash, err := utxoView.GetAllPosts()
		require.NoError(err)
		require.Equal(4, len(corePosts))
		totalComments := 0
		for _, currentComment := range commentsByPostHash {
			totalComments += len(currentComment)
		}
		// 3 comments from seed txns
		require.Equal(3, totalComments)

		require.Equal(0, len(utxoView.RepostKeyToRepostEntry))

		// TODO: add checks that repost entries are deleted
	}
	checkPostsDeleted()

	updateProfile := func(
		feeRateNanosPerKB uint64, updaterPkBase58Check string,
		updaterPrivBase58Check string, profilePubKey []byte, newUsername string,
		newDescription string, newProfilePic string, newCreatorBasisPoints uint64,
		newStakeMultipleBasisPoints uint64, isHidden bool) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, updaterPkBase58Check))

		currentOps, currentTxn, _, err := _updateProfile(
			t, chain, db, params,
			feeRateNanosPerKB, updaterPkBase58Check,
			updaterPrivBase58Check, profilePubKey, newUsername,
			newDescription, newProfilePic, newCreatorBasisPoints,
			newStakeMultipleBasisPoints, isHidden, false)

		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}
	_, _, _ = m2Priv, m3Priv, updateProfile

	submitPost := func(
		feeRateNanosPerKB uint64, updaterPkBase58Check string,
		updaterPrivBase58Check string,
		postHashToModify []byte,
		parentStakeID []byte,
		body *DeSoBodySchema,
		repostedPostHash []byte,
		tstampNanos uint64,
		isHidden bool) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, updaterPkBase58Check))

		currentOps, currentTxn, _, err := _submitPost(
			t, chain, db, params, feeRateNanosPerKB,
			updaterPkBase58Check,
			updaterPrivBase58Check,
			postHashToModify,
			parentStakeID,
			body,
			repostedPostHash,
			tstampNanos,
			isHidden)

		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}
	_ = submitPost

	swapIdentity := func(
		feeRateNanosPerKB uint64, updaterPkBase58Check string,
		updaterPrivBase58Check string,
		fromPkBytes []byte,
		toPkBytes []byte) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, updaterPkBase58Check))

		currentOps, currentTxn, _, err := _swapIdentity(
			t, chain, db, params, feeRateNanosPerKB,
			updaterPkBase58Check,
			updaterPrivBase58Check,
			fromPkBytes, toPkBytes)

		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// Creating a post from an unregistered profile should succeed
	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m0Pub,    /*updaterPkBase58Check*/
			m0Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body 1 no profile"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Txn := txns[len(txns)-1]
	post1Hash := post1Txn.Hash()
	_, _ = post1Txn, post1Hash

	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m0Pub,    /*updaterPkBase58Check*/
			m0Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body 2 no profile"}, /*body*/
			[]byte{},
			1502947012*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post2Txn := txns[len(txns)-1]
	post2Hash := post2Txn.Hash()
	_, _ = post2Txn, post2Hash

	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m1Pub,    /*updaterPkBase58Check*/
			m1Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "m1 post body 1 no profile"}, /*body*/
			[]byte{},
			1502947013*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post3Txn := txns[len(txns)-1]
	post3Hash := post3Txn.Hash()
	_, _ = post3Txn, post3Hash

	// Creating a post from a registered profile should succeed
	{
		updateProfile(
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

		submitPost(
			10,       /*feeRateNanosPerKB*/
			m2Pub,    /*updaterPkBase58Check*/
			m2Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "m2 post body 1 WITH profile"}, /*body*/
			[]byte{},
			1502947014*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post4Txn := txns[len(txns)-1]
	post4Hash := post4Txn.Hash()
	_, _ = post4Txn, post4Hash

	{
		updateProfile(
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

		submitPost(
			10,       /*feeRateNanosPerKB*/
			m3Pub,    /*updaterPkBase58Check*/
			m3Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "m3 post body 1 WITH profile"}, /*body*/
			[]byte{},
			1502947015*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post5Txn := txns[len(txns)-1]
	post5Hash := post5Txn.Hash()
	_, _ = post5Txn, post5Hash

	// Create another post for m2
	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m2Pub,    /*updaterPkBase58Check*/
			m2Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "m2 post body 2 WITH profile"}, /*body*/
			[]byte{},
			1502947016*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post6Txn := txns[len(txns)-1]
	post6Hash := post6Txn.Hash()
	_, _ = post6Txn, post6Hash

	// A zero input post should fail
	{
		_, _, _, err := _submitPost(
			t, chain, db, params,
			0,        /*feeRateNanosPerKB*/
			m0Pub,    /*updaterPkBase58Check*/
			m0Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "this is a post body"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		blockHeight := chain.blockTip().Height + 1
		if blockHeight < BalanceModelBlockHeight {
			require.Contains(err.Error(), RuleErrorTxnMustHaveAtLeastOneInput)
		} else {
			require.Contains(err.Error(), RuleErrorTxnFeeBelowNetworkMinimum)
		}
	}

	// PostHashToModify with bad length
	{
		_, _, _, err := _submitPost(
			t, chain, db, params,
			10,                           /*feeRateNanosPerKB*/
			m0Pub,                        /*updaterPkBase58Check*/
			m0Priv,                       /*updaterPrivBase58Check*/
			RandomBytes(HashSizeBytes-1), /*postHashToModify*/
			[]byte{},                     /*parentStakeID*/
			&DeSoBodySchema{Body: "this is a post body"}, /*body*/
			[]byte{},
			1502947048*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostInvalidPostHashToModify)
	}

	// Setting PostHashToModify should fail for a non-existent post
	{
		_, _, _, err := _submitPost(
			t, chain, db, params,
			10,                         /*feeRateNanosPerKB*/
			m0Pub,                      /*updaterPkBase58Check*/
			m0Priv,                     /*updaterPrivBase58Check*/
			RandomBytes(HashSizeBytes), /*postHashToModify*/
			[]byte{},                   /*parentStakeID*/
			&DeSoBodySchema{Body: "this is a post body"}, /*body*/
			[]byte{},
			1502947048*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostModifyingNonexistentPost)
	}

	// Bad length for parent stake id should fail
	{
		_, _, _, err := _submitPost(
			t, chain, db, params,
			10,                           /*feeRateNanosPerKB*/
			m0Pub,                        /*updaterPkBase58Check*/
			m0Priv,                       /*updaterPrivBase58Check*/
			[]byte{},                     /*postHashToModify*/
			RandomBytes(HashSizeBytes-1), /*parentStakeID*/
			&DeSoBodySchema{Body: "this is a post body"}, /*body*/
			[]byte{},
			1502947048*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostInvalidParentStakeIDLength)
	}

	// Non-owner modifying post should fail
	{
		_, _, _, err := _submitPost(
			t, chain, db, params,
			10,           /*feeRateNanosPerKB*/
			m1Pub,        /*updaterPkBase58Check*/
			m1Priv,       /*updaterPrivBase58Check*/
			post1Hash[:], /*postHashToModify*/
			[]byte{},     /*parentStakeID*/
			&DeSoBodySchema{Body: "this is a post body"}, /*body*/
			[]byte{},
			1502947048*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostPostModificationNotAuthorized)
	}

	// Zero timestamp should fail
	{
		_, _, _, err = _submitPost(
			t, chain, db, params,
			10,       /*feeRateNanosPerKB*/
			m1Pub,    /*updaterPkBase58Check*/
			m1Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "this is a post body"}, /*body*/
			[]byte{},
			0, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostTimestampIsZero)
	}

	// User without profile modifying another user without profile's post
	// should fail
	{
		_, _, _, err = _submitPost(
			t, chain, db, params,
			10,     /*feeRateNanosPerKB*/
			m0Pub,  /*updaterPkBase58Check*/
			m0Priv, /*updaterPrivBase58Check*/
			// this belongs to m1 who doesn't have a profile.
			post3Hash[:],                            /*postHashToModify*/
			RandomBytes(HashSizeBytes),              /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body 2"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostPostModificationNotAuthorized)
	}

	// User WITH profile modifying another user without profile's post
	// should fail
	{
		_, _, _, err = _submitPost(
			t, chain, db, params,
			10,     /*feeRateNanosPerKB*/
			m2Pub,  /*updaterPkBase58Check*/
			m2Priv, /*updaterPrivBase58Check*/
			// this belongs to m1 who doesn't have a profile.
			post1Hash[:],                            /*postHashToModify*/
			RandomBytes(HashSizeBytes),              /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body 2"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostPostModificationNotAuthorized)
	}

	// User without profile modifying another user WITH profile's post
	// should fail
	{
		_, _, _, err = _submitPost(
			t, chain, db, params,
			10,     /*feeRateNanosPerKB*/
			m0Pub,  /*updaterPkBase58Check*/
			m0Priv, /*updaterPrivBase58Check*/
			// this belongs to m1 who doesn't have a profile.
			post4Hash[:],                            /*postHashToModify*/
			RandomBytes(HashSizeBytes),              /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body 2"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostPostModificationNotAuthorized)
	}

	// User WITH profile modifying another user WITH profile's post
	// should fail
	{
		_, _, _, err = _submitPost(
			t, chain, db, params,
			10,     /*feeRateNanosPerKB*/
			m2Pub,  /*updaterPkBase58Check*/
			m2Priv, /*updaterPrivBase58Check*/
			// this belongs to m1 who doesn't have a profile.
			post5Hash[:],                            /*postHashToModify*/
			RandomBytes(HashSizeBytes),              /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body 2"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostPostModificationNotAuthorized)
	}

	// Owner without profile modifying post should succeed but all the non-body fields
	// should be ignored.
	{
		submitPost(
			10,                         /*feeRateNanosPerKB*/
			m0Pub,                      /*updaterPkBase58Check*/
			m0Priv,                     /*updaterPrivBase58Check*/
			post1Hash[:],               /*postHashToModify*/
			RandomBytes(HashSizeBytes), /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body MODIFIED"}, /*body*/
			[]byte{},
			1502947017*1e9, /*tstampNanos*/
			true /*isHidden*/)
	}

	// Owner with profile modifying one of their posts should succeed but
	// all non-body posts should be unchanged.
	{
		submitPost(
			10,                         /*feeRateNanosPerKB*/
			m2Pub,                      /*updaterPkBase58Check*/
			m2Priv,                     /*updaterPrivBase58Check*/
			post4Hash[:],               /*postHashToModify*/
			RandomBytes(HashSizeBytes), /*parentStakeID*/
			&DeSoBodySchema{Body: "m2 post body MODIFIED"}, /*body*/
			[]byte{},
			1502947018*1e9, /*tstampNanos*/
			true /*isHidden*/)
	}

	// ParamUpdater modifying their own post should succeed
	{
		submitPost(
			10,                         /*feeRateNanosPerKB*/
			m3Pub,                      /*updaterPkBase58Check*/
			m3Priv,                     /*updaterPrivBase58Check*/
			post5Hash[:],               /*postHashToModify*/
			RandomBytes(HashSizeBytes), /*parentStakeID*/
			&DeSoBodySchema{Body: "paramUpdater post body MODIFIED"}, /*body*/
			[]byte{},
			1502947019*1e9, /*tstampNanos*/
			true /*isHidden*/)
	}

	// Modifying a post and then modifying it back should work.
	{
		submitPost(
			10,                         /*feeRateNanosPerKB*/
			m1Pub,                      /*updaterPkBase58Check*/
			m1Priv,                     /*updaterPrivBase58Check*/
			post3Hash[:],               /*postHashToModify*/
			RandomBytes(HashSizeBytes), /*parentStakeID*/
			&DeSoBodySchema{Body: "sldkfjlskdfjlajflkasjdflkasjdf"}, /*body*/
			[]byte{},
			1502947022*1e9, /*tstampNanos*/
			true /*isHidden*/)
		submitPost(
			10,                         /*feeRateNanosPerKB*/
			m1Pub,                      /*updaterPkBase58Check*/
			m1Priv,                     /*updaterPrivBase58Check*/
			post3Hash[:],               /*postHashToModify*/
			RandomBytes(HashSizeBytes), /*parentStakeID*/
			&DeSoBodySchema{Body: "m1 post body 1 no profile modified back"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}

	// Comment on a post with an anonymous public key
	{
		submitPost(
			10,           /*feeRateNanosPerKB*/
			m0Pub,        /*updaterPkBase58Check*/
			m0Priv,       /*updaterPrivBase58Check*/
			[]byte{},     /*postHashToModify*/
			post3Hash[:], /*parentStakeID*/
			&DeSoBodySchema{Body: "comment 1 from m0 on post3"}, /*body*/
			[]byte{},
			1502947001*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment1Txn := txns[len(txns)-1]
	comment1Hash := comment1Txn.Hash()

	// Make a few more comments.
	{
		submitPost(
			10,           /*feeRateNanosPerKB*/
			m0Pub,        /*updaterPkBase58Check*/
			m0Priv,       /*updaterPrivBase58Check*/
			[]byte{},     /*postHashToModify*/
			post6Hash[:], /*parentStakeID*/
			&DeSoBodySchema{Body: "comment 2 from m0 on post3"}, /*body*/
			[]byte{},
			1502947002*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment2CreatedTxnIndex := len(txns) - 1
	comment2Txn := txns[comment2CreatedTxnIndex]
	comment2Hash := comment2Txn.Hash()

	{
		submitPost(
			10,           /*feeRateNanosPerKB*/
			m2Pub,        /*updaterPkBase58Check*/
			m2Priv,       /*updaterPrivBase58Check*/
			[]byte{},     /*postHashToModify*/
			post6Hash[:], /*parentStakeID*/
			&DeSoBodySchema{Body: "comment 1 from m2 on post6"}, /*body*/
			[]byte{},
			1502947003*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment3CreatedTxnIndex := len(txns) - 1
	comment3Txn := txns[comment3CreatedTxnIndex]
	comment3Hash := comment3Txn.Hash()

	{
		submitPost(
			10,           /*feeRateNanosPerKB*/
			m3Pub,        /*updaterPkBase58Check*/
			m3Priv,       /*updaterPrivBase58Check*/
			[]byte{},     /*postHashToModify*/
			post6Hash[:], /*parentStakeID*/
			&DeSoBodySchema{Body: "comment 1 from m3 on post6"}, /*body*/
			[]byte{},
			1502947004*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment4CreatedTxnIndex := len(txns) - 1
	comment4Txn := txns[comment4CreatedTxnIndex]
	comment4Hash := comment4Txn.Hash()

	// Modify some comments
	var comment3HiddenTxnIndex int
	{
		// Modifying the comment with the wrong pub should fail.
		_, _, _, err = _submitPost(
			t, chain, db, params,
			10,              /*feeRateNanosPerKB*/
			m1Pub,           /*updaterPkBase58Check*/
			m1Priv,          /*updaterPrivBase58Check*/
			comment1Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "modifying comment 1 by m1 should fail"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostPostModificationNotAuthorized)

		// Modifying the comment with the proper key should work.
		submitPost(
			10,              /*feeRateNanosPerKB*/
			m0Pub,           /*updaterPkBase58Check*/
			m0Priv,          /*updaterPrivBase58Check*/
			comment1Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "comment from m0 on post3 MODIFIED"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)

		// Modifying the comment with the proper key should work.
		submitPost(
			10,              /*feeRateNanosPerKB*/
			m2Pub,           /*updaterPkBase58Check*/
			m2Priv,          /*updaterPrivBase58Check*/
			comment3Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "comment from m2 on post6 MODIFIED"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			true /*isHidden*/)
		comment3HiddenTxnIndex = len(txns) - 1

		// Modify a comment and modify it back.
		submitPost(
			10,              /*feeRateNanosPerKB*/
			m0Pub,           /*updaterPkBase58Check*/
			m0Priv,          /*updaterPrivBase58Check*/
			comment2Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "comment from m0 on post3 MODIFIED"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			true /*isHidden*/)
		submitPost(
			10,              /*feeRateNanosPerKB*/
			m0Pub,           /*updaterPkBase58Check*/
			m0Priv,          /*updaterPrivBase58Check*/
			comment2Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "comment 2 from m0 on post3"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}

	// Commenting on a public key should work regardless of whether
	// a profile actually exists for that stake ID.
	{
		submitPost(
			10,        /*feeRateNanosPerKB*/
			m0Pub,     /*updaterPkBase58Check*/
			m0Priv,    /*updaterPrivBase58Check*/
			[]byte{},  /*postHashToModify*/
			m1PkBytes, /*parentStakeID*/
			&DeSoBodySchema{Body: "comment m0 on profile m1 [1]"}, /*body*/
			[]byte{},
			1502947005*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment5Txn := txns[len(txns)-1]
	comment5Hash := comment5Txn.Hash()
	{
		submitPost(
			10,        /*feeRateNanosPerKB*/
			m1Pub,     /*updaterPkBase58Check*/
			m1Priv,    /*updaterPrivBase58Check*/
			[]byte{},  /*postHashToModify*/
			m2PkBytes, /*parentStakeID*/
			&DeSoBodySchema{Body: "comment m1 on profile m2 [1]"}, /*body*/
			[]byte{},
			1502947006*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment6Txn := txns[len(txns)-1]
	comment6Hash := comment6Txn.Hash()
	{
		submitPost(
			10,        /*feeRateNanosPerKB*/
			m3Pub,     /*updaterPkBase58Check*/
			m3Priv,    /*updaterPrivBase58Check*/
			[]byte{},  /*postHashToModify*/
			m3PkBytes, /*parentStakeID*/
			&DeSoBodySchema{Body: "comment m3 on profile m3 [1]"}, /*body*/
			[]byte{},
			1502947007*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment7Txn := txns[len(txns)-1]
	comment7Hash := comment7Txn.Hash()
	{
		submitPost(
			10,        /*feeRateNanosPerKB*/
			m0Pub,     /*updaterPkBase58Check*/
			m0Priv,    /*updaterPrivBase58Check*/
			[]byte{},  /*postHashToModify*/
			m3PkBytes, /*parentStakeID*/
			&DeSoBodySchema{Body: "comment m0 on profile m3 [2]"}, /*body*/
			[]byte{},
			1502947008*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment8Txn := txns[len(txns)-1]
	comment8Hash := comment8Txn.Hash()

	// Modifying the profile comments should work when the key is authorized
	// and fail when it's not.
	{
		submitPost(
			10,              /*feeRateNanosPerKB*/
			m0Pub,           /*updaterPkBase58Check*/
			m0Priv,          /*updaterPrivBase58Check*/
			comment5Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "comment 1 from m0 on post3 MODIFIED"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			true /*isHidden*/)

		_, _, _, err = _submitPost(
			t, chain, db, params,
			10,              /*feeRateNanosPerKB*/
			m1Pub,           /*updaterPkBase58Check*/
			m1Priv,          /*updaterPrivBase58Check*/
			comment5Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "modifying comment 1 by m1 should fail"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostPostModificationNotAuthorized)

		// Modify a profile comment then modify it back.
		submitPost(
			10,              /*feeRateNanosPerKB*/
			m1Pub,           /*updaterPkBase58Check*/
			m1Priv,          /*updaterPrivBase58Check*/
			comment6Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "comment m1 on profile m2 [1] MODIFIED"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			true /*isHidden*/)
		submitPost(
			10,              /*feeRateNanosPerKB*/
			m1Pub,           /*updaterPkBase58Check*/
			m1Priv,          /*updaterPrivBase58Check*/
			comment6Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "comment m1 on profile m2 [1]"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}

	// Reposting tests
	// repost 1 - vanilla repost
	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m1Pub,    /*updaterPkBase58Check*/
			m1Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{},
			post3Hash[:],
			15029557050*1e9, /*tstampNanos*/
			false /*isHidden*/)

	}
	repost1Txn := txns[len(txns)-1]
	repost1Hash := repost1Txn.Hash()
	_, _ = repost1Txn, repost1Hash
	// repost 2 - vanilla repost + hide
	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m1Pub,    /*updaterPkBase58Check*/
			m1Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{},
			post4Hash[:],
			15029557051*1e9, /*tstampNanos*/
			false /*isHidden*/)
		repost2Txn := txns[len(txns)-1]
		repost2Hash := repost2Txn.Hash()
		submitPost(
			10,             /*feeRateNanosPerKB*/
			m1Pub,          /*updaterPkBase58Check*/
			m1Priv,         /*updaterPrivBase58Check*/
			repost2Hash[:], /*postHashToModify*/
			[]byte{},       /*parentStakeID*/
			&DeSoBodySchema{},
			post4Hash[:],
			15029557052*1e9, /*tstampNanos*/
			true /*isHidden*/)
	}
	// repost 3 - Quote Repost
	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m1Pub,    /*updaterPkBase58Check*/
			m1Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "quote-post"},
			post5Hash[:],
			15029557053*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	// repost 4 - Quote Repost + hide
	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m1Pub,    /*updaterPkBase58Check*/
			m1Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "quote-post-hide-me"},
			post6Hash[:],
			15029557054*1e9, /*tstampNanos*/
			false /*isHidden*/)
		repost4Txn := txns[len(txns)-1]
		repost4hash := repost4Txn.Hash()
		submitPost(
			10,             /*feeRateNanosPerKB*/
			m1Pub,          /*updaterPkBase58Check*/
			m1Priv,         /*updaterPrivBase58Check*/
			repost4hash[:], /*postHashToModify*/
			[]byte{},       /*parentStakeID*/
			&DeSoBodySchema{Body: "quote-post-hide-me"},
			post6Hash[:],
			15029557054*1e9, /*tstampNanos*/
			true /*isHidden*/)
	}
	// repost -- test exceptions
	{
		{
			// Reposting a post that doesn't exist will raise an error.
			_, _, _, err = _submitPost(t, chain, db, params,
				10,
				m1Pub,
				m1Priv,
				[]byte{},
				[]byte{},
				&DeSoBodySchema{},
				[]byte{1, 2, 3},
				15029557055,
				false,
			)
			require.Error(err)
			require.Contains(err.Error(), RuleErrorSubmitPostRepostPostNotFound)
		}
		{
			// Cannot repost a vanilla repost
			_, _, _, err = _submitPost(t, chain, db, params,
				10,
				m1Pub,
				m1Priv,
				[]byte{},
				[]byte{},
				&DeSoBodySchema{},
				repost1Hash[:],
				15029557055,
				false,
			)
			require.Error(err)
			require.Contains(err.Error(), RuleErrorSubmitPostRepostOfRepost)
		}
		{
			// Cannot update the repostedPostHashHex
			_, _, _, err = _submitPost(t, chain, db, params,
				10,
				m1Pub,
				m1Priv,
				repost1Hash[:],
				[]byte{},
				&DeSoBodySchema{},
				post4Hash[:],
				15029557055,
				false,
			)
			require.Error(err)
			require.Contains(err.Error(), RuleErrorSubmitPostUpdateRepostHash)
		}

	}

	// Swapping the identity of m0 and m1 should not result in any issues.
	// TODO: This will no longer be the case once posts are a part of the PKID
	// infrastructure.
	swapIdentity(
		10,    /*feeRateNanosPerKB*/
		m3Pub, // m3 is paramUpdater for this test.
		m3Priv,
		m0PkBytes,
		m1PkBytes)

	// post1: m0 post body MODIFIED
	// post2: paramUpdater post body MODIFIED
	// post3: m1 post body 1 no profile modified back (isHidden = false)
	// post4: m2 post body MODIFIED
	// post5: paramUpdater post body MODIFIED
	// post6: paramUpdater m2 post body MODIFIED
	// comment1: m0 comment from m0 on post3 MODIFIED
	// comment2: m0 comment 2 from m0 on post3
	// comment3: comment from m2 on post6 MODIFIED (isHidden = true)
	// comment4: m3 comment 1 from m3 on post6
	// comment5: comment 1 from m0 on post3 MODIFIED
	// comment6: m1 comment m1 on profile m2 [1]
	// comment7: m3 comment m3 on profile m3 [1]
	// comment8: m0 comment m0 on profile m3 [2]
	// Comments for post3
	// - comment1
	// Comments for post6
	// - comment2, comment3, comment4
	// Coomments for m1
	// - comment5
	// Comments profile m2
	// - comment6
	// Comments profile m3
	// - comment7, comment8
	// - repost1
	// Reposts post3
	// - repost 2
	// reposts post4 and then hides itself -- test RepostCount
	// - repost 3
	// quote repost post 5
	// - repost 4
	// quote repost post 6 and then hides itself

	comparePostBody := func(postEntry *PostEntry, message string, repostPostHash *BlockHash) {
		bodyJSONObj := &DeSoBodySchema{}
		err := json.Unmarshal(postEntry.Body, bodyJSONObj)
		require.NoError(err)
		require.Equal(message, bodyJSONObj.Body)
		if repostPostHash != nil {
			require.Equal(repostPostHash, postEntry.RepostedPostHash)
		}
	}

	checkPostsExist := func() {
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		corePosts, commentsByPostHash, err := utxoView.GetAllPosts()
		require.NoError(err)
		// 4 posts from seed txns
		require.Equal(14, len(corePosts))

		totalComments := 0
		for _, currentComment := range commentsByPostHash {
			totalComments += len(currentComment)
		}
		// 3 comments from seed txns
		require.Equal(11, totalComments)

		// post3 should have 1 comment
		{
			commentsForPost, exists := commentsByPostHash[*post3Hash]
			require.True(exists)
			require.Equal(1, len(commentsForPost))

			require.Equal(m0PkBytes, commentsForPost[0].PosterPublicKey)
			require.Equal(post3Hash[:], commentsForPost[0].ParentStakeID)
			require.Equal(*comment1Hash, *commentsForPost[0].PostHash)
			comparePostBody(commentsForPost[0], "comment from m0 on post3 MODIFIED", nil)
			require.Equal(false, commentsForPost[0].IsHidden)

			post3 := findPostByPostHash(corePosts, post3Hash)
			require.Equal(uint64(1), post3.CommentCount)
		}
		// post6 should have 3 comments
		{
			commentsForPost, err := commentsByPostHash[*post6Hash]
			require.True(err)
			require.Equal(3, len(commentsForPost))

			require.Equal(m0PkBytes, commentsForPost[0].PosterPublicKey)
			require.Equal(post6Hash[:], commentsForPost[0].ParentStakeID)
			require.Equal(*comment2Hash, *commentsForPost[0].PostHash)
			comparePostBody(commentsForPost[0], "comment 2 from m0 on post3", nil)
			require.Equal(false, commentsForPost[0].IsHidden)

			require.Equal(m2PkBytes, commentsForPost[1].PosterPublicKey)
			require.Equal(post6Hash[:], commentsForPost[1].ParentStakeID)
			require.Equal(*comment3Hash, *commentsForPost[1].PostHash)
			comparePostBody(commentsForPost[1], "comment from m2 on post6 MODIFIED", nil)
			require.Equal(true, commentsForPost[1].IsHidden)

			require.Equal(m3PkBytes, commentsForPost[2].PosterPublicKey)
			require.Equal(post6Hash[:], commentsForPost[2].ParentStakeID)
			require.Equal(*comment4Hash, *commentsForPost[2].PostHash)
			comparePostBody(commentsForPost[2], "comment 1 from m3 on post6", nil)
			require.Equal(false, commentsForPost[2].IsHidden)

			// Two comments are not hidden, so commentCount should be 2
			post6 := findPostByPostHash(corePosts, post6Hash)
			require.Equal(uint64(2), post6.CommentCount)
		}
		// m1 should have 1 comment
		{
			commentsForPost, err := commentsByPostHash[*NewBlockHash(m1PkBytes)]
			require.True(err)
			require.Equal(1, len(commentsForPost))

			require.Equal(m0PkBytes, commentsForPost[0].PosterPublicKey)
			require.Equal(m1PkBytes[:], commentsForPost[0].ParentStakeID)
			require.Equal(*comment5Hash, *commentsForPost[0].PostHash)
			comparePostBody(commentsForPost[0], "comment 1 from m0 on post3 MODIFIED", nil)
			require.Equal(true, commentsForPost[0].IsHidden)
		}
		// m2 should have 1 comment
		{
			commentsForPost, err := commentsByPostHash[*NewBlockHash(m2PkBytes)]
			require.True(err)
			require.Equal(1, len(commentsForPost))

			require.Equal(m1PkBytes, commentsForPost[0].PosterPublicKey)
			require.Equal(m2PkBytes[:], commentsForPost[0].ParentStakeID)
			require.Equal(*comment6Hash, *commentsForPost[0].PostHash)
			comparePostBody(commentsForPost[0], "comment m1 on profile m2 [1]", nil)
			require.Equal(false, commentsForPost[0].IsHidden)
		}
		// m3 should have 2 comments
		{
			commentsForPost, err := commentsByPostHash[*NewBlockHash(m3PkBytes)]
			require.True(err)
			require.Equal(2, len(commentsForPost))

			require.Equal(m3PkBytes, commentsForPost[0].PosterPublicKey)
			require.Equal(m3PkBytes[:], commentsForPost[0].ParentStakeID)
			require.Equal(*comment7Hash, *commentsForPost[0].PostHash)
			comparePostBody(commentsForPost[0], "comment m3 on profile m3 [1]", nil)
			require.Equal(false, commentsForPost[0].IsHidden)

			require.Equal(m0PkBytes, commentsForPost[1].PosterPublicKey)
			require.Equal(m3PkBytes[:], commentsForPost[1].ParentStakeID)
			require.Equal(*comment8Hash, *commentsForPost[1].PostHash)
			comparePostBody(commentsForPost[1], "comment m0 on profile m3 [2]", nil)
			require.Equal(false, commentsForPost[1].IsHidden)
		}

		sort.Slice(corePosts, func(ii, jj int) bool {
			return corePosts[ii].TimestampNanos < corePosts[jj].TimestampNanos
		})

		{
			require.Equal(m0PkBytes, corePosts[0].PosterPublicKey)
			comparePostBody(corePosts[0], "m0 post body MODIFIED", nil)
			require.Equal(true, corePosts[0].IsHidden)
			require.Equal(int64(10*100), int64(corePosts[0].CreatorBasisPoints))
			require.Equal(int64(1.25*100*100), int64(corePosts[0].StakeMultipleBasisPoints))
		}
		{
			require.Equal(m0PkBytes, corePosts[1].PosterPublicKey)
			comparePostBody(corePosts[1], "m0 post body 2 no profile", nil)
			require.Equal(false, corePosts[1].IsHidden)
			require.Equal(int64(10*100), int64(corePosts[1].CreatorBasisPoints))
			require.Equal(int64(1.25*100*100), int64(corePosts[1].StakeMultipleBasisPoints))
		}
		{
			require.Equal(m1PkBytes, corePosts[2].PosterPublicKey)
			comparePostBody(corePosts[2], "m1 post body 1 no profile modified back", nil)
			require.Equal(false, corePosts[2].IsHidden)
			require.Equal(int64(10*100), int64(corePosts[2].CreatorBasisPoints))
			require.Equal(int64(1.25*100*100), int64(corePosts[2].StakeMultipleBasisPoints))
			require.Equal(int64(1), int64(corePosts[2].RepostCount))
		}
		{
			require.Equal(m2PkBytes, corePosts[3].PosterPublicKey)
			comparePostBody(corePosts[3], "m2 post body MODIFIED", nil)
			require.Equal(true, corePosts[3].IsHidden)
			require.Equal(int64(10*100), int64(corePosts[3].CreatorBasisPoints))
			require.Equal(int64(1.25*100*100), int64(corePosts[3].StakeMultipleBasisPoints))
			require.Equal(int64(0), int64(corePosts[3].RepostCount))
		}
		{
			require.Equal(m3PkBytes, corePosts[4].PosterPublicKey)
			comparePostBody(corePosts[4], "paramUpdater post body MODIFIED", nil)
			require.Equal(true, corePosts[4].IsHidden)
			require.Equal(int64(10*100), int64(corePosts[4].CreatorBasisPoints))
			require.Equal(int64(1.25*100*100), int64(corePosts[4].StakeMultipleBasisPoints))
			// Quote desos do not count towards repost count
			require.Equal(int64(0), int64(corePosts[4].RepostCount))
		}
		{
			require.Equal(m2PkBytes, corePosts[5].PosterPublicKey)
			comparePostBody(corePosts[5], "m2 post body 2 WITH profile", nil)
			require.Equal(false, corePosts[5].IsHidden)
			require.Equal(int64(10*100), int64(corePosts[5].CreatorBasisPoints))
			require.Equal(int64(1.25*100*100), int64(corePosts[5].StakeMultipleBasisPoints))
			// Quote desos do not count towards repost count
			require.Equal(int64(0), int64(corePosts[5].RepostCount))
		}
		{
			require.Equal(m1PkBytes, corePosts[10].PosterPublicKey)
			comparePostBody(corePosts[10], "", corePosts[2].PostHash)
			require.Equal(false, corePosts[10].IsHidden)
			m1Post2ReaderState := utxoView.GetPostEntryReaderState(m1PkBytes, corePosts[2])
			require.Equal(m1Post2ReaderState.RepostedByReader, true)
			require.Equal(m1Post2ReaderState.RepostPostHashHex, hex.EncodeToString(corePosts[10].PostHash[:]))
			// Make sure the utxoView has the correct repost entry mapping
			require.Equal(utxoView.RepostKeyToRepostEntry[MakeRepostKey(m1PkBytes, *corePosts[2].PostHash)],
				&RepostEntry{
					ReposterPubKey:   m1PkBytes,
					RepostedPostHash: corePosts[2].PostHash,
					RepostPostHash:   corePosts[10].PostHash,
				})
		}
		{
			require.Equal(m1PkBytes, corePosts[11].PosterPublicKey)
			comparePostBody(corePosts[11], "", corePosts[3].PostHash)
			require.Equal(true, corePosts[11].IsHidden)
			m1Post3ReaderState := utxoView.GetPostEntryReaderState(m1PkBytes, corePosts[3])
			// If we hide the repost, we expect RepostedByReader to be false, but RepostPostHashHex to still be set.
			require.Equal(m1Post3ReaderState.RepostedByReader, false)
			require.Equal(m1Post3ReaderState.RepostPostHashHex, hex.EncodeToString(corePosts[11].PostHash[:]))
			// Make sure the utxoView has the correct repost entry mapping
			require.Equal(utxoView.RepostKeyToRepostEntry[MakeRepostKey(m1PkBytes, *corePosts[3].PostHash)],
				&RepostEntry{
					ReposterPubKey:   m1PkBytes,
					RepostedPostHash: corePosts[3].PostHash,
					RepostPostHash:   corePosts[11].PostHash,
				})
		}
		{
			require.Equal(m1PkBytes, corePosts[12].PosterPublicKey)
			comparePostBody(corePosts[12], "quote-post", corePosts[4].PostHash)
			require.Equal(false, corePosts[12].IsHidden)
			m1Post4ReaderState := utxoView.GetPostEntryReaderState(m1PkBytes, corePosts[4])
			// Quote reposts do not impact PostEntryReaderState
			require.Equal(m1Post4ReaderState.RepostedByReader, false)
			require.Equal(m1Post4ReaderState.RepostPostHashHex, "")
			// Quote reposts do not make repost entry mappings
			_, repostEntryExists := utxoView.RepostKeyToRepostEntry[MakeRepostKey(m1PkBytes, *corePosts[4].PostHash)]
			require.False(repostEntryExists)
		}
		{
			require.Equal(m1PkBytes, corePosts[13].PosterPublicKey)
			comparePostBody(corePosts[13], "quote-post-hide-me", corePosts[5].PostHash)
			require.Equal(true, corePosts[13].IsHidden)
			m1Post5ReaderState := utxoView.GetPostEntryReaderState(m1PkBytes, corePosts[5])
			// Quote reposts do not impact PostEntryReaderState
			require.Equal(m1Post5ReaderState.RepostedByReader, false)
			require.Equal(m1Post5ReaderState.RepostPostHashHex, "")
			// Quote reposts do not make repost entry mappings
			_, repostEntryExists := utxoView.RepostKeyToRepostEntry[MakeRepostKey(m1PkBytes, *corePosts[5].PostHash)]
			require.False(repostEntryExists)
		}
	}
	checkPostsExist()

	// ===================================================================================
	// Finish it off with some transactions
	// ===================================================================================
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]
		fmt.Printf("Disconnecting transaction with type %v index %d (going backwards)\n", currentTxn.TxnMeta.GetTxnType(), backwardIter)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(expectedSenderBalances[backwardIter], _getBalance(t, chain, nil, PkToStringTestnet(currentTxn.PublicKey)))
	}

	// Verify that all the profiles have been deleted.
	checkPostsDeleted()

	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	for ii, tx := range txns {
		// See comment above on this transaction.
		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		require.Equal(expectedSenderBalances[ii], _getBalance(t, chain, mempool, PkToStringTestnet(tx.PublicKey)))

		_, err := mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}

	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii, txn := range txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Assert "before" comment counts are correct at a few different spots
		if ii == comment2CreatedTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 0)
		}
		if ii == comment3CreatedTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 1)
		}
		if ii == comment4CreatedTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 2)
		}
		if ii == comment3HiddenTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 3)
		}

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.NoError(err)

		// Assert "after" comment counts are correct at a few different spots
		if ii == comment2CreatedTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 1)
		}
		if ii == comment3CreatedTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 2)
		}
		if ii == comment4CreatedTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 3)
		}
		if ii == comment3HiddenTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 2)
		}
	}
	// Flush the utxoView after having added all the transactions.
	require.NoError(utxoView.FlushToDb())

	// Verify the profiles exist.
	checkPostsExist()

	// Disonnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView2, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		// Assert "before" comment counts are correct at a few different spots
		if backwardIter == comment3HiddenTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 2)
		}
		if backwardIter == comment4CreatedTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 3)
		}
		if backwardIter == comment3CreatedTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 2)
		}
		if backwardIter == comment2CreatedTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 1)
		}

		currentHash := currentTxn.Hash()
		err = utxoView2.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		// Assert "after" comment counts are correct at a few different spots
		if backwardIter == comment3HiddenTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 3)
		}
		if backwardIter == comment4CreatedTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 2)
		}
		if backwardIter == comment3CreatedTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 1)
		}
		if backwardIter == comment2CreatedTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 0)
		}
	}
	require.NoError(utxoView2.FlushToDb())
	require.Equal(expectedSenderBalances[0], _getBalance(t, chain, nil, senderPkString))

	// Verify that all the profiles have been deleted.
	checkPostsDeleted()

	// All the txns should be in the mempool already so mining a block should put
	// all those transactions in it.
	block, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(len(txnOps)+1, len(block.Txns))

	// Roll back the block and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := block.Header.Hash()
		require.NoError(err)
		utxoOps, err := GetUtxoOperationsForBlock(db, hash)
		require.NoError(err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(block.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(block, txHashes, utxoOps))

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
	}

	// Verify that all the profiles have been deleted.
	checkPostsDeleted()
}

func assertCommentCount(utxoView *UtxoView, require *require.Assertions, postHash *BlockHash,
	expectedCommentCount int) {
	corePosts, _, err := utxoView.GetAllPosts()
	require.NoError(err)

	post := findPostByPostHash(corePosts, postHash)
	require.Equal(uint64(expectedCommentCount), post.CommentCount)
}

func findPostByPostHash(posts []*PostEntry, targetPostHash *BlockHash) (_targetPost *PostEntry) {
	var targetPost *PostEntry
	for _, post := range posts {
		if reflect.DeepEqual(post.PostHash, targetPostHash) {
			targetPost = post
			break
		}
	}
	return targetPost
}

const (
	longPic       string = "data:image/jpeg;base64,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"
	shortPic      string = "data:image/jpeg;base64,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"
	otherShortPic string = "data:image/jpeg;base64,/9j/2wCEAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDIBCQkJDAsMGA0NGDIhHCEyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMv/AABEIAGQAZAMBIgACEQEDEQH/xAGiAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgsQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+gEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoLEQACAQIEBAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXxFxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo6ery8/T19vf4+fr/2gAMAwEAAhEDEQA/APf6KKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAoopGJVSQpYgcAd6AForyO++JmrHUJCgg05bZyj2dxHuckcEOeD/wB8fma7SDxpDH4Stte1OxurRJ3WNIVQyO5Y4UqBzhu2QDz0rSdKUEpPqZQrRnJxj08jqKKwbTxdp17p9/cwR3ZksB+/tGt2SdTjcAEbBJI6etXptasLU2KXU4gkvmCQRyAhmbaWwR2OAevpWZqaFFc5qfjfRtJv5bS5kuD5Gw3M8UDPFbb/ALvmOOFzViz8TQXfiSfQ2sryC5ihadZJkURyxhgu5SGJIJPcCgDbopnmx/N86/L97np9ar6hqVnpdjPe3twkNvAhkkdudq+uBzQBbopkM0c8SyROHRgCCD1p9ABRRRQAUjbtp2kBscZGRS0UAfP/AIkOqN4guzrccn29WAcW0a+XKv8AAU7gHpzkn7pzjFd34hsvEWo/DywXULaSbUlvbeaWOxTEiRrID9N4XqRgZ6V291o+n3t/a31zaxyXNoSYZGHKZ/n+PQ81exSV+rua1JwlFKMUn1fc8dvNEu7jQPE3m+H9WvVvmT+z2vYlkuxMImXe5z8qLwFPUZPFamt6UNU03wxqk3hm6uPsUyw3tvJbKZzCI2XG3PzLvIOPxr07FGKZkeb2R1HQb3WY7Xwvd3cerSQz2URRViRfLVDHMcny9u3pg8dKmvJ9Sk+IUtxbaPqcSHTH02O6EA8tZjJkPnP3B1z+lehYoxQB4gfCeq3Witaaf4fu7G8j0eaDUpJsAX05KlcHJ8w7lZg3vitbU9Ev/FDeJLj+wrqIz6PAlkt7EEYzp5nTk4YZ46dfevWcUYoA5/wetpHoax2miz6SqsN8M1uISz7RlsA8+mfaugoooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAP/9k="
)

func TestUpdateProfile(t *testing.T) {
	// For testing purposes, we set the fix block height to be 0 for the ParamUpdaterProfileUpdateFixBlockHeight.
	ParamUpdaterProfileUpdateFixBlockHeight = 0
	UpdateProfileFixBlockHeight = 0

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

	// Setup some convenience functions for the test.
	txnOps := [][]*UtxoOperation{}
	txns := []*MsgDeSoTxn{}
	expectedSenderBalances := []uint64{}

	// We take the block tip to be the blockchain height rather than the
	// header chain height.
	savedHeight := chain.blockTip().Height + 1
	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPk))

		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, senderPk, recipientPk,
			senderPriv, 70 /*amount to send*/, 11 /*feerate*/)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// Fund all the keys.
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)

	// Fund key to test CreateProfile fee
	registerOrTransfer("", senderPkString, m4Pub, senderPrivString)

	updateProfile := func(
		feeRateNanosPerKB uint64, updaterPkBase58Check string,
		updaterPrivBase58Check string, profilePubKey []byte, newUsername string,
		newDescription string, newProfilePic string, newCreatorBasisPoints uint64,
		newStakeMultipleBasisPoints uint64, isHidden bool) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, updaterPkBase58Check))

		currentOps, currentTxn, _, err := _updateProfile(
			t, chain, db, params,
			feeRateNanosPerKB, updaterPkBase58Check,
			updaterPrivBase58Check, profilePubKey, newUsername,
			newDescription, newProfilePic, newCreatorBasisPoints,
			newStakeMultipleBasisPoints, isHidden, false)

		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}
	_, _, _ = m2Priv, m3Priv, updateProfile

	updateGlobalParamsEntry := func(
		feeRateNanosPerKB uint64, updaterPkBase58Check string,
		updaterPrivBase58Check string,
		USDCentsPerBitcoinExchangeRate int64,
		minimumNetworkFeeNanosPerKb int64,
		createProfileFeeNanos int64) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, updaterPkBase58Check))

		currentOps, currentTxn, _, err := _updateGlobalParamsEntry(t, chain, db, params,
			feeRateNanosPerKB,
			updaterPkBase58Check,
			updaterPrivBase58Check,
			int64(InitialUSDCentsPerBitcoinExchangeRate),
			minimumNetworkFeeNanosPerKb,
			createProfileFeeNanos,
			0,  /*createNFTFeeNanos*/
			-1, /*maxCopiesPerNFT*/
			true)
		require.NoError(err)
		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// ===================================================================================
	// Do some UpdateProfile transactions
	// ===================================================================================

	// Zero input txn should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			0,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"I am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			2*100*100,     /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		blockHeight := chain.blockTip().Height
		if blockHeight < BalanceModelBlockHeight {
			require.Contains(err.Error(), RuleErrorTxnMustHaveAtLeastOneInput)
		} else {
			require.Contains(err.Error(), RuleErrorTxnFeeBelowNetworkMinimum)
		}
	}

	// Username too long should fail.
	{
		badUsername := string(append([]byte("badUsername: "),
			RandomBytes(int32(params.MaxUsernameLengthBytes))...))
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			10,            /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			badUsername,   /*newUsername*/
			"I am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			2*100*100,     /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileUsernameTooLong)
	}

	// Description too long should fail.
	{
		badDescription := string(append([]byte("badDescription: "),
			RandomBytes(int32(params.MaxUserDescriptionLengthBytes))...))
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			2,              /*feeRateNanosPerKB*/
			m0Pub,          /*updaterPkBase58Check*/
			m0Priv,         /*updaterPrivBase58Check*/
			[]byte{},       /*profilePubKey*/
			"m0",           /*newUsername*/
			badDescription, /*newDescription*/
			shortPic,       /*newProfilePic*/
			10*100,         /*newCreatorBasisPoints*/
			2*100*100,      /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileDescriptionTooLong)
	}

	// Profile pic too long should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			longPic,       /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			2*100*100,     /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorMaxProfilePicSize)
	}

	// Stake multiple too large should fail long too long should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			100*100*100,   /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileStakeMultipleSize)
	}

	// Stake multiple too small should fail long too long should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			.99*100*100,   /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileStakeMultipleSize)
	}

	// Creator percentage too large should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			101*100,       /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileCreatorPercentageSize)
	}

	// Invalid profile public key should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,               /*feeRateNanosPerKB*/
			m0Pub,           /*updaterPkBase58Check*/
			m0Priv,          /*updaterPrivBase58Check*/
			RandomBytes(33), /*profilePubKey*/
			"m0",            /*newUsername*/
			"i am the m0",   /*newDescription*/
			shortPic,        /*newProfilePic*/
			10*100,          /*newCreatorBasisPoints*/
			1.25*100*100,    /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		// This returned RuleErrorProfilePubKeyNotAuthorized for me once
		// "ConnectTransaction: : _connectUpdateProfile: ... RuleErrorProfilePubKeyNotAuthorized"
		require.Contains(err.Error(), RuleErrorProfileBadPublicKey)
	}

	// Profile public key that is not authorized should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			m1PkBytes,     /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfilePubKeyNotAuthorized)
	}

	// A simple registration should succeed
	{
		updateProfile(
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

	// Username that does not match our regex should fail
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			10,            /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0\x00",      /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidUsername)

		_, _, _, err = _updateProfile(
			t, chain, db, params,
			10,                /*feeRateNanosPerKB*/
			m1Pub,             /*updaterPkBase58Check*/
			m1Priv,            /*updaterPrivBase58Check*/
			[]byte{},          /*profilePubKey*/
			"m0 with a space", /*newUsername*/
			"i am the m0",     /*newDescription*/
			shortPic,          /*newProfilePic*/
			10*100,            /*newCreatorBasisPoints*/
			1.25*100*100,      /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidUsername)

		_, _, _, err = _updateProfile(
			t, chain, db, params,
			10,                  /*feeRateNanosPerKB*/
			m1Pub,               /*updaterPkBase58Check*/
			m1Priv,              /*updaterPrivBase58Check*/
			[]byte{},            /*profilePubKey*/
			"m0TraillingSpace ", /*newUsername*/
			"i am the m0",       /*newDescription*/
			shortPic,            /*newProfilePic*/
			10*100,              /*newCreatorBasisPoints*/
			1.25*100*100,        /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidUsername)

		_, _, _, err = _updateProfile(
			t, chain, db, params,
			10,            /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0-Hyphen",   /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidUsername)

		_, _, _, err = _updateProfile(
			t, chain, db, params,
			10,                    /*feeRateNanosPerKB*/
			m1Pub,                 /*updaterPkBase58Check*/
			m1Priv,                /*updaterPrivBase58Check*/
			[]byte{},              /*profilePubKey*/
			" m0SpaceAtBeginning", /*newUsername*/
			"i am the m0",         /*newDescription*/
			shortPic,              /*newProfilePic*/
			10*100,                /*newCreatorBasisPoints*/
			1.25*100*100,          /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidUsername)
	}

	// Trying to take an already-registered username should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileUsernameExists)

		// The username should be case-insensitive so creating a duplicate
		// with different casing should fail.
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"M0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileUsernameExists)

		// Register m1 and then try to steal the username
		updateProfile(
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

		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileUsernameExists)

		// The username should be case-insensitive so creating a duplicate
		// with different casing should fail.
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m1Pub,         /*updaterPkBase58Check*/
			m1Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"M0",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileUsernameExists)

		// The username should be case-insensitive so creating a duplicate
		// with different casing should fail.
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,             /*feeRateNanosPerKB*/
			m0Pub,         /*updaterPkBase58Check*/
			m0Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"M1",          /*newUsername*/
			"i am the m0", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfileUsernameExists)
	}

	// Register m2 (should succeed)
	{
		updateProfile(
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

	// Leaving username, description, and pic blank should result in a noop.
	{
		updateProfile(
			10,           /*feeRateNanosPerKB*/
			m2Pub,        /*updaterPkBase58Check*/
			m2Priv,       /*updaterPrivBase58Check*/
			[]byte{},     /*profilePubKey*/
			"",           /*newUsername*/
			"",           /*newDescription*/
			"",           /*newProfilePic*/
			10*100,       /*newCreatorBasisPoints*/
			1.25*100*100, /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// An update followed by a reversion should result in no change.
	{
		updateProfile(
			10,                   /*feeRateNanosPerKB*/
			m2Pub,                /*updaterPkBase58Check*/
			m2Priv,               /*updaterPrivBase58Check*/
			[]byte{},             /*profilePubKey*/
			"m2_update",          /*newUsername*/
			"i am the m2 update", /*newDescription*/
			shortPic+"woohoo",    /*newProfilePic*/
			15*100,               /*newCreatorBasisPoints*/
			1.7*100*100,          /*newStakeMultipleBasisPoints*/
			true /*isHidden*/)

		updateProfile(
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

	// A normal user updating their profile should succeed.
	{
		updateProfile(
			10,                 /*feeRateNanosPerKB*/
			m1Pub,              /*updaterPkBase58Check*/
			m1Priv,             /*updaterPrivBase58Check*/
			[]byte{},           /*profilePubKey*/
			"m1_updated_by_m1", /*newUsername*/
			"m1 updated by m1", /*newDescription*/
			otherShortPic,      /*newProfilePic*/
			12*100,             /*newCreatorBasisPoints*/
			1.6*100*100,        /*newStakeMultipleBasisPoints*/
			true /*isHidden*/)
	}

	// Normal user updating another user's profile should fail.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,                /*feeRateNanosPerKB*/
			m1Pub,            /*updaterPkBase58Check*/
			m1Priv,           /*updaterPrivBase58Check*/
			m0PkBytes,        /*profilePubKey*/
			"m0_actually_m1", /*newUsername*/
			"i am the m1",    /*newDescription*/
			shortPic,         /*newProfilePic*/
			10*100,           /*newCreatorBasisPoints*/
			1.25*100*100,     /*newStakeMultipleBasisPoints*/
			false /*isHidden*/, false)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorProfilePubKeyNotAuthorized)
	}

	// ParamUpdater updating another user's profile should succeed.
	{
		updateProfile(
			10,                           /*feeRateNanosPerKB*/
			m3Pub,                        /*updaterPkBase58Check*/
			m3Priv,                       /*updaterPrivBase58Check*/
			m0PkBytes,                    /*profilePubKey*/
			"m0_paramUpdater",            /*newUsername*/
			"m0 updated by paramUpdater", /*newDescription*/
			otherShortPic,                /*newProfilePic*/
			11*100,                       /*newCreatorBasisPoints*/
			1.5*100*100,                  /*newStakeMultipleBasisPoints*/
			true /*isHidden*/)
	}

	// ParamUpdater creating another user's profile should succeed.
	{
		updateProfile(
			10,                           /*feeRateNanosPerKB*/
			m3Pub,                        /*updaterPkBase58Check*/
			m3Priv,                       /*updaterPrivBase58Check*/
			m5PkBytes,                    /*profilePubKey*/
			"m5_paramUpdater",            /*newUsername*/
			"m5 created by paramUpdater", /*newDescription*/
			otherShortPic,                /*newProfilePic*/
			11*100,                       /*newCreatorBasisPoints*/
			1.5*100*100,                  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)
	}

	// Create Profile Fee and Minimum Network Fee tests
	{
		// Set the create profile fee to 100 nanos
		updateGlobalParamsEntry(
			100,
			m3Pub,
			m3Priv,
			int64(InitialUSDCentsPerBitcoinExchangeRate),
			0,
			100)

		// m4 does not have enough to create a profile including fee
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,
			m4Pub,
			m4Priv,
			m4PkBytes,
			"m4_username",
			"m4 desc",
			shortPic,
			11*100,
			1.5*100*100,
			false, false)
		blockHeight := chain.blockTip().Height + 1
		require.Error(err)
		if blockHeight < BalanceModelBlockHeight {
			require.Contains(err.Error(), RuleErrorCreateProfileTxnOutputExceedsInput)
		} else {
			require.Contains(err.Error(), RuleErrorInsufficientBalance)
		}

		// For the balance model, check the new RuleErrorCreateProfileTxnWithInsufficientFee
		if blockHeight >= BalanceModelBlockHeight {
			// Reduce the minimum network fee to 1 nanos per kb but make the create profile fee 50.
			updateGlobalParamsEntry(
				100,
				m3Pub,
				m3Priv,
				int64(InitialUSDCentsPerBitcoinExchangeRate),
				1,
				50)

			// Update profile fails as the fee is too low
			_, _, _, err = _updateProfile(
				t, chain, db, params,
				10,
				m4Pub,
				m4Priv,
				m4PkBytes,
				"m4_username",
				"m4 description",
				otherShortPic,
				11*100,
				1.5*100*100,
				false,
				true, /*forceZeroAdditionalFees*/
			)
			require.Error(err)
			require.Contains(err.Error(), RuleErrorCreateProfileTxnWithInsufficientFee)
		}

		// Reduce the create profile fee, Set minimum network fee to 10 nanos per kb
		updateGlobalParamsEntry(
			100,
			m3Pub,
			m3Priv,
			int64(InitialUSDCentsPerBitcoinExchangeRate),
			5,
			1)

		// Update profile fails as the fee is too low
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			1,
			m4Pub,
			m4Priv,
			m4PkBytes,
			"m4_username",
			"m4 description",
			otherShortPic,
			11*100,
			1.5*100*100,
			false, false,
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorTxnFeeBelowNetworkMinimum)

		// Update succeeds because fee is high enough and user has enough to meet fee.
		updateProfile(
			10,
			m4Pub,
			m4Priv,
			m4PkBytes,
			"m4",
			"m4 description",
			otherShortPic,
			11*100,
			1.5*100*100,
			false,
		)
		// Reset the create profile fee to 0 nanos (no fee) and set network minimum back to 0.
		updateGlobalParamsEntry(
			100,
			m3Pub,
			m3Priv,
			int64(InitialUSDCentsPerBitcoinExchangeRate),
			0,
			0)

	}

	// user0
	// m0Pub, m0_updated_by_paramUpdater, m0 updated by paramUpdater, otherShortPic, 11*100, 1.5*100*100, true
	// user1
	// m1Pub, m1_updated_by_m1, m1 updated by m1, otherShortPic, 12*100, 1.6*100*100, true
	// user2
	// m2Pub, m2, i am m2, 10*100, 1.25*100*100
	// user5
	// m5Pub, m5_paramUpdater, m5 created by paramUpdater, otherShortPic, 11*100, 1.5*100*100, false
	checkProfilesExist := func() {
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		profileEntriesByPublicKey, _, _, _, err := utxoView.GetAllProfiles(nil)
		require.NoError(err)
		// 3 profiles from seed txns
		require.Equal(8, len(profileEntriesByPublicKey))
		{
			m0Entry, m0Exists := profileEntriesByPublicKey[MakePkMapKey(m0PkBytes)]
			require.True(m0Exists)
			require.Equal(string(m0Entry.Username), "m0_paramUpdater")
			require.Equal(string(m0Entry.Description), "m0 updated by paramUpdater")
			require.Equal(string(m0Entry.ProfilePic), otherShortPic)
			require.Equal(int64(m0Entry.CreatorBasisPoints), int64(11*100))
			require.True(m0Entry.IsHidden)
		}
		{
			m1Entry, m1Exists := profileEntriesByPublicKey[MakePkMapKey(m1PkBytes)]
			require.True(m1Exists)
			require.Equal(string(m1Entry.Username), "m1_updated_by_m1")
			require.Equal(string(m1Entry.Description), "m1 updated by m1")
			require.Equal(string(m1Entry.ProfilePic), otherShortPic)
			require.Equal(int64(m1Entry.CreatorBasisPoints), int64(12*100))
			require.True(m1Entry.IsHidden)
		}
		{
			m2Entry, m2Exists := profileEntriesByPublicKey[MakePkMapKey(m2PkBytes)]
			require.True(m2Exists)
			require.Equal(string(m2Entry.Username), "m2")
			require.Equal(string(m2Entry.Description), "i am the m2")
			require.Equal(string(m2Entry.ProfilePic), shortPic)
			require.Equal(int64(m2Entry.CreatorBasisPoints), int64(10*100))
			require.False(m2Entry.IsHidden)
		}
		{
			m4Entry, m4Exists := profileEntriesByPublicKey[MakePkMapKey(m4PkBytes)]
			require.True(m4Exists)
			require.Equal(string(m4Entry.Username), "m4")
			require.Equal(string(m4Entry.Description), "m4 description")
			require.Equal(string(m4Entry.ProfilePic), otherShortPic)
			require.Equal(int64(m4Entry.CreatorBasisPoints), int64(11*100))
			require.False(m4Entry.IsHidden)
		}
		{
			m5Entry, m5Exists := profileEntriesByPublicKey[MakePkMapKey(m5PkBytes)]
			require.True(m5Exists)
			require.Equal(string(m5Entry.Username), "m5_paramUpdater")
			require.Equal(string(m5Entry.Description), "m5 created by paramUpdater")
			require.Equal(string(m5Entry.ProfilePic), otherShortPic)
			require.Equal(int64(m5Entry.CreatorBasisPoints), int64(11*100))
			require.False(m5Entry.IsHidden)
		}
	}
	checkProfilesExist()

	checkProfilesDeleted := func() {
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		profileEntriesByPublicKey, _, _, _, err := utxoView.GetAllProfiles(nil)
		require.NoError(err)
		// 3 remain because of the seed txns
		require.Equal(3, len(profileEntriesByPublicKey))
	}

	// ===================================================================================
	// Finish it off with some transactions
	// ===================================================================================
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]
		fmt.Printf("Disconnecting transaction with type %v index %d (going backwards)\n", currentTxn.TxnMeta.GetTxnType(), backwardIter)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(expectedSenderBalances[backwardIter], _getBalance(t, chain, nil, PkToStringTestnet(currentTxn.PublicKey)))
	}

	// Verify that all the profiles have been deleted.
	checkProfilesDeleted()

	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	for ii, tx := range txns {
		// See comment above on this transaction.
		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		require.Equal(expectedSenderBalances[ii], _getBalance(
			t, chain, mempool, PkToStringTestnet(tx.PublicKey)))

		_, err := mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}

	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii, txn := range txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err :=
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.NoError(err)
	}
	// Flush the utxoView after having added all the transactions.
	require.NoError(utxoView.FlushToDb())

	// Verify the profiles exist.
	checkProfilesExist()

	// Disonnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView2, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		currentHash := currentTxn.Hash()
		err = utxoView2.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)
	}
	require.NoError(utxoView2.FlushToDb())
	require.Equal(expectedSenderBalances[0], _getBalance(t, chain, nil, senderPkString))

	// Verify that all the profiles have been deleted.
	checkProfilesDeleted()

	// All the txns should be in the mempool already so mining a block should put
	// all those transactions in it.
	block, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(len(txnOps)+1, len(block.Txns))

	// Roll back the block and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := block.Header.Hash()
		require.NoError(err)
		utxoOps, err := GetUtxoOperationsForBlock(db, hash)
		require.NoError(err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(block.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(block, txHashes, utxoOps))

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
	}

	// Verify that all the profiles have been deleted.
	checkProfilesDeleted()
}

func TestPrivateMessage(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Mine a few blocks to give the senderPkString some money.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	// Setup some convenience functions for the test.
	txnOps := [][]*UtxoOperation{}
	txns := []*MsgDeSoTxn{}
	expectedSenderBalances := []uint64{}
	expectedRecipientBalances := []uint64{}

	// We take the block tip to be the blockchain height rather than the
	// header chain height.
	savedHeight := chain.blockTip().Height + 1
	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, senderPk, recipientPk,
			senderPriv, 7 /*amount to send*/, 11 /*feerate*/)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// Fund all the keys.
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)

	privateMessage := func(
		senderPkBase58Check string, recipientPkBase58Check string,
		senderPrivBase58Check string, unencryptedMessageText string, tstampNanos uint64,
		feeRateNanosPerKB uint64) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _privateMessage(
			t, chain, db, params, feeRateNanosPerKB, senderPkBase58Check,
			recipientPkBase58Check, senderPrivBase58Check, unencryptedMessageText, tstampNanos)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// ===================================================================================
	// Do some PrivateMessage transactions
	// ===================================================================================
	tstamp1 := uint64(time.Now().UnixNano())
	message1 := string(append([]byte("message1: "), RandomBytes(100)...))
	tstamp2 := uint64(time.Now().UnixNano())
	message2 := string(append([]byte("message2: "), RandomBytes(100)...))
	tstamp3 := uint64(time.Now().UnixNano())
	message3 := string(append([]byte("message3: "), RandomBytes(100)...))
	tstamp4 := uint64(time.Now().UnixNano())
	message4 := string(append([]byte("message4: "), RandomBytes(100)...))
	message5 := string(append([]byte("message5: "), RandomBytes(100)...))

	// Message where the sender is the recipient should fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		m0Pub, m0Priv, "test" /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageSenderPublicKeyEqualsRecipientPublicKey)

	// Message with length too long should fail.
	badMessage := string(append([]byte("badMessage: "),
		RandomBytes(int32(params.MaxPrivateMessageLengthBytes))...))
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, badMessage /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageEncryptedTextLengthExceedsMax)

	// Zero tstamp should fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, message1 /*unencryptedMessageText*/, 0)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageTstampIsZero)

	// m0 -> m1: message1, tstamp1
	privateMessage(
		m0Pub, m1Pub, m0Priv, message1, tstamp1, 0 /*feeRateNanosPerKB*/)

	// Duplicating (m0, tstamp1) should fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, message1 /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageExistsWithSenderPublicKeyTstampTuple)

	// Duplicating (m1, tstamp1) should fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m1Pub,
		m0Pub, m1Priv, message1 /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageExistsWithSenderPublicKeyTstampTuple)

	// Duplicating (m0, tstamp1) with a different sender should still fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m2Pub,
		m0Pub, m2Priv, message1 /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageExistsWithRecipientPublicKeyTstampTuple)

	// Duplicating (m1, tstamp1) with a different sender should still fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m2Pub,
		m1Pub, m2Priv, message1 /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageExistsWithRecipientPublicKeyTstampTuple)

	// m2 -> m1: message2, tstamp2
	privateMessage(
		m2Pub, m1Pub, m2Priv, message2, tstamp2, 10 /*feeRateNanosPerKB*/)

	// m3 -> m1: message3, tstamp3
	privateMessage(
		m3Pub, m1Pub, m3Priv, message3, tstamp3, 10 /*feeRateNanosPerKB*/)

	// m2 -> m1: message4Str, tstamp4
	privateMessage(
		m1Pub, m2Pub, m1Priv, message4, tstamp4, 10 /*feeRateNanosPerKB*/)

	// m2 -> m3: message5Str, tstamp1
	// Using tstamp1 should be OK since the message is between two new users.
	privateMessage(
		m2Pub, m3Pub, m2Priv, message5, tstamp1, 10 /*feeRateNanosPerKB*/)

	// Verify that the messages are as we expect them in the db.
	// 1: m0 m1
	// 2: m2 m1
	// 3: m3 m1
	// 4: m1 m2
	// 5: m2 m3
	// => m0: 1
	// 		m1: 4
	//    m2: 3
	//    m3: 2
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(1, len(messages))
		messageEntry := messages[0]
		require.Equal(messageEntry.SenderPublicKey, _strToPk(t, m0Pub))
		require.Equal(messageEntry.RecipientPublicKey, _strToPk(t, m1Pub))
		require.Equal(messageEntry.TstampNanos, tstamp1)
		require.Equal(messageEntry.isDeleted, false)
		priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), _strToPk(t, m1Priv))
		decryptedBytes, err := DecryptBytesWithPrivateKey(messageEntry.EncryptedText, priv.ToECDSA())
		require.NoError(err)
		require.Equal(message1, string(decryptedBytes))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(4, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(3, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(2, len(messages))
	}

	// ===================================================================================
	// Finish it off with some transactions
	// ===================================================================================
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]
		fmt.Printf("Disconnecting transaction with type %v index %d (going backwards)\n", currentTxn.TxnMeta.GetTxnType(), backwardIter)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(expectedSenderBalances[backwardIter], _getBalance(t, chain, nil, senderPkString))
		require.Equal(expectedRecipientBalances[backwardIter], _getBalance(t, chain, nil, recipientPkString))
	}

	// Verify that all the messages have been deleted.
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}

	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	for ii, tx := range txns {
		// See comment above on this transaction.
		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		require.Equal(expectedSenderBalances[ii], _getBalance(t, chain, mempool, senderPkString))
		require.Equal(expectedRecipientBalances[ii], _getBalance(t, chain, mempool, recipientPkString))

		acceptedTxns, err := mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, tx)
		require.Equal(1, len(acceptedTxns))
	}

	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii, txn := range txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err :=
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.NoError(err)
	}
	// Flush the utxoView after having added all the transactions.
	require.NoError(utxoView.FlushToDb())

	// Disonnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView2, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		currentHash := currentTxn.Hash()
		err = utxoView2.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)
	}
	require.NoError(utxoView2.FlushToDb())
	require.Equal(expectedSenderBalances[0], _getBalance(t, chain, nil, senderPkString))
	require.Equal(expectedRecipientBalances[0], _getBalance(t, chain, nil, recipientPkString))

	// Verify that all the messages have been deleted.
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}

	// Try and estimate the fees in a situation where the last block contains just a
	// block reward.
	{
		// Fee should just equal the min passed in because the block has so few transactions.
		require.Equal(int64(0), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 0)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 7)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 7)))
		require.Equal(int64(0), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 0)))
		require.Equal(int64(1), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 1)))
		require.Equal(int64(1), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 1)))
	}

	// All the txns should be in the mempool already so mining a block should put
	// all those transactions in it.
	block, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(len(txnOps)+1, len(block.Txns))
	// Estimate the transaction fees of the tip block in various ways.
	{
		// Threshold above what's in the block should return the default fee at all times.
		require.Equal(int64(0), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 0)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 7)))
		// Threshold below what's in the block should return the max of the median
		// and the minfee. This means with a low minfee the value returned should be
		// higher. And with a high minfee the value returned should be equal to the
		// fee.
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 7)))
		require.Equal(int64(4), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 0)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.01, 7)))
		require.Equal(int64(4), int64(chain.EstimateDefaultFeeRateNanosPerKB(.01, 1)))
	}

	// Roll back the block and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := block.Header.Hash()
		require.NoError(err)
		utxoOps, err := GetUtxoOperationsForBlock(db, hash)
		require.NoError(err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(block.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(block, txHashes, utxoOps))

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
	}

	// Verify that all the messages have been deleted.
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
}

func TestLikeTxns(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Mine a few blocks to give the senderPkString some money.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	// Setup some convenience functions for the test.
	txnOps := [][]*UtxoOperation{}
	txns := []*MsgDeSoTxn{}
	expectedSenderBalances := []uint64{}
	expectedRecipientBalances := []uint64{}

	// We take the block tip to be the blockchain height rather than the
	// header chain height.
	savedHeight := chain.blockTip().Height + 1
	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		expectedSenderBalances = append(
			expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(
			expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, senderPk, recipientPk,
			senderPriv, 7 /*amount to send*/, 11 /*feerate*/)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// Fund all the keys.
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)

	doLikeTxn := func(
		senderPkBase58Check string, likedPostHash BlockHash,
		senderPrivBase58Check string, isUnfollow bool, feeRateNanosPerKB uint64) {

		expectedSenderBalances = append(
			expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(
			expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _doLikeTxn(
			t, chain, db, params, feeRateNanosPerKB, senderPkBase58Check,
			likedPostHash, senderPrivBase58Check, isUnfollow)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	submitPost := func(
		feeRateNanosPerKB uint64, updaterPkBase58Check string,
		updaterPrivBase58Check string,
		postHashToModify []byte,
		parentStakeID []byte,
		bodyObj *DeSoBodySchema,
		repostedPostHash []byte,
		tstampNanos uint64,
		isHidden bool) {

		expectedSenderBalances = append(
			expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(
			expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _submitPost(
			t, chain, db, params, feeRateNanosPerKB,
			updaterPkBase58Check,
			updaterPrivBase58Check,
			postHashToModify,
			parentStakeID,
			bodyObj,
			repostedPostHash,
			tstampNanos,
			isHidden)

		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	fakePostHash := BlockHash{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
		0x30, 0x31,
	}
	// Attempting "m0 -> fakePostHash" should fail since the post doesn't exist.
	_, _, _, err = _doLikeTxn(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		fakePostHash, m0Priv, false /*isUnfollow*/)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorCannotLikeNonexistentPost)

	submitPost(
		10,       /*feeRateNanosPerKB*/
		m0Pub,    /*updaterPkBase58Check*/
		m0Priv,   /*updaterPrivBase58Check*/
		[]byte{}, /*postHashToModify*/
		[]byte{}, /*parentStakeID*/
		&DeSoBodySchema{Body: "m0 post body 1 no profile"}, /*body*/
		[]byte{},
		1602947011*1e9, /*tstampNanos*/
		false /*isHidden*/)
	post1Txn := txns[len(txns)-1]
	post1Hash := *post1Txn.Hash()

	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m0Pub,    /*updaterPkBase58Check*/
			m0Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body 2 no profile"}, /*body*/
			[]byte{},
			1502947012*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post2Txn := txns[len(txns)-1]
	post2Hash := *post2Txn.Hash()

	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m1Pub,    /*updaterPkBase58Check*/
			m1Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "m1 post body 1 no profile"}, /*body*/
			[]byte{},
			1502947013*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post3Txn := txns[len(txns)-1]
	post3Hash := *post3Txn.Hash()

	// m0 -> p1
	doLikeTxn(m0Pub, post1Hash, m0Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// Duplicating "m0 -> p1" should fail.
	_, _, _, err = _doLikeTxn(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		post1Hash, m0Priv, false /*isUnfollow*/)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorLikeEntryAlreadyExists)

	// m2 -> p1
	doLikeTxn(m2Pub, post1Hash, m2Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m3 -> p1
	doLikeTxn(m3Pub, post1Hash, m3Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m3 -> p2
	doLikeTxn(m3Pub, post2Hash, m3Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m1 -> p2
	doLikeTxn(m1Pub, post2Hash, m1Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m2 -> p3
	doLikeTxn(m2Pub, post3Hash, m2Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	likingP1 := [][]byte{
		_strToPk(t, m0Pub),
		_strToPk(t, m2Pub),
		_strToPk(t, m3Pub),
	}

	likingP2 := [][]byte{
		_strToPk(t, m1Pub),
		_strToPk(t, m3Pub),
	}

	likingP3 := [][]byte{
		_strToPk(t, m2Pub),
	}

	// Verify pks liking p1 and check like count.
	{
		likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post1Hash)
		require.NoError(err)
		require.Equal(len(likingP1), len(likingPks))
		for ii := 0; ii < len(likingPks); ii++ {
			require.Contains(likingP1, likingPks[ii])
		}
		post1 := DBGetPostEntryByPostHash(db, &post1Hash)
		require.Equal(uint64(len(likingP1)), post1.LikeCount)
	}

	// Verify pks liking p2 and check like count.
	{
		likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post2Hash)
		require.NoError(err)
		require.Equal(len(likingP2), len(likingPks))
		for ii := 0; ii < len(likingPks); ii++ {
			require.Contains(likingP2, likingPks[ii])
		}
		post2 := DBGetPostEntryByPostHash(db, &post2Hash)
		require.Equal(uint64(len(likingP2)), post2.LikeCount)
	}

	// Verify pks liking p3 and check like count.
	{
		likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post3Hash)
		require.NoError(err)
		require.Equal(len(likingP3), len(likingPks))
		for ii := 0; ii < len(likingPks); ii++ {
			require.Contains(likingP3, likingPks[ii])
		}
		post3 := DBGetPostEntryByPostHash(db, &post3Hash)
		require.Equal(uint64(len(likingP3)), post3.LikeCount)
	}

	m0Likes := []BlockHash{
		post1Hash,
	}

	m1Likes := []BlockHash{
		post2Hash,
	}

	m2Likes := []BlockHash{
		post1Hash,
		post3Hash,
	}

	m3Likes := []BlockHash{
		post1Hash,
		post2Hash,
	}

	// Verify m0's likes.
	{
		likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(len(m0Likes), len(likedPostHashes))
		for ii := 0; ii < len(likedPostHashes); ii++ {
			require.Contains(m0Likes, *likedPostHashes[ii])
		}
	}

	// Verify m1's likes.
	{
		likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(len(m1Likes), len(likedPostHashes))
		for ii := 0; ii < len(likedPostHashes); ii++ {
			require.Contains(m1Likes, *likedPostHashes[ii])
		}
	}

	// Verify m2's likes.
	{
		likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(len(m2Likes), len(likedPostHashes))
		for ii := 0; ii < len(likedPostHashes); ii++ {
			require.Contains(m2Likes, *likedPostHashes[ii])
		}
	}

	// Verify m3's likes.
	{
		likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(len(m3Likes), len(likedPostHashes))
		for ii := 0; ii < len(likedPostHashes); ii++ {
			require.Contains(m3Likes, *likedPostHashes[ii])
		}
	}

	// Try an "unlike."
	//
	// m0 -> p1 (unfollow)
	doLikeTxn(m0Pub, post1Hash, m0Priv, true /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m3 -> p2 (unfollow)
	doLikeTxn(m3Pub, post2Hash, m3Priv, true /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// Duplicating "m0 -> p1" (unfollow) should fail.
	_, _, _, err = _doLikeTxn(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		post1Hash, m0Priv, true /*isUnfollow*/)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorCannotUnlikeWithoutAnExistingLike)

	likingP1 = [][]byte{
		_strToPk(t, m2Pub),
		_strToPk(t, m3Pub),
	}

	likingP2 = [][]byte{
		_strToPk(t, m1Pub),
	}

	// Verify pks liking p1 and check like count.
	{
		likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post1Hash)
		require.NoError(err)
		require.Equal(len(likingP1), len(likingPks))
		for ii := 0; ii < len(likingPks); ii++ {
			require.Contains(likingP1, likingPks[ii])
		}
		post1 := DBGetPostEntryByPostHash(db, &post1Hash)
		require.Equal(uint64(len(likingP1)), post1.LikeCount)
	}

	// Verify pks liking p2 and check like count.
	{
		likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post2Hash)
		require.NoError(err)
		require.Equal(len(likingP2), len(likingPks))
		for ii := 0; ii < len(likingPks); ii++ {
			require.Contains(likingP2, likingPks[ii])
		}
		post2 := DBGetPostEntryByPostHash(db, &post2Hash)
		require.Equal(uint64(len(likingP2)), post2.LikeCount)
	}

	m3Likes = []BlockHash{
		post1Hash,
	}

	// Verify m0 has no likes.
	{
		likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(likedPostHashes))
	}

	// Verify m3's likes.
	{
		likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(len(m3Likes), len(likedPostHashes))
		for i := 0; i < len(likedPostHashes); i++ {
			require.Contains(m3Likes, *likedPostHashes[i])
		}
	}

	// ===================================================================================
	// Finish it off with some transactions
	// ===================================================================================
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]
		fmt.Printf(
			"Disconnecting transaction with type %v index %d (going backwards)\n",
			currentTxn.TxnMeta.GetTxnType(), backwardIter)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(
			int64(expectedSenderBalances[backwardIter]),
			int64(_getBalance(t, chain, nil, senderPkString)))
		require.Equal(
			expectedRecipientBalances[backwardIter],
			_getBalance(t, chain, nil, recipientPkString))

		// Here we check the like counts after all the like entries have been disconnected.
		if backwardIter == 19 {
			post1 := DBGetPostEntryByPostHash(db, &post1Hash)
			require.Equal(uint64(0), post1.LikeCount)
			post2 := DBGetPostEntryByPostHash(db, &post2Hash)
			require.Equal(uint64(0), post2.LikeCount)
			post3 := DBGetPostEntryByPostHash(db, &post3Hash)
			require.Equal(uint64(0), post3.LikeCount)
		}
	}

	testDisconnectedState := func() {
		// Verify that all the pks liking each post hash have been deleted and like count == 0.
		{
			likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post1Hash)
			require.NoError(err)
			require.Equal(0, len(likingPks))
		}
		{
			likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post2Hash)
			require.NoError(err)
			require.Equal(0, len(likingPks))
		}
		{
			likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post3Hash)
			require.NoError(err)
			require.Equal(0, len(likingPks))
		}

		// Verify that all the post hashes liked by users have been deleted.
		{
			likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m0Pub))
			require.NoError(err)
			require.Equal(0, len(likedPostHashes))
		}
		{
			likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m1Pub))
			require.NoError(err)
			require.Equal(0, len(likedPostHashes))
		}
		{
			likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m2Pub))
			require.NoError(err)
			require.Equal(0, len(likedPostHashes))
		}
		{
			likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m3Pub))
			require.NoError(err)
			require.Equal(0, len(likedPostHashes))
		}
	}
	testDisconnectedState()

	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	for ii, tx := range txns {
		// See comment above on this transaction.
		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		require.Equal(expectedSenderBalances[ii], _getBalance(t, chain, mempool, senderPkString))
		require.Equal(expectedRecipientBalances[ii], _getBalance(t, chain, mempool, recipientPkString))

		_, err := mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}

	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii, txn := range txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err :=
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.NoError(err)
	}
	// Flush the utxoView after having added all the transactions.
	require.NoError(utxoView.FlushToDb())

	testConnectedState := func() {
		likingP1 = [][]byte{
			_strToPk(t, m2Pub),
			_strToPk(t, m3Pub),
		}

		likingP2 = [][]byte{
			_strToPk(t, m1Pub),
		}

		likingP3 := [][]byte{
			_strToPk(t, m2Pub),
		}

		// Verify pks liking p1 and check like count.
		{
			likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post1Hash)
			require.NoError(err)
			require.Equal(len(likingP1), len(likingPks))
			for ii := 0; ii < len(likingPks); ii++ {
				require.Contains(likingP1, likingPks[ii])
			}
			post1 := DBGetPostEntryByPostHash(db, &post1Hash)
			require.Equal(uint64(len(likingP1)), post1.LikeCount)
		}

		// Verify pks liking p2 and check like count.
		{
			likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post2Hash)
			require.NoError(err)
			require.Equal(len(likingP2), len(likingPks))
			for ii := 0; ii < len(likingPks); ii++ {
				require.Contains(likingP2, likingPks[ii])
			}
			post2 := DBGetPostEntryByPostHash(db, &post2Hash)
			require.Equal(uint64(len(likingP2)), post2.LikeCount)
		}

		// Verify pks liking p3 and check like count.
		{
			likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post3Hash)
			require.NoError(err)
			require.Equal(len(likingP3), len(likingPks))
			for ii := 0; ii < len(likingPks); ii++ {
				require.Contains(likingP3, likingPks[ii])
			}
			post3 := DBGetPostEntryByPostHash(db, &post3Hash)
			require.Equal(uint64(len(likingP3)), post3.LikeCount)
		}

		m1Likes := []BlockHash{
			post2Hash,
		}

		m2Likes := []BlockHash{
			post1Hash,
			post3Hash,
		}

		m3Likes = []BlockHash{
			post1Hash,
		}

		// Verify m0 has no likes.
		{
			followPks, err := DbGetPostHashesYouLike(db, _strToPk(t, m0Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}

		// Verify m1's likes.
		{
			likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m1Pub))
			require.NoError(err)
			require.Equal(len(m1Likes), len(likedPostHashes))
			for ii := 0; ii < len(likedPostHashes); ii++ {
				require.Contains(m1Likes, *likedPostHashes[ii])
			}
		}

		// Verify m2's likes.
		{
			likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m2Pub))
			require.NoError(err)
			require.Equal(len(m2Likes), len(likedPostHashes))
			for ii := 0; ii < len(likedPostHashes); ii++ {
				require.Contains(m2Likes, *likedPostHashes[ii])
			}
		}

		// Verify m3's likes.
		{
			likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m3Pub))
			require.NoError(err)
			require.Equal(len(m3Likes), len(likedPostHashes))
			for ii := 0; ii < len(likedPostHashes); ii++ {
				require.Contains(m3Likes, *likedPostHashes[ii])
			}
		}
	}
	testConnectedState()

	// Disconnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView2, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		currentHash := currentTxn.Hash()
		err = utxoView2.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)
	}
	require.NoError(utxoView2.FlushToDb())
	require.Equal(expectedSenderBalances[0], _getBalance(t, chain, nil, senderPkString))
	require.Equal(expectedRecipientBalances[0], _getBalance(t, chain, nil, recipientPkString))

	testDisconnectedState()

	// All the txns should be in the mempool already so mining a block should put
	// all those transactions in it.
	block, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(len(txnOps)+1, len(block.Txns))
	// Estimate the transaction fees of the tip block in various ways.
	{
		// Threshold above what's in the block should return the default fee at all times.
		require.Equal(int64(0), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 0)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 7)))
		// Threshold below what's in the block should return the max of the median
		// and the minfee. This means with a low minfee the value returned should be
		// higher. And with a high minfee the value returned should be equal to the
		// fee.
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 7)))
		require.Equal(int64(4), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 0)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.01, 7)))
		require.Equal(int64(4), int64(chain.EstimateDefaultFeeRateNanosPerKB(.01, 1)))
	}

	testConnectedState()

	// Roll back the block and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := block.Header.Hash()
		require.NoError(err)
		utxoOps, err := GetUtxoOperationsForBlock(db, hash)
		require.NoError(err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(block.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(block, txHashes, utxoOps))

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
	}

	testDisconnectedState()
}

func TestFollowTxns(t *testing.T) {
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

	// Setup some convenience functions for the test.
	txnOps := [][]*UtxoOperation{}
	txns := []*MsgDeSoTxn{}
	expectedSenderBalances := []uint64{}
	expectedRecipientBalances := []uint64{}

	// We take the block tip to be the blockchain height rather than the
	// header chain height.
	savedHeight := chain.blockTip().Height + 1
	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		expectedSenderBalances = append(
			expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(
			expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, senderPk, recipientPk,
			senderPriv, 7 /*amount to send*/, 11 /*feerate*/)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// Fund all the keys.
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)

	doFollowTxn := func(
		senderPkBase58Check string, followedPkBase58Check string,
		senderPrivBase58Check string, isUnfollow bool, feeRateNanosPerKB uint64) {

		expectedSenderBalances = append(
			expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(
			expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _doFollowTxn(
			t, chain, db, params, feeRateNanosPerKB, senderPkBase58Check,
			followedPkBase58Check, senderPrivBase58Check, isUnfollow)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	updateProfile := func(
		feeRateNanosPerKB uint64, updaterPkBase58Check string,
		updaterPrivBase58Check string, profilePubKey []byte, newUsername string,
		newDescription string, newProfilePic string, newCreatorBasisPoints uint64,
		newStakeMultipleBasisPoints uint64, isHidden bool) {

		expectedSenderBalances = append(
			expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(
			expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _updateProfile(
			t, chain, db, params,
			feeRateNanosPerKB, updaterPkBase58Check,
			updaterPrivBase58Check, profilePubKey, newUsername,
			newDescription, newProfilePic, newCreatorBasisPoints,
			newStakeMultipleBasisPoints, isHidden, false)

		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// Attempting to do "m0 -> m1" should fail since m1 doesn't have a profile yet.
	_, _, _, err = _doFollowTxn(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, false /*isUnfollow*/)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFollowingNonexistentProfile)

	// Add profiles so they can be followed.
	updateProfile(
		5,             /*feeRateNanosPerKB*/
		m1Pub,         /*updaterPkBase58Check*/
		m1Priv,        /*updaterPrivBase58Check*/
		[]byte{},      /*profilePubKey*/
		"m1",          /*newUsername*/
		"i am the m1", /*newDescription*/
		shortPic,      /*newProfilePic*/
		0,             /*newCreatorBasisPoints*/
		1.25*100*100,  /*newStakeMultipleBasisPoints*/
		false /*isHidden*/)

	updateProfile(
		5,             /*feeRateNanosPerKB*/
		m2Pub,         /*updaterPkBase58Check*/
		m2Priv,        /*updaterPrivBase58Check*/
		[]byte{},      /*profilePubKey*/
		"m2",          /*newUsername*/
		"i am the m2", /*newDescription*/
		shortPic,      /*newProfilePic*/
		0,             /*newCreatorBasisPoints*/
		1.25*100*100,  /*newStakeMultipleBasisPoints*/
		false /*isHidden*/)

	updateProfile(
		5,             /*feeRateNanosPerKB*/
		m3Pub,         /*updaterPkBase58Check*/
		m3Priv,        /*updaterPrivBase58Check*/
		[]byte{},      /*profilePubKey*/
		"m3",          /*newUsername*/
		"i am the m3", /*newDescription*/
		shortPic,      /*newProfilePic*/
		0,             /*newCreatorBasisPoints*/
		1.25*100*100,  /*newStakeMultipleBasisPoints*/
		false /*isHidden*/)

	// m0 -> m1
	doFollowTxn(m0Pub, m1Pub, m0Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// Duplicating "m0 -> m1" should fail.
	_, _, _, err = _doFollowTxn(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, false /*isUnfollow*/)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFollowEntryAlreadyExists)

	// m2 -> m1
	doFollowTxn(m2Pub, m1Pub, m2Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m3 -> m1
	doFollowTxn(m3Pub, m1Pub, m3Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m3 -> m2
	doFollowTxn(m3Pub, m2Pub, m3Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m1 -> m2
	doFollowTxn(m1Pub, m2Pub, m1Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m2 -> m3
	doFollowTxn(m2Pub, m3Pub, m2Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	followingM1 := [][]byte{
		_strToPk(t, m0Pub),
		_strToPk(t, m2Pub),
		_strToPk(t, m3Pub),
	}

	followingM2 := [][]byte{
		_strToPk(t, m1Pub),
		_strToPk(t, m3Pub),
	}

	followingM3 := [][]byte{
		_strToPk(t, m2Pub),
	}

	// Verify m0 has no follows.
	{
		followPks, err := DbGetPubKeysFollowingYou(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(followPks))
	}

	// Verify pks following and check like count m1.
	{
		followPks, err := DbGetPubKeysFollowingYou(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(len(followingM1), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(followingM1, followPks[ii])
		}
	}

	// Verify pks following and check like count m2.
	{
		followPks, err := DbGetPubKeysFollowingYou(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(len(followingM2), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(followingM2, followPks[ii])
		}
	}

	// Verify pks following and check like count m3.
	{
		followPks, err := DbGetPubKeysFollowingYou(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(len(followingM3), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(followingM3, followPks[ii])
		}
	}

	m0Follows := [][]byte{
		_strToPk(t, m1Pub),
	}

	m1Follows := [][]byte{
		_strToPk(t, m2Pub),
	}

	m2Follows := [][]byte{
		_strToPk(t, m1Pub),
		_strToPk(t, m3Pub),
	}

	m3Follows := [][]byte{
		_strToPk(t, m1Pub),
		_strToPk(t, m2Pub),
	}

	// Verify m0's follows.
	{
		followPks, err := DbGetPubKeysYouFollow(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(len(m0Follows), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(m0Follows, followPks[ii])
		}
	}

	// Verify m1's follows.
	{
		followPks, err := DbGetPubKeysYouFollow(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(len(m1Follows), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(m1Follows, followPks[ii])
		}
	}

	// Verify m2's follows.
	{
		followPks, err := DbGetPubKeysYouFollow(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(len(m2Follows), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(m2Follows, followPks[ii])
		}
	}

	// Verify m3's follows.
	{
		followPks, err := DbGetPubKeysYouFollow(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(len(m3Follows), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(m3Follows, followPks[ii])
		}
	}

	// Try an "unfollow".
	//
	// m0 -> m1 (unfollow)
	doFollowTxn(m0Pub, m1Pub, m0Priv, true /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m3 -> m2 (unfollow)
	doFollowTxn(m3Pub, m2Pub, m3Priv, true /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// Duplicating "m0 -> m1" (unfollow) should fail now that the follow entry is deleted.
	_, _, _, err = _doFollowTxn(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, true /*isUnfollow*/)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorCannotUnfollowNonexistentFollowEntry)

	followingM1 = [][]byte{
		_strToPk(t, m2Pub),
		_strToPk(t, m3Pub),
	}

	followingM2 = [][]byte{
		_strToPk(t, m1Pub),
	}

	// Verify pks following and check like count m1.
	{
		followPks, err := DbGetPubKeysFollowingYou(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(len(followingM1), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(followingM1, followPks[ii])
		}
	}

	// Verify pks following and check like count m2.
	{
		followPks, err := DbGetPubKeysFollowingYou(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(len(followingM2), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(followingM2, followPks[ii])
		}
	}

	m3Follows = [][]byte{
		_strToPk(t, m1Pub),
	}

	// Verify m0 has no follows.
	{
		followPks, err := DbGetPubKeysYouFollow(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(followPks))
	}

	// Verify m3's follows.
	{
		followPks, err := DbGetPubKeysYouFollow(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(len(m3Follows), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(m3Follows, followPks[ii])
		}
	}

	// ===================================================================================
	// Finish it off with some transactions
	// ===================================================================================
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)

	// This function tests the final state of applying all transactions to the view.
	testConnectedState := func() {

		followingM1 = [][]byte{
			_strToPk(t, m2Pub),
			_strToPk(t, m3Pub),
		}

		followingM2 = [][]byte{
			_strToPk(t, m1Pub),
		}

		followingM3 := [][]byte{
			_strToPk(t, m2Pub),
		}

		// Verify m0 has no follows.
		{
			followPks, err := DbGetPubKeysFollowingYou(db, _strToPk(t, m0Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}

		// Verify pks following and check like count m1.
		{
			followPks, err := DbGetPubKeysFollowingYou(db, _strToPk(t, m1Pub))
			require.NoError(err)
			require.Equal(len(followingM1), len(followPks))
			for ii := 0; ii < len(followPks); ii++ {
				require.Contains(followingM1, followPks[ii])
			}
		}

		// Verify pks following and check like count m2.
		{
			followPks, err := DbGetPubKeysFollowingYou(db, _strToPk(t, m2Pub))
			require.NoError(err)
			require.Equal(len(followingM2), len(followPks))
			for ii := 0; ii < len(followPks); ii++ {
				require.Contains(followingM2, followPks[ii])
			}
		}

		// Verify pks following and check like count m3.
		{
			followPks, err := DbGetPubKeysFollowingYou(db, _strToPk(t, m3Pub))
			require.NoError(err)
			require.Equal(len(followingM3), len(followPks))
			for i := 0; i < len(followPks); i++ {
				require.Contains(followingM3, followPks[i])
			}
		}

		m1Follows := [][]byte{
			_strToPk(t, m2Pub),
		}

		m2Follows := [][]byte{
			_strToPk(t, m1Pub),
			_strToPk(t, m3Pub),
		}

		m3Follows = [][]byte{
			_strToPk(t, m1Pub),
		}

		// Verify m0 has no follows.
		{
			followPks, err := DbGetPubKeysYouFollow(db, _strToPk(t, m0Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}

		// Verify m1's follows.
		{
			followPks, err := DbGetPubKeysYouFollow(db, _strToPk(t, m1Pub))
			require.NoError(err)
			require.Equal(len(m1Follows), len(followPks))
			for i := 0; i < len(followPks); i++ {
				require.Contains(m1Follows, followPks[i])
			}
		}

		// Verify m2's follows.
		{
			followPks, err := DbGetPubKeysYouFollow(db, _strToPk(t, m2Pub))
			require.NoError(err)
			require.Equal(len(m2Follows), len(followPks))
			for i := 0; i < len(followPks); i++ {
				require.Contains(m2Follows, followPks[i])
			}
		}

		// Verify m3's follows.
		{
			followPks, err := DbGetPubKeysYouFollow(db, _strToPk(t, m3Pub))
			require.NoError(err)
			require.Equal(len(m3Follows), len(followPks))
			for i := 0; i < len(followPks); i++ {
				require.Contains(m3Follows, followPks[i])
			}
		}
	}
	testConnectedState()

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]
		fmt.Printf("Disconnecting transaction with type %v index %d (going backwards)\n", currentTxn.TxnMeta.GetTxnType(), backwardIter)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(int64(expectedSenderBalances[backwardIter]), int64(_getBalance(t, chain, nil, senderPkString)))
		require.Equal(expectedRecipientBalances[backwardIter], _getBalance(t, chain, nil, recipientPkString))
	}

	// This function is used to test the state after all ops are rolled back.
	testDisconnectedState := func() {
		// Verify that all the pks following you have been deleted.
		{
			followPks, err := DbGetPubKeysFollowingYou(db, _strToPk(t, m0Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}
		{
			followPks, err := DbGetPubKeysFollowingYou(db, _strToPk(t, m1Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}
		{
			followPks, err := DbGetPubKeysFollowingYou(db, _strToPk(t, m2Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}
		{
			followPks, err := DbGetPubKeysFollowingYou(db, _strToPk(t, m3Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}

		// Verify that all the keys you followed have been deleted.
		{
			followPks, err := DbGetPubKeysYouFollow(db, _strToPk(t, m0Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}
		{
			followPks, err := DbGetPubKeysYouFollow(db, _strToPk(t, m1Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}
		{
			followPks, err := DbGetPubKeysYouFollow(db, _strToPk(t, m2Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}
		{
			followPks, err := DbGetPubKeysYouFollow(db, _strToPk(t, m3Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}
	}

	testDisconnectedState()

	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	for ii, tx := range txns {
		// See comment above on this transaction.
		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		require.Equal(expectedSenderBalances[ii], _getBalance(t, chain, mempool, senderPkString))
		require.Equal(expectedRecipientBalances[ii], _getBalance(t, chain, mempool, recipientPkString))

		_, err := mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}

	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii, txn := range txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err :=
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.NoError(err)
	}
	// Flush the utxoView after having added all the transactions.
	require.NoError(utxoView.FlushToDb())
	testConnectedState()

	// Disconnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView2, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		currentHash := currentTxn.Hash()
		err = utxoView2.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)
	}
	require.NoError(utxoView2.FlushToDb())
	require.Equal(expectedSenderBalances[0], _getBalance(t, chain, nil, senderPkString))
	require.Equal(expectedRecipientBalances[0], _getBalance(t, chain, nil, recipientPkString))

	testDisconnectedState()

	// All the txns should be in the mempool already so mining a block should put
	// all those transactions in it.
	block, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(len(txnOps)+1, len(block.Txns))
	// Estimate the transaction fees of the tip block in various ways.
	{
		// Threshold above what's in the block should return the default fee at all times.
		require.Equal(int64(0), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 0)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 7)))
		// Threshold below what's in the block should return the max of the median
		// and the minfee. This means with a low minfee the value returned should be
		// higher. And with a high minfee the value returned should be equal to the
		// fee.
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 7)))
		require.Equal(int64(4), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 0)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.01, 7)))
		require.Equal(int64(4), int64(chain.EstimateDefaultFeeRateNanosPerKB(.01, 1)))
	}

	testConnectedState()

	// Roll back the block and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := block.Header.Hash()
		require.NoError(err)
		utxoOps, err := GetUtxoOperationsForBlock(db, hash)
		require.NoError(err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(block.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(block, txHashes, utxoOps))

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
	}

	testDisconnectedState()
}

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

func _privStringToKeys(t *testing.T, privString string) (*btcec.PrivateKey, *btcec.PublicKey) {
	require := require.New(t)
	result, _, err := Base58CheckDecodePrefix(privString, 1)
	require.NoError(err)
	result = result[:len(result)-1]
	return btcec.PrivKeyFromBytes(btcec.S256(), result)
}

func _readBitcoinExchangeTestData(t *testing.T) (
	_blocks []*wire.MsgBlock, _headers []*wire.BlockHeader, _headerHeights []uint32) {

	require := require.New(t)

	blocks := []*wire.MsgBlock{}
	{
		data, err := ioutil.ReadFile(TestDataDir + "/bitcoin_testnet_blocks_containing_burn.txt")
		require.NoError(err)

		lines := strings.Split(string(data), "\n")
		lines = lines[:len(lines)-1]

		for _, ll := range lines {
			cols := strings.Split(ll, ",")
			blockHash := mustDecodeHexBlockHash(cols[0])
			block := &wire.MsgBlock{}
			blockBytes, err := hex.DecodeString(cols[1])
			require.NoError(err)

			err = block.Deserialize(bytes.NewBuffer(blockBytes))
			require.NoError(err)

			parsedBlockHash := (BlockHash)(block.BlockHash())
			require.Equal(*blockHash, parsedBlockHash)

			blocks = append(blocks, block)
		}
	}

	headers := []*wire.BlockHeader{}
	headerHeights := []uint32{}
	{
		data, err := ioutil.ReadFile(TestDataDir + "/bitcoin_testnet_headers_for_burn.txt")
		require.NoError(err)

		lines := strings.Split(string(data), "\n")
		lines = lines[:len(lines)-1]

		for _, ll := range lines {
			cols := strings.Split(ll, ",")

			// Parse the block height
			blockHeight, err := strconv.Atoi(cols[0])
			require.NoError(err)

			// Parse the header hash
			headerHashBytes, err := hex.DecodeString(cols[1])
			require.NoError(err)
			headerHash := BlockHash{}
			copy(headerHash[:], headerHashBytes[:])

			// Parse the header
			headerBytes, err := hex.DecodeString(cols[2])
			require.NoError(err)
			header := &wire.BlockHeader{}
			header.Deserialize(bytes.NewBuffer(headerBytes))

			// Verify that the header hash matches the hash of the header.
			require.Equal(headerHash, (BlockHash)(header.BlockHash()))

			headers = append(headers, header)
			headerHeights = append(headerHeights, uint32(blockHeight))
		}
	}
	return blocks, headers, headerHeights
}

// FakeTimeSource just returns the same time every time when called. It
// implements AddTimeSample and Offset just to satisfy the interface but
// doesn't actually make use of them.
type FakeTimeSource struct {
	TimeToReturn time.Time
}

func NewFakeTimeSource(timeToReturn time.Time) *FakeTimeSource {
	return &FakeTimeSource{
		TimeToReturn: timeToReturn,
	}
}

func (m *FakeTimeSource) AdjustedTime() time.Time {
	return m.TimeToReturn
}

func (m *FakeTimeSource) AddTimeSample(_ string, _ time.Time) {
}

func (m *FakeTimeSource) Offset() time.Duration {
	return 0
}

func GetTestParamsCopy(
	startHeader *wire.BlockHeader, startHeight uint32,
	paramss *DeSoParams, minBurnBlocks uint32,
) *DeSoParams {
	// Set the BitcoinExchange-related params to canned values.
	paramsCopy := *paramss
	headerHash := (BlockHash)(startHeader.BlockHash())
	paramsCopy.BitcoinStartBlockNode = NewBlockNode(
		nil,         /*ParentNode*/
		&headerHash, /*Hash*/
		startHeight,
		_difficultyBitsToHash(startHeader.Bits),
		// CumWork: We set the work of the start node such that, when added to all of the
		// blocks that follow it, it hurdles the min chain work.
		big.NewInt(0),
		// We are bastardizing the DeSo header to store Bitcoin information here.
		&MsgDeSoHeader{
			TstampSecs: uint64(startHeader.Timestamp.Unix()),
			Height:     0,
		},
		StatusBitcoinHeaderValidated,
	)

	return &paramsCopy
}

type MedianTimeSource interface {
	// AdjustedTime returns the current time adjusted by the median time
	// offset as calculated from the time samples added by AddTimeSample.
	AdjustedTime() time.Time

	// AddTimeSample adds a time sample that is used when determining the
	// median time of the added samples.
	AddTimeSample(id string, timeVal time.Time)

	// Offset returns the number of seconds to adjust the local clock based
	// upon the median of the time samples added by AddTimeData.
	Offset() time.Duration
}

func _dumpAndLoadMempool(mempool *DeSoMempool) {
	mempoolDir := os.TempDir()
	mempool.mempoolDir = mempoolDir
	mempool.DumpTxnsToDB()
	newMempool := NewDeSoMempool(
		mempool.bc, 0, /* rateLimitFeeRateNanosPerKB */
		0 /* minFeeRateNanosPerKB */, "", true,
		mempool.dataDir, mempoolDir)
	mempool.mempoolDir = ""
	mempool.resetPool(newMempool)
}

func TestBitcoinExchange(t *testing.T) {
	glog.Init()
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// Don't refresh the universal view for this test, since it causes a race condition
	// to trigger.
	// TODO: Lower this value to .1 and fix this race condition.
	ReadOnlyUtxoViewRegenerationIntervalSeconds = 100

	oldInitialUSDCentsPerBitcoinExchangeRate := InitialUSDCentsPerBitcoinExchangeRate
	InitialUSDCentsPerBitcoinExchangeRate = uint64(1350000)
	defer func() {
		InitialUSDCentsPerBitcoinExchangeRate = oldInitialUSDCentsPerBitcoinExchangeRate
	}()

	paramsTmp := DeSoTestnetParams
	paramsTmp.DeSoNanosPurchasedAtGenesis = 0
	chain, params, db := NewLowDifficultyBlockchainWithParams(&paramsTmp)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Read in the test Bitcoin blocks and headers.
	bitcoinBlocks, bitcoinHeaders, bitcoinHeaderHeights := _readBitcoinExchangeTestData(t)

	// Extract BitcoinExchange transactions from the test Bitcoin blocks.
	bitcoinExchangeTxns := []*MsgDeSoTxn{}
	for _, block := range bitcoinBlocks {
		currentBurnTxns, err :=
			ExtractBitcoinExchangeTransactionsFromBitcoinBlock(
				block, BitcoinTestnetBurnAddress, params)
		require.NoError(err)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentBurnTxns...)
	}

	// Verify that Bitcoin burn transactions are properly extracted from Bitcoin blocks
	// and the their burn amounts are computed correctly.
	require.Equal(9, len(bitcoinExchangeTxns))
	expectedBitcoinBurnAmounts := []int64{
		10000,
		12500,
		41000,
		20000,
		15000,
		50000,
		15000,
		20482,
		2490,
	}
	rateUpdateIndex := 4
	expectedDeSoNanosMinted := []int64{
		2700510570,
		3375631103,
		11072014581,
		5400951887,
		// We double the exchange rate at this point. Include a zero
		// here to account for this.
		0,
		8103578296,
		27011598923,
		8103381058,
		11064823217,
		1345146534,
	}
	blockIndexesForTransactions := []int{1, 1, 1, 1, 1, 1, 1, 3, 3}
	for ii, bitcoinExchangeTxn := range bitcoinExchangeTxns {
		txnMeta := bitcoinExchangeTxn.TxnMeta.(*BitcoinExchangeMetadata)
		burnTxn := txnMeta.BitcoinTransaction
		burnOutput, err := _computeBitcoinBurnOutput(
			burnTxn, BitcoinTestnetBurnAddress, params.BitcoinBtcdParams)
		require.NoError(err)
		assert.Equalf(expectedBitcoinBurnAmounts[ii], burnOutput,
			"Bitcoin burn amount for burn txn %d doesn't line up with "+
				"what is expected", ii)

		// Sanity-check that the Bitcoin block hashes line up.
		blockIndex := blockIndexesForTransactions[ii]
		blockForTxn := bitcoinBlocks[blockIndex]
		{
			hash1 := (BlockHash)(blockForTxn.BlockHash())
			hash2 := *txnMeta.BitcoinBlockHash
			require.Equalf(
				hash1, hash2,
				"Bitcoin block hash for txn does not line up with block hash: %v %v %d", &hash1, &hash2, ii)
		}

		// Sanity-check that the Merkle root lines up with what's in the block.
		{
			hash1 := (BlockHash)(blockForTxn.Header.MerkleRoot)
			hash2 := *txnMeta.BitcoinMerkleRoot
			require.Equalf(
				hash1, hash2,
				"Bitcoin merkle root for txn does not line up with block hash: %v %v %d", &hash1, &hash2, ii)
		}

		// Verify that the merkle proof checks out.
		{
			txHash := ((BlockHash)(txnMeta.BitcoinTransaction.TxHash()))
			merkleProofIsValid := merkletree.VerifyProof(
				txHash[:], txnMeta.BitcoinMerkleProof, txnMeta.BitcoinMerkleRoot[:])
			require.Truef(
				merkleProofIsValid, "Problem verifying merkle proof for burn txn %d", ii)
		}

		// Verify that using the wrong Merkle root doesn't work.
		{
			badBlock := bitcoinBlocks[blockIndex-1]
			badMerkleRoot := badBlock.Header.MerkleRoot[:]
			txHash := ((BlockHash)(txnMeta.BitcoinTransaction.TxHash()))
			merkleProofIsValid := merkletree.VerifyProof(
				txHash[:], txnMeta.BitcoinMerkleProof, badMerkleRoot)
			require.Falsef(
				merkleProofIsValid, "Bad Merkle root was actually verified for burn txn %d", ii)
		}

		// Verify that serializing and deserializing work for this transaction.
		bb, err := bitcoinExchangeTxn.ToBytes(false /*preSignature*/)
		require.NoError(err)
		parsedBitcoinExchangeTxn := &MsgDeSoTxn{}
		parsedBitcoinExchangeTxn.FromBytes(bb)
		require.Equal(bitcoinExchangeTxn, parsedBitcoinExchangeTxn)
	}

	// Find the header in our header list corresponding to the first test block,
	// which contains the first Bitcoin
	firstBitcoinBurnBlock := bitcoinBlocks[1]
	firstBitcoinBurnBlockHash := firstBitcoinBurnBlock.BlockHash()
	headerIndexOfFirstBurn := -1
	for headerIndex := range bitcoinHeaders {
		if firstBitcoinBurnBlockHash == bitcoinHeaders[headerIndex].BlockHash() {
			headerIndexOfFirstBurn = headerIndex
			break
		}
	}
	require.Greater(headerIndexOfFirstBurn, 0)

	minBurnBlocks := uint32(2)
	startHeaderIndex := 0
	paramsCopy := GetTestParamsCopy(
		bitcoinHeaders[startHeaderIndex], bitcoinHeaderHeights[startHeaderIndex],
		params, minBurnBlocks,
	)
	paramsCopy.BitcoinBurnAddress = BitcoinTestnetBurnAddress
	chain.params = paramsCopy
	// Reset the pool to give the mempool access to the new BitcoinManager object.
	mempool.resetPool(NewDeSoMempool(chain, 0, /* rateLimitFeeRateNanosPerKB */
		0, /* minFeeRateNanosPerKB */
		"" /*blockCypherAPIKey*/, false,
		"" /*dataDir*/, ""))

	// Validating the first Bitcoin burn transaction via a UtxoView should
	// fail because the block corresponding to it is not yet in the BitcoinManager.
	burnTxn1 := bitcoinExchangeTxns[0]
	burnTxn2 := bitcoinExchangeTxns[1]

	// Applying the full transaction with its merkle proof should work.
	{
		mempoolTxs, err := mempool.processTransaction(
			burnTxn1, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(1, len(mempoolTxs))
		require.Equal(1, len(mempool.poolMap))
		mempoolTxRet := mempool.poolMap[*mempoolTxs[0].Hash]
		require.Equal(
			mempoolTxRet.Tx.TxnMeta.(*BitcoinExchangeMetadata),
			burnTxn1.TxnMeta.(*BitcoinExchangeMetadata))
	}

	// According to the mempool, the balance of the user whose public key created
	// the Bitcoin burn transaction should now have some DeSo.
	pkBytes1, _ := hex.DecodeString(BitcoinTestnetPub1)
	pkBytes2, _ := hex.DecodeString(BitcoinTestnetPub2)
	pkBytes3, _ := hex.DecodeString(BitcoinTestnetPub3)
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool, nil)
		require.NoError(err)

		require.Equal(1, len(utxoEntries))
		assert.Equal(int64(2697810060), int64(utxoEntries[0].AmountNanos))
	}

	// The mempool should be able to process a burn transaction directly.
	{
		mempoolTxsAdded, err := mempool.processTransaction(
			burnTxn2, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
			true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(1, len(mempoolTxsAdded))
		require.Equal(2, len(mempool.poolMap))
		mempoolTxRet := mempool.poolMap[*mempoolTxsAdded[0].Hash]
		require.Equal(
			mempoolTxRet.Tx.TxnMeta.(*BitcoinExchangeMetadata),
			burnTxn2.TxnMeta.(*BitcoinExchangeMetadata))
	}

	// According to the mempool, the balances should have updated.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool, nil)
		require.NoError(err)

		require.Equal(1, len(utxoEntries))
		assert.Equal(int64(3372255472), int64(utxoEntries[0].AmountNanos))
	}

	// If the mempool is not consulted, the balances should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// The UtxoView should accept all of the burn transactions now that their blocks
	// have enough work built on them.

	// Set the founder public key to something else for the remainder of the test.
	// Give this public key a bit of money to play with.
	//oldFounderRewardPubKey := FounderRewardPubKeyBase58Check
	//FounderRewardPubKeyBase58Check = moneyPkString
	//defer func() {
	//FounderRewardPubKeyBase58Check = oldFounderRewardPubKey
	//}()

	// Make the moneyPkString the paramUpdater so they can update the exchange rate.
	params.ParamUpdaterPublicKeys = make(map[PkMapKey]bool)
	params.ParamUpdaterPublicKeys[MakePkMapKey(MustBase58CheckDecode(moneyPkString))] = true
	paramsCopy.ParamUpdaterPublicKeys = params.ParamUpdaterPublicKeys

	// Applying all the txns to the UtxoView should work. Include a rate update
	// in the middle.
	utxoOpsList := [][]*UtxoOperation{}
	{
		utxoView, err := NewUtxoView(db, paramsCopy, nil)
		require.NoError(err)

		// Add a placeholder where the rate update is going to be
		fff := append([]*MsgDeSoTxn{}, bitcoinExchangeTxns[:rateUpdateIndex]...)
		fff = append(fff, nil)
		fff = append(fff, bitcoinExchangeTxns[rateUpdateIndex:]...)
		bitcoinExchangeTxns = fff

		for ii := range bitcoinExchangeTxns {
			fmt.Println("Processing BitcoinExchange: ", ii)

			// When we hit the rate update, populate the placeholder.
			if ii == rateUpdateIndex {
				newUSDCentsPerBitcoin := uint64(27000 * 100)
				_, rateUpdateTxn, _, err := _updateUSDCentsPerBitcoinExchangeRate(
					t, chain, db, params, 100, /*feeRateNanosPerKB*/
					moneyPkString,
					moneyPrivString,
					newUSDCentsPerBitcoin)
				require.NoError(err)

				bitcoinExchangeTxns[ii] = rateUpdateTxn
				burnTxn := bitcoinExchangeTxns[ii]
				burnTxnSize := getTxnSize(*burnTxn)
				blockHeight := chain.blockTip().Height + 1
				utxoOps, totalInput, totalOutput, fees, err :=
					utxoView.ConnectTransaction(
						burnTxn, burnTxn.Hash(), burnTxnSize, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
				_, _, _ = totalInput, totalOutput, fees
				require.NoError(err)
				utxoOpsList = append(utxoOpsList, utxoOps)
				continue
			}

			burnTxn := bitcoinExchangeTxns[ii]
			burnTxnSize := getTxnSize(*burnTxn)
			blockHeight := chain.blockTip().Height + 1
			utxoOps, totalInput, totalOutput, fees, err :=
				utxoView.ConnectTransaction(
					burnTxn, burnTxn.Hash(), burnTxnSize, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.NoError(err)

			require.Equal(2, len(utxoOps))
			//fmt.Println(int64(totalInput), ",")
			assert.Equal(expectedDeSoNanosMinted[ii], int64(totalInput))
			assert.Equal(expectedDeSoNanosMinted[ii]*int64(paramsCopy.BitcoinExchangeFeeBasisPoints)/10000, int64(fees))
			assert.Equal(int64(fees), int64(totalInput-totalOutput))

			_, _, _ = ii, totalOutput, fees
			utxoOpsList = append(utxoOpsList, utxoOps)
		}

		// Flushing the UtxoView should work.
		require.NoError(utxoView.FlushToDb())
	}

	// The balances according to the db after the flush should be correct.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		require.Equal(5, len(utxoEntries))
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		// Note the 10bp fee.
		assert.Equal(int64(47475508103), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		require.Equal(1, len(utxoEntries))
		// Note the 10bp fee.
		assert.Equal(int64(8095277677), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(3, len(utxoEntries))
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		// Note the 10bp fee.
		assert.Equal(int64(22528672757), int64(totalBalance))
	}

	// Spending from the outputs created by a burn should work.
	desoPub1 := Base58CheckEncode(pkBytes1, false /*isPrivate*/, paramsCopy)
	priv1, _ := _privStringToKeys(t, BitcoinTestnetPriv1)
	desoPriv1 := Base58CheckEncode(priv1.Serialize(), true /*isPrivate*/, paramsCopy)
	desoPub2 := Base58CheckEncode(pkBytes2, false /*isPrivate*/, paramsCopy)
	priv2, _ := _privStringToKeys(t, BitcoinTestnetPriv2)
	desoPriv2 := Base58CheckEncode(priv2.Serialize(), true /*isPrivate*/, paramsCopy)
	desoPub3 := Base58CheckEncode(pkBytes3, false /*isPrivate*/, paramsCopy)
	priv3, _ := _privStringToKeys(t, BitcoinTestnetPriv3)
	desoPriv3 := Base58CheckEncode(priv3.Serialize(), true /*isPrivate*/, paramsCopy)
	{
		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, desoPub1, desoPub2,
			desoPriv1, 100000*100000 /*amount to send*/, 11 /*feerate*/)

		utxoOpsList = append(utxoOpsList, currentOps)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentTxn)
	}
	{
		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, desoPub3, desoPub1,
			desoPriv3, 60000*100000 /*amount to send*/, 11 /*feerate*/)

		utxoOpsList = append(utxoOpsList, currentOps)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentTxn)
	}
	{
		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, desoPub2, desoPub1,
			desoPriv2, 60000*100000 /*amount to send*/, 11 /*feerate*/)

		utxoOpsList = append(utxoOpsList, currentOps)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentTxn)
	}

	// The balances according to the db after the spends above should be correct.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(49455017177), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		assert.Equal(int64(2087182397), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(16517205024), int64(totalBalance))
	}

	{
		// Rolling back all the transactions should work.
		utxoView, err := NewUtxoView(db, paramsCopy, nil)
		require.NoError(err)
		for ii := range bitcoinExchangeTxns {
			index := len(bitcoinExchangeTxns) - 1 - ii
			burnTxn := bitcoinExchangeTxns[index]
			blockHeight := chain.blockTip().Height + 1
			err := utxoView.DisconnectTransaction(burnTxn, burnTxn.Hash(), utxoOpsList[index], blockHeight)
			require.NoErrorf(err, "Transaction index: %v", index)
		}

		// Flushing the UtxoView back to the db after rolling back the
		require.NoError(utxoView.FlushToDb())
	}

	// The balances according to the db after rolling back and flushing everything
	// should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Re-applying all the transactions to the view and rolling back without
	// flushing should be fine.
	utxoOpsList = [][]*UtxoOperation{}
	{
		utxoView, err := NewUtxoView(db, paramsCopy, nil)
		require.NoError(err)
		for ii, burnTxn := range bitcoinExchangeTxns {
			blockHeight := chain.blockTip().Height + 1
			burnTxnSize := getTxnSize(*burnTxn)
			utxoOps, totalInput, totalOutput, fees, err :=
				utxoView.ConnectTransaction(burnTxn, burnTxn.Hash(), burnTxnSize, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.NoError(err)

			if ii < len(expectedBitcoinBurnAmounts) {
				if ii != rateUpdateIndex {
					require.Equal(2, len(utxoOps))
					assert.Equal(int64(totalInput), expectedDeSoNanosMinted[ii])
					assert.Equal(int64(fees), expectedDeSoNanosMinted[ii]*int64(paramsCopy.BitcoinExchangeFeeBasisPoints)/10000)
					assert.Equal(int64(fees), int64(totalInput-totalOutput))
				}
			}

			utxoOpsList = append(utxoOpsList, utxoOps)
		}

		for ii := range bitcoinExchangeTxns {
			index := len(bitcoinExchangeTxns) - 1 - ii
			burnTxn := bitcoinExchangeTxns[index]
			blockHeight := chain.blockTip().Height + 1
			err := utxoView.DisconnectTransaction(burnTxn, burnTxn.Hash(), utxoOpsList[index], blockHeight)
			require.NoError(err)
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
	}

	// The balances according to the db after applying and unapplying all the
	// transactions to a view with a flush at the end should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Running all the transactions through the mempool should work and result
	// in all of them being added.
	{
		for _, burnTxn := range bitcoinExchangeTxns {
			// We have to remove the transactions first.
			mempool.inefficientRemoveTransaction(burnTxn)
		}
		for ii, burnTxn := range bitcoinExchangeTxns {
			require.Equal(ii, len(mempool.poolMap))
			mempoolTxsAdded, err := mempool.processTransaction(
				burnTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "on index: %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}
	}

	// Test that the mempool can be backed up properly by dumping them and then
	// reloading them.
	_dumpAndLoadMempool(mempool)

	// The balances according to the mempool after applying all the transactions
	// should be correct.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(49455017177), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, mempool, nil)
		require.NoError(err)
		assert.Equal(int64(2087182397), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(16517205024), int64(totalBalance))
	}

	// Remove all the transactions from the mempool.
	for _, burnTxn := range bitcoinExchangeTxns {
		mempool.inefficientRemoveTransaction(burnTxn)
	}

	// Check that removals hit the database properly by calling a dump and
	// then reloading the db state into the view.
	_dumpAndLoadMempool(mempool)

	// The balances should be zero after removing transactions from the mempool.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, mempool, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Re-add all of the transactions to the mempool so we can mine them into a block.
	{
		for _, burnTxn := range bitcoinExchangeTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				burnTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
			//require.Equal(0, len(mempool.immatureBitcoinTxns))
		}
	}

	// Check the db one more time after adding back all the txns.
	_dumpAndLoadMempool(mempool)

	// Mine a block with all the mempool transactions.
	miner.params = paramsCopy
	miner.BlockProducer.params = paramsCopy
	//
	// All the txns should be in the mempool already but only some of them have enough
	// burn work to satisfy the miner. Note we need to mine two blocks since the first
	// one just makes the DeSo chain time-current.
	finalBlock1, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_ = finalBlock1
	// Check the mempool dumps and loads from the db properly each time
	_dumpAndLoadMempool(mempool)

	finalBlock2, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_dumpAndLoadMempool(mempool)

	finalBlock3, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_dumpAndLoadMempool(mempool)

	finalBlock4, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_dumpAndLoadMempool(mempool)

	// Add one for the block reward.
	assert.Equal(len(finalBlock1.Txns), 1)
	// The first block should only have some of the Bitcoin txns since
	// the MinerBitcoinBurnWorkBlocks is higher than the regular burn work.
	assert.Equal(len(finalBlock2.Txns), 14)
	assert.Equal(len(finalBlock3.Txns), 1)
	require.Equal(len(finalBlock4.Txns), 1)

	// The balances after mining the block should line up.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(49455017177), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		assert.Equal(int64(2087182397), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(16517205024), int64(totalBalance))
	}

	// Roll back the blocks and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(db, paramsCopy, nil)
		require.NoError(err)

		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock4.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock4.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock4, txHashes, utxoOps))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock3.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock3.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock3, txHashes, utxoOps))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock2.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock2.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock2, txHashes, utxoOps))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock1.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock1.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock1, txHashes, utxoOps))
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
	}

	// The balances according to the db after applying and unapplying all the
	// transactions to a view with a flush at the end should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	_, _, _, _, _, _ = db, mempool, miner, bitcoinBlocks, bitcoinHeaders, bitcoinHeaderHeights
}

func TestBitcoinExchangeGlobalParams(t *testing.T) {
	glog.Init()
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// Don't refresh the universal view for this test, since it causes a race condition
	// to trigger.
	// TODO: Lower this value to .1 and fix this race condition.
	ReadOnlyUtxoViewRegenerationIntervalSeconds = 100

	oldInitialUSDCentsPerBitcoinExchangeRate := InitialUSDCentsPerBitcoinExchangeRate
	InitialUSDCentsPerBitcoinExchangeRate = uint64(1350000)
	defer func() {
		InitialUSDCentsPerBitcoinExchangeRate = oldInitialUSDCentsPerBitcoinExchangeRate
	}()

	paramsTmp := DeSoTestnetParams
	paramsTmp.DeSoNanosPurchasedAtGenesis = 0
	chain, params, db := NewLowDifficultyBlockchainWithParams(&paramsTmp)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Read in the test Bitcoin blocks and headers.
	bitcoinBlocks, bitcoinHeaders, bitcoinHeaderHeights := _readBitcoinExchangeTestData(t)

	// Extract BitcoinExchange transactions from the test Bitcoin blocks.
	bitcoinExchangeTxns := []*MsgDeSoTxn{}
	for _, block := range bitcoinBlocks {
		currentBurnTxns, err :=
			ExtractBitcoinExchangeTransactionsFromBitcoinBlock(
				block, BitcoinTestnetBurnAddress, params)
		require.NoError(err)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentBurnTxns...)
	}

	// Verify that Bitcoin burn transactions are properly extracted from Bitcoin blocks
	// and the their burn amounts are computed correctly.
	require.Equal(9, len(bitcoinExchangeTxns))
	expectedBitcoinBurnAmounts := []int64{
		10000,
		12500,
		41000,
		20000,
		15000,
		50000,
		15000,
		20482,
		2490,
	}
	rateUpdateIndex := 4
	expectedDeSoNanosMinted := []int64{
		2700510570,
		3375631103,
		11072014581,
		5400951887,
		// We double the exchange rate at this point. Include a zero
		// here to account for this.
		0,
		8103578296,
		27011598923,
		8103381058,
		11064823217,
		1345146534,
	}
	blockIndexesForTransactions := []int{1, 1, 1, 1, 1, 1, 1, 3, 3}
	for ii, bitcoinExchangeTxn := range bitcoinExchangeTxns {
		txnMeta := bitcoinExchangeTxn.TxnMeta.(*BitcoinExchangeMetadata)
		burnTxn := txnMeta.BitcoinTransaction
		burnOutput, err := _computeBitcoinBurnOutput(
			burnTxn, BitcoinTestnetBurnAddress, params.BitcoinBtcdParams)
		require.NoError(err)
		assert.Equalf(expectedBitcoinBurnAmounts[ii], burnOutput,
			"Bitcoin burn amount for burn txn %d doesn't line up with "+
				"what is expected", ii)

		// Sanity-check that the Bitcoin block hashes line up.
		blockIndex := blockIndexesForTransactions[ii]
		blockForTxn := bitcoinBlocks[blockIndex]
		{
			hash1 := (BlockHash)(blockForTxn.BlockHash())
			hash2 := *txnMeta.BitcoinBlockHash
			require.Equalf(
				hash1, hash2,
				"Bitcoin block hash for txn does not line up with block hash: %v %v %d", &hash1, &hash2, ii)
		}

		// Sanity-check that the Merkle root lines up with what's in the block.
		{
			hash1 := (BlockHash)(blockForTxn.Header.MerkleRoot)
			hash2 := *txnMeta.BitcoinMerkleRoot
			require.Equalf(
				hash1, hash2,
				"Bitcoin merkle root for txn does not line up with block hash: %v %v %d", &hash1, &hash2, ii)
		}

		// Verify that the merkle proof checks out.
		{
			txHash := ((BlockHash)(txnMeta.BitcoinTransaction.TxHash()))
			merkleProofIsValid := merkletree.VerifyProof(
				txHash[:], txnMeta.BitcoinMerkleProof, txnMeta.BitcoinMerkleRoot[:])
			require.Truef(
				merkleProofIsValid, "Problem verifying merkle proof for burn txn %d", ii)
		}

		// Verify that using the wrong Merkle root doesn't work.
		{
			badBlock := bitcoinBlocks[blockIndex-1]
			badMerkleRoot := badBlock.Header.MerkleRoot[:]
			txHash := ((BlockHash)(txnMeta.BitcoinTransaction.TxHash()))
			merkleProofIsValid := merkletree.VerifyProof(
				txHash[:], txnMeta.BitcoinMerkleProof, badMerkleRoot)
			require.Falsef(
				merkleProofIsValid, "Bad Merkle root was actually verified for burn txn %d", ii)
		}

		// Verify that serializing and deserializing work for this transaction.
		bb, err := bitcoinExchangeTxn.ToBytes(false /*preSignature*/)
		require.NoError(err)
		parsedBitcoinExchangeTxn := &MsgDeSoTxn{}
		parsedBitcoinExchangeTxn.FromBytes(bb)
		require.Equal(bitcoinExchangeTxn, parsedBitcoinExchangeTxn)
	}

	// Find the header in our header list corresponding to the first test block,
	// which contains the first Bitcoin
	firstBitcoinBurnBlock := bitcoinBlocks[1]
	firstBitcoinBurnBlockHash := firstBitcoinBurnBlock.BlockHash()
	headerIndexOfFirstBurn := -1
	for headerIndex := range bitcoinHeaders {
		if firstBitcoinBurnBlockHash == bitcoinHeaders[headerIndex].BlockHash() {
			headerIndexOfFirstBurn = headerIndex
			break
		}
	}
	require.Greater(headerIndexOfFirstBurn, 0)

	// Create a Bitcoinmanager that is current whose tip corresponds to the block
	// just before the block containing the first Bitcoin burn transaction.
	minBurnBlocks := uint32(2)
	startHeaderIndex := 0
	paramsCopy := GetTestParamsCopy(bitcoinHeaders[startHeaderIndex],
		bitcoinHeaderHeights[startHeaderIndex], params, minBurnBlocks)

	// Update some of the params to make them reflect what we've hacked into
	// the bitcoinManager.
	paramsCopy.BitcoinBurnAddress = BitcoinTestnetBurnAddress
	chain.params = paramsCopy
	// Reset the pool to give the mempool access to the new BitcoinManager object.
	mempool.resetPool(NewDeSoMempool(chain, 0, /* rateLimitFeeRateNanosPerKB */
		0, /* minFeeRateNanosPerKB */
		"" /*blockCypherAPIKey*/, false,
		"" /*dataDir*/, ""))

	//// Validating the first Bitcoin burn transaction via a UtxoView should
	//// fail because the block corresponding to it is not yet in the BitcoinManager.
	burnTxn1 := bitcoinExchangeTxns[0]
	burnTxn1Size := getTxnSize(*burnTxn1)
	txHash1 := burnTxn1.Hash()
	burnTxn2 := bitcoinExchangeTxns[1]

	// The user we just applied this transaction for should have a balance now.
	pkBytes1, _ := hex.DecodeString(BitcoinTestnetPub1)

	// Applying the full transaction with its merkle proof to the mempool should
	// replace the existing "unmined" version that we added previously.
	{
		mempoolTxs, err := mempool.processTransaction(
			burnTxn1, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(1, len(mempoolTxs))
		require.Equal(1, len(mempool.poolMap))
		mempoolTxRet := mempool.poolMap[*mempoolTxs[0].Hash]
		require.Equal(
			mempoolTxRet.Tx.TxnMeta.(*BitcoinExchangeMetadata),
			burnTxn1.TxnMeta.(*BitcoinExchangeMetadata))
	}

	// Applying the full txns a second time should fail.
	{
		mempoolTxs, err := mempool.processTransaction(
			burnTxn1, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
		require.Error(err)
		require.Equal(0, len(mempoolTxs))
		require.Equal(1, len(mempool.poolMap))
		mempoolTxRet := mempool.poolMap[*burnTxn1.Hash()]
		require.Equal(
			mempoolTxRet.Tx.TxnMeta.(*BitcoinExchangeMetadata),
			burnTxn1.TxnMeta.(*BitcoinExchangeMetadata))
	}

	// According to the mempool, the balance of the user whose public key created
	// the Bitcoin burn transaction should now have some DeSo.
	pkBytes2, _ := hex.DecodeString(BitcoinTestnetPub2)
	pkBytes3, _ := hex.DecodeString(BitcoinTestnetPub3)
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool, nil)
		require.NoError(err)

		require.Equal(1, len(utxoEntries))
		assert.Equal(int64(2697810060), int64(utxoEntries[0].AmountNanos))
	}

	// The mempool should be able to process a burn transaction directly.
	{
		mempoolTxsAdded, err := mempool.processTransaction(
			burnTxn2, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
			true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(1, len(mempoolTxsAdded))
		require.Equal(2, len(mempool.poolMap))
		mempoolTxRet := mempool.poolMap[*mempoolTxsAdded[0].Hash]
		require.Equal(
			mempoolTxRet.Tx.TxnMeta.(*BitcoinExchangeMetadata),
			burnTxn2.TxnMeta.(*BitcoinExchangeMetadata))
	}

	// According to the mempool, the balances should have updated.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool, nil)
		require.NoError(err)

		require.Equal(1, len(utxoEntries))
		assert.Equal(int64(3372255472), int64(utxoEntries[0].AmountNanos))
	}

	// If the mempool is not consulted, the balances should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Verify that adding the transaction to the UtxoView fails because there is
	// not enough work on the burn block yet.
	{
		utxoView, _ := NewUtxoView(db, paramsCopy, nil)
		blockHeight := chain.blockTip().Height + 1
		utxoView.ConnectTransaction(burnTxn1, txHash1, burnTxn1Size, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	}

	{
		utxoView, _ := NewUtxoView(db, paramsCopy, nil)
		blockHeight := chain.blockTip().Height + 1
		utxoView.ConnectTransaction(burnTxn1, txHash1, burnTxn1Size, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	}

	// The transaction should pass now
	{
		utxoView, _ := NewUtxoView(db, paramsCopy, nil)
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err :=
			utxoView.ConnectTransaction(burnTxn1, txHash1, burnTxn1Size, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.NoError(err)
	}

	// Make the moneyPkString the paramUpdater so they can update the exchange rate.
	params.ParamUpdaterPublicKeys = make(map[PkMapKey]bool)
	params.ParamUpdaterPublicKeys[MakePkMapKey(MustBase58CheckDecode(moneyPkString))] = true
	paramsCopy.ParamUpdaterPublicKeys = params.ParamUpdaterPublicKeys

	// Applying all the txns to the UtxoView should work. Include a rate update
	// in the middle.
	utxoOpsList := [][]*UtxoOperation{}
	{
		utxoView, err := NewUtxoView(db, paramsCopy, nil)
		require.NoError(err)

		// Add a placeholder where the rate update is going to be
		fff := append([]*MsgDeSoTxn{}, bitcoinExchangeTxns[:rateUpdateIndex]...)
		fff = append(fff, nil)
		fff = append(fff, bitcoinExchangeTxns[rateUpdateIndex:]...)
		bitcoinExchangeTxns = fff

		for ii := range bitcoinExchangeTxns {
			fmt.Println("Processing BitcoinExchange: ", ii)

			// When we hit the rate update, populate the placeholder.
			if ii == rateUpdateIndex {
				newUSDCentsPerBitcoin := int64(27000 * 100)
				_, rateUpdateTxn, _, err := _updateGlobalParamsEntry(t, chain, db, params, 10,
					moneyPkString, moneyPrivString, newUSDCentsPerBitcoin, 0, 0, 0, -1, false)

				require.NoError(err)

				bitcoinExchangeTxns[ii] = rateUpdateTxn
				burnTxn := bitcoinExchangeTxns[ii]
				burnTxnSize := getTxnSize(*burnTxn)
				blockHeight := chain.blockTip().Height + 1
				utxoOps, totalInput, totalOutput, fees, err :=
					utxoView.ConnectTransaction(
						burnTxn, burnTxn.Hash(), burnTxnSize, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
				_, _, _ = totalInput, totalOutput, fees
				require.NoError(err)
				utxoOpsList = append(utxoOpsList, utxoOps)
				continue
			}

			burnTxn := bitcoinExchangeTxns[ii]
			burnTxnSize := getTxnSize(*burnTxn)
			blockHeight := chain.blockTip().Height + 1
			utxoOps, totalInput, totalOutput, fees, err :=
				utxoView.ConnectTransaction(
					burnTxn, burnTxn.Hash(), burnTxnSize, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.NoError(err)

			require.Equal(2, len(utxoOps))
			//fmt.Println(int64(totalInput), ",")
			assert.Equal(expectedDeSoNanosMinted[ii], int64(totalInput))
			assert.Equal(expectedDeSoNanosMinted[ii]*int64(paramsCopy.BitcoinExchangeFeeBasisPoints)/10000, int64(fees))
			assert.Equal(int64(fees), int64(totalInput-totalOutput))

			_, _, _ = ii, totalOutput, fees
			utxoOpsList = append(utxoOpsList, utxoOps)
		}

		// Flushing the UtxoView should work.
		require.NoError(utxoView.FlushToDb())
	}

	// The balances according to the db after the flush should be correct.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		require.Equal(5, len(utxoEntries))
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		// Note the 10bp fee.
		assert.Equal(int64(47475508103), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		require.Equal(1, len(utxoEntries))
		// Note the 10bp fee.
		assert.Equal(int64(8095277677), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(3, len(utxoEntries))
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		// Note the 10bp fee.
		assert.Equal(int64(22528672757), int64(totalBalance))
	}

	// Spending from the outputs created by a burn should work.
	desoPub1 := Base58CheckEncode(pkBytes1, false /*isPrivate*/, paramsCopy)
	priv1, _ := _privStringToKeys(t, BitcoinTestnetPriv1)
	desoPriv1 := Base58CheckEncode(priv1.Serialize(), true /*isPrivate*/, paramsCopy)
	desoPub2 := Base58CheckEncode(pkBytes2, false /*isPrivate*/, paramsCopy)
	priv2, _ := _privStringToKeys(t, BitcoinTestnetPriv2)
	desoPriv2 := Base58CheckEncode(priv2.Serialize(), true /*isPrivate*/, paramsCopy)
	desoPub3 := Base58CheckEncode(pkBytes3, false /*isPrivate*/, paramsCopy)
	priv3, _ := _privStringToKeys(t, BitcoinTestnetPriv3)
	desoPriv3 := Base58CheckEncode(priv3.Serialize(), true /*isPrivate*/, paramsCopy)
	{
		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, desoPub1, desoPub2,
			desoPriv1, 100000*100000 /*amount to send*/, 11 /*feerate*/)

		utxoOpsList = append(utxoOpsList, currentOps)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentTxn)
	}
	{
		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, desoPub3, desoPub1,
			desoPriv3, 60000*100000 /*amount to send*/, 11 /*feerate*/)

		utxoOpsList = append(utxoOpsList, currentOps)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentTxn)
	}
	{
		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, desoPub2, desoPub1,
			desoPriv2, 60000*100000 /*amount to send*/, 11 /*feerate*/)

		utxoOpsList = append(utxoOpsList, currentOps)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentTxn)
	}

	// The balances according to the db after the spends above should be correct.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(49455017177), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		assert.Equal(int64(2087182397), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(16517205024), int64(totalBalance))
	}

	{
		// Rolling back all the transactions should work.
		utxoView, err := NewUtxoView(db, paramsCopy, nil)
		require.NoError(err)
		for ii := range bitcoinExchangeTxns {
			index := len(bitcoinExchangeTxns) - 1 - ii
			burnTxn := bitcoinExchangeTxns[index]
			blockHeight := chain.blockTip().Height + 1
			err := utxoView.DisconnectTransaction(burnTxn, burnTxn.Hash(), utxoOpsList[index], blockHeight)
			require.NoErrorf(err, "Transaction index: %v", index)
		}

		// Flushing the UtxoView back to the db after rolling back the
		require.NoError(utxoView.FlushToDb())
	}

	// The balances according to the db after rolling back and flushing everything
	// should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Re-applying all the transactions to the view and rolling back without
	// flushing should be fine.
	utxoOpsList = [][]*UtxoOperation{}
	{
		utxoView, err := NewUtxoView(db, paramsCopy, nil)
		require.NoError(err)
		for ii, burnTxn := range bitcoinExchangeTxns {
			blockHeight := chain.blockTip().Height + 1
			burnTxnSize := getTxnSize(*burnTxn)
			utxoOps, totalInput, totalOutput, fees, err :=
				utxoView.ConnectTransaction(burnTxn, burnTxn.Hash(), burnTxnSize, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.NoError(err)

			if ii < len(expectedBitcoinBurnAmounts) {
				if ii != rateUpdateIndex {
					require.Equal(2, len(utxoOps))
					assert.Equal(int64(totalInput), expectedDeSoNanosMinted[ii])
					assert.Equal(int64(fees), expectedDeSoNanosMinted[ii]*int64(paramsCopy.BitcoinExchangeFeeBasisPoints)/10000)
					assert.Equal(int64(fees), int64(totalInput-totalOutput))
				}
			}

			utxoOpsList = append(utxoOpsList, utxoOps)
		}

		for ii := range bitcoinExchangeTxns {
			index := len(bitcoinExchangeTxns) - 1 - ii
			burnTxn := bitcoinExchangeTxns[index]
			blockHeight := chain.blockTip().Height + 1
			err := utxoView.DisconnectTransaction(burnTxn, burnTxn.Hash(), utxoOpsList[index], blockHeight)
			require.NoError(err)
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
	}

	// The balances according to the db after applying and unapplying all the
	// transactions to a view with a flush at the end should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Running all the transactions through the mempool should work and result
	// in all of them being added.
	{
		for _, burnTxn := range bitcoinExchangeTxns {
			// We have to remove the transactions first.
			mempool.inefficientRemoveTransaction(burnTxn)
		}
		for ii, burnTxn := range bitcoinExchangeTxns {
			require.Equal(ii, len(mempool.poolMap))
			mempoolTxsAdded, err := mempool.processTransaction(
				burnTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "on index: %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}
	}

	// Test that the mempool can be backed up properly by dumping them and then
	// reloading them.
	_dumpAndLoadMempool(mempool)

	// The balances according to the mempool after applying all the transactions
	// should be correct.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(49455017177), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, mempool, nil)
		require.NoError(err)
		assert.Equal(int64(2087182397), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(16517205024), int64(totalBalance))
	}

	// Remove all the transactions from the mempool.
	for _, burnTxn := range bitcoinExchangeTxns {
		mempool.inefficientRemoveTransaction(burnTxn)
	}

	// Check that removals hit the database properly by calling a dump and
	// then reloading the db state into the view.
	_dumpAndLoadMempool(mempool)

	// The balances should be zero after removing transactions from the mempool.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, mempool, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Re-add all of the transactions to the mempool so we can mine them into a block.
	{
		for _, burnTxn := range bitcoinExchangeTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				burnTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
			//require.Equal(0, len(mempool.immatureBitcoinTxns))
		}
	}

	// Check the db one more time after adding back all the txns.
	_dumpAndLoadMempool(mempool)

	miner.params = paramsCopy
	miner.BlockProducer.params = paramsCopy

	// All the txns should be in the mempool already but only some of them have enough
	// burn work to satisfy the miner. Note we need to mine two blocks since the first
	// one just makes the DeSo chain time-current.
	finalBlock1, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_ = finalBlock1
	// Check the mempool dumps and loads from the db properly each time
	_dumpAndLoadMempool(mempool)

	finalBlock2, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_dumpAndLoadMempool(mempool)

	finalBlock3, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_dumpAndLoadMempool(mempool)

	finalBlock4, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_dumpAndLoadMempool(mempool)

	// Add one for the block reward.
	assert.Equal(len(finalBlock1.Txns), 1)
	// The first block should only have some of the Bitcoin txns since
	// the MinerBitcoinBurnWorkBlocks is higher than the regular burn work.
	assert.Equal(len(finalBlock2.Txns), 14)
	assert.Equal(len(finalBlock3.Txns), 1)
	require.Equal(len(finalBlock4.Txns), 1)

	// The balances after mining the block should line up.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(49455017177), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		assert.Equal(int64(2087182397), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(16517205024), int64(totalBalance))
	}

	// Roll back the blocks and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(db, paramsCopy, nil)
		require.NoError(err)

		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock4.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock4.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock4, txHashes, utxoOps))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock3.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock3.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock3, txHashes, utxoOps))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock2.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock2.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock2, txHashes, utxoOps))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock1.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock1.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock1, txHashes, utxoOps))
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
	}

	// The balances according to the db after applying and unapplying all the
	// transactions to a view with a flush at the end should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	_, _, _, _, _, _ = db, mempool, miner, bitcoinBlocks, bitcoinHeaders, bitcoinHeaderHeights
}

func TestSpendOffOfUnminedTxnsBitcoinExchange(t *testing.T) {
	glog.Init()
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	oldInitialUSDCentsPerBitcoinExchangeRate := InitialUSDCentsPerBitcoinExchangeRate
	InitialUSDCentsPerBitcoinExchangeRate = 1350000
	defer func() {
		InitialUSDCentsPerBitcoinExchangeRate = oldInitialUSDCentsPerBitcoinExchangeRate
	}()

	paramsTmp := DeSoTestnetParams
	paramsTmp.DeSoNanosPurchasedAtGenesis = 0
	chain, params, db := NewLowDifficultyBlockchainWithParams(&paramsTmp)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Read in the test Bitcoin blocks and headers.
	bitcoinBlocks, bitcoinHeaders, bitcoinHeaderHeights := _readBitcoinExchangeTestData(t)

	// Extract BitcoinExchange transactions from the test Bitcoin blocks.
	bitcoinExchangeTxns := []*MsgDeSoTxn{}
	for _, block := range bitcoinBlocks {
		currentBurnTxns, err :=
			ExtractBitcoinExchangeTransactionsFromBitcoinBlock(
				block, BitcoinTestnetBurnAddress, params)
		require.NoError(err)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentBurnTxns...)
	}

	// Verify that Bitcoin burn transactions are properly extracted from Bitcoin blocks
	// and the their burn amounts are computed correctly.
	require.Equal(9, len(bitcoinExchangeTxns))
	expectedBitcoinBurnAmounts := []int64{
		10000,
		12500,
		41000,
		20000,
		15000,
		50000,
		15000,
		20482,
		2490,
	}
	rateUpdateIndex := 4
	// We don't need these for this test because checking the final balances
	// is sufficient.
	//expectedDeSoNanosMinted := []int64{
	//2700510570,
	//3375631103,
	//11072014581,
	//5400951887,
	//// We double the exchange rate at this point. Include a zero
	//// here to account for this.
	//0,
	//8103578296,
	//27011598923,
	//8103381058,
	//11064823217,
	//1345146534,
	//}
	blockIndexesForTransactions := []int{1, 1, 1, 1, 1, 1, 1, 3, 3}
	for ii, bitcoinExchangeTxn := range bitcoinExchangeTxns {
		txnMeta := bitcoinExchangeTxn.TxnMeta.(*BitcoinExchangeMetadata)
		burnTxn := txnMeta.BitcoinTransaction
		burnOutput, err := _computeBitcoinBurnOutput(
			burnTxn, BitcoinTestnetBurnAddress, params.BitcoinBtcdParams)
		require.NoError(err)
		assert.Equalf(expectedBitcoinBurnAmounts[ii], burnOutput,
			"Bitcoin burn amount for burn txn %d doesn't line up with "+
				"what is expected", ii)

		// Sanity-check that the Bitcoin block hashes line up.
		blockIndex := blockIndexesForTransactions[ii]
		blockForTxn := bitcoinBlocks[blockIndex]
		{
			hash1 := (BlockHash)(blockForTxn.BlockHash())
			hash2 := *txnMeta.BitcoinBlockHash
			require.Equalf(
				hash1, hash2,
				"Bitcoin block hash for txn does not line up with block hash: %v %v %d", &hash1, &hash2, ii)
		}

		// Sanity-check that the Merkle root lines up with what's in the block.
		{
			hash1 := (BlockHash)(blockForTxn.Header.MerkleRoot)
			hash2 := *txnMeta.BitcoinMerkleRoot
			require.Equalf(
				hash1, hash2,
				"Bitcoin merkle root for txn does not line up with block hash: %v %v %d", &hash1, &hash2, ii)
		}

		// Verify that the merkle proof checks out.
		{
			txHash := ((BlockHash)(txnMeta.BitcoinTransaction.TxHash()))
			merkleProofIsValid := merkletree.VerifyProof(
				txHash[:], txnMeta.BitcoinMerkleProof, txnMeta.BitcoinMerkleRoot[:])
			require.Truef(
				merkleProofIsValid, "Problem verifying merkle proof for burn txn %d", ii)
		}

		// Verify that using the wrong Merkle root doesn't work.
		{
			badBlock := bitcoinBlocks[blockIndex-1]
			badMerkleRoot := badBlock.Header.MerkleRoot[:]
			txHash := ((BlockHash)(txnMeta.BitcoinTransaction.TxHash()))
			merkleProofIsValid := merkletree.VerifyProof(
				txHash[:], txnMeta.BitcoinMerkleProof, badMerkleRoot)
			require.Falsef(
				merkleProofIsValid, "Bad Merkle root was actually verified for burn txn %d", ii)
		}

		// Verify that serializing and deserializing work for this transaction.
		bb, err := bitcoinExchangeTxn.ToBytes(false /*preSignature*/)
		require.NoError(err)
		parsedBitcoinExchangeTxn := &MsgDeSoTxn{}
		parsedBitcoinExchangeTxn.FromBytes(bb)
		require.Equal(bitcoinExchangeTxn, parsedBitcoinExchangeTxn)
	}

	// Find the header in our header list corresponding to the first test block,
	// which contains the first Bitcoin
	firstBitcoinBurnBlock := bitcoinBlocks[1]
	firstBitcoinBurnBlockHash := firstBitcoinBurnBlock.BlockHash()
	headerIndexOfFirstBurn := -1
	for headerIndex := range bitcoinHeaders {
		if firstBitcoinBurnBlockHash == bitcoinHeaders[headerIndex].BlockHash() {
			headerIndexOfFirstBurn = headerIndex
			break
		}
	}
	require.Greater(headerIndexOfFirstBurn, 0)

	// Create a Bitcoinmanager that is current whose tip corresponds to the block
	// just before the block containing the first Bitcoin burn transaction.
	minBurnBlocks := uint32(2)
	startHeaderIndex := 0
	paramsCopy := GetTestParamsCopy(
		bitcoinHeaders[startHeaderIndex], bitcoinHeaderHeights[startHeaderIndex],
		params, minBurnBlocks,
	)

	// Update some of the params to make them reflect what we've hacked into
	// the bitcoinManager.
	paramsCopy.BitcoinBurnAddress = BitcoinTestnetBurnAddress
	chain.params = paramsCopy
	// Reset the pool to give the mempool access to the new BitcoinManager object.
	mempool.resetPool(NewDeSoMempool(chain, 0, /* rateLimitFeeRateNanosPerKB */
		0, /* minFeeRateNanosPerKB */
		"" /*blockCypherAPIKey*/, false,
		"" /*dataDir*/, ""))

	// The amount of work on the first burn transaction should be zero.
	burnTxn1 := bitcoinExchangeTxns[0]
	burnTxn1Size := getTxnSize(*burnTxn1)
	burnTxn2 := bitcoinExchangeTxns[1]
	txHash1 := burnTxn1.Hash()

	// The mempool should accept a BitcoinExchange transaction if its merkle proof
	// is empty, since it skips the merkle proof checks in this case.
	{
		txnCopy := *burnTxn1
		txnCopy.TxnMeta = &BitcoinExchangeMetadata{
			BitcoinTransaction: txnCopy.TxnMeta.(*BitcoinExchangeMetadata).BitcoinTransaction,
			BitcoinBlockHash:   &BlockHash{},
			BitcoinMerkleRoot:  &BlockHash{},
			BitcoinMerkleProof: []*merkletree.ProofPart{},
		}
		mempoolTxs, err := mempool.processTransaction(
			&txnCopy, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(1, len(mempoolTxs))
		require.Equal(1, len(mempool.poolMap))
	}

	// The user we just applied this transaction for should have a balance now.
	pkBytes1, _ := hex.DecodeString(BitcoinTestnetPub1)
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool, nil)
		require.NoError(err)

		require.Equal(1, len(utxoEntries))
		assert.Equal(int64(2697810060), int64(utxoEntries[0].AmountNanos))
	}

	// DO NOT process the Bitcoin block containing the first set of burn transactions.
	// This is the difference between this test and the previous test.

	// According to the mempool, the balance of the user whose public key created
	// the Bitcoin burn transaction should now have some DeSo.
	pkBytes2, _ := hex.DecodeString(BitcoinTestnetPub2)
	pkBytes3, _ := hex.DecodeString(BitcoinTestnetPub3)

	// The mempool should be able to process a burn transaction directly.
	{
		txnCopy := *burnTxn2
		txnCopy.TxnMeta = &BitcoinExchangeMetadata{
			BitcoinTransaction: txnCopy.TxnMeta.(*BitcoinExchangeMetadata).BitcoinTransaction,
			BitcoinBlockHash:   &BlockHash{},
			BitcoinMerkleRoot:  &BlockHash{},
			BitcoinMerkleProof: []*merkletree.ProofPart{},
		}
		mempoolTxsAdded, err := mempool.processTransaction(
			&txnCopy, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
			true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(1, len(mempoolTxsAdded))
		require.Equal(2, len(mempool.poolMap))
		mempoolTxRet := mempool.poolMap[*mempoolTxsAdded[0].Hash]
		require.Equal(
			mempoolTxRet.Tx.TxnMeta.(*BitcoinExchangeMetadata),
			txnCopy.TxnMeta.(*BitcoinExchangeMetadata))
	}

	// According to the mempool, the balances should have updated.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool, nil)
		require.NoError(err)

		require.Equal(1, len(utxoEntries))
		assert.Equal(int64(3372255472), int64(utxoEntries[0].AmountNanos))
	}

	// If the mempool is not consulted, the balances should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Make the moneyPkString the paramUpdater so they can update the exchange rate.
	params.ParamUpdaterPublicKeys = make(map[PkMapKey]bool)
	params.ParamUpdaterPublicKeys[MakePkMapKey(MustBase58CheckDecode(moneyPkString))] = true
	paramsCopy.ParamUpdaterPublicKeys = params.ParamUpdaterPublicKeys

	// Running the remaining transactions through the mempool should work and result
	// in all of them being added.
	{
		// Add a placeholder where the rate update is going to be
		fff := append([]*MsgDeSoTxn{}, bitcoinExchangeTxns[:rateUpdateIndex]...)
		fff = append(fff, nil)
		fff = append(fff, bitcoinExchangeTxns[rateUpdateIndex:]...)
		bitcoinExchangeTxns = fff

		for fakeIndex, burnTxn := range bitcoinExchangeTxns[2:] {
			realIndex := fakeIndex + 2
			if realIndex == rateUpdateIndex {
				newUSDCentsPerBitcoin := int64(27000 * 100)
				updaterPkBytes, _, err := Base58CheckDecode(moneyPkString)
				require.NoError(err)
				rateUpdateTxn, _, _, _, err := chain.CreateUpdateGlobalParamsTxn(
					updaterPkBytes,
					newUSDCentsPerBitcoin,
					0,
					0,
					-1,
					0,
					nil,
					100, /*feeRateNanosPerKB*/
					nil,
					[]*DeSoOutput{})
				require.NoError(err)
				// Sign the transaction now that its inputs are set up.
				_signTxn(t, rateUpdateTxn, moneyPrivString)

				bitcoinExchangeTxns[realIndex] = rateUpdateTxn
				burnTxn := bitcoinExchangeTxns[realIndex]

				require.Equal(realIndex, len(mempool.poolMap))
				mempoolTxsAdded, err := mempool.processTransaction(
					burnTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
					true /*verifySignatures*/)
				require.NoErrorf(err, "on index: %v", realIndex)
				require.Equal(1, len(mempoolTxsAdded))

				continue
			}

			txnCopy := *burnTxn
			txnCopy.TxnMeta = &BitcoinExchangeMetadata{
				BitcoinTransaction: txnCopy.TxnMeta.(*BitcoinExchangeMetadata).BitcoinTransaction,
				BitcoinBlockHash:   &BlockHash{},
				BitcoinMerkleRoot:  &BlockHash{},
				BitcoinMerkleProof: []*merkletree.ProofPart{},
			}
			require.Equal(realIndex, len(mempool.poolMap))
			mempoolTxsAdded, err := mempool.processTransaction(
				&txnCopy, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "on index: %v", realIndex)
			require.Equal(1, len(mempoolTxsAdded))
		}
	}

	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool, nil)
		require.NoError(err)
		require.Equal(5, len(utxoEntries))
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		// Note the 10bp fee.
		assert.Equal(int64(47475508103), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, mempool, nil)
		require.NoError(err)
		require.Equal(1, len(utxoEntries))
		// Note the 10bp fee.
		assert.Equal(int64(8095277677), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool, nil)
		require.NoError(err)
		require.Equal(3, len(utxoEntries))
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		// Note the 10bp fee.
		assert.Equal(int64(22528672757), int64(totalBalance))
	}

	// Spending from the outputs created by a burn should work.
	desoPub1 := Base58CheckEncode(pkBytes1, false /*isPrivate*/, paramsCopy)
	priv1, _ := _privStringToKeys(t, BitcoinTestnetPriv1)
	desoPriv1 := Base58CheckEncode(priv1.Serialize(), true /*isPrivate*/, paramsCopy)
	desoPub2 := Base58CheckEncode(pkBytes2, false /*isPrivate*/, paramsCopy)
	priv2, _ := _privStringToKeys(t, BitcoinTestnetPriv2)
	desoPriv2 := Base58CheckEncode(priv2.Serialize(), true /*isPrivate*/, paramsCopy)
	desoPub3 := Base58CheckEncode(pkBytes3, false /*isPrivate*/, paramsCopy)
	priv3, _ := _privStringToKeys(t, BitcoinTestnetPriv3)
	desoPriv3 := Base58CheckEncode(priv3.Serialize(), true /*isPrivate*/, paramsCopy)
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 100000*100000, 11, desoPub1, desoPub2,
			desoPriv1, mempool)
		mempoolTxsAdded, err := mempool.processTransaction(
			txn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
			true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(1, len(mempoolTxsAdded))
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, txn)
	}
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 60000*100000, 11, desoPub3, desoPub1,
			desoPriv3, mempool)
		mempoolTxsAdded, err := mempool.processTransaction(
			txn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
			true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(1, len(mempoolTxsAdded))
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, txn)
	}
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 60000*100000, 11, desoPub2, desoPub1,
			desoPriv2, mempool)
		mempoolTxsAdded, err := mempool.processTransaction(
			txn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
			true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(1, len(mempoolTxsAdded))
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, txn)
	}

	// The balances according to the db after the spends above should be correct.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(49455017177), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, mempool, nil)
		require.NoError(err)
		assert.Equal(int64(2087182397), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(16517205024), int64(totalBalance))
	}
	prevMempoolSize := len(mempool.poolMap)

	// The transaction should pass now
	{
		utxoView, _ := NewUtxoView(db, paramsCopy, nil)
		blockHeight := chain.blockTip().Height + 1

		_, _, _, _, err :=
			utxoView.ConnectTransaction(burnTxn1, txHash1, burnTxn1Size, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.NoError(err)
	}

	miner.params = paramsCopy
	miner.BlockProducer.params = paramsCopy

	// At this point, the mempool should contain *mined* BitcoinExchange
	// transactions with fully proper merkle proofs.

	// Now mining the blocks should get us the balances that the mempool
	// reported previously.
	finalBlock1, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_ = finalBlock1
	finalBlock2, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	finalBlock3, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	finalBlock4, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	// The first block should contain the txns because we mined a
	// block to get the chain current previously.
	require.Equal(len(finalBlock1.Txns), 1)
	require.Equal(len(finalBlock2.Txns), 14)
	require.Equal(len(finalBlock3.Txns), 1)
	require.Equal(len(finalBlock4.Txns), 1)

	// The transactions should all have been processed into blocks and
	// removed from the mempool.
	require.Equal(0, len(mempool.poolMap))
	// The balances should be what they were even if you query the mempool
	// because the txns have now moved into the db.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(49455017177), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, mempool, nil)
		require.NoError(err)
		assert.Equal(int64(2087182397), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(16517205024), int64(totalBalance))
	}

	// The balances after mining the block should line up.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(49455017177), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		assert.Equal(int64(2087182397), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(16517205024), int64(totalBalance))
	}

	// Roll back the blocks and make sure we don't hit any errors. Call
	// the mempool's disconnect function to make sure we get the txns
	// back during a reorg.
	{
		utxoView, err := NewUtxoView(db, paramsCopy, nil)
		require.NoError(err)

		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock4.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock4.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock4, txHashes, utxoOps))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock3.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock3.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock3, txHashes, utxoOps))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock2.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock2.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock2, txHashes, utxoOps))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock1.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock1.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock1, txHashes, utxoOps))
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())

		mempool.UpdateAfterDisconnectBlock(finalBlock4)
		mempool.UpdateAfterDisconnectBlock(finalBlock3)
		mempool.UpdateAfterDisconnectBlock(finalBlock2)
		mempool.UpdateAfterDisconnectBlock(finalBlock1)
	}

	// The balances according to the db without querying the mempool should
	// be zero again.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// The mempool should have all of its txns back and the balances should be what
	// they were before we did a block reorg.
	require.Equal(prevMempoolSize, len(mempool.poolMap))
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(49455017177), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, mempool, nil)
		require.NoError(err)
		assert.Equal(int64(2087182397), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(16517205024), int64(totalBalance))
	}

	_, _, _, _, _, _ = db, mempool, miner, bitcoinBlocks, bitcoinHeaders, bitcoinHeaderHeights
}

func TestBitcoinExchangeWithAmountNanosNonZeroAtGenesis(t *testing.T) {
	glog.Init()
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// Don't refresh the universal view for this test, since it causes a race condition
	// to trigger.
	// TODO: Lower this value to .1 and fix this race condition.
	ReadOnlyUtxoViewRegenerationIntervalSeconds = 100

	oldInitialUSDCentsPerBitcoinExchangeRate := InitialUSDCentsPerBitcoinExchangeRate
	InitialUSDCentsPerBitcoinExchangeRate = 1350000
	defer func() {
		InitialUSDCentsPerBitcoinExchangeRate = oldInitialUSDCentsPerBitcoinExchangeRate
	}()

	paramsTmp := DeSoTestnetParams
	paramsTmp.DeSoNanosPurchasedAtGenesis = 500000123456789
	chain, params, db := NewLowDifficultyBlockchainWithParams(&paramsTmp)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Read in the test Bitcoin blocks and headers.
	bitcoinBlocks, bitcoinHeaders, bitcoinHeaderHeights := _readBitcoinExchangeTestData(t)

	// Extract BitcoinExchange transactions from the test Bitcoin blocks.
	bitcoinExchangeTxns := []*MsgDeSoTxn{}
	for _, block := range bitcoinBlocks {
		currentBurnTxns, err :=
			ExtractBitcoinExchangeTransactionsFromBitcoinBlock(
				block, BitcoinTestnetBurnAddress, params)
		require.NoError(err)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentBurnTxns...)
	}

	// Verify that Bitcoin burn transactions are properly extracted from Bitcoin blocks
	// and the their burn amounts are computed correctly.
	require.Equal(9, len(bitcoinExchangeTxns))
	expectedBitcoinBurnAmounts := []int64{
		10000,
		12500,
		41000,
		20000,
		15000,
		50000,
		15000,
		20482,
		2490,
	}
	rateUpdateIndex := 4
	expectedDeSoNanosMinted := []int64{
		1909549696,
		2386933566,
		7829114379,
		3819064767,
		// We double the exchange rate at this point. Include a zero
		// here to account for this.
		0,
		5730125620,
		19100254365,
		5730026999,
		7824124112,
		951177121,
	}
	blockIndexesForTransactions := []int{1, 1, 1, 1, 1, 1, 1, 3, 3}
	for ii, bitcoinExchangeTxn := range bitcoinExchangeTxns {
		txnMeta := bitcoinExchangeTxn.TxnMeta.(*BitcoinExchangeMetadata)
		burnTxn := txnMeta.BitcoinTransaction
		burnOutput, err := _computeBitcoinBurnOutput(
			burnTxn, BitcoinTestnetBurnAddress, params.BitcoinBtcdParams)
		require.NoError(err)
		assert.Equalf(expectedBitcoinBurnAmounts[ii], burnOutput,
			"Bitcoin burn amount for burn txn %d doesn't line up with "+
				"what is expected", ii)

		// Sanity-check that the Bitcoin block hashes line up.
		blockIndex := blockIndexesForTransactions[ii]
		blockForTxn := bitcoinBlocks[blockIndex]
		{
			hash1 := (BlockHash)(blockForTxn.BlockHash())
			hash2 := *txnMeta.BitcoinBlockHash
			require.Equalf(
				hash1, hash2,
				"Bitcoin block hash for txn does not line up with block hash: %v %v %d", &hash1, &hash2, ii)
		}

		// Sanity-check that the Merkle root lines up with what's in the block.
		{
			hash1 := (BlockHash)(blockForTxn.Header.MerkleRoot)
			hash2 := *txnMeta.BitcoinMerkleRoot
			require.Equalf(
				hash1, hash2,
				"Bitcoin merkle root for txn does not line up with block hash: %v %v %d", &hash1, &hash2, ii)
		}

		// Verify that the merkle proof checks out.
		{
			txHash := ((BlockHash)(txnMeta.BitcoinTransaction.TxHash()))
			merkleProofIsValid := merkletree.VerifyProof(
				txHash[:], txnMeta.BitcoinMerkleProof, txnMeta.BitcoinMerkleRoot[:])
			require.Truef(
				merkleProofIsValid, "Problem verifying merkle proof for burn txn %d", ii)
		}

		// Verify that using the wrong Merkle root doesn't work.
		{
			badBlock := bitcoinBlocks[blockIndex-1]
			badMerkleRoot := badBlock.Header.MerkleRoot[:]
			txHash := ((BlockHash)(txnMeta.BitcoinTransaction.TxHash()))
			merkleProofIsValid := merkletree.VerifyProof(
				txHash[:], txnMeta.BitcoinMerkleProof, badMerkleRoot)
			require.Falsef(
				merkleProofIsValid, "Bad Merkle root was actually verified for burn txn %d", ii)
		}

		// Verify that serializing and deserializing work for this transaction.
		bb, err := bitcoinExchangeTxn.ToBytes(false /*preSignature*/)
		require.NoError(err)
		parsedBitcoinExchangeTxn := &MsgDeSoTxn{}
		parsedBitcoinExchangeTxn.FromBytes(bb)
		require.Equal(bitcoinExchangeTxn, parsedBitcoinExchangeTxn)
	}

	// Find the header in our header list corresponding to the first test block,
	// which contains the first Bitcoin
	firstBitcoinBurnBlock := bitcoinBlocks[1]
	firstBitcoinBurnBlockHash := firstBitcoinBurnBlock.BlockHash()
	headerIndexOfFirstBurn := -1
	for headerIndex := range bitcoinHeaders {
		if firstBitcoinBurnBlockHash == bitcoinHeaders[headerIndex].BlockHash() {
			headerIndexOfFirstBurn = headerIndex
			break
		}
	}
	require.Greater(headerIndexOfFirstBurn, 0)

	// Create a Bitcoinmanager that is current whose tip corresponds to the block
	// just before the block containing the first Bitcoin burn transaction.
	minBurnBlocks := uint32(2)
	startHeaderIndex := 0
	paramsCopy := GetTestParamsCopy(
		bitcoinHeaders[startHeaderIndex], bitcoinHeaderHeights[startHeaderIndex],
		params, minBurnBlocks,
	)

	// Update some of the params to make them reflect what we've hacked into
	// the bitcoinManager.
	paramsCopy.BitcoinBurnAddress = BitcoinTestnetBurnAddress
	chain.params = paramsCopy
	// Reset the pool to give the mempool access to the new BitcoinManager object.
	mempool.resetPool(NewDeSoMempool(chain, 0, /* rateLimitFeeRateNanosPerKB */
		0, /* minFeeRateNanosPerKB */
		"" /*blockCypherAPIKey*/, false,
		"" /*dataDir*/, ""))

	// The amount of work on the first burn transaction should be zero.
	burnTxn1 := bitcoinExchangeTxns[0]
	burnTxn2 := bitcoinExchangeTxns[1]

	// Applying the full transaction with its merkle proof to the mempool should work
	{
		mempoolTxs, err := mempool.processTransaction(
			burnTxn1, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(1, len(mempoolTxs))
		require.Equal(1, len(mempool.poolMap))
		mempoolTxRet := mempool.poolMap[*mempoolTxs[0].Hash]
		require.Equal(
			mempoolTxRet.Tx.TxnMeta.(*BitcoinExchangeMetadata),
			burnTxn1.TxnMeta.(*BitcoinExchangeMetadata))
	}

	// According to the mempool, the balance of the user whose public key created
	// the Bitcoin burn transaction should now have some DeSo.
	pkBytes1, _ := hex.DecodeString(BitcoinTestnetPub1)
	pkBytes2, _ := hex.DecodeString(BitcoinTestnetPub2)
	pkBytes3, _ := hex.DecodeString(BitcoinTestnetPub3)
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool, nil)
		require.NoError(err)

		require.Equal(1, len(utxoEntries))
		assert.Equal(int64(1907640147), int64(utxoEntries[0].AmountNanos))
	}

	// The mempool should be able to process a burn transaction directly.
	{
		mempoolTxsAdded, err := mempool.processTransaction(
			burnTxn2, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
			true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(1, len(mempoolTxsAdded))
		require.Equal(2, len(mempool.poolMap))
		mempoolTxRet := mempool.poolMap[*mempoolTxsAdded[0].Hash]
		require.Equal(
			mempoolTxRet.Tx.TxnMeta.(*BitcoinExchangeMetadata),
			burnTxn2.TxnMeta.(*BitcoinExchangeMetadata))
	}

	// According to the mempool, the balances should have updated.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool, nil)
		require.NoError(err)

		require.Equal(1, len(utxoEntries))
		assert.Equal(int64(2384546633), int64(utxoEntries[0].AmountNanos))
	}

	// If the mempool is not consulted, the balances should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Make the moneyPkString the paramUpdater so they can update the exchange rate.
	params.ParamUpdaterPublicKeys = make(map[PkMapKey]bool)
	params.ParamUpdaterPublicKeys[MakePkMapKey(MustBase58CheckDecode(moneyPkString))] = true
	paramsCopy.ParamUpdaterPublicKeys = params.ParamUpdaterPublicKeys

	// Applying all the txns to the UtxoView should work. Include a rate update
	// in the middle.
	utxoOpsList := [][]*UtxoOperation{}
	{
		utxoView, err := NewUtxoView(db, paramsCopy, nil)
		require.NoError(err)

		// Add a placeholder where the rate update is going to be
		fff := append([]*MsgDeSoTxn{}, bitcoinExchangeTxns[:rateUpdateIndex]...)
		fff = append(fff, nil)
		fff = append(fff, bitcoinExchangeTxns[rateUpdateIndex:]...)
		bitcoinExchangeTxns = fff

		for ii := range bitcoinExchangeTxns {
			// When we hit the rate update, populate the placeholder.
			if ii == rateUpdateIndex {
				newUSDCentsPerBitcoin := uint64(27000 * 100)
				_, rateUpdateTxn, _, err := _updateUSDCentsPerBitcoinExchangeRate(
					t, chain, db, params, 100, /*feeRateNanosPerKB*/
					moneyPkString,
					moneyPrivString,
					newUSDCentsPerBitcoin)
				require.NoError(err)

				bitcoinExchangeTxns[ii] = rateUpdateTxn
				burnTxn := bitcoinExchangeTxns[ii]
				burnTxnSize := getTxnSize(*burnTxn)
				blockHeight := chain.blockTip().Height + 1
				utxoOps, totalInput, totalOutput, fees, err :=
					utxoView.ConnectTransaction(
						burnTxn, burnTxn.Hash(), burnTxnSize, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
				_, _, _ = totalInput, totalOutput, fees
				require.NoError(err)
				utxoOpsList = append(utxoOpsList, utxoOps)
				continue
			}

			burnTxn := bitcoinExchangeTxns[ii]
			burnTxnSize := getTxnSize(*burnTxn)
			blockHeight := chain.blockTip().Height + 1
			utxoOps, totalInput, totalOutput, fees, err :=
				utxoView.ConnectTransaction(
					burnTxn, burnTxn.Hash(), burnTxnSize, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.NoError(err)

			require.Equal(2, len(utxoOps))
			//fmt.Println(int64(totalInput), ",")
			assert.Equal(expectedDeSoNanosMinted[ii], int64(totalInput))
			assert.Equal(expectedDeSoNanosMinted[ii]*int64(paramsCopy.BitcoinExchangeFeeBasisPoints)/10000, int64(fees))
			assert.Equal(int64(fees), int64(totalInput-totalOutput))

			_, _, _ = ii, totalOutput, fees
			utxoOpsList = append(utxoOpsList, utxoOps)
		}

		// Flushing the UtxoView should work.
		require.NoError(utxoView.FlushToDb())
	}

	// The balances according to the db after the flush should be correct.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		require.Equal(5, len(utxoEntries))
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		// Note the 10bp fee.
		assert.Equal(int64(33570565893), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		require.Equal(1, len(utxoEntries))
		// Note the 10bp fee.
		assert.Equal(int64(5724296973), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(3, len(utxoEntries))
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		// Note the 10bp fee.
		assert.Equal(int64(15930227393), int64(totalBalance))
	}

	// Spending from the outputs created by a burn should work.
	desoPub1 := Base58CheckEncode(pkBytes1, false /*isPrivate*/, paramsCopy)
	priv1, _ := _privStringToKeys(t, BitcoinTestnetPriv1)
	desoPriv1 := Base58CheckEncode(priv1.Serialize(), true /*isPrivate*/, paramsCopy)
	desoPub2 := Base58CheckEncode(pkBytes2, false /*isPrivate*/, paramsCopy)
	priv2, _ := _privStringToKeys(t, BitcoinTestnetPriv2)
	desoPriv2 := Base58CheckEncode(priv2.Serialize(), true /*isPrivate*/, paramsCopy)
	desoPub3 := Base58CheckEncode(pkBytes3, false /*isPrivate*/, paramsCopy)
	priv3, _ := _privStringToKeys(t, BitcoinTestnetPriv3)
	desoPriv3 := Base58CheckEncode(priv3.Serialize(), true /*isPrivate*/, paramsCopy)
	{
		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, desoPub1, desoPub2,
			desoPriv1, 100000*100000 /*amount to send*/, 11 /*feerate*/)

		utxoOpsList = append(utxoOpsList, currentOps)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentTxn)
	}
	{
		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, desoPub3, desoPub1,
			desoPriv3, 60000*100000 /*amount to send*/, 11 /*feerate*/)

		utxoOpsList = append(utxoOpsList, currentOps)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentTxn)
	}
	{
		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, desoPub2, desoPub1,
			desoPriv2, 60000*100000 /*amount to send*/, 11 /*feerate*/)

		utxoOpsList = append(utxoOpsList, currentOps)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentTxn)
	}

	// The balances according to the db after the spends above should be correct.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(35556076477), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		assert.Equal(int64(9718572674), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(9922118448), int64(totalBalance))
	}

	{
		// Rolling back all the transactions should work.
		utxoView, err := NewUtxoView(db, paramsCopy, nil)
		require.NoError(err)
		for ii := range bitcoinExchangeTxns {
			index := len(bitcoinExchangeTxns) - 1 - ii
			burnTxn := bitcoinExchangeTxns[index]
			blockHeight := chain.blockTip().Height + 1
			err := utxoView.DisconnectTransaction(burnTxn, burnTxn.Hash(), utxoOpsList[index], blockHeight)
			require.NoErrorf(err, "Transaction index: %v", index)
		}

		// Flushing the UtxoView back to the db after rolling back the
		require.NoError(utxoView.FlushToDb())
	}

	// The balances according to the db after rolling back and flushing everything
	// should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Re-applying all the transactions to the view and rolling back without
	// flushing should be fine.
	utxoOpsList = [][]*UtxoOperation{}
	{
		utxoView, err := NewUtxoView(db, paramsCopy, nil)
		require.NoError(err)
		for ii, burnTxn := range bitcoinExchangeTxns {
			blockHeight := chain.blockTip().Height + 1
			burnTxnSize := getTxnSize(*burnTxn)
			utxoOps, totalInput, totalOutput, fees, err :=
				utxoView.ConnectTransaction(burnTxn, burnTxn.Hash(), burnTxnSize, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.NoError(err)

			if ii < len(expectedBitcoinBurnAmounts) {
				if ii != rateUpdateIndex {
					require.Equal(2, len(utxoOps))
					assert.Equal(int64(totalInput), expectedDeSoNanosMinted[ii])
					assert.Equal(int64(fees), expectedDeSoNanosMinted[ii]*int64(paramsCopy.BitcoinExchangeFeeBasisPoints)/10000)
					assert.Equal(int64(fees), int64(totalInput-totalOutput))
				}
			}

			utxoOpsList = append(utxoOpsList, utxoOps)
		}

		for ii := range bitcoinExchangeTxns {
			index := len(bitcoinExchangeTxns) - 1 - ii
			burnTxn := bitcoinExchangeTxns[index]
			blockHeight := chain.blockTip().Height + 1
			err := utxoView.DisconnectTransaction(burnTxn, burnTxn.Hash(), utxoOpsList[index], blockHeight)
			require.NoError(err)
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
	}

	// The balances according to the db after applying and unapplying all the
	// transactions to a view with a flush at the end should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Running all the transactions through the mempool should work and result
	// in all of them being added.
	{
		for _, burnTxn := range bitcoinExchangeTxns {
			// We have to remove the transactions first.
			mempool.inefficientRemoveTransaction(burnTxn)
		}
		for ii, burnTxn := range bitcoinExchangeTxns {
			require.Equal(ii, len(mempool.poolMap))
			mempoolTxsAdded, err := mempool.processTransaction(
				burnTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "on index: %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}
	}

	// The balances according to the mempool after applying all the transactions
	// should be correct.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(35556076477), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, mempool, nil)
		require.NoError(err)
		assert.Equal(int64(9718572674), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(9922118448), int64(totalBalance))
	}

	// Remove all the transactions from the mempool.
	for _, burnTxn := range bitcoinExchangeTxns {
		mempool.inefficientRemoveTransaction(burnTxn)
	}

	// The balances should be zero after removing transactions from the mempool.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, mempool, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Re-add all of the transactions to the mempool so we can mine them into a block.
	{
		for _, burnTxn := range bitcoinExchangeTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				burnTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
			//require.Equal(0, len(mempool.immatureBitcoinTxns))
		}
	}

	miner.params = paramsCopy
	miner.BlockProducer.params = paramsCopy
	// All the txns should be in the mempool already so mining a block should put
	// all those transactions in it. Note we need to mine two blocks since the first
	// one just makes the DeSo chain time-current.
	finalBlock1, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_ = finalBlock1
	finalBlock2, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	finalBlock3, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	finalBlock4, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	// Add one for the block reward. Now we have a meaty block.
	assert.Equal(len(finalBlock1.Txns), 1)
	assert.Equal(len(finalBlock2.Txns), 14)
	assert.Equal(len(finalBlock3.Txns), 1)
	require.Equal(len(finalBlock4.Txns), 1)

	// The balances after mining the block should line up.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(35556076477), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		assert.Equal(int64(9718572674), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		assert.Equal(int64(9922118448), int64(totalBalance))
	}

	// Roll back the blocks and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(db, paramsCopy, nil)
		require.NoError(err)

		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock4.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock4.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock4, txHashes, utxoOps))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock3.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock3.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock3, txHashes, utxoOps))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock2.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock2.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock2, txHashes, utxoOps))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock1.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock1.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock1, txHashes, utxoOps))
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
	}

	// The balances according to the db after applying and unapplying all the
	// transactions to a view with a flush at the end should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	_, _, _, _, _, _ = db, mempool, miner, bitcoinBlocks, bitcoinHeaders, bitcoinHeaderHeights
}

func TestUpdateExchangeRate(t *testing.T) {
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
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, 11 /*feerate*/)

	// Should fail when founder key is not equal to moneyPk
	{
		newUSDCentsPerBitcoin := uint64(27000 * 100)
		_, _, _, err := _updateUSDCentsPerBitcoinExchangeRate(
			t, chain, db, params, 100, /*feeRateNanosPerKB*/
			m0Pub,
			m0Priv,
			newUSDCentsPerBitcoin)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorUserNotAuthorizedToUpdateExchangeRate)
	}

	// Should pass when founder key is equal to moneyPk
	var updateExchangeRateTxn *MsgDeSoTxn
	var err error
	{
		newUSDCentsPerBitcoin := uint64(27000 * 100)
		_, updateExchangeRateTxn, _, err = _updateUSDCentsPerBitcoinExchangeRate(
			t, chain, db, params, 100, /*feeRateNanosPerKB*/
			moneyPkString,
			moneyPrivString,
			newUSDCentsPerBitcoin)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		txnSize := getTxnSize(*updateExchangeRateTxn)
		blockHeight := chain.blockTip().Height + 1
		utxoOps, totalInput, totalOutput, fees, err :=
			utxoView.ConnectTransaction(updateExchangeRateTxn,
				updateExchangeRateTxn.Hash(), txnSize, blockHeight, true, /*verifySignature*/
				false /*ignoreUtxos*/)
		require.NoError(err)
		_, _, _, _ = utxoOps, totalInput, totalOutput, fees
		require.NoError(utxoView.FlushToDb())

		// Check the balance of the updater after this txn
		require.NotEqual(0, _getBalance(t, chain, nil, moneyPkString))
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

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		txnSize := getTxnSize(*updateGlobalParamsTxn)
		blockHeight := chain.blockTip().Height + 1
		utxoOps, totalInput, totalOutput, fees, err :=
			utxoView.ConnectTransaction(updateGlobalParamsTxn,
				updateGlobalParamsTxn.Hash(), txnSize, blockHeight, true, /*verifySignature*/
				false /*ignoreUtxos*/)
		require.NoError(err)
		_, _, _, _ = utxoOps, totalInput, totalOutput, fees
		require.NoError(utxoView.FlushToDb())

		// Verify that utxoView and db reflect the new global parmas entry.
		expectedGlobalParams := GlobalParamsEntry{
			USDCentsPerBitcoin:          uint64(newUSDCentsPerBitcoin),
			MinimumNetworkFeeNanosPerKB: uint64(newMinimumNetworkFeeNanosPerKB),
			CreateProfileFeeNanos:       uint64(newCreateProfileFeeNanos),
			CreateNFTFeeNanos:           uint64(newCreateNFTFeeNanos),
			MaxCopiesPerNFT:             123,
		}
		require.Equal(DbGetGlobalParamsEntry(utxoView.Handle), &expectedGlobalParams)

		require.Equal(utxoView.GlobalParamsEntry, &expectedGlobalParams)

		// Check the balance of the updater after this txn
		require.NotEqual(0, _getBalance(t, chain, nil, moneyPkString))
	}

	{

		// Save the prev global params entry so we can check it after disconnect.
		prevGlobalParams := DbGetGlobalParamsEntry(db)

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

		require.Equal(DbGetGlobalParamsEntry(db), expectedGlobalParams)

		// Now let's do a disconnect and make sure the values reflect the previous entry.
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		blockHeight := chain.blockTip().Height + 1
		utxoView.DisconnectTransaction(
			updateGlobalParamsTxn, updateGlobalParamsTxn.Hash(), utxoOps, blockHeight)

		require.NoError(utxoView.FlushToDb())

		require.Equal(DbGetGlobalParamsEntry(utxoView.Handle), prevGlobalParams)
		require.Equal(utxoView.GlobalParamsEntry, prevGlobalParams)

		// Check the balance of the updater after this txn
		require.NotEqual(0, _getBalance(t, chain, nil, moneyPkString))
	}
}

type _CreatorCoinTestData struct {
	// These are the transaction params
	UpdaterPublicKeyBase58Check  string
	UpdaterPrivateKeyBase58Check string
	ProfilePublicKeyBase58Check  string
	OperationType                CreatorCoinOperationType
	DeSoToSellNanos              uint64
	CreatorCoinToSellNanos       uint64
	DeSoToAddNanos               uint64
	MinDeSoExpectedNanos         uint64
	MinCreatorCoinExpectedNanos  uint64

	// The Diamond info
	DiamondPostHashIndex int
	DiamondLevel         int64

	// SubmitPost info
	SubmitPostBody string
	PostIsHidden   bool
	// We save all post hashes of posts that are created into
	// an array ordered by the time when they were created. To
	// reference a previous post, one just needs to set these
	// indexes to the index of the post in this array.
	PostHashToModifyIndex int
	ParentPostHashIndex   int

	// For creator coin transfers.
	CreatorCoinToTransferNanos   uint64
	ReceiverPublicKeyBase58Check string

	// The type of txn we're having the helper execute. When unset, this defaults to
	// a CreatorCoin transaction to avoid having to change existing code.
	TxnType TxnType

	// Extra fields for UpdateProfile txns
	ProfileUsername           string
	ProfileDescription        string
	ProfilePic                string
	ProfileCreatorBasisPoints uint64
	ProfileIsHidden           bool

	// Extra fields for SwapIdentity
	FromPublicKey []byte
	ToPublicKey   []byte

	// Extra fields for Follow
	FollowedPublicKey []byte
	IsUnfollow        bool

	// When set, the checks are skipped
	SkipChecks bool

	// These are the expectations (skipped when SkipChecks is set)
	CoinsInCirculationNanos uint64
	DeSoLockedNanos         uint64
	CoinWatermarkNanos      uint64
	m0CCBalance             uint64
	m1CCBalance             uint64
	m2CCBalance             uint64
	m3CCBalance             uint64
	m4CCBalance             uint64
	m5CCBalance             uint64
	m6CCBalance             uint64
	m0DeSoBalance           uint64
	m1DeSoBalance           uint64
	m2DeSoBalance           uint64
	m3DeSoBalance           uint64
	m4DeSoBalance           uint64
	m5DeSoBalance           uint64
	m6DeSoBalance           uint64
	m0HasPurchased          bool
	m1HasPurchased          bool
	m2HasPurchased          bool
	m3HasPurchased          bool
	m4HasPurchased          bool
	m5HasPurchased          bool
	m6HasPurchased          bool

	// These fields allow us to fetch and check profile data during validation.
	ProfilesToCheckPublicKeysBase58Check []string
	ProfilesToCheckUsernames             []string
	ProfilesToCheckDescriptions          []string
	ProfilesToCheckProfilePic            []string

	// These fields allow us to check follows
	FollowPublicKeysToCheck           []string
	FollowPublicKeysUserIsFollowing   []map[string]bool
	FollowPublicKeysFollowingThisUser []map[string]bool
}

// Sets up a test harness for running and checking various permutations
// of buy/sell transactions on creator coins. m0 is the creator coin being
// traded and m1 and m2 are other users.
func _helpTestCreatorCoinBuySell(
	t *testing.T,
	creatorCoinTests []*_CreatorCoinTestData,
	desoFounderReward bool) {

	// These are block heights where deso forked.
	SalomonFixBlockHeight = 0
	BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight = 0
	DeSoFounderRewardBlockHeight = 0
	if !desoFounderReward {
		DeSoFounderRewardBlockHeight = 1e9
	}

	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	feeRateNanosPerKB := uint64(11)
	_, _ = mempool, miner

	// Create a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

	// Give paramUpdater some mony
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, paramUpdaterPub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	// Send money to people from moneyPk
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m0Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m1Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m2Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m3Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m4Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m5Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m6Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	m0StartNanos := _getBalance(t, chain, nil, m0Pub)
	m1StartNanos := _getBalance(t, chain, nil, m1Pub)
	m2StartNanos := _getBalance(t, chain, nil, m2Pub)
	m3StartNanos := _getBalance(t, chain, nil, m3Pub)
	m4StartNanos := _getBalance(t, chain, nil, m4Pub)
	m5StartNanos := _getBalance(t, chain, nil, m5Pub)
	m6StartNanos := _getBalance(t, chain, nil, m6Pub)

	testUtxoOps := [][]*UtxoOperation{}
	testTxns := []*MsgDeSoTxn{}
	_checkTestData := func(
		testData *_CreatorCoinTestData, message string, utxoView *UtxoView, mempool *DeSoMempool) {

		// If we were instructed to skip these checks then skip them.
		if testData.SkipChecks {
			return
		}

		// If a mempool object is provided then just check balances and return
		if mempool != nil {
			// DeSo balances
			if _getBalance(t, chain, mempool, m0Pub) != 6*NanosPerUnit && testData.m0DeSoBalance != 0 {
				assert.Equalf(int64(testData.m0DeSoBalance),
					int64(_getBalance(t, chain, mempool, m0Pub)), "MempoolIncrementalBalanceCheck: m0 DeSo balance: %v", message)
			}
			if _getBalance(t, chain, mempool, m1Pub) != 6*NanosPerUnit && testData.m1DeSoBalance != 0 {
				assert.Equalf(int64(testData.m1DeSoBalance),
					int64(_getBalance(t, chain, mempool, m1Pub)), "MempoolIncrementalBalanceCheck: m1 DeSo balance: %v", message)
			}
			if _getBalance(t, chain, mempool, m2Pub) != 6*NanosPerUnit && testData.m2DeSoBalance != 0 {
				assert.Equalf(int64(testData.m2DeSoBalance),
					int64(_getBalance(t, chain, mempool, m2Pub)), "MempoolIncrementalBalanceCheck: m2 DeSo balance: %v", message)
			}
			if _getBalance(t, chain, mempool, m3Pub) != 6*NanosPerUnit && testData.m3DeSoBalance != 0 {
				assert.Equalf(int64(testData.m3DeSoBalance),
					int64(_getBalance(t, chain, mempool, m3Pub)), "MempoolIncrementalBalanceCheck: m3 DeSo balance: %v", message)
			}
			if _getBalance(t, chain, mempool, m4Pub) != 6*NanosPerUnit && testData.m4DeSoBalance != 0 {
				assert.Equalf(int64(testData.m4DeSoBalance),
					int64(_getBalance(t, chain, mempool, m4Pub)), "MempoolIncrementalBalanceCheck: m4 DeSo balance: %v", message)
			}
			if _getBalance(t, chain, mempool, m5Pub) != 6*NanosPerUnit && testData.m5DeSoBalance != 0 {
				assert.Equalf(int64(testData.m5DeSoBalance),
					int64(_getBalance(t, chain, mempool, m5Pub)), "MempoolIncrementalBalanceCheck: m5 DeSo balance: %v", message)
			}
			if _getBalance(t, chain, mempool, m6Pub) != 6*NanosPerUnit && testData.m6DeSoBalance != 0 {
				assert.Equalf(int64(testData.m6DeSoBalance),
					int64(_getBalance(t, chain, mempool, m6Pub)), "MempoolIncrementalBalanceCheck: m6 DeSo balance: %v", message)
			}

			return
		}

		// If no UtxoView is passed, use a new one to run our checks.
		if utxoView == nil {
			var err error
			utxoView, err = NewUtxoView(db, params, nil)
			require.NoError(err)
		}

		// Profile fields
		creatorPkBytes, _, _ := Base58CheckDecode(testData.ProfilePublicKeyBase58Check)
		creatorProfile := utxoView.GetProfileEntryForPublicKey(creatorPkBytes)
		require.NotNil(creatorProfile)

		assert.Equalf(int64(testData.CoinsInCirculationNanos),
			int64(creatorProfile.CoinsInCirculationNanos), "CoinsInCirculationNanos: %v", message)
		assert.Equalf(int64(testData.DeSoLockedNanos),
			int64(creatorProfile.DeSoLockedNanos), "DeSoLockedNanos: %v", message)
		assert.Equalf(int64(testData.CoinWatermarkNanos),
			int64(creatorProfile.CoinWatermarkNanos), "CoinWatermarkNanos: %v", message)

		// Coin balances, also used for figuring out how many holders hold a creator.
		// m0
		actualNumberOfHolders := uint64(0)
		m0BalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m0PkBytes, creatorPkBytes)
		if m0BalanceEntry != nil && !m0BalanceEntry.isDeleted {
			assert.Equalf(int64(testData.m0CCBalance),
				int64(m0BalanceEntry.BalanceNanos), "m0CCBalance: %v", message)
			if m0BalanceEntry.BalanceNanos > 0 {
				actualNumberOfHolders += 1
			}
			assert.Equal(testData.m0HasPurchased, m0BalanceEntry.HasPurchased)
		} else {
			assert.Equalf(int64(testData.m0CCBalance),
				int64(0), "m0CCBalance: %v", message)
			assert.Equal(testData.m0HasPurchased, false)
		}
		// m1
		m1BalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m1PkBytes, creatorPkBytes)
		if m1BalanceEntry != nil && !m1BalanceEntry.isDeleted {
			assert.Equalf(int64(testData.m1CCBalance),
				int64(m1BalanceEntry.BalanceNanos), "m1CCBalance: %v", message)
			if m1BalanceEntry.BalanceNanos > 0 {
				actualNumberOfHolders += 1
			}
			assert.Equal(testData.m1HasPurchased, m1BalanceEntry.HasPurchased)
		} else {
			assert.Equalf(int64(testData.m1CCBalance),
				int64(0), "m1CCBalance: %v", message)
			assert.Equal(testData.m1HasPurchased, false)
		}
		// m2
		m2BalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m2PkBytes, creatorPkBytes)
		if m2BalanceEntry != nil && !m2BalanceEntry.isDeleted {
			assert.Equalf(int64(testData.m2CCBalance),
				int64(m2BalanceEntry.BalanceNanos), "%v", message)
			if m2BalanceEntry.BalanceNanos > 0 {
				actualNumberOfHolders += 1
			}
			assert.Equal(testData.m2HasPurchased, m2BalanceEntry.HasPurchased)
		} else {
			assert.Equalf(int64(testData.m2CCBalance),
				int64(0), "m2CCBalance: %v", message)
			assert.Equal(testData.m2HasPurchased, false)
		}
		// m3
		m3BalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m3PkBytes, creatorPkBytes)
		if m3BalanceEntry != nil && !m3BalanceEntry.isDeleted {
			assert.Equalf(int64(testData.m3CCBalance),
				int64(m3BalanceEntry.BalanceNanos), "%v", message)
			if m3BalanceEntry.BalanceNanos > 0 {
				actualNumberOfHolders += 1
			}
			assert.Equal(testData.m3HasPurchased, m3BalanceEntry.HasPurchased)
		} else {
			assert.Equalf(int64(testData.m3CCBalance),
				int64(0), "m3CCBalance: %v", message)
			assert.Equal(testData.m3HasPurchased, false)
		}
		// m4
		m4BalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m4PkBytes, creatorPkBytes)
		if m4BalanceEntry != nil && !m4BalanceEntry.isDeleted {
			assert.Equalf(int64(testData.m4CCBalance),
				int64(m4BalanceEntry.BalanceNanos), "%v", message)
			if m4BalanceEntry.BalanceNanos > 0 {
				actualNumberOfHolders += 1
			}
			assert.Equal(testData.m4HasPurchased, m4BalanceEntry.HasPurchased)
		} else {
			assert.Equalf(int64(testData.m4CCBalance),
				int64(0), "m4CCBalance: %v", message)
			assert.Equal(testData.m4HasPurchased, false)
		}
		// m5
		m5BalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m5PkBytes, creatorPkBytes)
		if m5BalanceEntry != nil && !m5BalanceEntry.isDeleted {
			assert.Equalf(int64(testData.m5CCBalance),
				int64(m5BalanceEntry.BalanceNanos), "%v", message)
			if m5BalanceEntry.BalanceNanos > 0 {
				actualNumberOfHolders += 1
			}
			assert.Equal(testData.m5HasPurchased, m5BalanceEntry.HasPurchased)
		} else {
			assert.Equalf(int64(testData.m5CCBalance),
				int64(0), "m5CCBalance: %v", message)
			assert.Equal(testData.m5HasPurchased, false)
		}
		// m6
		m6BalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(m6PkBytes, creatorPkBytes)
		if m6BalanceEntry != nil && !m6BalanceEntry.isDeleted {
			assert.Equalf(int64(testData.m6CCBalance),
				int64(m6BalanceEntry.BalanceNanos), "%v", message)
			if m6BalanceEntry.BalanceNanos > 0 {
				actualNumberOfHolders += 1
			}
			assert.Equal(testData.m6HasPurchased, m6BalanceEntry.HasPurchased)
		} else {
			assert.Equalf(int64(testData.m6CCBalance),
				int64(0), "m6CCBalance: %v", message)
			assert.Equal(testData.m6HasPurchased, false)
		}

		// creatorNumberOfHolders must equal creatorProfile.NumberOfHolders
		assert.Equalf(actualNumberOfHolders, creatorProfile.NumberOfHolders,
			"Actual number of creators != creatorProfile.NumberOfHolders: %v", message)

		// Coins in m0+m1+m2+m3+m4+m5+m6 must equal the circulating supply
		assert.Equalf(
			int64(testData.m0CCBalance+testData.m1CCBalance+testData.m2CCBalance+testData.m3CCBalance+
				testData.m4CCBalance+testData.m5CCBalance+testData.m6CCBalance),
			int64(creatorProfile.CoinsInCirculationNanos),
			"m0+m1+m2+m3+m4+m5+m6 != CoinsInCirculationNanos: %v", message)

		// DeSo balances
		if _getBalanceWithView(t, utxoView, m0Pub) != 6*NanosPerUnit && testData.m0DeSoBalance != 0 {
			assert.Equalf(int64(testData.m0DeSoBalance),
				int64(_getBalanceWithView(t, utxoView, m0Pub)), "m0 DeSo balance: %v", message)
		}
		if _getBalanceWithView(t, utxoView, m1Pub) != 6*NanosPerUnit && testData.m1DeSoBalance != 0 {
			assert.Equalf(int64(testData.m1DeSoBalance),
				int64(_getBalanceWithView(t, utxoView, m1Pub)), "m1 DeSo balance: %v", message)
		}
		if _getBalanceWithView(t, utxoView, m2Pub) != 6*NanosPerUnit && testData.m2DeSoBalance != 0 {
			assert.Equalf(int64(testData.m2DeSoBalance),
				int64(_getBalanceWithView(t, utxoView, m2Pub)), "m2 DeSo balance: %v", message)
		}
		if _getBalanceWithView(t, utxoView, m3Pub) != 6*NanosPerUnit && testData.m3DeSoBalance != 0 {
			assert.Equalf(int64(testData.m3DeSoBalance),
				int64(_getBalanceWithView(t, utxoView, m3Pub)), "m3 DeSo balance: %v", message)
		}
		if _getBalanceWithView(t, utxoView, m4Pub) != 6*NanosPerUnit && testData.m4DeSoBalance != 0 {
			assert.Equalf(int64(testData.m4DeSoBalance),
				int64(_getBalanceWithView(t, utxoView, m4Pub)), "m4 DeSo balance: %v", message)
		}
		if _getBalanceWithView(t, utxoView, m5Pub) != 6*NanosPerUnit && testData.m5DeSoBalance != 0 {
			assert.Equalf(int64(testData.m5DeSoBalance),
				int64(_getBalanceWithView(t, utxoView, m5Pub)), "m5 DeSo balance: %v", message)
		}
		if _getBalanceWithView(t, utxoView, m6Pub) != 6*NanosPerUnit && testData.m6DeSoBalance != 0 {
			assert.Equalf(int64(testData.m6DeSoBalance),
				int64(_getBalanceWithView(t, utxoView, m6Pub)), "m6 DeSo balance: %v", message)
		}

		for ii, profilePubStr := range testData.ProfilesToCheckPublicKeysBase58Check {
			// Look up the profile for the public key.
			profilePkBytes, _, _ := Base58CheckDecode(profilePubStr)
			profileEntry := utxoView.GetProfileEntryForPublicKey(profilePkBytes)
			if testData.ProfilesToCheckUsernames[ii] == "" {
				if profileEntry != nil && !profileEntry.isDeleted {
					require.Fail("Profile for pub key %v should not exist but does: index %v: %v", profilePubStr, ii, message)
				}
				continue
			} else {
				require.NotNil(profileEntry, "Profile for pub key %v does not exist: index %v: %v", profilePubStr, ii, message)
			}
			require.Equalf(profilePkBytes, profileEntry.PublicKey, "Profile public keys don't match: index %v: %v", ii, message)
			require.Equalf(string(profileEntry.Username), testData.ProfilesToCheckUsernames[ii], "Profile usernames don't match: index %v: %v", ii, message)
			require.Equalf(string(profileEntry.Description), testData.ProfilesToCheckDescriptions[ii], "Profile descripptions don't match: index %v: %v", ii, message)
			require.Equalf(string(profileEntry.ProfilePic), testData.ProfilesToCheckProfilePic[ii], "Profile profile pics don't match: index %v: %v", ii, message)
		}

		for ii, userPubStr := range testData.FollowPublicKeysToCheck {
			// Look up the profile for the public key.
			userPkBytes, _, _ := Base58CheckDecode(userPubStr)

			userIsFollowing := testData.FollowPublicKeysUserIsFollowing[ii]
			followingUser := testData.FollowPublicKeysFollowingThisUser[ii]

			// Look up the public keys that are following this user.
			{
				followEntries, err := utxoView.GetFollowEntriesForPublicKey(
					userPkBytes, true /*followingPublicKey*/)
				require.NoError(err)

				require.Equal(len(followEntries), len(followingUser))

				for _, followEntry := range followEntries {
					followPk := utxoView.GetPublicKeyForPKID(followEntry.FollowerPKID)
					if _, exists := followingUser[PkToString(followPk, params)]; !exists {
						require.Fail(fmt.Sprintf("Pub key %v should be following user %v but is not: %v %v",
							PkToString(followPk, params), userPubStr, ii, message))
					}
				}
			}
			// Look up the public keys this user is following
			{
				followEntries, err := utxoView.GetFollowEntriesForPublicKey(
					userPkBytes, false /*followingPublicKey*/)
				require.NoError(err)

				require.Equal(len(followEntries), len(userIsFollowing))

				for _, followEntry := range followEntries {
					followPk := utxoView.GetPublicKeyForPKID(followEntry.FollowedPKID)
					if _, exists := userIsFollowing[PkToString(followPk, params)]; !exists {
						require.Fail(fmt.Sprintf("Pub key %v should be in the users this one is following %v but is not: %v %v",
							PkToString(followPk, params), userPubStr, ii, message))
					}
				}
			}
		}
	}

	postHashes := []*BlockHash{}
	for testIndex, testData := range creatorCoinTests {
		fmt.Printf("Applying test index: %v\n", testIndex)

		// If this is a profile swap, then execute that.
		var utxoOps []*UtxoOperation
		var txn *MsgDeSoTxn
		var err error
		if testData.TxnType == TxnTypeSwapIdentity {
			utxoOps, txn, _, err = _swapIdentity(
				t, chain, db, params, feeRateNanosPerKB,
				paramUpdaterPub,
				paramUpdaterPriv,
				testData.FromPublicKey, testData.ToPublicKey)
			require.NoError(err)
		} else if testData.TxnType == TxnTypeUpdateProfile {
			// Create a profile using the testData params
			profilePkBytes, _, _ := Base58CheckDecode(testData.ProfilePublicKeyBase58Check)
			utxoOps, txn, _, err = _updateProfile(
				t, chain, db, params,
				feeRateNanosPerKB /*feerate*/, testData.UpdaterPublicKeyBase58Check,
				testData.UpdaterPrivateKeyBase58Check, profilePkBytes, testData.ProfileUsername,
				testData.ProfileDescription, testData.ProfilePic,
				testData.ProfileCreatorBasisPoints, /*CreatorBasisPoints*/
				12500 /*stakeMultipleBasisPoints*/, testData.ProfileIsHidden /*isHidden*/, false)
			require.NoError(err)
		} else if testData.TxnType == TxnTypeFollow {
			utxoOps, txn, _, err = _doFollowTxn(
				t, chain, db, params, feeRateNanosPerKB /*feeRateNanosPerKB*/, testData.UpdaterPublicKeyBase58Check,
				PkToString(testData.FollowedPublicKey, params),
				testData.UpdaterPrivateKeyBase58Check, testData.IsUnfollow /*isUnfollow*/)
			require.NoError(err)
		} else if testData.TxnType == TxnTypeSubmitPost {

			var postHashToModify []byte
			if testData.PostHashToModifyIndex >= 0 {
				postHashToModify = postHashes[testData.PostHashToModifyIndex][:]
			}
			var parentPostHash []byte
			if testData.ParentPostHashIndex >= 0 {
				parentPostHash = postHashes[testData.ParentPostHashIndex][:]
			}

			utxoOps, txn, _, err = _doSubmitPostTxn(
				t, chain, db, params, feeRateNanosPerKB,
				testData.UpdaterPublicKeyBase58Check, testData.UpdaterPrivateKeyBase58Check,
				postHashToModify,
				parentPostHash,
				testData.SubmitPostBody,
				make(map[string][]byte),
				testData.PostIsHidden)
			require.NoError(err)

			// If this transaction was not modifying an existing post then
			// add its post hash to the list.
			if len(postHashToModify) == 0 {
				postHashes = append(postHashes, txn.Hash())
			}

		} else if testData.TxnType == TxnTypeCreatorCoinTransfer {
			var diamondPostHash *BlockHash
			if testData.DiamondLevel > 0 {
				diamondPostHash = postHashes[testData.DiamondPostHashIndex]
			}
			// If we have a DiamondPostHash then do a diamond txn
			if diamondPostHash != nil {
				utxoOps, txn, _, err = _doCreatorCoinTransferTxnWithDiamonds(
					t, chain, db, params, feeRateNanosPerKB,
					testData.UpdaterPublicKeyBase58Check, testData.UpdaterPrivateKeyBase58Check,
					testData.ReceiverPublicKeyBase58Check,
					diamondPostHash,
					testData.DiamondLevel)
				require.NoError(err)
			} else {
				// Apply the txn according to the test spec
				utxoOps, txn, _, err = _doCreatorCoinTransferTxn(
					t, chain, db, params, feeRateNanosPerKB,
					testData.UpdaterPublicKeyBase58Check, testData.UpdaterPrivateKeyBase58Check,
					testData.ProfilePublicKeyBase58Check,
					testData.ReceiverPublicKeyBase58Check,
					testData.CreatorCoinToTransferNanos)
				require.NoError(err)
			}

		} else {
			// When TxnType is 0 aka "unset," we assume we're doing a CreatorCoin txn.

			// Apply the txn according to the test spec
			utxoOps, txn, _, err = _creatorCoinTxn(
				t, chain, db, params, feeRateNanosPerKB,
				testData.UpdaterPublicKeyBase58Check, testData.UpdaterPrivateKeyBase58Check, /*updater*/
				testData.ProfilePublicKeyBase58Check, /*profile*/
				testData.OperationType,               /*buy/sell*/
				testData.DeSoToSellNanos,             /*DeSoToSellNanos*/
				testData.CreatorCoinToSellNanos,      /*CreatorCoinToSellNanos*/
				testData.DeSoToAddNanos,              /*DeSoToAddNanos*/
				testData.MinDeSoExpectedNanos,        /*MinDeSoExpectedNanos*/
				testData.MinCreatorCoinExpectedNanos /*MinCreatorCoinExpectedNanos*/)
			require.NoError(err)
		}

		// Append the txn we just created to our list
		testTxns = append(testTxns, txn)
		testUtxoOps = append(testUtxoOps, utxoOps)

		// Check the txn according to the test spec.
		_checkTestData(testData, fmt.Sprintf("SimpleConnect: Index: %v", testIndex), nil, nil)
	}

	// The sum of all the balances shouldn't exceed what we started with.
	assert.Less(
		int64(_getBalance(t, chain, nil, m0Pub)+_getBalance(t, chain, nil, m1Pub)+
			_getBalance(t, chain, nil, m2Pub)+_getBalance(t, chain, nil, m3Pub)+
			_getBalance(t, chain, nil, m4Pub)+_getBalance(t, chain, nil, m5Pub)+
			_getBalance(t, chain, nil, m6Pub)),
		int64(m0StartNanos+m1StartNanos+m2StartNanos+m3StartNanos+m4StartNanos+m5StartNanos+m6StartNanos))

	// Disconnect each txn and rerun the checks in the reverse direction
	for iterIndex := range creatorCoinTests {
		testIndex := len(creatorCoinTests) - 1 - iterIndex
		testData := creatorCoinTests[testIndex]
		currentTxn := testTxns[testIndex]
		currentUtxoOps := testUtxoOps[testIndex]

		// Check that the state lines up with the test data
		fmt.Printf("Running checks before disconnecting test index: %v\n", testIndex)
		_checkTestData(testData, fmt.Sprintf("SimpleDisconnect: Index: %v", testIndex), nil, nil)

		// Disconnect the transaction
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		blockHeight := chain.blockTip().Height + 1
		fmt.Printf("Disconnecting test index: %v\n", testIndex)
		require.NoError(utxoView.DisconnectTransaction(
			currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
		fmt.Printf("Disconnected test index: %v\n", testIndex)
		require.NoErrorf(utxoView.FlushToDb(), "SimpleDisconnect: Index: %v", testIndex)
	}

	// Verify the DeSo balances are back to where they started after disconnecting all the txns.
	assert.Equalf(int64(m0StartNanos),
		int64(_getBalance(t, chain, nil, m0Pub)), "m0 DeSo balance after SimpleDisconnect is incorrect")
	assert.Equalf(int64(m1StartNanos),
		int64(_getBalance(t, chain, nil, m1Pub)), "m1 DeSo balance after SimpleDisconnect is incorrect")
	assert.Equalf(int64(m2StartNanos),
		int64(_getBalance(t, chain, nil, m2Pub)), "m2 DeSo balance after SimpleDisconnect is incorrect")
	assert.Equalf(int64(m3StartNanos),
		int64(_getBalance(t, chain, nil, m3Pub)), "m3 DeSo balance after SimpleDisconnect is incorrect")
	assert.Equalf(int64(m4StartNanos),
		int64(_getBalance(t, chain, nil, m4Pub)), "m4 DeSo balance after SimpleDisconnect is incorrect")
	assert.Equalf(int64(m5StartNanos),
		int64(_getBalance(t, chain, nil, m5Pub)), "m5 DeSo balance after SimpleDisconnect is incorrect")
	assert.Equalf(int64(m6StartNanos),
		int64(_getBalance(t, chain, nil, m6Pub)), "m6 DeSo balance after SimpleDisconnect is incorrect")

	// Connect all the txns to a single UtxoView without flushing
	{
		// Create a new UtxoView to check on the state of things
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		for testIndex, testData := range creatorCoinTests {
			fmt.Printf("Applying test index: %v\n", testIndex)
			txn := testTxns[testIndex]
			blockHeight := chain.blockTip().Height + 1
			txnSize := getTxnSize(*txn)
			_, _, _, _, err :=
				utxoView.ConnectTransaction(
					txn, txn.Hash(), txnSize, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.NoError(err)
			_checkTestData(testData, fmt.Sprintf("SimpleConnect: Index: %v", testIndex), utxoView, nil)
		}

		// Now flush at the end.
		require.NoError(utxoView.FlushToDb())

		// Check that the state matches the final testData.
		testIndex := len(creatorCoinTests) - 1
		testData := creatorCoinTests[testIndex]
		_checkTestData(testData, fmt.Sprintf("OnebigFlush: %v", testIndex), nil, nil)
	}

	// Disconnect all the txns on a single view and flush at the end
	{
		// Create a new UtxoView to check on the state of things
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		blockHeight := chain.blockTip().Height + 1
		for iterIndex := range creatorCoinTests {
			testIndex := len(creatorCoinTests) - 1 - iterIndex
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			txn := testTxns[testIndex]
			require.NoError(utxoView.DisconnectTransaction(
				txn, txn.Hash(), testUtxoOps[testIndex], blockHeight))

			// Check that the testData lines up
			if testIndex > 0 {
				testData := creatorCoinTests[testIndex-1]
				_checkTestData(testData, fmt.Sprintf("OneBigFlush: %v", testIndex), utxoView, nil)
			}
		}

		// Now flush at the end.
		require.NoError(utxoView.FlushToDb())

		// Verify the DeSo balances are back to where they started after disconnecting all the txns.
		assert.Equalf(int64(m0StartNanos),
			int64(_getBalance(t, chain, nil, m0Pub)), "m0 DeSo balance after BatchDisconnect is incorrect")
		assert.Equalf(int64(m1StartNanos),
			int64(_getBalance(t, chain, nil, m1Pub)), "m1 DeSo balance after BatchDisconnect is incorrect")
		assert.Equalf(int64(m2StartNanos),
			int64(_getBalance(t, chain, nil, m2Pub)), "m2 DeSo balance after BatchDisconnect is incorrect")
		assert.Equalf(int64(m3StartNanos),
			int64(_getBalance(t, chain, nil, m3Pub)), "m3 DeSo balance after BatchDisconnect is incorrect")
		assert.Equalf(int64(m4StartNanos),
			int64(_getBalance(t, chain, nil, m4Pub)), "m4 DeSo balance after BatchDisconnect is incorrect")
		assert.Equalf(int64(m5StartNanos),
			int64(_getBalance(t, chain, nil, m5Pub)), "m5 DeSo balance after BatchDisconnect is incorrect")
		assert.Equalf(int64(m6StartNanos),
			int64(_getBalance(t, chain, nil, m6Pub)), "m6 DeSo balance after BatchDisconnect is incorrect")
	}

	// Running all the transactions through the mempool should work and result
	// in all of them being added.
	{
		for ii, currentTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				currentTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "mempool index %v", ii)
			require.Equal(1, len(mempoolTxsAdded))

			// This will check the balances according to the mempool
			_checkTestData(creatorCoinTests[ii], fmt.Sprintf("MempoolIncrementalBalances: %v", ii), nil, mempool)
		}
	}

	// Remove all the transactions from the mempool.
	for _, burnTxn := range testTxns {
		mempool.inefficientRemoveTransaction(burnTxn)
	}

	// The balances should be reset after removing transactions from the mempool.
	assert.Equalf(int64(m0StartNanos),
		int64(_getBalance(t, chain, nil, m0Pub)), "m0 DeSo balance after BatchDisconnect is incorrect")
	assert.Equalf(int64(m1StartNanos),
		int64(_getBalance(t, chain, nil, m1Pub)), "m1 DeSo balance after BatchDisconnect is incorrect")
	assert.Equalf(int64(m2StartNanos),
		int64(_getBalance(t, chain, nil, m2Pub)), "m2 DeSo balance after BatchDisconnect is incorrect")
	assert.Equalf(int64(m3StartNanos),
		int64(_getBalance(t, chain, nil, m3Pub)), "m3 DeSo balance after BatchDisconnect is incorrect")
	assert.Equalf(int64(m4StartNanos),
		int64(_getBalance(t, chain, nil, m4Pub)), "m4 DeSo balance after BatchDisconnect is incorrect")
	assert.Equalf(int64(m5StartNanos),
		int64(_getBalance(t, chain, nil, m5Pub)), "m5 DeSo balance after BatchDisconnect is incorrect")
	assert.Equalf(int64(m6StartNanos),
		int64(_getBalance(t, chain, nil, m6Pub)), "m6 DeSo balance after BatchDisconnect is incorrect")

	// Re-add all of the transactions to the mempool so we can mine them into a block.
	{
		for _, burnTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				burnTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
		}
	}

	// Mine a block with all the mempool transactions.
	//
	// All the txns should be in the mempool already so mining a block should put
	// all those transactions in it. Note we need to mine two blocks since the first
	// one just makes the DeSo chain time-current.
	finalBlock1, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_ = finalBlock1
	finalBlock2, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	require.Equal(0, len(mempool.poolMap))

	// Add one for the block reward. Now we have a meaty block.
	require.Equal(len(finalBlock1.Txns), 1)
	require.Equal(len(finalBlock2.Txns), len(creatorCoinTests)+1)

	// The balances after mining the block should match the last testData
	{
		// Check that the state matches the final testData.
		testIndex := len(creatorCoinTests) - 1
		testData := creatorCoinTests[testIndex]
		// DeSo balances
		if _getBalance(t, chain, nil, m0Pub) != 6*NanosPerUnit && testData.m0DeSoBalance != 0 {
			assert.Equalf(int64(testData.m0DeSoBalance),
				int64(_getBalance(t, chain, nil, m0Pub)), "BlockConnect: m0 DeSo balance: %v", testIndex)
		}
		if _getBalance(t, chain, nil, m1Pub) != 6*NanosPerUnit && testData.m1DeSoBalance != 0 {
			assert.Equalf(int64(testData.m1DeSoBalance),
				int64(_getBalance(t, chain, nil, m1Pub)), "BlockConnect: m1 DeSo balance: %v", testIndex)
		}
		if _getBalance(t, chain, nil, m2Pub) != 6*NanosPerUnit && testData.m2DeSoBalance != 0 {
			assert.Equalf(int64(testData.m2DeSoBalance),
				int64(_getBalance(t, chain, nil, m2Pub)), "BlockConnect: m2 DeSo balance: %v", testIndex)
		}
		if _getBalance(t, chain, nil, m3Pub) != 6*NanosPerUnit && testData.m3DeSoBalance != 0 {
			assert.Equalf(int64(testData.m3DeSoBalance),
				int64(_getBalance(t, chain, nil, m3Pub)), "BlockConnect: m3 DeSo balance: %v", testIndex)
		}
		if _getBalance(t, chain, nil, m4Pub) != 6*NanosPerUnit && testData.m4DeSoBalance != 0 {
			assert.Equalf(int64(testData.m4DeSoBalance),
				int64(_getBalance(t, chain, nil, m4Pub)), "BlockConnect: m4 DeSo balance: %v", testIndex)
		}
		if _getBalance(t, chain, nil, m5Pub) != 6*NanosPerUnit && testData.m5DeSoBalance != 0 {
			assert.Equalf(int64(testData.m5DeSoBalance),
				int64(_getBalance(t, chain, nil, m5Pub)), "BlockConnect: m5 DeSo balance: %v", testIndex)
		}
		if _getBalance(t, chain, nil, m6Pub) != 6*NanosPerUnit && testData.m5DeSoBalance != 0 {
			assert.Equalf(int64(testData.m6DeSoBalance),
				int64(_getBalance(t, chain, nil, m6Pub)), "BlockConnect: m6 DeSo balance: %v", testIndex)
		}

	}

	// Roll back the blocks and make sure we don't hit any errors.
	disconnectSingleBlock := func(blockToDisconnect *MsgDeSoBlock, utxoView *UtxoView) {
		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := blockToDisconnect.Header.Hash()
		require.NoError(err)
		utxoOps, err := GetUtxoOperationsForBlock(db, hash)
		require.NoError(err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(blockToDisconnect.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(blockToDisconnect, txHashes, utxoOps))
	}
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		disconnectSingleBlock(finalBlock2, utxoView)
		disconnectSingleBlock(finalBlock1, utxoView)

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
	}

	// The DeSo balances should line up with what they were initially after
	// disconnecting the blocks.
	assert.Equalf(int64(m0StartNanos),
		int64(_getBalance(t, chain, nil, m0Pub)), "m0 DeSo balance after BlockDisconnect is incorrect")
	assert.Equalf(int64(m1StartNanos),
		int64(_getBalance(t, chain, nil, m1Pub)), "m1 DeSo balance after BlockDisconnect is incorrect")
	assert.Equalf(int64(m2StartNanos),
		int64(_getBalance(t, chain, nil, m2Pub)), "m2 DeSo balance after BlockDisconnect is incorrect")
	assert.Equalf(int64(m3StartNanos),
		int64(_getBalance(t, chain, nil, m3Pub)), "m3 DeSo balance after BlockDisconnect is incorrect")
	assert.Equalf(int64(m5StartNanos),
		int64(_getBalance(t, chain, nil, m5Pub)), "m5 DeSo balance after BlockDisconnect is incorrect")
	assert.Equalf(int64(m6StartNanos),
		int64(_getBalance(t, chain, nil, m6Pub)), "m6 DeSo balance after BlockDisconnect is incorrect")
}

func TestCreatorCoinWithDiamonds(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m0 buy some of their own coin
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10832150315,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           4728876540,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// Create a post for m0
		{
			TxnType:                      TxnTypeSubmitPost,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,

			PostHashToModifyIndex: -1,
			ParentPostHashIndex:   -1,
			SubmitPostBody:        "this is a post for m0",
			PostIsHidden:          false,

			SkipChecks: true,
		},
		// Create a post from m1 that is a comment on m0
		{
			TxnType:                      TxnTypeSubmitPost,
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			PostHashToModifyIndex:        -1,
			ParentPostHashIndex:          0,
			SubmitPostBody:               "this is a comment for m1",
			PostIsHidden:                 false,

			SkipChecks: true,
		},
		// Create a post from m2 that is a comment on m0
		{
			TxnType:                      TxnTypeSubmitPost,
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			PostHashToModifyIndex:        -1,
			ParentPostHashIndex:          0,
			SubmitPostBody:               "this is a comment for m2",
			PostIsHidden:                 false,

			SkipChecks: true,
		},
		// Have m0 throw a diamond on m1's comment
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ReceiverPublicKeyBase58Check: m1Pub,
			ProfilePublicKeyBase58Check:  m0Pub,
			// This field is ignored when giving a diamond. It's computed
			// by the functions called.
			CreatorCoinToTransferNanos: 0,
			DiamondPostHashIndex:       1,
			DiamondLevel:               3,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10817255342,
			m0HasPurchased:          true,
			m1CCBalance:             14894973,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           4728876535,
			m1DeSoBalance:           5999999998,
			m2DeSoBalance:           5999999998,
		},
		// m0 upgrading the diamond level should work
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ReceiverPublicKeyBase58Check: m1Pub,
			ProfilePublicKeyBase58Check:  m0Pub,
			// This field is ignored when giving a diamond. It's computed
			// by the functions called.
			CreatorCoinToTransferNanos: 0,
			DiamondPostHashIndex:       1,
			DiamondLevel:               4,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10684919520,
			m0HasPurchased:          true,
			m1CCBalance:             147230795,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           4728876532,
			m1DeSoBalance:           5999999998,
			m2DeSoBalance:           5999999998,
		},
		// m0 giving diamond level 4 to m2 should result in the same
		// CC balance for m2 as m1 has
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ReceiverPublicKeyBase58Check: m2Pub,
			ProfilePublicKeyBase58Check:  m0Pub,
			// This field is ignored when giving a diamond. It's computed
			// by the functions called.
			CreatorCoinToTransferNanos: 0,
			DiamondPostHashIndex:       2,
			DiamondLevel:               4,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10537688724,
			m0HasPurchased:          true,
			m1CCBalance:             147230795,
			m1HasPurchased:          false,
			m2CCBalance:             147230796,
			m2HasPurchased:          false,
			m0DeSoBalance:           4728876529,
			m1DeSoBalance:           5999999998,
			m2DeSoBalance:           5999999998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinWithDiamondsFailureCases(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	feeRateNanosPerKB := uint64(11)
	_, _ = mempool, miner

	// Create a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

	// Give paramUpdater some mony
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, paramUpdaterPub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	// Send money to people from moneyPk
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m0Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m1Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m2Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	// Create a post for m0
	_, postTxn, _, err := _doSubmitPostTxn(
		t, chain, db, params, feeRateNanosPerKB,
		m0Pub, m0Priv,
		nil,
		nil,
		"a post from m0",
		make(map[string][]byte),
		false)
	require.NoError(err)

	// Create a profile for m0
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			feeRateNanosPerKB /*feerate*/, m0Pub,
			m0Priv, nil, "m0",
			"m0 profile", "",
			2500, /*CreatorBasisPoints*/
			12500 /*stakeMultipleBasisPoints*/, false /*isHidden*/, false)
		require.NoError(err)
	}
	// Create a profile for m1
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			feeRateNanosPerKB /*feerate*/, m1Pub,
			m1Priv, nil, "m1",
			"m1 profile", "",
			2500, /*CreatorBasisPoints*/
			12500 /*stakeMultipleBasisPoints*/, false /*isHidden*/, false)
		require.NoError(err)
	}

	// Have m0 buy some of their own coin
	{
		_, _, _, err = _creatorCoinTxn(
			t, chain, db, params, feeRateNanosPerKB,
			m0Pub, m0Priv, /*updater*/
			m0Pub,                       /*profile*/
			CreatorCoinOperationTypeBuy, /*buy/sell*/
			1000000000,                  /*DeSoToSellNanos*/
			0,                           /*CreatorCoinToSellNanos*/
			0,                           /*DeSoToAddNanos*/
			0,                           /*MinDeSoExpectedNanos*/
			0 /*MinCreatorCoinExpectedNanos*/)
		require.NoError(err)
	}
	// Have m0 buy some m1 as well
	{
		_, _, _, err = _creatorCoinTxn(
			t, chain, db, params, feeRateNanosPerKB,
			m0Pub, m0Priv, /*updater*/
			m1Pub,                       /*profile*/
			CreatorCoinOperationTypeBuy, /*buy/sell*/
			1000000000,                  /*DeSoToSellNanos*/
			0,                           /*CreatorCoinToSellNanos*/
			0,                           /*DeSoToAddNanos*/
			0,                           /*MinDeSoExpectedNanos*/
			0 /*MinCreatorCoinExpectedNanos*/)
		require.NoError(err)
	}

	// Missing a DiamondLevel should fail
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPkBytes,
			receiverPkBytes,
			postTxn.Hash(),
			5,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		delete(txn.ExtraData, DiamondLevelKey)

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m0Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreatorCoinTransferHasDiamondPostHashWithoutDiamondLevel)
	}

	// An invalid DiamondLevel should fail
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPkBytes,
			receiverPkBytes,
			postTxn.Hash(),
			5,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		txn.ExtraData[DiamondLevelKey] = IntToBuf(15)

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m0Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), "level 15 not allowed")
	}
	// A DiamondLevel of zero should fail
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPkBytes,
			receiverPkBytes,
			postTxn.Hash(),
			5,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		txn.ExtraData[DiamondLevelKey] = IntToBuf(0)

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m0Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), "level 0 not allowed")
	}
	// You cannot give diamonds for profiles that are not your own.
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPkBytes,
			receiverPkBytes,
			postTxn.Hash(),
			5,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		txn.TxnMeta.(*CreatorCoinTransferMetadataa).ProfilePublicKey = receiverPkBytes

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m0Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreatorCoinTransferCantSendDiamondsForOtherProfiles)
	}
	// You can't Diamond yourself
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPkBytes,
			receiverPkBytes,
			postTxn.Hash(),
			5,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		txn.TxnMeta.(*CreatorCoinTransferMetadataa).ReceiverPublicKey = senderPkBytes

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m0Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreatorCoinTransferCannotTransferToSelf)
	}
	// You can't Diamond off a post that doesn't exist
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPkBytes,
			receiverPkBytes,
			postTxn.Hash(),
			5,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		emptyHash := &BlockHash{}
		txn.ExtraData[DiamondPostHashKey] = emptyHash[:]

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m0Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreatorCoinTransferDiamondPostEntryDoesNotExist)
	}
	// If you don't have enough creator coins, you can't Diamond
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			receiverPkBytes,
			senderPkBytes,
			postTxn.Hash(),
			1,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		txn.ExtraData[DiamondLevelKey] = IntToBuf(7)

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m1Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreatorCoinTransferInsufficientCreatorCoinsForDiamondLevel)
	}
	// You can't apply the same number of Diamonds to a post twice
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		// Let's have a successful transaction
		{
			senderPkBytes, _, err := Base58CheckDecode(m0Pub)
			require.NoError(err)

			receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
			require.NoError(err)

			txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
				senderPkBytes,
				receiverPkBytes,
				postTxn.Hash(),
				3,
				feeRateNanosPerKB, nil, []*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m0Priv)

			txHash := txn.Hash()
			// Always use height+1 for validation since it's assumed the transaction will
			// get mined into the next block.
			blockHeight := chain.blockTip().Height + 1
			_, _, _, _, err =
				utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.NoError(err)
			_, err = mempool.processTransaction(txn, false, false, 0, false)
			require.NoError(err)
		}
		// Now do a transaction with the same number of Diamonds
		{
			senderPkBytes, _, err := Base58CheckDecode(m0Pub)
			require.NoError(err)

			receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
			require.NoError(err)

			txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
				senderPkBytes,
				receiverPkBytes,
				postTxn.Hash(),
				5,
				feeRateNanosPerKB, mempool, []*DeSoOutput{})
			require.NoError(err)

			txn.ExtraData[DiamondLevelKey] = IntToBuf(3)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m0Priv)

			txHash := txn.Hash()
			// Always use height+1 for validation since it's assumed the transaction will
			// get mined into the next block.
			blockHeight := chain.blockTip().Height + 1
			_, _, _, _, err =
				utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.Error(err)
			require.Contains(err.Error(), RuleErrorCreatorCoinTransferPostAlreadyHasSufficientDiamonds)
		}
	}
}

func TestCreatorCoinDiamondAfterDeSoDiamondsBlockHeight(t *testing.T) {
	// Set the DeSoDiamondsBlockHeight so that it is immediately hit.
	DeSoDiamondsBlockHeight = uint32(0)

	// Set up a blockchain.
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	feeRateNanosPerKB := uint64(11)
	_, _ = mempool, miner

	// Create a paramUpdater for this test.
	params.ParamUpdaterPublicKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

	// Give paramUpdater some mony.
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, paramUpdaterPub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	// Send money to people from moneyPk.
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m0Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m1Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m2Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	// Create a post for m0.
	_, postTxn, _, err := _doSubmitPostTxn(
		t, chain, db, params, feeRateNanosPerKB,
		m0Pub, m0Priv,
		nil,
		nil,
		"a post from m0",
		make(map[string][]byte),
		false)
	require.NoError(err)

	// Create a profile for m0.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			feeRateNanosPerKB /*feerate*/, m0Pub,
			m0Priv, nil, "m0",
			"m0 profile", "",
			2500, /*CreatorBasisPoints*/
			12500 /*stakeMultipleBasisPoints*/, false /*isHidden*/, false)
		require.NoError(err)
	}
	// Create a profile for m1.
	{
		_, _, _, err = _updateProfile(
			t, chain, db, params,
			feeRateNanosPerKB /*feerate*/, m1Pub,
			m1Priv, nil, "m1",
			"m1 profile", "",
			2500, /*CreatorBasisPoints*/
			12500 /*stakeMultipleBasisPoints*/, false /*isHidden*/, false)
		require.NoError(err)
	}

	// Have m0 buy some of their own coin.
	{
		_, _, _, err = _creatorCoinTxn(
			t, chain, db, params, feeRateNanosPerKB,
			m0Pub, m0Priv, /*updater*/
			m0Pub,                       /*profile*/
			CreatorCoinOperationTypeBuy, /*buy/sell*/
			1000000000,                  /*DeSoToSellNanos*/
			0,                           /*CreatorCoinToSellNanos*/
			0,                           /*DeSoToAddNanos*/
			0,                           /*MinDeSoExpectedNanos*/
			0 /*MinCreatorCoinExpectedNanos*/)
		require.NoError(err)
	}
	// Have m0 buy some m1 as well.
	{
		_, _, _, err = _creatorCoinTxn(
			t, chain, db, params, feeRateNanosPerKB,
			m0Pub, m0Priv, /*updater*/
			m1Pub,                       /*profile*/
			CreatorCoinOperationTypeBuy, /*buy/sell*/
			1000000000,                  /*DeSoToSellNanos*/
			0,                           /*CreatorCoinToSellNanos*/
			0,                           /*DeSoToAddNanos*/
			0,                           /*MinDeSoExpectedNanos*/
			0 /*MinCreatorCoinExpectedNanos*/)
		require.NoError(err)
	}

	// Adding diamonds after the DeSo Diamonds block height should fail.
	{
		senderPkBytes, _, err := Base58CheckDecode(m0Pub)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(m1Pub)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		// Attempt to give two diamonds.
		txn, _, _, _, err := chain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPkBytes,
			receiverPkBytes,
			postTxn.Hash(),
			2,
			feeRateNanosPerKB, nil, []*DeSoOutput{})
		require.NoError(err)

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, m0Priv)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorCreatorCoinTransferHasDiamondsAfterDeSoBlockHeight)
	}
}

func TestCreatorCoinTransferSimple_CreatorCoinFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 transfer some creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   1000000,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8123112737,
			m1HasPurchased:          true,
			m2CCBalance:             1000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 transfer some more creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   20000000,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8103112737,
			m1HasPurchased:          true,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876538,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 transfer some more creator coins to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   8000000000,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10708037578,
			m0HasPurchased:          false,
			m1CCBalance:             103112737,
			m1HasPurchased:          true,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876536,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 transfer the rest of her creator coins to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   103112737,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10811150315,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 transfer all coins back to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   10811150315,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             10832150315,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999996,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 transfer all coins back to m1. Weeeeee!!!
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m1Pub,
			CreatorCoinToTransferNanos:   10832150315,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             10832150315,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999996,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           5999999998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false /*desoFounderReward*/)
}

func TestCreatorCoinTransferSimple_DeSoFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// [0] Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// [1] Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0, // Founder reward is given in DeSo here.
			m0HasPurchased:          false,
			m1CCBalance:             9841661798,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// [2] Have m1 transfer some creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   1000000,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9840661798,
			m1HasPurchased:          true,
			m2CCBalance:             1000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           6000000000,
		},
		// [3] Have m1 transfer some more creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   20000000,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9820661798,
			m1HasPurchased:          true,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876538,
			m2DeSoBalance:           6000000000,
		},
		// [4] Have m1 transfer some more creator coins to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   8000000000,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             8000000000,
			m0HasPurchased:          false,
			m1CCBalance:             1820661798,
			m1HasPurchased:          true,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876536,
			m2DeSoBalance:           6000000000,
		},
		// [5] Have m1 transfer the rest of her creator coins to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   1820661798,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             9820661798,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             21000000,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           6000000000,
		},
		// [6] Have m0 transfer all coins back to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   9820661798,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             9841661798,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749081,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           6000000000,
		},
		// [7] Have m2 transfer all coins back to m1. Weeeeee!!!
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m1Pub,
			CreatorCoinToTransferNanos:   9841661798,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9841661798,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749081,
			m1DeSoBalance:           4728876534,
			m2DeSoBalance:           5999999998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, true /*desoFounderReward*/)
}

func TestCreatorCoinTransferWithSwapIdentity(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1172373183,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           4827626815,
		},
		// Have m1 transfer 1e9 creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   1000000000,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             7124112737,
			m1HasPurchased:          true,
			m2CCBalance:             2977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           4827626815,
		},
		// Swap m0 and m3
		{
			TxnType:       TxnTypeSwapIdentity,
			FromPublicKey: m0PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m3Pub,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             7124112737,
			m1HasPurchased:          true,
			m2CCBalance:             2977342329,
			m2HasPurchased:          true,
			m3CCBalance:             3367151687,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           4827626815,
		},
		// Have m2 transfer 2e9 creator coins (now attached to m3Pub's profile) to m0
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   2000000000,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             2000000000,
			m0HasPurchased:          false,
			m1CCBalance:             7124112737,
			m1HasPurchased:          true,
			m2CCBalance:             977342329,
			m2HasPurchased:          true,
			m3CCBalance:             3367151687,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           4827626813,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinTransferWithSmallBalancesLeftOver(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 all but one nano of their creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   8124112736,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             8124112737,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 transfer all but the min threshold back to m1 (threshold assumed to be 10 nanos).
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m1Pub,
			CreatorCoinToTransferNanos:   8124112727,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112727,
			m1HasPurchased:          false,
			m2CCBalance:             10,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           5999999998,
		},
		// Have m2 transfer their remaining 10 nanos back to m1.
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m1Pub,
			CreatorCoinToTransferNanos:   10,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           5999999996,
		},
		// Have m1 transfer all but 5 nanos back to m0.
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m0Pub,
			CreatorCoinToTransferNanos:   8124112732,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10832150315,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876538,
			m2DeSoBalance:           5999999996,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinTransferWithMaxTransfers(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 send all of their creator coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   8124112737,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             8124112737,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876540,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 buy some more of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13647653882,
			DeSoLockedNanos:         2541992686,
			CoinWatermarkNanos:      13647653882,
			m0CCBalance:             3411913469,
			m0HasPurchased:          false,
			m1CCBalance:             2111627676,
			m1HasPurchased:          true,
			m2CCBalance:             8124112737,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           3457753082,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 transfer all their m0 coins to m2
		{
			TxnType: TxnTypeCreatorCoinTransfer,
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ReceiverPublicKeyBase58Check: m2Pub,
			CreatorCoinToTransferNanos:   2111627676,

			// These are the expectations
			CoinsInCirculationNanos: 13647653882,
			DeSoLockedNanos:         2541992686,
			CoinWatermarkNanos:      13647653882,
			m0CCBalance:             3411913469,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             10235740413,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           3457753080,
			m2DeSoBalance:           5999999998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinTransferBelowMinThreshold(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	// Set up a blockchain
	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	feeRateNanosPerKB := uint64(11)
	_, _ = mempool, miner

	// Send money to people from moneyPk
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m0Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m1Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m2Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m3Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m4Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m5Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m6Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	_, _, _, err := _updateProfile(
		t, chain, db, params,
		feeRateNanosPerKB /*feerate*/, m0Pub, m0Priv, m0PkBytes, "m0",
		"i am m0", "m0 profile pic", 2500, /*CreatorBasisPoints*/
		12500 /*stakeMultipleBasisPoints*/, false /*isHidden*/, false)
	require.NoError(err)

	// m1 buys some m0 creator coin.
	_, _, _, err = _creatorCoinTxn(
		t, chain, db, params, feeRateNanosPerKB,
		m1Pub, m1Priv,
		m0Pub,                       /*profile*/
		CreatorCoinOperationTypeBuy, /*buy/sell*/
		1000000000,                  /*DeSoToSellNanos*/
		0,                           /*CreatorCoinToSellNanos*/
		0,                           /*DeSoToAddNanos*/
		0,                           /*MinDeSoExpectedNanos*/
		0 /*MinCreatorCoinExpectedNanos*/)
	require.NoError(err)

	_, _, _, err = _doCreatorCoinTransferTxn(
		t, chain, db, params, feeRateNanosPerKB,
		m1Pub, m1Priv, m0Pub, m2Pub,
		mempool.bc.params.CreatorCoinAutoSellThresholdNanos-1)
	require.Contains(err.Error(), RuleErrorCreatorCoinTransferMustBeGreaterThanMinThreshold)
}

func TestCreatorCoinBuySellSimple_CreatorCoinFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1172373183,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           4827626815,
		},
		// Have m1 sell half of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4123456789,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
		},
		// Have m2 sell all of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       1977342329,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 7367807635,
			DeSoLockedNanos:         399958612,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           5243756077,
		},
		// Have m1 buy more
		// Following SalomonFixBlockHeight, this should continue
		// to mint creator coins for the creator. Read about SalomonFixBlockHeight
		// in constants.go for a more indepth explanation.
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13613944261,
			DeSoLockedNanos:         2523203055,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             4928685843,
			m0HasPurchased:          false,
			m1CCBalance:             8685258418,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4232379830,
			m2DeSoBalance:           5243756077,
		},

		// Have m1 sell the rest of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       8685258418,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4928685843,
			DeSoLockedNanos:         119727407,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             4928685843,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
		},

		{
			// Have m0 sell all of their remaining stake except for 1 CreatorCoin nano
			// This will trigger an autosell due to CreatorCoinAutoSellThresholdNanos.
			// Nobody should be left with creator coins, and the deso locked should be zero.
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4928685842,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6119715430,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
		},

		// Have m1 buy a little more, again m0 should receive some more as a founders reward
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 12852863707,
			DeSoLockedNanos:         2123244443,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             3213215926,
			m0HasPurchased:          false,
			m1CCBalance:             9639647781,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6119715430,
			m1DeSoBalance:           4512158337,
			m2DeSoBalance:           5243756077,
		},

		// Have m1 sell their creator coins.
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       9639647781,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 3213215926,
			DeSoLockedNanos:         33175681,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             3213215926,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6119715430,
			m1DeSoBalance:           6602018090,
			m2DeSoBalance:           5243756077,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinBuySellSimple_DeSoFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// [0] Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// [1] Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9841661798,
			DeSoLockedNanos:         953247258,
			CoinWatermarkNanos:      9841661798,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9841661798,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6317749083,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// [2] Have m2 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1172373183,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 12237041464,
			DeSoLockedNanos:         1832439217,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9841661798,
			m1HasPurchased:          true,
			m2CCBalance:             2395379666,
			m2HasPurchased:          true,
			m0DeSoBalance:           6610813069,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           4827626815,
		},
		// [3] Have m1 sell a large chunk of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4123456789,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 8113584675,
			DeSoLockedNanos:         534119641,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             5718205009,
			m1HasPurchased:          true,
			m2CCBalance:             2395379666,
			m2HasPurchased:          true,
			m0DeSoBalance:           6610813069,
			m1DeSoBalance:           6027066284,
			m2DeSoBalance:           4827626815,
		},
		// [4] Have m2 sell all of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       2395379666,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 5718205009,
			DeSoLockedNanos:         186973195,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             5718205009,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6610813069,
			m1DeSoBalance:           6027066284,
			m2DeSoBalance:           5174738544,
		},
		// [5] Have m1 buy more
		// Following SalomonFixBlockHeight, this should continue
		// to mint creator coins / deso for the creator. Read about SalomonFixBlockHeight
		// in constants.go for a more indepth explanation.
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 12117833075,
			DeSoLockedNanos:         1779406528,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             12117833075,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           7141624179,
			m1DeSoBalance:           3903609493,
			m2DeSoBalance:           5174738544,
		},

		// [6] Have m1 sell the rest of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       12117833075,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           7141624179,
			m1DeSoBalance:           5682838078,
			m2DeSoBalance:           5174738544,
		},

		// [7] Have m0 buy some of their own coins.
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1e6,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 999966698,
			DeSoLockedNanos:         999900,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             999966698,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           7140624177,
			m1DeSoBalance:           5682838078,
			m2DeSoBalance:           5174738544,
		},

		{
			// [8] Have m0 sell all of their remaining stake except for 1 CreatorCoin nano
			// This will trigger an autosell due to CreatorCoinAutoSellThresholdNanos.
			// Nobody should be left with creator coins, and the deso locked should be zero.
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       999966697,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           7141623975,
			m1DeSoBalance:           5682838078,
			m2DeSoBalance:           5174738544,
		},

		// [9] Have m1 buy a little more, again m0 should receive some deso as a founders reward
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 11677601773,
			DeSoLockedNanos:         1592433333,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             11677601773,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           7672435085,
			m1DeSoBalance:           3559381287,
			m2DeSoBalance:           5174738544,
		},

		// [10] Have m1 sell their creator coins.
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       11677601773,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      12237041464,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           7672435085,
			m1DeSoBalance:           5151655374,
			m2DeSoBalance:           5174738544,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, true)
}

// This test exercises some logic whereby a creator buys and
// sells their own coin before anybody else.
func TestCreatorCoinSelfBuying_DeSoAndCreatorCoinFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m0 buy his own coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             10832150315,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           4728876540,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 buy his own coins *again*
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1172373183,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             13468606753,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           3556503355,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 sell half of his own coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       1556503355,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 11912103398,
			DeSoLockedNanos:         1690307207,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             11912103398,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           4309373139,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 sell the rest of his own coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       11912103398,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999511313,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
	}

	// Buying one's own coin should always result in a creator coin founder reward,
	// even after the deso founder reward block height.
	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false /*desoFounderReward*/)
	_helpTestCreatorCoinBuySell(t, creatorCoinTests, true /*desoFounderReward*/)
}

func TestCreatorCoinTinyFounderRewardBuySellAmounts_CreatorCoinFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    1,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy a large amount of m0 to push up the watermark
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              100000000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641433551,
			DeSoLockedNanos:         99990000,
			CoinWatermarkNanos:      4641433551,
			m0CCBalance:             464143,
			m0HasPurchased:          false,
			m1CCBalance:             4640969408,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           5899999998,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 sell all their coins such that they're below the autosell threshold
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       464143,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4640969408,
			DeSoLockedNanos:         99960007,
			CoinWatermarkNanos:      4641433551,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             4640969408,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6000029986,
			m1DeSoBalance:           5899999998,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 buy more just up till CoinsInCirculationNanos is almost CoinWatermarkNanos
		// m0 should continue to receieve 1 basis point founders reward irrelevant of the CoinWatermarkNanos.
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              10000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641124148,
			DeSoLockedNanos:         99970006,
			CoinWatermarkNanos:      4641433551,
			m0CCBalance:             15, // Notice how this is just barely above the autosell threshold.
			// If this was any smaller, this transaction would fail.
			m0HasPurchased: false,
			m1CCBalance:    4641124133,
			m1HasPurchased: true,
			m2CCBalance:    0,
			m2HasPurchased: false,
			m0DeSoBalance:  6000029986,
			m1DeSoBalance:  5899989996,
			m2DeSoBalance:  6000000000,
		},
		// Now we have m2 buy a tiny amount of m0
		// This should also mint m0 a tiny founders reward, but because m0's balance
		// is above the autosell threshold, any amount will suffice.
		{
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641139607,
			DeSoLockedNanos:         99971005,
			CoinWatermarkNanos:      4641433551,
			m0CCBalance:             16,
			m0HasPurchased:          false,
			m1CCBalance:             4641124133,
			m1HasPurchased:          true,
			m2CCBalance:             15458,
			m2HasPurchased:          true,
			m0DeSoBalance:           6000029986,
			m1DeSoBalance:           5899989996,
			m2DeSoBalance:           5999998998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinTinyFounderRewardBuySellAmounts_DeSoFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    1,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy a large amount of m0 to push up the watermark
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              100000000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641278831,
			DeSoLockedNanos:         99980001,
			CoinWatermarkNanos:      4641278831,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             4641278831,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6000009997,
			m1DeSoBalance:           5899999998,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 buy more just up till CoinsInCirculationNanos is almost CoinWatermarkNanos
		// m0 should continue to receieve 1 basis point founders reward irrelevant of the CoinWatermarkNanos.
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              10000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641433550,
			DeSoLockedNanos:         99990000,
			CoinWatermarkNanos:      4641433550,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             4641433550,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6000009997,
			m1DeSoBalance:           5899989996,
			m2DeSoBalance:           6000000000,
		},
		// Now we have m2 buy a tiny amount of m0
		// This should also mint m0 a tiny founders reward, but because m0's balance
		// is above the autosell threshold, any amount will suffice.
		{
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641449007,
			DeSoLockedNanos:         99990999,
			CoinWatermarkNanos:      4641449007,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             4641433550,
			m1HasPurchased:          true,
			m2CCBalance:             15457,
			m2HasPurchased:          true,
			m0DeSoBalance:           6000009997,
			m1DeSoBalance:           5899989996,
			m2DeSoBalance:           5999998998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, true /*desoFounderReward*/)
}

func TestCreatorCoinFullFounderRewardBuySellAmounts_CreatorCoinFounderReward(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    10000,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy a large amount of m0. It should all go to m0.
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              100000000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641433551,
			DeSoLockedNanos:         99990000,
			CoinWatermarkNanos:      4641433551,
			m0CCBalance:             4641433551,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          true, // Even though m1 does not received any creator coins, we set HasPurchased to true.
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           5899999998,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 sell. The DeSo should've effectively
		// been transferred from m1 to m0.
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4641433551,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      4641433551,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          true, // Even though m1 does not received any creator coins, we set HasPurchased to true.
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6099979997,
			m1DeSoBalance:           5899999998,
			m2DeSoBalance:           6000000000,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinLargeFounderRewardBuySellAmounts(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    9999,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy a huge amount of m0. This will move CoinWatermarkNanos up.
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              100000000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4641433551,
			DeSoLockedNanos:         99990000,
			CoinWatermarkNanos:      4641433551,
			m0CCBalance:             4640969407,
			m0HasPurchased:          false,
			m1CCBalance:             464144,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           5899999998,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 try and buy a small amount of m0. If you set the amount
		// to 64000 DeSo nanos to sell, the amount to mint for m2 would
		// be 99 nano creator coins. This is below the autosell threshold,
		// so the buy (should) fail. It should respond with a rule error stating:
		// RuleErrorCreatorCoinBuyMustSatisfyAutoSellThresholdNanosForBuyer
		// Here it's set to 66000, minting just enough to push m2 above the threshold (103 nanos).
		{
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              66000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4642454435,
			DeSoLockedNanos:         100055993,
			CoinWatermarkNanos:      4642454435,
			m0CCBalance:             4641990188,
			m0HasPurchased:          false,
			m1CCBalance:             464144,
			m1HasPurchased:          true,
			m2CCBalance:             103,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           5899999998,
			m2DeSoBalance:           5999933998,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinAroundThresholdBuySellAmounts(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    0,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m0 buy his a teeny amount of his own coins
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              7,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 18171213,
			DeSoLockedNanos:         6,
			CoinWatermarkNanos:      18171213,
			m0CCBalance:             18171213,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999989,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// m0 sells just enough creator coins to reach the CreatorCoinAutoSellThresholdNanos.
		// This should not completely sell the remaining holdings.
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       18171213 - DeSoMainnetParams.CreatorCoinAutoSellThresholdNanos,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: DeSoMainnetParams.CreatorCoinAutoSellThresholdNanos,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      18171213,
			m0CCBalance:             DeSoMainnetParams.CreatorCoinAutoSellThresholdNanos,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999992,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// m1 buys m0 increasing the total number of holders to 2.
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 99966681,
			DeSoLockedNanos:         999,
			CoinWatermarkNanos:      99966681,
			m0CCBalance:             DeSoMainnetParams.CreatorCoinAutoSellThresholdNanos,
			m0HasPurchased:          true,
			m1CCBalance:             99966671,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999992,
			m1DeSoBalance:           5999998998,
			m2DeSoBalance:           6000000000,
		},
		// m0 sells a single nano of their own creator coin. This triggers the
		// CreatorCoinAutoSellThresholdNanos. This reduces the number of holders to 1.
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       1,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 99966671,
			DeSoLockedNanos:         999,
			CoinWatermarkNanos:      99966681,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             99966671,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999990,
			m1DeSoBalance:           5999998998,
			m2DeSoBalance:           6000000000,
		},
		// m2 now purchases m0's creator coins
		{
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1000000000,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9999666925,
			DeSoLockedNanos:         999900999,
			CoinWatermarkNanos:      9999666925,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             99966671,
			m1HasPurchased:          true,
			m2CCBalance:             9899700254,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999990,
			m1DeSoBalance:           5999998998,
			m2DeSoBalance:           4999999998,
		},
		// m1 sells to just past the threshold, should trigger an autosell
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       99966671 - DeSoMainnetParams.CreatorCoinAutoSellThresholdNanos + 1,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9899700254,
			DeSoLockedNanos:         970211757,
			CoinWatermarkNanos:      9999666925,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             9899700254,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999990,
			m1DeSoBalance:           6029685269,
			m2DeSoBalance:           4999999998,
		},
		// m2 sells to just past the threshold, should trigger an autosell and clear the profile
		{
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       9899700254 - DeSoMainnetParams.CreatorCoinAutoSellThresholdNanos + 1,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      9999666925,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999990,
			m1DeSoBalance:           6029685269,
			m2DeSoBalance:           5970114731,
		},
	}

	// These tests shoudl behave the same since there is no founder reward.
	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
	_helpTestCreatorCoinBuySell(t, creatorCoinTests, true /*desoFounderReward*/)
}

// The salomon sequence is a sequence of transactions known to
// cause Bancor curve errors in the earlier days of the chain.
// The sequence is named after @salomon, the finder of the sequence.
func TestSalomonSequence(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0. m0 represents salomon.
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    0,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// m0 buys a specific amount of salomon
		// In the UI this would represent selling 323138431 nanos.
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              323106117 + 6,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 6861733544,
			DeSoLockedNanos:         323073812,
			CoinWatermarkNanos:      6861733544,
			m0CCBalance:             6861733544,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5676893873,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// m0 follows up with another specific purchase.
		// In the UI this represented selling 191807888 nanos.
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              191807888 + 6,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 8014879883,
			DeSoLockedNanos:         514862525,
			CoinWatermarkNanos:      8014879883,
			m0CCBalance:             8014879883,
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5485085977,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// Now is where things got interesting. In the original salomon sequence,
		// the user (m0) attempted a max sell of all their creator coins. However,
		// due to some rounding error bugs this caused an abnormal reserve ratio
		// and the price quickly approached billions of USD / creator coins. Very
		// few creator coins were in circulation, and it would not have returned
		// to a normal price. Here we check that the amount is reset upon sale.
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       8014879883,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      8014879883,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999897012,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

// This test stress-tests our Bancor equation by doing the smallest
// possible buy one can do, which utilizes the polynomial equation
// to bootstrap, and then doing a normal-sized buy
func TestCreatorCoinBigBuyAfterSmallBuy(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m0 buy his a teeny amount of his own coins
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10000004, // Something small
			DeSoLockedNanos:         1,
			CoinWatermarkNanos:      10000004, // Something small
			m0CCBalance:             10000004, // Something small
			m0HasPurchased:          true,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999994,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 do a normal-sized buy of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832149301,
			DeSoLockedNanos:         1270996344,
			CoinWatermarkNanos:      10832149301,
			m0CCBalance:             2715537328,
			m0HasPurchased:          true,
			m1CCBalance:             8116611973,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999994,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m0 sell their amount.
		{
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       2715537328,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832149301 - 2715537328,
			DeSoLockedNanos:         534717879,
			CoinWatermarkNanos:      10832149301,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             8116611973,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6736204829,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m1 sell their amount.
		{
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       8116611973,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      10832149301,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6736204829,
			m1DeSoBalance:           5263540947,
			m2DeSoBalance:           6000000000,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestCreatorCoinBigBigBuyBigSell(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	desoToSellNanos := uint64(30000000000000000)
	{
		// Buy 30M DeSo worth of CC using polynomial model.
		polyMintedCCNanos := CalculateCreatorCoinToMintPolynomial(
			desoToSellNanos, 0, &DeSoMainnetParams)

		// Sell half of the CC
		desoReturnedNanos := CalculateDeSoToReturn(
			polyMintedCCNanos/2, polyMintedCCNanos,
			desoToSellNanos, &DeSoMainnetParams)

		// Sell the other half of the CC
		desoReturned2Nanos := CalculateDeSoToReturn(
			polyMintedCCNanos-polyMintedCCNanos/2, polyMintedCCNanos-polyMintedCCNanos/2,
			desoToSellNanos-desoReturnedNanos, &DeSoMainnetParams)

		// Should get back the amount of DeSo we put in.
		require.Equal(desoToSellNanos, desoReturnedNanos+desoReturned2Nanos)
	}

	{
		// Buy 30M worth of DeSo using the Bancor model at the very
		// beginning of the curve.
		// Sell the CC from the previous step down to zero.
		initialCCNanos := uint64(10000004)
		bancorMintedCCNanos := CalculateCreatorCoinToMintBancor(
			desoToSellNanos, initialCCNanos, 1, &DeSoMainnetParams)

		// Sell half of the CC
		desoReturnedNanos := CalculateDeSoToReturn(
			bancorMintedCCNanos/2, bancorMintedCCNanos+initialCCNanos,
			desoToSellNanos+1, &DeSoMainnetParams)

		// Sell the other half of the CC
		desoReturned2Nanos := CalculateDeSoToReturn(
			bancorMintedCCNanos-bancorMintedCCNanos/2,
			bancorMintedCCNanos-bancorMintedCCNanos/2+initialCCNanos,
			desoToSellNanos-desoReturnedNanos+1, &DeSoMainnetParams)

		// Should get back the amount of DeSo we put in.
		require.Equal(int64(desoToSellNanos), int64(desoReturnedNanos+desoReturned2Nanos))
	}
}

func TestSpamUpdateProfile(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	f, err := os.Create("/tmp/perf")
	if err != nil {
		log.Fatal(err)
	}
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()

	chain, params, _ := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	feeRateNanosPerKB := uint64(11)
	_, _ = mempool, miner

	numTxns := 250
	for ii := 0; ii < numTxns; ii++ {
		fmt.Println("Creating txns: ", ii)
		startTimeCreateTxn := time.Now()
		moneyPkBytes, _, _ := Base58CheckDecode(moneyPkString)
		txn, _, _, _, err := chain.CreateUpdateProfileTxn(
			moneyPkBytes,
			nil,
			"money",
			fmt.Sprintf("this is a new description: %v", ii),
			"profile pic",
			5000,  /*CreatorBasisPoints*/
			12500, /*StakeMultiple*/
			false, /*isHidden*/
			0,
			feeRateNanosPerKB, /*feeRateNanosPerKB*/
			mempool,           /*mempool*/
			[]*DeSoOutput{})
		require.NoError(err)
		_signTxn(t, txn, moneyPrivString)
		fmt.Printf("Creating txn took: %v seconds\n", time.Since(startTimeCreateTxn).Seconds())

		fmt.Println("Running txns through mempool: ", ii)
		startTimeMempoolAdd := time.Now()
		mempoolTxsAdded, err := mempool.processTransaction(
			txn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
			true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(1, len(mempoolTxsAdded))
		fmt.Printf("Adding to mempool took: %v seconds\n", time.Since(startTimeMempoolAdd).Seconds())
	}
}

func TestSwapIdentityNOOPCreatorCoinBuySimple(t *testing.T) {

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1172373183,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           4827626815,
		},
		// Have m1 sell half of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4123456789,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
			m3DeSoBalance:           6000000000,
		},
		// Swap m0 and m3
		// State after swapping:
		// m0Pk: m3 profile
		// m3Pk: m0 profile (the one with the profile)
		{
			TxnType:       TxnTypeSwapIdentity,
			FromPublicKey: m0PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m3Pub,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             0, // Should go to zero because it belongs to m3 now
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m3CCBalance:             3367151687,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
			m3DeSoBalance:           6000000000,
		},
		// Swap m3 and m1
		// State after swapping:
		// m0Pk: m3 profile
		// m1Pk: m0 profile (the one with the profile)
		// m3Pk: m1 profile
		{
			TxnType:       TxnTypeSwapIdentity,
			FromPublicKey: m3PkBytes,
			ToPublicKey:   m1PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m1Pub,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             0, // m0 still has zero because they got a dummy profile
			m0HasPurchased:          false,
			m1CCBalance:             3367151687, // This becomes what m3 had a moment ago.
			m1HasPurchased:          false,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m3CCBalance:             4000655948, // This becomes what m1 had a moment ago.
			m3HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
			m3DeSoBalance:           6000000000,
		},
		// Swap m0 and m1. Should restore m0's profile to it.
		// State after swapping:
		// m0Pk: m0 profile (the one with the profile)
		// m1Pk: m3 profile
		// m3Pk: m1 profile
		{
			TxnType:       TxnTypeSwapIdentity,
			FromPublicKey: m0PkBytes,
			ToPublicKey:   m1PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m0Pub,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687, // m0 should be back to normal
			m0HasPurchased:          false,
			m1CCBalance:             0, // m1 is the zero now since it took the empty profile from m0
			m1HasPurchased:          false,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m3CCBalance:             4000655948, // This is still what m1 started with.
			m3HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
			m3DeSoBalance:           6000000000,
		},
		// Swap m1 and m3. Should restore everything back to normal.
		// State after swapping:
		// m0Pk: m0 profile
		// m1Pk: m1 profile (the one with the profile)
		// m3Pk: m3 profile
		{
			TxnType:       TxnTypeSwapIdentity,
			FromPublicKey: m1PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m0Pub,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m3CCBalance:             0, // This goes back to zero as we started with.
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
			m3DeSoBalance:           6000000000,
		},
		// Have m2 sell all of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       1977342329,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 7367807635,
			DeSoLockedNanos:         399958612,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           5243756077,
		},
		// Have m1 buy more, m0 should receive 25% of the minted coins as a founders reward
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13613944261,
			DeSoLockedNanos:         2523203055,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             4928685843,
			m0HasPurchased:          false,
			m1CCBalance:             8685258418,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4232379830,
			m2DeSoBalance:           5243756077,
		},

		// Have m1 sell the rest of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       8685258418,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4928685843,
			DeSoLockedNanos:         119727407,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             4928685843,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
		},

		// Have m0 sell all of their stake except leave 1 DeSo locked
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4925685829,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 3000014,
			DeSoLockedNanos:         1,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             3000014,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6119715429,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
		},

		{
			// Have m0 sell all of their remaining stake except for 1 CreatorCoin nano
			// This will trigger an autosell.
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       3000013,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6119715427,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
		},

		// Have m1 buy a little more, m0 should receieve some
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 12852863707,
			DeSoLockedNanos:         2123244443,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             3213215926,
			m0HasPurchased:          false,
			m1CCBalance:             9639647781,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6119715427,
			m1DeSoBalance:           4512158337,
			m2DeSoBalance:           5243756077,
		},

		// Have m1 sell their creator coins. m0 should be the only one left with coins.
		// Meaning m0 is effectively being left with their founders reward, even after all
		// their supporters have sold.
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       9639647781,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 3213215926,
			DeSoLockedNanos:         33175681,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             3213215926,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           6119715427,
			m1DeSoBalance:           6602018090,
			m2DeSoBalance:           5243756077,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestSwapIdentityCreatorCoinBuySimple(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m1 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             2708037578,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           6000000000,
		},
		// Have m2 buy some of m0's coins
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1172373183,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13468606753,
			DeSoLockedNanos:         2443252288,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             8124112737,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4728876542,
			m2DeSoBalance:           4827626815,
		},
		// Have m1 sell half of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4123456789,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             3367151687,
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
		},

		// Swap m0 and m3
		{
			TxnType:       TxnTypeSwapIdentity,
			FromPublicKey: m0PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m3Pub,

			// These are the expectations
			CoinsInCirculationNanos: 9345149964,
			DeSoLockedNanos:         816129494,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             0, // Should go to zero because it belongs to m3 now
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             1977342329,
			m2HasPurchased:          true,
			m3CCBalance:             3367151687,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           4827626815,
		},

		// Have m2 sell all of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       1977342329,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 7367807635,
			DeSoLockedNanos:         399958612,
			CoinWatermarkNanos:      13468606753,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             4000655948,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             3367151687,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6355836621,
			m2DeSoBalance:           5243756077,
		},
		// Have m1 buy more, m3 should receieve a founders reward
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 13613944261,
			DeSoLockedNanos:         2523203055,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             8685258418,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             4928685843,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4232379830,
			m2DeSoBalance:           5243756077,
		},

		// Have m1 sell the rest of their stake
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       8685258418,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 4928685843,
			DeSoLockedNanos:         119727407,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             4928685843,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
		},

		// Have m3 sell all of their stake except leave 1 DeSo locked
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m3Pub,
			UpdaterPrivateKeyBase58Check: m3Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       4925685829,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 3000014,
			DeSoLockedNanos:         1,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             3000014,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
			m3DeSoBalance:           6119715431,
		},

		{
			// Have m3 sell all of their remaining stake except for 1 CreatorCoin nano
			// This should trigger the CreatorCoinAutoSellThresholdNanos threshold leaving
			// m3 with no CreatorCoins.
			UpdaterPublicKeyBase58Check:  m3Pub,
			UpdaterPrivateKeyBase58Check: m3Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       3000013,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6635615128,
			m2DeSoBalance:           5243756077,
			m3DeSoBalance:           6119715429,
		},

		// Have m1 buy a little more, m3 should receieve a founders reward
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2123456789,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 12852863707,
			DeSoLockedNanos:         2123244443,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             9639647781,
			m1HasPurchased:          true,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             3213215926,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           4512158337,
			m2DeSoBalance:           5243756077,
			m3DeSoBalance:           6119715429,
		},

		// Have m1 sell their creator coins except CreatorCoinAutoSellThresholdNanos - 1. This should
		// cause an auto sell and m1 back to zero.
		{
			// These are the transaction params
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                CreatorCoinOperationTypeSell,
			DeSoToSellNanos:              0,
			CreatorCoinToSellNanos:       9639647781 - DeSoMainnetParams.CreatorCoinAutoSellThresholdNanos + 1,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 3213215926,
			DeSoLockedNanos:         33175681,
			CoinWatermarkNanos:      13613944261,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             3213215926,
			m3HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6602018090,
			m2DeSoBalance:           5243756077,
			m3DeSoBalance:           6119715429,
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestSwapIdentityFailureCases(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	// Set up a blockchain
	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	feeRateNanosPerKB := uint64(11)
	_, _ = mempool, miner

	// Send money to people from moneyPk
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, paramUpdaterPub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m0Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m1Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, moneyPkString, m2Pub,
		moneyPrivString, 6*NanosPerUnit /*amount to send*/, feeRateNanosPerKB /*feerate*/)

	// Create a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

	// Swapping identities with a key that is not paramUpdater should fail.
	_, _, _, err := _swapIdentity(
		t, chain, db, params, feeRateNanosPerKB,
		m0Pub,
		m0Priv,
		m1PkBytes, m2PkBytes)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorSwapIdentityIsParamUpdaterOnly)

	// Swapping identities with a key that is not paramUpdater should fail.
	// - Case where the transactor is the from public key
	_, _, _, err = _swapIdentity(
		t, chain, db, params, feeRateNanosPerKB,
		m0Pub,
		m0Priv,
		m0PkBytes, m2PkBytes)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorSwapIdentityIsParamUpdaterOnly)

	// Swapping identities with a key that is not paramUpdater should fail.
	// - Case where the transactor is the to public key
	_, _, _, err = _swapIdentity(
		t, chain, db, params, feeRateNanosPerKB,
		m0Pub,
		m0Priv,
		m2PkBytes, m0PkBytes)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorSwapIdentityIsParamUpdaterOnly)
}

func TestSwapIdentityMain(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m0 so we can check creator coin balances easily.
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			ProfilePublicKeyBase58Check:  m0Pub,
			ProfileUsername:              "m0",
			ProfileDescription:           "i am m0",
			ProfilePic:                   "m0 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Swap m1 and m2, which don't have profiles yet. This should work.
		{
			TxnType:       TxnTypeSwapIdentity,
			FromPublicKey: m1PkBytes,
			ToPublicKey:   m2PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m0Pub,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      0,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             0,
			m5HasPurchased:          false,
			m6CCBalance:             0,
			m6HasPurchased:          false,
			m0DeSoBalance:           5999999998, // m0 lost 2 nanos in fees when creating her profile
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           6000000000,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           6000000000,
			m6DeSoBalance:           6000000000,

			// Profiles should not exist for either of these keys
			ProfilesToCheckPublicKeysBase58Check: []string{m1Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"", ""},
		},
		// Create a profile for m3
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m3Pub,
			UpdaterPrivateKeyBase58Check: m3Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			ProfileUsername:              "m3",
			ProfileDescription:           "i am m3",
			ProfilePic:                   "m3 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			// These are the expectations
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      0,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             0,
			m5HasPurchased:          false,
			m6CCBalance:             0,
			m6HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999998,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           6000000000,
			m6DeSoBalance:           6000000000,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic"},
		},
		// Have m5 buy coins for m3
		{
			UpdaterPublicKeyBase58Check:  m5Pub,
			UpdaterPrivateKeyBase58Check: m5Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              1271123456,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// These are the expectations
			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             2708037578,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             8124112737,
			m5HasPurchased:          true,
			m6CCBalance:             0,
			m6HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999998,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876542,
			m6DeSoBalance:           6000000000,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic"},
		},
		// Swap m2 and m3. Everything should stay the same except m2 should be the
		// creator everyone owns a piece of
		{
			TxnType:       TxnTypeSwapIdentity,
			FromPublicKey: m2PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m2Pub,

			CoinsInCirculationNanos: 10832150315,
			DeSoLockedNanos:         1270996343,
			CoinWatermarkNanos:      10832150315,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             2708037578, // The CC balance moves from m3 to m2
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             8124112737,
			m5HasPurchased:          true,
			m6CCBalance:             0,
			m6HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999998,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876542,
			m6DeSoBalance:           6000000000,

			// Profile check. Note m2 is the public key that owns the profile now.
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m2Pub, m3Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", ""},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", ""},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", ""},
		},
		// Create a profile for m3 again. This should work, since m3 lost its
		// profile to m2 easrlier
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m3Pub,
			UpdaterPrivateKeyBase58Check: m3Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			ProfileUsername:              "the_real_m3",
			ProfileDescription:           "i am the real m3",
			ProfilePic:                   "the real m3 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			// The CC balances are zero because we're checking against m3
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      0,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             0,
			m5HasPurchased:          false,
			m6CCBalance:             0,
			m6HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876542,
			m6DeSoBalance:           6000000000,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m2Pub, m3Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic"},
		},
		// Have m6 buy some coins in m3
		{
			UpdaterPublicKeyBase58Check:  m6Pub,
			UpdaterPrivateKeyBase58Check: m6Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              2000000001,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			// The CC balances are zero because we're checking against m3
			CoinsInCirculationNanos: 12598787739,
			DeSoLockedNanos:         1999800000,
			CoinWatermarkNanos:      12598787739,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             3149696934, // m3 has some of its own coins as a founder reward
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             0,
			m5HasPurchased:          false,
			m6CCBalance:             9449090805, // m6 now owns some m3
			m6HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876542,
			m6DeSoBalance:           3999999997,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m2Pub, m3Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic"},
		},
		// Have m6 buy a tiny amount of m2.
		// This should fail the AutoSellThreshold test if you set it to 2 DeSoToSellNanos
		{
			UpdaterPublicKeyBase58Check:  m6Pub,
			UpdaterPrivateKeyBase58Check: m6Priv,
			ProfilePublicKeyBase58Check:  m2Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              10,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			CoinsInCirculationNanos: 10832150340,
			DeSoLockedNanos:         1270996352,
			CoinWatermarkNanos:      10832150340,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             2708037584, // The CC balance moves from m3 to m2
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             8124112737,
			m5HasPurchased:          true,
			m6CCBalance:             19,
			m6HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876542,
			m6DeSoBalance:           3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m2Pub, m3Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic"},
		},
		// Swap m2 and m3 again.
		{
			TxnType:       TxnTypeSwapIdentity,
			FromPublicKey: m2PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m2Pub,

			CoinsInCirculationNanos: 12598787739,
			DeSoLockedNanos:         1999800000,
			CoinWatermarkNanos:      12598787739,
			// This was previously the m3 cap table, but now it's the m2 cap table.
			m0CCBalance:    0,
			m0HasPurchased: false,
			m1CCBalance:    0,
			m1HasPurchased: false,
			m2CCBalance:    3149696934,
			m2HasPurchased: false,
			m3CCBalance:    0,
			m3HasPurchased: false,
			m4CCBalance:    0,
			m4HasPurchased: false,
			m5CCBalance:    0,
			m5HasPurchased: false,
			m6CCBalance:    9449090805, // m6 now owns some m2
			m6HasPurchased: true,
			m0DeSoBalance:  5999999998,
			m1DeSoBalance:  6000000000,
			m2DeSoBalance:  6000000000,
			m3DeSoBalance:  5999999996,
			m4DeSoBalance:  6000000000,
			m5DeSoBalance:  4728876542,
			m6DeSoBalance:  3999999985,

			// Profile check. Note m2 is the public key that owns the profile now.
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic"},
		},
		// Have m5 buy a small amount of m3 and check the cap table
		// If you set the DeSoToSellNanos to 2, this will also fail the autosell threshold.
		{
			UpdaterPublicKeyBase58Check:  m5Pub,
			UpdaterPrivateKeyBase58Check: m5Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              10,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			CoinsInCirculationNanos: 10832150365,
			DeSoLockedNanos:         1270996361,
			CoinWatermarkNanos:      10832150365,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0, // The CC balance moves from m3 to m2
			m2HasPurchased:          false,
			m3CCBalance:             2708037590,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             8124112756,
			m5HasPurchased:          true,
			m6CCBalance:             19,
			m6HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876530,
			m6DeSoBalance:           3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic"},
		},
		// Swap m3 for m4 and check the m4 cap table. It should be identical to
		// the m3 cap table from before.
		{
			TxnType:       TxnTypeSwapIdentity,
			FromPublicKey: m3PkBytes,
			ToPublicKey:   m4PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m4Pub,

			CoinsInCirculationNanos: 10832150365,
			DeSoLockedNanos:         1270996361,
			CoinWatermarkNanos:      10832150365,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             2708037590, // The m3 balance has moved to m4 now
			m4HasPurchased:          false,
			m5CCBalance:             8124112756,
			m5HasPurchased:          true,
			m6CCBalance:             19,
			m6HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876530,
			m6DeSoBalance:           3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m4Pub, m2Pub, m3Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3", ""},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3", ""},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic", ""},
		},
		// Swap m2 for m3 and check the m3 cap table. It should be identical to
		// the m2 cap table from before.
		{
			TxnType:       TxnTypeSwapIdentity,
			FromPublicKey: m2PkBytes,
			ToPublicKey:   m3PkBytes,
			// This is the creator whose coins we are testing the balances of.
			// Normally it's m0, but because we swapped m0 for m3 we should test
			// that one instead.
			ProfilePublicKeyBase58Check: m3Pub,

			CoinsInCirculationNanos: 12598787739,
			DeSoLockedNanos:         1999800000,
			CoinWatermarkNanos:      12598787739,
			// This was previously the m2 cap table, but now it's the m3 cap table.
			m0CCBalance:    0,
			m0HasPurchased: false,
			m1CCBalance:    0,
			m1HasPurchased: false,
			m2CCBalance:    0,
			m2HasPurchased: false,
			m3CCBalance:    3149696934,
			m3HasPurchased: false,
			m4CCBalance:    0,
			m4HasPurchased: false,
			m5CCBalance:    0,
			m6CCBalance:    9449090805,
			m6HasPurchased: true,
			m0DeSoBalance:  5999999998,
			m1DeSoBalance:  6000000000,
			m2DeSoBalance:  6000000000,
			m3DeSoBalance:  5999999996,
			m4DeSoBalance:  6000000000,
			m5DeSoBalance:  4728876530,
			m6DeSoBalance:  3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m4Pub, m3Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3", ""},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3", ""},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic", ""},
		},
		// Swap m4 and m3 and check the m4 cap table. It should be identical to the above.
		{
			TxnType:                     TxnTypeSwapIdentity,
			FromPublicKey:               m3PkBytes,
			ToPublicKey:                 m4PkBytes,
			ProfilePublicKeyBase58Check: m4Pub,

			CoinsInCirculationNanos: 12598787739,
			DeSoLockedNanos:         1999800000,
			CoinWatermarkNanos:      12598787739,
			// This was previously the m2 cap table, but now it's the m3 cap table.
			m0CCBalance:    0,
			m0HasPurchased: false,
			m1CCBalance:    0,
			m1HasPurchased: false,
			m2CCBalance:    0,
			m2HasPurchased: false,
			m3CCBalance:    0,
			m3HasPurchased: false,
			m4CCBalance:    3149696934,
			m4HasPurchased: false,
			m5CCBalance:    0,
			m5HasPurchased: false,
			m6CCBalance:    9449090805,
			m6HasPurchased: true,
			m0DeSoBalance:  5999999998,
			m1DeSoBalance:  6000000000,
			m2DeSoBalance:  6000000000,
			m3DeSoBalance:  5999999996,
			m4DeSoBalance:  6000000000,
			m5DeSoBalance:  4728876530,
			m6DeSoBalance:  3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub, m4Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3", ""},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3", ""},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic", ""},
		},
		// Do a small m3 buy and check that the cap table lines up.
		{
			UpdaterPublicKeyBase58Check:  m5Pub,
			UpdaterPrivateKeyBase58Check: m5Priv,
			ProfilePublicKeyBase58Check:  m3Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              10,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			CoinsInCirculationNanos: 10832150390,
			DeSoLockedNanos:         1270996370,
			CoinWatermarkNanos:      10832150390,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             2708037596,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             8124112775,
			m5HasPurchased:          true,
			m6CCBalance:             19,
			m6HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           6000000000,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876518,
			m6DeSoBalance:           3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub, m4Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3", ""},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3", ""},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic", ""},
		},
		// Create a profile for m2
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			ProfilePublicKeyBase58Check:  m2Pub,
			ProfileUsername:              "the_new_m2",
			ProfileDescription:           "i am the new m2",
			ProfilePic:                   "the new m2 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			// The CC balances are zero because we're checking against m3
			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      0,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             0,
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             0,
			m5HasPurchased:          false,
			m6CCBalance:             0,
			m6HasPurchased:          false,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           5999999998,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876518,
			m6DeSoBalance:           3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub, m4Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3", "the_new_m2"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3", "i am the new m2"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic", "the new m2 profile pic"},
		},
		// Swap m2 and m4 and verify that m4 now has the zeros
		{
			TxnType:                     TxnTypeSwapIdentity,
			FromPublicKey:               m2PkBytes,
			ToPublicKey:                 m4PkBytes,
			ProfilePublicKeyBase58Check: m4Pub,

			CoinsInCirculationNanos: 0,
			DeSoLockedNanos:         0,
			CoinWatermarkNanos:      0,
			// This was previously the m2 cap table, but now it's the m3 cap table.
			m0CCBalance:    0,
			m0HasPurchased: false,
			m1CCBalance:    0,
			m1HasPurchased: false,
			m2CCBalance:    0,
			m2HasPurchased: false,
			m3CCBalance:    0,
			m3HasPurchased: false,
			m4CCBalance:    0,
			m4HasPurchased: false,
			m5CCBalance:    0,
			m5HasPurchased: false,
			m6CCBalance:    0,
			m6HasPurchased: false,
			m0DeSoBalance:  5999999998,
			m1DeSoBalance:  6000000000,
			m2DeSoBalance:  5999999998,
			m3DeSoBalance:  5999999996,
			m4DeSoBalance:  6000000000,
			m5DeSoBalance:  4728876518,
			m6DeSoBalance:  3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub, m2Pub, m4Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3", "the_new_m2"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3", "i am the new m2"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic", "the new m2 profile pic"},
		},
		// Do a small m2 buy and make sure that the m4 cap table is what we have
		// Setting DeSoToSellNanos to zero will cause an RuleErrorCreatorCoinBuyMustSatisfyAutoSellThresholdNanos
		// rule exception.
		{
			UpdaterPublicKeyBase58Check:  m5Pub,
			UpdaterPrivateKeyBase58Check: m5Priv,
			ProfilePublicKeyBase58Check:  m2Pub,
			OperationType:                CreatorCoinOperationTypeBuy,
			DeSoToSellNanos:              10,
			CreatorCoinToSellNanos:       0,
			DeSoToAddNanos:               0,
			MinDeSoExpectedNanos:         0,
			MinCreatorCoinExpectedNanos:  0,

			CoinsInCirculationNanos: 12598787757,
			DeSoLockedNanos:         1999800009,
			CoinWatermarkNanos:      12598787757,
			m0CCBalance:             0,
			m0HasPurchased:          false,
			m1CCBalance:             0,
			m1HasPurchased:          false,
			m2CCBalance:             3149696938,
			m2HasPurchased:          false,
			m3CCBalance:             0,
			m3HasPurchased:          false,
			m4CCBalance:             0,
			m4HasPurchased:          false,
			m5CCBalance:             14,
			m5HasPurchased:          true,
			m6CCBalance:             9449090805,
			m6HasPurchased:          true,
			m0DeSoBalance:           5999999998,
			m1DeSoBalance:           6000000000,
			m2DeSoBalance:           5999999998,
			m3DeSoBalance:           5999999996,
			m4DeSoBalance:           6000000000,
			m5DeSoBalance:           4728876506,
			m6DeSoBalance:           3999999985,

			// Profile check
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m3Pub, m2Pub, m4Pub},
			ProfilesToCheckUsernames:             []string{"m0", "m3", "the_real_m3", "the_new_m2"},
			ProfilesToCheckDescriptions:          []string{"i am m0", "i am m3", "i am the real m3", "i am the new m2"},
			ProfilesToCheckProfilePic:            []string{"m0 profile pic", "m3 profile pic", "the real m3 profile pic", "the new m2 profile pic"},
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestSwapIdentityWithFollows(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	creatorCoinTests := []*_CreatorCoinTestData{
		// Create a profile for m1
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m1Pub,
			ProfileUsername:              "m1",
			ProfileDescription:           "i am m1",
			ProfilePic:                   "m1 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			SkipChecks: true,
		},
		// Have m0 follow m1
		{
			TxnType:                      TxnTypeFollow,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			FollowedPublicKey:            m1PkBytes,
			IsUnfollow:                   false,
			ProfilePublicKeyBase58Check:  m1Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m1Pub, m0Pub},
			ProfilesToCheckUsernames:             []string{"m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", ""},

			// These are our follow checks
			FollowPublicKeysToCheck: []string{m0Pub, m1Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{m1Pub: true},
				{},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{},
				{m0Pub: true},
			},
		},
		// Swap m0 and m1
		{
			TxnType:                     TxnTypeSwapIdentity,
			FromPublicKey:               m0PkBytes,
			ToPublicKey:                 m1PkBytes,
			ProfilePublicKeyBase58Check: m0Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m1Pub},
			ProfilesToCheckUsernames:             []string{"m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", ""},

			// Follow checks
			// The whole thing should be reversed now. Instead of m1 following
			// m0, it should be m0 following m1.
			FollowPublicKeysToCheck: []string{m0Pub, m1Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{},
				{m0Pub: true},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{m1Pub: true},
				{},
			},
		},
		// Swap m1 and m2. m2 should now be the one following m0
		{
			TxnType:                     TxnTypeSwapIdentity,
			FromPublicKey:               m1PkBytes,
			ToPublicKey:                 m2PkBytes,
			ProfilePublicKeyBase58Check: m0Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m1Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m1", "", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", "", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", "", ""},

			// Follow checks
			// The whole thing should be reversed now. Instead of m1 following
			// m0, it should be m0 following m1.
			FollowPublicKeysToCheck: []string{m0Pub, m1Pub, m2Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{},
				{},
				{m0Pub: true},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{m2Pub: true},
				{},
				{},
			},
		},
		// Give m1 a new profile
		{
			TxnType:                      TxnTypeUpdateProfile,
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			ProfilePublicKeyBase58Check:  m1Pub,
			ProfileUsername:              "new_m1",
			ProfileDescription:           "i am new m1",
			ProfilePic:                   "new m1 profile pic",
			ProfileCreatorBasisPoints:    2500,
			ProfileIsHidden:              false,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m1Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m1", "new_m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", "i am new m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", "new m1 profile pic", ""},
		},
		// Have m2 follow m1
		{
			TxnType:                      TxnTypeFollow,
			UpdaterPublicKeyBase58Check:  m2Pub,
			UpdaterPrivateKeyBase58Check: m2Priv,
			FollowedPublicKey:            m1PkBytes,
			IsUnfollow:                   false,
			ProfilePublicKeyBase58Check:  m1Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m1Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m1", "new_m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", "i am new m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", "new m1 profile pic", ""},

			// Follow checks
			// The whole thing should be reversed now. Instead of m1 following
			// m0, it should be m0 following m1.
			FollowPublicKeysToCheck: []string{m0Pub, m1Pub, m2Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{},
				{},
				{m0Pub: true, m1Pub: true},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{m2Pub: true},
				{m2Pub: true},
				{},
			},
		},
		// Have m0 follow m1
		{
			TxnType:                      TxnTypeFollow,
			UpdaterPublicKeyBase58Check:  m0Pub,
			UpdaterPrivateKeyBase58Check: m0Priv,
			FollowedPublicKey:            m1PkBytes,
			IsUnfollow:                   false,
			ProfilePublicKeyBase58Check:  m1Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m1Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m1", "new_m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", "i am new m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", "new m1 profile pic", ""},

			// Follow checks
			// The whole thing should be reversed now. Instead of m1 following
			// m0, it should be m0 following m1.
			FollowPublicKeysToCheck: []string{m0Pub, m1Pub, m2Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{m1Pub: true},
				{},
				{m0Pub: true, m1Pub: true},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{m2Pub: true},
				{m2Pub: true, m0Pub: true},
				{},
			},
		},
		// Have m1 follow m0
		{
			TxnType:                      TxnTypeFollow,
			UpdaterPublicKeyBase58Check:  m1Pub,
			UpdaterPrivateKeyBase58Check: m1Priv,
			FollowedPublicKey:            m0PkBytes,
			IsUnfollow:                   false,
			ProfilePublicKeyBase58Check:  m1Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m1Pub, m2Pub},
			ProfilesToCheckUsernames:             []string{"m1", "new_m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", "i am new m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", "new m1 profile pic", ""},

			// Follow checks
			// The whole thing should be reversed now. Instead of m1 following
			// m0, it should be m0 following m1.
			FollowPublicKeysToCheck: []string{m0Pub, m1Pub, m2Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{m1Pub: true},
				{m0Pub: true},
				{m0Pub: true, m1Pub: true},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{m2Pub: true, m1Pub: true},
				{m2Pub: true, m0Pub: true},
				{},
			},
		},
		// Swap m1 and m2. m2 should now inherit m1's follows
		// This is a tricky one...
		{
			TxnType:                     TxnTypeSwapIdentity,
			FromPublicKey:               m1PkBytes,
			ToPublicKey:                 m2PkBytes,
			ProfilePublicKeyBase58Check: m0Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m0Pub, m2Pub, m1Pub},
			ProfilesToCheckUsernames:             []string{"m1", "new_m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", "i am new m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", "new m1 profile pic", ""},

			// Follow checks
			// The whole thing should be reversed now. Instead of m1 following
			// m0, it should be m0 following m1.
			FollowPublicKeysToCheck: []string{m0Pub, m1Pub, m2Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{m2Pub: true},
				{m0Pub: true, m2Pub: true},
				{m0Pub: true},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{m1Pub: true, m2Pub: true},
				{},
				{m1Pub: true, m0Pub: true},
			},
		},
		// Swap m2 and m0.
		{
			TxnType:                     TxnTypeSwapIdentity,
			FromPublicKey:               m2PkBytes,
			ToPublicKey:                 m0PkBytes,
			ProfilePublicKeyBase58Check: m0Pub,

			// Profile checks
			ProfilesToCheckPublicKeysBase58Check: []string{m2Pub, m0Pub, m1Pub},
			ProfilesToCheckUsernames:             []string{"m1", "new_m1", ""},
			ProfilesToCheckDescriptions:          []string{"i am m1", "i am new m1", ""},
			ProfilesToCheckProfilePic:            []string{"m1 profile pic", "new m1 profile pic", ""},

			// Follow checks
			// The whole thing should be reversed now. Instead of m1 following
			// m0, it should be m0 following m1.
			FollowPublicKeysToCheck: []string{m2Pub, m1Pub, m0Pub},
			FollowPublicKeysUserIsFollowing: []map[string]bool{
				{m0Pub: true},
				{m2Pub: true, m0Pub: true},
				{m2Pub: true},
			},
			FollowPublicKeysFollowingThisUser: []map[string]bool{
				{m1Pub: true, m0Pub: true},
				{},
				{m1Pub: true, m2Pub: true},
			},
		},
	}

	_helpTestCreatorCoinBuySell(t, creatorCoinTests, false)
}

func TestUpdateProfileChangeBack(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// This test fails non-deterministically so we wrap it in a loop to make it
	// not flake.
	for ii := 0; ii < 10; ii++ {
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

		_, _, _ = _doBasicTransferWithViewFlush(
			t, chain, db, params, moneyPkString, m0Pub,
			moneyPrivString, 10000 /*amount to send*/, 11 /*feerate*/)
		_, _, _ = _doBasicTransferWithViewFlush(
			t, chain, db, params, moneyPkString, m1Pub,
			moneyPrivString, 10000 /*amount to send*/, 11 /*feerate*/)
		_, _, _ = _doBasicTransferWithViewFlush(
			t, chain, db, params, moneyPkString, m2Pub,
			moneyPrivString, 10000 /*amount to send*/, 11 /*feerate*/)
		_, _, _ = _doBasicTransferWithViewFlush(
			t, chain, db, params, moneyPkString, m3Pub,
			moneyPrivString, 10000 /*amount to send*/, 11 /*feerate*/)

		// m0 takes m0
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				m0PkBytes,
				m0PkBytes,
				"m0",
				"",
				"",
				0,
				20000,
				false,
				0,
				100,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m0Priv)
			require.NoError(err)
			mempoolTxsAdded, err := mempool.processTransaction(
				txn, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
		}
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				m1PkBytes,
				m1PkBytes,
				"m1",
				"",
				"",
				0,
				20000,
				false,
				0,
				100,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m1Priv)
			require.NoError(err)
			mempoolTxsAdded, err := mempool.processTransaction(
				txn, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
		}
		// Write to db
		block, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		// one for the block reward, two for the new profiles
		require.Equal(1+2, len(block.Txns))

		// m1 takes m2
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				m1PkBytes,
				m1PkBytes,
				"m2",
				"",
				"",
				0,
				20000,
				false,
				0,
				100,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m1Priv)
			require.NoError(err)
			mempoolTxsAdded, err := mempool.processTransaction(
				txn, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
		}
		// m0 takes m1
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				m0PkBytes,
				m0PkBytes,
				"m1",
				"",
				"",
				0,
				20000,
				false,
				0,
				100,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m0Priv)
			require.NoError(err)

			// This ensure that the read-only version of the utxoView accurately reflects the current set of profile names taken.
			utxoViewCopy, err := mempool.universalUtxoView.CopyUtxoView()
			require.NoError(err)
			txnSize := getTxnSize(*txn)
			_, _, _, _, err = utxoViewCopy.ConnectTransaction(txn, txn.Hash(), txnSize, chain.blockTip().Height+1, false, false)
			require.NoError(err)

			mempoolTxsAdded, err := mempool.processTransaction(
				txn, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
		}
		// m1 takes m0
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				m1PkBytes,
				m1PkBytes,
				"m0",
				"",
				"",
				0,
				20000,
				false,
				0,
				100,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m1Priv)
			require.NoError(err)
			mempoolTxsAdded, err := mempool.processTransaction(
				txn, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
		}
		// Write to db
		block, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		// one for the block reward, three for the new txns
		require.Equal(1+3, len(block.Txns))

		// m2 takes m0 should fail
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				m2PkBytes,
				m2PkBytes,
				"m0",
				"",
				"",
				0,
				20000,
				false,
				0,
				100,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m2Priv)
			require.NoError(err)
			mempoolTxsAdded, err := mempool.processTransaction(
				txn, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.Error(err)
			require.Equal(0, len(mempoolTxsAdded))
		}
		// m3 takes m0 should fail
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				m3PkBytes,
				m3PkBytes,
				"m0",
				"",
				"",
				0,
				20000,
				false,
				0,
				100,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, m3Priv)
			require.NoError(err)
			mempoolTxsAdded, err := mempool.processTransaction(
				txn, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.Error(err)
			require.Equal(0, len(mempoolTxsAdded))
		}
	}
}

// Because txns in the balance model use fewer bytes, balances will differ
// after completing a transaction vs. the UTXO model.
func _balanceModelDiff(bc *Blockchain, diffAmount uint64) uint64 {
	if bc.blockTip().Height >= BalanceModelBlockHeight {
		return diffAmount
	} else {
		return 0
	}
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
		require.Equal(uint64(28)+_balanceModelDiff(chain, 1), m0BalBeforeNFT)

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
		require.Equal(uint64(27)+_balanceModelDiff(chain, 1), m0BalAfterNFT)
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
		if chain.blockTip().Height < BalanceModelBlockHeight {
			require.Contains(err.Error(), RuleErrorCreateNFTWithInsufficientFunds)
		} else {
			require.Contains(err.Error(), RuleErrorCreateNFTTxnWithInsufficientFee)
		}
	}

	// Creating an NFT with the correct NFT fee should succeed.
	// This time set HasUnlockable to 'true'.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		numCopies := uint64(10)
		nftFee := utxoView.GlobalParamsEntry.CreateNFTFeeNanos * numCopies

		m0BalBeforeNFT := _getBalance(testMeta.t, testMeta.chain, nil, m0Pub)
		require.Equal(uint64(26)+_balanceModelDiff(chain, 1), m0BalBeforeNFT)

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
		require.Equal(uint64(25)+_balanceModelDiff(chain, 1)-nftFee, m0BalAfterNFT)
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

func TestAuthorizeDerivedKeyBasic(t *testing.T) {
	NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)

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
	senderPrivBytes, _, err := Base58CheckDecode(senderPrivString)
	require.NoError(err)
	recipientPkBytes, _, err := Base58CheckDecode(recipientPkString)
	require.NoError(err)

	// Get AuthorizeDerivedKey txn metadata with expiration at block 6
	senderPriv, _ := btcec.PrivKeyFromBytes(btcec.S256(), senderPrivBytes)
	authTxnMeta, derivedPriv := _getAuthorizeDerivedKeyMetadata(t, senderPriv, params, 6, false)
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
			utxoView, err = NewUtxoView(db, params, nil)
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
			derivedKeyEntry := DBGetOwnerToDerivedKeyMapping(db, *NewPublicKey(senderPkBytes), *NewPublicKey(derivedPublicKey))
			// If we removed the derivedKeyEntry from utxoView altogether, it'll be nil.
			// To pass the tests, we initialize it to a default struct.
			if derivedKeyEntry == nil {
				derivedKeyEntry = &DerivedKeyEntry{*NewPublicKey(senderPkBytes), *NewPublicKey(derivedPublicKey), 0, AuthorizeDerivedKeyOperationValid, false}
			}
			assert.Equal(derivedKeyEntry.ExpirationBlock, expirationBlockExpected)
			assert.Equal(derivedKeyEntry.OperationType, operationTypeExpected)
		} else {
			utxoView, err := mempool.GetAugmentedUniversalView()
			require.NoError(err)
			derivedKeyEntry := utxoView._getDerivedKeyMappingForOwner(senderPkBytes, derivedPublicKey)
			// If we removed the derivedKeyEntry from utxoView altogether, it'll be nil.
			// To pass the tests, we initialize it to a default struct.
			if derivedKeyEntry == nil {
				derivedKeyEntry = &DerivedKeyEntry{*NewPublicKey(senderPkBytes), *NewPublicKey(derivedPublicKey), 0, AuthorizeDerivedKeyOperationValid, false}
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
		utxoView, err := NewUtxoView(db, params, nil)
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
		utxoView, err := NewUtxoView(db, params, nil)
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
			false)
		require.Contains(err.Error(), RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn signed with an unauthorized private key.")
	}
	// Attempt sending an AuthorizeDerivedKey txn where access signature is signed with
	// an invalid private key. This must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil)
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
			false)
		require.Error(err)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn signed with an invalid access signature.")
	}
	// Check basic transfer signed with still unauthorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, nil)
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
		utxoView, err := NewUtxoView(db, params, nil)
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
			false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())

		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// Verify that expiration block was persisted in the db
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed connecting AuthorizeDerivedKey txn signed with an authorized private key. Flushed to Db.")
	}
	// Check basic transfer signed by the owner key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 1, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with owner key. Flushed to Db.")
	}
	// Check basic transfer signed with now authorized derived key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
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
		utxoView, err := NewUtxoView(db, params, nil)
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
			utxoView, err := NewUtxoView(db, params, nil)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(), "SimpleDisconnect: Index: %v", testIndex)
		}

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txns. Flushed to Db.")
	}
	// After disconnecting, check basic transfer signed with unauthorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, nil)
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
		utxoView, err := NewUtxoView(db, params, nil)
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
		require.NoError(utxoView.FlushToDb())

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
		utxoView, err := NewUtxoView(db, params, nil)
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
		utxoView, err := NewUtxoView(db, params, nil)
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
		require.NoError(utxoView.FlushToDb())

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
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		fmt.Println("Passed basic transfer signed with owner key. Flushed to Db.")
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 3, AuthorizeDerivedKeyOperationValid, nil)
	}
	// Check basic transfer signed with authorized derived key. Now the auth txn is persisted in the db.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
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
		utxoView, err := NewUtxoView(db, params, nil)
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
			utxoView, err := NewUtxoView(db, params, nil)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(), "SimpleDisconnect: Index: %v", testIndex)
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
		utxoView, err := NewUtxoView(db, params, nil)
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
		utxoView, err := NewUtxoView(db, params, nil)
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
	authTxnMetaDeAuth, derivedDeAuthPriv := _getAuthorizeDerivedKeyMetadata(t, senderPriv, params, 10, false)
	derivedPrivDeAuthBase58Check := Base58CheckEncode(derivedDeAuthPriv.Serialize(), true, params)
	derivedDeAuthPkBytes := derivedDeAuthPriv.PubKey().SerializeCompressed()
	fmt.Println("Derived public key:", hex.EncodeToString(derivedDeAuthPkBytes))
	// Send an authorize transaction signed with the correct derived key.
	// This must pass.
	{
		utxoView, err := NewUtxoView(db, params, nil)
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
			false)
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
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
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
		utxoView, err := NewUtxoView(db, params, nil)
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
			true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)
		// Verify the expiration block in the db
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed connecting AuthorizeDerivedKey txn with isDeleted signed with an authorized private key.")
	}
	// Check basic transfer signed with new authorized derived key.
	// Now that key has been de-authorized this must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil)
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
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// Balance should change to 4
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed basic transfer signed with owner key.")
	}
	// Send an authorize transaction signed with a derived key.
	// Since we've already deleted this derived key, this must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil)
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
			false)
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
			utxoView, err := NewUtxoView(db, params, nil)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(), "SimpleDisconnect: Index: %v", testIndex)
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
			false)
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
		utxoView, err := NewUtxoView(db, params, nil)
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
		utxoView, err := NewUtxoView(db, params, nil)
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
			false)
		require.Contains(err.Error(), RuleErrorAuthorizeDerivedKeyDeletedDerivedPublicKey)

		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn with de-authorized private key.")
	}
	// Sanity check basic transfer signed by the owner key.
	// Should succeed.
	{
		utxoView, err := NewUtxoView(db, params, nil)
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
		utxoOps, err := GetUtxoOperationsForBlock(db, hash)
		require.NoError(err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(blockToDisconnect.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(blockToDisconnect, txHashes, utxoOps))
	}
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		for iterIndex := range testBlocks {
			testIndex := len(testBlocks) - 1 - iterIndex
			testBlock := testBlocks[testIndex]
			disconnectSingleBlock(testBlock, utxoView)
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
		fmt.Println("Successfully rolled back the blocks.")
	}

	// After we rolled back the blocks, db should reset
	_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, AuthorizeDerivedKeyOperationValid, nil)
	fmt.Println("Successfuly run TestAuthorizeDerivedKeyBasic()")
}

func TestDeSoDiamonds(t *testing.T) {
	DeSoDiamondsBlockHeight = 0
	diamondValueMap := GetDeSoNanosDiamondLevelMapAtBlockHeight(0)

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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 1000000000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 1000000000)

	// Get PKIDs for looking up diamond entries.
	m0PkBytes, _, err := Base58CheckDecode(m0Pub)
	require.NoError(err)
	m0PKID := DBGetPKIDEntryForPublicKey(db, m0PkBytes)

	m1PkBytes, _, err := Base58CheckDecode(m1Pub)
	require.NoError(err)
	m1PKID := DBGetPKIDEntryForPublicKey(db, m1PkBytes)

	m2PkBytes, _, err := Base58CheckDecode(m2Pub)
	require.NoError(err)
	m2PKID := DBGetPKIDEntryForPublicKey(db, m2PkBytes)
	_ = m2PKID

	validateDiamondEntry := func(
		senderPKID *PKID, receiverPKID *PKID, diamondPostHash *BlockHash, diamondLevel int64) {

		diamondEntry := DbGetDiamondMappings(db, receiverPKID, senderPKID, diamondPostHash)

		if diamondEntry == nil && diamondLevel > 0 {
			t.Errorf("validateDiamondEntry: couldn't find diamond entry for diamondLevel %d", diamondLevel)
		} else if diamondEntry == nil && diamondLevel == 0 {
			// If diamondLevel is set to zero, we are checking that diamondEntry is nil.
			return
		}

		require.Equal(diamondEntry.DiamondLevel, diamondLevel)
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

	// Have m1 give the post a diamond.
	{
		// Balances before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999), m0BalBeforeNFT)
		m1BalBeforeNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 0)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 1)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 1)

		// Balances after.
		m0BalAfterNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[1]), m0BalAfterNFT)
		m1BalAfterNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[1]-2), m1BalAfterNFT)
	}

	// Upgrade the post from 1 -> 2 diamonds.
	{
		// Balances before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[1]), m0BalBeforeNFT)
		m1BalBeforeNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[1]-2), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 1)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 2)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 2)

		// Balances after.
		m0BalAfterNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[2]), m0BalAfterNFT)
		m1BalAfterNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[2]-4), m1BalAfterNFT)
	}

	// Upgrade the post from 2 -> 3 diamonds.
	{
		// Balances before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[2]), m0BalBeforeNFT)
		m1BalBeforeNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[2]-4), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 2)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 3)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 3)

		// Balances after.
		m0BalAfterNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[3]), m0BalAfterNFT)
		m1BalAfterNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[3]-6), m1BalAfterNFT)
	}

	// Upgrade the post from 3 -> 4 diamonds.
	{
		// Balances before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[3]), m0BalBeforeNFT)
		m1BalBeforeNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[3]-6), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 3)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 4)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 4)

		// Balances after.
		m0BalAfterNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[4]), m0BalAfterNFT)
		m1BalAfterNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[4]-8), m1BalAfterNFT)
	}

	// Upgrade the post from 4 -> 5 diamonds.
	{
		// Balances before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[4]), m0BalBeforeNFT)
		m1BalBeforeNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[4]-8), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 4)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 5)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 5)

		// Balances after.
		m0BalAfterNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[5]), m0BalAfterNFT)
		m1BalAfterNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[5]-10), m1BalAfterNFT)
	}

	// Have m2 give the post 5 diamonds right off the bat.
	{
		// Balances before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[5]), m0BalBeforeNFT)
		m2BalBeforeNFT := _getBalance(t, chain, nil, m2Pub)
		require.Equal(uint64(1e9), m2BalBeforeNFT)

		validateDiamondEntry(m2PKID.PKID, m0PKID.PKID, post1Hash, 0)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m2Pub, m2Priv, post1Hash, 5)
		validateDiamondEntry(m2PKID.PKID, m0PKID.PKID, post1Hash, 5)

		// Balances after.
		m0BalAfterNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[5]+diamondValueMap[5]), m0BalAfterNFT)
		m2BalAfterNFT := _getBalance(t, chain, nil, m2Pub)
		require.Equal(uint64(1e9-diamondValueMap[5]-2), m2BalAfterNFT)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestDeSoDiamondErrorCases(t *testing.T) {
	DeSoDiamondsBlockHeight = 0
	diamondValueMap := GetDeSoNanosDiamondLevelMapAtBlockHeight(0)

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
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 1000000000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 1000000000)

	// Since the "CreateBasicTransferTxnWithDiamonds()" function in blockchain.go won't let us
	// trigger most errors that we want to check, we create another version of the function here
	// that allows us to put together whatever type of broken txn we want.
	_giveCustomDeSoDiamondTxn := func(
		senderPkBase58Check string, senderPrivBase58Check string, receiverPkBase58Check string,
		diamondPostHashBytes []byte, diamondLevel int64, amountNanos uint64) (_err error) {

		senderPkBytes, _, err := Base58CheckDecode(senderPkBase58Check)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(receiverPkBase58Check)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		// Build the basic transfer txn.
		txn := &MsgDeSoTxn{
			PublicKey: senderPkBytes,
			TxnMeta:   &BasicTransferMetadata{},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   receiverPkBytes,
					AmountNanos: amountNanos,
				},
			},
			// TxInputs and TxOutputs will be set below.
			// This function does not compute a signature.
		}

		// Make a map for the diamond extra data and add it.
		diamondsExtraData := make(map[string][]byte)
		diamondsExtraData[DiamondLevelKey] = IntToBuf(diamondLevel)
		diamondsExtraData[DiamondPostHashKey] = diamondPostHashBytes
		txn.ExtraData = diamondsExtraData

		// We don't need to make any tweaks to the amount because it's basically
		// a standard "pay per kilobyte" transaction.
		totalInput, _, _, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, mempool)
		if err != nil {
			return errors.Wrapf(
				err, "giveCustomDeSoDiamondTxn: Problem adding inputs: ")
		}

		// We want our transaction to have at least one input, even if it all
		// goes to change. This ensures that the transaction will not be "replayable."
		blockHeight := chain.blockTip().Height + 1
		if len(txn.TxInputs) == 0 && blockHeight < BalanceModelBlockHeight {
			return fmt.Errorf(
				"giveCustomDeSoDiamondTxn: BasicTransfer txn must have at" +
					" least one input but had zero inputs instead. Try increasing the fee rate.")
		}

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, senderPrivBase58Check)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		utxoOps, totalInput, totalOutput, fees, err :=
			utxoView.ConnectTransaction(
				txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		if err != nil {
			return err
		}
		require.Equal(t, totalInput, totalOutput+fees)

		if blockHeight < BalanceModelBlockHeight {
			// We should have one SPEND UtxoOperation for each input, one ADD operation
			// for each output, and one OperationTypeDeSoDiamond operation at the end.
			require.Equal(t, len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
			for ii := 0; ii < len(txn.TxInputs); ii++ {
				require.Equal(t, OperationTypeSpendUtxo, utxoOps[ii].Type)
			}
			require.Equal(t, OperationTypeDeSoDiamond, utxoOps[len(utxoOps)-1].Type)
		} else {
			require.Equal(t, OperationTypeAddBalance, utxoOps[0].Type)
			require.Equal(t, OperationTypeSpendBalance, utxoOps[1].Type)
			require.Equal(t, OperationTypeDeSoDiamond, utxoOps[2].Type)
		}

		require.NoError(utxoView.FlushToDb())

		return nil
	}

	// Error case: PostHash with bad length.
	{
		err := _giveCustomDeSoDiamondTxn(
			m0Pub,
			m0Priv,
			m1Pub,
			RandomBytes(HashSizeBytes-1),
			1,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBasicTransferDiamondInvalidLengthForPostHashBytes)
	}

	// Error case: non-existent post.
	{
		err := _giveCustomDeSoDiamondTxn(
			m0Pub,
			m0Priv,
			m1Pub,
			RandomBytes(HashSizeBytes),
			1,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBasicTransferDiamondPostEntryDoesNotExist)
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

	// Error case: cannot diamond yourself.
	{
		err := _giveCustomDeSoDiamondTxn(
			m0Pub,
			m0Priv,
			m1Pub,
			post1Hash[:],
			1,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBasicTransferDiamondCannotTransferToSelf)
	}

	// Error case: don't include diamond level.
	{
		_, _, _, err := _giveDeSoDiamonds(
			t, chain, db, params,
			10,
			m1Pub,
			m1Priv,
			post1Hash,
			1,
			true, /*deleteDiamondLevel*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBasicTransferHasDiamondPostHashWithoutDiamondLevel)
	}

	// Error case: invalid diamond level.
	{
		err := _giveCustomDeSoDiamondTxn(
			m1Pub,
			m1Priv,
			m0Pub,
			post1Hash[:],
			-1,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBasicTransferHasInvalidDiamondLevel)
	}

	// Error case: insufficient deso.
	{
		err := _giveCustomDeSoDiamondTxn(
			m1Pub,
			m1Priv,
			m0Pub,
			post1Hash[:],
			2,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBasicTransferInsufficientDeSoForDiamondLevel)
	}
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
