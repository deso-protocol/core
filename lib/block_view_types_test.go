package lib

import (
	"bytes"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"reflect"
	"testing"
)

/*
	TODO: Maybe we add generic encoder tests that create DeSoEncoder structs with
		some random data and try to encode/decode
*/
func TestEmptyTypeEncoders(t *testing.T) {
	require := require.New(t)
	testCases := []DeSoEncoder{
		&BalanceEntry{},
		&CoinEntry{},
		&DerivedKeyEntry{},
		&DiamondEntry{},
		&ForbiddenPubKeyEntry{},
		&GlobalParamsEntry{},
		&LikeEntry{},
		&MessageEntry{},
		&MessagingGroupEntry{},
		&MessagingGroupMember{},
		&NFTBidEntry{},
		&NFTEntry{},
		&PKIDEntry{},
		&PostEntry{},
		&ProfileEntry{},
		&PublicKeyRoyaltyPair{},
		&RepostEntry{},
		&UtxoEntry{},
		&UtxoOperation{},
	}
	for _, testType := range testCases {
		testBytes := testType.Encode()
		rr := bytes.NewReader(testBytes)
		require.NoError(testType.Decode(rr))
	}
}

// A lazy test based on TestBitcoinExchange to check utxo encoding/decoding.
func TestUtxoEntryEncodeDecode(t *testing.T) {
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
	mempool, _ := NewTestMiner(t, chain, params, true /*isSender*/)

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
	pkBytes3, _ := hex.DecodeString(BitcoinTestnetPub3)

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

	// Make the moneyPkString the paramUpdater so they can update the exchange rate.
	rateUpdateIndex := 4
	params.ParamUpdaterPublicKeys = make(map[PkMapKey]bool)
	params.ParamUpdaterPublicKeys[MakePkMapKey(MustBase58CheckDecode(moneyPkString))] = true
	paramsCopy.ParamUpdaterPublicKeys = params.ParamUpdaterPublicKeys
	// Applying all the txns to the UtxoView should work. Include a rate update
	// in the middle.
	utxoOpsList := [][]*UtxoOperation{}
	{
		utxoView, err := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
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
			assert.Equal(int64(fees), int64(totalInput-totalOutput))

			_, _, _ = ii, totalOutput, fees
			utxoOpsList = append(utxoOpsList, utxoOps)
		}
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, utxoView)
		for _, entry := range utxoEntries {
			entryBytes := entry.Encode()
			newEntry := UtxoEntry{}
			rr := bytes.NewReader(entryBytes)
			newEntry.Decode(rr)
			require.Equal(reflect.DeepEqual(entry.String(), newEntry.String()), true)
		}

		// Flushing the UtxoView should work.
		require.NoError(utxoView.FlushToDb())
	}
	//utxoEntries, _ := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil, utxoView)
	//fmt.Println("Length of UtxoEntrie:", len(utxoEntries))
}
