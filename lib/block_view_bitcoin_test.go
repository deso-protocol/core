package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	merkletree "github.com/deso-protocol/go-merkle-tree"
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
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

func _privStringToKeys(t *testing.T, privString string) (*btcec.PrivateKey, *btcec.PublicKey) {
	require := require.New(t)
	result, _, err := Base58CheckDecodePrefix(privString, 1)
	require.NoError(err)
	result = result[:len(result)-1]
	return btcec.PrivKeyFromBytes(btcec.S256(), result)
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

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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

func TestBitcoinExchange(t *testing.T) {
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
		utxoView, err := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
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
		require.NoError(utxoView.FlushToDb(0))
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
		utxoView, err := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
		require.NoError(err)
		for ii := range bitcoinExchangeTxns {
			index := len(bitcoinExchangeTxns) - 1 - ii
			burnTxn := bitcoinExchangeTxns[index]
			blockHeight := chain.blockTip().Height + 1
			err := utxoView.DisconnectTransaction(burnTxn, burnTxn.Hash(), utxoOpsList[index], blockHeight)
			require.NoErrorf(err, "Transaction index: %v", index)
		}

		// Flushing the UtxoView back to the db after rolling back the
		require.NoError(utxoView.FlushToDb(0))
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
		utxoView, err := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
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
		require.NoError(utxoView.FlushToDb(0))
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
		utxoView, err := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
		require.NoError(err)

		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock4.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock4.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock4, txHashes, utxoOps, 0))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock3.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock3.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock3, txHashes, utxoOps, 0))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock2.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock2.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock2, txHashes, utxoOps, 0))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock1.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock1.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock1, txHashes, utxoOps, 0))
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb(0))
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
		utxoView, _ := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
		blockHeight := chain.blockTip().Height + 1
		utxoView.ConnectTransaction(burnTxn1, txHash1, burnTxn1Size, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	}

	{
		utxoView, _ := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
		blockHeight := chain.blockTip().Height + 1
		utxoView.ConnectTransaction(burnTxn1, txHash1, burnTxn1Size, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	}

	// The transaction should pass now
	{
		utxoView, _ := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
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
		utxoView, err := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
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
		require.NoError(utxoView.FlushToDb(0))
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
		utxoView, err := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
		require.NoError(err)
		for ii := range bitcoinExchangeTxns {
			index := len(bitcoinExchangeTxns) - 1 - ii
			burnTxn := bitcoinExchangeTxns[index]
			blockHeight := chain.blockTip().Height + 1
			err := utxoView.DisconnectTransaction(burnTxn, burnTxn.Hash(), utxoOpsList[index], blockHeight)
			require.NoErrorf(err, "Transaction index: %v", index)
		}

		// Flushing the UtxoView back to the db after rolling back the
		require.NoError(utxoView.FlushToDb(0))
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
		utxoView, err := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
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
		require.NoError(utxoView.FlushToDb(0))
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
		utxoView, err := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
		require.NoError(err)

		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock4.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock4.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock4, txHashes, utxoOps, 0))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock3.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock3.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock3, txHashes, utxoOps, 0))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock2.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock2.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock2, txHashes, utxoOps, 0))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock1.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock1.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock1, txHashes, utxoOps, 0))
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb(0))
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
		utxoView, _ := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
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
		utxoView, err := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
		require.NoError(err)

		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock4.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock4.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock4, txHashes, utxoOps, 0))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock3.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock3.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock3, txHashes, utxoOps, 0))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock2.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock2.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock2, txHashes, utxoOps, 0))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock1.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock1.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock1, txHashes, utxoOps, 0))
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb(0))

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
			assert.Equal(expectedDeSoNanosMinted[ii], int64(totalInput))
			assert.Equal(expectedDeSoNanosMinted[ii]*int64(paramsCopy.BitcoinExchangeFeeBasisPoints)/10000, int64(fees))
			assert.Equal(int64(fees), int64(totalInput-totalOutput))

			_, _, _ = ii, totalOutput, fees
			utxoOpsList = append(utxoOpsList, utxoOps)
		}

		// Flushing the UtxoView should work.
		require.NoError(utxoView.FlushToDb(0))
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
		utxoView, err := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
		require.NoError(err)
		for ii := range bitcoinExchangeTxns {
			index := len(bitcoinExchangeTxns) - 1 - ii
			burnTxn := bitcoinExchangeTxns[index]
			blockHeight := chain.blockTip().Height + 1
			err := utxoView.DisconnectTransaction(burnTxn, burnTxn.Hash(), utxoOpsList[index], blockHeight)
			require.NoErrorf(err, "Transaction index: %v", index)
		}

		// Flushing the UtxoView back to the db after rolling back the
		require.NoError(utxoView.FlushToDb(0))
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
		utxoView, err := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
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
		require.NoError(utxoView.FlushToDb(0))
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
		utxoView, err := NewUtxoView(db, paramsCopy, nil, chain.snapshot)
		require.NoError(err)

		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock4.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock4.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock4, txHashes, utxoOps, 0))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock3.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock3.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock3, txHashes, utxoOps, 0))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock2.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock2.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock2, txHashes, utxoOps, 0))
		}
		{
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			hash, err := finalBlock1.Header.Hash()
			require.NoError(err)
			utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
			require.NoError(err)

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(finalBlock1.Txns)
			require.NoError(err)
			require.NoError(utxoView.DisconnectBlock(finalBlock1, txHashes, utxoOps, 0))
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb(0))
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

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		txnSize := getTxnSize(*updateExchangeRateTxn)
		blockHeight := chain.blockTip().Height + 1
		utxoOps, totalInput, totalOutput, fees, err :=
			utxoView.ConnectTransaction(updateExchangeRateTxn,
				updateExchangeRateTxn.Hash(), txnSize, blockHeight, true, /*verifySignature*/
				false /*ignoreUtxos*/)
		require.NoError(err)
		_, _, _, _ = utxoOps, totalInput, totalOutput, fees
		require.NoError(utxoView.FlushToDb(0))

		// Check the balance of the updater after this txn
		require.NotEqual(0, _getBalance(t, chain, nil, moneyPkString))
	}
}
