package lib

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Increase numProfiles and numPostsPerProfile to load test
func TestComputeMaxTPS(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_, _ = mempool, db

	// Send money to 1,000 public keys
	// For each public key, create a profile
	// For each profile, make 1,000 posts
	numProfiles := 1
	numPostsPerProfile := 1000
	privKeys := []*btcec.PrivateKey{}
	pubKeys := []*btcec.PublicKey{}
	txns := []*MsgDeSoTxn{}
	for ii := 0; ii < numProfiles; ii++ {
		fmt.Println("Processing top txn: ", len(txns))
		// Compute a private/public key pair
		privKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		privKeys = append(privKeys, privKey)
		pubKeys = append(pubKeys, privKey.PubKey())
		currentPubStr := PkToString(
			pubKeys[len(pubKeys)-1].SerializeCompressed(), params)
		currentPrivStr := PrivToString(
			privKeys[len(privKeys)-1].Serialize(), params)

		// Send money to this key
		{
			txn := _assembleBasicTransferTxnFullySigned(
				t, chain, 1000000000, 100, moneyPkString,
				currentPubStr, moneyPrivString, mempool)

			_, err := mempool.ProcessTransaction(txn, false, false, 0, false)
			require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, txn)

			txns = append(txns, txn)
		}

		// Create a profile for this key
		{
			txn, _, _, _, err := chain.CreateUpdateProfileTxn(
				pubKeys[len(pubKeys)-1].SerializeCompressed(),
				nil,
				fmt.Sprintf("username_%v", ii),
				"",
				"",
				500,
				12500,
				false,
				0,
				nil,
				10,
				mempool, /*mempool*/
				[]*DeSoOutput{})
			require.NoError(err)
			_signTxn(t, txn, currentPrivStr)
			_, err = mempool.ProcessTransaction(
				txn, false, false, 0, false)
			require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, txn)

			txns = append(txns, txn)
		}
		bodyObj := &DeSoBodySchema{Body: "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" +
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" +
			"12345678901234567890123456789012345678901234567890123456789012345678901234567890"}
		bodyBytes, err := json.Marshal(bodyObj)
		require.NoError(err)
		postExtraData := make(map[string][]byte)
		// Create posts for this profile
		for jj := 0; jj < numPostsPerProfile; jj++ {
			fmt.Println("Processing inner txn: ", len(txns))
			txn, _, _, _, err := chain.CreateSubmitPostTxn(
				pubKeys[len(pubKeys)-1].SerializeCompressed(),
				[]byte{},
				[]byte{},
				bodyBytes,
				[]byte{},
				false,
				uint64(time.Now().UnixNano()),
				postExtraData,
				false,
				100,
				mempool,
				[]*DeSoOutput{})
			require.NoError(err)

			// Sign the transaction now that its inputs are set up.
			_signTxn(t, txn, currentPrivStr)

			_, err = mempool.ProcessTransaction(
				txn, false, false, 0, false)
			require.NoError(err, "Problem adding transaction %d to mempool: %v", jj, txn)

			txns = append(txns, txn)
		}
	}

	// Set the read-only view to update less frequently
	ReadOnlyUtxoViewRegenerationIntervalTxns = 1000
	defer func() {
		ReadOnlyUtxoViewRegenerationIntervalTxns = 1
	}()

	// Time how fast we can add transactions to a UtxoView
	{
		fmt.Println("woo")

		ff, err := os.Create("/tmp/block-processing-profile")
		require.NoError(err)
		pprof.StartCPUProfile(ff)

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		timeStart := time.Now()
		for _, tx := range txns {
			_, _, _, _, err := utxoView.ConnectTransaction(tx, tx.Hash(), 0, 1, false /*verifySignature*/, false /*ignoreUtxos*/)
			require.NoError(err)
		}
		//require.NoError(utxoView.FlushToDb())
		elapsedSecs := (time.Since(timeStart)).Seconds()
		fmt.Printf("UtxoView added %v txns in %v seconds with TPS: %v\n",
			len(txns), elapsedSecs,
			float64(len(txns))/float64((elapsedSecs)))

		pprof.StopCPUProfile()
	}

	// At this point we have some number of transactions. Clear the mempool and see how
	// long it takes to add them all to the mempool.
	newMP := NewDeSoMempool(mempool.bc, 0, /* rateLimitFeeRateNanosPerKB */
		0, /* minFeeRateNanosPerKB */
		"" /*blockCypherAPIKey*/, false,
		"" /*dataDir*/, "")
	mempool.resetPool(newMP)
	{
		timeStart := time.Now()
		for _, tx := range txns {
			mempoolTxsAdded, err := mempool.processTransaction(
				tx, true /*allowUnconnectedTxn*/, false /*rateLimit*/, 0, /*peerID*/
				false /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(mempoolTxsAdded))
		}
		elapsedSecs := (time.Since(timeStart)).Seconds()
		fmt.Printf("Mempool added %v txns in %v seconds with TPS: %v\n",
			len(txns), elapsedSecs,
			float64(len(txns))/float64((elapsedSecs)))

	}

	// Mine blocks until the mempool is empty.
	blocksMined := []*MsgDeSoBlock{}
	mempoolTxns, _, err := mempool.GetTransactionsOrderedByTimeAdded()
	require.NoError(err)
	for ii := 0; len(mempoolTxns) > 0; ii++ {
		finalBlock1, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		mempoolTxns, _, err = mempool.GetTransactionsOrderedByTimeAdded()
		require.NoError(err)
		blocksMined = append(blocksMined, finalBlock1)
		fmt.Printf("Block %v contains %v txns\n", ii, len(finalBlock1.Txns))
	}
	fmt.Println(len(blocksMined))

	// Apply the blocks to a new chain with timings
	{

		newChain, newParams, newDB := NewLowDifficultyBlockchain(t)
		_, _ = newParams, newDB
		timeStart := time.Now()
		for _, blockToConnect := range blocksMined {
			_, _, err := newChain.ProcessBlock(blockToConnect, true /*verifySignatures*/)
			require.NoError(err)
		}
		elapsedSecs := (time.Since(timeStart)).Seconds()
		fmt.Printf("Connected %v txns in %v seconds with TPS: %v\n",
			len(txns), elapsedSecs,
			float64(len(txns))/float64((elapsedSecs)))
	}
	t.Cleanup(func() {
		if !newMP.stopped {
			newMP.Stop()
		}
	})
}

// Increase numBlocksToMine to load test
func TestConnectBlocksLoadTest(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_, _ = mempool, db

	// Mine blocks until the mempool is empty.
	numBlocksToMine := 10
	blocksMined := []*MsgDeSoBlock{}
	for ii := 0; ii < numBlocksToMine; ii++ {
		finalBlock1, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		blocksMined = append(blocksMined, finalBlock1)
		fmt.Printf("Block %v contains %v txns\n", ii, len(finalBlock1.Txns))
		fmt.Println(len(blocksMined))
	}
	fmt.Println(len(blocksMined))

	// Apply the blocks to a new chain with timings
	{
		newChain, newParams, newDB := NewLowDifficultyBlockchain(t)
		_, _ = newParams, newDB
		ff, err := os.Create("/tmp/block-processing-profile")
		require.NoError(err)
		pprof.StartCPUProfile(ff)
		timeStart := time.Now()
		for _, blockToConnect := range blocksMined {
			_, _, err := newChain.ProcessBlock(blockToConnect, false /*verifySignatures*/)
			require.NoError(err)
		}
		elapsedSecs := (time.Since(timeStart)).Seconds()
		fmt.Printf("Connected %v blocks in %v seconds with blocks per second: %v\n",
			len(blocksMined), elapsedSecs,
			float64(len(blocksMined))/float64((elapsedSecs)))
		pprof.StopCPUProfile()
	}
}
