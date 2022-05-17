package lib

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/go-pg/pg/v10"
	"log"
	"math/big"
	"os"
	"testing"
	"time"

	chainlib "github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// go run transaction_util.go --manual_entropy_hex=0,1
	senderPkString      = "tBCKXFJEDSF7Thcc6BUBcB6kicE5qzmLbAtvFf9LfKSXN4LwFt36oX"
	senderPrivString    = "tbc31669t2YuZ2mi1VLtK6a17RXFPdsuBDcenPLc1eU1ZVRHF9Zv4"
	recipientPkString   = "tBCKXU8pf7nkn8M38sYJeAwiBP7HbSJWy9Zmn4sHNL6gA6ahkriymq"
	recipientPrivString = "tbc24UM432ikvtmyv4zus7HomtUYkxNg3B3HusSLghVxoQXKi9QjZ"

	moneyPkString   = "tBCKVUCQ9WxpVmNthS2PKfY1BCxG4GkWvXqDhQ4q3zLtiwKVUNMGYS"
	moneyPrivString = "tbc2yg6BS7we86H8WUF2xSAmnyJ1x63ZqXaiDkE2mostsxpfmCZiB"

	blockSignerSeed = "essence camp ghost remove document vault ladder swim pupil index apart ring"
	blockSignerPk   = "BC1YLiQ86kwXUy3nfK391xht7N72UmbFY6bGrUsds1A7QKZrs4jJsxo"
)

func TestProcessBlock(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	//hexBytes, _ := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	{
		hexBytes, err := hex.DecodeString("00000000e9a0b8435a2fc5e19952ceb3a2d5042fb87b6d5f180ea825f3a4cd65")
		assert.NoError(err)
		assert.Equal("000000000000000000000000000000000000000000000000000000011883b96c", fmt.Sprintf("%064x", *ExpectedWorkForBlockHash(CopyBytesIntoBlockHash(hexBytes))))

	}
	// Satoshi's genesis block hash.
	{
		hexBytes, err := hex.DecodeString("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
		assert.NoError(err)
		assert.Equal("000000000000000000000000000000000000000000000000000009e8770a5c23", fmt.Sprintf("%064x", *ExpectedWorkForBlockHash(CopyBytesIntoBlockHash(hexBytes))))
	}
	// A more serious block.
	{

		hexBytes, err := hex.DecodeString("00000000000000000000c4c7bfde307b37ca6e4234d636cdea3e443df2926fff")
		assert.NoError(err)
		assert.Equal(
			"000000000000000000000000000000000000000000014d0aa0d2497b13fcd703",
			fmt.Sprintf("%064x", *ExpectedWorkForBlockHash(CopyBytesIntoBlockHash(hexBytes))))
	}
	// Some annoying edge cases.
	{
		hexBytes, err := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
		assert.NoError(err)
		assert.Equal(
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			fmt.Sprintf("%064x", *ExpectedWorkForBlockHash(CopyBytesIntoBlockHash(hexBytes))))
	}
	{
		hexBytes, err := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
		assert.NoError(err)
		assert.Equal(
			"0000000000000000000000000000000000000000000000000000000000000000",
			fmt.Sprintf("%064x", *ExpectedWorkForBlockHash(CopyBytesIntoBlockHash(hexBytes))))
	}
	{
		hexBytes, err := hex.DecodeString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe")
		assert.NoError(err)
		assert.Equal(
			"0000000000000000000000000000000000000000000000000000000000000001",
			fmt.Sprintf("%064x", *ExpectedWorkForBlockHash(CopyBytesIntoBlockHash(hexBytes))))
	}
}

func _copyBlock(blk *MsgDeSoBlock) *MsgDeSoBlock {
	data, _ := blk.ToBytes(false)

	testBlock := NewMessage(MsgTypeBlock).(*MsgDeSoBlock)
	_ = testBlock.FromBytes(data)

	return testBlock
}

func getForkedChain(t *testing.T) (blockA1, blockA2, blockB1, blockB2,
	blockB3, blockB4, blockB5 *MsgDeSoBlock) {

	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	var err error
	{
		chain1, params, _ := NewLowDifficultyBlockchain()
		mempool1, miner1 := NewTestMiner(t, chain1, params, true /*isSender*/)
		_ = mempool1

		// Mine two blocks to give the sender some DeSo.
		blockA1, err = miner1.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool1)
		require.NoError(err)
		blockA2, err = miner1.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool1)
		require.NoError(err)
	}
	{
		chain1, params, _ := NewLowDifficultyBlockchain()
		mempool1, miner1 := NewTestMiner(t, chain1, params, true /*isSender*/)
		_ = mempool1

		// Mine two blocks to give the sender some DeSo.
		blockB1, err = miner1.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool1)
		require.NoError(err)
		blockB2, err = miner1.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool1)
		require.NoError(err)
		blockB3, err = miner1.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool1)
		require.NoError(err)
		blockB4, err = miner1.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool1)
		require.NoError(err)
		blockB5, err = miner1.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool1)
		require.NoError(err)
	}

	// The variables  are set above.
	return
}

func NewTestBlockchain() (*Blockchain, *DeSoParams, *badger.DB) {
	db, _ := GetTestBadgerDb()
	timesource := chainlib.NewMedianTime()

	// Set the number of txns per view regeneration to one while creating the txns
	ReadOnlyUtxoViewRegenerationIntervalTxns = 1

	// Set some special parameters for testing. If the blocks above are changed
	// these values should be updated to reflect the latest testnet values.
	paramsCopy := DeSoTestnetParams

	chain, err := NewBlockchain([]string{blockSignerPk}, 0, 0, &paramsCopy,
		timesource, db, nil, nil, nil, false)
	if err != nil {
		log.Fatal(err)
	}

	return chain, &paramsCopy, db
}

func NewLowDifficultyBlockchain() (
	*Blockchain, *DeSoParams, *badger.DB) {

	// Set the number of txns per view regeneration to one while creating the txns
	ReadOnlyUtxoViewRegenerationIntervalTxns = 1

	return NewLowDifficultyBlockchainWithParams(&DeSoTestnetParams)
}

func NewLowDifficultyBlockchainWithParams(params *DeSoParams) (
	*Blockchain, *DeSoParams, *badger.DB) {

	// Set the number of txns per view regeneration to one while creating the txns
	ReadOnlyUtxoViewRegenerationIntervalTxns = 1

	db, dbDir := GetTestBadgerDb()
	timesource := chainlib.NewMedianTime()
	var postgresDb *Postgres

	if len(os.Getenv("POSTGRES_URI")) > 0 {
		postgresDb = NewPostgres(pg.Connect(ParsePostgresURI(os.Getenv("POSTGRES_URI"))))
	}

	// Set some special parameters for testing. If the blocks above are changed
	// these values should be updated to reflect the latest testnet values.
	paramsCopy := *params
	paramsCopy.GenesisBlock = &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			Version:               0,
			PrevBlockHash:         mustDecodeHexBlockHash("0000000000000000000000000000000000000000000000000000000000000000"),
			TransactionMerkleRoot: mustDecodeHexBlockHash("097158f0d27e6d10565c4dc696c784652c3380e0ff8382d3599a4d18b782e965"),
			TstampSecs:            uint64(1560735050),
			Height:                uint64(0),
			Nonce:                 uint64(0),
			// No ExtraNonce is set in the genesis block
		},
		Txns: []*MsgDeSoTxn{
			{
				TxInputs:  []*DeSoInput{},
				TxOutputs: []*DeSoOutput{},
				TxnMeta: &BlockRewardMetadataa{
					ExtraData: []byte("They came here, to the new world. World 2.0, version 1776."),
				},
				// A signature is not required for BLOCK_REWARD transactions since they
				// don't spend anything.
			},
		},
	}
	paramsCopy.MinDifficultyTargetHex = "999999948931e5874cf66a74c0fda790dd8c7458243d400324511a4c71f54faa"
	paramsCopy.MinChainWorkHex = "0000000000000000000000000000000000000000000000000000000000000000"
	paramsCopy.MiningIterationsPerCycle = 500
	// Set maturity to 2 blocks so we can test spending on short chains. The
	// tests rely on the maturity equaling exactly two blocks (i.e. being
	// two times the time between blocks).
	paramsCopy.TimeBetweenBlocks = 2 * time.Second
	paramsCopy.BlockRewardMaturity = time.Second * 4
	paramsCopy.TimeBetweenDifficultyRetargets = 100 * time.Second
	paramsCopy.MaxDifficultyRetargetFactor = 2
	paramsCopy.SeedBalances = []*DeSoOutput{
		{
			PublicKey:   MustBase58CheckDecode(moneyPkString),
			AmountNanos: uint64(2000000 * NanosPerUnit),
		},
	}

	// Temporarily modify the seed balances to make a specific public
	// key have some DeSo
	snap, err, _ := NewSnapshot(db, dbDir, SnapshotBlockHeightPeriod, false, false, &paramsCopy, false)
	chain, err := NewBlockchain([]string{blockSignerPk}, 0, 0,
		&paramsCopy, timesource, db, postgresDb, nil, snap, false)
	if err != nil {
		log.Fatal(err)
	}

	return chain, &paramsCopy, db
}

func NewTestMiner(t *testing.T, chain *Blockchain, params *DeSoParams, isSender bool) (*DeSoMempool, *DeSoMiner) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	mempool := NewDeSoMempool(
		chain, 0, /* rateLimitFeeRateNanosPerKB */
		0 /* minFeeRateNanosPerKB */, "", true,
		"" /*dataDir*/, "")
	minerPubKeys := []string{}
	if isSender {
		minerPubKeys = append(minerPubKeys, senderPkString)
	} else {
		minerPubKeys = append(minerPubKeys, recipientPkString)
	}

	blockProducer, err := NewDeSoBlockProducer(
		0, 1,
		blockSignerSeed,
		mempool, chain,
		params, chain.postgres)
	require.NoError(err)

	newMiner, err := NewDeSoMiner(minerPubKeys, 1 /*numThreads*/, blockProducer, params)
	require.NoError(err)
	return mempool, newMiner
}

func _getBalance(t *testing.T, chain *Blockchain, mempool *DeSoMempool, pkStr string) uint64 {
	pkBytes, _, err := Base58CheckDecode(pkStr)
	require.NoError(t, err)

	utxoEntriesFound, err := chain.GetSpendableUtxosForPublicKey(pkBytes, mempool, nil)
	require.NoError(t, err)

	balanceForUserNanos := uint64(0)
	for _, utxoEntry := range utxoEntriesFound {
		balanceForUserNanos += utxoEntry.AmountNanos
	}

	utxoView, err := NewUtxoView(chain.db, chain.params, chain.postgres, chain.snapshot)
	require.NoError(t, err)
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUniversalView()
		require.NoError(t, err)
	}

	balanceNanos, err := utxoView.GetSpendableDeSoBalanceNanosForPublicKey(
		pkBytes, chain.headerTip().Height)
	require.NoError(t, err)

	// DO NOT REMOVE: This is used to test the similarity of UTXOs vs. the pubkey balance index.
	require.Equal(t, balanceForUserNanos, balanceNanos)

	return balanceForUserNanos
}

func _getCreatorCoinInfo(t *testing.T, chain *Blockchain, params *DeSoParams, pkStr string,
) (_desoLocked uint64, _coinsInCirculation uint64) {
	pkBytes, _, err := Base58CheckDecode(pkStr)
	require.NoError(t, err)

	utxoView, _ := NewUtxoView(chain.db, params, nil, chain.snapshot)

	// Profile fields
	creatorProfile := utxoView.GetProfileEntryForPublicKey(pkBytes)
	if creatorProfile == nil {
		return 0, 0
	}

	// Note that it's OK to cast creator coin to uint64 because we check for
	// overflow everywhere.
	return creatorProfile.CreatorCoinEntry.DeSoLockedNanos, creatorProfile.CreatorCoinEntry.CoinsInCirculationNanos.Uint64()
}

func _getBalanceWithView(t *testing.T, utxoView *UtxoView, pkStr string) uint64 {
	pkBytes, _, err := Base58CheckDecode(pkStr)
	require.NoError(t, err)

	utxoEntriesFound, err := utxoView.GetUnspentUtxoEntrysForPublicKey(pkBytes)
	require.NoError(t, err)

	totalBalanceNanos := uint64(0)
	for _, utxoEntry := range utxoEntriesFound {
		totalBalanceNanos += utxoEntry.AmountNanos
	}

	return totalBalanceNanos
}

func TestBasicTransferReorg(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain1, params, _ := NewLowDifficultyBlockchain()
	{
		mempool1, miner1 := NewTestMiner(t, chain1, params, true /*isSender*/)

		// Mine two blocks to give the sender some DeSo.
		_, err := miner1.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool1)
		require.NoError(err)
		_, err = miner1.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool1)
		require.NoError(err)

		// Have the sender send some DeSo to the recipient and have the
		// recipient send some back. Mine both of these transactions into
		// a block.
		{
			txn := _assembleBasicTransferTxnFullySigned(t, chain1, 17, 0,
				senderPkString, recipientPkString, senderPrivString, mempool1)
			_, err := mempool1.ProcessTransaction(txn, false /*allowUnconnectedTxn*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
			require.NoError(err)
		}
		{
			txn := _assembleBasicTransferTxnFullySigned(t, chain1, 4, 0,
				recipientPkString, senderPkString, recipientPrivString, mempool1)
			_, err := mempool1.ProcessTransaction(txn, false /*allowUnconnectedTxn*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
			require.NoError(err)
		}
		block, err := miner1.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool1)
		require.NoError(err)
		// block reward adds one txn.
		require.Equal(3, len(block.Txns))
		require.Equal(uint64(13), _getBalance(t, chain1, mempool1, recipientPkString))

		// Have the sender send a bit more DeSo over and mine that into a
		// block.
		{
			txn := _assembleBasicTransferTxnFullySigned(t, chain1, 2, 0,
				senderPkString, recipientPkString, senderPrivString, mempool1)
			_, err := mempool1.ProcessTransaction(txn, false /*allowUnconnectedTxn*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
			require.NoError(err)
		}
		block, err = miner1.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool1)
		require.NoError(err)
		// block reward adds one txn.
		require.Equal(2, len(block.Txns))
		require.Equal(uint64(15), _getBalance(t, chain1, mempool1, recipientPkString))

		// A transaction signed by the wrong private key should be rejected.
		{
			txn := _assembleBasicTransferTxnFullySigned(t, chain1, 2, 0,
				senderPkString, recipientPkString, recipientPrivString, mempool1)
			_, err := mempool1.ProcessTransaction(txn, false /*allowUnconnectedTxn*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
			require.Error(err)
			require.Contains(err.Error(), RuleErrorInvalidTransactionSignature)
		}

		// Have the recipient send some DeSo back and mine that into a block.
		{
			txn := _assembleBasicTransferTxnFullySigned(t, chain1, 8, 0,
				recipientPkString, senderPkString, recipientPrivString, mempool1)
			_, err := mempool1.ProcessTransaction(txn, false /*allowUnconnectedTxn*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
			require.NoError(err)
		}
		block, err = miner1.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool1)
		require.NoError(err)
		// block reward adds one txn.
		require.Equal(2, len(block.Txns))

		// Recipient should have exactly 7 DeSo after all this.
		require.Equal(uint64(7), _getBalance(t, chain1, mempool1, recipientPkString))
	}

	// Create a second test chain so we can mine a fork.
	// Mine enough blocks to create a fork. Throw in a transaction
	// from the sender to the recipient right before the third block
	// just to make things interesting.
	chain2, _, _ := NewLowDifficultyBlockchain()
	forkBlocks := []*MsgDeSoBlock{}
	{
		mempool2, miner2 := NewTestMiner(t, chain2, params, true /*isSender*/)

		// Mine two blocks to give the sender some DeSo.
		block, err := miner2.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool2)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)
		block, err = miner2.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool2)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)

		// Have the sender send some DeSo to the recipient and have the
		// recipient send some back. Mine both of these transactions into
		// a block.
		{
			txn := _assembleBasicTransferTxnFullySigned(t, chain2, 7, 0,
				senderPkString, recipientPkString, senderPrivString, mempool2)
			_, err := mempool2.ProcessTransaction(txn, false /*allowUnconnectedTxn*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
			require.NoError(err)
		}
		{
			txn := _assembleBasicTransferTxnFullySigned(t, chain2, 2, 0,
				recipientPkString, senderPkString, recipientPrivString, mempool2)
			_, err := mempool2.ProcessTransaction(txn, false /*allowUnconnectedTxn*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
			require.NoError(err)
		}
		block, err = miner2.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool2)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)
		// block reward adds one txn.
		require.Equal(3, len(block.Txns))
		require.Equal(uint64(5), _getBalance(t, chain2, mempool2, recipientPkString))

		// Mine several more blocks so we can make the fork dominant.
		block, err = miner2.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool2)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)
		block, err = miner2.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool2)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)
		block, err = miner2.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool2)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)
		block, err = miner2.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool2)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)
		block, err = miner2.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool2)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)
	}

	// Process all of the fork blocks on the original chain to make it
	// experience a reorg.
	for _, forkBlock := range forkBlocks {
		_, _, err := chain1.ProcessBlock(forkBlock, true /*verifySignatures*/)
		require.NoError(err)
	}

	// Require that the tip of the first chain is now the same as the last
	// fork block.
	lastForkBlockHash, _ := forkBlocks[len(forkBlocks)-1].Hash()
	require.Equal(*lastForkBlockHash, *chain1.blockTip().Hash)

	// After the reorg, all of the transactions should have been undone
	// expcept the single spend from the sender to the recipient that
	/// occurred in the fork. As such the fork chain's balance should now
	// reflect the updated balance.
	require.Equal(uint64(5), _getBalance(t, chain1, nil, recipientPkString))
}

func TestProcessBlockConnectBlocks(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	var blockA1 *MsgDeSoBlock
	{
		chain1, params, _ := NewLowDifficultyBlockchain()
		mempool1, miner1 := NewTestMiner(t, chain1, params, true /*isSender*/)
		_ = mempool1

		// Mine two blocks to give the sender some DeSo.
		var err error
		blockA1, err = miner1.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool1)
		require.NoError(err)
	}

	chain, _, _ := NewLowDifficultyBlockchain()
	_shouldConnectBlock(blockA1, t, chain)
}

func _shouldConnectBlock(blk *MsgDeSoBlock, t *testing.T, chain *Blockchain) {
	require := require.New(t)

	blockHash, _ := blk.Hash()

	verifySignatures := true
	isMainChain, isOrphan, err := chain.ProcessBlock(blk, verifySignatures)
	require.NoError(err)
	require.Falsef(isOrphan, "Block %v should not be an orphan", blockHash)
	require.Truef(isMainChain, "Block %v should be on the main chain", blockHash)

	// The header tip and the block tip should now be equal to this block.
	require.Equal(*blockHash, *chain.headerTip().Hash)
	require.Equal(*blockHash, *chain.blockTip().Hash)
}

func TestSeedBalancesTest(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	_, _ = assert, require

	chain, params, db := NewTestBlockchain()
	for _, seedBalance := range params.SeedBalances {
		require.Equal(int64(482), int64(GetUtxoNumEntries(db, chain.snapshot)))
		foundUtxos, err := chain.GetSpendableUtxosForPublicKey(seedBalance.PublicKey, nil, nil)
		require.NoError(err)
		require.Equal(int64(1), int64(len(foundUtxos)))
		require.Equal(int64(seedBalance.AmountNanos), int64(foundUtxos[0].AmountNanos))
	}
}

func init() {
	// Set up logging.
	flag.Set("alsologtostderr", "true")
	glog.CopyStandardLogTo("INFO")
}

func TestProcessHeaderskReorgBlocks(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	blockA1, blockA2, blockB1, blockB2, blockB3, _, _ := getForkedChain(t)

	chain, _, db := NewLowDifficultyBlockchain()

	{
		// These should connect without issue.
		fmt.Println("Connecting header A1")
		// We should start with one UTXO since there's a founder reward.
		require.Equal(uint64(1), GetUtxoNumEntries(db, chain.snapshot))
		headerHash, err := blockA1.Header.Hash()
		require.NoError(err)
		isMainChain, isOrphan, err := chain.ProcessHeader(blockA1.Header, headerHash)
		require.NoError(err)
		require.True(isMainChain)
		require.False(isOrphan)
		// Make sure the tip lines up.
		currentHash, err := blockA1.Hash()
		require.NoError(err)
		require.Equal(*currentHash, *(chain.headerTip().Hash))
	}
	{
		// These should connect without issue.
		fmt.Println("Connecting header A2")
		// We should start with one UTXO since there's a founder reward.
		require.Equal(uint64(1), GetUtxoNumEntries(db, chain.snapshot))
		headerHash, err := blockA2.Header.Hash()
		require.NoError(err)
		isMainChain, isOrphan, err := chain.ProcessHeader(blockA2.Header, headerHash)
		require.NoError(err)
		require.True(isMainChain)
		require.False(isOrphan)
		// Make sure the tip lines up.
		currentHash, err := blockA2.Hash()
		require.NoError(err)
		require.Equal(*currentHash, *(chain.headerTip().Hash))
	}
	{
		// These should connect without issue.
		fmt.Println("Connecting header B1")
		// We should start with one UTXO since there's a founder reward.
		require.Equal(uint64(1), GetUtxoNumEntries(db, chain.snapshot))
		headerHash, err := blockB1.Header.Hash()
		require.NoError(err)
		isMainChain, isOrphan, err := chain.ProcessHeader(blockB1.Header, headerHash)
		require.NoError(err)
		// Should not be main chain yet
		require.False(isMainChain)
		require.False(isOrphan)
		// Make sure the tip lines up.
		currentHash, err := blockA2.Hash()
		require.NoError(err)
		require.Equal(*currentHash, *(chain.headerTip().Hash))
	}
	{
		// These should connect without issue.
		fmt.Println("Connecting header B2")
		// We should start with one UTXO since there's a founder reward.
		require.Equal(uint64(1), GetUtxoNumEntries(db, chain.snapshot))
		headerHash, err := blockB2.Header.Hash()
		require.NoError(err)
		isMainChain, isOrphan, err := chain.ProcessHeader(blockB2.Header, headerHash)
		require.NoError(err)
		// Should not be main chain yet
		require.False(isMainChain)
		require.False(isOrphan)
		// Make sure the tip lines up.
		currentHash, err := blockA2.Hash()
		require.NoError(err)
		require.Equal(*currentHash, *(chain.headerTip().Hash))
	}
	{
		// These should connect without issue.
		fmt.Println("Connecting header B3")
		// We should start with one UTXO since there's a founder reward.
		require.Equal(uint64(1), GetUtxoNumEntries(db, chain.snapshot))
		headerHash, err := blockB3.Header.Hash()
		require.NoError(err)
		isMainChain, isOrphan, err := chain.ProcessHeader(blockB3.Header, headerHash)
		require.NoError(err)
		// Should not be main chain yet
		require.True(isMainChain)
		require.False(isOrphan)
		// Make sure the tip lines up.
		currentHash, err := blockB3.Hash()
		require.NoError(err)
		require.Equal(*currentHash, *(chain.headerTip().Hash))
	}
}

func TestProcessBlockReorgBlocks(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	blockA1, blockA2, blockB1, blockB2, blockB3, _, _ := getForkedChain(t)

	chain, _, db := NewLowDifficultyBlockchain()

	{
		// These should connect without issue.
		fmt.Println("Connecting block a1")
		// We should start with one UTXO since there's a founder reward.
		require.Equal(uint64(1), GetUtxoNumEntries(db, chain.snapshot))
		_shouldConnectBlock(blockA1, t, chain)

		// Make sure the tip lines up.
		currentHash, err := blockA1.Hash()
		require.NoError(err)
		require.Equal(*currentHash, *(chain.headerTip().Hash))
		require.Equal(*currentHash, *(chain.blockTip().Hash))
	}

	{
		fmt.Println("Connecting block a2")
		require.Equal(uint64(2), GetUtxoNumEntries(db, chain.snapshot))
		_shouldConnectBlock(blockA2, t, chain)

		// Make sure the tip lines up.
		currentHash, err := blockA2.Hash()
		require.NoError(err)
		require.Equal(*currentHash, *(chain.headerTip().Hash))
		require.Equal(*currentHash, *(chain.blockTip().Hash))
	}

	verifySignatures := true
	{
		// These should not be on the main chain.
		// Block b1
		fmt.Println("Connecting block b1")
		require.Equal(uint64(3), GetUtxoNumEntries(db, chain.snapshot))
		isMainChain, isOrphan, err := chain.ProcessBlock(blockB1, verifySignatures)
		require.NoError(err)
		require.Falsef(isOrphan, "Block b1 should not be an orphan")
		require.Falsef(isMainChain, "Block b1 should not be on the main chain")

		// Make sure the tip lines up.
		currentHash, err := blockA2.Hash()
		require.NoError(err)
		require.Equal(*currentHash, *(chain.headerTip().Hash))
		require.Equal(*currentHash, *(chain.blockTip().Hash))
	}

	{
		// Block b2
		fmt.Println("Connecting block b2")
		require.Equal(uint64(3), GetUtxoNumEntries(db, chain.snapshot))
		isMainChain, isOrphan, err := chain.ProcessBlock(blockB2, verifySignatures)
		require.NoError(err)
		require.Falsef(isOrphan, "Block b2 should not be an orphan")
		require.Falsef(isMainChain, "Block b2 should not be on the main chain")

		// Make sure the tip lines up.
		currentHash, err := blockA2.Hash()
		require.NoError(err)
		require.Equal(*currentHash, *(chain.headerTip().Hash))
		require.Equal(*currentHash, *(chain.blockTip().Hash))
	}

	{
		// This should cause the fork to take over, changing the main chain.
		fmt.Println("Connecting block b3")
		require.Equal(uint64(3), GetUtxoNumEntries(db, chain.snapshot))
		_shouldConnectBlock(blockB3, t, chain)
		fmt.Println("b3 is connected")
		require.Equal(uint64(4), GetUtxoNumEntries(db, chain.snapshot))

		// Make sure the tip lines up.
		currentHash, err := blockB3.Hash()
		require.NoError(err)
		require.Equal(*currentHash, *(chain.headerTip().Hash))
		require.Equal(*currentHash, *(chain.blockTip().Hash))
	}
}

func _assembleBasicTransferTxnNoInputs(t *testing.T, amountNanos uint64) *MsgDeSoTxn {
	require := require.New(t)

	// manual_entropy_hex=0
	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)

	// manual_entropy_hex=1
	recipientPkBytes, _, err := Base58CheckDecode(recipientPkString)
	require.NoError(err)

	// Assemble the transaction so that inputs can be found and fees can
	// be computed.
	txnOutputs := []*DeSoOutput{}
	txnOutputs = append(txnOutputs, &DeSoOutput{
		PublicKey:   recipientPkBytes,
		AmountNanos: amountNanos,
	})
	txn := &MsgDeSoTxn{
		// The inputs will be set below.
		TxInputs:  []*DeSoInput{},
		TxOutputs: txnOutputs,
		PublicKey: senderPkBytes,
		TxnMeta:   &BasicTransferMetadata{},
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	return txn
}

func _signTxn(t *testing.T, txn *MsgDeSoTxn, privKeyStrArg string) {
	require := require.New(t)

	privKeyBytes, _, err := Base58CheckDecode(privKeyStrArg)
	require.NoError(err)
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
	txnSignature, err := txn.Sign(privKey)
	require.NoError(err)
	txn.Signature = txnSignature
}

// Signs the transaction with a derived key. Transaction ExtraData contains the derived
// public key, so that _verifySignature() knows transaction wasn't signed by the owner.
func _signTxnWithDerivedKey(t *testing.T, txn *MsgDeSoTxn, privKeyStrArg string) {
	require := require.New(t)

	privKeyBytes, _, err := Base58CheckDecode(privKeyStrArg)
	require.NoError(err)
	privateKey, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
	if txn.ExtraData == nil {
		txn.ExtraData = make(map[string][]byte)
	}
	txn.ExtraData[DerivedPublicKey] = publicKey.SerializeCompressed()
	txnSignature, err := txn.Sign(privateKey)
	require.NoError(err)

	txn.Signature = txnSignature
}

func _assembleBasicTransferTxnFullySigned(t *testing.T, chain *Blockchain,
	amountNanos uint64, feeRateNanosPerKB uint64, senderPkStrArg string,
	recipientPkStrArg string, privKeyStrArg string,
	mempool *DeSoMempool) *MsgDeSoTxn {

	require := require.New(t)

	// go run transaction_util.go --operation_type=generate_keys --manual_entropy_hex=0
	senderPkBytes, _, err := Base58CheckDecode(senderPkStrArg)
	require.NoError(err)

	// go run transaction_util.go --operation_type=generate_keys --manual_entropy_hex=1
	recipientPkBytes, _, err := Base58CheckDecode(recipientPkStrArg)
	require.NoError(err)

	// Assemble the transaction so that inputs can be found and fees can
	// be computed.
	txnOutputs := []*DeSoOutput{}
	txnOutputs = append(txnOutputs, &DeSoOutput{
		PublicKey:   recipientPkBytes,
		AmountNanos: amountNanos,
	})
	txn := &MsgDeSoTxn{
		// The inputs will be set below.
		TxInputs:  []*DeSoInput{},
		TxOutputs: txnOutputs,
		PublicKey: senderPkBytes,
		TxnMeta:   &BasicTransferMetadata{},
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	totalInputAdded, spendAmount, totalChangeAdded, fee, err :=
		chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, mempool)
	require.NoError(err)
	require.Equal(totalInputAdded, spendAmount+totalChangeAdded+fee)

	_signTxn(t, txn, privKeyStrArg)

	return txn
}

func TestAddInputsAndChangeToTransaction(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, _, db := NewLowDifficultyBlockchain()
	_ = db

	_, _, blockB1, blockB2, blockB3, _, _ := getForkedChain(t)

	// Spending nothing should be OK. It shouldn't add anything to the transaction.
	{
		txn := _assembleBasicTransferTxnNoInputs(t, 0)
		feeRateNanosPerKB := uint64(0)

		totalInputAdded, spendAmount, totalChangeAdded, fee, err :=
			chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
		require.NoError(err)
		require.Equal(0, len(txn.TxInputs))
		require.Equal(1, len(txn.TxOutputs))
		require.Equal(totalInputAdded, uint64(0))
		require.Equal(spendAmount, uint64(0))
		require.Equal(totalChangeAdded, uint64(0))
		require.Equal(fee, uint64(0))
	}

	// Spending a nonzero amount should fail before we have mined a block
	// reward for ourselves.
	{
		txn := _assembleBasicTransferTxnNoInputs(t, 1)
		feeRateNanosPerKB := uint64(0)

		_, _, _, _, err :=
			chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
		require.Error(err)
	}

	// Nonzero/high fee should also cause an error if we have no money.
	{
		txn := _assembleBasicTransferTxnNoInputs(t, 0)
		feeRateNanosPerKB := uint64(1000)

		_, _, _, _, err :=
			chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
		require.Error(err)
	}

	// Save the block reward in the first block to use it for testing.
	firstBlockReward := CalcBlockRewardNanos(1)

	// Connect a block. The sender address should have mined some DeSo but
	// it should be unspendable until the block after this one. See
	// BlockRewardMaturity.
	_shouldConnectBlock(blockB1, t, chain)

	// Verify that spending a nonzero amount fails after the first block.
	{
		txn := _assembleBasicTransferTxnNoInputs(t, 1)
		feeRateNanosPerKB := uint64(0)

		_, _, _, _, err :=
			chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
		require.Error(err)
	}

	_shouldConnectBlock(blockB2, t, chain)

	// Verify that spending a nonzero amount passes after the second block
	// since at this point it is presumed the transaction will be mined
	// into the third block at which point the block reward shouild be
	// mature.

	// Verify a moderate spend with a moderate feerate works.
	{
		testSpend := firstBlockReward / 2
		txn := _assembleBasicTransferTxnNoInputs(t, testSpend)
		feeRateNanosPerKB := uint64(testSpend)

		totalInputAdded, spendAmount, totalChangeAdded, fee, err :=
			chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
		require.NoError(err)
		require.Equal(1, len(txn.TxInputs))
		require.Equal(2, len(txn.TxOutputs))
		require.Equal(spendAmount, uint64(testSpend))
		require.Greater(fee, uint64(0))
		require.Equal(uint64(firstBlockReward), totalInputAdded)
		require.Equal(totalInputAdded, spendAmount+totalChangeAdded+fee)
	}

	// Verify spending more than a block reward fails.
	{
		testSpend := firstBlockReward + 1
		txn := _assembleBasicTransferTxnNoInputs(t, testSpend)
		feeRateNanosPerKB := uint64(0)

		_, _, _, _, err :=
			chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
		require.Error(err)
	}

	_shouldConnectBlock(blockB3, t, chain)

	// Verify spending more than the first block reward passes after the
	// next block.
	{
		testSpend := firstBlockReward + 1
		txn := _assembleBasicTransferTxnNoInputs(t, testSpend)
		feeRateNanosPerKB := uint64(0)

		_, _, _, _, err :=
			chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
		require.NoError(err)
	}
}

func TestValidateBasicTransfer(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, _, db := NewLowDifficultyBlockchain()
	_ = db

	_, _, blockB1, blockB2, _, _, _ := getForkedChain(t)

	// Save the block reward in the first block to use it for testing.
	firstBlockReward := CalcBlockRewardNanos(1)

	// Connect a block. The sender address should have mined some DeSo but
	// it should be unspendable until the block after this one. See
	// BlockRewardMaturity.
	_shouldConnectBlock(blockB1, t, chain)
	_shouldConnectBlock(blockB2, t, chain)

	// Verify that a transaction spending a nonzero amount passes validation
	// after the second block due to the block reward having matured.
	{
		spendAmount := firstBlockReward / 2
		feeRateNanosPerKB := firstBlockReward
		txn := _assembleBasicTransferTxnFullySigned(t, chain, spendAmount, feeRateNanosPerKB,
			senderPkString, recipientPkString, senderPrivString, nil)
		err := chain.ValidateTransaction(txn, chain.blockTip().Height+1,
			true /*verifySignatures*/, nil)
		require.NoError(err)
	}

	// Verify that a transaction spending more than its input is shot down.
	{
		spendAmount := firstBlockReward / 2
		feeRateNanosPerKB := firstBlockReward
		txn := _assembleBasicTransferTxnFullySigned(t, chain, spendAmount, feeRateNanosPerKB,
			senderPkString, recipientPkString, senderPrivString, nil)
		{
			senderPkBytes, _, err := Base58CheckDecode(senderPkString)
			require.NoError(err)
			txn.TxOutputs = append(txn.TxOutputs, &DeSoOutput{
				PublicKey: senderPkBytes,
				// Guaranteed to be more than we're allowed to spend.
				AmountNanos: firstBlockReward,
			})
			// Re-sign the transaction.
			_signTxn(t, txn, senderPrivString)
		}

		err := chain.ValidateTransaction(txn, chain.blockTip().Height+1, true, nil)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorTxnOutputExceedsInput)
	}

	// Verify that a transaction spending an immature block reward is shot down.
	{
		spendAmount := firstBlockReward
		feeRateNanosPerKB := uint64(0)
		txn := _assembleBasicTransferTxnFullySigned(t, chain, spendAmount, feeRateNanosPerKB,
			senderPkString, recipientPkString, senderPrivString, nil)
		// Try and spend the block reward from block B2, which should not have matured
		// yet.
		b2RewardHash := blockB2.Txns[0].Hash()
		require.NotNil(b2RewardHash)
		txn.TxInputs = append(txn.TxInputs, &DeSoInput{
			TxID:  *b2RewardHash,
			Index: 0,
		})
		// Re-sign the transaction.
		_signTxn(t, txn, senderPrivString)
		err := chain.ValidateTransaction(txn, chain.blockTip().Height+1, true, nil)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInputSpendsImmatureBlockReward)
	}
}

func TestComputeMerkle(t *testing.T) {
	//assert := assert.New(t)
	//require := require.New(t)
	//_ = assert
	//_ = require

	//blk := _copyBlock(expectedBlock)
	//merkleRoot1, _, err := ComputeMerkleRoot(blk.Txns)
	//require.NoError(err)

	//blk.Header.Nonce[0] = 0x00
	//merkleRoot2, _, err := ComputeMerkleRoot(blk.Txns)
	//require.NoError(err)
	//assert.Equal(merkleRoot1, merkleRoot2)

	//oldSigVal := blk.Txns[1].Signature[5]
	//blk.Txns[1].Signature[5] = 0x00
	//merkleRoot3, _, err := ComputeMerkleRoot(blk.Txns)
	//require.NoError(err)
	//assert.NotEqual(merkleRoot1, merkleRoot3)

	//blk.Txns[1].Signature[5] = oldSigVal
	//merkleRoot4, _, err := ComputeMerkleRoot(blk.Txns)
	//require.NoError(err)
	//assert.Equal(merkleRoot1, merkleRoot4)
}

func TestCalcNextDifficultyTargetHalvingDoublingHitLimit(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	fakeParams := &DeSoParams{
		MinDifficultyTargetHex:         hex.EncodeToString(BigintToHash(big.NewInt(100000))[:]),
		TimeBetweenDifficultyRetargets: 6 * time.Second,
		TimeBetweenBlocks:              2 * time.Second,
		MaxDifficultyRetargetFactor:    2,
	}

	nodes := []*BlockNode{}
	diffsAsInts := []int64{}
	for ii := 0; ii < 13; ii++ {
		var lastNode *BlockNode
		if ii > 0 {
			lastNode = nodes[ii-1]
		}
		nextDiff, err := CalcNextDifficultyTarget(lastNode, HeaderVersion0, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgDeSoHeader{
				// Blocks generating every 1 second, which is 2x too fast.
				TstampSecs: uint64(ii),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		50000,
		50000,
		50000,
		25000,
		25000,
		25000,
	}, diffsAsInts)

	diffsAsInts = []int64{}
	for ii := 13; ii < 30; ii++ {
		lastNode := nodes[ii-1]
		nextDiff, err := CalcNextDifficultyTarget(lastNode, HeaderVersion0, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgDeSoHeader{
				// Blocks generating every 4 second, which is 2x too slow.
				TstampSecs: uint64(ii * 4),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		12500,
		12500,
		12500,
		25000,
		25000,
		25000,
		50000,
		50000,
		50000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
	}, diffsAsInts)
}

func TestCalcNextDifficultyTargetHittingLimitsSlow(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	fakeParams := &DeSoParams{
		MinDifficultyTargetHex:         hex.EncodeToString(BigintToHash(big.NewInt(100000))[:]),
		TimeBetweenDifficultyRetargets: 6 * time.Second,
		TimeBetweenBlocks:              2 * time.Second,
		MaxDifficultyRetargetFactor:    2,
	}

	nodes := []*BlockNode{}
	diffsAsInts := []int64{}
	for ii := 0; ii < 13; ii++ {
		var lastNode *BlockNode
		if ii > 0 {
			lastNode = nodes[ii-1]
		}
		nextDiff, err := CalcNextDifficultyTarget(lastNode, HeaderVersion0, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgDeSoHeader{
				// Blocks generating every 1 second, which is 2x too fast.
				TstampSecs: uint64(ii),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		50000,
		50000,
		50000,
		25000,
		25000,
		25000,
	}, diffsAsInts)

	diffsAsInts = []int64{}
	for ii := 13; ii < 30; ii++ {
		lastNode := nodes[ii-1]
		nextDiff, err := CalcNextDifficultyTarget(lastNode, HeaderVersion0, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgDeSoHeader{
				// Blocks generating every 8 second, which is >2x too slow.
				TstampSecs: uint64(ii * 4),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		12500,
		12500,
		12500,
		25000,
		25000,
		25000,
		50000,
		50000,
		50000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
	}, diffsAsInts)
}

func TestCalcNextDifficultyTargetHittingLimitsFast(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	fakeParams := &DeSoParams{
		MinDifficultyTargetHex:         hex.EncodeToString(BigintToHash(big.NewInt(100000))[:]),
		TimeBetweenDifficultyRetargets: 6 * time.Second,
		TimeBetweenBlocks:              2 * time.Second,
		MaxDifficultyRetargetFactor:    2,
	}

	nodes := []*BlockNode{}
	diffsAsInts := []int64{}
	for ii := 0; ii < 13; ii++ {
		var lastNode *BlockNode
		if ii > 0 {
			lastNode = nodes[ii-1]
		}
		nextDiff, err := CalcNextDifficultyTarget(lastNode, HeaderVersion0, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgDeSoHeader{
				// Blocks generating all at once.
				TstampSecs: uint64(0),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		50000,
		50000,
		50000,
		25000,
		25000,
		25000,
	}, diffsAsInts)
}

func TestCalcNextDifficultyTargetJustRight(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	fakeParams := &DeSoParams{
		MinDifficultyTargetHex:         hex.EncodeToString(BigintToHash(big.NewInt(100000))[:]),
		TimeBetweenDifficultyRetargets: 6 * time.Second,
		TimeBetweenBlocks:              2 * time.Second,
		MaxDifficultyRetargetFactor:    3,
	}

	nodes := []*BlockNode{}
	diffsAsInts := []int64{}
	for ii := 0; ii < 13; ii++ {
		var lastNode *BlockNode
		if ii > 0 {
			lastNode = nodes[ii-1]
		}
		nextDiff, err := CalcNextDifficultyTarget(lastNode, HeaderVersion0, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgDeSoHeader{
				// Blocks generating every 2 second, which is under the limit.
				TstampSecs: uint64(ii * 2),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
	}, diffsAsInts)
}

func TestCalcNextDifficultyTargetSlightlyOff(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	fakeParams := &DeSoParams{
		MinDifficultyTargetHex:         hex.EncodeToString(BigintToHash(big.NewInt(100000))[:]),
		TimeBetweenDifficultyRetargets: 6 * time.Second,
		TimeBetweenBlocks:              2 * time.Second,
		MaxDifficultyRetargetFactor:    2,
	}

	nodes := []*BlockNode{}
	diffsAsInts := []int64{}
	for ii := 0; ii < 13; ii++ {
		var lastNode *BlockNode
		if ii > 0 {
			lastNode = nodes[ii-1]
		}
		nextDiff, err := CalcNextDifficultyTarget(lastNode, HeaderVersion0, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgDeSoHeader{
				// Blocks generating every 1 second, which is 2x too fast.
				TstampSecs: uint64(ii),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		50000,
		50000,
		50000,
		25000,
		25000,
		25000,
	}, diffsAsInts)

	diffsAsInts = []int64{}
	for ii := 13; ii < 34; ii++ {
		lastNode := nodes[ii-1]
		nextDiff, err := CalcNextDifficultyTarget(lastNode, HeaderVersion0, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgDeSoHeader{
				// Blocks generating every 3 seconds, which is slow but under the limit.
				TstampSecs: uint64(float32(ii) * 3),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		12500,
		12500,
		12500,
		25000,
		25000,
		25000,
		37500,
		37500,
		37500,
		56250,
		56250,
		56250,
		84375,
		84375,
		84375,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
	}, diffsAsInts)
}

func _testMerkleRoot(t *testing.T, shouldFail bool, blk *MsgDeSoBlock) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	computedMerkle, _, err := ComputeMerkleRoot(blk.Txns)
	require.NoError(err)
	if shouldFail {
		require.NotEqual(blk.Header.TransactionMerkleRoot, computedMerkle)
	} else {
		require.Equal(blk.Header.TransactionMerkleRoot, computedMerkle)
	}
}

func TestBadMerkleRoot(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	// Grab some block hex by running miner.go at v=2 and use test_scratch.go
	// to perturb the merkle root to mess it up.
	blockA1, _, _, _, _, _, _ := getForkedChain(t)
	_testMerkleRoot(t, false /*shouldFail*/, blockA1)
	blockA1.Header.TransactionMerkleRoot = &BlockHash{}
	_testMerkleRoot(t, true /*shouldFail*/, blockA1)
}

func TestBadBlockSignature(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	chain, params, db := NewLowDifficultyBlockchainWithParams(&DeSoTestnetParams)

	// Change the trusted public keys expected by the blockchain.
	chain.trustedBlockProducerPublicKeys = make(map[PkMapKey]bool)
	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)
	chain.trustedBlockProducerPublicKeys[MakePkMapKey(senderPkBytes)] = true

	// The "blockSignerPk" does not match "senderPk" so processing the block will fail.
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	finalBlock1, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorBlockProducerPublicKeyNotInWhitelist)

	// Since MineAndProcesssSingleBlock returns a valid block above, we can play with its
	// signature and re-process the block to see what happens.
	blockProducerInfoCopy := &BlockProducerInfo{Signature: &btcec.Signature{}}
	blockProducerInfoCopy.PublicKey = append([]byte{}, finalBlock1.BlockProducerInfo.PublicKey...)
	*blockProducerInfoCopy.Signature = *finalBlock1.BlockProducerInfo.Signature

	// A bad signature with the right public key should fail.
	finalBlock1.BlockProducerInfo.PublicKey = senderPkBytes
	_, _, err = chain.ProcessBlock(finalBlock1, true)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorInvalidBlockProducerSIgnature)

	// A signature that's outright missing should fail
	blockSignerPkBytes, _, err := Base58CheckDecode(blockSignerPk)
	require.NoError(err)
	finalBlock1.BlockProducerInfo.PublicKey = blockSignerPkBytes
	finalBlock1.BlockProducerInfo.Signature = nil
	_, _, err = chain.ProcessBlock(finalBlock1, true)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorMissingBlockProducerSignature)

	// If all the BlockProducerInfo is missing, things should fail
	finalBlock1.BlockProducerInfo = nil
	_, _, err = chain.ProcessBlock(finalBlock1, true)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorMissingBlockProducerSignature)

	// Now let's add blockSignerPK to the map of trusted keys and confirm that the block processes.
	chain.trustedBlockProducerPublicKeys[MakePkMapKey(blockSignerPkBytes)] = true
	finalBlock1.BlockProducerInfo = blockProducerInfoCopy
	_, _, err = chain.ProcessBlock(finalBlock1, true)
	require.NoError(err)

	_, _ = finalBlock1, db
}

func TestForbiddenBlockSignaturePubKey(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	chain, params, _ := NewLowDifficultyBlockchainWithParams(&DeSoTestnetParams)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Make the senderPk a paramUpdater for this test
	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	params.ParamUpdaterPublicKeys[MakePkMapKey(senderPkBytes)] = true

	// Mine a few blocks to give the senderPkString some money.
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	// Ban the block signer public key.
	blockSignerPkBytes, _, err := Base58CheckDecode(blockSignerPk)
	require.NoError(err)
	txn, _, _, _, err := chain.CreateUpdateGlobalParamsTxn(
		senderPkBytes, -1, -1, -1, -1, -1, blockSignerPkBytes, 100 /*feeRateNanosPerKB*/, nil, []*DeSoOutput{})
	require.NoError(err)

	// Mine a few blocks to give the senderPkString some money.
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, senderPrivString)

	// Process the signed transaction.
	txDescsAdded, err := mempool.processTransaction(
		txn, true /*allowOrphan*/, true /*rateLimit*/, 0, /*peerID*/
		true /*verifySignatures*/)
	require.NoError(err)
	require.Equal(1, len(txDescsAdded))

	// Make sure that the forbidden pub key made it into the mempool properly.
	_, entryExists := mempool.universalUtxoView.ForbiddenPubKeyToForbiddenPubKeyEntry[MakePkMapKey(blockSignerPkBytes)]
	require.True(entryExists)

	// Mine the transaction.
	forbiddenPubKeyBlock, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	require.Equal(2, len(forbiddenPubKeyBlock.Txns))

	// Now mining a block should fail now that the block signer pub key is forbidden.
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorForbiddenBlockProducerPublicKey)
}
