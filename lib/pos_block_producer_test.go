package lib

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/stretchr/testify/require"
	"math"
	"math/rand"
	"testing"
	"time"
)

func TestCreateBlockTemplate(t *testing.T) {
	require := require.New(t)
	seed := int64(887)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()
	feeMin := globalParams.MinimumNetworkFeeNanosPerKB
	feeMax := uint64(2000)
	passingTransactions := 50
	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)

	params, db := _posTestBlockchainSetupWithBalances(t, 200000, 200000)
	params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 1
	latestBlockView, err := NewUtxoView(db, params, nil, nil)
	require.NoError(err)
	dir := _dbDirSetup(t)

	mempool := NewPosMempool(params, globalParams, latestBlockView, 2, dir, false)
	require.NoError(mempool.Start())
	defer mempool.Stop()
	require.True(mempool.IsRunning())

	// Add a bunch of passing transactions to the mempool that we'll use to produce a block.
	passingTxns := []*MsgDeSoTxn{}
	totalUtilityFee := uint64(0)
	for ii := 0; ii < passingTransactions; ii++ {
		txn := _generateTestTxn(t, rand, feeMin, feeMax, m0PubBytes, m0Priv, 100, 20)
		passingTxns = append(passingTxns, txn)
		_, utilityFee := computeBMF(txn.TxnFeeNanos)
		totalUtilityFee += utilityFee
		_wrappedPosMempoolAddTransaction(t, mempool, txn)
	}

	priv, err := bls.NewPrivateKey()
	require.NoError(err)
	pub := priv.PublicKey()
	seedHash := &RandomSeedHash{}
	_, err = seedHash.FromBytes(Sha256DoubleHash([]byte("seed")).ToBytes())
	require.NoError(err)
	m0Pk := NewPublicKey(m0PubBytes)
	pbp := NewPosBlockProducer(mempool, params, m0Pk, pub)

	blockTemplate, err := pbp.createBlockTemplate(latestBlockView, 3, 10, seedHash)
	require.NoError(err)
	require.NotNil(blockTemplate)
	require.NotNil(blockTemplate.Header)
	require.Equal(blockTemplate.Header.Version, HeaderVersion2)
	require.Equal(blockTemplate.Header.PrevBlockHash, latestBlockView.TipHash)
	root, _, err := ComputeMerkleRoot(blockTemplate.Txns)
	require.NoError(err)
	require.Equal(blockTemplate.Header.TransactionMerkleRoot, root)
	require.Equal(true, blockTemplate.Header.TstampNanoSecs < uint64(time.Now().UnixNano()))
	require.Equal(blockTemplate.Header.Height, uint64(3))
	require.Equal(blockTemplate.Header.ProposedInView, uint64(10))
	require.Equal(blockTemplate.Header.ProposerPublicKey, m0Pk)
	require.Equal(blockTemplate.Header.ProposerVotingPublicKey, pub)
	require.Equal(blockTemplate.Header.ProposerRandomSeedHash, seedHash)
}

func TestCreateBlockWithoutHeader(t *testing.T) {
	require := require.New(t)
	seed := int64(881)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()
	feeMin := globalParams.MinimumNetworkFeeNanosPerKB
	feeMax := uint64(2000)
	passingTransactions := 50
	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	params, db := _posTestBlockchainSetupWithBalances(t, 200000, 200000)
	params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 1

	latestBlockView, err := NewUtxoView(db, params, nil, nil)
	require.NoError(err)
	dir := _dbDirSetup(t)

	mempool := NewPosMempool(params, globalParams, latestBlockView, 2, dir, false)
	require.NoError(mempool.Start())
	defer mempool.Stop()
	require.True(mempool.IsRunning())

	// Add a bunch of passing transactions to the mempool that we'll use to produce a block.
	passingTxns := []*MsgDeSoTxn{}
	totalUtilityFee := uint64(0)
	for ii := 0; ii < passingTransactions; ii++ {
		txn := _generateTestTxn(t, rand, feeMin, feeMax, m0PubBytes, m0Priv, 100, 20)
		passingTxns = append(passingTxns, txn)
		_, utilityFee := computeBMF(txn.TxnFeeNanos)
		totalUtilityFee += utilityFee
		_wrappedPosMempoolAddTransaction(t, mempool, txn)
	}

	pbp := NewPosBlockProducer(mempool, params, nil, nil)
	txns, txnConnectStatus, maxUtilityFee, err := pbp.getBlockTransactions(
		latestBlockView, 3, 50000)
	require.NoError(err)

	blockTemplate, err := pbp.createBlockWithoutHeader(latestBlockView, 3)
	require.NoError(err)
	require.Equal(txns, blockTemplate.Txns[1:])
	require.Equal(txnConnectStatus, blockTemplate.TxnConnectStatusByIndex)
	require.Equal(maxUtilityFee, blockTemplate.Txns[0].TxOutputs[0].AmountNanos)
	require.Equal(NewMessage(MsgTypeHeader).(*MsgDeSoHeader), blockTemplate.Header)
	require.Nil(blockTemplate.BlockProducerInfo)
}

func TestGetBlockTransactions(t *testing.T) {
	require := require.New(t)
	seed := int64(381)
	rand := rand.New(rand.NewSource(seed))
	passingTransactions := 50
	failingTransactions := 30
	invalidTransactions := 10
	m1InitialBalance := uint64(20000)

	globalParams := _testGetDefaultGlobalParams()
	feeMin := globalParams.MinimumNetworkFeeNanosPerKB
	feeMax := uint64(2000)

	params, db := _posTestBlockchainSetupWithBalances(t, 200000, m1InitialBalance)
	params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = 1
	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	m1PubBytes, _, _ := Base58CheckDecode(m1Pub)

	latestBlockView, err := NewUtxoView(db, params, nil, nil)
	require.NoError(err)
	dir := _dbDirSetup(t)

	mempool := NewPosMempool(params, globalParams, latestBlockView, 2, dir, false)
	require.NoError(mempool.Start())
	defer mempool.Stop()
	require.True(mempool.IsRunning())

	// First test happy path with a bunch of passing transactions.
	passingTxns := []*MsgDeSoTxn{}
	totalUtilityFee := uint64(0)
	for ii := 0; ii < passingTransactions; ii++ {
		txn := _generateTestTxn(t, rand, feeMin, feeMax, m0PubBytes, m0Priv, 100, 20)
		passingTxns = append(passingTxns, txn)
		_, utilityFee := computeBMF(txn.TxnFeeNanos)
		totalUtilityFee += utilityFee
		_wrappedPosMempoolAddTransaction(t, mempool, txn)
	}

	pbp := NewPosBlockProducer(mempool, params, nil, nil)
	_testProduceBlockNoSizeLimit(t, mempool, pbp, latestBlockView, 3,
		len(passingTxns), 0, 0)

	// Now test the case where we have a bunch of transactions that don't pass.
	// A failing transaction will try to send an excessive balance in a basic transfer.
	failingTxns := []*MsgDeSoTxn{}
	for ii := 0; ii < failingTransactions; ii++ {
		failingTxn := _generateTestTxn(t, rand, feeMin, feeMax, m0PubBytes, m0Priv, 100, 20)
		failingTxn.TxOutputs = append(failingTxn.TxOutputs, &DeSoOutput{
			PublicKey:   m1PubBytes,
			AmountNanos: 1e10,
		})
		_signTxn(t, failingTxn, m0Priv)
		effectiveFee := failingTxn.TxnFeeNanos * globalParams.FailingTransactionBMFRateBasisPoints / 10000
		_, utilityFee := computeBMF(effectiveFee)
		totalUtilityFee += utilityFee
		failingTxns = append(failingTxns, failingTxn)
		_wrappedPosMempoolAddTransaction(t, mempool, failingTxn)
	}
	_testProduceBlockNoSizeLimit(t, mempool, pbp, latestBlockView, 3,
		len(passingTxns), len(failingTxns), 0)

	// We will now test some invalid transactions, which make it in the mempool, yet will not connect to utxo view,
	// nor as failing transactions. To do this, we will create a couple transactions with high spends compared to their
	// fees. The spend will be high enough so that the public key won't have enough balance to cover the fees of
	// the remaining transactions.
	invalidTxns := []*MsgDeSoTxn{}
	for ii := 0; ii < invalidTransactions; ii++ {
		invalidTxn := _generateTestTxn(t, rand, feeMin, feeMax, m1PubBytes, m1Priv, 100, 20)
		if m1InitialBalance < invalidTxn.TxnFeeNanos+1 {
			t.Fatalf("m1InitialBalance (%d) must be greater than txn fee (%d) + 1", m1InitialBalance, invalidTxn.TxnFeeNanos+1)
		}
		invalidTxn.TxOutputs = append(invalidTxn.TxOutputs, &DeSoOutput{
			PublicKey:   m2PkBytes,
			AmountNanos: m1InitialBalance - invalidTxn.TxnFeeNanos - 1,
		})
		_signTxn(t, invalidTxn, m1Priv)
		invalidTxns = append(invalidTxns, invalidTxn)
		_wrappedPosMempoolAddTransaction(t, mempool, invalidTxn)
	}

	_testProduceBlockNoSizeLimit(t, mempool, pbp, latestBlockView, 3,
		len(passingTxns)+1, len(failingTxns), len(invalidTxns)-1)
	// Now test the case where we have too many transactions in the mempool compared to the max block size.
	// In this case, some transactions should not make it into the block, despite being valid. The transactions
	// that are rejected should have the lowest Fee-Time priority.

	latestBlockViewCopy, err := latestBlockView.CopyUtxoView()
	require.NoError(err)
	txns, txnConnectStatus, maxUtilityFee, err := pbp.getBlockTransactions(latestBlockView, 3, 1000)
	require.NoError(err)
	require.Equal(latestBlockViewCopy, latestBlockView)
	require.Equal(true, len(passingTxns) > len(txns))
	require.Equal(true, len(passingTxns) > txnConnectStatus.Size())
	totalUtilityFee = 0
	for _, txn := range txns {
		_, utilityFee := computeBMF(txn.TxnFeeNanos)
		totalUtilityFee += utilityFee
	}
	require.Equal(totalUtilityFee, maxUtilityFee)

	// Create an in-memory mempool instance and add the transactions to it. Each transaction will be added with a
	// Simulated Transaction Timestamp and afterward, mempool will be queried for the transactions. The transactions should
	// be returned in the same order as the transaction from getBlockTransactions.
	testMempool := NewPosMempool(params, globalParams, latestBlockView, 2, "", true)
	require.NoError(testMempool.Start())
	defer testMempool.Stop()
	currentTime := uint64(time.Now().UnixMicro())
	for ii, txn := range txns {
		// Use the Simulated Transaction Timestamp.
		mtxn := NewMempoolTransaction(txn, currentTime+uint64(ii))
		require.NoError(testMempool.AddTransaction(mtxn, false))
	}
	newTxns := testMempool.GetTransactions()
	require.Equal(len(txns), len(newTxns))
	for ii := 0; ii < len(txns); ii++ {
		require.Equal(txns[ii], newTxns[ii].GetTxn())
	}
}

func _testProduceBlockNoSizeLimit(t *testing.T, mp *PosMempool, pbp *PosBlockProducer, latestBlockView *UtxoView, blockHeight uint64,
	numPassing int, numFailing int, numInvalid int) (_txns []*MsgDeSoTxn, _txnConnectStatusByIndex *bitset.Bitset, _maxUtilityFee uint64) {
	require := require.New(t)

	totalAcceptedTxns := numPassing + numFailing
	totalTxns := numPassing + numFailing + numInvalid
	require.Equal(totalTxns, len(mp.GetTransactions()))

	latestBlockViewCopy, err := latestBlockView.CopyUtxoView()
	require.NoError(err)
	txns, txnConnectStatus, maxUtilityFee, err := pbp.getBlockTransactions(latestBlockView, blockHeight, math.MaxUint64)
	require.NoError(err)
	require.Equal(latestBlockViewCopy, latestBlockView)
	require.Equal(totalAcceptedTxns, len(txns))
	require.Equal(true, totalAcceptedTxns >= txnConnectStatus.Size())
	numConnected := 0
	for ii := range txns {
		if txnConnectStatus.Get(ii) {
			numConnected++
		}
	}
	require.Equal(numPassing, numConnected)
	return txns, txnConnectStatus, maxUtilityFee
}