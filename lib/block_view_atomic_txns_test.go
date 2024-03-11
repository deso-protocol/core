package lib

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestVerifyAtomicTxnsWrapperRuleErrors(t *testing.T) {
	// Initialize test chain, miner, and testMeta.
	testMeta := _setUpMinerAndTestMetaForAtomicTransactionTests(t)

	// Initialize m0, m1, m2, m3, m4.
	_setUpUsersForAtomicTransactionsTesting(testMeta)

	// Generate 100 dependent atomic transactions.
	atomicTxns := _generateDependentAtomicTransactions(testMeta, 100)

	// Bundle the transactions together in a (valid) wrapper.
	atomicTxnsWrapper, _, err := testMeta.chain.CreateAtomicTxnsWrapper(atomicTxns, nil)
	require.NoError(t, err)

	// Try to use a public key other than the zero public key in the wrapper.
	// (This should fail -- RuleErrorAtomicTxnsWrapperPublicKeyMustBeZero)
	atomicTxnsWrapperDuplicate, err := atomicTxnsWrapper.Copy()
	require.NoError(t, err)
	atomicTxnsWrapperDuplicate.PublicKey = m0PkBytes
	_, err = _atomicTransactionsWrapperWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params, atomicTxnsWrapperDuplicate, 0)
	require.Contains(t, err.Error(), RuleErrorAtomicTxnsWrapperPublicKeyMustBeZero)

	// Try to sign the wrapper.
	// (This should fail -- RuleErrorAtomicTxnsWrapperSignatureMustBeNil)
	atomicTxnsWrapperDuplicate, err = atomicTxnsWrapper.Copy()
	require.NoError(t, err)
	_signTxn(t, atomicTxnsWrapperDuplicate, m0Priv)
	_, err = _atomicTransactionsWrapperWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params, atomicTxnsWrapperDuplicate, 0)
	require.Contains(t, err.Error(), RuleErrorAtomicTxnsWrapperSignatureMustBeNil)

	// Try to add inputs to the wrapper.
	// (This should fail -- RuleErrorAtomicTxnsWrapperMustHaveZeroInputs)
	atomicTxnsWrapperDuplicate, err = atomicTxnsWrapper.Copy()
	require.NoError(t, err)
	atomicTxnsWrapperDuplicate.TxInputs = append(atomicTxnsWrapperDuplicate.TxInputs, &DeSoInput{
		TxID:  ZeroBlockHash,
		Index: 0,
	})
	_, err = _atomicTransactionsWrapperWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params, atomicTxnsWrapperDuplicate, 0)
	require.Contains(t, err.Error(), RuleErrorAtomicTxnsWrapperMustHaveZeroInputs)

	// Try to add outputs to the wrapper.
	// (This should fail -- RuleErrorAtomicTxnsWrapperMustHaveZeroOutputs)
	atomicTxnsWrapperDuplicate, err = atomicTxnsWrapper.Copy()
	require.NoError(t, err)
	atomicTxnsWrapperDuplicate.TxOutputs = append(atomicTxnsWrapperDuplicate.TxOutputs, &DeSoOutput{
		PublicKey:   m0PkBytes,
		AmountNanos: 10000,
	})
	_, err = _atomicTransactionsWrapperWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params, atomicTxnsWrapperDuplicate, 0)
	require.Contains(t, err.Error(), RuleErrorAtomicTxnsWrapperMustHaveZeroOutputs)

	// Try to trigger overflow when summing the inner transactions.
	// (This should fail -- RuleErrorAtomicTxnsWrapperHasInternalFeeOverflow)
	atomicTxnsWrapperDuplicate, err = atomicTxnsWrapper.Copy()
	require.NoError(t, err)
	atomicTxnsWrapperDuplicate.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns[0].TxnFeeNanos = math.MaxUint64
	_, err = _atomicTransactionsWrapperWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params, atomicTxnsWrapperDuplicate, 0)
	require.Contains(t, err.Error(), RuleErrorAtomicTxnsWrapperHasInternalFeeOverflow)

	// Try to mismatch the fees in the wrapper and the total fees of the atomic transactions.
	// (This should fail -- RuleErrorAtomicTxnsWrapperMustHaveEqualFeeToInternalTxns)
	atomicTxnsWrapperDuplicate, err = atomicTxnsWrapper.Copy()
	require.NoError(t, err)
	atomicTxnsWrapperDuplicate.TxnFeeNanos = atomicTxnsWrapperDuplicate.TxnFeeNanos - 1
	_, err = _atomicTransactionsWrapperWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params, atomicTxnsWrapperDuplicate, 0)
	require.Contains(t, err.Error(), RuleErrorAtomicTxnsWrapperMustHaveEqualFeeToInternalTxns)

	// Try to use a non-zeroed nonce for the wrapper.
	// (This should fail -- RuleErrorAtomicTxnsWrapperMustHaveZeroedNonce)
	atomicTxnsWrapperDuplicate, err = atomicTxnsWrapper.Copy()
	require.NoError(t, err)
	atomicTxnsWrapperDuplicate.TxnNonce.ExpirationBlockHeight = 1
	_, err = _atomicTransactionsWrapperWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params, atomicTxnsWrapperDuplicate, 0)
	require.Contains(t, err.Error(), RuleErrorAtomicTxnsWrapperMustHaveZeroedNonce)
}

func TestVerifyAtomicTxnsChain(t *testing.T) {
	// Initialize test chain, miner, and testMeta.
	testMeta := _setUpMinerAndTestMetaForAtomicTransactionTests(t)

	// Initialize m0, m1, m2, m3, m4.
	_setUpUsersForAtomicTransactionsTesting(testMeta)

	// Generate 100 dependent atomic transactions.
	atomicTxns := _generateDependentAtomicTransactions(testMeta, 100)

	// Bundle the transactions together in a (valid) wrapper.
	atomicTxnsWrapper, _, err := testMeta.chain.CreateAtomicTxnsWrapper(atomicTxns, nil)
	require.NoError(t, err)

	// Try to put an atomic transaction wrapper INSIDE an atomic transaction wrapper.
	// (This should fail -- RuleErrorAtomicTxnsHasAtomicTxnsInnerTxn)
	atomicTxnsWrapperDuplicate, err := atomicTxnsWrapper.Copy()
	require.NoError(t, err)
	innerAtomicTxnsWrapper, _, err := testMeta.chain.CreateAtomicTxnsWrapper(atomicTxns[:100], nil)
	require.NoError(t, err)
	atomicTxnsWrapperDuplicate.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns =
		atomicTxnsWrapperDuplicate.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns[100:]
	atomicTxnsWrapperDuplicate.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns =
		append([]*MsgDeSoTxn{innerAtomicTxnsWrapper},
			atomicTxnsWrapperDuplicate.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns...)
	_, err = _atomicTransactionsWrapperWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params, atomicTxnsWrapperDuplicate, 0)
	require.Contains(t, err.Error(), RuleErrorAtomicTxnsHasAtomicTxnsInnerTxn)

	// Try to have a transaction not meant for inclusion in an atomic transaction wrapper
	// in the atomic transaction wrapper.
	// (This should fail -- RuleErrorAtomicTxnsHasNonAtomicInnerTxn)
	atomicTxnsWrapperDuplicate, err = atomicTxnsWrapper.Copy()
	require.NoError(t, err)
	atomicTxnsWrapperDuplicate.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns[1].ExtraData = make(map[string][]byte)
	_, err = _atomicTransactionsWrapperWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params, atomicTxnsWrapperDuplicate, 0)
	require.Contains(t, err.Error(), RuleErrorAtomicTxnsHasNonAtomicInnerTxn)

	// Remove the chain length starter pointer for the atomic transactions.
	// (This should fail -- RuleErrorAtomicTxnsMustStartWithChainLength)
	atomicTxnsWrapperDuplicate, err = atomicTxnsWrapper.Copy()
	require.NoError(t, err)
	delete(
		atomicTxnsWrapperDuplicate.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns[0].ExtraData,
		AtomicTxnsChainLength)
	_, err = _atomicTransactionsWrapperWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params, atomicTxnsWrapperDuplicate, 0)
	require.Contains(t, err.Error(), RuleErrorAtomicTxnsMustStartWithChainLength)

	// Add a second start point for the atomic transactions.
	// (This should fail -- RuleErrorAtomicTxnsHasMoreThanOneStartPoint)
	atomicTxnsWrapperDuplicate, err = atomicTxnsWrapper.Copy()
	require.NoError(t, err)
	atomicTxnsWrapperDuplicate.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns[1].ExtraData[AtomicTxnsChainLength] =
		atomicTxnsWrapperDuplicate.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns[0].ExtraData[AtomicTxnsChainLength]
	_, err = _atomicTransactionsWrapperWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params, atomicTxnsWrapperDuplicate, 0)
	require.Contains(t, err.Error(), RuleErrorAtomicTxnsHasMoreThanOneStartPoint)

	// Try to change the sequence of transactions, ultimately breaking the chain.
	// (This should fail -- RuleErrorAtomicTxnsHasBrokenChain)
	atomicTxnsWrapperDuplicate, err = atomicTxnsWrapper.Copy()
	require.NoError(t, err)
	txnCopy, err := atomicTxnsWrapperDuplicate.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns[2].Copy()
	require.NoError(t, err)
	atomicTxnsWrapperDuplicate.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns[2] =
		atomicTxnsWrapperDuplicate.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns[1]
	atomicTxnsWrapperDuplicate.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns[1] = txnCopy
	_, err = _atomicTransactionsWrapperWithConnectTimestamp(
		t, testMeta.chain, testMeta.db, testMeta.params, atomicTxnsWrapperDuplicate, 0)
	require.Contains(t, err.Error(), RuleErrorAtomicTxnsHasBrokenChain)

}

func TestDependentAtomicTransactionGeneration(t *testing.T) {
	// Initialize test chain, miner, and testMeta.
	testMeta := _setUpMinerAndTestMetaForAtomicTransactionTests(t)

	// Initialize m0, m1, m2, m3, m4.
	_setUpUsersForAtomicTransactionsTesting(testMeta)

	// Generate 100 dependent atomic transactions.
	atomicTxns := _generateDependentAtomicTransactions(testMeta, 100)

	// Construct a new view to connect the transactions to.
	utxoView, err := NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	require.NoError(t, err)
	blockHeight := testMeta.chain.BlockTip().Height + 1

	// Get the initial balance for m0.
	m0InitialBalanceNanos := _getBalance(t, testMeta.chain, testMeta.mempool, m0Pub)

	// Connect the transactions to ensure they can actually be connected.
	var totalFees uint64
	for _, txn := range atomicTxns {
		// Connect the transaction.
		txHash := txn.Hash()
		_, _, _, fees, err := utxoView.ConnectTransaction(
			txn, txHash, blockHeight, 0, true, false)
		require.NoError(t, err)
		totalFees += fees
	}

	// Flush the view to ensure everything is working properly.
	require.NoError(t, utxoView.FlushToDb(uint64(blockHeight)))

	// Get the final balance for m0.
	m0FinalBalanceNanos := _getBalance(t, testMeta.chain, testMeta.mempool, m0Pub)

	// Check that fees were paid.
	require.Equal(t, m0InitialBalanceNanos-totalFees, m0FinalBalanceNanos)

	//
	// Now we test that the transactions are truly dependent on each-other by reorganizing them.
	//

	// Reorganize the transactions.
	initialTxn := atomicTxns[0]
	atomicTxns[0] = atomicTxns[len(atomicTxns)-1]
	atomicTxns[0] = initialTxn

	// Initialize test chain, miner, and testMeta for failing use.
	testMetaFail := _setUpMinerAndTestMetaForAtomicTransactionTests(t)

	// Initialize m0, m1, m2, m3, m4.
	_setUpUsersForAtomicTransactionsTesting(testMetaFail)

	// Construct a new view to connect the transactions to.
	utxoView, err = NewUtxoView(
		testMetaFail.db, testMetaFail.params, testMetaFail.chain.postgres, testMetaFail.chain.snapshot, nil)
	require.NoError(t, err)
	blockHeight = testMetaFail.chain.BlockTip().Height + 1

	// Connect the transactions to ensure they can actually be connected.
	for _, txn := range atomicTxns {
		// Connect the transaction.
		txHash := txn.Hash()
		_, _, _, _, err := utxoView.ConnectTransaction(
			txn, txHash, blockHeight, 0, true, false)
		if err != nil {
			require.Contains(t, err.Error(), RuleErrorInsufficientBalance)
		}
	}
}

//----------------------------------------------------------
// (Testing) Atomic Transactions Setup Helper Functions
//----------------------------------------------------------

// The goal of _generateDependentAtomicTransactions is to generate
// a sequence of transactions who CANNOT be reordered meaning they
// must be executed in the sequence returned. This mean transaction
// with position ii in atomicTransactions CANNOT be placed in an
// index jj of atomicTransactions such that jj < ii
//
// How can we generate "dependent atomic transactions" algorithmically using
// TestMeta initialized with _setUpUsersForAtomicTransactionTesting?
//
//	(1) Choose an arbitrary starter public key with DESO (m0PkBytes)
//	(2) For ii in [0, numberOfTransactions):
//		(2a) Generate a new public/private key pair (pub_ii, priv_ii)
//		(2b) Have pub_(ii-1) do a max DESO transfer to pub_ii. Use m0PkBytes as pub_(-1).
//	(3) Have pub_numberOfTransactions perform a max transfer back to m0PkBytes
//
// Notice that because pub_ii only has DESO at following the transaction with
// the iith index in numberOfTransactions, it's impossible to reorder the transactions
// in any other order. Hence, these transactions are dependent on each other.
//
// The length of the returned list of transactions is specified by numberOfTransactions.
func _generateDependentAtomicTransactions(
	testMeta *TestMeta,
	numberOfTransactions int,
) (
	_atomicTransactions []*MsgDeSoTxn,
) {
	var atomicTransactions []*MsgDeSoTxn
	var receiverPublicKeysBase58 []string
	var receiverPrivateKeysBase58 []string
	var receiverBalancesNanos []uint64

	// Get the initial balance of m0.
	m0InitialBalanceNanos := _getBalance(
		testMeta.t, testMeta.chain, testMeta.mempool, m0Pub)

	// Generate the atomic transactions.
	for ii := 0; ii < numberOfTransactions-1; ii++ {
		// Generate a new public/private key pair.
		privKey_ii, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(testMeta.t, err)
		pubKey_ii := privKey_ii.PubKey()
		receiverPrivateKeysBase58 = append(receiverPrivateKeysBase58, Base58CheckEncode(
			privKey_ii.Serialize(), true, testMeta.params))
		receiverPublicKeysBase58 = append(receiverPublicKeysBase58, Base58CheckEncode(
			pubKey_ii.SerializeCompressed(), false, testMeta.params))

		// Determine the sender.
		var senderPubKeyBase58 string
		var senderPrivKeyBase58 string
		var senderBalanceNanos uint64
		if ii == 0 {
			senderPubKeyBase58 = m0Pub
			senderPrivKeyBase58 = m0Priv
			senderBalanceNanos = m0InitialBalanceNanos
		} else {
			senderPubKeyBase58 = receiverPublicKeysBase58[ii-1]
			senderPrivKeyBase58 = receiverPrivateKeysBase58[ii-1]
			senderBalanceNanos = receiverBalancesNanos[ii-1]
		}

		// Generate a max atomic transfer.
		maxTransferTxn, receiverBalanceNanos, err := _generateMaxBasicTransfer(
			testMeta, senderPubKeyBase58, senderPrivKeyBase58, senderBalanceNanos, receiverPublicKeysBase58[ii])
		require.NoError(testMeta.t, err)
		atomicTransactions = append(atomicTransactions, maxTransferTxn)

		// Store the receiver balance as blockchain state is not updated yet.
		receiverBalancesNanos = append(receiverBalancesNanos, receiverBalanceNanos)
	}

	// Perform a max transfer back to m0.
	maxTransferTxn, _, err := _generateMaxBasicTransfer(
		testMeta,
		receiverPublicKeysBase58[len(receiverPublicKeysBase58)-1],
		receiverPrivateKeysBase58[len(receiverPrivateKeysBase58)-1],
		receiverBalancesNanos[len(receiverBalancesNanos)-1],
		m0Pub)
	require.NoError(testMeta.t, err)
	atomicTransactions = append(atomicTransactions, maxTransferTxn)

	return atomicTransactions
}

func _generateMaxBasicTransfer(
	testMeta *TestMeta,
	senderPubKeyBase58 string,
	senderPrivKeyBase58 string,
	senderBalanceNanos uint64,
	receiverPubKeyBase58 string,
) (
	_maxTransferTransaction *MsgDeSoTxn,
	_transferredAmount uint64,
	_err error,
) {
	// Convert the public keys to bytes.
	senderPubKeyBytes, _, err := Base58CheckDecode(senderPubKeyBase58)
	if err != nil {
		return nil, 0, err
	}
	receiverPubKeyBytes, _, err := Base58CheckDecode(receiverPubKeyBase58)
	if err != nil {
		return nil, 0, err
	}

	// Construct a UtxoView for fetching state.
	utxoView, err := NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
	require.NoError(testMeta.t, err)

	// Construct a transfer template.
	// NOTE: Because of variable encoding of txn.TxOutputs[0].AmountNanos, we use MaxUint64 to ensure
	//		 the computed transaction fees are sufficient.
	txnNonce, err := utxoView.ConstructNonceForPublicKey(senderPubKeyBytes, uint64(testMeta.chain.BlockTip().Height))
	require.NoError(testMeta.t, err)
	txn := &MsgDeSoTxn{
		TxnVersion: 1,
		TxInputs:   []*DeSoInput{},
		TxOutputs: []*DeSoOutput{
			{
				PublicKey:   receiverPubKeyBytes,
				AmountNanos: math.MaxUint64,
			},
		},
		TxnMeta:   &BasicTransferMetadata{},
		TxnNonce:  txnNonce,
		PublicKey: senderPubKeyBytes,
	}

	// Compute the fees and update the template to reflect the accurate transfer amount.
	txn.TxnFeeNanos = EstimateMaxTxnFeeV1(txn, testMeta.feeRateNanosPerKb)
	if txn.TxnFeeNanos > senderBalanceNanos {
		return nil, 0,
			errors.New("_generateMaxBasicTransfer: transaction fees more than sender balance.")
	}
	txn.TxOutputs[0].AmountNanos = senderBalanceNanos - txn.TxnFeeNanos

	// Sign and return the transaction.
	_signTxn(testMeta.t, txn, senderPrivKeyBase58)
	return txn, txn.TxOutputs[0].AmountNanos, nil
}

// _setUpUsersForAtomicTransactionsTesting is a simple helper function which takes
// with a miner who has a DESO balance equivalent to 10 block rewards assumed
// to be assigned the public key senderPkString. After running _setUpUsersForAtomicTransactionsTesting
// we expect the following test state:
//
// m0Pub - 1e9 nDESO, m0 profile
// m1Pub - 1e6 nDESO, m1 profile
// m2Pub - 1e6 nDESO
// m3Pub - 1e6 nDESO
// m4Pub - 1e6 nDESO
func _setUpUsersForAtomicTransactionsTesting(testMeta *TestMeta) {
	// Create on-chain public keys with DESO sent from miner
	_registerOrTransferWithTestMeta(testMeta, "m0", senderPkString, m0Pub, senderPrivString, 1e9)
	_registerOrTransferWithTestMeta(testMeta, "m1", senderPkString, m1Pub, senderPrivString, 1e6)
	_registerOrTransferWithTestMeta(testMeta, "m2", senderPkString, m2Pub, senderPrivString, 1e6)
	_registerOrTransferWithTestMeta(testMeta, "m3", senderPkString, m3Pub, senderPrivString, 1e6)
	_registerOrTransferWithTestMeta(testMeta, "m4", senderPkString, m4Pub, senderPrivString, 1e6)

	// Create profile for m0 and m1.
	{
		_updateProfileWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m0Pub,
			m0Priv,
			[]byte{},
			"m0",
			"i am the m0",
			shortPic,
			10*100,
			1.25*100*100,
			false,
		)
	}
	{
		_updateProfileWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			m1Pub,
			m1Priv,
			[]byte{},
			"m1",
			"i am the m1",
			shortPic,
			10*100,
			1.25*100*100,
			false,
		)
	}
}

func _setUpMinerAndTestMetaForAtomicTransactionTests(t *testing.T) *TestMeta {
	// Initialize balance model fork heights.
	setBalanceModelBlockHeights(t)

	// Initialize pos fork heights.
	setPoSBlockHeights(t, 11, 100)

	// Initialize test chain and miner.
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Ensure DAO coins are enabled (helpful for atomic testing)
	params.ForkHeights.DAOCoinBlockHeight = uint32(0)

	// Initialize atomics block height.
	params.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(11)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

	// Mine a few blocks to give the senderPkString some money.
	for ii := 0; ii < 10; ii++ {
		_, err := miner.MineAndProcessSingleBlock(0, mempool)
		require.NoError(t, err)
	}

	// We build the testMeta obj after mining blocks so that we save the correct block height.
	blockHeight := uint64(chain.blockTip().Height) + 1

	return &TestMeta{
		t:                 t,
		chain:             chain,
		params:            params,
		db:                db,
		mempool:           mempool,
		miner:             miner,
		savedHeight:       uint32(blockHeight),
		feeRateNanosPerKb: uint64(101),
	}
}

//----------------------------------------------------------
// (Testing) Atomic Transaction Connection Helper Functions
//----------------------------------------------------------

func _atomicTransactionsWithTestMeta(
	testMeta *TestMeta,
	atomicTransactions []*MsgDeSoTxn,
	connectTimestamp int64,
) {
	// For atomic transaction sanity check reasons, save the ZeroPublicKey's balance.
	testMeta.expectedSenderBalances =
		append(testMeta.expectedSenderBalances,
			_getBalance(testMeta.t, testMeta.chain, nil,
				Base58CheckEncode(ZeroPublicKey.ToBytes(), false, testMeta.params)))

	// Connect the transactions.
	currentOps, currentTxn, _, err := _atomicTransactionsWithConnectTimestamp(
		testMeta.t,
		testMeta.chain,
		testMeta.db,
		testMeta.params,
		atomicTransactions,
		connectTimestamp)
	require.NoError(testMeta.t, err)

	// Append the transaction as well as the transaction ops.
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _atomicTransactionsWithConnectTimestamp(
	t *testing.T,
	chain *Blockchain,
	db *badger.DB,
	params *DeSoParams,
	atomicTransactions []*MsgDeSoTxn,
	connectTimestamp int64,
) (
	_utxoOps []*UtxoOperation,
	_txn *MsgDeSoTxn,
	_height uint32,
	_err error,
) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// Construct a new view to connect the transactions to.
	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot, nil)
	require.NoError(err)

	// Create the atomic transaction wrapper.
	txn, totalFees, err := chain.CreateAtomicTxnsWrapper(atomicTransactions, nil)
	if err != nil {
		return nil, nil, 0, err
	}

	// Connect the transaction.
	txHash := txn.Hash()
	blockHeight := chain.BlockTip().Height + 1
	utxoOps, totalInput, _, fees, err := utxoView.ConnectTransaction(
		txn, txHash, blockHeight, connectTimestamp, true, false)
	if err != nil {
		return nil, nil, 0, err
	}

	// Check that the total input reflected from the transaction connect equals the total fees.
	require.Equal(totalInput, totalFees)
	require.Equal(totalInput, fees)

	// Check that the UtxoOps reflect those of an atomic transaction.
	require.Equal(1, len(utxoOps))
	require.Equal(OperationTypeAtomicTxnsWrapper, utxoOps[0].Type)

	// Ensure the transaction can be flushed without issue.
	require.NoError(utxoView.FlushToDb(uint64(blockHeight)))
	return utxoOps, txn, blockHeight, nil
}

func _atomicTransactionsWrapperWithConnectTimestamp(
	t *testing.T,
	chain *Blockchain,
	db *badger.DB,
	params *DeSoParams,
	atomicTransactionsWrapper *MsgDeSoTxn,
	connectTimestamp int64,
) (
	_utxoOps []*UtxoOperation,
	_err error,
) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// Construct a new view to connect the transactions to.
	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot, nil)
	require.NoError(err)

	// Connect the transaction.
	txHash := atomicTransactionsWrapper.Hash()
	blockHeight := chain.BlockTip().Height + 1
	utxoOps, _, _, _, err := utxoView.ConnectTransaction(
		atomicTransactionsWrapper, txHash, blockHeight, connectTimestamp, true, false)
	if err != nil {
		return nil, err
	}

	return utxoOps, nil
}
