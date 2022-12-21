package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	_ "net/http/pprof"
	"reflect"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/decred/dcrd/lru"
	"github.com/dgraph-io/badger/v3"
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/golang/glog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// ================================== TRANSACTION TEST FRAMEWORK ==============================================
// transactionTest is a new testing framework intended to streamline testing of blockchain transactions.
// The idea behind this framework is to create a unified unit testing structure that can be used to test different
// edge-cases of how transactions are connected/disconnected without having to write a lot of boilerplate code. Most
// of our current unit tests are written in a way that's hard to read and non-intuitive to maintain. While this worked
// well when our transaction set was small, as we expand DeSo adding more and more complex abstractions, we also need
// to keep simplifying the development process, minimizing the range of potential errors, and lowering the amount of
// brain RAM required to cover all edge-cases. Right now, adding a new transaction involves accommodating multiple
// components of the codebase such as utxoOps, DeSoEncoders, badger, postgres, snapshot, txindex, etc. The transactionTest
// framework is supposed to make it easy to test all of these components for a newly-added transaction, and somewhat
// "guide" you in testing them. The framework is designed with simplicity and modularity in mind. It also allows for
// easy debugging and test isolation. The framework is meant to be used in conjunction with the existing unit tests,
// and not replace them. Ideally, we could write additional parallel tests for the current unit tests that will stress-test
// the existing transactions even more.
//
// The general premise for the transactionTest framework is that real-life transactions follow a rather simple life-cycle.
// Transactions are assembled into a block via a mempool and once all of them are connected, the block is mined and
// everything is flushed at once to the db (be it badger or postgres). There is no other way that transactions can be
// connected. In particular, it will never be the case that transaction will be flushed without a whole block being mined;
// however, this is what we do in our unit tests, which is counter-intuitive, and (on a side-note) has created a lot of
// overhead when developing complex features such as postgres or hypersync. When a transaction is connected, it will create
// UtxoView and UtxoOps mappings; which will be persisted to the db when the block is mined and the mempool is flushed. Next,
// transaction can be disconnected when the block is disconnected. There is no other way for a transaction to be
// disconnected, and the order in which transactions are disconnected is always the reverse of the order in which they were
// connected. When a transaction is disconnected, it will either set a "isDeleted" entry in UtxoView, which will indicate
// that a db record should be deleted, or it will set a "previous" entry in UtxoView according to the UtxoOps, which will
// be flushed to the db. The transactionTest framework is essentially trying to verify that all of these steps are properly
// followed, and all the utxoView entries are properly set and then flushed to the db.
//
// When using the transactionTest framework the developer will be defining a list of transactions that he wants to test
// in-order. These transactions will be described by creating transactionTestVector structs that will contain all the
// information needed to create a transaction and verify the utxoView mappings and db records after the transaction is
// connected and flushed. Once a collection of testVectors is defined, the developer will need to create a transactionTestSuite
// object containing previously defined testVectors. Finally, the developer will need to call the Run() method on the
// transactionTestSuite object. This will run the test suite and verify that all the testVectors are properly connected
// and disconnected.
// ============================================================================================================

// TransactionTestInputType specifies the type of input that a transactionTestVector will use.
type transactionTestInputType byte

const (
	transactionTestInputTypeAccessGroupCreate transactionTestInputType = iota
	transactionTestInputTypeAccessGroupMembers
)

type testTxn interface {
	generateTxn(t *testing.T, tb *TestBlockChain) *MsgDeSoTxn
}

type basicTestTxn struct {
	senderPublicKeyBytes   []byte
	receiverPublicKeyBytes []byte
	amountNanos            uint64
}

func generateRandomPrivateKeyBase58(t *testing.T, tbc *TestBlockChain) string {
	t.Helper()

	randomPrivKey, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)
	randomPrivKeyBase58Check := Base58CheckEncode(randomPrivKey.Serialize(), true, tbc.params)
	return randomPrivKeyBase58Check
}

func (bt basicTestTxn) generateTxn(t *testing.T, tb *TestBlockChain) *MsgDeSoTxn {
	t.Helper()
	txn := &MsgDeSoTxn{
		// The inputs will be set below.
		TxInputs: []*DeSoInput{},
		TxOutputs: []*DeSoOutput{
			{
				PublicKey:   bt.receiverPublicKeyBytes,
				AmountNanos: bt.amountNanos,
			},
		},
		PublicKey: bt.senderPublicKeyBytes,
		TxnMeta:   &BasicTransferMetadata{},
	}
	return txn
}

type derivedKeyTestTxn struct {
	transactionSpendingLimit *TransactionSpendingLimit
	derivedPrivKey           *btcec.PrivateKey
	senderPublicKey          string
}

func (txn derivedKeyTestTxn) doDerivedKeyTransaction(t *testing.T, tb *TestBlockChain) (derivedKeyTxn *MsgDeSoTxn,
	derivedPrivateKey *btcec.PrivateKey) {

	t.Helper()
	require := require.New(t)
	extraData := make(map[string]interface{})
	extraData[TransactionSpendingLimitKey] = txn.transactionSpendingLimit
	blockHeight, err := GetBlockTipHeight(tb.db, false)
	require.NoError(err)

	senderPkBytes, _, err := Base58CheckDecode(txn.senderPublicKey)
	require.NoError(err)
	senderPrivBytes, _, err := Base58CheckDecode(senderPrivString)
	require.NoError(err)
	senderPrivKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), senderPrivBytes)

	authTxnMeta, derivedPriv := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(
		t, senderPrivKey, 10, txn.transactionSpendingLimit, false, blockHeight+1)
	transactionSpendingLimitBytes, err := txn.transactionSpendingLimit.ToBytes(blockHeight + 1)
	require.NoError(err)
	derivedKeyTxn, totalInput, changeAmount, fees, err := tb.chain.CreateAuthorizeDerivedKeyTxn(
		senderPkBytes,
		authTxnMeta.DerivedPublicKey,
		authTxnMeta.ExpirationBlock,
		authTxnMeta.AccessSignature,
		false,
		false,
		nil,
		[]byte{},
		hex.EncodeToString(transactionSpendingLimitBytes),
		10,
		tb.mempool,
		nil,
	)

	require.NoError(err)
	require.Equal(totalInput, changeAmount+fees)
	require.Greater(totalInput, uint64(0))
	require.NoError(err)
	return derivedKeyTxn, derivedPriv
}

func (txn derivedKeyTestTxn) generateTxn(t *testing.T, tb *TestBlockChain) *MsgDeSoTxn {
	t.Helper()
	derivedKeyTxn, derivedPrivKey := txn.doDerivedKeyTransaction(t, tb)

	txn.derivedPrivKey = derivedPrivKey
	return derivedKeyTxn
}

func (txn derivedKeyTestTxn) getDerivedPrivKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()
	return txn.derivedPrivKey
}

type transactionTestInputSpace interface {
	// IsDependency should return true if the other input space will have overlapping utxoView/utxoOps mappings or db records
	// with the current input space. This is used by the transactionTest framework to determine which transactionTestVector
	// will describe entries that will be flushed to the db after both test vectors are applied.
	// We assume that IsDependant is a symmetric relation, i.e. IsDependency(TV1, TV2) == IsDependency(TV2, TV1); however,
	// it is not necessarily a transitive relation, i.e. IsDependency(TV1, TV2) && IsDependency(TV2, TV3) does
	// not have to imply IsDependency(TV1, TV3).
	IsDependency(other transactionTestInputSpace) bool
	// Get input type should just return a unique transactionTestInputType associated with the particular input space.
	GetInputType() transactionTestInputType
}

// transactionTestMeta defines some environment variables about the blockchain.
type transactionTestMeta struct {
	t       *testing.T
	chain   *Blockchain
	db      *badger.DB
	pg      *Postgres
	embpg   *embeddedpostgres.EmbeddedPostgres
	params  *DeSoParams
	mempool *DeSoMempool
	miner   *DeSoMiner
}

func (tm *transactionTestMeta) Quit() {
	require := require.New(tm.t)

	if tm.miner != nil {
		tm.miner.Stop()
	}

	if tm.mempool != nil {
		if tm.mempool.mempoolDir != "" {
			tm.mempool.DumpTxnsToDB()
		}
		tm.mempool.Stop()
	}

	if tm.chain.snapshot != nil {
		tm.chain.snapshot.Stop()
	}

	if tm.chain.db != nil {
		require.NoError(tm.chain.db.Close())
	}
}

type transactionTestConfig struct {
	t                          *testing.T
	testBadger                 bool
	testPostgres               bool
	testPostgresPort           uint32
	initialBlocksMined         int
	fundPublicKeysWithNanosMap map[PublicKey]uint64
	initChainCallback          func(tm *transactionTestMeta)
}

// transactionTestIdentifier is a unique identifier for a transactionTestVector.
type transactionTestIdentifier string

// transactionTestVector is the main struct that comprises the unit tests for the transaction testing framework.
// It contains the transactionTestMetadata, the test's id, the inputSpace for the test -- the data that will be used to
// construct the transaction when the test vector is processed by the test suite's run. In addition, the test vector
// contains a methods such as getTransaction, which will be called to get the transaction out of this test vector.
// It's worth noting that getTransaction should return both the _transaction and the _expectedConnectUtxoViewError in case
// we want to check a failing transaction and make sure it returns the anticipated error.
// The test vector also contains validation functions verifyConnectUtxoViewEntry and verifyDbEntry which will be used to verify
// that a correct entry exists in the mempool and the db after the transaction has been connected/disconnected (in the
// latter case, the expectDeleted bool will be passed as true).
// The testVector also allows specifying two callback functions connectCallback, which will be called once the transaction
// acquired from getTransaction has been connected, and disconnectCallback, which will be called when the transaction
// gets disconnected.
type transactionTestVector struct {
	id             transactionTestIdentifier
	inputSpace     transactionTestInputSpace
	getTransaction func(tv *transactionTestVector, tm *transactionTestMeta) (
		_transaction *MsgDeSoTxn, _expectedConnectUtxoViewError error)
	verifyConnectUtxoViewEntry    func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView)
	verifyDisconnectUtxoViewEntry func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView, utxoOps []*UtxoOperation)
	verifyDbEntry                 func(tv *transactionTestVector, tm *transactionTestMeta, dbAdapter *DbAdapter)
	connectCallback               func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView)
	disconnectCallback            func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView)
}

type transactionTestVectorBlock struct {
	testVectors        []*transactionTestVector
	connectCallback    func(tvb *transactionTestVectorBlock, tm *transactionTestMeta)
	disconnectCallback func(tvb *transactionTestVectorBlock, tm *transactionTestMeta)
}

func NewTransactionTestVectorBlock(
	testVectors []*transactionTestVector,
	connectCallback func(tvb *transactionTestVectorBlock, tm *transactionTestMeta),
	disconnectCallback func(tvb *transactionTestVectorBlock, tm *transactionTestMeta)) *transactionTestVectorBlock {
	return &transactionTestVectorBlock{
		testVectors:        testVectors,
		connectCallback:    connectCallback,
		disconnectCallback: disconnectCallback,
	}
}

// transactionTestSuite is the main component of the transaction testing framework. It contains the test metadata
// transactionTestMeta, and the test vectors ordered sequentially block by block in the order in which they should be
// connected to the blockchain.
// The remaining fields are for internal use only: _testVectorsInDb keeps track of test vectors that have already been
// flushed to the db, while _testVectorsInMempool keeps track of all the test vectors that have currently been connected
// to the mempool. Lastly, _testVectorDependency keeps track of all the test vectors which should be skipped from checking
// verifyConnectUtxoViewEntry and verifyDbEntry because there has been a later test vector (test vector identified by map key id) that
// had a pairwise IsDependency evaluate to true. This is used to avoid checking the same utxoView or db records repeatedly:
// once for the latest testVector, and twice, thrice, etc. for the earlier, dependent testVectors.
type transactionTestSuite struct {
	t                *testing.T
	testVectorBlocks []*transactionTestVectorBlock
	config           *transactionTestConfig

	_testVectorsInDb      []*transactionTestVector
	_testVectorsInMempool []*transactionTestVector
	_testVectorDependency map[transactionTestIdentifier][]transactionTestIdentifier
}

func NewTransactionTestSuite(t *testing.T, testVectorBlocks []*transactionTestVectorBlock,
	config *transactionTestConfig) *transactionTestSuite {

	return &transactionTestSuite{
		t:                     t,
		testVectorBlocks:      testVectorBlocks,
		config:                config,
		_testVectorDependency: make(map[transactionTestIdentifier][]transactionTestIdentifier),
	}
}

// Run is the main method of the transactionTestSuite. It will run the test suite and verify that all the testVectors are
// pass a variety of tests.
func (tes *transactionTestSuite) Run() {
	// Make sure all test vectors have unique Ids.
	tes.ValidateTestVectors()

	if tes.config.testBadger {
		tes.RunBadgerTest()
	}
	if tes.config.testPostgres {
		tes.RunPostgresTest()
	}
}

// Iterate over all testVectors and ensure all of them have unique Ids.
func (tes *transactionTestSuite) ValidateTestVectors() {
	testVectorsIds := make(map[transactionTestIdentifier]struct{})
	for _, testVectorBlocks := range tes.testVectorBlocks {
		for _, testVectors := range testVectorBlocks.testVectors {
			if _, exists := testVectorsIds[testVectors.id]; exists {
				tes.t.Fatalf("Duplicate test vector id: %v", testVectors.id)
			}
			testVectorsIds[testVectors.id] = struct{}{}
		}
	}
}

func (tes *transactionTestSuite) RunBadgerTest() {
	glog.Infof(CLog(Yellow, "RunBadgerTest: TESTING BADGER"))

	tm := tes.InitializeChainAndGetTestMeta(true, false)
	tes._testVectorsInDb = []*transactionTestVector{}
	tes._testVectorsInMempool = []*transactionTestVector{}
	tes._testVectorDependency = make(map[transactionTestIdentifier][]transactionTestIdentifier)

	for _, testVectorBlock := range tes.testVectorBlocks {
		// Run all the test vectors for this block.
		dbEntriesBefore := tes.GetAllStateDbEntries(tm)
		tes.testConnectBlock(tm, testVectorBlock)
		tes.testDisconnectBlock(tm, testVectorBlock)
		dbEntriesAfter := tes.GetAllStateDbEntries(tm)
		tes.compareBeforeAfterDbEntries(dbEntriesBefore, dbEntriesAfter)
		glog.Infof(CLog(Yellow, "RunBadgerTest: successfully connected/disconnected block and verified db state"))
		tes.testConnectBlock(tm, testVectorBlock)
		glog.Infof(CLog(Yellow, "RunBadgerTest: successfully connected block"))
	}
	tm.Quit()
}

func (tes *transactionTestSuite) RunPostgresTest() {
	glog.Infof(CLog(Yellow, "RunPostgresTest: TESTING POSTGRES"))

	require := require.New(tes.t)
	tm := tes.InitializeChainAndGetTestMeta(false, true)
	tes._testVectorsInDb = []*transactionTestVector{}
	tes._testVectorsInMempool = []*transactionTestVector{}
	tes._testVectorDependency = make(map[transactionTestIdentifier][]transactionTestIdentifier)

	defer func() {
		// Note that deferred function will be called even if the rest of the function panics.
		glog.Infof("RunPostgresTest: Got into deferred cleanup function")
		require.NoError(StopTestEmbeddedPostgresDB(tm.embpg))
		glog.Infof(CLog(Yellow, "RunPostgresTest: successfully stopped embedded postgres db"))
	}()

	for _, testVectorBlock := range tes.testVectorBlocks {
		// Run all the test vectors for this block.
		tes.testConnectBlock(tm, testVectorBlock)
		tes.testDisconnectBlock(tm, testVectorBlock)
		glog.Infof(CLog(Yellow, "RunPostgresTest: successfully connected/disconnected block"))
		tes.testConnectBlock(tm, testVectorBlock)
		glog.Infof(CLog(Yellow, "RunPostgresTest: successfully connected block"))
	}
	tm.Quit()
}

func (tes *transactionTestSuite) InitializeChainAndGetTestMeta(useBadger bool, usePostgres bool) *transactionTestMeta {

	var chain *Blockchain
	var db *badger.DB
	var pg *Postgres
	var embpg *embeddedpostgres.EmbeddedPostgres
	var params *DeSoParams
	var mempool *DeSoMempool
	var miner *DeSoMiner

	config := tes.config
	require := require.New(config.t)
	require.Equal(true, useBadger || usePostgres)

	// Initialize the blockchain, database, mempool, and miner.
	if useBadger {
		chain, params, db = NewLowDifficultyBlockchain()
		mempool, miner = NewTestMiner(config.t, chain, params, true /*isSender*/)
	} else if usePostgres {
		pgPort := uint32(5433)
		if config.testPostgresPort != 0 {
			pgPort = config.testPostgresPort
		}
		chain, params, embpg = NewLowDifficultyBlockchainWithParamsAndDb(&DeSoTestnetParams,
			true, pgPort)
		mempool, miner = NewTestMiner(config.t, chain, params, true /*isSender*/)
		pg = chain.postgres
		db = chain.db
	}

	// Construct the transaction test meta object.
	tm := &transactionTestMeta{
		t:       config.t,
		chain:   chain,
		db:      db,
		pg:      pg,
		embpg:   embpg,
		params:  params,
		mempool: mempool,
		miner:   miner,
	}

	// Call the initChainCallback if it is provided in the config.
	if config.initChainCallback != nil {
		config.initChainCallback(tm)
	}

	// Mine a few blocks according to the configuration.
	for ii := 0; ii < config.initialBlocksMined; ii++ {
		_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
	}

	// Fund public keys in fundPublicKeysWithNanosMap.
	for publicKey, amountNanos := range config.fundPublicKeysWithNanosMap {
		tes.fundPublicKey(tm, publicKey, amountNanos)
	}

	return tm
}

// Fund provided public key with the desired amount of DeSo in nanos.
func (tes *transactionTestSuite) fundPublicKey(tm *transactionTestMeta, publicKey PublicKey, amountNanos uint64) {
	// Note we don't need to pass Postgres here, because _doBasicTransferWithVieFlush takes it from Blockchain.
	publicKeyBytes := publicKey.ToBytes()
	publicKeyBase58Check := Base58CheckEncode(publicKeyBytes, false, tm.params)
	_, _, _ = _doBasicTransferWithViewFlush(
		tes.t, tm.chain, tm.db, tm.params, senderPkString, publicKeyBase58Check,
		senderPrivString, amountNanos, 11)
}

func (tes *transactionTestSuite) GetAllStateDbEntries(tm *transactionTestMeta) (_dbEntries []*DBEntry) {
	var dbEntries []*DBEntry
	require := require.New(tes.t)

	// Get all state prefixes and sort them.
	var prefixes [][]byte
	for prefix, isState := range StatePrefixes.StatePrefixesMap {
		if !isState {
			continue
		}
		prefixes = append(prefixes, []byte{prefix})
	}
	sort.Slice(prefixes, func(ii, jj int) bool {
		return prefixes[ii][0] < prefixes[jj][0]
	})

	// Fetch all db entries.
	require.NoError(tm.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		for _, prefix := range prefixes {
			it := txn.NewIterator(opts)
			for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
				item := it.Item()
				key := item.Key()
				err := item.Value(func(value []byte) error {
					dbEntries = append(dbEntries, &DBEntry{
						Key:   key,
						Value: value,
					})
					return nil
				})
				if err != nil {
					return err
				}
			}
			it.Close()
		}
		return nil
	}))

	return dbEntries
}

func (tes *transactionTestSuite) compareBeforeAfterDbEntries(beforeDbEntries []*DBEntry, afterDbEntries []*DBEntry) {
	beforeDbEntriesMap := make(map[string]*DBEntry)
	afterDbEntriesMap := make(map[string]*DBEntry)
	for _, dbEntry := range beforeDbEntries {
		beforeDbEntriesMap[string(dbEntry.Key)] = dbEntry
	}
	for _, dbEntry := range afterDbEntries {
		afterDbEntriesMap[string(dbEntry.Key)] = dbEntry
	}

	// Check for db entries present in the beforeDbEntries state. Look for missing entries.
	for key, beforeDbEntry := range beforeDbEntriesMap {
		afterDbEntry, ok := afterDbEntriesMap[key]
		if !ok {
			tes.t.Errorf("compareBeforeAfterDbEntries: Key %v is missing in the db after connect and a disconnect", []byte(key))
			continue
		}
		if !reflect.DeepEqual(beforeDbEntry, afterDbEntry) {
			tes.t.Errorf("compareBeforeAfterDbEntries: Key %v has different values before and after connect and a disconnect: "+
				"before (%v), after (%v)", []byte(key), beforeDbEntry.Value, afterDbEntry.Value)
		}
	}

	// Check for db entries present in the afterDbEntries state. Look for extra entries.
	for key := range afterDbEntriesMap {
		_, ok := beforeDbEntriesMap[key]
		if !ok {
			tes.t.Errorf("compareBeforeAfterDbEntries: Key %v didn't exist in the db before connect and disconnect", []byte(key))
		}
	}
}

func (tes *transactionTestSuite) testConnectBlock(tm *transactionTestMeta, testVectorBlock *transactionTestVectorBlock) (
	_validTransactions []bool, _addedBlock *MsgDeSoBlock) {
	require := require.New(tes.t)

	testVectors := testVectorBlock.testVectors
	validTransactions := make([]bool, len(testVectors))
	for ii, tv := range testVectors {
		glog.Infof("Running test vector: %v", tv.id)
		txn, _expectedErr := tv.getTransaction(tv, tm)
		_, err := tm.mempool.ProcessTransaction(txn, false, false, 0, true)
		utxoView, _err := tm.mempool.GetAugmentedUniversalView()
		require.NoError(_err)
		if _expectedErr != nil {
			if err == nil {
				require.Fail(fmt.Sprintf("Expected error (%v) but got nil", _expectedErr))
			}
			require.Contains(err.Error(), _expectedErr.Error())
			validTransactions[ii] = false
		} else {
			require.NoError(err)
			glog.Infof("Verifying UtxoView entry for test vector: %v", tv.id)
			tv.verifyConnectUtxoViewEntry(tv, tm, utxoView)
			validTransactions[ii] = true
		}
		if tv.connectCallback != nil {
			tv.connectCallback(tv, tm, utxoView)
		}
		tes.addTestVectorToMempool(tv)
	}
	addedBlock, err := tm.miner.MineAndProcessSingleBlock(0, tm.mempool)
	require.NoError(err)
	dbAdapter := tm.chain.NewDbAdapter()

	// Get the map of all testVector Ids that will be overwritten by other testVectors in this block.
	idsToSkip := make(map[transactionTestIdentifier]struct{})
	for ii := 0; ii < len(testVectors); ii++ {
		if dependencyList, exists := tes._testVectorDependency[testVectors[ii].id]; exists {
			for _, dependency := range dependencyList {
				idsToSkip[dependency] = struct{}{}
			}
		}
	}
	for ii, tv := range testVectors {
		if !validTransactions[ii] {
			continue
		}
		// Verify db entries for testVectors that have no later dependencies.
		if _, exists := idsToSkip[tv.id]; !exists {
			glog.Infof("Verifying db entries for test vector: %v", tv.id)
			tv.verifyDbEntry(tv, tm, dbAdapter)
		} else {
			glog.Infof("Skipping verifying db entries for test vector %v because it has later dependencies", tv.id)
		}
	}
	if testVectorBlock.connectCallback != nil {
		testVectorBlock.connectCallback(testVectorBlock, tm)
	}
	tes.moveTestVectorsFromMempoolToDb()

	return validTransactions, addedBlock
}

// Note: snapshot might be broken after calling this function.
func (tes *transactionTestSuite) testDisconnectBlock(tm *transactionTestMeta, testVectorBlock *transactionTestVectorBlock) {
	require := require.New(tes.t)

	// Gather all valid expectedTxns and expectedTvs from the test vector block.
	expectedTvs := []*transactionTestVector{}
	expectedTxns := []*MsgDeSoTxn{}
	for _, tv := range testVectorBlock.testVectors {
		txn, err := tv.getTransaction(tv, tm)
		if err != nil {
			if tv.disconnectCallback != nil {
				glog.Fatalf("testDisconnectBlock: disconnectCallback should be nil for test vectors that fail on connecting")
			}
			continue
		}
		expectedTxns = append(expectedTxns, txn)
		expectedTvs = append(expectedTvs, tv)
	}

	// Get the latest block from the db.
	// Note: we will not pass snapshot to the below functions because we don't really need to, and it might cause some issues.
	lastBlockNode := tm.chain.BlockTip()
	lastBlockHash := lastBlockNode.Hash
	lastBlock, err := GetBlock(lastBlockHash, tm.db, nil)
	utxoOps, err := GetUtxoOperationsForBlock(tm.db, nil, lastBlockHash)
	blockHeight := lastBlock.Header.Height
	require.NoError(err)
	// sanity-check that the last block hash is the same as the last header hash.
	require.Equal(true, bytes.Equal(
		tm.chain.bestChain[len(tm.chain.bestChain)-1].Hash.ToBytes(),
		tm.chain.bestHeaderChain[len(tm.chain.bestHeaderChain)-1].Hash.ToBytes()))
	// Last block shouldn't be nil, and the number of expectedTxns should be the same as in the testVectorBlock + 1,
	// because of the additional block reward.
	require.NotNil(lastBlock)
	require.Equal(len(expectedTxns)+1, len(lastBlock.Txns))

	// Verify that we're trying to disconnect the latest block.
	for ii := 0; ii < len(expectedTxns); ii++ {
		// Make sure that the block transaction metadata matches the expected transaction.
		expectedTxnMetaBytes, err := expectedTxns[ii].TxnMeta.ToBytes(true)
		require.NoError(err)
		blockTxnMetaBytes, err := lastBlock.Txns[ii+1].TxnMeta.ToBytes(true)
		require.NoError(err)
		require.Equal(true, bytes.Equal(expectedTxnMetaBytes, blockTxnMetaBytes))

		// Now make sure the block transaction public key matches the expected transaction.
		require.Equal(true, bytes.Equal(expectedTxns[ii].PublicKey, lastBlock.Txns[ii+1].PublicKey))
	}

	// Disconnect the block on a dummy UtxoView using DisconnectBlock to run all sanity-checks on the block.
	{
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, nil)
		require.NoError(err)
		txHashes, err := ComputeTransactionHashes(lastBlock.Txns)
		require.NoError(err)
		err = utxoView.DisconnectBlock(lastBlock, txHashes, utxoOps, blockHeight)
		require.NoError(err)
	}

	// Disconnect the block transaction by transaction using DisconnectTransaction.
	utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
	require.NoError(err)
	for ii := len(lastBlock.Txns) - 1; ii >= 0; ii-- {
		currentTxn := lastBlock.Txns[ii]
		txnHash := currentTxn.Hash()
		utxoOpsForTxn := utxoOps[ii]
		err := utxoView.DisconnectTransaction(currentTxn, txnHash, utxoOpsForTxn, uint32(blockHeight))
		require.NoError(err)

		// Verify that the UtxoView is correct after disconnecting each transaction. Skip block reward txn.
		if ii > 0 {
			expectedTv := expectedTvs[ii-1]
			expectedTv.verifyDisconnectUtxoViewEntry(expectedTv, tm, utxoView, utxoOpsForTxn)
			if expectedTv.disconnectCallback != nil {
				expectedTv.disconnectCallback(expectedTv, tm, utxoView)
			}
		}
	}

	// Move all disconnected transactions to our transactionTestSuite mempool map.
	// TODO: should we be doing this while we disconnect transaction by transaction?
	require.Equal(0, len(tes._testVectorsInMempool))
	tes.moveTestVectorsFromDbToMempoolForDisconnect(testVectorBlock)

	// Update the tip to point to the parent of this block since we've managed
	// to successfully disconnect it.
	prevHash := lastBlock.Header.PrevBlockHash
	utxoView.TipHash = prevHash

	// Now flush to db.
	require.NoError(utxoView.FlushToDb(blockHeight))

	// Set the best node hash to the new tip.
	if tm.pg != nil {
		require.NoError(tm.pg.UpsertChain(MAIN_CHAIN, prevHash))
	} else {
		require.NoError(PutBestHash(tm.db, nil, prevHash, ChainTypeDeSoBlock))
	}

	// Delete the utxo operations for the blocks we're detaching since we don't need them anymore.
	require.NoError(tm.db.Update(func(txn *badger.Txn) error {
		require.NoError(DeleteUtxoOperationsForBlockWithTxn(txn, nil, lastBlockHash))
		require.NoError(DeleteBlockRewardWithTxn(txn, nil, lastBlock))
		return nil
	}))

	// Revert the detached block's status to StatusHeaderValidated and save the blockNode to the db.
	lastBlockNode.Status = StatusHeaderValidated
	if tm.pg != nil {
		require.NoError(tm.pg.DeleteTransactionsForBlock(lastBlock, lastBlockNode))
		require.NoError(tm.pg.UpsertBlock(lastBlockNode))
	} else {
		require.NoError(PutHeightHashToNodeInfo(tm.db, nil, lastBlockNode, false))
	}

	// TODO: if ever needed we can call tm.chain.eventManager.blockDisconnected() here.

	// Update the block and header metadata chains.
	tm.chain.bestChain = tm.chain.bestChain[:len(tm.chain.bestChain)-1]
	tm.chain.bestHeaderChain = tm.chain.bestHeaderChain[:len(tm.chain.bestHeaderChain)-1]
	delete(tm.chain.bestChainMap, *lastBlockHash)
	delete(tm.chain.bestHeaderChainMap, *lastBlockHash)

	// We don't pass the chain's snapshot above to prevent certain concurrency issues. As a
	// result, we need to reset the snapshot's db cache to get rid of stale data.
	if tm.chain.snapshot != nil {
		tm.chain.snapshot.DatabaseCache = lru.NewKVCache(DatabaseCacheSize)
	}

	// Note that unlike connecting test vectors, when disconnecting, we don't need to verify db entries.
	// This is because, we know that the db state after a disconnect should be the same as before.
	// Because of that, we can run a generic db sweep to verify that the db is in a consistent state
	// after a disconnect. So because of that, developer doesn't need to write a db verifier for disconnects.

	// Call disconnect callback
	if testVectorBlock.disconnectCallback != nil {
		testVectorBlock.disconnectCallback(testVectorBlock, tm)
	}
	tes.removeTestVectorsInMempool()
}

func (tes *transactionTestSuite) addTestVectorToMempool(tv *transactionTestVector) {
	require := require.New(tes.t)
	require.NotNil(tes._testVectorDependency)
	require.Nil(tes._testVectorDependency[tv.id])

	for _, tvInDb := range tes._testVectorsInDb {
		if tvInDb.inputSpace.GetInputType() != tv.inputSpace.GetInputType() {
			continue
		}
		if tvInDb.inputSpace.IsDependency(tv.inputSpace) {
			tes._testVectorDependency[tv.id] = append(tes._testVectorDependency[tv.id], tvInDb.id)
		}
	}
	for _, tvInMempool := range tes._testVectorsInMempool {
		if tvInMempool.inputSpace.GetInputType() != tv.inputSpace.GetInputType() {
			continue
		}
		if tvInMempool.inputSpace.IsDependency(tv.inputSpace) {
			tes._testVectorDependency[tv.id] = append(tes._testVectorDependency[tv.id], tvInMempool.id)
		}
	}
	tes._testVectorsInMempool = append(tes._testVectorsInMempool, tv)
}

func (tes *transactionTestSuite) moveTestVectorsFromMempoolToDb() {

	for ii := 0; ii < len(tes._testVectorsInMempool); ii++ {
		tes._testVectorsInDb = append(tes._testVectorsInDb, tes._testVectorsInMempool[ii])
	}
	tes._testVectorsInMempool = []*transactionTestVector{}
}

func (tes *transactionTestSuite) moveTestVectorsFromDbToMempoolForDisconnect(tvb *transactionTestVectorBlock) {

	blocksTestVectors := make(map[transactionTestIdentifier]struct{})
	for _, tv := range tvb.testVectors {
		blocksTestVectors[tv.id] = struct{}{}
	}
	smallestIndex := -1
	for ii := 0; ii < len(tes._testVectorsInDb); ii++ {
		if _, exists := blocksTestVectors[tes._testVectorsInDb[ii].id]; exists {
			tes._testVectorsInMempool = append(tes._testVectorsInMempool, tes._testVectorsInDb[ii])
			if smallestIndex == -1 {
				smallestIndex = ii
			}
		}
	}
	tes._testVectorsInDb = tes._testVectorsInDb[:smallestIndex]
}

func (tes *transactionTestSuite) removeTestVectorsInMempool() {
	for _, tv := range tes._testVectorsInMempool {
		delete(tes._testVectorDependency, tv.id)
	}
	tes._testVectorsInMempool = []*transactionTestVector{}
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

	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
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

	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs), len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	for ii := len(txn.TxInputs); ii < len(txn.TxInputs)+len(txn.TxOutputs); ii++ {
		require.Equal(OperationTypeAddUtxo, utxoOps[ii].Type)
	}

	require.NoError(utxoView.FlushToDb(0))

	return utxoOps, txn, blockHeight
}

func _registerOrTransferWithTestMeta(testMeta *TestMeta, username string,
	senderPk string, recipientPk string, senderPriv string, amountToSend uint64) {

	tbc := testMeta.tbc
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, tbc.chain, nil, senderPk))

	currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
		testMeta.t, tbc.chain, tbc.db, tbc.params, senderPk, recipientPk,
		senderPriv, amountToSend, 11 /*feerate*/)

	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
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

	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)

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
		OperationTypeUpdateGlobalParams, utxoOps[len(utxoOps)-1].Type)
	if flushToDb {
		require.NoError(utxoView.FlushToDb(0))
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
		_getBalance(testMeta.t, testMeta.tbc.chain, nil, updaterPkBase58Check))

	currentOps, currentTxn, _, err := _updateGlobalParamsEntry(
		testMeta.t, testMeta.tbc.chain, testMeta.tbc.db, testMeta.tbc.params,
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

type TestBlockChain struct {
	t        *testing.T
	chain    *Blockchain
	db       *badger.DB
	mempool  *DeSoMempool
	miner    *DeSoMiner
	params   *DeSoParams
	postgres *Postgres
}

// Sign the transaciton based on the signature type.
func signTransaction(t *testing.T, txn *MsgDeSoTxn, signType signatureType, privKeyBase58Check string) *MsgDeSoTxn {
	t.Helper()
	require := require.New(t)

	// Standard ECDSA signature, used by default for signing transactions
	signECDSA := func(txn *MsgDeSoTxn) {
		privKeyBytes, _, err := Base58CheckDecode(privKeyBase58Check)
		require.NoError(err)
		privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
		txnSignature, err := txn.Sign(privKey)
		require.NoError(err)
		txn.Signature.SetSignature(txnSignature)
	}

	// DER Signature for transactions
	signStandardDER := func(txn *MsgDeSoTxn) {
		privKeyBytes, _, err := Base58CheckDecode(privKeyBase58Check)
		require.NoError(err)
		privateKey, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
		if txn.ExtraData == nil {
			txn.ExtraData = make(map[string][]byte)
		}
		txn.ExtraData[DerivedPublicKey] = publicKey.SerializeCompressed()
		txnSignature, err := txn.Sign(privateKey)
		require.NoError(err)
		txn.Signature.SetSignature(txnSignature)
	}

	// DeSoDER signature for signing transactions
	signDeSoDER := func(txn *MsgDeSoTxn) {
		privKeyBytes, _, err := Base58CheckDecode(privKeyBase58Check)
		require.NoError(err)
		privateKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)

		txBytes, err := txn.ToBytes(true /*preSignature*/)
		require.NoError(err)
		txHash := Sha256DoubleHash(txBytes)[:]

		desoSignature, err := SignRecoverable(txHash, privateKey)
		require.NoError(err)
		txn.Signature = *desoSignature
	}

	switch signType {
	case ECDSA:
		signECDSA(txn)

	case STANDARD_DER:
		signStandardDER(txn)

	case DESO_DER:
		signDeSoDER(txn)
	// randomly choose between Standard DER and Deso DER
	case RANDOM_DERIVED_SIGN:
		pickSign := rand.Int() % 2
		if pickSign == 1 {
			signStandardDER(txn)
		} else {
			signDeSoDER(txn)
		}
	// Invalid signature type.
	default:
		t.Fail()
	}
	return txn

}

func (tb *TestBlockChain) mempoolProcessTransaction(txn *MsgDeSoTxn) (_mempoolTxs []*MempoolTx, _err error) {
	require := require.New(tb.t)
	tb.t.Helper()
	mempoolTxs, err := tb.mempool.processTransaction(txn, true, true, 0, true)
	if err != nil {
		return nil, err
	}
	require.Equal(1, len(mempoolTxs))
	return mempoolTxs, err
}

func (tb *TestBlockChain) connectTransaction(txn *MsgDeSoTxn) error {
	tb.t.Helper()
	utxoView, _ := NewUtxoView(tb.chain.db, tb.chain.params, tb.chain.postgres, tb.chain.snapshot)
	txHash := txn.Hash()
	blockHeight := tb.chain.blockTip().Height + 1
	_, _, _, _, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
			true /*verifySignatures*/, false /*ignoreUtxos*/)
	return err
}

func (tb *TestBlockChain) addTxnInputs(txn *MsgDeSoTxn) {
	tb.t.Helper()
	require := require.New(tb.t)
	// testChain.buildTransaction(txn, recipientPrivString)
	totalInput, spendAmount, changeAmount, fees, err :=
		tb.chain.AddInputsAndChangeToTransaction(txn, 10, nil)
	require.NoError(err)
	require.Equal(totalInput, spendAmount+changeAmount+fees)
	require.Greater(totalInput, uint64(0))

	// Sign the transaction with the recipient's key rather than the
	// sender's key.
	//txn.Signature.SetSignature(generateTxnSign(tb.t, txn, keyToSignTxn))
}

func (tb *TestBlockChain) mineBlock() {
	tb.t.Helper()
	require := require.New(tb.t)
	// Mine blocks to give the sender some DeSo.
	_, err := tb.miner.MineAndProcessSingleBlock(0 /*threadIndex*/, tb.mempool)
	require.NoError(err)
}

type TestMeta struct {
	t                      *testing.T
	tbc                    *TestBlockChain
	txnOps                 [][]*UtxoOperation
	txns                   []*MsgDeSoTxn
	expectedSenderBalances []uint64
	savedHeight            uint32
}

func _executeAllTestRollbackAndFlush(testMeta *TestMeta) {
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
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

		tbc := testMeta.tbc
		utxoView, err := NewUtxoView(tbc.db, tbc.params,
			tbc.chain.postgres, tbc.chain.snapshot)
		require.NoError(testMeta.t, err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps,
			testMeta.savedHeight)
		require.NoError(testMeta.t, err)

		blockHeight := uint64(tbc.chain.BlockTip().Height)
		require.NoError(testMeta.t, utxoView.FlushToDb(blockHeight+1))

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(
			testMeta.t,
			testMeta.expectedSenderBalances[backwardIter],
			_getBalance(testMeta.t, tbc.chain, nil, PkToStringTestnet(currentTxn.PublicKey)),
		)
	}
}

func _applyTestMetaTxnsToMempool(testMeta *TestMeta) {
	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	tbc := testMeta.tbc
	for ii, tx := range testMeta.txns {
		require.Equal(
			testMeta.t,
			testMeta.expectedSenderBalances[ii],
			_getBalance(testMeta.t, tbc.chain, tbc.mempool, PkToStringTestnet(tx.PublicKey)))

		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		_, err := tbc.mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(testMeta.t, err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}
}

func _applyTestMetaTxnsToViewAndFlush(testMeta *TestMeta) {
	// Apply all the transactions to a view and flush the view to the db.
	tbc := testMeta.tbc
	utxoView, err := NewUtxoView(tbc.db, tbc.params, tbc.chain.postgres, tbc.chain.snapshot)
	require.NoError(testMeta.t, err)
	for ii, txn := range testMeta.txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := tbc.chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.NoError(testMeta.t, err)
	}
	// Flush the utxoView after having added all the transactions.
	blockHeight := uint64(tbc.chain.BlockTip().Height)
	require.NoError(testMeta.t, utxoView.FlushToDb(blockHeight+1))
}

func _disconnectTestMetaTxnsFromViewAndFlush(testMeta *TestMeta) {
	// Disonnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	tbc := testMeta.tbc
	utxoView, err := NewUtxoView(tbc.db, tbc.params, tbc.chain.postgres, tbc.chain.snapshot)
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
	blockHeight := uint64(tbc.chain.BlockTip().Height)
	require.NoError(testMeta.t, utxoView.FlushToDb(blockHeight))
}

func _connectBlockThenDisconnectBlockAndFlush(testMeta *TestMeta) {
	tbc := testMeta.tbc
	// all those transactions in it.
	block, err := tbc.miner.MineAndProcessSingleBlock(0 /*threadIndex*/, tbc.mempool)
	require.NoError(testMeta.t, err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(testMeta.t, len(testMeta.txnOps)+1, len(block.Txns))

	// Roll back the block and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(tbc.db, tbc.params, tbc.chain.postgres, tbc.chain.snapshot)
		require.NoError(testMeta.t, err)

		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := block.Header.Hash()
		require.NoError(testMeta.t, err)
		utxoOps, err := GetUtxoOperationsForBlock(tbc.db, tbc.chain.snapshot, hash)
		require.NoError(testMeta.t, err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(block.Txns)
		require.NoError(testMeta.t, err)
		blockHeight := uint64(tbc.chain.BlockTip().Height)
		require.NoError(testMeta.t, utxoView.DisconnectBlock(block, txHashes, utxoOps, blockHeight))

		// Flushing the view after applying and rolling back should work.
		require.NoError(testMeta.t, utxoView.FlushToDb(blockHeight))
	}
}

func TestUpdateGlobalParams(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	chain, params, db := NewLowDifficultyBlockchain()
	postgres := chain.postgres
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_, _ = mempool, miner

	// Set the founder equal to the moneyPk
	params.ExtraRegtestParamUpdaterKeys = make(map[PkMapKey]bool)
	params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(MustBase58CheckDecode(moneyPkString))] = true

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

		utxoView, err := NewUtxoView(db, params, postgres, chain.snapshot)
		require.NoError(err)
		txnSize := getTxnSize(*updateGlobalParamsTxn)
		blockHeight := chain.blockTip().Height + 1
		utxoOps, totalInput, totalOutput, fees, err :=
			utxoView.ConnectTransaction(updateGlobalParamsTxn,
				updateGlobalParamsTxn.Hash(), txnSize, blockHeight, true, /*verifySignature*/
				false /*ignoreUtxos*/)
		require.NoError(err)
		_, _, _, _ = utxoOps, totalInput, totalOutput, fees
		require.NoError(utxoView.FlushToDb(0))

		// Verify that utxoView and db reflect the new global parmas entry.
		expectedGlobalParams := GlobalParamsEntry{
			USDCentsPerBitcoin:          uint64(newUSDCentsPerBitcoin),
			MinimumNetworkFeeNanosPerKB: uint64(newMinimumNetworkFeeNanosPerKB),
			CreateProfileFeeNanos:       uint64(newCreateProfileFeeNanos),
			CreateNFTFeeNanos:           uint64(newCreateNFTFeeNanos),
			MaxCopiesPerNFT:             123,
		}
		require.Equal(DbGetGlobalParamsEntry(utxoView.Handle, chain.snapshot), &expectedGlobalParams)

		require.Equal(utxoView.GlobalParamsEntry, &expectedGlobalParams)

		// Check the balance of the updater after this txn
		require.NotEqual(0, _getBalance(t, chain, nil, moneyPkString))
	}

	{

		// Save the prev global params entry so we can check it after disconnect.
		prevGlobalParams := DbGetGlobalParamsEntry(db, chain.snapshot)

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

		require.Equal(DbGetGlobalParamsEntry(db, chain.snapshot), expectedGlobalParams)

		// Now let's do a disconnect and make sure the values reflect the previous entry.
		utxoView, err := NewUtxoView(db, params, postgres, chain.snapshot)
		require.NoError(err)
		blockHeight := chain.blockTip().Height + 1
		utxoView.DisconnectTransaction(
			updateGlobalParamsTxn, updateGlobalParamsTxn.Hash(), utxoOps, blockHeight)

		require.NoError(utxoView.FlushToDb(0))

		require.Equal(DbGetGlobalParamsEntry(utxoView.Handle, chain.snapshot), prevGlobalParams)
		require.Equal(utxoView.GlobalParamsEntry, prevGlobalParams)

		// Check the balance of the updater after this txn
		require.NotEqual(0, _getBalance(t, chain, nil, moneyPkString))
	}
}

// Returns a test blockchain (block with testing parameters), with two blocks mined.
func NewTestBlockChain(t *testing.T) *TestBlockChain {
	t.Helper()

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	return &TestBlockChain{
		chain:    chain,
		db:       db,
		mempool:  mempool,
		miner:    miner,
		params:   params,
		postgres: chain.postgres,
	}
}

// Processes the key string into byte array.
func ProcessKeyBytes(t *testing.T, keyString string) []byte {
	t.Helper()
	require := require.New(t)
	keyBytes, _, err := Base58CheckDecode(keyString)
	require.NoError(err)
	return keyBytes
}

// validates totalInput, spendAmount, changeAmount, fees and error result
// from chain.AddInputsAndChangeToTransaction
func TestVerifyInputFeeSpendValues(t *testing.T) {

	require := require.New(t)

	tb := NewTestBlockChain(t)
	tb.mineBlock()
	tb.mineBlock()

	senderPkBytes := ProcessKeyBytes(t, senderPkString)
	recipientPkBytes := ProcessKeyBytes(t, recipientPkString)

	testCases := []struct {
		// description of the test case
		description string
		// Deso transaction data, to be used as a parameter for AddInputsAndChangeToTransaction
		txnSpend []*DeSoOutput
		// flag indicating whether the test case is expected to fail
		expectedToFail bool
		// expected error if the test is expected to fail.
		// set to nil if the test is expected to pass.
		expectedErr error
		// expected totalInput as calcualated by AddInputsAndChangeToTransaction
		// InputComputation is an important part of the transaction.
		// Blockchains compose the inputs containing sufficient balance
		// when a transaction is proposef.
		// It verifies whether sufficient balance (a.k.a input) to complete the transaction exists.
		expectedTotalInput uint64
		// Total intended spend amount as specified by the user + transaction fee.
		// The input computed should be greater than or equal to the expected spend amount.
		// if not it indicates insufficient balance.
		expectedSpendAmount uint64
		// Change is returned if there's more balance in the inputs than the specified spend amount.
		expectedChangeAmount uint64
		// expected transaction fees.
		expectedFees uint64
	}{
		// test case 1
		// simple test case in only one value in the transaction spend array.
		{
			description: "Case 1: Simple spend and fee test case",
			txnSpend: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			// test is expected to pass
			expectedToFail: false,
			expectedErr:    nil,
			// expected total input, spend amount, change amount, fee
			expectedTotalInput:   1000000000,
			expectedSpendAmount:  1,
			expectedChangeAmount: 999999998,
			expectedFees:         1,
		},
		// test case 2
		// adding two values to txnSpend array.
		// verifying whether the sum of the values in the DesoOutput array
		// is taken into account for
		{
			description: "Case 2: Case with two spend requests",
			txnSpend: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 3,
				},
			},
			// test is expected to pass
			expectedToFail: false,
			expectedErr:    nil,
			// expected total input, spend amount, change amount, fee
			expectedTotalInput:   1000000000,
			expectedSpendAmount:  4,
			expectedChangeAmount: 999999994,
			expectedFees:         2,
		},
		// test case 3
		{
			description: "Case 3: Testing with four spend requests.",
			txnSpend: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 3,
				},
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 11,
				},
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 20,
				},
			},
			// test is expected to pass.
			expectedToFail: false,
			expectedErr:    nil,
			// expected total input, spend amount, change amount, fee
			expectedTotalInput:   1000000000,
			expectedSpendAmount:  35,
			expectedChangeAmount: 999999963,
			expectedFees:         2,
		},
		// test case 4
		{
			description: "case 4: Testing case with spend equal to the available balance.",
			txnSpend: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1000000000,
				},
			},
			// test is expected to fail
			expectedToFail:       true,
			expectedErr:          fmt.Errorf("Total input 1000000000 is not sufficient to cover the spend amount (=1000000000) plus the fee (=1, feerate=10, txsize=185), total=1000000001"),
			expectedTotalInput:   0,
			expectedSpendAmount:  0,
			expectedChangeAmount: 0,
			expectedFees:         0,
		},
		// test case 5
		{
			description: "Case 5: Case where single entry of the DeSoOutput for the spend is greater than the avaialble input balance.",
			txnSpend: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 2000000000,
				},
			},
			// test is expected to fail
			expectedToFail:       true,
			expectedErr:          fmt.Errorf("Total input 1000000000 is not sufficient to cover the spend amount (=2000000000) plus the fee (=1, feerate=10, txsize=185), total=2000000001"),
			expectedTotalInput:   0,
			expectedSpendAmount:  0,
			expectedChangeAmount: 0,
			expectedFees:         0,
		},
		// test case 6
		{
			description: "Case 6: Testing sum of four test cases.",
			txnSpend: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 500000000,
				},
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 400000000,
				},
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 300000000,
				},
			},
			// test is expected to fail
			expectedToFail:       true,
			expectedErr:          fmt.Errorf("Total input 1000000000 is not sufficient to cover the spend amount (=1200000000) plus the fee (=2, feerate=10, txsize=261), total=1200000002"),
			expectedTotalInput:   0,
			expectedSpendAmount:  0,
			expectedChangeAmount: 0,
			expectedFees:         0,
		},
	}

	for i := 0; i < len(testCases); i++ {
		txn := &MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs:  []*DeSoInput{},
			TxOutputs: testCases[i].txnSpend,
			PublicKey: senderPkBytes,
			TxnMeta:   &BasicTransferMetadata{},
		}

		totalInput, spendAmount, changeAmount, fees, err :=
			tb.chain.AddInputsAndChangeToTransaction(txn, 10, nil)

		// validate error message and continue if the test is expected to fail
		if testCases[i].expectedToFail {
			require.Error(err)
			require.Contains(err.Error(), testCases[i].expectedErr.Error())
			continue
		}

		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		require.Equal(testCases[i].expectedTotalInput, totalInput)
		require.Equal(testCases[i].expectedSpendAmount, spendAmount)
		require.Equal(testCases[i].expectedChangeAmount, changeAmount)
		require.Equal(testCases[i].expectedFees, fees)
	}
}

func TestBasicTransfer(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	tb := NewTestBlockChain(t)
	// mine two blocks for the sender to have some balance.
	// mines blocks on the test block chain
	tb.mineBlock()
	tb.mineBlock()

	senderPkBytes := ProcessKeyBytes(t, senderPkString)
	recipientPkBytes := ProcessKeyBytes(t, recipientPkString)

	// A basic transfer with input value set should fail during AddInputsAndChangeToTransaction
	t.Run("txn_with_inputs_should_fail", func(t *testing.T) {
		txn := &MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs: []*DeSoInput{{
				TxID: BlockHash{},
			}},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPkBytes,
			TxnMeta:   &BasicTransferMetadata{},
		}

		_, _, _, _, err :=
			tb.chain.AddInputsAndChangeToTransaction(txn, 10, nil)
		require.Error(err)

		require.Contains(err.Error(), fmt.Sprintf("_computeInputsForTxn: Transaction passed in "+
			"txArg should not have any inputs set but found the found %d inputs",
			len(txn.TxInputs)))
	})

	// A basic transfer whose input public keys differ from the
	// transaction-level public key should fail.
	t.Run("txn_public_txb_keys_differ", func(t *testing.T) {
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

		// At this point the txn has inputs for senderPkString. Change
		// the public key to recipientPkString and sign it with the
		// recipientPrivString.
		txn.PublicKey = recipientPkBytes
		// build transaction with inputs ans sign the transaction using the recipient string

		// Connect the transaction
		err := tb.connectTransaction(txn)
		// Expected error
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey)
	})

	// Just a basic transfer with a bad signature.
	t.Run("txn_basic_bad_signature", func(t *testing.T) {
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

		// Sign the transaction with the recipient's key rather than the
		// sender's key.
		signTransaction(t, txn, ECDSA, recipientPrivString)
		// Connect the transaction
		err := tb.connectTransaction(txn)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidTransactionSignature)
	})

	// A block reward with a bad signature should fail.
	t.Run("txn_block_reward_bad_sign", func(t *testing.T) {
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
		// Sign the transaction with the recipient's key rather than the
		// sender's key.
		signTransaction(t, txn, ECDSA, senderPrivString)
		// Connect the transaction
		err := tb.connectTransaction(txn)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardTxnNotAllowedToHaveSignature)
	})

	// A block reward with an input, even if it's signed legitimately,
	// should fail.
	t.Run("txn_reward_with_input", func(t *testing.T) {
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

		// Sign the transaction with the recipient's key rather than the
		// sender's key.
		signTransaction(t, txn, ECDSA, senderPrivString)
		// Connect the transaction
		err := tb.connectTransaction(txn)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardTxnNotAllowedToHaveSignature)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardTxnNotAllowedToHaveInputs)
	})

	allowedBlockReward := CalcBlockRewardNanos(tb.chain.blockTip().Height)
	assert.Equal(int64(allowedBlockReward), int64(1*NanosPerUnit))
	blockToMine, _, _, err := tb.miner._getBlockToMine(0 /*threadIndex*/)
	require.NoError(err)

	// A block with too much block reward should fail.

	t.Run("txn_block_too_much_reward", func(t *testing.T) {
		blockToMine.Txns[0].TxOutputs[0].AmountNanos = allowedBlockReward + 1
		// One iteration should be sufficient to find us a good block.
		_, bestNonce, err := FindLowestHash(blockToMine.Header, 10000)
		require.NoError(err)
		blockToMine.Header.Nonce = bestNonce

		txHashes, err := ComputeTransactionHashes(blockToMine.Txns)
		require.NoError(err)
		utxoView, _ := NewUtxoView(tb.db, tb.params, tb.postgres, tb.chain.snapshot)
		_, err = utxoView.ConnectBlock(blockToMine, txHashes, true /*verifySignatures*/, nil, 0)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardExceedsMaxAllowed)
	})

	// A block with less than the max block reward should be OK.
	t.Run("txn_block_less_max_reward", func(t *testing.T) {
		blockToMine.Txns[0].TxOutputs[0].AmountNanos = allowedBlockReward - 1
		// One iteration should be sufficient to find us a good block.
		_, bestNonce, err := FindLowestHash(blockToMine.Header, 10000)
		require.NoError(err)
		blockToMine.Header.Nonce = bestNonce

		txHashes, err := ComputeTransactionHashes(blockToMine.Txns)
		require.NoError(err)
		utxoView, _ := NewUtxoView(tb.db, tb.params, tb.postgres, tb.chain.snapshot)
		_, err = utxoView.ConnectBlock(blockToMine, txHashes, true /*verifySignatures*/, nil, 0)
		require.NoError(err)
	})
}

// Tests and validates the error values returned Mempool Transaction process.
func TestMempoolProcessError(t *testing.T) {
	require := require.New(t)

	tb := NewTestBlockChain(t)

	senderPkBytes := ProcessKeyBytes(t, senderPkString)
	recipientPkBytes := ProcessKeyBytes(t, recipientPkString)

	testCases := []struct {
		signType                  signatureType
		signaturePrivateKeyBase58 string
		expectedError             RuleError
	}{
		// Try signing the basic transfer with the owner's private key.
		// Test case 1
		{

			signType:                  STANDARD_DER,
			expectedError:             RuleErrorDerivedKeyNotAuthorized,
			signaturePrivateKeyBase58: senderPrivString,
		},
		// Test case 2
		{

			signType:                  DESO_DER,
			expectedError:             RuleErrorDerivedKeyNotAuthorized,
			signaturePrivateKeyBase58: senderPrivString,
		},
		// Test case 3
		// Try signing the basic transfer with a random private key.
		{

			signType:                  ECDSA,
			expectedError:             RuleErrorInvalidTransactionSignature,
			signaturePrivateKeyBase58: generateRandomPrivateKeyBase58(t, tb),
		},
		// Test case 4
		{

			signType:                  STANDARD_DER,
			expectedError:             RuleErrorDerivedKeyNotAuthorized,
			signaturePrivateKeyBase58: generateRandomPrivateKeyBase58(t, tb),
		},
		// Test case 5
		{
			signType:                  DESO_DER,
			expectedError:             RuleErrorDerivedKeyNotAuthorized,
			signaturePrivateKeyBase58: generateRandomPrivateKeyBase58(t, tb),
		},
	}

	for i := 0; i < len(testCases); i++ {
		tc := testCases[i]
		txnGen := basicTestTxn{senderPublicKeyBytes: senderPkBytes,
			receiverPublicKeyBytes: recipientPkBytes, amountNanos: 1}
		txn := txnGen.generateTxn(t, tb)
		signTransaction(tb.t, txn, tc.signType, tc.signaturePrivateKeyBase58)

		_, err := tb.mempool.processTransaction(txn, true, true, 0, true)
		require.Error(err)
		require.Contains(err.Error(), testCases[i].expectedError.Error())
	}
}

// Tests and validates the error values returned Mempool Derived Key Transaction process.
func TestMempoolProcessDerivedKeyTransactionError(t *testing.T) {
	require := require.New(t)

	tb := NewTestBlockChain(t)

	transactionSpendingLimit := &TransactionSpendingLimit{
		GlobalDESOLimit:              100,
		TransactionCountLimitMap:     map[TxnType]uint64{TxnTypeAuthorizeDerivedKey: 1},
		CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
		DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
		NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
	}

	// Creating an derived key entry for the tests.
	transactionSpendingLimitWithDerivedKeyEntry := &TransactionSpendingLimit{
		GlobalDESOLimit:              100,
		TransactionCountLimitMap:     map[TxnType]uint64{TxnTypeAuthorizeDerivedKey: 1, TxnTypeBasicTransfer: 2},
		CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
		DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
		NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
	}

	dkTxn := derivedKeyTestTxn{
		transactionSpendingLimit: transactionSpendingLimitWithDerivedKeyEntry,
	}

	derivedKeyTxn := dkTxn.generateTxn(t, tb)

	derivedPrivBase58CheckWithEntry := Base58CheckEncode(dkTxn.getDerivedPrivKey(t).Serialize(),
		true, tb.params)
	signTransaction(t, derivedKeyTxn, ECDSA, senderPrivString)
	_, err := tb.mempoolProcessTransaction(derivedKeyTxn)
	require.NoError(err)

	testCases := []struct {
		signType                  signatureType
		signaturePrivateKeyBase58 string
		transactionSpendingLimit  *TransactionSpendingLimit
		expectedError             RuleError
	}{
		// Try signing the basic transfer with the owner's private key.
		// Test case 1
		{

			signType:                  ECDSA,
			transactionSpendingLimit:  transactionSpendingLimit,
			expectedError:             RuleErrorInvalidTransactionSignature,
			signaturePrivateKeyBase58: "",
		},
		// Test case 2
		{

			signType:                  DESO_DER,
			transactionSpendingLimit:  transactionSpendingLimit,
			expectedError:             RuleErrorInvalidTransactionSignature,
			signaturePrivateKeyBase58: senderPrivString,
		},
		// Test case 3
		// Try signing the basic transfer with a random private key.
		{

			signType:                  STANDARD_DER,
			transactionSpendingLimit:  transactionSpendingLimit,
			expectedError:             RuleErrorDerivedKeyNotAuthorized,
			signaturePrivateKeyBase58: senderPrivString,
		},
		// Test case 4
		{

			signType:                  ECDSA,
			transactionSpendingLimit:  transactionSpendingLimit,
			expectedError:             RuleErrorInvalidTransactionSignature,
			signaturePrivateKeyBase58: generateRandomPrivateKeyBase58(t, tb),
		},
		{

			signType:                  STANDARD_DER,
			transactionSpendingLimit:  transactionSpendingLimit,
			expectedError:             RuleErrorDerivedKeyNotAuthorized,
			signaturePrivateKeyBase58: generateRandomPrivateKeyBase58(t, tb),
		},
		// Test case 5
		{
			signType:                  DESO_DER,
			transactionSpendingLimit:  transactionSpendingLimit,
			expectedError:             RuleErrorDerivedKeyNotAuthorized,
			signaturePrivateKeyBase58: generateRandomPrivateKeyBase58(t, tb),
		},
		// Third scenario, there exists an authorize derived key entry
		// and we're signing a basic transfer.
		// Sign the basic transfer with the sender's private key.
		// Test case 6
		{

			signType:                  STANDARD_DER,
			transactionSpendingLimit:  transactionSpendingLimit,
			signaturePrivateKeyBase58: senderPrivString,
			expectedError:             RuleErrorDerivedKeyNotAuthorized,
		},
		// Test case 7
		{
			signType:                  DESO_DER,
			transactionSpendingLimit:  transactionSpendingLimit,
			signaturePrivateKeyBase58: senderPrivString,
			expectedError:             RuleErrorDerivedKeyNotAuthorized,
		},
		// Test case 8
		{
			signType:                  ECDSA,
			transactionSpendingLimit:  transactionSpendingLimit,
			signaturePrivateKeyBase58: derivedPrivBase58CheckWithEntry,
			expectedError:             RuleErrorInvalidTransactionSignature,
		},
		// sign using random private key
		// Test case 9
		{

			signType:                  ECDSA,
			transactionSpendingLimit:  transactionSpendingLimit,
			signaturePrivateKeyBase58: generateRandomPrivateKeyBase58(t, tb),
			expectedError:             RuleErrorInvalidTransactionSignature,
		},
		// Test case 10
		{

			signType:                  STANDARD_DER,
			transactionSpendingLimit:  transactionSpendingLimit,
			signaturePrivateKeyBase58: generateRandomPrivateKeyBase58(t, tb),
			expectedError:             RuleErrorDerivedKeyNotAuthorized,
		},
		// Test case 11
		{
			signType:                  DESO_DER,
			transactionSpendingLimit:  transactionSpendingLimit,
			signaturePrivateKeyBase58: generateRandomPrivateKeyBase58(t, tb),
			expectedError:             RuleErrorDerivedKeyNotAuthorized,
		},
	}

	for i := 0; i < len(testCases); i++ {
		dKeytxn := derivedKeyTestTxn{transactionSpendingLimit: testCases[i].transactionSpendingLimit,
			senderPublicKey: senderPkString}

		signaturePrivateKeyBase58 := testCases[i].signaturePrivateKeyBase58
		derivedKeyTxn, derivedPriv := dKeytxn.doDerivedKeyTransaction(t, tb)

		var signerPrivBase58 string
		if signaturePrivateKeyBase58 != "" {
			signerPrivBase58 = signaturePrivateKeyBase58
		} else {
			signerPrivBase58 = Base58CheckEncode(derivedPriv.Serialize(), true, tb.params)
		}
		signTransaction(t, derivedKeyTxn, testCases[i].signType, signerPrivBase58)
		_, err := tb.mempool.processTransaction(derivedKeyTxn, true, true, 0, true)
		require.Error(err)
		require.Contains(err.Error(), testCases[i].expectedError.Error())
	}
}

// Create a derived key transaction based on the provided spending limit.

// TestBasicTransferSignatures thoroughly tests all possible ways to sign a DeSo transaction.
// There are three available signature schemas that are accepted by the DeSo blockchain:
//
//	(1) Transaction signed by user's main public key
//	(2) Transaction signed by user's derived key with "DerivedPublicKey" passed in ExtraData
//	(3) Transaction signed by user's derived key using DESO-DER signature standard.
//
// We will try all these schemas while running three main tests scenarios:
//   - try signing and processing a basicTransfer
//   - try signing and processing a authorizeDerivedKey
//   - try signing and processing a authorizeDerivedKey followed by a basicTransfer
//
// We use basicTransfer as a placeholder for a normal DeSo transaction (alternatively, we could have used a post,
// follow, nft, etc transaction). For each scenario we try signing the transaction with either user's main public
// key, a derived key, or a random key. Basically, we try every possible context in which a transaction can be signed.
func TestBasicTransferSignatures(t *testing.T) {
	require := require.New(t)

	tb := NewTestBlockChain(t)

	tb.params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)
	tb.params.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight = uint32(0)
	tb.params.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight = uint32(0)
	// Make sure encoder migrations are not triggered yet.
	GlobalDeSoParams = *tb.params
	GlobalDeSoParams.ForkHeights.DeSoUnlimitedDerivedKeysBlockHeight = uint32(100)
	for ii := range GlobalDeSoParams.EncoderMigrationHeightsList {
		if GlobalDeSoParams.EncoderMigrationHeightsList[ii].Version == 0 {
			continue
		}
		GlobalDeSoParams.EncoderMigrationHeightsList[ii].Height = 100
	}

	_ = tb.db

	senderPkBytes := ProcessKeyBytes(t, senderPkString)
	recipientPkBytes := ProcessKeyBytes(t, recipientPkString)

	tb.mineBlock()
	tb.mineBlock()

	var allTxns []*MsgDeSoTxn
	// Add a transaction to the mempool.
	// Mine block with the latest mempool. Validate that the persisted transaction signatures match original transactions.
	mineBlockAndVerifySignatures := func(allTxns []*MsgDeSoTxn) {
		block, err := tb.miner.MineAndProcessSingleBlock(0, tb.mempool)
		blockHash, err := block.Hash()
		require.NoError(err)
		require.NoError(err)
		require.Equal(1+len(allTxns), len(block.Txns))
		for ii := 1; ii < len(block.Txns); ii++ {
			txn := allTxns[ii-1]
			transactionHash := allTxns[ii-1].Hash()
			require.Equal(true, reflect.DeepEqual(transactionHash.ToBytes(), block.Txns[ii].Hash().ToBytes()))

			// Now fetch all transactions from the db and verify their signatures have been properly persisted.
			if tb.postgres != nil {
				pgTxn := tb.postgres.GetTransactionByHash(transactionHash)
				require.Equal(true, reflect.DeepEqual(txn.Signature.Sign.R.Bytes(), HashToBigint(pgTxn.R).Bytes()))
				require.Equal(true, reflect.DeepEqual(txn.Signature.Sign.S.Bytes(), HashToBigint(pgTxn.S).Bytes()))
				require.Equal(txn.Signature.RecoveryId, byte(pgTxn.RecoveryId))
				require.Equal(txn.Signature.IsRecoverable, pgTxn.IsRecoverable)
			} else {
				dbBlock, err := GetBlock(blockHash, tb.db, tb.chain.Snapshot())
				require.NoError(err)
				for _, blockTxn := range dbBlock.Txns {
					if reflect.DeepEqual(transactionHash.ToBytes(), blockTxn.Hash().ToBytes()) {
						require.Equal(true, reflect.DeepEqual(txn.Signature.Sign.R.Bytes(), blockTxn.Signature.Sign.R.Bytes()))
						require.Equal(true, reflect.DeepEqual(txn.Signature.Sign.S.Bytes(), blockTxn.Signature.Sign.S.Bytes()))
						require.Equal(txn.Signature.RecoveryId, blockTxn.Signature.RecoveryId)
						require.Equal(txn.Signature.IsRecoverable, blockTxn.Signature.IsRecoverable)
					}
				}
			}
		}
	}

	transactionSpendingLimitWithDerivedKeyEntry := &TransactionSpendingLimit{
		GlobalDESOLimit:              100,
		TransactionCountLimitMap:     map[TxnType]uint64{TxnTypeAuthorizeDerivedKey: 1, TxnTypeBasicTransfer: 2},
		CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
		DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
		NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
	}

	dkTxn := derivedKeyTestTxn{
		transactionSpendingLimit: transactionSpendingLimitWithDerivedKeyEntry,
	}

	derivedKeyTxn := dkTxn.generateTxn(t, tb)

	derivedPrivBase58CheckWithEntry := Base58CheckEncode(dkTxn.getDerivedPrivKey(t).Serialize(), true, tb.params)
	signTransaction(t, derivedKeyTxn, ECDSA, senderPrivString)
	_, err := tb.mempoolProcessTransaction(derivedKeyTxn)
	require.NoError(err)

	testCases := []struct {
		transactionGen   testTxn
		signType         signatureType
		signingKeyBase58 string
	}{
		{
			transactionGen: basicTestTxn{
				senderPublicKeyBytes:   senderPkBytes,
				receiverPublicKeyBytes: recipientPkBytes,
				amountNanos:            1,
			},
			signType:         ECDSA,
			signingKeyBase58: senderPrivString,
		},
		{
			transactionGen: derivedKeyTestTxn{
				transactionSpendingLimit: &TransactionSpendingLimit{
					GlobalDESOLimit:              100,
					TransactionCountLimitMap:     map[TxnType]uint64{TxnTypeAuthorizeDerivedKey: 1},
					CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
					DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
					NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
				},
			},
			signType:         STANDARD_DER,
			signingKeyBase58: "",
		},
		{
			transactionGen: derivedKeyTestTxn{
				transactionSpendingLimit: &TransactionSpendingLimit{
					GlobalDESOLimit:              100,
					TransactionCountLimitMap:     map[TxnType]uint64{TxnTypeAuthorizeDerivedKey: 1},
					CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
					DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
					NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
				},
			},
			signType:         DESO_DER,
			signingKeyBase58: "",
		},
		{
			transactionGen: derivedKeyTestTxn{
				transactionSpendingLimit: &TransactionSpendingLimit{
					GlobalDESOLimit:              100,
					TransactionCountLimitMap:     map[TxnType]uint64{TxnTypeAuthorizeDerivedKey: 1},
					CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
					DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
					NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
				},
			},
			signType:         ECDSA,
			signingKeyBase58: senderPrivString,
		},

		{
			transactionGen: derivedKeyTestTxn{
				transactionSpendingLimit: nil,
			},
			signType:         ECDSA,
			signingKeyBase58: senderPrivString,
		},
		{
			transactionGen: derivedKeyTestTxn{
				transactionSpendingLimit: nil,
			},
			signType:         STANDARD_DER,
			signingKeyBase58: derivedPrivBase58CheckWithEntry,
		},
		{
			transactionGen: derivedKeyTestTxn{
				transactionSpendingLimit: nil,
			},
			signType:         DESO_DER,
			signingKeyBase58: derivedPrivBase58CheckWithEntry,
		},
	}

	var signingKeyBase58 string
	// Go through the test cases, add and process the transaction to the mempool
	for i := 0; i < len(testCases); i++ {
		tc := testCases[i]
		txn := tc.transactionGen.generateTxn(t, tb)

		switch v := tc.transactionGen.(type) {
		case basicTestTxn:
			signingKeyBase58 = tc.signingKeyBase58
			tb.addTxnInputs(txn)
		case derivedKeyTestTxn:
			derivedKey := v.getDerivedPrivKey(t)
			if tc.signingKeyBase58 == "" {
				signingKeyBase58 = Base58CheckEncode(derivedKey.Serialize(), true, tb.params)
			} else {
				signingKeyBase58 = tc.signingKeyBase58
			}
		}
		signTransaction(tb.t, txn, tc.signType, signingKeyBase58)
		tb.mempoolProcessTransaction(txn)
		allTxns = append(allTxns, txn)
	}
	// Mine and verify the blocks processed in mempool
	mineBlockAndVerifySignatures(allTxns)
}
