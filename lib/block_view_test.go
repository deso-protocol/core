package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	_ "net/http/pprof"
	"reflect"
	"sort"
	"testing"

	"github.com/deso-protocol/core/bls"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/lru"
	"github.com/dgraph-io/badger/v4"
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

func setBalanceModelBlockHeights(t *testing.T) {
	DeSoTestnetParams.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = 0
	DeSoTestnetParams.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight = 0
	DeSoTestnetParams.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight = 0
	DeSoTestnetParams.ForkHeights.DerivedKeyEthSignatureCompatibilityBlockHeight = 0
	DeSoTestnetParams.ForkHeights.ExtraDataOnEntriesBlockHeight = 0
	DeSoTestnetParams.ForkHeights.AssociationsAndAccessGroupsBlockHeight = 0
	DeSoTestnetParams.ForkHeights.BalanceModelBlockHeight = 1
	DeSoTestnetParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&DeSoTestnetParams.ForkHeights)
	DeSoTestnetParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&DeSoTestnetParams.ForkHeights)
	GlobalDeSoParams = DeSoTestnetParams

	t.Cleanup(resetBalanceModelBlockHeights)
}

func resetBalanceModelBlockHeights() {
	DeSoTestnetParams.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(60743)
	DeSoTestnetParams.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight = uint32(304087)
	DeSoTestnetParams.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight = uint32(304087 + 18*60)
	DeSoTestnetParams.ForkHeights.DerivedKeyEthSignatureCompatibilityBlockHeight = uint32(360584)
	DeSoTestnetParams.ForkHeights.ExtraDataOnEntriesBlockHeight = uint32(304087)
	DeSoTestnetParams.ForkHeights.AssociationsAndAccessGroupsBlockHeight = uint32(596555)
	DeSoTestnetParams.ForkHeights.BalanceModelBlockHeight = uint32(683058)
	DeSoTestnetParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&DeSoTestnetParams.ForkHeights)
	DeSoTestnetParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&DeSoTestnetParams.ForkHeights)
	GlobalDeSoParams = DeSoTestnetParams
}

func setPoSBlockHeights(t *testing.T, posSetupHeight uint32, posCutoverHeight uint32) {
	DeSoTestnetParams.ForkHeights.ProofOfStake1StateSetupBlockHeight = posSetupHeight
	DeSoTestnetParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = posCutoverHeight
	DeSoTestnetParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&DeSoTestnetParams.ForkHeights)
	DeSoTestnetParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&DeSoTestnetParams.ForkHeights)
	GlobalDeSoParams = DeSoTestnetParams

	t.Cleanup(resetPoSBlockHeights)
}

func resetPoSBlockHeights() {
	DeSoTestnetParams.ForkHeights.ProofOfStake1StateSetupBlockHeight = uint32(math.MaxUint32)
	DeSoTestnetParams.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight = uint32(math.MaxUint32)
	GlobalDeSoParams = DeSoTestnetParams
}

func GetConditionalBalanceFunc(chain *Blockchain, params *DeSoParams) func(uint64, uint64) uint64 {
	return func(deso uint64, balanceModelBalance uint64) uint64 {
		if chain.blockTip().Height >= params.ForkHeights.BalanceModelBlockHeight {
			return balanceModelBalance
		}
		return deso
	}
}

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
	transactionTestInputTypeAccessGroup transactionTestInputType = iota
	transactionTestInputTypeAccessGroupMembers
	transactionTestInputTypeNewMessage
	transactionTestInputTypeDerivedKey
)

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

	if tm.miner.BlockProducer != nil {
		tm.miner.BlockProducer.Stop()
	}

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
		require.NoError(tm.chain.snapshot.SnapshotDb.Close())
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
	disableLogging             bool
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
	getDerivedPrivateKey          func(tv *transactionTestVector, tm *transactionTestMeta) (_derivedPriv *btcec.PrivateKey, _signatureType int)
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

const testDeSoEncoderRetries = 3

func setupTestDeSoEncoder(t *testing.T) {
	EncodeToBytesImpl = func(blockHeight uint64, encoder DeSoEncoder, skipMetadata ...bool) []byte {
		versionByte := encoder.GetVersionByte(blockHeight)
		encodingBytes := encodeToBytes(blockHeight, encoder, skipMetadata...)
		// Check for deterministic encoding, try re-encoding the same encoder a couple of times and compare it with
		// the original bytes.
		{
			for ii := 0; ii < testDeSoEncoderRetries; ii++ {
				newVersionByte := encoder.GetVersionByte(blockHeight)
				reEncodingBytes := encodeToBytes(blockHeight, encoder, skipMetadata...)
				if !bytes.Equal(encodingBytes, reEncodingBytes) {
					t.Fatalf("EncodeToBytes: Found non-deterministic encoding for a DeSoEncoder. Attempted "+
						"encoder type (%v), version byte (original: %v, reEncoding: %v) at block height (%v).\n "+
						"First encoding: (%v)\n"+"Second encoding: (%v)\n",
						encoder.GetEncoderType(), versionByte, newVersionByte,
						blockHeight, hex.EncodeToString(encodingBytes), hex.EncodeToString(reEncodingBytes))
				}
			}
		}

		return encodingBytes
	}
}

func resetTestDeSoEncoder(t *testing.T) {
	EncodeToBytesImpl = encodeToBytes
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
		beforeConnectBlockHeight := tm.chain.blockTip().Height
		dbEntriesBefore := tes.GetAllStateDbEntries(tm, beforeConnectBlockHeight)
		tes.testConnectBlock(tm, testVectorBlock)
		afterConnectBlockHeight := tm.chain.blockTip().Height
		tes.testDisconnectBlock(tm, testVectorBlock)
		dbEntriesAfter := tes.GetAllStateDbEntries(tm, beforeConnectBlockHeight)
		tes.compareBeforeAfterDbEntries(dbEntriesBefore, dbEntriesAfter, afterConnectBlockHeight)
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
		chain, params, db = NewLowDifficultyBlockchain(tes.t)
		mempool, miner = NewTestMiner(config.t, chain, params, true /*isSender*/)
	} else if usePostgres {
		pgPort := uint32(5433)
		if config.testPostgresPort != 0 {
			pgPort = config.testPostgresPort
		}
		chain, params, embpg = NewLowDifficultyBlockchainWithParamsAndDb(tes.t, &DeSoTestnetParams,
			true, pgPort, false)
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

func (tes *transactionTestSuite) GetAllStateDbEntries(tm *transactionTestMeta, blockHeight uint32) (_dbEntries []*DBEntry) {
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
					dbEntryCopy := DBEntry{
						Key:   append([]byte{}, key...),
						Value: append([]byte{}, value...),
					}
					dbEntries = append(dbEntries, &dbEntryCopy)
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

func (tes *transactionTestSuite) compareBeforeAfterDbEntries(beforeDbEntries []*DBEntry, afterDbEntries []*DBEntry,
	afterConnectBlockHeight uint32) {
	beforeDbEntriesMap := make(map[string]DBEntry)
	afterDbEntriesMap := make(map[string]DBEntry)
	for _, dbEntry := range beforeDbEntries {
		beforeDbEntryCopy := *dbEntry
		beforeDbEntriesMap[string(beforeDbEntryCopy.Key)] = beforeDbEntryCopy
	}
	for _, dbEntry := range afterDbEntries {
		afterDbEntryCopy := *dbEntry
		afterDbEntriesMap[string(afterDbEntryCopy.Key)] = afterDbEntryCopy
	}

	// Check for db entries present in the beforeDbEntries state. Look for missing entries.
	for keyIter, beforeDbEntryIter := range beforeDbEntriesMap {
		key := keyIter
		beforeDbEntry := beforeDbEntryIter
		afterDbEntryIter, ok := afterDbEntriesMap[key]
		afterDbEntry := afterDbEntryIter
		if !ok {
			tes.t.Errorf("compareBeforeAfterDbEntries: Key %v is missing in the db after connect and a disconnect", []byte(key))
			continue
		}

		// Make sure either both entries are nil or both are non-nil.
		if (beforeDbEntry.Value != nil) != (afterDbEntry.Value != nil) {
			tes.t.Errorf("compareBeforeAfterDbEntries: Key %v has an uneven non-nil XOR for before and after value: "+
				"before (%v) (blockheight: %v), after (%v) (blockheight: %v)", []byte(key), beforeDbEntry.Value, afterDbEntry.Value,
				afterConnectBlockHeight-1, afterConnectBlockHeight)
		}
		// Make sure to compare db entries using the same migration if entries are non-nil.
		var beforeChecksumEncodedEntry, afterChecksumEncodedEntry []byte
		if beforeDbEntry.Value != nil && afterDbEntry.Value != nil {
			beforeChecksumEncodedEntry = EncodeKeyAndValueForChecksum(beforeDbEntry.Key, beforeDbEntry.Value, uint64(afterConnectBlockHeight))
			afterChecksumEncodedEntry = EncodeKeyAndValueForChecksum(afterDbEntry.Key, afterDbEntry.Value, uint64(afterConnectBlockHeight))
		}

		if !bytes.Equal(beforeChecksumEncodedEntry, afterChecksumEncodedEntry) {
			tes.t.Errorf("compareBeforeAfterDbEntries: Key %v has different values before and after connect and a disconnect: "+
				"before (%v) (blockheight: %v), after (%v) (blockheight: %v)", []byte(key), beforeDbEntry.Value, afterConnectBlockHeight-1,
				afterDbEntry.Value, afterConnectBlockHeight)
		}
	}

	// Check for db entries present in the afterDbEntries state. Look for extra entries.
	for key := range afterDbEntriesMap {
		_, ok := beforeDbEntriesMap[key]
		if !ok {
			tes.t.Fatalf("compareBeforeAfterDbEntries: Key %v didn't exist in the db before connect and disconnect", []byte(key))
		}
	}
}

func (tes *transactionTestSuite) testConnectBlock(tm *transactionTestMeta, testVectorBlock *transactionTestVectorBlock) (
	_validTransactions []bool, _addedBlock *MsgDeSoBlock) {
	require := require.New(tes.t)

	testVectors := testVectorBlock.testVectors
	validTransactions := make([]bool, len(testVectors))
	for ii, tv := range testVectors {
		if !tes.config.disableLogging {
			glog.Infof("Running test vector: %v", tv.id)
		}
		txn, _expectedErr := tv.getTransaction(tv, tm)
		if tv.getDerivedPrivateKey != nil {
			derivedPriv, signatureType := tv.getDerivedPrivateKey(tv, tm)
			derivedPrivString := Base58CheckEncode(derivedPriv.Serialize(), true, tm.params)
			_signTxnWithDerivedKeyAndType(tm.t, txn, derivedPrivString, signatureType)
		}
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
			if !tes.config.disableLogging {
				glog.Infof("Verifying UtxoView entry for test vector: %v", tv.id)
			}
			if tv.verifyConnectUtxoViewEntry != nil {
				tv.verifyConnectUtxoViewEntry(tv, tm, utxoView)
			}
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
			if !tes.config.disableLogging {
				glog.Infof("Verifying db entries for test vector: %v", tv.id)
			}
			if tv.verifyDbEntry != nil {
				tv.verifyDbEntry(tv, tm, dbAdapter)
			}
		} else {
			if !tes.config.disableLogging {
				glog.Infof("Skipping verifying db entries for test vector %v because it has later dependencies", tv.id)
			}
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
		if tv.getDerivedPrivateKey != nil {
			derivedPriv, signatureType := tv.getDerivedPrivateKey(tv, tm)
			derivedPrivString := Base58CheckEncode(derivedPriv.Serialize(), true, tm.params)
			_signTxnWithDerivedKeyAndType(tm.t, txn, derivedPrivString, signatureType)
		}
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
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, nil, nil)
		require.NoError(err)
		txHashes, err := ComputeTransactionHashes(lastBlock.Txns)
		require.NoError(err)
		err = utxoView.DisconnectBlock(lastBlock, txHashes, utxoOps, blockHeight)
		require.NoError(err)
	}

	// Disconnect the block transaction by transaction using DisconnectTransaction.
	utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot, nil)
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
			if expectedTv.verifyDisconnectUtxoViewEntry != nil {
				expectedTv.verifyDisconnectUtxoViewEntry(expectedTv, tm, utxoView, utxoOpsForTxn)
			}
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
		require.NoError(PutBestHash(tm.db, nil, prevHash, ChainTypeDeSoBlock, nil))
	}

	// Delete the utxo operations for the blocks we're detaching since we don't need them anymore.
	require.NoError(tm.db.Update(func(txn *badger.Txn) error {
		require.NoError(DeleteUtxoOperationsForBlockWithTxn(txn, nil, lastBlockHash, nil, false))
		require.NoError(DeleteBlockRewardWithTxn(txn, nil, lastBlock, nil, false))
		return nil
	}))

	// Revert the detached block's status to StatusHeaderValidated and save the blockNode to the db.
	lastBlockNode.Status = StatusHeaderValidated
	if tm.pg != nil {
		require.NoError(tm.pg.DeleteTransactionsForBlock(lastBlock, lastBlockNode))
		require.NoError(tm.pg.UpsertBlock(lastBlockNode))
	} else {
		require.NoError(PutHeightHashToNodeInfo(tm.db, nil, lastBlockNode, false, nil))
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
	if smallestIndex != -1 {
		tes._testVectorsInDb = tes._testVectorsInDb[:smallestIndex]
	}
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

	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
	require.NoError(err)

	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	txHash := txn.Hash()
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, blockHeight, 0, true, false)
	require.NoError(err)
	require.GreaterOrEqual(totalOutput, amountNanos)
	require.Equal(totalInput, totalOutput+fees)

	if blockHeight < params.ForkHeights.BalanceModelBlockHeight {
		require.Equal(len(txn.TxInputs)+len(txn.TxOutputs), len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		for ii := len(txn.TxInputs); ii < len(txn.TxInputs)+len(txn.TxOutputs); ii++ {
			require.Equal(OperationTypeAddUtxo, utxoOps[ii].Type)
		}
	} else {
		require.Equal(0, len(txn.TxInputs))
		// The first utxo operation is the transactor paying for
		// fees and the DESO sent to outputs.
		require.Equal(OperationTypeSpendBalance, utxoOps[0].Type)
		// The remaining utxo operations are the outputs.
		for ii := 1; ii < len(txn.TxOutputs); ii++ {
			require.Equal(OperationTypeAddBalance, utxoOps[ii].Type)
		}
	}

	require.NoError(utxoView.FlushToDb(uint64(chain.blockTip().Height)))

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

func _updateGlobalParamsEntry(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, usdCentsPerBitcoin int64, minimumNetworkFeesNanosPerKB int64,
	createProfileFeeNanos int64, createNFTFeeNanos int64, maxCopiesPerNFT int64, flushToDb bool) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	return _updateGlobalParamsEntryWithMempool(t, chain, db, params, feeRateNanosPerKB, updaterPkBase58Check,
		updaterPrivBase58Check, usdCentsPerBitcoin, minimumNetworkFeesNanosPerKB, createProfileFeeNanos,
		createNFTFeeNanos, maxCopiesPerNFT, -1, map[string][]byte{}, flushToDb, nil)
}

func _updateGlobalParamsEntryWithMaxNonceExpirationBlockHeightOffset(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, usdCentsPerBitcoin int64, minimumNetworkFeesNanosPerKB int64,
	createProfileFeeNanos int64, createNFTFeeNanos int64, maxCopiesPerNFT int64, maxNonceExpirationBlockHeightOffset int64, flushToDb bool) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {
	return _updateGlobalParamsEntryWithMempool(t, chain, db, params, feeRateNanosPerKB, updaterPkBase58Check,
		updaterPrivBase58Check, usdCentsPerBitcoin, minimumNetworkFeesNanosPerKB, createProfileFeeNanos,
		createNFTFeeNanos, maxCopiesPerNFT, maxNonceExpirationBlockHeightOffset, map[string][]byte{}, flushToDb, nil)
}

func _updateGlobalParamsEntryWithMempool(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, usdCentsPerBitcoin int64, minimumNetworkFeesNanosPerKB int64,
	createProfileFeeNanos int64, createNFTFeeNanos int64, maxCopiesPerNFT int64, maxNonceExpirationBlockHeightOffset int64,
	extraData map[string][]byte, flushToDb bool, mempool *DeSoMempool) (
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
		maxNonceExpirationBlockHeightOffset,
		extraData,
		feeRateNanosPerKB,
		mempool,
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, updaterPrivBase58Check)

	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)

	require.NoError(err)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, blockHeight, 0, true, false)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	if blockHeight < params.ForkHeights.BalanceModelBlockHeight {
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
		require.NoError(utxoView.FlushToDb(uint64(chain.blockTip().Height) + 1))
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

	currentOps, currentTxn, _, err := _updateGlobalParamsEntryWithMempool(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		int64(InitialUSDCentsPerBitcoinExchangeRate),
		minimumNetworkFeeNanosPerKb,
		createProfileFeeNanos,
		createNFTFeeNanos,
		maxCopiesPerNFT,
		-1,
		map[string][]byte{},
		true,
		testMeta.mempool) /*flushToDB*/
	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _updateGlobalParamsEntryWithExtraData(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	updaterPkBase58Check string,
	updaterPrivBase58Check string,
	extraData map[string][]byte,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances,
		_getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))

	currentOps, currentTxn, _, err := _updateGlobalParamsEntryWithMempool(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		-1,
		int64(feeRateNanosPerKB),
		-1,
		-1,
		-1,
		-1,
		extraData,
		true,
		testMeta.mempool) /*flushToDB*/
	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _updateGlobalParamsEntryWithMaxNonceExpirationBlockHeightOffsetAndTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	updaterPkBase58Check string,
	updaterPrivBase58Check string,
	USDCentsPerBitcoinExchangeRate int64,
	minimumNetworkFeeNanosPerKb int64,
	createProfileFeeNanos int64,
	createNFTFeeNanos int64,
	maxCopiesPerNFT int64,
	maxNonceExpirationBlockHeightOffset int64,
) {
	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances,
		_getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))

	currentOps, currentTxn, _, err := _updateGlobalParamsEntryWithMempool(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		int64(InitialUSDCentsPerBitcoinExchangeRate),
		minimumNetworkFeeNanosPerKb,
		createProfileFeeNanos,
		createNFTFeeNanos,
		maxCopiesPerNFT,
		maxNonceExpirationBlockHeightOffset,
		map[string][]byte{},
		true,
		testMeta.mempool) /*flushToDB*/
	require.NoError(testMeta.t, err)
	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
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
	feeRateNanosPerKb      uint64
	posMempool             *PosMempool
	posBlockProducer       *PosBlockProducer
	pubKeyToBLSKeyMap      map[string]*bls.PrivateKey
	blsPubKeyToBLSKeyMap   map[string]*bls.PrivateKey
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
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, nil)
		require.NoError(testMeta.t, err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, testMeta.savedHeight)
		require.NoError(testMeta.t, err)

		blockHeight := uint64(testMeta.chain.BlockTip().Height)
		require.NoError(testMeta.t, utxoView.FlushToDb(blockHeight+1))

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
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, testMeta.chain.eventManager)
	require.NoError(testMeta.t, err)
	for ii, txn := range testMeta.txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := testMeta.chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, blockHeight, 0, true, false)
		require.NoError(testMeta.t, err)
	}
	// Flush the utxoView after having added all the transactions.
	blockHeight := uint64(testMeta.chain.BlockTip().Height)
	require.NoError(testMeta.t, utxoView.FlushToDb(blockHeight+1))
}

func _disconnectTestMetaTxnsFromViewAndFlush(testMeta *TestMeta) {
	// Disonnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, testMeta.chain.eventManager)
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
	blockHeight := uint64(testMeta.chain.BlockTip().Height)
	require.NoError(testMeta.t, utxoView.FlushToDb(blockHeight))
}

func _connectBlockThenDisconnectBlockAndFlush(testMeta *TestMeta) {
	// all those transactions in it.
	block, err := testMeta.miner.MineAndProcessSingleBlock(0 /*threadIndex*/, testMeta.mempool)
	require.NoError(testMeta.t, err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(testMeta.t, len(testMeta.txnOps)+1, len(block.Txns))

	// Roll back the block and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, testMeta.chain.eventManager)
		require.NoError(testMeta.t, err)

		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := block.Header.Hash()
		require.NoError(testMeta.t, err)
		utxoOps, err := GetUtxoOperationsForBlock(testMeta.db, testMeta.chain.snapshot, hash)
		require.NoError(testMeta.t, err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(block.Txns)
		require.NoError(testMeta.t, err)
		blockHeight := uint64(testMeta.chain.BlockTip().Height)
		require.NoError(testMeta.t, utxoView.DisconnectBlock(block, txHashes, utxoOps, blockHeight))

		// Flushing the view after applying and rolling back should work.
		require.NoError(testMeta.t, utxoView.FlushToDb(blockHeight))
	}
}

func TestBalanceModelUpdateGlobalParams(t *testing.T) {
	setBalanceModelBlockHeights(t)

	TestUpdateGlobalParams(t)
	TestUpdateGlobalParamsPoS(t)
}

func TestUpdateGlobalParams(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	chain, params, db := NewLowDifficultyBlockchain(t)
	postgres := chain.postgres
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_, _ = mempool, miner

	// Set the founder equal to the moneyPk
	params.ExtraRegtestParamUpdaterKeys = make(map[PkMapKey]bool)
	params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(MustBase58CheckDecode(moneyPkString))] = true

	// Mine a few blocks
	_, err := miner.MineAndProcessSingleBlock(0, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0, mempool)
	require.NoError(err)

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

		utxoView, err := NewUtxoView(db, params, postgres, chain.snapshot, chain.eventManager)
		require.NoError(err)
		blockHeight := chain.blockTip().Height + 1
		utxoOps, totalInput, totalOutput, fees, err :=
			utxoView.ConnectTransaction(updateGlobalParamsTxn, updateGlobalParamsTxn.Hash(), blockHeight, 0, true, false)
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
		utxoView, err := NewUtxoView(db, params, postgres, chain.snapshot, chain.eventManager)
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
	{
		if chain.blockTip().Height < params.ForkHeights.BalanceModelBlockHeight {
			return
		}

		// Save the prev global params entry so we can check it after disconnect.
		prevGlobalParams := DbGetGlobalParamsEntry(db, chain.snapshot)

		var utxoOps []*UtxoOperation
		utxoOps, updateGlobalParamsTxn, _, err = _updateGlobalParamsEntryWithMaxNonceExpirationBlockHeightOffset(
			t, chain, db, params, 200, /*feeRateNanosPerKB*/
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1, /*maxCopiesPerNFT*/
			5000,
			true)
		require.NoError(err)
		_ = utxoOps

		// Verify that the db reflects the new global params entry.
		expectedGlobalParams := &GlobalParamsEntry{
			USDCentsPerBitcoin:                  prevGlobalParams.USDCentsPerBitcoin,
			MinimumNetworkFeeNanosPerKB:         prevGlobalParams.MinimumNetworkFeeNanosPerKB,
			CreateProfileFeeNanos:               prevGlobalParams.CreateProfileFeeNanos,
			CreateNFTFeeNanos:                   prevGlobalParams.CreateNFTFeeNanos,
			MaxCopiesPerNFT:                     prevGlobalParams.MaxCopiesPerNFT,
			MaxNonceExpirationBlockHeightOffset: 5000,
		}

		require.Equal(DbGetGlobalParamsEntry(db, chain.snapshot), expectedGlobalParams)

		// Make sure mempool won't accept expired nonces or nonces with expiration block heights
		// that exceed the max offset.
		txn := _assembleBasicTransferTxnFullySigned(t, chain, 200, 200, m0Pub, moneyPkString, m0Priv, mempool)
		txn.TxnNonce.ExpirationBlockHeight = uint64(chain.blockTip().Height + 1 + 5001)
		_signTxn(t, txn, m0Priv)
		newMP := NewDeSoMempool(chain, 0, 0, "", true, "", "", true)
		_, _, err = newMP.TryAcceptTransaction(txn, false, false)
		require.Error(err)
		require.Contains(err.Error(), TxErrorNonceExpirationBlockHeightOffsetExceeded)

		txn.TxnNonce.ExpirationBlockHeight = uint64(chain.blockTip().Height - 1)
		_signTxn(t, txn, m0Priv)
		_, _, err = newMP.TryAcceptTransaction(txn, false, false)
		require.Error(err)
		require.Contains(err.Error(), TxErrorNonceExpired)

		// Now let's do a disconnect and make sure the values reflect the previous entry.
		utxoView, err := NewUtxoView(db, params, postgres, chain.snapshot, nil)
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

func TestUpdateGlobalParamsPoS(t *testing.T) {
	// Set pos block heights
	setPoSBlockHeights(t, 2, 1000)
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	chain, params, db := NewLowDifficultyBlockchain(t)
	postgres := chain.postgres
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_, _ = mempool, miner

	// Set the founder equal to the moneyPk
	params.ExtraRegtestParamUpdaterKeys = make(map[PkMapKey]bool)
	params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(MustBase58CheckDecode(moneyPkString))] = true

	// Mine a few blocks
	for ii := 0; ii < 10; ii++ {
		_, err := miner.MineAndProcessSingleBlock(0, mempool)
		require.NoError(err)
	}

	// Update min fee rate on global params to be 1000.
	_, _, _, err := _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
		moneyPkString,
		moneyPrivString,
		-1,
		1000,
		-1,
		-1,
		-1,
		-1,
		map[string][]byte{},
		true,
		mempool)
	require.NoError(err)
	// MaxBlockSizeBytesPoS tests.
	{
		params.ForkHeights = GlobalDeSoParams.ForkHeights
		params.EncoderMigrationHeights = GlobalDeSoParams.EncoderMigrationHeights
		params.EncoderMigrationHeightsList = GlobalDeSoParams.EncoderMigrationHeightsList
		mempool.bc.params = params
		// Make sure setting max block size too low fails.
		_, _, _, err := _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				MaxBlockSizeBytesPoSKey: UintToBuf(MinMaxBlockSizeBytes - 1),
			},
			true,
			mempool)
		require.ErrorIs(err, RuleErrorMaxBlockSizeBytesTooLow)
		// Make sure setting max block size too high fails.
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				MaxBlockSizeBytesPoSKey: UintToBuf(MaxMaxBlockSizeBytes + 1),
			},
			true,
			mempool)
		require.ErrorIs(err, RuleErrorMaxBlockSizeBytesTooHigh)
		// Make sure setting max block size to a valid value works and updates global params.
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				MaxBlockSizeBytesPoSKey: UintToBuf(5000),
			},
			true,
			mempool)
		require.NoError(err)
		utxoView, err := NewUtxoView(db, params, postgres, chain.snapshot, nil)
		require.NoError(err)
		require.Equal(utxoView.GetCurrentGlobalParamsEntry().MaxBlockSizeBytesPoS, uint64(5000))
	}
	// SoftMaxBlockSizeBytesPoS tests.
	{
		// Make sure setting soft max block size too low fails.
		_, _, _, err := _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				SoftMaxBlockSizeBytesPoSKey: UintToBuf(MinSoftMaxBlockSizeBytes - 1),
			},
			true,
			mempool)
		require.ErrorIs(err, RuleErrorSoftMaxBlockSizeBytesTooLow)
		// Make sure setting soft max block size too high fails.
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				SoftMaxBlockSizeBytesPoSKey: UintToBuf(MaxSoftMaxBlockSizeBytes + 1),
			},
			true,
			mempool)
		require.ErrorIs(err, RuleErrorSoftMaxBlockSizeBytesTooHigh)
		// Make sure setting soft max block size to a value greater than max block size fails.
		utxoView, err := NewUtxoView(db, params, postgres, chain.snapshot, nil)
		require.NoError(err)
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				SoftMaxBlockSizeBytesPoSKey: UintToBuf(utxoView.GetCurrentGlobalParamsEntry().MaxBlockSizeBytesPoS + 1),
			},
			true,
			mempool)
		require.ErrorIs(err, RuleErrorSoftMaxBlockSizeBytesExceedsMaxBlockSizeBytes)
		// Make sure setting max block size to a valid value works and updates global params.
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				SoftMaxBlockSizeBytesPoSKey: UintToBuf(4000),
			},
			true,
			mempool)
		require.NoError(err)
		utxoView, err = NewUtxoView(db, params, postgres, chain.snapshot, nil)
		require.NoError(err)
		require.Equal(utxoView.GetCurrentGlobalParamsEntry().SoftMaxBlockSizeBytesPoS, uint64(4000))
	}
	// MaxTxnSizeBytesPoS tests.
	{
		// Make sure setting max txn size too low fails.
		_, _, _, err := _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				MaxTxnSizeBytesPoSKey: UintToBuf(MinMaxTxnSizeBytes - 1),
			},
			true,
			mempool)
		require.ErrorIs(err, RuleErrorMaxTxnSizeBytesTooLow)
		// Make sure setting max txn size too high fails.
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				MaxTxnSizeBytesPoSKey: UintToBuf(MaxMaxTxnSizeBytes + 1),
			},
			true,
			mempool)
		require.ErrorIs(err, RuleErrorMaxTxnSizeBytesTooHigh)
		// Make sure setting max txn size to a value greater than max block size fails.
		utxoView, err := NewUtxoView(db, params, postgres, chain.snapshot, nil)
		require.NoError(err)
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				MaxTxnSizeBytesPoSKey: UintToBuf(utxoView.GetCurrentGlobalParamsEntry().MaxBlockSizeBytesPoS + 1),
			},
			true,
			mempool)
		require.ErrorIs(err, RuleErrorMaxTxnSizeBytesExceedsMaxBlockSizeBytes)
		// Make sure setting max txn size to a valid value works and updates global params.
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				MaxTxnSizeBytesPoSKey: UintToBuf(4000),
			},
			true,
			mempool)
		require.NoError(err)
		utxoView, err = NewUtxoView(db, params, postgres, chain.snapshot, nil)
		require.NoError(err)
		require.Equal(utxoView.GetCurrentGlobalParamsEntry().MaxTxnSizeBytesPoS, uint64(4000))
	}
	// MinFeeBucket size tests.
	{

		utxoView, err := NewUtxoView(db, params, postgres, chain.snapshot, nil)
		require.NoError(err)
		require.Equal(utxoView.GetCurrentGlobalParamsEntry().MinimumNetworkFeeNanosPerKB, uint64(1000))
		require.Equal(utxoView.GetCurrentGlobalParamsEntry().FeeBucketGrowthRateBasisPoints, uint64(1000))
		// Make sure setting min fee bucket size too low fails. 1% of 1000 is 10, so anything less than that
		// should fail.
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				FeeBucketGrowthRateBasisPointsKey: UintToBuf(90),
			},
			true,
			mempool)
		require.ErrorIs(err, RuleErrorFeeBucketSizeTooSmall)
		// Okay now set it to 1%
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				FeeBucketGrowthRateBasisPointsKey: UintToBuf(100),
			},
			true,
			mempool)
		require.NoError(err)
	}
	{
		// Block production global params test.
		// Make sure setting block production interval too low fails.
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				BlockProductionIntervalPoSKey: UintToBuf(MinBlockProductionIntervalMillisecondsPoS - 1),
			},
			true,
			mempool)
		require.ErrorIs(err, RuleErrorBlockProductionIntervalPoSTooLow)
		// Make sure setting block production interval too high fails. Anything over the max allowed will fail.
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				BlockProductionIntervalPoSKey: UintToBuf(MaxBlockProductionIntervalMillisecondsPoS + 1),
			},
			true,
			mempool)
		require.ErrorIs(err, RuleErrorBlockProductionIntervalPoSTooHigh)
		// Make sure setting block timeout interval to a reasonable value works. Make it 5s
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				BlockProductionIntervalPoSKey: UintToBuf(5000),
			},
			true,
			mempool)
		require.NoError(err)
		utxoView, err := NewUtxoView(db, params, postgres, chain.snapshot, nil)
		require.NoError(err)
		require.Equal(utxoView.GetCurrentGlobalParamsEntry().BlockProductionIntervalMillisecondsPoS, uint64(5000))
	}
	{
		// Timeout interval global params test
		// Make sure setting timeout interval too low fails. Anything below min should fail
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				TimeoutIntervalPoSKey: UintToBuf(MinTimeoutIntervalMillisecondsPoS - 1),
			},
			true,
			mempool)
		require.ErrorIs(err, RuleErrorTimeoutIntervalPoSTooLow)
		// Make sure setting timeout interval too low fails. Anything above max should fail
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				TimeoutIntervalPoSKey: UintToBuf(MaxTimeoutIntervalMillisecondsPoS + 1),
			},
			true,
			mempool)
		require.ErrorIs(err, RuleErrorTimeoutIntervalPoSTooHigh)
		// Make sure setting timeout interval to a reasonable value works. Make it 5s
		_, _, _, err = _updateGlobalParamsEntryWithMempool(t, chain, db, params, 1000,
			moneyPkString,
			moneyPrivString,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			map[string][]byte{
				TimeoutIntervalPoSKey: UintToBuf(5000),
			},
			true,
			mempool)
		require.NoError(err)
		utxoView, err := NewUtxoView(db, params, postgres, chain.snapshot, nil)
		require.NoError(err)
		require.Equal(utxoView.GetCurrentGlobalParamsEntry().TimeoutIntervalMillisecondsPoS, uint64(5000))
	}
}

func TestBalanceModelBasicTransfers(t *testing.T) {
	setBalanceModelBlockHeights(t)

	t.Run("TestBasicTransfer", TestBasicTransfer)
	t.Run("TestBasicTransferSignatures", TestBasicTransferSignatures)
	t.Run("TestBlockRewardPatch", TestBlockRewardPatch)
}

func TestBasicTransfer(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain(t)
	postgres := chain.postgres
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
		utxoView, _ := NewUtxoView(db, params, postgres, chain.snapshot, chain.eventManager)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, blockHeight, 0, true, false)
		require.Error(err)
		if blockHeight < params.ForkHeights.BalanceModelBlockHeight {
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
		utxoView, _ := NewUtxoView(db, params, postgres, chain.snapshot, nil)
		if blockHeight < params.ForkHeights.BalanceModelBlockHeight {
			totalInput, spendAmount, changeAmount, fees, err :=
				chain.AddInputsAndChangeToTransaction(txn, 10, nil)
			require.NoError(err)
			require.Equal(totalInput, spendAmount+changeAmount+fees)
			require.Greater(totalInput, uint64(0))
		} else {
			txn.TxnVersion = 1
			txn.TxnNonce, err = utxoView.ConstructNonceForPublicKey(senderPkBytes, uint64(chain.BlockTip().Height))
			require.NoError(err)
		}
		// Sign the transaction with the recipient's key rather than the
		// sender's key.
		_signTxn(t, txn, recipientPrivString)
		txHash := txn.Hash()
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, blockHeight, 0, true, false)
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
		_signTxn(t, txn, senderPrivString)
		utxoView, _ := NewUtxoView(db, params, postgres, chain.snapshot, chain.eventManager)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, blockHeight, 0, true, false)
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

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, nil)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		_signTxn(t, txn, senderPrivString)
		utxoView, _ := NewUtxoView(db, params, postgres, chain.snapshot, chain.eventManager)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, blockHeight, 0, true, false)
		require.Error(err)
		if blockHeight < params.ForkHeights.BalanceModelBlockHeight {
			require.Contains(err.Error(), RuleErrorBlockRewardTxnNotAllowedToHaveInputs)
		} else {
			// AddInputsAndChange() does not add inputs in the balance model case so this
			// transaction fails with a different error.
			require.Contains(err.Error(), RuleErrorBlockRewardTxnNotAllowedToHaveSignature)
		}
	}

	// A block with too much block reward should fail.
	allowedBlockReward := CalcBlockRewardNanos(chain.blockTip().Height, params)
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
		utxoView, _ := NewUtxoView(db, params, postgres, chain.snapshot, chain.eventManager)
		_, err = utxoView.ConnectBlock(blockToMine, txHashes, true /*verifySignatures*/, nil, 0)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardExceedsMaxAllowed)
	}

	// A block with less than the max block reward should be OK.
	{

		utxoView, _ := NewUtxoView(db, params, chain.postgres, chain.snapshot, nil)
		minerBalanceBefore, _ := utxoView.GetDeSoBalanceNanosForPublicKey(senderPkBytes)

		blockToMine.Txns[0].TxOutputs[0].AmountNanos = allowedBlockReward - 1
		// One iteration should be sufficient to find us a good block.
		_, bestNonce, err := FindLowestHash(blockToMine.Header, 10000)
		require.NoError(err)
		blockToMine.Header.Nonce = bestNonce

		txHashes, err := ComputeTransactionHashes(blockToMine.Txns)
		require.NoError(err)
		utxoView, _ = NewUtxoView(db, params, postgres, chain.snapshot, nil)
		_, err = utxoView.ConnectBlock(blockToMine, txHashes, true /*verifySignatures*/, nil, 0)
		require.NoError(err)

		minerBalanceAfter, _ := utxoView.GetDeSoBalanceNanosForPublicKey(senderPkBytes)

		// The miner starts with two DESO from two blocks being mined.
		require.Equal(uint64(2000000000), minerBalanceBefore)
		// Then mines another block reward worth .999999999 DESO.
		require.Equal(uint64(999999999), blockToMine.Txns[0].TxOutputs[0].AmountNanos)
		// Therefore the balance after mining should be 2.999999999 DESO.
		require.Equal(uint64(2999999999), minerBalanceAfter)

		err = utxoView.FlushToDb(uint64(chain.BlockTip().Height + 1))
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
		utxoView, _ := NewUtxoView(db, params, chain.postgres, chain.snapshot, nil)
		txHash := txn.Hash()
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, blockHeight, 0, true, false)
		require.NoError(err)

		senderBalance, _ := utxoView.GetDeSoBalanceNanosForPublicKey(senderPkBytes)
		recipientBalance, _ := utxoView.GetDeSoBalanceNanosForPublicKey(recipientPkBytes)
		require.Equal(uint64(2999999997), senderBalance)
		require.Equal(uint64(1), recipientBalance)
	}
}

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
	_ = require

	// Set up block heights
	DeSoTestnetParams.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)
	DeSoTestnetParams.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight = uint32(0)
	DeSoTestnetParams.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight = uint32(0)
	DeSoTestnetParams.ForkHeights.DeSoUnlimitedDerivedKeysBlockHeight = uint32(100)
	for ii := range DeSoTestnetParams.EncoderMigrationHeightsList {
		if DeSoTestnetParams.EncoderMigrationHeightsList[ii].Version == 0 {
			continue
		}
		DeSoTestnetParams.EncoderMigrationHeightsList[ii].Height = 100
	}

	// Make sure encoder migrations are not triggered yet.
	GlobalDeSoParams = DeSoTestnetParams

	chain, params, db := NewLowDifficultyBlockchain(t)
	postgres := chain.postgres

	_ = db
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
	senderPrivKey, _ := btcec.PrivKeyFromBytes(senderPrivBytes)
	recipientPkBytes, _, err := Base58CheckDecode(recipientPkString)
	require.NoError(err)

	// Construct an unsigned basic transfer transaction.
	createTransaction := func() *MsgDeSoTxn {
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

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, mempool)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))
		return txn
	}

	// Add a transaction to the mempool.
	mempoolProcess := func(txn *MsgDeSoTxn) (_mempoolTxs []*MempoolTx, _err error) {
		mempoolTxs, err := mempool.processTransaction(txn, true, true, 0,
			true)
		if err != nil {
			return nil, err
		}
		require.Equal(1, len(mempoolTxs))
		return mempoolTxs, err
	}

	// Mine block with the latest mempool. Validate that the persisted transaction signatures match original transactions.
	mineBlockAndVerifySignatures := func(allTxns []*MsgDeSoTxn) {
		block, err := miner.MineAndProcessSingleBlock(0, mempool)
		blockHash, err := block.Hash()
		require.NoError(err)
		require.NoError(err)
		require.Equal(1+len(allTxns), len(block.Txns))
		for ii := 1; ii < len(block.Txns); ii++ {
			txn := allTxns[ii-1]
			transactionHash := allTxns[ii-1].Hash()
			require.Equal(true, reflect.DeepEqual(transactionHash.ToBytes(), block.Txns[ii].Hash().ToBytes()))

			// Now fetch all transactions from the db and verify their signatures have been properly persisted.
			if postgres != nil {
				pgTxn := postgres.GetTransactionByHash(transactionHash)
				r := txn.Signature.Sign.R()
				rBytes := (&r).Bytes()
				s := txn.Signature.Sign.S()
				sBytes := (&s).Bytes()
				require.Equal(true, reflect.DeepEqual(rBytes[:], HashToBigint(pgTxn.R).Bytes()))
				require.Equal(true, reflect.DeepEqual(sBytes[:], HashToBigint(pgTxn.S).Bytes()))
				require.Equal(txn.Signature.RecoveryId, byte(pgTxn.RecoveryId))
				require.Equal(txn.Signature.IsRecoverable, pgTxn.IsRecoverable)
			} else {
				dbBlock, err := GetBlock(blockHash, db, chain.Snapshot())
				require.NoError(err)
				for _, blockTxn := range dbBlock.Txns {
					if reflect.DeepEqual(transactionHash.ToBytes(), blockTxn.Hash().ToBytes()) {
						rTxn := txn.Signature.Sign.R()
						rTxnBytes := (&rTxn).Bytes()
						sTxn := txn.Signature.Sign.S()
						sTxnBytes := (&sTxn).Bytes()
						rBlockTxn := blockTxn.Signature.Sign.R()
						rBlockTxnBytes := (&rBlockTxn).Bytes()
						sBlockTxn := blockTxn.Signature.Sign.S()
						sBlockTxnBytes := (&sBlockTxn).Bytes()
						require.Equal(true, reflect.DeepEqual(rTxnBytes[:], rBlockTxnBytes[:]))
						require.Equal(true, reflect.DeepEqual(sTxnBytes[:], sBlockTxnBytes[:]))
						require.Equal(txn.Signature.RecoveryId, blockTxn.Signature.RecoveryId)
						require.Equal(txn.Signature.IsRecoverable, blockTxn.Signature.IsRecoverable)
					}
				}
			}
		}
	}

	// Create a derived key transaction based on the provided spending limit.
	doDerivedKeyTransaction := func(transactionSpendingLimit *TransactionSpendingLimit) (derivedKeyTxn *MsgDeSoTxn,
		derivedPrivateKey *btcec.PrivateKey) {

		extraData := make(map[string]interface{})
		extraData[TransactionSpendingLimitKey] = transactionSpendingLimit
		blockHeight, err := GetBlockTipHeight(db, false)
		require.NoError(err)
		authTxnMeta, derivedPriv := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(
			t, senderPrivKey, 10, transactionSpendingLimit, false, blockHeight+1)
		transactionSpendingLimitBytes, err := transactionSpendingLimit.ToBytes(blockHeight + 1)
		require.NoError(err)
		derivedKeyTxn, totalInput, changeAmount, fees, err := chain.CreateAuthorizeDerivedKeyTxn(
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
			mempool,
			nil,
		)
		require.NoError(err)
		require.Equal(totalInput, changeAmount+fees)
		require.Greater(totalInput, uint64(0))
		require.NoError(err)
		return derivedKeyTxn, derivedPriv
	}

	// This function will try all possible signature schemes (1), (2), (3) given signer's private key and transaction
	// generator function createTransaction (BasicTransafer) or derivedKeyTransaction (AuthorizeDerivedKey). TestVector
	// expresses our expectation as to the errors we are supposed to get when trying to process a transaction signed
	// with each respective signature scheme.
	mempoolProcessAllSignatureCombinations := func(
		createTransaction func() *MsgDeSoTxn,
		derivedKeyTransaction func(*TransactionSpendingLimit) (*MsgDeSoTxn, *btcec.PrivateKey),
		signaturePrivateKeyBase58 string,
		transactionSpendingLimit *TransactionSpendingLimit,
		testVector [3]RuleError) []*MsgDeSoTxn {

		var allTxns []*MsgDeSoTxn
		processTxn := func(ii int, txn *MsgDeSoTxn) {
			if testVector[ii].Error() == "" {
				allTxns = append(allTxns, txn)
				_, err = mempoolProcess(txn)
				require.NoError(err)
			} else {
				_, err = mempoolProcess(txn)
				require.Error(err)
				require.Contains(err.Error(), testVector[ii].Error())
			}
		}

		if createTransaction != nil {

			txn := createTransaction()
			// Sign the transaction with the recipient's key rather than the sender's key.
			_signTxn(t, txn, signaturePrivateKeyBase58)
			processTxn(0, txn)

			txn = createTransaction()
			_signTxnWithDerivedKeyAndType(t, txn, signaturePrivateKeyBase58, 0)
			processTxn(1, txn)

			txn = createTransaction()
			_signTxnWithDerivedKeyAndType(t, txn, signaturePrivateKeyBase58, 1)
			processTxn(2, txn)
		} else if derivedKeyTransaction != nil {
			var signerPrivBase58 string
			if signaturePrivateKeyBase58 != "" {
				signerPrivBase58 = signaturePrivateKeyBase58
			}

			derivedKeyTxn, derivedPriv := doDerivedKeyTransaction(transactionSpendingLimit)
			if signaturePrivateKeyBase58 == "" {
				signerPrivBase58 = Base58CheckEncode(derivedPriv.Serialize(), true, params)
			}
			_signTxn(t, derivedKeyTxn, signerPrivBase58)
			processTxn(0, derivedKeyTxn)

			derivedKeyTxn, derivedPriv = doDerivedKeyTransaction(transactionSpendingLimit)
			if signaturePrivateKeyBase58 == "" {
				signerPrivBase58 = Base58CheckEncode(derivedPriv.Serialize(), true, params)
			}
			_signTxnWithDerivedKeyAndType(t, derivedKeyTxn, signerPrivBase58, 0)
			processTxn(1, derivedKeyTxn)

			derivedKeyTxn, derivedPriv = doDerivedKeyTransaction(transactionSpendingLimit)
			if signaturePrivateKeyBase58 == "" {
				signerPrivBase58 = Base58CheckEncode(derivedPriv.Serialize(), true, params)
			}
			_signTxnWithDerivedKeyAndType(t, derivedKeyTxn, signerPrivBase58, 1)
			processTxn(2, derivedKeyTxn)
		}
		return allTxns
	}

	// First scenario, just signing a basic transfer.
	{
		var allTxns []*MsgDeSoTxn
		// Try signing the basic transfer with the owner's private key.
		testSenderVector := [3]RuleError{
			"", RuleErrorDerivedKeyNotAuthorized, RuleErrorDerivedKeyNotAuthorized,
		}
		allTxns = append(allTxns, mempoolProcessAllSignatureCombinations(
			createTransaction,
			nil,
			senderPrivString,
			nil,
			testSenderVector,
		)...)

		// Try signing the basic transfer with a random private key.
		testRandomVector := [3]RuleError{
			RuleErrorInvalidTransactionSignature, RuleErrorDerivedKeyNotAuthorized, RuleErrorDerivedKeyNotAuthorized,
		}
		randomPrivKey, err := btcec.NewPrivateKey()
		require.NoError(err)
		randomPrivKeyBase58Check := Base58CheckEncode(randomPrivKey.Serialize(), true, params)

		allTxns = append(allTxns, mempoolProcessAllSignatureCombinations(
			createTransaction,
			nil,
			randomPrivKeyBase58Check,
			nil,
			testRandomVector,
		)...)

		mineBlockAndVerifySignatures(allTxns)
	}

	// Second scenario, authorize derived key transaction.
	{
		var allTxns []*MsgDeSoTxn
		transactionSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit:              100,
			TransactionCountLimitMap:     make(map[TxnType]uint64),
			CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
			DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
			NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
		}
		transactionSpendingLimit.TransactionCountLimitMap[TxnTypeAuthorizeDerivedKey] = 1

		// First try signing the authorize derived key transaction with the derived key itself.
		testDerivedKeyVector := [3]RuleError{
			RuleErrorInvalidTransactionSignature, "", "",
		}
		allTxns = append(allTxns, mempoolProcessAllSignatureCombinations(
			nil,
			doDerivedKeyTransaction,
			"",
			transactionSpendingLimit,
			testDerivedKeyVector,
		)...)

		// Now try signing the authorize derived key transaction with the sender's private key.
		testSignerKeyVector := [3]RuleError{
			"", RuleErrorDerivedKeyNotAuthorized, RuleErrorDerivedKeyNotAuthorized,
		}
		allTxns = append(allTxns, mempoolProcessAllSignatureCombinations(
			nil,
			doDerivedKeyTransaction,
			senderPrivString,
			transactionSpendingLimit,
			testSignerKeyVector,
		)...)

		// Finally try a random private key.
		testRandomKeyVector := [3]RuleError{
			RuleErrorInvalidTransactionSignature, RuleErrorDerivedKeyNotAuthorized, RuleErrorDerivedKeyNotAuthorized,
		}
		randomPrivKey, err := btcec.NewPrivateKey()
		require.NoError(err)
		randomPrivKeyBase58Check := Base58CheckEncode(randomPrivKey.Serialize(), true, params)
		allTxns = append(allTxns, mempoolProcessAllSignatureCombinations(
			nil,
			doDerivedKeyTransaction,
			randomPrivKeyBase58Check,
			transactionSpendingLimit,
			testRandomKeyVector,
		)...)

		mineBlockAndVerifySignatures(allTxns)
	}

	// Third scenario, there exists an authorize derived key entry and we're signing a basic transfer.
	{
		var allTxns []*MsgDeSoTxn
		transactionSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit:              100,
			TransactionCountLimitMap:     make(map[TxnType]uint64),
			CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
			DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
			NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
		}
		transactionSpendingLimit.TransactionCountLimitMap[TxnTypeBasicTransfer] = 2
		transactionSpendingLimit.TransactionCountLimitMap[TxnTypeAuthorizeDerivedKey] = 1

		// First authorize the derived key.
		derivedKeyTxn, derivedPriv := doDerivedKeyTransaction(transactionSpendingLimit)
		derivedPrivBase58Check := Base58CheckEncode(derivedPriv.Serialize(), true, params)
		_signTxn(t, derivedKeyTxn, senderPrivString)
		allTxns = append(allTxns, derivedKeyTxn)
		_, err = mempoolProcess(derivedKeyTxn)
		require.NoError(err)

		// Sign the basic transfer with the sender's private key.
		testMoneyOwnerVector := [3]RuleError{
			"", RuleErrorDerivedKeyNotAuthorized, RuleErrorDerivedKeyNotAuthorized,
		}
		allTxns = append(allTxns, mempoolProcessAllSignatureCombinations(
			createTransaction,
			nil,
			senderPrivString,
			nil,
			testMoneyOwnerVector,
		)...)

		// Sign the basic transfer with the derived key.
		testMoneyDerivedVector := [3]RuleError{
			RuleErrorInvalidTransactionSignature, "", "",
		}
		allTxns = append(allTxns, mempoolProcessAllSignatureCombinations(
			createTransaction,
			nil,
			derivedPrivBase58Check,
			nil,
			testMoneyDerivedVector,
		)...)

		// Sign the basic transfer with a random private key.
		testMoneyRandomVector := [3]RuleError{
			RuleErrorInvalidTransactionSignature, RuleErrorDerivedKeyNotAuthorized, RuleErrorDerivedKeyNotAuthorized,
		}
		randomPrivKey, err := btcec.NewPrivateKey()
		require.NoError(err)
		randomPrivKeyBase58Check := Base58CheckEncode(randomPrivKey.Serialize(), true, params)

		allTxns = append(allTxns, mempoolProcessAllSignatureCombinations(
			createTransaction,
			nil,
			randomPrivKeyBase58Check,
			nil,
			testMoneyRandomVector,
		)...)

		mineBlockAndVerifySignatures(allTxns)
	}
}

func TestBlockRewardPatch(t *testing.T) {
	chain, params, db := NewLowDifficultyBlockchain(t)
	defer func() {
		if chain.postgres != nil {
			require.NoError(t, ResetPostgres(chain.postgres))
		}
	}()
	params.ForkHeights.BlockRewardPatchBlockHeight = 0
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Mine some blocks so we have SOME money
	_, err := miner.MineAndProcessSingleBlock(0, mempool)
	require.NoError(t, err)
	_, err = miner.MineAndProcessSingleBlock(0, mempool)
	require.NoError(t, err)
	_, err = miner.MineAndProcessSingleBlock(0, mempool)
	require.NoError(t, err)

	_, _ = mempool, db
	// Try to split block reward among multiple keys
	{
		blkToMine, _, _, err := miner._getBlockToMine(0)
		require.NoError(t, err)
		blkRewardAmount := blkToMine.Txns[0].TxOutputs[0].AmountNanos
		blkRewardAmountSplit := blkRewardAmount / 2
		blkToMine.Txns[0].TxOutputs[0].AmountNanos = blkRewardAmountSplit
		blkToMine.Txns[0].TxOutputs = append(blkToMine.Txns[0].TxOutputs, &DeSoOutput{
			PublicKey:   MustBase58CheckDecode(recipientPkString),
			AmountNanos: blkRewardAmountSplit,
		})
		_, bestNonce, err := FindLowestHash(blkToMine.Header, 10000)
		require.NoError(t, err)
		txHashes, err := ComputeTransactionHashes(blkToMine.Txns)
		require.NoError(t, err)
		blkToMine.Header.Nonce = bestNonce
		utxoView, _ := NewUtxoView(db, params, chain.postgres, chain.snapshot, nil)
		_, err = utxoView.ConnectBlock(blkToMine, txHashes, true, nil, uint64(chain.blockTip().Height+1))
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorBlockRewardTxnMustHaveOneOutput)
	}
	testMeta := &TestMeta{
		t:                 t,
		chain:             chain,
		params:            params,
		db:                db,
		mempool:           mempool,
		miner:             miner,
		savedHeight:       chain.blockTip().Height + 1,
		feeRateNanosPerKb: uint64(101),
	}

	// Try include fees from block reward output public key, should fail.
	{
		txn := &MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs: []*DeSoInput{},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   MustBase58CheckDecode(recipientPkString),
					AmountNanos: 100,
				},
			},
			PublicKey: MustBase58CheckDecode(senderPkString),
			TxnMeta:   &BasicTransferMetadata{},
		}
		_, _, _, _, err :=
			chain.AddInputsAndChangeToTransaction(txn, testMeta.feeRateNanosPerKb, nil)
		require.NoError(t, err)
		_signTxn(t, txn, senderPrivString)
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot, nil)
		require.NoError(t, err)
		_, _, _, fees, err := utxoView._connectTransaction(txn, txn.Hash(), chain.blockTip().Height+1, 0, true, false)
		require.NoError(t, err)
		blkToMine, _, _, err := miner._getBlockToMine(0)
		require.NoError(t, err)
		// Append transaction and add fees to block reward output.
		blkToMine.Txns = append(blkToMine.Txns, txn)
		require.Len(t, blkToMine.Txns, 2)
		blkToMine.Txns[0].TxOutputs[0].AmountNanos += fees
		_, bestNonce, err := FindLowestHash(blkToMine.Header, 10000)
		require.NoError(t, err)
		txHashes, err := ComputeTransactionHashes(blkToMine.Txns)
		require.NoError(t, err)
		blkToMine.Header.Nonce = bestNonce
		utxoView, err = NewUtxoView(db, params, chain.postgres, chain.snapshot, nil)
		require.NoError(t, err)
		_, err = utxoView.ConnectBlock(blkToMine, txHashes, true, nil, uint64(chain.blockTip().Height+1))
		require.Contains(t, err.Error(), RuleErrorBlockRewardExceedsMaxAllowed)

		utxoView, err = NewUtxoView(db, params, chain.postgres, chain.snapshot, nil)
		require.NoError(t, err)
		// Reduce fees and try again, should succeed.
		blkToMine.Txns[0].TxOutputs[0].AmountNanos -= fees
		_, err = utxoView.ConnectBlock(blkToMine, txHashes, true, nil, uint64(chain.blockTip().Height+1))
		require.NoError(t, err)
	}
}
