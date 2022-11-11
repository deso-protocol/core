package lib

import (
	"bytes"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAccessGroupCreate(t *testing.T) {
	require := require.New(t)
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
	_ = savedHeight
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

	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	m1PubBytes, _, _ := Base58CheckDecode(m1Pub)
	_ = m1PubBytes
	m2PubBytes, _, _ := Base58CheckDecode(m2Pub)
	_ = m2PubBytes

	groupPriv1, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	groupPk1 := groupPriv1.PubKey().SerializeCompressed()

	groupPriv2, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	groupPk2 := groupPriv2.PubKey().SerializeCompressed()
	_ = groupPk2

	groupPriv3, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	groupPk3 := groupPriv3.PubKey().SerializeCompressed()
	_ = groupPk3

	// ===================================================================================
	// Test #1: Make sure transaction fails before the block height.
	// ===================================================================================
	groupName1 := []byte("group1")
	groupName2 := []byte("group2")
	groupName3 := []byte("group3")
	groupName4 := []byte("group4")
	groupName5 := []byte("group5")
	tm := testMeta{
		t:       t,
		chain:   chain,
		db:      db,
		pg:      nil,
		params:  params,
		mempool: mempool,
		miner:   miner,
	}

	tv1 := _createAccessGroupCreateTestVector(tm, "TEST 1: (FAIL) Try connecting access group create transaction "+
		"before fork height", m0Priv, m0PubBytes, groupPk1, groupName1, nil,
		RuleErrorAccessGroupsBeforeBlockHeight)
	tv1.connectCallback = func(tv *testVector) {
		tv.params.ForkHeights.DeSoAccessGroupsBlockHeight = uint32(0)
	}
	tv1.disconnectCallback = func(tv *testVector) {
		tv.params.ForkHeights.DeSoAccessGroupsBlockHeight = uint32(1000)
	}
	tv2 := _createAccessGroupCreateTestVector(tm, "TEST 2: (PASS) Try connecting access group create transaction "+
		"after fork height", m0Priv, m0PubBytes, groupPk1, groupName1, nil,
		nil)
	tv3 := _createAccessGroupCreateTestVector(tm, "TEST 3: (FAIL) Try connecting access group create transaction "+
		"with a base group name", m0Priv, m0PubBytes, groupPk1, []byte{0}, nil,
		RuleErrorAccessGroupsNameCannotBeZeros)
	tv4 := _createAccessGroupCreateTestVector(tm, "TEST 4: (FAIL) Try connecting access group create transaction "+
		"with a duplicate group name", m0Priv, m0PubBytes, groupPk1, groupName1, nil,
		RuleErrorAccessGroupAlreadyExists)
	tv5 := _createAccessGroupCreateTestVector(tm, "TEST 5: (PASS) Try connecting access group create transaction "+
		"with unused group key name", m0Priv, m0PubBytes, groupPk1, groupName2, nil,
		nil)
	tv6 := _createAccessGroupCreateTestVector(tm, "TEST 6: (PASS) Try connecting access group create transaction "+
		"with another unused group key name", m0Priv, m0PubBytes, groupPk2, groupName3, nil,
		nil)
	tv7 := _createAccessGroupCreateTestVector(tm, "TEST 7: (FAIL) Try connecting access group create transaction "+
		"signed by non-group-owner public key", m1Priv, m0PubBytes, groupPk1, groupName1, nil,
		RuleErrorAccessGroupAlreadyExists)
	tv8 := _createAccessGroupCreateTestVector(tm, "TEST 8: (PASS) Try connecting access group create transaction "+
		"submitted by user 2", m1Priv, m1PubBytes, groupPk1, groupName1, nil,
		nil)
	tv9 := _createAccessGroupCreateTestVector(tm, "TEST 9: (PASS) Try connecting another access group create transaction "+
		"submitted by user 2 ", m1Priv, m1PubBytes, groupPk3, groupName4, nil,
		nil)
	tv10 := _createAccessGroupCreateTestVector(tm, "TEST 10: (FAIL) Try connecting group create transaction "+
		"submitted by user 2, but reusing the keyname", m1Priv, m1PubBytes, groupPk3, groupName1, nil,
		RuleErrorAccessGroupAlreadyExists)
	tv11 := _createAccessGroupCreateTestVector(tm, "TEST 11: (PASS) Try connecting group create transaction "+
		"submitted by user 2, with new group key name", m1Priv, m1PubBytes, groupPk1, groupName3, nil,
		nil)
	tv12 := _createAccessGroupCreateTestVector(tm, "TEST 12: (PASS) Try connecting group create transaction "+
		"submitted by user 3, with unused group key name", m2Priv, m2PubBytes, groupPk2, groupName4, nil,
		nil)
	tv13 := _createAccessGroupCreateTestVector(tm, "TEST 13: (PASS) Try connecting group create transaction "+
		"submitted by user 3, with another unused group key name", m2Priv, m2PubBytes, groupPk3, groupName5, nil,
		nil)
	tv14 := _createAccessGroupCreateTestVector(tm, "TEST 14: (FAIL) Try connecting group create transaction "+
		"submitted by user 3, but reusing the keyname", m2Priv, m2PubBytes, groupPk2, groupName5, nil,
		RuleErrorAccessGroupAlreadyExists)

	tvv := [][]*testVector{{tv1, tv2, tv3, tv4, tv5, tv6, tv7, tv8, tv9, tv10, tv11, tv12, tv13, tv14}}
	tes := testSuite{
		testMeta:             tm,
		testVectorsByBlock:   tvv,
		testVectorDependency: make(map[identifier][]identifier),
	}
	tes.run()

	//txn0, err := _createSignedAccessGroupCreateTransaction(
	//	t, chain, mempool, m0Priv, m0PubBytes, groupPk1, groupName1, nil)
	//_, err = mempool.ProcessTransaction(txn0, false, false, 0, true)
	//require.Contains(err.Error(), RuleErrorAccessGroupsBeforeBlockHeight)
	//_verifyMempoolUtxoViewEntryForAccessGroupCreate(t, mempool, false, m0PubBytes, groupPk1, groupName1, nil)
	//
	//params.ForkHeights.DeSoAccessGroupsBlockHeight = uint32(0)
	//_, err = mempool.ProcessTransaction(txn0, false, false, 0, true)
	//require.NoError(err)
	//
	//_verifyMempoolUtxoViewEntryForAccessGroupCreate(t, mempool, true, m0PubBytes, groupPk1, groupName1, nil)
}

type InputType byte

const (
	InputTypeAccessGroupCreate InputType = iota
)

type InputSpace interface {
	IsDependency(other InputSpace) bool
	GetInputType() InputType
}

type accessGroupCreateTestData struct {
	userPrivateKey            string
	accessGroupOwnerPublicKey []byte
	accessGroupPublicKey      []byte
	accessGroupName           []byte
	extraData                 map[string][]byte

	_expectedConnectError error
}

func (data *accessGroupCreateTestData) IsDependency(other InputSpace) bool {
	otherData := other.(*accessGroupCreateTestData)

	return bytes.Equal(data.accessGroupOwnerPublicKey, otherData.accessGroupOwnerPublicKey) &&
		bytes.Equal(data.accessGroupName, otherData.accessGroupName)
}

func (data *accessGroupCreateTestData) GetInputType() InputType {
	return InputTypeAccessGroupCreate
}

type testMeta struct {
	t       *testing.T
	chain   *Blockchain
	db      *badger.DB
	pg      *Postgres
	params  *DeSoParams
	mempool *DeSoMempool
	miner   *DeSoMiner
}

type identifier string

type testVector struct {
	testMeta
	id                 identifier
	inputSpace         InputSpace
	getTransaction     func(tv *testVector) (_transaction *MsgDeSoTxn, _expectedConnectUtxoViewError error)
	verifyMempoolEntry func(tv *testVector, expectDeleted bool)
	verifyDbEntry      func(tv *testVector, expectDeleted bool)
	connectCallback    func(tv *testVector)
	disconnectCallback func(tv *testVector)
}

type testSuite struct {
	testMeta
	testVectorsByBlock   [][]*testVector
	testVectorsInDb      []*testVector
	testVectorsInMempool []*testVector
	testVectorDependency map[identifier][]identifier
}

func (tes *testSuite) run() {
	//require := require.New(tes.t)
	for _, testVectors := range tes.testVectorsByBlock {
		// Run all the test vectors for this block.
		tes.testConnectDisconnectBlock(testVectors)
	}
}

func (tes *testSuite) testConnectBlock(testVectors []*testVector) (
	_validTransactions []bool, _addedBlock *MsgDeSoBlock) {
	require := require.New(tes.t)

	validTransactions := make([]bool, len(testVectors))
	for ii, tv := range testVectors {
		glog.Infof("Running test vector: %v", tv.id)
		txn, _expectedErr := tv.getTransaction(tv)
		_, err := tes.mempool.ProcessTransaction(txn, false, false, 0, true)
		if _expectedErr != nil {
			require.Contains(err.Error(), _expectedErr.Error())
			validTransactions[ii] = false
		} else {
			require.NoError(err)
			tv.verifyMempoolEntry(tv, false)
			validTransactions[ii] = true
		}
		if tv.connectCallback != nil {
			tv.connectCallback(tv)
		}
	}
	addedBlock, err := tes.miner.MineAndProcessSingleBlock(0, tes.mempool)
	require.NoError(err)
	_ = addedBlock

	for ii, tv := range testVectors {
		if !validTransactions[ii] {
			continue
		}
		tv.verifyDbEntry(tv, false)
	}

	return validTransactions, addedBlock
}

func (tes *testSuite) testConnectDisconnectBlock(testVectors []*testVector) {
	require := require.New(tes.t)

	validTransactions, addedBlock := tes.testConnectBlock(testVectors)
	blockHeight := tes.chain.BlockTip().Height
	utxoView, err := NewUtxoView(tes.db, tes.params, tes.pg, tes.chain.snapshot)
	require.NoError(err)
	txHashes, err := ComputeTransactionHashes(addedBlock.Txns)
	require.NoError(err)
	blockHash, err := addedBlock.Header.Hash()
	require.NoError(err)
	utxoOps, err := GetUtxoOperationsForBlock(tes.db, tes.chain.snapshot, blockHash)
	err = utxoView.DisconnectBlock(addedBlock, txHashes, utxoOps, uint64(blockHeight))
	require.NoError(err)
	for ii, tv := range testVectors {
		if !validTransactions[ii] {
			continue
		}
		tv.verifyMempoolEntry(tv, true)
	}

	err = tes.chain.DisconnectBlocksToHeight(uint64(blockHeight)-1, tes.chain.snapshot)
	require.NoError(err)
	for ii := len(testVectors) - 1; ii >= 0; ii-- {
		if !validTransactions[ii] {
			continue
		}
		tv := testVectors[ii]
		tv.verifyDbEntry(tv, true)
		if tv.disconnectCallback != nil {
			tv.disconnectCallback(tv)
		}
	}
}

func (tes *testSuite) addTestVectorToMempool(tv *testVector) {
	require := require.New(tes.t)
	require.NotNil(tes.testVectorDependency)
	require.Nil(tes.testVectorDependency[tv.id])

	for _, tvInDb := range tes.testVectorsInDb {
		if tvInDb.inputSpace.IsDependency(tv.inputSpace) {
			tes.testVectorDependency[tv.id] = append(tes.testVectorDependency[tv.id], tvInDb.id)
		}
	}
	for _, tvInMempool := range tes.testVectorsInMempool {
		if tvInMempool.inputSpace.IsDependency(tv.inputSpace) {
			tes.testVectorDependency[tv.id] = append(tes.testVectorDependency[tv.id], tvInMempool.id)
		}
	}
	tes.testVectorsInMempool = append(tes.testVectorsInMempool, tv)
}

func _createAccessGroupCreateTestVector(tm testMeta, id string, userPrivateKey string, accessGroupOwnerPublicKey []byte,
	accessGroupPublicKey []byte, accessGroupName []byte, extraData map[string][]byte, _expectedConnectError error) (_tv *testVector) {

	require := require.New(tm.t)
	testData := &accessGroupCreateTestData{
		userPrivateKey:            userPrivateKey,
		accessGroupOwnerPublicKey: accessGroupOwnerPublicKey,
		accessGroupPublicKey:      accessGroupPublicKey,
		accessGroupName:           accessGroupName,
		extraData:                 extraData,
		_expectedConnectError:     _expectedConnectError,
	}
	return &testVector{
		testMeta:   tm,
		id:         identifier(id),
		inputSpace: testData,
		getTransaction: func(tv *testVector) (*MsgDeSoTxn, error) {
			dataSpace := tv.inputSpace.(*accessGroupCreateTestData)
			txn, err := _createSignedAccessGroupCreateTransaction(
				tv.testMeta.t, tv.testMeta.chain, tv.testMeta.mempool,
				dataSpace.userPrivateKey, dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupPublicKey,
				dataSpace.accessGroupName, dataSpace.extraData)
			require.NoError(err)
			return txn, dataSpace._expectedConnectError
		},
		verifyMempoolEntry: func(tv *testVector, expectDeleted bool) {
			dataSpace := tv.inputSpace.(*accessGroupCreateTestData)
			_verifyMempoolUtxoViewEntryForAccessGroupCreate(
				tv.testMeta.t, tv.testMeta.mempool, expectDeleted,
				dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupPublicKey,
				dataSpace.accessGroupName, dataSpace.extraData)
		},
		verifyDbEntry: func(tv *testVector, expectDeleted bool) {
			dataSpace := tv.inputSpace.(*accessGroupCreateTestData)
			_verifyDbEntryForAccessGroupCreate(
				tv.testMeta.t, tv.testMeta.chain, expectDeleted,
				dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupPublicKey,
				dataSpace.accessGroupName, dataSpace.extraData)
		},
	}
}

func _createSignedAccessGroupCreateTransaction(t *testing.T, chain *Blockchain, mempool *DeSoMempool, userPrivateKey string,
	accessGroupOwnerPublicKey []byte, accessGroupPublicKey []byte, accessGroupName []byte, extraData map[string][]byte) (
	_txn *MsgDeSoTxn, _err error) {

	require := require.New(t)

	// Create the transaction.
	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateAccessGroupCreateTxn(
		accessGroupOwnerPublicKey, accessGroupPublicKey, accessGroupName,
		extraData, 10, mempool, []*DeSoOutput{})
	if err != nil {
		return nil, errors.Wrapf(err, "_createSignedAccessGroupCreateTransaction: ")
	}
	require.Equal(totalInputMake, changeAmountMake+feesMake)
	_signTxn(t, txn, userPrivateKey)
	return txn, nil
}

func _verifyMempoolUtxoViewEntryForAccessGroupCreate(t *testing.T, mempool *DeSoMempool, expectDeleted bool,
	accessGroupOwnerPublicKey []byte, accessGroupPublicKey []byte, accessGroupKeyName []byte, extraData map[string][]byte) {

	require := require.New(t)
	utxoView, err := mempool.GetAugmentedUniversalView()
	require.NoError(err)
	// If either of the provided parameters is nil, we return.
	accessGroupKey := NewAccessGroupKey(NewPublicKey(accessGroupOwnerPublicKey), NewGroupKeyName(accessGroupKeyName)[:])

	// If the group has already been fetched in this utxoView, then we get it directly from there.
	accessGroupEntry, exists := utxoView.AccessGroupKeyToAccessGroupEntry[*accessGroupKey]
	if !expectDeleted {
		require.Equal(true, exists)
		require.NotNil(accessGroupEntry)
		require.Equal(false, accessGroupEntry.isDeleted)
		require.Equal(true, _verifyEqualAccessGroupCreateEntry(t, accessGroupEntry, accessGroupOwnerPublicKey, accessGroupPublicKey, accessGroupKeyName, extraData))
	} else {
		if !exists || accessGroupEntry == nil || accessGroupEntry.isDeleted {
			return
		}
		require.Equal(false, _verifyEqualAccessGroupCreateEntry(t, accessGroupEntry, accessGroupOwnerPublicKey, accessGroupPublicKey, accessGroupKeyName, extraData))
	}

}

func _verifyDbEntryForAccessGroupCreate(t *testing.T, chain *Blockchain, expectDeleted bool,
	accessGroupOwnerPublicKey []byte, accessGroupPublicKey []byte, accessGroupKeyName []byte, extraData map[string][]byte) {

	require := require.New(t)

	// If either of the provided parameters is nil, we return.
	accessGroupEntry, err := DBGetAccessGroupEntryByAccessGroupId(chain.db, chain.snapshot,
		NewPublicKey(accessGroupOwnerPublicKey), NewGroupKeyName(accessGroupKeyName))
	require.NoError(err)
	if !expectDeleted {
		require.Equal(true, _verifyEqualAccessGroupCreateEntry(t, accessGroupEntry, accessGroupOwnerPublicKey, accessGroupPublicKey, accessGroupKeyName, extraData))
	} else {
		if accessGroupEntry == nil {
			return
		}
		require.Equal(false, _verifyEqualAccessGroupCreateEntry(t, accessGroupEntry, accessGroupOwnerPublicKey, accessGroupPublicKey, accessGroupKeyName, extraData))
	}
}

func _verifyEqualAccessGroupCreateEntry(t *testing.T, accessGroupEntry *AccessGroupEntry, accessGroupOwnerPublicKey []byte,
	accessGroupPublicKey []byte, accessGroupKeyName []byte, extraData map[string][]byte) bool {

	require := require.New(t)
	// TODO: add error logging
	require.NotNil(accessGroupEntry)
	require.NotNil(accessGroupEntry.AccessGroupOwnerPublicKey)
	require.NotNil(accessGroupEntry.AccessGroupPublicKey)
	require.NotNil(accessGroupEntry.AccessGroupKeyName)
	if !bytes.Equal(NewPublicKey(accessGroupOwnerPublicKey).ToBytes(), accessGroupEntry.AccessGroupOwnerPublicKey.ToBytes()) {
		return false
	}
	if !bytes.Equal(NewPublicKey(accessGroupPublicKey).ToBytes(), accessGroupEntry.AccessGroupPublicKey.ToBytes()) {
		return false
	}
	if !bytes.Equal(NewGroupKeyName(accessGroupKeyName).ToBytes(), accessGroupEntry.AccessGroupKeyName.ToBytes()) {
		return false
	}
	if !bytes.Equal(EncodeExtraData(extraData), EncodeExtraData(accessGroupEntry.ExtraData)) {
		return false
	}
	return true
}
