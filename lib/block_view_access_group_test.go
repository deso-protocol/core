package lib

import (
	"bytes"
	"github.com/btcsuite/btcd/btcec"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"testing"
)

type accessGroupCreateTestData struct {
	userPrivateKey            string
	accessGroupOwnerPublicKey []byte
	accessGroupPublicKey      []byte
	accessGroupName           []byte
	extraData                 map[string][]byte
	expectedConnectError      error
}

func (data *accessGroupCreateTestData) IsDependency(other transactionTestInputSpace) bool {
	otherData := other.(*accessGroupCreateTestData)

	return bytes.Equal(data.accessGroupOwnerPublicKey, otherData.accessGroupOwnerPublicKey) &&
		bytes.Equal(data.accessGroupName, otherData.accessGroupName)
}

func (data *accessGroupCreateTestData) GetInputType() transactionTestInputType {
	return transactionTestInputTypeAccessGroupCreate
}

func TestAccessGroupCreate(t *testing.T) {
	require := require.New(t)
	_ = require

	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	m0PublicKey := NewPublicKey(m0PubBytes)
	m1PubBytes, _, _ := Base58CheckDecode(m1Pub)
	m1PublicKey := NewPublicKey(m1PubBytes)
	m2PubBytes, _, _ := Base58CheckDecode(m2Pub)
	m2PublicKey := NewPublicKey(m2PubBytes)
	m3PubBytes, _, _ := Base58CheckDecode(m3Pub)
	m3PublicKey := NewPublicKey(m3PubBytes)

	fundPublicKeysWithNanosMap := make(map[PublicKey]uint64)
	fundPublicKeysWithNanosMap[*m0PublicKey] = 100
	fundPublicKeysWithNanosMap[*m1PublicKey] = 100
	fundPublicKeysWithNanosMap[*m2PublicKey] = 100
	fundPublicKeysWithNanosMap[*m3PublicKey] = 100
	initChainCallback := func(tm *transactionTestMeta) {
		tm.params.ForkHeights.ExtraDataOnEntriesBlockHeight = 0
		tm.params.ForkHeights.DeSoAccessGroupsBlockHeight = 100
	}
	tConfig := &transactionTestConfig{
		t:                          t,
		testBadger:                 true,
		testPostgres:               true,
		testPostgresPort:           5433,
		initialBlocksMined:         4,
		fundPublicKeysWithNanosMap: fundPublicKeysWithNanosMap,
		initChainCallback:          initChainCallback,
	}

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

	groupName1 := []byte("group1")
	groupName2 := []byte("group2")
	groupName3 := []byte("group3")
	groupName4 := []byte("group4")
	groupName5 := []byte("group5")

	tv1 := _createAccessGroupCreateTestVector("TEST 1: (FAIL) Try connecting access group create transaction "+
		"before fork height", m0Priv, m0PubBytes, groupPk1, groupName1, nil,
		RuleErrorAccessGroupsBeforeBlockHeight)
	tv1.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta) {
		tm.params.ForkHeights.DeSoAccessGroupsBlockHeight = uint32(0)
	}
	tv1.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta) {
		tm.params.ForkHeights.DeSoAccessGroupsBlockHeight = uint32(1000)
	}
	tv2 := _createAccessGroupCreateTestVector("TEST 2: (PASS) Try connecting access group create transaction "+
		"after fork height", m0Priv, m0PubBytes, groupPk1, groupName1, nil,
		nil)
	tv3 := _createAccessGroupCreateTestVector("TEST 3: (FAIL) Try connecting access group create transaction "+
		"with a base group name", m0Priv, m0PubBytes, groupPk1, []byte{0}, nil,
		RuleErrorAccessGroupsNameCannotBeZeros)
	tv4 := _createAccessGroupCreateTestVector("TEST 4: (FAIL) Try connecting access group create transaction "+
		"with a duplicate group name", m0Priv, m0PubBytes, groupPk1, groupName1, nil,
		RuleErrorAccessGroupAlreadyExists)
	tv5 := _createAccessGroupCreateTestVector("TEST 5: (PASS) Try connecting access group create transaction "+
		"with unused group key name", m0Priv, m0PubBytes, groupPk1, groupName2, nil,
		nil)
	tv6 := _createAccessGroupCreateTestVector("TEST 6: (PASS) Try connecting access group create transaction "+
		"with another unused group key name", m0Priv, m0PubBytes, groupPk2, groupName3, nil,
		nil)
	tv7 := _createAccessGroupCreateTestVector("TEST 7: (FAIL) Try connecting access group create transaction "+
		"signed by non-group-owner public key", m1Priv, m0PubBytes, groupPk1, groupName1, nil,
		RuleErrorAccessGroupAlreadyExists)
	tv8 := _createAccessGroupCreateTestVector("TEST 8: (PASS) Try connecting access group create transaction "+
		"submitted by user 2", m1Priv, m1PubBytes, groupPk1, groupName1, nil,
		nil)
	tv9 := _createAccessGroupCreateTestVector("TEST 9: (PASS) Try connecting another access group create transaction "+
		"submitted by user 2 ", m1Priv, m1PubBytes, groupPk3, groupName4, nil,
		nil)
	tv10 := _createAccessGroupCreateTestVector("TEST 10: (FAIL) Try connecting group create transaction "+
		"submitted by user 2, but reusing the keyname", m1Priv, m1PubBytes, groupPk3, groupName1, nil,
		RuleErrorAccessGroupAlreadyExists)
	tv11 := _createAccessGroupCreateTestVector("TEST 11: (PASS) Try connecting group create transaction "+
		"submitted by user 2, with new group key name", m1Priv, m1PubBytes, groupPk1, groupName3, nil,
		nil)
	tv12 := _createAccessGroupCreateTestVector("TEST 12: (PASS) Try connecting group create transaction "+
		"submitted by user 3, with unused group key name", m2Priv, m2PubBytes, groupPk2, groupName4, nil,
		nil)
	tv13 := _createAccessGroupCreateTestVector("TEST 13: (PASS) Try connecting group create transaction "+
		"submitted by user 3, with another unused group key name", m2Priv, m2PubBytes, groupPk3, groupName5, nil,
		nil)
	tv14 := _createAccessGroupCreateTestVector("TEST 14: (FAIL) Try connecting group create transaction "+
		"submitted by user 3, but reusing the keyname", m2Priv, m2PubBytes, groupPk2, groupName5, nil,
		RuleErrorAccessGroupAlreadyExists)
	extraData1 := make(map[string][]byte)
	extraData1["test1"] = []byte("test1")
	extraData1["test2"] = []byte("test2")
	tv15 := _createAccessGroupCreateTestVector("TEST 15: (PASS) Try connecting group create transaction "+
		"submitted by user 3, with ExtraData", m2Priv, m2PubBytes, groupPk2, groupName3, extraData1,
		nil)

	tvv := [][]*transactionTestVector{{tv1, tv2, tv3, tv4, tv5, tv6, tv7, tv8, tv9, tv10, tv11, tv12, tv13, tv14, tv15}}
	tes := NewTransactionTestSuite(t, tvv, tConfig)
	tes.Run()
}

func _createAccessGroupCreateTestVector(id string, userPrivateKey string, accessGroupOwnerPublicKey []byte,
	accessGroupPublicKey []byte, accessGroupName []byte, extraData map[string][]byte, expectedConnectError error) (_tv *transactionTestVector) {

	testData := &accessGroupCreateTestData{
		userPrivateKey:            userPrivateKey,
		accessGroupOwnerPublicKey: accessGroupOwnerPublicKey,
		accessGroupPublicKey:      accessGroupPublicKey,
		accessGroupName:           accessGroupName,
		extraData:                 extraData,
		expectedConnectError:      expectedConnectError,
	}
	return &transactionTestVector{
		id:         transactionTestIdentifier(id),
		inputSpace: testData,
		getTransaction: func(tv *transactionTestVector, tm *transactionTestMeta) (*MsgDeSoTxn, error) {
			dataSpace := tv.inputSpace.(*accessGroupCreateTestData)
			txn, err := _createSignedAccessGroupCreateTransaction(
				tm.t, tm.chain, tm.mempool,
				dataSpace.userPrivateKey, dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupPublicKey,
				dataSpace.accessGroupName, dataSpace.extraData)
			require.NoError(tm.t, err)
			return txn, dataSpace.expectedConnectError
		},
		verifyUtxoViewEntry: func(tv *transactionTestVector, tm *transactionTestMeta,
			utxoView *UtxoView, expectDeleted bool) {

			dataSpace := tv.inputSpace.(*accessGroupCreateTestData)
			_verifyUtxoViewEntryForAccessGroupCreate(
				tm.t, utxoView, expectDeleted,
				dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupPublicKey,
				dataSpace.accessGroupName, dataSpace.extraData)
		},
		verifyDbEntry: func(tv *transactionTestVector, tm *transactionTestMeta,
			dbAdapter *DbAdapter, expectDeleted bool) {

			dataSpace := tv.inputSpace.(*accessGroupCreateTestData)
			_verifyDbEntryForAccessGroupCreate(
				tm.t, dbAdapter, expectDeleted,
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

func _verifyUtxoViewEntryForAccessGroupCreate(t *testing.T, utxoView *UtxoView, expectDeleted bool,
	accessGroupOwnerPublicKey []byte, accessGroupPublicKey []byte, accessGroupKeyName []byte, extraData map[string][]byte) {

	require := require.New(t)
	// If either of the provided parameters is nil, we return.
	accessGroupKey := NewAccessGroupId(NewPublicKey(accessGroupOwnerPublicKey), NewGroupKeyName(accessGroupKeyName)[:])

	// If the group has already been fetched in this utxoView, then we get it directly from there.
	accessGroupEntry, exists := utxoView.AccessGroupIdToAccessGroupEntry[*accessGroupKey]
	if !expectDeleted {
		require.Equal(true, exists)
		require.NotNil(accessGroupEntry)
		require.Equal(false, accessGroupEntry.isDeleted)
		require.Equal(true, _verifyEqualAccessGroupCreateEntry(
			t, accessGroupEntry, accessGroupOwnerPublicKey, accessGroupPublicKey, accessGroupKeyName, extraData))
	} else {
		if !exists || accessGroupEntry == nil || accessGroupEntry.isDeleted {
			return
		}
		require.Equal(false, _verifyEqualAccessGroupCreateEntry(
			t, accessGroupEntry, accessGroupOwnerPublicKey, accessGroupPublicKey, accessGroupKeyName, extraData))
	}

}

func _verifyDbEntryForAccessGroupCreate(t *testing.T, dbAdapter *DbAdapter, expectDeleted bool,
	accessGroupOwnerPublicKey []byte, accessGroupPublicKey []byte, accessGroupKeyName []byte, extraData map[string][]byte) {

	require := require.New(t)

	// If either of the provided parameters is nil, we return.

	accessGroupId := NewAccessGroupId(NewPublicKey(accessGroupOwnerPublicKey), accessGroupKeyName)
	accessGroupEntry, err := dbAdapter.GetAccessGroupEntryByAccessGroupId(accessGroupId)
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
