package lib

import (
	"bytes"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"testing"
)

type AccessGroupTestData struct {
	userPrivateKey            string
	userPublicKey             []byte
	accessGroupOwnerPublicKey []byte
	accessGroupPublicKey      []byte
	accessGroupName           []byte
	operationType             AccessGroupOperationType
	extraData                 map[string][]byte
	expectedConnectError      error
}

func (data *AccessGroupTestData) IsDependency(other transactionTestInputSpace) bool {
	otherData := other.(*AccessGroupTestData)

	return bytes.Equal(data.accessGroupOwnerPublicKey, otherData.accessGroupOwnerPublicKey) &&
		bytes.Equal(data.accessGroupName, otherData.accessGroupName)
}

func (data *AccessGroupTestData) GetInputType() transactionTestInputType {
	return transactionTestInputTypeAccessGroup
}

func TestAccessGroup(t *testing.T) {
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
		_setAccessGroupParams(tm)
		tm.params.ForkHeights.AssociationsAndAccessGroupsBlockHeight = 100
	}
	tConfig := &transactionTestConfig{
		t:                          t,
		testBadger:                 true,
		testPostgres:               false,
		testPostgresPort:           5433,
		disableLogging:             true,
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

	tv1 := _createAccessGroupTestVector("TEST 1: (FAIL) Try connecting access group create transaction "+
		"before fork height", m0Priv, m0PubBytes, m0PubBytes, groupPk1, groupName1,
		AccessGroupOperationTypeCreate, nil, RuleErrorAccessGroupsBeforeBlockHeight)
	tv1.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		tm.params.ForkHeights.AssociationsAndAccessGroupsBlockHeight = uint32(1)
	}
	tv2 := _createAccessGroupTestVector("TEST 2: (PASS) Try connecting access group create transaction "+
		"after fork height", m0Priv, m0PubBytes, m0PubBytes, groupPk1, groupName1,
		AccessGroupOperationTypeCreate, nil, nil)
	groupM0N1 := &AccessGroupId{*m0PublicKey, *NewGroupKeyName(groupName1)}
	groupM0B := &AccessGroupId{*m0PublicKey, *BaseGroupKeyName()}
	tv2.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0B}, []*AccessGroupId{})
	}
	tv2.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0B}, []*AccessGroupId{})
	}
	tv3 := _createAccessGroupTestVector("TEST 3: (FAIL) Try connecting access group create transaction "+
		"with a base group name", m0Priv, m0PubBytes, m0PubBytes, groupPk1, []byte{0}, AccessGroupOperationTypeCreate,
		nil, RuleErrorAccessGroupsNameCannotBeZeros)
	tv4 := _createAccessGroupTestVector("TEST 4: (FAIL) Try connecting access group create transaction "+
		"with a duplicate group name", m0Priv, m0PubBytes, m0PubBytes, groupPk1, groupName1, AccessGroupOperationTypeCreate,
		nil, RuleErrorAccessGroupAlreadyExists)
	tv5 := _createAccessGroupTestVector("TEST 5: (PASS) Try connecting access group create transaction "+
		"with unused group key name", m0Priv, m0PubBytes, m0PubBytes, groupPk1, groupName2, AccessGroupOperationTypeCreate,
		nil, nil)
	groupM0N2 := &AccessGroupId{*m0PublicKey, *NewGroupKeyName(groupName2)}
	tv5.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0N2, groupM0B}, []*AccessGroupId{})
	}
	tv5.disconnectCallback = tv2.connectCallback
	tv6 := _createAccessGroupTestVector("TEST 6: (PASS) Try connecting access group create transaction "+
		"with another unused group key name", m0Priv, m0PubBytes, m0PubBytes, groupPk2, groupName3,
		AccessGroupOperationTypeCreate, nil, nil)
	groupM0N3 := &AccessGroupId{*m0PublicKey, *NewGroupKeyName(groupName3)}
	tv6.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0N2, groupM0N3, groupM0B}, []*AccessGroupId{})
	}
	tv6.disconnectCallback = tv5.connectCallback
	tv7 := _createAccessGroupTestVector("TEST 7: (FAIL) Try connecting access group create transaction "+
		"signed by non-group-owner public key", m1Priv, m1PubBytes, m0PubBytes, groupPk1, groupName1,
		AccessGroupOperationTypeCreate, nil, RuleErrorAccessGroupOwnerPublicKeyCannotBeDifferent)
	tv8 := _createAccessGroupTestVector("TEST 8: (PASS) Try connecting access group create transaction "+
		"submitted by user 2", m1Priv, m1PubBytes, m1PubBytes, groupPk1, groupName1, AccessGroupOperationTypeCreate,
		nil, nil)
	groupM1N1 := &AccessGroupId{*m1PublicKey, *NewGroupKeyName(groupName1)}
	groupM1B := &AccessGroupId{*m1PublicKey, *BaseGroupKeyName()}
	tv8.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0N2, groupM0N3, groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1N1, groupM1B}, []*AccessGroupId{})
	}
	tv8.disconnectCallback = tv6.connectCallback
	// Some simple access group update tests.
	otherExtraData := make(map[string][]byte)
	otherExtraData["dummy"] = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	otherGroupPk := groupPk3
	tv8p5 := _createAccessGroupTestVector("TEST 8.5: (PASS) Try connecting access group update transaction "+
		"submitted by user 2", m1Priv, m1PubBytes, m1PubBytes, otherGroupPk, groupName1, AccessGroupOperationTypeUpdate,
		otherExtraData, nil)
	tv8p75 := _createAccessGroupTestVector("TEST 8.75: (PASS) Try connecting access group update transaction "+
		"submitted by user 2", m1Priv, m1PubBytes, m1PubBytes, otherGroupPk, groupName1, AccessGroupOperationTypeUpdate,
		otherExtraData, nil)
	tv8p99 := _createAccessGroupTestVector("TEST 8.99: (FAIL) Try connecting access group update transaction "+
		"submitted by user 2 for non existing group", m1Priv, m1PubBytes, m1PubBytes, groupPk2, groupName4,
		AccessGroupOperationTypeUpdate, nil, RuleErrorAccessGroupDoesNotExist)
	tv9 := _createAccessGroupTestVector("TEST 9: (PASS) Try connecting another access group create transaction "+
		"submitted by user 2 ", m1Priv, m1PubBytes, m1PubBytes, groupPk3, groupName4,
		AccessGroupOperationTypeCreate, nil, nil)
	groupM1N4 := &AccessGroupId{*m1PublicKey, *NewGroupKeyName(groupName4)}
	tv9.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0N2, groupM0N3, groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1N1, groupM1N4, groupM1B}, []*AccessGroupId{})
	}
	tv9.disconnectCallback = tv8.connectCallback
	tv10 := _createAccessGroupTestVector("TEST 10: (FAIL) Try connecting group create transaction "+
		"submitted by user 2, but reusing the keyname", m1Priv, m1PubBytes, m1PubBytes, groupPk3, groupName1,
		AccessGroupOperationTypeCreate, nil, RuleErrorAccessGroupAlreadyExists)
	tv11 := _createAccessGroupTestVector("TEST 11: (PASS) Try connecting group create transaction "+
		"submitted by user 2, with new group key name", m1Priv, m1PubBytes, m1PubBytes, groupPk1, groupName3,
		AccessGroupOperationTypeCreate, nil, nil)
	groupM1N3 := &AccessGroupId{*m1PublicKey, *NewGroupKeyName(groupName3)}
	tv11.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0N2, groupM0N3, groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1N1, groupM1N3, groupM1N4, groupM1B}, []*AccessGroupId{})
	}
	tv11.disconnectCallback = tv9.connectCallback
	tv12 := _createAccessGroupTestVector("TEST 12: (PASS) Try connecting group create transaction "+
		"submitted by user 3, with unused group key name", m2Priv, m2PubBytes, m2PubBytes, groupPk2, groupName4,
		AccessGroupOperationTypeCreate, nil, nil)
	groupM2N4 := &AccessGroupId{*m2PublicKey, *NewGroupKeyName(groupName4)}
	groupM2B := &AccessGroupId{*m2PublicKey, *BaseGroupKeyName()}
	tv12.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0N2, groupM0N3, groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1N1, groupM1N3, groupM1N4, groupM1B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m2PubBytes, utxoView, []*AccessGroupId{groupM2N4, groupM2B}, []*AccessGroupId{})
	}
	tv12.disconnectCallback = tv11.connectCallback
	tv13 := _createAccessGroupTestVector("TEST 13: (PASS) Try connecting group create transaction "+
		"submitted by user 3, with another unused group key name", m2Priv, m2PubBytes, m2PubBytes, groupPk3, groupName5,
		AccessGroupOperationTypeCreate, nil, nil)
	groupM2N5 := &AccessGroupId{*m2PublicKey, *NewGroupKeyName(groupName5)}
	tv13.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0N2, groupM0N3, groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1N1, groupM1N3, groupM1N4, groupM1B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m2PubBytes, utxoView, []*AccessGroupId{groupM2N4, groupM2N5, groupM2B}, []*AccessGroupId{})
	}
	tv13.disconnectCallback = tv12.connectCallback
	tv14 := _createAccessGroupTestVector("TEST 14: (FAIL) Try connecting group create transaction "+
		"submitted by user 3, but reusing the keyname", m2Priv, m2PubBytes, m2PubBytes, groupPk2, groupName5,
		AccessGroupOperationTypeCreate, nil, RuleErrorAccessGroupAlreadyExists)
	extraData1 := make(map[string][]byte)
	extraData1["test1"] = []byte("test1")
	extraData1["test2"] = []byte("test2")
	tv15 := _createAccessGroupTestVector("TEST 15: (PASS) Try connecting group create transaction "+
		"submitted by user 3, with ExtraData", m2Priv, m2PubBytes, m2PubBytes, groupPk2, groupName3,
		AccessGroupOperationTypeCreate, extraData1, nil)
	groupM2N3 := &AccessGroupId{*m2PublicKey, *NewGroupKeyName(groupName3)}
	tv15.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0N2, groupM0N3, groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1N1, groupM1N3, groupM1N4, groupM1B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m2PubBytes, utxoView, []*AccessGroupId{groupM2N3, groupM2N4, groupM2N5, groupM2B}, []*AccessGroupId{})
	}
	tv15.disconnectCallback = tv13.connectCallback
	tv16 := _createAccessGroupTestVector("TEST 16: (FAIL) Try connecting group create transaction "+
		"submitted by user 4, but access group owner public key is malformed", m3Priv, m3PubBytes, m3PubBytes[:10],
		groupPk1, groupName1, AccessGroupOperationTypeCreate, nil, RuleErrorAccessGroupOwnerPublicKeyCannotBeDifferent)
	var groupNameTooShort []byte
	groupNameTooShort = nil
	groupNameTooLong := []byte{}
	for ii := 0; ii < MaxAccessGroupKeyNameCharacters+5; ii++ {
		groupNameTooLong = append(groupNameTooLong, 0)
	}
	tv17 := _createAccessGroupTestVector("TEST 17: (FAIL) Try connecting group create transaction "+
		"submitted by user 4, but access group key name is too short", m3Priv, m3PubBytes, m3PubBytes, groupPk1,
		groupNameTooShort, AccessGroupOperationTypeCreate, nil, RuleErrorAccessGroupKeyNameTooShort)
	tv18 := _createAccessGroupTestVector("TEST 18: (FAIL) Try connecting group create transaction "+
		"submitted by user 4, but access group key name is too long", m3Priv, m3PubBytes, m3PubBytes, groupPk1,
		groupNameTooLong, AccessGroupOperationTypeCreate, nil, RuleErrorAccessGroupKeyNameTooLong)
	tv19 := _createAccessGroupTestVector("TEST 19: (FAIL) Try connecting group create transaction "+
		"submitted by user 4, but access group public key is malformed", m3Priv, m3PubBytes, m3PubBytes, groupPk1[:10],
		groupName1, AccessGroupOperationTypeCreate, nil, RuleErrorPubKeyLen)
	tv20 := _createAccessGroupTestVector("TEST 20: (FAIL) Try connecting group create transaction "+
		"submitted by user 4, but access group public key is the same as access group owner public key",
		m3Priv, m3PubBytes, m3PubBytes, m3PubBytes, groupName1,
		AccessGroupOperationTypeCreate, nil, RuleErrorAccessPublicKeyCannotBeOwnerKey)

	tvv := []*transactionTestVector{tv1, tv2, tv3, tv4, tv5, tv6, tv7, tv8, tv8p5, tv8p75, tv8p99, tv9, tv10, tv11, tv12,
		tv13, tv14, tv15, tv16, tv17, tv18, tv19, tv20}

	tvbConnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		tv15.connectCallback(tv15, tm, utxoView)
	}
	tvbDisconnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		// Reset the ForkHeight for access groups
		tm.params.ForkHeights.AssociationsAndAccessGroupsBlockHeight = uint32(1000)
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m2PubBytes, utxoView, []*AccessGroupId{groupM2B}, []*AccessGroupId{})
	}
	tvb := []*transactionTestVectorBlock{NewTransactionTestVectorBlock(tvv, tvbConnectCallback, tvbDisconnectCallback)}
	tes := NewTransactionTestSuite(t, tvb, tConfig)
	tes.Run()
}

func _createAccessGroupTestVector(id string, userPrivateKey string, userPublicKey []byte, accessGroupOwnerPublicKey []byte,
	accessGroupPublicKey []byte, accessGroupName []byte, operationType AccessGroupOperationType,
	extraData map[string][]byte, expectedConnectError error) (_tv *transactionTestVector) {

	testData := &AccessGroupTestData{
		userPrivateKey:            userPrivateKey,
		userPublicKey:             userPublicKey,
		accessGroupOwnerPublicKey: accessGroupOwnerPublicKey,
		accessGroupPublicKey:      accessGroupPublicKey,
		accessGroupName:           accessGroupName,
		operationType:             operationType,
		extraData:                 extraData,
		expectedConnectError:      expectedConnectError,
	}
	return &transactionTestVector{
		id:         transactionTestIdentifier(id),
		inputSpace: testData,
		getTransaction: func(tv *transactionTestVector, tm *transactionTestMeta) (*MsgDeSoTxn, error) {
			dataSpace := tv.inputSpace.(*AccessGroupTestData)
			txn, err := _createSignedAccessGroupTransaction(
				tm.t, tm.chain, tm.mempool,
				dataSpace.userPrivateKey, dataSpace.userPublicKey, dataSpace.accessGroupOwnerPublicKey,
				dataSpace.accessGroupPublicKey, dataSpace.accessGroupName, dataSpace.operationType, dataSpace.extraData)
			require.NoError(tm.t, err)
			return txn, dataSpace.expectedConnectError
		},
		verifyConnectUtxoViewEntry: func(tv *transactionTestVector, tm *transactionTestMeta,
			utxoView *UtxoView) {

			dataSpace := tv.inputSpace.(*AccessGroupTestData)
			_verifyConnectUtxoViewEntryForAccessGroup(
				tm.t, utxoView,
				dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupPublicKey,
				dataSpace.accessGroupName, dataSpace.extraData)
		},
		verifyDisconnectUtxoViewEntry: func(tv *transactionTestVector, tm *transactionTestMeta,
			utxoView *UtxoView, utxoOps []*UtxoOperation) {

			dataSpace := tv.inputSpace.(*AccessGroupTestData)
			_verifyDisconnectUtxoViewEntryForAccessGroup(
				tm.t, utxoView, utxoOps,
				dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupPublicKey,
				dataSpace.accessGroupName, dataSpace.operationType, dataSpace.extraData)
		},
		verifyDbEntry: func(tv *transactionTestVector, tm *transactionTestMeta,
			dbAdapter *DbAdapter) {

			dataSpace := tv.inputSpace.(*AccessGroupTestData)
			_verifyDbEntryForAccessGroup(
				tm.t, dbAdapter,
				dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupPublicKey,
				dataSpace.accessGroupName, dataSpace.extraData)
		},
	}
}

func _createSignedAccessGroupTransaction(t *testing.T, chain *Blockchain, mempool *DeSoMempool, userPrivateKey string,
	userPublicKey []byte, accessGroupOwnerPublicKey []byte, accessGroupPublicKey []byte, accessGroupName []byte,
	operationType AccessGroupOperationType, extraData map[string][]byte) (_txn *MsgDeSoTxn, _err error) {

	require := require.New(t)

	// Create the transaction.
	txn, totalInputMake, changeAmountMake, feesMake, err := _customCreateAccessGroupTxn(
		chain, userPublicKey, accessGroupOwnerPublicKey, accessGroupPublicKey, accessGroupName, operationType,
		extraData, 10, mempool, []*DeSoOutput{})
	if err != nil {
		return nil, errors.Wrapf(err, "_createSignedAccessGroupTransaction: ")
	}
	require.Equal(totalInputMake, changeAmountMake+feesMake)
	_signTxn(t, txn, userPrivateKey)
	return txn, nil
}

func _verifyConnectUtxoViewEntryForAccessGroup(t *testing.T, utxoView *UtxoView,
	accessGroupOwnerPublicKey []byte, accessGroupPublicKey []byte, accessGroupKeyName []byte, extraData map[string][]byte) {

	require := require.New(t)
	// If either of the provided parameters is nil, we return.
	accessGroupKey := NewAccessGroupId(NewPublicKey(accessGroupOwnerPublicKey), NewGroupKeyName(accessGroupKeyName)[:])

	// If the group has already been fetched in this utxoView, then we get it directly from there.
	accessGroupEntry, exists := utxoView.AccessGroupIdToAccessGroupEntry[*accessGroupKey]
	require.Equal(true, exists)
	require.NotNil(accessGroupEntry)
	require.Equal(false, accessGroupEntry.isDeleted)
	require.Equal(true, _verifyEqualAccessGroupEntry(
		t, accessGroupEntry, accessGroupOwnerPublicKey, accessGroupPublicKey, accessGroupKeyName, extraData))
}

func _verifyDisconnectUtxoViewEntryForAccessGroup(t *testing.T, utxoView *UtxoView, utxoOps []*UtxoOperation,
	accessGroupOwnerPublicKey []byte, accessGroupPublicKey []byte, accessGroupKeyName []byte,
	operationType AccessGroupOperationType, extraData map[string][]byte) {

	require := require.New(t)
	// If either of the provided parameters is nil, we return.
	accessGroupKey := NewAccessGroupId(NewPublicKey(accessGroupOwnerPublicKey), NewGroupKeyName(accessGroupKeyName)[:])

	// If the group has already been fetched in this utxoView, then we get it directly from there.
	accessGroupEntry, exists := utxoView.AccessGroupIdToAccessGroupEntry[*accessGroupKey]
	require.Equal(true, exists)

	currentUtxoOp := utxoOps[len(utxoOps)-1]
	require.Equal(OperationTypeAccessGroup, currentUtxoOp.Type)

	switch operationType {
	case AccessGroupOperationTypeCreate:
		require.NotNil(accessGroupEntry)
		require.Equal(true, accessGroupEntry.isDeleted)
	case AccessGroupOperationTypeUpdate:
		require.NotNil(accessGroupEntry)
		require.Equal(false, accessGroupEntry.isDeleted)

		previousEntry := currentUtxoOp.PrevAccessGroupEntry
		require.NotNil(previousEntry)
		require.Equal(true, _verifyEqualAccessGroupEntry(
			t, accessGroupEntry, previousEntry.AccessGroupOwnerPublicKey.ToBytes(), previousEntry.AccessGroupPublicKey.ToBytes(),
			previousEntry.AccessGroupKeyName.ToBytes(), previousEntry.ExtraData))
	}
}

func _verifyDbEntryForAccessGroup(t *testing.T, dbAdapter *DbAdapter,
	accessGroupOwnerPublicKey []byte, accessGroupPublicKey []byte, accessGroupKeyName []byte, extraData map[string][]byte) {

	require := require.New(t)

	// If either of the provided parameters is nil, we return.

	accessGroupId := NewAccessGroupId(NewPublicKey(accessGroupOwnerPublicKey), accessGroupKeyName)
	accessGroupEntry, err := dbAdapter.GetAccessGroupEntryByAccessGroupId(accessGroupId)
	require.NoError(err)
	require.NotNil(accessGroupEntry)
	require.Equal(true, _verifyEqualAccessGroupEntry(t, accessGroupEntry, accessGroupOwnerPublicKey, accessGroupPublicKey, accessGroupKeyName, extraData))
}

func _verifyEqualAccessGroupEntry(t *testing.T, accessGroupEntry *AccessGroupEntry, accessGroupOwnerPublicKey []byte,
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

func _verifyGroupIdsForUser(t *testing.T, publicKey []byte, utxoView *UtxoView, expectedOwnerIds, expectedMemberIds []*AccessGroupId) {
	require := require.New(t)

	groupIdsOwner, groupIdsMember, err := utxoView.GetAllAccessGroupIdsForUser(publicKey)
	require.NoError(err)
	for _, groupId := range groupIdsOwner {
		require.Equal(true, bytes.Equal(publicKey, groupId.AccessGroupOwnerPublicKey.ToBytes()))
	}

	// Verify that the length of the groupIdsOwner and the expectedOwnerIds are the same.
	require.Equal(len(expectedOwnerIds), len(groupIdsOwner))
	expectedOwnerGroupIds := make(map[AccessGroupId]struct{})
	for _, groupId := range expectedOwnerIds {
		expectedOwnerGroupIds[*groupId] = struct{}{}
	}
	// Verify the owner group ids.
	for _, groupId := range groupIdsOwner {
		_, exists := expectedOwnerGroupIds[*groupId]
		require.Equal(true, exists)
	}

	// Verify that the length of the groupIdsMember and the expectedMemberIds are the same.
	require.Equal(len(expectedMemberIds), len(groupIdsMember))
	expectedMemberGroupIds := make(map[AccessGroupId]struct{})
	for _, groupId := range expectedMemberIds {
		expectedMemberGroupIds[*groupId] = struct{}{}
	}
	// Verify the member group ids.
	for _, groupId := range groupIdsMember {
		_, exists := expectedMemberGroupIds[*groupId]
		require.Equal(true, exists)
	}
}

func _customCreateAccessGroupTxn(
	bc *Blockchain,
	userPublicKey []byte,
	ownerPublicKey []byte,
	accessGroupPublicKey []byte,
	accessGroupKeyName []byte,
	operationType AccessGroupOperationType,
	extraData map[string][]byte,
	minFeeRateNanosPerKB uint64, mempool *DeSoMempool, additionalOutputs []*DeSoOutput) (
	_txn *MsgDeSoTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	txn := &MsgDeSoTxn{
		PublicKey: userPublicKey,
		TxnMeta: &AccessGroupMetadata{
			AccessGroupOwnerPublicKey: ownerPublicKey,
			AccessGroupPublicKey:      accessGroupPublicKey,
			AccessGroupKeyName:        accessGroupKeyName,
			AccessGroupOperationType:  operationType,
		},
		ExtraData: extraData,
		TxOutputs: additionalOutputs,
	}

	// Add inputs and change for a standard pay per KB transaction.
	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateAccessGroupTxn: Problem adding inputs: ")
	}

	// Sanity-check that the spend amount is non-zero.
	if spendAmount != 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreateAccessGroupTxn: Spend amount is zero")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func TestAccessGroupTxnWithDerivedKey(t *testing.T) {
	// Initialize test chain and miner.
	var err error
	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true)

	// Initialize fork heights.
	params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight = uint32(0)
	params.ForkHeights.DerivedKeyEthSignatureCompatibilityBlockHeight = uint32(0)
	params.ForkHeights.ExtraDataOnEntriesBlockHeight = uint32(0)
	params.ForkHeights.AssociationsAndAccessGroupsBlockHeight = uint32(0)
	GlobalDeSoParams.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	GlobalDeSoParams.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)

	// Mine a few blocks to give the senderPkString some money.
	for ii := 0; ii < 10; ii++ {
		_, err = miner.MineAndProcessSingleBlock(0, mempool)
		require.NoError(t, err)
	}

	// We build the testMeta obj after mining blocks so that we save the correct block height.
	blockHeight := uint64(chain.blockTip().Height) + 1
	testMeta := &TestMeta{
		t:                 t,
		chain:             chain,
		params:            params,
		db:                db,
		mempool:           mempool,
		miner:             miner,
		savedHeight:       uint32(blockHeight),
		feeRateNanosPerKb: uint64(101),
	}

	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 1e3)

	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(t, err)
	senderPrivBytes, _, err := Base58CheckDecode(senderPrivString)
	require.NoError(t, err)
	senderPrivKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), senderPrivBytes)

	// Helper funcs
	_submitAuthorizeDerivedKeyTxn := func(accessGroupLimitKey AccessGroupLimitKey, count int) string {
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(t, err)

		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			AccessGroupMap: map[AccessGroupLimitKey]uint64{
				accessGroupLimitKey: uint64(count),
			},
		}

		derivedKeyMetadata, derivedKeyAuthPriv := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(
			t, senderPrivKey, blockHeight+5, txnSpendingLimit, false, blockHeight,
		)
		derivedKeyAuthPrivBase58Check := Base58CheckEncode(derivedKeyAuthPriv.Serialize(), true, params)

		utxoOps, txn, _, err := _doAuthorizeTxnWithExtraDataAndSpendingLimits(
			t,
			chain,
			db,
			params,
			utxoView,
			testMeta.feeRateNanosPerKb,
			senderPkBytes,
			derivedKeyMetadata.DerivedPublicKey,
			derivedKeyAuthPrivBase58Check,
			derivedKeyMetadata.ExpirationBlock,
			derivedKeyMetadata.AccessSignature,
			false,
			nil,
			nil,
			txnSpendingLimit,
		)
		require.NoError(t, err)
		require.NoError(t, utxoView.FlushToDb(0))
		testMeta.txnOps = append(testMeta.txnOps, utxoOps)
		testMeta.txns = append(testMeta.txns, txn)

		err = utxoView.ValidateDerivedKey(senderPkBytes, derivedKeyMetadata.DerivedPublicKey, blockHeight)
		require.NoError(t, err)
		return derivedKeyAuthPrivBase58Check
	}

	_submitAccessGroupTxnWithDerivedKey := func(
		accessGroupKeyName string,
		operationType AccessGroupOperationType,
		derivedKeyPrivBase58Check string,
	) error {
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(t, err)

		// Construct txn.
		var txn *MsgDeSoTxn
		txn, _, _, _, err = testMeta.chain.CreateAccessGroupTxn(
			senderPkBytes,
			m0PkBytes,
			[]byte(accessGroupKeyName),
			operationType,
			make(map[string][]byte),
			testMeta.feeRateNanosPerKb,
			mempool,
			[]*DeSoOutput{},
		)
		if err != nil {
			return err
		}
		// Sign txn.
		_signTxnWithDerivedKey(t, txn, derivedKeyPrivBase58Check)
		// Connect txn.
		utxoOps, _, _, _, err := utxoView.ConnectTransaction(
			txn,
			txn.Hash(),
			getTxnSize(*txn),
			testMeta.savedHeight,
			true,
			false,
		)
		if err != nil {
			return err
		}
		// Flush UTXO view to the db.
		require.NoError(t, utxoView.FlushToDb(0))
		testMeta.txnOps = append(testMeta.txnOps, utxoOps)
		testMeta.txns = append(testMeta.txns, txn)
		return nil
	}

	{
		// ParamUpdater set min fee rate
		params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true
		_updateGlobalParamsEntryWithTestMeta(
			testMeta,
			testMeta.feeRateNanosPerKb,
			paramUpdaterPub,
			paramUpdaterPriv,
			-1,
			1,
			-1,
			-1,
			-1,
		)
	}
	{
		// Create access group derived key for scoped GroupKeyName + OperationType.
		groupKeyName := "TestGroupKeyName"
		derivedKeyPriv := _submitAuthorizeDerivedKeyTxn(
			MakeAccessGroupLimitKey(
				*NewPublicKey(senderPkBytes),
				AccessGroupScopeTypeScoped,
				*NewGroupKeyName([]byte(groupKeyName)),
				AccessGroupOperationTypeCreate,
			),
			1,
		)

		// Sad path: try to create access group with different group key name, unauthorized
		err = _submitAccessGroupTxnWithDerivedKey(
			groupKeyName+"2", AccessGroupOperationTypeCreate, derivedKeyPriv,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAccessGroupTransactionSpendingLimitInvalid)

		// Sad path: try to update access group, not found
		err = _submitAccessGroupTxnWithDerivedKey(
			groupKeyName, AccessGroupOperationTypeUpdate, derivedKeyPriv,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAccessGroupDoesNotExist)

		// Happy path: create authorized access group
		err = _submitAccessGroupTxnWithDerivedKey(
			groupKeyName, AccessGroupOperationTypeCreate, derivedKeyPriv,
		)
		require.NoError(t, err)
	}
	{
		// Create access group derived key for any GroupKeyName + OperationType
		derivedKeyPriv := _submitAuthorizeDerivedKeyTxn(
			MakeAccessGroupLimitKey(
				*NewPublicKey(senderPkBytes),
				AccessGroupScopeTypeAny,
				*NewGroupKeyName([]byte{}),
				AccessGroupOperationTypeAny,
			),
			3,
		)

		// Happy path: create authorized access group
		err = _submitAccessGroupTxnWithDerivedKey(
			"GroupKeyName1", AccessGroupOperationTypeCreate, derivedKeyPriv,
		)
		require.NoError(t, err)

		// Happy path: create authorized access group with different name
		err = _submitAccessGroupTxnWithDerivedKey(
			"GroupKeyName2", AccessGroupOperationTypeCreate, derivedKeyPriv,
		)
		require.NoError(t, err)

		// Happy path: update authorized access group
		err = _submitAccessGroupTxnWithDerivedKey(
			"GroupKeyName1", AccessGroupOperationTypeUpdate, derivedKeyPriv,
		)
		require.NoError(t, err)

		// Sad path: spending limit is exceeded, unauthorized
		err = _submitAccessGroupTxnWithDerivedKey(
			"GroupKeyName2", AccessGroupOperationTypeUpdate, derivedKeyPriv,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAccessGroupTransactionSpendingLimitInvalid)
	}
}

func TestAccessGroupTxnSpendingLimitToMetamaskString(t *testing.T) {
	toMetamaskString := func(
		scopeType AccessGroupScopeType,
		groupKeyName GroupKeyName,
		operationType AccessGroupOperationType,
	) string {
		accessGroupLimitKey := MakeAccessGroupLimitKey(
			*NewPublicKey(m0PkBytes),
			scopeType,
			groupKeyName,
			operationType,
		)
		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
			AccessGroupMap: map[AccessGroupLimitKey]uint64{
				accessGroupLimitKey: 1,
			},
		}
		return txnSpendingLimit.ToMetamaskString(&GlobalDeSoParams)
	}

	// Scoped GroupKeyName + OperationType
	metamaskStr := toMetamaskString(
		AccessGroupScopeTypeScoped,
		*NewGroupKeyName([]byte("TestGroupKeyName")),
		AccessGroupOperationTypeCreate,
	)
	require.Equal(t, metamaskStr,
		"Spending limits on the derived key:\n"+
			"	Total $DESO Limit: 1.0 $DESO\n"+
			"	Transaction Count Limit: \n"+
			"		AUTHORIZE_DERIVED_KEY: 1\n"+
			"	Access Group Restrictions:\n"+
			"		[\n"+
			"			Access Group Owner Public Key: "+m0Pub+"\n"+
			"			Access Group Key Name: TestGroupKeyName\n"+
			"			Access Group Operation: Create\n"+
			"			Transaction Count: 1\n"+
			"		]\n",
	)

	// Any GroupKeyName + OperationType
	metamaskStr = toMetamaskString(
		AccessGroupScopeTypeAny,
		*NewGroupKeyName([]byte{}),
		AccessGroupOperationTypeAny,
	)
	require.Equal(t, metamaskStr,
		"Spending limits on the derived key:\n"+
			"	Total $DESO Limit: 1.0 $DESO\n"+
			"	Transaction Count Limit: \n"+
			"		AUTHORIZE_DERIVED_KEY: 1\n"+
			"	Access Group Restrictions:\n"+
			"		[\n"+
			"			Access Group Owner Public Key: "+m0Pub+"\n"+
			"			Access Group Key Name: Any\n"+
			"			Access Group Operation: Any\n"+
			"			Transaction Count: 1\n"+
			"		]\n",
	)
}
