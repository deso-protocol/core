package lib

import (
	"bytes"
	"github.com/btcsuite/btcd/btcec"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"testing"
)

type accessGroupMembersTestData struct {
	userPrivateKey            string
	accessGroupOwnerPublicKey []byte
	accessGroupKeyName        []byte
	accessGroupMembersList    []*AccessGroupMember
	operationType             AccessGroupMemberOperationType
	extraData                 map[string][]byte
	expectedConnectError      error
}

func (data *accessGroupMembersTestData) IsDependency(other transactionTestInputSpace) bool {
	otherData := other.(*accessGroupMembersTestData)

	isSameGroup := bytes.Equal(data.accessGroupOwnerPublicKey, otherData.accessGroupOwnerPublicKey) &&
		bytes.Equal(data.accessGroupKeyName, otherData.accessGroupKeyName)
	isSameMembers := false
	for _, member := range data.accessGroupMembersList {
		for _, otherMember := range otherData.accessGroupMembersList {
			if bytes.Equal(member.AccessGroupMemberPublicKey, otherMember.AccessGroupMemberPublicKey) {
				isSameMembers = true
				break
			}
		}
		if isSameMembers {
			break
		}
	}
	return isSameGroup && isSameMembers
}

func (data *accessGroupMembersTestData) GetInputType() transactionTestInputType {
	return transactionTestInputTypeAccessGroupMembers
}

func TestAccessGroupMembersAdd(t *testing.T) {
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
		tm.params.ForkHeights.DeSoAccessGroupsBlockHeight = 0
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

	tv1 := _createAccessGroupCreateTestVector("TEST 1: (PASS) Connect access group create transaction made by "+
		"user 0", m0Priv, m0PubBytes, m0PubBytes, groupPk1, groupName1, nil,
		nil)
	tv2Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: groupName1, EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv2 := _createAccessGroupMembersTestVector("TEST 2: (FAIL) Connect access group members transaction to the "+
		"access group made by user 0 with group name 1, adding user 0 as member with the same access group name 1", m0Priv, m0PubBytes,
		groupName1, tv2Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupMemberCantAddOwnerBySameGroup)
	tv3Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv3 := _createAccessGroupMembersTestVector("TEST 3: (PASS) Connect access group members transaction to the "+
		"access group made by user 0 with group name 1, adding user 0 as member with the base access group", m0Priv, m0PubBytes,
		groupName1, tv3Members, AccessGroupMemberOperationTypeAdd, nil)
	tv4 := _createAccessGroupCreateTestVector("TEST 4: (PASS) Connect access group create transaction made by "+
		"user 0 with group name 2", m0Priv, m0PubBytes, m0PubBytes, groupPk2, groupName2, nil, nil)
	tv5Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv5 := _createAccessGroupMembersTestVector("TEST 5: (FAIL) Connect access group members transaction to the "+
		"access group made by user 0 with group name 1, again adding user 0 by base group key", m0Priv, m0PubBytes, groupName1,
		tv5Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessMemberAlreadyExists)
	tv6Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: groupName2, EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv6 := _createAccessGroupMembersTestVector("TEST 6: (FAIL) Connect access group members transaction to the "+
		"access group made by user 0 with group name 1, again adding user 0 but by group name 2", m0Priv, m0PubBytes, groupName1,
		tv6Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessMemberAlreadyExists)
	tv7 := _createAccessGroupMembersTestVector("TEST 7: (FAIL) Connect access group members transaction to the "+
		"access group made by user 0 with group name 1, with empty members list", m0Priv, m0PubBytes, groupName1,
		[]*AccessGroupMember{}, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupMembersListCannotBeEmpty)
	tv8Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName()[:], EncryptedKey: []byte{1}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName()[:], EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv8 := _createAccessGroupMembersTestVector("TEST 8: (FAIL) Connect access group members transaction to the "+
		"access group made by user 1 with group name 1, adding user 1 by base key twice within same transaction",
		m0Priv, m0PubBytes, groupName1, tv8Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupMemberListDuplicateMember)
	tv9Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: groupName1, EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv9 := _createAccessGroupMembersTestVector("TEST 9: (PASS) Connect access group members transaction to the "+
		"access group made by user 0 with group name 2, adding user 0 by group name 1", m0Priv, m0PubBytes, groupName2,
		tv9Members, AccessGroupMemberOperationTypeAdd, nil)

	tvv := [][]*transactionTestVector{{tv1, tv2, tv3, tv4, tv5, tv6, tv7, tv8, tv9}}
	tes := NewTransactionTestSuite(t, tvv, tConfig)
	tes.Run()
}

func _createAccessGroupMembersTestVector(id string, userPrivateKey string, accessGroupOwnerPublicKey []byte,
	accessGroupKeyName []byte, accessGroupMembersList []*AccessGroupMember, operationType AccessGroupMemberOperationType,
	expectedConnectError error) (_tv *transactionTestVector) {

	testData := &accessGroupMembersTestData{
		userPrivateKey:            userPrivateKey,
		accessGroupOwnerPublicKey: accessGroupOwnerPublicKey,
		accessGroupKeyName:        accessGroupKeyName,
		accessGroupMembersList:    accessGroupMembersList,
		operationType:             operationType,
		expectedConnectError:      expectedConnectError,
	}
	return &transactionTestVector{
		id:         transactionTestIdentifier(id),
		inputSpace: testData,
		getTransaction: func(tv *transactionTestVector, tm *transactionTestMeta) (*MsgDeSoTxn, error) {
			dataSpace := tv.inputSpace.(*accessGroupMembersTestData)
			txn, err := _createSignedAccessGroupMembersTransaction(
				tm.t, tm.chain, tm.mempool,
				dataSpace.userPrivateKey, dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupKeyName,
				dataSpace.accessGroupMembersList, dataSpace.operationType)
			require.NoError(tm.t, err)
			return txn, dataSpace.expectedConnectError
		},
		verifyUtxoViewEntry: func(tv *transactionTestVector, tm *transactionTestMeta,
			utxoView *UtxoView, expectDeleted bool) {
			dataSpace := tv.inputSpace.(*accessGroupMembersTestData)
			_verifyUtxoViewEntryForAccessGroupMembers(
				tm.t, utxoView, expectDeleted, operationType,
				dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupKeyName,
				dataSpace.accessGroupMembersList)
		},
		verifyDbEntry: func(tv *transactionTestVector, tm *transactionTestMeta,
			dbAdapter *DbAdapter, expectDeleted bool) {
			dataSpace := tv.inputSpace.(*accessGroupMembersTestData)
			_verifyDbEntryForAccessGroupMembers(
				tm.t, dbAdapter, expectDeleted, operationType,
				dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupKeyName,
				dataSpace.accessGroupMembersList)
		},
	}
}

func _createSignedAccessGroupMembersTransaction(t *testing.T, chain *Blockchain, mempool *DeSoMempool, userPrivateKey string,
	accessGroupOwnerPublicKey []byte, accessGroupKeyName []byte, accessGroupMembersList []*AccessGroupMember,
	operationType AccessGroupMemberOperationType) (_txn *MsgDeSoTxn, _err error) {

	require := require.New(t)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateAccessGroupMembersTxn(
		accessGroupOwnerPublicKey, accessGroupKeyName, accessGroupMembersList, operationType,
		10, mempool, []*DeSoOutput{})
	if err != nil {
		return nil, errors.Wrapf(err, "_createSignedAccessGroupMembersTransaction: ")
	}
	require.Equal(totalInputMake, changeAmountMake+feesMake)
	_signTxn(t, txn, userPrivateKey)
	return txn, nil
}

func _verifyUtxoViewEntryForAccessGroupMembers(t *testing.T, utxoView *UtxoView, expectDeleted bool,
	operationType AccessGroupMemberOperationType, accessGroupOwnerPublicKey []byte, accessGroupKeyName []byte,
	accessGroupMembersList []*AccessGroupMember) {

	require := require.New(t)

	for _, member := range accessGroupMembersList {
		groupMembershipKey := NewGroupMembershipKey(*NewPublicKey(member.AccessGroupMemberPublicKey),
			*NewPublicKey(accessGroupOwnerPublicKey), *NewGroupKeyName(accessGroupKeyName))

		// If the group has already been fetched in this utxoView, then we get it directly from there.
		accessGroupMember, exists := utxoView.GroupMembershipKeyToAccessGroupMember[*groupMembershipKey]

		switch operationType {
		case AccessGroupMemberOperationTypeAdd, AccessGroupMemberOperationTypeUpdate:
			if !expectDeleted {
				require.Equal(true, exists)
				require.NotNil(accessGroupMember)
				require.Equal(false, accessGroupMember.isDeleted)
				require.Equal(true, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
			} else {
				if !exists || accessGroupMember == nil || accessGroupMember.isDeleted {
					return
				}
				// It's possible that there is another testVector' that makes overlapping utxoEntries to this testVector.
				// If it was connected later, we just check that the current UtxoView accessGroupMember entry is different.
				require.Equal(false, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
			}
		case AccessGroupMemberOperationTypeRemove:
			// OperationTypeRemove will have inverted validation for the UtxoView than add/updates since it deletes the entry.
			if !expectDeleted {
				// TODO: do we want to also OR a case where accessGroupMember == nil? This would only be the case if we flushed.
				if !exists || accessGroupMember == nil || accessGroupMember.isDeleted {
					return
				}
				require.Equal(false, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
			} else {
				require.Equal(true, exists)
				require.NotNil(accessGroupMember)
				require.Equal(false, accessGroupMember.isDeleted)
				require.Equal(true, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
			}
		}
	}
}

func _verifyDbEntryForAccessGroupMembers(t *testing.T, dbAdapter *DbAdapter, expectDeleted bool,
	operationType AccessGroupMemberOperationType, accessGroupOwnerPublicKey []byte, accessGroupKeyName []byte,
	accessGroupMembersList []*AccessGroupMember) {

	require := require.New(t)

	for _, member := range accessGroupMembersList {
		// If the group has already been fetched in this utxoView, then we get it directly from there.
		accessGroupMember, err := dbAdapter.GetAccessGroupMemberEntry(*NewPublicKey(member.AccessGroupMemberPublicKey),
			*NewPublicKey(accessGroupOwnerPublicKey), *NewGroupKeyName(accessGroupKeyName))
		require.NoError(err)
		accessGroupEnumerationEntry, err := dbAdapter.GetAccessGroupMemberEnumerationEntry(*NewPublicKey(member.AccessGroupMemberPublicKey),
			*NewPublicKey(accessGroupOwnerPublicKey), *NewGroupKeyName(accessGroupKeyName))
		require.NoError(err)

		switch operationType {
		case AccessGroupMemberOperationTypeAdd, AccessGroupMemberOperationTypeUpdate:
			if !expectDeleted {
				require.Equal(true, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
				require.Equal(true, accessGroupEnumerationEntry)
			} else {
				if accessGroupMember == nil && !accessGroupEnumerationEntry {
					return
				}
				require.Equal(false, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
				require.Equal(false, accessGroupEnumerationEntry)

			}
		case AccessGroupMemberOperationTypeRemove:
			if !expectDeleted {
				if accessGroupMember == nil && !accessGroupEnumerationEntry {
					return
				}
				require.Equal(false, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
				require.Equal(false, accessGroupEnumerationEntry)
			} else {
				require.Equal(true, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
				require.Equal(true, accessGroupEnumerationEntry)
			}
		}
	}
}

func _verifyEqualAccessGroupMember(t *testing.T, accessGroupMemberEntry *AccessGroupMemberEntry,
	accessGroupMember *AccessGroupMember) bool {

	require := require.New(t)
	require.NotNil(accessGroupMemberEntry)
	require.NotNil(accessGroupMemberEntry.AccessGroupMemberPublicKey)
	require.NotNil(accessGroupMemberEntry.AccessGroupMemberKeyName)
	require.NotEqual(0, len(accessGroupMemberEntry.EncryptedKey))
	if !bytes.Equal(NewPublicKey(accessGroupMember.AccessGroupMemberPublicKey).ToBytes(),
		accessGroupMemberEntry.AccessGroupMemberPublicKey.ToBytes()) {
		return false
	}
	if !bytes.Equal(NewGroupKeyName(accessGroupMember.AccessGroupMemberKeyName).ToBytes(),
		accessGroupMemberEntry.AccessGroupMemberKeyName.ToBytes()) {
		return false
	}
	if !bytes.Equal(accessGroupMember.EncryptedKey, accessGroupMemberEntry.EncryptedKey) {
		return false
	}
	if !bytes.Equal(EncodeExtraData(accessGroupMember.ExtraData), EncodeExtraData(accessGroupMemberEntry.ExtraData)) {
		return false
	}
	return true
}
