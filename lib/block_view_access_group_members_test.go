package lib

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
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

	// randomMemberCounter is used to generate random members for the test.
	randomMemberCounter := 50
	randomMemberPrivateKeys := []string{}
	randomMemberPublicKeys := []*PublicKey{}
	randomMemberGroupKeys := []*GroupKeyName{}
	for ii := 0; ii < randomMemberCounter; ii++ {
		privateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		privateKeyBase58Check := Base58CheckEncode(
			privateKey.Serialize(), true, &DeSoTestnetParams)
		randomMemberPrivateKeys = append(randomMemberPrivateKeys, privateKeyBase58Check)
		publicKeyBytes := privateKey.PubKey().SerializeCompressed()
		publicKey := NewPublicKey(publicKeyBytes)
		randomMemberPublicKeys = append(randomMemberPublicKeys, publicKey)
		randomGroupKey := NewGroupKeyName([]byte(fmt.Sprintf("random-group-key-%d", ii)))
		randomMemberGroupKeys = append(randomMemberGroupKeys, randomGroupKey)
	}

	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	m0PublicKey := NewPublicKey(m0PubBytes)
	m1PubBytes, _, _ := Base58CheckDecode(m1Pub)
	m1PublicKey := NewPublicKey(m1PubBytes)
	m2PubBytes, _, _ := Base58CheckDecode(m2Pub)
	m2PublicKey := NewPublicKey(m2PubBytes)
	m3PubBytes, _, _ := Base58CheckDecode(m3Pub)
	m3PublicKey := NewPublicKey(m3PubBytes)
	m4PubBytes, _, _ := Base58CheckDecode(m4Pub)
	m4PublicKey := NewPublicKey(m4PubBytes)
	m5PubBytes, _, _ := Base58CheckDecode(m5Pub)

	fundPublicKeysWithNanosMap := make(map[PublicKey]uint64)
	fundPublicKeysWithNanosMap[*m0PublicKey] = 200
	fundPublicKeysWithNanosMap[*m1PublicKey] = 200
	fundPublicKeysWithNanosMap[*m2PublicKey] = 200
	fundPublicKeysWithNanosMap[*m3PublicKey] = 200
	for _, publicKey := range randomMemberPublicKeys {
		fundPublicKeysWithNanosMap[*publicKey] = 50
	}
	initChainCallback := func(tm *transactionTestMeta) {
		_setAccessGroupParams(tm)
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

	// Access group (m0Pub, groupName1) with access public key groupPk1.
	tv1 := _createAccessGroupTestVector("TEST 1: (PASS) Connect access group create transaction made by "+
		"(pk0, groupName1)", m0Priv, m0PkBytes, m0PkBytes, groupPk1, groupName1, AccessGroupOperationTypeCreate, nil,
		nil)
	tv2Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PkBytes, AccessGroupMemberKeyName: groupName1, EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv2 := _createAccessGroupMembersTestVector("TEST 2: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk0, groupName1), re-adding yourself as member with (pk0, groupName1)", m0Priv, m0PkBytes,
		groupName1, tv2Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupMemberCantAddOwnerBySameGroup)
	tv3Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PkBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	// Membership:
	// (m0Pub, groupName1) ->
	//		(m0Pub, BaseGroupKeyName)
	tv3 := _createAccessGroupMembersTestVector("TEST 3: (PASS) Connect access group members transaction to the "+
		"access group made by (user0, groupName1), adding as member (pk0, baseGroup)", m0Priv, m0PkBytes,
		groupName1, tv3Members, AccessGroupMemberOperationTypeAdd, nil)
	tv3.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey})
	}
	tv3.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
	}
	tv4Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PkBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv4 := _createAccessGroupMembersTestVector("TEST 4: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk0, groupName1), again adding as member (pk0, baseGroup)", m0Priv, m0PkBytes, groupName1,
		tv4Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessMemberAlreadyExists)
	tv4p5Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m4PkBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{}, ExtraData: nil,
	}}
	tv4p5 := _createAccessGroupMembersTestVector("TEST 4.5: (PASS) Access group members transaction to the "+
		"access group made by (pk0, groupName1), adding as member (pk4, baseGroup) with nil encrypted key",
		m0Priv, m0PkBytes, groupName1, tv4p5Members, AccessGroupMemberOperationTypeAdd, nil)

	// Place the above transactions into a block.
	tvv1 := []*transactionTestVector{tv1, tv2, tv3, tv4, tv4p5}
	blockConnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m4PublicKey})
	}
	blockDisconnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
	}
	tvb1 := NewTransactionTestVectorBlock(tvv1, blockConnectCallback, blockDisconnectCallback)

	// Access group (m0Pub, groupName2) with access public key groupPk2.
	// Membership:
	// (m0Pub, groupName1) ->
	//		(m0Pub, BaseGroupKeyName)
	// (m0Pub, groupName2) ->
	tv5 := _createAccessGroupTestVector("TEST 5: (PASS) Connect access group create transaction made by "+
		"(pk0, groupName2)", m0Priv, m0PkBytes, m0PkBytes, groupPk2, groupName2, AccessGroupOperationTypeCreate,
		nil, nil)
	tv6Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PkBytes, AccessGroupMemberKeyName: groupName2, EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv6 := _createAccessGroupMembersTestVector("TEST 6: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk0, groupName1), again adding user 0 as member but by (pk0, groupName2)", m0Priv, m0PkBytes,
		groupName1, tv6Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessMemberAlreadyExists)
	tv7 := _createAccessGroupMembersTestVector("TEST 7: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk0, groupName1), with empty members list", m0Priv, m0PkBytes, groupName1,
		[]*AccessGroupMember{}, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupMembersListCannotBeEmpty)
	tv8Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PkBytes, AccessGroupMemberKeyName: BaseGroupKeyName()[:], EncryptedKey: []byte{1}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m1PkBytes, AccessGroupMemberKeyName: BaseGroupKeyName()[:], EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv8 := _createAccessGroupMembersTestVector("TEST 8: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk0, groupName1), adding as member (pk1, baseGroup) twice within same transaction",
		m0Priv, m0PkBytes, groupName1, tv8Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupMemberListDuplicateMember)

	// Membership:
	// (m0Pub, groupName1) ->
	//		(m0Pub, BaseGroupKeyName)
	//		(m1Pub, BaseGroupKeyName)
	// (m0Pub, groupName2) ->
	tv9Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PkBytes, AccessGroupMemberKeyName: BaseGroupKeyName()[:], EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv9 := _createAccessGroupMembersTestVector("TEST 9: (PASS) Connect access group members transaction to the "+
		"access group made by (pk0, groupName1), adding as member (pk1, baseGroup)", m0Priv, m0PkBytes, groupName1,
		tv9Members, AccessGroupMemberOperationTypeAdd, nil)
	tv9.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey, m4PublicKey})
	}
	tv9.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m4PublicKey})
	}
	// A bunch of failing tests to try out different validation rule errors.
	tv10Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PkBytes, AccessGroupMemberKeyName: BaseGroupKeyName()[:], EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv10 := _createAccessGroupMembersTestVector("TEST 10: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk0, baseGroup), adding as member (pk1, baseGroup)", m0Priv, m0PkBytes, BaseGroupKeyName().ToBytes(),
		tv10Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupsNameCannotBeZeros)
	tv11Members := tv10Members
	tv11 := _createAccessGroupMembersTestVector("TEST 11: (FAIL) Connect access group members transaction to the "+
		"non-existing access group (pk0, groupName3), adding as member (pk1, baseGroup)", m0Priv, m0PkBytes, groupName3,
		tv11Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupDoesntExist)
	tv12Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m2PkBytes, AccessGroupMemberKeyName: groupName1, EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv12 := _createAccessGroupMembersTestVector("TEST 12: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk0, groupName1), adding as member (pk2, groupName1) by non-existing group", m0Priv, m0PkBytes, groupName1,
		tv12Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupDoesntExist)

	// Membership:
	// (m0Pub, groupName1) ->
	//		(m0Pub, BaseGroupKeyName)
	//		(m1Pub, BaseGroupKeyName)
	// (m0Pub, groupName2) ->
	// 		(m0Pub, groupName1)
	tv13Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PkBytes, AccessGroupMemberKeyName: groupName1, EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv13 := _createAccessGroupMembersTestVector("TEST 13: (PASS) Connect access group members transaction to the "+
		"access group made by (pk0, groupName2), adding as member (pk0, groupName1)", m0Priv, m0PkBytes, groupName2,
		tv13Members, AccessGroupMemberOperationTypeAdd, nil)
	tv13.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName2), []*PublicKey{m0PublicKey})
	}
	tv13.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName2), []*PublicKey{})
	}
	// Create an access group (pk1, groupName3) and (pk2, groupName4)
	tv14 := _createAccessGroupTestVector("TEST 14: (PASS) Connect access group transaction made by "+
		"(pk1, groupName3)", m1Priv, m1PkBytes, m1PkBytes, groupPk2, groupName3,
		AccessGroupOperationTypeCreate, nil, nil)
	tv15 := _createAccessGroupTestVector("TEST 15: (PASS) Connect access group transaction made by "+
		"(pk2, groupName4)", m2Priv, m2PkBytes, m2PkBytes, groupPk2, groupName4,
		AccessGroupOperationTypeCreate, nil, nil)
	// Add (m0Pub, groupName1), (m1Pub, groupName3), and (m2Pub, BaseGroup) to the group (m2pub, groupName4)
	// Membership:
	// (m0Pub, groupName1) ->
	//		(m0Pub, BaseGroupKeyName)
	//		(m1Pub, BaseGroupKeyName)
	// (m0Pub, groupName2) ->
	// 		(m0Pub, groupName1)
	// (m1Pub, groupName3) ->
	// (m2Pub, groupName4) ->
	//		(m0Pub, groupName1)
	//		(m1Pub, groupName3)
	//		(m2Pub, BaseGroupKeyName)
	tv16Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PkBytes, AccessGroupMemberKeyName: groupName1, EncryptedKey: []byte{1}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m1PkBytes, AccessGroupMemberKeyName: groupName3, EncryptedKey: []byte{1}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m2PkBytes, AccessGroupMemberKeyName: BaseGroupKeyName()[:], EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv16 := _createAccessGroupMembersTestVector("TEST 16: (PASS) Connect access group members transaction to the "+
		"access group made by (pk2, groupName4), adding as member (pk0, groupName1), (pk1, groupName3), and (pk2, baseGroup)",
		m2Priv, m2PkBytes, groupName4, tv16Members, AccessGroupMemberOperationTypeAdd, nil)
	tv16.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName3), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName4), []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey})
	}
	tv16.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName3), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName4), []*PublicKey{})
	}

	// Try adding (member0, groupName1) &  (member1, groupName3) again!
	// Should result in RuleErrorAccessMemberAlreadyExists.
	tv17Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: groupName1, EncryptedKey: []byte{1}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: groupName3, EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv17 := _createAccessGroupMembersTestVector("TEST 17: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk2, groupName4), adding as member (pk0, groupName1), (pk1, groupName3)",
		m2Priv, m2PubBytes, groupName4, tv17Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessMemberAlreadyExists)

	// Test to verify that only group owners can add members.
	// Though groupName4 has existing members m0, m1 and m2, only m2 being the group owner can add a member.
	// Any attempt by members m0 and m1 to add a new member to groupName4 should fail.
	tv18Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m5PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName()[:], EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv18 := _createAccessGroupMembersTestVector("TEST 18: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk2, groupName4),but using m1Priv as an owner to add (pk5, BaseGroupKeyName) as member",
		m1Priv, m1PubBytes, groupName4, tv18Members, AccessGroupMemberOperationTypeAdd,
		errors.New("ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView: non-existent access key entry for groupOwnerPublicKey"))

	tv19Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m5PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName()[:], EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv19 := _createAccessGroupMembersTestVector("TEST 19: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk2, groupName4),but using m0Priv as an owner to add (pk5, BaseGroupKeyName) as member",
		m0Priv, m0PubBytes, groupName4, tv19Members, AccessGroupMemberOperationTypeAdd,
		errors.New("ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView: non-existent access key entry for groupOwnerPublicKey"))

	// Mine all the above transactions into a new block.
	tvv2 := []*transactionTestVector{tv5, tv6, tv7, tv8, tv9, tv10, tv11, tv12, tv13, tv14, tv15, tv16, tv17, tv18, tv19}
	block2ConnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey, m4PublicKey})
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName2), []*PublicKey{m0PublicKey})
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName3), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName4), []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey})
	}
	block2DisconnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m4PublicKey})
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName2), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName3), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName4), []*PublicKey{})
	}
	tvb2 := NewTransactionTestVectorBlock(tvv2, block2ConnectCallback, block2DisconnectCallback)

	// Add a bunch of random members to the access group (m2Pub, groupName4)
	randomGroupsTransactionVectors := []*transactionTestVector{}
	for ii := 0; ii < 50; ii++ {
		randomGroupsTransactionVectors = append(randomGroupsTransactionVectors, _createAccessGroupTestVector(
			fmt.Sprintf("TEST %d: (PASS) Connect access group transaction made by (randomPk%d, groupName%d)",
				len(tvv1)+len(tvv2)+1+ii, ii, ii), randomMemberPrivateKeys[ii], randomMemberPublicKeys[ii].ToBytes(),
			randomMemberPublicKeys[ii].ToBytes(), groupPk1, randomMemberGroupKeys[ii].ToBytes(),
			AccessGroupOperationTypeCreate, nil, nil))
	}
	randomMembers := []*AccessGroupMember{}
	totalMembers := []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey}
	for ii := 0; ii < 50; ii++ {
		extraDataMap := make(map[string][]byte)
		extraDataMap[fmt.Sprintf("randomField%v", ii)] = []byte(fmt.Sprintf("randomValue%v", ii))
		randomMembers = append(randomMembers, &AccessGroupMember{
			AccessGroupMemberPublicKey: randomMemberPublicKeys[ii].ToBytes(),
			AccessGroupMemberKeyName:   randomMemberGroupKeys[ii].ToBytes(),
			EncryptedKey:               []byte{1}, ExtraData: extraDataMap,
		})
		totalMembers = append(totalMembers, randomMemberPublicKeys[ii])
	}
	tvRandomMembers := _createAccessGroupMembersTestVector(
		fmt.Sprintf("TEST %d: (PASS) Connect access group members transaction to the access group made by "+
			"(m2Pub, groupName4), adding all random members", len(tvv1)+len(tvv2)+len(randomGroupsTransactionVectors)+1),
		m2Priv, m2PkBytes, groupName4, randomMembers, AccessGroupMemberOperationTypeAdd, nil)
	randomGroupsTransactionVectors = append(randomGroupsTransactionVectors, tvRandomMembers)
	tvRandomMembers.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName4), totalMembers)
	}
	tvRandomMembers.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName4), []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey})
	}

	// Mine all the above transactions into a new block.
	block3ConnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey, m4PublicKey})
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName2), []*PublicKey{m0PublicKey})
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName3), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName4), totalMembers)
	}
	block3DisconnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey, m4PublicKey})
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName2), []*PublicKey{m0PublicKey})
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName3), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName4), []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey})
	}
	tvb3 := NewTransactionTestVectorBlock(randomGroupsTransactionVectors, block3ConnectCallback, block3DisconnectCallback)

	tvbb := []*transactionTestVectorBlock{tvb1, tvb2, tvb3}
	tes := NewTransactionTestSuite(t, tvbb, tConfig)
	tes.Run()
}

func TestAccessGroupMembersRemove(t *testing.T) {
	require := require.New(t)
	_ = require

	// randomMemberCounter is used to generate random members for the test.
	randomMemberCounter1 := 20
	randomMemberCounter2 := 30
	randomMemberPrivateKeys1 := []string{}
	randomMemberPrivateKeys2 := []string{}
	randomMemberPublicKeys1 := []*PublicKey{}
	randomMemberPublicKeys2 := []*PublicKey{}
	for ii := 0; ii < randomMemberCounter1; ii++ {
		privateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		privateKeyBase58Check := Base58CheckEncode(
			privateKey.Serialize(), true, &DeSoTestnetParams)
		randomMemberPrivateKeys1 = append(randomMemberPrivateKeys1, privateKeyBase58Check)
		publicKeyBytes := privateKey.PubKey().SerializeCompressed()
		publicKey := NewPublicKey(publicKeyBytes)
		randomMemberPublicKeys1 = append(randomMemberPublicKeys1, publicKey)
	}
	for ii := 0; ii < randomMemberCounter2; ii++ {
		privateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		privateKeyBase58Check := Base58CheckEncode(
			privateKey.Serialize(), true, &DeSoTestnetParams)
		randomMemberPrivateKeys2 = append(randomMemberPrivateKeys2, privateKeyBase58Check)
		publicKeyBytes := privateKey.PubKey().SerializeCompressed()
		publicKey := NewPublicKey(publicKeyBytes)
		randomMemberPublicKeys2 = append(randomMemberPublicKeys2, publicKey)
	}

	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	m0PublicKey := NewPublicKey(m0PubBytes)
	m1PubBytes, _, _ := Base58CheckDecode(m1Pub)
	m1PublicKey := NewPublicKey(m1PubBytes)
	m2PubBytes, _, _ := Base58CheckDecode(m2Pub)
	m2PublicKey := NewPublicKey(m2PubBytes)
	m3PubBytes, _, _ := Base58CheckDecode(m3Pub)
	m3PublicKey := NewPublicKey(m3PubBytes)

	fundPublicKeysWithNanosMap := make(map[PublicKey]uint64)
	fundPublicKeysWithNanosMap[*m0PublicKey] = 200
	fundPublicKeysWithNanosMap[*m1PublicKey] = 200
	fundPublicKeysWithNanosMap[*m2PublicKey] = 200
	fundPublicKeysWithNanosMap[*m3PublicKey] = 200

	initChainCallback := func(tm *transactionTestMeta) {
		_setAccessGroupParams(tm)
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
	_ = groupPk1

	groupPriv2, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	groupPk2 := groupPriv2.PubKey().SerializeCompressed()
	_ = groupPk2

	groupPriv3, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	groupPk3 := groupPriv3.PubKey().SerializeCompressed()
	_ = groupPk3

	groupName1 := []byte("group1")
	_ = groupName1
	groupName2 := []byte("group2")
	_ = groupName2
	groupName3 := []byte("group3")
	_ = groupName3
	groupName4 := []byte("group4")
	_ = groupName4

	// Access group (m0Pub, groupName1) with access public key groupPk1.
	// Membership [create]:
	// (m0Pub, groupName1) ->
	tv1 := _createAccessGroupTestVector("TEST 1: (PASS) Connect access group create transaction made by "+
		"(pk0, groupName1)", m0Priv, m0PubBytes, m0PubBytes, groupPk1, groupName1,
		AccessGroupOperationTypeCreate, nil, nil)
	groupM0N1 := &AccessGroupId{*m0PublicKey, *NewGroupKeyName(groupName1)}
	groupM0B := &AccessGroupId{*m0PublicKey, *BaseGroupKeyName()}
	// Membership [memberAdd]:
	// (m0Pub, groupName1) ->
	//		(m1Pub, BaseGroupKeyName)
	tv2Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv2 := _createAccessGroupMembersTestVector("TEST 2: (PASS) Connect access group members add transaction made by "+
		"(pk0, groupName1) adding as member (pk1, baseGroup)", m0Priv, m0PubBytes, groupName1, tv2Members,
		AccessGroupMemberOperationTypeAdd, nil)
	memberM1GroupM0N1 := &AccessGroupId{*m0PublicKey, *NewGroupKeyName(groupName1)}
	groupM1B := &AccessGroupId{*m1PublicKey, *BaseGroupKeyName()}
	tv2.connectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m1PublicKey})
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1B}, []*AccessGroupId{memberM1GroupM0N1})
	}
	tv2.disconnectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1B}, []*AccessGroupId{})
	}

	tv3Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv3 := _createAccessGroupMembersTestVector("TEST 3: (FAIL) Connect access group members remove transaction made by "+
		"(pk0, groupName1) removing member (pk1, baseGroup) with non-empty encrypted key", m0Priv, m0PubBytes, groupName1, tv3Members,
		AccessGroupMemberOperationTypeRemove, RuleErrorAccessGroupMemberRemoveEncryptedKeyNotEmpty)
	randomExtraData := make(map[string][]byte)
	randomExtraData["random"] = []byte{1}
	tv3p5Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: nil, ExtraData: randomExtraData},
	}
	tv3p5 := _createAccessGroupMembersTestVector("TEST 3.5: (FAIL) Connect access group members remove transaction made by "+
		"(pk0, groupName1) removing member (pk1, baseGroup) with non-empty extra data", m0Priv, m0PubBytes, groupName1, tv3p5Members,
		AccessGroupMemberOperationTypeRemove, RuleErrorAccessGroupMemberRemoveExtraDataNotEmpty)
	// Membership [memberRemove]:
	// (m0Pub, groupName1) ->
	tv4Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: nil, ExtraData: nil},
	}
	tv4 := _createAccessGroupMembersTestVector("TEST 4: (PASS) Connect access group members remove transaction made by "+
		"(pk0, groupName1) removing member (pk1, baseGroup)", m0Priv, m0PubBytes, groupName1, tv4Members,
		AccessGroupMemberOperationTypeRemove, nil)
	tv4.connectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1B}, []*AccessGroupId{})
	}
	tv4.disconnectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m1PublicKey})
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1B}, []*AccessGroupId{memberM1GroupM0N1})
	}
	tv5Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes[:10], AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: nil, ExtraData: nil},
	}
	tv5 := _createAccessGroupMembersTestVector("TEST 5: (FAIL) Connect access group members remove transaction made by "+
		"(pk0, groupName1) removing member (invalid, baseGroup) with invalid public key", m0Priv, m0PubBytes, groupName1, tv5Members,
		AccessGroupMemberOperationTypeRemove, RuleErrorPubKeyLen)
	tv6Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m2PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: nil, ExtraData: nil},
	}
	tv6 := _createAccessGroupMembersTestVector("TEST 6: (FAIL) Connect access group members remove transaction made by "+
		"(pk0, groupName1) removing non-existing member (pk2, baseKey) with invalid key name", m0Priv, m0PubBytes, groupName1, tv6Members,
		AccessGroupMemberOperationTypeRemove, RuleErrorAccessGroupMemberDoesntExistOrIsDeleted)
	// Membership [memberAdd]:
	// (m0Pub, groupName1) ->
	//		(m1Pub, BaseGroupKeyName)
	tv7Members := tv2Members
	tv7 := _createAccessGroupMembersTestVector("TEST 7: (PASS) Connect access group members add transaction made by "+
		"(pk0, groupName1) adding again as member (pk1, baseGroup)", m0Priv, m0PubBytes, groupName1, tv7Members,
		AccessGroupMemberOperationTypeAdd, nil)
	tv7.connectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m1PublicKey})
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1B}, []*AccessGroupId{memberM1GroupM0N1})
	}
	tv7.disconnectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1B}, []*AccessGroupId{})
	}
	// Membership [memberRemove]:
	// (m0Pub, groupName1) ->
	tv8Members := tv4Members
	tv8 := _createAccessGroupMembersTestVector("TEST 8: (PASS) Connect access group members remove transaction made by "+
		"(pk0, groupName1) removing again member (pk1, baseGroup)", m0Priv, m0PubBytes, groupName1, tv8Members,
		AccessGroupMemberOperationTypeRemove, nil)
	tv8.connectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1B}, []*AccessGroupId{})
	}
	tv8.disconnectCallback = tv7.connectCallback
	// Access group (m1Pub, groupName2) with access public key groupPk2
	// Membership [create]:
	// (m0Pub, groupName1) ->
	// (m1Pub, groupName2) ->
	tv9 := _createAccessGroupTestVector("TEST 9: (PASS) Connect access group create transaction made by "+
		"(pk1, groupName2)", m1Priv, m1PubBytes, m1PubBytes, groupPk2, groupName2,
		AccessGroupOperationTypeCreate, nil, nil)
	groupM1N2 := &AccessGroupId{*m1PublicKey, *NewGroupKeyName(groupName2)}
	// Membership [memberAdd]:
	// (m0Pub, groupName1) ->
	//		(m0Pub, baseGroup)
	// 		(m1Pub, groupName2)
	// (m1Pub, groupName2) ->
	tv10Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: groupName2, EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv10 := _createAccessGroupMembersTestVector("TEST 10: (PASS) Connect access group members add transaction made by "+
		"(pk0, groupName1) adding member (pk0, baseGroup) and (pk1, groupName2)", m0Priv, m0PubBytes, groupName1, tv10Members,
		AccessGroupMemberOperationTypeAdd, nil)

	memberM0GroupM0N1 := &AccessGroupId{*m0PublicKey, *NewGroupKeyName(groupName1)}
	tv10.connectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey})
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName2), []*PublicKey{})
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0B}, []*AccessGroupId{memberM0GroupM0N1})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1N2, groupM1B}, []*AccessGroupId{memberM1GroupM0N1})
	}
	tv10.disconnectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
	}
	// Membership [memberAdd]:
	// (m0Pub, groupName1) ->
	//		(m0Pub, baseGroup)
	// 		(m1Pub, groupName2)
	// (m1Pub, groupName2) ->
	// 		(m0Pub, groupName1)
	// 		(m1Pub, baseGroup)
	// 		(m2Pub, baseGroup)
	tv11Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: groupName1, EncryptedKey: []byte{1}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m2PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv11 := _createAccessGroupMembersTestVector("TEST 11: (PASS) Connect access group members add transaction made by "+
		"(pk1, groupName2) adding member (pk0, groupName1), (pk1, baseGroup) and (pk2, baseGroup)", m1Priv, m1PubBytes, groupName2, tv11Members,
		AccessGroupMemberOperationTypeAdd, nil)
	memberM0GroupM1N2 := &AccessGroupId{*m1PublicKey, *NewGroupKeyName(groupName2)}
	memberM1GroupM1N2 := &AccessGroupId{*m1PublicKey, *NewGroupKeyName(groupName2)}
	memberM2GroupM1N2 := &AccessGroupId{*m1PublicKey, *NewGroupKeyName(groupName2)}
	groupM2B := &AccessGroupId{*m2PublicKey, *BaseGroupKeyName()}
	tv11.connectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey})
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName2), []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey})
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N1, groupM0B}, []*AccessGroupId{memberM0GroupM0N1, memberM0GroupM1N2})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1N2, groupM1B}, []*AccessGroupId{memberM1GroupM0N1, memberM1GroupM1N2})
		_verifyGroupIdsForUser(t, m2PubBytes, utxoView, []*AccessGroupId{groupM2B}, []*AccessGroupId{memberM2GroupM1N2})
	}
	tv11.disconnectCallback = tv10.connectCallback

	// Mine all above transactions into a block.
	tvv1 := []*transactionTestVector{tv1, tv2, tv3, tv3p5, tv4, tv5, tv6, tv7, tv8, tv9, tv10, tv11}
	tvb1ConnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		tv11.connectCallback(tv11, tm, utxoView)
	}
	tvb1DisconnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName2), []*PublicKey{})
	}
	tvb1 := NewTransactionTestVectorBlock(tvv1, tvb1ConnectCallback, tvb1DisconnectCallback)

	// Membership [memberAdd]:
	// (m0Pub, groupName1) ->
	//		(m0Pub, baseGroup)
	// 		(m1Pub, groupName2)
	//		20 x (randomPk, baseGroup)
	// (m1Pub, groupName2) ->
	// 		(m0Pub, groupName1)
	// 		(m1Pub, baseGroup)
	// 		(m2Pub, baseGroup)
	//		30 x (randomPk, baseGroup)
	tv12Members := []*AccessGroupMember{}
	tempMemberMap1 := make(map[PublicKey]AccessGroupMember)
	for ii := 0; ii < randomMemberCounter1; ii++ {
		extraDataMap := make(map[string][]byte)
		extraDataMap[fmt.Sprintf("randomField%v", ii)] = []byte(fmt.Sprintf("randomValue%v", ii))
		groupMember := &AccessGroupMember{
			AccessGroupMemberPublicKey: randomMemberPublicKeys1[ii].ToBytes(),
			AccessGroupMemberKeyName:   BaseGroupKeyName().ToBytes(),
			EncryptedKey:               []byte{byte(ii)},
			ExtraData:                  extraDataMap,
		}
		tv12Members = append(tv12Members, groupMember)
		tempMemberMap1[*randomMemberPublicKeys1[ii]] = *groupMember
	}
	tv12 := _createAccessGroupMembersTestVector(fmt.Sprintf("TEST 12: (PASS) Connect access group members add transaction made by "+
		"(pk0, groupName1) adding member and %v x (randomPk, baseGroup)", randomMemberCounter1), m0Priv, m0PubBytes, groupName1, tv12Members,
		AccessGroupMemberOperationTypeAdd, nil)
	tv12.connectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1),
			append([]*PublicKey{m0PublicKey, m1PublicKey}, randomMemberPublicKeys1...))
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName2), []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey})
	}
	tv12.disconnectCallback = tv11.connectCallback

	tv13Members := []*AccessGroupMember{}
	tempMemberMap2 := make(map[PublicKey]AccessGroupMember)
	for ii := 0; ii < randomMemberCounter2; ii++ {
		extraDataMap := make(map[string][]byte)
		extraDataMap[fmt.Sprintf("randomField%v", ii)] = []byte(fmt.Sprintf("randomValue%v", ii))
		groupMember := &AccessGroupMember{
			AccessGroupMemberPublicKey: randomMemberPublicKeys2[ii].ToBytes(),
			AccessGroupMemberKeyName:   BaseGroupKeyName().ToBytes(),
			EncryptedKey:               []byte{byte(ii)},
			ExtraData:                  extraDataMap,
		}
		tv13Members = append(tv13Members, groupMember)
		tempMemberMap2[*randomMemberPublicKeys2[ii]] = *groupMember
	}
	tv13 := _createAccessGroupMembersTestVector(fmt.Sprintf("TEST 13: (PASS) Connect access group members add transaction made by "+
		"(pk1, groupName2) adding member and %v x (randomPk, baseGroup)", randomMemberCounter2), m1Priv, m1PubBytes, groupName2, tv13Members,
		AccessGroupMemberOperationTypeAdd, nil)
	tv13.connectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1),
			append([]*PublicKey{m0PublicKey, m1PublicKey}, randomMemberPublicKeys1...))
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName2),
			append([]*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey}, randomMemberPublicKeys2...))
	}
	tv13.disconnectCallback = tv12.connectCallback
	// Remove member (m0Pub, baseGroup) and half of the random members from the group (m0Pub, groupName1).
	// Membership [memberRemove]:
	// (m0Pub, groupName1) ->
	// 		(m1Pub, groupName2)
	//		10 x (randomPk, baseGroup)
	// (m1Pub, groupName2) ->
	// 		(m0Pub, groupName1)
	// 		(m1Pub, baseGroup)
	// 		(m2Pub, baseGroup)
	//		30 x (randomPk, baseGroup)
	tv14Members := []*AccessGroupMember{}
	randomMembersShuffleOrder1 := []*AccessGroupMember{}
	randomMembersShuffleOrder2 := []*AccessGroupMember{}
	for _, member := range tempMemberMap1 {
		memberCopy := member
		memberCopy.ExtraData = nil
		memberCopy.EncryptedKey = nil
		randomMembersShuffleOrder1 = append(randomMembersShuffleOrder1, &memberCopy)
	}
	for _, member := range tempMemberMap2 {
		memberCopy := member
		memberCopy.ExtraData = nil
		memberCopy.EncryptedKey = nil
		randomMembersShuffleOrder2 = append(randomMembersShuffleOrder2, &memberCopy)
	}
	// Get half of the shuffled random members from the first group.
	for ii := 0; ii < randomMemberCounter1/2; ii++ {
		tv14Members = append(tv14Members, randomMembersShuffleOrder1[ii])
	}
	tv14Members = append(tv14Members, &AccessGroupMember{
		AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: nil, ExtraData: nil,
	})
	tv14 := _createAccessGroupMembersTestVector(fmt.Sprintf("TEST 14: (PASS) Connect access group members remove transaction made by "+
		"(pk0, groupName1) removing (m0Pub, baseGroup) and %v x (randomPk, baseGroup)", randomMemberCounter1/2), m0Priv, m0PubBytes, groupName1, tv14Members,
		AccessGroupMemberOperationTypeRemove, nil)
	tv14.connectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		remainingRandomMembers1 := []*PublicKey{}
		for _, member := range randomMembersShuffleOrder1[randomMemberCounter1/2:] {
			remainingRandomMembers1 = append(remainingRandomMembers1, NewPublicKey(member.AccessGroupMemberPublicKey))
		}
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1),
			append([]*PublicKey{m1PublicKey}, remainingRandomMembers1...))
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName2),
			append([]*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey}, randomMemberPublicKeys2...))
	}
	tv14.disconnectCallback = tv13.connectCallback
	// Remove members (m0Pub, groupName1), (m1Pub, baseGroup), (m2Pub, baseGroup) and
	// half of the random members from the group (m1Pub, groupName2).
	// Membership [memberRemove]:
	// (m0Pub, groupName1) ->
	// 		(m1Pub, groupName2)
	//		10 x (randomPk, baseGroup)
	// (m1Pub, groupName2) ->
	//		15 x (randomPk, baseGroup)
	tv15Members := []*AccessGroupMember{}
	// Get half of the shuffled random members from the second group.
	tv15Members = append(tv15Members, randomMembersShuffleOrder2[:randomMemberCounter2/2]...)
	tv15Members = append(tv15Members, []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: NewGroupKeyName(groupName1).ToBytes(), EncryptedKey: nil, ExtraData: nil},
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: nil, ExtraData: nil},
		{AccessGroupMemberPublicKey: m2PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: nil, ExtraData: nil},
	}...)
	tv15 := _createAccessGroupMembersTestVector(fmt.Sprintf("TEST 15: (PASS) Connect access group members remove "+
		"transaction made by (pk1, groupName2) removing (m0Pub, groupName1), (m1Pub, baseGroup), (m2Pub, baseGroup) "+
		"and %v x (randomPk, baseGroup)", randomMemberCounter2/2),
		m1Priv, m1PubBytes, groupName2, tv15Members, AccessGroupMemberOperationTypeRemove, nil)
	tv15.connectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		remainingRandomMembers1 := []*PublicKey{}
		for _, member := range randomMembersShuffleOrder1[randomMemberCounter1/2:] {
			remainingRandomMembers1 = append(remainingRandomMembers1, NewPublicKey(member.AccessGroupMemberPublicKey))
		}
		remainingRandomMembers2 := []*PublicKey{}
		for _, member := range randomMembersShuffleOrder2[randomMemberCounter2/2:] {
			remainingRandomMembers2 = append(remainingRandomMembers2, NewPublicKey(member.AccessGroupMemberPublicKey))
		}
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), append([]*PublicKey{m1PublicKey}, remainingRandomMembers1...))
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName2), remainingRandomMembers2)
	}
	tv15.disconnectCallback = tv14.connectCallback

	// Mine all above transactions into a block.
	tvv2 := []*transactionTestVector{tv12, tv13, tv14, tv15}
	tvb2ConnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		tv15.connectCallback(tv15, tm, utxoView)
	}
	tvb2DisconnectCallback := tvb1ConnectCallback
	tvb2 := NewTransactionTestVectorBlock(tvv2, tvb2ConnectCallback, tvb2DisconnectCallback)

	// Remove member (m1Pub, groupName2) and remaining random members from (m0Pub, groupName1)
	// Membership [memberRemove]:
	// (m0Pub, groupName1) ->
	// (m1Pub, groupName2) ->
	//		15 x (randomPk, baseGroup)
	tv16Members := []*AccessGroupMember{}
	for _, member := range randomMembersShuffleOrder1[randomMemberCounter1/2:] {
		tv16Members = append(tv16Members, &AccessGroupMember{
			AccessGroupMemberPublicKey: member.AccessGroupMemberPublicKey,
			AccessGroupMemberKeyName:   BaseGroupKeyName().ToBytes(),
			EncryptedKey:               nil,
			ExtraData:                  nil,
		})
	}
	tv16Members = append(tv16Members, &AccessGroupMember{
		AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: NewGroupKeyName(groupName2).ToBytes(), EncryptedKey: nil, ExtraData: nil,
	})
	tv16 := _createAccessGroupMembersTestVector(fmt.Sprintf("TEST 16: (PASS) Connect access group members remove "+
		"transaction made by (pk0, groupName1) removing (m1Pub, groupName2) and remaining %v x (randomPk, baseGroup)",
		randomMemberCounter1/2), m0Priv, m0PubBytes, groupName1, tv16Members, AccessGroupMemberOperationTypeRemove, nil)
	tv16.connectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		remainingRandomMembers2 := []*PublicKey{}
		for _, member := range randomMembersShuffleOrder2[randomMemberCounter2/2:] {
			remainingRandomMembers2 = append(remainingRandomMembers2, NewPublicKey(member.AccessGroupMemberPublicKey))
		}
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName2), remainingRandomMembers2)
	}
	tv16.disconnectCallback = tv15.connectCallback
	// Remove remaining random members from (m1Pub, groupName2)
	// Membership [memberRemove]:
	// (m0Pub, groupName1) ->
	// (m1Pub, groupName2) ->
	tv17Members := []*AccessGroupMember{}
	for _, member := range randomMembersShuffleOrder2[randomMemberCounter2/2:] {
		tv17Members = append(tv17Members, &AccessGroupMember{
			AccessGroupMemberPublicKey: member.AccessGroupMemberPublicKey,
			AccessGroupMemberKeyName:   BaseGroupKeyName().ToBytes(),
			EncryptedKey:               nil,
			ExtraData:                  nil,
		})
	}
	tv17 := _createAccessGroupMembersTestVector(fmt.Sprintf("TEST 17: (PASS) Connect access group members remove "+
		"transaction made by (pk1, groupName2) removing remaining %v x (randomPk, baseGroup)", randomMemberCounter2/2),
		m1Priv, m1PubBytes, groupName2, tv17Members, AccessGroupMemberOperationTypeRemove, nil)
	tv17.connectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName2), []*PublicKey{})
	}
	tv17.disconnectCallback = tv16.connectCallback
	// Mine the above transactions into a block.
	tvv3 := []*transactionTestVector{tv16, tv17}
	tvb3ConnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		tv17.connectCallback(tv17, tm, utxoView)
	}
	tvb3DisconnectCallback := tvb2ConnectCallback
	tvb3 := NewTransactionTestVectorBlock(tvv3, tvb3ConnectCallback, tvb3DisconnectCallback)

	tvbb := []*transactionTestVectorBlock{tvb1, tvb2, tvb3}
	tes := NewTransactionTestSuite(t, tvbb, tConfig)
	tes.Run()
}

func TestAccessGroupMembersUpdate(t *testing.T) {
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
	fundPublicKeysWithNanosMap[*m0PublicKey] = 200
	fundPublicKeysWithNanosMap[*m1PublicKey] = 200
	fundPublicKeysWithNanosMap[*m2PublicKey] = 200
	fundPublicKeysWithNanosMap[*m3PublicKey] = 200

	initChainCallback := func(tm *transactionTestMeta) {
		_setAccessGroupParams(tm)
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
	_ = groupPk1

	groupPriv2, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	groupPk2 := groupPriv2.PubKey().SerializeCompressed()
	_ = groupPk2

	groupPriv3, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	groupPk3 := groupPriv3.PubKey().SerializeCompressed()
	_ = groupPk3

	groupName1 := []byte("group1")
	_ = groupName1
	groupName2 := []byte("group2")
	_ = groupName2
	groupName3 := []byte("group3")
	_ = groupName3
	groupName4 := []byte("group4")
	_ = groupName4

	// Access groups (m2Pub, groupName1) and (m3Pub, groupName1).
	// Membership [create]:
	// (m2Pub, groupName1) ->
	// (m3Pub, groupName1) ->
	tv1 := _createAccessGroupTestVector("TEST 1: (PASS) Connect access group create transaction made by (pk2, groupName1)",
		m2Priv, m2PubBytes, m2PubBytes, groupPk1, groupName1,
		AccessGroupOperationTypeCreate, nil, nil)
	tv2 := _createAccessGroupTestVector("TEST 2: (PASS) Connect access group members add transaction made by (pk3, groupName1)",
		m3Priv, m3PubBytes, m3PubBytes, groupPk2, groupName1,
		AccessGroupOperationTypeCreate, nil, nil)
	groupM2N1 := &AccessGroupId{*m2PublicKey, *NewGroupKeyName(groupName1)}
	groupM2B := &AccessGroupId{*m2PublicKey, *BaseGroupKeyName()}
	groupM3N1 := &AccessGroupId{*m3PublicKey, *NewGroupKeyName(groupName1)}
	groupM3B := &AccessGroupId{*m3PublicKey, *BaseGroupKeyName()}
	// Add member (m0Pub, BaseGroup) to access group (m0Pub, groupName1).
	// Membership [add]:
	// (m2Pub, groupName1) ->
	// 		(m0Pub, BaseGroup) ->
	// (m3Pub, groupName1) ->
	tv3Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{7, 8, 0}, ExtraData: nil},
	}
	tv3 := _createAccessGroupMembersTestVector("TEST 3: (PASS) Connect access group members add transaction "+
		"made by (pk2, groupName1) with (pk0, BaseGroup) as member",
		m2Priv, m2PubBytes, groupName1, tv3Members, AccessGroupMemberOperationTypeAdd, nil)
	groupM0B := &AccessGroupId{*m0PublicKey, *BaseGroupKeyName()}
	memberM0GroupM2N1 := &AccessGroupId{*m2PublicKey, *NewGroupKeyName(groupName1)}
	tv3.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey})
		groupMemberEntry, err := utxoView.GetAccessGroupMemberEntry(m0PublicKey, m2PublicKey, NewGroupKeyName(groupName1))
		require.NoError(err)
		require.Equal(true, _verifyEqualAccessGroupMember(tm.t, groupMemberEntry, tv3Members[0]))
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0B}, []*AccessGroupId{memberM0GroupM2N1})
		_verifyGroupIdsForUser(t, m2PubBytes, utxoView, []*AccessGroupId{groupM2N1, groupM2B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m3PubBytes, utxoView, []*AccessGroupId{groupM3N1, groupM3B}, []*AccessGroupId{})
	}
	tv3.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
	}
	// Now modify the member (m0Pub, BaseGroup) of the (m2Pub, groupName1) access group.
	tv4MemberExtraData := make(map[string][]byte)
	tv4MemberExtraData["foo"] = []byte("bar")
	tv4Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(),
			EncryptedKey: []byte{1, 1, 1}, ExtraData: tv4MemberExtraData},
	}
	tv4 := _createAccessGroupMembersTestVector("TEST 4: (PASS) Connect access group members update transaction "+
		"made by (pk2, groupName1) updating member (pk0, BaseGroup)",
		m2Priv, m2PubBytes, groupName1, tv4Members, AccessGroupMemberOperationTypeUpdate, nil)
	tv4.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey})
		groupMemberEntry, err := utxoView.GetAccessGroupMemberEntry(m0PublicKey, m2PublicKey, NewGroupKeyName(groupName1))
		require.NoError(err)
		require.Equal(true, _verifyEqualAccessGroupMember(tm.t, groupMemberEntry, tv4Members[0]))
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0B}, []*AccessGroupId{memberM0GroupM2N1})
	}
	tv4.disconnectCallback = tv3.connectCallback
	// Revert to the same member as in tv3.
	tv5Members := []*AccessGroupMember{
		tv3Members[0],
	}
	tv5 := _createAccessGroupMembersTestVector("TEST 5: (PASS) Connect access group members update transaction "+
		"made by (pk2, groupName1) updating member (pk0, BaseGroup) to the same value as before",
		m2Priv, m2PubBytes, groupName1, tv5Members, AccessGroupMemberOperationTypeUpdate, nil)
	tv5.connectCallback = tv3.connectCallback
	tv5.disconnectCallback = tv4.connectCallback
	// Check a failing scenario. Try modifying non-existent member.
	tv6Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m3PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(),
			EncryptedKey: []byte{1, 1, 1}, ExtraData: nil},
	}
	tv6 := _createAccessGroupMembersTestVector("TEST 6: (FAIL) Connect access group members update transaction "+
		"made by (pk2, groupName1) updating non-existent member (pk3, BaseGroup)",
		m2Priv, m2PubBytes, groupName1, tv6Members, AccessGroupMemberOperationTypeUpdate,
		RuleErrorAccessGroupMemberDoesntExistOrIsDeleted)
	// Create group (m0Pub, groupName4)
	tv7 := _createAccessGroupTestVector("TEST 7: (PASS) Connect access group create transaction "+
		"made by (pk0, groupName4)", m0Priv, m0PubBytes, m0PubBytes, groupPk3, groupName4,
		AccessGroupOperationTypeCreate, nil, nil)
	groupM0N4 := &AccessGroupId{*m0PublicKey, *NewGroupKeyName(groupName4)}
	// Change the member (m0Pub, BaseGroup) to (m0Pub, groupName4).
	// Membership [update]:
	// (m0Pub, groupName4) ->
	// (m2Pub, groupName1) ->
	// 		(m0Pub, groupName4) ->
	// (m3Pub, groupName1) ->
	tv8ExtraData := make(map[string][]byte)
	tv8ExtraData["RaRandom"] = []byte("veryRandom")
	tv8Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: groupName4,
			EncryptedKey: []byte{200, 200, 200, 111}, ExtraData: tv8ExtraData},
	}
	tv8 := _createAccessGroupMembersTestVector("TEST 8: (PASS) Connect access group members add transaction "+
		"made by (m2Pub, groupName1) updating (pk0, groupName4) as member, changing all fields",
		m2Priv, m2PubBytes, groupName1, tv8Members, AccessGroupMemberOperationTypeUpdate, nil)
	tv8.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey})
		groupMemberEntry, err := utxoView.GetAccessGroupMemberEntry(m0PublicKey, m2PublicKey, NewGroupKeyName(groupName1))
		require.NoError(err)
		require.Equal(true, _verifyEqualAccessGroupMember(tm.t, groupMemberEntry, tv8Members[0]))
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N4, groupM0B}, []*AccessGroupId{memberM0GroupM2N1})
	}
	tv7.disconnectCallback = tv5.connectCallback

	// Mine the above transactions into a block.
	tvv1 := []*transactionTestVector{tv1, tv2, tv3, tv4, tv5, tv6, tv7, tv8}
	tvb1ConnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		tv8.connectCallback(tv8, tm, utxoView)
	}
	tvb1DisconnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
	}
	tvb1 := NewTransactionTestVectorBlock(tvv1, tvb1ConnectCallback, tvb1DisconnectCallback)

	// Add a few more members to the access group (m2Pub, groupName1).
	// Membership [add]:
	// (m0Pub, groupName4) ->
	// (m2Pub, groupName1) ->
	// 		(m0Pub, groupName4) ->
	// 		(m1Pub, baseGroup) ->
	// 		(m2Pub, baseGroup) ->
	// 		(m3Pub, baseGroup) ->
	// (m3Pub, groupName1) ->
	tv9Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1, 1, 1}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m2PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{2, 2, 2}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m3PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{3, 3, 3}, ExtraData: nil},
	}
	tv9 := _createAccessGroupMembersTestVector("TEST 9: (PASS) Connect access group members add transaction "+
		"made by (m2Pub, groupName1) adding (pk1, BaseGroup), (pk2, BaseGroup), (pk3, BaseGroup)",
		m2Priv, m2PubBytes, groupName1, tv9Members, AccessGroupMemberOperationTypeAdd, nil)
	memberM1GroupM2N1 := &AccessGroupId{*m2PublicKey, *NewGroupKeyName(groupName1)}
	groupM1B := &AccessGroupId{*m1PublicKey, *BaseGroupKeyName()}
	memberM2GroupM2N1 := &AccessGroupId{*m2PublicKey, *NewGroupKeyName(groupName1)}
	memberM3GroupM2N1 := &AccessGroupId{*m2PublicKey, *NewGroupKeyName(groupName1)}

	tv9.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey, m3PublicKey})
		groupMember, err := utxoView.GetAccessGroupMemberEntry(m0PublicKey, m2PublicKey, NewGroupKeyName(groupName1))
		require.NoError(err)
		require.Equal(true, _verifyEqualAccessGroupMember(tm.t, groupMember, tv8Members[0]))
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N4, groupM0B}, []*AccessGroupId{memberM0GroupM2N1})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1B}, []*AccessGroupId{memberM1GroupM2N1})
		_verifyGroupIdsForUser(t, m2PubBytes, utxoView, []*AccessGroupId{groupM2N1, groupM2B}, []*AccessGroupId{memberM2GroupM2N1})
		_verifyGroupIdsForUser(t, m3PubBytes, utxoView, []*AccessGroupId{groupM3N1, groupM3B}, []*AccessGroupId{memberM3GroupM2N1})
	}
	tv9.disconnectCallback = tv8.connectCallback
	// Add a few more members to the access group (m3Pub, groupName1)
	// Membership [add]:
	// (m0Pub, groupName4) ->
	// (m2Pub, groupName1) ->
	// 		(m0Pub, groupName4) ->
	// 		(m1Pub, baseGroup) ->
	// 		(m2Pub, baseGroup) ->
	// 		(m3Pub, baseGroup) ->
	// (m3Pub, groupName1) ->
	// 		(m0Pub, baseGroup) ->
	// 		(m1Pub, baseGroup) ->
	// 		(m2Pub, baseGroup) ->
	// 		(m3Pub, baseGroup) ->
	tv10Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{0, 0, 0}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1, 1, 1}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m2PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{2, 2, 2}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m3PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{3, 3, 3}, ExtraData: nil},
	}
	memberM0GroupM3N1 := &AccessGroupId{*m3PublicKey, *NewGroupKeyName(groupName1)}
	memberM1GroupM3N1 := &AccessGroupId{*m3PublicKey, *NewGroupKeyName(groupName1)}
	memberM2GroupM3N1 := &AccessGroupId{*m3PublicKey, *NewGroupKeyName(groupName1)}
	memberM3GroupM3N1 := &AccessGroupId{*m3PublicKey, *NewGroupKeyName(groupName1)}
	tv10 := _createAccessGroupMembersTestVector("TEST 10: (PASS) Connect access group members add transaction "+
		"made by (m3Pub, groupName1) adding (pk0, BaseGroup), (pk1, BaseGroup), (pk2, BaseGroup), (pk3, BaseGroup)",
		m3Priv, m3PubBytes, groupName1, tv10Members, AccessGroupMemberOperationTypeAdd, nil)
	tv10.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey, m3PublicKey})
		_verifyMembersList(tm, utxoView, m3PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey, m3PublicKey})
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N4, groupM0B}, []*AccessGroupId{memberM0GroupM2N1, memberM0GroupM3N1})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1B}, []*AccessGroupId{memberM1GroupM2N1, memberM1GroupM3N1})
		_verifyGroupIdsForUser(t, m2PubBytes, utxoView, []*AccessGroupId{groupM2N1, groupM2B}, []*AccessGroupId{memberM2GroupM2N1, memberM2GroupM3N1})
		_verifyGroupIdsForUser(t, m3PubBytes, utxoView, []*AccessGroupId{groupM3N1, groupM3B}, []*AccessGroupId{memberM3GroupM2N1, memberM3GroupM3N1})
	}
	tv10.disconnectCallback = tv9.connectCallback
	// Create a group (m1Pub, groupName3).
	tv11 := _createAccessGroupTestVector("TEST 11: (PASS) Connect access group create transaction "+
		"creating (m1Pub, groupName3)", m1Priv, m1PubBytes, m1PubBytes, groupPk2, groupName3,
		AccessGroupOperationTypeCreate, nil, nil)
	groupM1N3 := &AccessGroupId{*m1PublicKey, *NewGroupKeyName(groupName3)}
	// Update members of group (m2Pub, groupName1).
	// Membership [update]:
	// (m0Pub, groupName4) ->
	// (m1Pub, groupName3) ->
	// (m2Pub, groupName1) ->
	// 		(m0Pub, groupName4) ->
	// 		(m1Pub, groupName3) ->
	// 		(m2Pub, baseGroup) ->
	// 		(m3Pub, groupName1) ->
	// (m3Pub, groupName1) ->
	// 		(m0Pub, baseGroup) ->
	// 		(m1Pub, baseGroup) ->
	// 		(m2Pub, baseGroup) ->
	// 		(m3Pub, baseGroup) ->
	differentKey := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	differentMap := make(map[string][]byte)
	differentMap["11111"] = []byte("11111")
	differentMap["22222"] = []byte("22222")
	differentMap["33333"] = []byte("33333")
	tv12Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: NewGroupKeyName(groupName4).ToBytes(),
			EncryptedKey: differentKey, ExtraData: differentMap},
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: NewGroupKeyName(groupName3).ToBytes(),
			EncryptedKey: differentKey, ExtraData: differentMap},
		{AccessGroupMemberPublicKey: m2PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(),
			EncryptedKey: differentKey, ExtraData: differentMap},
		{AccessGroupMemberPublicKey: m3PubBytes, AccessGroupMemberKeyName: NewGroupKeyName(groupName1).ToBytes(),
			EncryptedKey: differentKey, ExtraData: differentMap},
	}
	tv12 := _createAccessGroupMembersTestVector("TEST 12: (PASS) Connect access group members update transaction "+
		"made by (m2Pub, groupName1) updating (pk0, groupName4), (pk1, groupName3), (pk2, baseGroup), (pk3, groupName1)",
		m2Priv, m2PubBytes, groupName1, tv12Members, AccessGroupMemberOperationTypeUpdate, nil)
	tv12.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey, m3PublicKey})
		_verifyMembersList(tm, utxoView, m3PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey, m3PublicKey})
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N4, groupM0B}, []*AccessGroupId{memberM0GroupM2N1, memberM0GroupM3N1})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1N3, groupM1B}, []*AccessGroupId{memberM1GroupM2N1, memberM1GroupM3N1})
		_verifyGroupIdsForUser(t, m2PubBytes, utxoView, []*AccessGroupId{groupM2N1, groupM2B}, []*AccessGroupId{memberM2GroupM2N1, memberM2GroupM3N1})
		_verifyGroupIdsForUser(t, m3PubBytes, utxoView, []*AccessGroupId{groupM3N1, groupM3B}, []*AccessGroupId{memberM3GroupM2N1, memberM3GroupM3N1})
	}
	// Now delete half members of group (m2Pub, groupName1).
	// Membership [delete]:
	// (m0Pub, groupName4) ->
	// (m1Pub, groupName3) ->
	// (m2Pub, groupName1) ->
	// 		(m2Pub, baseGroup) ->
	// 		(m3Pub, groupName1) ->
	// (m3Pub, groupName1) ->
	// 		(m0Pub, baseGroup) ->
	// 		(m1Pub, baseGroup) ->
	// 		(m2Pub, baseGroup) ->
	// 		(m3Pub, baseGroup) ->
	tv13Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: NewGroupKeyName(groupName4).ToBytes(), EncryptedKey: nil, ExtraData: nil},
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: NewGroupKeyName(groupName3).ToBytes(), EncryptedKey: nil, ExtraData: nil},
	}
	tv13 := _createAccessGroupMembersTestVector("TEST 13: (PASS) Connect access group members delete transaction "+
		"made by (m2Pub, groupName1) deleting (pk0, groupName4), (pk1, groupName3)",
		m2Priv, m2PubBytes, groupName1, tv13Members, AccessGroupMemberOperationTypeRemove, nil)
	tv13.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m2PublicKey, m3PublicKey})
		_verifyMembersList(tm, utxoView, m3PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey, m3PublicKey})
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N4, groupM0B}, []*AccessGroupId{memberM0GroupM3N1})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1N3, groupM1B}, []*AccessGroupId{memberM1GroupM3N1})
		_verifyGroupIdsForUser(t, m2PubBytes, utxoView, []*AccessGroupId{groupM2N1, groupM2B}, []*AccessGroupId{memberM2GroupM2N1, memberM2GroupM3N1})
		_verifyGroupIdsForUser(t, m3PubBytes, utxoView, []*AccessGroupId{groupM3N1, groupM3B}, []*AccessGroupId{memberM3GroupM2N1, memberM3GroupM3N1})
	}
	tv13.disconnectCallback = tv12.connectCallback
	// Try updating one of the removed members as a sanity-check, should fail.
	tv14Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: NewGroupKeyName(groupName4).ToBytes(),
			EncryptedKey: differentKey, ExtraData: differentMap},
	}
	tv14 := _createAccessGroupMembersTestVector("TEST 14: (FAIL) Connect access group members update transaction "+
		"made by (m2Pub, groupName1) updating (pk0, groupName4) which was removed",
		m2Priv, m2PubBytes, groupName1, tv14Members, AccessGroupMemberOperationTypeUpdate, RuleErrorAccessGroupMemberDoesntExistOrIsDeleted)
	// Try deleting three of the members of the other group (m3Pub, groupName1).
	// Membership [delete]:
	// (m0Pub, groupName4) ->
	// (m1Pub, groupName3) ->
	// (m2Pub, groupName1) ->
	// 		(m2Pub, baseGroup) ->
	// 		(m3Pub, groupName1) ->
	// (m3Pub, groupName1) ->
	// 		(m3Pub, baseGroup) ->
	tv15Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: NewGroupKeyName(groupName4).ToBytes(), EncryptedKey: nil, ExtraData: nil},
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: NewGroupKeyName(groupName3).ToBytes(), EncryptedKey: nil, ExtraData: nil},
		{AccessGroupMemberPublicKey: m2PubBytes, AccessGroupMemberKeyName: NewGroupKeyName(groupName1).ToBytes(), EncryptedKey: nil, ExtraData: nil},
	}
	tv15 := _createAccessGroupMembersTestVector("TEST 15: (PASS) Connect access group members delete transaction "+
		"made by (m3Pub, groupName1) deleting (pk0, groupName4), (pk1, groupName3), (pk2, groupName1) which are not in the group",
		m3Priv, m3PubBytes, groupName1, tv15Members, AccessGroupMemberOperationTypeRemove, nil)
	tv15.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m2PublicKey, m3PublicKey})
		_verifyMembersList(tm, utxoView, m3PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m3PublicKey})
		_verifyGroupIdsForUser(t, m0PubBytes, utxoView, []*AccessGroupId{groupM0N4, groupM0B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m1PubBytes, utxoView, []*AccessGroupId{groupM1N3, groupM1B}, []*AccessGroupId{})
		_verifyGroupIdsForUser(t, m2PubBytes, utxoView, []*AccessGroupId{groupM2N1, groupM2B}, []*AccessGroupId{memberM2GroupM2N1})
		_verifyGroupIdsForUser(t, m3PubBytes, utxoView, []*AccessGroupId{groupM3N1, groupM3B}, []*AccessGroupId{memberM3GroupM2N1, memberM3GroupM3N1})
	}
	tv15.disconnectCallback = tv13.connectCallback
	// Update both of the members of (m2Pub, groupName1).
	// Membership [update]:
	// (m0Pub, groupName4) ->
	// (m1Pub, groupName3) ->
	// (m2Pub, groupName1) ->
	// 		(m2Pub, baseGroup) ->
	// 		(m3Pub, baseGroup) ->
	// (m3Pub, groupName1) ->
	// 		(m3Pub, baseGroup) ->
	uniqueKey := []byte{1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233}
	uniqueMap := map[string][]byte{"unique": uniqueKey}
	tv16Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m2PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(),
			EncryptedKey: uniqueKey, ExtraData: uniqueMap},
		{AccessGroupMemberPublicKey: m3PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(),
			EncryptedKey: uniqueKey, ExtraData: uniqueMap},
	}
	tv16 := _createAccessGroupMembersTestVector("TEST 16: (PASS) Connect access group members update transaction "+
		"made by (m2Pub, groupName1) updating (pk2, baseGroup) and (pk3, baseGroup)",
		m2Priv, m2PubBytes, groupName1, tv16Members, AccessGroupMemberOperationTypeUpdate, nil)
	tv16.connectCallback = tv15.connectCallback
	tv16.disconnectCallback = tv15.connectCallback
	// Update the member of (m3Pub, groupName1).
	tv17Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m3PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(),
			EncryptedKey: uniqueKey, ExtraData: uniqueMap},
	}
	tv17 := _createAccessGroupMembersTestVector("TEST 17: (PASS) Connect access group members update transaction "+
		"made by (m3Pub, groupName1) updating (pk3, baseGroup)",
		m3Priv, m3PubBytes, groupName1, tv17Members, AccessGroupMemberOperationTypeUpdate, nil)
	tv17.connectCallback = tv16.connectCallback
	tv17.disconnectCallback = tv16.connectCallback
	tvv2 := []*transactionTestVector{tv9, tv10, tv11, tv12, tv13, tv14, tv15, tv16, tv17}
	tvb2ConnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		tv17.connectCallback(tv17, tm, utxoView)
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName4), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName3), []*PublicKey{})
		memberPk2groupPk2, err := utxoView.GetAccessGroupMemberEntry(m2PublicKey, m2PublicKey, NewGroupKeyName(groupName1))
		require.NoError(err)
		require.Equal(true, _verifyEqualAccessGroupMember(tm.t, memberPk2groupPk2, tv16Members[0]))
		memberPk3groupPk2, err := utxoView.GetAccessGroupMemberEntry(m3PublicKey, m2PublicKey, NewGroupKeyName(groupName1))
		require.NoError(err)
		require.Equal(true, _verifyEqualAccessGroupMember(tm.t, memberPk3groupPk2, tv16Members[1]))
		memberPk3groupPk3, err := utxoView.GetAccessGroupMemberEntry(m3PublicKey, m3PublicKey, NewGroupKeyName(groupName1))
		require.NoError(err)
		require.Equal(true, _verifyEqualAccessGroupMember(tm.t, memberPk3groupPk3, tv17Members[0]))
	}
	tvb2DisconnectCallback := tvb1ConnectCallback
	tvb2 := NewTransactionTestVectorBlock(tvv2, tvb2ConnectCallback, tvb2DisconnectCallback)

	tvbb := []*transactionTestVectorBlock{tvb1, tvb2}
	tes := NewTransactionTestSuite(t, tvbb, tConfig)
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
		verifyConnectUtxoViewEntry: func(tv *transactionTestVector, tm *transactionTestMeta,
			utxoView *UtxoView) {
			dataSpace := tv.inputSpace.(*accessGroupMembersTestData)
			_verifyConnectUtxoViewEntryForAccessGroupMembers(
				tm.t, utxoView, operationType,
				dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupKeyName,
				dataSpace.accessGroupMembersList)
		},
		verifyDisconnectUtxoViewEntry: func(tv *transactionTestVector, tm *transactionTestMeta,
			utxoView *UtxoView, utxoOps []*UtxoOperation) {
			dataSpace := tv.inputSpace.(*accessGroupMembersTestData)
			_verifyDisconnectUtxoViewEntryForAccessGroupMembers(
				tm.t, utxoView, utxoOps, operationType,
				dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupKeyName,
				dataSpace.accessGroupMembersList)
		},
		verifyDbEntry: func(tv *transactionTestVector, tm *transactionTestMeta,
			dbAdapter *DbAdapter) {
			dataSpace := tv.inputSpace.(*accessGroupMembersTestData)
			_verifyDbEntryForAccessGroupMembers(
				tm.t, dbAdapter, operationType,
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
		nil, 10, mempool, []*DeSoOutput{})
	if err != nil {
		return nil, errors.Wrapf(err, "_createSignedAccessGroupMembersTransaction: ")
	}
	require.Equal(totalInputMake, changeAmountMake+feesMake)
	_signTxn(t, txn, userPrivateKey)
	return txn, nil
}

func _verifyConnectUtxoViewEntryForAccessGroupMembers(t *testing.T, utxoView *UtxoView,
	operationType AccessGroupMemberOperationType, accessGroupOwnerPublicKey []byte, accessGroupKeyName []byte,
	accessGroupMembersList []*AccessGroupMember) {

	require := require.New(t)

	for _, member := range accessGroupMembersList {
		groupMembershipKey := NewGroupMembershipKey(*NewPublicKey(member.AccessGroupMemberPublicKey),
			*NewPublicKey(accessGroupOwnerPublicKey), *NewGroupKeyName(accessGroupKeyName))

		// If the group has already been fetched in this utxoView, then we get it directly from there.
		accessGroupMember, exists := utxoView.AccessGroupMembershipKeyToAccessGroupMember[*groupMembershipKey]

		switch operationType {
		case AccessGroupMemberOperationTypeAdd, AccessGroupMemberOperationTypeUpdate:
			require.Equal(true, exists)
			require.NotNil(accessGroupMember)
			require.Equal(false, accessGroupMember.isDeleted)
			require.Equal(true, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
		case AccessGroupMemberOperationTypeRemove:
			// OperationTypeRemove will have inverted validation for the UtxoView than add/updates since it deletes the entry.
			// TODO: do we want to also OR a case where accessGroupMember == nil? This would only be the case if we flushed.
			if !exists || accessGroupMember == nil || accessGroupMember.isDeleted {
				return
			}
			require.Equal(false, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
		}
	}
}

func _verifyDisconnectUtxoViewEntryForAccessGroupMembers(t *testing.T, utxoView *UtxoView, utxoOps []*UtxoOperation,
	operationType AccessGroupMemberOperationType, accessGroupOwnerPublicKey []byte, accessGroupKeyName []byte,
	accessGroupMembersList []*AccessGroupMember) {

	require := require.New(t)

	for ii, member := range accessGroupMembersList {
		groupMembershipKey := NewGroupMembershipKey(*NewPublicKey(member.AccessGroupMemberPublicKey),
			*NewPublicKey(accessGroupOwnerPublicKey), *NewGroupKeyName(accessGroupKeyName))

		// If the group has already been fetched in this utxoView, then we get it directly from there.
		accessGroupMember, exists := utxoView.AccessGroupMembershipKeyToAccessGroupMember[*groupMembershipKey]
		currentUtxoOp := utxoOps[len(utxoOps)-1]
		require.Equal(currentUtxoOp.Type, OperationTypeAccessGroupMembers)

		switch operationType {
		case AccessGroupMemberOperationTypeAdd, AccessGroupMemberOperationTypeUpdate:
			if !exists || accessGroupMember == nil || accessGroupMember.isDeleted {
				return
			}
			// It's possible that there is another testVector' that makes overlapping utxoEntries to this testVector.
			// If it was connected later, we just check that the current UtxoView accessGroupMember entry is different.
			require.Equal(false, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
		case AccessGroupMemberOperationTypeRemove:
			require.Equal(true, exists)
			require.NotNil(accessGroupMember)
			require.Equal(false, accessGroupMember.isDeleted)
			// Verify that the current entry in UtxoView correctly reflects the UtxoOperation.
			prevAccessGroupMemberEntry := currentUtxoOp.PrevAccessGroupMembersList[ii]
			previousAccessGroupMember := &AccessGroupMember{
				AccessGroupMemberPublicKey: prevAccessGroupMemberEntry.AccessGroupMemberPublicKey.ToBytes(),
				AccessGroupMemberKeyName:   prevAccessGroupMemberEntry.AccessGroupMemberKeyName.ToBytes(),
				EncryptedKey:               prevAccessGroupMemberEntry.EncryptedKey,
				ExtraData:                  prevAccessGroupMemberEntry.ExtraData,
			}
			require.Equal(true, _verifyEqualAccessGroupMember(t, accessGroupMember,
				previousAccessGroupMember))
		}
	}
}

func _verifyDbEntryForAccessGroupMembers(t *testing.T, dbAdapter *DbAdapter,
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
			require.Equal(true, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
			require.Equal(true, accessGroupEnumerationEntry)
		case AccessGroupMemberOperationTypeRemove:
			if accessGroupMember == nil && !accessGroupEnumerationEntry {
				return
			}
			require.Equal(false, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
			require.Equal(false, accessGroupEnumerationEntry)
		}
	}
}

func _verifyEqualAccessGroupMember(t *testing.T, accessGroupMemberEntry *AccessGroupMemberEntry,
	accessGroupMember *AccessGroupMember) bool {

	require := require.New(t)
	require.NotNil(accessGroupMemberEntry)
	require.NotNil(accessGroupMemberEntry.AccessGroupMemberPublicKey)
	require.NotNil(accessGroupMemberEntry.AccessGroupMemberKeyName)
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

func _verifyMembersList(tm *transactionTestMeta, utxoView *UtxoView, accessGroupOwnerPublicKey *PublicKey, accessGroupKeyName *GroupKeyName,
	expectedMembersList []*PublicKey) {

	// First, try fetching all the members with a single paginated call.
	require := require.New(tm.t)
	// Sort the expected members list to make sure there is no ordering issues.
	var expectedMembersCopy []*PublicKey
	for _, expectedMember := range expectedMembersList {
		expectedMemberCopy := *expectedMember
		expectedMembersCopy = append(expectedMembersCopy, &expectedMemberCopy)
	}
	sort.Slice(expectedMembersCopy, func(ii, jj int) bool {
		return bytes.Compare(expectedMembersCopy[ii].ToBytes(), expectedMembersCopy[jj].ToBytes()) < 0
	})
	_verify := func(accessGroupMembers []*PublicKey) {
		require.Equal(len(expectedMembersList), len(accessGroupMembers))
		for ii, expectedMember := range expectedMembersCopy {
			require.Equal(true, bytes.Equal(expectedMember.ToBytes(), accessGroupMembers[ii].ToBytes()))
		}
	}

	// Now, try fetching all the members with multiple paginated calls, one by one.
	loopWithPaginatedCalls := func(maxMembersToFetch int) {
		startKey := []byte{}
		accessGroupMembers := []*PublicKey{}
		for {
			accessGroupMembersPage, err := utxoView.GetPaginatedAccessGroupMembersEnumerationEntries(
				accessGroupOwnerPublicKey, accessGroupKeyName, startKey, uint32(maxMembersToFetch))
			// If the regular paginated fetch fails, try the paginated fetch with a higher recursion depth. Because
			// we use maxMembersToFetch = 1, in worst-case scenario, the recursion depth will be equal to the number
			// of members in the group. This isn't a bug, but rather a downside of using such small maxMembersToFetch,
			// and in practice we should use a higher values e.g. maxMembersToFetch=25.
			if err != nil {
				glog.Errorf(CLog(Red, "Problem fetching paginated access group members: %v. Re-trying with higher "+
					"recursion depth."), err)
				accessGroupMembersPage, _, err = utxoView._getPaginatedAccessGroupMembersEnumerationEntriesRecursionSafe(
					accessGroupOwnerPublicKey, accessGroupKeyName, startKey, uint32(maxMembersToFetch), 100, nil, true)
			}
			if len(accessGroupMembersPage) == 0 {
				break
			}
			require.Equal(true, len(accessGroupMembersPage) <= maxMembersToFetch)
			accessGroupMembers = append(accessGroupMembers, accessGroupMembersPage...)
			startKey = accessGroupMembersPage[len(accessGroupMembersPage)-1].ToBytes()
			if len(accessGroupMembersPage) < maxMembersToFetch {
				break
			}
		}
		_verify(accessGroupMembers)
	}

	// Check a couple of different maxMembersToFetch values to fetch all members.
	loopWithPaginatedCalls(1)
	loopWithPaginatedCalls(2)
	loopWithPaginatedCalls(3)
	loopWithPaginatedCalls(5)
	loopWithPaginatedCalls(10)
	loopWithPaginatedCalls(math.MaxUint32)
}

func _setAccessGroupParams(tm *transactionTestMeta) {
	tm.params.ForkHeights.ExtraDataOnEntriesBlockHeight = 0
	tm.params.ForkHeights.AssociationsAndAccessGroupsBlockHeight = 1
	tm.params.EncoderMigrationHeights = GetEncoderMigrationHeights(&tm.params.ForkHeights)
	tm.params.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&tm.params.ForkHeights)
	GlobalDeSoParams = *tm.params
}

func TestAccessGroupMemberTxnSpendingLimitToMetamaskString(t *testing.T) {
	toMetamaskString := func(
		scopeType AccessGroupScopeType,
		groupKeyName GroupKeyName,
		operationType AccessGroupMemberOperationType,
	) string {
		accessGroupMemberLimitKey := MakeAccessGroupMemberLimitKey(
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
			AccessGroupMemberMap: map[AccessGroupMemberLimitKey]uint64{
				accessGroupMemberLimitKey: 1,
			},
		}
		return txnSpendingLimit.ToMetamaskString(&GlobalDeSoParams)
	}

	// Scoped GroupKeyName + OperationType
	metamaskStr := toMetamaskString(
		AccessGroupScopeTypeScoped,
		*NewGroupKeyName([]byte("TestGroupKeyName")),
		AccessGroupMemberOperationTypeAdd,
	)
	require.Equal(t, metamaskStr,
		"Spending limits on the derived key:\n"+
			"	Total $DESO Limit: 1.0 $DESO\n"+
			"	Transaction Count Limit: \n"+
			"		AUTHORIZE_DERIVED_KEY: 1\n"+
			"	Access Group Member Restrictions:\n"+
			"		[\n"+
			"			Access Group Owner Public Key: "+m0Pub+"\n"+
			"			Access Group Key Name: TestGroupKeyName\n"+
			"			Access Group Member Operation Type: Add\n"+
			"			Transaction Count: 1\n"+
			"		]\n",
	)

	// Any GroupKeyName + OperationType
	metamaskStr = toMetamaskString(
		AccessGroupScopeTypeAny,
		*NewGroupKeyName([]byte{}),
		AccessGroupMemberOperationTypeAny,
	)
	require.Equal(t, metamaskStr,
		"Spending limits on the derived key:\n"+
			"	Total $DESO Limit: 1.0 $DESO\n"+
			"	Transaction Count Limit: \n"+
			"		AUTHORIZE_DERIVED_KEY: 1\n"+
			"	Access Group Member Restrictions:\n"+
			"		[\n"+
			"			Access Group Owner Public Key: "+m0Pub+"\n"+
			"			Access Group Key Name: Any\n"+
			"			Access Group Member Operation Type: Any\n"+
			"			Transaction Count: 1\n"+
			"		]\n",
	)
}

func TestAccessGroupMembersTxnWithDerivedKey(t *testing.T) {
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
	_submitAuthorizeDerivedKeyTxn := func(
		accessGroupLimitKey *AccessGroupLimitKey,
		accessGroupMemberLimitKey *AccessGroupMemberLimitKey,
		count int,
	) string {
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(t, err)

		txnSpendingLimit := &TransactionSpendingLimit{
			GlobalDESOLimit: NanosPerUnit, // 1 $DESO spending limit
			TransactionCountLimitMap: map[TxnType]uint64{
				TxnTypeAuthorizeDerivedKey: 1,
			},
		}
		if accessGroupLimitKey != nil {
			txnSpendingLimit.AccessGroupMap = map[AccessGroupLimitKey]uint64{
				*accessGroupLimitKey: uint64(count),
			}
		}
		if accessGroupMemberLimitKey != nil {
			txnSpendingLimit.AccessGroupMemberMap = map[AccessGroupMemberLimitKey]uint64{
				*accessGroupMemberLimitKey: uint64(count),
			}
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

	_createAccessGroupTxn := func(
		accessGroupKeyName string,
		operationType AccessGroupOperationType,
	) *MsgDeSoTxn {
		txn, _, _, _, err := testMeta.chain.CreateAccessGroupTxn(
			senderPkBytes,
			m0PkBytes,
			[]byte(accessGroupKeyName),
			operationType,
			make(map[string][]byte),
			testMeta.feeRateNanosPerKb,
			mempool,
			[]*DeSoOutput{},
		)
		require.NoError(t, err)
		return txn
	}

	_createAccessGroupMemberTxn := func(
		accessGroupKeyName string,
		operationType AccessGroupMemberOperationType,
	) *MsgDeSoTxn {
		txn, _, _, _, err := testMeta.chain.CreateAccessGroupMembersTxn(
			senderPkBytes,
			[]byte(accessGroupKeyName),
			[]*AccessGroupMember{
				{
					AccessGroupMemberPublicKey: m1PkBytes,
					AccessGroupMemberKeyName:   BaseGroupKeyName().ToBytes(),
					EncryptedKey:               []byte{1},
					ExtraData:                  make(map[string][]byte),
				},
			},
			operationType,
			make(map[string][]byte),
			testMeta.feeRateNanosPerKb,
			mempool,
			[]*DeSoOutput{},
		)
		require.NoError(t, err)
		return txn
	}

	_submitTxnWithDerivedKey := func(
		txn *MsgDeSoTxn,
		derivedKeyPrivBase58Check string,
	) error {
		// Get UTXO view.
		utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
		require.NoError(t, err)
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
	var txn *MsgDeSoTxn
	groupKeyName := "TestGroupKeyName"
	{
		// Create access group derived key for any GroupKeyName + OperationType
		accessGroupLimitKey := MakeAccessGroupLimitKey(
			*NewPublicKey(senderPkBytes),
			AccessGroupScopeTypeAny,
			*NewGroupKeyName([]byte{}),
			AccessGroupOperationTypeAny,
		)
		derivedKeyPriv := _submitAuthorizeDerivedKeyTxn(&accessGroupLimitKey, nil, 2)

		// Happy path: create access group for TestGroupKeyName
		txn = _createAccessGroupTxn(groupKeyName, AccessGroupOperationTypeCreate)
		err = _submitTxnWithDerivedKey(txn, derivedKeyPriv)
		require.NoError(t, err)

		// Happy path: create access group for TestGroupKeyName2
		txn = _createAccessGroupTxn(groupKeyName+"2", AccessGroupOperationTypeCreate)
		err = _submitTxnWithDerivedKey(txn, derivedKeyPriv)
		require.NoError(t, err)
	}
	{
		// Create access group members derived key for scoped GroupKeyName + OperationType.
		accessGroupMemberLimitKey := MakeAccessGroupMemberLimitKey(
			*NewPublicKey(senderPkBytes),
			AccessGroupScopeTypeScoped,
			*NewGroupKeyName([]byte(groupKeyName)),
			AccessGroupMemberOperationTypeAdd,
		)
		derivedKeyPriv := _submitAuthorizeDerivedKeyTxn(nil, &accessGroupMemberLimitKey, 1)

		// Sad path: try to add access group members with different group key name, unauthorized
		txn = _createAccessGroupMemberTxn(groupKeyName+"2", AccessGroupMemberOperationTypeAdd)
		err = _submitTxnWithDerivedKey(txn, derivedKeyPriv)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAccessGroupMemberSpendingLimitInvalid)

		// Sad path: try to update access group members, unauthorized
		txn = _createAccessGroupMemberTxn(groupKeyName, AccessGroupMemberOperationTypeUpdate)
		err = _submitTxnWithDerivedKey(txn, derivedKeyPriv)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAccessGroupMemberSpendingLimitInvalid)

		// Happy path: add authorized access group members
		txn = _createAccessGroupMemberTxn(groupKeyName, AccessGroupMemberOperationTypeAdd)
		err = _submitTxnWithDerivedKey(txn, derivedKeyPriv)
		require.NoError(t, err)
	}
	{
		// Create access group members derived key for any GroupKeyName + OperationType
		accessGroupMemberLimitKey := MakeAccessGroupMemberLimitKey(
			*NewPublicKey(senderPkBytes),
			AccessGroupScopeTypeAny,
			*NewGroupKeyName([]byte{}),
			AccessGroupMemberOperationTypeAny,
		)
		derivedKeyPriv := _submitAuthorizeDerivedKeyTxn(nil, &accessGroupMemberLimitKey, 2)

		// Happy path: update authorized access group members
		txn = _createAccessGroupMemberTxn(groupKeyName, AccessGroupMemberOperationTypeUpdate)
		err = _submitTxnWithDerivedKey(txn, derivedKeyPriv)
		require.NoError(t, err)

		// Happy path: add authorized access group members to different group
		txn = _createAccessGroupMemberTxn(groupKeyName+"2", AccessGroupMemberOperationTypeAdd)
		err = _submitTxnWithDerivedKey(txn, derivedKeyPriv)
		require.NoError(t, err)

		// Sad path: spending limit is exceeded, unauthorized
		txn = _createAccessGroupMemberTxn(groupKeyName+"2", AccessGroupMemberOperationTypeAdd)
		err = _submitTxnWithDerivedKey(txn, derivedKeyPriv)
		require.Error(t, err)
		require.Contains(t, err.Error(), RuleErrorAccessGroupMemberSpendingLimitInvalid)
	}
}
