package lib

import (
	"bytes"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"math"
	"sort"
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

	fundPublicKeysWithNanosMap := make(map[PublicKey]uint64)
	fundPublicKeysWithNanosMap[*m0PublicKey] = 200
	fundPublicKeysWithNanosMap[*m1PublicKey] = 200
	fundPublicKeysWithNanosMap[*m2PublicKey] = 200
	fundPublicKeysWithNanosMap[*m3PublicKey] = 200
	for _, publicKey := range randomMemberPublicKeys {
		fundPublicKeysWithNanosMap[*publicKey] = 50
	}
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
	groupName3 := []byte("group3")
	groupName4 := []byte("group4")

	// Access group (m0Pub, groupName1) with access public key groupPk1.
	tv1 := _createAccessGroupCreateTestVector("TEST 1: (PASS) Connect access group create transaction made by "+
		"(pk0, groupName1)", m0Priv, m0PubBytes, m0PubBytes, groupPk1, groupName1, nil,
		nil)
	tv2Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: groupName1, EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv2 := _createAccessGroupMembersTestVector("TEST 2: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk0, groupName1), re-adding yourself as member with (pk0, groupName1)", m0Priv, m0PubBytes,
		groupName1, tv2Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupMemberCantAddOwnerBySameGroup)
	tv3Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	// Membership:
	// (m0Pub, groupName1) ->
	//		(m0Pub, BaseGroupKeyName)
	tv3 := _createAccessGroupMembersTestVector("TEST 3: (PASS) Connect access group members transaction to the "+
		"access group made by (user0, groupName1), adding as member (pk0, baseGroup)", m0Priv, m0PubBytes,
		groupName1, tv3Members, AccessGroupMemberOperationTypeAdd, nil)
	tv3.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey})
	}
	tv3.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
	}
	tv4Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv4 := _createAccessGroupMembersTestVector("TEST 4: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk0, groupName1), again adding as member (pk0, baseGroup)", m0Priv, m0PubBytes, groupName1,
		tv4Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessMemberAlreadyExists)

	// Place the above transactions into a block.
	tvv1 := []*transactionTestVector{tv1, tv2, tv3, tv4}
	blockConnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey})
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
	tv5 := _createAccessGroupCreateTestVector("TEST 5: (PASS) Connect access group create transaction made by "+
		"(pk0, groupName2)", m0Priv, m0PubBytes, m0PubBytes, groupPk2, groupName2, nil, nil)
	tv6Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: groupName2, EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv6 := _createAccessGroupMembersTestVector("TEST 6: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk0, groupName1), again adding user 0 as member but by (pk0, groupName2)", m0Priv, m0PubBytes,
		groupName1, tv6Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessMemberAlreadyExists)
	tv7 := _createAccessGroupMembersTestVector("TEST 7: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk0, groupName1), with empty members list", m0Priv, m0PubBytes, groupName1,
		[]*AccessGroupMember{}, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupMembersListCannotBeEmpty)
	tv8Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName()[:], EncryptedKey: []byte{1}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName()[:], EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv8 := _createAccessGroupMembersTestVector("TEST 8: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk0, groupName1), adding as member (pk1, baseGroup) twice within same transaction",
		m0Priv, m0PubBytes, groupName1, tv8Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupMemberListDuplicateMember)

	// Membership:
	// (m0Pub, groupName1) ->
	//		(m0Pub, BaseGroupKeyName)
	//		(m1Pub, BaseGroupKeyName)
	// (m0Pub, groupName2) ->
	tv9Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName()[:], EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv9 := _createAccessGroupMembersTestVector("TEST 9: (PASS) Connect access group members transaction to the "+
		"access group made by (pk0, groupName1), adding as member (pk1, baseGroup)", m0Priv, m0PubBytes, groupName1,
		tv9Members, AccessGroupMemberOperationTypeAdd, nil)
	tv9.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey})
	}
	tv9.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey})
	}
	// A bunch of failing tests to try out different validation rule errors.
	tv10Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName()[:], EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv10 := _createAccessGroupMembersTestVector("TEST 10: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk0, baseGroup), adding as member (pk1, baseGroup)", m0Priv, m0PubBytes, BaseGroupKeyName().ToBytes(),
		tv10Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupsNameCannotBeZeros)
	tv11Members := tv10Members
	tv11 := _createAccessGroupMembersTestVector("TEST 11: (FAIL) Connect access group members transaction to the "+
		"non-existing access group (pk0, groupName3), adding as member (pk1, baseGroup)", m0Priv, m0PubBytes, groupName3,
		tv11Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupDoesntExist)
	tv12Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m2PubBytes, AccessGroupMemberKeyName: groupName1, EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv12 := _createAccessGroupMembersTestVector("TEST 12: (FAIL) Connect access group members transaction to the "+
		"access group made by (pk0, groupName1), adding as member (pk2, groupName1) by non-existing group", m0Priv, m0PubBytes, groupName1,
		tv12Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupDoesntExist)

	// Membership:
	// (m0Pub, groupName1) ->
	//		(m0Pub, BaseGroupKeyName)
	//		(m1Pub, BaseGroupKeyName)
	// (m0Pub, groupName2) ->
	// 		(m0Pub, groupName1)
	tv13Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: groupName1, EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv13 := _createAccessGroupMembersTestVector("TEST 13: (PASS) Connect access group members transaction to the "+
		"access group made by (pk0, groupName2), adding as member (pk0, groupName1)", m0Priv, m0PubBytes, groupName2,
		tv13Members, AccessGroupMemberOperationTypeAdd, nil)
	tv13.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName2), []*PublicKey{m0PublicKey})
	}
	tv13.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName2), []*PublicKey{})
	}
	// Create an access group (pk1, groupName3) and (pk2, groupName4)
	tv14 := _createAccessGroupCreateTestVector("TEST 14: (PASS) Connect access group transaction made by "+
		"(pk1, groupName3)", m1Priv, m1PubBytes, m1PubBytes, groupPk2, groupName3, nil, nil)
	tv15 := _createAccessGroupCreateTestVector("TEST 15: (PASS) Connect access group transaction made by "+
		"(pk2, groupName4)", m2Priv, m2PubBytes, m2PubBytes, groupPk2, groupName4, nil, nil)
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
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: groupName1, EncryptedKey: []byte{1}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: groupName3, EncryptedKey: []byte{1}, ExtraData: nil},
		{AccessGroupMemberPublicKey: m2PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName()[:], EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv16 := _createAccessGroupMembersTestVector("TEST 16: (PASS) Connect access group members transaction to the "+
		"access group made by (pk2, groupName4), adding as member (pk0, groupName1), (pk1, groupName3), and (pk2, baseGroup)",
		m2Priv, m2PubBytes, groupName4, tv16Members, AccessGroupMemberOperationTypeAdd, nil)
	tv16.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName3), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName4), []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey})
	}
	tv16.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName3), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName4), []*PublicKey{})
	}

	// Mine all the above transactions into a new block.
	tvv2 := []*transactionTestVector{tv5, tv6, tv7, tv8, tv9, tv10, tv11, tv12, tv13, tv14, tv15, tv16}
	block2ConnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey})
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName2), []*PublicKey{m0PublicKey})
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName3), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName4), []*PublicKey{m0PublicKey, m1PublicKey, m2PublicKey})
	}
	block2DisconnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey})
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName2), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName3), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName4), []*PublicKey{})
	}
	tvb2 := NewTransactionTestVectorBlock(tvv2, block2ConnectCallback, block2DisconnectCallback)

	// Add a bunch of random members to the access group (m2Pub, groupName4)
	randomGroupsTransactionVectors := []*transactionTestVector{}
	for ii := 0; ii < 50; ii++ {
		randomGroupsTransactionVectors = append(randomGroupsTransactionVectors, _createAccessGroupCreateTestVector(
			fmt.Sprintf("TEST %d: (PASS) Connect access group transaction made by (randomPk%d, groupName%d)",
				len(tvv1)+len(tvv2)+1+ii, ii, ii), randomMemberPrivateKeys[ii], randomMemberPublicKeys[ii].ToBytes(),
			randomMemberPublicKeys[ii].ToBytes(), groupPk1, randomMemberGroupKeys[ii].ToBytes(),
			nil, nil))
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
		m2Priv, m2PubBytes, groupName4, randomMembers, AccessGroupMemberOperationTypeAdd, nil)
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
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey})
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName2), []*PublicKey{m0PublicKey})
		_verifyMembersList(tm, utxoView, m1PublicKey, NewGroupKeyName(groupName3), []*PublicKey{})
		_verifyMembersList(tm, utxoView, m2PublicKey, NewGroupKeyName(groupName4), totalMembers)
	}
	block3DisconnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m0PublicKey, m1PublicKey})
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
	randomMemberCounter := 50
	randomMemberPrivateKeys := []string{}
	randomMemberPublicKeys := []*PublicKey{}
	for ii := 0; ii < randomMemberCounter; ii++ {
		privateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		privateKeyBase58Check := Base58CheckEncode(
			privateKey.Serialize(), true, &DeSoTestnetParams)
		randomMemberPrivateKeys = append(randomMemberPrivateKeys, privateKeyBase58Check)
		publicKeyBytes := privateKey.PubKey().SerializeCompressed()
		publicKey := NewPublicKey(publicKeyBytes)
		randomMemberPublicKeys = append(randomMemberPublicKeys, publicKey)
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
	fundPublicKeysWithNanosMap[*m0PublicKey] = 100
	fundPublicKeysWithNanosMap[*m1PublicKey] = 100
	fundPublicKeysWithNanosMap[*m2PublicKey] = 100
	fundPublicKeysWithNanosMap[*m3PublicKey] = 100

	initChainCallback := func(tm *transactionTestMeta) {
		tm.params.ForkHeights.ExtraDataOnEntriesBlockHeight = 0
		tm.params.ForkHeights.DeSoAccessGroupsBlockHeight = 0
		tm.params.EncoderMigrationHeights.DeSoUnlimitedDerivedKeys.Height = 0
		tm.params.EncoderMigrationHeights.DeSoAccessGroups.Height = 0
		GlobalDeSoParams.EncoderMigrationHeights.DeSoUnlimitedDerivedKeys.Height = 0
		GlobalDeSoParams.EncoderMigrationHeights.DeSoAccessGroups.Height = 0
		for ii := range GlobalDeSoParams.EncoderMigrationHeightsList {
			tm.params.EncoderMigrationHeightsList[ii].Height = 0
			GlobalDeSoParams.EncoderMigrationHeightsList[ii].Height = 0
		}
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
	tv1 := _createAccessGroupCreateTestVector("TEST 1: (PASS) Connect access group create transaction made by "+
		"(pk0, groupName1)", m0Priv, m0PubBytes, m0PubBytes, groupPk1, groupName1, nil,
		nil)
	tv2Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv2 := _createAccessGroupMembersTestVector("TEST 2: (PASS) Connect access group members add transaction made by "+
		"(pk0, groupName1) adding as member (pk1, baseGroup)", m0Priv, m0PubBytes, groupName1, tv2Members,
		AccessGroupMemberOperationTypeAdd, nil)
	tv2.connectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m1PublicKey})
	}
	tv2.disconnectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
	}

	tv3Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil},
	}
	tv3 := _createAccessGroupMembersTestVector("TEST 3: (FAIL) Connect access group members remove transaction made by "+
		"(pk0, groupName1) removing member (pk1, baseGroup) with non-empty encrypted key", m0Priv, m0PubBytes, groupName1, tv3Members,
		AccessGroupMemberOperationTypeRemove, RuleErrorAccessGroupMemberRemoveEncryptedKeyNotEmpty)
	tv4Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: nil, ExtraData: nil},
	}
	tv4 := _createAccessGroupMembersTestVector("TEST 4: (PASS) Connect access group members remove transaction made by "+
		"(pk0, groupName1) removing member (pk1, baseGroup)", m0Priv, m0PubBytes, groupName1, tv4Members,
		AccessGroupMemberOperationTypeRemove, nil)
	tv4.connectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{})
	}
	tv4.disconnectCallback = func(tvb *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyMembersList(tm, utxoView, m0PublicKey, NewGroupKeyName(groupName1), []*PublicKey{m1PublicKey})
	}

	//randomMembers := []*AccessGroupMember{}
	//for ii := 0; ii < 50; ii++ {
	//	extraDataMap := make(map[string][]byte)
	//	extraDataMap[fmt.Sprintf("randomField%v", ii)] = []byte(fmt.Sprintf("randomValue%v", ii))
	//	randomMembers = append(randomMembers, &AccessGroupMember{
	//		AccessGroupMemberPublicKey: randomMemberPublicKeys[ii].ToBytes(),
	//		AccessGroupMemberKeyName:   BaseGroupKeyName().ToBytes(),
	//		EncryptedKey:               []byte{1}, ExtraData: extraDataMap,
	//	})
	//}
	//tv2 := _createAccessGroupMembersTestVector("TEST 2: (PASS) Connect access group add members transaction made by "+
	//	"(pk0, groupName1), adding all random members", m0Priv, m0PubBytes, groupName1, randomMembers,
	//	AccessGroupMemberOperationTypeAdd, nil)

	tvv := []*transactionTestVector{tv1, tv2, tv3, tv4}
	tvb := []*transactionTestVectorBlock{{tvv, nil, nil}}
	tes := NewTransactionTestSuite(t, tvb, tConfig)
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
		10, mempool, []*DeSoOutput{})
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
			currentUtxoOp := utxoOps[len(utxoOps)-1]
			require.Equal(currentUtxoOp.Type, OperationTypeAccessGroupMembers)
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

	{
		accessGroupMembers, err := utxoView.GetPaginatedAccessGroupMembersEnumerationEntries(
			accessGroupOwnerPublicKey, accessGroupKeyName, []byte{}, math.MaxUint32)
		require.NoError(err)
		_verify(accessGroupMembers)
	}

	// Now, try fetching all the members with multiple paginated calls, one by one.
	{
		startKey := []byte{}
		accessGroupMembers := []*PublicKey{}
		for {
			accessGroupMembersPage, err := utxoView.GetPaginatedAccessGroupMembersEnumerationEntries(
				accessGroupOwnerPublicKey, accessGroupKeyName, startKey, 1)
			require.NoError(err)
			if len(accessGroupMembersPage) == 0 {
				break
			}
			require.Equal(1, len(accessGroupMembersPage))
			accessGroupMembers = append(accessGroupMembers, accessGroupMembersPage[0])
			startKey = accessGroupMembersPage[0].ToBytes()
		}
		_verify(accessGroupMembers)
	}

}
