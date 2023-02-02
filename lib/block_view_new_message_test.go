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

type NewMessageTestData struct {
	userPrivateKey       string
	userPublicKey        []byte
	expectedConnectError error
	extraData            map[string][]byte
	NewMessageMetadata
}

func (data *NewMessageTestData) IsDependency(other transactionTestInputSpace) bool {
	otherData := other.(*NewMessageTestData)

	switch otherData.NewMessageType {
	case NewMessageTypeDm:
		groupsData := make(map[AccessGroupId]struct{})
		dataSenderGroup := NewAccessGroupId(&data.SenderAccessGroupOwnerPublicKey, data.SenderAccessGroupKeyName.ToBytes())
		dataRecipientGroup := NewAccessGroupId(&data.RecipientAccessGroupOwnerPublicKey, data.RecipientAccessGroupKeyName.ToBytes())
		groupsData[*dataSenderGroup] = struct{}{}
		groupsData[*dataRecipientGroup] = struct{}{}

		otherSenderGroup := NewAccessGroupId(&otherData.SenderAccessGroupOwnerPublicKey, otherData.SenderAccessGroupKeyName.ToBytes())
		otherRecipientGroup := NewAccessGroupId(&otherData.RecipientAccessGroupOwnerPublicKey, otherData.RecipientAccessGroupKeyName.ToBytes())
		_, okOtherSender := groupsData[*otherSenderGroup]
		_, okOtherRecipient := groupsData[*otherRecipientGroup]
		return okOtherSender && okOtherRecipient
	case NewMessageTypeGroupChat:
		if bytes.Equal(data.RecipientAccessGroupOwnerPublicKey.ToBytes(), otherData.RecipientAccessGroupOwnerPublicKey.ToBytes()) &&
			bytes.Equal(data.RecipientAccessGroupKeyName.ToBytes(), otherData.RecipientAccessGroupKeyName.ToBytes()) {
			return true
		}
		return false
	}
	return false
}

func (data *NewMessageTestData) GetInputType() transactionTestInputType {
	return transactionTestInputTypeNewMessage
}

func TestNewMessage(t *testing.T) {
	require := require.New(t)
	_ = require

	const DmEnumerationMsgCount = 50
	const GroupChatEnumerationMsgCount = 50

	m0PubBytes, _, _ := Base58CheckDecode(m0Pub)
	m0PublicKey := NewPublicKey(m0PubBytes)
	m1PubBytes, _, _ := Base58CheckDecode(m1Pub)
	m1PublicKey := NewPublicKey(m1PubBytes)
	m2PubBytes, _, _ := Base58CheckDecode(m2Pub)
	m2PublicKey := NewPublicKey(m2PubBytes)
	m3PubBytes, _, _ := Base58CheckDecode(m3Pub)
	m3PublicKey := NewPublicKey(m3PubBytes)

	fundPublicKeysWithNanosMap := make(map[PublicKey]uint64)
	fundPublicKeysWithNanosMap[*m0PublicKey] = 1000
	fundPublicKeysWithNanosMap[*m1PublicKey] = 1000
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
	_ = groupPk1

	groupPriv2, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	groupPk2 := groupPriv2.PubKey().SerializeCompressed()
	_ = groupPk2

	groupPriv3, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	groupPk3 := groupPriv3.PubKey().SerializeCompressed()
	_ = groupPk3

	groupNameBytes1 := []byte("group1")
	groupName1 := NewGroupKeyName(groupNameBytes1)
	groupNameBytes2 := []byte("group2")
	groupName2 := NewGroupKeyName(groupNameBytes2)
	groupNameBytes3 := []byte("gang-gang")
	groupName3 := NewGroupKeyName(groupNameBytes3)
	_ = groupName3

	// -------------------------------------------------------------------------------------
	// Basic DM and Group Chat Validation Tests.
	// -------------------------------------------------------------------------------------
	tv1MessageEntry := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
		*m1PublicKey, *BaseGroupKeyName(), *m1PublicKey, []byte{1, 2, 3}, 1, nil)
	tv1 := _createNewMessageTestVector("TEST 1: (FAIL) Try connecting new message create transaction for a DM "+
		"sent from (m0, baseGroup) to (m1, baseGroup) before fork height", m0Priv, m0PubBytes,
		tv1MessageEntry, NewMessageTypeDm, NewMessageOperationCreate,
		RuleErrorNewMessageBeforeDeSoAccessGroups)
	tv1.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		tm.params.ForkHeights.AssociationsAndAccessGroupsBlockHeight = 1
	}
	// Send and update a dm message from (m0, baseGroup) to (m1, baseGroup)
	tv2MessageEntry := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
		*m1PublicKey, *BaseGroupKeyName(), *m1PublicKey, []byte{1, 2, 3}, 1, nil)
	tv2 := _createNewMessageTestVector("TEST 2: (PASS) Try connecting new message create transaction for a DM "+
		"sent from (m0, baseGroup) to (m1, baseGroup)", m0Priv, m0PubBytes,
		tv2MessageEntry, NewMessageTypeDm, NewMessageOperationCreate, nil)
	groupIdM0B := *NewAccessGroupId(m0PublicKey, BaseGroupKeyName().ToBytes())
	groupIdM1B := *NewAccessGroupId(m1PublicKey, BaseGroupKeyName().ToBytes())
	dmM0BM1B := _createDmThreadKey(groupIdM0B, groupIdM1B)
	dmThreads2M0 := []*DmThreadKey{&dmM0BM1B}
	dmThreads2M1 := []*DmThreadKey{&dmM0BM1B}
	tv2.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m0PublicKey, dmThreads2M0)
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m1PublicKey, dmThreads2M1)
		_verifyDmMessageEntries(t, utxoView, dmM0BM1B, []*NewMessageEntry{tv2MessageEntry})
	}
	tv2.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m0PublicKey, []*DmThreadKey{})
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m1PublicKey, []*DmThreadKey{})
		_verifyDmMessageEntries(t, utxoView, dmM0BM1B, []*NewMessageEntry{})
	}

	updatedDmMessage := []byte("updated dm message")
	updatedDmExtraData := map[string][]byte{
		"some random value": []byte("even more random value"),
	}
	tv3MessageEntry := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
		*m1PublicKey, *BaseGroupKeyName(), *m1PublicKey, updatedDmMessage, 1, updatedDmExtraData)
	tv3 := _createNewMessageTestVector("TEST 3: (PASS) Try connecting new message update transaction for a DM "+
		"sent from (m0, baseGroup) to (m1, baseGroup)", m0Priv, m0PubBytes,
		tv3MessageEntry, NewMessageTypeDm, NewMessageOperationUpdate, nil)
	dmThreads3M0 := dmThreads2M0
	dmThreads3M1 := dmThreads2M1
	tv3.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m0PublicKey, dmThreads3M0)
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m1PublicKey, dmThreads3M1)
		_verifyDmMessageEntries(t, utxoView, dmM0BM1B, []*NewMessageEntry{tv3MessageEntry})
	}
	tv3.disconnectCallback = tv2.connectCallback

	// Create access group (m1, groupName1) and add m0 to it.
	// We will then attempt sending some group chat messages.
	// Membership:
	// (m1, groupName1) ->
	// 		(m0, baseGroup)
	tv4 := _createAccessGroupTestVector("TEST 4: (PASS) Try connecting an access group create transaction for "+
		"group (m1, groupName1)", m1Priv, m1PubBytes, m1PubBytes, groupPk1, groupNameBytes1, AccessGroupOperationTypeCreate,
		nil, nil)
	groupIdM1N1 := *NewAccessGroupId(m1PublicKey, groupName1.ToBytes())
	groupChatThreads4 := []*AccessGroupId{&groupIdM1N1}
	tv4.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, []*AccessGroupId{}) // Not added to group yet
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, groupChatThreads4)
		_verifyGroupMessageEntries(t, utxoView, groupIdM1N1, []*NewMessageEntry{})
	}
	tv4.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, []*AccessGroupId{})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, []*AccessGroupId{})
		_verifyGroupMessageEntries(t, utxoView, groupIdM1N1, []*NewMessageEntry{})
	}
	tv5Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{5, 6, 7}, ExtraData: nil},
	}
	tv5 := _createAccessGroupMembersTestVector("TEST 5: (PASS) Try connecting an access group members add transaction made by "+
		"(m1, groupName1) to add (m1, groupName1) as member", m1Priv, m1PubBytes, groupNameBytes1, tv5Members,
		AccessGroupMemberOperationTypeAdd, nil)
	tv5.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, groupChatThreads4)
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, groupChatThreads4)
		_verifyGroupMessageEntries(t, utxoView, groupIdM1N1, []*NewMessageEntry{})
	}
	tv5.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, []*AccessGroupId{}) // Not added to group yet
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, groupChatThreads4)
		_verifyGroupMessageEntries(t, utxoView, groupIdM1N1, []*NewMessageEntry{})
	}
	// Send and update a group chat message from (m0, baseGroup) to (m1, groupName1)
	tv6MessageEntry := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
		*m1PublicKey, *groupName1, *m1PublicKey, []byte{4, 5, 6}, 2, nil)
	tv6 := _createNewMessageTestVector("TEST 6: (PASS) Try connecting new message create transaction for a group chat "+
		"sent from (m0, baseGroup) to (m1, groupName1)", m0Priv, m0PubBytes,
		tv6MessageEntry, NewMessageTypeGroupChat, NewMessageOperationCreate, nil)
	tv6.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, groupChatThreads4)
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, groupChatThreads4)
		_verifyGroupMessageEntries(t, utxoView, groupIdM1N1, []*NewMessageEntry{tv6MessageEntry})
	}
	tv6.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, groupChatThreads4)
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, groupChatThreads4)
		_verifyGroupMessageEntries(t, utxoView, groupIdM1N1, []*NewMessageEntry{})
	}
	updateGroupMessage := []byte("updated group message")
	updateGroupExtraData := map[string][]byte{
		"some random group value": []byte("we are what we repeatedly do. Excellence, then, is not an act but a habit " +
			"- Aristotle & Durant"),
	}
	tv7MessageEntry := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
		*m1PublicKey, *groupName1, *m1PublicKey, updateGroupMessage, 2, updateGroupExtraData)
	tv7 := _createNewMessageTestVector("TEST 7: (PASS) Try connecting new message update transaction for a group chat "+
		"sent from (m0, baseGroup) to (m1, groupName1)", m0Priv, m0PubBytes,
		tv7MessageEntry, NewMessageTypeGroupChat, NewMessageOperationUpdate, nil)
	tv7.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, groupChatThreads4)
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, groupChatThreads4)
		_verifyGroupMessageEntries(t, utxoView, groupIdM1N1, []*NewMessageEntry{tv7MessageEntry})
	}
	tv7.disconnectCallback = tv6.connectCallback

	// Add the above transactions to a block.
	tvv1 := []*transactionTestVector{tv1, tv2, tv3, tv4, tv5, tv6, tv7}
	tvb1DisconnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		tm.params.ForkHeights.AssociationsAndAccessGroupsBlockHeight = 100
	}
	tvb1 := NewTransactionTestVectorBlock(tvv1, nil, tvb1DisconnectCallback)

	// -------------------------------------------------------------------------------------
	// Some Failing DM and Group Chat Tests.
	// -------------------------------------------------------------------------------------
	tv8MessageEntry := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
		*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey, []byte{1, 2, 3}, 5, nil)
	tv8 := _createNewMessageTestVector("TEST 8: (FAIL) Try connecting new message create transaction sent to "+
		"yourself from (m0, baseGroup) to (m0, baseGroup)", m0Priv, m0PubBytes, tv8MessageEntry, NewMessageTypeDm,
		NewMessageOperationCreate, RuleErrorNewMessageDmSenderAndRecipientCannotBeTheSame)
	tv9MessageEntry := _createMessageEntry(*m1PublicKey, *BaseGroupKeyName(), *m1PublicKey,
		*m1PublicKey, *BaseGroupKeyName(), *m1PublicKey, []byte{1, 2, 3}, 6, nil)
	tv9 := _createNewMessageTestVector("TEST 9: (FAIL) Try connecting new message create transaction sent to "+
		"another user from (m1, baseGroup) to (m1, groupName1)", m1Priv, m1PubBytes, tv9MessageEntry, NewMessageTypeDm,
		NewMessageOperationCreate, RuleErrorNewMessageDmSenderAndRecipientCannotBeTheSame)
	tooLongMessage := []byte{}
	for ii := 0; ii < int(DeSoTestnetParams.MaxNewMessageLengthBytes)+10; ii++ {
		tooLongMessage = append(tooLongMessage, byte(10))
	}
	tv10MessageEntry := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
		*m1PublicKey, *BaseGroupKeyName(), *m1PublicKey, tooLongMessage, 7, nil)
	tv10 := _createNewMessageTestVector("TEST 10: (FAIL) Try connecting new message dm create transaction with a too long "+
		"message sent by (m0, baseGroup) to (m1, baseGroup)", m0Priv, m0PubBytes,
		tv10MessageEntry, NewMessageTypeDm, NewMessageOperationCreate, RuleErrorNewMessageEncryptedTextLengthExceedsMax)
	tv11MessageEntry := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
		*m1PublicKey, *groupName1, *m1PublicKey, tooLongMessage, 8, nil)
	tv11 := _createNewMessageTestVector("TEST 11: (FAIL) Try connecting new message group chat create transaction with a too long "+
		"message sent by (m0, baseGroup) to (m1, groupName1)", m0Priv, m0PubBytes,
		tv11MessageEntry, NewMessageTypeGroupChat, NewMessageOperationCreate, RuleErrorNewMessageEncryptedTextLengthExceedsMax)
	tv12MessageEntry := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
		*m1PublicKey, *groupName1, *m1PublicKey, []byte{1, 2, 3}, 0, nil)
	tv12 := _createNewMessageTestVector("TEST 12: (FAIL) Try connecting new message dm create transaction with a "+
		"timestamp of 0 sent by (m0, baseGroup) to (m1, groupName1)", m0Priv, m0PubBytes,
		tv12MessageEntry, NewMessageTypeDm, NewMessageOperationCreate, RuleErrorNewMessageTimestampNanosCannotBeZero)
	tv12p2MessageEntry := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
		*m3PublicKey, *groupName3, *m3PublicKey, []byte{1, 2, 3}, 5, nil)
	tv12p2 := _createNewMessageTestVector("TEST 12.2: (FAIL) Try connecting new message dm create transaction sent from"+
		" (m0, baseGroup) to a non-existent group (m3, groupName3)", m0Priv, m0PubBytes, tv12p2MessageEntry,
		NewMessageTypeDm, NewMessageOperationCreate, fmt.Errorf("ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView"))
	tv12p4MessageEntry := tv12p2MessageEntry
	tv12p4 := _createNewMessageTestVector("TEST 12.4: (FAIL) Try connecting new message dm create transaction sent from"+
		" (m0, baseGroup) to a non-existent group (m3, groupName3)", m0Priv, m0PubBytes, tv12p4MessageEntry,
		NewMessageTypeGroupChat, NewMessageOperationCreate, fmt.Errorf("ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView"))
	tv12p6MessageEntry := _createMessageEntry(*m3PublicKey, *groupName3, *m3PublicKey,
		*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey, []byte{1, 2, 3}, 5, nil)
	tv12p6 := _createNewMessageTestVector("TEST 12.6: (FAIL) Try connecting new message dm create transaction sent from"+
		" non-existent group (m3, groupName3) to (m0, baseGroup)", m3Priv, m3PubBytes, tv12p6MessageEntry,
		NewMessageTypeDm, NewMessageOperationCreate, fmt.Errorf("ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView"))
	tv12p8MessageEntry := tv12p6MessageEntry
	tv12p8 := _createNewMessageTestVector("TEST 12.8: (FAIL) Try connecting new message group chat create transaction sent from"+
		" non-existent group (m3, groupName3) to (m0, baseGroup)", m3Priv, m3PubBytes, tv12p8MessageEntry,
		NewMessageTypeGroupChat, NewMessageOperationCreate, fmt.Errorf("ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView"))

	tvv2 := []*transactionTestVector{tv8, tv9, tv10, tv11, tv12, tv12p2, tv12p4, tv12p6, tv12p8}
	tvb2 := NewTransactionTestVectorBlock(tvv2, nil, nil)

	// -------------------------------------------------------------------------------------
	// More DM and Group Chat Tests.
	// -------------------------------------------------------------------------------------
	tv13Timestamp := uint64(10)
	tv13MessageEntry := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
		*m2PublicKey, *BaseGroupKeyName(), *m2PublicKey, []byte{1, 2, 3}, tv13Timestamp, nil)
	tv13 := _createNewMessageTestVector("TEST 13: (PASS) Try connecting new message dm create transaction with a "+
		"timestamp of 10 sent by (m0, baseGroup) to (m2, baseGroup)", m0Priv, m0PubBytes,
		tv13MessageEntry, NewMessageTypeDm, NewMessageOperationCreate, nil)
	groupIdM2B := *NewAccessGroupId(m2PublicKey, BaseGroupKeyName().ToBytes())
	dmM0BM2B := _createDmThreadKey(groupIdM0B, groupIdM2B)
	dmThreads13M0 := append(dmThreads3M0, &dmM0BM2B)
	dmThreads13M2 := []*DmThreadKey{&dmM0BM2B}
	tv13.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m0PublicKey, dmThreads13M0)
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m2PublicKey, dmThreads13M2)
		_verifyDmMessageEntries(t, utxoView, dmM0BM2B, []*NewMessageEntry{tv13MessageEntry})
	}
	tv14MessageEntry := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
		*m2PublicKey, *BaseGroupKeyName(), *m2PublicKey, []byte{4, 5, 6}, tv13Timestamp, nil)
	tv14 := _createNewMessageTestVector("TEST 14: (FAIL) Try connecting new message dm create transaction with a "+
		"duplicated timestamp sent by (m0, baseGroup) to (m2, baseGroup)", m0Priv, m0PubBytes,
		tv14MessageEntry, NewMessageTypeDm, NewMessageOperationCreate, RuleErrorNewMessageDmMessageAlreadyExists)
	tv15Timestamp := uint64(11)
	tv15MessageEntry := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
		*m1PublicKey, *groupName1, *m1PublicKey, []byte{7, 8, 9}, tv15Timestamp, nil)
	tv15 := _createNewMessageTestVector("TEST 15: (PASS) Try connecting new message group chat create transaction with a "+
		"timestamp of 11 sent by (m0, baseGroup) to (m1, groupName1)", m0Priv, m0PubBytes,
		tv15MessageEntry, NewMessageTypeGroupChat, NewMessageOperationCreate, nil)
	groupChatThread15 := groupChatThreads4
	messages15GroupM1N1 := append([]*NewMessageEntry{tv7MessageEntry}, tv15MessageEntry)
	tv15.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, groupChatThread15)
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, groupChatThread15)
		_verifyGroupMessageEntries(t, utxoView, groupIdM1N1, messages15GroupM1N1)
	}
	tv15.disconnectCallback = tv7.connectCallback
	tv16MessageEntry := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
		*m1PublicKey, *groupName1, *m1PublicKey, []byte{10, 11, 12}, tv15Timestamp, nil)
	tv16 := _createNewMessageTestVector("TEST 16: (FAIL) Try connecting new message group chat create transaction with a "+
		"duplicated timestamp sent by (m0, baseGroup) to (m1, groupName1)", m0Priv, m0PubBytes,
		tv16MessageEntry, NewMessageTypeGroupChat, NewMessageOperationCreate, RuleErrorNewMessageGroupChatMessageAlreadyExists)
	// Create access group (m2, groupName2).
	// Membership:
	// (m1, groupName1) ->
	// 		(m0, baseGroup)
	// (m2, groupName2) ->
	tv17 := _createAccessGroupTestVector("TEST 17: (PASS) Try connecting an access group create transaction for "+
		"group (m2, groupName2)", m2Priv, m2PubBytes, m2PubBytes, groupPk2, groupNameBytes2, AccessGroupOperationTypeCreate,
		nil, nil)
	tv18MessageEntry := _createMessageEntry(*m2PublicKey, *groupName2, *m2PublicKey,
		*m2PublicKey, *groupName2, *m2PublicKey, []byte{13, 14, 15}, 15, nil)
	tv18 := _createNewMessageTestVector("TEST 18: (PASS) Try connecting new message group chat create transaction "+
		"sent to itself from (m2, groupName2) to (m2, groupName2)", m2Priv, m2PubBytes,
		tv18MessageEntry, NewMessageTypeGroupChat, NewMessageOperationCreate, nil)
	groupIdM2N2 := *NewAccessGroupId(m2PublicKey, groupName2.ToBytes())
	tv18.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m2PublicKey, []*AccessGroupId{&groupIdM2N2})
		_verifyGroupMessageEntries(t, utxoView, groupIdM2N2, []*NewMessageEntry{tv18MessageEntry})
	}
	tv19MessageEntry := _createMessageEntry(*m2PublicKey, *BaseGroupKeyName(), *m2PublicKey,
		*m2PublicKey, *groupName2, *m2PublicKey, []byte{16, 17, 18}, 16, nil)
	tv19 := _createNewMessageTestVector("TEST 19: (PASS) Try connecting new message group chat create transaction "+
		"sent to itself from (m2, baseGroup) to (m2, groupName2)", m2Priv, m2PubBytes,
		tv19MessageEntry, NewMessageTypeGroupChat, NewMessageOperationCreate, nil)
	tv19.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m2PublicKey, []*AccessGroupId{&groupIdM2N2})
		_verifyGroupMessageEntries(t, utxoView, groupIdM2N2, []*NewMessageEntry{tv18MessageEntry, tv19MessageEntry})
	}
	// -------------------------------------------------------------------------------------
	// Verify Group Chat With Encryption/Decryption aka. Gang-Gang test.
	// -------------------------------------------------------------------------------------
	// Create access groups (m0, defaultKey) and (m3, defaultKey).
	// Membership:
	// (m1, groupName1) ->
	// 		(m0, baseGroup)
	// (m2, groupName2) ->
	// (m0, defaultKey) ->
	// (m1, defaultKey) ->
	// (m3, defaultKey) ->
	m0DefaultKeyPriv, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	m0DefaultKeyPk := NewPublicKey(m0DefaultKeyPriv.PubKey().SerializeCompressed())
	m1DefaultKeyPriv, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	m1DefaultKeyPk := NewPublicKey(m1DefaultKeyPriv.PubKey().SerializeCompressed())
	m3DefaultKeyPriv, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	m3DefaultKeyPk := NewPublicKey(m3DefaultKeyPriv.PubKey().SerializeCompressed())

	tv20 := _createAccessGroupTestVector("TEST 20: (PASS) Try connecting an access group create transaction for "+
		"group (m0, defaultKey)", m0Priv, m0PubBytes, m0PubBytes, m0DefaultKeyPk.ToBytes(), DefaultGroupKeyName().ToBytes(), AccessGroupOperationTypeCreate,
		nil, nil)
	tv20p5 := _createAccessGroupTestVector("TEST 20.5: (PASS) Try connecting an access group create transaction for "+
		"group (m1, defaultKey)", m1Priv, m1PubBytes, m1PubBytes, m1DefaultKeyPk.ToBytes(), DefaultGroupKeyName().ToBytes(), AccessGroupOperationTypeCreate,
		nil, nil)
	tv21 := _createAccessGroupTestVector("TEST 21: (PASS) Try connecting an access group create transaction for "+
		"group (m3, defaultKey)", m3Priv, m3PubBytes, m3PubBytes, m3DefaultKeyPk.ToBytes(), DefaultGroupKeyName().ToBytes(), AccessGroupOperationTypeCreate,
		nil, nil)

	// Create access group (m3, groupName3) and add members (m3, defaultKey), (m0, defaultKey).
	// Membership:
	// (m1, groupName1) ->
	// 		(m0, baseGroup)
	// (m2, groupName2) ->
	// (m0, defaultKey) ->
	// (m3, defaultKey) ->
	// (m3, groupName3) ->
	//      (m3, defaultKey)
	// 		(m0, defaultKey)
	groupName3SharedPriv, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	groupName3SharedPk := NewPublicKey(groupName3SharedPriv.PubKey().SerializeCompressed())
	groupName3SharedPk_EncryptedTo_m0DefaultPk := _encryptBytes(groupName3SharedPriv.Serialize(), *m0DefaultKeyPk)
	groupName3SharedPk_EncryptedTo_m1DefaultPk := _encryptBytes(groupName3SharedPriv.Serialize(), *m1DefaultKeyPk)
	groupName3SharedPk_EncryptedTo_m3DefaultPk := _encryptBytes(groupName3SharedPriv.Serialize(), *m3DefaultKeyPk)

	tv22 := _createAccessGroupTestVector("TEST 22: (PASS) Try connecting an access group create transaction for "+
		"group (m3, groupName3)", m3Priv, m3PubBytes, m3PubBytes, groupName3SharedPk.ToBytes(), groupNameBytes3, AccessGroupOperationTypeCreate,
		nil, nil)
	groupIdM3N3 := *NewAccessGroupId(m3PublicKey, groupName3.ToBytes())
	groupIdM3DefaultKey := *NewAccessGroupId(m3PublicKey, DefaultGroupKeyName().ToBytes())
	groupIdM0DefaultKey := *NewAccessGroupId(m0PublicKey, DefaultGroupKeyName().ToBytes())
	groupIdM1DefaultKey := *NewAccessGroupId(m1PublicKey, DefaultGroupKeyName().ToBytes())
	tv23Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m3PublicKey.ToBytes(), AccessGroupMemberKeyName: DefaultGroupKeyName().ToBytes(),
			EncryptedKey: groupName3SharedPk_EncryptedTo_m3DefaultPk, ExtraData: nil},
		{AccessGroupMemberPublicKey: m0PublicKey.ToBytes(), AccessGroupMemberKeyName: DefaultGroupKeyName().ToBytes(),
			EncryptedKey: groupName3SharedPk_EncryptedTo_m0DefaultPk, ExtraData: nil},
	}
	tv23 := _createAccessGroupMembersTestVector("TEST 23: (PASS) Try connecting an access group members transaction for "+
		"group (m3, groupName3) adding (m3, defaultKey) and (m0, defaultKey)", m3Priv, m3PubBytes, groupName3.ToBytes(),
		tv23Members, AccessGroupMemberOperationTypeAdd, nil)
	tv23.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m3PublicKey, []*AccessGroupId{&groupIdM3DefaultKey, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, []*AccessGroupId{&groupIdM0DefaultKey, &groupIdM1N1, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, []*AccessGroupId{&groupIdM1DefaultKey, &groupIdM1N1})
		_verifyGroupMessageEntries(t, utxoView, groupIdM3N3, []*NewMessageEntry{})
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m0PublicKey, m0DefaultKeyPriv.Serialize(), [][]byte{})
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m3PublicKey, m3DefaultKeyPriv.Serialize(), [][]byte{})
	}
	tv23.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		// The groupIdM3N3 is there before-hand because m3 is the owner of the group.
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m3PublicKey, []*AccessGroupId{&groupIdM3DefaultKey, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, []*AccessGroupId{&groupIdM0DefaultKey, &groupIdM1N1})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, []*AccessGroupId{&groupIdM1DefaultKey, &groupIdM1N1})
		_verifyGroupMessageEntries(t, utxoView, groupIdM3N3, []*NewMessageEntry{})
	}

	// We will send a couple messages to the group (m3, groupName3) and verify that everyone can decrypt them.
	// Messages
	// (m3, groupName3) ->
	// 		(m3, defaultKey | m3, groupName3 | {"hello world", 17})
	// 		(m0, defaultKey | m3, groupName3 | {"hello world too", 15})
	//      (m0, defaultKey | m3, groupName3 | {"hello world three", 20})
	plainText1 := []byte("hello world")
	plainText2 := []byte("hello world too")
	plainText3 := []byte("hello world three")
	groupName3Message1 := _encryptBytes(plainText1, *groupName3SharedPk)
	groupName3Message2 := _encryptBytes(plainText2, *groupName3SharedPk)
	groupName3Message3 := _encryptBytes(plainText3, *groupName3SharedPk)
	tv24MessageEntry := _createMessageEntry(*m3PublicKey, *DefaultGroupKeyName(), *m3DefaultKeyPk,
		*m3PublicKey, *groupName3, *groupName3SharedPk, groupName3Message1, 17, nil)
	tv25MessageEntry := _createMessageEntry(*m0PublicKey, *DefaultGroupKeyName(), *m0DefaultKeyPk,
		*m3PublicKey, *groupName3, *groupName3SharedPk, groupName3Message2, 15, nil)
	tv26MessageEntry := _createMessageEntry(*m0PublicKey, *DefaultGroupKeyName(), *m0DefaultKeyPk,
		*m3PublicKey, *groupName3, *groupName3SharedPk, groupName3Message3, 20, nil)
	tv24 := _createNewMessageTestVector("TEST 24: (PASS) Try connecting a message transaction for "+
		"group (m3, groupName3)", m3Priv, m3PubBytes, tv24MessageEntry,
		NewMessageTypeGroupChat, NewMessageOperationCreate, nil)
	messages24GroupM3N3 := []*NewMessageEntry{tv24MessageEntry}
	plainTexts24GroupM3N3 := [][]byte{plainText1}
	tv24.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		// Nothing should change with the threads.
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m3PublicKey, []*AccessGroupId{&groupIdM3DefaultKey, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, []*AccessGroupId{&groupIdM0DefaultKey, &groupIdM1N1, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, []*AccessGroupId{&groupIdM1DefaultKey, &groupIdM1N1})

		_verifyGroupMessageEntries(t, utxoView, groupIdM3N3, messages24GroupM3N3)
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m0PublicKey, m0DefaultKeyPriv.Serialize(), plainTexts24GroupM3N3)
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m3PublicKey, m3DefaultKeyPriv.Serialize(), plainTexts24GroupM3N3)
	}
	tv24.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		// Nothing should change with the threads.
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m3PublicKey, []*AccessGroupId{&groupIdM3DefaultKey, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, []*AccessGroupId{&groupIdM0DefaultKey, &groupIdM1N1, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, []*AccessGroupId{&groupIdM1DefaultKey, &groupIdM1N1})

		_verifyGroupMessageEntries(t, utxoView, groupIdM3N3, []*NewMessageEntry{})
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m0PublicKey, m0DefaultKeyPriv.Serialize(), [][]byte{})
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m3PublicKey, m3DefaultKeyPriv.Serialize(), [][]byte{})
	}
	messages25GroupM3N3 := []*NewMessageEntry{tv24MessageEntry, tv25MessageEntry}
	plainTexts25GroupM3N3 := [][]byte{plainText1, plainText2}
	tv25 := _createNewMessageTestVector("TEST 25: (PASS) Try connecting a message transaction for "+
		"group (m3, groupName3)", m0Priv, m0PubBytes, tv25MessageEntry,
		NewMessageTypeGroupChat, NewMessageOperationCreate, nil)
	tv25.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		// Nothing should change with the threads.
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m3PublicKey, []*AccessGroupId{&groupIdM3DefaultKey, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, []*AccessGroupId{&groupIdM0DefaultKey, &groupIdM1N1, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, []*AccessGroupId{&groupIdM1DefaultKey, &groupIdM1N1})

		_verifyGroupMessageEntries(t, utxoView, groupIdM3N3, messages25GroupM3N3)
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m0PublicKey, m0DefaultKeyPriv.Serialize(), plainTexts25GroupM3N3)
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m3PublicKey, m3DefaultKeyPriv.Serialize(), plainTexts25GroupM3N3)
	}
	tv25.disconnectCallback = tv24.connectCallback
	messages26GroupM3N3 := []*NewMessageEntry{tv24MessageEntry, tv25MessageEntry, tv26MessageEntry}
	plainTexts26GroupM3N3 := [][]byte{plainText3, plainText1, plainText2}
	tv26 := _createNewMessageTestVector("TEST 26: (PASS) Try connecting a message transaction for "+
		"group (m3, groupName3)", m0Priv, m0PubBytes, tv26MessageEntry,
		NewMessageTypeGroupChat, NewMessageOperationCreate, nil)
	tv26.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		// Nothing should change with the threads.
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m3PublicKey, []*AccessGroupId{&groupIdM3DefaultKey, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, []*AccessGroupId{&groupIdM0DefaultKey, &groupIdM1N1, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, []*AccessGroupId{&groupIdM1DefaultKey, &groupIdM1N1})

		_verifyGroupMessageEntries(t, utxoView, groupIdM3N3, messages26GroupM3N3)
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m0PublicKey, m0DefaultKeyPriv.Serialize(), plainTexts26GroupM3N3)
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m3PublicKey, m3DefaultKeyPriv.Serialize(), plainTexts26GroupM3N3)
	}
	tv26.disconnectCallback = tv25.connectCallback

	// Now let's try sending a message from non-existing member (m1, defaultKey) to (m3, groupName3).
	plainText4 := []byte("Hello world four")
	groupName3Message4 := _encryptBytes(plainText4, *groupName3SharedPk)
	tv27MessageEntry := _createMessageEntry(*m1PublicKey, *DefaultGroupKeyName(), *m1DefaultKeyPk,
		*m3PublicKey, *groupName3, *groupName3SharedPk, groupName3Message4, 25, nil)
	tv27 := _createNewMessageTestVector("TEST 27: (FAIL) Try connecting new message group chat create transaction "+
		"sent from non-member (m1, defaultKey) to (m2, groupName2)", m1Priv, m1PubBytes,
		tv27MessageEntry, NewMessageTypeGroupChat, NewMessageOperationCreate, RuleErrorNewMessageGroupChatMemberEntryDoesntExist)

	// We will add (m1, defaultKey) to the group (m3, groupName3) and try sending the message again. It should pass.
	// Membership:
	// (m1, groupName1) ->
	// 		(m0, baseGroup)
	// (m2, groupName2) ->
	// (m0, defaultKey) ->
	// (m3, defaultKey) ->
	// (m3, groupName3) ->
	//      (m3, defaultKey)
	// 		(m0, defaultKey)
	//      (m1, defaultKey)
	//
	// Messages:
	// (m3, groupName3) ->
	// 		(m3, defaultKey | m3, groupName3 | {"hello world", 17})
	// 		(m0, defaultKey | m3, groupName3 | {"hello world too", 15})
	//      (m0, defaultKey | m3, groupName3 | {"hello world three", 20})
	// 		(m1, defaultKey | m3, groupName3 | {"hello world four", 25})
	tv28Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m1PublicKey.ToBytes(), AccessGroupMemberKeyName: DefaultGroupKeyName().ToBytes(),
			EncryptedKey: groupName3SharedPk_EncryptedTo_m1DefaultPk, ExtraData: nil},
	}
	tv28 := _createAccessGroupMembersTestVector("TEST 28: (PASS) Try connecting an access group members transaction for "+
		"group (m3, groupName3) adding (m1, defaultKey)", m3Priv, m3PubBytes, groupName3.ToBytes(),
		tv28Members, AccessGroupMemberOperationTypeAdd, nil)
	tv28.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		// Nothing should change with the threads.
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m3PublicKey, []*AccessGroupId{&groupIdM3DefaultKey, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, []*AccessGroupId{&groupIdM0DefaultKey, &groupIdM1N1, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, []*AccessGroupId{&groupIdM1DefaultKey, &groupIdM1N1, &groupIdM3N3})

		_verifyGroupMessageEntries(t, utxoView, groupIdM3N3, messages26GroupM3N3)
		// Make sure m1pub can now also decrypt messages.
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m0PublicKey, m0DefaultKeyPriv.Serialize(), plainTexts26GroupM3N3)
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m3PublicKey, m3DefaultKeyPriv.Serialize(), plainTexts26GroupM3N3)
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m1PublicKey, m1DefaultKeyPriv.Serialize(), plainTexts26GroupM3N3)
	}
	tv29 := _createNewMessageTestVector("TEST 29: (PASS) Try connecting new message group chat create transaction "+
		"sent from (m1, defaultKey) to (m3, groupName3)", m1Priv, m1PubBytes,
		tv27MessageEntry, NewMessageTypeGroupChat, NewMessageOperationCreate, nil)
	messages29GroupM3N3 := []*NewMessageEntry{tv24MessageEntry, tv25MessageEntry, tv26MessageEntry, tv27MessageEntry}
	plainTexts29GroupM3N3 := [][]byte{plainText4, plainText3, plainText1, plainText2}
	tv29.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		// Nothing should change with the threads.
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m3PublicKey, []*AccessGroupId{&groupIdM3DefaultKey, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, []*AccessGroupId{&groupIdM0DefaultKey, &groupIdM1N1, &groupIdM3N3})
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m1PublicKey, []*AccessGroupId{&groupIdM1DefaultKey, &groupIdM1N1, &groupIdM3N3})
		_verifyGroupMessageEntries(t, utxoView, groupIdM3N3, messages29GroupM3N3)
		// Sanity-check that everyone can decrypt the new message.
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m0PublicKey, m0DefaultKeyPriv.Serialize(), plainTexts29GroupM3N3)
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m3PublicKey, m3DefaultKeyPriv.Serialize(), plainTexts29GroupM3N3)
		_verifyGroupMessageEntriesDecryption(t, utxoView, groupIdM3N3, *m1PublicKey, m1DefaultKeyPriv.Serialize(), plainTexts29GroupM3N3)
	}
	tvv3 := []*transactionTestVector{tv13, tv14, tv15, tv16, tv17, tv18, tv19, tv20, tv20p5, tv21, tv22, tv23, tv24,
		tv25, tv26, tv27, tv28, tv29}
	tvb3 := NewTransactionTestVectorBlock(tvv3, nil, nil)

	// -------------------------------------------------------------------------------------
	// Enumeration tests. Add a bunch of threads and messages and make sure we can enumerate them properly.
	// -------------------------------------------------------------------------------------
	// Create a bunch of messages that will be sent within the same DM thread.
	// We will send them from (m0, "enumeration-sender") to (m1, "enumeration-recipient"), or other way round.
	dmEnumerationSenderKeyNameBytes := []byte("enumeration-sender")
	dmEnumerationSenderKeyName := NewGroupKeyName(dmEnumerationSenderKeyNameBytes)
	dmEnumerationRecipientKeyNameBytes := []byte("enumeration-recipient")
	dmEnumerationRecipientKeyName := NewGroupKeyName(dmEnumerationRecipientKeyNameBytes)
	tv30 := _createAccessGroupTestVector("TEST 30: (PASS) Try connecting access group create transaction "+
		"for group (m0, enumerationSender)", m0Priv, m0PubBytes, m0PubBytes, groupPk1, dmEnumerationSenderKeyName.ToBytes(),
		AccessGroupOperationTypeCreate, nil, nil)
	tv31 := _createAccessGroupTestVector("TEST 31: (PASS) Try connecting access group create transaction "+
		"for group (m1, enumerationRecipient)", m1Priv, m1PubBytes, m1PubBytes, groupPk2, dmEnumerationRecipientKeyName.ToBytes(),
		AccessGroupOperationTypeCreate, nil, nil)
	groupIdM0Es := *NewAccessGroupId(m0PublicKey, dmEnumerationSenderKeyNameBytes)
	groupIdM1Er := *NewAccessGroupId(m1PublicKey, dmEnumerationRecipientKeyNameBytes)
	dmThreadEnumeration := _createDmThreadKey(groupIdM0Es, groupIdM1Er)
	dmThreads31M0 := append(dmThreads13M0, &dmThreadEnumeration)
	dmThreads31M1 := append(dmThreads3M1, &dmThreadEnumeration)
	var dmEnumerationMessages []*NewMessageEntry
	var dmEnumerationTestVectors []*transactionTestVector
	for ii := 0; ii < DmEnumerationMsgCount; ii++ {
		var msg *NewMessageEntry
		var tv *transactionTestVector
		// If ii % 2 == 0, we will send the message from the sender; otherwise we will use the recipient.
		if ii%2 == 0 {
			msg = _createMessageEntry(*m0PublicKey, *dmEnumerationSenderKeyName, *m0PublicKey,
				*m1PublicKey, *dmEnumerationRecipientKeyName, *m1PublicKey, []byte(fmt.Sprintf("message %d", ii)),
				uint64(ii+1), nil)
			tv = _createNewMessageTestVector(fmt.Sprintf("TEST 32.%d: (PASS) Try connecting new message DM transaction "+
				"sent from (m0, enumerationSender) to (m1, enumerationRecipient)", ii), m0Priv, m0PubBytes,
				msg, NewMessageTypeDm, NewMessageOperationCreate, nil)
		} else {
			msg = _createMessageEntry(*m1PublicKey, *dmEnumerationRecipientKeyName, *m1PublicKey,
				*m0PublicKey, *dmEnumerationSenderKeyName, *m0PublicKey, []byte(fmt.Sprintf("message %d", ii)),
				uint64(ii+1), nil)
			tv = _createNewMessageTestVector(fmt.Sprintf("TEST 32.%d: (PASS) Try connecting new message DM transaction "+
				"sent from (m1, enumerationRecipient) to (m0, enumerationSender)", ii), m1Priv, m1PubBytes,
				msg, NewMessageTypeDm, NewMessageOperationCreate, nil)
		}
		dmEnumerationMessages = append(dmEnumerationMessages, msg)
		dmEnumerationTestVectors = append(dmEnumerationTestVectors, tv)
	}
	tvv4 := []*transactionTestVector{tv30, tv31}
	tvv4 = append(tvv4, dmEnumerationTestVectors...)

	// Create a bunch of messages that will be sent within the same group chat thread.
	groupChatEnumerationKeyNameBytes := []byte("enumeration-group")
	groupChatEnumerationKeyName := NewGroupKeyName(groupChatEnumerationKeyNameBytes)
	tv33 := _createAccessGroupTestVector("TEST 33: (PASS) Try connecting access group create transaction "+
		"for group (m0, enumerationGroup)", m0Priv, m0PubBytes, m0PubBytes, groupPk1, groupChatEnumerationKeyName.ToBytes(),
		AccessGroupOperationTypeCreate, nil, nil)
	groupIdM0Eg := *NewAccessGroupId(m0PublicKey, groupChatEnumerationKeyNameBytes)
	var groupChatEnumerationMessages []*NewMessageEntry
	var groupChatEnumerationTestVectors []*transactionTestVector
	for ii := 0; ii < GroupChatEnumerationMsgCount; ii++ {
		msg := _createMessageEntry(*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey,
			*m0PublicKey, *groupChatEnumerationKeyName, *m0PublicKey, []byte(fmt.Sprintf("message %d", ii)),
			uint64(ii+1), nil)
		tv := _createNewMessageTestVector(fmt.Sprintf("TEST 34.%d: (PASS) Try connecting new message group chat transaction "+
			"sent from (m0, baseGroup) to (m0, enumerationGroup)", ii), m0Priv, m0PubBytes,
			msg, NewMessageTypeGroupChat, NewMessageOperationCreate, nil)
		groupChatEnumerationMessages = append(groupChatEnumerationMessages, msg)
		groupChatEnumerationTestVectors = append(groupChatEnumerationTestVectors, tv)
	}
	tvv4 = append(tvv4, tv33)
	tvv4 = append(tvv4, groupChatEnumerationTestVectors...)

	tvb4ConnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m0PublicKey, dmThreads31M0)
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m1PublicKey, dmThreads31M1)
		_verifyDmMessageEntries(t, utxoView, dmThreadEnumeration, dmEnumerationMessages)
		_verifyGroupMessageEntries(t, utxoView, groupIdM0Eg, groupChatEnumerationMessages)
	}
	tvb4 := NewTransactionTestVectorBlock(tvv4, tvb4ConnectCallback, nil)

	// Now update some dm enumeration messages to make sure combining db and utxoView entries works in the paginated call.
	var dmEnumerationUpdateMessages []*NewMessageEntry
	var dmEnumerationUpdateTestVectors []*transactionTestVector
	for ii := 0; ii < DmEnumerationMsgCount; ii++ {
		// If ii % 2 == 0 then we do nothing to the message; otherwise we update it.
		if ii%2 == 0 {
			dmEnumerationUpdateMessages = append(dmEnumerationUpdateMessages, dmEnumerationMessages[ii])
		} else {
			originalMsg := dmEnumerationMessages[ii]
			randomExtraData := map[string][]byte{
				"random": []byte(fmt.Sprintf("random data %d", ii)),
			}
			msg := _createMessageEntry(*originalMsg.SenderAccessGroupOwnerPublicKey, *originalMsg.SenderAccessGroupKeyName,
				*originalMsg.SenderAccessGroupPublicKey, *originalMsg.RecipientAccessGroupOwnerPublicKey,
				*originalMsg.RecipientAccessGroupKeyName, *originalMsg.RecipientAccessGroupPublicKey,
				[]byte(fmt.Sprintf("message %d updated", ii)), originalMsg.TimestampNanos, randomExtraData)
			dmEnumerationUpdateMessages = append(dmEnumerationUpdateMessages, msg)
			// We use m1 to update the message as it was previously used in the ii%2 == 1 case.
			tv := _createNewMessageTestVector(fmt.Sprintf("TEST 35.%d: (PASS) Try connecting new message DM update transaction "+
				"sent from (m1, enumerationRecipient) to (m0, enumerationSender)", ii), m1Priv, m1PubBytes,
				msg, NewMessageTypeDm, NewMessageOperationUpdate, nil)
			dmEnumerationUpdateTestVectors = append(dmEnumerationUpdateTestVectors, tv)
		}
	}
	tvv5 := dmEnumerationUpdateTestVectors
	// Now update some group chat enumeration entries to make sure combining db and utxoView entries works in the paginated call.
	var groupChatEnumerationUpdateMessages []*NewMessageEntry
	var groupChatEnumerationUpdateTestVectors []*transactionTestVector
	for ii := 0; ii < GroupChatEnumerationMsgCount; ii++ {
		// If ii % 2 == 0 then we do nothing to the message; otherwise we update it.
		if ii%2 == 0 {
			groupChatEnumerationUpdateMessages = append(groupChatEnumerationUpdateMessages, groupChatEnumerationMessages[ii])
		} else {
			originalMsg := groupChatEnumerationMessages[ii]
			randomExtraData := map[string][]byte{
				"random": []byte(fmt.Sprintf("random data %d", ii)),
			}
			msg := _createMessageEntry(*originalMsg.SenderAccessGroupOwnerPublicKey, *originalMsg.SenderAccessGroupKeyName,
				*originalMsg.SenderAccessGroupPublicKey, *originalMsg.RecipientAccessGroupOwnerPublicKey,
				*originalMsg.RecipientAccessGroupKeyName, *originalMsg.RecipientAccessGroupPublicKey,
				[]byte(fmt.Sprintf("message %d updated", ii)), originalMsg.TimestampNanos, randomExtraData)
			groupChatEnumerationUpdateMessages = append(groupChatEnumerationUpdateMessages, msg)
			// We use m1 to update the message as it was previously used in the ii%2 == 1 case.
			tv := _createNewMessageTestVector(fmt.Sprintf("TEST 36.%d: (PASS) Try connecting new message group chat update transaction "+
				"sent from (m0, enumerationGroup) to (m0, enumerationGroup)", ii), m0Priv, m0PubBytes,
				msg, NewMessageTypeGroupChat, NewMessageOperationUpdate, nil)
			groupChatEnumerationUpdateTestVectors = append(groupChatEnumerationUpdateTestVectors, tv)
		}
	}
	tvv5 = append(tvv5, groupChatEnumerationUpdateTestVectors...)

	tvb5ConnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		utxoView, err := NewUtxoView(tm.db, tm.params, tm.pg, tm.chain.snapshot)
		require.NoError(err)
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m0PublicKey, dmThreads31M0)
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m1PublicKey, dmThreads31M1)
		_verifyDmMessageEntries(t, utxoView, dmThreadEnumeration, dmEnumerationUpdateMessages)
		_verifyGroupMessageEntries(t, utxoView, groupIdM0Eg, groupChatEnumerationUpdateMessages)
	}
	tvb5 := NewTransactionTestVectorBlock(tvv5, tvb5ConnectCallback, tvb4ConnectCallback)

	tvbb := []*transactionTestVectorBlock{tvb1, tvb2, tvb3, tvb4, tvb5}

	tes := NewTransactionTestSuite(t, tvbb, tConfig)
	tes.Run()
}

func _createNewMessageTestVector(id string, userPrivateKey string, userPublicKey []byte, messageEntry *NewMessageEntry,
	messageType NewMessageType, messageOperation NewMessageOperation, expectedConnectError error) (
	_tv *transactionTestVector) {

	txnMeta := NewMessageMetadata{
		SenderAccessGroupOwnerPublicKey:    *messageEntry.SenderAccessGroupOwnerPublicKey,
		SenderAccessGroupKeyName:           *messageEntry.SenderAccessGroupKeyName,
		SenderAccessGroupPublicKey:         *messageEntry.SenderAccessGroupPublicKey,
		RecipientAccessGroupOwnerPublicKey: *messageEntry.RecipientAccessGroupOwnerPublicKey,
		RecipientAccessGroupKeyName:        *messageEntry.RecipientAccessGroupKeyName,
		RecipientAccessGroupPublicKey:      *messageEntry.RecipientAccessGroupPublicKey,
		EncryptedText:                      messageEntry.EncryptedText,
		TimestampNanos:                     messageEntry.TimestampNanos,
		NewMessageType:                     messageType,
		NewMessageOperation:                messageOperation,
	}
	testData := &NewMessageTestData{
		userPrivateKey:       userPrivateKey,
		userPublicKey:        userPublicKey,
		expectedConnectError: expectedConnectError,
		extraData:            messageEntry.ExtraData,
		NewMessageMetadata:   txnMeta,
	}
	return &transactionTestVector{
		id:         transactionTestIdentifier(id),
		inputSpace: testData,
		getTransaction: func(tv *transactionTestVector, tm *transactionTestMeta) (*MsgDeSoTxn, error) {
			dataSpace := tv.inputSpace.(*NewMessageTestData)
			txn, err := _createSignedNewMessageTransaction(tm.t, tm.chain, tm.mempool, dataSpace)
			require.NoError(tm.t, err)
			return txn, dataSpace.expectedConnectError
		},
		verifyConnectUtxoViewEntry: func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
			dataSpace := tv.inputSpace.(*NewMessageTestData)
			_verifyConnectUtxoViewEntryForNewMessage(tm.t, utxoView, dataSpace)
		},
		verifyDisconnectUtxoViewEntry: func(tv *transactionTestVector, tm *transactionTestMeta,
			utxoView *UtxoView, utxoOps []*UtxoOperation) {

			dataSpace := tv.inputSpace.(*NewMessageTestData)
			blockHeight := uint64(tm.chain.blockTip().Height)
			_verifyDisconnectUtxoViewEntryForNewMessage(tm.t, utxoView, utxoOps, blockHeight, dataSpace)
		},
		verifyDbEntry: func(tv *transactionTestVector, tm *transactionTestMeta, dbAdapter *DbAdapter) {

			dataSpace := tv.inputSpace.(*NewMessageTestData)
			_verifyDbEntryForNewMessage(tm.t, dbAdapter, dataSpace)
		},
	}
}

func _createSignedNewMessageTransaction(t *testing.T, chain *Blockchain, mempool *DeSoMempool,
	dataSpace *NewMessageTestData) (_txn *MsgDeSoTxn, _err error) {

	require := require.New(t)

	// Create the transaction.
	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateNewMessageTxn(
		dataSpace.userPublicKey,
		dataSpace.SenderAccessGroupOwnerPublicKey, dataSpace.SenderAccessGroupKeyName, dataSpace.SenderAccessGroupPublicKey,
		dataSpace.RecipientAccessGroupOwnerPublicKey, dataSpace.RecipientAccessGroupKeyName, dataSpace.RecipientAccessGroupPublicKey,
		dataSpace.EncryptedText, dataSpace.TimestampNanos, dataSpace.NewMessageType, dataSpace.NewMessageOperation, dataSpace.extraData,
		10, mempool, []*DeSoOutput{})
	if err != nil {
		return nil, errors.Wrapf(err, "_createSignedNewMessageTransaction: problem for "+
			"dataSpace %v", dataSpace)
	}
	require.Equal(totalInputMake, changeAmountMake+feesMake)
	_signTxn(t, txn, dataSpace.userPrivateKey)
	return txn, nil
}

func _verifyConnectUtxoViewEntryForNewMessage(t *testing.T, utxoView *UtxoView, dataSpace *NewMessageTestData) {
	require := require.New(t)

	// Verify that the UtxoView is correct.
	var messageEntry *NewMessageEntry
	var exists bool

	switch dataSpace.NewMessageType {
	case NewMessageTypeDm:
		// Verify that the sender's access group key was updated.
		dmMessageKey := MakeDmMessageKeyForSenderRecipient(dataSpace.SenderAccessGroupOwnerPublicKey, dataSpace.SenderAccessGroupKeyName,
			dataSpace.RecipientAccessGroupOwnerPublicKey, dataSpace.RecipientAccessGroupKeyName, dataSpace.TimestampNanos)
		messageEntry, exists = utxoView.DmMessagesIndex[dmMessageKey]
	case NewMessageTypeGroupChat:
		// Verify that the group chat message was updated.
		groupChatMessageKey := MakeGroupChatMessageKey(dataSpace.RecipientAccessGroupOwnerPublicKey, dataSpace.RecipientAccessGroupKeyName,
			dataSpace.TimestampNanos)
		messageEntry, exists = utxoView.GroupChatMessagesIndex[groupChatMessageKey]
	}

	require.Equal(true, exists)
	require.NotNil(messageEntry)
	require.Equal(false, messageEntry.isDeleted)
	require.Equal(true, _verifyEqualNewMessage(t, messageEntry, dataSpace))
}

func _verifyDisconnectUtxoViewEntryForNewMessage(t *testing.T, utxoView *UtxoView, utxoOps []*UtxoOperation,
	blockHeight uint64, dataSpace *NewMessageTestData) {

	require := require.New(t)
	dmMessageKey := MakeDmMessageKeyForSenderRecipient(dataSpace.SenderAccessGroupOwnerPublicKey, dataSpace.SenderAccessGroupKeyName,
		dataSpace.RecipientAccessGroupOwnerPublicKey, dataSpace.RecipientAccessGroupKeyName, dataSpace.TimestampNanos)
	groupChatMessageKey := MakeGroupChatMessageKey(dataSpace.RecipientAccessGroupOwnerPublicKey, dataSpace.RecipientAccessGroupKeyName,
		dataSpace.TimestampNanos)
	currentUtxoOp := utxoOps[len(utxoOps)-1]
	require.Equal(OperationTypeNewMessage, currentUtxoOp.Type)

	switch dataSpace.NewMessageOperation {
	case NewMessageOperationCreate:
		var messageEntry *NewMessageEntry
		var exists bool
		switch dataSpace.NewMessageType {
		case NewMessageTypeDm:
			messageEntry, exists = utxoView.DmMessagesIndex[dmMessageKey]
		case NewMessageTypeGroupChat:
			messageEntry, exists = utxoView.GroupChatMessagesIndex[groupChatMessageKey]
		}
		require.Equal(true, exists)
		require.NotNil(messageEntry)
		require.Equal(true, messageEntry.isDeleted)
	case NewMessageOperationUpdate:
		var messageEntry *NewMessageEntry
		var exists bool
		previousMessageEntry := currentUtxoOp.PrevNewMessageEntry
		require.NotNil(previousMessageEntry)

		switch dataSpace.NewMessageType {
		case NewMessageTypeDm:
			messageEntry, exists = utxoView.DmMessagesIndex[dmMessageKey]
		case NewMessageTypeGroupChat:
			messageEntry, exists = utxoView.GroupChatMessagesIndex[groupChatMessageKey]
		}
		require.Equal(true, exists)
		require.NotNil(messageEntry)
		require.Equal(false, messageEntry.isDeleted)
		require.Equal(true, bytes.Equal(EncodeToBytes(blockHeight, messageEntry), EncodeToBytes(blockHeight, previousMessageEntry)))
	}
}

func _verifyDbEntryForNewMessage(t *testing.T, dbAdapter *DbAdapter, dataSpace *NewMessageTestData) {
	require := require.New(t)

	var messageEntry *NewMessageEntry
	var err error
	switch dataSpace.NewMessageType {
	case NewMessageTypeDm:
		dmMessageKey := MakeDmMessageKeyForSenderRecipient(dataSpace.SenderAccessGroupOwnerPublicKey, dataSpace.SenderAccessGroupKeyName,
			dataSpace.RecipientAccessGroupOwnerPublicKey, dataSpace.RecipientAccessGroupKeyName, dataSpace.TimestampNanos)
		messageEntry, err = dbAdapter.GetDmMessageEntry(dmMessageKey)
	case NewMessageTypeGroupChat:
		groupChatMessageKey := MakeGroupChatMessageKey(dataSpace.RecipientAccessGroupOwnerPublicKey, dataSpace.RecipientAccessGroupKeyName,
			dataSpace.TimestampNanos)
		messageEntry, err = dbAdapter.GetGroupChatMessageEntry(groupChatMessageKey)
	}

	require.NoError(err)
	require.NotNil(messageEntry)
	require.Equal(true, _verifyEqualNewMessage(t, messageEntry, dataSpace))
}

func _verifyEqualNewMessage(t *testing.T, newMessageEntry *NewMessageEntry, dataSpace *NewMessageTestData) bool {

	require := require.New(t)
	// Make sure no field of the newMessageEntry is nil.
	require.NotNil(newMessageEntry)
	require.NotNil(newMessageEntry.SenderAccessGroupOwnerPublicKey)
	require.NotNil(newMessageEntry.SenderAccessGroupKeyName)
	require.NotNil(newMessageEntry.SenderAccessGroupPublicKey)
	require.NotNil(newMessageEntry.RecipientAccessGroupOwnerPublicKey)
	require.NotNil(newMessageEntry.RecipientAccessGroupKeyName)
	require.NotNil(newMessageEntry.RecipientAccessGroupPublicKey)

	// Compare each field of newMessageEntry with the dataSpace.
	if !bytes.Equal(newMessageEntry.SenderAccessGroupOwnerPublicKey.ToBytes(), dataSpace.SenderAccessGroupOwnerPublicKey.ToBytes()) {
		return false
	}
	if !bytes.Equal(newMessageEntry.SenderAccessGroupKeyName.ToBytes(), dataSpace.SenderAccessGroupKeyName.ToBytes()) {
		return false
	}
	if !bytes.Equal(newMessageEntry.SenderAccessGroupPublicKey.ToBytes(), dataSpace.SenderAccessGroupPublicKey.ToBytes()) {
		return false
	}
	if !bytes.Equal(newMessageEntry.RecipientAccessGroupOwnerPublicKey.ToBytes(), dataSpace.RecipientAccessGroupOwnerPublicKey.ToBytes()) {
		return false
	}
	if !bytes.Equal(newMessageEntry.RecipientAccessGroupKeyName.ToBytes(), dataSpace.RecipientAccessGroupKeyName.ToBytes()) {
		return false
	}
	if !bytes.Equal(newMessageEntry.RecipientAccessGroupPublicKey.ToBytes(), dataSpace.RecipientAccessGroupPublicKey.ToBytes()) {
		return false
	}
	if !bytes.Equal(newMessageEntry.EncryptedText, dataSpace.EncryptedText) {
		return false
	}
	if newMessageEntry.TimestampNanos != dataSpace.TimestampNanos {
		return false
	}
	if !bytes.Equal(EncodeExtraData(dataSpace.extraData), EncodeExtraData(newMessageEntry.ExtraData)) {
		return false
	}
	return true
}

func _createDmThreadKey(userAccessGroupId AccessGroupId, partyAccessGroupId AccessGroupId) DmThreadKey {
	return DmThreadKey{
		UserAccessGroupOwnerPublicKey:  userAccessGroupId.AccessGroupOwnerPublicKey,
		UserAccessGroupKeyName:         userAccessGroupId.AccessGroupKeyName,
		PartyAccessGroupOwnerPublicKey: partyAccessGroupId.AccessGroupOwnerPublicKey,
		PartyAccessGroupKeyName:        partyAccessGroupId.AccessGroupKeyName,
	}
}

func _createMessageEntry(senderAccessGroupOwnerPublicKey PublicKey, senderAccessGroupKeyName GroupKeyName,
	senderAccessPublicKey PublicKey, recipientAccessGroupOwnerPublicKey PublicKey, recipientAccessGroupKeyName GroupKeyName,
	recipientAccessPublicKey PublicKey, encryptedText []byte, timestampNanos uint64, extraData map[string][]byte) *NewMessageEntry {

	return &NewMessageEntry{
		SenderAccessGroupOwnerPublicKey:    &senderAccessGroupOwnerPublicKey,
		SenderAccessGroupKeyName:           &senderAccessGroupKeyName,
		SenderAccessGroupPublicKey:         &senderAccessPublicKey,
		RecipientAccessGroupOwnerPublicKey: &recipientAccessGroupOwnerPublicKey,
		RecipientAccessGroupKeyName:        &recipientAccessGroupKeyName,
		RecipientAccessGroupPublicKey:      &recipientAccessPublicKey,
		EncryptedText:                      encryptedText,
		TimestampNanos:                     timestampNanos,
		ExtraData:                          extraData,
	}
}

func _verifyDmThreadKeysWithUtxoView(t *testing.T, utxoView *UtxoView, userAccessGroupOwnerPublicKey PublicKey,
	expectedDmThreadKeys []*DmThreadKey) {

	require := require.New(t)
	dmThreads, err := utxoView.GetAllUserDmThreads(userAccessGroupOwnerPublicKey)
	require.NoError(err)
	_verifyDmThreadKeys(t, dmThreads, userAccessGroupOwnerPublicKey, expectedDmThreadKeys)
}

func _verifyDmThreadKeys(t *testing.T, dmThreadKeys []*DmThreadKey, userAccessGroupOwnerPublicKey PublicKey,
	expectedDmThreadKeys []*DmThreadKey) {

	require := require.New(t)
	require.Equal(len(expectedDmThreadKeys), len(dmThreadKeys))
	expectedDmThreadKeysMap := make(map[DmThreadKey]struct{})
	for _, dmThreadKey := range expectedDmThreadKeys {
		if bytes.Equal(dmThreadKey.UserAccessGroupOwnerPublicKey.ToBytes(), dmThreadKey.PartyAccessGroupOwnerPublicKey.ToBytes()) {
			t.Fatalf("UserAccessGroupOwnerPublicKey and PartyAccessGroupOwnerPublicKey should not be equal in these tests.")
		}
		if bytes.Equal(dmThreadKey.PartyAccessGroupOwnerPublicKey.ToBytes(), userAccessGroupOwnerPublicKey.ToBytes()) {
			swapDmThreadKey := DmThreadKey{
				UserAccessGroupOwnerPublicKey:  dmThreadKey.PartyAccessGroupOwnerPublicKey,
				UserAccessGroupKeyName:         dmThreadKey.PartyAccessGroupKeyName,
				PartyAccessGroupOwnerPublicKey: dmThreadKey.UserAccessGroupOwnerPublicKey,
				PartyAccessGroupKeyName:        dmThreadKey.UserAccessGroupKeyName,
			}
			expectedDmThreadKeysMap[swapDmThreadKey] = struct{}{}
		} else {
			expectedDmThreadKeysMap[*dmThreadKey] = struct{}{}
		}
	}

	// Verify there is no repetitions among dmThreadKeys.
	tempDmThreadKeysMap := make(map[DmThreadKey]struct{})
	for _, dmThreadKey := range dmThreadKeys {
		_, exists := tempDmThreadKeysMap[*dmThreadKey]
		require.Equal(false, exists)
		tempDmThreadKeysMap[*dmThreadKey] = struct{}{}
	}

	// Make sure expectedDmThreadKeys is identical to dmThreadKeys.
	for _, dmThreadKey := range dmThreadKeys {
		require.Equal(true, bytes.Equal(dmThreadKey.UserAccessGroupOwnerPublicKey.ToBytes(), userAccessGroupOwnerPublicKey.ToBytes()))
		_, exists := expectedDmThreadKeysMap[*dmThreadKey]
		require.Equal(true, exists)
	}
}

func _verifyGroupChatThreadsWithUtxoView(t *testing.T, utxoView *UtxoView, userAccessGroupOwnerPublicKey PublicKey,
	expectedGroupThreadIds []*AccessGroupId) {

	require := require.New(t)
	groupChatThreads, err := utxoView.GetAllUserGroupChatThreads(userAccessGroupOwnerPublicKey)
	require.NoError(err)
	_verifyGroupChatThreads(t, groupChatThreads, expectedGroupThreadIds)
}

func _verifyGroupChatThreads(t *testing.T, groupChatThreads []*AccessGroupId, expectedGroupThreadIds []*AccessGroupId) {

	require := require.New(t)
	// Subtract one to account for the base key, which is always returned.
	require.Equal(len(expectedGroupThreadIds), len(groupChatThreads)-1)
	expectedGroupChatThreadKeysMap := make(map[AccessGroupId]struct{})
	for _, groupChatThreadIter := range groupChatThreads {
		groupChatThread := *groupChatThreadIter

		if _, ok := expectedGroupChatThreadKeysMap[groupChatThread]; ok {
			t.Fatalf("Duplicate group Id in expected group chat thread keys")
		}
		expectedGroupChatThreadKeysMap[groupChatThread] = struct{}{}
	}

	for _, groupChatThreadIter := range groupChatThreads {
		groupChatThread := *groupChatThreadIter

		if _, ok := expectedGroupChatThreadKeysMap[groupChatThread]; !ok {
			t.Fatalf("Group chat thread %v does not exist in expected group chat threads", groupChatThread)
		}
	}
}

func _verifyDmMessageEntries(t *testing.T, utxoView *UtxoView, dmThreadKey DmThreadKey, expectedMessageEntries []*NewMessageEntry) {
	require := require.New(t)

	sort.Slice(expectedMessageEntries, func(ii, jj int) bool {
		return expectedMessageEntries[ii].TimestampNanos > expectedMessageEntries[jj].TimestampNanos
	})
	_verify := func(messageEntries []*NewMessageEntry) {
		require.Equal(len(expectedMessageEntries), len(messageEntries))
		for ii, expectedMessageEntry := range expectedMessageEntries {
			_verifyEqualMessageEntries(t, expectedMessageEntry, messageEntries[ii])
		}
	}

	loopWithPaginatedCall := func(maxMessagesToFetch uint64) {
		var startTimestamp uint64
		startTimestamp = math.MaxUint64
		messageEntries := []*NewMessageEntry{}
		for {
			// Fetch the next page of messages.
			messageEntriesPage, err := utxoView.GetPaginatedMessageEntriesForDmThread(dmThreadKey, startTimestamp, maxMessagesToFetch)
			require.NoError(err)
			if len(messageEntriesPage) == 0 {
				break
			}
			require.Equal(true, uint64(len(messageEntriesPage)) <= maxMessagesToFetch)
			messageEntries = append(messageEntries, messageEntriesPage...)
			startTimestamp = messageEntriesPage[len(messageEntriesPage)-1].TimestampNanos
			if uint64(len(messageEntriesPage)) < maxMessagesToFetch {
				break
			}
		}
		_verify(messageEntries)
	}

	// Check a couple of different page sizes.
	loopWithPaginatedCall(1)
	loopWithPaginatedCall(2)
	loopWithPaginatedCall(3)
	loopWithPaginatedCall(5)
	loopWithPaginatedCall(10)
	loopWithPaginatedCall(math.MaxUint32)
}

func _verifyGroupMessageEntries(t *testing.T, utxoView *UtxoView, groupChatThreadKey AccessGroupId, expectedMessageEntries []*NewMessageEntry) {
	require := require.New(t)

	sort.Slice(expectedMessageEntries, func(ii, jj int) bool {
		return expectedMessageEntries[ii].TimestampNanos > expectedMessageEntries[jj].TimestampNanos
	})
	_verify := func(messageEntries []*NewMessageEntry) {
		require.Equal(len(expectedMessageEntries), len(messageEntries))
		for ii, expectedMessageEntry := range expectedMessageEntries {
			_verifyEqualMessageEntries(t, expectedMessageEntry, messageEntries[ii])
		}
	}

	loopWithPaginatedCall := func(maxMessagesToFetch uint64) {
		var startTimestamp uint64
		startTimestamp = math.MaxUint64
		messageEntries := []*NewMessageEntry{}
		for {
			// Fetch the next page of messages.
			messageEntriesPage, err := utxoView.GetPaginatedMessageEntriesForGroupChatThread(groupChatThreadKey, startTimestamp, maxMessagesToFetch)
			require.NoError(err)
			if len(messageEntriesPage) == 0 {
				break
			}
			require.Equal(true, uint64(len(messageEntriesPage)) <= maxMessagesToFetch)
			messageEntries = append(messageEntries, messageEntriesPage...)
			startTimestamp = messageEntriesPage[len(messageEntriesPage)-1].TimestampNanos
			if uint64(len(messageEntriesPage)) < maxMessagesToFetch {
				break
			}
		}
		_verify(messageEntries)
	}

	// Check a couple of different page sizes.
	loopWithPaginatedCall(math.MaxUint32)
	loopWithPaginatedCall(1)
	loopWithPaginatedCall(2)
	loopWithPaginatedCall(3)
	loopWithPaginatedCall(5)
	loopWithPaginatedCall(10)

}

func _verifyGroupMessageEntriesDecryption(t *testing.T, utxoView *UtxoView, groupChatThreadKey AccessGroupId,
	memberAccessGroupOwnerPublicKey PublicKey, memberAccessGroupPrivateKey []byte, expectedPlainTextsInOrder [][]byte) {

	require := require.New(t)
	// Make sure the group chat access group exists.
	groupChatAccessGroupEntry, err := utxoView.GetAccessGroupEntryWithAccessGroupId(&groupChatThreadKey)
	require.NoError(err)
	require.NotNil(groupChatAccessGroupEntry)
	require.Equal(false, groupChatAccessGroupEntry.isDeleted)
	// Fetch messages for the group chat.
	messageEntries, err := utxoView.GetPaginatedMessageEntriesForGroupChatThread(groupChatThreadKey, math.MaxUint64, 100)
	require.NoError(err)
	require.Equal(len(expectedPlainTextsInOrder), len(messageEntries))
	// Verify that the member entry exists
	memberEntry, err := utxoView.GetAccessGroupMemberEntry(&memberAccessGroupOwnerPublicKey,
		&groupChatThreadKey.AccessGroupOwnerPublicKey, &groupChatThreadKey.AccessGroupKeyName)
	require.NoError(err)
	require.NotNil(memberEntry)
	require.Equal(false, memberEntry.isDeleted)
	// Fetch the access group corresponding to the member entry we've found and make sure its access group public key
	// matches the private key provided through the params.
	memberAccessGroupEntry, err := utxoView.GetAccessGroupEntry(&memberAccessGroupOwnerPublicKey, memberEntry.AccessGroupMemberKeyName)
	require.NoError(err)
	require.NotNil(memberAccessGroupEntry)
	require.Equal(false, memberAccessGroupEntry.isDeleted)
	_, memberAccessGroupPublicKeyFromPriv := btcec.PrivKeyFromBytes(btcec.S256(), memberAccessGroupPrivateKey)
	require.Equal(true, bytes.Equal(memberAccessGroupEntry.AccessGroupPublicKey.ToBytes(), memberAccessGroupPublicKeyFromPriv.SerializeCompressed()))
	// Decrypt the EncryptedKey present in the memberEntry to get the message encryption/decryption key.
	decryptionKey := _decryptBytes(memberEntry.EncryptedKey, memberAccessGroupPrivateKey)
	for ii, messageEntry := range messageEntries {
		plainText := _decryptBytes(messageEntry.EncryptedText, decryptionKey)
		require.Equal(true, bytes.Equal(plainText, expectedPlainTextsInOrder[ii]))
	}
}

func _verifyEqualMessageEntries(t *testing.T, messageEntryA *NewMessageEntry, messageEntryB *NewMessageEntry) {
	require := require.New(t)
	require.Equal(true, bytes.Equal(messageEntryA.SenderAccessGroupOwnerPublicKey.ToBytes(), messageEntryB.SenderAccessGroupOwnerPublicKey.ToBytes()))
	require.Equal(true, bytes.Equal(messageEntryA.SenderAccessGroupKeyName.ToBytes(), messageEntryB.SenderAccessGroupKeyName.ToBytes()))
	require.Equal(true, bytes.Equal(messageEntryA.SenderAccessGroupPublicKey.ToBytes(), messageEntryB.SenderAccessGroupPublicKey.ToBytes()))
	require.Equal(true, bytes.Equal(messageEntryA.RecipientAccessGroupOwnerPublicKey.ToBytes(), messageEntryB.RecipientAccessGroupOwnerPublicKey.ToBytes()))
	require.Equal(true, bytes.Equal(messageEntryA.RecipientAccessGroupKeyName.ToBytes(), messageEntryB.RecipientAccessGroupKeyName.ToBytes()))
	require.Equal(true, bytes.Equal(messageEntryA.RecipientAccessGroupPublicKey.ToBytes(), messageEntryB.RecipientAccessGroupPublicKey.ToBytes()))
	require.Equal(true, bytes.Equal(messageEntryA.EncryptedText, messageEntryB.EncryptedText))
	require.Equal(true, messageEntryA.TimestampNanos == messageEntryB.TimestampNanos)
	require.Equal(true, bytes.Equal(EncodeExtraData(messageEntryA.ExtraData), EncodeExtraData(messageEntryB.ExtraData)))
}

func _encryptBytes(plainText []byte, publicKey PublicKey) []byte {
	pk, err := btcec.ParsePubKey(publicKey.ToBytes(), btcec.S256())
	if err != nil {
		return nil
	}
	encryptedMessageBytes, err := EncryptBytesWithPublicKey(
		plainText, pk.ToECDSA())
	if err != nil {
		return nil
	}
	return encryptedMessageBytes
}

func _decryptBytes(cipherText []byte, privateKey []byte) []byte {
	recipientPriv, _ := btcec.PrivKeyFromBytes(btcec.S256(), privateKey)
	plain, err := DecryptBytesWithPrivateKey(cipherText, recipientPriv.ToECDSA())
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return plain
}
