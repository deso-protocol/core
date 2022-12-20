package lib

import (
	"bytes"
	"github.com/btcsuite/btcd/btcec"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
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

	tv1 := _createNewMessageTestVector("TEST 1: (FAIL) Try connecting new message create transaction for a DM "+
		"sent from (m0, baseGroup) to (m1, baseGroup) before fork height", m0Priv, m0PubBytes,
		*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey, *m1PublicKey, *BaseGroupKeyName(), *m1PublicKey,
		[]byte{1, 2, 3}, 1, NewMessageTypeDm, NewMessageOperationCreate, nil,
		RuleErrorNewMessageBeforeDeSoAccessGroups)
	tv1.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		tm.params.ForkHeights.DeSoAccessGroupsBlockHeight = 0
	}
	// Send and update a dm message from (m0, baseGroup) to (m1, baseGroup)
	tv2 := _createNewMessageTestVector("TEST 2: (PASS) Try connecting new message create transaction for a DM "+
		"sent from (m0, baseGroup) to (m1, baseGroup)", m0Priv, m0PubBytes,
		*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey, *m1PublicKey, *BaseGroupKeyName(), *m1PublicKey,
		[]byte{1, 2, 3}, 1, NewMessageTypeDm, NewMessageOperationCreate, nil,
		nil)
	updatedDmMessage := []byte("updated dm message")
	updatedDmExtraData := map[string][]byte{
		"some random value": []byte("even more random value"),
	}
	groupIdM0B := *NewAccessGroupId(m0PublicKey, BaseGroupKeyName().ToBytes())
	groupIdM1B := *NewAccessGroupId(m1PublicKey, BaseGroupKeyName().ToBytes())
	dmM0BM1B := _createDmThreadKey(groupIdM0B, groupIdM1B)
	dmThreads2 := []*DmThreadKey{&dmM0BM1B}
	tv2.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m0PublicKey, dmThreads2)
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m1PublicKey, dmThreads2)
	}
	tv2.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m0PublicKey, []*DmThreadKey{})
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m1PublicKey, []*DmThreadKey{})
	}

	tv3 := _createNewMessageTestVector("TEST 3: (PASS) Try connecting new message update transaction for a DM "+
		"sent from (m0, baseGroup) to (m1, baseGroup)", m0Priv, m0PubBytes,
		*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey, *m1PublicKey, *BaseGroupKeyName(), *m1PublicKey,
		updatedDmMessage, 1, NewMessageTypeDm, NewMessageOperationUpdate, updatedDmExtraData,
		nil)
	dmThreads3 := dmThreads2
	tv3.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m0PublicKey, dmThreads3)
		_verifyDmThreadKeysWithUtxoView(t, utxoView, *m1PublicKey, dmThreads3)
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
	groupM1N1 := NewAccessGroupId(m1PublicKey, groupName1.ToBytes())
	tv5Members := []*AccessGroupMember{
		{AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{5, 6, 7}, ExtraData: nil},
	}
	tv5 := _createAccessGroupMembersTestVector("TEST 5: (PASS) Try connecting an access group members add transaction made by "+
		"(m1, groupName1) to add (m1, groupName1) as member", m1Priv, m1PubBytes, groupNameBytes1, tv5Members,
		AccessGroupMemberOperationTypeAdd, nil)
	// Send and update a group chat message from (m0, baseGroup) to (m1, groupName1)
	tv6 := _createNewMessageTestVector("TEST 6: (PASS) Try connecting new message create transaction for a group chat "+
		"sent from (m0, baseGroup) to (m1, groupName1)", m0Priv, m0PubBytes,
		*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey, *m1PublicKey, *groupName1, *NewPublicKey(groupPk1),
		[]byte{4, 5, 6}, 2, NewMessageTypeGroupChat, NewMessageOperationCreate, nil,
		nil)
	groupChatThreads6 := []*AccessGroupId{groupM1N1}
	_ = groupChatThreads6
	tv6.connectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, groupChatThreads6)
	}
	tv6.disconnectCallback = func(tv *transactionTestVector, tm *transactionTestMeta, utxoView *UtxoView) {
		_verifyGroupChatThreadsWithUtxoView(t, utxoView, *m0PublicKey, []*AccessGroupId{})
	}
	updateGroupMessage := []byte("updated group message")
	updateGroupExtraData := map[string][]byte{
		"some random group value": []byte("we are what we repeatedly do. Excellence, then, is not an act but a habit " +
			"- Aristotle & Durant"),
	}
	tv7 := _createNewMessageTestVector("TEST 7: (PASS) Try connecting new message update transaction for a group chat "+
		"sent from (m0, baseGroup) to (m1, groupName1)", m0Priv, m0PubBytes,
		*m0PublicKey, *BaseGroupKeyName(), *m0PublicKey, *m1PublicKey, *groupName1, *m1PublicKey,
		updateGroupMessage, 2, NewMessageTypeGroupChat, NewMessageOperationUpdate, updateGroupExtraData,
		nil)
	tv7.connectCallback = tv6.connectCallback
	tv7.disconnectCallback = tv6.connectCallback
	// TODO: Test owner sending group chat, test minor / major for the same public key.
	// TODO: Test that only group members can send group chat messages.
	// TODO: Re-read your old messaging group tests.
	// TODO: Make sure group id cant send a message to itself.

	// Add the above transactions to a block.
	tvv1 := []*transactionTestVector{tv1, tv2, tv3, tv4, tv5, tv6, tv7}
	tvb1DisconnectCallback := func(tvb *transactionTestVectorBlock, tm *transactionTestMeta) {
		tm.params.ForkHeights.DeSoAccessGroupsBlockHeight = 100
	}
	tvb1 := NewTransactionTestVectorBlock(tvv1, nil, tvb1DisconnectCallback)

	tvbb := []*transactionTestVectorBlock{tvb1}

	tes := NewTransactionTestSuite(t, tvbb, tConfig)
	tes.Run()
}

func _createNewMessageTestVector(id string, userPrivateKey string, userPublicKey []byte, senderAccessGroupOwnerPublicKey PublicKey,
	senderAccessGroupKeyName GroupKeyName, senderAccessPublicKey PublicKey, recipientAccessGroupOwnerPublicKey PublicKey,
	recipientAccessGroupKeyName GroupKeyName, recipientAccessPublicKey PublicKey, encryptedText []byte, timestampNanos uint64,
	messageType NewMessageType, messageOperation NewMessageOperation, extraData map[string][]byte, expectedConnectError error) (
	_tv *transactionTestVector) {

	txnMeta := NewMessageMetadata{
		SenderAccessGroupOwnerPublicKey:    senderAccessGroupOwnerPublicKey,
		SenderAccessGroupKeyName:           senderAccessGroupKeyName,
		SenderAccessGroupPublicKey:         senderAccessPublicKey,
		RecipientAccessGroupOwnerPublicKey: recipientAccessGroupOwnerPublicKey,
		RecipientAccessGroupKeyName:        recipientAccessGroupKeyName,
		RecipientAccessGroupPublicKey:      recipientAccessPublicKey,
		EncryptedText:                      encryptedText,
		TimestampNanos:                     timestampNanos,
		NewMessageType:                     messageType,
		NewMessageOperation:                messageOperation,
	}
	testData := &NewMessageTestData{
		userPrivateKey:       userPrivateKey,
		userPublicKey:        userPublicKey,
		expectedConnectError: expectedConnectError,
		extraData:            extraData,
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
		userGroupOwnerPublicKey:  userAccessGroupId.AccessGroupOwnerPublicKey,
		userGroupKeyName:         userAccessGroupId.AccessGroupKeyName,
		partyGroupOwnerPublicKey: partyAccessGroupId.AccessGroupOwnerPublicKey,
		partyGroupKeyName:        partyAccessGroupId.AccessGroupKeyName,
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
		if bytes.Equal(dmThreadKey.userGroupOwnerPublicKey.ToBytes(), dmThreadKey.partyGroupOwnerPublicKey.ToBytes()) {
			t.Fatalf("userGroupOwnerPublicKey and partyGroupOwnerPublicKey should not be equal in these tests.")
		}
		if bytes.Equal(dmThreadKey.partyGroupOwnerPublicKey.ToBytes(), userAccessGroupOwnerPublicKey.ToBytes()) {
			swapDmThreadKey := DmThreadKey{
				userGroupOwnerPublicKey:  dmThreadKey.partyGroupOwnerPublicKey,
				userGroupKeyName:         dmThreadKey.partyGroupKeyName,
				partyGroupOwnerPublicKey: dmThreadKey.userGroupOwnerPublicKey,
				partyGroupKeyName:        dmThreadKey.userGroupKeyName,
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
		require.Equal(true, bytes.Equal(dmThreadKey.userGroupOwnerPublicKey.ToBytes(), userAccessGroupOwnerPublicKey.ToBytes()))
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
	require.Equal(len(groupChatThreads), len(expectedGroupThreadIds))
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
