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

func TestAccessGroupMembers(t *testing.T) {
	require := require.New(t)
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	params.ForkHeights.ExtraDataOnEntriesBlockHeight = 0
	params.ForkHeights.DeSoAccessGroupsBlockHeight = 0

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

	groupName1 := []byte("group1")
	groupName2 := []byte("group2")

	tm := transactionTestMeta{
		t:       t,
		chain:   chain,
		db:      db,
		params:  params,
		mempool: mempool,
		miner:   miner,
	}

	tv1 := _createAccessGroupCreateTestVector(tm, "TEST 1: (PASS) Connect access group create transaction made by "+
		"user 0", m0Priv, m0PubBytes, groupPk1, groupName1, nil,
		nil)
	tv2Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: groupName1, EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv2 := _createAccessGroupMembersTestVector(tm, "TEST 2: (FAIL) Connect access group members transaction to the "+
		"access group made by user 0 with group name 1, adding user 0 as member with the same access group name 1", m0Priv, m0PubBytes,
		groupName1, tv2Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessGroupMemberCantAddOwnerBySameGroup)
	tv3Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv3 := _createAccessGroupMembersTestVector(tm, "TEST 3: (PASS) Connect access group members transaction to the "+
		"access group made by user 0 with group name 1, adding user 0 as member with the base access group", m0Priv, m0PubBytes,
		groupName1, tv3Members, AccessGroupMemberOperationTypeAdd, nil)
	tv4 := _createAccessGroupCreateTestVector(tm, "TEST 4: (PASS) Connect access group create transaction made by "+
		"user 0 with group name 2", m0Priv, m0PubBytes, groupPk2, groupName2, nil, nil)
	tv5Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: BaseGroupKeyName().ToBytes(), EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv5 := _createAccessGroupMembersTestVector(tm, "TEST 5: (FAIL) Connect access group members transaction to the "+
		"access group made by user 0 with group name 1, again adding user 0 by base group key", m0Priv, m0PubBytes, groupName1,
		tv5Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessMemberAlreadyExists)
	tv6Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: groupName2, EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv6 := _createAccessGroupMembersTestVector(tm, "TEST 5: (PASS) Connect access group members transaction to the "+
		"access group made by user 0 with group name 1, again adding user 0 but by group name 2", m0Priv, m0PubBytes, groupName1,
		tv6Members, AccessGroupMemberOperationTypeAdd, RuleErrorAccessMemberAlreadyExists)
	tv7Members := []*AccessGroupMember{{
		AccessGroupMemberPublicKey: m0PubBytes, AccessGroupMemberKeyName: groupName1, EncryptedKey: []byte{1}, ExtraData: nil,
	}}
	tv7 := _createAccessGroupMembersTestVector(tm, "TEST 7: (PASS) Connect access group members transaction to the "+
		"access group made by user 0 with group name 2, adding user 0 by group name 1", m0Priv, m0PubBytes, groupName2,
		tv7Members, AccessGroupMemberOperationTypeAdd, nil)

	tvv := [][]*transactionTestVector{{tv1, tv2, tv3, tv4, tv5, tv6, tv7}}
	tes := transactionTestSuite{
		transactionTestMeta:  tm,
		testVectorsByBlock:   tvv,
		testVectorDependency: make(map[transactionTestIdentifier][]transactionTestIdentifier),
	}
	tes.run()
}

func _createAccessGroupMembersTestVector(tm transactionTestMeta, id string, userPrivateKey string, accessGroupOwnerPublicKey []byte,
	accessGroupKeyName []byte, accessGroupMembersList []*AccessGroupMember, operationType AccessGroupMemberOperationType,
	expectedConnectError error) (_tv *transactionTestVector) {

	require := require.New(tm.t)
	testData := &accessGroupMembersTestData{
		userPrivateKey:            userPrivateKey,
		accessGroupOwnerPublicKey: accessGroupOwnerPublicKey,
		accessGroupKeyName:        accessGroupKeyName,
		accessGroupMembersList:    accessGroupMembersList,
		operationType:             operationType,
		expectedConnectError:      expectedConnectError,
	}
	return &transactionTestVector{
		transactionTestMeta: tm,
		id:                  transactionTestIdentifier(id),
		inputSpace:          testData,
		getTransaction: func(tv *transactionTestVector) (*MsgDeSoTxn, error) {
			dataSpace := tv.inputSpace.(*accessGroupMembersTestData)
			txn, err := _createSignedAccessGroupMembersTransaction(
				tv.transactionTestMeta.t, tv.transactionTestMeta.chain, tv.transactionTestMeta.mempool,
				dataSpace.userPrivateKey, dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupKeyName,
				dataSpace.accessGroupMembersList, dataSpace.operationType)
			require.NoError(err)
			return txn, dataSpace.expectedConnectError
		},
		verifyMempoolEntry: func(tv *transactionTestVector, expectDeleted bool) {
			dataSpace := tv.inputSpace.(*accessGroupMembersTestData)
			_verifyMempoolUtxoViewEntryForAccessGroupMembers(
				tv.transactionTestMeta.t, tv.transactionTestMeta.mempool, expectDeleted,
				dataSpace.accessGroupOwnerPublicKey, dataSpace.accessGroupKeyName,
				dataSpace.accessGroupMembersList)
		},
		verifyDbEntry: func(tv *transactionTestVector, expectDeleted bool) {
			dataSpace := tv.inputSpace.(*accessGroupMembersTestData)
			_verifyDbEntryForAccessGroupMembers(
				tv.transactionTestMeta.t, tv.transactionTestMeta.chain, expectDeleted,
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

func _verifyMempoolUtxoViewEntryForAccessGroupMembers(t *testing.T, mempool *DeSoMempool, expectDeleted bool,
	accessGroupOwnerPublicKey []byte, accessGroupKeyName []byte, accessGroupMembersList []*AccessGroupMember) {

	require := require.New(t)
	utxoView, err := mempool.GetAugmentedUniversalView()
	require.NoError(err)

	for _, member := range accessGroupMembersList {
		groupMembershipKey := NewGroupMembershipKey(*NewPublicKey(member.AccessGroupMemberPublicKey),
			*NewPublicKey(accessGroupOwnerPublicKey), *NewGroupKeyName(accessGroupKeyName))

		// If the group has already been fetched in this utxoView, then we get it directly from there.
		accessGroupMember, exists := utxoView.GroupMembershipKeyToAccessGroupMember[*groupMembershipKey]
		if !expectDeleted {
			require.Equal(true, exists)
			require.NotNil(accessGroupMember)
			require.Equal(false, accessGroupMember.isDeleted)
			require.Equal(true, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
		} else {
			if !exists || accessGroupMember == nil || accessGroupMember.isDeleted {
				return
			}
			require.Equal(false, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
		}
	}
}

func _verifyDbEntryForAccessGroupMembers(t *testing.T, chain *Blockchain, expectDeleted bool,
	accessGroupOwnerPublicKey []byte, accessGroupKeyName []byte, accessGroupMembersList []*AccessGroupMember) {

	require := require.New(t)

	for _, member := range accessGroupMembersList {
		// If the group has already been fetched in this utxoView, then we get it directly from there.
		accessGroupMember, err := DBGetAccessGroupMemberEntry(chain.db, chain.snapshot,
			*NewPublicKey(member.AccessGroupMemberPublicKey), *NewPublicKey(accessGroupOwnerPublicKey), *NewGroupKeyName(accessGroupKeyName))
		require.NoError(err)
		if !expectDeleted {
			require.Equal(true, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
		} else {
			if accessGroupMember == nil {
				return
			}
			require.Equal(false, _verifyEqualAccessGroupMember(t, accessGroupMember, member))
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
