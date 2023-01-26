package lib

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"log"
	"net/http"
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
	tes := GetTestAccessGroupTransactionTestSuite(t, m0Pub, m1Pub, m2Pub, m3Pub)
	tes.Run()
}

type privatePublicBase58Check struct {
	priv *btcec.PrivateKey
	pub  string
}

func getPublicKeysTest1(seed byte, number int) []*privatePublicBase58Check {
	var privPublic []*privatePublicBase58Check
	for ii := 0; ii < number; ii++ {
		priv, pub := btcec.PrivKeyFromBytes(btcec.S256(), []byte{byte(ii), 2, 3, 4, seed})
		publicKeyBase58Check := Base58CheckEncode(pub.SerializeCompressed(), false, &DeSoTestnetParams)
		privPub := &privatePublicBase58Check{
			priv: priv,
			pub:  publicKeyBase58Check,
		}
		privPublic = append(privPublic, privPub)
	}

	return privPublic
}

func TestLogTransactionBytes(t *testing.T) {
	privPublic := getPublicKeysTest1(5, 4)

	glog.Infof("publicKey0Base58Check: %v", privPublic[0].pub)
	glog.Infof("publicKey1Base58Check: %v", privPublic[1].pub)
	glog.Infof("publicKey2Base58Check: %v", privPublic[2].pub)
	glog.Infof("publicKey3Base58Check: %v", privPublic[3].pub)
}

func TestSignSomething(t *testing.T) {
	require := require.New(t)

	txnHex := "01c49c4915154cb20f5b34739006f04d41b6e8a30a07d74dcb11f9eab5c886f3920102023472f3b193294e1b6c8556fe1f42f36b91a2daedb9df1dbc4e2b275b7daa523e904e03a39c7250d5522d902d36286bf7942599e33d302fb1b3fda50d4dc3cfdaca9092de97b3fc0f02002103a39c7250d5522d902d36286bf7942599e33d302fb1b3fda50d4dc3cfdaca90920000"
	txnBytes, _ := hex.DecodeString(txnHex)
	txn := &MsgDeSoTxn{}
	err := txn.FromBytes(txnBytes)
	require.NoError(err)

	seed, _ := hex.DecodeString("590f245dd25a0e6471d528a969f6bea16c707db5545096214c0878c19bd25303")
	privateKeyBase58Check := Base58CheckEncode(seed, true, &DeSoTestnetParams)
	_signTxn(t, txn, privateKeyBase58Check)

	txnBytes, _ = txn.ToBytes(false)
	glog.Infof("txnBytes: %v", hex.EncodeToString(txnBytes))
}

type TransactionFee struct {
	// PublicKeyBase58Check is the public key of the user who receives the fee.
	PublicKeyBase58Check string
	// ProfileEntryResponse is only non-nil when TransactionFees are retrieved through admin endpoints.
	// The ProfileEntryResponse is only used to display usernames and avatars in the admin dashboard and thus is
	// excluded in other places to reduce payload sizes and improve performance.
	ProfileEntryResponse []byte
	// AmountNanos is the amount PublicKeyBase58Check receives when this fee is incurred.
	AmountNanos uint64
}

type AccessGroupMemberAPI struct {
	AccessGroupMemberPublicKeyBase58Check string
	AccessGroupMemberKeyName              string
	EncryptedKey                          string

	ExtraData map[string]string
}

func txnToPostBody(txn *MsgDeSoTxn) []byte {
	var postBody []byte

	txnType := txn.TxnMeta.GetTxnType()
	debyteExtraData := func(extraData map[string][]byte) map[string]string {
		extraDataString := make(map[string]string)
		for k, v := range extraData {
			extraDataString[k] = string(v)
		}
		return extraDataString
	}
	txnExtraData := debyteExtraData(txn.ExtraData)

	switch txnType {
	case TxnTypeAccessGroup:
		txnMeta := txn.TxnMeta.(*AccessGroupMetadata)
		postBody, _ = json.Marshal(map[string]any{
			"AccessGroupOwnerPublicKeyBase58Check": Base58CheckEncode(txnMeta.AccessGroupOwnerPublicKey, false, &DeSoTestnetParams),
			"AccessGroupPublicKeyBase58Check":      Base58CheckEncode(txnMeta.AccessGroupPublicKey, false, &DeSoTestnetParams),
			"AccessGroupKeyName":                   string(txnMeta.AccessGroupKeyName),
			"MinFeeRateNanosPerKB":                 uint64(1000),
			"TransactionFees":                      []TransactionFee{},
			"ExtraData":                            txnExtraData,
		})
	case TxnTypeAccessGroupMembers:
		txnMeta := txn.TxnMeta.(*AccessGroupMembersMetadata)
		members := make([]AccessGroupMemberAPI, len(txnMeta.AccessGroupMembersList))
		for ii, member := range txnMeta.AccessGroupMembersList {
			members[ii] = AccessGroupMemberAPI{
				AccessGroupMemberPublicKeyBase58Check: Base58CheckEncode(member.AccessGroupMemberPublicKey, false, &DeSoTestnetParams),
				AccessGroupMemberKeyName:              string(member.AccessGroupMemberKeyName),
				EncryptedKey:                          string(member.EncryptedKey),
				ExtraData:                             debyteExtraData(member.ExtraData),
			}
		}
		postBody, _ = json.Marshal(map[string]any{
			"AccessGroupOwnerPublicKeyBase58Check": Base58CheckEncode(txnMeta.AccessGroupOwnerPublicKey, false, &DeSoTestnetParams),
			"AccessGroupKeyName":                   string(txnMeta.AccessGroupKeyName),
			"AccessGroupMemberList":                members,
			"MinFeeRateNanosPerKB":                 uint64(1000),
			"TransactionFees":                      []TransactionFee{},
			"ExtraData":                            txnExtraData,
		})
	case TxnTypeNewMessage:
		txnMeta := txn.TxnMeta.(*NewMessageMetadata)
		postBody, _ = json.Marshal(map[string]any{
			"SenderAccessGroupOwnerPublicKeyBase58Check":    Base58CheckEncode(txnMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), false, &DeSoTestnetParams),
			"SenderAccessGroupPublicKeyBase58Check":         Base58CheckEncode(txnMeta.SenderAccessGroupPublicKey.ToBytes(), false, &DeSoTestnetParams),
			"SenderAccessGroupKeyName":                      string(txnMeta.SenderAccessGroupKeyName.ToBytes()),
			"RecipientAccessGroupOwnerPublicKeyBase58Check": Base58CheckEncode(txnMeta.RecipientAccessGroupOwnerPublicKey.ToBytes(), false, &DeSoTestnetParams),
			"RecipientAccessGroupPublicKeyBase58Check":      Base58CheckEncode(txnMeta.RecipientAccessGroupPublicKey.ToBytes(), false, &DeSoTestnetParams),
			"RecipientAccessGroupKeyName":                   string(txnMeta.RecipientAccessGroupKeyName.ToBytes()),
			"EncryptedMessageText":                          string(txnMeta.EncryptedText),
			"MinFeeRateNanosPerKB":                          uint64(1000),
			"TransactionFees":                               []TransactionFee{},
			"ExtraData":                                     txnExtraData,
		})
	}
	return postBody
}

func txnToPostTransactionHex(t *testing.T, txn *MsgDeSoTxn) (_transactionHex string, _failed bool) {
	var transactionHex string
	if txn.TxnMeta.GetTxnType() == TxnTypeAccessGroup {
		accessGroupTxn := txn.TxnMeta.(*AccessGroupMetadata)
		if accessGroupTxn.AccessGroupOperationType != AccessGroupOperationTypeCreate {
			return "", true
		}
		glog.Infof("\t AccessGroupOwnerPublicKey: %v\n"+
			"\t AccessGroupPublicKey: %v\n"+
			"\t AccessGroupKeyName: %v\n"+
			"\t AccessGroupOperationType: %v\n"+
			"\t ExtraData: %v\n",
			Base58CheckEncode(accessGroupTxn.AccessGroupOwnerPublicKey, false, &DeSoTestnetParams),
			Base58CheckEncode(accessGroupTxn.AccessGroupPublicKey, false, &DeSoTestnetParams),
			hex.EncodeToString(accessGroupTxn.AccessGroupKeyName),
			accessGroupTxn.AccessGroupOperationType,
			txn.ExtraData)
		postBody := txnToPostBody(txn)
		transactionHex = submitPostRequest(t, postBody, "/api/v0/create-access-group")["TransactionHex"].(string)
	} else if txn.TxnMeta.GetTxnType() == TxnTypeAccessGroupMembers {
		accessGroupMembersTxn := txn.TxnMeta.(*AccessGroupMembersMetadata)
		if accessGroupMembersTxn.AccessGroupMemberOperationType != AccessGroupMemberOperationTypeAdd {
			return "", true
		}
		newMembers := []AccessGroupMember{}
		for _, memberIter := range accessGroupMembersTxn.AccessGroupMembersList {
			member := *memberIter
			newMembers = append(newMembers, member)
		}
		glog.Infof("\t AccessGroupOwnerPublicKey: %v\n"+
			"\t AccessGroupKeyName: %v\n"+
			"\t AccessGroupMemberList: %v\n"+
			"\t ExtraData: %v\n",
			Base58CheckEncode(accessGroupMembersTxn.AccessGroupOwnerPublicKey, false, &DeSoTestnetParams),
			hex.EncodeToString(accessGroupMembersTxn.AccessGroupKeyName),
			newMembers,
			txn.ExtraData)
		postBody := txnToPostBody(txn)
		transactionHex = submitPostRequest(t, postBody, "/api/v0/add-access-group-members")["TransactionHex"].(string)
	} else if txn.TxnMeta.GetTxnType() == TxnTypeNewMessage {
		newMessageTxn := txn.TxnMeta.(*NewMessageMetadata)
		if newMessageTxn.NewMessageOperation != NewMessageOperationCreate {
			return "", true
		}
		glog.Infof("\t SenderAccessGroupOwnerPublicKeyBase58Check: %v\n"+
			"\t SenderAccessGroupPublicKeyBase58Check: %v\n"+
			"\t SenderAccessGroupKeyName: %v\n"+
			"\t RecipientAccessGroupOwnerPublicKeyBase58Check: %v\n"+
			"\t RecipientAccessGroupPublicKeyBase58Check: %v\n"+
			"\t RecipientAccessGroupKeyName: %v\n"+
			"\t EncryptedText: %v\n"+
			"\t ExtraData: %v\n",
			Base58CheckEncode(newMessageTxn.SenderAccessGroupOwnerPublicKey.ToBytes(), false, &DeSoTestnetParams),
			Base58CheckEncode(newMessageTxn.SenderAccessGroupPublicKey.ToBytes(), false, &DeSoTestnetParams),
			hex.EncodeToString(newMessageTxn.SenderAccessGroupKeyName.ToBytes()),
			Base58CheckEncode(newMessageTxn.RecipientAccessGroupOwnerPublicKey.ToBytes(), false, &DeSoTestnetParams),
			Base58CheckEncode(newMessageTxn.RecipientAccessGroupPublicKey.ToBytes(), false, &DeSoTestnetParams),
			hex.EncodeToString(newMessageTxn.RecipientAccessGroupKeyName.ToBytes()),
			hex.EncodeToString(newMessageTxn.EncryptedText),
			txn.ExtraData)
		postBody := txnToPostBody(txn)
		if newMessageTxn.NewMessageType == NewMessageTypeDm {
			transactionHex = submitPostRequest(t, postBody, "/api/v0/send-dm-message")["TransactionHex"].(string)
		} else if newMessageTxn.NewMessageType == NewMessageTypeGroupChat {
			transactionHex = submitPostRequest(t, postBody, "/api/v0/send-group-chat-message")["TransactionHex"].(string)
		} else {
			return "", true
		}
	} else {
		return "", true
	}
	glog.Infof("TransactionHex: %v", transactionHex)
	return transactionHex, false
}

func submitTxnPostBody(txnBytes []byte) []byte {
	postBody, _ := json.Marshal(map[string]any{
		"TransactionHex": hex.EncodeToString(txnBytes),
	})
	return postBody
}

func sendDesoBody(fromPublicKey string, toPublicKey string, amount uint64) []byte {
	postBody, _ := json.Marshal(map[string]any{
		"SenderPublicKeyBase58Check":   fromPublicKey,
		"RecipientPublicKeyOrUsername": toPublicKey,
		"AmountNanos":                  amount,
		"MinFeeRateNanosPerKB":         uint64(1000),
		"TransactionFees":              []TransactionFee{},
	})
	return postBody
}

func TestCreateAccessGroupTxn(t *testing.T) {
	postBody, _ := json.Marshal(map[string]any{
		"AccessGroupOwnerPublicKeyBase58Check": "tBCKYP6LM4Q5hqNQqu7XQRLUJns6m51Pqy395oWHYmNkEnd2sAMgyh",
		"AccessGroupPublicKeyBase58Check":      "tBCKYUdUDF16yHy8Qn1WFnyA3vRsEBXuWr9PaRiv54biYkbVKkbZNY",
		"AccessGroupKeyName":                   "67726f757031",
		"MinFeeRateNanosPerKB":                 uint64(1000),
		"TransactionFees":                      []TransactionFee{},
		"ExtraData":                            map[string]string{"abc": "def"},
	})

	TransactionHex := submitPostRequest(t, postBody, "/api/v0/create-access-group")["TransactionHex"].(string)
	log.Printf("TransactionHex: %v", TransactionHex)
	require := require.New(t)
	transactionBytes, err := hex.DecodeString(TransactionHex)
	require.NoError(err)
	txn := &MsgDeSoTxn{}
	err = txn.FromBytes(transactionBytes)
	require.NoError(err)
	glog.Infof("txn: %v", txn)
}

func submitPostRequest(t *testing.T, postBody []byte, route string) map[string]any {
	//Encode the data
	responseBody := bytes.NewBuffer(postBody)
	//Leverage Go's HTTP Post function to make request
	resp, err := http.Post(fmt.Sprintf("https://test.deso.org%v", route), "application/json", responseBody)
	//Handle Error
	if err != nil {
		log.Fatalf("An Error Occured %v", err)
	}
	defer resp.Body.Close()
	//Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	log.Printf(sb)
	entries := make(map[string]any)
	err = json.Unmarshal(body, &entries)
	if err != nil {
		log.Fatalln(err)
	}
	return entries
}

func fundPublicKey(t *testing.T, publicKeyBase58Check string, amount uint64) {
	require := require.New(t)

	body := sendDesoBody("tBCKXyutsCWVbECXqE5zqP7NyGjmXg1SHkYJgKUsNujHfVF7GsVxzU", publicKeyBase58Check, amount)
	transactionHex := submitPostRequest(t, body, "/api/v0/send-deso")["TransactionHex"].(string)
	txnBytes, _ := hex.DecodeString(transactionHex)
	txn := &MsgDeSoTxn{}
	err := txn.FromBytes(txnBytes)
	require.NoError(err)

	seed, _ := hex.DecodeString("590f245dd25a0e6471d528a969f6bea16c707db5545096214c0878c19bd25303")
	privateKeyBase58Check := Base58CheckEncode(seed, true, &DeSoTestnetParams)
	_signTxn(t, txn, privateKeyBase58Check)

	txnBytes, _ = txn.ToBytes(false)
	submitPostBody := submitTxnPostBody(txnBytes)
	response := submitPostRequest(t, submitPostBody, "/api/v0/submit-transaction")
	glog.Infof("response: %v", response)

}

func signTransactionWithPublicKeyToPriv(t *testing.T, transactionHex string, publicKeyToPriv map[string]*btcec.PrivateKey) []byte {
	require := require.New(t)

	transactionBytes, err := hex.DecodeString(transactionHex)
	require.NoError(err)
	actualTxn := &MsgDeSoTxn{}
	err = actualTxn.FromBytes(transactionBytes)
	require.NoError(err)
	signerPriv, exists := publicKeyToPriv[Base58CheckEncode(actualTxn.PublicKey, false, &DeSoTestnetParams)]
	require.Equal(true, exists)
	signerPrivBase58Check := Base58CheckEncode(signerPriv.Serialize(), true, &DeSoTestnetParams)
	_signTxn(t, actualTxn, signerPrivBase58Check)
	txnBytes, err := actualTxn.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	return txnBytes
}

func processTestVectorsWithPublicKeyToPriv(t *testing.T, testVectors []*transactionTestVector, testMeta *transactionTestMeta,
	publicKeyToPriv map[string]*btcec.PrivateKey, submitTxn bool) {

	transactionCounter := 0
	for _, testVector := range testVectors {
		txn, err := testVector.getTransaction(testVector, testMeta)
		if err != nil {
			continue
		}

		glog.Infof("transactionCounter: %v", transactionCounter)
		transactionHex, failed := txnToPostTransactionHex(t, txn)
		if failed {
			glog.Infof("FAILED")
			continue
		}

		txnBytes := signTransactionWithPublicKeyToPriv(t, transactionHex, publicKeyToPriv)
		if submitTxn {
			submitPostBody := submitTxnPostBody(txnBytes)
			response := submitPostRequest(t, submitPostBody, "/api/v0/submit-transaction")
			glog.Infof("response: %v", response)
		}
		transactionCounter += 1
	}
}

func TestSignAccessGroupTxnVectors(t *testing.T) {
	require := require.New(t)
	_ = require

	privPublic := getPublicKeysTest1(200, 4)
	glog.Infof("publicKey0Base58Check: %v", privPublic[0].pub)
	glog.Infof("publicKey1Base58Check: %v", privPublic[1].pub)
	glog.Infof("publicKey2Base58Check: %v", privPublic[2].pub)
	glog.Infof("publicKey3Base58Check: %v", privPublic[3].pub)

	publicKeyToPriv := make(map[string]*btcec.PrivateKey)
	for _, privPub := range privPublic {
		publicKeyToPriv[privPub.pub] = privPub.priv
		fundPublicKey(t, privPub.pub, 10000)
	}
	submit := true

	testVectorsSuite := GetTestAccessGroupTransactionTestSuite(t, privPublic[0].pub, privPublic[1].pub,
		privPublic[2].pub, privPublic[3].pub)
	tm := testVectorsSuite.InitializeChainAndGetTestMeta(true, false)
	blockCounter := 0
	for _, block := range testVectorsSuite.testVectorBlocks {
		testVectors := block.testVectors
		glog.Infof("Processing Block %v", blockCounter)
		processTestVectorsWithPublicKeyToPriv(t, testVectors, tm, publicKeyToPriv, submit)
		blockCounter += 1
	}
}

func TestSignAccessGroupMembersAddTxnVectors(t *testing.T) {
	require := require.New(t)
	_ = require

	privPublic := getPublicKeysTest1(220, 6)
	glog.Infof("publicKey0Base58Check: %v", privPublic[0].pub)
	glog.Infof("publicKey1Base58Check: %v", privPublic[1].pub)
	glog.Infof("publicKey2Base58Check: %v", privPublic[2].pub)
	glog.Infof("publicKey3Base58Check: %v", privPublic[3].pub)
	glog.Infof("publicKey4Base58Check: %v", privPublic[4].pub)
	glog.Infof("publicKey5Base58Check: %v", privPublic[5].pub)

	publicKeyToPriv := make(map[string]*btcec.PrivateKey)
	for _, privPub := range privPublic {
		publicKeyToPriv[privPub.pub] = privPub.priv
		fundPublicKey(t, privPub.pub, 10000)
	}
	submit := true

	testVectorsSuite := GetTestAccessGroupMembersAddTransactionTestSuite(t, privPublic[0].pub, privPublic[1].pub,
		privPublic[2].pub, privPublic[3].pub, privPublic[4].pub, privPublic[5].pub)
	tm := testVectorsSuite.InitializeChainAndGetTestMeta(true, false)
	for blockCounter, block := range testVectorsSuite.testVectorBlocks {
		// Skip the last block
		if blockCounter == len(testVectorsSuite.testVectorBlocks)-1 {
			continue
		}
		testVectors := block.testVectors
		glog.Infof("Processing Block %v", blockCounter)
		processTestVectorsWithPublicKeyToPriv(t, testVectors, tm, publicKeyToPriv, submit)
	}
}

func TestSignNewMessageTxnVectors(t *testing.T) {
	require := require.New(t)
	_ = require

	privPublic := getPublicKeysTest1(222, 4)
	glog.Infof("publicKey0Base58Check: %v", privPublic[0].pub)
	glog.Infof("publicKey1Base58Check: %v", privPublic[1].pub)
	glog.Infof("publicKey2Base58Check: %v", privPublic[2].pub)
	glog.Infof("publicKey3Base58Check: %v", privPublic[3].pub)

	publicKeyToPriv := make(map[string]*btcec.PrivateKey)
	for _, privPub := range privPublic {
		publicKeyToPriv[privPub.pub] = privPub.priv
		fundPublicKey(t, privPub.pub, 50000)
	}
	submit := true

	testVectorsSuite := GetTestNewMessageTransactionTestSuite(t, privPublic[0].pub, privPublic[1].pub,
		privPublic[2].pub, privPublic[3].pub)
	tm := testVectorsSuite.InitializeChainAndGetTestMeta(true, false)
	for blockCounter, block := range testVectorsSuite.testVectorBlocks {
		testVectors := block.testVectors
		glog.Infof("Processing Block %v", blockCounter)
		processTestVectorsWithPublicKeyToPriv(t, testVectors, tm, publicKeyToPriv, submit)
	}
}

func GetTestAccessGroupTransactionTestSuite(t *testing.T, m0PublicKeyBase58Check string, m1PublicKeyBase58Check string,
	m2PublicKeyBase58Check string, m3PublicKeyBase58Check string) (_transactionTestSuite *transactionTestSuite) {
	require := require.New(t)
	_ = require

	m0PubBytes, _, _ := Base58CheckDecode(m0PublicKeyBase58Check)
	m0PublicKey := NewPublicKey(m0PubBytes)
	m1PubBytes, _, _ := Base58CheckDecode(m1PublicKeyBase58Check)
	m1PublicKey := NewPublicKey(m1PubBytes)
	m2PubBytes, _, _ := Base58CheckDecode(m2PublicKeyBase58Check)
	m2PublicKey := NewPublicKey(m2PubBytes)
	m3PubBytes, _, _ := Base58CheckDecode(m3PublicKeyBase58Check)
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
		disableLogging:             false,
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
	return tes
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
