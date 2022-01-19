package lib

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"reflect"
	"sort"
	"testing"
	"time"
)

func _submitPost(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, updaterPkBase58Check string,
	updaterPrivBase58Check string, postHashToModify []byte,
	parentStakeID []byte,
	bodyObj *DeSoBodySchema,
	repostedPostHash []byte,
	tstampNanos uint64,
	isHidden bool) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(updaterPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	body, err := json.Marshal(bodyObj)
	require.NoError(err)

	isQuotedRepost := false
	if len(repostedPostHash) > 0 && (bodyObj.Body != "" || len(bodyObj.ImageURLs) > 0 || len(bodyObj.VideoURLs) > 0) {
		isQuotedRepost = true
	}
	postExtraData := make(map[string][]byte)
	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateSubmitPostTxn(
		updaterPkBytes,
		postHashToModify,
		parentStakeID,
		body,
		repostedPostHash,
		isQuotedRepost,
		tstampNanos,
		postExtraData,
		isHidden,
		feeRateNanosPerKB,
		nil,
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, updaterPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypePrivateMessage operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeSubmitPost, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _submitPostWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	updaterPkBase58Check string,
	updaterPrivBase58Check string,
	postHashToModify []byte,
	parentStakeID []byte,
	body *DeSoBodySchema,
	repostedPostHash []byte,
	tstampNanos uint64,
	isHidden bool) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, updaterPkBase58Check))

	currentOps, currentTxn, _, err := _submitPost(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params, feeRateNanosPerKB,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		postHashToModify,
		parentStakeID,
		body,
		repostedPostHash,
		tstampNanos,
		isHidden)

	require.NoError(testMeta.t, err)

	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _giveDeSoDiamonds(t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams,
	feeRateNanosPerKB uint64, senderPkBase58Check string, senderPrivBase58Check string,
	diamondPostHash *BlockHash, diamondLevel int64, deleteDiamondLevel bool,
) (_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	senderPkBytes, _, err := Base58CheckDecode(senderPkBase58Check)
	require.NoError(t, err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(t, err)

	txn, totalInputMake, spendAmount, changeAmountMake, feesMake, err := chain.CreateBasicTransferTxnWithDiamonds(
		senderPkBytes,
		diamondPostHash,
		diamondLevel,
		feeRateNanosPerKB,
		nil,
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(t, totalInputMake, spendAmount+changeAmountMake+feesMake)

	// For testing purposes.
	if deleteDiamondLevel {
		delete(txn.ExtraData, DiamondLevelKey)
	}

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, senderPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(t, totalInput, totalOutput+fees)
	require.Equal(t, totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeDeSoDiamond operation at the end.
	require.Equal(t, len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(t, OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(t, OperationTypeDeSoDiamond, utxoOps[len(utxoOps)-1].Type)

	require.NoError(t, utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _giveDeSoDiamondsWithTestMeta(
	testMeta *TestMeta,
	feeRateNanosPerKB uint64,
	senderPkBase58Check string,
	senderPrivBase58Check string,
	postHashToModify *BlockHash,
	diamondLevel int64,
) {

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, _getBalance(testMeta.t, testMeta.chain, nil, senderPkBase58Check))
	currentOps, currentTxn, _, err := _giveDeSoDiamonds(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params, feeRateNanosPerKB,
		senderPkBase58Check,
		senderPrivBase58Check,
		postHashToModify,
		diamondLevel,
		false,
	)
	require.NoError(testMeta.t, err)

	testMeta.txnOps = append(testMeta.txnOps, currentOps)
	testMeta.txns = append(testMeta.txns, currentTxn)
}

func _doSubmitPostTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64,
	UpdaterPublicKeyBase58Check string, UpdaterPrivateKeyBase58Check string,
	postHashToModify []byte,
	parentPostHashBytes []byte,
	body string,
	extraData map[string][]byte,
	isHidden bool) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updaterPkBytes, _, err := Base58CheckDecode(UpdaterPublicKeyBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, _, _, err := chain.CreateSubmitPostTxn(
		updaterPkBytes,
		postHashToModify,
		parentPostHashBytes,
		[]byte(body),
		nil,
		false,
		uint64(time.Now().UnixNano()),
		extraData,
		isHidden,
		feeRateNanosPerKB,
		nil, /*mempool*/
		[]*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, UpdaterPrivateKeyBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.GreaterOrEqual(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeSubmitPost operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeSubmitPost, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func TestSubmitPost(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true

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

	// We take the block tip to be the blockchain height rather than the
	// header chain height.
	savedHeight := chain.blockTip().Height + 1
	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPk))

		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, senderPk, recipientPk,
			senderPriv, 70 /*amount to send*/, 11 /*feerate*/)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// Fund all the keys.
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

	checkPostsDeleted := func() {
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		corePosts, commentsByPostHash, err := utxoView.GetAllPosts()
		require.NoError(err)
		require.Equal(4, len(corePosts))
		totalComments := 0
		for _, currentComment := range commentsByPostHash {
			totalComments += len(currentComment)
		}
		// 3 comments from seed txns
		require.Equal(3, totalComments)

		require.Equal(0, len(utxoView.RepostKeyToRepostEntry))

		// TODO: add checks that repost entries are deleted
	}
	checkPostsDeleted()

	updateProfile := func(
		feeRateNanosPerKB uint64, updaterPkBase58Check string,
		updaterPrivBase58Check string, profilePubKey []byte, newUsername string,
		newDescription string, newProfilePic string, newCreatorBasisPoints uint64,
		newStakeMultipleBasisPoints uint64, isHidden bool) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, updaterPkBase58Check))

		currentOps, currentTxn, _, err := _updateProfile(
			t, chain, db, params,
			feeRateNanosPerKB, updaterPkBase58Check,
			updaterPrivBase58Check, profilePubKey, newUsername,
			newDescription, newProfilePic, newCreatorBasisPoints,
			newStakeMultipleBasisPoints, isHidden)

		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}
	_, _, _ = m2Priv, m3Priv, updateProfile

	submitPost := func(
		feeRateNanosPerKB uint64, updaterPkBase58Check string,
		updaterPrivBase58Check string,
		postHashToModify []byte,
		parentStakeID []byte,
		body *DeSoBodySchema,
		repostedPostHash []byte,
		tstampNanos uint64,
		isHidden bool) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, updaterPkBase58Check))

		currentOps, currentTxn, _, err := _submitPost(
			t, chain, db, params, feeRateNanosPerKB,
			updaterPkBase58Check,
			updaterPrivBase58Check,
			postHashToModify,
			parentStakeID,
			body,
			repostedPostHash,
			tstampNanos,
			isHidden)

		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}
	_ = submitPost

	swapIdentity := func(
		feeRateNanosPerKB uint64, updaterPkBase58Check string,
		updaterPrivBase58Check string,
		fromPkBytes []byte,
		toPkBytes []byte) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, updaterPkBase58Check))

		currentOps, currentTxn, _, err := _swapIdentity(
			t, chain, db, params, feeRateNanosPerKB,
			updaterPkBase58Check,
			updaterPrivBase58Check,
			fromPkBytes, toPkBytes)

		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// Creating a post from an unregistered profile should succeed
	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m0Pub,    /*updaterPkBase58Check*/
			m0Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body 1 no profile"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Txn := txns[len(txns)-1]
	post1Hash := post1Txn.Hash()
	_, _ = post1Txn, post1Hash

	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m0Pub,    /*updaterPkBase58Check*/
			m0Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body 2 no profile"}, /*body*/
			[]byte{},
			1502947012*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post2Txn := txns[len(txns)-1]
	post2Hash := post2Txn.Hash()
	_, _ = post2Txn, post2Hash

	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m1Pub,    /*updaterPkBase58Check*/
			m1Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "m1 post body 1 no profile"}, /*body*/
			[]byte{},
			1502947013*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post3Txn := txns[len(txns)-1]
	post3Hash := post3Txn.Hash()
	_, _ = post3Txn, post3Hash

	// Creating a post from a registered profile should succeed
	{
		updateProfile(
			1,             /*feeRateNanosPerKB*/
			m2Pub,         /*updaterPkBase58Check*/
			m2Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m2",          /*newUsername*/
			"i am the m2", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)

		submitPost(
			10,       /*feeRateNanosPerKB*/
			m2Pub,    /*updaterPkBase58Check*/
			m2Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "m2 post body 1 WITH profile"}, /*body*/
			[]byte{},
			1502947014*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post4Txn := txns[len(txns)-1]
	post4Hash := post4Txn.Hash()
	_, _ = post4Txn, post4Hash

	{
		updateProfile(
			1,             /*feeRateNanosPerKB*/
			m3Pub,         /*updaterPkBase58Check*/
			m3Priv,        /*updaterPrivBase58Check*/
			[]byte{},      /*profilePubKey*/
			"m3",          /*newUsername*/
			"i am the m3", /*newDescription*/
			shortPic,      /*newProfilePic*/
			10*100,        /*newCreatorBasisPoints*/
			1.25*100*100,  /*newStakeMultipleBasisPoints*/
			false /*isHidden*/)

		submitPost(
			10,       /*feeRateNanosPerKB*/
			m3Pub,    /*updaterPkBase58Check*/
			m3Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "m3 post body 1 WITH profile"}, /*body*/
			[]byte{},
			1502947015*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post5Txn := txns[len(txns)-1]
	post5Hash := post5Txn.Hash()
	_, _ = post5Txn, post5Hash

	// Create another post for m2
	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m2Pub,    /*updaterPkBase58Check*/
			m2Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "m2 post body 2 WITH profile"}, /*body*/
			[]byte{},
			1502947016*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post6Txn := txns[len(txns)-1]
	post6Hash := post6Txn.Hash()
	_, _ = post6Txn, post6Hash

	// A zero input post should fail
	{
		_, _, _, err := _submitPost(
			t, chain, db, params,
			0,        /*feeRateNanosPerKB*/
			m0Pub,    /*updaterPkBase58Check*/
			m0Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "this is a post body"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorTxnMustHaveAtLeastOneInput)
	}

	// PostHashToModify with bad length
	{
		_, _, _, err := _submitPost(
			t, chain, db, params,
			10,                           /*feeRateNanosPerKB*/
			m0Pub,                        /*updaterPkBase58Check*/
			m0Priv,                       /*updaterPrivBase58Check*/
			RandomBytes(HashSizeBytes-1), /*postHashToModify*/
			[]byte{},                     /*parentStakeID*/
			&DeSoBodySchema{Body: "this is a post body"}, /*body*/
			[]byte{},
			1502947048*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostInvalidPostHashToModify)
	}

	// Setting PostHashToModify should fail for a non-existent post
	{
		_, _, _, err := _submitPost(
			t, chain, db, params,
			10,                         /*feeRateNanosPerKB*/
			m0Pub,                      /*updaterPkBase58Check*/
			m0Priv,                     /*updaterPrivBase58Check*/
			RandomBytes(HashSizeBytes), /*postHashToModify*/
			[]byte{},                   /*parentStakeID*/
			&DeSoBodySchema{Body: "this is a post body"}, /*body*/
			[]byte{},
			1502947048*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostModifyingNonexistentPost)
	}

	// Bad length for parent stake id should fail
	{
		_, _, _, err := _submitPost(
			t, chain, db, params,
			10,                           /*feeRateNanosPerKB*/
			m0Pub,                        /*updaterPkBase58Check*/
			m0Priv,                       /*updaterPrivBase58Check*/
			[]byte{},                     /*postHashToModify*/
			RandomBytes(HashSizeBytes-1), /*parentStakeID*/
			&DeSoBodySchema{Body: "this is a post body"}, /*body*/
			[]byte{},
			1502947048*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostInvalidParentStakeIDLength)
	}

	// Non-owner modifying post should fail
	{
		_, _, _, err := _submitPost(
			t, chain, db, params,
			10,           /*feeRateNanosPerKB*/
			m1Pub,        /*updaterPkBase58Check*/
			m1Priv,       /*updaterPrivBase58Check*/
			post1Hash[:], /*postHashToModify*/
			[]byte{},     /*parentStakeID*/
			&DeSoBodySchema{Body: "this is a post body"}, /*body*/
			[]byte{},
			1502947048*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostPostModificationNotAuthorized)
	}

	// Zero timestamp should fail
	{
		_, _, _, err = _submitPost(
			t, chain, db, params,
			10,       /*feeRateNanosPerKB*/
			m1Pub,    /*updaterPkBase58Check*/
			m1Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "this is a post body"}, /*body*/
			[]byte{},
			0, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostTimestampIsZero)
	}

	// User without profile modifying another user without profile's post
	// should fail
	{
		_, _, _, err = _submitPost(
			t, chain, db, params,
			10,     /*feeRateNanosPerKB*/
			m0Pub,  /*updaterPkBase58Check*/
			m0Priv, /*updaterPrivBase58Check*/
			// this belongs to m1 who doesn't have a profile.
			post3Hash[:],                            /*postHashToModify*/
			RandomBytes(HashSizeBytes),              /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body 2"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostPostModificationNotAuthorized)
	}

	// User WITH profile modifying another user without profile's post
	// should fail
	{
		_, _, _, err = _submitPost(
			t, chain, db, params,
			10,     /*feeRateNanosPerKB*/
			m2Pub,  /*updaterPkBase58Check*/
			m2Priv, /*updaterPrivBase58Check*/
			// this belongs to m1 who doesn't have a profile.
			post1Hash[:],                            /*postHashToModify*/
			RandomBytes(HashSizeBytes),              /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body 2"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostPostModificationNotAuthorized)
	}

	// User without profile modifying another user WITH profile's post
	// should fail
	{
		_, _, _, err = _submitPost(
			t, chain, db, params,
			10,     /*feeRateNanosPerKB*/
			m0Pub,  /*updaterPkBase58Check*/
			m0Priv, /*updaterPrivBase58Check*/
			// this belongs to m1 who doesn't have a profile.
			post4Hash[:],                            /*postHashToModify*/
			RandomBytes(HashSizeBytes),              /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body 2"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostPostModificationNotAuthorized)
	}

	// User WITH profile modifying another user WITH profile's post
	// should fail
	{
		_, _, _, err = _submitPost(
			t, chain, db, params,
			10,     /*feeRateNanosPerKB*/
			m2Pub,  /*updaterPkBase58Check*/
			m2Priv, /*updaterPrivBase58Check*/
			// this belongs to m1 who doesn't have a profile.
			post5Hash[:],                            /*postHashToModify*/
			RandomBytes(HashSizeBytes),              /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body 2"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostPostModificationNotAuthorized)
	}

	// Owner without profile modifying post should succeed but all the non-body fields
	// should be ignored.
	{
		submitPost(
			10,                         /*feeRateNanosPerKB*/
			m0Pub,                      /*updaterPkBase58Check*/
			m0Priv,                     /*updaterPrivBase58Check*/
			post1Hash[:],               /*postHashToModify*/
			RandomBytes(HashSizeBytes), /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body MODIFIED"}, /*body*/
			[]byte{},
			1502947017*1e9, /*tstampNanos*/
			true /*isHidden*/)
	}

	// Owner with profile modifying one of their posts should succeed but
	// all non-body posts should be unchanged.
	{
		submitPost(
			10,                         /*feeRateNanosPerKB*/
			m2Pub,                      /*updaterPkBase58Check*/
			m2Priv,                     /*updaterPrivBase58Check*/
			post4Hash[:],               /*postHashToModify*/
			RandomBytes(HashSizeBytes), /*parentStakeID*/
			&DeSoBodySchema{Body: "m2 post body MODIFIED"}, /*body*/
			[]byte{},
			1502947018*1e9, /*tstampNanos*/
			true /*isHidden*/)
	}

	// ParamUpdater modifying their own post should succeed
	{
		submitPost(
			10,                         /*feeRateNanosPerKB*/
			m3Pub,                      /*updaterPkBase58Check*/
			m3Priv,                     /*updaterPrivBase58Check*/
			post5Hash[:],               /*postHashToModify*/
			RandomBytes(HashSizeBytes), /*parentStakeID*/
			&DeSoBodySchema{Body: "paramUpdater post body MODIFIED"}, /*body*/
			[]byte{},
			1502947019*1e9, /*tstampNanos*/
			true /*isHidden*/)
	}

	// Modifying a post and then modifying it back should work.
	{
		submitPost(
			10,                         /*feeRateNanosPerKB*/
			m1Pub,                      /*updaterPkBase58Check*/
			m1Priv,                     /*updaterPrivBase58Check*/
			post3Hash[:],               /*postHashToModify*/
			RandomBytes(HashSizeBytes), /*parentStakeID*/
			&DeSoBodySchema{Body: "sldkfjlskdfjlajflkasjdflkasjdf"}, /*body*/
			[]byte{},
			1502947022*1e9, /*tstampNanos*/
			true /*isHidden*/)
		submitPost(
			10,                         /*feeRateNanosPerKB*/
			m1Pub,                      /*updaterPkBase58Check*/
			m1Priv,                     /*updaterPrivBase58Check*/
			post3Hash[:],               /*postHashToModify*/
			RandomBytes(HashSizeBytes), /*parentStakeID*/
			&DeSoBodySchema{Body: "m1 post body 1 no profile modified back"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}

	// Comment on a post with an anonymous public key
	{
		submitPost(
			10,           /*feeRateNanosPerKB*/
			m0Pub,        /*updaterPkBase58Check*/
			m0Priv,       /*updaterPrivBase58Check*/
			[]byte{},     /*postHashToModify*/
			post3Hash[:], /*parentStakeID*/
			&DeSoBodySchema{Body: "comment 1 from m0 on post3"}, /*body*/
			[]byte{},
			1502947001*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment1Txn := txns[len(txns)-1]
	comment1Hash := comment1Txn.Hash()

	// Make a few more comments.
	{
		submitPost(
			10,           /*feeRateNanosPerKB*/
			m0Pub,        /*updaterPkBase58Check*/
			m0Priv,       /*updaterPrivBase58Check*/
			[]byte{},     /*postHashToModify*/
			post6Hash[:], /*parentStakeID*/
			&DeSoBodySchema{Body: "comment 2 from m0 on post3"}, /*body*/
			[]byte{},
			1502947002*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment2CreatedTxnIndex := len(txns) - 1
	comment2Txn := txns[comment2CreatedTxnIndex]
	comment2Hash := comment2Txn.Hash()

	{
		submitPost(
			10,           /*feeRateNanosPerKB*/
			m2Pub,        /*updaterPkBase58Check*/
			m2Priv,       /*updaterPrivBase58Check*/
			[]byte{},     /*postHashToModify*/
			post6Hash[:], /*parentStakeID*/
			&DeSoBodySchema{Body: "comment 1 from m2 on post6"}, /*body*/
			[]byte{},
			1502947003*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment3CreatedTxnIndex := len(txns) - 1
	comment3Txn := txns[comment3CreatedTxnIndex]
	comment3Hash := comment3Txn.Hash()

	{
		submitPost(
			10,           /*feeRateNanosPerKB*/
			m3Pub,        /*updaterPkBase58Check*/
			m3Priv,       /*updaterPrivBase58Check*/
			[]byte{},     /*postHashToModify*/
			post6Hash[:], /*parentStakeID*/
			&DeSoBodySchema{Body: "comment 1 from m3 on post6"}, /*body*/
			[]byte{},
			1502947004*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment4CreatedTxnIndex := len(txns) - 1
	comment4Txn := txns[comment4CreatedTxnIndex]
	comment4Hash := comment4Txn.Hash()

	// Modify some comments
	var comment3HiddenTxnIndex int
	{
		// Modifying the comment with the wrong pub should fail.
		_, _, _, err = _submitPost(
			t, chain, db, params,
			10,              /*feeRateNanosPerKB*/
			m1Pub,           /*updaterPkBase58Check*/
			m1Priv,          /*updaterPrivBase58Check*/
			comment1Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "modifying comment 1 by m1 should fail"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostPostModificationNotAuthorized)

		// Modifying the comment with the proper key should work.
		submitPost(
			10,              /*feeRateNanosPerKB*/
			m0Pub,           /*updaterPkBase58Check*/
			m0Priv,          /*updaterPrivBase58Check*/
			comment1Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "comment from m0 on post3 MODIFIED"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)

		// Modifying the comment with the proper key should work.
		submitPost(
			10,              /*feeRateNanosPerKB*/
			m2Pub,           /*updaterPkBase58Check*/
			m2Priv,          /*updaterPrivBase58Check*/
			comment3Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "comment from m2 on post6 MODIFIED"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			true /*isHidden*/)
		comment3HiddenTxnIndex = len(txns) - 1

		// Modify a comment and modify it back.
		submitPost(
			10,              /*feeRateNanosPerKB*/
			m0Pub,           /*updaterPkBase58Check*/
			m0Priv,          /*updaterPrivBase58Check*/
			comment2Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "comment from m0 on post3 MODIFIED"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			true /*isHidden*/)
		submitPost(
			10,              /*feeRateNanosPerKB*/
			m0Pub,           /*updaterPkBase58Check*/
			m0Priv,          /*updaterPrivBase58Check*/
			comment2Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "comment 2 from m0 on post3"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}

	// Commenting on a public key should work regardless of whether
	// a profile actually exists for that stake ID.
	{
		submitPost(
			10,        /*feeRateNanosPerKB*/
			m0Pub,     /*updaterPkBase58Check*/
			m0Priv,    /*updaterPrivBase58Check*/
			[]byte{},  /*postHashToModify*/
			m1PkBytes, /*parentStakeID*/
			&DeSoBodySchema{Body: "comment m0 on profile m1 [1]"}, /*body*/
			[]byte{},
			1502947005*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment5Txn := txns[len(txns)-1]
	comment5Hash := comment5Txn.Hash()
	{
		submitPost(
			10,        /*feeRateNanosPerKB*/
			m1Pub,     /*updaterPkBase58Check*/
			m1Priv,    /*updaterPrivBase58Check*/
			[]byte{},  /*postHashToModify*/
			m2PkBytes, /*parentStakeID*/
			&DeSoBodySchema{Body: "comment m1 on profile m2 [1]"}, /*body*/
			[]byte{},
			1502947006*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment6Txn := txns[len(txns)-1]
	comment6Hash := comment6Txn.Hash()
	{
		submitPost(
			10,        /*feeRateNanosPerKB*/
			m3Pub,     /*updaterPkBase58Check*/
			m3Priv,    /*updaterPrivBase58Check*/
			[]byte{},  /*postHashToModify*/
			m3PkBytes, /*parentStakeID*/
			&DeSoBodySchema{Body: "comment m3 on profile m3 [1]"}, /*body*/
			[]byte{},
			1502947007*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment7Txn := txns[len(txns)-1]
	comment7Hash := comment7Txn.Hash()
	{
		submitPost(
			10,        /*feeRateNanosPerKB*/
			m0Pub,     /*updaterPkBase58Check*/
			m0Priv,    /*updaterPrivBase58Check*/
			[]byte{},  /*postHashToModify*/
			m3PkBytes, /*parentStakeID*/
			&DeSoBodySchema{Body: "comment m0 on profile m3 [2]"}, /*body*/
			[]byte{},
			1502947008*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	comment8Txn := txns[len(txns)-1]
	comment8Hash := comment8Txn.Hash()

	// Modifying the profile comments should work when the key is authorized
	// and fail when it's not.
	{
		submitPost(
			10,              /*feeRateNanosPerKB*/
			m0Pub,           /*updaterPkBase58Check*/
			m0Priv,          /*updaterPrivBase58Check*/
			comment5Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "comment 1 from m0 on post3 MODIFIED"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			true /*isHidden*/)

		_, _, _, err = _submitPost(
			t, chain, db, params,
			10,              /*feeRateNanosPerKB*/
			m1Pub,           /*updaterPkBase58Check*/
			m1Priv,          /*updaterPrivBase58Check*/
			comment5Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "modifying comment 1 by m1 should fail"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorSubmitPostPostModificationNotAuthorized)

		// Modify a profile comment then modify it back.
		submitPost(
			10,              /*feeRateNanosPerKB*/
			m1Pub,           /*updaterPkBase58Check*/
			m1Priv,          /*updaterPrivBase58Check*/
			comment6Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "comment m1 on profile m2 [1] MODIFIED"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			true /*isHidden*/)
		submitPost(
			10,              /*feeRateNanosPerKB*/
			m1Pub,           /*updaterPkBase58Check*/
			m1Priv,          /*updaterPrivBase58Check*/
			comment6Hash[:], /*postHashToModify*/
			[]byte{},        /*parentStakeID*/
			&DeSoBodySchema{Body: "comment m1 on profile m2 [1]"}, /*body*/
			[]byte{},
			1502947049*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}

	// Reposting tests
	// repost 1 - vanilla repost
	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m1Pub,    /*updaterPkBase58Check*/
			m1Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{},
			post3Hash[:],
			15029557050*1e9, /*tstampNanos*/
			false /*isHidden*/)

	}
	repost1Txn := txns[len(txns)-1]
	repost1Hash := repost1Txn.Hash()
	_, _ = repost1Txn, repost1Hash
	// repost 2 - vanilla repost + hide
	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m1Pub,    /*updaterPkBase58Check*/
			m1Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{},
			post4Hash[:],
			15029557051*1e9, /*tstampNanos*/
			false /*isHidden*/)
		repost2Txn := txns[len(txns)-1]
		repost2Hash := repost2Txn.Hash()
		submitPost(
			10,             /*feeRateNanosPerKB*/
			m1Pub,          /*updaterPkBase58Check*/
			m1Priv,         /*updaterPrivBase58Check*/
			repost2Hash[:], /*postHashToModify*/
			[]byte{},       /*parentStakeID*/
			&DeSoBodySchema{},
			post4Hash[:],
			15029557052*1e9, /*tstampNanos*/
			true /*isHidden*/)
	}
	// repost 3 - Quote Repost
	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m1Pub,    /*updaterPkBase58Check*/
			m1Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "quote-post"},
			post5Hash[:],
			15029557053*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	// repost 4 - Quote Repost + hide
	{
		submitPost(
			10,       /*feeRateNanosPerKB*/
			m1Pub,    /*updaterPkBase58Check*/
			m1Priv,   /*updaterPrivBase58Check*/
			[]byte{}, /*postHashToModify*/
			[]byte{}, /*parentStakeID*/
			&DeSoBodySchema{Body: "quote-post-hide-me"},
			post6Hash[:],
			15029557054*1e9, /*tstampNanos*/
			false /*isHidden*/)
		repost4Txn := txns[len(txns)-1]
		repost4hash := repost4Txn.Hash()
		submitPost(
			10,             /*feeRateNanosPerKB*/
			m1Pub,          /*updaterPkBase58Check*/
			m1Priv,         /*updaterPrivBase58Check*/
			repost4hash[:], /*postHashToModify*/
			[]byte{},       /*parentStakeID*/
			&DeSoBodySchema{Body: "quote-post-hide-me"},
			post6Hash[:],
			15029557054*1e9, /*tstampNanos*/
			true /*isHidden*/)
	}
	// repost -- test exceptions
	{
		{
			// Reposting a post that doesn't exist will raise an error.
			_, _, _, err = _submitPost(t, chain, db, params,
				10,
				m1Pub,
				m1Priv,
				[]byte{},
				[]byte{},
				&DeSoBodySchema{},
				[]byte{1, 2, 3},
				15029557055,
				false,
			)
			require.Error(err)
			require.Contains(err.Error(), RuleErrorSubmitPostRepostPostNotFound)
		}
		{
			// Cannot repost a vanilla repost
			_, _, _, err = _submitPost(t, chain, db, params,
				10,
				m1Pub,
				m1Priv,
				[]byte{},
				[]byte{},
				&DeSoBodySchema{},
				repost1Hash[:],
				15029557055,
				false,
			)
			require.Error(err)
			require.Contains(err.Error(), RuleErrorSubmitPostRepostOfRepost)
		}
		{
			// Cannot update the repostedPostHashHex
			_, _, _, err = _submitPost(t, chain, db, params,
				10,
				m1Pub,
				m1Priv,
				repost1Hash[:],
				[]byte{},
				&DeSoBodySchema{},
				post4Hash[:],
				15029557055,
				false,
			)
			require.Error(err)
			require.Contains(err.Error(), RuleErrorSubmitPostUpdateRepostHash)
		}

	}

	// Swapping the identity of m0 and m1 should not result in any issues.
	// TODO: This will no longer be the case once posts are a part of the PKID
	// infrastructure.
	swapIdentity(
		10,    /*feeRateNanosPerKB*/
		m3Pub, // m3 is paramUpdater for this test.
		m3Priv,
		m0PkBytes,
		m1PkBytes)

	// post1: m0 post body MODIFIED
	// post2: paramUpdater post body MODIFIED
	// post3: m1 post body 1 no profile modified back (isHidden = false)
	// post4: m2 post body MODIFIED
	// post5: paramUpdater post body MODIFIED
	// post6: paramUpdater m2 post body MODIFIED
	// comment1: m0 comment from m0 on post3 MODIFIED
	// comment2: m0 comment 2 from m0 on post3
	// comment3: comment from m2 on post6 MODIFIED (isHidden = true)
	// comment4: m3 comment 1 from m3 on post6
	// comment5: comment 1 from m0 on post3 MODIFIED
	// comment6: m1 comment m1 on profile m2 [1]
	// comment7: m3 comment m3 on profile m3 [1]
	// comment8: m0 comment m0 on profile m3 [2]
	// Comments for post3
	// - comment1
	// Comments for post6
	// - comment2, comment3, comment4
	// Coomments for m1
	// - comment5
	// Comments profile m2
	// - comment6
	// Comments profile m3
	// - comment7, comment8
	// - repost1
	// Reposts post3
	// - repost 2
	// reposts post4 and then hides itself -- test RepostCount
	// - repost 3
	// quote repost post 5
	// - repost 4
	// quote repost post 6 and then hides itself

	comparePostBody := func(postEntry *PostEntry, message string, repostPostHash *BlockHash) {
		bodyJSONObj := &DeSoBodySchema{}
		err := json.Unmarshal(postEntry.Body, bodyJSONObj)
		require.NoError(err)
		require.Equal(message, bodyJSONObj.Body)
		if repostPostHash != nil {
			require.Equal(repostPostHash, postEntry.RepostedPostHash)
		}
	}

	checkPostsExist := func() {
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		corePosts, commentsByPostHash, err := utxoView.GetAllPosts()
		require.NoError(err)
		// 4 posts from seed txns
		require.Equal(14, len(corePosts))

		totalComments := 0
		for _, currentComment := range commentsByPostHash {
			totalComments += len(currentComment)
		}
		// 3 comments from seed txns
		require.Equal(11, totalComments)

		// post3 should have 1 comment
		{
			commentsForPost, exists := commentsByPostHash[*post3Hash]
			require.True(exists)
			require.Equal(1, len(commentsForPost))

			require.Equal(m0PkBytes, commentsForPost[0].PosterPublicKey)
			require.Equal(post3Hash[:], commentsForPost[0].ParentStakeID)
			require.Equal(*comment1Hash, *commentsForPost[0].PostHash)
			comparePostBody(commentsForPost[0], "comment from m0 on post3 MODIFIED", nil)
			require.Equal(false, commentsForPost[0].IsHidden)

			post3 := findPostByPostHash(corePosts, post3Hash)
			require.Equal(uint64(1), post3.CommentCount)
		}
		// post6 should have 3 comments
		{
			commentsForPost, err := commentsByPostHash[*post6Hash]
			require.True(err)
			require.Equal(3, len(commentsForPost))

			require.Equal(m0PkBytes, commentsForPost[0].PosterPublicKey)
			require.Equal(post6Hash[:], commentsForPost[0].ParentStakeID)
			require.Equal(*comment2Hash, *commentsForPost[0].PostHash)
			comparePostBody(commentsForPost[0], "comment 2 from m0 on post3", nil)
			require.Equal(false, commentsForPost[0].IsHidden)

			require.Equal(m2PkBytes, commentsForPost[1].PosterPublicKey)
			require.Equal(post6Hash[:], commentsForPost[1].ParentStakeID)
			require.Equal(*comment3Hash, *commentsForPost[1].PostHash)
			comparePostBody(commentsForPost[1], "comment from m2 on post6 MODIFIED", nil)
			require.Equal(true, commentsForPost[1].IsHidden)

			require.Equal(m3PkBytes, commentsForPost[2].PosterPublicKey)
			require.Equal(post6Hash[:], commentsForPost[2].ParentStakeID)
			require.Equal(*comment4Hash, *commentsForPost[2].PostHash)
			comparePostBody(commentsForPost[2], "comment 1 from m3 on post6", nil)
			require.Equal(false, commentsForPost[2].IsHidden)

			// Two comments are not hidden, so commentCount should be 2
			post6 := findPostByPostHash(corePosts, post6Hash)
			require.Equal(uint64(2), post6.CommentCount)
		}
		// m1 should have 1 comment
		{
			commentsForPost, err := commentsByPostHash[*NewBlockHash(m1PkBytes)]
			require.True(err)
			require.Equal(1, len(commentsForPost))

			require.Equal(m0PkBytes, commentsForPost[0].PosterPublicKey)
			require.Equal(m1PkBytes[:], commentsForPost[0].ParentStakeID)
			require.Equal(*comment5Hash, *commentsForPost[0].PostHash)
			comparePostBody(commentsForPost[0], "comment 1 from m0 on post3 MODIFIED", nil)
			require.Equal(true, commentsForPost[0].IsHidden)
		}
		// m2 should have 1 comment
		{
			commentsForPost, err := commentsByPostHash[*NewBlockHash(m2PkBytes)]
			require.True(err)
			require.Equal(1, len(commentsForPost))

			require.Equal(m1PkBytes, commentsForPost[0].PosterPublicKey)
			require.Equal(m2PkBytes[:], commentsForPost[0].ParentStakeID)
			require.Equal(*comment6Hash, *commentsForPost[0].PostHash)
			comparePostBody(commentsForPost[0], "comment m1 on profile m2 [1]", nil)
			require.Equal(false, commentsForPost[0].IsHidden)
		}
		// m3 should have 2 comments
		{
			commentsForPost, err := commentsByPostHash[*NewBlockHash(m3PkBytes)]
			require.True(err)
			require.Equal(2, len(commentsForPost))

			require.Equal(m3PkBytes, commentsForPost[0].PosterPublicKey)
			require.Equal(m3PkBytes[:], commentsForPost[0].ParentStakeID)
			require.Equal(*comment7Hash, *commentsForPost[0].PostHash)
			comparePostBody(commentsForPost[0], "comment m3 on profile m3 [1]", nil)
			require.Equal(false, commentsForPost[0].IsHidden)

			require.Equal(m0PkBytes, commentsForPost[1].PosterPublicKey)
			require.Equal(m3PkBytes[:], commentsForPost[1].ParentStakeID)
			require.Equal(*comment8Hash, *commentsForPost[1].PostHash)
			comparePostBody(commentsForPost[1], "comment m0 on profile m3 [2]", nil)
			require.Equal(false, commentsForPost[1].IsHidden)
		}

		sort.Slice(corePosts, func(ii, jj int) bool {
			return corePosts[ii].TimestampNanos < corePosts[jj].TimestampNanos
		})

		{
			require.Equal(m0PkBytes, corePosts[0].PosterPublicKey)
			comparePostBody(corePosts[0], "m0 post body MODIFIED", nil)
			require.Equal(true, corePosts[0].IsHidden)
			require.Equal(int64(10*100), int64(corePosts[0].CreatorBasisPoints))
			require.Equal(int64(1.25*100*100), int64(corePosts[0].StakeMultipleBasisPoints))
		}
		{
			require.Equal(m0PkBytes, corePosts[1].PosterPublicKey)
			comparePostBody(corePosts[1], "m0 post body 2 no profile", nil)
			require.Equal(false, corePosts[1].IsHidden)
			require.Equal(int64(10*100), int64(corePosts[1].CreatorBasisPoints))
			require.Equal(int64(1.25*100*100), int64(corePosts[1].StakeMultipleBasisPoints))
		}
		{
			require.Equal(m1PkBytes, corePosts[2].PosterPublicKey)
			comparePostBody(corePosts[2], "m1 post body 1 no profile modified back", nil)
			require.Equal(false, corePosts[2].IsHidden)
			require.Equal(int64(10*100), int64(corePosts[2].CreatorBasisPoints))
			require.Equal(int64(1.25*100*100), int64(corePosts[2].StakeMultipleBasisPoints))
			require.Equal(int64(1), int64(corePosts[2].RepostCount))
		}
		{
			require.Equal(m2PkBytes, corePosts[3].PosterPublicKey)
			comparePostBody(corePosts[3], "m2 post body MODIFIED", nil)
			require.Equal(true, corePosts[3].IsHidden)
			require.Equal(int64(10*100), int64(corePosts[3].CreatorBasisPoints))
			require.Equal(int64(1.25*100*100), int64(corePosts[3].StakeMultipleBasisPoints))
			require.Equal(int64(0), int64(corePosts[3].RepostCount))
		}
		{
			require.Equal(m3PkBytes, corePosts[4].PosterPublicKey)
			comparePostBody(corePosts[4], "paramUpdater post body MODIFIED", nil)
			require.Equal(true, corePosts[4].IsHidden)
			require.Equal(int64(10*100), int64(corePosts[4].CreatorBasisPoints))
			require.Equal(int64(1.25*100*100), int64(corePosts[4].StakeMultipleBasisPoints))
			// Quote desos do not count towards repost count
			require.Equal(int64(0), int64(corePosts[4].RepostCount))
		}
		{
			require.Equal(m2PkBytes, corePosts[5].PosterPublicKey)
			comparePostBody(corePosts[5], "m2 post body 2 WITH profile", nil)
			require.Equal(false, corePosts[5].IsHidden)
			require.Equal(int64(10*100), int64(corePosts[5].CreatorBasisPoints))
			require.Equal(int64(1.25*100*100), int64(corePosts[5].StakeMultipleBasisPoints))
			// Quote desos do not count towards repost count
			require.Equal(int64(0), int64(corePosts[5].RepostCount))
		}
		{
			require.Equal(m1PkBytes, corePosts[10].PosterPublicKey)
			comparePostBody(corePosts[10], "", corePosts[2].PostHash)
			require.Equal(false, corePosts[10].IsHidden)
			m1Post2ReaderState := utxoView.GetPostEntryReaderState(m1PkBytes, corePosts[2])
			require.Equal(m1Post2ReaderState.RepostedByReader, true)
			require.Equal(m1Post2ReaderState.RepostPostHashHex, hex.EncodeToString(corePosts[10].PostHash[:]))
			// Make sure the utxoView has the correct repost entry mapping
			require.Equal(utxoView.RepostKeyToRepostEntry[MakeRepostKey(m1PkBytes, *corePosts[2].PostHash)],
				&RepostEntry{
					ReposterPubKey:   m1PkBytes,
					RepostedPostHash: corePosts[2].PostHash,
					RepostPostHash:   corePosts[10].PostHash,
				})
		}
		{
			require.Equal(m1PkBytes, corePosts[11].PosterPublicKey)
			comparePostBody(corePosts[11], "", corePosts[3].PostHash)
			require.Equal(true, corePosts[11].IsHidden)
			m1Post3ReaderState := utxoView.GetPostEntryReaderState(m1PkBytes, corePosts[3])
			// If we hide the repost, we expect RepostedByReader to be false, but RepostPostHashHex to still be set.
			require.Equal(m1Post3ReaderState.RepostedByReader, false)
			require.Equal(m1Post3ReaderState.RepostPostHashHex, hex.EncodeToString(corePosts[11].PostHash[:]))
			// Make sure the utxoView has the correct repost entry mapping
			require.Equal(utxoView.RepostKeyToRepostEntry[MakeRepostKey(m1PkBytes, *corePosts[3].PostHash)],
				&RepostEntry{
					ReposterPubKey:   m1PkBytes,
					RepostedPostHash: corePosts[3].PostHash,
					RepostPostHash:   corePosts[11].PostHash,
				})
		}
		{
			require.Equal(m1PkBytes, corePosts[12].PosterPublicKey)
			comparePostBody(corePosts[12], "quote-post", corePosts[4].PostHash)
			require.Equal(false, corePosts[12].IsHidden)
			m1Post4ReaderState := utxoView.GetPostEntryReaderState(m1PkBytes, corePosts[4])
			// Quote reposts do not impact PostEntryReaderState
			require.Equal(m1Post4ReaderState.RepostedByReader, false)
			require.Equal(m1Post4ReaderState.RepostPostHashHex, "")
			// Quote reposts do not make repost entry mappings
			_, repostEntryExists := utxoView.RepostKeyToRepostEntry[MakeRepostKey(m1PkBytes, *corePosts[4].PostHash)]
			require.False(repostEntryExists)
		}
		{
			require.Equal(m1PkBytes, corePosts[13].PosterPublicKey)
			comparePostBody(corePosts[13], "quote-post-hide-me", corePosts[5].PostHash)
			require.Equal(true, corePosts[13].IsHidden)
			m1Post5ReaderState := utxoView.GetPostEntryReaderState(m1PkBytes, corePosts[5])
			// Quote reposts do not impact PostEntryReaderState
			require.Equal(m1Post5ReaderState.RepostedByReader, false)
			require.Equal(m1Post5ReaderState.RepostPostHashHex, "")
			// Quote reposts do not make repost entry mappings
			_, repostEntryExists := utxoView.RepostKeyToRepostEntry[MakeRepostKey(m1PkBytes, *corePosts[5].PostHash)]
			require.False(repostEntryExists)
		}
	}
	checkPostsExist()

	// ===================================================================================
	// Finish it off with some transactions
	// ===================================================================================
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]
		fmt.Printf("Disconnecting transaction with type %v index %d (going backwards)\n", currentTxn.TxnMeta.GetTxnType(), backwardIter)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(expectedSenderBalances[backwardIter], _getBalance(t, chain, nil, PkToStringTestnet(currentTxn.PublicKey)))
	}

	// Verify that all the profiles have been deleted.
	checkPostsDeleted()

	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	for ii, tx := range txns {
		// See comment above on this transaction.
		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		require.Equal(expectedSenderBalances[ii], _getBalance(t, chain, mempool, PkToStringTestnet(tx.PublicKey)))

		_, err := mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}

	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii, txn := range txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Assert "before" comment counts are correct at a few different spots
		if ii == comment2CreatedTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 0)
		}
		if ii == comment3CreatedTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 1)
		}
		if ii == comment4CreatedTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 2)
		}
		if ii == comment3HiddenTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 3)
		}

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.NoError(err)

		// Assert "after" comment counts are correct at a few different spots
		if ii == comment2CreatedTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 1)
		}
		if ii == comment3CreatedTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 2)
		}
		if ii == comment4CreatedTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 3)
		}
		if ii == comment3HiddenTxnIndex {
			assertCommentCount(utxoView, require, post6Hash, 2)
		}
	}
	// Flush the utxoView after having added all the transactions.
	require.NoError(utxoView.FlushToDb())

	// Verify the profiles exist.
	checkPostsExist()

	// Disonnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView2, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		// Assert "before" comment counts are correct at a few different spots
		if backwardIter == comment3HiddenTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 2)
		}
		if backwardIter == comment4CreatedTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 3)
		}
		if backwardIter == comment3CreatedTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 2)
		}
		if backwardIter == comment2CreatedTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 1)
		}

		currentHash := currentTxn.Hash()
		err = utxoView2.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		// Assert "after" comment counts are correct at a few different spots
		if backwardIter == comment3HiddenTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 3)
		}
		if backwardIter == comment4CreatedTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 2)
		}
		if backwardIter == comment3CreatedTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 1)
		}
		if backwardIter == comment2CreatedTxnIndex {
			assertCommentCount(utxoView2, require, post6Hash, 0)
		}
	}
	require.NoError(utxoView2.FlushToDb())
	require.Equal(expectedSenderBalances[0], _getBalance(t, chain, nil, senderPkString))

	// Verify that all the profiles have been deleted.
	checkPostsDeleted()

	// All the txns should be in the mempool already so mining a block should put
	// all those transactions in it.
	block, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(len(txnOps)+1, len(block.Txns))

	// Roll back the block and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := block.Header.Hash()
		require.NoError(err)
		utxoOps, err := GetUtxoOperationsForBlock(db, hash)
		require.NoError(err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(block.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(block, txHashes, utxoOps))

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
	}

	// Verify that all the profiles have been deleted.
	checkPostsDeleted()
}

func assertCommentCount(utxoView *UtxoView, require *require.Assertions, postHash *BlockHash,
	expectedCommentCount int) {
	corePosts, _, err := utxoView.GetAllPosts()
	require.NoError(err)

	post := findPostByPostHash(corePosts, postHash)
	require.Equal(uint64(expectedCommentCount), post.CommentCount)
}

func findPostByPostHash(posts []*PostEntry, targetPostHash *BlockHash) (_targetPost *PostEntry) {
	var targetPost *PostEntry
	for _, post := range posts {
		if reflect.DeepEqual(post.PostHash, targetPostHash) {
			targetPost = post
			break
		}
	}
	return targetPost
}

func TestDeSoDiamonds(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3, m4 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true
	params.ParamUpdaterPublicKeys[MakePkMapKey(m4PkBytes)] = true
	params.ForkHeights.DeSoDiamondsBlockHeight = 0
	diamondValueMap := GetDeSoNanosDiamondLevelMapAtBlockHeight(0)


	// Mine a few blocks to give the senderPkString some money.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	// We build the testMeta obj after mining blocks so that we save the correct block height.
	testMeta := &TestMeta{
		t:           t,
		chain:       chain,
		params:      params,
		db:          db,
		mempool:     mempool,
		miner:       miner,
		savedHeight: chain.blockTip().Height + 1,
	}

	// Fund all the keys.
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 1000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 1000000000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m2Pub, senderPrivString, 1000000000)

	// Get PKIDs for looking up diamond entries.
	m0PkBytes, _, err := Base58CheckDecode(m0Pub)
	require.NoError(err)
	m0PKID := DBGetPKIDEntryForPublicKey(db, m0PkBytes)

	m1PkBytes, _, err := Base58CheckDecode(m1Pub)
	require.NoError(err)
	m1PKID := DBGetPKIDEntryForPublicKey(db, m1PkBytes)

	m2PkBytes, _, err := Base58CheckDecode(m2Pub)
	require.NoError(err)
	m2PKID := DBGetPKIDEntryForPublicKey(db, m2PkBytes)
	_ = m2PKID

	validateDiamondEntry := func(
		senderPKID *PKID, receiverPKID *PKID, diamondPostHash *BlockHash, diamondLevel int64) {

		diamondEntry := DbGetDiamondMappings(db, receiverPKID, senderPKID, diamondPostHash)

		if diamondEntry == nil && diamondLevel > 0 {
			t.Errorf("validateDiamondEntry: couldn't find diamond entry for diamondLevel %d", diamondLevel)
		} else if diamondEntry == nil && diamondLevel == 0 {
			// If diamondLevel is set to zero, we are checking that diamondEntry is nil.
			return
		}

		require.Equal(diamondEntry.DiamondLevel, diamondLevel)
	}

	// Create a post for testing.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-1].Hash()
	_ = post1Hash

	// Have m1 give the post a diamond.
	{
		// Balances before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999), m0BalBeforeNFT)
		m1BalBeforeNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 0)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 1)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 1)

		// Balances after.
		m0BalAfterNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[1]), m0BalAfterNFT)
		m1BalAfterNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[1]-2), m1BalAfterNFT)
	}

	// Upgrade the post from 1 -> 2 diamonds.
	{
		// Balances before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[1]), m0BalBeforeNFT)
		m1BalBeforeNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[1]-2), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 1)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 2)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 2)

		// Balances after.
		m0BalAfterNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[2]), m0BalAfterNFT)
		m1BalAfterNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[2]-4), m1BalAfterNFT)
	}

	// Upgrade the post from 2 -> 3 diamonds.
	{
		// Balances before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[2]), m0BalBeforeNFT)
		m1BalBeforeNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[2]-4), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 2)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 3)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 3)

		// Balances after.
		m0BalAfterNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[3]), m0BalAfterNFT)
		m1BalAfterNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[3]-6), m1BalAfterNFT)
	}

	// Upgrade the post from 3 -> 4 diamonds.
	{
		// Balances before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[3]), m0BalBeforeNFT)
		m1BalBeforeNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[3]-6), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 3)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 4)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 4)

		// Balances after.
		m0BalAfterNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[4]), m0BalAfterNFT)
		m1BalAfterNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[4]-8), m1BalAfterNFT)
	}

	// Upgrade the post from 4 -> 5 diamonds.
	{
		// Balances before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[4]), m0BalBeforeNFT)
		m1BalBeforeNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[4]-8), m1BalBeforeNFT)

		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 4)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m1Pub, m1Priv, post1Hash, 5)
		validateDiamondEntry(m1PKID.PKID, m0PKID.PKID, post1Hash, 5)

		// Balances after.
		m0BalAfterNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[5]), m0BalAfterNFT)
		m1BalAfterNFT := _getBalance(t, chain, nil, m1Pub)
		require.Equal(uint64(1e9-diamondValueMap[5]-10), m1BalAfterNFT)
	}

	// Have m2 give the post 5 diamonds right off the bat.
	{
		// Balances before.
		m0BalBeforeNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[5]), m0BalBeforeNFT)
		m2BalBeforeNFT := _getBalance(t, chain, nil, m2Pub)
		require.Equal(uint64(1e9), m2BalBeforeNFT)

		validateDiamondEntry(m2PKID.PKID, m0PKID.PKID, post1Hash, 0)
		_giveDeSoDiamondsWithTestMeta(testMeta, 10, m2Pub, m2Priv, post1Hash, 5)
		validateDiamondEntry(m2PKID.PKID, m0PKID.PKID, post1Hash, 5)

		// Balances after.
		m0BalAfterNFT := _getBalance(t, chain, nil, m0Pub)
		require.Equal(uint64(999+diamondValueMap[5]+diamondValueMap[5]), m0BalAfterNFT)
		m2BalAfterNFT := _getBalance(t, chain, nil, m2Pub)
		require.Equal(uint64(1e9-diamondValueMap[5]-2), m2BalAfterNFT)
	}

	// Roll all successful txns through connect and disconnect loops to make sure nothing breaks.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)
}

func TestDeSoDiamondErrorCases(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3, m4 a paramUpdater for this test
	params.ParamUpdaterPublicKeys[MakePkMapKey(m3PkBytes)] = true
	params.ParamUpdaterPublicKeys[MakePkMapKey(m4PkBytes)] = true
	params.ForkHeights.DeSoDiamondsBlockHeight = 0
	diamondValueMap := GetDeSoNanosDiamondLevelMapAtBlockHeight(0)


	// Mine a few blocks to give the senderPkString some money.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	// We build the testMeta obj after mining blocks so that we save the correct block height.
	testMeta := &TestMeta{
		t:           t,
		chain:       chain,
		params:      params,
		db:          db,
		mempool:     mempool,
		miner:       miner,
		savedHeight: chain.blockTip().Height + 1,
	}

	// Fund all the keys.
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 1000000000)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 1000000000)

	// Since the "CreateBasicTransferTxnWithDiamonds()" function in blockchain.go won't let us
	// trigger most errors that we want to check, we create another version of the function here
	// that allows us to put together whatever type of broken txn we want.
	_giveCustomDeSoDiamondTxn := func(
		senderPkBase58Check string, senderPrivBase58Check string, receiverPkBase58Check string,
		diamondPostHashBytes []byte, diamondLevel int64, amountNanos uint64) (_err error) {

		senderPkBytes, _, err := Base58CheckDecode(senderPkBase58Check)
		require.NoError(err)

		receiverPkBytes, _, err := Base58CheckDecode(receiverPkBase58Check)
		require.NoError(err)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		// Build the basic transfer txn.
		txn := &MsgDeSoTxn{
			PublicKey: senderPkBytes,
			TxnMeta:   &BasicTransferMetadata{},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   receiverPkBytes,
					AmountNanos: amountNanos,
				},
			},
			// TxInputs and TxOutputs will be set below.
			// This function does not compute a signature.
		}

		// Make a map for the diamond extra data and add it.
		diamondsExtraData := make(map[string][]byte)
		diamondsExtraData[DiamondLevelKey] = IntToBuf(diamondLevel)
		diamondsExtraData[DiamondPostHashKey] = diamondPostHashBytes
		txn.ExtraData = diamondsExtraData

		// We don't need to make any tweaks to the amount because it's basically
		// a standard "pay per kilobyte" transaction.
		totalInput, _, _, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, mempool)
		if err != nil {
			return errors.Wrapf(
				err, "giveCustomDeSoDiamondTxn: Problem adding inputs: ")
		}

		// We want our transaction to have at least one input, even if it all
		// goes to change. This ensures that the transaction will not be "replayable."
		if len(txn.TxInputs) == 0 {
			return fmt.Errorf(
				"giveCustomDeSoDiamondTxn: BasicTransfer txn must have at" +
					" least one input but had zero inputs instead. Try increasing the fee rate.")
		}

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, senderPrivBase58Check)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		utxoOps, totalInput, totalOutput, fees, err :=
			utxoView.ConnectTransaction(
				txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		if err != nil {
			return err
		}
		require.Equal(t, totalInput, totalOutput+fees)

		// We should have one SPEND UtxoOperation for each input, one ADD operation
		// for each output, and one OperationTypeDeSoDiamond operation at the end.
		require.Equal(t, len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
		for ii := 0; ii < len(txn.TxInputs); ii++ {
			require.Equal(t, OperationTypeSpendUtxo, utxoOps[ii].Type)
		}
		require.Equal(OperationTypeDeSoDiamond, utxoOps[len(utxoOps)-1].Type)

		require.NoError(utxoView.FlushToDb())

		return nil
	}

	// Error case: PostHash with bad length.
	{
		err := _giveCustomDeSoDiamondTxn(
			m0Pub,
			m0Priv,
			m1Pub,
			RandomBytes(HashSizeBytes-1),
			1,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBasicTransferDiamondInvalidLengthForPostHashBytes)
	}

	// Error case: non-existent post.
	{
		err := _giveCustomDeSoDiamondTxn(
			m0Pub,
			m0Priv,
			m1Pub,
			RandomBytes(HashSizeBytes),
			1,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBasicTransferDiamondPostEntryDoesNotExist)
	}

	// Create a post for testing.
	{
		_submitPostWithTestMeta(
			testMeta,
			10,                                 /*feeRateNanosPerKB*/
			m0Pub,                              /*updaterPkBase58Check*/
			m0Priv,                             /*updaterPrivBase58Check*/
			[]byte{},                           /*postHashToModify*/
			[]byte{},                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post 1"}, /*body*/
			[]byte{},
			1502947011*1e9, /*tstampNanos*/
			false /*isHidden*/)
	}
	post1Hash := testMeta.txns[len(testMeta.txns)-1].Hash()
	_ = post1Hash

	// Error case: cannot diamond yourself.
	{
		err := _giveCustomDeSoDiamondTxn(
			m0Pub,
			m0Priv,
			m1Pub,
			post1Hash[:],
			1,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBasicTransferDiamondCannotTransferToSelf)
	}

	// Error case: don't include diamond level.
	{
		_, _, _, err := _giveDeSoDiamonds(
			t, chain, db, params,
			10,
			m1Pub,
			m1Priv,
			post1Hash,
			1,
			true, /*deleteDiamondLevel*/
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBasicTransferHasDiamondPostHashWithoutDiamondLevel)
	}

	// Error case: invalid diamond level.
	{
		err := _giveCustomDeSoDiamondTxn(
			m1Pub,
			m1Priv,
			m0Pub,
			post1Hash[:],
			-1,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBasicTransferHasInvalidDiamondLevel)
	}

	// Error case: insufficient deso.
	{
		err := _giveCustomDeSoDiamondTxn(
			m1Pub,
			m1Priv,
			m0Pub,
			post1Hash[:],
			2,
			diamondValueMap[1],
		)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBasicTransferInsufficientDeSoForDiamondLevel)
	}
}
