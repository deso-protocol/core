package lib

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/unicode/norm"
	"testing"
)

var (
	HappyReaction     = rune(norm.NFC.String(string('😊'))[0])
	SadReaction       = rune(norm.NFC.String(string('😥'))[0])
	AngryReaction     = rune(norm.NFC.String(string('😠'))[0])
	SurprisedReaction = rune(norm.NFC.String(string('😮'))[0])
)

func _doReactTxn(testMeta *TestMeta, feeRateNanosPerKB uint64, senderPkBase58Check string,
	postHash BlockHash, senderPrivBase58Check string, isRemove bool, emojiReaction rune) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	require := require.New(testMeta.t)

	senderPkBytes, _, err := Base58CheckDecode(senderPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := testMeta.chain.CreateReactTxn(
		senderPkBytes, postHash, isRemove, emojiReaction, feeRateNanosPerKB, nil, []*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(testMeta.t, txn, senderPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := testMeta.chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true, /*verifySignature*/
			false /*ignoreUtxos*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeReact operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeReact, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb(0))

	return utxoOps, txn, blockHeight, nil
}

func TestReactTxns(t *testing.T) {
	// Test constants
	const feeRateNanosPerKb = uint64(101)
	var err error

	//Initialize test chain and miner
	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Mine a few blocks to give the senderPkString some money.
	for ii := 0; ii < 20; ii++ {
		_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(t, err)
	}

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

	// Helpers
	type User struct {
		Pub       string
		Priv      string
		PkBytes   []byte
		PublicKey *PublicKey
		Pkid      *PKID
	}

	//TODO Use this correctly
	//deso := User{
	//	PublicKey: &ZeroPublicKey,
	//	Pkid:      &ZeroPKID,
	//}

	m0 := User{
		Pub:       m0Pub,
		Priv:      m0Priv,
		PkBytes:   m0PkBytes,
		PublicKey: NewPublicKey(m0PkBytes),
		Pkid:      DBGetPKIDEntryForPublicKey(db, chain.snapshot, m0PkBytes).PKID,
	}

	m1 := User{
		Pub:       m1Pub,
		Priv:      m1Priv,
		PkBytes:   m1PkBytes,
		PublicKey: NewPublicKey(m1PkBytes),
		Pkid:      DBGetPKIDEntryForPublicKey(db, chain.snapshot, m1PkBytes).PKID,
	}

	m2 := User{
		Pub:       m2Pub,
		Priv:      m2Priv,
		PkBytes:   m2PkBytes,
		PublicKey: NewPublicKey(m2PkBytes),
		Pkid:      DBGetPKIDEntryForPublicKey(db, chain.snapshot, m2PkBytes).PKID,
	}

	m3 := User{
		Pub:       m3Pub,
		Priv:      m3Priv,
		PkBytes:   m3PkBytes,
		PublicKey: NewPublicKey(m3PkBytes),
		Pkid:      DBGetPKIDEntryForPublicKey(db, chain.snapshot, m3PkBytes).PKID,
	}

	// Setup some convenience functions for the test.
	var txnOps [][]*UtxoOperation
	var txns []*MsgDeSoTxn
	var expectedSenderBalances []uint64
	var expectedRecipientBalances []uint64

	// We take the block tip to be the blockchain height rather than the
	// header chain height.
	savedHeight := chain.blockTip().Height + 1

	// Fund all the keys.
	for ii := 0; ii < 5; ii++ {
		_registerOrTransferWithTestMeta(testMeta, "m0", senderPkString, m0.Pub, senderPrivString, 7e6)
		_registerOrTransferWithTestMeta(testMeta, "m1", senderPkString, m1.Pub, senderPrivString, 7e6)
		_registerOrTransferWithTestMeta(testMeta, "m2", senderPkString, m2.Pub, senderPrivString, 7e6)
		_registerOrTransferWithTestMeta(testMeta, "m3", senderPkString, m3.Pub, senderPrivString, 7e6)
	}

	doReactTxn := func(
		senderPkBase58Check string, postHash BlockHash,
		senderPrivBase58Check string, isRemove bool, emojiReaction rune, feeRateNanosPerKB uint64) {

		expectedSenderBalances = append(
			expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(
			expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _doReactTxn(
			testMeta, feeRateNanosPerKB, senderPkBase58Check,
			postHash, senderPrivBase58Check, isRemove, emojiReaction)
		require.NoError(t, err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	submitPost := func(
		feeRateNanosPerKB uint64, updaterPkBase58Check string,
		updaterPrivBase58Check string,
		postHashToModify []byte,
		parentStakeID []byte,
		bodyObj *DeSoBodySchema,
		repostedPostHash []byte,
		tstampNanos uint64,
		isHidden bool) {

		expectedSenderBalances = append(
			expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(
			expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _submitPost(
			t, chain, db, params, feeRateNanosPerKB,
			updaterPkBase58Check,
			updaterPrivBase58Check,
			postHashToModify,
			parentStakeID,
			bodyObj,
			repostedPostHash,
			tstampNanos,
			isHidden)

		require.NoError(t, err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	fakePostHash := BlockHash{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
		0x30, 0x31,
	}
	// Attempting "m0 -> fakePostHash" should fail since the post doesn't exist.
	_, _, _, err = _doReactTxn(
		testMeta, 10                /*feeRateNanosPerKB*/, m0Pub,
		fakePostHash, m0Priv, false /*isRemove*/, HappyReaction)
	require.Error(t, err)
	require.Contains(t, err.Error(), RuleErrorCannotReactNonexistentPost)

	// p1
	submitPost(
		10,                                                 /*feeRateNanosPerKB*/
		m0Pub,                                              /*updaterPkBase58Check*/
		m0Priv,                                             /*updaterPrivBase58Check*/
		[]byte{},                                           /*postHashToModify*/
		[]byte{},                                           /*parentStakeID*/
		&DeSoBodySchema{Body: "m0 post body 1 no profile"}, /*body*/
		[]byte{},
		1602947011*1e9, /*tstampNanos*/
		false           /*isHidden*/)
	post1Txn := txns[len(txns)-1]
	post1Hash := *post1Txn.Hash()

	// p2
	{
		submitPost(
			10,                                                 /*feeRateNanosPerKB*/
			m0Pub,                                              /*updaterPkBase58Check*/
			m0Priv,                                             /*updaterPrivBase58Check*/
			[]byte{},                                           /*postHashToModify*/
			[]byte{},                                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m0 post body 2 no profile"}, /*body*/
			[]byte{},
			1502947012*1e9, /*tstampNanos*/
			false           /*isHidden*/)
	}
	post2Txn := txns[len(txns)-1]
	post2Hash := *post2Txn.Hash()

	// p3
	{
		submitPost(
			10,                                                 /*feeRateNanosPerKB*/
			m1Pub,                                              /*updaterPkBase58Check*/
			m1Priv,                                             /*updaterPrivBase58Check*/
			[]byte{},                                           /*postHashToModify*/
			[]byte{},                                           /*parentStakeID*/
			&DeSoBodySchema{Body: "m1 post body 1 no profile"}, /*body*/
			[]byte{},
			1502947013*1e9, /*tstampNanos*/
			false           /*isHidden*/)
	}
	post3Txn := txns[len(txns)-1]
	post3Hash := *post3Txn.Hash()

	// m0 -> p1 (happy)
	doReactTxn(m0Pub, post1Hash, m0Priv, false /*isRemove*/, HappyReaction, 10 /*feeRateNanosPerKB*/)

	// Duplicating "m0 -> p1" should fail.
	_, _, _, err = _doReactTxn(
		testMeta, 10             /*feeRateNanosPerKB*/, m0Pub,
		post1Hash, m0Priv, false /*isRemove*/, HappyReaction)
	require.Error(t, err)
	require.Contains(t, err.Error(), RuleErrorReactEntryAlreadyExists)

	// m2 -> p1 (happy)
	doReactTxn(m2Pub, post1Hash, m2Priv, false /*isRemove*/, HappyReaction, 10 /*feeRateNanosPerKB*/)

	// m3 -> p1 (surprised)
	doReactTxn(m3Pub, post1Hash, m3Priv, false /*isRemove*/, HappyReaction, 10 /*feeRateNanosPerKB*/)

	// m3 -> p2 (sad)
	doReactTxn(m3Pub, post2Hash, m3Priv, false /*isRemove*/, HappyReaction, 10 /*feeRateNanosPerKB*/)

	// m1 -> p2 (angry)
	doReactTxn(m1Pub, post2Hash, m1Priv, false /*isRemove*/, HappyReaction, 10 /*feeRateNanosPerKB*/)

	// m2 -> p3 (surprised)
	doReactTxn(m2Pub, post3Hash, m2Priv, false /*isRemove*/, HappyReaction, 10 /*feeRateNanosPerKB*/)

	reactingP1 := [][]byte{
		_strToPk(t, m0Pub),
		_strToPk(t, m2Pub),
		_strToPk(t, m3Pub),
	}

	reactingP2 := [][]byte{
		_strToPk(t, m1Pub),
		_strToPk(t, m3Pub),
	}

	reactingP3 := [][]byte{
		_strToPk(t, m2Pub),
	}

	// Verify pks reacting p1 and check reactcount.
	{
		reactingPks, err := DbGetReactorPubKeysReactingToPostHash(db, post1Hash)
		require.NoError(t, err)
		require.Equal(t, len(reactingP1), len(reactingPks))
		for ii := 0; ii < len(reactingPks); ii++ {
			require.Contains(t, reactingP1, reactingPks[ii])
		}
		post1 := DBGetPostEntryByPostHash(testMeta.db, testMeta.chain.snapshot, &post1Hash)
		require.Equal(t, uint64(len(reactingP1)), post1.EmojiCount[HappyReaction])
	}

	// Verify pks reacting p2 and check reactcount.
	{
		reactingPks, err := DbGetReactorPubKeysReactingToPostHash(db, post2Hash)
		require.NoError(t, err)
		require.Equal(t, len(reactingP2), len(reactingPks))
		for ii := 0; ii < len(reactingPks); ii++ {
			require.Contains(t, reactingP2, reactingPks[ii])
		}
		post2 := DBGetPostEntryByPostHash(testMeta.db, testMeta.chain.snapshot, &post2Hash)
		require.Equal(t, uint64(len(reactingP2)), post2.EmojiCount[HappyReaction])
	}

	// Verify pks reacting p3 and check reactcount.
	{
		reactingPks, err := DbGetReactorPubKeysReactingToPostHash(db, post3Hash)
		require.NoError(t, err)
		require.Equal(t, len(reactingP3), len(reactingPks))
		for ii := 0; ii < len(reactingPks); ii++ {
			require.Contains(t, reactingP3, reactingPks[ii])
		}
		post3 := DBGetPostEntryByPostHash(testMeta.db, testMeta.chain.snapshot, &post3Hash)
		require.Equal(t, uint64(len(reactingP3)), post3.EmojiCount[HappyReaction])
	}

	m0Reacts := []BlockHash{
		post1Hash,
	}

	m1Reacts := []BlockHash{
		post2Hash,
	}

	m2Reacts := []BlockHash{
		post1Hash,
		post3Hash,
	}

	m3Reacts := []BlockHash{
		post1Hash,
		post2Hash,
	}

	// Verify m0's reactions.
	{
		reactedPostHashes, err := DbGetPostHashesYouReact(db, _strToPk(t, m0Pub))
		require.NoError(t, err)
		require.Equal(t, len(m0Reacts), len(reactedPostHashes))
		for ii := 0; ii < len(reactedPostHashes); ii++ {
			require.Contains(t, m0Reacts, *reactedPostHashes[ii])
		}
	}

	// Verify m1's reactions.
	{
		reactedPostHashes, err := DbGetPostHashesYouReact(db, _strToPk(t, m1Pub))
		require.NoError(t, err)
		require.Equal(t, len(m1Reacts), len(reactedPostHashes))
		for ii := 0; ii < len(reactedPostHashes); ii++ {
			require.Contains(t, m1Reacts, *reactedPostHashes[ii])
		}
	}

	// Verify m2's reactions.
	{
		reactedPostHashes, err := DbGetPostHashesYouReact(db, _strToPk(t, m2Pub))
		require.NoError(t, err)
		require.Equal(t, len(m2Reacts), len(reactedPostHashes))
		for ii := 0; ii < len(reactedPostHashes); ii++ {
			require.Contains(t, m2Reacts, *reactedPostHashes[ii])
		}
	}

	// Verify m3's reactions.
	{
		reactedPostHashes, err := DbGetPostHashesYouReact(db, _strToPk(t, m3Pub))
		require.NoError(t, err)
		require.Equal(t, len(m3Reacts), len(reactedPostHashes))
		for ii := 0; ii < len(reactedPostHashes); ii++ {
			require.Contains(t, m3Reacts, *reactedPostHashes[ii])
		}
	}

	// Try an removing a reaction.
	//
	// m0 -> p1 (remove, happy)
	doReactTxn(m0Pub, post1Hash, m0Priv, true /*isRemove*/, HappyReaction, 10 /*feeRateNanosPerKB*/)

	// m3 -> p2 (remove, happy)
	doReactTxn(m3Pub, post2Hash, m3Priv, true /*isRemove*/, HappyReaction, 10 /*feeRateNanosPerKB*/)

	// Duplicating "m0 -> p1" (unfollow) should fail.
	_, _, _, err = _doReactTxn(
		testMeta, 10            /*feeRateNanosPerKB*/, m0Pub,
		post1Hash, m0Priv, true /*isRemove*/, HappyReaction)
	require.Error(t, err)
	require.Contains(t, err.Error(), RuleErrorCannotRemoveReactionWithoutAnExistingReaction)

	reactingP1 = [][]byte{
		_strToPk(t, m2Pub),
		_strToPk(t, m3Pub),
	}

	reactingP2 = [][]byte{
		_strToPk(t, m1Pub),
	}

	// Verify pks reacting p1 and check reactcount.
	{
		reactingPks, err := DbGetReactorPubKeysReactingToPostHash(db, post1Hash)
		require.NoError(t, err)
		require.Equal(t, len(reactingP1), len(reactingPks))
		for ii := 0; ii < len(reactingPks); ii++ {
			require.Contains(t, reactingP1, reactingPks[ii])
		}
		post1 := DBGetPostEntryByPostHash(testMeta.db, testMeta.chain.snapshot, &post1Hash)
		require.Equal(t, uint64(len(reactingP1)), post1.EmojiCount[HappyReaction])
	}

	// Verify pks reacting p2 and check reactcount.
	{
		reactingPks, err := DbGetReactorPubKeysReactingToPostHash(db, post2Hash)
		require.NoError(t, err)
		require.Equal(t, len(reactingP2), len(reactingPks))
		for ii := 0; ii < len(reactingPks); ii++ {
			require.Contains(t, reactingP2, reactingPks[ii])
		}
		post2 := DBGetPostEntryByPostHash(testMeta.db, testMeta.chain.snapshot, &post2Hash)
		require.Equal(t, uint64(len(reactingP2)), post2.EmojiCount[HappyReaction])
	}

	m3Reacts = []BlockHash{
		post1Hash,
	}

	// Verify m0 has no reactions.
	{
		reactedPostHashes, err := DbGetPostHashesYouReact(db, _strToPk(t, m0Pub))
		require.NoError(t, err)
		require.Equal(t, 0, len(reactedPostHashes))
	}

	// Verify m3's reactions.
	{
		reactedPostHashes, err := DbGetPostHashesYouReact(db, _strToPk(t, m3Pub))
		require.NoError(t, err)
		require.Equal(t, len(m3Reacts), len(reactedPostHashes))
		for i := 0; i < len(reactedPostHashes); i++ {
			require.Contains(t, m3Reacts, *reactedPostHashes[i])
		}
	}

	// ===================================================================================
	// Finish it off with some transactions
	// ===================================================================================
	_registerOrTransferWithTestMeta(testMeta, "m0", senderPkString, m0.Pub, senderPrivString, 42e6)
	_registerOrTransferWithTestMeta(testMeta, "m1", senderPkString, m1.Pub, senderPrivString, 42e6)
	_registerOrTransferWithTestMeta(testMeta, "m0 -> m1", m0Pub, m1Pub, m0Priv, 7e6)
	_registerOrTransferWithTestMeta(testMeta, "m1 -> m0", m1Pub, m0Pub, m1Priv, 7e6)
	_registerOrTransferWithTestMeta(testMeta, "m1 -> m0", m1Pub, m0Pub, m1Priv, 7e6)
	_registerOrTransferWithTestMeta(testMeta, "m0 -> m1", m0Pub, m1Pub, m0Priv, 7e6)
	_registerOrTransferWithTestMeta(testMeta, "m1 -> m0", m1Pub, m0Pub, m1Priv, 7e6)
	_registerOrTransferWithTestMeta(testMeta, "m0 -> m1", m0Pub, m1Pub, m0Priv, 7e6)
	_registerOrTransferWithTestMeta(testMeta, "m1 -> m0", m1Pub, m0Pub, m1Priv, 7e6)
	_registerOrTransferWithTestMeta(testMeta, "m0 -> m1", m0Pub, m1Pub, m0Priv, 7e6)
	_registerOrTransferWithTestMeta(testMeta, "m1 -> m0", m1Pub, m0Pub, m1Priv, 7e6)
	_registerOrTransferWithTestMeta(testMeta, "m1 -> m0", m1Pub, m0Pub, m1Priv, 7e6)
	_registerOrTransferWithTestMeta(testMeta, "m0 -> m1", m0Pub, m1Pub, m0Priv, 7e6)
	_registerOrTransferWithTestMeta(testMeta, "m0 -> m1", m0Pub, m1Pub, m0Priv, 7e6)
	_registerOrTransferWithTestMeta(testMeta, "m0 -> m1", m0Pub, m1Pub, m0Priv, 7e6)

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]
		fmt.Printf(
			"Disconnecting transaction with type %v index %d (going backwards)\n",
			currentTxn.TxnMeta.GetTxnType(), backwardIter)

		utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
		require.NoError(t, err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(t, err)

		require.NoError(t, utxoView.FlushToDb(0))

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(t,
			int64(expectedSenderBalances[backwardIter]),
			int64(_getBalance(t, chain, nil, senderPkString)))
		require.Equal(t,
			expectedRecipientBalances[backwardIter],
			_getBalance(t, chain, nil, recipientPkString))

		// Here we check the reactcounts after all the reactentries have been disconnected.
		if backwardIter == 19 {
			post1 := DBGetPostEntryByPostHash(testMeta.db, testMeta.chain.snapshot, &post1Hash)
			require.Equal(t, uint64(0), post1.EmojiCount[HappyReaction])
			post2 := DBGetPostEntryByPostHash(testMeta.db, testMeta.chain.snapshot, &post2Hash)
			require.Equal(t, uint64(0), post2.EmojiCount[HappyReaction])
			post3 := DBGetPostEntryByPostHash(testMeta.db, testMeta.chain.snapshot, &post3Hash)
			require.Equal(t, uint64(0), post3.EmojiCount[HappyReaction])
		}
	}

	_executeAllTestRollbackAndFlush(testMeta)

	// TODO (Michel) Everything below is unecessary since we call _executeAllTestRollbackAndFlush
	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	for ii, tx := range txns {
		// See comment above on this transaction.
		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		require.Equal(t, expectedSenderBalances[ii], _getBalance(t, chain, mempool, senderPkString))
		require.Equal(t, expectedRecipientBalances[ii], _getBalance(t, chain, mempool, recipientPkString))

		_, err := mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(t, err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}

	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	for ii, txn := range txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err :=
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.NoError(t, err)
	}
	// Flush the utxoView after having added all the transactions.
	require.NoError(t, utxoView.FlushToDb(0))

	testConnectedState := func() {
		reactingP1 = [][]byte{
			_strToPk(t, m2Pub),
			_strToPk(t, m3Pub),
		}

		reactingP2 = [][]byte{
			_strToPk(t, m1Pub),
		}

		reactingP3 := [][]byte{
			_strToPk(t, m2Pub),
		}

		// Verify pks reacting p1 and check reactcount.
		{
			reactingPks, err := DbGetReactorPubKeysReactingToPostHash(db, post1Hash)
			require.NoError(t, err)
			require.Equal(t, len(reactingP1), len(reactingPks))
			for ii := 0; ii < len(reactingPks); ii++ {
				require.Contains(t, reactingP1, reactingPks[ii])
			}
			post1 := DBGetPostEntryByPostHash(testMeta.db, testMeta.chain.snapshot, &post1Hash)
			require.Equal(t, uint64(len(reactingP1)), post1.EmojiCount[HappyReaction])
		}

		// Verify pks reacting p2 and check reactcount.
		{
			reactingPks, err := DbGetReactorPubKeysReactingToPostHash(db, post2Hash)
			require.NoError(t, err)
			require.Equal(t, len(reactingP2), len(reactingPks))
			for ii := 0; ii < len(reactingPks); ii++ {
				require.Contains(t, reactingP2, reactingPks[ii])
			}
			post2 := DBGetPostEntryByPostHash(testMeta.db, testMeta.chain.snapshot, &post2Hash)
			require.Equal(t, uint64(len(reactingP2)), post2.EmojiCount[HappyReaction])
		}

		// Verify pks reacting p3 and check reactcount.
		{
			reactingPks, err := DbGetReactorPubKeysReactingToPostHash(db, post3Hash)
			require.NoError(t, err)
			require.Equal(t, len(reactingP3), len(reactingPks))
			for ii := 0; ii < len(reactingPks); ii++ {
				require.Contains(t, reactingP3, reactingPks[ii])
			}
			post3 := DBGetPostEntryByPostHash(testMeta.db, testMeta.chain.snapshot, &post3Hash)
			require.Equal(t, uint64(len(reactingP3)), post3.EmojiCount[HappyReaction])
		}

		m1Reacts := []BlockHash{
			post2Hash,
		}

		m2Reacts := []BlockHash{
			post1Hash,
			post3Hash,
		}

		m3Reacts = []BlockHash{
			post1Hash,
		}

		// Verify m0 has no reactions.
		{
			followPks, err := DbGetPostHashesYouReact(db, _strToPk(t, m0Pub))
			require.NoError(t, err)
			require.Equal(t, 0, len(followPks))
		}

		// Verify m1's reactions.
		{
			reactedPostHashes, err := DbGetPostHashesYouReact(db, _strToPk(t, m1Pub))
			require.NoError(t, err)
			require.Equal(t, len(m1Reacts), len(reactedPostHashes))
			for ii := 0; ii < len(reactedPostHashes); ii++ {
				require.Contains(t, m1Reacts, *reactedPostHashes[ii])
			}
		}

		// Verify m2's reactions.
		{
			reactedPostHashes, err := DbGetPostHashesYouReact(db, _strToPk(t, m2Pub))
			require.NoError(t, err)
			require.Equal(t, len(m2Reacts), len(reactedPostHashes))
			for ii := 0; ii < len(reactedPostHashes); ii++ {
				require.Contains(t, m2Reacts, *reactedPostHashes[ii])
			}
		}

		// Verify m3's reactions.
		{
			reactedPostHashes, err := DbGetPostHashesYouReact(db, _strToPk(t, m3Pub))
			require.NoError(t, err)
			require.Equal(t, len(m3Reacts), len(reactedPostHashes))
			for ii := 0; ii < len(reactedPostHashes); ii++ {
				require.Contains(t, m3Reacts, *reactedPostHashes[ii])
			}
		}
	}
	testConnectedState()

	// Disconnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView2, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(t, err)
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		currentHash := currentTxn.Hash()
		err = utxoView2.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(t, err)
	}
	require.NoError(t, utxoView2.FlushToDb(0))
	require.Equal(t, expectedSenderBalances[0], _getBalance(t, chain, nil, senderPkString))
	require.Equal(t, expectedRecipientBalances[0], _getBalance(t, chain, nil, recipientPkString))

	_executeAllTestRollbackAndFlush(testMeta)

	// All the txns should be in the mempool already so mining a block should put
	// all those transactions in it.
	block, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(t, err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(t, len(txnOps)+1, len(block.Txns))
	// Estimate the transaction fees of the tip block in various ways.
	{
		// Threshold above what's in the block should return the default fee at all times.
		require.Equal(t, int64(0), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 0)))
		require.Equal(t, int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 7)))
		// Threshold below what's in the block should return the max of the median
		// and the minfee. This means with a low minfee the value returned should be
		// higher. And with a high minfee the value returned should be equal to the
		// fee.
		require.Equal(t, int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 7)))
		require.Equal(t, int64(4), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 0)))
		require.Equal(t, int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.01, 7)))
		require.Equal(t, int64(4), int64(chain.EstimateDefaultFeeRateNanosPerKB(.01, 1)))
	}

	testConnectedState()

	_executeAllTestRollbackAndFlush(testMeta)
}

// func TestReactTxns
// - one successful happy, sad, angry, confused
// - one failure (invalid character?, not amongst the other characters)

// func _createReactTxn
// func _connectReactTxn
// func _doReactTxnWithTestMeta
// func _doReactRxnErrorToBeDefined
// func Eq
// func ToEntry
// func TestFlushingReactTxn
