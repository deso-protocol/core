package lib

import (
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func _doLikeTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, senderPkBase58Check string,
	likedPostHash BlockHash, senderPrivBase58Check string, isUnfollow bool) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := Base58CheckDecode(senderPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateLikeTxn(
		senderPkBytes, likedPostHash, isUnfollow, feeRateNanosPerKB, nil, []*DeSoOutput{})
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, senderPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
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
	// for each output, and one OperationTypeLike operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeLike, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb(0))

	return utxoOps, txn, blockHeight, nil
}

func TestLikeTxns(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

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
	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		expectedSenderBalances = append(
			expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(
			expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

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
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)

	doLikeTxn := func(
		senderPkBase58Check string, likedPostHash BlockHash,
		senderPrivBase58Check string, isUnfollow bool, feeRateNanosPerKB uint64) {

		expectedSenderBalances = append(
			expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(
			expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _doLikeTxn(
			t, chain, db, params, feeRateNanosPerKB, senderPkBase58Check,
			likedPostHash, senderPrivBase58Check, isUnfollow)
		require.NoError(err)

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

		require.NoError(err)

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
	_, _, _, err = _doLikeTxn(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		fakePostHash, m0Priv, false /*isUnfollow*/)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorCannotLikeNonexistentPost)

	submitPost(
		10,       /*feeRateNanosPerKB*/
		m0Pub,    /*updaterPkBase58Check*/
		m0Priv,   /*updaterPrivBase58Check*/
		[]byte{}, /*postHashToModify*/
		[]byte{}, /*parentStakeID*/
		&DeSoBodySchema{Body: "m0 post body 1 no profile"}, /*body*/
		[]byte{},
		1602947011*1e9, /*tstampNanos*/
		false /*isHidden*/)
	post1Txn := txns[len(txns)-1]
	post1Hash := *post1Txn.Hash()

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
	post2Hash := *post2Txn.Hash()

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
	post3Hash := *post3Txn.Hash()

	// m0 -> p1
	doLikeTxn(m0Pub, post1Hash, m0Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// Duplicating "m0 -> p1" should fail.
	_, _, _, err = _doLikeTxn(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		post1Hash, m0Priv, false /*isUnfollow*/)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorLikeEntryAlreadyExists)

	// m2 -> p1
	doLikeTxn(m2Pub, post1Hash, m2Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m3 -> p1
	doLikeTxn(m3Pub, post1Hash, m3Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m3 -> p2
	doLikeTxn(m3Pub, post2Hash, m3Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m1 -> p2
	doLikeTxn(m1Pub, post2Hash, m1Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m2 -> p3
	doLikeTxn(m2Pub, post3Hash, m2Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	likingP1 := [][]byte{
		_strToPk(t, m0Pub),
		_strToPk(t, m2Pub),
		_strToPk(t, m3Pub),
	}

	likingP2 := [][]byte{
		_strToPk(t, m1Pub),
		_strToPk(t, m3Pub),
	}

	likingP3 := [][]byte{
		_strToPk(t, m2Pub),
	}

	// Verify pks liking p1 and check like count.
	{
		likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post1Hash)
		require.NoError(err)
		require.Equal(len(likingP1), len(likingPks))
		for ii := 0; ii < len(likingPks); ii++ {
			require.Contains(likingP1, likingPks[ii])
		}
		post1 := DBGetPostEntryByPostHash(db, chain.snapshot, &post1Hash)
		require.Equal(uint64(len(likingP1)), post1.LikeCount)
	}

	// Verify pks liking p2 and check like count.
	{
		likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post2Hash)
		require.NoError(err)
		require.Equal(len(likingP2), len(likingPks))
		for ii := 0; ii < len(likingPks); ii++ {
			require.Contains(likingP2, likingPks[ii])
		}
		post2 := DBGetPostEntryByPostHash(db, chain.snapshot, &post2Hash)
		require.Equal(uint64(len(likingP2)), post2.LikeCount)
	}

	// Verify pks liking p3 and check like count.
	{
		likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post3Hash)
		require.NoError(err)
		require.Equal(len(likingP3), len(likingPks))
		for ii := 0; ii < len(likingPks); ii++ {
			require.Contains(likingP3, likingPks[ii])
		}
		post3 := DBGetPostEntryByPostHash(db, chain.snapshot, &post3Hash)
		require.Equal(uint64(len(likingP3)), post3.LikeCount)
	}

	m0Likes := []BlockHash{
		post1Hash,
	}

	m1Likes := []BlockHash{
		post2Hash,
	}

	m2Likes := []BlockHash{
		post1Hash,
		post3Hash,
	}

	m3Likes := []BlockHash{
		post1Hash,
		post2Hash,
	}

	// Verify m0's likes.
	{
		likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(len(m0Likes), len(likedPostHashes))
		for ii := 0; ii < len(likedPostHashes); ii++ {
			require.Contains(m0Likes, *likedPostHashes[ii])
		}
	}

	// Verify m1's likes.
	{
		likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(len(m1Likes), len(likedPostHashes))
		for ii := 0; ii < len(likedPostHashes); ii++ {
			require.Contains(m1Likes, *likedPostHashes[ii])
		}
	}

	// Verify m2's likes.
	{
		likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(len(m2Likes), len(likedPostHashes))
		for ii := 0; ii < len(likedPostHashes); ii++ {
			require.Contains(m2Likes, *likedPostHashes[ii])
		}
	}

	// Verify m3's likes.
	{
		likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(len(m3Likes), len(likedPostHashes))
		for ii := 0; ii < len(likedPostHashes); ii++ {
			require.Contains(m3Likes, *likedPostHashes[ii])
		}
	}

	// Try an "unlike."
	//
	// m0 -> p1 (unfollow)
	doLikeTxn(m0Pub, post1Hash, m0Priv, true /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m3 -> p2 (unfollow)
	doLikeTxn(m3Pub, post2Hash, m3Priv, true /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// Duplicating "m0 -> p1" (unfollow) should fail.
	_, _, _, err = _doLikeTxn(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		post1Hash, m0Priv, true /*isUnfollow*/)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorCannotUnlikeWithoutAnExistingLike)

	likingP1 = [][]byte{
		_strToPk(t, m2Pub),
		_strToPk(t, m3Pub),
	}

	likingP2 = [][]byte{
		_strToPk(t, m1Pub),
	}

	// Verify pks liking p1 and check like count.
	{
		likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post1Hash)
		require.NoError(err)
		require.Equal(len(likingP1), len(likingPks))
		for ii := 0; ii < len(likingPks); ii++ {
			require.Contains(likingP1, likingPks[ii])
		}
		post1 := DBGetPostEntryByPostHash(db, chain.snapshot, &post1Hash)
		require.Equal(uint64(len(likingP1)), post1.LikeCount)
	}

	// Verify pks liking p2 and check like count.
	{
		likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post2Hash)
		require.NoError(err)
		require.Equal(len(likingP2), len(likingPks))
		for ii := 0; ii < len(likingPks); ii++ {
			require.Contains(likingP2, likingPks[ii])
		}
		post2 := DBGetPostEntryByPostHash(db, chain.snapshot, &post2Hash)
		require.Equal(uint64(len(likingP2)), post2.LikeCount)
	}

	m3Likes = []BlockHash{
		post1Hash,
	}

	// Verify m0 has no likes.
	{
		likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(likedPostHashes))
	}

	// Verify m3's likes.
	{
		likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(len(m3Likes), len(likedPostHashes))
		for i := 0; i < len(likedPostHashes); i++ {
			require.Contains(m3Likes, *likedPostHashes[i])
		}
	}

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
		fmt.Printf(
			"Disconnecting transaction with type %v index %d (going backwards)\n",
			currentTxn.TxnMeta.GetTxnType(), backwardIter)

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb(0))

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(
			int64(expectedSenderBalances[backwardIter]),
			int64(_getBalance(t, chain, nil, senderPkString)))
		require.Equal(
			expectedRecipientBalances[backwardIter],
			_getBalance(t, chain, nil, recipientPkString))

		// Here we check the like counts after all the like entries have been disconnected.
		if backwardIter == 19 {
			post1 := DBGetPostEntryByPostHash(db, chain.snapshot, &post1Hash)
			require.Equal(uint64(0), post1.LikeCount)
			post2 := DBGetPostEntryByPostHash(db, chain.snapshot, &post2Hash)
			require.Equal(uint64(0), post2.LikeCount)
			post3 := DBGetPostEntryByPostHash(db, chain.snapshot, &post3Hash)
			require.Equal(uint64(0), post3.LikeCount)
		}
	}

	testDisconnectedState := func() {
		// Verify that all the pks liking each post hash have been deleted and like count == 0.
		{
			likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post1Hash)
			require.NoError(err)
			require.Equal(0, len(likingPks))
		}
		{
			likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post2Hash)
			require.NoError(err)
			require.Equal(0, len(likingPks))
		}
		{
			likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post3Hash)
			require.NoError(err)
			require.Equal(0, len(likingPks))
		}

		// Verify that all the post hashes liked by users have been deleted.
		{
			likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m0Pub))
			require.NoError(err)
			require.Equal(0, len(likedPostHashes))
		}
		{
			likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m1Pub))
			require.NoError(err)
			require.Equal(0, len(likedPostHashes))
		}
		{
			likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m2Pub))
			require.NoError(err)
			require.Equal(0, len(likedPostHashes))
		}
		{
			likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m3Pub))
			require.NoError(err)
			require.Equal(0, len(likedPostHashes))
		}
	}
	testDisconnectedState()

	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	for ii, tx := range txns {
		// See comment above on this transaction.
		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		require.Equal(expectedSenderBalances[ii], _getBalance(t, chain, mempool, senderPkString))
		require.Equal(expectedRecipientBalances[ii], _getBalance(t, chain, mempool, recipientPkString))

		_, err := mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}

	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
	require.NoError(err)
	for ii, txn := range txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err :=
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		require.NoError(err)
	}
	// Flush the utxoView after having added all the transactions.
	require.NoError(utxoView.FlushToDb(0))

	testConnectedState := func() {
		likingP1 = [][]byte{
			_strToPk(t, m2Pub),
			_strToPk(t, m3Pub),
		}

		likingP2 = [][]byte{
			_strToPk(t, m1Pub),
		}

		likingP3 := [][]byte{
			_strToPk(t, m2Pub),
		}

		// Verify pks liking p1 and check like count.
		{
			likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post1Hash)
			require.NoError(err)
			require.Equal(len(likingP1), len(likingPks))
			for ii := 0; ii < len(likingPks); ii++ {
				require.Contains(likingP1, likingPks[ii])
			}
			post1 := DBGetPostEntryByPostHash(db, chain.snapshot, &post1Hash)
			require.Equal(uint64(len(likingP1)), post1.LikeCount)
		}

		// Verify pks liking p2 and check like count.
		{
			likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post2Hash)
			require.NoError(err)
			require.Equal(len(likingP2), len(likingPks))
			for ii := 0; ii < len(likingPks); ii++ {
				require.Contains(likingP2, likingPks[ii])
			}
			post2 := DBGetPostEntryByPostHash(db, chain.snapshot, &post2Hash)
			require.Equal(uint64(len(likingP2)), post2.LikeCount)
		}

		// Verify pks liking p3 and check like count.
		{
			likingPks, err := DbGetLikerPubKeysLikingAPostHash(db, post3Hash)
			require.NoError(err)
			require.Equal(len(likingP3), len(likingPks))
			for ii := 0; ii < len(likingPks); ii++ {
				require.Contains(likingP3, likingPks[ii])
			}
			post3 := DBGetPostEntryByPostHash(db, chain.snapshot, &post3Hash)
			require.Equal(uint64(len(likingP3)), post3.LikeCount)
		}

		m1Likes := []BlockHash{
			post2Hash,
		}

		m2Likes := []BlockHash{
			post1Hash,
			post3Hash,
		}

		m3Likes = []BlockHash{
			post1Hash,
		}

		// Verify m0 has no likes.
		{
			followPks, err := DbGetPostHashesYouLike(db, _strToPk(t, m0Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}

		// Verify m1's likes.
		{
			likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m1Pub))
			require.NoError(err)
			require.Equal(len(m1Likes), len(likedPostHashes))
			for ii := 0; ii < len(likedPostHashes); ii++ {
				require.Contains(m1Likes, *likedPostHashes[ii])
			}
		}

		// Verify m2's likes.
		{
			likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m2Pub))
			require.NoError(err)
			require.Equal(len(m2Likes), len(likedPostHashes))
			for ii := 0; ii < len(likedPostHashes); ii++ {
				require.Contains(m2Likes, *likedPostHashes[ii])
			}
		}

		// Verify m3's likes.
		{
			likedPostHashes, err := DbGetPostHashesYouLike(db, _strToPk(t, m3Pub))
			require.NoError(err)
			require.Equal(len(m3Likes), len(likedPostHashes))
			for ii := 0; ii < len(likedPostHashes); ii++ {
				require.Contains(m3Likes, *likedPostHashes[ii])
			}
		}
	}
	testConnectedState()

	// Disconnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView2, err := NewUtxoView(db, params, nil, chain.snapshot)
	require.NoError(err)
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		currentHash := currentTxn.Hash()
		err = utxoView2.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)
	}
	require.NoError(utxoView2.FlushToDb(0))
	require.Equal(expectedSenderBalances[0], _getBalance(t, chain, nil, senderPkString))
	require.Equal(expectedRecipientBalances[0], _getBalance(t, chain, nil, recipientPkString))

	testDisconnectedState()

	// All the txns should be in the mempool already so mining a block should put
	// all those transactions in it.
	block, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(len(txnOps)+1, len(block.Txns))
	// Estimate the transaction fees of the tip block in various ways.
	{
		// Threshold above what's in the block should return the default fee at all times.
		require.Equal(int64(0), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 0)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 7)))
		// Threshold below what's in the block should return the max of the median
		// and the minfee. This means with a low minfee the value returned should be
		// higher. And with a high minfee the value returned should be equal to the
		// fee.
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 7)))
		require.Equal(int64(4), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 0)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.01, 7)))
		require.Equal(int64(4), int64(chain.EstimateDefaultFeeRateNanosPerKB(.01, 1)))
	}

	testConnectedState()

	// Roll back the block and make sure we don't hit any errors.
	{
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := block.Header.Hash()
		require.NoError(err)
		utxoOps, err := GetUtxoOperationsForBlock(db, chain.snapshot, hash)
		require.NoError(err)

		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(block.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(block, txHashes, utxoOps, 0))

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb(0))
	}

	testDisconnectedState()
}
