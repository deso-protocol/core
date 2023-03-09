package lib

import (
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func _doFollowTxn(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, senderPkBase58Check string,
	followedPkBase58Check string, senderPrivBase58Check string, isUnfollow bool) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := Base58CheckDecode(senderPkBase58Check)
	require.NoError(err)

	followedPkBytes, _, err := Base58CheckDecode(followedPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateFollowTxn(
		senderPkBytes, followedPkBytes, isUnfollow, feeRateNanosPerKB, nil, []*DeSoOutput{})
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
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeFollow operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeFollow, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb(0))

	return utxoOps, txn, blockHeight, nil
}

func TestFollowTxns(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Make m3 a paramUpdater for this test
	params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(m3PkBytes)] = true

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

	doFollowTxn := func(
		senderPkBase58Check string, followedPkBase58Check string,
		senderPrivBase58Check string, isUnfollow bool, feeRateNanosPerKB uint64) {

		expectedSenderBalances = append(
			expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(
			expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _doFollowTxn(
			t, chain, db, params, feeRateNanosPerKB, senderPkBase58Check,
			followedPkBase58Check, senderPrivBase58Check, isUnfollow)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	updateProfile := func(
		feeRateNanosPerKB uint64, updaterPkBase58Check string,
		updaterPrivBase58Check string, profilePubKey []byte, newUsername string,
		newDescription string, newProfilePic string, newCreatorBasisPoints uint64,
		newStakeMultipleBasisPoints uint64, isHidden bool) {

		expectedSenderBalances = append(
			expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(
			expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

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

	// Attempting to do "m0 -> m1" should fail since m1 doesn't have a profile yet.
	_, _, _, err = _doFollowTxn(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, false /*isUnfollow*/)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFollowingNonexistentProfile)

	// Add profiles so they can be followed.
	updateProfile(
		5,             /*feeRateNanosPerKB*/
		m1Pub,         /*updaterPkBase58Check*/
		m1Priv,        /*updaterPrivBase58Check*/
		[]byte{},      /*profilePubKey*/
		"m1",          /*newUsername*/
		"i am the m1", /*newDescription*/
		shortPic,      /*newProfilePic*/
		0,             /*newCreatorBasisPoints*/
		1.25*100*100,  /*newStakeMultipleBasisPoints*/
		false /*isHidden*/)

	updateProfile(
		5,             /*feeRateNanosPerKB*/
		m2Pub,         /*updaterPkBase58Check*/
		m2Priv,        /*updaterPrivBase58Check*/
		[]byte{},      /*profilePubKey*/
		"m2",          /*newUsername*/
		"i am the m2", /*newDescription*/
		shortPic,      /*newProfilePic*/
		0,             /*newCreatorBasisPoints*/
		1.25*100*100,  /*newStakeMultipleBasisPoints*/
		false /*isHidden*/)

	updateProfile(
		5,             /*feeRateNanosPerKB*/
		m3Pub,         /*updaterPkBase58Check*/
		m3Priv,        /*updaterPrivBase58Check*/
		[]byte{},      /*profilePubKey*/
		"m3",          /*newUsername*/
		"i am the m3", /*newDescription*/
		shortPic,      /*newProfilePic*/
		0,             /*newCreatorBasisPoints*/
		1.25*100*100,  /*newStakeMultipleBasisPoints*/
		false /*isHidden*/)

	// m0 -> m1
	doFollowTxn(m0Pub, m1Pub, m0Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// Duplicating "m0 -> m1" should fail.
	_, _, _, err = _doFollowTxn(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, false /*isUnfollow*/)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFollowEntryAlreadyExists)

	// m2 -> m1
	doFollowTxn(m2Pub, m1Pub, m2Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m3 -> m1
	doFollowTxn(m3Pub, m1Pub, m3Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m3 -> m2
	doFollowTxn(m3Pub, m2Pub, m3Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m1 -> m2
	doFollowTxn(m1Pub, m2Pub, m1Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m2 -> m3
	doFollowTxn(m2Pub, m3Pub, m2Priv, false /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	followingM1 := [][]byte{
		_strToPk(t, m0Pub),
		_strToPk(t, m2Pub),
		_strToPk(t, m3Pub),
	}

	followingM2 := [][]byte{
		_strToPk(t, m1Pub),
		_strToPk(t, m3Pub),
	}

	followingM3 := [][]byte{
		_strToPk(t, m2Pub),
	}

	// Verify m0 has no follows.
	{
		followPks, err := DbGetPubKeysFollowingYou(db, chain.snapshot, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(followPks))
	}

	// Verify pks following and check like count m1.
	{
		followPks, err := DbGetPubKeysFollowingYou(db, chain.snapshot, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(len(followingM1), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(followingM1, followPks[ii])
		}
	}

	// Verify pks following and check like count m2.
	{
		followPks, err := DbGetPubKeysFollowingYou(db, chain.snapshot, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(len(followingM2), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(followingM2, followPks[ii])
		}
	}

	// Verify pks following and check like count m3.
	{
		followPks, err := DbGetPubKeysFollowingYou(db, chain.snapshot, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(len(followingM3), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(followingM3, followPks[ii])
		}
	}

	m0Follows := [][]byte{
		_strToPk(t, m1Pub),
	}

	m1Follows := [][]byte{
		_strToPk(t, m2Pub),
	}

	m2Follows := [][]byte{
		_strToPk(t, m1Pub),
		_strToPk(t, m3Pub),
	}

	m3Follows := [][]byte{
		_strToPk(t, m1Pub),
		_strToPk(t, m2Pub),
	}

	// Verify m0's follows.
	{
		followPks, err := DbGetPubKeysYouFollow(db, chain.snapshot, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(len(m0Follows), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(m0Follows, followPks[ii])
		}
	}

	// Verify m1's follows.
	{
		followPks, err := DbGetPubKeysYouFollow(db, chain.snapshot, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(len(m1Follows), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(m1Follows, followPks[ii])
		}
	}

	// Verify m2's follows.
	{
		followPks, err := DbGetPubKeysYouFollow(db, chain.snapshot, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(len(m2Follows), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(m2Follows, followPks[ii])
		}
	}

	// Verify m3's follows.
	{
		followPks, err := DbGetPubKeysYouFollow(db, chain.snapshot, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(len(m3Follows), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(m3Follows, followPks[ii])
		}
	}

	// Try an "unfollow".
	//
	// m0 -> m1 (unfollow)
	doFollowTxn(m0Pub, m1Pub, m0Priv, true /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// m3 -> m2 (unfollow)
	doFollowTxn(m3Pub, m2Pub, m3Priv, true /*isUnfollow*/, 10 /*feeRateNanosPerKB*/)

	// Duplicating "m0 -> m1" (unfollow) should fail now that the follow entry is deleted.
	_, _, _, err = _doFollowTxn(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, true /*isUnfollow*/)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorCannotUnfollowNonexistentFollowEntry)

	followingM1 = [][]byte{
		_strToPk(t, m2Pub),
		_strToPk(t, m3Pub),
	}

	followingM2 = [][]byte{
		_strToPk(t, m1Pub),
	}

	// Verify pks following and check like count m1.
	{
		followPks, err := DbGetPubKeysFollowingYou(db, chain.snapshot, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(len(followingM1), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(followingM1, followPks[ii])
		}
	}

	// Verify pks following and check like count m2.
	{
		followPks, err := DbGetPubKeysFollowingYou(db, chain.snapshot, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(len(followingM2), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(followingM2, followPks[ii])
		}
	}

	m3Follows = [][]byte{
		_strToPk(t, m1Pub),
	}

	// Verify m0 has no follows.
	{
		followPks, err := DbGetPubKeysYouFollow(db, chain.snapshot, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(followPks))
	}

	// Verify m3's follows.
	{
		followPks, err := DbGetPubKeysYouFollow(db, chain.snapshot, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(len(m3Follows), len(followPks))
		for ii := 0; ii < len(followPks); ii++ {
			require.Contains(m3Follows, followPks[ii])
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

	// This function tests the final state of applying all transactions to the view.
	testConnectedState := func() {

		followingM1 = [][]byte{
			_strToPk(t, m2Pub),
			_strToPk(t, m3Pub),
		}

		followingM2 = [][]byte{
			_strToPk(t, m1Pub),
		}

		followingM3 := [][]byte{
			_strToPk(t, m2Pub),
		}

		// Verify m0 has no follows.
		{
			followPks, err := DbGetPubKeysFollowingYou(db, chain.snapshot, _strToPk(t, m0Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}

		// Verify pks following and check like count m1.
		{
			followPks, err := DbGetPubKeysFollowingYou(db, chain.snapshot, _strToPk(t, m1Pub))
			require.NoError(err)
			require.Equal(len(followingM1), len(followPks))
			for ii := 0; ii < len(followPks); ii++ {
				require.Contains(followingM1, followPks[ii])
			}
		}

		// Verify pks following and check like count m2.
		{
			followPks, err := DbGetPubKeysFollowingYou(db, chain.snapshot, _strToPk(t, m2Pub))
			require.NoError(err)
			require.Equal(len(followingM2), len(followPks))
			for ii := 0; ii < len(followPks); ii++ {
				require.Contains(followingM2, followPks[ii])
			}
		}

		// Verify pks following and check like count m3.
		{
			followPks, err := DbGetPubKeysFollowingYou(db, chain.snapshot, _strToPk(t, m3Pub))
			require.NoError(err)
			require.Equal(len(followingM3), len(followPks))
			for i := 0; i < len(followPks); i++ {
				require.Contains(followingM3, followPks[i])
			}
		}

		m1Follows := [][]byte{
			_strToPk(t, m2Pub),
		}

		m2Follows := [][]byte{
			_strToPk(t, m1Pub),
			_strToPk(t, m3Pub),
		}

		m3Follows = [][]byte{
			_strToPk(t, m1Pub),
		}

		// Verify m0 has no follows.
		{
			followPks, err := DbGetPubKeysYouFollow(db, chain.snapshot, _strToPk(t, m0Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}

		// Verify m1's follows.
		{
			followPks, err := DbGetPubKeysYouFollow(db, chain.snapshot, _strToPk(t, m1Pub))
			require.NoError(err)
			require.Equal(len(m1Follows), len(followPks))
			for i := 0; i < len(followPks); i++ {
				require.Contains(m1Follows, followPks[i])
			}
		}

		// Verify m2's follows.
		{
			followPks, err := DbGetPubKeysYouFollow(db, chain.snapshot, _strToPk(t, m2Pub))
			require.NoError(err)
			require.Equal(len(m2Follows), len(followPks))
			for i := 0; i < len(followPks); i++ {
				require.Contains(m2Follows, followPks[i])
			}
		}

		// Verify m3's follows.
		{
			followPks, err := DbGetPubKeysYouFollow(db, chain.snapshot, _strToPk(t, m3Pub))
			require.NoError(err)
			require.Equal(len(m3Follows), len(followPks))
			for i := 0; i < len(followPks); i++ {
				require.Contains(m3Follows, followPks[i])
			}
		}
	}
	testConnectedState()

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]
		fmt.Printf("Disconnecting transaction with type %v index %d (going backwards)\n", currentTxn.TxnMeta.GetTxnType(), backwardIter)

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb(0))

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(int64(expectedSenderBalances[backwardIter]), int64(_getBalance(t, chain, nil, senderPkString)))
		require.Equal(expectedRecipientBalances[backwardIter], _getBalance(t, chain, nil, recipientPkString))
	}

	// This function is used to test the state after all ops are rolled back.
	testDisconnectedState := func() {
		// Verify that all the pks following you have been deleted.
		{
			followPks, err := DbGetPubKeysFollowingYou(db, chain.snapshot, _strToPk(t, m0Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}
		{
			followPks, err := DbGetPubKeysFollowingYou(db, chain.snapshot, _strToPk(t, m1Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}
		{
			followPks, err := DbGetPubKeysFollowingYou(db, chain.snapshot, _strToPk(t, m2Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}
		{
			followPks, err := DbGetPubKeysFollowingYou(db, chain.snapshot, _strToPk(t, m3Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}

		// Verify that all the keys you followed have been deleted.
		{
			followPks, err := DbGetPubKeysYouFollow(db, chain.snapshot, _strToPk(t, m0Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}
		{
			followPks, err := DbGetPubKeysYouFollow(db, chain.snapshot, _strToPk(t, m1Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}
		{
			followPks, err := DbGetPubKeysYouFollow(db, chain.snapshot, _strToPk(t, m2Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
		}
		{
			followPks, err := DbGetPubKeysYouFollow(db, chain.snapshot, _strToPk(t, m3Pub))
			require.NoError(err)
			require.Equal(0, len(followPks))
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
