package lib

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"reflect"
	"strings"
	"testing"
	"time"
)

func _privateMessage(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, senderPkBase58Check string,
	recipientPkBase58Check string,
	senderPrivBase58Check string, unencryptedMessageText string, tstampNanos uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := Base58CheckDecode(senderPkBase58Check)
	require.NoError(err)

	recipientPkBytes, _, err := Base58CheckDecode(recipientPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreatePrivateMessageTxn(
		senderPkBytes, recipientPkBytes, unencryptedMessageText, "",
		[]byte{}, []byte{}, []byte{}, []byte{},
		tstampNanos, feeRateNanosPerKB, nil, []*DeSoOutput{})
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
	// for each output, and one OperationTypePrivateMessage operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypePrivateMessage, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func TestPrivateMessage(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
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

	privateMessage := func(
		senderPkBase58Check string, recipientPkBase58Check string,
		senderPrivBase58Check string, unencryptedMessageText string, tstampNanos uint64,
		feeRateNanosPerKB uint64) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _privateMessage(
			t, chain, db, params, feeRateNanosPerKB, senderPkBase58Check,
			recipientPkBase58Check, senderPrivBase58Check, unencryptedMessageText, tstampNanos)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// ===================================================================================
	// Do some PrivateMessage transactions
	// ===================================================================================
	tstamp1 := uint64(time.Now().UnixNano())
	message1 := string(append([]byte("message1: "), RandomBytes(100)...))
	tstamp2 := uint64(time.Now().UnixNano())
	message2 := string(append([]byte("message2: "), RandomBytes(100)...))
	tstamp3 := uint64(time.Now().UnixNano())
	message3 := string(append([]byte("message3: "), RandomBytes(100)...))
	tstamp4 := uint64(time.Now().UnixNano())
	message4 := string(append([]byte("message4: "), RandomBytes(100)...))
	message5 := string(append([]byte("message5: "), RandomBytes(100)...))
	// Because M1 actually evaluates two consecutive time.Now().UnixNano() to the same number lol!
	if tstamp1 == tstamp2 {
		tstamp2 += uint64(1)
		tstamp3 += uint64(1)
		tstamp4 += uint64(1)
	}
	if tstamp2 == tstamp3 {
		tstamp3 += uint64(1)
		tstamp4 += uint64(1)
	}
	if tstamp3 == tstamp4 {
		tstamp4 += uint64(1)
	}
	// Message where the sender is the recipient should fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		m0Pub, m0Priv, "test" /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageSenderPublicKeyEqualsRecipientPublicKey)

	// Message with length too long should fail.
	badMessage := string(append([]byte("badMessage: "),
		RandomBytes(int32(params.MaxPrivateMessageLengthBytes))...))
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, badMessage /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageEncryptedTextLengthExceedsMax)

	// Zero tstamp should fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, message1 /*unencryptedMessageText*/, 0)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageTstampIsZero)

	// m0 -> m1: message1, tstamp1
	privateMessage(
		m0Pub, m1Pub, m0Priv, message1, tstamp1, 0 /*feeRateNanosPerKB*/)

	// Duplicating (m0, tstamp1) should fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, message1 /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageExistsWithSenderPublicKeyTstampTuple)

	// Duplicating (m1, tstamp1) should fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m1Pub,
		m0Pub, m1Priv, message1 /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageExistsWithSenderPublicKeyTstampTuple)

	// Duplicating (m0, tstamp1) with a different sender should still fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m2Pub,
		m0Pub, m2Priv, message1 /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageExistsWithRecipientPublicKeyTstampTuple)

	// Duplicating (m1, tstamp1) with a different sender should still fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m2Pub,
		m1Pub, m2Priv, message1 /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageExistsWithRecipientPublicKeyTstampTuple)

	// m2 -> m1: message2, tstamp2
	privateMessage(
		m2Pub, m1Pub, m2Priv, message2, tstamp2, 10 /*feeRateNanosPerKB*/)

	// m3 -> m1: message3, tstamp3
	privateMessage(
		m3Pub, m1Pub, m3Priv, message3, tstamp3, 10 /*feeRateNanosPerKB*/)

	// m2 -> m1: message4Str, tstamp4
	privateMessage(
		m1Pub, m2Pub, m1Priv, message4, tstamp4, 10 /*feeRateNanosPerKB*/)

	// m2 -> m3: message5Str, tstamp1
	// Using tstamp1 should be OK since the message is between two new users.
	privateMessage(
		m2Pub, m3Pub, m2Priv, message5, tstamp1, 10 /*feeRateNanosPerKB*/)

	// Verify that the messages are as we expect them in the db.
	// 1: m0 m1
	// 2: m2 m1
	// 3: m3 m1
	// 4: m1 m2
	// 5: m2 m3
	// => m0: 1
	// 		m1: 4
	//    m2: 3
	//    m3: 2
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(1, len(messages))
		messageEntry := messages[0]
		require.Equal(messageEntry.SenderPublicKey, _strToPk(t, m0Pub))
		require.Equal(messageEntry.RecipientPublicKey, _strToPk(t, m1Pub))
		require.Equal(messageEntry.TstampNanos, tstamp1)
		require.Equal(messageEntry.isDeleted, false)
		priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), _strToPk(t, m1Priv))
		decryptedBytes, err := DecryptBytesWithPrivateKey(messageEntry.EncryptedText, priv.ToECDSA())
		require.NoError(err)
		require.Equal(message1, string(decryptedBytes))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(4, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(3, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(2, len(messages))
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
		fmt.Printf("Disconnecting transaction with type %v index %d (going backwards)\n", currentTxn.TxnMeta.GetTxnType(), backwardIter)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(expectedSenderBalances[backwardIter], _getBalance(t, chain, nil, senderPkString))
		require.Equal(expectedRecipientBalances[backwardIter], _getBalance(t, chain, nil, recipientPkString))
	}

	// Verify that all the messages have been deleted.
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}

	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	for ii, tx := range txns {
		// See comment above on this transaction.
		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		require.Equal(expectedSenderBalances[ii], _getBalance(t, chain, mempool, senderPkString))
		require.Equal(expectedRecipientBalances[ii], _getBalance(t, chain, mempool, recipientPkString))

		acceptedTxns, err := mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, tx)
		require.Equal(1, len(acceptedTxns))
	}

	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(db, params, nil)
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
	require.NoError(utxoView.FlushToDb())

	// Disonnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView2, err := NewUtxoView(db, params, nil)
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
	require.NoError(utxoView2.FlushToDb())
	require.Equal(expectedSenderBalances[0], _getBalance(t, chain, nil, senderPkString))
	require.Equal(expectedRecipientBalances[0], _getBalance(t, chain, nil, recipientPkString))

	// Verify that all the messages have been deleted.
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}

	// Try and estimate the fees in a situation where the last block contains just a
	// block reward.
	{
		// Fee should just equal the min passed in because the block has so few transactions.
		require.Equal(int64(0), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 0)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 7)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 7)))
		require.Equal(int64(0), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 0)))
		require.Equal(int64(1), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 1)))
		require.Equal(int64(1), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 1)))
	}

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

	// Verify that all the messages have been deleted.
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
}

// This helper function is used to generate a random messaging key and the signed hash(publicKey || keyName).
func _generateMessagingKey(senderPub, senderPriv, keyName []byte) (
	priv *btcec.PrivateKey, sign []byte, messagingKeyEntry *MessagingKeyEntry) {

	senderPrivKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), senderPriv)

	priv, _ = btcec.NewPrivateKey(btcec.S256())
	pub := priv.PubKey().SerializeCompressed()

	payload := append(pub, keyName...)
	signature, _ := senderPrivKey.Sign(Sha256DoubleHash(payload)[:])

	return priv, signature.Serialize(), _initMessagingKey(senderPub, pub, keyName)
}

// Adds a messaging key to provided utxoView
func _messagingKey(t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams,
	senderPk []byte, signerPriv string, messagingPublicKey, messagingKeyName,
	keySignature []byte, recipients []MessagingRecipient) ([]*UtxoOperation, *MsgDeSoTxn, error) {

	require := require.New(t)
	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateMessagingKeyTxn(senderPk, messagingPublicKey, messagingKeyName, keySignature,
		[]byte{}, recipients, 10, nil, []*DeSoOutput{})
	require.NoError(err)
	require.Equal(totalInputMake, changeAmountMake+feesMake)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	_signTxn(t, txn, signerPriv)
	txHash := txn.Hash()
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
			true /*verifySignature*/, false /*ignoreUtxos*/)
	if err != nil {
		return nil, nil, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)
	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypePrivateMessage operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeMessagingKey, utxoOps[len(utxoOps)-1].Type)
	require.NoError(utxoView.FlushToDb())
	return utxoOps, txn, err
}

func _messagingKeyWithTestMeta(testMeta *TestMeta, senderPk []byte, signerPriv string,
	messagingPublicKey, messagingKeyName, keySignature []byte, recipients []MessagingRecipient,
	expectedError error) {

	require := require.New(testMeta.t)
	assert := assert.New(testMeta.t)

	senderPkBase58Check := Base58CheckEncode(senderPk, false, testMeta.params)
	balance := _getBalance(testMeta.t, testMeta.chain, nil, senderPkBase58Check)

	utxoOps, txn, err := _messagingKey(testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		senderPk, signerPriv, messagingPublicKey, messagingKeyName, keySignature, recipients)

	if expectedError != nil {
		assert.Equal(true, strings.Contains(err.Error(), expectedError.Error()))
		return
	}
	require.NoError(err)

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, balance)
	testMeta.txnOps = append(testMeta.txnOps, utxoOps)
	testMeta.txns = append(testMeta.txns, txn)
}

// This helper function allows us to verify that a messaging key was properly connected to utxoView and
// that it matches the expected entry that's provided.
func _verifyMessagingKey(testMeta *TestMeta, entry *MessagingKeyEntry) bool {
	var utxoMessagingEntry *MessagingKeyEntry

	require := require.New(testMeta.t)
	messagingKey := NewMessagingKey(entry.PublicKey, entry.MessagingKeyName[:])
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, nil)
	require.NoError(err)
	utxoMessagingEntry = utxoView.GetMessagingKeyToMessagingKeyEntryMapping(messagingKey)

	if utxoMessagingEntry == nil || utxoMessagingEntry.isDeleted {
		return false
	}

	return reflect.DeepEqual(utxoMessagingEntry.Encode(), entry.Encode())
	//return reflect.DeepEqual(*entry.MessagingPublicKey, *utxoMessagingEntry.MessagingPublicKey) &&
	//	reflect.DeepEqual(*entry.MessagingKeyName, *utxoMessagingEntry.MessagingKeyName) &&
	//	reflect.DeepEqual(*entry.publicKey, *utxoMessagingEntry.publicKey)
}

func _verifyAddedMessagingKeys(testMeta *TestMeta, publicKey []byte, expectedEntries []*MessagingKeyEntry) error {
	return testMeta.chain.db.View(func(txn *badger.Txn) error {
		entries, err := DbGetAllUserMessagingKeys(txn, publicKey)
		if err != nil {
			return err
		}
		if len(entries) != len(expectedEntries) {
			return fmt.Errorf("")
		}
		for _, expectedEntry := range expectedEntries {
			ok := false
			for _, entry := range entries {
				if reflect.DeepEqual(expectedEntry.Encode(), entry.Encode()) {
					ok = true
					break
				}
			}
			if !ok {
				return fmt.Errorf("")
			}
		}
		return nil
	})
}

func _initMessagingKey(senderPublicKey, messagingPublicKey, messagingKeyName []byte) *MessagingKeyEntry {
	return &MessagingKeyEntry{
		PublicKey:          NewPublicKey(senderPublicKey),
		MessagingPublicKey: NewPublicKey(messagingPublicKey),
		MessagingKeyName:   NewKeyName(messagingKeyName),
	}
}

func TestMessagingKeys(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	_ = require
	_ = assert

	// Set the DeSo V3 messages block height to 0
	DeSoV3MessagesBlockHeight = 0

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_ = miner

	// Mine two blocks to give the sender some DeSo.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	testMeta := &TestMeta{
		t:           t,
		chain:       chain,
		params:      params,
		db:          db,
		mempool:     mempool,
		miner:       miner,
		savedHeight: chain.blockTip().Height + 1,
	}

	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)
	senderPrivBytes, _, err := Base58CheckDecode(senderPrivString)
	require.NoError(err)

	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		_, _, _ = _doBasicTransferWithViewFlush(
			t, chain, db, params, senderPk, recipientPk,
			senderPriv, 7 /*amount to send*/, 11 /*feerate*/)
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

	m0PubKey, _, err := Base58CheckDecode(m0Pub)
	require.NoError(err)
	m0PrivKey, _, err := Base58CheckDecode(m0Priv)
	require.NoError(err)

	m1PubKey, _, err := Base58CheckDecode(m1Pub)
	require.NoError(err)
	m1PrivKey, _, err := Base58CheckDecode(m1Priv)
	require.NoError(err)

	m2PubKey, _, err := Base58CheckDecode(m2Pub)
	require.NoError(err)
	m2PrivKey, _, err := Base58CheckDecode(m2Priv)
	require.NoError(err)

	m3PubKey, _, err := Base58CheckDecode(m3Pub)
	require.NoError(err)
	m3PrivKey, _, err := Base58CheckDecode(m3Priv)
	require.NoError(err)

	// -------------------------------------------------------------------------------------
	//	Test #1: Check that entry is correctly set in UtxoView and flushed to DB
	// -------------------------------------------------------------------------------------
	entriesAdded := make(map[PublicKey][]*MessagingKeyEntry)
	{
		// Try adding base messaging key, should fail
		baseKeyName := BaseKeyName()
		_, sign, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, baseKeyName[:])
		// The base entry has the same messaging public key as the owner's main key
		entry.MessagingPublicKey = entry.PublicKey
		// The base key should always be present in UtxoView.
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			baseKeyName[:],
			sign,
			[]MessagingRecipient{},
			RuleErrorMessagingKeyNameCannotBeZeros)
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
		// Append the base key to the entries added
		entriesAdded[*NewPublicKey(senderPkBytes)] = append(entriesAdded[*NewPublicKey(senderPkBytes)], entry)
	}
	{
		// Try adding default messaging key without signature
		defaultKeyName := []byte("default-key")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, defaultKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			defaultKeyName,
			[]byte{},
			[]MessagingRecipient{},
			RuleErrorMessagingSignatureInvalid)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
	}
	{
		// Try adding default messaging key with malformed messaging public key
		defaultKeyName := []byte("default-key")
		_, sign, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, defaultKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:15],
			defaultKeyName,
			sign,
			[]MessagingRecipient{},
			RuleErrorPubKeyLen)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
	}
	{
		// Try adding messaging key with malformed messaging key name
		defaultKeyName := []byte("default-key")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, defaultKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			defaultKeyName[:4],
			[]byte{},
			[]MessagingRecipient{},
			RuleErrorMessagingKeyNameTooShort)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
	}
	{
		// Try adding messaging key with malformed messaging key name
		defaultKeyName := []byte("default-key")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, defaultKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			append(defaultKeyName, NewKeyName([]byte{})[:]...),
			[]byte{},
			[]MessagingRecipient{},
			RuleErrorMessagingKeyNameTooLong)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
	}
	{
		// Try adding correct default messaging key
		defaultKeyName := []byte("default-key")
		_, sign, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, defaultKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			defaultKeyName,
			sign,
			[]MessagingRecipient{},
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
		// Append the default key to the entries added
		entriesAdded[*NewPublicKey(senderPkBytes)] = append(entriesAdded[*NewPublicKey(senderPkBytes)], entry)
	}
	{
		// Try adding a non-default key without signature
		randomKeyName := []byte("test-key-1")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomKeyName,
			[]byte{},
			[]MessagingRecipient{},
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
		// Append the non-default key to the entries added
		entriesAdded[*NewPublicKey(senderPkBytes)] = append(entriesAdded[*NewPublicKey(senderPkBytes)], entry)
	}
	{
		// Try adding another non-default key but with signature.
		// Shouldn't affect anything
		randomKeyName := []byte("test-key-2")
		_, sign, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomKeyName,
			sign,
			[]MessagingRecipient{},
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
		// Append the non-default key to the entries added
		entriesAdded[*NewPublicKey(senderPkBytes)] = append(entriesAdded[*NewPublicKey(senderPkBytes)], entry)
	}
	{
		// Try adding the random key again without changing anything, this should fail.
		// We would accept an update to a messaging key only if we add group recipients.
		randomKeyName := []byte("test-key-2")
		entry := entriesAdded[*NewPublicKey(senderPkBytes)][len(entriesAdded[*NewPublicKey(senderPkBytes)])-1]
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomKeyName,
			[]byte{},
			[]MessagingRecipient{},
			RuleErrorMessagingKeyDoesntAddRecipients)
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
	}
	{
		// Try adding the random key again but with a different messaging public key, this should fail.
		randomKeyName := []byte("test-key-2")
		entry := entriesAdded[*NewPublicKey(senderPkBytes)][len(entriesAdded[*NewPublicKey(senderPkBytes)])-1]
		_, _, newEntry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomKeyName)
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			newEntry.MessagingPublicKey[:],
			randomKeyName,
			[]byte{},
			[]MessagingRecipient{},
			RuleErrorMessagingPublicKeyCannotBeDifferent)
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
		require.Equal(false, _verifyMessagingKey(testMeta, newEntry))
	}
	{
		// Try adding the random key again but with a "filled" key name, this should fail.
		randomKeyName := []byte("test-key-2")
		entry := entriesAdded[*NewPublicKey(senderPkBytes)][len(entriesAdded[*NewPublicKey(senderPkBytes)])-1]
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			append(randomKeyName, byte(0)),
			[]byte{},
			[]MessagingRecipient{},
			RuleErrorMessagingKeyDoesntAddRecipients)
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
	}
	require.NoError(_verifyAddedMessagingKeys(testMeta, senderPkBytes, entriesAdded[*NewPublicKey(senderPkBytes)]))

	// -------------------------------------------------------------------------------------
	//	Test #2: We will add messaging keys with message recipients
	// -------------------------------------------------------------------------------------
	{
		// SenderPk: Try adding a non-default key with an incorrect recipient of senderPk
		// Can't add yourself as a recipient.
		randomGroupKeyName := []byte("test-key-3")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		entry.Recipients = append(entry.Recipients, MessagingRecipient{
			NewPublicKey(senderPkBytes),
			BaseKeyName(),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.Recipients,
			RuleErrorMessagingRecipientAlreadyExists)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
	}
	{
		// SenderPk: Try adding a non-default key with an incorrect recipient of senderPk
		// Can't add messaging public key as a recipient.
		randomGroupKeyName := []byte("test-key-3")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		entry.Recipients = append(entry.Recipients, MessagingRecipient{
			NewPublicKey(entry.MessagingPublicKey[:]),
			BaseKeyName(),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.Recipients,
			RuleErrorMessagingRecipientAlreadyExists)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
	}
	{
		// SenderPk: Try adding a messaging recipient for m0PubKey with a non-existent key.
		randomGroupKeyName := []byte("test-key-3")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		entry.Recipients = append(entry.Recipients, MessagingRecipient{
			NewPublicKey(m0PubKey),
			NewKeyName([]byte("non-existent-key")),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.Recipients,
			RuleErrorMessagingRecipientKeyDoesntExist)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
	}
	{
		// SenderPk: Try adding a messaging recipient for m0PubKey with a malformed encrypted key.
		randomGroupKeyName := []byte("test-key-3")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		entry.Recipients = append(entry.Recipients, MessagingRecipient{
			NewPublicKey(m0PubKey),
			BaseKeyName(),
			senderPrivBytes[:15],
		})
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.Recipients,
			RuleErrorMessagingRecipientEncryptedKeyTooShort)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
	}
	{
		// SenderPk: Try adding same messaging recipient for m0PubKey twice.
		randomGroupKeyName := []byte("test-key-3")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		entry.Recipients = append(entry.Recipients, MessagingRecipient{
			NewPublicKey(m0PubKey),
			BaseKeyName(),
			senderPrivBytes,
		}, MessagingRecipient{
			NewPublicKey(m0PubKey),
			BaseKeyName(),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.Recipients,
			RuleErrorMessagingRecipientAlreadyExists)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
	}
	// Now we will actually try to add recipients
	{
		_, _, entry := _generateMessagingKey(m0PubKey, m0PrivKey, BaseKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m0PubKey)
		entriesAdded[*NewPublicKey(m0PubKey)] = append(entriesAdded[*NewPublicKey(m0PubKey)], entry)

		_, _, entry = _generateMessagingKey(m1PubKey, m1PrivKey, BaseKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m1PubKey)
		entriesAdded[*NewPublicKey(m1PubKey)] = append(entriesAdded[*NewPublicKey(m1PubKey)], entry)

		_, _, entry = _generateMessagingKey(m2PubKey, m2PrivKey, BaseKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m2PubKey)
		entriesAdded[*NewPublicKey(m2PubKey)] = append(entriesAdded[*NewPublicKey(m2PubKey)], entry)

		_, _, entry = _generateMessagingKey(m3PubKey, m3PrivKey, BaseKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m3PubKey)
		entriesAdded[*NewPublicKey(m3PubKey)] = append(entriesAdded[*NewPublicKey(m3PubKey)], entry)
	}
	// Add some random key for m1Pub
	{
		// Try adding another non-default key but with signature.
		// Shouldn't affect anything
		randomKeyName := []byte("totally-random-key")
		_, _, entry := _generateMessagingKey(m1PubKey, m1PrivKey, randomKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			m1PubKey,
			m1Priv,
			entry.MessagingPublicKey[:],
			randomKeyName,
			[]byte{},
			[]MessagingRecipient{},
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
		// Append the non-default key to the entries added
		entriesAdded[*NewPublicKey(m1PubKey)] = append(entriesAdded[*NewPublicKey(m1PubKey)], entry)
	}
	{
		// SenderPk: Try adding a correct recipient for m0PubKey.
		randomGroupKeyName := []byte("test-key-3")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		entry.Recipients = append(entry.Recipients, MessagingRecipient{
			NewPublicKey(m0PubKey),
			BaseKeyName(),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.Recipients,
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, entry))

		// SenderPk: Try re-adding the same recipient for m0PubKey, should fail
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.Recipients,
			RuleErrorMessagingRecipientAlreadyExists)
		require.Equal(true, _verifyMessagingKey(testMeta, entry))

		// m1: Try to add himself to the group
		var entryCopy MessagingKeyEntry
		require.NoError(entryCopy.Decode(entry.Encode()))
		entryCopy.Recipients[0] = MessagingRecipient{
			NewPublicKey(m1PubKey),
			NewKeyName([]byte("totally-random-key")),
			senderPrivBytes,
		}
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			m1Priv,
			entryCopy.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entryCopy.Recipients,
			RuleErrorInvalidTransactionSignature)

		var workingCopy MessagingKeyEntry
		require.NoError(workingCopy.Decode(entry.Encode()))
		workingCopy.Recipients[0] = MessagingRecipient{
			NewPublicKey(m1PubKey),
			NewKeyName([]byte("totally-random-key")),
			senderPrivBytes,
		}
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			workingCopy.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			workingCopy.Recipients,
			nil)

		entry.Recipients = append(entry.Recipients, MessagingRecipient{
			NewPublicKey(m1PubKey),
			NewKeyName([]byte("totally-random-key")),
			senderPrivBytes,
		})
		// Append the base key to the entries added
		entriesAdded[*NewPublicKey(senderPkBytes)] = append(entriesAdded[*NewPublicKey(senderPkBytes)], entry)
		entriesAdded[*NewPublicKey(m0PubKey)] = append(entriesAdded[*NewPublicKey(m0PubKey)], &MessagingKeyEntry{
			PublicKey:          NewPublicKey(m0PubKey),
			MessagingPublicKey: NewPublicKey(entry.MessagingPublicKey[:]),
			MessagingKeyName:   BaseKeyName(),
			EncryptedKey:       senderPrivBytes,
		})
		entriesAdded[*NewPublicKey(m1PubKey)] = append(entriesAdded[*NewPublicKey(m1PubKey)], &MessagingKeyEntry{
			PublicKey: NewPublicKey(m1PubKey),
			MessagingPublicKey: NewPublicKey(entry.MessagingPublicKey[:]),
			MessagingKeyName: NewKeyName([]byte("totally-random-key")),
			EncryptedKey: senderPrivBytes,
		})
	}
	// Add some random key for m0Pub
	{
		// Try adding another non-default key but with signature.
		// Shouldn't affect anything
		randomKeyName := []byte("totally-random-key2")
		_, _, entry := _generateMessagingKey(m0PubKey, m0PrivKey, randomKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			m0PubKey,
			m0Priv,
			entry.MessagingPublicKey[:],
			randomKeyName,
			[]byte{},
			[]MessagingRecipient{},
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
		// Append the non-default key to the entries added
		entriesAdded[*NewPublicKey(m0PubKey)] = append(entriesAdded[*NewPublicKey(m0PubKey)], entry)
	}
	// Add a default key for m3Pub
	{
		// Try adding another non-default key but with signature.
		// Shouldn't affect anything
		randomKeyName := DefaultKeyName()
		_, sign, entry := _generateMessagingKey(m3PubKey, m3PrivKey, randomKeyName[:])
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			m3PubKey,
			m3Priv,
			entry.MessagingPublicKey[:],
			randomKeyName[:],
			sign,
			[]MessagingRecipient{},
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
		// Append the non-default key to the entries added
		entriesAdded[*NewPublicKey(m3PubKey)] = append(entriesAdded[*NewPublicKey(m3PubKey)], entry)
	}
	{
		// SenderPk: Try adding a correct recipient for m0PubKey.
		randomGroupKeyName := []byte("final-group-key")
		_, _, entry := _generateMessagingKey(m1PubKey, m1PrivKey, randomGroupKeyName)
		// Now add a lot of people
		entry.Recipients = append(entry.Recipients, MessagingRecipient{
			NewPublicKey(senderPkBytes),
			DefaultKeyName(),
			senderPrivBytes,
		})
		entry.Recipients = append(entry.Recipients, MessagingRecipient{
			NewPublicKey(m0PubKey),
			NewKeyName([]byte("totally-random-key2")),
			senderPrivBytes,
		})
		entry.Recipients = append(entry.Recipients, MessagingRecipient{
			NewPublicKey(m2PubKey),
			BaseKeyName(),
			senderPrivBytes,
		})
		entry.Recipients = append(entry.Recipients, MessagingRecipient{
			NewPublicKey(m3PubKey),
			DefaultKeyName(),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			m1PubKey,
			m1Priv,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.Recipients,
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, entry))
		entriesAdded[*NewPublicKey(m1PubKey)] = append(entriesAdded[*NewPublicKey(m1PubKey)], entry)
		entriesAdded[*NewPublicKey(senderPkBytes)] = append(entriesAdded[*NewPublicKey(senderPkBytes)], &MessagingKeyEntry{
			PublicKey:          NewPublicKey(senderPkBytes),
			MessagingPublicKey: NewPublicKey(entry.MessagingPublicKey[:]),
			MessagingKeyName:   DefaultKeyName(),
			EncryptedKey:       senderPrivBytes,
		})
		entriesAdded[*NewPublicKey(m0PubKey)] = append(entriesAdded[*NewPublicKey(m0PubKey)], &MessagingKeyEntry{
			PublicKey: NewPublicKey(m0PubKey),
			MessagingPublicKey: NewPublicKey(entry.MessagingPublicKey[:]),
			MessagingKeyName: NewKeyName([]byte("totally-random-key2")),
			EncryptedKey: senderPrivBytes,
		})
		entriesAdded[*NewPublicKey(m2PubKey)] = append(entriesAdded[*NewPublicKey(m2PubKey)], &MessagingKeyEntry{
			PublicKey: NewPublicKey(m2PubKey),
			MessagingPublicKey: NewPublicKey(entry.MessagingPublicKey[:]),
			MessagingKeyName: BaseKeyName(),
			EncryptedKey: senderPrivBytes,
		})
		entriesAdded[*NewPublicKey(m3PubKey)] = append(entriesAdded[*NewPublicKey(m3PubKey)], &MessagingKeyEntry{
			PublicKey: NewPublicKey(m3PubKey),
			MessagingPublicKey: NewPublicKey(entry.MessagingPublicKey[:]),
			MessagingKeyName: DefaultKeyName(),
			EncryptedKey: senderPrivBytes,
		})
	}
	require.NoError(_verifyAddedMessagingKeys(testMeta, senderPkBytes, entriesAdded[*NewPublicKey(senderPkBytes)]))
	require.NoError(_verifyAddedMessagingKeys(testMeta, m0PubKey, entriesAdded[*NewPublicKey(m0PubKey)]))
	require.NoError(_verifyAddedMessagingKeys(testMeta, m1PubKey, entriesAdded[*NewPublicKey(m1PubKey)]))
	require.NoError(_verifyAddedMessagingKeys(testMeta, m2PubKey, entriesAdded[*NewPublicKey(m2PubKey)]))
	require.NoError(_verifyAddedMessagingKeys(testMeta, m3PubKey, entriesAdded[*NewPublicKey(m3PubKey)]))

	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)

	{
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, BaseKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(senderPkBytes)
		entriesAdded[*NewPublicKey(senderPkBytes)] = append([]*MessagingKeyEntry{}, entry)

		_, _, entry = _generateMessagingKey(m0PubKey, m0PrivKey, BaseKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m0PubKey)
		entriesAdded[*NewPublicKey(m0PubKey)] = append([]*MessagingKeyEntry{}, entry)

		_, _, entry = _generateMessagingKey(m1PubKey, m1PrivKey, BaseKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m1PubKey)
		entriesAdded[*NewPublicKey(m1PubKey)] = append([]*MessagingKeyEntry{}, entry)

		_, _, entry = _generateMessagingKey(m2PubKey, m2PrivKey, BaseKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m2PubKey)
		entriesAdded[*NewPublicKey(m2PubKey)] = append([]*MessagingKeyEntry{}, entry)

		_, _, entry = _generateMessagingKey(m3PubKey, m3PrivKey, BaseKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m3PubKey)
		entriesAdded[*NewPublicKey(m3PubKey)] = append([]*MessagingKeyEntry{}, entry)
	}

	require.NoError(_verifyAddedMessagingKeys(testMeta, senderPkBytes, entriesAdded[*NewPublicKey(senderPkBytes)]))
	require.NoError(_verifyAddedMessagingKeys(testMeta, m0PubKey, entriesAdded[*NewPublicKey(m0PubKey)]))
	require.NoError(_verifyAddedMessagingKeys(testMeta, m1PubKey, entriesAdded[*NewPublicKey(m1PubKey)]))
	require.NoError(_verifyAddedMessagingKeys(testMeta, m2PubKey, entriesAdded[*NewPublicKey(m2PubKey)]))
	require.NoError(_verifyAddedMessagingKeys(testMeta, m3PubKey, entriesAdded[*NewPublicKey(m3PubKey)]))

}

// In these tests we basically want to verify that MessageParty records are correctly added to UtxoView and DB
// after we send V3 messages.
func TestMessageParty(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	_ = require
	_ = assert

	// Set the DeSo V3 messages block height to 0
	DeSoV3MessagesBlockHeight = 0

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_ = miner

	// Mine two blocks to give the sender some DeSo.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	// This helper function connects a private message transaction with the message party in ExtraData.
	_helpConnectPrivateMessage := func(senderPkBytes []byte, senderPrivBase58 string, recipientPkBytes,
		senderMessagingPublicKey, senderMessagingKeyName, recipientMessagingPublicKey,
		recipientMessagingKeyName []byte, encryptedMessageText string, tstampNanos uint64,
		utxoView *UtxoView) ([]*UtxoOperation, *MsgDeSoTxn, error) {

		// Create a private message transaction with the sender and recipient messaging keys.
		txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreatePrivateMessageTxn(
			senderPkBytes, recipientPkBytes, "", encryptedMessageText,
			senderMessagingPublicKey, senderMessagingKeyName, recipientMessagingPublicKey,
			recipientMessagingKeyName, tstampNanos, 10, nil, []*DeSoOutput{})
		if err != nil {
			return nil, nil, err
		}

		require.Equal(totalInputMake, changeAmountMake+feesMake)

		// Sign the transaction now that its inputs are set up.
		_signTxn(t, txn, senderPrivBase58)

		txHash := txn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		utxoOps, totalInput, totalOutput, fees, err :=
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
		// ConnectTransaction should treat the amount locked as contributing to the
		// output.
		if err != nil {
			return nil, nil, err
		}
		require.Equal(totalInput, totalOutput+fees)
		require.Equal(totalInput, totalInputMake)

		return utxoOps, txn, nil
	}

	// Verify that a message party entry exists iff message entry exists.
	_verifyExistsMessageEntryAndParty := func(utxoView *UtxoView, senderPk []byte, tstampNanos uint64) bool {
		messageKey := MakeMessageKey(senderPk, tstampNanos)
		messageEntry := utxoView._getMessageEntryForMessageKey(&messageKey)
		messageParty := utxoView._getMessageKeyToMessageParty(&messageKey)
		if messageEntry != nil && !messageEntry.isDeleted {
			if messageParty != nil && !messageParty.isDeleted {
				return reflect.DeepEqual((*messageParty.senderPublicKey)[:], messageEntry.SenderPublicKey) &&
					reflect.DeepEqual((*messageParty.recipientPublicKey)[:], messageEntry.RecipientPublicKey)
			} else {
				return false
			}
		} else {
			if messageParty == nil || messageParty.isDeleted {
				return true
			}
			return false
		}
		return true
	}

	// Verify the message party entry in UtxoView or DB matches the expected entry.
	_verifyMessageParty := func(utxoView *UtxoView, senderPk []byte, tstampNanos uint64,
		senderMsgPk, recipientMsgPk []byte, senderMsgKeyName, recipientMsgKeyName KeyName) bool {
		messageKey := MakeMessageKey(senderPk, tstampNanos)
		messageParty := utxoView._getMessageKeyToMessageParty(&messageKey)
		if messageParty == nil || messageParty.isDeleted {
			return false
		}
		return reflect.DeepEqual(senderMsgPk, (*messageParty.SenderMessagingPublicKey)[:]) &&
			reflect.DeepEqual(recipientMsgPk, (*messageParty.RecipientMessagingPublicKey)[:]) &&
			reflect.DeepEqual(senderMsgKeyName[:], (*messageParty.SenderMessagingKeyName)[:]) &&
			reflect.DeepEqual(recipientMsgKeyName[:], (*messageParty.RecipientMessagingKeyName)[:])
	}

	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)
	senderPrivBytes, _, err := Base58CheckDecode(senderPrivString)
	require.NoError(err)

	recipientPkBytes, _, err := Base58CheckDecode(recipientPkString)
	require.NoError(err)
	recipientPrivBytes, _, err := Base58CheckDecode(recipientPrivString)
	_ = recipientPrivBytes
	require.NoError(err)

	// -------------------------------------------------------------------------------------
	//	Test #1: Attempt sending a V3 private message without a previously authorized messaging key.
	// -------------------------------------------------------------------------------------
	{
		// Generate a random messaging key but never authorize it.
		keyName := []byte("default-key")
		priv, pub, _ := _generateMessagingKey(senderPkBytes, senderPrivBytes, keyName)
		_ = priv

		// Connect a V3 private message to the UtxoView, which should fail.
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		tstampNanos := uint64(time.Now().UnixNano())
		testMessage1 := hex.EncodeToString([]byte{1, 2, 3, 4, 5, 6})
		_, _, err = _helpConnectPrivateMessage(senderPkBytes, senderPrivString,
			recipientPkBytes, pub, keyName, []byte{}, []byte{}, testMessage1, tstampNanos, utxoView)
		assert.Error(err)
		// Verification should fail because the <pub, keyName> was never added to UtxoView.
		// This will return true because neither message nor message party was added.
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos))
		fmt.Println("PASSED Test #1: Attempt sending a V3 private message without a previously authorized messaging key.")
	}

	// -------------------------------------------------------------------------------------
	//	Test #2: Attempt sending a V3 private message with an authorized messaging key.
	//	Test #3: Attempt disconnecting a valid V3 private message.
	// -------------------------------------------------------------------------------------
	{
		// Generate a random messaging key and this time authorize it.
		keyName := []byte("default-key")
		priv, pub, _ := _generateMessagingKey(senderPkBytes, senderPrivBytes, keyName)
		_ = priv

		// Authorize the messaging key with a basic transfer and flush to DB.
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		// Add the messaging key to the utxoView
		//_, _, err = _messagingKey(t, chain, db, params, senderPkBytes, recipientPkBytes, senderPrivString, utxoView,
		//	nil, pub, keyName, sign)
		require.NoError(utxoView.FlushToDb())

		// Connect a V3 message in a fresh new UtxoView with the <pub, keyName>
		utxoView, err = NewUtxoView(db, params, nil)
		tstampNanos := uint64(time.Now().UnixNano())
		testMessage1 := hex.EncodeToString([]byte{1, 2, 3, 4, 5, 6})
		utxoOps, txn, err := _helpConnectPrivateMessage(senderPkBytes, senderPrivString,
			recipientPkBytes, pub, keyName, []byte{}, []byte{}, testMessage1, tstampNanos, utxoView)
		assert.NoError(err)
		// Because the key has been authorized we should pass verification of the message party entry.
		// We first verify that both message entry and message party entry are present in the UtxoView.
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos))
		// We now verify that message party entry matches expected result.
		require.Equal(true, _verifyMessageParty(utxoView, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))
		fmt.Println("PASSED Test #2: Attempt sending a V3 private message with an authorized messaging key.")

		// Test #3: Attempt disconnecting a valid V3 private message.
		// First we disconnect the transaction from UtxoView
		require.NoError(utxoView.DisconnectTransaction(txn, txn.Hash(), utxoOps, chain.blockTip().Height+1))
		// Verify that neither message entry nor message party entry exist in the DB. Test should pass.
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos))
		// Verify that the entry is deleted from the DB. Should evaluate to false.
		require.Equal(false, _verifyMessageParty(utxoView, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))

		// We will add the message transaction again, then flush it to DB, and then try disconnecting it.
		utxoOps, _, _, _, err = utxoView.ConnectTransaction(txn, txn.Hash(), getTxnSize(*txn), chain.blockTip().Height+1, true, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
		// Verify just in case.
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos))
		require.Equal(true, _verifyMessageParty(utxoView, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))

		// Disconnect the transaction and verify that tests fail.
		require.NoError(utxoView.DisconnectTransaction(txn, txn.Hash(), utxoOps, chain.blockTip().Height+1))
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos))
		require.Equal(false, _verifyMessageParty(utxoView, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))
		// Flush to DB and verify again.
		require.NoError(utxoView.FlushToDb())
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos))
		require.Equal(false, _verifyMessageParty(utxoView, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))
		fmt.Println("PASSED Test #3: Attempt disconnecting a valid V3 private message.")
	}

	// -------------------------------------------------------------------------------------
	//	Test #4: Add V3 messages and message parties in a block and then disconnect block.
	// -------------------------------------------------------------------------------------
	{
		// First part of this test is identical to Tests #3 & #2
		// Generate a random messaging key and this time authorize it.
		keyName := []byte("default-key2")
		priv, pub, _ := _generateMessagingKey(senderPkBytes, senderPrivBytes, keyName)
		_ = priv

		// Authorize the messaging key with a basic transfer and flush to DB.
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		// Add the messaging key to the utxoView
		//_, _, err = _messagingKey(t, chain, db, params, senderPkBytes, recipientPkBytes, senderPrivString, utxoView,
		//	nil, pub, keyName, sign)
		require.NoError(utxoView.FlushToDb())

		// Connect a V3 message in a fresh new UtxoView with the <pub, keyName>
		utxoView, err = NewUtxoView(db, params, nil)
		tstampNanos := uint64(time.Now().UnixNano())
		testMessage1 := hex.EncodeToString([]byte{1, 2, 3, 4, 5, 6})
		_, txn, err := _helpConnectPrivateMessage(senderPkBytes, senderPrivString,
			recipientPkBytes, pub, keyName, []byte{}, []byte{}, testMessage1, tstampNanos, utxoView)
		assert.NoError(err)
		// Because the key has been authorized we should pass verification of the message party entry.
		// We first verify that both message entry and message party entry are present in the UtxoView.
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos))
		// We now verify that message party entry matches expected result.
		require.Equal(true, _verifyMessageParty(utxoView, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))

		// Add the message to the mempool and verify that message party is present.
		mempoolTxn, err := mempool.processTransaction(txn, true, true, 0, true)
		require.NoError(err)
		require.Equal(1, len(mempoolTxn))
		utxoMempool, err := mempool.GetAugmentedUniversalView()
		require.NoError(err)
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoMempool, senderPkBytes, tstampNanos))
		// We now verify that message party entry matches expected result.
		require.Equal(true, _verifyMessageParty(utxoMempool, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))

		// Remove the transaction from the mempool and verify that the message party entry is not present.
		mempool.inefficientRemoveTransaction(txn)
		utxoMempool, err = mempool.GetAugmentedUniversalView()
		require.NoError(err)
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoMempool, senderPkBytes, tstampNanos))
		// We now verify that message party entry matches expected result.
		require.Equal(false, _verifyMessageParty(utxoMempool, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))

		// Again add the message to the mempool and verify.
		mempoolTxn, err = mempool.processTransaction(txn, true, true, 0, true)
		require.NoError(err)
		require.Equal(1, len(mempoolTxn))
		utxoMempool, err = mempool.GetAugmentedUniversalView()
		require.NoError(err)
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoMempool, senderPkBytes, tstampNanos))
		// We now verify that message party entry matches expected result.
		require.Equal(true, _verifyMessageParty(utxoMempool, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))
		addedBlock, err := miner.MineAndProcessSingleBlock(0, mempool)
		require.NoError(err)

		// Verify that the record was persisted in the DB
		utxoView, err = NewUtxoView(db, params, nil)
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos))
		// We now verify that message party entry matches expected result.
		require.Equal(true, _verifyMessageParty(utxoView, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))

		// Now disconnect the block
		hash, err := addedBlock.Header.Hash()
		require.NoError(err)
		utxoOps, err := GetUtxoOperationsForBlock(db, hash)
		require.NoError(err)
		txHashes, err := ComputeTransactionHashes(addedBlock.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(addedBlock, txHashes, utxoOps))
		// We now verify that we fail tests.
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos))
		require.Equal(false, _verifyMessageParty(utxoView, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))

		// And flush to DB and verify we fail tests
		require.NoError(utxoView.FlushToDb())
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos))
		require.Equal(false, _verifyMessageParty(utxoView, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))
		// And verify on a fresh UtxoView
		utxoView, err = NewUtxoView(db, params, nil)
		require.NoError(err)
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos))
		require.Equal(false, _verifyMessageParty(utxoView, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))
		fmt.Println("PASSED Test #4: Add V3 messages and message parties in a block and then disconnect block.")
	}
}
