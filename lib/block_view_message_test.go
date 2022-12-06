package lib

import (
	"bytes"
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

func TestBasePointSignature(t *testing.T) {
	require := require.New(t)
	// Retrieve the base point bytes and parse them to a public key.
	basePointBytes := GetS256BasePointCompressed()
	basePoint, err := btcec.ParsePubKey(basePointBytes, btcec.S256())
	require.NoError(err)

	// Verify that k = 1 is the correct private key for the secp256k1 base point
	priveKeyBytes := []byte{1}
	priveKey, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), priveKeyBytes)
	require.Equal(basePointBytes, publicKey.SerializeCompressed())
	require.Equal(basePoint.SerializeCompressed(), publicKey.SerializeCompressed())

	// Now test signing messages with the private key of the base point k = 1.
	message := []byte("Test message")
	messageHash := Sha256DoubleHash(message)
	messageSignature, err := priveKey.Sign(messageHash[:])
	require.NoError(err)

	// Now make sure the base point passes signature verification.
	require.Equal(true, messageSignature.Verify(messageHash[:], basePoint))
}

func _privateMessage(
	t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams, feeRateNanosPerKB uint64,
	senderPkBase58Check string, recipientPkBase58Check string, senderPrivBase58Check string,
	unencryptedMessageText string, tstampNanos uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error,
) {
	return _privateMessageWithExtraData(
		t, chain, db, params, feeRateNanosPerKB,
		senderPkBase58Check, recipientPkBase58Check, senderPrivBase58Check, unencryptedMessageText, tstampNanos, nil,
	)
}

func _privateMessageWithExtraData(t *testing.T, chain *Blockchain, db *badger.DB,
	params *DeSoParams, feeRateNanosPerKB uint64, senderPkBase58Check string,
	recipientPkBase58Check string,
	senderPrivBase58Check string, unencryptedMessageText string, tstampNanos uint64, extraData map[string][]byte) (
	_utxoOps []*UtxoOperation, _txn *MsgDeSoTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := Base58CheckDecode(senderPkBase58Check)
	require.NoError(err)

	recipientPkBytes, _, err := Base58CheckDecode(recipientPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreatePrivateMessageTxn(
		senderPkBytes, recipientPkBytes, unencryptedMessageText, "",
		[]byte{}, []byte{}, []byte{}, []byte{},
		tstampNanos, extraData, feeRateNanosPerKB, nil, []*DeSoOutput{})
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

	require.NoError(utxoView.FlushToDb(0))

	return utxoOps, txn, blockHeight, nil
}

func TestPrivateMessage(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Allow extra data
	params.ForkHeights.ExtraDataOnEntriesBlockHeight = uint32(0)
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
	registerOrTransfer("", senderPkString, m4Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m4Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m4Pub, senderPrivString)

	privateMessageWithExtraData := func(
		senderPkBase58Check string, recipientPkBase58Check string,
		senderPrivBase58Check string, unencryptedMessageText string, tstampNanos uint64, extraData map[string][]byte,
		feeRateNanosPerKB uint64) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _privateMessageWithExtraData(
			t, chain, db, params, feeRateNanosPerKB, senderPkBase58Check,
			recipientPkBase58Check, senderPrivBase58Check, unencryptedMessageText, tstampNanos, extraData)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}
	privateMessage := func(
		senderPkBase58Check string, recipientPkBase58Check string,
		senderPrivBase58Check string, unencryptedMessageText string, tstampNanos uint64,
		feeRateNanosPerKB uint64) {
		privateMessageWithExtraData(senderPkBase58Check, recipientPkBase58Check, senderPrivBase58Check,
			unencryptedMessageText, tstampNanos, nil, feeRateNanosPerKB)
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
	message6 := string(append([]byte("message6: "), RandomBytes(100)...))
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

	// m4 -> m5
	m4MessageExtraData := map[string][]byte{
		"extraextra": []byte("readallaboutit"),
	}
	privateMessageWithExtraData(m4Pub, m5Pub, m4Priv, message6, tstamp4, m4MessageExtraData, 10)

	// Verify that the messages are as we expect them in the db.
	// 1: m0 m1
	// 2: m2 m1
	// 3: m3 m1
	// 4: m1 m2
	// 5: m2 m3
	// 6: m4 m5
	// => m0: 1
	// 	  m1: 4
	//    m2: 3
	//    m3: 2
	//    m4: 1
	//    m5: 1
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(1, len(messages))
		messageEntry := messages[0]
		require.Equal(messageEntry.SenderPublicKey[:], _strToPk(t, m0Pub))
		require.Equal(messageEntry.RecipientPublicKey[:], _strToPk(t, m1Pub))
		require.Equal(messageEntry.TstampNanos, tstamp1)
		require.Equal(messageEntry.isDeleted, false)
		priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), _strToPk(t, m1Priv))
		decryptedBytes, err := DecryptBytesWithPrivateKey(messageEntry.EncryptedText, priv.ToECDSA())
		require.NoError(err)
		require.Equal(message1, string(decryptedBytes))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(4, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(3, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(2, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m4Pub))
		require.NoError(err)
		require.Equal(1, len(messages))
		require.Equal(messages[0].ExtraData["extraextra"], []byte("readallaboutit"))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m5Pub))
		require.NoError(err)
		require.Equal(1, len(messages))
		require.Equal(messages[0].ExtraData["extraextra"], []byte("readallaboutit"))
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

		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb(0))

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(expectedSenderBalances[backwardIter], _getBalance(t, chain, nil, senderPkString))
		require.Equal(expectedRecipientBalances[backwardIter], _getBalance(t, chain, nil, recipientPkString))
	}

	// Verify that all the messages have been deleted.
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m4Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m5Pub))
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

	// Disonnect the transactions from a single view in the same way as above
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

	// Verify that all the messages have been deleted.
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m4Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m5Pub))
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

	// Verify that all the messages have been deleted.
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m4Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DBGetMessageEntriesForPublicKey(db, _strToPk(t, m5Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
}

// _generateMessagingKey is used to generate a random messaging key and the signed hash(publicKey || keyName).
func _generateMessagingKey(senderPub []byte, senderPriv []byte, keyName []byte) (
	priv *btcec.PrivateKey, sign []byte, messagingKeyEntry *MessagingGroupEntry) {

	senderPrivKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), senderPriv)

	priv, _ = btcec.NewPrivateKey(btcec.S256())
	pub := priv.PubKey().SerializeCompressed()

	payload := append(pub, keyName...)
	signature, _ := senderPrivKey.Sign(Sha256DoubleHash(payload)[:])

	return priv, signature.Serialize(), _initMessagingKey(senderPub, pub, keyName)
}

// _messagingKey adds a messaging key entry to a new utxo and flushes to DB.
func _messagingKey(t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams,
	senderPk []byte, signerPriv string, messagingPublicKey []byte, messagingKeyName []byte,
	keySignature []byte, recipients []*MessagingGroupMember) ([]*UtxoOperation, *MsgDeSoTxn, error) {
	return _messagingKeyWithExtraData(t, chain, db, params, senderPk, signerPriv, messagingPublicKey, messagingKeyName, keySignature, recipients, nil)
}

func _messagingKeyWithExtraData(t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams,
	senderPk []byte, signerPriv string, messagingPublicKey []byte, messagingKeyName []byte,
	keySignature []byte, recipients []*MessagingGroupMember, extraData map[string][]byte) (
	[]*UtxoOperation, *MsgDeSoTxn, error) {

	require := require.New(t)
	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreateMessagingKeyTxn(
		senderPk, messagingPublicKey, messagingKeyName, keySignature,
		recipients, extraData, 10, nil, []*DeSoOutput{})
	require.NoError(err)
	require.Equal(totalInputMake, changeAmountMake+feesMake)

	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
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
	require.NoError(utxoView.FlushToDb(0))
	return utxoOps, txn, err
}

func _messagingKeyWithTestMeta(testMeta *TestMeta, senderPk []byte, signerPriv string,
	messagingPublicKey []byte, messagingKeyName []byte, keySignature []byte, recipients []*MessagingGroupMember,
	expectedError error) {
	_messagingKeyWithExtraDataWithTestMeta(testMeta, senderPk, signerPriv, messagingPublicKey, messagingKeyName,
		keySignature, recipients, nil, expectedError)
}

// _messagingKeyWithTestMeta is used to connect and flush a messaging key to the DB.
func _messagingKeyWithExtraDataWithTestMeta(testMeta *TestMeta, senderPk []byte, signerPriv string,
	messagingPublicKey []byte, messagingKeyName []byte, keySignature []byte, recipients []*MessagingGroupMember,
	extraData map[string][]byte, expectedError error) {

	require := require.New(testMeta.t)
	assert := assert.New(testMeta.t)

	senderPkBase58Check := Base58CheckEncode(senderPk, false, testMeta.params)
	balance := _getBalance(testMeta.t, testMeta.chain, nil, senderPkBase58Check)

	utxoOps, txn, err := _messagingKeyWithExtraData(testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		senderPk, signerPriv, messagingPublicKey, messagingKeyName, keySignature, recipients, extraData)

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

// _verifyMessagingKey allows us to verify that a messaging key was properly connected to utxoView and
// that it matches the expected entry that's provided.
func _verifyMessagingKey(testMeta *TestMeta, publicKey *PublicKey, entry *MessagingGroupEntry) bool {
	var utxoMessagingEntry *MessagingGroupEntry

	require := require.New(testMeta.t)
	messagingKey := NewMessagingGroupKey(publicKey, entry.MessagingGroupKeyName[:])
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, nil, testMeta.chain.snapshot)
	require.NoError(err)
	utxoMessagingEntry = utxoView.GetMessagingGroupKeyToMessagingGroupEntryMapping(messagingKey)

	if utxoMessagingEntry == nil || utxoMessagingEntry.isDeleted {
		return false
	}

	return reflect.DeepEqual(EncodeToBytes(0, utxoMessagingEntry), EncodeToBytes(0, entry))
}

// _verifyAddedMessagingKeys is used to verify that messaging key entries in db match the expected entries.
func _verifyAddedMessagingKeys(testMeta *TestMeta, publicKey []byte, expectedEntries []*MessagingGroupEntry) {
	require := require.New(testMeta.t)
	assert := assert.New(testMeta.t)

	require.NoError(testMeta.chain.db.View(func(txn *badger.Txn) error {
		// Get the DB record.
		entries, err := DBGetAllUserGroupEntiresWithTxn(txn, publicKey)
		require.NoError(err)
		// Make sure the number of entries between the DB and expectation match.
		assert.Equal(len(entries), len(expectedEntries))
		// Verify entries one by one.
		for _, expectedEntry := range expectedEntries {
			expectedEntry.MessagingGroupMembers = sortMessagingGroupMembers(expectedEntry.MessagingGroupMembers)
			ok := false
			for _, entry := range entries {
				if reflect.DeepEqual(EncodeToBytes(0, expectedEntry), EncodeToBytes(0, entry)) {
					ok = true
					break
				}
			}
			assert.Equal(true, ok)
		}
		return nil
	}))
}

// _initMessagingKey is a helper function that instantiates a MessagingGroupEntry.
func _initMessagingKey(senderPub []byte, messagingPublicKey []byte, messagingKeyName []byte) *MessagingGroupEntry {
	return &MessagingGroupEntry{
		GroupOwnerPublicKey:   NewPublicKey(senderPub),
		MessagingPublicKey:    NewPublicKey(messagingPublicKey),
		MessagingGroupKeyName: NewGroupKeyName(messagingKeyName),
	}
}

func TestMessagingKeys(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	_ = require
	_ = assert

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Allow extra data
	params.ForkHeights.ExtraDataOnEntriesBlockHeight = uint32(0)

	// Set the DeSo V3 messages block height to 0
	params.ForkHeights.DeSoV3MessagesBlockHeight = 0

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
	senderPublicKey := *NewPublicKey(senderPkBytes)

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
	m0PublicKey := *NewPublicKey(m0PubKey)

	m1PubKey, _, err := Base58CheckDecode(m1Pub)
	require.NoError(err)
	m1PrivKey, _, err := Base58CheckDecode(m1Priv)
	require.NoError(err)
	m1PublicKey := *NewPublicKey(m1PubKey)

	m2PubKey, _, err := Base58CheckDecode(m2Pub)
	require.NoError(err)
	m2PrivKey, _, err := Base58CheckDecode(m2Priv)
	require.NoError(err)
	m2PublicKey := *NewPublicKey(m2PubKey)

	m3PubKey, _, err := Base58CheckDecode(m3Pub)
	require.NoError(err)
	m3PrivKey, _, err := Base58CheckDecode(m3Priv)
	require.NoError(err)
	m3PublicKey := *NewPublicKey(m3PubKey)

	// -------------------------------------------------------------------------------------
	//	Test #1: Check that non-group-chat messaging keys are correctly set in UtxoView and flushed to DB
	// -------------------------------------------------------------------------------------

	// Entries is a map keeping track of messaging keys added for each public key. We will use it
	// to validate the DB state after the flushes.
	keyEntriesAdded := make(map[PublicKey][]*MessagingGroupEntry)

	// Add base keys for all users. These keys are present by default because they're just the main user keys.
	{
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, BaseGroupKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(senderPkBytes)
		keyEntriesAdded[senderPublicKey] = append(keyEntriesAdded[senderPublicKey], entry)

		_, _, entry = _generateMessagingKey(m0PubKey, m0PrivKey, BaseGroupKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m0PubKey)
		keyEntriesAdded[m0PublicKey] = append(keyEntriesAdded[m0PublicKey], entry)

		_, _, entry = _generateMessagingKey(m1PubKey, m1PrivKey, BaseGroupKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m1PubKey)
		keyEntriesAdded[m1PublicKey] = append(keyEntriesAdded[m1PublicKey], entry)

		_, _, entry = _generateMessagingKey(m2PubKey, m2PrivKey, BaseGroupKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m2PubKey)
		keyEntriesAdded[m2PublicKey] = append(keyEntriesAdded[m2PublicKey], entry)

		_, _, entry = _generateMessagingKey(m3PubKey, m3PrivKey, BaseGroupKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m3PubKey)
		keyEntriesAdded[m3PublicKey] = append(keyEntriesAdded[m3PublicKey], entry)
	}

	// First some failing tests.
	// Sender tries to add base messaging key, must fail.
	{
		// Try adding base messaging key, should fail
		baseKeyName := BaseGroupKeyName()
		_, sign, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, baseKeyName[:])
		// The base key has the same messaging public key as the owner's main key
		entry.MessagingPublicKey = &senderPublicKey
		// The base key should always be present in UtxoView. So we expect true.
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			baseKeyName[:],
			sign,
			[]*MessagingGroupMember{},
			RuleErrorMessagingKeyNameCannotBeZeros)
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// Sender tries to add default messaging key without proper signature, must fail.
	{
		defaultKeyName := []byte("default-key")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, defaultKeyName)
		// The default key was not added so verification is false.
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			defaultKeyName,
			[]byte{},
			[]*MessagingGroupMember{},
			RuleErrorMessagingSignatureInvalid)
		// Verification still fails because the txn wasn't successful.
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// Sender tries adding default messaging key with malformed messaging public key, must fail.
	{
		defaultKeyName := []byte("default-key")
		_, sign, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, defaultKeyName)
		// The default key was not added so verification is false.
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:15],
			defaultKeyName,
			sign,
			[]*MessagingGroupMember{},
			RuleErrorPubKeyLen)
		// Verification still fails because the txn wasn't successful.
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// Sender tries adding a messaging key with an empty messaging key name, must fail.
	{
		failingKeyName := []byte{}
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, failingKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			[]byte{},
			[]byte{},
			[]*MessagingGroupMember{},
			RuleErrorMessagingKeyNameCannotBeZeros)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	{
		defaultKeyName := []byte("default-key")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, defaultKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			append(defaultKeyName, NewGroupKeyName([]byte{})[:]...),
			[]byte{},
			[]*MessagingGroupMember{},
			RuleErrorMessagingKeyNameTooLong)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// Now let's make a valid transaction.
	// Sender tries adding correct default messaging key, this time it passes.
	{
		defaultKeyName := []byte("default-key")
		_, sign, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, defaultKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			defaultKeyName,
			sign,
			[]*MessagingGroupMember{},
			nil)
		// Verification is now successful.
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		// Append the default key to the entries added for sender.
		keyEntriesAdded[senderPublicKey] = append(keyEntriesAdded[senderPublicKey], entry)
	}
	// Sender tries adding some random messaging key, must pass.
	{
		// Try adding a non-default key without signature
		randomKeyName := []byte("test-key-1")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomKeyName,
			[]byte{},
			[]*MessagingGroupMember{},
			nil)
		// Verification is successful.
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		// Append the default key to the entries added for sender.
		keyEntriesAdded[senderPublicKey] = append(keyEntriesAdded[senderPublicKey], entry)
	}
	// Sender tries adding another random messaging key, must pass.
	// We add the signature just for the lols, as it shouldn't affect anything.
	{
		randomKeyName := []byte("test-key-2")
		_, sign, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomKeyName,
			sign,
			[]*MessagingGroupMember{},
			nil)
		// Verification is successful.
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		// Append the non-default key to the entries added
		keyEntriesAdded[senderPublicKey] = append(keyEntriesAdded[senderPublicKey], entry)
	}
	// Sender tries adding the same key again without changing anything, this should fail.
	// We would accept an update to a messaging key only if we add group recipients.
	{
		randomKeyName := []byte("test-key-2")
		entry := keyEntriesAdded[senderPublicKey][len(keyEntriesAdded[senderPublicKey])-1]
		// Verification is successful because the key was already added.
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		// However, the transaction must fail.
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomKeyName,
			[]byte{},
			[]*MessagingGroupMember{},
			RuleErrorMessagingKeyDoesntAddMembers)
		// Verification is still successful.
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// Sender tries adding the random key again but with a different messaging public key, this should fail.
	{
		randomKeyName := []byte("test-key-2")
		entry := keyEntriesAdded[senderPublicKey][len(keyEntriesAdded[senderPublicKey])-1]
		_, _, newEntry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomKeyName)
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			newEntry.MessagingPublicKey[:],
			randomKeyName,
			[]byte{},
			[]*MessagingGroupMember{},
			RuleErrorMessagingPublicKeyCannotBeDifferent)
		// The existing entry will pass verification.
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		// The newly-generated entry will fail verification.
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, newEntry))
	}
	// Sender tries adding the random key again but with a "filled" key name, this should fail.
	{
		randomKeyName := []byte("test-key-2")
		entry := keyEntriesAdded[senderPublicKey][len(keyEntriesAdded[senderPublicKey])-1]
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			append(randomKeyName, byte(0)),
			[]byte{},
			[]*MessagingGroupMember{},
			RuleErrorMessagingKeyDoesntAddMembers)
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// m1Pub adds some random key, should pass.
	{
		randomKeyName := []byte("totally-random-key")
		_, _, entry := _generateMessagingKey(m1PubKey, m1PrivKey, randomKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, &m1PublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			m1PubKey,
			m1Priv,
			entry.MessagingPublicKey[:],
			randomKeyName,
			[]byte{},
			[]*MessagingGroupMember{},
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, &m1PublicKey, entry))
		// Append the key to the entries added.
		keyEntriesAdded[m1PublicKey] = append(keyEntriesAdded[m1PublicKey], entry)
	}
	// m0pub add some random key, should pass.
	{
		randomKeyName := []byte("totally-random-key2")
		_, _, entry := _generateMessagingKey(m0PubKey, m0PrivKey, randomKeyName)
		require.Equal(false, _verifyMessagingKey(testMeta, &m0PublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			m0PubKey,
			m0Priv,
			entry.MessagingPublicKey[:],
			randomKeyName,
			[]byte{},
			[]*MessagingGroupMember{},
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, &m0PublicKey, entry))
		// Append the key to the entries added.
		keyEntriesAdded[m0PublicKey] = append(keyEntriesAdded[m0PublicKey], entry)
	}
	// Add a default key for m3Pub, should pass.
	{
		randomKeyName := DefaultGroupKeyName()
		_, sign, entry := _generateMessagingKey(m3PubKey, m3PrivKey, randomKeyName[:])
		require.Equal(false, _verifyMessagingKey(testMeta, &m3PublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			m3PubKey,
			m3Priv,
			entry.MessagingPublicKey[:],
			randomKeyName[:],
			sign,
			[]*MessagingGroupMember{},
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, &m3PublicKey, entry))
		// Append the key to the entries added.
		keyEntriesAdded[m3PublicKey] = append(keyEntriesAdded[m3PublicKey], entry)
	}
	// Add another key for m3 with some extra data
	extraDataKeyName := []byte("extra-data-key-m3")
	{
		randomKeyName := extraDataKeyName
		_, sign, entry := _generateMessagingKey(m3PubKey, m3PrivKey, randomKeyName[:])
		require.Equal(false, _verifyMessagingKey(testMeta, &m3PublicKey, entry))
		extraData := map[string][]byte{
			"extrakey":   []byte("discussion"),
			"dontchange": []byte("checkmelater"),
		}
		_messagingKeyWithExtraDataWithTestMeta(
			testMeta,
			m3PubKey,
			m3Priv,
			entry.MessagingPublicKey[:],
			randomKeyName[:],
			sign,
			[]*MessagingGroupMember{},
			extraData,
			nil,
		)
		entry = DBGetMessagingGroupEntry(db, chain.snapshot, NewMessagingGroupKey(&m3PublicKey, entry.MessagingGroupKeyName[:]))
		// We get the entry from the DB so that it has the extra data
		require.Len(entry.ExtraData, 2)
		require.Equal(entry.ExtraData["extrakey"], []byte("discussion"))
		require.Equal(entry.ExtraData["dontchange"], []byte("checkmelater"))
		require.Equal(true, _verifyMessagingKey(testMeta, &m3PublicKey, entry))

		// For fun, m3 adds group members to the conversation that has extra data
		//_, sign, _ := _generateMessagingKey(m3PubKey, m3PrivKey, extraDataKeyName)
		//entry := DBGetMessagingGroupEntry(db, NewMessagingGroupKey(&m3PublicKey, extraDataKeyName))
		var MessagingGroupMembers []*MessagingGroupMember
		members := [][]byte{m3PubKey, m1PubKey, m2PubKey}
		for _, member := range members {
			MessagingGroupMembers = append(MessagingGroupMembers, &MessagingGroupMember{
				NewPublicKey(member),
				BaseGroupKeyName(),
				m3PrivKey,
			})
		}
		extraData = map[string][]byte{
			"extrakey": []byte("newval"),
			"newkey":   []byte("test"),
		}
		//entry := DBGetMessagingGroupEntry(db, NewMessagingGroupKey(&m3PublicKey, extraDataKeyName))
		_messagingKeyWithExtraDataWithTestMeta(
			testMeta,
			m3PubKey,
			m3Priv,
			entry.MessagingPublicKey[:],
			randomKeyName[:],
			sign,
			MessagingGroupMembers,
			extraData,
			nil,
		)
		entry = DBGetMessagingGroupEntry(db, chain.snapshot, NewMessagingGroupKey(&m3PublicKey, extraDataKeyName))
		require.True(_verifyMessagingKey(testMeta, &m3PublicKey, entry))

		require.Len(entry.ExtraData, 3)
		require.Equal(entry.ExtraData["dontchange"], []byte("checkmelater"))
		require.Equal(entry.ExtraData["extrakey"], []byte("newval"))
		require.Equal(entry.ExtraData["newkey"], []byte("test"))

		for _, member := range MessagingGroupMembers {
			pubKey := *member.GroupMemberPublicKey
			if reflect.DeepEqual(pubKey[:], m3PubKey) {
				continue
			}
			keyEntriesAdded[pubKey] = append(keyEntriesAdded[pubKey], &MessagingGroupEntry{
				GroupOwnerPublicKey:   &m3PublicKey,
				MessagingPublicKey:    NewPublicKey(entry.MessagingPublicKey[:]),
				MessagingGroupKeyName: NewGroupKeyName(randomKeyName),
				MessagingGroupMembers: []*MessagingGroupMember{member},
			})
		}
		keyEntriesAdded[m3PublicKey] = append(keyEntriesAdded[m3PublicKey], entry)
	}
	// A bit of an overkill, but verify that all key entries are present in the DB.
	_verifyAddedMessagingKeys(testMeta, senderPkBytes, keyEntriesAdded[senderPublicKey])
	_verifyAddedMessagingKeys(testMeta, m0PubKey, keyEntriesAdded[m0PublicKey])
	_verifyAddedMessagingKeys(testMeta, m1PubKey, keyEntriesAdded[m1PublicKey])
	_verifyAddedMessagingKeys(testMeta, m2PubKey, keyEntriesAdded[m2PublicKey])
	_verifyAddedMessagingKeys(testMeta, m3PubKey, keyEntriesAdded[m3PublicKey])

	// -------------------------------------------------------------------------------------
	//	Test #2: We will add messaging keys with message recipients, aka, group chats.
	// -------------------------------------------------------------------------------------

	// Sender tries adding himself as a recipient, this should pass.
	{
		// Can add yourself as a recipient.
		randomGroupKeyName := []byte("test-key-3")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, &MessagingGroupMember{
			NewPublicKey(senderPkBytes),
			BaseGroupKeyName(),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.MessagingGroupMembers,
			nil)
		// Verify that we're passing.
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		keyEntriesAdded[senderPublicKey] = append(keyEntriesAdded[senderPublicKey], entry)
	}
	// Sender tries adding a messaging public key as one of the recipients, this is also forbidden so we fail.
	{
		randomGroupKeyName := []byte("test-key-4")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		// Can't add messaging public key as a recipient.
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, &MessagingGroupMember{
			NewPublicKey(entry.MessagingPublicKey[:]),
			BaseGroupKeyName(),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.MessagingGroupMembers,
			RuleErrorMessagingMemberAlreadyExists)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// Sender tries adding a messaging recipient for m0PubKey with a non-existent key, this should fail.
	{
		randomGroupKeyName := []byte("test-key-5")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, &MessagingGroupMember{
			NewPublicKey(m0PubKey),
			NewGroupKeyName([]byte("non-existent-key")),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.MessagingGroupMembers,
			RuleErrorMessagingMemberKeyDoesntExist)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// Sender tries adding a messaging recipient for m0PubKey with a malformed encrypted key, so we fail.
	{
		randomGroupKeyName := []byte("test-key-6")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		// Encrypted key must have at least 32 bytes.
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, &MessagingGroupMember{
			NewPublicKey(m0PubKey),
			BaseGroupKeyName(),
			senderPrivBytes[:15],
		})
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.MessagingGroupMembers,
			RuleErrorMessagingMemberEncryptedKeyTooShort)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// Sender tries adding m0PubKey as a recipient twice, this should also fail.
	{
		randomGroupKeyName := []byte("test-key-7")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, &MessagingGroupMember{
			NewPublicKey(m0PubKey),
			BaseGroupKeyName(),
			senderPrivBytes,
		}, &MessagingGroupMember{
			NewPublicKey(m0PubKey),
			BaseGroupKeyName(),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.MessagingGroupMembers,
			RuleErrorMessagingMemberAlreadyExists)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// Now we get to passing tests.
	// We will do a bunch of tests in the same context so that we preserve the entry messaging key.
	{
		// Sender tries adding a correct recipient for m0PubKey.
		randomGroupKeyName := []byte("test-key-8")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, &MessagingGroupMember{
			NewPublicKey(m0PubKey),
			BaseGroupKeyName(),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.MessagingGroupMembers,
			nil)
		// The entry should now pass verification, since it was added successfully.
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))

		// We will do some failing tests on this added entry.
		// Try re-adding the same recipient for m0PubKey, should fail.
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.MessagingGroupMembers,
			RuleErrorMessagingMemberAlreadyExists)
		// The entry still passes verification, because transaction was rejected.
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))

		// m1PubKey tries to add himself to the group, this will fail because only sender can add
		// new members.
		entryCopy := &MessagingGroupEntry{}
		rr := bytes.NewReader(EncodeToBytes(0, entry))
		exists, err := DecodeFromBytes(entryCopy, rr)
		require.Equal(true, exists)
		require.NoError(err)
		entryCopy.MessagingGroupMembers[0] = &MessagingGroupMember{
			NewPublicKey(m1PubKey),
			NewGroupKeyName([]byte("totally-random-key")),
			senderPrivBytes,
		}
		// Transaction fails.
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			m1Priv,
			entryCopy.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entryCopy.MessagingGroupMembers,
			RuleErrorInvalidTransactionSignature)

		// Sender adds m1PubKey to the group chat, this time we will succeed.
		workingCopy := &MessagingGroupEntry{}
		rr = bytes.NewReader(EncodeToBytes(0, entry))
		exists, err = DecodeFromBytes(workingCopy, rr)
		require.Equal(true, exists)
		require.NoError(err)
		workingCopy.MessagingGroupMembers[0] = &MessagingGroupMember{
			NewPublicKey(m1PubKey),
			NewGroupKeyName([]byte("totally-random-key")),
			senderPrivBytes,
		}
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			workingCopy.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			workingCopy.MessagingGroupMembers,
			nil)

		// Reflect the newly added recipient in the entry.
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, &MessagingGroupMember{
			NewPublicKey(m1PubKey),
			NewGroupKeyName([]byte("totally-random-key")),
			senderPrivBytes,
		})

		// Append all the new keys to our keyEntriesAdded.
		keyEntriesAdded[senderPublicKey] = append(keyEntriesAdded[senderPublicKey], entry)

		// Recipient entries have the group owner added as a recipient when fetched from the DB.
		// This is convenient in case we want to fetch the full group messaging key entry as a recipient.
		keyEntriesAdded[m0PublicKey] = append(keyEntriesAdded[m0PublicKey], &MessagingGroupEntry{
			GroupOwnerPublicKey:   &senderPublicKey,
			MessagingPublicKey:    NewPublicKey(entry.MessagingPublicKey[:]),
			MessagingGroupKeyName: NewGroupKeyName(randomGroupKeyName),
			MessagingGroupMembers: append([]*MessagingGroupMember{}, entry.MessagingGroupMembers[0]),
		})
		keyEntriesAdded[m1PublicKey] = append(keyEntriesAdded[m1PublicKey], &MessagingGroupEntry{
			GroupOwnerPublicKey:   &senderPublicKey,
			MessagingPublicKey:    NewPublicKey(entry.MessagingPublicKey[:]),
			MessagingGroupKeyName: NewGroupKeyName(randomGroupKeyName),
			MessagingGroupMembers: append([]*MessagingGroupMember{}, entry.MessagingGroupMembers[1]),
		})
	}
	// We will test unencrypted groups, which are intended as large group chats that anyone can join.
	{
		// The unencrypted group will have the messaging public key set as the Secp256k1 base element.
		groupKeyName := []byte("open-group")
		_, _, entry := _generateMessagingKey(m0PubKey, m0PrivKey, groupKeyName)
		basePk := NewPublicKey(GetS256BasePointCompressed())
		entry.MessagingPublicKey = basePk
		require.Equal(false, _verifyMessagingKey(testMeta, basePk, entry))
		// This should pass.
		_messagingKeyWithTestMeta(
			testMeta,
			m0PubKey,
			m0Priv,
			entry.MessagingPublicKey[:],
			groupKeyName,
			[]byte{},
			entry.MessagingGroupMembers,
			nil)
		// The DB entry should have the messaging public key derived deterministically from the group key name.
		// Compute the public key and compare it with the DB entry.
		_, groupPkBytes := btcec.PrivKeyFromBytes(btcec.S256(), Sha256DoubleHash(groupKeyName)[:])
		groupPk := NewPublicKey(groupPkBytes.SerializeCompressed())
		expectedEntry := &MessagingGroupEntry{}
		rr := bytes.NewReader(EncodeToBytes(0, entry))
		exists, err := DecodeFromBytes(expectedEntry, rr)
		require.Equal(true, exists)
		require.NoError(err)
		expectedEntry.MessagingPublicKey = groupPk
		expectedEntry.GroupOwnerPublicKey = basePk
		// Should pass.
		require.Equal(true, _verifyMessagingKey(testMeta, basePk, expectedEntry))

		// Anyone can add recipients to the group.
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, &MessagingGroupMember{
			&m1PublicKey,
			BaseGroupKeyName(),
			senderPrivBytes,
		})
		_messagingKeyWithTestMeta(
			testMeta,
			m1PubKey,
			m1Priv,
			entry.MessagingPublicKey[:],
			groupKeyName,
			[]byte{},
			entry.MessagingGroupMembers,
			nil)
		// Verify that the entry exists in the DB.
		expectedEntry = &MessagingGroupEntry{}
		rr = bytes.NewReader(EncodeToBytes(0, entry))
		exists, err = DecodeFromBytes(expectedEntry, rr)
		require.Equal(true, exists)
		require.NoError(err)
		expectedEntry.MessagingPublicKey = groupPk
		expectedEntry.GroupOwnerPublicKey = basePk
		require.Equal(true, _verifyMessagingKey(testMeta, basePk, expectedEntry))

		// And the entry behaves as expected, as in we can't re-add recipients, etc.
		_messagingKeyWithTestMeta(
			testMeta,
			m0PubKey,
			m0Priv,
			entry.MessagingPublicKey[:],
			groupKeyName,
			[]byte{},
			entry.MessagingGroupMembers,
			RuleErrorMessagingMemberAlreadyExists)
		require.Equal(true, _verifyMessagingKey(testMeta, basePk, expectedEntry))

		// Now add all the entries to our expected entries list.
		keyEntriesAdded[*basePk] = append(keyEntriesAdded[*basePk], expectedEntry)

		keyEntriesAdded[m1PublicKey] = append(keyEntriesAdded[m1PublicKey], &MessagingGroupEntry{
			GroupOwnerPublicKey:   basePk,
			MessagingPublicKey:    groupPk,
			MessagingGroupKeyName: NewGroupKeyName(groupKeyName),
			MessagingGroupMembers: append([]*MessagingGroupMember{}, &MessagingGroupMember{
				GroupMemberPublicKey: &m1PublicKey,
				GroupMemberKeyName:   BaseGroupKeyName(),
				EncryptedKey:         senderPrivBytes,
			}),
		})
	}
	// Now we will go all-in on the group chats and create a 5-party group chat with everyone.
	{
		// Sender generates the group chat messaging key.
		randomGroupKeyName := []byte("final-group-key")
		_, _, entry := _generateMessagingKey(m1PubKey, m1PrivKey, randomGroupKeyName)
		// Now add a lot of people
		senderMember := &MessagingGroupMember{
			NewPublicKey(senderPkBytes),
			DefaultGroupKeyName(),
			senderPrivBytes,
		}
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, senderMember)
		m0Member := &MessagingGroupMember{
			NewPublicKey(m0PubKey),
			NewGroupKeyName([]byte("totally-random-key2")),
			senderPrivBytes,
		}
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, m0Member)
		m2Member := &MessagingGroupMember{
			NewPublicKey(m2PubKey),
			BaseGroupKeyName(),
			senderPrivBytes,
		}
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, m2Member)
		m3Member := &MessagingGroupMember{
			NewPublicKey(m3PubKey),
			DefaultGroupKeyName(),
			senderPrivBytes,
		}
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, m3Member)
		// And finally create the group chat.
		require.Equal(false, _verifyMessagingKey(testMeta, &m1PublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			m1PubKey,
			m1Priv,
			entry.MessagingPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.MessagingGroupMembers,
			nil)
		// Everything should pass verification.
		require.Equal(true, _verifyMessagingKey(testMeta, &m1PublicKey, entry))
		// So now reflect the key entries added with the new keys.
		keyEntriesAdded[m1PublicKey] = append(keyEntriesAdded[m1PublicKey], entry)

		// Recipient entries have the group owner added as a recipient when fetched from the DB.
		// This is convenient in case we want to fetch the full group messaging key entry as a recipient.
		keyEntriesAdded[senderPublicKey] = append(keyEntriesAdded[senderPublicKey], &MessagingGroupEntry{
			GroupOwnerPublicKey:   &m1PublicKey,
			MessagingPublicKey:    NewPublicKey(entry.MessagingPublicKey[:]),
			MessagingGroupKeyName: NewGroupKeyName(randomGroupKeyName),
			MessagingGroupMembers: append([]*MessagingGroupMember{}, senderMember),
		})
		keyEntriesAdded[m0PublicKey] = append(keyEntriesAdded[m0PublicKey], &MessagingGroupEntry{
			GroupOwnerPublicKey:   &m1PublicKey,
			MessagingPublicKey:    NewPublicKey(entry.MessagingPublicKey[:]),
			MessagingGroupKeyName: NewGroupKeyName(randomGroupKeyName),
			MessagingGroupMembers: append([]*MessagingGroupMember{}, m0Member),
		})
		keyEntriesAdded[m2PublicKey] = append(keyEntriesAdded[m2PublicKey], &MessagingGroupEntry{
			GroupOwnerPublicKey:   &m1PublicKey,
			MessagingPublicKey:    NewPublicKey(entry.MessagingPublicKey[:]),
			MessagingGroupKeyName: NewGroupKeyName(randomGroupKeyName),
			MessagingGroupMembers: append([]*MessagingGroupMember{}, m2Member),
		})
		keyEntriesAdded[m3PublicKey] = append(keyEntriesAdded[m3PublicKey], &MessagingGroupEntry{
			GroupOwnerPublicKey:   &m1PublicKey,
			MessagingPublicKey:    NewPublicKey(entry.MessagingPublicKey[:]),
			MessagingGroupKeyName: NewGroupKeyName(randomGroupKeyName),
			MessagingGroupMembers: append([]*MessagingGroupMember{}, m3Member),
		})
	}

	// Now we verify that all keys were properly added.
	_verifyAddedMessagingKeys(testMeta, senderPkBytes, keyEntriesAdded[senderPublicKey])
	_verifyAddedMessagingKeys(testMeta, m0PubKey, keyEntriesAdded[m0PublicKey])
	_verifyAddedMessagingKeys(testMeta, m1PubKey, keyEntriesAdded[m1PublicKey])
	_verifyAddedMessagingKeys(testMeta, m2PubKey, keyEntriesAdded[m2PublicKey])
	_verifyAddedMessagingKeys(testMeta, m3PubKey, keyEntriesAdded[m3PublicKey])

	// Do some block connecting/disconnecting, mempooling, etc to verify everything works.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)

	// Finally, verify that there are no more keys, besides the base keys, in the db.
	{
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, BaseGroupKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(senderPkBytes)
		keyEntriesAdded[senderPublicKey] = append([]*MessagingGroupEntry{}, entry)

		_, _, entry = _generateMessagingKey(m0PubKey, m0PrivKey, BaseGroupKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m0PubKey)
		keyEntriesAdded[m0PublicKey] = append([]*MessagingGroupEntry{}, entry)

		_, _, entry = _generateMessagingKey(m1PubKey, m1PrivKey, BaseGroupKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m1PubKey)
		keyEntriesAdded[m1PublicKey] = append([]*MessagingGroupEntry{}, entry)

		_, _, entry = _generateMessagingKey(m2PubKey, m2PrivKey, BaseGroupKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m2PubKey)
		keyEntriesAdded[m2PublicKey] = append([]*MessagingGroupEntry{}, entry)

		_, _, entry = _generateMessagingKey(m3PubKey, m3PrivKey, BaseGroupKeyName()[:])
		entry.MessagingPublicKey = NewPublicKey(m3PubKey)
		keyEntriesAdded[m3PublicKey] = append([]*MessagingGroupEntry{}, entry)
	}
	_verifyAddedMessagingKeys(testMeta, senderPkBytes, keyEntriesAdded[senderPublicKey])
	_verifyAddedMessagingKeys(testMeta, m0PubKey, keyEntriesAdded[m0PublicKey])
	_verifyAddedMessagingKeys(testMeta, m1PubKey, keyEntriesAdded[m1PublicKey])
	_verifyAddedMessagingKeys(testMeta, m2PubKey, keyEntriesAdded[m2PublicKey])
	_verifyAddedMessagingKeys(testMeta, m3PubKey, keyEntriesAdded[m3PublicKey])
}

func _connectPrivateMessageWithParty(testMeta *TestMeta, senderPkBytes []byte, senderPrivBase58 string,
	recipientPkBytes, senderMessagingPublicKey []byte, senderMessagingKeyName []byte, recipientMessagingPublicKey []byte,
	recipientMessagingKeyName []byte, encryptedMessageText string, tstampNanos uint64, expectedError error,
) {
	_connectPrivateMessageWithPartyWithExtraData(testMeta, senderPkBytes, senderPrivBase58, recipientPkBytes,
		senderMessagingPublicKey, senderMessagingKeyName, recipientMessagingPublicKey, recipientMessagingKeyName,
		encryptedMessageText, tstampNanos, nil, expectedError)
}

// This helper function connects a private message transaction with the message party in ExtraData.
func _connectPrivateMessageWithPartyWithExtraData(testMeta *TestMeta, senderPkBytes []byte, senderPrivBase58 string,
	recipientPkBytes, senderMessagingPublicKey []byte, senderMessagingKeyName []byte, recipientMessagingPublicKey []byte,
	recipientMessagingKeyName []byte, encryptedMessageText string, tstampNanos uint64, extraData map[string][]byte,
	expectedError error) {

	require := require.New(testMeta.t)
	assert := assert.New(testMeta.t)

	senderPkBase58Check := Base58CheckEncode(senderPkBytes, false, testMeta.params)
	balance := _getBalance(testMeta.t, testMeta.chain, nil, senderPkBase58Check)

	// Create a private message transaction with the sender and recipient messaging keys.
	txn, totalInputMake, changeAmountMake, feesMake, err := testMeta.chain.CreatePrivateMessageTxn(
		senderPkBytes, recipientPkBytes, "", encryptedMessageText,
		senderMessagingPublicKey, senderMessagingKeyName, recipientMessagingPublicKey,
		recipientMessagingKeyName, tstampNanos, extraData, 10, nil, []*DeSoOutput{})
	require.NoError(err)

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(testMeta.t, txn, senderPrivBase58)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, nil, testMeta.chain.snapshot)
	blockHeight := testMeta.chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	// ConnectTransaction should treat the amount locked as contributing to the output.
	if expectedError != nil {
		assert.Equal(true, strings.Contains(err.Error(), expectedError.Error()))
		return
	}
	require.NoError(err)

	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypePrivateMessage, utxoOps[len(utxoOps)-1].Type)
	require.NoError(utxoView.FlushToDb(0))

	testMeta.expectedSenderBalances = append(
		testMeta.expectedSenderBalances, balance)
	testMeta.txnOps = append(testMeta.txnOps, utxoOps)
	testMeta.txns = append(testMeta.txns, txn)
}

// _helpConnectPrivateMessageWithParty is a simplified version of _connectPrivateMessageWithParty
func _helpConnectPrivateMessageWithParty(testMeta *TestMeta, senderPrivBase58 string,
	entry MessageEntry, expectedError error) {

	_connectPrivateMessageWithParty(testMeta, entry.SenderPublicKey[:], senderPrivBase58, entry.RecipientPublicKey[:],
		entry.SenderMessagingPublicKey[:], entry.SenderMessagingGroupKeyName[:], entry.RecipientMessagingPublicKey[:],
		entry.RecipientMessagingGroupKeyName[:], hex.EncodeToString(entry.EncryptedText), entry.TstampNanos, expectedError)
}

// Verify the message party entry in UtxoView or DB matches the expected entry. Also add the message entries
// to the expected entries map, which we use for verifying that DB entries match added messages.
func _verifyMessageParty(testMeta *TestMeta, expectedMessageEntries map[PublicKey][]MessageEntry,
	expectedEntry MessageEntry, groupOwner bool) bool {

	require := require.New(testMeta.t)

	// First validate that the expected entry was properly added to the UtxoView.
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, nil, testMeta.chain.snapshot)
	require.NoError(err)
	messageKey := MakeMessageKey(expectedEntry.SenderMessagingPublicKey[:], expectedEntry.TstampNanos)
	messageEntrySender := utxoView._getMessageEntryForMessageKey(&messageKey)
	if messageEntrySender == nil || messageEntrySender.isDeleted {
		return false
	}
	messageKey = MakeMessageKey(expectedEntry.RecipientMessagingPublicKey[:], expectedEntry.TstampNanos)
	messageEntryRecipient := utxoView._getMessageEntryForMessageKey(&messageKey)
	if messageEntryRecipient == nil || messageEntryRecipient.isDeleted {
		return false
	}
	if !reflect.DeepEqual(EncodeToBytes(0, messageEntrySender), EncodeToBytes(0, messageEntryRecipient)) {
		return false
	}
	if !reflect.DeepEqual(EncodeToBytes(0, messageEntrySender), EncodeToBytes(0, &expectedEntry)) {
		return false
	}
	addedEntries := make(map[PublicKey]bool)
	expectedMessageEntries[*expectedEntry.SenderPublicKey] = append(expectedMessageEntries[*expectedEntry.SenderPublicKey], expectedEntry)
	addedEntries[*expectedEntry.SenderPublicKey] = true

	// There is an edge-case where group owner sends a message to their group which complicates the logic for adding
	// messages to our expected entries map.
	if !groupOwner {
		expectedMessageEntries[*expectedEntry.RecipientPublicKey] = append(expectedMessageEntries[*expectedEntry.RecipientPublicKey], expectedEntry)
		addedEntries[*expectedEntry.RecipientPublicKey] = true
	}
	fetchKey := expectedEntry.RecipientPublicKey
	if groupOwner {
		fetchKey = expectedEntry.SenderPublicKey
	}
	messagingKey := utxoView.GetMessagingGroupKeyToMessagingGroupEntryMapping(&MessagingGroupKey{
		*fetchKey,
		*expectedEntry.RecipientMessagingGroupKeyName,
	})
	if messagingKey != nil {
		for _, recipient := range messagingKey.MessagingGroupMembers {
			if _, exists := addedEntries[*recipient.GroupMemberPublicKey]; !exists {
				expectedMessageEntries[*recipient.GroupMemberPublicKey] = append(expectedMessageEntries[*recipient.GroupMemberPublicKey], expectedEntry)
			}
		}
	}

	return true
}

// _verifyMessages verifies that the expected messages map is identical to the DB entries.
func _verifyMessages(testMeta *TestMeta, expectedMessageEntries map[PublicKey][]MessageEntry) {

	require := require.New(testMeta.t)
	assert := assert.New(testMeta.t)

	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, nil, testMeta.chain.snapshot)
	require.NoError(err)

	for key, messageEntries := range expectedMessageEntries {
		dbMessageEntries, _, err := utxoView.GetLimitedMessagesForUser(key[:], 100)
		require.NoError(err)
		assert.Equal(len(messageEntries), len(dbMessageEntries))

		for _, messageEntry := range messageEntries {
			ok := false
			for _, dbMessageEntry := range dbMessageEntries {
				if reflect.DeepEqual(EncodeToBytes(0, &messageEntry),
					EncodeToBytes(0, dbMessageEntry)) {
					ok = true
					break
				}
			}
			assert.Equal(true, ok)
		}
	}
}

// In these tests we basically want to verify that messages are correctly added to UtxoView and DB
// after we send V3 group messages.
func TestGroupMessages(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	_ = require
	_ = assert

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_ = miner

	// Set the DeSo V3 messages block height to 0
	params.ForkHeights.DeSoV3MessagesBlockHeight = 0

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

	// Decode the test key so they're easier to use throughout the tests.
	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)
	senderPrivBytes, _, err := Base58CheckDecode(senderPrivString)
	require.NoError(err)
	senderPublicKey := NewPublicKey(senderPkBytes)

	recipientPkBytes, _, err := Base58CheckDecode(recipientPkString)
	require.NoError(err)
	recipientPrivBytes, _, err := Base58CheckDecode(recipientPrivString)
	_ = recipientPrivBytes
	require.NoError(err)
	recipientPublicKey := NewPublicKey(recipientPkBytes)

	m0PubKey, _, err := Base58CheckDecode(m0Pub)
	require.NoError(err)
	m0PrivKey, _, err := Base58CheckDecode(m0Priv)
	require.NoError(err)
	m0PublicKey := NewPublicKey(m0PubKey)

	m1PubKey, _, err := Base58CheckDecode(m1Pub)
	require.NoError(err)
	m1PrivKey, _, err := Base58CheckDecode(m1Priv)
	require.NoError(err)
	m1PublicKey := NewPublicKey(m1PubKey)

	m2PubKey, _, err := Base58CheckDecode(m2Pub)
	require.NoError(err)
	m2PrivKey, _, err := Base58CheckDecode(m2Priv)
	require.NoError(err)
	m2PublicKey := NewPublicKey(m2PubKey)

	// Fund all the keys.
	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		_, _, _ = _doBasicTransferWithViewFlush(
			t, chain, db, params, senderPk, recipientPk,
			senderPriv, 1000 /*amount to send*/, 11 /*feerate*/)
	}

	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)

	expectedMessageEntries := make(map[PublicKey][]MessageEntry)

	// -------------------------------------------------------------------------------------
	//	Test #1: Attempt sending a V3 private message without a previously authorized messaging key.
	// -------------------------------------------------------------------------------------
	{
		// Generate a random messaging key but never authorize it.
		keyName := []byte("default-key")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, keyName)

		// SenderPk tries to submit a V3 private message with a non-existent key, which should fail.
		tstampNanos := uint64(time.Now().UnixNano())
		testMessage1 := []byte{1, 2, 3, 4, 5, 6}
		messageEntry := MessageEntry{
			NewPublicKey(senderPkBytes),
			NewPublicKey(recipientPkBytes),
			testMessage1,
			tstampNanos,
			false,
			MessagesVersion1,
			NewPublicKey(entry.MessagingPublicKey[:]),
			NewGroupKeyName(keyName),
			NewPublicKey(recipientPkBytes),
			BaseGroupKeyName(),
			nil,
		}
		_helpConnectPrivateMessageWithParty(testMeta, senderPrivString, messageEntry, RuleErrorPrivateMessageFailedToValidateMessagingKey)
		// Verification should fail because the messaging key was never added to UtxoView.
		require.Equal(false, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry, false))

		// SenderPk tries to submit another malformed V3 message, but this time the recipient is malformed, should fail.
		messageEntry.SenderMessagingPublicKey = NewPublicKey(senderPkBytes)
		messageEntry.SenderMessagingGroupKeyName = BaseGroupKeyName()
		messageEntry.RecipientMessagingPublicKey = entry.MessagingPublicKey
		messageEntry.RecipientMessagingGroupKeyName = NewGroupKeyName(keyName)
		_helpConnectPrivateMessageWithParty(testMeta, senderPrivString, messageEntry, RuleErrorPrivateMessageFailedToValidateMessagingKey)
		// Should fail.
		require.Equal(false, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry, false))

		// We will send a v2-like message just to make sure everything is gucci.
		// We will set version as 3 because we're adding messaging keys.
		messageEntry.SenderMessagingPublicKey = NewPublicKey(senderPkBytes)
		messageEntry.SenderMessagingGroupKeyName = BaseGroupKeyName()
		messageEntry.RecipientMessagingPublicKey = NewPublicKey(recipientPkBytes)
		messageEntry.RecipientMessagingGroupKeyName = BaseGroupKeyName()
		messageEntry.Version = MessagesVersion3
		_helpConnectPrivateMessageWithParty(testMeta, senderPrivString, messageEntry, nil)
		// Should pass, so we have:
		// sender -> recipient
		//	sender: 1
		//	recipient: 1
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry, false))

		_verifyMessages(testMeta, expectedMessageEntries)
		// Just to sanity-check, verify that the number of messages is as intended.
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err := utxoView.GetMessagesForUser(senderPkBytes)
		require.NoError(err)
		assert.Equal(1, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes)
		require.NoError(err)
		assert.Equal(1, len(messages))
	}

	// -------------------------------------------------------------------------------------
	//	Test #2: Attempt sending V3 messages with authorizing messaging keys
	// -------------------------------------------------------------------------------------
	{
		// Add a default key for the sender.
		defaultKey := []byte("default-key")
		_, sign, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, defaultKey)
		require.Equal(false, _verifyMessagingKey(testMeta, senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			defaultKey,
			sign,
			[]*MessagingGroupMember{},
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, senderPublicKey, entry))

		// SenderPk sends a message from their default key to recipient's base key, should pass.
		tstampNanos1 := uint64(time.Now().UnixNano())
		testMessage1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		messageEntry := MessageEntry{
			NewPublicKey(senderPkBytes),
			NewPublicKey(recipientPkBytes),
			testMessage1,
			tstampNanos1,
			false,
			MessagesVersion3,
			NewPublicKey(entry.MessagingPublicKey[:]),
			NewGroupKeyName(defaultKey),
			NewPublicKey(recipientPkBytes),
			BaseGroupKeyName(),
			nil,
		}
		_helpConnectPrivateMessageWithParty(testMeta, senderPrivString, messageEntry, nil)
		// Should pass, so we have:
		// sender -> recipient
		// 	sender: 2
		//	recipient: 2
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry, false))

		// Add another message cause why not:
		tstampNanos2 := uint64(time.Now().UnixNano())
		testMessage2 := []byte{1, 2, 2, 4, 3, 6, 7, 8, 9}
		messageEntry.TstampNanos = tstampNanos2
		messageEntry.EncryptedText = testMessage2
		_helpConnectPrivateMessageWithParty(testMeta, senderPrivString, messageEntry, nil)
		// Should pass, so we have:
		// sender -> recipient
		// 	sender: 3
		//	recipient: 3
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry, false))

		// Register a default key for the recipient, so we can try sending messages between two messaging keys.
		defaultKey = []byte("default-key")
		_, sign, entryRecipient := _generateMessagingKey(recipientPkBytes, recipientPrivBytes, defaultKey)
		require.Equal(false, _verifyMessagingKey(testMeta, recipientPublicKey, entryRecipient))
		_messagingKeyWithTestMeta(
			testMeta,
			recipientPkBytes,
			recipientPrivString,
			entryRecipient.MessagingPublicKey[:],
			defaultKey,
			sign,
			[]*MessagingGroupMember{},
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, recipientPublicKey, entryRecipient))

		// SenderPk makes a message from their default key to recipient's default key.
		tstampNanos3 := uint64(time.Now().UnixNano())
		testMessage3 := []byte{7, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
		messageEntry.TstampNanos = tstampNanos3
		messageEntry.EncryptedText = testMessage3
		messageEntry.RecipientMessagingPublicKey = entryRecipient.MessagingPublicKey
		messageEntry.RecipientMessagingGroupKeyName = NewGroupKeyName(defaultKey)
		_helpConnectPrivateMessageWithParty(testMeta, senderPrivString, messageEntry, nil)
		// Should pass, so we have:
		// sender -> recipient
		// 	sender: 4
		//	recipient: 4
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry, false))

		// Now send a message from recipient -> sender
		tstampNanos4 := uint64(time.Now().UnixNano())
		testMessage4 := []byte{8, 2, 3, 4, 5, 6, 9, 8, 9, 10, 11, 12, 13}
		messageEntry.TstampNanos = tstampNanos4
		messageEntry.EncryptedText = testMessage4
		messageEntry.SenderPublicKey = NewPublicKey(recipientPkBytes)
		messageEntry.SenderMessagingPublicKey = entryRecipient.MessagingPublicKey
		messageEntry.RecipientPublicKey = NewPublicKey(senderPkBytes)
		messageEntry.RecipientMessagingPublicKey = entry.MessagingPublicKey
		_helpConnectPrivateMessageWithParty(testMeta, recipientPrivString, messageEntry, nil)
		// Should pass, so we have:
		// recipient -> sender
		// 	sender: 5
		//	recipient: 5
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry, false))

		// Verify that all the messages are correct.
		_verifyMessages(testMeta, expectedMessageEntries)
		// Just to sanity-check, verify that the number of messages is as intended.
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err := utxoView.GetMessagesForUser(senderPkBytes)
		require.NoError(err)
		assert.Equal(5, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes)
		require.NoError(err)
		assert.Equal(5, len(messages))
	}

	// -------------------------------------------------------------------------------------
	//	Test #3: Attempt sending group V3 messages
	// -------------------------------------------------------------------------------------
	{
		// Start with an empty group chat made by m1.
		addingMembersKey := []byte("adding-members-key")
		_, _, entry := _generateMessagingKey(m1PubKey, m1PrivKey, addingMembersKey)
		require.Equal(false, _verifyMessagingKey(testMeta, m1PublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			m1PubKey,
			m1Priv,
			entry.MessagingPublicKey[:],
			addingMembersKey,
			[]byte{},
			entry.MessagingGroupMembers,
			nil)
		// Everything should pass verification.
		require.Equal(true, _verifyMessagingKey(testMeta, m1PublicKey, entry))

		// m1 sends a message to the empty group, which in this case means it's sending a message to its own public key.
		tstampNanos1 := uint64(time.Now().UnixNano())
		testMessage1 := []byte{1, 5, 5, 4, 5, 6, 7, 8}
		messageEntry1 := MessageEntry{
			NewPublicKey(m1PubKey),
			NewPublicKey(m1PubKey),
			testMessage1,
			tstampNanos1,
			false,
			MessagesVersion3,
			NewPublicKey(m1PubKey),
			BaseGroupKeyName(),
			entry.MessagingPublicKey,
			NewGroupKeyName(addingMembersKey),
			nil,
		}
		_helpConnectPrivateMessageWithParty(testMeta, m1Priv, messageEntry1, nil)
		// We set groupOwner=true because of the edge-case where the user who made the group sends the message.
		// Should pass, so we have:
		// m1 -> group(m1)
		// 	sender: 5
		//	recipient: 5
		//  m1: 1
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry1, true))

		_verifyMessages(testMeta, expectedMessageEntries)
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err := utxoView.GetMessagesForUser(m1PubKey)
		assert.Equal(1, len(messages))
	}

	// Same test but add another key to the group later and verify they see all messages.
	{
		// Start with an empty group chat made by m1.
		addingMembersKey := []byte("adding-members-key2")
		_, _, entry := _generateMessagingKey(m1PubKey, m1PrivKey, addingMembersKey)
		require.Equal(false, _verifyMessagingKey(testMeta, m1PublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			m1PubKey,
			m1Priv,
			entry.MessagingPublicKey[:],
			addingMembersKey,
			[]byte{},
			entry.MessagingGroupMembers,
			nil)
		// Everything should pass verification.
		require.Equal(true, _verifyMessagingKey(testMeta, m1PublicKey, entry))

		// m1 sends a message to the empty group, which in this case means it's sending a message to its own public key.
		tstampNanos1 := uint64(time.Now().UnixNano())
		testMessage1 := []byte{1, 2, 5, 4, 5, 6, 7, 8, 15}
		messageEntry1 := MessageEntry{
			NewPublicKey(m1PubKey),
			NewPublicKey(m1PubKey),
			testMessage1,
			tstampNanos1,
			false,
			MessagesVersion3,
			NewPublicKey(m1PubKey),
			BaseGroupKeyName(),
			entry.MessagingPublicKey,
			NewGroupKeyName(addingMembersKey),
			nil,
		}
		_helpConnectPrivateMessageWithParty(testMeta, m1Priv, messageEntry1, nil)
		// Should pass, we don't verify the messaging entry yet because we want to make
		// sure that our expected entries map includes entries for all recipients.
		// m1 -> group(m1)
		// 	sender: 5
		//	recipient: 5
		//  m1: 2

		// Now add m0 to the group.
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, &MessagingGroupMember{
			m0PublicKey,
			BaseGroupKeyName(),
			senderPrivBytes,
		})
		_messagingKeyWithTestMeta(
			testMeta,
			m1PubKey,
			m1Priv,
			entry.MessagingPublicKey[:],
			addingMembersKey,
			[]byte{},
			entry.MessagingGroupMembers,
			nil)
		// Everything should pass verification.
		require.Equal(true, _verifyMessagingKey(testMeta, m1PublicKey, entry))

		// m0 sends another message to the group.
		tstampNanos2 := uint64(time.Now().UnixNano())
		testMessage2 := []byte{1, 2, 5, 4, 5, 6, 7, 8, 15, 22}
		// We have the edge-case where we need to
		messageEntry2 := MessageEntry{
			m0PublicKey,
			m1PublicKey,
			testMessage2,
			tstampNanos2,
			false,
			MessagesVersion3,
			m0PublicKey,
			BaseGroupKeyName(),
			entry.MessagingPublicKey,
			NewGroupKeyName(addingMembersKey),
			nil,
		}
		_helpConnectPrivateMessageWithParty(testMeta, m0Priv, messageEntry2, nil)
		// Should pass, so we have:
		// m1 -> group(m1, m0)
		// 	sender: 5
		//	recipient: 5
		//  m1: 3
		// 	m0: 2 (note that m0 now sees both messages in the group chat)

		// We will send a message from a key that's not a member of the group chat. This is expected,
		// for instance if we want to facilitate a functionality where more than one user can respond
		// to messages. Non-members can always be filtered out in the application layer.
		// To add some entropy, the message will be sent by recipient and through default key.
		tstampNanos3 := uint64(time.Now().UnixNano())
		testMessage3 := []byte{1, 2, 5, 4, 5, 6, 7, 8, 15, 22, 27}
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messagingKey := utxoView.GetMessagingGroupKeyToMessagingGroupEntryMapping(&MessagingGroupKey{
			*recipientPublicKey,
			*DefaultGroupKeyName(),
		})
		messageEntry3 := MessageEntry{
			recipientPublicKey,
			m1PublicKey,
			testMessage3,
			tstampNanos3,
			false,
			MessagesVersion3,
			messagingKey.MessagingPublicKey,
			DefaultGroupKeyName(),
			entry.MessagingPublicKey,
			NewGroupKeyName(addingMembersKey),
			nil,
		}
		_helpConnectPrivateMessageWithParty(testMeta, recipientPrivString, messageEntry3, nil)
		// Should pass, so we have:
		// m1 -> group(m1, m0)
		// 	sender: 5
		//	recipient: 6
		//  m1: 4
		// 	m0: 3

		// Verify that all messages are present in the DB.
		// We set groupOwner=true because of the edge-case where the user who made the group sends the message.
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry1, true))
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry2, false))
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry3, false))

		// Verify all messages.
		_verifyMessages(testMeta, expectedMessageEntries)
		// Just to sanity-check, verify that the number of messages is as intended.
		utxoView, err = NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err := utxoView.GetMessagesForUser(recipientPkBytes)
		require.NoError(err)
		assert.Equal(6, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(m1PubKey)
		require.NoError(err)
		assert.Equal(4, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(m0PubKey)
		require.NoError(err)
		assert.Equal(3, len(messages))
	}
	// Now we will get to the real test where we construct a 4-party group chat, aka, the gang,
	// and create the *first* legit on-chain DeSo group chat!
	{
		// Create the group messaging key.
		gangKey := []byte("gang-gang")
		priv, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, gangKey)
		privBytes := priv.Serialize()

		// Define helper functions for encryption/decryption so that we can do some real crypto.
		encrypt := func(plain, recipient []byte) []byte {
			recipientPk, err := btcec.ParsePubKey(recipient, btcec.S256())
			if err != nil {
				return nil
			}
			encryptedMessageBytes, err := EncryptBytesWithPublicKey(
				plain, recipientPk.ToECDSA())
			if err != nil {
				return nil
			}
			return encryptedMessageBytes
		}
		decrypt := func(cipher, recipientPrivKey []byte) []byte {
			recipientPriv, _ := btcec.PrivKeyFromBytes(btcec.S256(), recipientPrivKey)
			plain, err := DecryptBytesWithPrivateKey(cipher, recipientPriv.ToECDSA())
			if err != nil {
				fmt.Println(err)
				return nil
			}
			return plain
		}

		// We can add any messaging keys as recipients, but we'll just add base keys for simplicity,
		// since it's not what we're testing here.
		// We're making a group chat with: (sender, recipient, m0, m2).
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, &MessagingGroupMember{
			recipientPublicKey,
			BaseGroupKeyName(),
			encrypt(privBytes, recipientPkBytes),
		})
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, &MessagingGroupMember{
			m0PublicKey,
			BaseGroupKeyName(),
			encrypt(privBytes, m0PubKey),
		})
		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, &MessagingGroupMember{
			m2PublicKey,
			BaseGroupKeyName(),
			encrypt(privBytes, m2PubKey),
		})
		require.Equal(false, _verifyMessagingKey(testMeta, senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.MessagingPublicKey[:],
			gangKey,
			[]byte{},
			entry.MessagingGroupMembers,
			nil)
		// Everything should pass verification.
		require.Equal(true, _verifyMessagingKey(testMeta, senderPublicKey, entry))

		// Now let's have m0 send the first message to the group chat.
		// We will fetch the encrypted messaging key from m0, decrypt it, and use it to make the message.
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messagingGroupEntries, err := utxoView.GetMessagingGroupEntriesForUser(m0PubKey)
		require.NoError(err)
		require.NotNil(messagingGroupEntries)
		var m0PrivBytes []byte
		for _, groupEntry := range messagingGroupEntries {
			if reflect.DeepEqual(groupEntry.MessagingPublicKey[:], entry.MessagingPublicKey[:]) {
				m0PrivBytes = decrypt(groupEntry.MessagingGroupMembers[0].EncryptedKey, m0PrivKey)
				break
			}
		}
		// The decrypted key should match the original private key.
		require.Equal(privBytes, m0PrivBytes)

		// Now it's time to encrypt the message.
		tstampNanos := uint64(time.Now().UnixNano())
		testMessage := []byte("DeSo V3 Messages work!")
		encryptedMessage := encrypt(testMessage, entry.MessagingPublicKey[:])
		// Create the corresponding message entry and connect it.
		messageEntry := MessageEntry{
			m0PublicKey,
			senderPublicKey,
			encryptedMessage,
			tstampNanos,
			false,
			MessagesVersion3,
			m0PublicKey,
			BaseGroupKeyName(),
			entry.MessagingPublicKey,
			NewGroupKeyName(gangKey),
			nil,
		}
		_helpConnectPrivateMessageWithParty(testMeta, m0Priv, messageEntry, nil)
		// The message should be successfully added, so we have:
		// m0 -> group(sender, recipient, m0, m2)
		// 	sender: 6
		//	recipient: 7
		//  m1: 4
		// 	m0: 4
		// 	m2: 1

		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry, false))

		// Verify the messages.
		_verifyMessages(testMeta, expectedMessageEntries)
		// Just to sanity-check, verify that the number of messages is as intended.
		utxoView, err = NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err := utxoView.GetMessagesForUser(senderPkBytes)
		require.NoError(err)
		assert.Equal(6, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes)
		require.NoError(err)
		assert.Equal(7, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(m0PubKey)
		require.NoError(err)
		assert.Equal(4, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(m2PubKey)
		require.NoError(err)
		assert.Equal(1, len(messages))

		// And also sanity-check that the message exists in the group chat.
		gangMessage, _, err := utxoView.GetMessagesForUser(entry.MessagingPublicKey[:])
		require.NoError(err)
		assert.Equal(1, len(gangMessage))

		// Okay but now let's see if group members can actually decrypt the message.
		// Define a helper function that does just that.
		verifyGangMessage := func(msg, pk, priv []byte) {
			// Get all user messages from the DB.
			var msgKeys []*MessagingGroupEntry
			require.NoError(db.View(func(txn *badger.Txn) error {
				msgKeys, err = DBGetAllMessagingGroupEntriesForMemberWithTxn(txn, NewPublicKey(pk))
				return err
			}))
			assert.NotNil(msgKeys)

			// Now single out the gang message, so we can try decrypting it
			var encryptedKey []byte
			for _, key := range msgKeys {
				if reflect.DeepEqual(key.MessagingPublicKey[:], entry.MessagingPublicKey[:]) {
					encryptedKey = key.MessagingGroupMembers[0].EncryptedKey
					break
				}
			}
			require.NotEqual(0, len(encryptedKey))

			// If the group chat was constructed correctly, then we can decrypt the key present in
			// the recipient messaging key with user's private key, and use it to decrypt the message.
			decryptedKey := decrypt(encryptedKey, priv)
			plaintext := decrypt(msg, decryptedKey)
			// If the message was successfuly decrypted, it should match our original message.
			require.Equal(plaintext, testMessage)
		}
		// Verify that all group members can decrypt the message (skip the group owner)
		verifyGangMessage(gangMessage[0].EncryptedText, recipientPkBytes, recipientPrivBytes)
		verifyGangMessage(gangMessage[0].EncryptedText, m0PubKey, m0PrivKey)
		verifyGangMessage(gangMessage[0].EncryptedText, m2PubKey, m2PrivKey)
	}

	// Now disconnect all entries.
	_rollBackTestMetaTxnsAndFlush(testMeta)
	_applyTestMetaTxnsToMempool(testMeta)
	_applyTestMetaTxnsToViewAndFlush(testMeta)
	_disconnectTestMetaTxnsFromViewAndFlush(testMeta)
	_connectBlockThenDisconnectBlockAndFlush(testMeta)

	// Sanity-check that all entries were reverted from the DB.
	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
	require.NoError(err)
	messages, _, err := utxoView.GetMessagesForUser(senderPkBytes)
	require.NoError(err)
	assert.Equal(0, len(messages))
	messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes)
	require.NoError(err)
	assert.Equal(0, len(messages))
	messages, _, err = utxoView.GetMessagesForUser(m0PubKey)
	require.NoError(err)
	assert.Equal(0, len(messages))
	messages, _, err = utxoView.GetMessagesForUser(m1PubKey)
	require.NoError(err)
	assert.Equal(0, len(messages))
	messages, _, err = utxoView.GetMessagesForUser(m2PubKey)
	require.NoError(err)
	assert.Equal(0, len(messages))
}
