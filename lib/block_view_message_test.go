package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
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

	require := require.New(t)
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

	require.NoError(utxoView.FlushToDb(uint64(blockHeight)))

	return utxoOps, txn, blockHeight, nil
}

func TestPrivateMessage(t *testing.T) {
	require := require.New(t)
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
		blockHeight := chain.blockTip().Height + 1
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, blockHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb(uint64(blockHeight)))

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
	blockHeight := uint64(chain.blockTip().Height + 1)
	require.NoError(utxoView.FlushToDb(blockHeight))

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
	require.NoError(utxoView2.FlushToDb(blockHeight))
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
		require.NoError(utxoView.DisconnectBlock(block, txHashes, utxoOps, block.Header.Height))

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb(block.Header.Height))
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
	priv *btcec.PrivateKey, sign []byte, messagingKeyEntry *AccessGroupEntry) {

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
	keySignature []byte, recipients []*AccessGroupMember) ([]*UtxoOperation, *MsgDeSoTxn, error) {
	return _messagingKeyWithExtraData(t, chain, db, params, senderPk, signerPriv, messagingPublicKey, messagingKeyName, keySignature, recipients, nil)
}

func _messagingKeyWithExtraData(t *testing.T, chain *Blockchain, db *badger.DB, params *DeSoParams,
	senderPk []byte, signerPriv string, messagingPublicKey []byte, messagingKeyName []byte,
	keySignature []byte, recipients []*AccessGroupMember, extraData map[string][]byte) (
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
	require.NoError(utxoView.FlushToDb(uint64(blockHeight)))
	return utxoOps, txn, err
}

func _messagingKeyWithTestMeta(testMeta *TestMeta, senderPk []byte, signerPriv string,
	messagingPublicKey []byte, messagingKeyName []byte, keySignature []byte, recipients []*AccessGroupMember,
	expectedError error) {
	_messagingKeyWithExtraDataWithTestMeta(testMeta, senderPk, signerPriv, messagingPublicKey, messagingKeyName,
		keySignature, recipients, nil, expectedError)
}

// _messagingKeyWithTestMeta is used to connect and flush a messaging key to the DB.
func _messagingKeyWithExtraDataWithTestMeta(testMeta *TestMeta, senderPk []byte, signerPriv string,
	messagingPublicKey []byte, messagingKeyName []byte, keySignature []byte, recipients []*AccessGroupMember,
	extraData map[string][]byte, expectedError error) {

	require := require.New(testMeta.t)

	senderPkBase58Check := Base58CheckEncode(senderPk, false, testMeta.params)
	balance := _getBalance(testMeta.t, testMeta.chain, nil, senderPkBase58Check)

	utxoOps, txn, err := _messagingKeyWithExtraData(testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		senderPk, signerPriv, messagingPublicKey, messagingKeyName, keySignature, recipients, extraData)

	if expectedError != nil {
		require.Equal(true, strings.Contains(err.Error(), expectedError.Error()))
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
func _verifyMessagingKey(testMeta *TestMeta, publicKey *PublicKey, entry *AccessGroupEntry) bool {
	var utxoMessagingEntry *AccessGroupEntry

	require := require.New(testMeta.t)
	messagingKey := NewAccessGroupKey(publicKey, entry.AccessGroupKeyName[:])
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(err)
	utxoMessagingEntry = utxoView.GetAccessGroupKeyToAccessGroupEntryMapping(messagingKey)

	if utxoMessagingEntry == nil || utxoMessagingEntry.isDeleted {
		return false
	}

	return reflect.DeepEqual(EncodeToBytes(0, utxoMessagingEntry), EncodeToBytes(0, entry))
}

// _verifyAddedMessagingKeys is used to verify that messaging key entries in db match the expected entries.
func _verifyAddedMessagingKeys(testMeta *TestMeta, publicKey []byte, expectedEntries []*AccessGroupEntry) {
	require := require.New(testMeta.t)

	require.NoError(testMeta.chain.db.View(func(txn *badger.Txn) error {
		// Get the DB record.
		var entries []*AccessGroupEntry
		var err error
		blockHeight := testMeta.chain.blockTip().Height + 1
		if blockHeight >= testMeta.params.ForkHeights.DeSoAccessGroupsBlockHeight {
			entries, err = DBGetAllAccessGroupEntriesForMemberWithTxn(txn, testMeta.chain.snapshot, publicKey)
			require.NoError(err)
		} else {
			entries, err = DEPRECATEDDBGetAllUserGroupEntriesWithTxn(txn, publicKey)
			require.NoError(err)
		}

		// Make sure the number of entries between the DB and expectation match.
		require.Equal(len(entries), len(expectedEntries))
		// Verify entries one by one.
		for _, expectedEntry := range expectedEntries {
			expectedEntry.DEPRECATED_AccessGroupMembers = sortAccessGroupMembers(expectedEntry.DEPRECATED_AccessGroupMembers)
			ok := false
			for _, entry := range entries {
				actualEntry := &AccessGroupEntry{}
				_, err = DecodeFromBytes(actualEntry, bytes.NewReader(EncodeToBytes(uint64(blockHeight), expectedEntry)))
				require.NoError(err)
				// If we're after the block height then the DB will fetch the simplified membership entry, rather
				// than the entire group chat. If the expected entry assumes the old, full-entry then we will rewrite it
				// to the empty []*AccessGroupMember (+ the member entry for the owner).
				if bytes.Equal(entry.GroupOwnerPublicKey[:], publicKey) &&
					blockHeight >= testMeta.params.ForkHeights.DeSoAccessGroupsBlockHeight {
					actualEntry.DEPRECATED_AccessGroupMembers = []*AccessGroupMember{}
					for _, member := range expectedEntry.DEPRECATED_AccessGroupMembers {
						if bytes.Equal(member.GroupMemberPublicKey[:], publicKey) {
							ownerEntry := &AccessGroupMember{}
							_, err = DecodeFromBytes(ownerEntry, bytes.NewReader(EncodeToBytes(uint64(blockHeight), member)))
							require.NoError(err)
							actualEntry.DEPRECATED_AccessGroupMembers = append(actualEntry.DEPRECATED_AccessGroupMembers, ownerEntry)
							break
						}
					}
				}

				if reflect.DeepEqual(EncodeToBytes(uint64(blockHeight), actualEntry), EncodeToBytes(uint64(blockHeight), entry)) {
					ok = true
					break
				}
			}
			require.Equal(true, ok)
		}
		return nil
	}))
}

// _initMessagingKey is a helper function that instantiates a AccessGroupEntry.
func _initMessagingKey(senderPub []byte, messagingPublicKey []byte, messagingKeyName []byte) *AccessGroupEntry {
	return &AccessGroupEntry{
		GroupOwnerPublicKey: NewPublicKey(senderPub),
		AccessPublicKey:     NewPublicKey(messagingPublicKey),
		AccessGroupKeyName:  NewGroupKeyName(messagingKeyName),
	}
}

func TestMessagingKeys(t *testing.T) {
	require := require.New(t)
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Allow extra data
	params.ForkHeights.ExtraDataOnEntriesBlockHeight = uint32(0)
	// Set the DeSo V3 messages block height to 0
	params.ForkHeights.DeSoV3MessagesBlockHeight = 0
	params.ForkHeights.DeSoAccessGroupsBlockHeight = 0
	params.EncoderMigrationHeights.DeSoAccessGroups.Height = 0
	params.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	GlobalDeSoParams = *params

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
	keyEntriesAdded := make(map[PublicKey][]*AccessGroupEntry)

	// Add base keys for all users. These keys are present by default because they're just the main user keys.
	{
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, BaseGroupKeyName()[:])
		entry.AccessPublicKey = NewPublicKey(senderPkBytes)
		keyEntriesAdded[senderPublicKey] = append(keyEntriesAdded[senderPublicKey], entry)

		_, _, entry = _generateMessagingKey(m0PubKey, m0PrivKey, BaseGroupKeyName()[:])
		entry.AccessPublicKey = NewPublicKey(m0PubKey)
		keyEntriesAdded[m0PublicKey] = append(keyEntriesAdded[m0PublicKey], entry)

		_, _, entry = _generateMessagingKey(m1PubKey, m1PrivKey, BaseGroupKeyName()[:])
		entry.AccessPublicKey = NewPublicKey(m1PubKey)
		keyEntriesAdded[m1PublicKey] = append(keyEntriesAdded[m1PublicKey], entry)

		_, _, entry = _generateMessagingKey(m2PubKey, m2PrivKey, BaseGroupKeyName()[:])
		entry.AccessPublicKey = NewPublicKey(m2PubKey)
		keyEntriesAdded[m2PublicKey] = append(keyEntriesAdded[m2PublicKey], entry)

		_, _, entry = _generateMessagingKey(m3PubKey, m3PrivKey, BaseGroupKeyName()[:])
		entry.AccessPublicKey = NewPublicKey(m3PubKey)
		keyEntriesAdded[m3PublicKey] = append(keyEntriesAdded[m3PublicKey], entry)
	}

	// First some failing tests.
	// Sender tries to add base messaging key, must fail.
	{
		// Try adding base messaging key, should fail
		baseKeyName := BaseGroupKeyName()
		_, sign, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, baseKeyName[:])
		// The base key has the same messaging public key as the owner's main key
		entry.AccessPublicKey = &senderPublicKey
		// The base key should always be present in UtxoView. So we expect true.
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.AccessPublicKey[:],
			baseKeyName[:],
			sign,
			[]*AccessGroupMember{},
			RuleErrorAccessKeyNameCannotBeZeros)
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// Sender tries to add default messaging key without proper signature, must fail.
	{
		defaultKeyName := []byte("default-key")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, defaultKeyName)
		// The default key was not added so verification is false.
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		// Only check that signature fails before we reach the block height, otherwise this would interfere with other tests.
		if chain.blockTip().Height < params.ForkHeights.DeSoAccessGroupsBlockHeight {
			_messagingKeyWithTestMeta(
				testMeta,
				senderPkBytes,
				senderPrivString,
				entry.AccessPublicKey[:],
				defaultKeyName,
				[]byte{},
				[]*AccessGroupMember{},
				RuleErrorAccessGroupSignatureInvalid)
			// Verification still fails because the txn wasn't successful.
			require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		}
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
			entry.AccessPublicKey[:15],
			defaultKeyName,
			sign,
			[]*AccessGroupMember{},
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
			entry.AccessPublicKey[:],
			[]byte{},
			[]byte{},
			[]*AccessGroupMember{},
			RuleErrorAccessKeyNameCannotBeZeros)
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
			entry.AccessPublicKey[:],
			append(defaultKeyName, NewGroupKeyName([]byte{})[:]...),
			[]byte{},
			[]*AccessGroupMember{},
			RuleErrorAccessKeyNameTooLong)
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
			entry.AccessPublicKey[:],
			defaultKeyName,
			sign,
			[]*AccessGroupMember{},
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
			entry.AccessPublicKey[:],
			randomKeyName,
			[]byte{},
			[]*AccessGroupMember{},
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
			entry.AccessPublicKey[:],
			randomKeyName,
			sign,
			[]*AccessGroupMember{},
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
			entry.AccessPublicKey[:],
			randomKeyName,
			[]byte{},
			[]*AccessGroupMember{},
			RuleErrorAccessKeyDoesntAddMembers)
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
			newEntry.AccessPublicKey[:],
			randomKeyName,
			[]byte{},
			[]*AccessGroupMember{},
			RuleErrorAccessPublicKeyCannotBeDifferent)
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
			entry.AccessPublicKey[:],
			append(randomKeyName, byte(0)),
			[]byte{},
			[]*AccessGroupMember{},
			RuleErrorAccessKeyDoesntAddMembers)
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
			entry.AccessPublicKey[:],
			randomKeyName,
			[]byte{},
			[]*AccessGroupMember{},
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
			entry.AccessPublicKey[:],
			randomKeyName,
			[]byte{},
			[]*AccessGroupMember{},
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
			entry.AccessPublicKey[:],
			randomKeyName[:],
			sign,
			[]*AccessGroupMember{},
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
			entry.AccessPublicKey[:],
			randomKeyName[:],
			sign,
			[]*AccessGroupMember{},
			extraData,
			nil,
		)
		entry = DBGetAccessGroupEntry(db, chain.snapshot, NewAccessGroupKey(&m3PublicKey, entry.AccessGroupKeyName[:]))
		// We get the entry from the DB so that it has the extra data
		require.Len(entry.ExtraData, 2)
		require.Equal(entry.ExtraData["extrakey"], []byte("discussion"))
		require.Equal(entry.ExtraData["dontchange"], []byte("checkmelater"))
		require.Equal(true, _verifyMessagingKey(testMeta, &m3PublicKey, entry))

		// For fun, m3 adds group members to the conversation that has extra data
		//_, sign, _ := _generateMessagingKey(m3PubKey, m3PrivKey, extraDataKeyName)
		//entry := DBGetAccessGroupEntry(db, NewAccessGroupKey(&m3PublicKey, extraDataKeyName))
		var MessagingGroupMembers []*AccessGroupMember
		members := [][]byte{m3PubKey, m1PubKey, m2PubKey}
		for _, member := range members {
			MessagingGroupMembers = append(MessagingGroupMembers, &AccessGroupMember{
				NewPublicKey(member),
				BaseGroupKeyName(),
				m3PrivKey,
			})
		}
		extraData = map[string][]byte{
			"extrakey": []byte("newval"),
			"newkey":   []byte("test"),
		}
		//entry := DBGetAccessGroupEntry(db, NewAccessGroupKey(&m3PublicKey, extraDataKeyName))
		_messagingKeyWithExtraDataWithTestMeta(
			testMeta,
			m3PubKey,
			m3Priv,
			entry.AccessPublicKey[:],
			randomKeyName[:],
			sign,
			MessagingGroupMembers,
			extraData,
			nil,
		)
		entry = DBGetAccessGroupEntry(db, chain.snapshot, NewAccessGroupKey(&m3PublicKey, extraDataKeyName))
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
			keyEntriesAdded[pubKey] = append(keyEntriesAdded[pubKey], &AccessGroupEntry{
				GroupOwnerPublicKey:           &m3PublicKey,
				AccessPublicKey:               NewPublicKey(entry.AccessPublicKey[:]),
				AccessGroupKeyName:            NewGroupKeyName(randomKeyName),
				DEPRECATED_AccessGroupMembers: []*AccessGroupMember{member},
				ExtraData:                     entry.ExtraData,
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
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
			NewPublicKey(senderPkBytes),
			BaseGroupKeyName(),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.AccessPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
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
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
			NewPublicKey(entry.AccessPublicKey[:]),
			BaseGroupKeyName(),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.AccessPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
			RuleErrorAccessMemberAlreadyExists)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// Sender tries adding a messaging recipient for m0PubKey with a non-existent key, this should fail.
	{
		randomGroupKeyName := []byte("test-key-5")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
			NewPublicKey(m0PubKey),
			NewGroupKeyName([]byte("non-existent-key")),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.AccessPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
			RuleErrorAccessMemberKeyDoesntExist)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// Sender tries adding a messaging recipient for m0PubKey with a malformed encrypted key, so we fail.
	{
		randomGroupKeyName := []byte("test-key-6")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		// Encrypted key must have at least 32 bytes.
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
			NewPublicKey(m0PubKey),
			BaseGroupKeyName(),
			senderPrivBytes[:15],
		})
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.AccessPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
			RuleErrorAccessMemberEncryptedKeyTooShort)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// Sender tries adding m0PubKey as a recipient twice, this should also fail.
	{
		randomGroupKeyName := []byte("test-key-7")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
			NewPublicKey(m0PubKey),
			BaseGroupKeyName(),
			senderPrivBytes,
		}, &AccessGroupMember{
			NewPublicKey(m0PubKey),
			BaseGroupKeyName(),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.AccessPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
			RuleErrorAccessMemberAlreadyExists)
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
	}
	// Now we get to passing tests.
	// We will do a bunch of tests in the same context so that we preserve the entry messaging key.
	{
		// Sender tries adding a correct recipient for m0PubKey.
		randomGroupKeyName := []byte("test-key-8")
		_, _, entry := _generateMessagingKey(senderPkBytes, senderPrivBytes, randomGroupKeyName)
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
			NewPublicKey(m0PubKey),
			BaseGroupKeyName(),
			senderPrivBytes,
		})
		require.Equal(false, _verifyMessagingKey(testMeta, &senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.AccessPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
			nil)
		// The entry should now pass verification, since it was added successfully.
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))

		// We will do some failing tests on this added entry.
		// Try re-adding the same recipient for m0PubKey, should fail.
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.AccessPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
			RuleErrorAccessMemberAlreadyExists)
		// The entry still passes verification, because transaction was rejected.
		require.Equal(true, _verifyMessagingKey(testMeta, &senderPublicKey, entry))

		// m1PubKey tries to add himself to the group, this will fail because only sender can add
		// new members.
		entryCopy := &AccessGroupEntry{}
		rr := bytes.NewReader(EncodeToBytes(0, entry))
		exists, err := DecodeFromBytes(entryCopy, rr)
		require.Equal(true, exists)
		require.NoError(err)
		entryCopy.DEPRECATED_AccessGroupMembers[0] = &AccessGroupMember{
			NewPublicKey(m1PubKey),
			NewGroupKeyName([]byte("totally-random-key")),
			senderPrivBytes,
		}
		// Transaction fails.
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			m1Priv,
			entryCopy.AccessPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entryCopy.DEPRECATED_AccessGroupMembers,
			RuleErrorInvalidTransactionSignature)

		// Sender adds m1PubKey to the group chat, this time we will succeed.
		workingCopy := &AccessGroupEntry{}
		rr = bytes.NewReader(EncodeToBytes(0, entry))
		exists, err = DecodeFromBytes(workingCopy, rr)
		require.Equal(true, exists)
		require.NoError(err)
		workingCopy.DEPRECATED_AccessGroupMembers[0] = &AccessGroupMember{
			NewPublicKey(m1PubKey),
			NewGroupKeyName([]byte("totally-random-key")),
			senderPrivBytes,
		}
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			workingCopy.AccessPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			workingCopy.DEPRECATED_AccessGroupMembers,
			nil)

		// Reflect the newly added recipient in the entry.
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
			NewPublicKey(m1PubKey),
			NewGroupKeyName([]byte("totally-random-key")),
			senderPrivBytes,
		})

		// Append all the new keys to our keyEntriesAdded.
		keyEntriesAdded[senderPublicKey] = append(keyEntriesAdded[senderPublicKey], entry)

		// Recipient entries have the group owner added as a recipient when fetched from the DB.
		// This is convenient in case we want to fetch the full group messaging key entry as a recipient.
		keyEntriesAdded[m0PublicKey] = append(keyEntriesAdded[m0PublicKey], &AccessGroupEntry{
			GroupOwnerPublicKey:           &senderPublicKey,
			AccessPublicKey:               NewPublicKey(entry.AccessPublicKey[:]),
			AccessGroupKeyName:            NewGroupKeyName(randomGroupKeyName),
			DEPRECATED_AccessGroupMembers: append([]*AccessGroupMember{}, entry.DEPRECATED_AccessGroupMembers[0]),
		})
		keyEntriesAdded[m1PublicKey] = append(keyEntriesAdded[m1PublicKey], &AccessGroupEntry{
			GroupOwnerPublicKey:           &senderPublicKey,
			AccessPublicKey:               NewPublicKey(entry.AccessPublicKey[:]),
			AccessGroupKeyName:            NewGroupKeyName(randomGroupKeyName),
			DEPRECATED_AccessGroupMembers: append([]*AccessGroupMember{}, entry.DEPRECATED_AccessGroupMembers[1]),
		})
	}
	// We will test unencrypted groups, which are intended as large group chats that anyone can join.
	{
		// The unencrypted group will have the messaging public key set as the Secp256k1 base element.
		groupKeyName := []byte("open-group")
		_, _, entry := _generateMessagingKey(m0PubKey, m0PrivKey, groupKeyName)
		basePk := NewPublicKey(GetS256BasePointCompressed())
		entry.AccessPublicKey = basePk
		require.Equal(false, _verifyMessagingKey(testMeta, basePk, entry))
		// This should pass.
		_messagingKeyWithTestMeta(
			testMeta,
			m0PubKey,
			m0Priv,
			entry.AccessPublicKey[:],
			groupKeyName,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
			nil)
		// The DB entry should have the messaging public key derived deterministically from the group key name.
		// Compute the public key and compare it with the DB entry.
		_, groupPkBytes := btcec.PrivKeyFromBytes(btcec.S256(), Sha256DoubleHash(groupKeyName)[:])
		groupPk := NewPublicKey(groupPkBytes.SerializeCompressed())
		expectedEntry := &AccessGroupEntry{}
		rr := bytes.NewReader(EncodeToBytes(0, entry))
		exists, err := DecodeFromBytes(expectedEntry, rr)
		require.Equal(true, exists)
		require.NoError(err)
		expectedEntry.AccessPublicKey = groupPk
		expectedEntry.GroupOwnerPublicKey = basePk
		// Should pass.
		require.Equal(true, _verifyMessagingKey(testMeta, basePk, expectedEntry))

		// Anyone can add recipients to the group.
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
			&m1PublicKey,
			BaseGroupKeyName(),
			senderPrivBytes,
		})
		_messagingKeyWithTestMeta(
			testMeta,
			m1PubKey,
			m1Priv,
			entry.AccessPublicKey[:],
			groupKeyName,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
			nil)
		// Verify that the entry exists in the DB.
		expectedEntry = &AccessGroupEntry{}
		rr = bytes.NewReader(EncodeToBytes(0, entry))
		exists, err = DecodeFromBytes(expectedEntry, rr)
		require.Equal(true, exists)
		require.NoError(err)
		expectedEntry.AccessPublicKey = groupPk
		expectedEntry.GroupOwnerPublicKey = basePk
		require.Equal(true, _verifyMessagingKey(testMeta, basePk, expectedEntry))

		// And the entry behaves as expected, as in we can't re-add recipients, etc.
		_messagingKeyWithTestMeta(
			testMeta,
			m0PubKey,
			m0Priv,
			entry.AccessPublicKey[:],
			groupKeyName,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
			RuleErrorAccessMemberAlreadyExists)
		require.Equal(true, _verifyMessagingKey(testMeta, basePk, expectedEntry))

		// Now add all the entries to our expected entries list.
		keyEntriesAdded[*basePk] = append(keyEntriesAdded[*basePk], expectedEntry)

		keyEntriesAdded[m1PublicKey] = append(keyEntriesAdded[m1PublicKey], &AccessGroupEntry{
			GroupOwnerPublicKey: basePk,
			AccessPublicKey:     groupPk,
			AccessGroupKeyName:  NewGroupKeyName(groupKeyName),
			DEPRECATED_AccessGroupMembers: append([]*AccessGroupMember{}, &AccessGroupMember{
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
		senderMember := &AccessGroupMember{
			NewPublicKey(senderPkBytes),
			DefaultGroupKeyName(),
			senderPrivBytes,
		}
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, senderMember)
		m0Member := &AccessGroupMember{
			NewPublicKey(m0PubKey),
			NewGroupKeyName([]byte("totally-random-key2")),
			senderPrivBytes,
		}
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, m0Member)
		m2Member := &AccessGroupMember{
			NewPublicKey(m2PubKey),
			BaseGroupKeyName(),
			senderPrivBytes,
		}
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, m2Member)
		m3Member := &AccessGroupMember{
			NewPublicKey(m3PubKey),
			DefaultGroupKeyName(),
			senderPrivBytes,
		}
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, m3Member)
		// And finally create the group chat.
		require.Equal(false, _verifyMessagingKey(testMeta, &m1PublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			m1PubKey,
			m1Priv,
			entry.AccessPublicKey[:],
			randomGroupKeyName,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
			nil)
		// Everything should pass verification.
		require.Equal(true, _verifyMessagingKey(testMeta, &m1PublicKey, entry))
		// So now reflect the key entries added with the new keys.
		keyEntriesAdded[m1PublicKey] = append(keyEntriesAdded[m1PublicKey], entry)

		// Recipient entries have the group owner added as a recipient when fetched from the DB.
		// This is convenient in case we want to fetch the full group messaging key entry as a recipient.
		keyEntriesAdded[senderPublicKey] = append(keyEntriesAdded[senderPublicKey], &AccessGroupEntry{
			GroupOwnerPublicKey:           &m1PublicKey,
			AccessPublicKey:               NewPublicKey(entry.AccessPublicKey[:]),
			AccessGroupKeyName:            NewGroupKeyName(randomGroupKeyName),
			DEPRECATED_AccessGroupMembers: append([]*AccessGroupMember{}, senderMember),
		})
		keyEntriesAdded[m0PublicKey] = append(keyEntriesAdded[m0PublicKey], &AccessGroupEntry{
			GroupOwnerPublicKey:           &m1PublicKey,
			AccessPublicKey:               NewPublicKey(entry.AccessPublicKey[:]),
			AccessGroupKeyName:            NewGroupKeyName(randomGroupKeyName),
			DEPRECATED_AccessGroupMembers: append([]*AccessGroupMember{}, m0Member),
		})
		keyEntriesAdded[m2PublicKey] = append(keyEntriesAdded[m2PublicKey], &AccessGroupEntry{
			GroupOwnerPublicKey:           &m1PublicKey,
			AccessPublicKey:               NewPublicKey(entry.AccessPublicKey[:]),
			AccessGroupKeyName:            NewGroupKeyName(randomGroupKeyName),
			DEPRECATED_AccessGroupMembers: append([]*AccessGroupMember{}, m2Member),
		})
		keyEntriesAdded[m3PublicKey] = append(keyEntriesAdded[m3PublicKey], &AccessGroupEntry{
			GroupOwnerPublicKey:           &m1PublicKey,
			AccessPublicKey:               NewPublicKey(entry.AccessPublicKey[:]),
			AccessGroupKeyName:            NewGroupKeyName(randomGroupKeyName),
			DEPRECATED_AccessGroupMembers: append([]*AccessGroupMember{}, m3Member),
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
		entry.AccessPublicKey = NewPublicKey(senderPkBytes)
		keyEntriesAdded[senderPublicKey] = append([]*AccessGroupEntry{}, entry)

		_, _, entry = _generateMessagingKey(m0PubKey, m0PrivKey, BaseGroupKeyName()[:])
		entry.AccessPublicKey = NewPublicKey(m0PubKey)
		keyEntriesAdded[m0PublicKey] = append([]*AccessGroupEntry{}, entry)

		_, _, entry = _generateMessagingKey(m1PubKey, m1PrivKey, BaseGroupKeyName()[:])
		entry.AccessPublicKey = NewPublicKey(m1PubKey)
		keyEntriesAdded[m1PublicKey] = append([]*AccessGroupEntry{}, entry)

		_, _, entry = _generateMessagingKey(m2PubKey, m2PrivKey, BaseGroupKeyName()[:])
		entry.AccessPublicKey = NewPublicKey(m2PubKey)
		keyEntriesAdded[m2PublicKey] = append([]*AccessGroupEntry{}, entry)

		_, _, entry = _generateMessagingKey(m3PubKey, m3PrivKey, BaseGroupKeyName()[:])
		entry.AccessPublicKey = NewPublicKey(m3PubKey)
		keyEntriesAdded[m3PublicKey] = append([]*AccessGroupEntry{}, entry)
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
		encryptedMessageText, tstampNanos, nil, expectedError, true)
}

func _helpConnectPrivateMessageWithPartyAndFlush(testMeta *TestMeta, senderPrivBase58 string,
	entry MessageEntry, expectedError error, flush bool) {

	_connectPrivateMessageWithPartyWithExtraData(testMeta, entry.SenderPublicKey[:], senderPrivBase58, entry.RecipientPublicKey[:],
		entry.SenderMessagingPublicKey[:], entry.SenderMessagingGroupKeyName[:], entry.RecipientMessagingPublicKey[:],
		entry.RecipientMessagingGroupKeyName[:], hex.EncodeToString(entry.EncryptedText), entry.TstampNanos, nil, expectedError, flush)
}

// This helper function connects a private message transaction with the message party in ExtraData.
func _connectPrivateMessageWithPartyWithExtraData(testMeta *TestMeta, senderPkBytes []byte, senderPrivBase58 string,
	recipientPkBytes, senderMessagingPublicKey []byte, senderMessagingKeyName []byte, recipientMessagingPublicKey []byte,
	recipientMessagingKeyName []byte, encryptedMessageText string, tstampNanos uint64, extraData map[string][]byte,
	expectedError error, flush bool) {

	require := require.New(testMeta.t)

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
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	blockHeight := testMeta.chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
	// ConnectTransaction should treat the amount locked as contributing to the output.
	if expectedError != nil {
		require.Equal(true, strings.Contains(err.Error(), expectedError.Error()))
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
	if !flush {
		return
	}
	require.NoError(utxoView.FlushToDb(uint64(blockHeight)))

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
	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
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
	blockHeight := uint64(testMeta.chain.blockTip().Height + 1)
	if !reflect.DeepEqual(EncodeToBytes(blockHeight, messageEntrySender), EncodeToBytes(blockHeight, messageEntryRecipient)) {
		return false
	}
	if !reflect.DeepEqual(EncodeToBytes(blockHeight, messageEntrySender), EncodeToBytes(blockHeight, &expectedEntry)) {
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
	messagingKey := utxoView.GetAccessGroupKeyToAccessGroupEntryMapping(&AccessGroupKey{
		*fetchKey,
		*expectedEntry.RecipientMessagingGroupKeyName,
	})
	if messagingKey != nil {
		for _, recipient := range messagingKey.DEPRECATED_AccessGroupMembers {
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

	utxoView, err := NewUtxoView(testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot)
	require.NoError(err)

	for key, messageEntries := range expectedMessageEntries {
		dbMessageEntries, _, err := utxoView.GetLimitedMessagesForUser(key[:], 100, testMeta.chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(len(messageEntries), len(dbMessageEntries))

		for _, messageEntry := range messageEntries {
			ok := false
			blockHeight := uint64(testMeta.chain.blockTip().Height + 1)
			for _, dbMessageEntry := range dbMessageEntries {
				if reflect.DeepEqual(EncodeToBytes(blockHeight, &messageEntry),
					EncodeToBytes(blockHeight, dbMessageEntry)) {
					ok = true
					break
				}
			}
			require.Equal(true, ok)
		}
	}
}

func setExtraDataBasedOnMessagingEntry(messageEntry *MessageEntry) {
	messageEntry.ExtraData = make(map[string][]byte)
	messageEntry.ExtraData[MessagesVersionString] = UintToBuf(MessagesVersion3)
	messageEntry.ExtraData[SenderMessagingPublicKey] = messageEntry.SenderMessagingPublicKey.ToBytes()
	messageEntry.ExtraData[SenderMessagingGroupKeyName] = messageEntry.SenderMessagingGroupKeyName.ToBytes()
	messageEntry.ExtraData[RecipientMessagingPublicKey] = messageEntry.RecipientMessagingPublicKey.ToBytes()
	messageEntry.ExtraData[RecipientMessagingGroupKeyName] = messageEntry.RecipientMessagingGroupKeyName.ToBytes()
}

// In these tests we basically want to verify that messages are correctly added to UtxoView and DB
// after we send V3 group messages.
func TestGroupMessages(t *testing.T) {
	require := require.New(t)
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_ = miner

	// Set the DeSo V3 messages block height to 0

	params.ForkHeights.ExtraDataOnEntriesBlockHeight = uint32(0)
	// Set the DeSo V3 messages block height to 0
	params.ForkHeights.DeSoV3MessagesBlockHeight = 0
	params.ForkHeights.DeSoAccessGroupsBlockHeight = 0
	params.EncoderMigrationHeights.DeSoAccessGroups.Height = 0
	params.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	GlobalDeSoParams = *params

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
			NewPublicKey(entry.AccessPublicKey[:]),
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
		messageEntry.RecipientMessagingPublicKey = entry.AccessPublicKey
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
		// Since we're passed the ExtraData migration, the entry will have the extra data field. We add it after
		// transaction is processed as an extra sanity-check.
		setExtraDataBasedOnMessagingEntry(&messageEntry)
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry, false))

		_verifyMessages(testMeta, expectedMessageEntries)
		// Just to sanity-check, verify that the number of messages is as intended.
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err := utxoView.GetMessagesForUser(senderPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(1, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(1, len(messages))
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
			entry.AccessPublicKey[:],
			defaultKey,
			sign,
			[]*AccessGroupMember{},
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, senderPublicKey, entry))

		// Verify that all the messages are correct.
		_verifyMessages(testMeta, expectedMessageEntries)
		// Just to sanity-check, verify that the number of messages is as intended.
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err := utxoView.GetMessagesForUser(senderPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(1, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(1, len(messages))

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
			NewPublicKey(entry.AccessPublicKey[:]),
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
		// Since we're passed the ExtraData migration, the entry will have the extra data field. We add it after
		// transaction is processed as an extra sanity-check.
		setExtraDataBasedOnMessagingEntry(&messageEntry)
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry, false))

		// Verify that all the messages are correct.
		_verifyMessages(testMeta, expectedMessageEntries)
		// Just to sanity-check, verify that the number of messages is as intended.
		utxoView, err = NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err = utxoView.GetMessagesForUser(senderPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(2, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(2, len(messages))

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
		// Verify that all the messages are correct.
		_verifyMessages(testMeta, expectedMessageEntries)
		// Just to sanity-check, verify that the number of messages is as intended.
		utxoView, err = NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err = utxoView.GetMessagesForUser(senderPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(3, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(3, len(messages))

		// Register a default key for the recipient, so we can try sending messages between two messaging keys.
		defaultKey = []byte("default-key")
		_, sign, entryRecipient := _generateMessagingKey(recipientPkBytes, recipientPrivBytes, defaultKey)
		require.Equal(false, _verifyMessagingKey(testMeta, recipientPublicKey, entryRecipient))
		_messagingKeyWithTestMeta(
			testMeta,
			recipientPkBytes,
			recipientPrivString,
			entryRecipient.AccessPublicKey[:],
			defaultKey,
			sign,
			[]*AccessGroupMember{},
			nil)
		require.Equal(true, _verifyMessagingKey(testMeta, recipientPublicKey, entryRecipient))

		// SenderPk makes a message from their default key to recipient's default key.
		tstampNanos3 := uint64(time.Now().UnixNano())
		testMessage3 := []byte{7, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
		messageEntry.TstampNanos = tstampNanos3
		messageEntry.EncryptedText = testMessage3
		messageEntry.RecipientMessagingPublicKey = entryRecipient.AccessPublicKey
		messageEntry.RecipientMessagingGroupKeyName = NewGroupKeyName(defaultKey)
		_helpConnectPrivateMessageWithParty(testMeta, senderPrivString, messageEntry, nil)
		// Should pass, so we have:
		// sender -> recipient
		// 	sender: 4
		//	recipient: 4
		// Since we're passed the ExtraData migration, the entry will have the extra data field. We add it after
		// transaction is processed as an extra sanity-check.
		setExtraDataBasedOnMessagingEntry(&messageEntry)
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry, false))

		// Verify that all the messages are correct.
		_verifyMessages(testMeta, expectedMessageEntries)
		// Just to sanity-check, verify that the number of messages is as intended.
		utxoView, err = NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err = utxoView.GetMessagesForUser(senderPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(4, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(4, len(messages))

		// Now send a message from recipient -> sender
		tstampNanos4 := uint64(time.Now().UnixNano())
		testMessage4 := []byte{8, 2, 3, 4, 5, 6, 9, 8, 9, 10, 11, 12, 13}
		messageEntry.TstampNanos = tstampNanos4
		messageEntry.EncryptedText = testMessage4
		messageEntry.SenderPublicKey = NewPublicKey(recipientPkBytes)
		messageEntry.SenderMessagingPublicKey = entryRecipient.AccessPublicKey
		messageEntry.RecipientPublicKey = NewPublicKey(senderPkBytes)
		messageEntry.RecipientMessagingPublicKey = entry.AccessPublicKey
		_helpConnectPrivateMessageWithParty(testMeta, recipientPrivString, messageEntry, nil)
		// Should pass, so we have:
		// recipient -> sender
		// 	sender: 5
		//	recipient: 5
		// Since we're passed the ExtraData migration, the entry will have the extra data field. We add it after
		// transaction is processed as an extra sanity-check.
		setExtraDataBasedOnMessagingEntry(&messageEntry)
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry, false))

		// Verify that all the messages are correct.
		_verifyMessages(testMeta, expectedMessageEntries)
		// Just to sanity-check, verify that the number of messages is as intended.
		utxoView, err = NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err = utxoView.GetMessagesForUser(senderPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(5, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(5, len(messages))
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
			entry.AccessPublicKey[:],
			addingMembersKey,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
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
			entry.AccessPublicKey,
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
		// Since we're passed the ExtraData migration, the entry will have the extra data field. We add it after
		// transaction is processed as an extra sanity-check.
		setExtraDataBasedOnMessagingEntry(&messageEntry1)
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry1, true))

		_verifyMessages(testMeta, expectedMessageEntries)
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err := utxoView.GetMessagesForUser(m1PubKey, chain.blockTip().Height+1)
		require.Equal(1, len(messages))
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
			entry.AccessPublicKey[:],
			addingMembersKey,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
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
			entry.AccessPublicKey,
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
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
			m0PublicKey,
			BaseGroupKeyName(),
			senderPrivBytes,
		})
		_messagingKeyWithTestMeta(
			testMeta,
			m1PubKey,
			m1Priv,
			entry.AccessPublicKey[:],
			addingMembersKey,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
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
			entry.AccessPublicKey,
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
		messagingKey := utxoView.GetAccessGroupKeyToAccessGroupEntryMapping(&AccessGroupKey{
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
			messagingKey.AccessPublicKey,
			DefaultGroupKeyName(),
			entry.AccessPublicKey,
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
		// Since we're passed the ExtraData migration, the entry will have the extra data field. We add it after
		// transaction is processed as an extra sanity-check.
		setExtraDataBasedOnMessagingEntry(&messageEntry1)
		setExtraDataBasedOnMessagingEntry(&messageEntry2)
		setExtraDataBasedOnMessagingEntry(&messageEntry3)
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry1, true))
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry2, false))
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry3, false))

		// Verify all messages.
		_verifyMessages(testMeta, expectedMessageEntries)
		// Just to sanity-check, verify that the number of messages is as intended.
		utxoView, err = NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err := utxoView.GetMessagesForUser(recipientPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(6, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(m1PubKey, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(4, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(m0PubKey, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(3, len(messages))
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
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
			senderPublicKey,
			BaseGroupKeyName(),
			encrypt(privBytes, senderPkBytes),
		})
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
			recipientPublicKey,
			BaseGroupKeyName(),
			encrypt(privBytes, recipientPkBytes),
		})
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
			m0PublicKey,
			BaseGroupKeyName(),
			encrypt(privBytes, m0PubKey),
		})
		entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
			m2PublicKey,
			BaseGroupKeyName(),
			encrypt(privBytes, m2PubKey),
		})
		require.Equal(false, _verifyMessagingKey(testMeta, senderPublicKey, entry))
		_messagingKeyWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.AccessPublicKey[:],
			gangKey,
			[]byte{},
			entry.DEPRECATED_AccessGroupMembers,
			nil)
		// Everything should pass verification.
		require.Equal(true, _verifyMessagingKey(testMeta, senderPublicKey, entry))

		// Now let's have m0 send the first message to the group chat.
		// We will fetch the encrypted messaging key from m0, decrypt it, and use it to make the message.
		utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		accessGroupEntries, err := utxoView.GetAccessGroupEntriesForUser(m0PubKey, chain.blockTip().Height+1)
		require.NoError(err)
		require.NotNil(accessGroupEntries)
		var m0PrivBytes []byte
		for _, groupEntry := range accessGroupEntries {
			if reflect.DeepEqual(groupEntry.AccessPublicKey[:], entry.AccessPublicKey[:]) {
				m0PrivBytes = decrypt(groupEntry.DEPRECATED_AccessGroupMembers[0].EncryptedKey, m0PrivKey)
				break
			}
		}
		// The decrypted key should match the original private key.
		require.Equal(privBytes, m0PrivBytes)

		// Now it's time to encrypt the message.
		tstampNanos := uint64(time.Now().UnixNano())
		testMessage := []byte("DeSo V3 Messages work!")
		encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
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
			entry.AccessPublicKey,
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

		setExtraDataBasedOnMessagingEntry(&messageEntry)
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, messageEntry, false))

		// Verify the messages.
		_verifyMessages(testMeta, expectedMessageEntries)
		// Just to sanity-check, verify that the number of messages is as intended.
		utxoView, err = NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err := utxoView.GetMessagesForUser(senderPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(6, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(7, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(m0PubKey, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(4, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(m2PubKey, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(1, len(messages))

		// And also sanity-check that the message exists in the group chat.
		gangMessage, _, err := utxoView.GetMessagesForUser(entry.AccessPublicKey[:], chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(1, len(gangMessage))

		// Okay but now let's see if group members can actually decrypt the message.
		// Define a helper function that does just that.
		verifyGangMessage := func(msg, pk, priv []byte) {
			// Get all user messages from the DB.
			var msgKeys []*AccessGroupEntry

			require.NoError(db.View(func(txn *badger.Txn) error {
				blockHeight := chain.blockTip().Height
				if blockHeight < params.ForkHeights.DeSoAccessGroupsBlockHeight {
					msgKeys, err = DEPRECATEDDBGetAllMessagingGroupEntriesForMemberWithTxn(txn, NewPublicKey(pk))
				} else {
					msgKeys, err = DBGetAllEntriesForPublicKeyFromMembershipIndexWithTxn(txn, chain.snapshot, NewPublicKey(pk))
				}
				return err
			}))
			require.NotNil(msgKeys)

			// Now single out the gang message, so we can try decrypting it
			var encryptedKey []byte
			for _, key := range msgKeys {
				if reflect.DeepEqual(key.AccessPublicKey[:], entry.AccessPublicKey[:]) {
					encryptedKey = key.DEPRECATED_AccessGroupMembers[0].EncryptedKey
					break
				}
			}
			require.NotEqual(0, len(encryptedKey))

			// If the group chat was constructed correctly, then we can decrypt the key present in
			// the recipient messaging key with user's private key, and use it to decrypt the message.
			decryptedKey := decrypt(encryptedKey, priv)
			plaintext := decrypt(msg, decryptedKey)
			// If the message was successfully decrypted, it should match our original message.
			require.Equal(plaintext, testMessage)
		}
		// Verify that all group members can decrypt the message (skip the group owner)
		verifyGangMessage(gangMessage[0].EncryptedText, recipientPkBytes, recipientPrivBytes)
		verifyGangMessage(gangMessage[0].EncryptedText, m0PubKey, m0PrivKey)
		verifyGangMessage(gangMessage[0].EncryptedText, m2PubKey, m2PrivKey)

		// MUTING TESTS
		// Let us now mute m0
		var muteList []*AccessGroupMember
		muteList = append(muteList, &AccessGroupMember{
			m0PublicKey,
			BaseGroupKeyName(),
			encrypt(privBytes, m0PubKey),
		})
		extraData := make(map[string][]byte)
		extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
		_messagingKeyWithExtraDataWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.AccessPublicKey[:],
			gangKey,
			[]byte{},
			muteList,
			extraData,
			nil)
		// The decrypted key should match the original private key.
		require.Equal(privBytes, m0PrivBytes)
		// Now it's time to encrypt the message.
		tstampNanos = uint64(time.Now().UnixNano())
		testMessage = []byte("DeSo Group Chat Muting Works because this won't be sent!")
		encryptedMessage = encrypt(testMessage, entry.AccessPublicKey[:])
		// Create the corresponding message entry and connect it.
		muteMessageEntry := MessageEntry{
			m0PublicKey,
			senderPublicKey,
			encryptedMessage,
			tstampNanos,
			false,
			MessagesVersion3,
			m0PublicKey,
			BaseGroupKeyName(),
			entry.AccessPublicKey,
			NewGroupKeyName(gangKey),
			nil,
		}
		_helpConnectPrivateMessageWithParty(testMeta, m0Priv, muteMessageEntry, RuleErrorAccessMemberMuted)
		// m0 is currently muted and hence:
		// The message should NOT be successfully added, so we STILL have:
		// m0 -> group(sender, recipient, m0, m2)
		// 	sender: 6
		//	recipient: 7
		//  m1: 4
		// 	m0: 4
		// 	m2: 1
		require.Equal(false, _verifyMessageParty(testMeta, expectedMessageEntries, muteMessageEntry, false))

		// Verify the messages AGAIN.
		_verifyMessages(testMeta, expectedMessageEntries)
		// Just to sanity-check, verify that the number of messages is as intended.
		utxoView, err = NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err = utxoView.GetMessagesForUser(senderPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(6, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(7, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(m1PubKey, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(4, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(m0PubKey, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(4, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(m2PubKey, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(1, len(messages))

		{
			// Let us now try to mute m0 AGAIN
			// This should produce an error since m0 is already muted
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m0PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m0PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
			_messagingKeyWithExtraDataWithTestMeta(
				testMeta,
				senderPkBytes,
				senderPrivString,
				entry.AccessPublicKey[:],
				gangKey,
				[]byte{},
				muteList,
				extraData,
				RuleErrorAccessMemberAlreadyMuted)
		}

		// UNMUTING TESTS
		// Let us now unmute m0
		var unmuteList []*AccessGroupMember
		unmuteList = append(unmuteList, &AccessGroupMember{
			m0PublicKey,
			BaseGroupKeyName(),
			encrypt(privBytes, m0PubKey),
		})
		extraData = make(map[string][]byte)
		extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationUnmuteMembers)}
		_messagingKeyWithExtraDataWithTestMeta(
			testMeta,
			senderPkBytes,
			senderPrivString,
			entry.AccessPublicKey[:],
			gangKey,
			[]byte{},
			unmuteList,
			extraData,
			nil)
		// Now it's time to encrypt the message.
		tstampNanos = uint64(time.Now().UnixNano())
		testMessage = []byte("DeSo Group Chat Unmuting Works because this will be sent!")
		encryptedMessage = encrypt(testMessage, entry.AccessPublicKey[:])
		// Create the corresponding message entry and connect it.
		unmuteMessageEntry := MessageEntry{
			m0PublicKey,
			senderPublicKey,
			encryptedMessage,
			tstampNanos,
			false,
			MessagesVersion3,
			m0PublicKey,
			BaseGroupKeyName(),
			entry.AccessPublicKey,
			NewGroupKeyName(gangKey),
			nil,
		}
		_helpConnectPrivateMessageWithParty(testMeta, m0Priv, unmuteMessageEntry, nil)
		// m0 is now unmuted and hence:
		// The message should be successfully added, so we now have:
		// m0 -> group(sender, recipient, m0, m2)
		// 	sender: 7
		//	recipient: 8
		//  m1: 4
		// 	m0: 5
		// 	m2: 2
		// Since we're passed the ExtraData migration, the entry will have the extra data field. We add it after
		// transaction is processed as an extra sanity-check.
		setExtraDataBasedOnMessagingEntry(&unmuteMessageEntry)
		require.Equal(true, _verifyMessageParty(testMeta, expectedMessageEntries, unmuteMessageEntry, false))

		// Verify the messages AGAIN.
		_verifyMessages(testMeta, expectedMessageEntries)
		// Just to sanity-check, verify that the number of messages is as intended.
		utxoView, err = NewUtxoView(db, params, nil, chain.snapshot)
		require.NoError(err)
		messages, _, err = utxoView.GetMessagesForUser(senderPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(7, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(8, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(m1PubKey, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(4, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(m0PubKey, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(5, len(messages))
		messages, _, err = utxoView.GetMessagesForUser(m2PubKey, chain.blockTip().Height+1)
		require.NoError(err)
		require.Equal(2, len(messages))

		{
			// Let us now try to unmute m0 AGAIN
			// This should produce an error since m0 is already unmuted
			var unmuteList []*AccessGroupMember
			unmuteList = append(unmuteList, &AccessGroupMember{
				m0PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m0PubKey),
			})
			extraData = make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationUnmuteMembers)}
			_messagingKeyWithExtraDataWithTestMeta(
				testMeta,
				senderPkBytes,
				senderPrivString,
				entry.AccessPublicKey[:],
				gangKey,
				[]byte{},
				unmuteList,
				extraData,
				RuleErrorAccessMemberAlreadyUnmuted)
		}

		{
			// Let us now try to mute m1 who is not part of the group
			// This should produce an error since m1 does not exist in the group
			var unmuteList []*AccessGroupMember
			unmuteList = append(unmuteList, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			extraData = make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
			_messagingKeyWithExtraDataWithTestMeta(
				testMeta,
				senderPkBytes,
				senderPrivString,
				entry.AccessPublicKey[:],
				gangKey,
				[]byte{},
				unmuteList,
				extraData,
				RuleErrorAccessMemberNotInGroup)
		}
		{
			// Let us now try to unmute m1 who is not part of the group
			// This should produce an error since m1 does not exist in the group
			var unmuteList []*AccessGroupMember
			unmuteList = append(unmuteList, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			extraData = make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationUnmuteMembers)}
			_messagingKeyWithExtraDataWithTestMeta(
				testMeta,
				senderPkBytes,
				senderPrivString,
				entry.AccessPublicKey[:],
				gangKey,
				[]byte{},
				unmuteList,
				extraData,
				RuleErrorAccessMemberNotInGroup)
		}

		{
			// MORE MUTING TESTS
			// Let us now try to mute group owner "sender" as a sanity check
			// This should fail because GroupOwner cannot mute/unmute herself
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				senderPublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, senderPkBytes),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
			_messagingKeyWithExtraDataWithTestMeta(
				testMeta,
				senderPkBytes,
				senderPrivString,
				entry.AccessPublicKey[:],
				gangKey,
				[]byte{},
				muteList,
				extraData,
				RuleErrorAccessGroupOwnerMutingSelf)
		}

		{
			// MORE UNMUTING TESTS
			// Let us now try to unmute group owner "sender" as a sanity check
			// This should fail because GroupOwner cannot mute/unmute herself
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				senderPublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, senderPkBytes),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationUnmuteMembers)}
			_messagingKeyWithExtraDataWithTestMeta(
				testMeta,
				senderPkBytes,
				senderPrivString,
				entry.AccessPublicKey[:],
				gangKey,
				[]byte{},
				muteList,
				extraData,
				RuleErrorAccessGroupOwnerUnmutingSelf)
		}

		{
			// Deprecated Hacked Prefix Test
			// Let us set the DeSoAccessGroupsBlockHeight to much higher than current blockHeight
			params.ForkHeights.DeSoAccessGroupsBlockHeight = chain.blockTip().Height + 10
			// Let us now mute m2
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m2PublicKey,
				BaseGroupKeyName(),
				privBytes,
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
			// This transaction would normally go through after the blockheight, but it would fail prior.
			// As the blockheight is not yet reached, this should fail for the "non-muting" reason.
			_messagingKeyWithExtraDataWithTestMeta(
				testMeta,
				senderPkBytes,
				senderPrivString,
				entry.AccessPublicKey[:],
				gangKey,
				[]byte{},
				muteList,
				extraData,
				RuleErrorAccessMemberAlreadyExists)
			// reset to 0 for further testing
			params.ForkHeights.DeSoAccessGroupsBlockHeight = 0
		}

		{
			// More Deprecated Hacked Prefix Test
			// Let us now try to mute m2 again
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m2PublicKey,
				BaseGroupKeyName(),
				privBytes,
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
			_messagingKeyWithExtraDataWithTestMeta(
				testMeta,
				senderPkBytes,
				senderPrivString,
				entry.AccessPublicKey[:],
				gangKey,
				[]byte{},
				muteList,
				extraData,
				nil)
			// The decrypted key should match the original private key.
			// Now it's time to encrypt the message.
			tstampNanos = uint64(time.Now().UnixNano())
			testMessage = []byte("DeSo Deprecated HackedMessagingGroupEntry is backwards compatible and " +
				"DeSo Group Chat Muting Works because this won't be sent!")
			encryptedMessage = encrypt(testMessage, entry.AccessPublicKey[:])
			// Create the corresponding message entry and connect it.
			muteMessageEntry := MessageEntry{
				m2PublicKey,
				senderPublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m2PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			// Let us set the DeSoAccessGroupsBlockHeight to much higher than current blockHeight,
			// don't flush because we are modifying the fork height. This transaction should pass because the connect logic
			// will disregard the fork height and ignore the fact that m2 is muted. That's why we don't flush.
			params.ForkHeights.DeSoAccessGroupsBlockHeight = chain.blockTip().Height + 10
			_helpConnectPrivateMessageWithPartyAndFlush(testMeta, m2Priv, muteMessageEntry, nil, false)
			// Now let's try to send a message to the group with DeSoAccessGroupsBlockHeight set to 0
			// This should fail since the member is muted.
			params.ForkHeights.DeSoAccessGroupsBlockHeight = 0
			_helpConnectPrivateMessageWithParty(testMeta, m2Priv, muteMessageEntry, RuleErrorAccessMemberMuted)
			// m2 is currently muted, so the txn should not complete muting should work due to gating of the check-if-muted
			// functionality. Note: This is just a sanity check and this probably won't happen on mainnet as the blockHeight
			// does not suddenly decrease below DeSoAccessGroupsBlockHeight after a muting txn:
			// The message should be unsuccessfully added, so we still have:
			// m2 -> group(sender, recipient, m0, m2)
			// 	sender: 7
			//	recipient: 8
			//  m1: 4
			// 	m0: 5
			// 	m2: 2
			require.Equal(false, _verifyMessageParty(testMeta, expectedMessageEntries, muteMessageEntry, false))

			// Lower the DeSoAccessGroupsBlockHeight to zero, otherwise we won't fetch all the group
			// chats and the _verifyMessages will fail. If we're past the block height, we use the membership index prefix to
			// store user's group chats. However, if we're before the block height, we use the old deprecated db prefix to
			// store the group chats that a user is a member of. If a user became a member of a group chat AFTER the block height
			// the corresponding group chat will not be saved in the deprecated prefix. As this is the case here, we need to
			// lower the block height to zero to fetch all the group chats.
			params.ForkHeights.DeSoAccessGroupsBlockHeight = 0
			// Verify the messages AGAIN.
			_verifyMessages(testMeta, expectedMessageEntries)
			// Just to sanity-check, verify that the number of messages is as intended.
			utxoView, err = NewUtxoView(db, params, nil, chain.snapshot)
			require.NoError(err)
			messages, _, err = utxoView.GetMessagesForUser(senderPkBytes, chain.blockTip().Height+1)
			require.NoError(err)
			require.Equal(7, len(messages))
			messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes, chain.blockTip().Height+1)
			require.NoError(err)
			require.Equal(8, len(messages))
			messages, _, err = utxoView.GetMessagesForUser(m1PubKey, chain.blockTip().Height+1)
			require.NoError(err)
			require.Equal(4, len(messages))
			messages, _, err = utxoView.GetMessagesForUser(m0PubKey, chain.blockTip().Height+1)
			require.NoError(err)
			require.Equal(5, len(messages))
			messages, _, err = utxoView.GetMessagesForUser(m2PubKey, chain.blockTip().Height+1)
			require.NoError(err)
			require.Equal(2, len(messages))
		}

		// TEST REMOVE-MEMBER FROM GROUP CHAT
		{
			// get block height
			blockHeight := chain.blockTip().Height + 1
			// get rotating version
			rotatingVersion := getMessagingGroupRotatingVersion(entry, blockHeight)
			_ = rotatingVersion
		}
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
	messages, _, err := utxoView.GetMessagesForUser(senderPkBytes, chain.blockTip().Height+1)
	require.NoError(err)
	require.Equal(0, len(messages))
	messages, _, err = utxoView.GetMessagesForUser(recipientPkBytes, chain.blockTip().Height+1)
	require.NoError(err)
	require.Equal(0, len(messages))
	messages, _, err = utxoView.GetMessagesForUser(m0PubKey, chain.blockTip().Height+1)
	require.NoError(err)
	require.Equal(0, len(messages))
	messages, _, err = utxoView.GetMessagesForUser(m1PubKey, chain.blockTip().Height+1)
	require.NoError(err)
	require.Equal(0, len(messages))
	messages, _, err = utxoView.GetMessagesForUser(m2PubKey, chain.blockTip().Height+1)
	require.NoError(err)
	require.Equal(0, len(messages))

}

func testMuting(t *testing.T) {
	require := require.New(t)
	_ = require
	chain, params, db := NewLowDifficultyBlockchain()
	_, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_ = miner
	utxoView, err := NewUtxoView(db, params, nil, chain.snapshot)
	require.NoError(err)

	// First test for post-muting block height.
	{
		chain.params.ForkHeights.DeSoAccessGroupsBlockHeight = 0
		// Call testTestnet to test the testnet code with regnet params.
		txns, expectedErrors := testTestnet(t, chain, utxoView, senderPkString, senderPrivString, 10)
		// Connect all txns.
		for ii, txn := range txns {
			txnHash := txn.Hash()
			txnSize := getTxnSize(*txn)
			blockheight := chain.blockTip().Height + 1
			utxoOps, totalInput, totalOutput, fees, err := utxoView.ConnectTransaction(txn, txnHash, txnSize, blockheight, true, false)

			fmt.Println(ii, expectedErrors[ii], err)
			// require that err contains the expected error
			if err == nil {
				require.Equal(expectedErrors[ii], err)
			} else {
				require.Contains(err.Error(), expectedErrors[ii].Error())
			}
			require.Equal(totalInput, totalOutput+fees)
			_ = utxoOps
		}
	}

	// Now test for pre-muting block height.
	{
		chain.params.ForkHeights.DeSoAccessGroupsBlockHeight = 1000000000
		// Call testTestnet to test the testnet code with regnet params.
		txns, expectedErrors := testTestnet(t, chain, utxoView, senderPkString, senderPrivString, 10)
		// Connect all txns.
		for ii, txn := range txns {
			txnHash := txn.Hash()
			txnSize := getTxnSize(*txn)
			blockheight := chain.blockTip().Height + 1
			utxoOps, totalInput, totalOutput, fees, err := utxoView.ConnectTransaction(txn, txnHash, txnSize, blockheight, true, false)

			fmt.Println(ii, expectedErrors[ii], err)
			// require that err contains the expected error
			if err == nil {
				require.Equal(expectedErrors[ii], err)
			} else {
				require.Contains(err.Error(), expectedErrors[ii].Error())
			}
			require.Equal(totalInput, totalOutput+fees)
			_ = utxoOps
		}
	}
}

// write a function that takes in a utxoView and a publicKey and returns a list of txns and a list of errors
func testTestnet(t *testing.T, bc *Blockchain, bav *UtxoView, fundedPublicKey string, fundedPrivKey string, nanosPerTxn uint64) (txns []*MsgDeSoTxn, expectedErrors []error) {
	require := require.New(t)

	var (
		// Set up some addresses
		m0Pub           = "tBCKY2X1Gbqn95tN1PfsCFLKX6x6h48g5LdHt9T95Wj9Rm6EVKLVpi"
		m0Priv          = "tbc2uXFwv3CJvr5HdLLKpAtLNCtBafvfxLBMbJFCNdLA61cLB7aLq"
		m0PkBytes, _, _ = Base58CheckDecode(m0Pub)
		_               = m0PkBytes

		m1Pub           = "tBCKYGWj36qERG57RKdrnCf6JQad1smGTzeLkj1bfN7UqKwY8SM57a"
		m1Priv          = "tbc2DtxgxPVB6T6sbFqhgNrPqwb7QUYG5ZS7aEXQ3ZxAyG88YAPVy"
		m1PkBytes, _, _ = Base58CheckDecode(m1Pub)
		_               = m1Priv
		_               = m1PkBytes

		m2Pub           = "tBCKVNYw7WgG59SGP8EdpR9nyywoMBYa3ChLG4UjCBhvFgd4e7oXNg"
		m2Priv          = "tbc37VGdu4RJ7uJcoGHrDJkr4FZPsVYbyo3dRxdhyQHPNp6jUjbK1"
		m2PkBytes, _, _ = Base58CheckDecode(m2Pub)
		_               = m2PkBytes

		m3Pub           = "tBCKWqMGE7xdz78juDSEsDFYt67CuL9VrTiv627Wj2sLwG6B2fcy7o"
		m3Priv          = "tbc2MkEWaCoVNh5rV4fyAdSmAkLQ9bZLqEMGSLYtoAAxgA1844Y67"
		m3PkBytes, _, _ = Base58CheckDecode(m3Pub)
		_               = m3Priv
		_               = m3PkBytes

		m4Pub           = "tBCKWu6nNQa3cUV8QLwRhX9r6NXcNpDuK7xtscwm27zXJ7MxdnmZ3g"
		m4Priv          = "tbc2GmpAmkm8CmMjS9NXiAFZHEDGqxSCCpkvkwnY8oqfZXAXnmtFV"
		m4PkBytes, _, _ = Base58CheckDecode(m4Pub)
		_               = m4Priv
		_               = m4PkBytes
	)

	m0PubKey, _, err := Base58CheckDecode(m0Pub)
	require.NoError(err)
	m0PrivKey, _, err := Base58CheckDecode(m0Priv)
	require.NoError(err)
	m0PublicKey := NewPublicKey(m0PubKey)

	m1PubKey, _, err := Base58CheckDecode(m1Pub)
	require.NoError(err)
	m1PrivKey, _, err := Base58CheckDecode(m1Priv)
	_ = m1PrivKey
	require.NoError(err)
	m1PublicKey := NewPublicKey(m1PubKey)

	m2PubKey, _, err := Base58CheckDecode(m2Pub)
	require.NoError(err)
	m2PrivKey, _, err := Base58CheckDecode(m2Priv)
	_ = m2PrivKey
	require.NoError(err)
	m2PublicKey := NewPublicKey(m2PubKey)

	m3PubKey, _, err := Base58CheckDecode(m3Pub)
	require.NoError(err)
	m3PrivKey, _, err := Base58CheckDecode(m3Priv)
	_ = m3PrivKey
	require.NoError(err)
	m3PublicKey := NewPublicKey(m3PubKey)

	// m4 is a public key that is not in the group.
	m4PubKey, _, err := Base58CheckDecode(m4Pub)
	require.NoError(err)
	m4PrivKey, _, err := Base58CheckDecode(m4Priv)
	_ = m4PrivKey
	require.NoError(err)
	m4PublicKey := NewPublicKey(m4PubKey)

	// Fund all the keys.
	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		_, _, _ = _doBasicTransferWithViewFlush(
			t, bc, bc.db, bc.params, senderPk, recipientPk,
			senderPriv, nanosPerTxn*100, 11)
	}

	registerOrTransfer("", fundedPublicKey, m0Pub, fundedPrivKey)
	registerOrTransfer("", fundedPublicKey, m1Pub, fundedPrivKey)
	registerOrTransfer("", fundedPublicKey, m2Pub, fundedPrivKey)
	registerOrTransfer("", fundedPublicKey, m3Pub, fundedPrivKey)
	registerOrTransfer("", fundedPublicKey, m4Pub, fundedPrivKey)

	// Create the group messaging key with m0 as the group owner.
	gangKey := []byte("gang-gang")
	priv, _, entry := _generateMessagingKey(m0PubKey, m0PrivKey, gangKey)

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
	_ = decrypt

	// ALL CORRECT BLOCKHEIGHT TXNS AS FOLLOWS

	if bc.blockTip().Height >= bc.params.ForkHeights.DeSoAccessGroupsBlockHeight {
		{
			// Create a txn where m0 adds m0, m1, m2 and m3 as members of the group.
			// We can add any messaging keys as recipients, but we'll just add base keys for simplicity,
			// since it's not what we're testing here.
			// We're making a group chat with: (m0, m1, m2, m3).
			entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
				m0PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m0PubKey),
			})
			entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
				m2PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m2PubKey),
			})
			entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
				m3PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m3PubKey),
			})
			recipients := entry.DEPRECATED_AccessGroupMembers
			extraData := make(map[string][]byte)
			extraData = nil
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				recipients, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m0 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should be sent to the group as m0 is not muted.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m0PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m0PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m1 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should be sent to the group as m1 is not muted.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m1PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m1PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m1Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m0 mutes m1.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m1 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should not be sent to the group as m1 is muted.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m1PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m1PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m1Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessMemberMuted)
		}

		{
			// Create a txn where m0 mutes m1.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessMemberAlreadyMuted)
		}

		{
			// Create a txn where m0 unmutes m1.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationUnmuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m1 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should be sent to the group as m1 is not muted.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m1PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m1PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m1Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m0 unmutes m1.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationUnmuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessMemberAlreadyUnmuted)
		}

		{
			// Create a txn where m0 mutes m4.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m4PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m4PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessMemberNotInGroup)
		}

		{
			// Create a txn where m0 unmutes m4.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m4PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m4PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationUnmuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessMemberNotInGroup)
		}

		{
			// Create a txn where m0 mutes self.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m0PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m0PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessGroupOwnerMutingSelf)
		}

		{
			// Create a txn where m0 unmutes self.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m0PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m0PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationUnmuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessGroupOwnerUnmutingSelf)
		}

		{
			// Create a txn where m1 mutes m2.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m2PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m2PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m1PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m1Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessGroupDoesntExist) // This should fail because m1 is not the group owner.
		}

		{
			// Create a txn where m2 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should be sent to the group as m2 is not muted.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m2PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m2PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m2Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m0 mutes m1, m2, and m3.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			muteList = append(muteList, &AccessGroupMember{
				m2PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m2PubKey),
			})
			muteList = append(muteList, &AccessGroupMember{
				m3PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m3PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m0 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should be sent to the group as m0 is the group owner.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m0PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m0PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m1 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should not be sent to the group as m1 is muted.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m1PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m1PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m1Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessMemberMuted)
		}

		{
			// Create a txn where m2 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should not be sent to the group as m2 is muted.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m2PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m2PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m2Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessMemberMuted)
		}

		{
			// Create a txn where m3 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should not be sent to the group as m3 is muted.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m3PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m3PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m3Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessMemberMuted)
		}

		{
			// Create a txn where m0 unmutes m1, m2, and m3.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			muteList = append(muteList, &AccessGroupMember{
				m2PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m2PubKey),
			})
			muteList = append(muteList, &AccessGroupMember{
				m3PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m3PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationUnmuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m1 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should be sent to the group as m1 is not muted.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m1PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m1PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m1Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m2 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should be sent to the group as m2 is not muted.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m2PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m2PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m2Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m3 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should be sent to the group as m3 is not muted.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m3PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m3PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m3Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m0 mutes m1.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m0 mutes m1 and m2.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			muteList = append(muteList, &AccessGroupMember{
				m2PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m2PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessMemberAlreadyMuted)
		}

		{
			// Create a txn where m0 unmutes m1 and m2.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			muteList = append(muteList, &AccessGroupMember{
				m2PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m2PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationUnmuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessMemberAlreadyUnmuted)
		}

		{
			// Create a txn where m0 unmutes m1.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationUnmuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}
	}

	if bc.blockTip().Height < bc.params.ForkHeights.DeSoAccessGroupsBlockHeight {
		{
			// Create a txn where m0 adds m0, m1, m2 and m3 as members of the group.
			// We can add any messaging keys as recipients, but we'll just add base keys for simplicity,
			// since it's not what we're testing here.
			// We're making a group chat with: (m0, m1, m2, m3).
			entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
				m0PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m0PubKey),
			})
			entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
				m2PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m2PubKey),
			})
			entry.DEPRECATED_AccessGroupMembers = append(entry.DEPRECATED_AccessGroupMembers, &AccessGroupMember{
				m3PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m3PubKey),
			})
			recipients := entry.DEPRECATED_AccessGroupMembers
			extraData := make(map[string][]byte)
			extraData = nil
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				recipients, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m0 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should be sent to the group as m0 is not muted.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m0PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m0PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m1 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should be sent to the group as m1 is not muted.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m1PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m1PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m1Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m0 mutes m1.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationMuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessMemberAlreadyExists) // Need to change this to reflect error of muting before block height. Should be RuleErrorMessagingMutingBeforeBlockHeight
		}

		{
			// Create a txn where m1 sends a message to the group.
			tstampNanos := uint64(time.Now().UnixNano())
			testMessage := []byte("This message should not be sent to the group as m1 is not muted.")
			encryptedMessage := encrypt(testMessage, entry.AccessPublicKey[:])
			msgEntry := MessageEntry{
				m1PublicKey,
				m0PublicKey,
				encryptedMessage,
				tstampNanos,
				false,
				MessagesVersion3,
				m1PublicKey,
				BaseGroupKeyName(),
				entry.AccessPublicKey,
				NewGroupKeyName(gangKey),
				nil,
			}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreatePrivateMessageTxn(
				msgEntry.SenderPublicKey[:], msgEntry.RecipientPublicKey[:], "", hex.EncodeToString(msgEntry.EncryptedText),
				msgEntry.SenderMessagingPublicKey[:], msgEntry.SenderMessagingGroupKeyName[:], msgEntry.RecipientMessagingPublicKey[:],
				msgEntry.RecipientMessagingGroupKeyName[:], tstampNanos, msgEntry.ExtraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m1Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, nil)
		}

		{
			// Create a txn where m0 unmutes m1.
			var muteList []*AccessGroupMember
			muteList = append(muteList, &AccessGroupMember{
				m1PublicKey,
				BaseGroupKeyName(),
				encrypt(privBytes, m1PubKey),
			})
			extraData := make(map[string][]byte)
			extraData[AccessGroupOperationType] = []byte{byte(AccessGroupOperationUnmuteMembers)}
			txn, totalInputMake, changeAmountMake, feesMake, err := bc.CreateMessagingKeyTxn(
				m0PubKey, entry.AccessPublicKey[:], gangKey, []byte{},
				muteList, extraData, 10, nil, []*DeSoOutput{})
			require.NoError(err)
			require.Equal(totalInputMake, changeAmountMake+feesMake)
			_signTxn(t, txn, m0Priv)
			txns = append(txns, txn)
			expectedErrors = append(expectedErrors, RuleErrorAccessMemberAlreadyExists) // Need to change this to reflect error of muting before block height. Should be RuleErrorMessagingMutingBeforeBlockHeight
		}
	}

	return txns, expectedErrors
}
