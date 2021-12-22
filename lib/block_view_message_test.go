package lib

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"reflect"
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

func TestMessagingKeys(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	_ = require
	_ = assert

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_ = miner

	// Mine two blocks to give the sender some DeSo.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	_generateMessagingKey := func(name []byte, signer []byte) (*btcec.PrivateKey, []byte, []byte) {
		signPriv, _ := btcec.PrivKeyFromBytes(btcec.S256(), signer)

		priv, _ := btcec.NewPrivateKey(btcec.S256())
		pub := priv.PubKey().SerializeCompressed()

		payload := append(pub, name...)
		signature, _ := signPriv.Sign(Sha256DoubleHash(payload)[:])
		return priv, pub, signature.Serialize()
	}

	// We create this inline function for attempting a basic transfer.
	// This helps us test that the DeSoChain recognizes a derived key.
	_basicTransfer := func(senderPk []byte, recipientPk []byte, signerPriv string, utxoView *UtxoView,
		mempool *DeSoMempool, extraData map[string][]byte) ([]*UtxoOperation, *MsgDeSoTxn, error) {

		txn := &MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs: []*DeSoInput{},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   recipientPk,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPk,
			TxnMeta:   &BasicTransferMetadata{},
			ExtraData: extraData,
		}

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, mempool)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		_signTxn(t, txn, signerPriv)

		// Get utxoView if it doesn't exist
		if mempool != nil {
			utxoView, err = mempool.GetAugmentedUniversalView()
			require.NoError(err)
		}
		if utxoView == nil {
			utxoView, err = NewUtxoView(db, params, nil)
			require.NoError(err)
		}

		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		utxoOps, _, _, _, err :=
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
				true /*verifySignature*/, false /*ignoreUtxos*/)
		return utxoOps, txn, err
	}

	_verifyMessagingKey := func(utxoView *UtxoView, mempool *DeSoMempool, entry *MessagingKeyEntry) bool {
		var utxoMessagingEntry *MessagingKeyEntry

		messagingKey := NewMessagingKey(entry.PublicKey, entry.MessagingKeyName[:])
		if utxoView == nil {
			utxoView, err := mempool.GetAugmentedUniversalView()
			if err != nil {
				fmt.Println("_verifyMessagingKey: Error fetching augmented universal view")
				return false
			}
			utxoMessagingEntry = utxoView._getMessagingKeyToMessagingKeyEntryMapping(messagingKey)
		} else {
			utxoMessagingEntry = utxoView._getMessagingKeyToMessagingKeyEntryMapping(messagingKey)
		}

		if utxoMessagingEntry == nil || utxoMessagingEntry.isDeleted {
			return false
		}

		return reflect.DeepEqual(*entry.MessagingPublicKey, *utxoMessagingEntry.MessagingPublicKey) &&
			reflect.DeepEqual(*entry.MessagingKeyName, *utxoMessagingEntry.MessagingKeyName) &&
			reflect.DeepEqual(*entry.PublicKey, *utxoMessagingEntry.PublicKey)
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

	// Test #1: Check that entry is correctly set in UtxoView and flushed to DB
	{
		extraData := make(map[string][]byte)
		keyName := []byte("default-key")
		priv, pub, sign := _generateMessagingKey(keyName, senderPrivBytes)
		_ = priv

		extraData[MessagingPublicKey] = pub
		extraData[MessagingKeyName] = keyName
		extraData[MessagingKeySignature] = sign

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes, senderPrivString, utxoView,
			nil, extraData)

		desiredMessagingKeyEntry := MessagingKeyEntry{
			PublicKey:          NewPublicKey(senderPkBytes),
			MessagingPublicKey: NewPublicKey(pub),
			MessagingKeyName:   NewKeyName(keyName),
		}
		require.Equal(_verifyMessagingKey(utxoView, nil, &desiredMessagingKeyEntry), true)

		err = utxoView.FlushToDb()
		require.NoError(err)
		require.Equal(_verifyMessagingKey(utxoView, nil, &desiredMessagingKeyEntry), true)
		fmt.Println("PASSED Test #1: Check that entry is correctly set in UtxoView and flushed to DB")
	}

	// Test #2: Check if messaging key is correctly disconnected.
	{
		extraData := make(map[string][]byte)
		keyName := []byte("default-key2")
		priv, pub, sign := _generateMessagingKey(keyName, senderPrivBytes)
		_ = priv

		extraData[MessagingPublicKey] = pub
		extraData[MessagingKeyName] = keyName
		extraData[MessagingKeySignature] = sign

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes, senderPrivString, utxoView,
			nil, extraData)
		require.NoError(err)

		desiredMessagingKeyEntry := MessagingKeyEntry{
			PublicKey:          NewPublicKey(senderPkBytes),
			MessagingPublicKey: NewPublicKey(pub),
			MessagingKeyName:   NewKeyName(keyName),
		}
		require.Equal(_verifyMessagingKey(utxoView, nil, &desiredMessagingKeyEntry), true)

		require.NoError(utxoView.DisconnectTransaction(txn, txn.Hash(), utxoOps, chain.blockTip().Height+1))
		require.Equal(_verifyMessagingKey(utxoView, nil, &desiredMessagingKeyEntry), false)
		fmt.Println("PASSED Test #2: Check if messaging key is correctly disconnected.")
	}

	// Test #3: Add messaging key in a mempool transaction and then remove it
	// Test #4: Add messaging key in a block and then disconnect block.
	{
		extraData := make(map[string][]byte)
		keyName := []byte("default-key3")
		priv, pub, sign := _generateMessagingKey(keyName, senderPrivBytes)
		_ = priv

		extraData[MessagingPublicKey] = pub
		extraData[MessagingKeyName] = keyName
		extraData[MessagingKeySignature] = sign

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes, senderPrivString, utxoView,
			nil, extraData)
		require.NoError(err)

		mempoolTxn, err := mempool.processTransaction(txn, true, true, 0, true)
		require.NoError(err)
		require.Equal(1, len(mempoolTxn))

		desiredMessagingKeyEntry := MessagingKeyEntry{
			PublicKey:          NewPublicKey(senderPkBytes),
			MessagingPublicKey: NewPublicKey(pub),
			MessagingKeyName:   NewKeyName(keyName),
		}
		require.Equal(_verifyMessagingKey(nil, mempool, &desiredMessagingKeyEntry), true)

		mempool.inefficientRemoveTransaction(txn)
		require.Equal(_verifyMessagingKey(nil, mempool, &desiredMessagingKeyEntry), false)
		fmt.Println("PASSED Test #3: Add messaging key in a mempool transaction and then remove it")

		// Test #4
		mempoolTxn, err = mempool.processTransaction(txn, true, true, 0, true)
		require.NoError(err)
		require.Equal(1, len(mempoolTxn))
		addedBlock, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)

		// Verify the record was persisted in the DB
		utxoView, err = NewUtxoView(db, params, nil)
		require.Equal(_verifyMessagingKey(utxoView, nil, &desiredMessagingKeyEntry), true)
		_ = addedBlock

		// Disconnect block
		hash, err := addedBlock.Header.Hash()
		require.NoError(err)
		utxoOps, err := GetUtxoOperationsForBlock(db, hash)
		require.NoError(err)
		// Compute the hashes for all the transactions.
		txHashes, err := ComputeTransactionHashes(addedBlock.Txns)
		require.NoError(err)
		err = utxoView.DisconnectBlock(addedBlock, txHashes, utxoOps)
		require.NoError(err)
		require.Equal(_verifyMessagingKey(utxoView, nil, &desiredMessagingKeyEntry), false)
		err = utxoView.FlushToDb()
		require.NoError(err)
		fmt.Println("PASSED Test #4: Add messaging key in a block and then disconnect block.")
	}

	// Test #5: Make sure user can't have more than one public key assigned to the same key name.
	// If the contrary was the case, we could make past messages un-decryptable (or rather hard to decrypt).
	{
		extraData := make(map[string][]byte)
		keyName := []byte("default-key4")
		priv, pub, sign := _generateMessagingKey(keyName, senderPrivBytes)
		_ = priv

		extraData[MessagingPublicKey] = pub
		extraData[MessagingKeyName] = keyName
		extraData[MessagingKeySignature] = sign

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes, senderPrivString, utxoView,
			nil, extraData)
		require.NoError(err)
		_, err = mempool.processTransaction(txn, true, true, 0, true)
		require.NoError(err)

		desiredMessagingKeyEntry1 := MessagingKeyEntry{
			PublicKey:          NewPublicKey(senderPkBytes),
			MessagingPublicKey: NewPublicKey(pub),
			MessagingKeyName:   NewKeyName(keyName),
		}
		require.Equal(_verifyMessagingKey(utxoView, nil, &desiredMessagingKeyEntry1), true)

		// Now let's try adding another public key for the same key name and make sure it silently fails.
		priv2, pub2, sign2 := _generateMessagingKey(keyName, senderPrivBytes)
		_ = priv2

		extraData = make(map[string][]byte)
		extraData[MessagingPublicKey] = pub2
		extraData[MessagingKeyName] = keyName
		extraData[MessagingKeySignature] = sign2

		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes, senderPrivString, nil,
			mempool, extraData)
		require.NoError(err)
		// If we failed, then the previous messaging key entry should remain valid.
		desiredMessagingKeyEntry2 := MessagingKeyEntry{
			PublicKey:          NewPublicKey(senderPkBytes),
			MessagingPublicKey: NewPublicKey(pub2),
			MessagingKeyName:   NewKeyName(keyName),
		}
		require.Equal(_verifyMessagingKey(utxoView, nil, &desiredMessagingKeyEntry1), true)
		require.Equal(_verifyMessagingKey(utxoView, nil, &desiredMessagingKeyEntry2), false)
		fmt.Println("PASSED Test #5: Make sure user can't have more than one public key assigned to the same key name.")
	}
}

func TestMessageParty(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	_ = require
	_ = assert

	// In these tests we basically want to verify that MessageParty records are correctly added to UtxoView and DB
	// after we send V3 messages.

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_ = miner

	// Mine two blocks to give the sender some DeSo.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	_generateMessagingKey := func(name []byte, signer []byte) (*btcec.PrivateKey, []byte, []byte) {
		signPriv, _ := btcec.PrivKeyFromBytes(btcec.S256(), signer)

		priv, _ := btcec.NewPrivateKey(btcec.S256())
		pub := priv.PubKey().SerializeCompressed()

		payload := append(pub, name...)
		signature, _ := signPriv.Sign(Sha256DoubleHash(payload)[:])
		return priv, pub, signature.Serialize()
	}

	_helpConnectPrivateMessage := func(senderPkBytes []byte, senderPrivBase58 string, recipientPkBytes,
		senderMessagingPublicKey, senderMessagingKeyName, recipientMessagingPublicKey,
		recipientMessagingKeyName []byte, encryptedMessageText string, tstampNanos uint64,
		utxoView *UtxoView) ([]*UtxoOperation, *MsgDeSoTxn, error) {

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

	_verifyExistsMessageEntryAndParty := func(utxoView *UtxoView, senderPk []byte, tstampNanos uint64) bool {
		messageKey := MakeMessageKey(senderPk, tstampNanos)
		messageEntry := utxoView._getMessageEntryForMessageKey(&messageKey)
		messageParty := utxoView._getMessageKeyToMessageParty(&messageKey)
		if messageEntry != nil && !messageEntry.isDeleted {
			if messageParty != nil && !messageParty.isDeleted {
				return reflect.DeepEqual((*messageParty.SenderPublicKey)[:], messageEntry.SenderPublicKey) &&
					reflect.DeepEqual((*messageParty.RecipientPublicKey)[:], messageEntry.RecipientPublicKey)
			} else {
				return false
			}
		} else {
			if messageParty != nil && !messageParty.isDeleted {
				return false
			}
		}
		return true
	}

	_verifyMessageParty := func(utxoView *UtxoView, senderPk []byte, tstampNanos uint64,
		senderMsgPk, recipientMsgPk []byte, senderMsgKeyName, recipientMsgKeyName KeyName) bool {
		messageKey := MakeMessageKey(senderPk, tstampNanos)
		messageParty := utxoView._getMessageKeyToMessageParty(&messageKey)
		return reflect.DeepEqual(senderMsgPk, (*messageParty.SenderMessagingPublicKey)[:]) &&
			reflect.DeepEqual(recipientMsgPk, (*messageParty.RecipientMessagingPublicKey)[:]) &&
			reflect.DeepEqual(senderMsgKeyName[:], (*messageParty.SenderMessagingKeyName)[:]) &&
			reflect.DeepEqual(recipientMsgKeyName[:], (*messageParty.RecipientMessagingKeyName)[:])
	}

	// This helps us test that the DeSoChain recognizes a derived key.
	_basicTransfer := func(senderPk []byte, recipientPk []byte, signerPriv string, utxoView *UtxoView,
		mempool *DeSoMempool, extraData map[string][]byte) ([]*UtxoOperation, *MsgDeSoTxn, error) {

		txn := &MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs: []*DeSoInput{},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   recipientPk,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPk,
			TxnMeta:   &BasicTransferMetadata{},
			ExtraData: extraData,
		}

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, mempool)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		_signTxn(t, txn, signerPriv)

		// Get utxoView if it doesn't exist
		if mempool != nil {
			utxoView, err = mempool.GetAugmentedUniversalView()
			require.NoError(err)
		}
		if utxoView == nil {
			utxoView, err = NewUtxoView(db, params, nil)
			require.NoError(err)
		}

		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		utxoOps, _, _, _, err :=
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
				true /*verifySignature*/, false /*ignoreUtxos*/)
		return utxoOps, txn, err
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

	// Test #1: Attempt sending a V3 private message without a previously authorized messaging key.
	{
		//extraData := make(map[string][]byte)
		keyName := []byte("default-key")
		priv, pub, _ := _generateMessagingKey(keyName, senderPrivBytes)
		_ = priv

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		tstampNanos := uint64(time.Now().UnixNano())

		testMessage1 := hex.EncodeToString([]byte{1, 2, 3, 4, 5, 6})
		_, _, err = _helpConnectPrivateMessage(senderPkBytes, senderPrivString,
			recipientPkBytes, pub, keyName, []byte{}, []byte{}, testMessage1, tstampNanos, utxoView)
		assert.NoError(err)
		require.Equal(_verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos), false)
		fmt.Println("PASSED Test #1: Attempt sending a V3 private message without a previously authorized messaging key.")
	}

	// Test #2: Attempt sending a V3 private message with an authorized messaging key.
	// Test #3: Attempt disconnecting a valid V3 private message.
	{
		extraData := make(map[string][]byte)
		keyName := []byte("default-key")
		priv, pub, sign := _generateMessagingKey(keyName, senderPrivBytes)
		_ = priv

		extraData[MessagingPublicKey] = pub
		extraData[MessagingKeyName] = keyName
		extraData[MessagingKeySignature] = sign

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		// Add the messaging key to the utxoView
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes, senderPrivString, utxoView,
			nil, extraData)
		require.NoError(utxoView.FlushToDb())
		utxoView, err = NewUtxoView(db, params, nil)
		tstampNanos := uint64(time.Now().UnixNano())
		testMessage1 := hex.EncodeToString([]byte{1, 2, 3, 4, 5, 6})
		_, _, err = _helpConnectPrivateMessage(senderPkBytes, senderPrivString,
			recipientPkBytes, pub, keyName, []byte{}, []byte{}, testMessage1, tstampNanos, utxoView)
		assert.NoError(err)
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos))
		require.Equal(true, _verifyMessageParty(utxoView, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))
		fmt.Println("PASSED Test #2: Attempt sending a V3 private message with an authorized messaging key.")

		require.NoError(utxoView.FlushToDb())
		require.Equal(true, _verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos))
		require.Equal(true, _verifyMessageParty(utxoView, senderPkBytes, tstampNanos, pub, recipientPkBytes,
			*NewKeyName(keyName), *NewKeyName([]byte{})))
		fmt.Println("Successfully flushed to DB")
		//require.NoError(utxoView.DisconnectTransaction(txn, txn.Hash(), utxoOps, chain.blockTip().Height+1))
		//require.NoError(utxoView.FlushToDb())
		//require.Equal(true, _verifyExistsMessageEntryAndParty(utxoView, senderPkBytes, tstampNanos))
		//require.Equal(true, _verifyMessageParty(utxoView, senderPkBytes, tstampNanos, pub, recipientPkBytes,
		//	*NewKeyName(keyName), *NewKeyName([]byte{})))
		//fmt.Println("PASSED Test #3: Attempt disconnecting a valid V3 private message.")

	}
}
