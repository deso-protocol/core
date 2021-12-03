package block_view

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/core/lib"
	"github.com/deso-protocol/core/network"
	"github.com/deso-protocol/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAuthorizeDerivedKeyBasic(t *testing.T) {
	types.NFTTransferOrBurnAndDerivedKeysBlockHeight = uint32(0)

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := lib.NewLowDifficultyBlockchain()
	mempool, miner := lib.NewTestMiner(t, chain, params, true /*isSender*/)

	// Mine two blocks to give the sender some DeSo.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	senderPkBytes, _, err := types.Base58CheckDecode(lib.senderPkString)
	require.NoError(err)
	senderPrivBytes, _, err := types.Base58CheckDecode(lib.senderPrivString)
	require.NoError(err)
	recipientPkBytes, _, err := types.Base58CheckDecode(lib.recipientPkString)
	require.NoError(err)

	// Get AuthorizeDerivedKey txn metadata with expiration at block 6
	senderPriv, _ := btcec.PrivKeyFromBytes(btcec.S256(), senderPrivBytes)
	authTxnMeta, derivedPriv := _getAuthorizeDerivedKeyMetadata(t, senderPriv, params, 6, false)
	derivedPrivBase58Check := types.Base58CheckEncode(derivedPriv.Serialize(), true, params)
	derivedPkBytes := derivedPriv.PubKey().SerializeCompressed()
	fmt.Println("Derived public key:", hex.EncodeToString(derivedPkBytes))

	// We create this inline function for attempting a basic transfer.
	// This helps us test that the DeSoChain recognizes a derived key.
	_basicTransfer := func(senderPk []byte, recipientPk []byte, signerPriv string, utxoView *UtxoView,
		mempool *lib.DeSoMempool, isSignerSender bool) ([]*UtxoOperation, *network.MsgDeSoTxn, error) {

		txn := &network.MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs: []*network.DeSoInput{},
			TxOutputs: []*network.DeSoOutput{
				{
					PublicKey:   recipientPk,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPk,
			TxnMeta:   &network.BasicTransferMetadata{},
			ExtraData: make(map[string][]byte),
		}

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, mempool)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		if isSignerSender {
			// Sign the transaction with the provided derived key
			lib._signTxn(t, txn, signerPriv)
		} else {
			// Sign the transaction with the provided derived key
			lib._signTxnWithDerivedKey(t, txn, signerPriv)
		}

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

	// Verify that the balance and expiration block in the db match expectation.
	_verifyTest := func(derivedPublicKey []byte, expirationBlockExpected uint64,
		balanceExpected uint64, operationTypeExpected network.AuthorizeDerivedKeyOperationType, mempool *lib.DeSoMempool) {
		// Verify that expiration block was persisted in the db or is in mempool utxoView
		if mempool == nil {
			derivedKeyEntry := db.DBGetOwnerToDerivedKeyMapping(db, *types.NewPublicKey(senderPkBytes), *types.NewPublicKey(derivedPublicKey))
			// If we removed the derivedKeyEntry from utxoView altogether, it'll be nil.
			// To pass the tests, we initialize it to a default struct.
			if derivedKeyEntry == nil {
				derivedKeyEntry = &DerivedKeyEntry{*types.NewPublicKey(senderPkBytes), *types.NewPublicKey(derivedPublicKey), 0, network.AuthorizeDerivedKeyOperationValid, false}
			}
			assert.Equal(derivedKeyEntry.ExpirationBlock, expirationBlockExpected)
			assert.Equal(derivedKeyEntry.OperationType, operationTypeExpected)
		} else {
			utxoView, err := mempool.GetAugmentedUniversalView()
			require.NoError(err)
			derivedKeyEntry := utxoView._getDerivedKeyMappingForOwner(senderPkBytes, derivedPublicKey)
			// If we removed the derivedKeyEntry from utxoView altogether, it'll be nil.
			// To pass the tests, we initialize it to a default struct.
			if derivedKeyEntry == nil {
				derivedKeyEntry = &DerivedKeyEntry{*types.NewPublicKey(senderPkBytes), *types.NewPublicKey(derivedPublicKey), 0, network.AuthorizeDerivedKeyOperationValid, false}
			}
			assert.Equal(derivedKeyEntry.ExpirationBlock, expirationBlockExpected)
			assert.Equal(derivedKeyEntry.OperationType, operationTypeExpected)
		}

		// Verify that the balance of recipient is equal to expected balance
		assert.Equal(lib._getBalance(t, chain, mempool, lib.recipientPkString), balanceExpected)
	}

	// We will use these to keep track of added utxo ops and txns
	testUtxoOps := [][]*UtxoOperation{}
	testTxns := []*network.MsgDeSoTxn{}

	// Just for the sake of consistency, we run the _basicTransfer on unauthorized
	// derived key. It should fail since blockchain hasn't seen this key yet.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), types.RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key")
	}
	// Attempt sending an AuthorizeDerivedKey txn signed with an invalid private key.
	// This must fail because the txn has to be signed either by owner or derived key.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := types.Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMeta.DerivedPublicKey,
			randomPrivBase58Check,
			authTxnMeta.ExpirationBlock,
			authTxnMeta.AccessSignature,
			false)
		require.Contains(err.Error(), types.RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn signed with an unauthorized private key.")
	}
	// Attempt sending an AuthorizeDerivedKey txn where access signature is signed with
	// an invalid private key. This must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		expirationBlockByte := network.UintToBuf(authTxnMeta.ExpirationBlock)
		accessBytes := append(authTxnMeta.DerivedPublicKey, expirationBlockByte[:]...)
		accessSignatureRandom, err := randomPrivateKey.Sign(types.Sha256DoubleHash(accessBytes)[:])
		require.NoError(err)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMeta.DerivedPublicKey,
			derivedPrivBase58Check,
			authTxnMeta.ExpirationBlock,
			accessSignatureRandom.Serialize(),
			false)
		require.Error(err)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn signed with an invalid access signature.")
	}
	// Check basic transfer signed with still unauthorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), types.RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key")
	}
	// Now attempt to send the same transaction but signed with the correct derived key.
	// This must pass. The new derived key will be flushed to the db here.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, _, err := _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMeta.DerivedPublicKey,
			derivedPrivBase58Check,
			authTxnMeta.ExpirationBlock,
			authTxnMeta.AccessSignature,
			false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())

		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// Verify that expiration block was persisted in the db
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 0, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed connecting AuthorizeDerivedKey txn signed with an authorized private key. Flushed to Db.")
	}
	// Check basic transfer signed by the owner key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			lib.senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 1, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with owner key. Flushed to Db.")
	}
	// Check basic transfer signed with now authorized derived key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with authorized derived key. Flushed to Db.")
	}
	// Check basic transfer signed with a random key.
	// Should fail. Well... theoretically, it could pass in a distant future.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := types.Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), types.RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Fail basic transfer signed with random key.")
	}
	// Try disconnecting all transactions so that key is deauthorized.
	// Should succeed.
	{
		for iterIndex := range testTxns {
			testIndex := len(testTxns) - 1 - iterIndex
			currentTxn := testTxns[testIndex]
			currentUtxoOps := testUtxoOps[testIndex]
			fmt.Println("currentTxn.String()", currentTxn.String())

			// Disconnect the transaction
			utxoView, err := NewUtxoView(db, params, nil)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(), "SimpleDisconnect: Index: %v", testIndex)
		}

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txns. Flushed to Db.")
	}
	// After disconnecting, check basic transfer signed with unauthorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), types.RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed basic transfer signed with unauthorized derived key after disconnecting")
	}
	// Connect all txns to a single UtxoView flushing only at the end.
	{
		// Create a new UtxoView
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		for testIndex, txn := range testTxns {
			fmt.Printf("Applying test index: %v\n", testIndex)
			blockHeight := chain.blockTip().Height + 1
			txnSize := getTxnSize(*txn)
			_, _, _, _, err :=
				utxoView.ConnectTransaction(
					txn, txn.Hash(), txnSize, blockHeight, true /*verifySignature*/, false /*ignoreUtxos*/)
			require.NoError(err)
		}

		// Now flush at the end.
		require.NoError(utxoView.FlushToDb())

		// Verify that expiration block and balance was persisted in the db
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed re-connecting all txn to a single utxoView")
	}
	// Check basic transfer signed with a random key.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := types.Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), types.RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Fail basic transfer signed with random key.")
	}
	// Disconnect all txns on a single UtxoView flushing only at the end
	{
		// Create a new UtxoView
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		for iterIndex := range testTxns {
			testIndex := len(testTxns) - 1 - iterIndex
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			txn := testTxns[testIndex]
			require.NoError(utxoView.DisconnectTransaction(
				txn, txn.Hash(), testUtxoOps[testIndex], blockHeight))
		}

		// Now flush at the end.
		require.NoError(utxoView.FlushToDb())

		// Verify that expiration block and balance was persisted in the db
		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txn on a single utxoView")
	}
	// Connect transactions to a single mempool, should pass.
	{
		for ii, currentTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				currentTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "mempool index %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}

		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, network.AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool")
	}
	// Check basic transfer signed with a random key, when passing mempool.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := types.Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, nil, mempool, false)
		require.Contains(err.Error(), types.RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, network.AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Fail basic transfer signed with random key with mempool.")
	}
	// Remove all the transactions from the mempool. Should pass.
	{
		for _, burnTxn := range testTxns {
			mempool.inefficientRemoveTransaction(burnTxn)
		}
		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, network.AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed removing all txn from the mempool.")
	}
	// After disconnecting, check basic transfer signed with unauthorized derived key.
	// Should fail.
	{
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, nil, mempool, false)
		require.Contains(err.Error(), types.RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, network.AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Failed basic transfer signed with unauthorized derived key after disconnecting")
	}
	// Re-connect transactions to a single mempool, should pass.
	{
		for ii, currentTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				currentTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "mempool index %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}

		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, network.AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool.")
	}
	// We will be adding some blocks so we define an array to keep track of them.
	testBlocks := []*network.MsgDeSoBlock{}
	// Mine a block with all the mempool transactions.
	{
		// All the txns should be in the mempool already so mining a block should put
		// all those transactions in it.
		addedBlock, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		testBlocks = append(testBlocks, addedBlock)
	}
	// Reset testUtxoOps and testTxns so we can test more transactions
	testUtxoOps = [][]*UtxoOperation{}
	testTxns = []*network.MsgDeSoTxn{}
	// Check basic transfer signed by the owner key.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			lib.senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		fmt.Println("Passed basic transfer signed with owner key. Flushed to Db.")
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 3, network.AuthorizeDerivedKeyOperationValid, nil)
	}
	// Check basic transfer signed with authorized derived key. Now the auth txn is persisted in the db.
	// Should succeed. Flush to db.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 4, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with authorized derived key. Flushed to Db.")
	}
	// Check basic transfer signed with a random key.
	// Should fail.
	{
		// Generate a random key pair
		randomPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		randomPrivBase58Check := types.Base58CheckEncode(randomPrivateKey.Serialize(), true, params)
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			randomPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), types.RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 4, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Fail basic transfer signed with random key.")
	}
	// Try disconnecting all transactions. Should succeed.
	{
		for iterIndex := range testTxns {
			testIndex := len(testTxns) - 1 - iterIndex
			currentTxn := testTxns[testIndex]
			currentUtxoOps := testUtxoOps[testIndex]
			fmt.Println("currentTxn.String()", currentTxn.String())

			// Disconnect the transaction
			utxoView, err := NewUtxoView(db, params, nil)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(), "SimpleDisconnect: Index: %v", testIndex)
		}

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txns. Flushed to Db.")
	}
	// Mine a few more blocks so that the authorization should expire
	{
		for i := uint64(chain.blockTip().Height); i < authTxnMeta.ExpirationBlock; i++ {
			addedBlock, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
			require.NoError(err)
			testBlocks = append(testBlocks, addedBlock)
		}
		fmt.Println("Added a few more blocks.")
	}
	// Check basic transfer signed by the owner key.
	// Should succeed.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			lib.senderPrivString, utxoView, nil, true)
		require.NoError(err)

		// We're not persisting in the db so balance should remain at 2.
		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with owner key.")
	}
	// Check basic transfer signed with expired authorized derived key.
	// Should fail.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), types.RuleErrorDerivedKeyNotAuthorized)

		_verifyTest(authTxnMeta.DerivedPublicKey, authTxnMeta.ExpirationBlock, 2, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Failed a txn signed with an expired derived key.")
	}

	// Reset testUtxoOps and testTxns so we can test more transactions
	testUtxoOps = [][]*UtxoOperation{}
	testTxns = []*network.MsgDeSoTxn{}
	// Get another AuthorizeDerivedKey txn metadata with expiration at block 10
	// We will try to de-authorize this key with a txn before it expires.
	authTxnMetaDeAuth, derivedDeAuthPriv := _getAuthorizeDerivedKeyMetadata(t, senderPriv, params, 10, false)
	derivedPrivDeAuthBase58Check := types.Base58CheckEncode(derivedDeAuthPriv.Serialize(), true, params)
	derivedDeAuthPkBytes := derivedDeAuthPriv.PubKey().SerializeCompressed()
	fmt.Println("Derived public key:", hex.EncodeToString(derivedDeAuthPkBytes))
	// Send an authorize transaction signed with the correct derived key.
	// This must pass.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, _, err := _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			authTxnMetaDeAuth.ExpirationBlock,
			authTxnMetaDeAuth.AccessSignature,
			false)
		require.NoError(err)
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// Verify that expiration block was persisted in the db
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, 0, 2, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed connecting AuthorizeDerivedKey txn signed with an authorized private key.")
	}
	// Re-connect transactions to a single mempool, should pass.
	{
		for ii, currentTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				currentTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "mempool index %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}

		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 2, network.AuthorizeDerivedKeyOperationValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool.")
	}
	// Mine a block so that mempool gets flushed to db
	{
		addedBlock, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		testBlocks = append(testBlocks, addedBlock)
		fmt.Println("Added a block.")
	}
	// Reset testUtxoOps and testTxns so we can test more transactions
	testUtxoOps = [][]*UtxoOperation{}
	testTxns = []*network.MsgDeSoTxn{}
	// Check basic transfer signed with new authorized derived key.
	// Sanity check. Should pass. We're not flushing to the db yet.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// We're persisting to the db so balance should change to 3.
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed basic transfer signed with derived key.")
	}
	// Send a de-authorize transaction signed with a derived key.
	// Doesn't matter if it's signed by the owner or not, once a isDeleted
	// txn appears, the key should be forever expired. This must pass.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, _, err := _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			10,
			authTxnMetaDeAuth.AccessSignature,
			true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)
		// Verify the expiration block in the db
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, network.AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed connecting AuthorizeDerivedKey txn with isDeleted signed with an authorized private key.")
	}
	// Check basic transfer signed with new authorized derived key.
	// Now that key has been de-authorized this must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), types.RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 3, network.AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed basic transfer signed with de-authorized derived key.")
	}
	// Sanity check basic transfer signed by the owner key.
	// Should succeed.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		utxoOps, txn, err := _basicTransfer(senderPkBytes, recipientPkBytes,
			lib.senderPrivString, utxoView, nil, true)
		require.NoError(err)
		require.NoError(utxoView.FlushToDb())
		testUtxoOps = append(testUtxoOps, utxoOps)
		testTxns = append(testTxns, txn)

		// Balance should change to 4
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, network.AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed basic transfer signed with owner key.")
	}
	// Send an authorize transaction signed with a derived key.
	// Since we've already deleted this derived key, this must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			10,
			authTxnMetaDeAuth.AccessSignature,
			false)
		require.Contains(err.Error(), types.RuleErrorAuthorizeDerivedKeyDeletedDerivedPublicKey)

		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, network.AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn with de-authorized private key.")
	}
	// Try disconnecting all transactions. Should succeed.
	{
		for iterIndex := range testTxns {
			testIndex := len(testTxns) - 1 - iterIndex
			currentTxn := testTxns[testIndex]
			currentUtxoOps := testUtxoOps[testIndex]
			fmt.Println("currentTxn.String()", currentTxn.String())

			// Disconnect the transaction
			utxoView, err := NewUtxoView(db, params, nil)
			require.NoError(err)
			blockHeight := chain.blockTip().Height + 1
			fmt.Printf("Disconnecting test index: %v\n", testIndex)
			require.NoError(utxoView.DisconnectTransaction(
				currentTxn, currentTxn.Hash(), currentUtxoOps, blockHeight))
			fmt.Printf("Disconnected test index: %v\n", testIndex)

			require.NoErrorf(utxoView.FlushToDb(), "SimpleDisconnect: Index: %v", testIndex)
		}

		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 2, network.AuthorizeDerivedKeyOperationValid, nil)
		fmt.Println("Passed disconnecting all txns. Flushed to Db.")
	}
	// Connect transactions to a single mempool, should pass.
	{
		for ii, currentTxn := range testTxns {
			mempoolTxsAdded, err := mempool.processTransaction(
				currentTxn, true /*allowUnconnectedTxn*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoErrorf(err, "mempool index %v", ii)
			require.Equal(1, len(mempoolTxsAdded))
		}

		// This will check the expiration block and balances according to the mempool augmented utxoView.
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, network.AuthorizeDerivedKeyOperationNotValid, mempool)
		fmt.Println("Passed connecting all txn to the mempool")
	}
	// Check adding basic transfer to mempool signed with new authorized derived key.
	// Now that key has been de-authorized this must fail.
	{
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, nil, mempool, false)
		require.Contains(err.Error(), types.RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, network.AuthorizeDerivedKeyOperationNotValid, mempool)
		fmt.Println("Failed basic transfer signed with de-authorized derived key in mempool.")
	}
	// Attempt re-authorizing a previously de-authorized derived key.
	// Since we've already deleted this derived key, this must fail.
	{
		utxoView, err := mempool.GetAugmentedUniversalView()
		require.NoError(err)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			10,
			authTxnMetaDeAuth.AccessSignature,
			false)
		require.Contains(err.Error(), types.RuleErrorAuthorizeDerivedKeyDeletedDerivedPublicKey)

		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, network.AuthorizeDerivedKeyOperationNotValid, mempool)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn with de-authorized private key.")
	}
	// Mine a block so that mempool gets flushed to db
	{
		addedBlock, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(err)
		testBlocks = append(testBlocks, addedBlock)
		fmt.Println("Added a block.")
	}
	// Check adding basic transfer signed with new authorized derived key.
	// Now that key has been de-authorized this must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			derivedPrivDeAuthBase58Check, utxoView, nil, false)
		require.Contains(err.Error(), types.RuleErrorDerivedKeyNotAuthorized)

		// Since this should fail, balance wouldn't change.
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, network.AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed basic transfer signed with de-authorized derived key.")
	}
	// Attempt re-authorizing a previously de-authorized derived key.
	// Since we've already deleted this derived key, this must fail.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, _, err = _doAuthorizeTxn(
			t,
			chain,
			db,
			params,
			utxoView,
			10,
			senderPkBytes,
			authTxnMetaDeAuth.DerivedPublicKey,
			derivedPrivDeAuthBase58Check,
			10,
			authTxnMetaDeAuth.AccessSignature,
			false)
		require.Contains(err.Error(), types.RuleErrorAuthorizeDerivedKeyDeletedDerivedPublicKey)

		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, network.AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Failed connecting AuthorizeDerivedKey txn with de-authorized private key.")
	}
	// Sanity check basic transfer signed by the owner key.
	// Should succeed.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, err = _basicTransfer(senderPkBytes, recipientPkBytes,
			lib.senderPrivString, utxoView, nil, true)
		require.NoError(err)

		// Balance should change to 4
		_verifyTest(authTxnMetaDeAuth.DerivedPublicKey, authTxnMetaDeAuth.ExpirationBlock, 4, network.AuthorizeDerivedKeyOperationNotValid, nil)
		fmt.Println("Passed basic transfer signed with owner key.")
	}
	// Roll back the blocks and make sure we don't hit any errors.
	disconnectSingleBlock := func(blockToDisconnect *network.MsgDeSoBlock, utxoView *UtxoView) {
		// Fetch the utxo operations for the block we're detaching. We need these
		// in order to be able to detach the block.
		hash, err := blockToDisconnect.Header.Hash()
		require.NoError(err)
		utxoOps, err := db.GetUtxoOperationsForBlock(db, hash)
		require.NoError(err)

		// Compute the hashes for all the transactions.
		txHashes, err := lib.ComputeTransactionHashes(blockToDisconnect.Txns)
		require.NoError(err)
		require.NoError(utxoView.DisconnectBlock(blockToDisconnect, txHashes, utxoOps))
	}
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		for iterIndex := range testBlocks {
			testIndex := len(testBlocks) - 1 - iterIndex
			testBlock := testBlocks[testIndex]
			disconnectSingleBlock(testBlock, utxoView)
		}

		// Flushing the view after applying and rolling back should work.
		require.NoError(utxoView.FlushToDb())
		fmt.Println("Successfully rolled back the blocks.")
	}

	// After we rolled back the blocks, db should reset
	_verifyTest(authTxnMeta.DerivedPublicKey, 0, 0, network.AuthorizeDerivedKeyOperationValid, nil)
	fmt.Println("Successfuly run TestAuthorizeDerivedKeyBasic()")
}
