package lib

import (
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// freezeMinNetworkFeeNanosPerKB is carried on every UpdateGlobalParams txn the freeze tests
// submit. UpdateGlobalParams refuses to leave the minimum network fee at zero once PoS global
// params are live, because that would make the fee time bucket ranges degenerate.
const freezeMinNetworkFeeNanosPerKB = int64(100)

//----------------------------------------------------------
// (Testing) Freeze enforcement helper functions
//----------------------------------------------------------

// _setUpMinerAndTestMetaForFreezeTests initializes a balance model chain with paramUpdaterPub as
// the only ParamUpdater, mines enough blocks for senderPkString to have a balance, and funds m0
// (the key the tests freeze), m1 (a bystander) and paramUpdaterPub.
func _setUpMinerAndTestMetaForFreezeTests(t *testing.T, freezeEnforcementBlockHeight uint32) *TestMeta {
	// Mainnet runs the balance model under PoS, so run these tests there too.
	setBalanceModelBlockHeights(t)
	setPoSBlockHeights(t, 11, 100)

	chain, params, db := NewLowDifficultyBlockchain(t)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Activate the freeze rule. This is deliberately set on the chain's own copy of the params
	// rather than on DeSoTestnetParams: the rule is only ever read through bav.Params, so there is
	// no reason to leak a fork height into the globals the rest of the package shares.
	params.ForkHeights.FreezeEnforcementBlockHeight = freezeEnforcementBlockHeight

	// paramUpdaterPub is the only key allowed to touch the forbidden public key list. Keeping it
	// distinct from the frozen key matters: a frozen ParamUpdater cannot unfreeze itself, which
	// TestFreezeParamUpdaterCannotUnfreezeItself asserts explicitly.
	params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(paramUpdaterPkBytes)] = true

	for ii := 0; ii < 10; ii++ {
		_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
		require.NoError(t, err)
	}

	testMeta := &TestMeta{
		t:                 t,
		chain:             chain,
		params:            params,
		db:                db,
		mempool:           mempool,
		miner:             miner,
		savedHeight:       chain.blockTip().Height + 1,
		feeRateNanosPerKb: uint64(101),
	}

	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m0Pub, senderPrivString, 1e9)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, m1Pub, senderPrivString, 1e9)
	_registerOrTransferWithTestMeta(testMeta, "", senderPkString, paramUpdaterPub, senderPrivString, 1e9)

	return testMeta
}

// _updateForbiddenPubKeyList submits an UpdateGlobalParams txn carrying a single forbidden public
// key ExtraData entry, connects it against a fresh view and flushes the result to the db. Pass
// ForbiddenBlockSignaturePubKeyKey to freeze and UnforbidBlockSignaturePubKeyKey to unfreeze.
func _updateForbiddenPubKeyList(
	testMeta *TestMeta,
	updaterPkBase58Check string,
	updaterPrivBase58Check string,
	extraDataKey string,
	pubKey []byte,
) error {
	_, _, _, err := _updateGlobalParamsEntryWithMempool(
		testMeta.t, testMeta.chain, testMeta.db, testMeta.params,
		testMeta.feeRateNanosPerKb,
		updaterPkBase58Check,
		updaterPrivBase58Check,
		-1, /*usdCentsPerBitcoin*/
		freezeMinNetworkFeeNanosPerKB,
		-1, /*createProfileFeeNanos*/
		-1, /*createNFTFeeNanos*/
		-1, /*maxCopiesPerNFT*/
		-1, /*maxNonceExpirationBlockHeightOffset*/
		map[string][]byte{extraDataKey: pubKey},
		true, /*flushToDb*/
		nil /*mempool*/)
	return err
}

// _tryBasicTransfer connects a basic transfer against a fresh view without flushing, and returns
// the connect error, if any.
func _tryBasicTransfer(testMeta *TestMeta, senderPk string, recipientPk string, senderPriv string) error {
	t, chain, db, params := testMeta.t, testMeta.chain, testMeta.db, testMeta.params

	txn := _assembleBasicTransferTxnFullySigned(
		t, chain, 100 /*amountNanos*/, testMeta.feeRateNanosPerKb, senderPk, recipientPk, senderPriv, nil)

	utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
	_, _, _, _, err := utxoView.ConnectTransaction(
		txn, txn.Hash(), chain.blockTip().Height+1, 0, true /*verifySignatures*/, false /*ignoreUtxos*/)
	return err
}

// _tryDerivedKeyTransfer connects a basic transfer whose transactor is ownerPkBytes but whose
// signature comes from a derived key, and returns the connect error, if any.
func _tryDerivedKeyTransfer(
	testMeta *TestMeta,
	ownerPkBytes []byte,
	recipientPkBytes []byte,
	derivedPrivBase58Check string,
) error {
	t, chain, db, params := testMeta.t, testMeta.chain, testMeta.db, testMeta.params

	txn := &MsgDeSoTxn{
		TxInputs:  []*DeSoInput{},
		TxOutputs: []*DeSoOutput{{PublicKey: recipientPkBytes, AmountNanos: 100}},
		PublicKey: ownerPkBytes,
		TxnMeta:   &BasicTransferMetadata{},
		ExtraData: make(map[string][]byte),
	}
	_, _, _, _, err := chain.AddInputsAndChangeToTransaction(txn, testMeta.feeRateNanosPerKb, nil)
	require.NoError(t, err)
	_signTxnWithDerivedKey(t, txn, derivedPrivBase58Check)

	utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
	_, _, _, _, err = utxoView.ConnectTransaction(
		txn, txn.Hash(), chain.blockTip().Height+1, 0, true /*verifySignatures*/, false /*ignoreUtxos*/)
	return err
}

// _isPubKeyForbidden reports whether the public key is forbidden according to a freshly
// constructed view, i.e. according to what is actually persisted in the db.
func _isPubKeyForbidden(testMeta *TestMeta, pubKey []byte) bool {
	utxoView := NewUtxoView(
		testMeta.db, testMeta.params, testMeta.chain.postgres, testMeta.chain.snapshot, testMeta.chain.eventManager)
	return utxoView.GetForbiddenPubKeyEntry(pubKey) != nil
}

//----------------------------------------------------------
// Tests
//----------------------------------------------------------

// TestFreezeBasicTransfer covers the core lifecycle: a key transacts freely, gets frozen, is
// rejected, and becomes spendable again once it is unfrozen.
func TestFreezeBasicTransfer(t *testing.T) {
	require := require.New(t)

	testMeta := _setUpMinerAndTestMetaForFreezeTests(t, 0 /*freezeEnforcementBlockHeight*/)

	// Before the freeze, m0 transacts normally and is not on the list.
	require.False(_isPubKeyForbidden(testMeta, m0PkBytes))
	require.NoError(_tryBasicTransfer(testMeta, m0Pub, m1Pub, m0Priv))

	// Freeze m0.
	require.NoError(_updateForbiddenPubKeyList(
		testMeta, paramUpdaterPub, paramUpdaterPriv, ForbiddenBlockSignaturePubKeyKey, m0PkBytes))

	// The entry has to be readable from the db, not just from the view that wrote it. This is the
	// path every subsequent transaction takes.
	require.True(_isPubKeyForbidden(testMeta, m0PkBytes))

	// m0 can no longer transact.
	err := _tryBasicTransfer(testMeta, m0Pub, m1Pub, m0Priv)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFrozenPublicKey)

	// Nobody else is affected, including when sending to the frozen key.
	require.NoError(_tryBasicTransfer(testMeta, m1Pub, m0Pub, m1Priv))

	// Unfreeze m0.
	require.NoError(_updateForbiddenPubKeyList(
		testMeta, paramUpdaterPub, paramUpdaterPriv, UnforbidBlockSignaturePubKeyKey, m0PkBytes))
	require.False(_isPubKeyForbidden(testMeta, m0PkBytes))

	// m0 is spendable again. This is the rollback path, so it has to work.
	require.NoError(_tryBasicTransfer(testMeta, m0Pub, m1Pub, m0Priv))
}

// TestFreezeDerivedKeySignedTxn covers derived-key-signed transactions. A derived-key-signed txn
// still carries the owner in txn.PublicKey, so freezing the owner has to stop it.
func TestFreezeDerivedKeySignedTxn(t *testing.T) {
	require := require.New(t)

	testMeta := _setUpMinerAndTestMetaForFreezeTests(t, 0 /*freezeEnforcementBlockHeight*/)
	chain, db, params := testMeta.chain, testMeta.db, testMeta.params

	// Authorize a derived key for m0.
	m0PrivBytes, _, err := Base58CheckDecode(m0Priv)
	require.NoError(err)
	m0PrivKey, _ := btcec.PrivKeyFromBytes(m0PrivBytes)

	transactionSpendingLimit := &TransactionSpendingLimit{
		GlobalDESOLimit: NanosPerUnit,
		TransactionCountLimitMap: map[TxnType]uint64{
			TxnTypeAuthorizeDerivedKey: 1,
			TxnTypeBasicTransfer:       10,
		},
		CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
		DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
		NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
	}

	blockHeight := uint64(chain.blockTip().Height) + 1
	authTxnMeta, derivedPriv := _getAuthorizeDerivedKeyMetadataWithTransactionSpendingLimit(
		t, m0PrivKey, 1e6 /*expirationBlock*/, transactionSpendingLimit, false /*isDeleted*/, blockHeight)
	derivedPrivBase58Check := Base58CheckEncode(derivedPriv.Serialize(), true, params)

	utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
	_, _, _, err = _doAuthorizeTxn(
		testMeta,
		utxoView,
		testMeta.feeRateNanosPerKb,
		m0PkBytes,
		authTxnMeta.DerivedPublicKey,
		derivedPrivBase58Check,
		authTxnMeta.ExpirationBlock,
		authTxnMeta.AccessSignature,
		false, /*deleteKey*/
		nil,   /*memo*/
		transactionSpendingLimit,
	)
	require.NoError(err)
	require.NoError(utxoView.FlushToDb(uint64(chain.blockTip().Height)))

	// Sanity check: the derived key can move m0's money right now.
	require.NoError(_tryDerivedKeyTransfer(testMeta, m0PkBytes, m1PkBytes, derivedPrivBase58Check))

	// Freeze the owner, not the derived key.
	require.NoError(_updateForbiddenPubKeyList(
		testMeta, paramUpdaterPub, paramUpdaterPriv, ForbiddenBlockSignaturePubKeyKey, m0PkBytes))

	// The derived key is now useless, because the txn it signs still declares m0 as transactor.
	err = _tryDerivedKeyTransfer(testMeta, m0PkBytes, m1PkBytes, derivedPrivBase58Check)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFrozenPublicKey)

	// The owner's own master key is stopped by the same rule.
	err = _tryBasicTransfer(testMeta, m0Pub, m1Pub, m0Priv)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFrozenPublicKey)
}

// TestFreezeAtomicTxnsWrapper checks the other way a transaction can reach consensus: wrapped
// inside an atomic txns wrapper. The wrapper itself has a zero transactor public key, so the rule
// has to bite on the inner transactions.
func TestFreezeAtomicTxnsWrapper(t *testing.T) {
	require := require.New(t)

	testMeta := _setUpMinerAndTestMetaForFreezeTests(t, 0 /*freezeEnforcementBlockHeight*/)
	chain, db, params := testMeta.chain, testMeta.db, testMeta.params

	buildWrapper := func() *MsgDeSoTxn {
		innerTxns, signerPrivKeys := _generateUnsignedDependentAtomicTransactions(testMeta, 3)
		// The inner transactions are max-value transfers, so a fee rate of zero here is load
		// bearing: it stops the wrapper from raising their fees above what they can afford.
		wrapper, _, err := testMeta.chain.CreateAtomicTxnsWrapper(innerTxns, nil, testMeta.mempool, 0)
		require.NoError(err)
		for ii := range innerTxns {
			_signTxn(t, wrapper.TxnMeta.(*AtomicTxnsWrapperMetadata).Txns[ii], signerPrivKeys[ii])
		}
		return wrapper
	}

	// The wrapper connects fine while m0 is unfrozen. m0 is the first inner transactor, courtesy
	// of _generateUnsignedDependentAtomicTransactions.
	_, err := _atomicTransactionsWrapperWithConnectTimestamp(t, chain, db, params, buildWrapper(), 0)
	require.NoError(err)

	// Freeze m0 by writing the entry straight to the db. The UpdateGlobalParams path is covered by
	// the other tests; using it here would also raise the minimum network fee, which these
	// max-value inner transfers cannot absorb.
	utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
	utxoView.ForbiddenPubKeyToForbiddenPubKeyEntry[MakePkMapKey(m0PkBytes)] =
		&ForbiddenPubKeyEntry{PubKey: m0PkBytes}
	require.NoError(utxoView.FlushToDb(uint64(chain.blockTip().Height)))
	require.True(_isPubKeyForbidden(testMeta, m0PkBytes))

	wrapper := buildWrapper()
	require.True(NewPublicKey(wrapper.PublicKey).IsZeroPublicKey())
	_, err = _atomicTransactionsWrapperWithConnectTimestamp(t, chain, db, params, wrapper, 0)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFrozenPublicKey)
}

// TestFreezeBelowForkHeight verifies that until the fork height is reached, a node running this
// code behaves exactly like one that does not have it.
func TestFreezeBelowForkHeight(t *testing.T) {
	require := require.New(t)

	testMeta := _setUpMinerAndTestMetaForFreezeTests(t, math.MaxUint32 /*freezeEnforcementBlockHeight*/)

	// The list can still be written to below the fork height -- that behaviour predates this
	// change.
	require.NoError(_updateForbiddenPubKeyList(
		testMeta, paramUpdaterPub, paramUpdaterPriv, ForbiddenBlockSignaturePubKeyKey, m0PkBytes))
	require.True(_isPubKeyForbidden(testMeta, m0PkBytes))

	// But it is not enforced, so m0 transacts as if nothing happened.
	require.NoError(_tryBasicTransfer(testMeta, m0Pub, m1Pub, m0Priv))

	// The unfreeze ExtraData key is also inert below the fork height: it is a new consensus rule,
	// so it must not take effect early. The entry is left exactly as it was.
	require.NoError(_updateForbiddenPubKeyList(
		testMeta, paramUpdaterPub, paramUpdaterPriv, UnforbidBlockSignaturePubKeyKey, m0PkBytes))
	require.True(_isPubKeyForbidden(testMeta, m0PkBytes))
}

// TestFreezeBlockRewardExempt confirms that freezing a validator's public key cannot stall block
// production, because block rewards are exempt from the rule.
func TestFreezeBlockRewardExempt(t *testing.T) {
	require := require.New(t)

	testMeta := _setUpMinerAndTestMetaForFreezeTests(t, 0 /*freezeEnforcementBlockHeight*/)

	// senderPkString is the miner, so freezing it points the rule directly at the block reward.
	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)
	require.NoError(_updateForbiddenPubKeyList(
		testMeta, paramUpdaterPub, paramUpdaterPriv, ForbiddenBlockSignaturePubKeyKey, senderPkBytes))

	// The frozen miner cannot spend...
	err = _tryBasicTransfer(testMeta, senderPkString, m1Pub, senderPrivString)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFrozenPublicKey)

	// ...but it can still mine, which is the property the exemption exists to preserve.
	_, err = testMeta.miner.MineAndProcessSingleBlock(0 /*threadIndex*/, testMeta.mempool)
	require.NoError(err)
}

// TestFreezeRequiresParamUpdater confirms the forbidden list stays under ParamUpdater governance
// and that a malformed public key is rejected.
func TestFreezeRequiresParamUpdater(t *testing.T) {
	require := require.New(t)

	testMeta := _setUpMinerAndTestMetaForFreezeTests(t, 0 /*freezeEnforcementBlockHeight*/)

	// A non-ParamUpdater cannot freeze anyone.
	err := _updateForbiddenPubKeyList(
		testMeta, m1Pub, m1Priv, ForbiddenBlockSignaturePubKeyKey, m0PkBytes)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorUserNotAuthorizedToUpdateGlobalParams)
	require.False(_isPubKeyForbidden(testMeta, m0PkBytes))

	// ...nor unfreeze anyone.
	require.NoError(_updateForbiddenPubKeyList(
		testMeta, paramUpdaterPub, paramUpdaterPriv, ForbiddenBlockSignaturePubKeyKey, m0PkBytes))
	err = _updateForbiddenPubKeyList(
		testMeta, m1Pub, m1Priv, UnforbidBlockSignaturePubKeyKey, m0PkBytes)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorUserNotAuthorizedToUpdateGlobalParams)
	require.True(_isPubKeyForbidden(testMeta, m0PkBytes))

	// A public key that isn't a compressed public key is rejected on both paths.
	err = _updateForbiddenPubKeyList(
		testMeta, paramUpdaterPub, paramUpdaterPriv, ForbiddenBlockSignaturePubKeyKey, m0PkBytes[:16])
	require.Error(err)
	require.Contains(err.Error(), RuleErrorForbiddenPubKeyLength)

	err = _updateForbiddenPubKeyList(
		testMeta, paramUpdaterPub, paramUpdaterPriv, UnforbidBlockSignaturePubKeyKey, m0PkBytes[:16])
	require.Error(err)
	require.Contains(err.Error(), RuleErrorForbiddenPubKeyLength)
}

// TestFreezeParamUpdaterCannotUnfreezeItself documents an operational footgun: the freeze applies
// to every txn type including UpdateGlobalParams, so a ParamUpdater that freezes itself locks
// itself out of the list it governs.
func TestFreezeParamUpdaterCannotUnfreezeItself(t *testing.T) {
	require := require.New(t)

	testMeta := _setUpMinerAndTestMetaForFreezeTests(t, 0 /*freezeEnforcementBlockHeight*/)

	require.NoError(_updateForbiddenPubKeyList(
		testMeta, paramUpdaterPub, paramUpdaterPriv, ForbiddenBlockSignaturePubKeyKey, paramUpdaterPkBytes))

	err := _updateForbiddenPubKeyList(
		testMeta, paramUpdaterPub, paramUpdaterPriv, UnforbidBlockSignaturePubKeyKey, paramUpdaterPkBytes)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFrozenPublicKey)
}

// TestFreezeMempoolRejection confirms a frozen key's transactions are turned away at mempool
// admission rather than only at block connect, so they never propagate.
func TestFreezeMempoolRejection(t *testing.T) {
	require := require.New(t)

	testMeta := _setUpMinerAndTestMetaForFreezeTests(t, 0 /*freezeEnforcementBlockHeight*/)

	require.NoError(_updateForbiddenPubKeyList(
		testMeta, paramUpdaterPub, paramUpdaterPriv, ForbiddenBlockSignaturePubKeyKey, m0PkBytes))

	txn := _assembleBasicTransferTxnFullySigned(
		t, testMeta.chain, 100, testMeta.feeRateNanosPerKb, m0Pub, m1Pub, m0Priv, nil)
	_, err := testMeta.mempool.processTransaction(
		txn, true /*allowOrphan*/, true /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFrozenPublicKey)

	// A bystander's transaction is still accepted.
	txn = _assembleBasicTransferTxnFullySigned(
		t, testMeta.chain, 100, testMeta.feeRateNanosPerKb, m1Pub, m0Pub, m1Priv, nil)
	txnsAdded, err := testMeta.mempool.processTransaction(
		txn, true /*allowOrphan*/, true /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
	require.NoError(err)
	require.Equal(1, len(txnsAdded))
}

// TestFreezeDisconnect covers reorg correctness. Before enforcement existed, disconnecting an
// UpdateGlobalParams txn that added a forbidden key left the entry in place. That is now a
// consensus bug: the freeze would survive a reorg that removed the txn which created it.
func TestFreezeDisconnect(t *testing.T) {
	require := require.New(t)

	testMeta := _setUpMinerAndTestMetaForFreezeTests(t, 0 /*freezeEnforcementBlockHeight*/)
	chain, db, params := testMeta.chain, testMeta.db, testMeta.params

	connectAndDisconnect := func(extraDataKey string, pubKey []byte) *UtxoView {
		utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)

		txn, _, _, _, err := chain.CreateUpdateGlobalParamsTxn(
			paramUpdaterPkBytes, -1, -1, -1, -1, freezeMinNetworkFeeNanosPerKB, nil, -1,
			map[string][]byte{extraDataKey: pubKey},
			testMeta.feeRateNanosPerKb, nil /*mempool*/, []*DeSoOutput{})
		require.NoError(err)
		_signTxn(t, txn, paramUpdaterPriv)

		blockHeight := chain.blockTip().Height + 1
		utxoOps, _, _, _, err := utxoView.ConnectTransaction(
			txn, txn.Hash(), blockHeight, 0, true /*verifySignatures*/, false /*ignoreUtxos*/)
		require.NoError(err)

		require.NoError(utxoView.DisconnectTransaction(txn, txn.Hash(), utxoOps, blockHeight))
		return utxoView
	}

	// Adding a key and then disconnecting must leave the key unfrozen, both on the view and, once
	// flushed, in the db.
	utxoView := connectAndDisconnect(ForbiddenBlockSignaturePubKeyKey, m0PkBytes)
	require.Nil(utxoView.GetForbiddenPubKeyEntry(m0PkBytes))
	require.NoError(utxoView.FlushToDb(uint64(chain.blockTip().Height)))
	require.False(_isPubKeyForbidden(testMeta, m0PkBytes))
	require.NoError(_tryBasicTransfer(testMeta, m0Pub, m1Pub, m0Priv))

	// Removing a key and then disconnecting must put it back.
	require.NoError(_updateForbiddenPubKeyList(
		testMeta, paramUpdaterPub, paramUpdaterPriv, ForbiddenBlockSignaturePubKeyKey, m0PkBytes))

	utxoView = connectAndDisconnect(UnforbidBlockSignaturePubKeyKey, m0PkBytes)
	require.NotNil(utxoView.GetForbiddenPubKeyEntry(m0PkBytes))
	require.NoError(utxoView.FlushToDb(uint64(chain.blockTip().Height)))
	require.True(_isPubKeyForbidden(testMeta, m0PkBytes))

	err := _tryBasicTransfer(testMeta, m0Pub, m1Pub, m0Priv)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFrozenPublicKey)
}

// TestFreezeUnrelatedGlobalParamsUpdate confirms that an UpdateGlobalParams txn which does not
// mention the forbidden list leaves the list alone -- both on connect and on disconnect.
func TestFreezeUnrelatedGlobalParamsUpdate(t *testing.T) {
	require := require.New(t)

	testMeta := _setUpMinerAndTestMetaForFreezeTests(t, 0 /*freezeEnforcementBlockHeight*/)
	chain, db, params := testMeta.chain, testMeta.db, testMeta.params

	require.NoError(_updateForbiddenPubKeyList(
		testMeta, paramUpdaterPub, paramUpdaterPriv, ForbiddenBlockSignaturePubKeyKey, m0PkBytes))

	utxoView := NewUtxoView(db, params, chain.postgres, chain.snapshot, chain.eventManager)
	txn, _, _, _, err := chain.CreateUpdateGlobalParamsTxn(
		paramUpdaterPkBytes, -1, -1, -1, -1, freezeMinNetworkFeeNanosPerKB+1, nil, -1,
		map[string][]byte{}, testMeta.feeRateNanosPerKb, nil /*mempool*/, []*DeSoOutput{})
	require.NoError(err)
	_signTxn(t, txn, paramUpdaterPriv)

	blockHeight := chain.blockTip().Height + 1
	utxoOps, _, _, _, err := utxoView.ConnectTransaction(
		txn, txn.Hash(), blockHeight, 0, true /*verifySignatures*/, false /*ignoreUtxos*/)
	require.NoError(err)
	require.NotNil(utxoView.GetForbiddenPubKeyEntry(m0PkBytes))

	require.NoError(utxoView.DisconnectTransaction(txn, txn.Hash(), utxoOps, blockHeight))
	require.NotNil(utxoView.GetForbiddenPubKeyEntry(m0PkBytes))

	require.NoError(utxoView.FlushToDb(uint64(chain.blockTip().Height)))
	require.True(_isPubKeyForbidden(testMeta, m0PkBytes))
}
