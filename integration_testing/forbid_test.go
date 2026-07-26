package integration_testing

import (
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"github.com/deso-protocol/go-deadlock"
	"github.com/stretchr/testify/require"
	"github.com/tyler-smith/go-bip39"
)

// These tests run two real nodes in one process with *different*
// FreezeEnforcementBlockHeight values, covering nodes that do and do not enforce the freeze
// rule side by side. They deliberately stay below
// RegtestForkHeights.ProofOfStake2ConsensusCutoverBlockHeight (300), so block production is PoW,
// which isolates the accept/reject mechanism from consensus. forbid_pos_test.go covers the same
// mixed network under Fast-HotStuff with a real three-validator set.

const (
	// freezeFeeRateNanosPerKB matches integration_testing's config.MinFeerate.
	freezeFeeRateNanosPerKB = uint64(1000)

	// freezeMinNetworkFeeNanosPerKB is carried on the UpdateGlobalParams txn that freezes a key.
	// UpdateGlobalParams refuses to leave the minimum network fee at zero once PoS global params
	// are live, and regtest activates those at height zero.
	freezeMinNetworkFeeNanosPerKB = int64(100)

	// regtestParamUpdaterSeed is the seed phrase behind
	// tBCKVERmG9nZpHTk2AVPqknWc1Mw9HHAnqrTpW1RnXpXMQ4PsQgnmV, which EnableRegtest puts in
	// ExtraRegtestParamUpdaterKeys. Mining to it gives the ParamUpdater a balance without any
	// extra setup.
	regtestParamUpdaterSeed = "verb find card ship another until version devote guilt strong lemon six"
)

//----------------------------------------------------------
// (Testing) Mixed-binary freeze helpers
//----------------------------------------------------------

// spawnFreezeRegtestNode creates (but does not start) a regtest node. seedPhrase backs the node's
// account key, its BLS voting key and its block producer key; isMiner additionally makes it mine
// PoW blocks to that same key.
//
// Tying all of a node's keys to one seed is what makes the regtest PoS bootstrap work: a mining
// node registers itself as a validator 15 blocks in, paying for the txn out of the block producer
// seed's balance, so that seed has to be the one collecting block rewards or the node panics.
func spawnFreezeRegtestNode(t *testing.T, port uint32, id string, seedPhrase string, isMiner bool) *cmd.Node {
	// go-deadlock keys its bookkeeping on the mutex pointer alone, so the PoW miner's write lock on
	// DeSoBlockProducer.mtxRecentBlockTemplatesProduced races with the server's read lock on the
	// same mutex and gets reported as recursive locking. That fires within a second of starting any
	// regtest miner, on unmodified HEAD as well, and aborts the process.
	prevDisable := deadlock.Opts.Disable
	deadlock.Opts.Disable = true
	t.Cleanup(func() { deadlock.Opts.Disable = prevDisable })

	node := spawnValidatorNodeProtocol2Testnet(t, port, id, seedPhrase)
	node.Config.MaxSyncBlockHeight = 0
	node.Config.Regtest = true
	node.Config.MinerPublicKeys = []string{}
	if isMiner {
		node.Config.MinerPublicKeys = []string{seedPhraseToPublicKeyBase58Check(t, seedPhrase, node.Params)}
	}
	// One thread is plenty at regtest difficulty, and it keeps the miner from racing several
	// candidate blocks per height.
	node.Config.NumMiningThreads = 1
	return node
}

// startFreezeNode starts a node whose freeze rule activates at freezeEnforcementBlockHeight. Pass
// math.MaxUint32 to simulate an un-upgraded binary.
//
// The height has to be injected through lib.RegtestForkHeights rather than set on node.Params
// directly, because EnableRegtest — which node.Start calls — overwrites params.ForkHeights
// wholesale from that variable. Doing it here also keeps the write off the hot path: by the time
// Start returns, the node has its own copy and nothing reads RegtestForkHeights again.
func startFreezeNode(t *testing.T, node *cmd.Node, freezeEnforcementBlockHeight uint32) *cmd.Node {
	prevHeight := lib.RegtestForkHeights.FreezeEnforcementBlockHeight
	lib.RegtestForkHeights.FreezeEnforcementBlockHeight = freezeEnforcementBlockHeight
	defer func() { lib.RegtestForkHeights.FreezeEnforcementBlockHeight = prevHeight }()

	node = startNode(t, node)
	require.Equal(t, freezeEnforcementBlockHeight, node.Params.ForkHeights.FreezeEnforcementBlockHeight)
	return node
}

// freezeKeyPairFromSeed derives the standard DeSo account key pair for a seed phrase.
func freezeKeyPairFromSeed(t *testing.T, seedPhrase string, params *lib.DeSoParams) (*btcec.PrivateKey, []byte) {
	seedBytes, err := bip39.NewSeedWithErrorChecking(seedPhrase, "")
	require.NoError(t, err)
	_, privKey, _, err := lib.ComputeKeysFromSeed(seedBytes, 0, params)
	require.NoError(t, err)
	return privKey, privKey.PubKey().SerializeCompressed()
}

// freezeSignAndSubmit signs txn and hands it to the node's mempool, returning the mempool's error
// verbatim so callers can assert on it.
func freezeSignAndSubmit(t *testing.T, node *cmd.Node, txn *lib.MsgDeSoTxn, privKey *btcec.PrivateKey) error {
	signature, err := txn.Sign(privKey)
	require.NoError(t, err)
	txn.Signature.SetSignature(signature)

	// Below the PoS cutover the node runs the legacy mempool, whose AddTransaction is a stub.
	mempool := node.Server.GetMempool()
	if legacyMempool, ok := mempool.(*lib.DeSoMempool); ok {
		_, err := legacyMempool.ProcessTransaction(
			txn, false /*allowUnconnectedTxn*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
		return err
	}
	return mempool.AddTransaction(txn, time.Now())
}

// freezeBasicTransferTxn builds an unsigned basic transfer, sized and priced against node's view.
func freezeBasicTransferTxn(
	t *testing.T, node *cmd.Node, fromPkBytes []byte, toPkBytes []byte, amountNanos uint64,
) *lib.MsgDeSoTxn {
	txn := &lib.MsgDeSoTxn{
		PublicKey: fromPkBytes,
		TxnMeta:   &lib.BasicTransferMetadata{},
		TxOutputs: []*lib.DeSoOutput{{PublicKey: toPkBytes, AmountNanos: amountNanos}},
	}
	_, _, _, _, err := node.Server.GetBlockchain().AddInputsAndChangeToTransaction(
		txn, freezeFeeRateNanosPerKB, node.Server.GetMempool())
	require.NoError(t, err)
	return txn
}

// freezeGlobalParamsTxn builds an unsigned UpdateGlobalParams txn that adds pubKeyToFreeze to the
// forbidden public key list.
func freezeGlobalParamsTxn(t *testing.T, node *cmd.Node, updaterPkBytes []byte, pubKeyToFreeze []byte) *lib.MsgDeSoTxn {
	txn, _, _, _, err := node.Server.GetBlockchain().CreateUpdateGlobalParamsTxn(
		updaterPkBytes,
		-1, /*usdCentsPerBitcoin*/
		-1, /*createProfileFeesNanos*/
		-1, /*createNFTFeesNanos*/
		-1, /*maxCopiesPerNFT*/
		freezeMinNetworkFeeNanosPerKB,
		pubKeyToFreeze,
		-1,  /*maxNonceExpirationBlockHeightOffset*/
		nil, /*extraData*/
		freezeFeeRateNanosPerKB,
		node.Server.GetMempool(),
		[]*lib.DeSoOutput{},
	)
	require.NoError(t, err)
	return txn
}

// freezeIsPubKeyForbidden reads the forbidden public key list straight out of the node's badger db,
// so it reflects committed state rather than a mempool view.
func freezeIsPubKeyForbidden(node *cmd.Node, pubKeyBytes []byte) bool {
	for _, forbiddenPk := range lib.DbGetAllForbiddenBlockSignaturePubKeys(node.ChainDB) {
		if lib.NewPublicKey(forbiddenPk).Equal(*lib.NewPublicKey(pubKeyBytes)) {
			return true
		}
	}
	return false
}

// waitForFreezeCondition is waitForCondition with a timeout long enough to cover a few regtest
// blocks (regtest TimeBetweenBlocks is 2s).
func waitForFreezeCondition(t *testing.T, id string, condition func() bool) {
	waitForFreezeConditionWithin(t, id, 60*time.Second, condition)
}

func waitForFreezeConditionWithin(t *testing.T, id string, timeout time.Duration, condition func() bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("waitForFreezeCondition: timed out after %v | %s", timeout, id)
}

//----------------------------------------------------------
// (Testing) Mixed-binary freeze tests
//----------------------------------------------------------

// TestFreezeSoftForkUnupgradedNodeFollowsUpgradedChain is the soft-fork direction: the upgraded
// node produces the chain, and the un-upgraded node — which does not know the freeze rule exists —
// still accepts every block of it, including the block carrying the freeze itself. This is the
// property that makes the rule a soft fork.
func TestFreezeSoftForkUnupgradedNodeFollowsUpgradedChain(t *testing.T) {
	require := require.New(t)

	// node1 is the upgraded miner. Regtest activates the freeze rule at height zero.
	node1 := spawnFreezeRegtestNode(t, 18000, "node1-upgraded-miner", regtestParamUpdaterSeed, true /*isMiner*/)
	node1 = startFreezeNode(t, node1, 0 /*freezeEnforcementBlockHeight*/)

	paramUpdaterPriv, paramUpdaterPk := freezeKeyPairFromSeed(t, regtestParamUpdaterSeed, node1.Params)
	require.True(node1.Params.ExtraRegtestParamUpdaterKeys[lib.MakePkMapKey(paramUpdaterPk)])

	// Let the miner build up a spendable balance. Regtest sets BlockRewardMaturity to zero.
	waitForFreezeCondition(t, "node1 mines", func() bool {
		return node1.Server.GetBlockchain().BlockTip().Height >= 5
	})

	// Fund the key we are about to freeze.
	frozenKeyPriv, frozenKeyPk := freezeKeyPairFromSeed(t, freezeRandomSeed(t), node1.Params)
	require.NoError(freezeSignAndSubmit(t, node1,
		freezeBasicTransferTxn(t, node1, paramUpdaterPk, frozenKeyPk, 1e9), paramUpdaterPriv))

	// node2 is the un-upgraded follower: same binary, but a freeze height it will never reach.
	node2 := spawnFreezeRegtestNode(t, 18001, "node2-unupgraded", freezeRandomSeed(t), false /*isMiner*/)
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node2 = startFreezeNode(t, node2, math.MaxUint32 /*freezeEnforcementBlockHeight*/)

	// Freeze the key on the upgraded chain.
	require.NoError(freezeSignAndSubmit(t, node1,
		freezeGlobalParamsTxn(t, node1, paramUpdaterPk, frozenKeyPk), paramUpdaterPriv))
	waitForFreezeCondition(t, "node1 commits the freeze", func() bool {
		return freezeIsPubKeyForbidden(node1, frozenKeyPk)
	})

	// The upgraded node now refuses the frozen key's transactions outright.
	err := freezeSignAndSubmit(t, node1,
		freezeBasicTransferTxn(t, node1, frozenKeyPk, paramUpdaterPk, 1e6), frozenKeyPriv)
	require.Error(err)
	require.Contains(err.Error(), lib.RuleErrorFrozenPublicKey)

	// The un-upgraded node follows the upgraded chain all the way to its tip, and applies the
	// freeze to its own state — the forbidden pub key list predates this change, so old binaries
	// already know how to store it. They simply never enforce it.
	targetHeight := node1.Server.GetBlockchain().BlockTip().Height
	waitForFreezeCondition(t, "node2 follows node1", func() bool {
		return node2.Server.GetBlockchain().BlockTip().Height >= targetHeight
	})
	require.True(freezeIsPubKeyForbidden(node2, frozenKeyPk))
	require.Equal(uint32(math.MaxUint32), node2.Params.ForkHeights.FreezeEnforcementBlockHeight)

	// And it still accepts what it is not upgraded to reject.
	require.NoError(freezeSignAndSubmit(t, node2,
		freezeBasicTransferTxn(t, node2, frozenKeyPk, paramUpdaterPk, 1e6), frozenKeyPriv))
}

// TestFreezeGriefingUnupgradedProducer is the griefing direction: an un-upgraded block producer
// includes a frozen transaction, and the upgraded node rejects the whole block. A producer that
// does not enforce the rule burns its slot.
//
// Under PoW this shows up as a permanent fork, which *overstates* the damage: on PoS the next
// leader simply proposes a valid block over the rejected one and the chain keeps finalizing. What
// this test establishes is the mechanism and which side rejects, not the stall duration.
func TestFreezeGriefingUnupgradedProducer(t *testing.T) {
	require := require.New(t)

	// node1 is the un-upgraded miner, so it will happily mine a frozen transaction.
	node1 := spawnFreezeRegtestNode(t, 18000, "node1-unupgraded-miner", regtestParamUpdaterSeed, true /*isMiner*/)
	node1 = startFreezeNode(t, node1, math.MaxUint32 /*freezeEnforcementBlockHeight*/)

	paramUpdaterPriv, paramUpdaterPk := freezeKeyPairFromSeed(t, regtestParamUpdaterSeed, node1.Params)

	waitForFreezeCondition(t, "node1 mines", func() bool {
		return node1.Server.GetBlockchain().BlockTip().Height >= 5
	})

	frozenKeyPriv, frozenKeyPk := freezeKeyPairFromSeed(t, freezeRandomSeed(t), node1.Params)
	require.NoError(freezeSignAndSubmit(t, node1,
		freezeBasicTransferTxn(t, node1, paramUpdaterPk, frozenKeyPk, 1e9), paramUpdaterPriv))

	// node2 is the upgraded observer.
	node2 := spawnFreezeRegtestNode(t, 18001, "node2-upgraded", freezeRandomSeed(t), false /*isMiner*/)
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node2 = startFreezeNode(t, node2, 0 /*freezeEnforcementBlockHeight*/)

	// Freeze the key. Both nodes store the entry; only node2 will act on it.
	require.NoError(freezeSignAndSubmit(t, node1,
		freezeGlobalParamsTxn(t, node1, paramUpdaterPk, frozenKeyPk), paramUpdaterPriv))
	waitForFreezeCondition(t, "both nodes commit the freeze", func() bool {
		return freezeIsPubKeyForbidden(node1, frozenKeyPk) && freezeIsPubKeyForbidden(node2, frozenKeyPk)
	})

	// Baseline: the upgraded node is keeping up with the producer.
	waitForFreezeCondition(t, "node2 tracks node1", func() bool {
		return node2.Server.GetBlockchain().BlockTip().Height+2 >=
			node1.Server.GetBlockchain().BlockTip().Height
	})

	// The un-upgraded producer accepts the frozen transaction into its mempool and mines it.
	require.NoError(freezeSignAndSubmit(t, node1,
		freezeBasicTransferTxn(t, node1, frozenKeyPk, paramUpdaterPk, 1e6), frozenKeyPriv))
	waitForFreezeCondition(t, "node1 mines past the offending block", func() bool {
		return node1.Server.GetBlockchain().BlockTip().Height >=
			node2.Server.GetBlockchain().BlockTip().Height+10
	})

	// The upgraded node rejects the offending block and every block built on it, so its tip stops
	// dead while the producer keeps going. Let the network settle first, then hold the upgraded
	// node's height still across five more blocks from the producer: that separates a real stall
	// from ordinary sync lag without depending on how fast regtest happens to be mining.
	time.Sleep(5 * time.Second)
	stalledHeight := node2.Server.GetBlockchain().BlockTip().Height
	producerHeightAtSample := node1.Server.GetBlockchain().BlockTip().Height
	waitForFreezeCondition(t, "the un-upgraded producer mines five more blocks", func() bool {
		return node1.Server.GetBlockchain().BlockTip().Height > producerHeightAtSample+5
	})

	require.Equal(stalledHeight, node2.Server.GetBlockchain().BlockTip().Height)
	require.Less(stalledHeight, node1.Server.GetBlockchain().BlockTip().Height)

	// The frozen key's balance never moved as far as the upgraded node is concerned.
	require.True(freezeIsPubKeyForbidden(node2, frozenKeyPk))
}

// freezeRandomSeed returns a fresh BIP39 mnemonic, so each test run freezes a key with no history.
func freezeRandomSeed(t *testing.T) string {
	seedPhrase, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	return seedPhrase
}
