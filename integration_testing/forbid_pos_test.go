package integration_testing

import (
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"github.com/deso-protocol/uint256"
	"github.com/stretchr/testify/require"
)

// This file is the Proof-of-Stake counterpart to forbid_test.go. It stands up three real nodes in
// one process, registers all three as validators with stake, lets Fast-HotStuff take over from PoW,
// and only then freezes a public key. Two of the three nodes enforce the freeze rule; the third
// runs with FreezeEnforcementBlockHeight set to math.MaxUint32 and so never enforces it.
//
// The stake split puts the upgraded nodes above the two-thirds needed to build a QC and leaves the
// un-upgraded node with enough stake to draw leader slots of its own, so the test exercises both
// sides of the rule: upgraded nodes must reject the frozen transaction, and the chain must
// keep finalizing anyway while the un-upgraded leader keeps proposing it.

const (
	// freezePosCutoverHeight is where accelerated regtest hands over from PoW to Fast-HotStuff.
	// EnableRegtest(true) hardcodes it.
	freezePosCutoverHeight = uint32(30)

	// Stake, in nanos, for each validator. node1's is fixed by the regtest auto-registration path
	// in pos_server_regtest.go; the other two are ours to choose. Upgraded stake is
	// (10 + 200) / (10 + 200 + 60) = 77.8%, comfortably over the two-thirds a QC needs, while the
	// un-upgraded node still holds 22.2% and so leads roughly one view in five.
	freezePosNode1StakeNanos = uint64(10 * 1e6)
	freezePosNode2StakeNanos = uint64(200 * 1e6)
	freezePosNode3StakeNanos = uint64(60 * 1e6)
)

//----------------------------------------------------------
// (Testing) PoS freeze helpers
//----------------------------------------------------------

// spawnFreezePosNode is spawnFreezeRegtestNode in accelerated regtest, which moves the PoS cutover
// down from block 300 to block 30 and drops the block production interval to 100ms.
func spawnFreezePosNode(t *testing.T, port uint32, id string, seedPhrase string, isMiner bool) *cmd.Node {
	node := spawnFreezeRegtestNode(t, port, id, seedPhrase, isMiner)
	node.Config.RegtestAccelerated = true
	return node
}

// freezePosRegisterValidator registers seedPhrase's account as a validator at domain and stakes
// stakeNanos to it. Both transactions are submitted through submitNode, which relays them to the
// rest of the network; the account itself must already be funded.
//
// The voting key is derived from the same seed phrase the node was spawned with, so the node
// recognizes itself in the validator set the moment the registration commits.
func freezePosRegisterValidator(
	t *testing.T, submitNode *cmd.Node, seedPhrase string, domain string, stakeNanos uint64,
) {
	privKey, pkBytes := freezeKeyPairFromSeed(t, seedPhrase, submitNode.Params)

	keystore, err := lib.NewBLSKeystore(seedPhrase)
	require.NoError(t, err)
	votingAuthorization, err := keystore.GetSigner().Sign(lib.CreateValidatorVotingAuthorizationPayload(pkBytes))
	require.NoError(t, err)

	registerTxn, _, _, _, err := submitNode.Server.GetBlockchain().CreateRegisterAsValidatorTxn(
		pkBytes,
		&lib.RegisterAsValidatorMetadata{
			Domains:                             [][]byte{[]byte(domain)},
			DelegatedStakeCommissionBasisPoints: 100,
			VotingPublicKey:                     keystore.GetSigner().GetPublicKey(),
			VotingAuthorization:                 votingAuthorization,
		},
		make(map[string][]byte),
		freezeFeeRateNanosPerKB,
		submitNode.Server.GetMempool(),
		[]*lib.DeSoOutput{},
	)
	require.NoError(t, err)
	require.NoError(t, freezePosSignAndSubmit(t, submitNode, registerTxn, privKey))

	stakeTxn, _, _, _, err := submitNode.Server.GetBlockchain().CreateStakeTxn(
		pkBytes,
		&lib.StakeMetadata{
			ValidatorPublicKey: lib.NewPublicKey(pkBytes),
			RewardMethod:       lib.StakingRewardMethodPayToBalance,
			StakeAmountNanos:   uint256.NewInt(stakeNanos),
		},
		make(map[string][]byte),
		freezeFeeRateNanosPerKB,
		submitNode.Server.GetMempool(),
		[]*lib.DeSoOutput{},
	)
	require.NoError(t, err)
	require.NoError(t, freezePosSignAndSubmit(t, submitNode, stakeTxn, privKey))
}

// freezePosSignAndSubmit signs txn, submits it to node, and blocks until the node has decided
// whether it is valid. Unlike the PoW mempool, the PoS mempool validates asynchronously:
// AddTransaction only runs sanity checks, and the connect error that a freeze produces surfaces
// later, out of the validation routine. VerifyAndBroadcastTransaction is the path that waits for
// that verdict and hands back the rule error, so it is what a real submitter would see.
func freezePosSignAndSubmit(
	t *testing.T, node *cmd.Node, txn *lib.MsgDeSoTxn, privKey *btcec.PrivateKey,
) error {
	signature, err := txn.Sign(privKey)
	require.NoError(t, err)
	txn.Signature.SetSignature(signature)

	// WaitForTxnValidation loops without a deadline of its own, so bound it here rather than let a
	// regression hang the whole package until the go test timeout.
	result := make(chan error, 1)
	go func() { result <- node.Server.VerifyAndBroadcastTransaction(txn) }()
	select {
	case err := <-result:
		return err
	case <-time.After(30 * time.Second):
		t.Fatalf("freezePosSignAndSubmit: timed out waiting on %s to validate txn", node.Params.UserAgent)
		return nil
	}
}

// freezePosBalanceNanos reads a public key's balance out of the node's committed tip view, so it
// only reflects finalized blocks.
func freezePosBalanceNanos(t *testing.T, node *cmd.Node, pkBytes []byte) uint64 {
	balanceNanos, err := node.Server.GetBlockchain().GetCommittedTipView().GetDeSoBalanceNanosForPublicKey(pkBytes)
	require.NoError(t, err)
	return balanceNanos
}

// freezePosSnapshotValidators returns the validator set Fast-HotStuff is currently running with,
// which lags registration by a couple of epochs.
func freezePosSnapshotValidators(t *testing.T, node *cmd.Node) []*lib.ValidatorEntry {
	validatorEntries, err := node.Server.GetBlockchain().GetCommittedTipView().GetAllSnapshotValidatorSetEntriesByStake()
	require.NoError(t, err)
	return validatorEntries
}

// freezePosCountProposals counts how many committed blocks in [fromHeight, toHeight] were proposed
// by each of the given voting public keys, keyed by index into votingPublicKeys.
func freezePosCountProposals(
	t *testing.T, node *cmd.Node, votingPublicKeys []*bls.PublicKey, fromHeight uint64, toHeight uint64,
) []int {
	counts := make([]int, len(votingPublicKeys))
	for height := fromHeight; height <= toHeight; height++ {
		blockNode, isInBestChain, err := node.Server.GetBlockchain().GetBlockFromBestChainByHeight(height, false)
		require.NoError(t, err)
		if !isInBestChain || blockNode.Header.ProposerVotingPublicKey == nil {
			continue
		}
		for ii, votingPublicKey := range votingPublicKeys {
			if blockNode.Header.ProposerVotingPublicKey.Eq(votingPublicKey) {
				counts[ii]++
			}
		}
	}
	return counts
}

// freezePosCountProposalsSince returns how many blocks votingPublicKey proposed at heights at or
// above fromHeight, as node's block index sees them, and how many of those node marked
// validate-failed. It reads the block index rather than the best chain so that blocks node threw
// out are still visible — which is the whole point, since a refused proposal never joins a chain.
func freezePosCountProposalsSince(
	t *testing.T, node *cmd.Node, votingPublicKey *bls.PublicKey, fromHeight uint64,
) (_proposed int, _rejected int, _toHeight uint64) {
	var proposed, rejected int
	toHeight := uint64(node.Server.GetBlockchain().BlockTip().Height)
	for height := fromHeight; height <= toHeight; height++ {
		for _, blockNode := range node.Server.GetBlockchain().GetBlockIndex().GetBlockNodesByHeight(height) {
			if blockNode.Header.ProposerVotingPublicKey == nil ||
				!blockNode.Header.ProposerVotingPublicKey.Eq(votingPublicKey) {
				continue
			}
			proposed++
			if blockNode.IsValidateFailed() {
				rejected++
			}
		}
	}
	return proposed, rejected, toHeight
}

// freezePosKeepTxnInMempool re-adds txn to node's mempool whenever it disappears, and returns a
// function that stops doing so.
//
// A validator drops a transaction from its mempool as soon as it connects a block carrying it,
// including a block it proposed itself — which it does before the rest of the network gets a chance
// to reject that block. Without this, an un-upgraded validator griefs for a slot or two and then
// quietly stops, which would make the griefing measurement a race rather than a property.
func freezePosKeepTxnInMempool(node *cmd.Node, txn *lib.MsgDeSoTxn) (_stop func()) {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				if node.Server.GetMempool().GetTransaction(txn.Hash()) == nil {
					// The node is un-upgraded, so this only fails on a shutdown race, which the
					// caller's own assertions will catch.
					_ = node.Server.GetMempool().AddTransaction(txn, time.Now())
				}
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

// freezePosVotingPublicKey derives the BLS voting public key a node spawned with seedPhrase uses.
func freezePosVotingPublicKey(t *testing.T, seedPhrase string) *bls.PublicKey {
	keystore, err := lib.NewBLSKeystore(seedPhrase)
	require.NoError(t, err)
	return keystore.GetSigner().GetPublicKey()
}

//----------------------------------------------------------
// (Testing) PoS freeze test
//----------------------------------------------------------

// TestFreezePoSTwoOfThreeValidatorsUpgraded runs a freeze through a live Fast-HotStuff network in
// which one of the three validators has not been upgraded, and asserts two properties:
//
//  1. Safety. The upgraded validators refuse the frozen key's transaction, and because they hold
//     more than two thirds of the stake, no block containing it can ever gather a QC. The frozen
//     key's balance never moves, on any node, including the un-upgraded one.
//
//  2. Liveness. The un-upgraded validator accepts the frozen transaction into its mempool and
//     proposes it every time it leads, burning those slots. The chain finalizes straight through
//     that, so the freeze does not stall the network.
func TestFreezePoSTwoOfThreeValidatorsUpgraded(t *testing.T) {
	require := require.New(t)

	// node1 mines the PoW prefix and auto-registers itself as the bootstrap validator at height 15,
	// which is what gives Fast-HotStuff a validator set to start from at the cutover. It has to use
	// the ParamUpdater seed so that the same key holds the regtest seed balance we fund everyone
	// else from.
	node1Seed := regtestParamUpdaterSeed
	node2Seed := freezeRandomSeed(t)
	node3Seed := freezeRandomSeed(t)

	node1 := spawnFreezePosNode(t, 18000, "node1-upgraded-miner", node1Seed, true /*isMiner*/)
	node1 = startFreezeNode(t, node1, 0 /*freezeEnforcementBlockHeight*/)

	node2 := spawnFreezePosNode(t, 18001, "node2-upgraded", node2Seed, false /*isMiner*/)
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node2 = startFreezeNode(t, node2, 0 /*freezeEnforcementBlockHeight*/)

	// node3 is the un-upgraded validator: same binary, a freeze height it will never reach.
	node3 := spawnFreezePosNode(t, 18002, "node3-unupgraded", node3Seed, false /*isMiner*/)
	node3.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node3 = startFreezeNode(t, node3, math.MaxUint32 /*freezeEnforcementBlockHeight*/)

	allNodes := []*cmd.Node{node1, node2, node3}
	require.Equal(freezePosCutoverHeight, node1.Params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight)
	require.Equal(uint32(math.MaxUint32), node3.Params.ForkHeights.FreezeEnforcementBlockHeight)

	// Wait for every node to be past the cutover, i.e. running Fast-HotStuff rather than PoW.
	waitForFreezeConditionWithin(t, "all nodes cross the PoS cutover", 180*time.Second, func() bool {
		for _, node := range allNodes {
			if uint64(node.Server.GetBlockchain().BlockTip().Height) <= uint64(freezePosCutoverHeight)+2 {
				return false
			}
		}
		return true
	})

	// Fund node2's and node3's accounts so they can pay for their own registrations and stake, and
	// fund a third key to freeze.
	paramUpdaterPriv, paramUpdaterPk := freezeKeyPairFromSeed(t, node1Seed, node1.Params)
	_, node2Pk := freezeKeyPairFromSeed(t, node2Seed, node1.Params)
	_, node3Pk := freezeKeyPairFromSeed(t, node3Seed, node1.Params)
	frozenKeySeed := freezeRandomSeed(t)
	frozenKeyPriv, frozenKeyPk := freezeKeyPairFromSeed(t, frozenKeySeed, node1.Params)

	for _, recipientPk := range [][]byte{node2Pk, node3Pk, frozenKeyPk} {
		require.NoError(freezePosSignAndSubmit(t, node1,
			freezeBasicTransferTxn(t, node1, paramUpdaterPk, recipientPk, 1e10), paramUpdaterPriv))
	}

	freezePosRegisterValidator(t, node1, node2Seed, "127.0.0.1:18001", freezePosNode2StakeNanos)
	freezePosRegisterValidator(t, node1, node3Seed, "127.0.0.1:18002", freezePosNode3StakeNanos)

	// Registrations only take effect a couple of epochs later, once they make it into the snapshot
	// validator set Fast-HotStuff actually votes with.
	waitForFreezeConditionWithin(t, "all three validators enter the snapshot validator set",
		120*time.Second, func() bool {
			return len(freezePosSnapshotValidators(t, node1)) == 3
		})

	node2VotingPk := freezePosVotingPublicKey(t, node2Seed)
	node3VotingPk := freezePosVotingPublicKey(t, node3Seed)

	// Confirm the stake really is split the way the test intends: the upgraded nodes above two
	// thirds, and the un-upgraded node holding a large enough minority to draw leader slots.
	var totalStakeNanos, upgradedStakeNanos, node3StakeNanos uint64
	for _, validatorEntry := range freezePosSnapshotValidators(t, node1) {
		stakeNanos := validatorEntry.TotalStakeAmountNanos.Uint64()
		totalStakeNanos += stakeNanos
		if validatorEntry.VotingPublicKey.Eq(node3VotingPk) {
			node3StakeNanos = stakeNanos
		} else {
			upgradedStakeNanos += stakeNanos
		}
	}
	require.Equal(freezePosNode3StakeNanos, node3StakeNanos)
	require.Equal(freezePosNode1StakeNanos+freezePosNode2StakeNanos+freezePosNode3StakeNanos, totalStakeNanos)
	require.Greater(upgradedStakeNanos*3, totalStakeNanos*2, "upgraded stake must exceed two thirds")

	// Establish that the un-upgraded validator is a real participant before we freeze anything:
	// it has to be winning leader slots, or the griefing half of this test proves nothing.
	proposalWindowStart := uint64(node1.Server.GetBlockchain().BlockTip().Height) + 1
	waitForFreezeConditionWithin(t, "node3 proposes a committed block", 120*time.Second, func() bool {
		committedTip, isCommitted := node1.Server.GetBlockchain().GetCommittedTip()
		if !isCommitted || uint64(committedTip.Height) < proposalWindowStart {
			return false
		}
		counts := freezePosCountProposals(t, node1,
			[]*bls.PublicKey{node2VotingPk, node3VotingPk}, proposalWindowStart, uint64(committedTip.Height))
		return counts[1] > 0
	})

	// Freeze the key. This is an ordinary UpdateGlobalParams txn signed by the ParamUpdater; it
	// has to travel through Fast-HotStuff and be finalized by a validator set that is only 77.8%
	// upgraded.
	require.NoError(freezePosSignAndSubmit(t, node1,
		freezeGlobalParamsTxn(t, node1, paramUpdaterPk, frozenKeyPk), paramUpdaterPriv))
	waitForFreezeCondition(t, "every node commits the freeze", func() bool {
		for _, node := range allNodes {
			if !freezeIsPubKeyForbidden(node, frozenKeyPk) {
				return false
			}
		}
		return true
	})

	// The upgraded validators reject the frozen key's transaction outright.
	frozenKeyTxn := freezeBasicTransferTxn(t, node1, frozenKeyPk, paramUpdaterPk, 1e6)
	frozenKeyBalanceBefore := freezePosBalanceNanos(t, node1, frozenKeyPk)
	for _, upgradedNode := range []*cmd.Node{node1, node2} {
		err := freezePosSignAndSubmit(t, upgradedNode, frozenKeyTxn, frozenKeyPriv)
		require.Error(err, "%s should have rejected the frozen key's txn", upgradedNode.Params.UserAgent)
		require.Contains(err.Error(), lib.RuleErrorFrozenPublicKey)
	}

	// The un-upgraded validator accepts the very same transaction, because it does not know the
	// rule exists. From here on it will propose that transaction in every block it leads.
	require.NoError(freezePosSignAndSubmit(t, node3, frozenKeyTxn, frozenKeyPriv))

	// Let the network run until the un-upgraded validator has actually drawn leader slots and had
	// its proposals thrown out. How often it leads swings a lot from run to run, so waiting on the
	// event rather than sleeping a fixed stretch and hoping is what keeps this from being a coin
	// flip.
	griefingWindowStart := uint64(node1.Server.GetBlockchain().BlockTip().Height) + 1
	tipsBefore := make([]uint32, len(allNodes))
	for ii, node := range allNodes {
		tipsBefore[ii] = node.Server.GetBlockchain().BlockTip().Height
	}
	stopGriefing := freezePosKeepTxnInMempool(node3, frozenKeyTxn)
	waitForFreezeConditionWithin(t, "the upgraded majority refuses the un-upgraded validator's proposals",
		180*time.Second, func() bool {
			_, rejected, _ := freezePosCountProposalsSince(t, node1, node3VotingPk, griefingWindowStart)
			return rejected >= 2
		})
	stopGriefing()

	// Liveness: every node, including the un-upgraded one, kept finalizing blocks.
	for ii, node := range allNodes {
		require.Greater(node.Server.GetBlockchain().BlockTip().Height, tipsBefore[ii],
			"%s stalled", node.Params.UserAgent)
	}

	// Safety: the frozen transaction never landed anywhere, so the frozen key's balance is untouched on
	// every node — the un-upgraded one included, because it follows the chain the upgraded majority
	// finalizes even though it would have accepted the transaction itself.
	for _, node := range allNodes {
		require.Equal(frozenKeyBalanceBefore, freezePosBalanceNanos(t, node, frozenKeyPk),
			"%s let the frozen key spend", node.Params.UserAgent)
		require.True(freezeIsPubKeyForbidden(node, frozenKeyPk))
	}

	// Griefing, measured on the upgraded node's own block index rather than inferred: every block
	// the un-upgraded validator proposed carrying the frozen transaction is marked validate-failed
	// and can never join the best chain, so that leader slot is burned.
	//
	// Not every one of its proposals is burned, and the test does not require that. The mempool
	// drops the transaction each time the node connects a block, so a slot it leads in the gap
	// before the re-add loop puts it back yields a perfectly good block. An un-upgraded validator
	// wastes some of its slots, not all of them, and the chain pays in views rather than in safety.
	node3Proposed, node3Rejected, griefingWindowEnd :=
		freezePosCountProposalsSince(t, node1, node3VotingPk, griefingWindowStart)
	t.Logf("un-upgraded validator proposed %d blocks over heights %d-%d; the upgraded majority "+
		"refused %d of them", node3Proposed, griefingWindowStart, griefingWindowEnd, node3Rejected)
	require.Greater(node3Rejected, 0,
		"the upgraded majority should have refused at least one un-upgraded proposal")

	// And it kept building the chain the whole time it was doing so.
	griefingCounts := freezePosCountProposals(t, node1,
		[]*bls.PublicKey{node2VotingPk, node3VotingPk}, griefingWindowStart, griefingWindowEnd)
	require.Greater(griefingCounts[0], 0, "the upgraded majority should have kept proposing")
}
