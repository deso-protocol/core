//go:build relic

package consensus

import (
	"testing"
	"time"

	"github.com/deso-protocol/core/collections"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

// This integration test simulates a network of 4 nodes with equal stake. It tests the
// a scenario in which a super-majority of stake is always online. Nodes sporadically
// go offline and come back online. The network should continue to produce blocks
// as long as a super-majority of stake is online.
func TestNetworkWithOfflineValidators(t *testing.T) {
	// Create 4 nodes with equal stake. The network has super-majority of stake online
	// as long as 3 out of 4 nodes are online.
	node1 := newValidatorNode(uint256.NewInt().SetUint64(50), true)  // block proposer
	node2 := newValidatorNode(uint256.NewInt().SetUint64(50), false) // validator
	node3 := newValidatorNode(uint256.NewInt().SetUint64(50), false) // validator
	node4 := newValidatorNode(uint256.NewInt().SetUint64(50), false) // validator

	allNodes := []*validatorNode{node1, node2, node3, node4}

	// Create the genesis block signed by all four nodes.
	genesisBlock := createDummyBlockWithVoteQC(createDummyBlockHash(), 2, 2, allNodes)

	// Set the crank and timeout durations
	crankTimer := time.Millisecond * 100    // Produce a block every 100ms
	timeoutTimer := time.Millisecond * 1000 // Time out if there is no block broadcast within 1000ms

	// Initialize all nodes and and connect them to each other
	for _, validator := range allNodes {
		require.NoError(t, validator.Init(crankTimer, timeoutTimer, genesisBlock, allNodes))
	}

	// Start all nodes' consensus event loops.
	for _, node := range allNodes {
		node.Start()
	}

	// Broadcast a block with a valid QC to all nodes. This kicks off the steady state flow
	// of the Fast-HotStuff consensus. All nodes will begin voting starting from this block.
	initialBlockToBroadcast := createDummyBlockWithVoteQC(genesisBlock.GetBlockHash(), 3, 3, allNodes)
	for _, node := range allNodes {
		node.ProcessBlock(initialBlockToBroadcast)
	}

	// Let all nodes run for 0.5 seconds so that the network produces at least one block.
	time.Sleep(time.Millisecond * 500)

	// Stop node 2 to simulate it going offline. The network has enough stake online
	// to continue producing blocks.
	node2.Stop()

	// Let all nodes run for 0.5 seconds so that the network produces at least one block.
	time.Sleep(time.Millisecond * 500)

	// Restart node 2 to simulate it going back online
	node2.Start()

	// Let all nodes run for 0.5 seconds so that the network produces at least one block.
	time.Sleep(time.Millisecond * 500)

	// Stop node 3 to simulate it going offline. The network has enough stake online to continue producing blocks.
	node3.Stop()

	// Let all nodes run for 0.5 seconds so that the network produces at least one block.
	time.Sleep(time.Millisecond * 500)

	// Restart node 3 to simulate it going back online
	node3.Start()

	// Let all nodes run for 0.5 seconds so that the network produces at least one block.
	time.Sleep(time.Millisecond * 500)

	// Stop node 4 to simulate it going offline. The network has enough stake online to continue producing blocks.
	node4.Stop()

	// Let all nodes run for 2 seconds so that the network produces at least one block.
	time.Sleep(time.Millisecond * 500)

	// Stop all remaining nodes
	node1.Stop()
	node2.Stop()
	node3.Stop()

	// Validate the resulting chain of blocks stored by all nodes
	validateAndPrintBlockChain(t, node1, node1.safeBlocks)
	validateAndPrintBlockChain(t, node2, node2.safeBlocks)
	validateAndPrintBlockChain(t, node3, node3.safeBlocks)
	validateAndPrintBlockChain(t, node4, node4.safeBlocks)

	// Verify that the network has produced more blocks after the node 4 stopped
	require.Greater(t, node3.eventLoop.tip.block.GetView(), node4.eventLoop.tip.block.GetView())
	require.Greater(t, node3.eventLoop.tip.block.GetHeight(), node4.eventLoop.tip.block.GetHeight())
}

// This integration test simulates a network of 4 nodes with equal stake. It tests the
// a scenario in which a super-majority of stake is always online, but the block proposer
// goes offline causing other nodes to timeout. The block proposer comes back online and
// the network gracefully recovers.
func TestNetworkWithOfflineBlockProposer(t *testing.T) {
	// Create 4 nodes with equal stake. The network has super-majority of stake online
	// as long as 3 out of 4 nodes are online.
	node1 := newValidatorNode(uint256.NewInt().SetUint64(50), true)  // block proposer
	node2 := newValidatorNode(uint256.NewInt().SetUint64(50), false) // validator
	node3 := newValidatorNode(uint256.NewInt().SetUint64(50), false) // validator
	node4 := newValidatorNode(uint256.NewInt().SetUint64(50), false) // validator

	allNodes := []*validatorNode{node1, node2, node3, node4}

	// Create the genesis block signed by all four nodes.
	genesisBlock := createDummyBlockWithVoteQC(createDummyBlockHash(), 2, 2, allNodes)

	// Set the crank and timeout durations
	crankTimer := time.Millisecond * 500    // Produce a block every 500ms
	timeoutTimer := time.Millisecond * 1000 // Time out if there is no block broadcast within 1000ms

	// Initialize all nodes and and connect them to each other
	for _, validator := range allNodes {
		require.NoError(t, validator.Init(crankTimer, timeoutTimer, genesisBlock, allNodes))
	}

	// Start all nodes' consensus event loops.
	for _, node := range allNodes {
		node.Start()
	}

	// Broadcast a block with a valid QC to all nodes. This kicks off the steady state flow
	// of the Fast-HotStuff consensus. All nodes will begin voting starting from this block.
	initialBlockToBroadcast := createDummyBlockWithVoteQC(genesisBlock.GetBlockHash(), 3, 3, allNodes)
	for _, node := range allNodes {
		node.ProcessBlock(initialBlockToBroadcast)
	}

	// Let all nodes run for 1 second so that the network produces at least one block.
	time.Sleep(time.Millisecond * 1000)

	// Stop node 1 to simulate the block proposer going offline. All other validators will
	// begin to time out. The network does not switch leaders during timeouts and instead
	// waits for the block proposer to come back online.
	node1.Stop()

	// Cache node 1's tip during the network halt
	node1TipDuringNetworkHalt := node1.eventLoop.tip.block.(*block)

	// Let all online nodes run for 2 seconds so they time out at least once.
	time.Sleep(time.Millisecond * 2000)

	// Restart node 2 to simulate a block proposer coming online.
	node1.Start()

	// Let all nodes run for 10 seconds. The block proposer's view start off lower than the
	// all other validators. All nodes' timeout have exponential backoff so they should all
	// converge on the same view eventually.
	time.Sleep(time.Millisecond * 10000)

	// Stop remaining nodes
	for _, node := range allNodes {
		node.Stop()
	}

	// Validate the resulting chain of blocks stored by all nodes
	validateAndPrintBlockChain(t, node1, node1.safeBlocks)
	validateAndPrintBlockChain(t, node2, node2.safeBlocks)
	validateAndPrintBlockChain(t, node3, node3.safeBlocks)
	validateAndPrintBlockChain(t, node4, node4.safeBlocks)

	// Verify that the network has produced at least one block since the block proposer returned
	require.Greater(t, node3.eventLoop.tip.block.GetView(), node1TipDuringNetworkHalt.GetView())
	require.Greater(t, node3.eventLoop.tip.block.GetHeight(), node1TipDuringNetworkHalt.GetHeight())
}

// This integration test simulates a network of 3 nodes, where a super-majority of stake is
// concentrated on node. It tests the a scenario in which the super-majority of stake goes
// offline, killing liveness. The network can recover as long as the super-majority of stake
// can sync to the same starting block height once they come back online. It simulates recovery
// from a catastrophic network failure.
func TestNetworkRecoveryAfterCatastrophicFailure(t *testing.T) {
	// Create 3 nodes with equal stake. Node 3 has a super-majority of the the stake
	// and needs to stay online for the network to remain live.
	node1 := newValidatorNode(uint256.NewInt().SetUint64(10), true)  // block proposer
	node2 := newValidatorNode(uint256.NewInt().SetUint64(10), false) // validator
	node3 := newValidatorNode(uint256.NewInt().SetUint64(80), false) // validator

	allNodes := []*validatorNode{node1, node2, node3}

	// Create the genesis block signed by all three nodes.
	genesisBlock := createDummyBlockWithVoteQC(createDummyBlockHash(), 2, 2, allNodes)

	// Set the crank and timeout durations
	crankTimer := time.Millisecond * 500    // Produce a block every 500ms
	timeoutTimer := time.Millisecond * 1000 // Time out if there is no block broadcast within 1000ms

	// Initialize all nodes and and connect them to each other
	for _, validator := range allNodes {
		require.NoError(t, validator.Init(crankTimer, timeoutTimer, genesisBlock, allNodes))
	}

	// Start all nodes' consensus event loops.
	for _, node := range allNodes {
		node.Start()
	}

	// Broadcast a block with a valid QC to all nodes. This kicks off the steady state flow
	// of the Fast-HotStuff consensus. All nodes will begin voting starting from this block.
	initialBlockToBroadcast := createDummyBlockWithVoteQC(genesisBlock.GetBlockHash(), 3, 3, allNodes)
	for _, node := range allNodes {
		node.ProcessBlock(initialBlockToBroadcast)
	}

	// Let all nodes run for 1 second so that the network produces at least one block.
	time.Sleep(time.Millisecond * 1000)

	// Stop node 3 to simulate the network going down catastrophically. All nodes will begin to
	// time out. No blocks will be proposed during this time.
	node3.Stop()

	// Let all online nodes run for 2 seconds so they time out at least once. The block proposer
	// may proposer at most one block during this time if it had enough votes stored for its current
	// tip to build a QC. The QC will not reach node 3.
	//
	// The network has halted during this period.
	time.Sleep(time.Millisecond * 2000)

	// Cache node 3's tip during the network halt. Nodes internal clocks and view will during this
	// period.
	node3TipDuringNetworkHalt := node3.eventLoop.tip.block.(*block)

	// After a catastrophic network failure, nodes with a super-majority of stake need to somehow
	// agree on a starting state of the chain. As long as they are able to sync from or to any peer
	// that eventually becomes a block proposer, the network will recover.
	node3.Resync(genesisBlock, node1.eventLoop.tip.block.(*block), collections.MapValues(node1.safeBlocks))
	node3.Start()

	// Let all nodes run for 10 seconds. Eventually all nodes will converge on a single view and
	// the network will start producing blocks again.
	time.Sleep(time.Millisecond * 10000)

	// Stop remaining nodes
	for _, node := range allNodes {
		node.Stop()
	}

	// Validate and print resulting chain of blocks stored by all nodes
	validateAndPrintBlockChain(t, node1, node1.safeBlocks)
	validateAndPrintBlockChain(t, node2, node2.safeBlocks)
	validateAndPrintBlockChain(t, node3, node3.safeBlocks)

	// Verify that the network has produced at least one block since it recovered
	require.Greater(t, node3.eventLoop.tip.block.GetView(), node3TipDuringNetworkHalt.GetView())
	require.Greater(t, node3.eventLoop.tip.block.GetHeight(), node3TipDuringNetworkHalt.GetHeight())
}
