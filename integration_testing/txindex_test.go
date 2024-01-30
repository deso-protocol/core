package integration_testing

import (
	"github.com/deso-protocol/core/lib"
	"testing"
)

// TestSimpleTxIndex test if a node can successfully build txindex after block syncing from another node:
//  1. Spawn two nodes node1, node2 with max block height of MaxSyncBlockHeight blocks.
//  2. node1 syncs MaxSyncBlockHeight blocks from the "deso-seed-2.io" generator, and builds txindex afterwards.
//  3. bridge node1 and node2
//  4. node2 syncs MaxSyncBlockHeight blocks from node1, and builds txindex afterwards.
//  5. compare node1 db and txindex matches node2.
func TestSimpleTxIndex(t *testing.T) {
	node1 := spawnNodeProtocol1(t, 18000, "node1")
	node1.Config.ConnectIPs = []string{"deso-seed-2.io:17000"}
	node1.Config.HyperSync = true
	node1.Config.TXIndex = true
	node1 = startNode(t, node1)
	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	node2 := spawnNodeProtocol1(t, 18001, "node2")
	node2.Config.SyncType = lib.NodeSyncTypeHyperSyncArchival
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node2.Config.HyperSync = true
	node2.Config.TXIndex = true
	node2 = startNode(t, node2)
	// wait for node1 to sync blocks
	waitForNodeToFullySync(node2)

	waitForNodeToFullySyncTxIndex(node1)
	waitForNodeToFullySyncTxIndex(node2)

	compareNodesByDB(t, node1, node2, 0)
	compareNodesByTxIndex(t, node1, node2, 0)
	t.Logf("Databases match!")
}
