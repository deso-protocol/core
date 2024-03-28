package integration_testing

import (
	"testing"
)

// TestSimpleBlockSync test if a node can successfully sync from another node:
//  1. Spawn two nodes node1, node2 with max block height of MaxSyncBlockHeight blocks.
//  2. node1 syncs MaxSyncBlockHeight blocks from the "deso-seed-2.io" generator.
//  3. bridge node1 and node2
//  4. node2 syncs MaxSyncBlockHeight blocks from node1.
//  5. compare node1 db matches node2 db.
func TestSimpleBlockSync(t *testing.T) {
	node1 := spawnNodeProtocol1(t, 18000, "node1")
	node1.Config.ConnectIPs = []string{"deso-seed-2.io:17000"}
	node1 = startNode(t, node1)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	node2 := spawnNodeProtocol1(t, 18001, "node2")
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node2 = startNode(t, node2)

	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)

	compareNodesByDB(t, node1, node2, 0)
	t.Logf("Databases match!")
}

// TestSimpleSyncRestart tests if a node can successfully restart while syncing blocks.
//  1. Spawn two nodes node1, node2 with max block height of MaxSyncBlockHeight blocks.
//  2. node1 syncs MaxSyncBlockHeight blocks from the "deso-seed-2.io" generator.
//  3. bridge node1 and node2
//  4. node2 syncs between 10 and MaxSyncBlockHeight blocks from node1.
//  5. node2 disconnects from node1 and reboots.
//  6. node2 reconnects with node1 and syncs remaining blocks.
//  7. compare node1 db matches node2 db.
func TestSimpleSyncRestart(t *testing.T) {
	node1 := spawnNodeProtocol1(t, 18000, "node1")
	node1.Config.ConnectIPs = []string{"deso-seed-2.io:17000"}
	node1 = startNode(t, node1)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	node2 := spawnNodeProtocol1(t, 18001, "node2")
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node2 = startNode(t, node2)

	randomHeight := randomUint32Between(t, 10, node2.Config.MaxSyncBlockHeight)
	t.Logf("Random height for a restart (re-use if test failed): %v", randomHeight)
	// Reboot node2 at a specific height and reconnect it with node1
	node2 = restartAtHeight(t, node2, randomHeight)
	waitForNodeToFullySync(node2)

	compareNodesByDB(t, node1, node2, 0)
	t.Logf("Random restart successful! Random height was: %v", randomHeight)
	t.Logf("Databases match!")
}

// TestSimpleSyncDisconnectWithSwitchingToNewPeer tests if a node can successfully restart while syncing blocks, and
// then connect to a different node and sync the remaining blocks.
//  1. Spawn three nodes node1, node2, node3 with max block height of MaxSyncBlockHeight blocks.
//  2. node1 and node3 syncs MaxSyncBlockHeight blocks from the "deso-seed-2.io" generator.
//  3. bridge node1 and node2
//  4. node2 syncs between 10 and MaxSyncBlockHeight blocks from node1.
//  5. node2 disconnects from node1 and reboots.
//  6. node2 reconnects with node3 and syncs remaining blocks.
//  7. compare node1 state matches node2 state.
//  8. compare node3 state matches node2 state.
func TestSimpleSyncDisconnectWithSwitchingToNewPeer(t *testing.T) {
	node1 := spawnNodeProtocol1(t, 18000, "node1")
	node1.Config.ConnectIPs = []string{"deso-seed-2.io:17000"}
	node1 = startNode(t, node1)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	node3 := spawnNodeProtocol1(t, 18002, "node3")
	node3.Config.ConnectIPs = []string{"deso-seed-2.io:17000"}
	node3 = startNode(t, node3)

	// wait for node3 to sync blocks
	waitForNodeToFullySync(node3)

	node2 := spawnNodeProtocol1(t, 18001, "node2")
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node2 = startNode(t, node2)

	randomHeight := randomUint32Between(t, 10, node2.Config.MaxSyncBlockHeight)
	t.Logf("Random height for a restart (re-use if test failed): %v", randomHeight)

	// Reboot node2 at a specific height and reconnect it with node3
	node2 = shutdownAtHeight(t, node2, randomHeight)
	node2.Config.ConnectIPs = []string{"127.0.0.1:18002"}
	node2 = startNode(t, node2)
	waitForNodeToFullySync(node2)

	compareNodesByDB(t, node1, node2, 0)
	compareNodesByDB(t, node3, node2, 0)
	t.Logf("Random restart successful! Random height was %v", randomHeight)
	t.Logf("Databases match!")
}
