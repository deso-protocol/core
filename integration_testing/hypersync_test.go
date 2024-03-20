package integration_testing

import (
	"github.com/deso-protocol/core/lib"
	"testing"
)

// TestSimpleHyperSync test if a node can successfully hyper sync from another node:
//  1. Spawn two nodes node1, node2 with max block height of MaxSyncBlockHeight blocks, and snapshot period of HyperSyncSnapshotPeriod.
//  2. node1 syncs MaxSyncBlockHeight blocks from the "deso-seed-2.io" generator and builds ancestral records.
//  3. bridge node1 and node2.
//  4. node2 hypersyncs from node1
//  5. once done, compare node1 state, db, and checksum matches node2.
func TestSimpleHyperSync(t *testing.T) {
	node1 := spawnNodeProtocol1(t, 18000, "node1")
	node1.Config.HyperSync = true
	node1.Config.ConnectIPs = []string{"deso-seed-2.io:17000"}
	node1 = startNode(t, node1)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	node2 := spawnNodeProtocol1(t, 18001, "node2")
	node2.Config.SyncType = lib.NodeSyncTypeHyperSync
	node2.Config.HyperSync = true
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node2 = startNode(t, node2)

	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)

	compareNodesByState(t, node1, node2, 0)
	//compareNodesByDB(t, node1, node2, 0)
	compareNodesByChecksum(t, node1, node2)
	t.Logf("Databases match!")
}

// TestHyperSyncFromHyperSyncedNode test if a node can successfully hypersync from another hypersynced node:
//  1. Spawn three nodes node1, node2, node3 with max block height of MaxSyncBlockHeight blocks, and snapshot period of HyperSyncSnapshotPeriod
//  2. node1 syncs MaxSyncBlockHeight blocks from the "deso-seed-2.io" generator and builds ancestral records.
//  3. bridge node1 and node2.
//  4. node2 hypersyncs state.
//  5. once done, bridge node3 and node2 so that node3 hypersyncs from node2.
//  6. compare node1 state, db, and checksum matches node2, and node3.
func TestHyperSyncFromHyperSyncedNode(t *testing.T) {
	node1 := spawnNodeProtocol1(t, 18000, "node1")
	node1.Config.HyperSync = true
	node1.Config.ConnectIPs = []string{"deso-seed-2.io:17000"}
	node1 = startNode(t, node1)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	node2 := spawnNodeProtocol1(t, 18001, "node2")
	node2.Config.SyncType = lib.NodeSyncTypeHyperSyncArchival
	node2.Config.HyperSync = true
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node2 = startNode(t, node2)

	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)

	node3 := spawnNodeProtocol1(t, 18002, "node3")
	node3.Config.SyncType = lib.NodeSyncTypeHyperSyncArchival
	node3.Config.HyperSync = true
	node3.Config.ConnectIPs = []string{"127.0.0.1:18001"}
	node3 = startNode(t, node3)

	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node3)

	// Make sure node1 has the same database as node2
	compareNodesByState(t, node1, node2, 0)
	//compareNodesByDB(t, node1, node2, 0)
	compareNodesByChecksum(t, node1, node2)
	// Make sure node2 has the same database as node3
	compareNodesByState(t, node2, node3, 0)
	//compareNodesByDB(t, node2, node3, 0)
	compareNodesByChecksum(t, node2, node3)

	t.Logf("Databases match!")
}

// TestSimpleHyperSyncRestart test if a node can successfully hyper sync from another node:
//  1. Spawn two nodes node1, node2 with max block height of MaxSyncBlockHeight blocks, and snapshot period of HyperSyncSnapshotPeriod.
//  2. node1 syncs MaxSyncBlockHeight blocks from the "deso-seed-2.io" generator and builds ancestral records.
//  3. bridge node1 and node2.
//  4. node2 hyper syncs a portion of the state from node1 and then restarts.
//  5. node2 reconnects to node1 and hypersyncs again.
//  6. Once node2 finishes sync, compare node1 state, db, and checksum matches node2.
func TestSimpleHyperSyncRestart(t *testing.T) {
	node1 := spawnNodeProtocol1(t, 18000, "node1")
	node1.Config.HyperSync = true
	node1.Config.ConnectIPs = []string{"deso-seed-2.io:17000"}
	node1 = startNode(t, node1)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	node2 := spawnNodeProtocol1(t, 18001, "node2")
	node2.Config.SyncType = lib.NodeSyncTypeHyperSyncArchival
	node2.Config.HyperSync = true
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node2 = startNode(t, node2)

	syncIndex := randomUint32Between(t, 0, uint32(len(lib.StatePrefixes.StatePrefixesList)))
	syncPrefix := lib.StatePrefixes.StatePrefixesList[syncIndex]
	t.Logf("Random sync prefix for a restart (re-use if test failed): %v", syncPrefix)

	// Reboot node2 at a specific sync prefix and reconnect it with node1
	node2 = restartAtSyncPrefix(t, node2, syncPrefix)
	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)

	compareNodesByState(t, node1, node2, 0)
	//compareNodesByDB(t, node1, node2, 0)
	compareNodesByChecksum(t, node1, node2)
	t.Logf("Random restart successful! Random sync prefix was: %v", syncPrefix)
	t.Logf("Databases match!")
}

// TestSimpleHyperSyncDisconnectWithSwitchingToNewPeer tests if a node can successfully restart while hypersyncing.
//  1. Spawn three nodes node1, node2, and node3 with max block height of MaxSyncBlockHeight blocks.
//  2. node1, node3 syncs MaxSyncBlockHeight blocks from the "deso-seed-2.io" generator.
//  3. bridge node1 and node2
//  4. node2 hypersyncs from node1 but we restart node2 midway.
//  5. after restart, bridge node2 with node3 and resume hypersync.
//  6. once node2 finishes, compare node1, node2, node3 state, db, and checksums are identical.
func TestSimpleHyperSyncDisconnectWithSwitchingToNewPeer(t *testing.T) {
	node1 := spawnNodeProtocol1(t, 18000, "node1")
	node1.Config.HyperSync = true
	node1.Config.ConnectIPs = []string{"deso-seed-2.io:17000"}
	node1 = startNode(t, node1)
	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	node3 := spawnNodeProtocol1(t, 18002, "node3")
	node3.Config.HyperSync = true
	node3.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node3 = startNode(t, node3)
	// wait for node3 to sync blocks
	waitForNodeToFullySync(node3)

	node2 := spawnNodeProtocol1(t, 18001, "node2")
	node2.Config.SyncType = lib.NodeSyncTypeHyperSyncArchival
	node2.Config.HyperSync = true
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node2 = startNode(t, node2)

	// Reboot node2 at a specific height and reconnect it with node1
	syncIndex := randomUint32Between(t, 0, uint32(len(lib.StatePrefixes.StatePrefixesList)))
	syncPrefix := lib.StatePrefixes.StatePrefixesList[syncIndex]
	t.Logf("Random prefix for a restart (re-use if test failed): %v", syncPrefix)
	node2 = shutdownAtSyncPrefix(t, node2, syncPrefix)
	node2.Config.ConnectIPs = []string{"127.0.0.1:18002"}
	node2 = startNode(t, node2)

	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)

	// Compare node2 with node3.
	compareNodesByState(t, node2, node3, 0)
	//compareNodesByDB(t, node2, node3, 0)
	compareNodesByChecksum(t, node2, node3)

	// Compare node1 with node2.
	compareNodesByState(t, node1, node2, 0)
	//compareNodesByDB(t, node1, node2, 0)
	compareNodesByChecksum(t, node1, node2)
	t.Logf("Random restart successful! Random sync prefix was: %v", syncPrefix)
	t.Logf("Databases match!")
}

// TODO: disconnecting the provider peer during hypersync doesn't work.
//func TestHyperSyncDropAtTheEnd(t *testing.T) {
//	require := require.New(t)
//	_ = require
//
//	dbDir1 := getDirectory(t)
//	dbDir2 := getDirectory(t)
//	defer os.RemoveAll(dbDir1)
//	defer os.RemoveAll(dbDir2)
//
//	config1 := generateConfig(t, 18000, dbDir1, 10)
//	config2 := generateConfig(t, 18001, dbDir2, 10)
//
//	config1.HyperSync = true
//	config2.HyperSync = true
//	config1.ConnectIPs = []string{"deso-seed-2.io:17000"}
//
//	node1 := cmd.NewNode(config1)
//	node2 := cmd.NewNode(config2)
//
//	node1 = startNode(t, node1)
//	node2 = startNode(t, node2)
//
//	// wait for node1 to sync blocks
//	waitForNodeToFullySync(node1)
//
//	// bridge the nodes together.
//	bridge := NewConnectionBridge(node1, node2)
//	require.NoError(bridge.Start())
//
//	syncIndex := randomUint32Between(t, 0, uint32(len(lib.StatePrefixes.StatePrefixesList)))
//	lastPrefix := lib.StatePrefixes.StatePrefixesList[syncIndex]
//	listener := make(chan bool)
//	listenForSyncPrefix(t, node2, lastPrefix, listener)
//	<-listener
//	bridge.Disconnect()
//	node1 = restartNode(t, node1)
//	bridge = NewConnectionBridge(node1, node2)
//	require.NoError(bridge.Start())
//	// wait for node2 to sync blocks.
//	waitForNodeToFullySync(node2)
//
//	compareNodesByState(t, node1, node2, 0)
//	//compareNodesByDB(t, node1, node2, 0)
//	compareNodesByChecksum(t, node1, node2)
//	fmt.Println("Databases match!")
//	node1.Stop()
//	node2.Stop()
//}

func TestArchivalMode(t *testing.T) {
	node1 := spawnNodeProtocol1(t, 18000, "node1")
	node1.Config.HyperSync = true
	node1.Config.ConnectIPs = []string{"deso-seed-2.io:17000"}
	node1 = startNode(t, node1)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	node2 := spawnNodeProtocol1(t, 18001, "node2")
	node2.Config.SyncType = lib.NodeSyncTypeHyperSyncArchival
	node2.Config.HyperSync = true
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node2 = startNode(t, node2)

	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)

	compareNodesByDB(t, node1, node2, 0)
	compareNodesByChecksum(t, node1, node2)
	t.Logf("Databases match!")
}

func TestBlockSyncFromArchivalModeHyperSync(t *testing.T) {
	node1 := spawnNodeProtocol1(t, 18000, "node1")
	node1.Config.HyperSync = true
	node1.Config.ConnectIPs = []string{"deso-seed-2.io:17000"}
	node1 = startNode(t, node1)
	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	node2 := spawnNodeProtocol1(t, 18001, "node2")
	node2.Config.SyncType = lib.NodeSyncTypeHyperSyncArchival
	node2.Config.HyperSync = true
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node2 = startNode(t, node2)
	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)

	node3 := spawnNodeProtocol1(t, 18002, "node3")
	node3.Config.SyncType = lib.NodeSyncTypeBlockSync
	node3.Config.HyperSync = true
	node3.Config.ConnectIPs = []string{"127.0.0.1:18001"}
	node3 = startNode(t, node3)
	// wait for node3 to sync blocks.
	waitForNodeToFullySync(node3)

	compareNodesByDB(t, node1, node2, 0)
	compareNodesByDB(t, node2, node3, 0)

	//compareNodesByDB(t, node1, node2, 0)
	compareNodesByChecksum(t, node1, node2)
	t.Logf("Databases match!")
}
