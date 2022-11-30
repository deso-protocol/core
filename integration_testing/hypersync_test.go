package integration_testing

import (
	"fmt"
	"os"
	"testing"

	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
)

// TestSimpleHyperSync test if a node can successfully hyper sync from another node:
//  1. Spawn two nodes node1, node2 with max block height of MaxSyncBlockHeight blocks, and snapshot period of HyperSyncSnapshotPeriod.
//  2. node1 syncs MaxSyncBlockHeight blocks from the "deso-seed-2.io" generator and builds ancestral records.
//  3. bridge node1 and node2.
//  4. node2 hypersyncs from node1
//  5. once done, compare node1 state, db, and checksum matches node2.
func TestSimpleHyperSync(t *testing.T) {
	require := require.New(t)
	_ = require

	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)
	defer os.RemoveAll(dbDir1)
	defer os.RemoveAll(dbDir2)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config1.SyncType = lib.NodeSyncTypeBlockSync
	config2 := generateConfig(t, 18001, dbDir2, 10)
	config2.SyncType = lib.NodeSyncTypeHyperSync

	config1.HyperSync = true
	config2.HyperSync = true
	config1.ConnectIPs = []string{"deso-seed-2.io:17000"}

	node1 := cmd.NewNode(config1)
	node2 := cmd.NewNode(config2)

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	// bridge the nodes together.
	bridge := NewConnectionBridge(node1, node2)
	require.NoError(bridge.Start())

	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)

	compareNodesByState(t, node1, node2, 0)
	//compareNodesByDB(t, node1, node2, 0)
	compareNodesByChecksum(t, node1, node2)
	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
}

// TestHyperSyncFromHyperSyncedNode test if a node can successfully hypersync from another hypersynced node:
//  1. Spawn three nodes node1, node2, node3 with max block height of MaxSyncBlockHeight blocks, and snapshot period of HyperSyncSnapshotPeriod
//  2. node1 syncs MaxSyncBlockHeight blocks from the "deso-seed-2.io" generator and builds ancestral records.
//  3. bridge node1 and node2.
//  4. node2 hypersyncs state.
//  5. once done, bridge node3 and node2 so that node3 hypersyncs from node2.
//  6. compare node1 state, db, and checksum matches node2, and node3.
func TestHyperSyncFromHyperSyncedNode(t *testing.T) {
	require := require.New(t)
	_ = require

	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)
	dbDir3 := getDirectory(t)
	defer os.RemoveAll(dbDir1)
	defer os.RemoveAll(dbDir2)
	defer os.RemoveAll(dbDir3)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config1.SyncType = lib.NodeSyncTypeBlockSync
	config2 := generateConfig(t, 18001, dbDir2, 10)
	config2.SyncType = lib.NodeSyncTypeHyperSyncArchival
	config3 := generateConfig(t, 18002, dbDir3, 10)
	config3.SyncType = lib.NodeSyncTypeHyperSyncArchival

	config1.HyperSync = true
	config2.HyperSync = true
	config3.HyperSync = true
	config1.ConnectIPs = []string{"deso-seed-2.io:17000"}

	node1 := cmd.NewNode(config1)
	node2 := cmd.NewNode(config2)
	node3 := cmd.NewNode(config3)

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)
	node3 = startNode(t, node3)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	// bridge the nodes together.
	bridge12 := NewConnectionBridge(node1, node2)
	require.NoError(bridge12.Start())

	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)

	// bridge node3 to node2 to kick off hyper sync from a hyper synced node
	bridge23 := NewConnectionBridge(node2, node3)
	require.NoError(bridge23.Start())

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

	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
	node3.Stop()
}

// TestSimpleHyperSyncRestart test if a node can successfully hyper sync from another node:
//  1. Spawn two nodes node1, node2 with max block height of MaxSyncBlockHeight blocks, and snapshot period of HyperSyncSnapshotPeriod.
//  2. node1 syncs MaxSyncBlockHeight blocks from the "deso-seed-2.io" generator and builds ancestral records.
//  3. bridge node1 and node2.
//  4. node2 hyper syncs a portion of the state from node1 and then restarts.
//  5. node2 reconnects to node1 and hypersyncs again.
//  6. Once node2 finishes sync, compare node1 state, db, and checksum matches node2.
func TestSimpleHyperSyncRestart(t *testing.T) {
	require := require.New(t)
	_ = require

	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)
	defer os.RemoveAll(dbDir1)
	defer os.RemoveAll(dbDir2)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config2 := generateConfig(t, 18001, dbDir2, 10)

	config1.HyperSync = true
	config1.SyncType = lib.NodeSyncTypeBlockSync
	config2.HyperSync = true
	config2.SyncType = lib.NodeSyncTypeHyperSyncArchival
	config1.ConnectIPs = []string{"deso-seed-2.io:17000"}

	node1 := cmd.NewNode(config1)
	node2 := cmd.NewNode(config2)

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	// bridge the nodes together.
	bridge := NewConnectionBridge(node1, node2)
	require.NoError(bridge.Start())

	syncIndex := randomUint32Between(t, 0, uint32(len(lib.StatePrefixes.StatePrefixesList)))
	syncPrefix := lib.StatePrefixes.StatePrefixesList[syncIndex]
	fmt.Println("Random sync prefix for a restart (re-use if test failed):", syncPrefix)
	// Reboot node2 at a specific sync prefix and reconnect it with node1
	node2, bridge = restartAtSyncPrefixAndReconnectNode(t, node2, node1, bridge, syncPrefix)
	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)

	compareNodesByState(t, node1, node2, 0)
	//compareNodesByDB(t, node1, node2, 0)
	compareNodesByChecksum(t, node1, node2)
	fmt.Println("Random restart successful! Random sync prefix was", syncPrefix)
	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
}

// TestSimpleHyperSyncDisconnectWithSwitchingToNewPeer tests if a node can successfully restart while hypersyncing.
//  1. Spawn three nodes node1, node2, and node3 with max block height of MaxSyncBlockHeight blocks.
//  2. node1, node3 syncs MaxSyncBlockHeight blocks from the "deso-seed-2.io" generator.
//  3. bridge node1 and node2
//  4. node2 hypersyncs from node1 but we restart node2 midway.
//  5. after restart, bridge node2 with node3 and resume hypersync.
//  6. once node2 finishes, compare node1, node2, node3 state, db, and checksums are identical.
func TestSimpleHyperSyncDisconnectWithSwitchingToNewPeer(t *testing.T) {
	require := require.New(t)
	_ = require

	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)
	dbDir3 := getDirectory(t)
	defer os.RemoveAll(dbDir1)
	defer os.RemoveAll(dbDir2)
	defer os.RemoveAll(dbDir3)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config1.SyncType = lib.NodeSyncTypeBlockSync
	config2 := generateConfig(t, 18001, dbDir2, 10)
	config2.SyncType = lib.NodeSyncTypeHyperSyncArchival
	config3 := generateConfig(t, 18002, dbDir3, 10)
	config3.SyncType = lib.NodeSyncTypeBlockSync

	config1.HyperSync = true
	config2.HyperSync = true
	config3.HyperSync = true
	config1.ConnectIPs = []string{"deso-seed-2.io:17000"}
	config3.ConnectIPs = []string{"deso-seed-2.io:17000"}

	node1 := cmd.NewNode(config1)
	node2 := cmd.NewNode(config2)
	node3 := cmd.NewNode(config3)

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)
	node3 = startNode(t, node3)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)
	// wait for node3 to sync blocks
	waitForNodeToFullySync(node3)

	// bridge the nodes together.
	bridge12 := NewConnectionBridge(node1, node2)
	require.NoError(bridge12.Start())

	syncIndex := randomUint32Between(t, 0, uint32(len(lib.StatePrefixes.StatePrefixesList)))
	syncPrefix := lib.StatePrefixes.StatePrefixesList[syncIndex]
	fmt.Println("Random prefix for a restart (re-use if test failed):", syncPrefix)
	disconnectAtSyncPrefix(t, node2, bridge12, syncPrefix)

	// bridge the nodes together.
	bridge23 := NewConnectionBridge(node2, node3)
	require.NoError(bridge23.Start())

	// Reboot node2 at a specific height and reconnect it with node1
	//node2, bridge12 = restartAtHeightAndReconnectNode(t, node2, node1, bridge12, randomHeight)
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
	fmt.Println("Random restart successful! Random sync prefix was", syncPrefix)
	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
	node3.Stop()
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
	require := require.New(t)
	_ = require

	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)
	defer os.RemoveAll(dbDir1)
	defer os.RemoveAll(dbDir2)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config2 := generateConfig(t, 18001, dbDir2, 10)

	config1.HyperSync = true
	config2.HyperSync = true
	config1.ConnectIPs = []string{"deso-seed-2.io:17000"}
	config1.SyncType = lib.NodeSyncTypeBlockSync
	config2.SyncType = lib.NodeSyncTypeHyperSyncArchival

	node1 := cmd.NewNode(config1)
	node2 := cmd.NewNode(config2)

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	// bridge the nodes together.
	bridge := NewConnectionBridge(node1, node2)
	require.NoError(bridge.Start())

	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)

	compareNodesByDB(t, node1, node2, 0)

	//compareNodesByDB(t, node1, node2, 0)
	compareNodesByChecksum(t, node1, node2)
	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
}

func TestBlockSyncFromArchivalModeHyperSync(t *testing.T) {
	require := require.New(t)
	_ = require

	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)
	dbDir3 := getDirectory(t)
	defer os.RemoveAll(dbDir1)
	defer os.RemoveAll(dbDir2)
	defer os.RemoveAll(dbDir3)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config2 := generateConfig(t, 18001, dbDir2, 10)
	config3 := generateConfig(t, 18002, dbDir3, 10)

	config1.HyperSync = true
	config1.SyncType = lib.NodeSyncTypeBlockSync
	config2.HyperSync = true
	config2.SyncType = lib.NodeSyncTypeHyperSyncArchival
	config3.HyperSync = false
	config3.SyncType = lib.NodeSyncTypeBlockSync
	config1.ConnectIPs = []string{"deso-seed-2.io:17000"}

	node1 := cmd.NewNode(config1)
	node2 := cmd.NewNode(config2)
	node3 := cmd.NewNode(config3)

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)
	node3 = startNode(t, node3)

	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	// bridge the nodes together.
	bridge12 := NewConnectionBridge(node1, node2)
	require.NoError(bridge12.Start())

	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)

	bridge23 := NewConnectionBridge(node2, node3)
	require.NoError(bridge23.Start())

	// wait for node3 to sync blocks.
	waitForNodeToFullySync(node3)

	compareNodesByDB(t, node1, node2, 0)
	compareNodesByDB(t, node2, node3, 0)

	//compareNodesByDB(t, node1, node2, 0)
	compareNodesByChecksum(t, node1, node2)
	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
}
