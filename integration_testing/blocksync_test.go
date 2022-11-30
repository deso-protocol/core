package integration_testing

import (
	"fmt"
	"os"
	"testing"

	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
)

// TestSimpleBlockSync test if a node can successfully sync from another node:
//  1. Spawn two nodes node1, node2 with max block height of MaxSyncBlockHeight blocks.
//  2. node1 syncs MaxSyncBlockHeight blocks from the "deso-seed-2.io" generator.
//  3. bridge node1 and node2
//  4. node2 syncs MaxSyncBlockHeight blocks from node1.
//  5. compare node1 db matches node2 db.
func TestSimpleBlockSync(t *testing.T) {
	require := require.New(t)
	_ = require

	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)
	defer os.RemoveAll(dbDir1)
	defer os.RemoveAll(dbDir2)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config1.SyncType = lib.NodeSyncTypeBlockSync
	config2 := generateConfig(t, 18001, dbDir2, 10)
	config2.SyncType = lib.NodeSyncTypeBlockSync

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

	compareNodesByDB(t, node1, node2, 0)
	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
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
	require := require.New(t)
	_ = require

	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)
	defer os.RemoveAll(dbDir1)
	defer os.RemoveAll(dbDir2)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config1.SyncType = lib.NodeSyncTypeBlockSync
	config2 := generateConfig(t, 18001, dbDir2, 10)
	config2.SyncType = lib.NodeSyncTypeBlockSync

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

	randomHeight := randomUint32Between(t, 10, config2.MaxSyncBlockHeight)
	fmt.Println("Random height for a restart (re-use if test failed):", randomHeight)
	// Reboot node2 at a specific height and reconnect it with node1
	node2, bridge = restartAtHeightAndReconnectNode(t, node2, node1, bridge, randomHeight)
	waitForNodeToFullySync(node2)

	compareNodesByDB(t, node1, node2, 0)
	fmt.Println("Random restart successful! Random height was", randomHeight)
	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
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
	config2.SyncType = lib.NodeSyncTypeBlockSync
	config3 := generateConfig(t, 18002, dbDir3, 10)
	config3.SyncType = lib.NodeSyncTypeBlockSync

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

	randomHeight := randomUint32Between(t, 10, config2.MaxSyncBlockHeight)
	fmt.Println("Random height for a restart (re-use if test failed):", randomHeight)
	disconnectAtBlockHeight(t, node2, bridge12, randomHeight)

	// bridge the nodes together.
	bridge23 := NewConnectionBridge(node2, node3)
	require.NoError(bridge23.Start())

	// Reboot node2 at a specific height and reconnect it with node1
	//node2, bridge12 = restartAtHeightAndReconnectNode(t, node2, node1, bridge12, randomHeight)
	waitForNodeToFullySync(node2)

	compareNodesByDB(t, node1, node2, 0)
	compareNodesByDB(t, node3, node2, 0)
	fmt.Println("Random restart successful! Random height was", randomHeight)
	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
	node3.Stop()
}
