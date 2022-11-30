package integration_testing

import (
	"fmt"
	"os"
	"testing"

	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
)

// TestSimpleTxIndex test if a node can successfully build txindex after block syncing from another node:
//  1. Spawn two nodes node1, node2 with max block height of MaxSyncBlockHeight blocks.
//  2. node1 syncs MaxSyncBlockHeight blocks from the "deso-seed-2.io" generator, and builds txindex afterwards.
//  3. bridge node1 and node2
//  4. node2 syncs MaxSyncBlockHeight blocks from node1, and builds txindex afterwards.
//  5. compare node1 db and txindex matches node2.
func TestSimpleTxIndex(t *testing.T) {
	require := require.New(t)
	_ = require

	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)
	defer os.RemoveAll(dbDir1)
	defer os.RemoveAll(dbDir2)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config1.HyperSync = true
	config1.SyncType = lib.NodeSyncTypeBlockSync
	config2 := generateConfig(t, 18001, dbDir2, 10)
	config2.HyperSync = true
	config2.SyncType = lib.NodeSyncTypeHyperSyncArchival

	config1.TXIndex = true
	config2.TXIndex = true
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

	waitForNodeToFullySyncTxIndex(node1)
	waitForNodeToFullySyncTxIndex(node2)

	compareNodesByDB(t, node1, node2, 0)
	compareNodesByTxIndex(t, node1, node2, 0)
	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
}
