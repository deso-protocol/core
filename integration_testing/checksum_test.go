package integration_testing

import (
	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"os"
	"testing"
)

func TestHypersyncTestnetChecksums(t *testing.T) {
	// Start Node1.
	dbDir1 := getDirectory(t)
	defer os.RemoveAll(dbDir1)
	config1 := _generateChecksumConfig(
		t, 18000, dbDir1, lib.NodeSyncTypeHyperSync, "dorsey.deso.org:18000",
	)
	node1 := cmd.NewNode(config1)
	node1 = startNode(t, node1)
	defer node1.Stop()

	// Wait for Node1 to sync blocks.
	waitForNodeToFullySync(node1)

	// Start Node2.
	dbDir2 := getDirectory(t)
	defer os.RemoveAll(dbDir2)
	config2 := _generateChecksumConfig(
		t, 19000, dbDir2, lib.NodeSyncTypeHyperSync, "localhost:18000",
	)
	node2 := cmd.NewNode(config2)
	node2 = startNode(t, node2)
	defer node2.Stop()

	// Wait for Node2 to sync blocks.
	waitForNodeToFullySync(node2)

	// Compare nodes.
	compareNodesByState(t, node1, node2, 0)
	compareNodesByChecksum(t, node1, node2)
}

func TestHypersyncArchivalTestnetChecksums(t *testing.T) {
	// Start Node1.
	dbDir1 := getDirectory(t)
	defer os.RemoveAll(dbDir1)
	config1 := _generateChecksumConfig(
		t, 18000, dbDir1, lib.NodeSyncTypeHyperSyncArchival, "dorsey.deso.org:18000",
	)
	node1 := cmd.NewNode(config1)
	node1 = startNode(t, node1)
	defer node1.Stop()

	// Wait for Node1 to sync blocks.
	waitForNodeToFullySync(node1)

	// Start Node2.
	dbDir2 := getDirectory(t)
	defer os.RemoveAll(dbDir2)
	config2 := _generateChecksumConfig(
		t, 19000, dbDir2, lib.NodeSyncTypeHyperSyncArchival, "localhost:18000",
	)
	node2 := cmd.NewNode(config2)
	node2 = startNode(t, node2)
	defer node2.Stop()

	// Wait for Node2 to sync blocks.
	waitForNodeToFullySync(node2)

	// Compare nodes.
	compareNodesByState(t, node1, node2, 0)
	compareNodesByChecksum(t, node1, node2)
}

func _generateChecksumConfig(
	t *testing.T,
	port uint32,
	dataDir string,
	syncType lib.NodeSyncType,
	connectIP string,
) *cmd.Config {
	config := generateConfig(t, port, dataDir, 10)
	config.Params = &lib.DeSoTestnetParams
	config.HyperSync = true
	config.SyncType = syncType
	config.ConnectIPs = []string{connectIP}
	config.MaxSyncBlockHeight = 0 // Sync all blocks to current tip.
	return config
}
