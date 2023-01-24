package integration_testing

import (
	"fmt"
	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"os"
	"testing"
	"time"
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

func TestHypersyncTestnetAndMiningBlockChecksums(t *testing.T) {
	// uuidgen | cut -d- -f1
	// cp -r /tmp/data-dir-hypersync/ /tmp/data-dir-

	// Start Node1.
	print("----- Starting Node1... -----\n")
	dbDir1 := "/tmp/data-dir-478e4d0d"
	//dbDir1 := getDirectory(t)
	defer os.RemoveAll(dbDir1)
	config1 := _generateChecksumConfig(
		t, 18000, dbDir1, lib.NodeSyncTypeHyperSync, "dorsey.deso.org:18000",
	)
	config1.NumMiningThreads = 16
	node1 := cmd.NewNode(config1)
	node1 = startNode(t, node1)

	// Wait for Node1 to sync blocks.
	waitForNodeToFullySync(node1)

	// Node1 mines a block.
	print("----- Mining a block... -----\n")
	waitForNodeToMineABlock(node1)

	// Start Node2.
	print("----- Starting Node2... -----\n")
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
	print("----- Comparing checksums... -----\n")
	compareNodesByState(t, node1, node2, 0)
	compareNodesByChecksum(t, node1, node2)
}

func TestRegtestNodes(t *testing.T) {
	print("----- Starting Node1... -----\n")
	dbDir1 := getDirectory(t)
	defer os.RemoveAll(dbDir1)
	config1 := _generateChecksumConfig(
		t, 18000, dbDir1, lib.NodeSyncTypeHyperSync, "",
	)
	config1.Regtest = true
	config1.NumMiningThreads = 16
	node1 := cmd.NewNode(config1)
	node1 = startNode(t, node1)
	waitForNodeToMineABlock(node1)

	print("----- Starting Node2... -----\n")
	dbDir2 := getDirectory(t)
	defer os.RemoveAll(dbDir2)
	config2 := _generateChecksumConfig(
		t, 19000, dbDir2, lib.NodeSyncTypeHyperSync, "localhost:18000",
	)
	node2 := cmd.NewNode(config2)
	node2 = startNode(t, node2)
	waitForNodeToFullySync(node2) // Wait for Node2 to sync blocks.
	waitForNodeToMineABlock(node2)

	print("----- Starting Node3... -----\n")
	dbDir3 := getDirectory(t)
	defer os.RemoveAll(dbDir3)
	config3 := _generateChecksumConfig(
		t, 20000, dbDir3, lib.NodeSyncTypeHyperSync, "localhost:19000",
	)
	node3 := cmd.NewNode(config3)
	node3 = startNode(t, node3)
	waitForNodeToFullySync(node3) // Wait for Node2 to sync blocks.

	print("----- Comparing checksums... -----\n")
	for _, nodeA := range []*cmd.Node{node1, node2, node3} {
		for _, nodeB := range []*cmd.Node{node1, node2, node3} {
			compareNodesByState(t, nodeA, nodeB, 0)
			compareNodesByChecksum(t, nodeA, nodeB)
		}
	}
}

func TestCachingHypersyncDirectory(t *testing.T) {
	syncType := lib.NodeSyncTypeHyperSync
	dataDir := fmt.Sprintf("/tmp/data-dir-%s", syncType)
	config := _generateChecksumConfig(
		t, 18000, dataDir, syncType, "dorsey.deso.org:18000",
	)
	node := cmd.NewNode(config)
	node = startNode(t, node)
	waitForNodeToFullySync(node)
}

func _generateChecksumConfig(
	t *testing.T,
	port uint32,
	dataDir string,
	syncType string,
	connectIP string,
) *cmd.Config {
	config := generateConfig(t, port, dataDir, 10)
	config.Params = &lib.DeSoTestnetParams
	config.HyperSync = true
	config.SyncType = lib.NodeSyncType(syncType)
	config.ConnectIPs = []string{connectIP}
	config.MaxSyncBlockHeight = 0 // Sync all blocks to current tip.
	config.TrustedBlockProducerPublicKeys = []string{}
	config.GlogVmodule = "*api*=0,*bitcoin_manager*=2,*balance*=0,*frontend*=0,*peer*=0,*addr*=0,*network*=0,*utils*=0,*connection*=0,*main*=0,server*=0,*mempool*=0,*miner*=0,*blockchain*=0,*block_producer*=1"
	return config
}

func waitForNodeToMineABlock(node *cmd.Node) {
	ticker := time.NewTicker(5 * time.Millisecond)
	startingHeight := node.Server.GetBlockchain().BlockTip().Height
	for {
		<-ticker.C
		if node.Server.GetBlockchain().BlockTip().Height > startingHeight {
			return
		}
	}
}
