package integration_testing

import (
	"fmt"
	"os"
	"testing"

	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
)

// TODO: Add an encoder migration height in constants.go then modify some
// random struct like UtxoEntry. Until we have a migration, we can't fully test this.
func TestEncoderMigrations(t *testing.T) {
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

	config1.ConnectIPs = []string{"deso-seed-2.io:17000"}
	config1.HyperSync = true
	config2.HyperSync = true

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
	fmt.Println("Chain state and operation channel", node2.Server.GetBlockchain().ChainState(),
		len(node2.Server.GetBlockchain().Snapshot().OperationChannel.OperationChannel))

	compareNodesByState(t, node1, node2, 0)
	fmt.Println("node1 checksum:", computeNodeStateChecksum(t, node1, 1500))
	fmt.Println("node2 checksum:", computeNodeStateChecksum(t, node2, 1500))
	checksum1, err := node1.Server.GetBlockchain().Snapshot().Checksum.ToBytes()
	require.NoError(err)
	checksum2, err := node2.Server.GetBlockchain().Snapshot().Checksum.ToBytes()
	require.NoError(err)
	fmt.Println("node1 server checksum:", checksum1)
	fmt.Println("node2 server checksum:", checksum2)

	compareNodesByChecksum(t, node1, node2)
	fmt.Println("Databases match!")
	node1.Stop()
	node2.Stop()
}
