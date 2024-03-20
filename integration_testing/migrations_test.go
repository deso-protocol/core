package integration_testing

import (
	"github.com/stretchr/testify/require"
	"testing"
)

// TODO: Add an encoder migration height in constants.go then modify some
// random struct like UtxoEntry. Until we have a migration, we can't fully test this.
func TestEncoderMigrations(t *testing.T) {
	node1 := spawnNodeProtocol1(t, 18000, "node1")
	node1.Config.HyperSync = true
	node1.Config.ConnectIPs = []string{"deso-seed-2.io:17000"}
	node1 = startNode(t, node1)
	// wait for node1 to sync blocks
	waitForNodeToFullySync(node1)

	node2 := spawnNodeProtocol1(t, 18001, "node2")
	node2.Config.HyperSync = true
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}
	node2 = startNode(t, node2)
	// wait for node2 to sync blocks.
	waitForNodeToFullySync(node2)
	t.Logf("Chain state and operation channel (state: %v), (len: %v)", node2.Server.GetBlockchain().ChainState(),
		len(node2.Server.GetBlockchain().Snapshot().OperationChannel.OperationChannel))

	compareNodesByState(t, node1, node2, 0)
	t.Logf("node1 checksum: %v", computeNodeStateChecksum(t, node1, 1500))
	t.Logf("node2 checksum: %v", computeNodeStateChecksum(t, node2, 1500))
	checksum1, err := node1.Server.GetBlockchain().Snapshot().Checksum.ToBytes()
	require.NoError(t, err)
	checksum2, err := node2.Server.GetBlockchain().Snapshot().Checksum.ToBytes()
	require.NoError(t, err)
	t.Logf("node1 server checksum: %v", checksum1)
	t.Logf("node2 server checksum: %v", checksum2)

	compareNodesByChecksum(t, node1, node2)
	t.Logf("Databases match!")
}
