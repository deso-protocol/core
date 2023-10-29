package integration_testing

import (
	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

func TestSimpleConnectDisconnect(t *testing.T) {
	require := require.New(t)
	_ = require

	dbDir1 := getDirectory(t)
	defer os.RemoveAll(dbDir1)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config1.SyncType = lib.NodeSyncTypeBlockSync
	config1.MaxSyncBlockHeight = 100
	node1 := cmd.NewNode(config1)
	node1 = startNode(t, node1)

	// connect node1 to deso-seed-2.io
	node1.Server.CreateOutboundConnection("deso-seed-2.io:17000")
	node1.Server.GetConnectionManager().SetTargetOutboundPeers(0)

	<-listenForBlockHeight(node1, 50)
	node1.Server.CloseConnection(1)
	time.Sleep(3 * time.Second)
	peers := node1.Server.GetConnectionManager().GetAllPeers()
	for _, peer := range peers {
		if peer.ID == 1 {
			t.Fatalf("Should have disconnected from peer 1")
		}
	}
	node1.Stop()
}
