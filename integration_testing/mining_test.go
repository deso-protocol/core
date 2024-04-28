package integration_testing

import (
	"os"
	"testing"

	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
)

// TestSimpleBlockSync test if a node can mine blocks on regtest
func TestRegtestMiner(t *testing.T) {
	require := require.New(t)
	_ = require

	dbDir1 := getDirectory(t)
	defer os.RemoveAll(dbDir1)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config1.SyncType = lib.NodeSyncTypeBlockSync
	config1.Params = &lib.DeSoTestnetParams
	config1.MaxSyncBlockHeight = 0
	config1.MinerPublicKeys = []string{"tBCKVERmG9nZpHTk2AVPqknWc1Mw9HHAnqrTpW1RnXpXMQ4PsQgnmV"}

	config1.Regtest = true

	node1 := cmd.NewNode(config1)
	node1 = startNode(t, node1)

	// wait for node1 to sync blocks
	mineHeight := uint32(40)
	listener := make(chan bool)
	listenForBlockHeight(t, node1, mineHeight, listener)
	<-listener

	node1.Stop()
}
