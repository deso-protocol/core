package integration_testing

import (
	"github.com/deso-protocol/core/lib"
	"testing"
)

// TestRegtestMiner test if a node can mine blocks on regtest
func TestRegtestMiner(t *testing.T) {
	node1 := spawnNodeProtocol1(t, 18000, "node1")
	params := lib.DeSoTestnetParams
	node1.Config.Params = &params
	node1.Params = &params
	node1.Config.MaxSyncBlockHeight = 0
	node1.Config.MinerPublicKeys = []string{"tBCKVERmG9nZpHTk2AVPqknWc1Mw9HHAnqrTpW1RnXpXMQ4PsQgnmV"}
	node1.Config.Regtest = true
	node1 = startNode(t, node1)

	// wait for node1 to sync blocks
	mineHeight := uint32(40)
	<-listenForBlockHeight(node1, mineHeight)
}
