package integration_testing

import (
	"fmt"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/consensus"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
	"github.com/tyler-smith/go-bip39"
	"testing"
	"time"
)

func TestConnectionControllerInitiatePersistentConnections(t *testing.T) {
	// NonValidator Node1 will set its --connect-ips to two non-validators node2 and node3,
	// and two validators node4 and node5.
	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node2 := spawnNonValidatorNodeProtocol2(t, 18001, "node2")
	node3 := spawnNonValidatorNodeProtocol2(t, 18002, "node3")
	blsSeedPhrase4, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsSeedPhrase4)
	blsSeedPhrase5, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node5 := spawnValidatorNodeProtocol2(t, 18004, "node5", blsSeedPhrase5)

	node2 = startNode(t, node2)
	node3 = startNode(t, node3)
	node4 = startNode(t, node4)
	node5 = startNode(t, node5)

	node1.Config.ConnectIPs = []string{
		node2.Listeners[0].Addr().String(),
		node3.Listeners[0].Addr().String(),
		node4.Listeners[0].Addr().String(),
		node5.Listeners[0].Addr().String(),
	}
	node1 = startNode(t, node1)
	activeValidatorsMap := getActiveValidatorsMapWithValidatorNodes(t, node4, node5)
	setActiveValidators(activeValidatorsMap, node1, node2, node3, node4, node5)
	waitForNonValidatorOutboundConnection(t, node1, node2)
	waitForNonValidatorOutboundConnection(t, node1, node3)
	waitForValidatorConnection(t, node1, node4)
	waitForValidatorConnection(t, node1, node5)
	waitForValidatorConnection(t, node4, node5)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node1, 4, 2, 2, 0)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node2, 1, 0, 0, 1)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node3, 1, 0, 0, 1)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node4, 2, 1, 0, 1)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node5, 2, 1, 0, 1)
	node1.Stop()
	t.Logf("Test #1 passed | Successfully run non-validator node1 with --connect-ips set to node2, node3, node4, node5")

	// Now try again with a validator node6, with connect-ips set to node2, node3, node4, node5.
	blsSeedPhrase6, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node6 := spawnValidatorNodeProtocol2(t, 18005, "node6", blsSeedPhrase6)
	node6.Config.ConnectIPs = []string{
		node2.Listeners[0].Addr().String(),
		node3.Listeners[0].Addr().String(),
		node4.Listeners[0].Addr().String(),
		node5.Listeners[0].Addr().String(),
	}
	node6 = startNode(t, node6)
	activeValidatorsMap = getActiveValidatorsMapWithValidatorNodes(t, node4, node5, node6)
	setActiveValidators(activeValidatorsMap, node1, node2, node3, node4, node5, node6)
	waitForNonValidatorOutboundConnection(t, node6, node2)
	waitForNonValidatorOutboundConnection(t, node6, node3)
	waitForValidatorConnection(t, node6, node4)
	waitForValidatorConnection(t, node6, node5)
	waitForValidatorConnection(t, node4, node5)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node6, 4, 2, 2, 0)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node2, 1, 1, 0, 0)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node3, 1, 1, 0, 0)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node4, 2, 2, 0, 0)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node5, 2, 2, 0, 0)
	t.Logf("Test #2 passed | Successfully run validator node6 with --connect-ips set to node2, node3, node4, node5")
}

func TestConnectionControllerNonValidatorCircularConnectIps(t *testing.T) {
	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node2 := spawnNonValidatorNodeProtocol2(t, 18001, "node2")

	node1.Config.ConnectIPs = []string{"127.0.0.1:18001"}
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)

	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node1, 2, 0, 1, 1)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node2, 2, 0, 1, 1)
}

func TestNetworkManagerPersistentConnectorReconnect(t *testing.T) {
	// Ensure that a node that is disconnected from a persistent connection will be reconnected to.
	// Spawn three nodes: a non-validator node1, and node2, and a validator node3. Then set node1 connectIps
	// to node2, node3, as well as a non-existing ip. Then we will stop node2, and wait for node1 to drop the
	// connection. Then we will restart node2, and wait for node1 to reconnect to node2. We will repeat this
	// process for node3.

	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	// Set TargetOutboundPeers to 0 to ensure the non-validator connector doesn't interfere.
	node1.Config.TargetOutboundPeers = 0

	node2 := spawnNonValidatorNodeProtocol2(t, 18001, "node2")
	blsSeedPhrase3, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node3 := spawnValidatorNodeProtocol2(t, 18002, "node3", blsSeedPhrase3)

	node2 = startNode(t, node2)
	node3 = startNode(t, node3)

	node1.Config.ConnectIPs = []string{
		node2.Listeners[0].Addr().String(),
		node3.Listeners[0].Addr().String(),
		"127.0.0.1:18003",
	}
	node1 = startNode(t, node1)
	activeValidatorsMap := getActiveValidatorsMapWithValidatorNodes(t, node3)
	setActiveValidators(activeValidatorsMap, node1, node2, node3)

	waitForNonValidatorOutboundConnection(t, node1, node2)
	waitForValidatorConnection(t, node1, node3)
	waitForCountRemoteNodeIndexer(t, node1, 3, 1, 2, 0)

	node2.Stop()
	waitForCountRemoteNodeIndexer(t, node1, 2, 1, 1, 0)
	// node1 should reopen the connection to node2, and it should be re-indexed as a non-validator (attempted).
	waitForCountRemoteNodeIndexer(t, node1, 3, 1, 2, 0)
	node2 = startNode(t, node2)
	setActiveValidators(activeValidatorsMap, node2)
	waitForCountRemoteNodeIndexer(t, node1, 3, 1, 2, 0)
	t.Logf("Test #1 passed | Successfully run reconnect test with non-validator node1 with --connect-ips for node2")

	// Now we will do the same for node3.
	node3.Stop()
	waitForCountRemoteNodeIndexer(t, node1, 2, 0, 2, 0)
	// node1 should reopen the connection to node3, and it should be re-indexed as a non-validator (attempted).
	waitForCountRemoteNodeIndexer(t, node1, 3, 0, 3, 0)
	node3 = startNode(t, node3)
	setActiveValidators(activeValidatorsMap, node3)
	waitForValidatorConnection(t, node1, node3)
	waitForCountRemoteNodeIndexer(t, node1, 3, 1, 2, 0)
	t.Logf("Test #2 passed | Successfully run reconnect test with non-validator node1 with --connect-ips for node3")
}

func TestConnectionControllerValidatorConnector(t *testing.T) {
	// Spawn 5 validators node1, node2, node3, node4, node5 and two non-validators node6 and node7.
	// All the validators are initially in the validator set. And later, node1 and node2 will be removed from the
	// validator set. Then, make node3 inactive, and node2 active again. Then, make all the validators inactive.
	// Make node6, and node7 connect-ips to all the validators.

	blsSeedPhrase1, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node1 := spawnValidatorNodeProtocol2(t, 18000, "node1", blsSeedPhrase1)
	blsSeedPhrase2, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node2 := spawnValidatorNodeProtocol2(t, 18001, "node2", blsSeedPhrase2)
	blsSeedPhrase3, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node3 := spawnValidatorNodeProtocol2(t, 18002, "node3", blsSeedPhrase3)
	blsSeedPhrase4, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsSeedPhrase4)
	blsSeedPhrase5, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node5 := spawnValidatorNodeProtocol2(t, 18004, "node5", blsSeedPhrase5)

	node6 := spawnNonValidatorNodeProtocol2(t, 18005, "node6")
	node7 := spawnNonValidatorNodeProtocol2(t, 18006, "node7")

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)
	node3 = startNode(t, node3)
	node4 = startNode(t, node4)
	node5 = startNode(t, node5)

	node6.Config.ConnectIPs = []string{
		node1.Listeners[0].Addr().String(),
		node2.Listeners[0].Addr().String(),
		node3.Listeners[0].Addr().String(),
		node4.Listeners[0].Addr().String(),
		node5.Listeners[0].Addr().String(),
	}
	node7.Config.ConnectIPs = node6.Config.ConnectIPs
	node6 = startNode(t, node6)
	node7 = startNode(t, node7)
	activeValidatorsMap := getActiveValidatorsMapWithValidatorNodes(t, node1, node2, node3, node4, node5)
	setActiveValidators(activeValidatorsMap, node1, node2, node3, node4, node5, node6, node7)

	// Verify full graph between active validators.
	waitForValidatorFullGraph(t, node1, node2, node3, node4, node5)
	// Verify connections of non-validators.
	for _, nonValidator := range []*cmd.Node{node6, node7} {
		waitForValidatorConnectionOneWay(t, nonValidator, node1, node2, node3, node4, node5)
	}
	// Verify connections of initial validators.
	for _, validator := range []*cmd.Node{node1, node2, node3, node4, node5} {
		waitForNonValidatorInboundConnection(t, validator, node6)
		waitForNonValidatorInboundConnection(t, validator, node7)
	}
	// Verify connection counts of active validators.
	for _, validator := range []*cmd.Node{node1, node2, node3, node4, node5} {
		waitForMinNonValidatorCountRemoteNodeIndexer(t, validator, 6, 4, 0, 2)
	}
	// NOOP Verify connection counts of inactive validators.
	// Verify connection counts of non-validators.
	waitForCountRemoteNodeIndexer(t, node6, 5, 5, 0, 0)
	waitForCountRemoteNodeIndexer(t, node7, 5, 5, 0, 0)
	t.Logf("Test #1 passed | Successfully run validators node1, node2, node3, node4, node5; non-validators node6, node7")

	// Remove node1 and node2 from the validator set.
	activeValidatorsMap = getActiveValidatorsMapWithValidatorNodes(t, node3, node4, node5)
	setActiveValidators(activeValidatorsMap, node1, node2, node3, node4, node5, node6, node7)
	// Verify full graph between active validators.
	waitForValidatorFullGraph(t, node3, node4, node5)
	// Verify connections of non-validators.
	for _, nonValidator := range []*cmd.Node{node1, node2, node6, node7} {
		waitForValidatorConnectionOneWay(t, nonValidator, node3, node4, node5)
	}
	// Verify connections of initial validators.
	for _, validator := range []*cmd.Node{node1, node2, node3, node4, node5} {
		waitForNonValidatorInboundConnection(t, validator, node6)
		waitForNonValidatorInboundConnection(t, validator, node7)
	}
	// Verify connections of active validators.
	for _, validator := range []*cmd.Node{node3, node4, node5} {
		waitForNonValidatorInboundXOROutboundConnection(t, validator, node1)
		waitForNonValidatorInboundXOROutboundConnection(t, validator, node2)
		waitForMinNonValidatorCountRemoteNodeIndexer(t, validator, 6, 2, 0, 2)
	}
	// Verify connection counts of inactive validators.
	for _, validator := range []*cmd.Node{node1, node2} {
		waitForMinNonValidatorCountRemoteNodeIndexer(t, validator, 6, 3, 0, 2)
	}
	// Verify connection counts of non-validators.
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node6, 5, 3, 2, 0)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node7, 5, 3, 2, 0)
	t.Logf("Test #2 passed | Successfully run validators node3, node4, node5; inactive-validators node1, node2; " +
		"non-validators node6, node7")

	// Remove node3 from the validator set. Make node1 active again.
	activeValidatorsMap = getActiveValidatorsMapWithValidatorNodes(t, node1, node4, node5)
	setActiveValidators(activeValidatorsMap, node1, node2, node3, node4, node5, node6, node7)
	// Verify full graph between active validators.
	waitForValidatorFullGraph(t, node1, node4, node5)
	// Verify connections of non-validators.
	for _, nonValidator := range []*cmd.Node{node2, node3, node6, node7} {
		waitForValidatorConnectionOneWay(t, nonValidator, node1, node4, node5)
	}
	// Verify connections of initial validators.
	for _, validator := range []*cmd.Node{node1, node2, node3, node4, node5} {
		waitForNonValidatorInboundConnection(t, validator, node6)
		waitForNonValidatorInboundConnection(t, validator, node7)
	}
	// Verify connections of active validators.
	for _, validator := range []*cmd.Node{node1, node4, node5} {
		waitForNonValidatorInboundXOROutboundConnection(t, validator, node2)
		waitForNonValidatorInboundXOROutboundConnection(t, validator, node3)
		waitForMinNonValidatorCountRemoteNodeIndexer(t, validator, 6, 2, 0, 2)
	}
	// Verify connection counts of inactive validators.
	for _, validator := range []*cmd.Node{node2, node3} {
		waitForMinNonValidatorCountRemoteNodeIndexer(t, validator, 6, 3, 0, 2)
	}
	// Verify connection counts of non-validators.
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node6, 5, 3, 2, 0)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node7, 5, 3, 2, 0)
	t.Logf("Test #3 passed | Successfully run validators node1, node4, node5; inactive validators node2, node3; " +
		"non-validators node6, node7")

	// Make all validators inactive.
	activeValidatorsMap = getActiveValidatorsMapWithValidatorNodes(t)
	setActiveValidators(activeValidatorsMap, node1, node2, node3, node4, node5, node6, node7)
	// NOOP Verify full graph between active validators.
	// NOOP Verify connections of non-validators.
	// Verify connections of initial validators.
	for _, validator := range []*cmd.Node{node1, node2, node3, node4, node5} {
		waitForNonValidatorInboundConnection(t, validator, node6)
		waitForNonValidatorInboundConnection(t, validator, node7)
	}
	// NOOP Verify connections of active validators.
	// Verify connections and counts of inactive validators.
	inactiveValidators := []*cmd.Node{node1, node2, node3, node4, node5}
	for ii := 0; ii < len(inactiveValidators); ii++ {
		for jj := ii + 1; jj < len(inactiveValidators); jj++ {
			waitForNonValidatorInboundXOROutboundConnection(t, inactiveValidators[ii], inactiveValidators[jj])
		}
	}
	inactiveValidatorsRev := []*cmd.Node{node5, node4, node3, node2, node1}
	for ii := 0; ii < len(inactiveValidatorsRev); ii++ {
		for jj := ii + 1; jj < len(inactiveValidatorsRev); jj++ {
			waitForNonValidatorInboundXOROutboundConnection(t, inactiveValidatorsRev[ii], inactiveValidatorsRev[jj])
		}
	}
	for _, validator := range inactiveValidators {
		waitForMinNonValidatorCountRemoteNodeIndexer(t, validator, 6, 0, 0, 2)
	}
	// Verify connection counts of non-validators.
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node6, 5, 0, 5, 0)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node7, 5, 0, 5, 0)
	t.Logf("Test #4 passed | Successfully run inactive validators node1, node2, node3, node4, node5; " +
		"non-validators node6, node7")
}

func TestConnectionControllerValidatorInboundDeduplication(t *testing.T) {
	// Spawn a non-validator node1, and two validators node2, node3. The validator nodes will have the same public key.
	// Node2 and node3 will not initially be in the validator set. First, node2 will start an outbound connection to
	// node1. We wait until the node2 is re-indexed as non-validator by node1, and then we make node3 open an outbound
	// connection to node1. We wait until node3 is re-indexed as non-validator by node1. Then, we make node2 and node3
	// join the validator set (i.e. add one entry with the duplicated public key). Now, node1 should disconnect from
	// either node2 or node3 because of duplicate public key.

	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	blsSeedPhrase2, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node2 := spawnValidatorNodeProtocol2(t, 18001, "node2", blsSeedPhrase2)
	node3 := spawnValidatorNodeProtocol2(t, 18002, "node3", blsSeedPhrase2)

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)
	node3 = startNode(t, node3)

	nm2 := node2.Server.GetNetworkManager()
	require.NoError(t, nm2.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	// First wait for node2 to be indexed as a validator by node1.
	waitForValidatorConnection(t, node1, node2)
	// Now wait for node2 to be re-indexed as a non-validator.
	waitForNonValidatorInboundConnectionDynamic(t, node1, node2, true)
	waitForNonValidatorOutboundConnection(t, node2, node1)

	// Now connect node3 to node1.
	nm3 := node3.Server.GetNetworkManager()
	require.NoError(t, nm3.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	// First wait for node3 to be indexed as a validator by node1.
	waitForValidatorConnection(t, node1, node3)
	// Now wait for node3 to be re-indexed as a non-validator.
	waitForNonValidatorInboundConnectionDynamic(t, node1, node3, true)
	waitForNonValidatorOutboundConnection(t, node3, node1)

	// Now add node2 and node3 to the validator set.
	activeValidatorsMap := getActiveValidatorsMapWithValidatorNodes(t, node2)
	setActiveValidators(activeValidatorsMap, node1, node2, node3)
	// Now wait for node1 to disconnect from either node2 or node3.
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node1, 1, 1, 0, 0)
	t.Logf("Test #1 passed | Successfully run non-validator node1; validators node2, node3 with duplicate public key")
}

func TestConnectionControllerNonValidatorConnectorOutbound(t *testing.T) {
	// Spawn 6 non-validators node1, node2, node3, node4, node5, node6. Set node1's targetOutboundPeers to 3. Then make
	// node1 create persistent outbound connections to node2, node3, and node4, as well as non-validator connections to
	// node5 and node6.
	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node1.Config.TargetOutboundPeers = 0
	node2 := spawnNonValidatorNodeProtocol2(t, 18001, "node2")
	node3 := spawnNonValidatorNodeProtocol2(t, 18002, "node3")
	node4 := spawnNonValidatorNodeProtocol2(t, 18003, "node4")
	node5 := spawnNonValidatorNodeProtocol2(t, 18004, "node5")
	node6 := spawnNonValidatorNodeProtocol2(t, 18005, "node6")

	node2 = startNode(t, node2)
	node3 = startNode(t, node3)
	node4 = startNode(t, node4)
	node5 = startNode(t, node5)
	node6 = startNode(t, node6)

	node1.Config.ConnectIPs = []string{
		node2.Listeners[0].Addr().String(),
		node3.Listeners[0].Addr().String(),
		node4.Listeners[0].Addr().String(),
	}
	node1 = startNode(t, node1)

	nm := node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node5.Listeners[0].Addr().String()))
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node6.Listeners[0].Addr().String()))

	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node1, 3, 0, 3, 0)
	waitForNonValidatorOutboundConnection(t, node1, node2)
	waitForNonValidatorOutboundConnection(t, node1, node3)
	waitForNonValidatorOutboundConnection(t, node1, node4)
}

func TestConnectionControllerNonValidatorConnectorInbound(t *testing.T) {
	// Spawn validators node1, node2, node3, node4, node5, node6. Also spawn non-validators node7, node8, node9, node10.
	// Set node1's targetOutboundPeers to 0 and targetInboundPeers to 1. Then make node1 create outbound connections to
	// node2, node3, and make node4, node5, node6 create inbound connections to node1. Then make node1 create outbound
	// connections to node7, node8, and make node9, node10 create inbound connections to node1.
	blsSeedPhrase1, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node1 := spawnValidatorNodeProtocol2(t, 18000, "node1", blsSeedPhrase1)
	node1.Config.TargetOutboundPeers = 0
	node1.Config.MaxInboundPeers = 1
	node1.Params.DialTimeout = 1 * time.Second
	node1.Params.VerackNegotiationTimeout = 1 * time.Second
	node1.Params.VersionNegotiationTimeout = 1 * time.Second

	blsSeedPhrase2, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node2 := spawnValidatorNodeProtocol2(t, 18001, "node2", blsSeedPhrase2)
	node2.Config.GlogV = 0
	blsSeedPhrase3, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node3 := spawnValidatorNodeProtocol2(t, 18002, "node3", blsSeedPhrase3)
	node3.Config.GlogV = 0
	blsSeedPhrase4, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsSeedPhrase4)
	node4.Config.GlogV = 0
	blsSeedPhrase5, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node5 := spawnValidatorNodeProtocol2(t, 18004, "node5", blsSeedPhrase5)
	node5.Config.GlogV = 0
	blsSeedPhrase6, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node6 := spawnValidatorNodeProtocol2(t, 18005, "node6", blsSeedPhrase6)
	node6.Config.GlogV = 0

	node7 := spawnNonValidatorNodeProtocol2(t, 18006, "node7")
	node8 := spawnNonValidatorNodeProtocol2(t, 18007, "node8")
	node9 := spawnNonValidatorNodeProtocol2(t, 18008, "node9")
	node10 := spawnNonValidatorNodeProtocol2(t, 18009, "node10")

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)
	node3 = startNode(t, node3)
	node4 = startNode(t, node4)
	node5 = startNode(t, node5)
	node6 = startNode(t, node6)
	node7 = startNode(t, node7)
	node8 = startNode(t, node8)
	node9 = startNode(t, node9)
	node10 = startNode(t, node10)

	// Connect node1 to node2, node3, node7, and node8.
	nm1 := node1.Server.GetNetworkManager()
	require.NoError(t, nm1.CreateNonValidatorOutboundConnection(node2.Listeners[0].Addr().String()))
	require.NoError(t, nm1.CreateNonValidatorOutboundConnection(node3.Listeners[0].Addr().String()))
	require.NoError(t, nm1.CreateNonValidatorOutboundConnection(node7.Listeners[0].Addr().String()))
	require.NoError(t, nm1.CreateNonValidatorOutboundConnection(node8.Listeners[0].Addr().String()))
	// Connect node4, node5, node6 to node1.
	nm4 := node4.Server.GetNetworkManager()
	require.NoError(t, nm4.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	nm5 := node5.Server.GetNetworkManager()
	require.NoError(t, nm5.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	nm6 := node6.Server.GetNetworkManager()
	require.NoError(t, nm6.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))

	// Connect node9, node10 to node1.
	nm9 := node9.Server.GetNetworkManager()
	require.NoError(t, nm9.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	nm10 := node10.Server.GetNetworkManager()
	require.NoError(t, nm10.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))

	activeValidatorsMap := getActiveValidatorsMapWithValidatorNodes(t, node1, node2, node3, node4, node5, node6)
	setActiveValidators(activeValidatorsMap, node1, node2, node3, node4, node5, node6, node7, node8, node9, node10)

	waitForValidatorConnection(t, node1, node2)
	waitForValidatorConnection(t, node1, node3)
	waitForValidatorConnection(t, node1, node4)
	waitForValidatorConnection(t, node1, node5)
	waitForValidatorConnection(t, node1, node6)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node1, 6, 5, 0, 1)
}

func TestConnectionControllerNonValidatorConnectorAddressMgr(t *testing.T) {
	// Spawn a non-validator node1. Set node1's targetOutboundPeers to 2 and targetInboundPeers to 0. Then
	// add two ip addresses to AddrMgr. Make sure that node1 creates outbound connections to these nodes.
	node1 := spawnNodeProtocol1(t, 18000, "node1")
	node1.Config.TargetOutboundPeers = 2
	node1.Config.MaxInboundPeers = 0
	node1.Config.MaxSyncBlockHeight = 1

	node1 = startNode(t, node1)
	nm := node1.Server.GetNetworkManager()
	na1, err := nm.ConvertIPStringToNetAddress("deso-seed-2.io:17000")
	require.NoError(t, err)
	nm.AddrMgr.AddAddress(na1, na1)
	waitForCountRemoteNodeIndexerHandshakeCompleted(t, node1, 1, 0, 1, 0)
}

func TestConnectionControllerNonValidatorConnectorAddIps(t *testing.T) {
	// Spawn a non-validator node1. Set node1's targetOutboundPeers to 2 and targetInboundPeers to 0. Then
	// add two ip addresses to the ConnectIPs. Make sure that node1 creates outbound connections to these nodes.
	node1 := spawnNodeProtocol1(t, 18000, "node1")
	node1.Config.TargetOutboundPeers = 2
	node1.Config.MaxInboundPeers = 0
	node1.Config.MaxSyncBlockHeight = 1
	node1.Config.AddIPs = []string{"deso-seed-2.io", "deso-seed-3.io"}

	node1 = startNode(t, node1)
	waitForCountRemoteNodeIndexer(t, node1, 2, 0, 2, 0)
}

func getActiveValidatorsMapWithValidatorNodes(t *testing.T, validators ...*cmd.Node) *collections.ConcurrentMap[bls.SerializedPublicKey, consensus.Validator] {
	mapping := collections.NewConcurrentMap[bls.SerializedPublicKey, consensus.Validator]()
	for _, validator := range validators {
		seed := validator.Config.PosValidatorSeed
		if seed == "" {
			t.Fatalf("Validator node %s does not have a PosValidatorSeed set", validator.Params.UserAgent)
		}
		keystore, err := lib.NewBLSKeystore(seed)
		require.NoError(t, err)
		mapping.Set(keystore.GetSigner().GetPublicKey().Serialize(), createSimpleValidatorEntry(validator))
	}
	return mapping
}

func setActiveValidators(validatorMap *collections.ConcurrentMap[bls.SerializedPublicKey, consensus.Validator], nodes ...*cmd.Node) {
	for _, node := range nodes {
		node.Server.GetNetworkManager().SetActiveValidatorsMap(validatorMap)
	}
}

func createSimpleValidatorEntry(node *cmd.Node) *lib.ValidatorEntry {
	return &lib.ValidatorEntry{
		Domains: [][]byte{[]byte(node.Listeners[0].Addr().String())},
	}
}

func waitForValidatorFullGraph(t *testing.T, validators ...*cmd.Node) {
	for ii := 0; ii < len(validators); ii++ {
		waitForValidatorConnectionOneWay(t, validators[ii], validators[ii+1:]...)
	}
}

func waitForValidatorConnectionOneWay(t *testing.T, n *cmd.Node, validators ...*cmd.Node) {
	if len(validators) == 0 {
		return
	}
	for _, validator := range validators {
		waitForValidatorConnection(t, n, validator)
	}
}

func waitForNonValidatorInboundXOROutboundConnection(t *testing.T, node1 *cmd.Node, node2 *cmd.Node) {
	userAgentN1 := node1.Params.UserAgent
	userAgentN2 := node2.Params.UserAgent
	conditionInbound := conditionNonValidatorInboundConnectionDynamic(t, node1, node2, true)
	conditionOutbound := conditionNonValidatorOutboundConnectionDynamic(t, node1, node2, true)
	xorCondition := func() bool {
		return conditionInbound() != conditionOutbound()
	}
	waitForCondition(t, fmt.Sprintf("Waiting for Node (%s) to connect to inbound XOR outbound non-validator Node (%s)",
		userAgentN1, userAgentN2), xorCondition)
}

func waitForMinNonValidatorCountRemoteNodeIndexer(t *testing.T, node *cmd.Node, allCount int, validatorCount int,
	minNonValidatorOutboundCount int, minNonValidatorInboundCount int) {

	userAgent := node.Params.UserAgent
	rnManager := node.Server.GetNetworkManager().GetRemoteNodeManager()
	condition := func() bool {
		return checkRemoteNodeIndexerMinNonValidatorCount(rnManager, allCount, validatorCount,
			minNonValidatorOutboundCount, minNonValidatorInboundCount)
	}
	waitForCondition(t, fmt.Sprintf("Waiting for Node (%s) to have at least %d non-validator outbound nodes and %d non-validator inbound nodes",
		userAgent, minNonValidatorOutboundCount, minNonValidatorInboundCount), condition)
}

func checkRemoteNodeIndexerMinNonValidatorCount(manager *lib.RemoteNodeManager, allCount int, validatorCount int,
	minNonValidatorOutboundCount int, minNonValidatorInboundCount int) bool {

	if allCount != manager.GetAllRemoteNodes().Count() {
		return false
	}
	if validatorCount != manager.GetValidatorIndex().Count() {
		return false
	}
	if minNonValidatorOutboundCount > manager.GetNonValidatorOutboundIndex().Count() {
		return false
	}
	if minNonValidatorInboundCount > manager.GetNonValidatorInboundIndex().Count() {
		return false
	}
	if allCount != manager.GetValidatorIndex().Count()+
		manager.GetNonValidatorOutboundIndex().Count()+
		manager.GetNonValidatorInboundIndex().Count() {
		return false
	}
	return true
}
