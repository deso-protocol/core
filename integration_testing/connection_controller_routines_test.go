package integration_testing

import (
	"fmt"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestConnectionControllerInitiatePersistentConnections(t *testing.T) {
	require := require.New(t)
	t.Cleanup(func() {
		setGetActiveValidatorImpl(lib.BasicGetActiveValidators)
	})

	// NonValidator Node1 will set its --connect-ips to two non-validators node2 and node3,
	// and two validators node4 and node5.
	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node2 := spawnNonValidatorNodeProtocol2(t, 18001, "node2")
	node3 := spawnNonValidatorNodeProtocol2(t, 18002, "node3")
	blsPriv4, err := bls.NewPrivateKey()
	require.NoError(err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsPriv4)
	blsPriv5, err := bls.NewPrivateKey()
	require.NoError(err)
	node5 := spawnValidatorNodeProtocol2(t, 18004, "node5", blsPriv5)

	node2 = startNode(t, node2)
	node3 = startNode(t, node3)
	node4 = startNode(t, node4)
	node5 = startNode(t, node5)

	setGetActiveValidatorImplWithValidatorNodes(t, node4, node5)

	node1.Config.ConnectIPs = []string{
		node2.Listeners[0].Addr().String(),
		node3.Listeners[0].Addr().String(),
		node4.Listeners[0].Addr().String(),
		node5.Listeners[0].Addr().String(),
	}
	node1 = startNode(t, node1)
	waitForNonValidatorOutboundConnection(t, node1, node2)
	waitForNonValidatorOutboundConnection(t, node1, node3)
	waitForValidatorConnection(t, node1, node4)
	waitForValidatorConnection(t, node1, node5)
	waitForValidatorConnection(t, node4, node5)
	waitForCountRemoteNodeIndexer(t, node1, 4, 2, 2, 0)
	waitForCountRemoteNodeIndexer(t, node2, 1, 0, 0, 1)
	waitForCountRemoteNodeIndexer(t, node3, 1, 0, 0, 1)
	waitForCountRemoteNodeIndexer(t, node4, 2, 1, 0, 1)
	waitForCountRemoteNodeIndexer(t, node5, 2, 1, 0, 1)
	node1.Stop()
	t.Logf("Test #1 passed | Successfully run non-validator node1 with --connect-ips set to node2, node3, node4, node5")

	// Now try again with a validator node6, with connect-ips set to node2, node3, node4, node5.
	blsPriv6, err := bls.NewPrivateKey()
	require.NoError(err)
	node6 := spawnValidatorNodeProtocol2(t, 18005, "node6", blsPriv6)
	node6.Config.ConnectIPs = []string{
		node2.Listeners[0].Addr().String(),
		node3.Listeners[0].Addr().String(),
		node4.Listeners[0].Addr().String(),
		node5.Listeners[0].Addr().String(),
	}
	node6 = startNode(t, node6)
	setGetActiveValidatorImplWithValidatorNodes(t, node4, node5, node6)
	waitForNonValidatorOutboundConnection(t, node6, node2)
	waitForNonValidatorOutboundConnection(t, node6, node3)
	waitForValidatorConnection(t, node6, node4)
	waitForValidatorConnection(t, node6, node5)
	waitForValidatorConnection(t, node4, node5)
	waitForCountRemoteNodeIndexer(t, node6, 4, 2, 2, 0)
	waitForCountRemoteNodeIndexer(t, node2, 1, 1, 0, 0)
	waitForCountRemoteNodeIndexer(t, node3, 1, 1, 0, 0)
	waitForCountRemoteNodeIndexer(t, node4, 2, 2, 0, 0)
	waitForCountRemoteNodeIndexer(t, node5, 2, 2, 0, 0)
	node2.Stop()
	node3.Stop()
	node4.Stop()
	node5.Stop()
	node6.Stop()
	t.Logf("Test #2 passed | Successfully run validator node6 with --connect-ips set to node2, node3, node4, node5")
}

func TestConnectionControllerNonValidatorCircularConnectIps(t *testing.T) {
	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node2 := spawnNonValidatorNodeProtocol2(t, 18001, "node2")

	node1.Config.ConnectIPs = []string{"127.0.0.1:18001"}
	node2.Config.ConnectIPs = []string{"127.0.0.1:18000"}

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)
	defer node1.Stop()
	defer node2.Stop()

	waitForCountRemoteNodeIndexer(t, node1, 2, 0, 1, 1)
	waitForCountRemoteNodeIndexer(t, node2, 2, 0, 1, 1)
}

func setGetActiveValidatorImplWithValidatorNodes(t *testing.T, validators ...*cmd.Node) {
	require := require.New(t)

	mapping := collections.NewConcurrentMap[bls.SerializedPublicKey, *lib.ValidatorEntry]()
	for _, validator := range validators {
		seed := validator.Config.PosValidatorSeed
		if seed == "" {
			t.Fatalf("Validator node %s does not have a PosValidatorSeed set", validator.Params.UserAgent)
		}
		keystore, err := lib.NewBLSKeystore(seed)
		require.NoError(err)
		mapping.Set(keystore.GetSigner().GetPublicKey().Serialize(), createSimpleValidatorEntry(validator))
	}
	setGetActiveValidatorImpl(func() *collections.ConcurrentMap[bls.SerializedPublicKey, *lib.ValidatorEntry] {
		return mapping
	})
}

func setGetActiveValidatorImpl(mapping func() *collections.ConcurrentMap[bls.SerializedPublicKey, *lib.ValidatorEntry]) {
	lib.GetActiveValidatorImpl = mapping
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
	rnManager := node.Server.GetConnectionController().GetRemoteNodeManager()
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
