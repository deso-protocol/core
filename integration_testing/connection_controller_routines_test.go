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

func TestConnectionControllerValidatorConnector(t *testing.T) {
	require := require.New(t)
	t.Cleanup(func() {
		setGetActiveValidatorImpl(lib.BasicGetActiveValidators)
	})

	// Spawn 5 validators node1, node2, node3, node4, node5 and two non-validators node6 and node7.
	// All the validators are initially in the validator set. And later, node1 and node2 will be removed from the
	// validator set. Then, make node3 inactive, and node2 active again. Then, make all the validators inactive.
	// Make node6, and node7 connect-ips to all the validators.

	blsPriv1, err := bls.NewPrivateKey()
	require.NoError(err)
	node1 := spawnValidatorNodeProtocol2(t, 18000, "node1", blsPriv1)
	blsPriv2, err := bls.NewPrivateKey()
	require.NoError(err)
	node2 := spawnValidatorNodeProtocol2(t, 18001, "node2", blsPriv2)
	blsPriv3, err := bls.NewPrivateKey()
	require.NoError(err)
	node3 := spawnValidatorNodeProtocol2(t, 18002, "node3", blsPriv3)
	blsPriv4, err := bls.NewPrivateKey()
	require.NoError(err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsPriv4)
	blsPriv5, err := bls.NewPrivateKey()
	require.NoError(err)
	node5 := spawnValidatorNodeProtocol2(t, 18004, "node5", blsPriv5)

	node6 := spawnNonValidatorNodeProtocol2(t, 18005, "node6")
	node7 := spawnNonValidatorNodeProtocol2(t, 18006, "node7")

	node1 = startNode(t, node1)
	defer node1.Stop()
	node2 = startNode(t, node2)
	defer node2.Stop()
	node3 = startNode(t, node3)
	defer node3.Stop()
	node4 = startNode(t, node4)
	defer node4.Stop()
	node5 = startNode(t, node5)
	defer node5.Stop()
	setGetActiveValidatorImplWithValidatorNodes(t, node1, node2, node3, node4, node5)

	node6.Config.ConnectIPs = []string{
		node1.Listeners[0].Addr().String(),
		node2.Listeners[0].Addr().String(),
		node3.Listeners[0].Addr().String(),
		node4.Listeners[0].Addr().String(),
		node5.Listeners[0].Addr().String(),
	}
	node7.Config.ConnectIPs = node6.Config.ConnectIPs
	node6 = startNode(t, node6)
	defer node6.Stop()
	node7 = startNode(t, node7)
	defer node7.Stop()

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
	setGetActiveValidatorImplWithValidatorNodes(t, node3, node4, node5)
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
	waitForCountRemoteNodeIndexer(t, node6, 5, 3, 2, 0)
	waitForCountRemoteNodeIndexer(t, node7, 5, 3, 2, 0)
	t.Logf("Test #2 passed | Successfully run validators node3, node4, node5; inactive-validators node1, node2; " +
		"non-validators node6, node7")

	// Remove node3 from the validator set. Make node1 active again.
	setGetActiveValidatorImplWithValidatorNodes(t, node1, node4, node5)
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
	waitForCountRemoteNodeIndexer(t, node6, 5, 3, 2, 0)
	waitForCountRemoteNodeIndexer(t, node7, 5, 3, 2, 0)
	t.Logf("Test #3 passed | Successfully run validators node1, node4, node5; inactive validators node2, node3; " +
		"non-validators node6, node7")

	// Make all validators inactive.
	setGetActiveValidatorImplWithValidatorNodes(t)
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
	waitForCountRemoteNodeIndexer(t, node6, 5, 0, 5, 0)
	waitForCountRemoteNodeIndexer(t, node7, 5, 0, 5, 0)
	t.Logf("Test #4 passed | Successfully run inactive validators node1, node2, node3, node4, node5; " +
		"non-validators node6, node7")
}

func TestConnectionControllerValidatorInboundDeduplication(t *testing.T) {
	require := require.New(t)
	t.Cleanup(func() {
		setGetActiveValidatorImpl(lib.BasicGetActiveValidators)
	})

	// Spawn a non-validator node1, and two validators node2, node3. The validator nodes will have the same public key.
	// Node2 and node3 will not initially be in the validator set. First, node2 will start an outbound connection to
	// node1. We wait until the node2 is re-indexed as non-validator by node1, and then we make node3 open an outbound
	// connection to node1. We wait until node3 is re-indexed as non-validator by node1. Then, we make node2 and node3
	// join the validator set (i.e. add one entry with the duplicated public key). Now, node1 should disconnect from
	// either node2 or node3 because of duplicate public key.

	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	blsPriv2, err := bls.NewPrivateKey()
	require.NoError(err)
	node2 := spawnValidatorNodeProtocol2(t, 18001, "node2", blsPriv2)
	node3 := spawnValidatorNodeProtocol2(t, 18002, "node3", blsPriv2)

	node1 = startNode(t, node1)
	defer node1.Stop()
	node2 = startNode(t, node2)
	defer node2.Stop()
	node3 = startNode(t, node3)
	defer node3.Stop()

	cc2 := node2.Server.GetConnectionController()
	require.NoError(cc2.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	// First wait for node2 to be indexed as a validator by node1.
	waitForValidatorConnection(t, node1, node2)
	// Now wait for node2 to be re-indexed as a non-validator.
	waitForNonValidatorInboundConnectionDynamic(t, node1, node2, true)
	waitForNonValidatorOutboundConnection(t, node2, node1)

	// Now connect node3 to node1.
	cc3 := node3.Server.GetConnectionController()
	require.NoError(cc3.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	// First wait for node3 to be indexed as a validator by node1.
	waitForValidatorConnection(t, node1, node3)
	// Now wait for node3 to be re-indexed as a non-validator.
	waitForNonValidatorInboundConnectionDynamic(t, node1, node3, true)
	waitForNonValidatorOutboundConnection(t, node3, node1)

	// Now add node2 and node3 to the validator set.
	setGetActiveValidatorImplWithValidatorNodes(t, node2)
	// Now wait for node1 to disconnect from either node2 or node3.
	waitForCountRemoteNodeIndexer(t, node1, 1, 1, 0, 0)
	t.Logf("Test #1 passed | Successfully run non-validator node1; validators node2, node3 with duplicate public key")
}

func TestConnectionControllerNonValidatorConnector(t *testing.T) {
	require := require.New(t)

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
	defer node2.Stop()
	node3 = startNode(t, node3)
	defer node3.Stop()
	node4 = startNode(t, node4)
	defer node4.Stop()
	node5 = startNode(t, node5)
	defer node5.Stop()
	node6 = startNode(t, node6)
	defer node6.Stop()

	node1.Config.ConnectIPs = []string{
		node2.Listeners[0].Addr().String(),
		node3.Listeners[0].Addr().String(),
		node4.Listeners[0].Addr().String(),
	}
	node1 = startNode(t, node1)
	defer node1.Stop()

	cc := node1.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node5.Listeners[0].Addr().String()))
	require.NoError(cc.CreateNonValidatorOutboundConnection(node6.Listeners[0].Addr().String()))

	waitForCountRemoteNodeIndexer(t, node1, 3, 0, 3, 0)
	waitForNonValidatorOutboundConnection(t, node1, node2)
	waitForNonValidatorOutboundConnection(t, node1, node3)
	waitForNonValidatorOutboundConnection(t, node1, node4)
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
