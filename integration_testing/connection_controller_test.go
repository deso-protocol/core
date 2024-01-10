package integration_testing

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestConnectionControllerNonValidator(t *testing.T) {
	require := require.New(t)

	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node1 = startNode(t, node1)
	defer node1.Stop()

	// Make sure NonValidator Node1 can create an outbound connection to NonValidator Node2
	node2 := spawnNonValidatorNodeProtocol2(t, 18001, "node2")
	node2 = startNode(t, node2)

	cc := node1.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node2.Listeners[0].Addr().String()))
	waitForNonValidatorOutboundConnection(t, node1, node2)
	waitForNonValidatorInboundConnection(t, node2, node1)

	node2.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #1 passed | Successfully created outbound connection from NonValidator Node1 to NonValidator Node2")

	// Make sure NonValidator Node1 can create an outbound connection to validator Node3
	blsPriv3, err := bls.NewPrivateKey()
	require.NoError(err)
	node3 := spawnValidatorNodeProtocol2(t, 18002, "node3", blsPriv3)
	node3 = startNode(t, node3)

	cc = node1.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node3.Listeners[0].Addr().String()))
	waitForValidatorConnection(t, node1, node3)
	waitForNonValidatorInboundConnection(t, node3, node1)

	node3.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #2 passed | Successfully created outbound connection from NonValidator Node1 to Validator Node3")

	// Make sure NonValidator Node1 can create a non-validator connection to validator Node4
	blsPriv4, err := bls.NewPrivateKey()
	require.NoError(err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsPriv4)
	node4 = startNode(t, node4)
	defer node4.Stop()

	cc = node1.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node4.Listeners[0].Addr().String()))
	waitForValidatorConnection(t, node1, node4)
	waitForNonValidatorInboundConnection(t, node4, node1)
	t.Logf("Test #3 passed | Successfully created outbound connection from NonValidator Node1 to Validator Node4")
}

func TestConnectionControllerValidator(t *testing.T) {
	require := require.New(t)

	blsPriv1, err := bls.NewPrivateKey()
	require.NoError(err)
	node1 := spawnValidatorNodeProtocol2(t, 18000, "node1", blsPriv1)
	node1 = startNode(t, node1)
	defer node1.Stop()

	// Make sure Validator Node1 can create an outbound connection to Validator Node2
	blsPriv2, err := bls.NewPrivateKey()
	blsPub2 := blsPriv2.PublicKey()
	require.NoError(err)
	node2 := spawnValidatorNodeProtocol2(t, 18001, "node2", blsPriv2)
	node2 = startNode(t, node2)

	cc := node1.Server.GetConnectionController()
	require.NoError(cc.CreateValidatorConnection(node2.Listeners[0].Addr().String(), blsPub2))
	waitForValidatorConnection(t, node1, node2)
	waitForValidatorConnection(t, node2, node1)

	node2.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #1 passed | Successfully created outbound connection from Validator Node1 to Validator Node2")

	// Make sure Validator Node1 can create an outbound connection to NonValidator Node3
	node3 := spawnNonValidatorNodeProtocol2(t, 18002, "node3")
	node3 = startNode(t, node3)

	cc = node1.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node3.Listeners[0].Addr().String()))
	waitForNonValidatorOutboundConnection(t, node1, node3)
	waitForValidatorConnection(t, node3, node1)

	node3.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #2 passed | Successfully created outbound connection from Validator Node1 to NonValidator Node3")

	// Make sure Validator Node1 can create an outbound non-validator connection to Validator Node4
	blsPriv4, err := bls.NewPrivateKey()
	require.NoError(err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsPriv4)
	node4 = startNode(t, node4)
	defer node4.Stop()

	cc = node1.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node4.Listeners[0].Addr().String()))
	waitForValidatorConnection(t, node1, node4)
	waitForValidatorConnection(t, node4, node1)
	t.Logf("Test #3 passed | Successfully created non-validator outbound connection from Validator Node1 to Validator Node4")
}

func TestConnectionControllerHandshakeDataErrors(t *testing.T) {
	require := require.New(t)

	blsPriv1, err := bls.NewPrivateKey()
	require.NoError(err)
	node1 := spawnValidatorNodeProtocol2(t, 18000, "node1", blsPriv1)

	// This node should have ProtocolVersion2, but it has ProtocolVersion1 as we want it to disconnect.
	blsPriv2, err := bls.NewPrivateKey()
	require.NoError(err)
	node2 := spawnValidatorNodeProtocol2(t, 18001, "node2", blsPriv2)
	node2.Params.ProtocolVersion = lib.ProtocolVersion1

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)
	defer node1.Stop()
	defer node2.Stop()

	cc := node2.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node2)
	t.Logf("Test #1 passed | Successfuly disconnected node with SFValidator flag and ProtocolVersion1 mismatch")

	// This node shouldn't have ProtocolVersion3, which is beyond latest ProtocolVersion2, meaning nodes should disconnect.
	blsPriv3, err := bls.NewPrivateKey()
	require.NoError(err)
	node3 := spawnValidatorNodeProtocol2(t, 18002, "node3", blsPriv3)
	node3.Params.ProtocolVersion = lib.ProtocolVersionType(3)
	node3 = startNode(t, node3)
	defer node3.Stop()

	cc = node1.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node3.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node3)
	t.Logf("Test #2 passed | Successfuly disconnected node with ProtocolVersion3")

	// This node shouldn't have ProtocolVersion0, which is outdated.
	node4 := spawnNonValidatorNodeProtocol2(t, 18003, "node4")
	node4.Params.ProtocolVersion = lib.ProtocolVersion0
	node4 = startNode(t, node4)
	defer node4.Stop()

	cc = node1.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node4.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node4)
	t.Logf("Test #3 passed | Successfuly disconnected node with ProtocolVersion0")

	// This node will have a different public key than the one it's supposed to have.
	blsPriv5, err := bls.NewPrivateKey()
	require.NoError(err)
	blsPriv5Wrong, err := bls.NewPrivateKey()
	require.NoError(err)
	node5 := spawnValidatorNodeProtocol2(t, 18004, "node5", blsPriv5)
	node5 = startNode(t, node5)
	defer node5.Stop()

	cc = node1.Server.GetConnectionController()
	require.NoError(cc.CreateValidatorConnection(node5.Listeners[0].Addr().String(), blsPriv5Wrong.PublicKey()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node5)
	t.Logf("Test #4 passed | Successfuly disconnected node with public key mismatch")

	// This node will be missing SFPosValidator flag while being connected as a validator.
	blsPriv6, err := bls.NewPrivateKey()
	require.NoError(err)
	node6 := spawnNonValidatorNodeProtocol2(t, 18005, "node6")
	node6 = startNode(t, node6)
	defer node6.Stop()

	cc = node1.Server.GetConnectionController()
	require.NoError(cc.CreateValidatorConnection(node6.Listeners[0].Addr().String(), blsPriv6.PublicKey()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node6)
	t.Logf("Test #5 passed | Successfuly disconnected supposed validator node with missing SFPosValidator flag")

	// This node will have ProtocolVersion1 and be connected as an outbound non-validator node.
	node7 := spawnNonValidatorNodeProtocol2(t, 18006, "node7")
	node7.Params.ProtocolVersion = lib.ProtocolVersion1
	node7 = startNode(t, node7)
	defer node7.Stop()

	cc = node1.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node7.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node7)
	t.Logf("Test #6 passed | Successfuly disconnected outbound non-validator node with ProtocolVersion1")
}

func TestConnectionControllerHandshakeTimeouts(t *testing.T) {
	require := require.New(t)

	// Set version negotiation timeout to 0 to make sure that the node will be disconnected
	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node1.Params.VersionNegotiationTimeout = 0
	node1 = startNode(t, node1)
	defer node1.Stop()

	node2 := spawnNonValidatorNodeProtocol2(t, 18001, "node2")
	node2 = startNode(t, node2)
	defer node2.Stop()

	cc := node1.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node2.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node2)
	t.Logf("Test #1 passed | Successfuly disconnected node after version negotiation timeout")

	// Now let's try timing out verack exchange
	node1.Params.VersionNegotiationTimeout = lib.DeSoTestnetParams.VersionNegotiationTimeout
	node3 := spawnNonValidatorNodeProtocol2(t, 18002, "node3")
	node3.Params.VerackNegotiationTimeout = 0
	node3 = startNode(t, node3)
	defer node3.Stop()

	cc = node3.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node3)
	t.Logf("Test #2 passed | Successfuly disconnected node after verack exchange timeout")

	// Now let's try timing out handshake between two validators node4 and node5
	blsPriv4, err := bls.NewPrivateKey()
	require.NoError(err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsPriv4)
	node4.Params.HandshakeTimeoutMicroSeconds = 0
	node4 = startNode(t, node4)
	defer node4.Stop()

	blsPriv5, err := bls.NewPrivateKey()
	require.NoError(err)
	node5 := spawnValidatorNodeProtocol2(t, 18004, "node5", blsPriv5)
	node5 = startNode(t, node5)
	defer node5.Stop()

	cc = node4.Server.GetConnectionController()
	require.NoError(cc.CreateValidatorConnection(node5.Listeners[0].Addr().String(), blsPriv5.PublicKey()))
	waitForEmptyRemoteNodeIndexer(t, node4)
	waitForEmptyRemoteNodeIndexer(t, node5)
	t.Logf("Test #3 passed | Successfuly disconnected validator node after handshake timeout")
}

func TestConnectionControllerValidatorDuplication(t *testing.T) {
	require := require.New(t)

	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node1 = startNode(t, node1)
	defer node1.Stop()

	// Create a validator Node2
	blsPriv2, err := bls.NewPrivateKey()
	require.NoError(err)
	node2 := spawnValidatorNodeProtocol2(t, 18001, "node2", blsPriv2)
	node2 = startNode(t, node2)

	// Create a duplicate validator Node3
	node3 := spawnValidatorNodeProtocol2(t, 18002, "node3", blsPriv2)
	node3 = startNode(t, node3)

	// Create validator connection from Node1 to Node2 and from Node1 to Node3
	cc := node1.Server.GetConnectionController()
	require.NoError(cc.CreateValidatorConnection(node2.Listeners[0].Addr().String(), blsPriv2.PublicKey()))
	// This should fail out right because Node3 has a duplicate public key.
	require.Error(cc.CreateValidatorConnection(node3.Listeners[0].Addr().String(), blsPriv2.PublicKey()))
	waitForValidatorConnection(t, node1, node2)
	waitForNonValidatorInboundConnection(t, node2, node1)

	// Now create an outbound connection from Node3 to Node1, which should pass handshake, but then fail because
	// Node1 already has a validator connection to Node2 with the same public key.
	cc3 := node3.Server.GetConnectionController()
	require.NoError(cc3.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node3)
	waitForCountRemoteNodeIndexer(t, node1, 1, 1, 0, 0)
	t.Logf("Test #1 passed | Successfuly rejected duplicate validator connection with inbound/outbound validators")

	node3.Stop()
	node2.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)

	// Create two more validators Node4, Node5 with duplicate public keys
	blsPriv4, err := bls.NewPrivateKey()
	require.NoError(err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsPriv4)
	node4 = startNode(t, node4)
	defer node4.Stop()

	node5 := spawnValidatorNodeProtocol2(t, 18004, "node5", blsPriv4)
	node5 = startNode(t, node5)
	defer node5.Stop()

	// Create validator connections from Node4 to Node1 and from Node5 to Node1
	cc4 := node4.Server.GetConnectionController()
	require.NoError(cc4.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	waitForValidatorConnection(t, node1, node4)
	waitForNonValidatorOutboundConnection(t, node4, node1)
	cc5 := node5.Server.GetConnectionController()
	require.NoError(cc5.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node5)
	waitForCountRemoteNodeIndexer(t, node1, 1, 1, 0, 0)
	t.Logf("Test #2 passed | Successfuly rejected duplicate validator connection with multiple outbound validators")
}

func TestConnectionControllerProtocolDifference(t *testing.T) {
	require := require.New(t)

	// Create a ProtocolVersion1 Node1
	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node1.Params.ProtocolVersion = lib.ProtocolVersion1
	node1 = startNode(t, node1)
	defer node1.Stop()

	// Create a ProtocolVersion2 NonValidator Node2
	node2 := spawnNonValidatorNodeProtocol2(t, 18001, "node2")
	node2 = startNode(t, node2)

	// Create non-validator connection from Node1 to Node2
	cc := node1.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node2.Listeners[0].Addr().String()))
	waitForNonValidatorOutboundConnection(t, node1, node2)
	waitForNonValidatorInboundConnection(t, node2, node1)
	t.Logf("Test #1 passed | Successfuly connected to a ProtocolVersion1 node with a ProtocolVersion2 non-validator")

	// Create a ProtocolVersion2 Validator Node3
	blsPriv3, err := bls.NewPrivateKey()
	require.NoError(err)
	node3 := spawnValidatorNodeProtocol2(t, 18002, "node3", blsPriv3)
	node3 = startNode(t, node3)

	// Create validator connection from Node1 to Node3
	require.NoError(cc.CreateValidatorConnection(node3.Listeners[0].Addr().String(), blsPriv3.PublicKey()))
	waitForValidatorConnection(t, node1, node3)
	waitForNonValidatorInboundConnection(t, node3, node1)
	t.Logf("Test #2 passed | Successfuly connected to a ProtocolVersion1 node with a ProtocolVersion2 validator")

	node2.Stop()
	node3.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)

	// Create a ProtocolVersion2 validator Node4
	blsPriv4, err := bls.NewPrivateKey()
	require.NoError(err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsPriv4)
	node4 = startNode(t, node4)
	defer node4.Stop()

	// Attempt to create non-validator connection from Node4 to Node1
	cc = node4.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node4)
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #3 passed | Successfuly rejected outbound connection from ProtocolVersion2 node to ProtcolVersion1 node")

	// Attempt to create validator connection from Node4 to Node1
	require.NoError(cc.CreateValidatorConnection(node1.Listeners[0].Addr().String(), blsPriv4.PublicKey()))
	waitForEmptyRemoteNodeIndexer(t, node4)
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #4 passed | Successfuly rejected validator connection from ProtocolVersion2 node to ProtcolVersion1 node")

	// Create a ProtocolVersion2 non-validator Node5
	node5 := spawnNonValidatorNodeProtocol2(t, 18004, "node5")
	node5 = startNode(t, node5)
	defer node5.Stop()

	// Attempt to create non-validator connection from Node5 to Node1
	cc = node5.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node5)
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #5 passed | Successfuly rejected outbound connection from ProtocolVersion2 node to ProtcolVersion1 node")
}

func TestConnectionControllerPersistentConnection(t *testing.T) {
	require := require.New(t)

	// Create a NonValidator Node1
	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node1 = startNode(t, node1)

	// Create a Validator Node2
	blsPriv2, err := bls.NewPrivateKey()
	require.NoError(err)
	node2 := spawnValidatorNodeProtocol2(t, 18001, "node2", blsPriv2)
	node2 = startNode(t, node2)

	// Create a persistent connection from Node1 to Node2
	cc := node1.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorPersistentOutboundConnection(node2.Listeners[0].Addr().String()))
	waitForValidatorConnection(t, node1, node2)
	waitForNonValidatorInboundConnection(t, node2, node1)
	node2.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #1 passed | Successfuly created persistent connection from non-validator Node1 to validator Node2")

	// Create a Non-validator Node3
	node3 := spawnNonValidatorNodeProtocol2(t, 18002, "node3")
	node3 = startNode(t, node3)

	// Create a persistent connection from Node1 to Node3
	require.NoError(cc.CreateNonValidatorPersistentOutboundConnection(node3.Listeners[0].Addr().String()))
	waitForNonValidatorOutboundConnection(t, node1, node3)
	waitForNonValidatorInboundConnection(t, node3, node1)
	node3.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)
	node1.Stop()
	t.Logf("Test #2 passed | Successfuly created persistent connection from non-validator Node1 to non-validator Node3")

	// Create a Validator Node4
	blsPriv4, err := bls.NewPrivateKey()
	require.NoError(err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsPriv4)
	node4 = startNode(t, node4)
	defer node4.Stop()

	// Create a non-validator Node5
	node5 := spawnNonValidatorNodeProtocol2(t, 18004, "node5")
	node5 = startNode(t, node5)

	// Create a persistent connection from Node4 to Node5
	cc = node4.Server.GetConnectionController()
	require.NoError(cc.CreateNonValidatorPersistentOutboundConnection(node5.Listeners[0].Addr().String()))
	waitForNonValidatorOutboundConnection(t, node4, node5)
	waitForValidatorConnection(t, node5, node4)
	node5.Stop()
	waitForEmptyRemoteNodeIndexer(t, node4)
	t.Logf("Test #3 passed | Successfuly created persistent connection from validator Node4 to non-validator Node5")

	// Create a Validator Node6
	blsPriv6, err := bls.NewPrivateKey()
	require.NoError(err)
	node6 := spawnValidatorNodeProtocol2(t, 18005, "node6", blsPriv6)
	node6 = startNode(t, node6)
	defer node6.Stop()

	// Create a persistent connection from Node4 to Node6
	require.NoError(cc.CreateNonValidatorPersistentOutboundConnection(node6.Listeners[0].Addr().String()))
	waitForValidatorConnection(t, node4, node6)
	waitForValidatorConnection(t, node6, node4)
	t.Logf("Test #4 passed | Successfuly created persistent connection from validator Node4 to validator Node6")
}
