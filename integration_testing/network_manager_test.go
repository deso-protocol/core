package integration_testing

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
	"github.com/tyler-smith/go-bip39"
	"testing"
)

func TestConnectionControllerNonValidator(t *testing.T) {
	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node1.Params.DisableNetworkManagerRoutines = true
	node1 = startNode(t, node1)

	// Make sure NonValidator Node1 can create an outbound connection to NonValidator Node2
	node2 := spawnNonValidatorNodeProtocol2(t, 18001, "node2")
	node2.Params.DisableNetworkManagerRoutines = true
	node2 = startNode(t, node2)

	nm := node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node2.Listeners[0].Addr().String()))
	waitForNonValidatorOutboundConnection(t, node1, node2)
	waitForNonValidatorInboundConnection(t, node2, node1)

	node2.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #1 passed | Successfully created outbound connection from NonValidator Node1 to NonValidator Node2")

	// Make sure NonValidator Node1 can create an outbound connection to validator Node3
	blsSeedPhrase3, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node3 := spawnValidatorNodeProtocol2(t, 18002, "node3", blsSeedPhrase3)
	node3.Params.DisableNetworkManagerRoutines = true
	node3 = startNode(t, node3)

	nm = node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node3.Listeners[0].Addr().String()))
	waitForValidatorConnection(t, node1, node3)
	waitForNonValidatorInboundConnection(t, node3, node1)

	node3.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #2 passed | Successfully created outbound connection from NonValidator Node1 to Validator Node3")

	// Make sure NonValidator Node1 can create a non-validator connection to validator Node4
	blsSeedPhrase4, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsSeedPhrase4)
	node4.Params.DisableNetworkManagerRoutines = true
	node4 = startNode(t, node4)

	nm = node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node4.Listeners[0].Addr().String()))
	waitForValidatorConnection(t, node1, node4)
	waitForNonValidatorInboundConnection(t, node4, node1)
	t.Logf("Test #3 passed | Successfully created outbound connection from NonValidator Node1 to Validator Node4")
}

func TestConnectionControllerValidator(t *testing.T) {
	blsSeedPhrase1, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node1 := spawnValidatorNodeProtocol2(t, 18000, "node1", blsSeedPhrase1)
	node1.Params.DisableNetworkManagerRoutines = true
	node1 = startNode(t, node1)

	// Make sure Validator Node1 can create an outbound connection to Validator Node2
	blsSeedPhrase2, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	blsKeyStore2, err := lib.NewBLSKeystore(blsSeedPhrase2)
	require.NoError(t, err)
	blsPub2 := blsKeyStore2.GetSigner().GetPublicKey()
	node2 := spawnValidatorNodeProtocol2(t, 18001, "node2", blsSeedPhrase2)
	node2.Params.DisableNetworkManagerRoutines = true
	node2 = startNode(t, node2)

	nm := node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateValidatorConnection(node2.Listeners[0].Addr().String(), blsPub2))
	waitForValidatorConnection(t, node1, node2)
	waitForValidatorConnection(t, node2, node1)

	node2.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #1 passed | Successfully created outbound connection from Validator Node1 to Validator Node2")

	// Make sure Validator Node1 can create an outbound connection to NonValidator Node3
	node3 := spawnNonValidatorNodeProtocol2(t, 18002, "node3")
	node3.Params.DisableNetworkManagerRoutines = true
	node3 = startNode(t, node3)

	nm = node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node3.Listeners[0].Addr().String()))
	waitForNonValidatorOutboundConnection(t, node1, node3)
	waitForValidatorConnection(t, node3, node1)

	node3.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #2 passed | Successfully created outbound connection from Validator Node1 to NonValidator Node3")

	// Make sure Validator Node1 can create an outbound non-validator connection to Validator Node4
	blsSeedPhrase4, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsSeedPhrase4)
	node4.Params.DisableNetworkManagerRoutines = true
	node4 = startNode(t, node4)

	nm = node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node4.Listeners[0].Addr().String()))
	waitForValidatorConnection(t, node1, node4)
	waitForValidatorConnection(t, node4, node1)
	t.Logf("Test #3 passed | Successfully created non-validator outbound connection from Validator Node1 to Validator Node4")
}

func TestConnectionControllerHandshakeDataErrors(t *testing.T) {
	blsSeedPhrase1, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node1 := spawnValidatorNodeProtocol2(t, 18000, "node1", blsSeedPhrase1)
	node1.Params.DisableNetworkManagerRoutines = true

	// This node should have ProtocolVersion2, but it has ProtocolVersion1 as we want it to disconnect.
	blsSeedPhrase2, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node2 := spawnValidatorNodeProtocol2(t, 18001, "node2", blsSeedPhrase2)
	node2.Params.DisableNetworkManagerRoutines = true
	node2.Params.ProtocolVersion = lib.ProtocolVersion1

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)

	nm := node2.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node2)
	t.Logf("Test #1 passed | Successfuly disconnected node with SFValidator flag and ProtocolVersion1 mismatch")

	// This node shouldn't have ProtocolVersion3, which is beyond latest ProtocolVersion2, meaning nodes should disconnect.
	blsSeedPhrase3, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node3 := spawnValidatorNodeProtocol2(t, 18002, "node3", blsSeedPhrase3)
	node3.Params.DisableNetworkManagerRoutines = true
	node3.Params.ProtocolVersion = lib.ProtocolVersionType(3)
	node3 = startNode(t, node3)

	nm = node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node3.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node3)
	t.Logf("Test #2 passed | Successfuly disconnected node with ProtocolVersion3")

	// This node shouldn't have ProtocolVersion0, which is outdated.
	node4 := spawnNonValidatorNodeProtocol2(t, 18003, "node4")
	node4.Params.DisableNetworkManagerRoutines = true
	node4.Params.ProtocolVersion = lib.ProtocolVersion0
	node4 = startNode(t, node4)

	nm = node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node4.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node4)
	t.Logf("Test #3 passed | Successfuly disconnected node with ProtocolVersion0")

	// This node will have a different public key than the one it's supposed to have.
	blsSeedPhrase5, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	blsSeedPhrase5Wrong, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	blsKeyStore5Wrong, err := lib.NewBLSKeystore(blsSeedPhrase5Wrong)
	require.NoError(t, err)
	node5 := spawnValidatorNodeProtocol2(t, 18004, "node5", blsSeedPhrase5)
	node5.Params.DisableNetworkManagerRoutines = true
	node5 = startNode(t, node5)

	nm = node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateValidatorConnection(node5.Listeners[0].Addr().String(), blsKeyStore5Wrong.GetSigner().GetPublicKey()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node5)
	t.Logf("Test #4 passed | Successfuly disconnected node with public key mismatch")

	// This node will be missing SFPosValidator flag while being connected as a validator.
	blsPriv6, err := bls.NewPrivateKey()
	require.NoError(t, err)
	node6 := spawnNonValidatorNodeProtocol2(t, 18005, "node6")
	node6.Params.DisableNetworkManagerRoutines = true
	node6 = startNode(t, node6)

	nm = node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateValidatorConnection(node6.Listeners[0].Addr().String(), blsPriv6.PublicKey()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node6)
	t.Logf("Test #5 passed | Successfuly disconnected supposed validator node with missing SFPosValidator flag")

	// This node will have ProtocolVersion1 and be connected as an outbound non-validator node.
	node7 := spawnNonValidatorNodeProtocol2(t, 18006, "node7")
	node7.Params.DisableNetworkManagerRoutines = true
	node7.Params.ProtocolVersion = lib.ProtocolVersion1
	node7 = startNode(t, node7)

	nm = node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node7.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node7)
	t.Logf("Test #6 passed | Successfuly disconnected outbound non-validator node with ProtocolVersion1")
}

func TestConnectionControllerHandshakeTimeouts(t *testing.T) {
	// Set version negotiation timeout to 0 to make sure that the node will be disconnected
	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node1.Params.DisableNetworkManagerRoutines = true
	node1.Params.VersionNegotiationTimeout = 0
	node1 = startNode(t, node1)

	node2 := spawnNonValidatorNodeProtocol2(t, 18001, "node2")
	node2.Params.DisableNetworkManagerRoutines = true
	node2 = startNode(t, node2)

	nm := node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node2.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node2)
	t.Logf("Test #1 passed | Successfuly disconnected node after version negotiation timeout")

	// Now let's try timing out verack exchange
	node1.Params.VersionNegotiationTimeout = lib.DeSoTestnetParams.VersionNegotiationTimeout
	node3 := spawnNonValidatorNodeProtocol2(t, 18002, "node3")
	node3.Params.DisableNetworkManagerRoutines = true
	node3.Params.VerackNegotiationTimeout = 0
	node3 = startNode(t, node3)

	nm = node3.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node1)
	waitForEmptyRemoteNodeIndexer(t, node3)
	t.Logf("Test #2 passed | Successfuly disconnected node after verack exchange timeout")

	// Now let's try timing out handshake between two validators node4 and node5
	blsSeedPhrase4, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsSeedPhrase4)
	node4.Params.DisableNetworkManagerRoutines = true
	node4.Params.HandshakeTimeoutMicroSeconds = 0
	node4 = startNode(t, node4)

	blsSeedPhrase5, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	blsKeyStore5, err := lib.NewBLSKeystore(blsSeedPhrase5)
	require.NoError(t, err)
	node5 := spawnValidatorNodeProtocol2(t, 18004, "node5", blsSeedPhrase5)
	node5.Params.DisableNetworkManagerRoutines = true
	node5 = startNode(t, node5)

	nm = node4.Server.GetNetworkManager()
	require.NoError(t, nm.CreateValidatorConnection(node5.Listeners[0].Addr().String(), blsKeyStore5.GetSigner().GetPublicKey()))
	waitForEmptyRemoteNodeIndexer(t, node4)
	waitForEmptyRemoteNodeIndexer(t, node5)
	t.Logf("Test #3 passed | Successfuly disconnected validator node after handshake timeout")
}

func TestConnectionControllerValidatorDuplication(t *testing.T) {
	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node1.Params.DisableNetworkManagerRoutines = true
	node1 = startNode(t, node1)

	// Create a validator Node2
	blsSeedPhrase2, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	blsKeyStore2, err := lib.NewBLSKeystore(blsSeedPhrase2)
	require.NoError(t, err)
	node2 := spawnValidatorNodeProtocol2(t, 18001, "node2", blsSeedPhrase2)
	node2.Params.DisableNetworkManagerRoutines = true
	node2 = startNode(t, node2)

	// Create a duplicate validator Node3
	node3 := spawnValidatorNodeProtocol2(t, 18002, "node3", blsSeedPhrase2)
	node3.Params.DisableNetworkManagerRoutines = true
	node3 = startNode(t, node3)

	// Create validator connection from Node1 to Node2 and from Node1 to Node3
	nm := node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateValidatorConnection(node2.Listeners[0].Addr().String(), blsKeyStore2.GetSigner().GetPublicKey()))
	// This should fail out right because Node3 has a duplicate public key.
	require.Error(t, nm.CreateValidatorConnection(node3.Listeners[0].Addr().String(), blsKeyStore2.GetSigner().GetPublicKey()))
	waitForValidatorConnection(t, node1, node2)
	waitForNonValidatorInboundConnection(t, node2, node1)

	// Now create an outbound connection from Node1 to Node3, which should pass handshake.
	nm3 := node3.Server.GetNetworkManager()
	require.NoError(t, nm3.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	waitForCountRemoteNodeIndexer(t, node1, 2, 1, 0, 0)
	t.Logf("Test #1 passed | Successfuly connected to inbound/outbound validators")

	node3.Stop()
	node2.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)

	// Create two more validators Node4, Node5 with duplicate public keys
	blsSeedPhrase4, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsSeedPhrase4)
	node4.Params.DisableNetworkManagerRoutines = true
	node4 = startNode(t, node4)

	node5 := spawnValidatorNodeProtocol2(t, 18004, "node5", blsSeedPhrase4)
	node5.Params.DisableNetworkManagerRoutines = true
	node5 = startNode(t, node5)

	// Create validator connections from Node4 to Node1 and from Node5 to Node1
	nm4 := node4.Server.GetNetworkManager()
	require.NoError(t, nm4.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	waitForValidatorConnection(t, node1, node4)
	waitForNonValidatorOutboundConnection(t, node4, node1)
	nm5 := node5.Server.GetNetworkManager()
	require.NoError(t, nm5.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node5)
	waitForCountRemoteNodeIndexer(t, node1, 1, 1, 0, 0)
	t.Logf("Test #2 passed | Successfuly rejected duplicate validator connection with multiple outbound validators")
}

func TestConnectionControllerProtocolDifference(t *testing.T) {
	// Create a ProtocolVersion1 Node1
	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node1.Params.DisableNetworkManagerRoutines = true
	node1.Params.ProtocolVersion = lib.ProtocolVersion1
	node1 = startNode(t, node1)

	// Create a ProtocolVersion2 NonValidator Node2
	node2 := spawnNonValidatorNodeProtocol2(t, 18001, "node2")
	node2.Params.DisableNetworkManagerRoutines = true
	node2 = startNode(t, node2)

	// Create non-validator connection from Node1 to Node2
	nm := node1.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node2.Listeners[0].Addr().String()))
	waitForNonValidatorOutboundConnection(t, node1, node2)
	waitForNonValidatorInboundConnection(t, node2, node1)
	t.Logf("Test #1 passed | Successfuly connected to a ProtocolVersion1 node with a ProtocolVersion2 non-validator")

	// Create a ProtocolVersion2 Validator Node3
	blsSeedPhrase3, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	blsKeyStore3, err := lib.NewBLSKeystore(blsSeedPhrase3)
	require.NoError(t, err)
	node3 := spawnValidatorNodeProtocol2(t, 18002, "node3", blsSeedPhrase3)
	node3.Params.DisableNetworkManagerRoutines = true
	node3 = startNode(t, node3)

	// Create validator connection from Node1 to Node3
	require.NoError(t, nm.CreateValidatorConnection(node3.Listeners[0].Addr().String(), blsKeyStore3.GetSigner().GetPublicKey()))
	waitForValidatorConnection(t, node1, node3)
	waitForNonValidatorInboundConnection(t, node3, node1)
	t.Logf("Test #2 passed | Successfuly connected to a ProtocolVersion1 node with a ProtocolVersion2 validator")

	node2.Stop()
	node3.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)

	// Create a ProtocolVersion2 validator Node4
	blsSeedPhrase4, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	blsKeyStore4, err := lib.NewBLSKeystore(blsSeedPhrase4)
	require.NoError(t, err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsSeedPhrase4)
	node4.Params.DisableNetworkManagerRoutines = true
	node4 = startNode(t, node4)

	// Attempt to create non-validator connection from Node4 to Node1
	nm = node4.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node4)
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #3 passed | Successfuly rejected outbound connection from ProtocolVersion2 node to ProtcolVersion1 node")

	// Attempt to create validator connection from Node4 to Node1
	require.NoError(t, nm.CreateValidatorConnection(node1.Listeners[0].Addr().String(), blsKeyStore4.GetSigner().GetPublicKey()))
	waitForEmptyRemoteNodeIndexer(t, node4)
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #4 passed | Successfuly rejected validator connection from ProtocolVersion2 node to ProtcolVersion1 node")

	// Create a ProtocolVersion2 non-validator Node5
	node5 := spawnNonValidatorNodeProtocol2(t, 18004, "node5")
	node5.Params.DisableNetworkManagerRoutines = true
	node5 = startNode(t, node5)

	// Attempt to create non-validator connection from Node5 to Node1
	nm = node5.Server.GetNetworkManager()
	require.NoError(t, nm.CreateNonValidatorOutboundConnection(node1.Listeners[0].Addr().String()))
	waitForEmptyRemoteNodeIndexer(t, node5)
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #5 passed | Successfuly rejected outbound connection from ProtocolVersion2 node to ProtcolVersion1 node")
}

func TestConnectionControllerPersistentConnection(t *testing.T) {
	// Create a NonValidator Node1
	node1 := spawnNonValidatorNodeProtocol2(t, 18000, "node1")
	node1.Params.DisableNetworkManagerRoutines = true
	node1 = startNode(t, node1)

	// Create a Validator Node2
	blsSeedPhrase2, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node2 := spawnValidatorNodeProtocol2(t, 18001, "node2", blsSeedPhrase2)
	node2.Params.DisableNetworkManagerRoutines = true
	node2 = startNode(t, node2)

	// Create a persistent connection from Node1 to Node2
	nm := node1.Server.GetNetworkManager()
	_, err = nm.CreateNonValidatorPersistentOutboundConnection(node2.Listeners[0].Addr().String())
	require.NoError(t, err)
	waitForValidatorConnection(t, node1, node2)
	waitForNonValidatorInboundConnection(t, node2, node1)
	node2.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)
	t.Logf("Test #1 passed | Successfuly created persistent connection from non-validator Node1 to validator Node2")

	// Create a Non-validator Node3
	node3 := spawnNonValidatorNodeProtocol2(t, 18002, "node3")
	node3.Params.DisableNetworkManagerRoutines = true
	node3 = startNode(t, node3)

	// Create a persistent connection from Node1 to Node3
	_, err = nm.CreateNonValidatorPersistentOutboundConnection(node3.Listeners[0].Addr().String())
	require.NoError(t, err)
	waitForNonValidatorOutboundConnection(t, node1, node3)
	waitForNonValidatorInboundConnection(t, node3, node1)
	node3.Stop()
	waitForEmptyRemoteNodeIndexer(t, node1)
	node1.Stop()
	t.Logf("Test #2 passed | Successfuly created persistent connection from non-validator Node1 to non-validator Node3")

	// Create a Validator Node4
	blsSeedPhrase4, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node4 := spawnValidatorNodeProtocol2(t, 18003, "node4", blsSeedPhrase4)
	node4.Params.DisableNetworkManagerRoutines = true
	node4 = startNode(t, node4)

	// Create a non-validator Node5
	node5 := spawnNonValidatorNodeProtocol2(t, 18004, "node5")
	node5.Params.DisableNetworkManagerRoutines = true
	node5 = startNode(t, node5)

	// Create a persistent connection from Node4 to Node5
	nm = node4.Server.GetNetworkManager()
	_, err = nm.CreateNonValidatorPersistentOutboundConnection(node5.Listeners[0].Addr().String())
	require.NoError(t, err)
	waitForNonValidatorOutboundConnection(t, node4, node5)
	waitForValidatorConnection(t, node5, node4)
	node5.Stop()
	waitForEmptyRemoteNodeIndexer(t, node4)
	t.Logf("Test #3 passed | Successfuly created persistent connection from validator Node4 to non-validator Node5")

	// Create a Validator Node6
	blsSeedPhrase6, err := bip39.NewMnemonic(lib.RandomBytes(32))
	require.NoError(t, err)
	node6 := spawnValidatorNodeProtocol2(t, 18005, "node6", blsSeedPhrase6)
	node6.Params.DisableNetworkManagerRoutines = true
	node6 = startNode(t, node6)

	// Create a persistent connection from Node4 to Node6
	_, err = nm.CreateNonValidatorPersistentOutboundConnection(node6.Listeners[0].Addr().String())
	require.NoError(t, err)
	waitForValidatorConnection(t, node4, node6)
	waitForValidatorConnection(t, node6, node4)
	t.Logf("Test #4 passed | Successfuly created persistent connection from validator Node4 to validator Node6")
}
