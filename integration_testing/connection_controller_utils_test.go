package integration_testing

import (
	"fmt"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"os"
	"testing"
	"time"
)

func waitForValidatorConnection(t *testing.T, node1 *cmd.Node, node2 *cmd.Node) {
	userAgentN1 := node1.Params.UserAgent
	userAgentN2 := node2.Params.UserAgent
	rnManagerN1 := node1.Server.GetConnectionController().GetRemoteNodeManager()
	n1ValidatedN2 := func() bool {
		if true != checkRemoteNodeIndexerUserAgent(rnManagerN1, userAgentN2, true, false, false) {
			return false
		}
		rnFromN2 := getRemoteNodeWithUserAgent(node1, userAgentN2)
		if rnFromN2 == nil {
			return false
		}
		if !rnFromN2.IsHandshakeCompleted() {
			return false
		}
		return true
	}
	waitForCondition(t, fmt.Sprintf("Waiting for Node (%s) to connect to validator Node (%s)", userAgentN1, userAgentN2), n1ValidatedN2)
}

func waitForNonValidatorOutboundConnection(t *testing.T, node1 *cmd.Node, node2 *cmd.Node) {
	userAgentN1 := node1.Params.UserAgent
	userAgentN2 := node2.Params.UserAgent
	condition := conditionNonValidatorOutboundConnection(t, node1, node2)
	waitForCondition(t, fmt.Sprintf("Waiting for Node (%s) to connect to outbound non-validator Node (%s)", userAgentN1, userAgentN2), condition)
}

func conditionNonValidatorOutboundConnection(t *testing.T, node1 *cmd.Node, node2 *cmd.Node) func() bool {
	return conditionNonValidatorOutboundConnectionDynamic(t, node1, node2, false)
}

func conditionNonValidatorOutboundConnectionDynamic(t *testing.T, node1 *cmd.Node, node2 *cmd.Node, inactiveValidator bool) func() bool {
	userAgentN2 := node2.Params.UserAgent
	rnManagerN1 := node1.Server.GetConnectionController().GetRemoteNodeManager()
	return func() bool {
		if true != checkRemoteNodeIndexerUserAgent(rnManagerN1, userAgentN2, false, true, false) {
			return false
		}
		rnFromN2 := getRemoteNodeWithUserAgent(node1, userAgentN2)
		if rnFromN2 == nil {
			return false
		}
		if !rnFromN2.IsHandshakeCompleted() {
			return false
		}
		// inactiveValidator should have the public key.
		if inactiveValidator {
			return rnFromN2.GetValidatorPublicKey() != nil
		}
		return rnFromN2.GetValidatorPublicKey() == nil
	}
}

func waitForNonValidatorInboundConnection(t *testing.T, node1 *cmd.Node, node2 *cmd.Node) {
	userAgentN1 := node1.Params.UserAgent
	userAgentN2 := node2.Params.UserAgent
	condition := conditionNonValidatorInboundConnection(t, node1, node2)
	waitForCondition(t, fmt.Sprintf("Waiting for Node (%s) to connect to inbound non-validator Node (%s)", userAgentN1, userAgentN2), condition)
}

func conditionNonValidatorInboundConnection(t *testing.T, node1 *cmd.Node, node2 *cmd.Node) func() bool {
	return conditionNonValidatorInboundConnectionDynamic(t, node1, node2, false)
}

func conditionNonValidatorInboundConnectionDynamic(t *testing.T, node1 *cmd.Node, node2 *cmd.Node, inactiveValidator bool) func() bool {
	userAgentN2 := node2.Params.UserAgent
	rnManagerN1 := node1.Server.GetConnectionController().GetRemoteNodeManager()
	return func() bool {
		if true != checkRemoteNodeIndexerUserAgent(rnManagerN1, userAgentN2, false, false, true) {
			return false
		}
		rnFromN2 := getRemoteNodeWithUserAgent(node1, userAgentN2)
		if rnFromN2 == nil {
			return false
		}
		if !rnFromN2.IsHandshakeCompleted() {
			return false
		}
		// inactiveValidator should have the public key.
		if inactiveValidator {
			return rnFromN2.GetValidatorPublicKey() != nil
		}
		return rnFromN2.GetValidatorPublicKey() == nil
	}
}

func waitForEmptyRemoteNodeIndexer(t *testing.T, node1 *cmd.Node) {
	userAgentN1 := node1.Params.UserAgent
	rnManagerN1 := node1.Server.GetConnectionController().GetRemoteNodeManager()
	n1ValidatedN2 := func() bool {
		if true != checkRemoteNodeIndexerEmpty(rnManagerN1) {
			return false
		}
		return true
	}
	waitForCondition(t, fmt.Sprintf("Waiting for Node (%s) to disconnect from all RemoteNodes", userAgentN1), n1ValidatedN2)
}

func waitForCountRemoteNodeIndexer(t *testing.T, node1 *cmd.Node, allCount int, validatorCount int,
	nonValidatorOutboundCount int, nonValidatorInboundCount int) {

	userAgent := node1.Params.UserAgent
	rnManager := node1.Server.GetConnectionController().GetRemoteNodeManager()
	condition := func() bool {
		if true != checkRemoteNodeIndexerCount(rnManager, allCount, validatorCount, nonValidatorOutboundCount, nonValidatorInboundCount) {
			return false
		}
		return true
	}
	waitForCondition(t, fmt.Sprintf("Waiting for Node (%s) to have appropriate RemoteNodes counts", userAgent), condition)
}

func checkRemoteNodeIndexerUserAgent(manager *lib.RemoteNodeManager, userAgent string, validator bool,
	nonValidatorOutbound bool, nonValidatorInbound bool) bool {

	if true != checkUserAgentInRemoteNodeList(userAgent, manager.GetAllRemoteNodes().GetAll()) {
		return false
	}
	if validator != checkUserAgentInRemoteNodeList(userAgent, manager.GetValidatorIndex().GetAll()) {
		return false
	}
	if nonValidatorOutbound != checkUserAgentInRemoteNodeList(userAgent, manager.GetNonValidatorOutboundIndex().GetAll()) {
		return false
	}
	if nonValidatorInbound != checkUserAgentInRemoteNodeList(userAgent, manager.GetNonValidatorInboundIndex().GetAll()) {
		return false
	}

	return true
}

func checkRemoteNodeIndexerCount(manager *lib.RemoteNodeManager, allCount int, validatorCount int,
	nonValidatorOutboundCount int, nonValidatorInboundCount int) bool {

	if allCount != manager.GetAllRemoteNodes().Count() {
		return false
	}
	if validatorCount != manager.GetValidatorIndex().Count() {
		return false
	}
	if nonValidatorOutboundCount != manager.GetNonValidatorOutboundIndex().Count() {
		return false
	}
	if nonValidatorInboundCount != manager.GetNonValidatorInboundIndex().Count() {
		return false
	}

	return true
}

func checkRemoteNodeIndexerEmpty(manager *lib.RemoteNodeManager) bool {
	if manager.GetAllRemoteNodes().Count() != 0 {
		return false
	}
	if manager.GetValidatorIndex().Count() != 0 {
		return false
	}
	if manager.GetNonValidatorOutboundIndex().Count() != 0 {
		return false
	}
	if manager.GetNonValidatorInboundIndex().Count() != 0 {
		return false
	}
	return true
}

func checkUserAgentInRemoteNodeList(userAgent string, rnList []*lib.RemoteNode) bool {
	for _, rn := range rnList {
		if rn == nil {
			continue
		}
		if rn.GetUserAgent() == userAgent {
			return true
		}
	}
	return false
}

func getRemoteNodeWithUserAgent(node *cmd.Node, userAgent string) *lib.RemoteNode {
	rnManager := node.Server.GetConnectionController().GetRemoteNodeManager()
	rnList := rnManager.GetAllRemoteNodes().GetAll()
	for _, rn := range rnList {
		if rn.GetUserAgent() == userAgent {
			return rn
		}
	}
	return nil
}

func spawnNonValidatorNodeProtocol2(t *testing.T, port uint32, id string) *cmd.Node {
	dbDir := getDirectory(t)
	t.Cleanup(func() {
		os.RemoveAll(dbDir)
	})
	config := generateConfig(t, port, dbDir, 10)
	config.SyncType = lib.NodeSyncTypeBlockSync
	node := cmd.NewNode(config)
	node.Params.UserAgent = id
	node.Params.ProtocolVersion = lib.ProtocolVersion2
	return node
}

func spawnValidatorNodeProtocol2(t *testing.T, port uint32, id string, blsPriv *bls.PrivateKey) *cmd.Node {
	dbDir := getDirectory(t)
	t.Cleanup(func() {
		os.RemoveAll(dbDir)
	})
	config := generateConfig(t, port, dbDir, 10)
	config.SyncType = lib.NodeSyncTypeBlockSync
	config.PosValidatorSeed = blsPriv.ToString()
	node := cmd.NewNode(config)
	node.Params.UserAgent = id
	node.Params.ProtocolVersion = lib.ProtocolVersion2
	node.Params.VersionNegotiationTimeout = 1 * time.Second
	node.Params.VerackNegotiationTimeout = 1 * time.Second
	return node
}
