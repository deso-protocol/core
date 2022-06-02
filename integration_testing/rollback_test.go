package testing

import (
	"github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
	"os"
	"reflect"
	"testing"
)

// Start blocks to height 5000 and then disconnect
func TestStateRollback(t *testing.T) {
	require := require.New(t)
	_ = require

	dbDir1 := getDirectory(t)
	dbDir2 := getDirectory(t)
	defer os.RemoveAll(dbDir1)
	defer os.RemoveAll(dbDir2)

	config1 := generateConfig(t, 18000, dbDir1, 10)
	config1.SyncType = lib.NodeSyncTypeBlockSync
	config2 := generateConfig(t, 18001, dbDir2, 10)
	config2.SyncType = lib.NodeSyncTypeBlockSync

	config1.MaxSyncBlockHeight = 5000
	config2.MaxSyncBlockHeight = 5689
	config1.HyperSync = true
	config2.HyperSync = true
	config1.ConnectIPs = []string{"deso-seed-2.io:17000"}
	config2.ConnectIPs = []string{"deso-seed-2.io:17000"}

	node1 := cmd.NewNode(config1)
	node2 := cmd.NewNode(config2)

	node1 = startNode(t, node1)
	node2 = startNode(t, node2)

	// wait for node1, node2 to sync blocks
	waitForNodeToFullySync(node1)
	waitForNodeToFullySync(node2)

	/* This code is no longer needed, but it was really useful in testing disconnect. Basically it goes transaction by
	transaction and compares that connecting/disconnecting the transaction gives the same state at the end. The check
	on the state is pretty hardcore. We checksum the entire database before the first connect and then compare it
	to the checksum of the db after applying the connect/disconnect. */

	//bestChain := node2.Server.GetBlockchain().BestChain()
	//lastNode := bestChain[len(bestChain)-1]
	//lastBlock, err := lib.GetBlock(lastNode.Hash, node2.Server.GetBlockchain().DB(), nil)
	//require.NoError(err)
	//height := lastBlock.Header.Height
	//_, txHashes, err := lib.ComputeMerkleRoot(lastBlock.Txns)
	//require.NoError(err)
	//
	//utxoOps := [][]*lib.UtxoOperation{}
	////howMany := 3
	//initialChecksum := computeNodeStateChecksum(t, node1, height)
	//checksumsBeforeTransactions := []*lib.StateChecksum{initialChecksum}
	////I0404 20:00:03.139818   76191 run_test.go:1280] checksumAfterTransactionBytes: ([8 89 214 239 199 116 26 139 218 1 24 67 190 194 178 16 137 186 76 7 124 98 185 77 198 214 201 50 248 152 75 4]), current txIndex (0), current txn (< TxHash: 4be39648eba47f54baa62e77e2423d57d12ed779d5e4b0044064a99ed5ba18b0, TxnType: BLOCK_REWARD, PubKey: 8mkU8yaVLs >)
	////I0404 20:00:06.246344   76191 run_test.go:1280] checksumAfterTransactionBytes: ([26 238 98 178 174 72 123 173 5 191 100 244 94 58 94 75 10 76 3 19 146 252 225 150 107 231 82 224 49 46 132 117]), current txIndex (1), current txn (< TxHash: 07a5ac6b44f8f5f91caf502465bfbd60324ee319140a76a2a3a01fe0609d258f, TxnType: BASIC_TRANSFER, PubKey: BC1YLhSkfH28QrMAVkbejMUZELwkAEMwr2FFwhEtofHvzHRtP6rd7s6 >)
	////I0404 20:00:17.912611   76191 run_test.go:1280] checksumAfterTransactionBytes: ([244 163 221 45 233 134 83 142 148 232 191 244 88 253 9 15 66 56 21 36 88 57 108 211 78 195 7 81 143 143 112 96]), current txIndex (2), current txn (< TxHash: 12e9af008054e4107c903e980149245149bc565b33d76b4a3c19cd68ee7ad485, TxnType: UPDATE_PROFILE, PubKey: BC1YLiMxepKu2kLBZssC2hQBahsjcg9Aat4ttsBZYy2WCnUE2WyrNzZ >)
	////   run_test.go:1291:
	//// 76390 db_utils.go:619] Getting into a set: key ([40]) value (11)
	//
	//for txIndex, txn := range lastBlock.Txns {
	//	initialChecksumBytes, err := checksumsBeforeTransactions[txIndex].ToBytes()
	//	require.NoError(err)
	//	blockView, err := lib.NewUtxoView(node1.Server.GetBlockchain().DB(), node1.Params, nil, nil)
	//	require.NoError(err)
	//
	//	txHash := txHashes[txIndex]
	//	utxoOpsForTxn, _, _, _, err := blockView.ConnectTransaction(txn, txHash,
	//		0, uint32(height), true, false)
	//	require.NoError(err)
	//	utxoOps = append(utxoOps, utxoOpsForTxn)
	//	glog.Infof(lib.CLog(lib.Red, "RIGHT BEFORE FLUSH TO DB"))
	//	require.NoError(blockView.FlushToDb(height))
	//	checksumAfterTransaction := computeNodeStateChecksum(t, node1, height)
	//	checksumsBeforeTransactions = append(checksumsBeforeTransactions, checksumAfterTransaction)
	//	checksumAfterTransactionBytes, err := checksumAfterTransaction.ToBytes()
	//	require.NoError(err)
	//	glog.Infof("checksumAfterTransactionBytes: (%v), current txIndex (%v), current txn (%v)",
	//		checksumAfterTransactionBytes, txIndex, txn)
	//
	//	blockView, err = lib.NewUtxoView(node1.Server.GetBlockchain().DB(), node1.Params, nil, nil)
	//	require.NoError(err)
	//	err = blockView.DisconnectTransaction(txn, txHash, utxoOpsForTxn, uint32(height))
	//	require.NoError(err)
	//	glog.Infof(lib.CLog(lib.Red, "RIGHT BEFORE DISCONNECT TO DB"))
	//	require.NoError(blockView.FlushToDb(height))
	//	afterDisconnectChecksum := computeNodeStateChecksum(t, node1, height)
	//	afterDisconnectBytes, err := afterDisconnectChecksum.ToBytes()
	//	require.NoError(err)
	//	require.Equal(true, reflect.DeepEqual(initialChecksumBytes, afterDisconnectBytes))
	//
	//	blockView, err = lib.NewUtxoView(node1.Server.GetBlockchain().DB(), node1.Params, nil, nil)
	//	require.NoError(err)
	//	utxoOpsForTxn, _, _, _, err = blockView.ConnectTransaction(txn, txHash,
	//		0, uint32(height), true, false)
	//	require.NoError(err)
	//	require.NoError(blockView.FlushToDb(height))
	//	checksumFinal := computeNodeStateChecksum(t, node1, height)
	//	checksumFinalFinalBytes, err := checksumFinal.ToBytes()
	//	require.NoError(err)
	//	require.Equal(true, reflect.DeepEqual(checksumAfterTransactionBytes, checksumFinalFinalBytes))
	//}

	require.NoError(node2.Server.GetBlockchain().DisconnectBlocksToHeight(5000))
	//compareNodesByState(t, node1, node2, 0)

	node1Bytes := computeNodeStateChecksum(t, node1, 5000)
	node2Bytes := computeNodeStateChecksum(t, node2, 5000)
	require.Equal(true, reflect.DeepEqual(node1Bytes, node2Bytes))

	node1.Stop()
	node2.Stop()
}

// FIXME: Uncomment '_' to run. This test is not intended to be executed with standard integration testing after core repo updates.
// Rather, it is used as a standalone script that should be run in a terminal to thoroughly test safety of utxoview disconencts.
// This test will repeatedly connect and disconnect blocks in cycles of 1000 blocks to test if state safety is maintained.
// So for instance, node start at height 1000, computes the state checksum, then it connects blocks to height 2000. Once done,
// the node will disconnect blocks back to height 1000 and recompute the checksum. Finally, we verify that the checksums match.
// If they do, we sync the node back to height 2000 and repeat the process to height 3000, etc. Before the connect cycle,
// node's state will be copied to copyDbDir for debugging purposes.
func _TestStateDisconnectHardcore(t *testing.T) {
	require := require.New(t)
	_ = require

	const maxHeight = uint32(8000)
	const heightIncrement = uint32(1000)
	const copyDbDir = "data_dirs/copy_db"

	dbDir := getDirectory(t)
	defer os.RemoveAll(dbDir)

	config := generateConfig(t, 18000, dbDir, 10)
	config.SyncType = lib.NodeSyncTypeBlockSync
	config.MaxSyncBlockHeight = heightIncrement
	config.HyperSync = true
	config.ConnectIPs = []string{"deso-seed-2.io:17000"}

	// First sync the node to heightIncrement.
	node := cmd.NewNode(config)
	node = startNode(t, node)
	waitForNodeToFullySync(node)
	node = shutdownNode(t, node)

	for currentHeight := heightIncrement; currentHeight < maxHeight; {
		// Start the node and make sure it's synced to currentHeight.
		node = cmd.NewNode(config)
		node = startNode(t, node)
		waitForNodeToFullySync(node)

		// Compute the checksum of the node's state at currentHeight.
		nodeChecksumBytesAtCurrentHeight := computeNodeStateChecksum(t, node, uint64(currentHeight))

		// Copy node's state from currentHeight.
		node = shutdownNode(t, node)
		copyNode(t, node, copyDbDir)

		// Now sync the node to currentHeight + heightIncrement.
		config.MaxSyncBlockHeight = currentHeight + heightIncrement
		node = cmd.NewNode(config)
		node = startNode(t, node)
		waitForNodeToFullySync(node)

		// Now disconnect blocks from node's state back to currentHeight.
		require.NoError(node.Server.GetBlockchain().DisconnectBlocksToHeight(uint64(currentHeight)))

		// Compare the state from before the disconnect and after.
		nodeChecksumBytesAtCurrentHeightAfterDisconnect := computeNodeStateChecksum(t, node, uint64(currentHeight))
		require.Equal(true, reflect.DeepEqual(
			nodeChecksumBytesAtCurrentHeight,
			nodeChecksumBytesAtCurrentHeightAfterDisconnect))

		// If we get here that means this disconnect iteration was successful, so we sync the node to currentHeight + heightIncrement.
		node = shutdownNode(t, node)
		node = startNode(t, node)
		waitForNodeToFullySync(node)
		node = shutdownNode(t, node)
		currentHeight += heightIncrement
	}
}