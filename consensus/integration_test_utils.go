package consensus

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/stretchr/testify/require"
)

func createDummyBlockWithVoteQC(prevBlockHash BlockHash, view uint64, blockHeight uint64, validators []*validatorNode) *block {
	signersList := bitset.NewBitset()
	signatures := []*bls.Signature{}

	// All signers will vote on the previous block has and previous view to build the QC.
	for ii, validator := range validators {
		signaturePayload := GetVoteSignaturePayload(view-1, prevBlockHash)
		signature, _ := validator.privateKey.Sign(signaturePayload[:])
		signatures = append(signatures, signature)
		signersList.Set(ii, true)
	}

	aggregateSignatures, _ := bls.AggregateSignatures(signatures)

	result := block{
		blockHash: createDummyBlockHash(),
		view:      view,
		height:    blockHeight,
		qc: &quorumCertificate{
			view:      view - 1,
			blockHash: prevBlockHash,
			aggregatedSignature: &aggregatedSignature{
				signature:   aggregateSignatures,
				signersList: signersList,
			},
		},
	}
	return &result
}

func validateAndPrintBlockChain(t *testing.T, node *validatorNode, allBlocks map[[32]byte]*block) {
	blockChainString := ""

	// Fetch the validator's tip block
	tipBlock, ok := allBlocks[node.eventLoop.tip.block.GetBlockHash().GetValue()]
	require.True(t, ok)

	require.Greater(t, tipBlock.GetView(), uint64(4))   // the network must have advanced more than two views
	require.Greater(t, tipBlock.GetHeight(), uint64(4)) // the network must have produced at least two blocks

	// Format string that represents the chain of blocks.
	blockChainString = ""

	// Validate the chain of blocks starting from the tip block and ending at the first block within
	// the chain.
	currentBlock := tipBlock
	parentBlock, hasParentBlock := allBlocks[currentBlock.GetQC().GetBlockHash().GetValue()]
	for hasParentBlock {
		// Updated formatted string that represents the chain of blocks.
		blockHashValue := currentBlock.GetBlockHash().GetValue()
		blockChainString = fmt.Sprintf(
			"->(view=%d,height=%d,hash=%s)%s",
			currentBlock.view,
			currentBlock.height,
			hex.EncodeToString(blockHashValue[:2]),
			blockChainString,
		)

		// Verify that the current block exists in in the allBlocks map
		_, ok := allBlocks[currentBlock.GetBlockHash().GetValue()]
		require.True(t, ok)

		// Cross-validate the current block's and the parent block's views
		if isInterfaceNil(currentBlock.aggregateQC) {
			// The current block contains a QC of votes
			require.Equal(t, currentBlock.GetView(), currentBlock.GetQC().GetView()+1)
		} else {
			// The current block contains a timeout QC
			require.Equal(t, currentBlock.GetView(), currentBlock.aggregateQC.GetView()+1)
			require.Greater(t, currentBlock.GetView(), currentBlock.aggregateQC.GetHighQC().GetView()+1)

			// The difference in view between the current block and its parent should be equal to the number of
			// timeout blocks between the current block and its parent.
			for ii := currentBlock.view - 1; ii > parentBlock.view; ii-- {
				blockChainString = fmt.Sprintf("->(view=%d,timeout)%s", ii, blockChainString)
			}
		}

		// Verify that the current block's height is one more than the parent
		require.Equal(t, currentBlock.GetHeight(), parentBlock.GetHeight()+1)

		// Move on to the parent block
		currentBlock = parentBlock
		parentBlock, hasParentBlock = allBlocks[currentBlock.GetQC().GetBlockHash().GetValue()]
	}

	// If we get here, we've validated the chain of blocks and reached the first block within the
	// node's chain. The first block may or may not be the genesis block of the full blockchain,
	// as the node may have left the network and rejoined at a later time.

	// Format the first block and the node's info.
	blockHashValue := currentBlock.GetBlockHash().GetValue()
	blockChainString = fmt.Sprintf(
		"\nnode=[publicKey=%s, currentView=%d, stake=%s]\nblockchain=[(view=%d,height=%d,hash=%s)%s]\n",
		node.privateKey.PublicKey().ToString()[:10],
		node.eventLoop.currentView,
		node.stake.ToBig().String(),
		currentBlock.view,
		currentBlock.height,
		hex.EncodeToString(blockHashValue[:2]),
		blockChainString,
	)

	// Log the formatted string
	t.Log(blockChainString)
}
