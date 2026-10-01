package lib

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

// This reproduces the original inflation path with a valid PoS proposal and
// quorum certificate. The extra reward must be rejected before it can enter
// the block index or change account balances.
func TestPoSRejectsAdditionalBlockReward(t *testing.T) {
	for _, amount := range []uint64{NanosPerUnit, MaxNanos} {
		t.Run(fmt.Sprintf("amount_%d", amount), func(t *testing.T) {
			m := NewTestPoSBlockchainWithValidators(t)
			privateKey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			recipient := privateKey.PubKey().SerializeCompressed()
			block := _generateRealBlock(m, 12, 12, 812, m.chain.BlockTip().Hash, false)
			block.Txns = append(block.Txns, &MsgDeSoTxn{
				TxnMeta:   &BlockRewardMetadataa{ExtraData: []byte("extra-reward")},
				TxOutputs: []*DeSoOutput{{PublicKey: recipient, AmountNanos: amount}},
			})
			merkleRoot, txHashes, err := ComputeMerkleRoot(block.Txns)
			require.NoError(t, err)
			block.Header.TransactionMerkleRoot = merkleRoot
			updateProposerVotePartialSignatureForBlock(m, block)

			require.ErrorIs(t, m.chain.isProperlyFormedBlockPoS(block), RuleErrorMoreThanOneBlockReward)
			view, err := m.chain.GetUncommittedTipView()
			require.NoError(t, err)
			oldSeed, err := view.GetCurrentRandomSeedHash()
			require.NoError(t, err)
			_, err = view.ConnectBlock(block, txHashes, true, nil, 12)
			require.ErrorIs(t, err, RuleErrorMoreThanOneBlockReward)
			newSeed, err := view.GetCurrentRandomSeedHash()
			require.NoError(t, err)
			require.Equal(t, oldSeed, newSeed)

			oldTip := m.chain.BlockTip().Hash
			success, isOrphan, missing, err := m.chain.ProcessBlockPoS(block, 12, true)
			require.Error(t, err)
			require.False(t, success)
			require.False(t, isOrphan)
			require.Empty(t, missing)
			require.Equal(t, oldTip, m.chain.BlockTip().Hash)
			blockHash, err := (*MsgDeSoBlock)(block).Hash()
			require.NoError(t, err)
			blockNode, exists := m.chain.blockIndex.GetBlockNodeByHashAndHeight(blockHash, 12)
			require.True(t, exists)
			require.True(t, blockNode.IsValidateFailed())
			balance, err := m.chain.GetCommittedTipView().GetDeSoBalanceNanosForPublicKey(recipient)
			require.NoError(t, err)
			require.Zero(t, balance)
			validBlock := _generateRealBlock(m, 12, 12, 813, oldTip, false)
			success, isOrphan, missing, err = m.chain.ProcessBlockPoS(validBlock, 12, true)
			require.NoError(t, err)
			require.True(t, success)
			require.False(t, isOrphan)
			require.Empty(t, missing)
		})
	}
}

func TestAtomicWrapperRejectsBlockReward(t *testing.T) {
	for _, position := range []int{0, 1} {
		t.Run(fmt.Sprintf("position_%d", position), func(t *testing.T) {
			txns := []*MsgDeSoTxn{
				{TxnMeta: &BasicTransferMetadata{}, ExtraData: map[string][]byte{
					NextAtomicTxnPreHash: {}, PreviousAtomicTxnPreHash: {}, AtomicTxnsChainLength: {},
				}},
				{TxnMeta: &BasicTransferMetadata{}, ExtraData: map[string][]byte{
					NextAtomicTxnPreHash: {}, PreviousAtomicTxnPreHash: {},
				}},
			}
			txns[position].TxnMeta = &BlockRewardMetadataa{}
			err := _verifyAtomicTxnsChain(&AtomicTxnsWrapperMetadata{Txns: txns})
			require.True(t, errors.Is(err, RuleErrorAtomicTxnsHasBlockRewardInnerTxn))
		})
	}
}
