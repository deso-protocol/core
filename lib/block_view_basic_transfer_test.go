package lib

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBasicTransfer(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Mine two blocks to give the sender some DeSo.
	_, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, err = miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)

	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)
	recipientPkBytes, _, err := Base58CheckDecode(recipientPkString)
	require.NoError(err)

	// A basic transfer whose input public keys differ from the
	// transaction-level public key should fail.
	{
		txn := &MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs: []*DeSoInput{},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPkBytes,
			TxnMeta:   &BasicTransferMetadata{},
		}

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, nil)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		// At this point the txn has inputs for senderPkString. Change
		// the public key to recipientPkString and sign it with the
		// recipientPrivString.
		txn.PublicKey = recipientPkBytes

		_signTxn(t, txn, recipientPrivString)
		utxoView, _ := NewUtxoView(db, params, nil)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
				true /*verifySignatures*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey)
	}

	// Just a basic transfer with a bad signature.
	{
		txn := &MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs: []*DeSoInput{},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPkBytes,
			TxnMeta:   &BasicTransferMetadata{},
		}

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, nil)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		// Sign the transaction with the recipient's key rather than the
		// sender's key.
		_signTxn(t, txn, recipientPrivString)
		utxoView, _ := NewUtxoView(db, params, nil)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
				true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidTransactionSignature)
	}

	// A block reward with a bad signature should fail.
	{
		txn := &MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs: []*DeSoInput{},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPkBytes,
			TxnMeta: &BlockRewardMetadataa{
				ExtraData: []byte{0x00, 0x01},
			},
		}
		_signTxn(t, txn, senderPrivString)
		utxoView, _ := NewUtxoView(db, params, nil)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
				true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardTxnNotAllowedToHaveSignature)
	}

	// A block reward with an input, even if it's signed legitimately,
	// should fail.
	{
		txn := &MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs: []*DeSoInput{},
			TxOutputs: []*DeSoOutput{
				{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPkBytes,
			TxnMeta: &BlockRewardMetadataa{
				ExtraData: []byte{0x00, 0x01},
			},
		}

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, nil)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		_signTxn(t, txn, senderPrivString)
		utxoView, _ := NewUtxoView(db, params, nil)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, getTxnSize(*txn), blockHeight,
				true /*verifySignature*/, false /*ignoreUtxos*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardTxnNotAllowedToHaveInputs)
	}

	// A block with too much block reward should fail.
	allowedBlockReward := CalcBlockRewardNanos(chain.blockTip().Height)
	assert.Equal(int64(allowedBlockReward), int64(1*NanosPerUnit))
	blockToMine, _, _, err := miner._getBlockToMine(0 /*threadIndex*/)
	require.NoError(err)
	{
		blockToMine.Txns[0].TxOutputs[0].AmountNanos = allowedBlockReward + 1
		// One iteration should be sufficient to find us a good block.
		_, bestNonce, err := FindLowestHash(blockToMine.Header, 10000)
		require.NoError(err)
		blockToMine.Header.Nonce = bestNonce

		txHashes, err := ComputeTransactionHashes(blockToMine.Txns)
		require.NoError(err)
		utxoView, _ := NewUtxoView(db, params, nil)
		_, err = utxoView.ConnectBlock(blockToMine, txHashes, true /*verifySignatures*/, nil)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardExceedsMaxAllowed)
	}

	// A block with less than the max block reward should be OK.
	{
		blockToMine.Txns[0].TxOutputs[0].AmountNanos = allowedBlockReward - 1
		// One iteration should be sufficient to find us a good block.
		_, bestNonce, err := FindLowestHash(blockToMine.Header, 10000)
		require.NoError(err)
		blockToMine.Header.Nonce = bestNonce

		txHashes, err := ComputeTransactionHashes(blockToMine.Txns)
		require.NoError(err)
		utxoView, _ := NewUtxoView(db, params, nil)
		_, err = utxoView.ConnectBlock(blockToMine, txHashes, true /*verifySignatures*/, nil)
		require.NoError(err)
	}
}
