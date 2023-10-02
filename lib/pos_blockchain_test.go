//go:build relic

package lib

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestValidateBlockGeneral(t *testing.T) {
	bc, _, _ := NewTestBlockchain(t)
	hash := NewBlockHash(RandomBytes(32))
	nowTimestamp := uint64(time.Now().UnixNano())
	bc.bestChain = []*BlockNode{
		NewPoSBlockNode(nil, hash, 1, &MsgDeSoHeader{
			Version:                      2,
			TstampNanoSecs:               nowTimestamp - uint64(time.Minute.Nanoseconds()),
			Height:                       1,
			ProposedInView:               1,
			ValidatorsVoteQC:             nil,
			ValidatorsTimeoutAggregateQC: nil,
		}, StatusBlockValidated, UNCOMMITTED),
	}
	// Create a block with a valid header.
	randomPayload := RandomBytes(256)
	randomBLSPrivateKey := _generateRandomBLSPrivateKey(t)
	signature, err := randomBLSPrivateKey.Sign(randomPayload)
	require.NoError(t, err)
	block := &MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			Version:        2,
			TstampNanoSecs: uint64(time.Now().UnixNano()) - 10,
			Height:         2,
			ProposedInView: 1,
			ValidatorsTimeoutAggregateQC: &TimeoutAggregateQuorumCertificate{
				TimedOutView: 2,
				ValidatorsHighQC: &QuorumCertificate{
					BlockHash:      bc.GetBestChainTip().Hash,
					ProposedInView: bc.GetBestChainTip().Header.ProposedInView,
					ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
						Signature:   signature,
						SignersList: bitset.NewBitset(),
					},
				},
				ValidatorsTimeoutHighQCViews: []uint64{28934},
				ValidatorsTimeoutAggregatedSignature: &AggregatedBLSSignature{
					Signature:   signature,
					SignersList: bitset.NewBitset(),
				},
			},
		},
		Txns: nil,
	}

	// Validate the block with a valid timeout QC and header.
	err = bc.validateBlockGeneral(block)
	// There should be no error.
	require.Nil(t, err)

	// Timeout QC shouldn't have any transactions
	block.Txns = []*MsgDeSoTxn{
		{ // The validation just checks the length of transactions.
			// Connecting the block elsewhere will ensure that the transactions themselves are valid.
			TxInputs: nil,
		},
	}
	err = bc.validateBlockGeneral(block)
	require.Equal(t, err, RuleErrorTimeoutQCWithTransactions)

	// Make sure block can't have both timeout and vote QC.
	block.Header.ValidatorsVoteQC = &QuorumCertificate{
		BlockHash:      bc.GetBestChainTip().Hash,
		ProposedInView: bc.GetBestChainTip().Header.ProposedInView,
		ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
			Signature:   signature,
			SignersList: bitset.NewBitset(),
		},
	}
	err = bc.validateBlockGeneral(block)
	require.Equal(t, err, RuleErrorBothTimeoutAndVoteQC)

	// Validate the block with a valid vote QC and header. Vote QCs must have at least 1 transaction.
	block.Header.ValidatorsTimeoutAggregateQC = nil
	block.Txns = []*MsgDeSoTxn{
		{ // The validation just checks the length of transactions.
			// Connecting the block elsewhere will ensure that the transactions themselves are valid.
			TxInputs: nil,
		},
	}
	// There should be no error.
	err = bc.validateBlockGeneral(block)
	require.Nil(t, err)

	// Timestamp validations
	// Block timestamp must be greater than the previous block timestamp
	block.Header.TstampNanoSecs = bc.GetBestChainTip().Header.GetTstampSecs() - 1
	err = bc.validateBlockGeneral(block)
	require.Equal(t, err, RuleErrorPoSBlockTstampNanoSecsTooOld)

	// Block timestamps can't be in the future.
	block.Header.TstampNanoSecs = uint64(time.Now().UnixNano() + time.Minute.Nanoseconds())
	err = bc.validateBlockGeneral(block)
	require.Equal(t, err, RuleErrorPoSBlockTstampNanoSecsInFuture)

	// Revert the Header's timestamp
	block.Header.TstampNanoSecs = nowTimestamp - 10

	//  Block Header version must be 2
	block.Header.Version = 1
	err = bc.validateBlockGeneral(block)
	require.Equal(t, err, RuleErrorInvalidPoSBlockHeaderVersion)

	// Revert block header version
	block.Header.Version = 2

	// Nil block header not allowed
	block.Header = nil
	err = bc.validateBlockGeneral(block)
	require.Equal(t, err, RuleErrorNilBlockHeader)
}

func _generateRandomBLSPrivateKey(t *testing.T) *bls.PrivateKey {
	privateKey, err := bls.NewPrivateKey()
	require.NoError(t, err)
	return privateKey
}
