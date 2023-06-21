//go:build relic

package lib

import (
	"testing"

	"github.com/deso-protocol/core/bls"
	"github.com/stretchr/testify/require"
)

func TestValidatorVoteEncodeDecode(t *testing.T) {
	validatorVotingPublicKey, votePartialSignature := _generateValidatorVotingPublicKeyAndSignature(t)

	originalMsg := MsgDeSoValidatorVote{
		MsgVersion:               MsgValidatorVoteVersion0,
		ValidatorPublicKey:       &PublicKey{},
		ValidatorVotingPublicKey: validatorVotingPublicKey,
		BlockHash:                &BlockHash{},
		ProposedInView:           9910,
		VotePartialSignature:     votePartialSignature,
	}

	// Encode the message and verify the length is correct.
	encodedMsgBytes, err := originalMsg.ToBytes(false)
	require.NoError(t, err)
	require.Equal(t, 214, len(encodedMsgBytes))

	// Decode the message.
	decodedMsg := &MsgDeSoValidatorVote{}
	err = decodedMsg.FromBytes(encodedMsgBytes)
	require.NoError(t, err)

	// Check that the message bodies are the same.
	require.Equal(t, originalMsg.MsgVersion, decodedMsg.MsgVersion)
	require.True(t, originalMsg.ValidatorPublicKey.Equal(*decodedMsg.ValidatorPublicKey))
	require.True(t, originalMsg.ValidatorVotingPublicKey.Eq(decodedMsg.ValidatorVotingPublicKey))
	require.Equal(t, originalMsg.BlockHash, decodedMsg.BlockHash)
	require.Equal(t, originalMsg.ProposedInView, decodedMsg.ProposedInView)
	require.True(t, originalMsg.VotePartialSignature.Eq(decodedMsg.VotePartialSignature))
}

func TestValidatorTimeoutEncodeDecode(t *testing.T) {
	validatorVotingPublicKey, timeoutPartialSignature := _generateValidatorVotingPublicKeyAndSignature(t)

	_, partialSignature1 := _generateValidatorVotingPublicKeyAndSignature(t)
	_, partialSignature2 := _generateValidatorVotingPublicKeyAndSignature(t)

	aggregateSignature, err := bls.AggregateSignatures([]*bls.Signature{partialSignature1, partialSignature2})
	require.NoError(t, err)

	originalMsg := MsgDeSoValidatorTimeout{
		MsgVersion:               MsgValidatorTimeoutVersion0,
		ValidatorPublicKey:       &PublicKey{},
		ValidatorVotingPublicKey: validatorVotingPublicKey,
		TimedOutView:             999912,
		HighQC: &QuorumCertificate{
			BlockHash:      &BlockHash{},
			ProposedInView: 999910,
			ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
				SignersList: []byte{1, 2},
				Signature:   aggregateSignature,
			},
		},
		TimeoutPartialSignature: timeoutPartialSignature,
	}

	// Encode the message and verify the length is correct.
	encodedMsgBytes, err := originalMsg.ToBytes(false)
	require.NoError(t, err)
	require.Equal(t, 270, len(encodedMsgBytes))

	// Decode the message.
	decodedMsg := &MsgDeSoValidatorTimeout{}
	err = decodedMsg.FromBytes(encodedMsgBytes)
	require.NoError(t, err)

	// Check that the message bodies are the same.
	require.Equal(t, originalMsg.MsgVersion, decodedMsg.MsgVersion)
	require.True(t, originalMsg.ValidatorPublicKey.Equal(*decodedMsg.ValidatorPublicKey))
	require.True(t, originalMsg.ValidatorVotingPublicKey.Eq(decodedMsg.ValidatorVotingPublicKey))
	require.Equal(t, originalMsg.TimedOutView, decodedMsg.TimedOutView)
	require.True(t, originalMsg.TimeoutPartialSignature.Eq(decodedMsg.TimeoutPartialSignature))

	// Check that the high QCs are the same.
	require.True(t,
		originalMsg.HighQC.ValidatorsVoteAggregatedSignature.Eq(
			decodedMsg.HighQC.ValidatorsVoteAggregatedSignature,
		),
	)
}

func TestMsgDeSoHeaderVersion2EncodeDecode(t *testing.T) {
	_, votePartialSignature1 := _generateValidatorVotingPublicKeyAndSignature(t)
	_, votePartialSignature2 := _generateValidatorVotingPublicKeyAndSignature(t)
	_, votePartialSignature3 := _generateValidatorVotingPublicKeyAndSignature(t)

	originalMsg := MsgDeSoHeader{
		Version:               HeaderVersion2,
		PrevBlockHash:         &BlockHash{},
		TransactionMerkleRoot: &BlockHash{},
		TstampSecs:            9910,
		Height:                9911,
		Nonce:                 0,
		ExtraNonce:            0,
		ValidatorsVoteQC: &QuorumCertificate{
			BlockHash:      &BlockHash{},
			ProposedInView: 9912,
			ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
				SignersList: []byte{3},
				Signature:   votePartialSignature1,
			},
		},
		ValidatorsTimeoutAggregateQC: &TimeoutAggregateQuorumCertificate{
			TimedOutView: 9913,
			ValidatorsHighQC: &QuorumCertificate{
				BlockHash:      &BlockHash{},
				ProposedInView: 9914,
				ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
					SignersList: []byte{4},
					Signature:   votePartialSignature2,
				},
			},
			ValidatorTimeoutHighQCViews: []uint64{9915, 9916},
			ValidatorTimeoutAggregatedSignature: &AggregatedBLSSignature{
				SignersList: []byte{5},
				Signature:   votePartialSignature3,
			},
		},
	}

	// Encode the message and verify the length is correct.
	encodedMsgBytes, err := originalMsg.ToBytes(false)
	require.NoError(t, err)
	require.Equal(t, 312, len(encodedMsgBytes))

	// Decode the message.
	decodedMsg := &MsgDeSoHeader{}
	err = decodedMsg.FromBytes(encodedMsgBytes)
	require.NoError(t, err)

	// Check that the message versions are the same.
	require.Equal(t, originalMsg.Version, decodedMsg.Version)
	require.Equal(t, originalMsg.PrevBlockHash, decodedMsg.PrevBlockHash)
	require.Equal(t, originalMsg.TransactionMerkleRoot, decodedMsg.TransactionMerkleRoot)
	require.Equal(t, originalMsg.TstampSecs, decodedMsg.TstampSecs)
	require.Equal(t, originalMsg.Height, decodedMsg.Height)
	require.Equal(t, originalMsg.Nonce, decodedMsg.Nonce)
	require.Equal(t, originalMsg.ExtraNonce, decodedMsg.ExtraNonce)
	require.Equal(t, originalMsg.ValidatorsVoteQC.BlockHash, decodedMsg.ValidatorsVoteQC.BlockHash)
	require.Equal(t, originalMsg.ValidatorsVoteQC.ProposedInView, decodedMsg.ValidatorsVoteQC.ProposedInView)
	require.Equal(t, originalMsg.ValidatorsTimeoutAggregateQC.TimedOutView, decodedMsg.ValidatorsTimeoutAggregateQC.TimedOutView)
	require.Equal(t, originalMsg.ValidatorsTimeoutAggregateQC.ValidatorsHighQC.BlockHash, decodedMsg.ValidatorsTimeoutAggregateQC.ValidatorsHighQC.BlockHash)
	// require.True(t, originalMsg.VotePartialSignature.Eq(decodedMsg.VotePartialSignature))
}

// Creates an arbitrary BLS public key and signature for testing.
func _generateValidatorVotingPublicKeyAndSignature(t *testing.T) (*bls.PublicKey, *bls.Signature) {
	blsPrivateKey, err := bls.NewPrivateKey()
	require.NoError(t, err)
	blsPublicKey := blsPrivateKey.PublicKey()
	blsSignature, err := blsPrivateKey.Sign([]byte{0x01, 0x02, 0x03})
	require.NoError(t, err)
	return blsPublicKey, blsSignature
}
