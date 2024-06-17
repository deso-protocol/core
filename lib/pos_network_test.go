package lib

import (
	"testing"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/stretchr/testify/require"
)

func TestValidatorVoteEncodeDecode(t *testing.T) {
	validatorVotingPublicKey, votePartialSignature := _generateValidatorVotingPublicKeyAndSignature(t)

	originalMsg := MsgDeSoValidatorVote{
		MsgVersion:           MsgValidatorVoteVersion0,
		VotingPublicKey:      validatorVotingPublicKey,
		BlockHash:            &BlockHash{},
		ProposedInView:       9910,
		VotePartialSignature: votePartialSignature,
	}

	// Encode the message and verify the length is correct.
	encodedMsgBytes, err := originalMsg.ToBytes(false)
	require.NoError(t, err)
	require.Equal(t, 181, len(encodedMsgBytes))

	// Decode the message.
	decodedMsg := &MsgDeSoValidatorVote{}
	err = decodedMsg.FromBytes(encodedMsgBytes)
	require.NoError(t, err)

	// Check that the message bodies are the same.
	require.Equal(t, originalMsg.MsgVersion, decodedMsg.MsgVersion)
	require.True(t, originalMsg.VotingPublicKey.Eq(decodedMsg.VotingPublicKey))
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
		MsgVersion:      MsgValidatorTimeoutVersion0,
		VotingPublicKey: validatorVotingPublicKey,
		TimedOutView:    999912,
		HighQC: &QuorumCertificate{
			BlockHash:      &BlockHash{},
			ProposedInView: 999910,
			ValidatorsVoteAggregatedSignature: &AggregatedBLSSignature{
				SignersList: bitset.NewBitset().Set(0, true).Set(3, true),
				Signature:   aggregateSignature,
			},
		},
		TimeoutPartialSignature: timeoutPartialSignature,
	}

	// Encode the message and verify the length is correct.
	encodedMsgBytes, err := originalMsg.ToBytes(false)
	require.NoError(t, err)
	require.Equal(t, 236, len(encodedMsgBytes))

	// Decode the message.
	decodedMsg := &MsgDeSoValidatorTimeout{}
	err = decodedMsg.FromBytes(encodedMsgBytes)
	require.NoError(t, err)

	// Check that the message bodies are the same.
	require.Equal(t, originalMsg.MsgVersion, decodedMsg.MsgVersion)
	require.True(t, originalMsg.VotingPublicKey.Eq(decodedMsg.VotingPublicKey))
	require.Equal(t, originalMsg.TimedOutView, decodedMsg.TimedOutView)
	require.True(t, originalMsg.TimeoutPartialSignature.Eq(decodedMsg.TimeoutPartialSignature))

	// Check that the high QCs are the same.
	require.True(t,
		originalMsg.HighQC.ValidatorsVoteAggregatedSignature.Eq(
			decodedMsg.HighQC.ValidatorsVoteAggregatedSignature,
		),
	)
}

// Creates an arbitrary BLS public key and signature for testing.
func _generateValidatorVotingPublicKeyAndSignature(t *testing.T) (*bls.PublicKey, *bls.Signature) {
	blsPrivateKey, err := bls.NewPrivateKey()
	require.NoError(t, err)
	blsPublicKey := blsPrivateKey.PublicKey()
	blsSignature, err := blsPrivateKey.Sign([]byte{0x01, 0x02, 0x03})
	require.NoError(t, err)
	blsPublicKey, err = (&bls.PublicKey{}).FromBytes(blsPublicKey.ToBytes())
	require.NoError(t, err)
	return blsPublicKey, blsSignature
}
