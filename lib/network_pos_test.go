//go:build relic

package lib

import (
	"testing"

	"github.com/deso-protocol/core/bls"
	"github.com/stretchr/testify/require"
)

func TestValidatorVoteEncodeDecode(t *testing.T) {
	blsPublicKey, blsSignature := _generateValidatorVotingPublicKeyAndSignature(t)

	originalMsg := MsgDeSoValidatorVote{
		MsgVersion:               ValidatorVoteVersion0,
		ValidatorVotingPublicKey: blsPublicKey,
		BlockHash:                &BlockHash{},
		VotePartialSignature:     blsSignature,
	}

	// Encode the message and verify the length is correct.
	encodedMsgBytes, err := originalMsg.ToBytes(false)
	require.NoError(t, err)
	require.Equal(t, 178, len(encodedMsgBytes))

	// Decode the message.
	decodedMsg := &MsgDeSoValidatorVote{}
	err = decodedMsg.FromBytes(encodedMsgBytes)
	require.NoError(t, err)

	// Check that the message versions are the same.
	require.Equal(t, originalMsg.MsgVersion, decodedMsg.MsgVersion)
	require.True(t, originalMsg.ValidatorVotingPublicKey.Eq(decodedMsg.ValidatorVotingPublicKey))
	require.Equal(t, originalMsg.BlockHash, decodedMsg.BlockHash)
	require.True(t, originalMsg.VotePartialSignature.Eq(decodedMsg.VotePartialSignature))
}

func TestValidatorTimeoutEncodeDecode(t *testing.T) {
	// TODO
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
