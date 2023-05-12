//go:build relic

package lib

import (
	"github.com/deso-protocol/core/bls"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCurrentRandomSeedHash(t *testing.T) {
	chain, params, db := NewLowDifficultyBlockchain(t)
	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
	require.NoError(t, err)

	// Generate two BLS public + private key pairs.
	privateKey1, err := bls.NewPrivateKey()
	require.NoError(t, err)
	publicKey1 := privateKey1.PublicKey()
	privateKey2, err := bls.NewPrivateKey()
	require.NoError(t, err)
	publicKey2 := privateKey2.PublicKey()

	// Test generating + verifying RandomSeedSignatures.
	randomSeedSignature1, err := utxoView.GenerateRandomSeedSignature(privateKey1)
	require.NoError(t, err)
	isVerified, err := utxoView.VerifyRandomSeedSignature(publicKey1, randomSeedSignature1)
	require.NoError(t, err)
	require.True(t, isVerified)
	isVerified, err = utxoView.VerifyRandomSeedSignature(publicKey2, randomSeedSignature1)
	require.NoError(t, err)
	require.False(t, isVerified)

	randomSeedSignature2, err := utxoView.GenerateRandomSeedSignature(privateKey2)
	require.NoError(t, err)
	isVerified, err = utxoView.VerifyRandomSeedSignature(publicKey1, randomSeedSignature2)
	require.NoError(t, err)
	require.False(t, isVerified)
	isVerified, err = utxoView.VerifyRandomSeedSignature(publicKey2, randomSeedSignature2)
	require.NoError(t, err)
	require.True(t, isVerified)
}
