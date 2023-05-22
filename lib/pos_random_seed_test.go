//go:build relic

package lib

import (
	"github.com/deso-protocol/core/bls"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCurrentRandomSeedHash(t *testing.T) {
	chain, params, db := NewLowDifficultyBlockchain(t)
	utxoView, err := NewUtxoView(db, params, chain.postgres, chain.snapshot)
	require.NoError(t, err)
	blockHeight := uint64(0)

	// Generate two BLS public + private key pairs.
	privateKey1, err := bls.NewPrivateKey()
	require.NoError(t, err)
	publicKey1 := privateKey1.PublicKey()
	privateKey2, err := bls.NewPrivateKey()
	require.NoError(t, err)
	publicKey2 := privateKey2.PublicKey()

	// Test generating + verifying RandomSeedSignatures.

	// PrivateKey1 creates a new RandomSeedSignature.
	randomSeedSignature1, err := utxoView.GenerateRandomSeedSignature(privateKey1)
	require.NoError(t, err)
	// PublicKey1 is verified to correspond to PrivateKey that signed the RandomSeedSignature.
	randomSeedHash1, err := utxoView.VerifyRandomSeedSignature(publicKey1, randomSeedSignature1)
	require.NoError(t, err)
	require.NotNil(t, randomSeedHash1)
	// PublicKey2 is not verified to correspond to the PrivateKey that signed the RandomSeedSignature.
	randomSeedHash1, err = utxoView.VerifyRandomSeedSignature(publicKey2, randomSeedSignature1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid RandomSeedSignature provided")
	require.Nil(t, randomSeedHash1)

	// PrivateKey2 creates a new RandomSeedSignature.
	randomSeedSignature2, err := utxoView.GenerateRandomSeedSignature(privateKey2)
	require.NoError(t, err)
	// PublicKey1 is not verified to correspond to the PrivateKey that signed the RandomSeedSignature.
	randomSeedHash2, err := utxoView.VerifyRandomSeedSignature(publicKey1, randomSeedSignature2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid RandomSeedSignature provided")
	require.Nil(t, randomSeedHash2)
	// PublicKey2 is verified to correspond to the PrivateKey that signed the RandomSeedSignature.
	randomSeedHash2, err = utxoView.VerifyRandomSeedSignature(publicKey2, randomSeedSignature2)
	require.NoError(t, err)
	require.NotNil(t, randomSeedHash2)

	// Test updating CurrentRandomSeedHash.

	// The initial CurrentRandomSeedHash is the GenesisRandomSeedHash.
	randomSeedHash1, err = utxoView.GetCurrentRandomSeedHash()
	require.NoError(t, err)
	require.True(t, randomSeedHash1.Eq(&RandomSeedHash{}))
	require.True(t, randomSeedHash1.ToUint256().Eq(uint256.NewInt()))

	// PrivateKey1 generates a new RandomSeedSignature.
	randomSeedSignature1, err = utxoView.GenerateRandomSeedSignature(privateKey1)
	require.NoError(t, err)
	// PublicKey1 is verified to correspond to the PrivateKey that signed the RandomSeedSignature.
	randomSeedHash1, err = utxoView.VerifyRandomSeedSignature(publicKey1, randomSeedSignature1)
	require.NoError(t, err)
	require.NotNil(t, randomSeedHash1)
	// The new RandomSeedHash is not the GenesisRandomSeedHash.
	require.False(t, randomSeedHash1.Eq(&RandomSeedHash{}))
	// We set the new CurrentRandomSeedHash.
	utxoView._setCurrentRandomSeedHash(randomSeedHash1)
	require.NoError(t, utxoView.FlushToDb(blockHeight))

	// PrivateKey2 generates a new RandomSeedSignature.
	randomSeedSignature2, err = utxoView.GenerateRandomSeedSignature(privateKey2)
	require.NoError(t, err)
	// PublicKey2 is verified to correspond to the PrivateKey that signed the RandomSeedSignature.
	randomSeedHash2, err = utxoView.VerifyRandomSeedSignature(publicKey2, randomSeedSignature2)
	require.NoError(t, err)
	require.NotNil(t, randomSeedHash2)
	// The new RandomSeedHash is not the GenesisRandomSeedHash.
	require.False(t, randomSeedHash2.Eq(&RandomSeedHash{}))
	// The new RandomSeedHash is not the previous CurrentRandomSeedHash.
	require.False(t, randomSeedHash2.Eq(randomSeedHash1))

	// Test RandomSeedHash.ToUint256(). Generates a valid uint256.
	// Idempotent: generates the same uint256 each time.
	require.True(t, randomSeedHash1.ToUint256().Cmp(uint256.NewInt()) > 0)
	require.True(t, randomSeedHash1.ToUint256().Cmp(MaxUint256) < 0)
	require.True(t, randomSeedHash1.ToUint256().Eq(randomSeedHash1.ToUint256()))
	require.True(t, randomSeedHash2.ToUint256().Cmp(uint256.NewInt()) > 0)
	require.True(t, randomSeedHash2.ToUint256().Cmp(MaxUint256) < 0)
	require.True(t, randomSeedHash2.ToUint256().Eq(randomSeedHash2.ToUint256()))
	require.False(t, randomSeedHash1.ToUint256().Eq(randomSeedHash2.ToUint256()))
}
