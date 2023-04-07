package lib

import (
	flowCrypto "github.com/onflow/flow-go/crypto"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVerifyingBLSSignatures(t *testing.T) {
	// Generate two BLS public/private key pairs.
	privateKey1, err := flowCrypto.GeneratePrivateKey(BLSSigningAlgorithm, RandomBytes(64))
	require.NoError(t, err)
	publicKey1 := privateKey1.PublicKey()
	blsPublicKey1, err := NewBLSPublicKey(publicKey1.Encode())
	require.NoError(t, err)

	privateKey2, err := flowCrypto.GeneratePrivateKey(BLSSigningAlgorithm, RandomBytes(64))
	require.NoError(t, err)
	publicKey2 := privateKey2.PublicKey()
	blsPublicKey2, err := NewBLSPublicKey(publicKey2.Encode())
	require.NoError(t, err)

	// Test Eq().
	require.True(t, blsPublicKey1.Eq(blsPublicKey1))
	require.True(t, blsPublicKey2.Eq(blsPublicKey2))
	require.False(t, blsPublicKey1.Eq(blsPublicKey2))

	// Test Verify().

	// Test BLSPublicKey.ToBytes() and BLSPublicKey.FromBytes().
	// Test BLSSignature.ToBytes() and BLSSignature.FromBytes().
}
