//go:build relic

package lib

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVerifyingBLSSignatures(t *testing.T) {
	// Generate two BLS public/private key pairs.
	blsPrivateKey1, err := NewBLSPrivateKey()
	require.NoError(t, err)
	blsPublicKey1 := blsPrivateKey1.PublicKey()

	blsPrivateKey2, err := NewBLSPrivateKey()
	require.NoError(t, err)
	blsPublicKey2 := blsPrivateKey2.PublicKey()

	// Test BLSPublicKey.Verify().
	// 1. PrivateKey1 signs a random payload.
	randomPayload1 := RandomBytes(256)
	blsSignature1, err := blsPrivateKey1.Sign(randomPayload1)
	require.NoError(t, err)
	// 2. Verify BLSPublicKey1 is the signer.
	isVerified, err := blsPublicKey1.Verify(blsSignature1, randomPayload1)
	require.NoError(t, err)
	require.True(t, isVerified)
	// 3. Verify BLSPublicKey2 is not the signer.
	isVerified, err = blsPublicKey2.Verify(blsSignature1, randomPayload1)
	require.NoError(t, err)
	require.False(t, isVerified)

	// 4. PrivateKey2 signs a different random payload.
	randomPayload2 := RandomBytes(256)
	blsSignature2, err := blsPrivateKey2.Sign(randomPayload2)
	require.NoError(t, err)
	// 5. Verify BLSPublicKey1 is not the signer.
	isVerified, err = blsPublicKey1.Verify(blsSignature2, randomPayload2)
	require.NoError(t, err)
	require.False(t, isVerified)
	// 6. Verify BLSPublicKey2 is the signer.
	isVerified, err = blsPublicKey2.Verify(blsSignature2, randomPayload2)
	require.NoError(t, err)
	require.True(t, isVerified)

	// Test BLSPrivateKey.Eq().
	require.True(t, blsPrivateKey1.Eq(blsPrivateKey1))
	require.True(t, blsPrivateKey2.Eq(blsPrivateKey2))
	require.False(t, blsPrivateKey1.Eq(blsPrivateKey2))

	// Test BLSPrivateKey.ToString() and BLSPrivateKey.FromString().
	blsPrivateKeyString := blsPrivateKey1.ToString()
	copyBLSPrivateKey1 := &BLSPrivateKey{}
	require.NoError(t, copyBLSPrivateKey1.FromString(blsPrivateKeyString))
	require.True(t, blsPrivateKey1.Eq(copyBLSPrivateKey1))

	// Test BLSPublicKey.Eq().
	require.True(t, blsPublicKey1.Eq(blsPublicKey1))
	require.True(t, blsPublicKey2.Eq(blsPublicKey2))
	require.False(t, blsPublicKey1.Eq(blsPublicKey2))

	// Test BLSPublicKey.ToBytes(), BLSPublicKey.FromBytes(), and BLSPublicKey.ReadBytes().
	blsPublicKeyBytes := blsPublicKey1.ToBytes()
	copyBLSPublicKey1 := &BLSPublicKey{}
	require.NoError(t, copyBLSPublicKey1.FromBytes(blsPublicKeyBytes))
	require.True(t, blsPublicKey1.Eq(copyBLSPublicKey1))
	copyBLSPublicKey1 = &BLSPublicKey{}
	require.NoError(t, copyBLSPublicKey1.ReadBytes(bytes.NewBuffer(blsPublicKeyBytes)))
	require.True(t, blsPublicKey1.Eq(copyBLSPublicKey1))

	// Test BLSPublicKey.ToString() and BLSPublicKey.FromString().
	blsPublicKeyString := blsPublicKey1.ToString()
	copyBLSPublicKey1 = &BLSPublicKey{}
	require.NoError(t, copyBLSPublicKey1.FromString(blsPublicKeyString))
	require.True(t, blsPublicKey1.Eq(copyBLSPublicKey1))

	// Test BLSSignature.Eq().
	require.True(t, blsSignature1.Eq(blsSignature1))
	require.True(t, blsSignature2.Eq(blsSignature2))
	require.False(t, blsSignature1.Eq(blsSignature2))

	// Test BLSSignature.ToBytes(), BLSSignature.FromBytes(), and BLSSignature.ReadBytes().
	blsSignatureBytes := blsSignature1.ToBytes()
	copyBLSSignature := &BLSSignature{}
	require.NoError(t, copyBLSSignature.FromBytes(blsSignatureBytes))
	require.True(t, blsSignature1.Eq(copyBLSSignature))
	copyBLSSignature = &BLSSignature{}
	require.NoError(t, copyBLSSignature.ReadBytes(bytes.NewBuffer(blsSignatureBytes)))
	require.True(t, blsSignature1.Eq(copyBLSSignature))

	// Test BLSSignature.ToString() and BLSSignature.FromString().
	blsSignatureString := blsSignature1.ToString()
	copyBLSSignature = &BLSSignature{}
	require.NoError(t, copyBLSSignature.FromString(blsSignatureString))
	require.True(t, blsSignature1.Eq(copyBLSSignature))
}
