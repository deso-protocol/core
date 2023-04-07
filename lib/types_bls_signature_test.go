package lib

import (
	"bytes"
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

	// Test BLSPublicKey.Eq().
	require.True(t, blsPublicKey1.Eq(blsPublicKey1))
	require.True(t, blsPublicKey2.Eq(blsPublicKey2))
	require.False(t, blsPublicKey1.Eq(blsPublicKey2))

	// Test BLSPublicKey.Verify().
	//   1. PrivateKey1 signs a random payload.
	//   2. Verify BLSPublicKey1 is the signer.
	//   3. Verify BLSPublicKey2 is not the signer.
	//   4. PrivateKey2 signs a random payload.
	//   5. Verify BLSPublicKey1 is not the signer.
	//   6. Verify BLSPublicKey2 is the signer.
	randomPayload1 := RandomBytes(256)
	signature1, err := privateKey1.Sign(randomPayload1, BLSHashingAlgorithm)
	require.NoError(t, err)
	blsSignature1 := NewBLSSignature(signature1)
	isVerified, err := blsPublicKey1.Verify(blsSignature1, randomPayload1)
	require.NoError(t, err)
	require.True(t, isVerified)
	isVerified, err = blsPublicKey2.Verify(blsSignature1, randomPayload1)
	require.NoError(t, err)
	require.False(t, isVerified)

	randomPayload2 := RandomBytes(256)
	signature2, err := privateKey2.Sign(randomPayload2, BLSHashingAlgorithm)
	require.NoError(t, err)
	blsSignature2 := NewBLSSignature(signature2)
	isVerified, err = blsPublicKey1.Verify(blsSignature2, randomPayload2)
	require.NoError(t, err)
	require.False(t, isVerified)
	isVerified, err = blsPublicKey2.Verify(blsSignature2, randomPayload2)
	require.NoError(t, err)
	require.True(t, isVerified)

	// Test BLSPublicKey.Eq().
	require.True(t, blsPublicKey1.Eq(blsPublicKey1))
	require.True(t, blsPublicKey2.Eq(blsPublicKey2))
	require.False(t, blsPublicKey1.Eq(blsPublicKey2))

	// Test BLSSignature.Eq().
	require.True(t, blsSignature1.Eq(blsSignature1))
	require.True(t, blsSignature2.Eq(blsSignature2))
	require.False(t, blsSignature1.Eq(blsSignature2))

	// Test BLSPublicKey.ToBytes() and BLSPublicKey.FromBytes().
	blsPublicKeyBytes := blsPublicKey1.ToBytes()
	copyBLSPublicKey1 := &BLSPublicKey{}
	require.NoError(t, copyBLSPublicKey1.FromBytes(bytes.NewBuffer(blsPublicKeyBytes)))
	require.True(t, blsPublicKey1.Eq(copyBLSPublicKey1))

	// Test BLSSignature.ToBytes() and BLSSignature.FromBytes().
	blsSignatureBytes := blsSignature1.ToBytes()
	copyBLSSignature := &BLSSignature{}
	require.NoError(t, copyBLSSignature.FromBytes(bytes.NewBuffer(blsSignatureBytes)))
	require.True(t, blsSignature1.Eq(copyBLSSignature))
}
