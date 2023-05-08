//go:build relic

package lib

import (
	"bytes"
	flowCrypto "github.com/onflow/flow-go/crypto"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVerifyingBLSSignatures(t *testing.T) {
	// Generate two BLS public/private key pairs.
	blsPrivateKey1 := _generateRandomBLSPrivateKey(t)
	blsPublicKey1 := blsPrivateKey1.PublicKey()

	blsPrivateKey2 := _generateRandomBLSPrivateKey(t)
	blsPublicKey2 := blsPrivateKey2.PublicKey()

	// Test BLSPrivateKey.Sign() and BLSPublicKey.Verify().
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

	// Test AggregateBLSSignatures() and VerifyAggregateBLSSignature().
	// 1. PrivateKey1 signs a random payload.
	randomPayload3 := RandomBytes(256)
	blsSignature1, err = blsPrivateKey1.Sign(randomPayload3)
	require.NoError(t, err)
	// 2. PrivateKey2 signs the same random payload.
	blsSignature2, err = blsPrivateKey2.Sign(randomPayload3)
	require.NoError(t, err)
	// 3. Aggregate their signatures.
	aggregateSignature, err := AggregateBLSSignatures([]*BLSSignature{blsSignature1, blsSignature2})
	require.NoError(t, err)
	// 4. Verify the AggregateSignature.
	isVerified, err = VerifyAggregateBLSSignature(
		[]*BLSPublicKey{blsPublicKey1, blsPublicKey2}, aggregateSignature, randomPayload3,
	)
	require.NoError(t, err)
	require.True(t, isVerified)
	// 5. Verify PrivateKey1's signature doesn't work on its own.
	isVerified, err = VerifyAggregateBLSSignature([]*BLSPublicKey{blsPublicKey1}, aggregateSignature, randomPayload3)
	require.NoError(t, err)
	require.False(t, isVerified)
	// 6. Verify PrivateKey2's signature doesn't work on its own.
	isVerified, err = VerifyAggregateBLSSignature([]*BLSPublicKey{blsPublicKey2}, aggregateSignature, randomPayload3)
	require.NoError(t, err)
	require.False(t, isVerified)
	// 7. Verify the AggregateSignature doesn't work on a different payload.
	isVerified, err = VerifyAggregateBLSSignature(
		[]*BLSPublicKey{blsPublicKey1, blsPublicKey2}, aggregateSignature, randomPayload1,
	)
	require.NoError(t, err)
	require.False(t, isVerified)

	// Test BLSPrivateKey.Eq().
	require.True(t, blsPrivateKey1.Eq(blsPrivateKey1))
	require.True(t, blsPrivateKey2.Eq(blsPrivateKey2))
	require.False(t, blsPrivateKey1.Eq(blsPrivateKey2))

	// Test BLSPrivateKey.ToString() and BLSPrivateKey.FromString().
	blsPrivateKeyString := blsPrivateKey1.ToString()
	copyBLSPrivateKey1, err := (&BLSPrivateKey{}).FromString(blsPrivateKeyString)
	require.NoError(t, err)
	require.True(t, blsPrivateKey1.Eq(copyBLSPrivateKey1))

	// Test BLSPublicKey.Eq().
	require.True(t, blsPublicKey1.Eq(blsPublicKey1))
	require.True(t, blsPublicKey2.Eq(blsPublicKey2))
	require.False(t, blsPublicKey1.Eq(blsPublicKey2))

	// Test BLSPublicKey.ToBytes(), BLSPublicKey.FromBytes(), and BLSPublicKey.ReadBytes().
	blsPublicKeyBytes := blsPublicKey1.ToBytes()
	copyBLSPublicKey1, err := (&BLSPublicKey{}).FromBytes(blsPublicKeyBytes)
	require.NoError(t, err)
	require.True(t, blsPublicKey1.Eq(copyBLSPublicKey1))
	copyBLSPublicKey1, err = (&BLSPublicKey{}).ReadBytes(bytes.NewBuffer(blsPublicKeyBytes))
	require.NoError(t, err)
	require.True(t, blsPublicKey1.Eq(copyBLSPublicKey1))

	// Test BLSPublicKey.ToString() and BLSPublicKey.FromString().
	blsPublicKeyString := blsPublicKey1.ToString()
	copyBLSPublicKey1, err = (&BLSPublicKey{}).FromString(blsPublicKeyString)
	require.NoError(t, err)
	require.True(t, blsPublicKey1.Eq(copyBLSPublicKey1))

	// Test BLSSignature.Eq().
	require.True(t, blsSignature1.Eq(blsSignature1))
	require.True(t, blsSignature2.Eq(blsSignature2))
	require.False(t, blsSignature1.Eq(blsSignature2))

	// Test BLSSignature.ToBytes(), BLSSignature.FromBytes(), and BLSSignature.ReadBytes().
	blsSignatureBytes := blsSignature1.ToBytes()
	copyBLSSignature, err := (&BLSSignature{}).FromBytes(blsSignatureBytes)
	require.NoError(t, err)
	require.True(t, blsSignature1.Eq(copyBLSSignature))
	copyBLSSignature, err = (&BLSSignature{}).ReadBytes(bytes.NewBuffer(blsSignatureBytes))
	require.NoError(t, err)
	require.True(t, blsSignature1.Eq(copyBLSSignature))

	// Test BLSSignature.ToString() and BLSSignature.FromString().
	blsSignatureString := blsSignature1.ToString()
	copyBLSSignature, err = (&BLSSignature{}).FromString(blsSignatureString)
	require.NoError(t, err)
	require.True(t, blsSignature1.Eq(copyBLSSignature))

	// Test BLSPublicKey.Copy().
	blsPublicKey1Copy := blsPublicKey1.Copy()
	require.True(t, blsPublicKey1.Eq(blsPublicKey1Copy))

	// Test BLSSignature.Copy().
	blsSignature1Copy := blsSignature1.Copy()
	require.True(t, blsSignature1.Eq(blsSignature1Copy))

	// Test nil BLSPrivateKey edge cases.
	// Sign()
	_, err = (&BLSPrivateKey{}).Sign(randomPayload1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "BLSPrivateKey is nil")
	// PublicKey()
	require.Nil(t, (&BLSPrivateKey{}).PublicKey())
	// ToString()
	require.Equal(t, (&BLSPrivateKey{}).ToString(), "")
	// FromString()
	_, err = (&BLSPrivateKey{}).FromString("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty BLSPrivateKey string provided")
	// Eq()
	require.False(t, (&BLSPrivateKey{}).Eq(nil))
	require.False(t, (&BLSPrivateKey{}).Eq(&BLSPrivateKey{}))
	require.False(t, (&BLSPrivateKey{}).Eq(_generateRandomBLSPrivateKey(t)))
	require.False(t, _generateRandomBLSPrivateKey(t).Eq(nil))
	require.False(t, _generateRandomBLSPrivateKey(t).Eq(&BLSPrivateKey{}))
	require.False(t, _generateRandomBLSPrivateKey(t).Eq(_generateRandomBLSPrivateKey(t)))

	// Test nil BLSPublicKey edge cases.
	// Verify()
	_, err = (&BLSPublicKey{}).Verify(blsSignature1, randomPayload1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "BLSPublicKey is nil")
	// ToBytes()
	require.True(t, bytes.Equal((&BLSPublicKey{}).ToBytes(), EncodeByteArray([]byte{})))
	// FromBytes()
	_, err = (&BLSPublicKey{}).FromBytes([]byte{})
	require.Error(t, err)
	// ToString()
	require.Equal(t, (&BLSPublicKey{}).ToString(), "")
	// FromString()
	_, err = (&BLSPublicKey{}).FromString("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty BLSPublicKey string provided")
	// Eq()
	require.False(t, (&BLSPublicKey{}).Eq(nil))
	require.False(t, (&BLSPublicKey{}).Eq(&BLSPublicKey{}))
	require.False(t, (&BLSPublicKey{}).Eq(_generateRandomBLSPrivateKey(t).PublicKey()))
	require.False(t, _generateRandomBLSPrivateKey(t).PublicKey().Eq(nil))
	require.False(t, _generateRandomBLSPrivateKey(t).PublicKey().Eq((&BLSPrivateKey{}).PublicKey()))
	require.False(t, _generateRandomBLSPrivateKey(t).PublicKey().Eq(_generateRandomBLSPrivateKey(t).PublicKey()))
	// Copy()
	require.Nil(t, (&BLSPublicKey{}).Copy().PublicKey)

	// Test nil BLSSignature edge cases.
	// ToBytes()
	require.True(t, bytes.Equal((&BLSSignature{}).ToBytes(), EncodeByteArray([]byte{})))
	// FromBytes()
	_, err = (&BLSSignature{}).FromBytes([]byte{})
	require.Error(t, err)
	// ToString()
	require.Equal(t, (&BLSSignature{}).ToString(), "")
	// FromString()
	_, err = (&BLSSignature{}).FromString("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty BLSSignature string provided")
	// Eq()
	require.False(t, (&BLSSignature{}).Eq(nil))
	require.False(t, (&BLSSignature{}).Eq(&BLSSignature{}))
	require.False(t, (&BLSSignature{}).Eq(blsSignature1))
	require.False(t, blsSignature1.Eq(nil))
	require.False(t, blsSignature1.Eq(&BLSSignature{}))
	// Copy()
	require.Nil(t, (&BLSSignature{}).Copy().Signature)
}

func _generateRandomBLSPrivateKey(t *testing.T) *BLSPrivateKey {
	privateKey, err := flowCrypto.GeneratePrivateKey(BLSSigningAlgorithm, RandomBytes(64))
	require.NoError(t, err)
	return &BLSPrivateKey{PrivateKey: privateKey}
}
