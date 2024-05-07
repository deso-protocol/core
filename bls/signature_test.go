package bls

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyingBLSSignatures(t *testing.T) {
	// Generate two BLS public/private key pairs.
	blsPrivateKey1 := _generateRandomBLSPrivateKey(t)
	blsPublicKey1 := blsPrivateKey1.PublicKey()

	blsPrivateKey2 := _generateRandomBLSPrivateKey(t)
	blsPublicKey2 := blsPrivateKey2.PublicKey()

	malformedBlsPublicKey := &PublicKey{
		flowPublicKeyBytes: _generateRandomBytes(t, 12),
	}

	// Test bls.PrivateKey.Sign() and bls.PublicKey.Verify().
	// 1. PrivateKey1 signs a random payload.
	randomPayload1 := _generateRandomBytes(t, 256)
	blsSignature1, err := blsPrivateKey1.Sign(randomPayload1)
	require.NoError(t, err)
	// 2. Verify bls.PublicKey1 is the signer.
	isVerified, err := blsPublicKey1.Verify(blsSignature1, randomPayload1)
	require.NoError(t, err)
	require.True(t, isVerified)
	// 3. Verify bls.PublicKey2 is not the signer.
	isVerified, err = blsPublicKey2.Verify(blsSignature1, randomPayload1)
	require.NoError(t, err)
	require.False(t, isVerified)

	// 4. PrivateKey2 signs a different random payload.
	randomPayload2 := _generateRandomBytes(t, 256)
	blsSignature2, err := blsPrivateKey2.Sign(randomPayload2)
	require.NoError(t, err)
	// 5. Verify bls.PublicKey1 is not the signer.
	isVerified, err = blsPublicKey1.Verify(blsSignature2, randomPayload2)
	require.NoError(t, err)
	require.False(t, isVerified)
	// 6. Verify bls.PublicKey2 is the signer.
	isVerified, err = blsPublicKey2.Verify(blsSignature2, randomPayload2)
	require.NoError(t, err)
	require.True(t, isVerified)
	// 7. Malformed public key fails to verify with an error.
	isVerified, err = malformedBlsPublicKey.Verify(blsSignature2, randomPayload2)
	require.Error(t, err)

	// Aggregating empty list of signatures fails.
	_, err = AggregateSignatures([]*Signature{})
	require.Error(t, err)

	// Test AggregateSignatures() and VerifyAggregateSignatureSinglePayload().
	// 1. PrivateKey1 signs a random payload.
	randomPayload3 := _generateRandomBytes(t, 256)
	blsSignature1, err = blsPrivateKey1.Sign(randomPayload3)
	require.NoError(t, err)
	// 2. PrivateKey2 signs the same random payload.
	blsSignature2, err = blsPrivateKey2.Sign(randomPayload3)
	require.NoError(t, err)
	// 3. Aggregate their signatures.
	aggregateSignature, err := AggregateSignatures([]*Signature{blsSignature1, blsSignature2})
	require.NoError(t, err)
	// 4. Verify the AggregateSignature.
	isVerified, err = VerifyAggregateSignatureSinglePayload(
		[]*PublicKey{blsPublicKey1, blsPublicKey2}, aggregateSignature, randomPayload3,
	)
	require.NoError(t, err)
	require.True(t, isVerified)
	// 5. Verify PrivateKey1's signature doesn't work on its own.
	isVerified, err = VerifyAggregateSignatureSinglePayload([]*PublicKey{blsPublicKey1}, aggregateSignature, randomPayload3)
	require.NoError(t, err)
	require.False(t, isVerified)
	// 6. Verify PrivateKey2's signature doesn't work on its own.
	isVerified, err = VerifyAggregateSignatureSinglePayload([]*PublicKey{blsPublicKey2}, aggregateSignature, randomPayload3)
	require.NoError(t, err)
	require.False(t, isVerified)
	// 7. Verify the AggregateSignature doesn't work on a different payload.
	isVerified, err = VerifyAggregateSignatureSinglePayload(
		[]*PublicKey{blsPublicKey1, blsPublicKey2}, aggregateSignature, randomPayload1,
	)
	require.NoError(t, err)
	require.False(t, isVerified)

	// VerifyAggregateSignatureSinglePayload fails if a public key is malformed.
	isVerified, err = VerifyAggregateSignatureSinglePayload(
		[]*PublicKey{blsPublicKey1, malformedBlsPublicKey}, aggregateSignature, randomPayload3,
	)
	require.Error(t, err)

	// Test AggregateSignatures() and VerifyMultiPayloadAggregateSignature() on different payloads.
	// 1. PrivateKey1 signs a random payload.
	randomPayload4 := _generateRandomBytes(t, 256)
	blsSignature1, err = blsPrivateKey1.Sign(randomPayload4)
	require.NoError(t, err)
	// 2. PrivateKey2 signs a different random payload.
	randomPayload5 := _generateRandomBytes(t, 256)
	blsSignature2, err = blsPrivateKey2.Sign(randomPayload5)
	require.NoError(t, err)
	// 3. Aggregate their signatures.
	aggregateSignature, err = AggregateSignatures([]*Signature{blsSignature1, blsSignature2})
	require.NoError(t, err)
	// 4. Verify the AggregateSignature on the different payloads.
	isVerified, err = VerifyAggregateSignatureMultiplePayloads(
		[]*PublicKey{blsPublicKey1, blsPublicKey2}, aggregateSignature, [][]byte{randomPayload4, randomPayload5},
	)
	require.NoError(t, err)
	require.True(t, isVerified)
	// 5. Verify PrivateKey1's signature doesn't work on its own.
	isVerified, err = VerifyAggregateSignatureMultiplePayloads(
		[]*PublicKey{blsPublicKey1}, aggregateSignature, [][]byte{randomPayload4},
	)
	require.NoError(t, err)
	require.False(t, isVerified)
	// 6. Verify PrivateKey2's signature doesn't work on its own.
	isVerified, err = VerifyAggregateSignatureMultiplePayloads(
		[]*PublicKey{blsPublicKey2}, aggregateSignature, [][]byte{randomPayload5},
	)
	require.NoError(t, err)
	require.False(t, isVerified)
	// 7. Verify the AggregateSignature doesn't work on different ordering of payloads.
	isVerified, err = VerifyAggregateSignatureMultiplePayloads(
		[]*PublicKey{blsPublicKey1, blsPublicKey2}, aggregateSignature, [][]byte{randomPayload5, randomPayload4},
	)
	require.NoError(t, err)
	require.False(t, isVerified)
	// 8. Verify the AggregateSignature doesn't work if the number of public keys doesn't match the number of payloads.
	isVerified, err = VerifyAggregateSignatureMultiplePayloads(
		[]*PublicKey{blsPublicKey1}, aggregateSignature, [][]byte{randomPayload4, randomPayload5},
	)
	require.Error(t, err)

	// 9. Verify the AggregateSignature doesn't work if a public key is malformed.
	isVerified, err = VerifyAggregateSignatureMultiplePayloads(
		[]*PublicKey{blsPublicKey1, malformedBlsPublicKey}, aggregateSignature, [][]byte{randomPayload4, randomPayload5},
	)
	require.Error(t, err)

	// Test bls.PrivateKey.Eq().
	require.True(t, blsPrivateKey1.Eq(blsPrivateKey1))
	require.True(t, blsPrivateKey2.Eq(blsPrivateKey2))
	require.False(t, blsPrivateKey1.Eq(blsPrivateKey2))

	// Test bls.PrivateKey.FromSeed
	seed := _generateRandomBytes(t, 64)
	testBlsPrivateKey, err := (&PrivateKey{}).FromSeed(seed)
	require.NoError(t, err)
	require.NotNil(t, testBlsPrivateKey)

	// Test bls.PrivateKey.ToString() and bls.PrivateKey.FromString().
	blsPrivateKeyString := blsPrivateKey1.ToString()
	copyBLSPrivateKey1, err := (&PrivateKey{}).FromString(blsPrivateKeyString)
	require.NoError(t, err)
	require.True(t, blsPrivateKey1.Eq(copyBLSPrivateKey1))

	// Test bls.PublicKey.Eq().
	require.True(t, blsPublicKey1.Eq(blsPublicKey1))
	require.True(t, blsPublicKey2.Eq(blsPublicKey2))
	require.False(t, blsPublicKey1.Eq(blsPublicKey2))

	// Test bls.PublicKey.ToBytes() and bls.PublicKey.FromBytes().
	blsPublicKeyBytes := blsPublicKey1.ToBytes()
	copyBLSPublicKey1, err := (&PublicKey{}).FromBytes(blsPublicKeyBytes)
	require.NoError(t, err)
	require.True(t, blsPublicKey1.Eq(copyBLSPublicKey1))

	// Test bls.PublicKey.ToString() and bls.PublicKey.FromString().
	blsPublicKeyString := blsPublicKey1.ToString()
	copyBLSPublicKey1, err = (&PublicKey{}).FromString(blsPublicKeyString)
	require.NoError(t, err)
	require.True(t, blsPublicKey1.Eq(copyBLSPublicKey1))

	// Test bls.PublicKey.ToAbbreviatedString
	abbrString := blsPublicKey1.ToAbbreviatedString()
	require.True(t, strings.HasPrefix(abbrString, blsPublicKeyString[:5]))
	require.True(t, strings.HasSuffix(abbrString, blsPublicKeyString[len(blsPublicKeyString)-5:]))
	_, err = (&PublicKey{}).FromString(abbrString)
	require.Error(t, err)

	// Test bls.Signature.Eq().
	require.True(t, blsSignature1.Eq(blsSignature1))
	require.True(t, blsSignature2.Eq(blsSignature2))
	require.False(t, blsSignature1.Eq(blsSignature2))

	// Test bls.Signature.ToBytes() and bls.Signature.FromBytes().
	blsSignatureBytes := blsSignature1.ToBytes()
	copyBLSSignature, err := (&Signature{}).FromBytes(blsSignatureBytes)
	require.NoError(t, err)
	require.True(t, blsSignature1.Eq(copyBLSSignature))

	// Test bls.Signature.ToString() and bls.Signature.FromString().
	blsSignatureString := blsSignature1.ToString()
	copyBLSSignature, err = (&Signature{}).FromString(blsSignatureString)
	require.NoError(t, err)
	require.True(t, blsSignature1.Eq(copyBLSSignature))

	// Test bls.Signature.ToAbbreviatedString()
	abbrString = blsSignature1.ToAbbreviatedString()
	require.True(t, strings.HasPrefix(abbrString, blsSignatureString[:5]))
	require.True(t, strings.HasSuffix(abbrString, blsSignatureString[len(blsSignatureString)-5:]))
	_, err = (&Signature{}).FromString(abbrString)
	require.Error(t, err)

	// Test bls.PublicKey.Copy().
	blsPublicKey1Copy := blsPublicKey1.Copy()
	require.True(t, blsPublicKey1.Eq(blsPublicKey1Copy))
	blsPublicKey1Copy.flowPublicKeyBytes = _generateRandomBLSPrivateKey(t).PublicKey().ToBytes()
	require.False(t, blsPublicKey1.Eq(blsPublicKey1Copy))

	// Test bls.Signature.Copy().
	blsSignature1Copy := blsSignature1.Copy()
	require.True(t, blsSignature1.Eq(blsSignature1Copy))
	blsRandomSignature, err := _generateRandomBLSPrivateKey(t).Sign(randomPayload1)
	require.NoError(t, err)
	blsSignature1Copy.flowSignature = blsRandomSignature.flowSignature
	require.False(t, blsSignature1.Eq(blsSignature1Copy))

	// Test nil bls.PrivateKey edge cases.
	// Sign()
	_, err = (&PrivateKey{}).Sign(randomPayload1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "PrivateKey is nil")
	// PublicKey()
	require.Nil(t, (&PrivateKey{}).PublicKey())
	// ToString()
	require.Equal(t, (&PrivateKey{}).ToString(), "")
	// FromString()
	blsPrivateKey, err := (&PrivateKey{}).FromString("")
	require.NoError(t, err)
	require.Nil(t, blsPrivateKey)
	// FromString malfored formed.
	blsPrivateKey, err = (&PrivateKey{}).FromString("malformed")
	require.Error(t, err)
	// Eq()
	require.False(t, (&PrivateKey{}).Eq(nil))
	require.False(t, (&PrivateKey{}).Eq(&PrivateKey{}))
	require.False(t, (&PrivateKey{}).Eq(_generateRandomBLSPrivateKey(t)))
	require.False(t, _generateRandomBLSPrivateKey(t).Eq(nil))
	require.False(t, _generateRandomBLSPrivateKey(t).Eq(&PrivateKey{}))
	require.False(t, _generateRandomBLSPrivateKey(t).Eq(_generateRandomBLSPrivateKey(t)))

	var nilPrivateKey *PrivateKey
	privKey, err := nilPrivateKey.FromSeed(nil)
	require.NoError(t, err)
	require.Nil(t, privKey)

	// Test nil bls.PublicKey edge cases.
	// Verify()
	_, err = (&PublicKey{}).Verify(blsSignature1, randomPayload1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "bls.PublicKey is nil")
	// ToBytes()
	require.True(t, bytes.Equal((&PublicKey{}).ToBytes(), []byte{}))
	// FromBytes()
	blsPublicKey, err := (&PublicKey{}).FromBytes(nil)
	require.NoError(t, err)
	require.Nil(t, blsPublicKey)
	blsPublicKey, err = (&PublicKey{}).FromBytes([]byte{})
	require.NoError(t, err)
	require.Nil(t, blsPublicKey)
	// ToString()
	require.Equal(t, (&PublicKey{}).ToString(), "")
	// ToAbbreviatedString()
	require.Equal(t, (&PublicKey{}).ToAbbreviatedString(), "")
	// FromString()
	blsPublicKey, err = (&PublicKey{}).FromString("")
	require.NoError(t, err)
	require.Nil(t, blsPublicKey)
	// Eq()
	require.False(t, (&PublicKey{}).Eq(nil))
	require.False(t, (&PublicKey{}).Eq(&PublicKey{}))
	require.False(t, (&PublicKey{}).Eq(_generateRandomBLSPrivateKey(t).PublicKey()))
	require.False(t, _generateRandomBLSPrivateKey(t).PublicKey().Eq(nil))
	require.False(t, _generateRandomBLSPrivateKey(t).PublicKey().Eq((&PrivateKey{}).PublicKey()))
	require.False(t, _generateRandomBLSPrivateKey(t).PublicKey().Eq(_generateRandomBLSPrivateKey(t).PublicKey()))
	// Copy()
	require.Nil(t, (&PublicKey{}).Copy().flowPublicKey)
	var nilPublicKey *PublicKey
	require.Nil(t, nilPublicKey.Copy())
	// IsEmpty
	require.True(t, (&PublicKey{}).IsEmpty())

	// Test SerializedPublicKey
	serializedPublicKey := blsPublicKey1.Serialize()
	require.NotNil(t, serializedPublicKey)
	require.True(t, len(serializedPublicKey) > 0)
	// DeserializePublicKey
	deserializedPublicKey, err := serializedPublicKey.Deserialize()
	require.NoError(t, err)
	require.True(t, blsPublicKey1.Eq(deserializedPublicKey))

	// Test nil bls.Signature edge cases.
	// ToBytes()
	require.True(t, bytes.Equal((&Signature{}).ToBytes(), []byte{}))
	// FromBytes()
	blsSignature, err := (&Signature{}).FromBytes(nil)
	require.NoError(t, err)
	require.Nil(t, blsSignature)
	blsSignature, err = (&Signature{}).FromBytes([]byte{})
	require.NoError(t, err)
	require.Nil(t, blsSignature)
	// ToString()
	require.Equal(t, (&Signature{}).ToString(), "")
	// FromString()
	blsSignature, err = (&Signature{}).FromString("")
	require.NoError(t, err)
	require.Nil(t, blsSignature)
	// Eq()
	require.False(t, (&Signature{}).Eq(nil))
	require.False(t, (&Signature{}).Eq(&Signature{}))
	require.False(t, (&Signature{}).Eq(blsSignature1))
	require.False(t, blsSignature1.Eq(nil))
	require.False(t, blsSignature1.Eq(&Signature{}))
	// Copy()
	require.Nil(t, (&Signature{}).Copy().flowSignature)
	var nilSignature *Signature
	require.Nil(t, nilSignature.Copy())
	// FromString with malformed signature.
	blsSignature, err = (&Signature{}).FromString("malformed")
	require.Error(t, err)
	// ToAbbreviatedString
	require.Equal(t, (&Signature{}).ToAbbreviatedString(), "")
	// IsEmpty
	require.True(t, (&Signature{}).IsEmpty())
}

func TestJsonMarshalingBLSKeys(t *testing.T) {
	// Generate random BLS PrivateKey, PublicKey, and Signature.
	privateKey := _generateRandomBLSPrivateKey(t)
	publicKey := privateKey.PublicKey()
	signature, err := privateKey.Sign(_generateRandomBytes(t, 64))
	require.NoError(t, err)

	// Test JSON marshaling of bls.PrivateKey.
	privateKeyEncoded, err := json.Marshal(privateKey)
	require.NoError(t, err)
	privateKeyDecoded := &PrivateKey{}
	require.NoError(t, json.Unmarshal(privateKeyEncoded, privateKeyDecoded))
	require.True(t, privateKey.Eq(privateKeyDecoded))

	// Test JSON marshaling of bls.PublicKey.
	publicKeyEncoded, err := json.Marshal(publicKey)
	require.NoError(t, err)
	publicKeyDecoded := &PublicKey{}
	require.NoError(t, json.Unmarshal(publicKeyEncoded, publicKeyDecoded))
	require.True(t, publicKey.Eq(publicKeyDecoded))

	// Test JSON marshaling of bls.Signature.
	signatureEncoded, err := json.Marshal(signature)
	require.NoError(t, err)
	signatureDecoded := &Signature{}
	require.NoError(t, json.Unmarshal(signatureEncoded, signatureDecoded))
	require.True(t, signature.Eq(signatureDecoded))
}

func _generateRandomBLSPrivateKey(t *testing.T) *PrivateKey {
	privateKey, err := NewPrivateKey()
	require.NoError(t, err)
	return privateKey
}

func _generateRandomBytes(t *testing.T, numBytes int) []byte {
	randomBytes := make([]byte, numBytes)
	_, err := rand.Read(randomBytes)
	require.NoError(t, err)
	return randomBytes
}
