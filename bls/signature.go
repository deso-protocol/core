//go:build relic

package bls

import (
	"bytes"
	"encoding/hex"
	"errors"
	flowCrypto "github.com/onflow/flow-go/crypto"
	"strings"
)

const SigningAlgorithm = flowCrypto.BLSBLS12381

// TODO: what should the domainTag param be?
var HashingAlgorithm = flowCrypto.NewExpandMsgXOFKMAC128("deso-protocol")

func AggregateSignatures(blsSignatures []*Signature) (*Signature, error) {
	var signatures []flowCrypto.Signature
	for _, blsSignature := range blsSignatures {
		signatures = append(signatures, blsSignature.Signature)
	}
	aggregateSignature, err := flowCrypto.AggregateBLSSignatures(signatures)
	if err != nil {
		return nil, err
	}
	return &Signature{Signature: aggregateSignature}, nil
}

func VerifyAggregateSignature(blsPublicKeys []*PublicKey, blsSignature *Signature, payloadBytes []byte) (bool, error) {
	var publicKeys []flowCrypto.PublicKey
	for _, blsPublicKey := range blsPublicKeys {
		publicKeys = append(publicKeys, blsPublicKey.PublicKey)
	}
	return flowCrypto.VerifyBLSSignatureOneMessage(publicKeys, blsSignature.Signature, payloadBytes, HashingAlgorithm)
}

//
// TYPES: PrivateKey
//

type PrivateKey struct {
	PrivateKey flowCrypto.PrivateKey
}

func (blsPrivateKey *PrivateKey) Sign(payloadBytes []byte) (*Signature, error) {
	if blsPrivateKey.PrivateKey == nil {
		return nil, errors.New("bls.PrivateKey is nil")
	}
	signature, err := blsPrivateKey.PrivateKey.Sign(payloadBytes, HashingAlgorithm)
	if err != nil {
		return nil, err
	}
	return &Signature{Signature: signature}, nil
}

func (blsPrivateKey *PrivateKey) PublicKey() *PublicKey {
	if blsPrivateKey.PrivateKey == nil {
		return nil
	}
	return &PublicKey{PublicKey: blsPrivateKey.PrivateKey.PublicKey()}
}

func (blsPrivateKey *PrivateKey) ToString() string {
	if blsPrivateKey.PrivateKey == nil {
		return ""
	}
	return blsPrivateKey.PrivateKey.String()
}

func (blsPrivateKey *PrivateKey) FromString(privateKeyString string) (*PrivateKey, error) {
	if privateKeyString == "" {
		return nil, errors.New("empty bls.PrivateKey string provided")
	}
	// Chop off leading 0x, if exists. Otherwise, does nothing.
	privateKeyStringCopy, _ := strings.CutPrefix(privateKeyString, "0x")
	// Convert from hex string to byte slice.
	privateKeyBytes, err := hex.DecodeString(privateKeyStringCopy)
	if err != nil {
		return nil, err
	}
	// Convert from byte slice to bls.PrivateKey.
	blsPrivateKey.PrivateKey, err = flowCrypto.DecodePrivateKey(SigningAlgorithm, privateKeyBytes)
	return blsPrivateKey, err
}

func (blsPrivateKey *PrivateKey) Eq(other *PrivateKey) bool {
	if blsPrivateKey.PrivateKey == nil || other == nil {
		return false
	}
	return blsPrivateKey.PrivateKey.Equals(other.PrivateKey)
}

//
// TYPES: PublicKey
//

type PublicKey struct {
	PublicKey flowCrypto.PublicKey
}

func (blsPublicKey *PublicKey) Verify(blsSignature *Signature, input []byte) (bool, error) {
	if blsPublicKey.PublicKey == nil {
		return false, errors.New("bls.PublicKey is nil")
	}
	return blsPublicKey.PublicKey.Verify(blsSignature.Signature, input, HashingAlgorithm)
}

func (blsPublicKey *PublicKey) ToBytes() []byte {
	var publicKeyBytes []byte
	if blsPublicKey.PublicKey != nil {
		publicKeyBytes = blsPublicKey.PublicKey.Encode()
	}
	return publicKeyBytes
}

func (blsPublicKey *PublicKey) FromBytes(publicKeyBytes []byte) (*PublicKey, error) {
	if len(publicKeyBytes) == 0 {
		return nil, errors.New("empty bls.PublicKey bytes provided")
	}
	var err error
	blsPublicKey.PublicKey, err = flowCrypto.DecodePublicKey(SigningAlgorithm, publicKeyBytes)
	return blsPublicKey, err
}

func (blsPublicKey *PublicKey) ToString() string {
	if blsPublicKey.PublicKey == nil {
		return ""
	}
	return blsPublicKey.PublicKey.String()
}

func (blsPublicKey *PublicKey) FromString(publicKeyString string) (*PublicKey, error) {
	if publicKeyString == "" {
		return nil, errors.New("empty bls.PublicKey string provided")
	}
	// Chop off leading 0x, if exists. Otherwise, does nothing.
	publicKeyStringCopy, _ := strings.CutPrefix(publicKeyString, "0x")
	// Convert from hex string to byte slice.
	publicKeyBytes, err := hex.DecodeString(publicKeyStringCopy)
	if err != nil {
		return nil, err
	}
	// Convert from byte slice to bls.PublicKey.
	blsPublicKey.PublicKey, err = flowCrypto.DecodePublicKey(SigningAlgorithm, publicKeyBytes)
	return blsPublicKey, err
}

func (blsPublicKey *PublicKey) Eq(other *PublicKey) bool {
	if blsPublicKey.PublicKey == nil || other == nil {
		return false
	}
	return blsPublicKey.PublicKey.Equals(other.PublicKey)
}

func (blsPublicKey *PublicKey) Copy() *PublicKey {
	return &PublicKey{
		PublicKey: blsPublicKey.PublicKey,
	}
}

//
// TYPES: Signature
//

type Signature struct {
	Signature flowCrypto.Signature
}

func (blsSignature *Signature) ToBytes() []byte {
	var signatureBytes []byte
	if blsSignature.Signature != nil {
		signatureBytes = blsSignature.Signature.Bytes()
	}
	return signatureBytes
}

func (blsSignature *Signature) FromBytes(signatureBytes []byte) (*Signature, error) {
	if len(signatureBytes) == 0 {
		return nil, errors.New("empty bls.Signature bytes provided")
	}
	blsSignature.Signature = signatureBytes
	return blsSignature, nil
}

func (blsSignature *Signature) ToString() string {
	if blsSignature.Signature == nil {
		return ""
	}
	return blsSignature.Signature.String()
}

func (blsSignature *Signature) FromString(signatureString string) (*Signature, error) {
	if signatureString == "" {
		return nil, errors.New("empty bls.Signature string provided")
	}
	// Chop off leading 0x, if exists. Otherwise, does nothing.
	signatureStringCopy, _ := strings.CutPrefix(signatureString, "0x")
	// Convert from hex string to byte slice.
	signatureBytes, err := hex.DecodeString(signatureStringCopy)
	if err != nil {
		return nil, err
	}
	// Convert from byte slice to bls.Signature.
	blsSignature.Signature = signatureBytes
	return blsSignature, nil
}

func (blsSignature *Signature) Eq(other *Signature) bool {
	if blsSignature.Signature == nil || other == nil {
		return false
	}
	return bytes.Equal(blsSignature.ToBytes(), other.ToBytes())
}

func (blsSignature *Signature) Copy() *Signature {
	if blsSignature.Signature == nil {
		return &Signature{}
	}
	return &Signature{
		Signature: append([]byte{}, blsSignature.Signature.Bytes()...),
	}
}
