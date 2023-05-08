//go:build relic

package lib

import (
	"bytes"
	"encoding/hex"
	"errors"
	flowCrypto "github.com/onflow/flow-go/crypto"
	"io"
	"strings"
)

const BLSSigningAlgorithm = flowCrypto.BLSBLS12381

// TODO: what should the domainTag param be?
var BLSHashingAlgorithm = flowCrypto.NewExpandMsgXOFKMAC128("deso-protocol")

func AggregateBLSSignatures(blsSignatures []*BLSSignature) (*BLSSignature, error) {
	var signatures []flowCrypto.Signature
	for _, blsSignature := range blsSignatures {
		signatures = append(signatures, blsSignature.Signature)
	}
	aggregateSignature, err := flowCrypto.AggregateBLSSignatures(signatures)
	if err != nil {
		return nil, err
	}
	return &BLSSignature{Signature: aggregateSignature}, nil
}

func VerifyAggregateBLSSignature(blsPublicKeys []*BLSPublicKey, blsSignature *BLSSignature, payloadBytes []byte) (bool, error) {
	var publicKeys []flowCrypto.PublicKey
	for _, blsPublicKey := range blsPublicKeys {
		publicKeys = append(publicKeys, blsPublicKey.PublicKey)
	}
	return flowCrypto.VerifyBLSSignatureOneMessage(publicKeys, blsSignature.Signature, payloadBytes, BLSHashingAlgorithm)
}

//
// TYPES: BLSPrivateKey
//

type BLSPrivateKey struct {
	PrivateKey flowCrypto.PrivateKey
}

func (blsPrivateKey *BLSPrivateKey) Sign(payloadBytes []byte) (*BLSSignature, error) {
	if blsPrivateKey.PrivateKey == nil {
		return nil, errors.New("BLSPrivateKey is nil")
	}
	signature, err := blsPrivateKey.PrivateKey.Sign(payloadBytes, BLSHashingAlgorithm)
	if err != nil {
		return nil, err
	}
	return &BLSSignature{Signature: signature}, nil
}

func (blsPrivateKey *BLSPrivateKey) PublicKey() *BLSPublicKey {
	if blsPrivateKey.PrivateKey == nil {
		return nil
	}
	return &BLSPublicKey{PublicKey: blsPrivateKey.PrivateKey.PublicKey()}
}

func (blsPrivateKey *BLSPrivateKey) ToString() string {
	if blsPrivateKey.PrivateKey == nil {
		return ""
	}
	return blsPrivateKey.PrivateKey.String()
}

func (blsPrivateKey *BLSPrivateKey) FromString(privateKeyString string) (*BLSPrivateKey, error) {
	if privateKeyString == "" {
		return nil, errors.New("empty BLSPrivateKey string provided")
	}
	// Chop off leading 0x, if exists. Otherwise, does nothing.
	privateKeyStringCopy, _ := strings.CutPrefix(privateKeyString, "0x")
	// Convert from hex string to byte slice.
	privateKeyBytes, err := hex.DecodeString(privateKeyStringCopy)
	if err != nil {
		return nil, err
	}
	// Convert from byte slice to BLSPrivateKey.
	blsPrivateKey.PrivateKey, err = flowCrypto.DecodePrivateKey(BLSSigningAlgorithm, privateKeyBytes)
	return blsPrivateKey, err
}

func (blsPrivateKey *BLSPrivateKey) Eq(other *BLSPrivateKey) bool {
	if blsPrivateKey.PrivateKey == nil || other == nil {
		return false
	}
	return blsPrivateKey.PrivateKey.Equals(other.PrivateKey)
}

//
// TYPES: BLSPublicKey
//

type BLSPublicKey struct {
	PublicKey flowCrypto.PublicKey
}

func (blsPublicKey *BLSPublicKey) Verify(blsSignature *BLSSignature, input []byte) (bool, error) {
	if blsPublicKey.PublicKey == nil {
		return false, errors.New("BLSPublicKey is nil")
	}
	return blsPublicKey.PublicKey.Verify(blsSignature.Signature, input, BLSHashingAlgorithm)
}

func (blsPublicKey *BLSPublicKey) ToBytes() []byte {
	var publicKeyBytes []byte
	if blsPublicKey.PublicKey != nil {
		publicKeyBytes = blsPublicKey.PublicKey.Encode()
	}
	return EncodeByteArray(publicKeyBytes)
}

func (blsPublicKey *BLSPublicKey) FromBytes(publicKeyBytes []byte) (*BLSPublicKey, error) {
	return blsPublicKey.ReadBytes(bytes.NewReader(publicKeyBytes))
}

func (blsPublicKey *BLSPublicKey) ReadBytes(rr io.Reader) (*BLSPublicKey, error) {
	publicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return nil, err
	}
	blsPublicKey.PublicKey, err = flowCrypto.DecodePublicKey(BLSSigningAlgorithm, publicKeyBytes)
	return blsPublicKey, err
}

func (blsPublicKey *BLSPublicKey) ToString() string {
	if blsPublicKey.PublicKey == nil {
		return ""
	}
	return blsPublicKey.PublicKey.String()
}

func (blsPublicKey *BLSPublicKey) FromString(publicKeyString string) (*BLSPublicKey, error) {
	if publicKeyString == "" {
		return nil, errors.New("empty BLSPublicKey string provided")
	}
	// Chop off leading 0x, if exists. Otherwise, does nothing.
	publicKeyStringCopy, _ := strings.CutPrefix(publicKeyString, "0x")
	// Convert from hex string to byte slice.
	publicKeyBytes, err := hex.DecodeString(publicKeyStringCopy)
	if err != nil {
		return nil, err
	}
	// Convert from byte slice to BLSPublicKey.
	blsPublicKey.PublicKey, err = flowCrypto.DecodePublicKey(BLSSigningAlgorithm, publicKeyBytes)
	return blsPublicKey, err
}

func (blsPublicKey *BLSPublicKey) Eq(other *BLSPublicKey) bool {
	if blsPublicKey.PublicKey == nil || other == nil {
		return false
	}
	return blsPublicKey.PublicKey.Equals(other.PublicKey)
}

func (blsPublicKey *BLSPublicKey) Copy() *BLSPublicKey {
	return &BLSPublicKey{
		PublicKey: blsPublicKey.PublicKey,
	}
}

//
// TYPES: BLSSignature
//

type BLSSignature struct {
	Signature flowCrypto.Signature
}

func (blsSignature *BLSSignature) ToBytes() []byte {
	var signatureBytes []byte
	if blsSignature.Signature != nil {
		signatureBytes = blsSignature.Signature.Bytes()
	}
	return EncodeByteArray(signatureBytes)
}

func (blsSignature *BLSSignature) FromBytes(signatureBytes []byte) (*BLSSignature, error) {
	return blsSignature.ReadBytes(bytes.NewReader(signatureBytes))
}

func (blsSignature *BLSSignature) ReadBytes(rr io.Reader) (*BLSSignature, error) {
	signatureBytes, err := DecodeByteArray(rr)
	if err != nil {
		return nil, err
	}
	blsSignature.Signature = signatureBytes
	return blsSignature, nil
}

func (blsSignature *BLSSignature) ToString() string {
	if blsSignature.Signature == nil {
		return ""
	}
	return blsSignature.Signature.String()
}

func (blsSignature *BLSSignature) FromString(signatureString string) (*BLSSignature, error) {
	if signatureString == "" {
		return nil, errors.New("empty BLSSignature string provided")
	}
	// Chop off leading 0x, if exists. Otherwise, does nothing.
	signatureStringCopy, _ := strings.CutPrefix(signatureString, "0x")
	// Convert from hex string to byte slice.
	signatureBytes, err := hex.DecodeString(signatureStringCopy)
	if err != nil {
		return nil, err
	}
	// Convert from byte slice to BLSSignature.
	blsSignature.Signature = signatureBytes
	return blsSignature, nil
}

func (blsSignature *BLSSignature) Eq(other *BLSSignature) bool {
	if blsSignature.Signature == nil || other == nil {
		return false
	}
	return bytes.Equal(blsSignature.ToBytes(), other.ToBytes())
}

func (blsSignature *BLSSignature) Copy() *BLSSignature {
	if blsSignature.Signature == nil {
		return &BLSSignature{}
	}
	return &BLSSignature{
		Signature: append([]byte{}, blsSignature.Signature.Bytes()...),
	}
}
