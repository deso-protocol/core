//go:build relic

package lib

import (
	"bytes"
	"encoding/hex"
	flowCrypto "github.com/onflow/flow-go/crypto"
	"io"
	"strings"
)

const BLSSigningAlgorithm = flowCrypto.BLSBLS12381

// TODO: what should the domainTag param be?
var BLSHashingAlgorithm = flowCrypto.NewExpandMsgXOFKMAC128("deso-protocol")

//
// TYPES: BLSPrivateKey
//

type BLSPrivateKey struct {
	PrivateKey flowCrypto.PrivateKey
}

func NewBLSPrivateKey() (*BLSPrivateKey, error) {
	// This is a helper util for generating a random BLSPrivateKey.
	privateKey, err := flowCrypto.GeneratePrivateKey(BLSSigningAlgorithm, RandomBytes(64))
	if err != nil {
		return nil, err
	}
	return &BLSPrivateKey{PrivateKey: privateKey}, nil
}

func (blsPrivateKey *BLSPrivateKey) Sign(payloadBytes []byte) (*BLSSignature, error) {
	signature, err := blsPrivateKey.PrivateKey.Sign(payloadBytes, BLSHashingAlgorithm)
	if err != nil {
		return nil, err
	}
	return &BLSSignature{Signature: signature}, nil
}

func (blsPrivateKey *BLSPrivateKey) PublicKey() *BLSPublicKey {
	return &BLSPublicKey{PublicKey: blsPrivateKey.PrivateKey.PublicKey()}
}

func (blsPrivateKey *BLSPrivateKey) ToString() string {
	return blsPrivateKey.PrivateKey.String()
}

func (blsPrivateKey *BLSPrivateKey) FromString(privateKeyString string) error {
	// Chop off leading 0x, if exists. Otherwise, does nothing.
	privateKeyStringCopy, _ := strings.CutPrefix(privateKeyString, "0x")
	// Convert from hex string to byte slice.
	privateKeyBytes, err := hex.DecodeString(privateKeyStringCopy)
	if err != nil {
		return err
	}
	// Convert from byte slice to BLSPrivateKey.
	blsPrivateKey.PrivateKey, err = flowCrypto.DecodePrivateKey(BLSSigningAlgorithm, privateKeyBytes)
	return err
}

func (blsPrivateKey *BLSPrivateKey) Eq(other *BLSPrivateKey) bool {
	return blsPrivateKey.PrivateKey.Equals(other.PrivateKey)
}

//
// TYPES: BLSPublicKey
//

type BLSPublicKey struct {
	PublicKey flowCrypto.PublicKey
}

func (blsPublicKey *BLSPublicKey) Verify(blsSignature *BLSSignature, input []byte) (bool, error) {
	return blsPublicKey.PublicKey.Verify(blsSignature.Signature, input, BLSHashingAlgorithm)
}

func (blsPublicKey *BLSPublicKey) ToBytes() []byte {
	return EncodeByteArray(blsPublicKey.PublicKey.Encode())
}

func (blsPublicKey *BLSPublicKey) FromBytes(publicKeyBytes []byte) error {
	return blsPublicKey.ReadBytes(bytes.NewReader(publicKeyBytes))
}

func (blsPublicKey *BLSPublicKey) ReadBytes(rr io.Reader) error {
	publicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return err
	}
	blsPublicKey.PublicKey, err = flowCrypto.DecodePublicKey(BLSSigningAlgorithm, publicKeyBytes)
	return err
}

func (blsPublicKey *BLSPublicKey) ToString() string {
	return blsPublicKey.PublicKey.String()
}

func (blsPublicKey *BLSPublicKey) FromString(publicKeyString string) error {
	// Chop off leading 0x, if exists. Otherwise, does nothing.
	publicKeyStringCopy, _ := strings.CutPrefix(publicKeyString, "0x")
	// Convert from hex string to byte slice.
	publicKeyBytes, err := hex.DecodeString(publicKeyStringCopy)
	if err != nil {
		return err
	}
	// Convert from byte slice to BLSPublicKey.
	blsPublicKey.PublicKey, err = flowCrypto.DecodePublicKey(BLSSigningAlgorithm, publicKeyBytes)
	return err
}

func (blsPublicKey *BLSPublicKey) Eq(other *BLSPublicKey) bool {
	return blsPublicKey.PublicKey.Equals(other.PublicKey)
}

//
// TYPES: BLSSignature
//

type BLSSignature struct {
	Signature flowCrypto.Signature
}

func (blsSignature *BLSSignature) ToBytes() []byte {
	return EncodeByteArray(blsSignature.Signature.Bytes())
}

func (blsSignature *BLSSignature) FromBytes(signatureBytes []byte) error {
	return blsSignature.ReadBytes(bytes.NewReader(signatureBytes))
}

func (blsSignature *BLSSignature) ReadBytes(rr io.Reader) error {
	signatureBytes, err := DecodeByteArray(rr)
	if err != nil {
		return err
	}
	blsSignature.Signature = signatureBytes
	return nil
}

func (blsSignature *BLSSignature) ToString() string {
	return blsSignature.Signature.String()
}

func (blsSignature *BLSSignature) FromString(signatureString string) error {
	// Chop off leading 0x, if exists. Otherwise, does nothing.
	signatureStringCopy, _ := strings.CutPrefix(signatureString, "0x")
	// Convert from hex string to byte slice.
	signatureBytes, err := hex.DecodeString(signatureStringCopy)
	if err != nil {
		return err
	}
	// Convert from byte slice to BLSSignature.
	blsSignature.Signature = signatureBytes
	return nil
}

func (blsSignature *BLSSignature) Eq(other *BLSSignature) bool {
	return bytes.Equal(blsSignature.ToBytes(), other.ToBytes())
}
