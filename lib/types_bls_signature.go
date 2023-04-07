//go:build relic

package lib

import (
	"bytes"
	flowCrypto "github.com/onflow/flow-go/crypto"
	"io"
)

//
// TYPES: BLSPublicKey
//

const BLSSigningAlgorithm = flowCrypto.BLSBLS12381

var BLSHashingAlgorithm = flowCrypto.NewExpandMsgXOFKMAC128("deso-protocol")

type BLSPublicKey struct {
	PublicKey flowCrypto.PublicKey
}

func NewBLSPublicKey(publicKeyBytes []byte) (*BLSPublicKey, error) {
	publicKey, err := flowCrypto.DecodePublicKey(BLSSigningAlgorithm, publicKeyBytes)
	return &BLSPublicKey{PublicKey: publicKey}, err
}

func (blsPublicKey *BLSPublicKey) ToBytes() []byte {
	return EncodeByteArray(blsPublicKey.PublicKey.Encode())
}

func (blsPublicKey *BLSPublicKey) FromBytes(rr io.Reader) error {
	publicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return err
	}
	blsPublicKey.PublicKey, err = flowCrypto.DecodePublicKey(BLSSigningAlgorithm, publicKeyBytes)
	return err
}

func (blsPublicKey *BLSPublicKey) Verify(blsSignature *BLSSignature, input []byte) (bool, error) {
	return blsPublicKey.PublicKey.Verify(blsSignature.Signature, input, BLSHashingAlgorithm)
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

func NewBLSSignature(signature []byte) *BLSSignature {
	return &BLSSignature{Signature: signature}
}

func (blsSignature *BLSSignature) ToBytes() []byte {
	return EncodeByteArray(blsSignature.Signature)
}

func (blsSignature *BLSSignature) FromBytes(rr io.Reader) error {
	var err error
	blsSignature.Signature, err = DecodeByteArray(rr)
	return err
}

func (blsSignature *BLSSignature) Eq(other *BLSSignature) bool {
	return bytes.Equal(blsSignature.ToBytes(), other.ToBytes())
}
