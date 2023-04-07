//go:build !relic

package lib

import (
	flowCrypto "github.com/onflow/flow-go/crypto"
	"io"
)

//
// TYPES: BLSPublicKey
//

const BLSNoRelicError = "BLS keys can't be used without Relic installed"

type BLSPublicKey struct {
	PublicKey flowCrypto.PublicKey
}

func NewBLSPublicKey(publicKeyBytes []byte) (*BLSPublicKey, error) {
	panic(BLSNoRelicError)
}

func (blsPublicKey *BLSPublicKey) ToBytes() []byte {
	panic(BLSNoRelicError)
}

func (blsPublicKey *BLSPublicKey) FromBytes(rr io.Reader) error {
	panic(BLSNoRelicError)
}

func (blsPublicKey *BLSPublicKey) Verify(blsSignature *BLSSignature, input []byte) (bool, error) {
	panic(BLSNoRelicError)
}

func (blsPublicKey *BLSPublicKey) Eq(other *BLSPublicKey) bool {
	panic(BLSNoRelicError)
}

//
// TYPES: BLSSignature
//

type BLSSignature struct {
	Signature flowCrypto.Signature
}

func NewBLSSignature(signature []byte) *BLSSignature {
	panic(BLSNoRelicError)
}

func (blsSignature *BLSSignature) ToBytes() []byte {
	panic(BLSNoRelicError)
}

func (blsSignature *BLSSignature) FromBytes(rr io.Reader) error {
	panic(BLSNoRelicError)
}

func (blsSignature *BLSSignature) Eq(other *BLSSignature) bool {
	panic(BLSNoRelicError)
}
