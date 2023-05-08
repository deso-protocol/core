//go:build !relic

package lib

import (
	flowCrypto "github.com/onflow/flow-go/crypto"
	"io"
)

const BLSNoRelicError = "BLS keys can't be used without Relic installed"

func AggregateBLSSignatures(blsSignatures []*BLSSignature) (*BLSSignature, error) {
	panic(BLSNoRelicError)
}

func VerifyAggregateBLSSignature(blsPublicKeys []*BLSPublicKey, blsSignature *BLSSignature, payloadBytes []byte) (bool, error) {
	panic(BLSNoRelicError)
}

//
// TYPES: BLSPrivateKey
//

type BLSPrivateKey struct {
	PrivateKey flowCrypto.PrivateKey
}

func (blsPrivateKey *BLSPrivateKey) Sign(payloadBytes []byte) (*BLSSignature, error) {
	panic(BLSNoRelicError)
}

func (blsPrivateKey *BLSPrivateKey) PublicKey() *BLSPublicKey {
	panic(BLSNoRelicError)
}

func (blsPrivateKey *BLSPrivateKey) ToString() string {
	panic(BLSNoRelicError)
}

func (blsPrivateKey *BLSPrivateKey) FromString(privateKeyString string) (*BLSPrivateKey, error) {
	panic(BLSNoRelicError)
}

func (blsPrivateKey *BLSPrivateKey) Eq(other *BLSPrivateKey) bool {
	panic(BLSNoRelicError)
}

//
// TYPES: BLSPublicKey
//

type BLSPublicKey struct {
	PublicKey flowCrypto.PublicKey
}

func (blsPublicKey *BLSPublicKey) Verify(blsSignature *BLSSignature, input []byte) (bool, error) {
	panic(BLSNoRelicError)
}

func (blsPublicKey *BLSPublicKey) ToBytes() []byte {
	panic(BLSNoRelicError)
}

func (blsPublicKey *BLSPublicKey) FromBytes(publicKeyBytes []byte) (*BLSPublicKey, error) {
	panic(BLSNoRelicError)
}

func (blsPublicKey *BLSPublicKey) ReadBytes(rr io.Reader) (*BLSPublicKey, error) {
	panic(BLSNoRelicError)
}

func (blsPublicKey *BLSPublicKey) ToString() string {
	panic(BLSNoRelicError)
}

func (blsPublicKey *BLSPublicKey) FromString(publicKeyString string) (*BLSPublicKey, error) {
	panic(BLSNoRelicError)
}

func (blsPublicKey *BLSPublicKey) Eq(other *BLSPublicKey) bool {
	panic(BLSNoRelicError)
}

func (blsPublicKey *BLSPublicKey) Copy() *BLSPublicKey {
	panic(BLSNoRelicError)
}

//
// TYPES: BLSSignature
//

type BLSSignature struct {
	Signature flowCrypto.Signature
}

func (blsSignature *BLSSignature) ToBytes() []byte {
	panic(BLSNoRelicError)
}

func (blsSignature *BLSSignature) FromBytes(signatureBytes []byte) (*BLSSignature, error) {
	panic(BLSNoRelicError)
}

func (blsSignature *BLSSignature) ReadBytes(rr io.Reader) (*BLSSignature, error) {
	panic(BLSNoRelicError)
}

func (blsSignature *BLSSignature) ToString() string {
	panic(BLSNoRelicError)
}

func (blsSignature *BLSSignature) FromString(signatureString string) (*BLSSignature, error) {
	panic(BLSNoRelicError)
}

func (blsSignature *BLSSignature) Eq(other *BLSSignature) bool {
	panic(BLSNoRelicError)
}

func (blsSignature *BLSSignature) Copy() *BLSSignature {
	panic(BLSNoRelicError)
}
