//go:build !relic

package bls

import (
	flowCrypto "github.com/onflow/flow-go/crypto"
)

const BLSNoRelicError = "BLS keys can't be used without Relic installed"

func AggregateSignatures(blsSignatures []*Signature) (*Signature, error) {
	panic(BLSNoRelicError)
}

func VerifyAggregateSignature(blsPublicKeys []*PublicKey, blsSignature *Signature, payloadBytes []byte) (bool, error) {
	panic(BLSNoRelicError)
}

//
// TYPES: PrivateKey
//

type PrivateKey struct {
	PrivateKey flowCrypto.PrivateKey
}

func (blsPrivateKey *PrivateKey) Sign(payloadBytes []byte) (*Signature, error) {
	panic(BLSNoRelicError)
}

func (blsPrivateKey *PrivateKey) PublicKey() *PublicKey {
	panic(BLSNoRelicError)
}

func (blsPrivateKey *PrivateKey) ToString() string {
	panic(BLSNoRelicError)
}

func (blsPrivateKey *PrivateKey) FromString(privateKeyString string) (*PrivateKey, error) {
	panic(BLSNoRelicError)
}

func (blsPrivateKey *PrivateKey) Eq(other *PrivateKey) bool {
	panic(BLSNoRelicError)
}

//
// TYPES: PublicKey
//

type PublicKey struct {
	PublicKey flowCrypto.PublicKey
}

func (blsPublicKey *PublicKey) Verify(blsSignature *Signature, input []byte) (bool, error) {
	panic(BLSNoRelicError)
}

func (blsPublicKey *PublicKey) ToBytes() []byte {
	panic(BLSNoRelicError)
}

func (blsPublicKey *PublicKey) FromBytes(publicKeyBytes []byte) (*PublicKey, error) {
	panic(BLSNoRelicError)
}

func (blsPublicKey *PublicKey) ToString() string {
	panic(BLSNoRelicError)
}

func (blsPublicKey *PublicKey) FromString(publicKeyString string) (*PublicKey, error) {
	panic(BLSNoRelicError)
}

func (blsPublicKey *PublicKey) Eq(other *PublicKey) bool {
	panic(BLSNoRelicError)
}

func (blsPublicKey *PublicKey) Copy() *PublicKey {
	panic(BLSNoRelicError)
}

//
// TYPES: Signature
//

type Signature struct {
	Signature flowCrypto.Signature
}

func (blsSignature *Signature) ToBytes() []byte {
	panic(BLSNoRelicError)
}

func (blsSignature *Signature) FromBytes(signatureBytes []byte) (*Signature, error) {
	panic(BLSNoRelicError)
}

func (blsSignature *Signature) ToString() string {
	panic(BLSNoRelicError)
}

func (blsSignature *Signature) FromString(signatureString string) (*Signature, error) {
	panic(BLSNoRelicError)
}

func (blsSignature *Signature) Eq(other *Signature) bool {
	panic(BLSNoRelicError)
}

func (blsSignature *Signature) Copy() *Signature {
	panic(BLSNoRelicError)
}
