//go:build !relic

package bls

const BLSNoRelicError = "BLS keys can't be used without Relic installed"

func AggregateSignatures(signatures []*Signature) (*Signature, error) {
	panic(BLSNoRelicError)
}

func VerifyAggregateSignatureSinglePayload(publicKeys []*PublicKey, signature *Signature, payloadBytes []byte) (bool, error) {
	panic(BLSNoRelicError)
}

func VerifyAggregateSignatureMultiplePayloads(publicKeys []*PublicKey, signature *Signature, payloadsBytes [][]byte) (bool, error) {
	panic(BLSNoRelicError)
}

//
// TYPES: PrivateKey
//

type PrivateKey struct{}

func NewPrivateKey() (*PrivateKey, error) {
	panic(BLSNoRelicError)
}

func (privateKey *PrivateKey) Sign(payloadBytes []byte) (*Signature, error) {
	panic(BLSNoRelicError)
}

func (privateKey *PrivateKey) PublicKey() *PublicKey {
	panic(BLSNoRelicError)
}

func (privateKey *PrivateKey) ToString() string {
	panic(BLSNoRelicError)
}

func (privateKey *PrivateKey) FromSeed(seed []byte) (*PrivateKey, error) {
	panic(BLSNoRelicError)
}

func (privateKey *PrivateKey) FromString(privateKeyString string) (*PrivateKey, error) {
	panic(BLSNoRelicError)
}

func (privateKey *PrivateKey) MarshalJSON() ([]byte, error) {
	panic(BLSNoRelicError)
}

func (privateKey *PrivateKey) UnmarshalJSON(data []byte) error {
	panic(BLSNoRelicError)
}

func (privateKey *PrivateKey) Eq(other *PrivateKey) bool {
	panic(BLSNoRelicError)
}

//
// TYPES: PublicKey
//

type PublicKey struct{}

func (publicKey *PublicKey) Verify(signature *Signature, input []byte) (bool, error) {
	panic(BLSNoRelicError)
}

func (publicKey *PublicKey) ToBytes() []byte {
	panic(BLSNoRelicError)
}

func (publicKey *PublicKey) FromBytes(publicKeyBytes []byte) (*PublicKey, error) {
	panic(BLSNoRelicError)
}

func (publicKey *PublicKey) ToString() string {
	panic(BLSNoRelicError)
}

func (publicKey *PublicKey) FromString(publicKeyString string) (*PublicKey, error) {
	panic(BLSNoRelicError)
}

func (publicKey *PublicKey) ToAbbreviatedString() string {
	panic(BLSNoRelicError)
}

func (publicKey *PublicKey) MarshalJSON() ([]byte, error) {
	panic(BLSNoRelicError)
}

func (publicKey *PublicKey) UnmarshalJSON(data []byte) error {
	panic(BLSNoRelicError)
}

func (publicKey *PublicKey) Eq(other *PublicKey) bool {
	panic(BLSNoRelicError)
}

func (publicKey *PublicKey) Copy() *PublicKey {
	panic(BLSNoRelicError)
}

func (publicKey *PublicKey) IsEmpty() bool {
	panic(BLSNoRelicError)
}

type SerializedPublicKey string

func (publicKey *PublicKey) Serialize() SerializedPublicKey {
	panic(BLSNoRelicError)
}

func (serializedPublicKey SerializedPublicKey) Deserialize() (*PublicKey, error) {
	panic(BLSNoRelicError)
}

//
// TYPES: Signature
//

type Signature struct{}

func (signature *Signature) ToBytes() []byte {
	panic(BLSNoRelicError)
}

func (signature *Signature) FromBytes(signatureBytes []byte) (*Signature, error) {
	panic(BLSNoRelicError)
}

func (signature *Signature) ToString() string {
	panic(BLSNoRelicError)
}

func (signature *Signature) FromString(signatureString string) (*Signature, error) {
	panic(BLSNoRelicError)
}

func (signature *Signature) ToAbbreviatedString() string {
	panic(BLSNoRelicError)
}

func (signature *Signature) MarshalJSON() ([]byte, error) {
	panic(BLSNoRelicError)
}

func (signature *Signature) UnmarshalJSON(data []byte) error {
	panic(BLSNoRelicError)
}

func (signature *Signature) Eq(other *Signature) bool {
	panic(BLSNoRelicError)
}

func (signature *Signature) Copy() *Signature {
	panic(BLSNoRelicError)
}

func (signature *Signature) IsEmpty() bool {
	panic(BLSNoRelicError)
}
