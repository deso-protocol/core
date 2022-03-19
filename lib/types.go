package lib

import (
	"bytes"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/pkg/errors"
)

// A PKID is an ID associated with a public key. In the DB, various fields are
// indexed using the PKID rather than the user's public key directly in order to
// create one layer of indirection between the public key and the user's data. This
// makes it easy for the user to transfer certain data to a new public key.
type PKID [33]byte
type PublicKey [33]byte

var (
	ZeroPKID      = PKID{}
	ZeroBlockHash = BlockHash{}
)

func NewPKID(pkidBytes []byte) *PKID {
	if len(pkidBytes) == 0 {
		return nil
	}
	pkid := &PKID{}
	copy(pkid[:], pkidBytes)
	return pkid
}

func (pkid *PKID) RawEncodeWithoutMetadata(blockHeight uint64) []byte {
	return EncodeByteArray(pkid[:])
}

func (pkid *PKID) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	pkidBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "PKID.Decode: Problem reading PKID")
	}
	copy(pkid[:], pkidBytes)
	return nil
}

func (pkid *PKID) ToBytes() []byte {
	return pkid[:]
}

func (pkid *PKID) ToString() string {
	return string(pkid.ToBytes())
}

func (pkid *PKID) NewPKID() *PKID {
	newPkid := &PKID{}
	copy(newPkid[:], pkid[:])
	return newPkid
}

func NewPublicKey(publicKeyBytes []byte) *PublicKey {
	if len(publicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		return nil
	}
	publicKey := &PublicKey{}
	copy(publicKey[:], publicKeyBytes)
	return publicKey
}

func (publicKey *PublicKey) ToBytes() []byte {
	return publicKey[:]
}

func (publicKey *PublicKey) RawEncodeWithoutMetadata(blockHeight uint64) []byte {
	return EncodeByteArray(publicKey[:])
}

func (publicKey *PublicKey) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	publicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "PublicKey.Decode: Problem reading publicKey")
	}
	copy(publicKey[:], publicKeyBytes)
	return nil
}

func PublicKeyToPKID(publicKey []byte) *PKID {
	if len(publicKey) == 0 {
		return nil
	}
	pkid := &PKID{}
	copy(pkid[:], publicKey)
	return pkid
}

func PKIDToPublicKey(pkid *PKID) []byte {
	if pkid == nil {
		return nil
	}
	return pkid[:]
}

const HashSizeBytes = 32

// BlockHash is a convenient alias for a block hash.
type BlockHash [HashSizeBytes]byte

func NewBlockHash(input []byte) *BlockHash {
	blockHash := &BlockHash{}
	copy(blockHash[:], input)
	return blockHash
}

func (bh *BlockHash) RawEncodeWithoutMetadata(blockHeight uint64) []byte {
	return EncodeByteArray(bh[:])
}

func (bh *BlockHash) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	blockHashBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "BlockHash.Decode: Problem reading BlockHash")
	}
	copy(bh[:], blockHashBytes)
	return nil
}

func (bh *BlockHash) String() string {
	return fmt.Sprintf("%064x", HashToBigint(bh))
}

func (bh *BlockHash) ToBytes() []byte {
	res := make([]byte, HashSizeBytes)
	copy(res, bh[:])
	return res
}

// IsEqual returns true if target is the same as hash.
func (bh *BlockHash) IsEqual(target *BlockHash) bool {
	if bh == nil && target == nil {
		return true
	}
	if bh == nil || target == nil {
		return false
	}
	return *bh == *target
}

func (bh *BlockHash) NewBlockHash() *BlockHash {
	newBlockhash := &BlockHash{}
	copy(newBlockhash[:], bh[:])
	return newBlockhash
}

//var _ sql.Scanner = (*BlockHash)(nil)
//
//// Scan scans the time parsing it if necessary using timeFormat.
//func (bb *BlockHash) Scan(src interface{}) (err error) {
//	switch src := src.(type) {
//	case []byte:
//		copy(bb[:], src)
//		return err
//	case nil:
//		return nil
//	default:
//		return fmt.Errorf("unsupported data type: %T", src)
//	}
//}
//
//var _ driver.Valuer = (*BlockHash)(nil)
//
//// Scan scans the time parsing it if necessary using timeFormat.
//func (bb *BlockHash) Value() (driver.Value, error) {
//	if bb == nil {
//		bb = &BlockHash{}
//	}
//	return bb[:], nil
//}
