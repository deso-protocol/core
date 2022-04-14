package lib

import (
	"bytes"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"io"
	"sort"
)

// A PKID is an ID associated with a public key. In the DB, various fields are
// indexed using the PKID rather than the user's public key directly in order to
// create one layer of indirection between the public key and the user's data. This
// makes it easy for the user to transfer certain data to a new public key.
type PKID [33]byte
type PublicKey [33]byte

func NewPKID(pkidBytes []byte) *PKID {
	if len(pkidBytes) == 0 {
		return nil
	}
	pkid := &PKID{}
	copy(pkid[:], pkidBytes)
	return pkid
}

var (
	ZeroPKID      = PKID{}
	ZeroPublicKey = PublicKey{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00}
	ZeroBlockHash = BlockHash{}
	MaxPKID       = PKID{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff}
)

func (pkid *PKID) ToBytes() []byte {
	return pkid[:]
}

func (pkid *PKID) Encode() []byte {
	data := append([]byte{}, UintToBuf(uint64(len(pkid[:])))...)
	return append(data, pkid[:]...)
}

func (pkid *PKID) Eq(other *PKID) bool {
	return bytes.Equal(pkid.ToBytes(), other.ToBytes())
}

func (pkid *PKID) IsZeroPKID() bool {
	return pkid.Eq(&ZeroPKID)
}

func SortPKIDs(pkids []PKID) []PKID {
	sort.Slice(pkids, func(ii, jj int) bool {
		return bytes.Compare(pkids[ii].ToBytes(), pkids[jj].ToBytes()) > 0
	})
	return pkids
}

func ReadPublicKey(rr io.Reader) (*PublicKey, error) {
	valBytes := make([]byte, 33, 33)
	_, err := io.ReadFull(rr, valBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "ReadPublicKey: Error reading public key")
	}
	return NewPublicKey(valBytes), nil
}

func ReadPKID(rr io.Reader) (*PKID, error) {
	pkidBytes, err := ReadVarString(rr)
	if err != nil {
		return nil, err
	}
	return PublicKeyToPKID(pkidBytes), nil
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

func (publicKey *PublicKey) IsZeroPublicKey() bool {
	return bytes.Equal(publicKey.ToBytes(), ZeroPublicKey.ToBytes())
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

func EncodeOptionalPublicKey(val *PublicKey) []byte {
	if val == nil {
		return UintToBuf(uint64(0))
	}
	encodedVal := val.ToBytes()
	return append(UintToBuf(uint64(len(encodedVal))), encodedVal...)
}

func ReadOptionalPublicKey(rr *bytes.Reader) (*PublicKey, error) {
	byteCount, err := ReadUvarint(rr)
	if err != nil {
		return nil, err
	}
	if byteCount > uint64(0) {
		return ReadPublicKey(rr)
	}
	return nil, nil
}

const HashSizeBytes = 32

// BlockHash is a convenient alias for a block hash.
type BlockHash [HashSizeBytes]byte

func NewBlockHash(input []byte) *BlockHash {
	blockHash := &BlockHash{}
	copy(blockHash[:], input)
	return blockHash
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

func ReadBlockHash(rr io.Reader) (*BlockHash, error) {
	valBytes := make([]byte, HashSizeBytes, HashSizeBytes)
	_, err := io.ReadFull(rr, valBytes)
	if err != nil {
		return nil, fmt.Errorf("ReadBlockHash: Error reading value bytes: %v", err)
	}
	return NewBlockHash(valBytes), nil
}

func EncodeOptionalBlockHash(val *BlockHash) []byte {
	if val == nil {
		return UintToBuf(uint64(0))
	}
	encodedVal := val.ToBytes()
	return append(UintToBuf(uint64(len(encodedVal))), encodedVal...)
}

func ReadOptionalBlockHash(rr *bytes.Reader) (*BlockHash, error) {
	byteCount, err := ReadUvarint(rr)
	if err != nil {
		return nil, err
	}
	if byteCount > uint64(0) {
		return ReadBlockHash(rr)
	}
	return nil, nil
}

func EncodeUint256(val *uint256.Int) []byte {
	valBytes := val.Bytes()
	data := make([]byte, 32, 32)
	return append(data, valBytes...)[len(valBytes):]
}

func ReadUint256(rr io.Reader) (*uint256.Int, error) {
	valBytes := make([]byte, 32, 32)
	_, err := io.ReadFull(rr, valBytes)
	if err != nil {
		return uint256.NewInt(), fmt.Errorf("ReadUint256: Error reading value bytes: %v", err)
	}
	return uint256.NewInt().SetBytes(valBytes), nil
}

func EncodeOptionalUint256(val *uint256.Int) []byte {
	if val == nil {
		return UintToBuf(uint64(0))
	}
	encodedVal := EncodeUint256(val)
	return append(UintToBuf(uint64(len(encodedVal))), encodedVal...)
}

func ReadOptionalUint256(rr *bytes.Reader) (*uint256.Int, error) {
	byteCount, err := ReadUvarint(rr)
	if err != nil {
		return nil, err
	}
	if byteCount > uint64(0) {
		return ReadUint256(rr)
	}
	return nil, nil
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
