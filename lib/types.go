package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"io"
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
	ZeroBlockHash = BlockHash{}
)

func (pkid *PKID) ToBytes() []byte {
	return pkid[:]
}

func (pkid *PKID) Encode() []byte {
	data := append([]byte{}, UintToBuf(uint64(len(pkid[:])))...)
	return append(data, pkid[:]...)
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

func EncodeUint256(val uint256.Int) []byte {
	valBytes := val.Bytes()
	data := append([]byte{}, UintToBuf(uint64(len(valBytes)))...)
	return append(data, valBytes...)
}

func ReadUint256(rr io.Reader) (uint256.Int, error) {
	maxUint256BytesLen := len(MaxUint256.Bytes())
	intLen, err := ReadUvarint(rr)
	if err != nil {
		return *uint256.NewInt(), errors.Wrapf(err, "ReadUint256: Problem reading length")
	}
	if intLen > uint64(maxUint256BytesLen) {
		return *uint256.NewInt(), fmt.Errorf("ReadUint256: value length %d "+
			"exceeds max %d", intLen, MaxMessagePayload)
	}
	valBytes := make([]byte, intLen)
	_, err = io.ReadFull(rr, valBytes)
	if err != nil {
		return *uint256.NewInt(), fmt.Errorf("ReadUint256: Error reading value bytes: %v", err)
	}
	return *uint256.NewInt().SetBytes(valBytes), nil
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
