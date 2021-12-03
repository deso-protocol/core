package types

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/deso-protocol/core/network"
	"github.com/golang/glog"
	"github.com/laser/go-merkle-tree"
	"github.com/pkg/errors"
	"io"
	"math"
	"math/big"
)

// BlockHash is a convenient alias for a block hash.
type BlockHash [HashSizeBytes]byte

const HashSizeBytes = 32

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

func Sha256DoubleHash(input []byte) *BlockHash {
	hashBytes := merkletree.Sha256DoubleHash(input)
	ret := &BlockHash{}
	copy(ret[:], hashBytes[:])
	return ret
}

func HashToBigint(hash *BlockHash) *big.Int {
	// No need to check errors since the string is necessarily a valid hex
	// string.
	val, itWorked := new(big.Int).SetString(hex.EncodeToString(hash[:]), 16)
	if !itWorked {
		glog.Errorf("Failed in converting []byte (%#v) to bigint.", hash)
	}
	return val
}

func BigintToHash(bigint *big.Int) *BlockHash {
	hexStr := bigint.Text(16)
	if len(hexStr)%2 != 0 {
		// If we have an odd number of bytes add one to the beginning (remember
		// the bigints are big-endian.
		hexStr = "0" + hexStr
	}
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		glog.Errorf("Failed in converting bigint (%#v) with hex "+
			"string (%s) to hash.", bigint, hexStr)
	}
	if len(hexBytes) > HashSizeBytes {
		glog.Errorf("BigintToHash: Bigint %v overflows the hash size %d", bigint, HashSizeBytes)
		return nil
	}

	var retBytes BlockHash
	copy(retBytes[HashSizeBytes-len(hexBytes):], hexBytes)
	return &retBytes
}

// UtxoKey is a 32-byte txid with a 4-byte uint32 index
// identifying the particular output in the transaction where
// this utxo occurs.
// When fetching from the db the txid and index are concatenated to
// form the key, with the index serialized as big-endian.
type UtxoKey struct {
	// The 32-byte transaction id where the unspent output occurs.
	TxID BlockHash
	// The index within the txn where the unspent output occurs.
	Index uint32
}

func (utxoKey *UtxoKey) String() string {
	return fmt.Sprintf("< TxID: %v, Index: %d >", &utxoKey.TxID, utxoKey.Index)
}

// MsgDeSoHeader definition.
//
// Note that all of these fields must be encoded as *full* big-endian
// ints/uints rather than varints. This is because these fields are hashed to
// produce a block and allowing them to be varints will heavily
// incentivize miners to keep them short, which corrupts their
// actual utility.
//
// Additionally note that it's particularly important that headers be
// space-efficient, since light clients will need to download an entire
// history of them in order to be able to validate anything.
type MsgDeSoHeader struct {
	// Note this is encoded as a fixed-width uint32 rather than a
	// uvarint or a uint64.
	Version uint32

	// Hash of the previous block in the chain.
	PrevBlockHash *BlockHash

	// The merkle root of all the transactions contained within the block.
	TransactionMerkleRoot *BlockHash

	// The unix timestamp (in seconds) specifying when this block was
	// mined.
	TstampSecs uint64

	// The height of the block this header corresponds to.
	Height uint64

	// The nonce that is used by miners in order to produce valid blocks.
	//
	// Note: Before the upgrade from HeaderVersion0 to HeaderVersion1, miners would make
	// use of ExtraData in the BlockRewardMetadata to get extra nonces. However, this is
	// no longer needed since HeaderVersion1 upgraded the nonce to 64 bits from 32 bits.
	Nonce uint64

	// An extra nonce that can be used to provice *even more* entropy for miners, in the
	// event that ASICs become powerful enough to have birthday problems in the future.
	ExtraNonce uint64
}

func HeaderSizeBytes() int {
	header := network.NewMessage(network.MsgTypeHeader)
	headerBytes, _ := header.ToBytes(false)
	return len(headerBytes)
}

func (msg *MsgDeSoHeader) EncodeHeaderVersion0(preSignature bool) ([]byte, error) {
	retBytes := []byte{}

	// Version
	{
		scratchBytes := [4]byte{}
		binary.BigEndian.PutUint32(scratchBytes[:], msg.Version)
		retBytes = append(retBytes, scratchBytes[:]...)
	}

	// PrevBlockHash
	prevBlockHash := msg.PrevBlockHash
	if prevBlockHash == nil {
		prevBlockHash = &BlockHash{}
	}
	retBytes = append(retBytes, prevBlockHash[:]...)

	// TransactionMerkleRoot
	transactionMerkleRoot := msg.TransactionMerkleRoot
	if transactionMerkleRoot == nil {
		transactionMerkleRoot = &BlockHash{}
	}
	retBytes = append(retBytes, transactionMerkleRoot[:]...)

	// TstampSecs
	{
		scratchBytes := [4]byte{}
		binary.LittleEndian.PutUint32(scratchBytes[:], uint32(msg.TstampSecs))
		retBytes = append(retBytes, scratchBytes[:]...)
	}

	// Height
	{
		scratchBytes := [4]byte{}
		// The height used to be a uint64
		binary.LittleEndian.PutUint32(scratchBytes[:], uint32(msg.Height))
		retBytes = append(retBytes, scratchBytes[:]...)
	}

	// Nonce
	{
		scratchBytes := [4]byte{}
		binary.LittleEndian.PutUint32(scratchBytes[:], uint32(msg.Nonce))
		retBytes = append(retBytes, scratchBytes[:]...)
	}

	return retBytes, nil
}

func (msg *MsgDeSoHeader) EncodeHeaderVersion1(preSignature bool) ([]byte, error) {
	retBytes := []byte{}

	// Version
	{
		scratchBytes := [4]byte{}
		binary.BigEndian.PutUint32(scratchBytes[:], msg.Version)
		retBytes = append(retBytes, scratchBytes[:]...)
	}

	// PrevBlockHash
	prevBlockHash := msg.PrevBlockHash
	if prevBlockHash == nil {
		prevBlockHash = &BlockHash{}
	}
	retBytes = append(retBytes, prevBlockHash[:]...)

	// TransactionMerkleRoot
	transactionMerkleRoot := msg.TransactionMerkleRoot
	if transactionMerkleRoot == nil {
		transactionMerkleRoot = &BlockHash{}
	}
	retBytes = append(retBytes, transactionMerkleRoot[:]...)

	// TstampSecs
	{
		scratchBytes := [8]byte{}
		binary.BigEndian.PutUint64(scratchBytes[:], msg.TstampSecs)
		retBytes = append(retBytes, scratchBytes[:]...)

		// TODO: Don't allow this field to exceed 32-bits for now. This will
		// adjust once other parts of the code are fixed to handle the wider
		// type.
		if msg.TstampSecs > math.MaxUint32 {
			return nil, fmt.Errorf("EncodeHeaderVersion1: TstampSecs not yet allowed " +
				"to exceed max uint32. This will be fixed in the future")
		}
	}

	// Height
	{
		scratchBytes := [8]byte{}
		binary.BigEndian.PutUint64(scratchBytes[:], msg.Height)
		retBytes = append(retBytes, scratchBytes[:]...)

		// TODO: Don't allow this field to exceed 32-bits for now. This will
		// adjust once other parts of the code are fixed to handle the wider
		// type.
		if msg.Height > math.MaxUint32 {
			return nil, fmt.Errorf("EncodeHeaderVersion1: Height not yet allowed " +
				"to exceed max uint32. This will be fixed in the future")
		}
	}

	// Nonce
	{
		scratchBytes := [8]byte{}
		binary.BigEndian.PutUint64(scratchBytes[:], msg.Nonce)
		retBytes = append(retBytes, scratchBytes[:]...)
	}

	// ExtraNonce
	{
		scratchBytes := [8]byte{}
		binary.BigEndian.PutUint64(scratchBytes[:], msg.ExtraNonce)
		retBytes = append(retBytes, scratchBytes[:]...)
	}

	return retBytes, nil
}

func (msg *MsgDeSoHeader) ToBytes(preSignature bool) ([]byte, error) {

	// Depending on the version, we decode the header differently.
	if msg.Version == HeaderVersion0 {
		return msg.EncodeHeaderVersion0(preSignature)
	} else if msg.Version == HeaderVersion1 {
		return msg.EncodeHeaderVersion1(preSignature)
	} else {
		// If we have an unrecognized version then we default to serializing with
		// version 0. This is necessary because there are places where we use a
		// MsgDeSoHeader struct to store Bitcoin headers.
		return msg.EncodeHeaderVersion0(preSignature)
	}
}

func DecodeHeaderVersion0(rr io.Reader) (*MsgDeSoHeader, error) {
	retHeader := network.NewMessage(network.MsgTypeHeader).(*MsgDeSoHeader)

	// PrevBlockHash
	_, err := io.ReadFull(rr, retHeader.PrevBlockHash[:])
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding PrevBlockHash")
	}

	// TransactionMerkleRoot
	_, err = io.ReadFull(rr, retHeader.TransactionMerkleRoot[:])
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding TransactionMerkleRoot")
	}

	// TstampSecs
	{
		scratchBytes := [4]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding TstampSecs")
		}
		retHeader.TstampSecs = uint64(binary.LittleEndian.Uint32(scratchBytes[:]))
	}

	// Height
	{
		scratchBytes := [4]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding Height")
		}
		retHeader.Height = uint64(binary.LittleEndian.Uint32(scratchBytes[:]))
	}

	// Nonce
	{
		scratchBytes := [4]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding Nonce")
		}
		retHeader.Nonce = uint64(binary.LittleEndian.Uint32(scratchBytes[:]))
	}

	return retHeader, nil
}

func DecodeHeaderVersion1(rr io.Reader) (*MsgDeSoHeader, error) {
	retHeader := network.NewMessage(network.MsgTypeHeader).(*MsgDeSoHeader)

	// PrevBlockHash
	_, err := io.ReadFull(rr, retHeader.PrevBlockHash[:])
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding PrevBlockHash")
	}

	// TransactionMerkleRoot
	_, err = io.ReadFull(rr, retHeader.TransactionMerkleRoot[:])
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding TransactionMerkleRoot")
	}

	// TstampSecs
	{
		scratchBytes := [8]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding TstampSecs")
		}
		retHeader.TstampSecs = binary.BigEndian.Uint64(scratchBytes[:])
	}

	// Height
	{
		scratchBytes := [8]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding Height")
		}
		retHeader.Height = binary.BigEndian.Uint64(scratchBytes[:])
	}

	// Nonce
	{
		scratchBytes := [8]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding Nonce")
		}
		retHeader.Nonce = binary.BigEndian.Uint64(scratchBytes[:])
	}

	// ExtraNonce
	{
		scratchBytes := [8]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding ExtraNonce")
		}
		retHeader.ExtraNonce = binary.BigEndian.Uint64(scratchBytes[:])
	}

	return retHeader, nil
}

func DecodeHeader(rr io.Reader) (*MsgDeSoHeader, error) {
	// Read the version to determine
	scratchBytes := [4]byte{}
	_, err := io.ReadFull(rr, scratchBytes[:])
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding Version")
	}
	headerVersion := binary.BigEndian.Uint32(scratchBytes[:])

	var ret *MsgDeSoHeader
	if headerVersion == HeaderVersion0 {
		ret, err = DecodeHeaderVersion0(rr)
	} else if headerVersion == HeaderVersion1 {
		ret, err = DecodeHeaderVersion1(rr)
	} else {
		// If we have an unrecognized version then we default to de-serializing with
		// version 0. This is necessary because there are places where we use a
		// MsgDeSoHeader struct to store Bitcoin headers.
		ret, err = DecodeHeaderVersion0(rr)
	}
	if err != nil {
		return nil, fmt.Errorf(
			"DecodeHeader: Unrecognized header version: %v", headerVersion)
	}
	// Set the version since it's not decoded in the version-specific handlers.
	ret.Version = headerVersion

	return ret, nil
}

func (msg *MsgDeSoHeader) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retHeader, err := DecodeHeader(rr)
	if err != nil {
		return fmt.Errorf("MsgDeSoHeader.FromBytes: %v", err)
	}

	*msg = *retHeader
	return nil
}

func (msg *MsgDeSoHeader) GetMsgType() network.MsgType {
	return network.MsgTypeHeader
}

// Hash is a helper function to compute a hash of the header. Note that the header
// hash is special in that we always hash it using the ProofOfWorkHash rather than
// Sha256DoubleHash.
func (msg *MsgDeSoHeader) Hash() (*BlockHash, error) {
	preSignature := false
	headerBytes, err := msg.ToBytes(preSignature)
	if err != nil {
		return nil, errors.Wrap(err, "MsgDeSoHeader.Hash: ")
	}

	return ProofOfWorkHash(headerBytes, msg.Version), nil
}

func (msg *MsgDeSoHeader) String() string {
	hash, _ := msg.Hash()
	return fmt.Sprintf("< %d, %s, %v >", msg.Height, hash, msg.Version)
}
