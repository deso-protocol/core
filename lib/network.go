package lib

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	merkletree "github.com/laser/go-merkle-tree"

	"github.com/pkg/errors"
)

// network.go defines all the basic data structures that get sent over the
// network and defines precisely how they are serialized and de-serialized.

// MaxMessagePayload is the maximum size alowed for a message payload.
const MaxMessagePayload = (1024 * 1024 * 100) // 100MB

// MaxBlockRewardDataSizeBytes is the maximum size allowed for a BLOCK_REWARD's ExtraData field.
var MaxBlockRewardDataSizeBytes = 250

// MaxHeadersPerMsg is the maximum numbers allowed in a GetHeaders response.
var MaxHeadersPerMsg = uint32(2000)

// MaxBitcoinHeadersPerMsg is the maximum number of headers Bitcoin allows in
// a getheaders response. It is used to determine whether a node has more headers
// to give us.
var MaxBitcoinHeadersPerMsg = uint32(2000)

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

// The MsgType is usually sent on the wire to indicate what type of
// struct is being sent in the payload part of the message.
type MsgType uint64

const (
	// ControlMessagesStart is used to indicate the ID value at which control
	// messages start. Anything with an ID value greater than or equal to this
	// is a control message.
	ControlMessagesStart = 1000000

	MsgTypeUnset MsgType = 0
	//
	// The first message a peer sends. Used to negotiate a version
	// between the two peers.
	MsgTypeVersion MsgType = 1
	//
	// Sent after a peer has both sent its version message
	// and received its peer's version message and completed
	// the version negotiation.
	MsgTypeVerack MsgType = 2
	MsgTypeHeader MsgType = 3
	MsgTypeBlock  MsgType = 4
	MsgTypeTxn    MsgType = 5
	// MsgTypeGetHeaders is used to fetch headers from a peer.
	MsgTypeGetHeaders MsgType = 6
	// MsgTypeHeaderBundle contains headers from a peer.
	MsgTypeHeaderBundle    MsgType = 7
	MsgTypePing            MsgType = 8
	MsgTypePong            MsgType = 9
	MsgTypeInv             MsgType = 10
	MsgTypeGetBlocks       MsgType = 11
	MsgTypeGetTransactions MsgType = 12
	// MsgTypeTransactionBundle contains transactions from a peer.
	MsgTypeTransactionBundle MsgType = 13
	MsgTypeMempool           MsgType = 14
	// MsgTypeAddr is used by peers to share addresses of nodes they're aware about
	// with other peers.
	MsgTypeAddr MsgType = 15
	// MsgTypeGetAddr is used to solicit Addr messages from peers.
	MsgTypeGetAddr MsgType = 16

	// NEXT_TAG = 18

	// Below are control messages used to signal to the Server from other parts of
	// the code but not actually sent among peers.
	//
	// TODO: Should probably split these out into a separate channel in the server to
	// make things more parallelized.

	MsgTypeQuit                 MsgType = ControlMessagesStart
	MsgTypeNewPeer              MsgType = ControlMessagesStart + 1
	MsgTypeDonePeer             MsgType = ControlMessagesStart + 2
	MsgTypeBlockAccepted        MsgType = ControlMessagesStart + 3
	MsgTypeBitcoinManagerUpdate MsgType = ControlMessagesStart + 4

	// NEXT_TAG = 7
)

// IsControlMessage is used by functions to determine whether a particular message
// is a control message. This is useful, for example, in disallowing external Peers
// from manipulating our node by sending control messages of their own.
func IsControlMessage(msgType MsgType) bool {
	return uint64(msgType) >= ControlMessagesStart
}

func (msgType MsgType) String() string {
	switch msgType {
	case MsgTypeUnset:
		return "UNSET"
	case MsgTypeVersion:
		return "VERSION"
	case MsgTypeVerack:
		return "VERACK"
	// Note that we don't usually write single block headers to the wire,
	// preferring instead to bundle headers into a single HEADER_BUNDLE message.
	case MsgTypeHeader:
		return "HEADER"
	case MsgTypeBlock:
		return "BLOCK"
	case MsgTypeTxn:
		return "TXN"
	case MsgTypeGetHeaders:
		return "GET_HEADERS"
	case MsgTypeHeaderBundle:
		return "HEADER_BUNDLE"
	case MsgTypePing:
		return "PING"
	case MsgTypePong:
		return "PONG"
	case MsgTypeInv:
		return "INV"
	case MsgTypeGetBlocks:
		return "GET_BLOCKS"
	case MsgTypeGetTransactions:
		return "GET_TRANSACTIONS"
	case MsgTypeTransactionBundle:
		return "TRANSACTION_BUNDLE"
	case MsgTypeMempool:
		return "MEMPOOL"
	case MsgTypeAddr:
		return "ADDR"
	case MsgTypeGetAddr:
		return "GET_ADDR"
	case MsgTypeQuit:
		return "QUIT"
	case MsgTypeNewPeer:
		return "NEW_PEER"
	case MsgTypeDonePeer:
		return "DONE_PEER"
	case MsgTypeBlockAccepted:
		return "BLOCK_ACCEPTED"
	case MsgTypeBitcoinManagerUpdate:
		return "BITCOIN_MANAGER_UPDATE"
	default:
		return fmt.Sprintf("UNRECOGNIZED(%d) - make sure String() is up to date", msgType)
	}
}

// BitCloutMessage is the interface that a message we send on the wire must implement.
type BitCloutMessage interface {
	// The following methods allow one to convert a message struct into
	// a byte slice and back. Example usage:
	//
	//   params := &BitCloutTestnetParams
	//   msgType := MsgTypeVersion
	//   byteSlice := []byte{0x00, ...}
	//
	// 	 msg := NewMessage(msgType)
	//   err := msg.FromBytes(byteSlice)
	//   newByteSlice, err := msg.ToBytes(false)
	//
	// The data format is intended to be compact while allowing for efficient
	// transmission over the wire and storage in a database.
	//
	// The preSignature field specifies whether the message should be fully
	// serialized or whether it should be serialized in such a way that it
	// can be signed (which involves, for example, not serializing signature
	// fields).
	ToBytes(preSignature bool) ([]byte, error)
	FromBytes(data []byte) error

	// Each Message has a particular type.
	GetMsgType() MsgType
}

// TxnType specifies the type for a transaction message.
type TxnType uint8

const (
	TxnTypeUnset                        TxnType = 0
	TxnTypeBlockReward                  TxnType = 1
	TxnTypeBasicTransfer                TxnType = 2
	TxnTypeBitcoinExchange              TxnType = 3
	TxnTypePrivateMessage               TxnType = 4
	TxnTypeSubmitPost                   TxnType = 5
	TxnTypeUpdateProfile                TxnType = 6
	TxnTypeUpdateBitcoinUSDExchangeRate TxnType = 8
	TxnTypeFollow                       TxnType = 9
	TxnTypeLike                         TxnType = 10
	TxnTypeCreatorCoin                  TxnType = 11
	TxnTypeSwapIdentity                 TxnType = 12
	TxnTypeUpdateGlobalParams           TxnType = 13
	TxnTypeCreatorCoinTransfer          TxnType = 14
	TxnTypeCreateNFT                    TxnType = 15
	TxnTypeUpdateNFT                    TxnType = 16
	TxnTypeAcceptNFTBid                 TxnType = 17
	TxnTypeNFTBid                       TxnType = 18
	TxnTypeAuthorizeDerivedKey          TxnType = 19

	// NEXT_ID = 20
)

func (txnType TxnType) String() string {
	switch txnType {
	case TxnTypeUnset:
		return "UNSET"
	case TxnTypeBlockReward:
		return "BLOCK_REWARD"
	case TxnTypeBasicTransfer:
		return "BASIC_TRANSFER"
	case TxnTypeBitcoinExchange:
		return "BITCOIN_EXCHANGE"
	case TxnTypePrivateMessage:
		return "PRIVATE_MESSAGE"
	case TxnTypeSubmitPost:
		return "SUBMIT_POST"
	case TxnTypeUpdateProfile:
		return "UPDATE_PROFILE"
	case TxnTypeUpdateBitcoinUSDExchangeRate:
		return "UPDATE_BITCOIN_USD_EXCHANGE_RATE"
	case TxnTypeFollow:
		return "FOLLOW"
	case TxnTypeLike:
		return "LIKE"
	case TxnTypeCreatorCoin:
		return "CREATOR_COIN"
	case TxnTypeCreatorCoinTransfer:
		return "CREATOR_COIN_TRANSFER"
	case TxnTypeSwapIdentity:
		return "SWAP_IDENTITY"
	case TxnTypeUpdateGlobalParams:
		return "UPDATE_GLOBAL_PARAMS"
	case TxnTypeCreateNFT:
		return "CREATE_NFT"
	case TxnTypeUpdateNFT:
		return "UPDATE_NFT"
	case TxnTypeAcceptNFTBid:
		return "ACCEPT_NFT_BID"
	case TxnTypeNFTBid:
		return "NFT_BID"
	case TxnTypeAuthorizeDerivedKey:
		return "AUTHORIZE_DERIVED_KEY"

	default:
		return fmt.Sprintf("UNRECOGNIZED(%d) - make sure String() is up to date", txnType)
	}
}

type BitCloutTxnMetadata interface {
	ToBytes(preSignature bool) ([]byte, error)
	FromBytes(data []byte) error
	New() BitCloutTxnMetadata
	GetTxnType() TxnType
}

func NewTxnMetadata(txType TxnType) (BitCloutTxnMetadata, error) {
	switch txType {
	case TxnTypeUnset:
		return nil, fmt.Errorf("NewTxnMetadata: UNSET TxnType: %v", TxnTypeUnset)
	case TxnTypeBlockReward:
		return (&BlockRewardMetadataa{}).New(), nil
	case TxnTypeBasicTransfer:
		return (&BasicTransferMetadata{}).New(), nil
	case TxnTypeBitcoinExchange:
		return (&BitcoinExchangeMetadata{}).New(), nil
	case TxnTypePrivateMessage:
		return (&PrivateMessageMetadata{}).New(), nil
	case TxnTypeSubmitPost:
		return (&SubmitPostMetadata{}).New(), nil
	case TxnTypeUpdateProfile:
		return (&UpdateProfileMetadata{}).New(), nil
	case TxnTypeUpdateBitcoinUSDExchangeRate:
		return (&UpdateBitcoinUSDExchangeRateMetadataa{}).New(), nil
	case TxnTypeFollow:
		return (&FollowMetadata{}).New(), nil
	case TxnTypeLike:
		return (&LikeMetadata{}).New(), nil
	case TxnTypeCreatorCoin:
		return (&CreatorCoinMetadataa{}).New(), nil
	case TxnTypeCreatorCoinTransfer:
		return (&CreatorCoinTransferMetadataa{}).New(), nil
	case TxnTypeSwapIdentity:
		return (&SwapIdentityMetadataa{}).New(), nil
	case TxnTypeUpdateGlobalParams:
		return (&UpdateGlobalParamsMetadata{}).New(), nil
	case TxnTypeCreateNFT:
		return (&CreateNFTMetadata{}).New(), nil
	case TxnTypeUpdateNFT:
		return (&UpdateNFTMetadata{}).New(), nil
	case TxnTypeAcceptNFTBid:
		return (&AcceptNFTBidMetadata{}).New(), nil
	case TxnTypeNFTBid:
		return (&NFTBidMetadata{}).New(), nil
	case TxnTypeAuthorizeDerivedKey:
		return (&AuthorizeDerivedKeyMetadata{}).New(), nil

	default:
		return nil, fmt.Errorf("NewTxnMetadata: Unrecognized TxnType: %v; make sure you add the new type of transaction to NewTxnMetadata", txType)
	}
}

// WriteMessage takes an io.Writer and serializes and writes the specified message
// to it. Returns an error if the message is malformed or invalid for any reason.
// Otherwise returns the payload that was written sans the header.
func WriteMessage(ww io.Writer, msg BitCloutMessage, networkType NetworkType) ([]byte, error) {
	hdr := []byte{}

	// Add the network as a uvarint.
	hdr = append(hdr, UintToBuf(uint64(networkType))...)

	// Add the MsgType as a uvarint.
	hdr = append(hdr, UintToBuf(uint64(msg.GetMsgType()))...)

	// Compute the payload we're going to write but don't add it
	// yet.
	payload, err := msg.ToBytes(false)
	if err != nil {
		return nil, errors.Wrap(err, "WriteMessage: Failed to convert message to bytes")
	}

	// Check that the length of the payload does not exceed the maximum
	// allowed limit.
	if len(payload) > MaxMessagePayload {
		return nil, fmt.Errorf("WriteMessage: Payload size (%d) bytes is too "+
			"large. Should be no larger than (%d) bytes", len(payload), MaxMessagePayload)
	}

	// Add an eight-byte checksum of the payload. Note that although
	// we generally communicate over TCP, it's not a great idea to rely on the
	// checksum it uses since its guarantees are relatively weak.
	// https://www.evanjones.ca/tcp-checksums.html
	hash := Sha256DoubleHash(payload)
	hdr = append(hdr, hash[:8]...)

	// Add the payload length as a uvarint.
	hdr = append(hdr, UintToBuf(uint64(len(payload)))...)

	// Write the message header.
	_, err = ww.Write(hdr)
	if err != nil {
		return nil, errors.Wrap(err, "WriteMessage: Failed to write header")
	}

	// Write the payload.
	_, err = ww.Write(payload)
	if err != nil {
		return nil, errors.Wrap(err, "WriteMessage: Failed to write payload")
	}
	return payload, nil
}

// ReadMessage takes an io.Reader and de-serializes a single message from it.
// Returns an error if the message is malformed or invalid for any reason. Otherwise
// returns a formed message object and the raw byte payload from which it was
// derived.
func ReadMessage(rr io.Reader, networkType NetworkType) (BitCloutMessage, []byte, error) {
	// Read the network as a uvarint.
	inNetworkType, err := ReadUvarint(rr)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "ReadMessage: Problem decoding NetworkType")
	}
	if NetworkType(inNetworkType) != networkType {
		return nil, nil, fmt.Errorf("ReadMessage: Incorrect network type (%s) expected (%s)", NetworkType(inNetworkType), networkType)
	}

	// Read the MsgType as a uvarint.
	inMsgType, err := ReadUvarint(rr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "ReadMessage: Could not read MsgType")
	}

	// Create a new message object based on the type.
	retMsg := NewMessage(MsgType(inMsgType))
	if retMsg == nil {
		return nil, nil, fmt.Errorf("ReadMessage: Unknown message type (%s)", MsgType(inMsgType))
	}

	// Read the payload checksum.
	checksum := make([]byte, 8)
	_, err = io.ReadFull(rr, checksum)
	if err != nil {
		return nil, nil, fmt.Errorf("ReadMessage: Error reading checksum for messate type (%s)", MsgType(inMsgType))
	}

	// Read the length of the payload.
	payloadLength, err := ReadUvarint(rr)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "ReadMessage: Could not read payload length for message type (%s)", MsgType(inMsgType))
	}

	// Check that the payload length does not exceed the maximum value allowed.
	// This prevents adversarial machines from overflowing our
	if payloadLength > MaxMessagePayload {
		return nil, nil, fmt.Errorf("ReadMessage: Payload size (%d) bytes is too "+
			"large. Should be no larger than (%d) bytes", payloadLength, MaxMessagePayload)
	}

	// Read the payload.
	payload := make([]byte, payloadLength)
	_, err = io.ReadFull(rr, payload)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "ReadMessage: Could not read payload for message type (%s)", MsgType(inMsgType))
	}

	// Check the payload checksum.
	hash := Sha256DoubleHash(payload)
	if !bytes.Equal(hash[:8], checksum) {
		return nil, nil, fmt.Errorf("ReadMessage: Payload checksum computed "+
			"(%#v) does not match payload checksum in header: (%#v)", hash[:8], checksum)
	}

	// Now we have the payload, initialize the message.
	err = retMsg.FromBytes(payload)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "ReadMessage: Problem parsing "+
			"message payload into message object for message type (%s)", MsgType(inMsgType))
	}

	return retMsg, payload, nil
}

func NewMessage(msgType MsgType) BitCloutMessage {
	switch msgType {
	case MsgTypeVersion:
		{
			return &MsgBitCloutVersion{}
		}
	case MsgTypeVerack:
		{
			return &MsgBitCloutVerack{}
		}
	case MsgTypeHeader:
		{
			return &MsgBitCloutHeader{
				PrevBlockHash:         &BlockHash{},
				TransactionMerkleRoot: &BlockHash{},
			}
		}
	case MsgTypeBlock:
		{
			return &MsgBitCloutBlock{
				Header: NewMessage(MsgTypeHeader).(*MsgBitCloutHeader),
			}
		}
	case MsgTypeTxn:
		{
			return &MsgBitCloutTxn{}
		}
	case MsgTypePing:
		{
			return &MsgBitCloutPing{}
		}
	case MsgTypePong:
		{
			return &MsgBitCloutPong{}
		}
	case MsgTypeInv:
		{
			return &MsgBitCloutInv{}
		}
	case MsgTypeGetBlocks:
		{
			return &MsgBitCloutGetBlocks{}
		}
	case MsgTypeGetTransactions:
		{
			return &MsgBitCloutGetTransactions{}
		}
	case MsgTypeTransactionBundle:
		{
			return &MsgBitCloutTransactionBundle{}
		}
	case MsgTypeMempool:
		{
			return &MsgBitCloutMempool{}
		}
	case MsgTypeGetHeaders:
		{
			return &MsgBitCloutGetHeaders{}
		}
	case MsgTypeHeaderBundle:
		{
			return &MsgBitCloutHeaderBundle{}
		}
	case MsgTypeAddr:
		{
			return &MsgBitCloutAddr{}
		}
	case MsgTypeGetAddr:
		{
			return &MsgBitCloutGetAddr{}
		}
	default:
		{
			return nil
		}
	}
}

// ==================================================================
// Control Messages
// ==================================================================

type MsgBitCloutQuit struct {
}

func (msg *MsgBitCloutQuit) GetMsgType() MsgType {
	return MsgTypeQuit
}

func (msg *MsgBitCloutQuit) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgBitCloutQuit.ToBytes not implemented")
}

func (msg *MsgBitCloutQuit) FromBytes(data []byte) error {
	return fmt.Errorf("MsgBitCloutQuit.FromBytes not implemented")
}

type MsgBitCloutNewPeer struct {
}

func (msg *MsgBitCloutNewPeer) GetMsgType() MsgType {
	return MsgTypeNewPeer
}

func (msg *MsgBitCloutNewPeer) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgBitCloutNewPeer.ToBytes: Not implemented")
}

func (msg *MsgBitCloutNewPeer) FromBytes(data []byte) error {
	return fmt.Errorf("MsgBitCloutNewPeer.FromBytes not implemented")
}

type MsgBitCloutDonePeer struct {
}

func (msg *MsgBitCloutDonePeer) GetMsgType() MsgType {
	return MsgTypeDonePeer
}

func (msg *MsgBitCloutDonePeer) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgBitCloutDonePeer.ToBytes: Not implemented")
}

func (msg *MsgBitCloutDonePeer) FromBytes(data []byte) error {
	return fmt.Errorf("MsgBitCloutDonePeer.FromBytes not implemented")
}

type MsgBitCloutBlockAccepted struct {
	block *MsgBitCloutBlock
}

func (msg *MsgBitCloutBlockAccepted) GetMsgType() MsgType {
	return MsgTypeBlockAccepted
}

func (msg *MsgBitCloutBlockAccepted) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgBitCloutBlockAccepted.ToBytes: Not implemented")
}

func (msg *MsgBitCloutBlockAccepted) FromBytes(data []byte) error {
	return fmt.Errorf("MsgBitCloutBlockAccepted.FromBytes not implemented")
}

type MsgBitCloutBitcoinManagerUpdate struct {
	// Keep it simple for now. A BitcoinManagerUpdate just signals that
	// the BitcoinManager has added at least one block or done a reorg.
	// No serialization because we don't want this sent on the wire ever.
	TransactionsFound []*MsgBitCloutTxn
}

func (msg *MsgBitCloutBitcoinManagerUpdate) GetMsgType() MsgType {
	return MsgTypeBitcoinManagerUpdate
}

func (msg *MsgBitCloutBitcoinManagerUpdate) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgBitCloutBitcoinManagerUpdate.ToBytes: Not implemented")
}

func (msg *MsgBitCloutBitcoinManagerUpdate) FromBytes(data []byte) error {
	return fmt.Errorf("MsgBitCloutBitcoinManagerUpdate.FromBytes not implemented")
}

// ==================================================================
// GET_HEADERS message
// ==================================================================

type MsgBitCloutGetHeaders struct {
	StopHash     *BlockHash
	BlockLocator []*BlockHash
}

func (msg *MsgBitCloutGetHeaders) GetMsgType() MsgType {
	return MsgTypeGetHeaders
}

func (msg *MsgBitCloutGetHeaders) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Encode the StopHash first.
	data = append(data, msg.StopHash[:]...)

	// Encode the number of hashes in the BlockLocator.
	data = append(data, UintToBuf(uint64(len(msg.BlockLocator)))...)

	// Encode all of the hashes in the BlockLocator.
	for _, hash := range msg.BlockLocator {
		data = append(data, hash[:]...)
	}

	return data, nil
}

func (msg *MsgBitCloutGetHeaders) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retGetHeaders := NewMessage(MsgTypeGetHeaders).(*MsgBitCloutGetHeaders)

	// StopHash
	stopHash := BlockHash{}
	_, err := io.ReadFull(rr, stopHash[:])
	if err != nil {
		return errors.Wrapf(err, "MsgBitCloutGetHeaders.FromBytes: Problem decoding StopHash")
	}
	retGetHeaders.StopHash = &stopHash

	// Number of hashes in block locator.
	numHeaders, err := ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("MsgBitCloutGetHeaders.FromBytes: %v", err)
	}

	for ii := uint64(0); ii < numHeaders; ii++ {
		currentHeader := BlockHash{}
		_, err := io.ReadFull(rr, currentHeader[:])
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutGetHeaders.FromBytes: Problem decoding header hash")
		}

		retGetHeaders.BlockLocator = append(retGetHeaders.BlockLocator, &currentHeader)
	}

	*msg = *retGetHeaders
	return nil
}

func (msg *MsgBitCloutGetHeaders) String() string {
	return fmt.Sprintf("StopHash: %v Locator: %v",
		msg.StopHash, msg.BlockLocator)
}

// ==================================================================
// HEADER_BUNDLE message
// ==================================================================

type MsgBitCloutHeaderBundle struct {
	Headers   []*MsgBitCloutHeader
	TipHash   *BlockHash
	TipHeight uint32
}

func (msg *MsgBitCloutHeaderBundle) GetMsgType() MsgType {
	return MsgTypeHeaderBundle
}

func (msg *MsgBitCloutHeaderBundle) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Encode the number of headers in the bundle.
	data = append(data, UintToBuf(uint64(len(msg.Headers)))...)

	// Encode all the headers.
	for _, header := range msg.Headers {
		headerBytes, err := header.ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "MsgBitCloutHeaderBundle.ToBytes: Problem encoding header")
		}
		data = append(data, headerBytes...)
	}

	// Encode the tip hash.
	data = append(data, msg.TipHash[:]...)

	// Encode the tip height.
	data = append(data, UintToBuf(uint64(msg.TipHeight))...)

	return data, nil
}

func (msg *MsgBitCloutHeaderBundle) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retBundle := NewMessage(MsgTypeHeaderBundle).(*MsgBitCloutHeaderBundle)

	// Read in the number of headers in the bundle.
	numHeaders, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgBitCloutHeaderBundle.FromBytes: Problem decoding number of header")
	}

	// Read in all of the headers.
	for ii := uint64(0); ii < numHeaders; ii++ {
		retHeader, err := DecodeHeader(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutHeader.FromBytes: ")
		}

		retBundle.Headers = append(retBundle.Headers, retHeader)
	}

	// Read in the tip hash.
	retBundle.TipHash = &BlockHash{}
	_, err = io.ReadFull(rr, retBundle.TipHash[:])
	if err != nil {
		return errors.Wrapf(err, "MsgBitCloutHeaderBundle.FromBytes:: Error reading TipHash: ")
	}

	// Read in the tip height.
	tipHeight, err := ReadUvarint(rr)
	if err != nil || tipHeight > math.MaxUint32 {
		return fmt.Errorf("MsgBitCloutHeaderBundle.FromBytes: %v", err)
	}
	retBundle.TipHeight = uint32(tipHeight)

	*msg = *retBundle
	return nil
}

func (msg *MsgBitCloutHeaderBundle) String() string {
	return fmt.Sprintf("Num Headers: %v, Tip Height: %v, Tip Hash: %v, Headers: %v", len(msg.Headers), msg.TipHeight, msg.TipHash, msg.Headers)
}

// ==================================================================
// GetBlocks Messages
// ==================================================================

type MsgBitCloutGetBlocks struct {
	HashList []*BlockHash
}

func (msg *MsgBitCloutGetBlocks) GetMsgType() MsgType {
	return MsgTypeGetBlocks
}

func (msg *MsgBitCloutGetBlocks) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	if len(msg.HashList) > MaxBlocksInFlight {
		return nil, fmt.Errorf("MsgBitCloutGetBlocks.ToBytes: Blocks requested %d "+
			"exceeds MaxBlocksInFlight %d", len(msg.HashList), MaxBlocksInFlight)
	}

	// Encode the number of hashes.
	data = append(data, UintToBuf(uint64(len(msg.HashList)))...)
	// Encode each hash.
	for _, hash := range msg.HashList {
		data = append(data, hash[:]...)
	}

	return data, nil
}

func (msg *MsgBitCloutGetBlocks) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// Parse the nmber of block hashes.
	numHashes, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgBitCloutGetBlocks.FromBytes: Problem "+
			"reading number of block hashes requested")
	}
	if numHashes > MaxBlocksInFlight {
		return fmt.Errorf("MsgBitCloutGetBlocks.FromBytes: HashList length (%d) "+
			"exceeds maximum allowed (%d)", numHashes, MaxBlocksInFlight)
	}

	// Read in all the hashes.
	hashList := []*BlockHash{}
	for ii := uint64(0); ii < numHashes; ii++ {
		newHash := BlockHash{}

		_, err = io.ReadFull(rr, newHash[:])
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutGetBlocks.FromBytes:: Error reading Hash: ")
		}
		hashList = append(hashList, &newHash)
	}

	*msg = MsgBitCloutGetBlocks{
		HashList: hashList,
	}
	return nil
}

func (msg *MsgBitCloutGetBlocks) String() string {
	return fmt.Sprintf("%v", msg.HashList)
}

// Within a post, the body typically has a particular
// schema defined below.
type BitCloutBodySchema struct {
	Body      string
	ImageURLs []string
}

// ==================================================================
// GetTransactions Messages
// ==================================================================

type MsgBitCloutGetTransactions struct {
	HashList []*BlockHash
}

func (msg *MsgBitCloutGetTransactions) GetMsgType() MsgType {
	return MsgTypeGetTransactions
}

func (msg *MsgBitCloutGetTransactions) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Encode the number of hashes.
	data = append(data, UintToBuf(uint64(len(msg.HashList)))...)
	// Encode each hash.
	for _, hash := range msg.HashList {
		data = append(data, hash[:]...)
	}

	return data, nil
}

func (msg *MsgBitCloutGetTransactions) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// Parse the nmber of block hashes.
	numHashes, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgBitCloutGetTransactions.FromBytes: Problem "+
			"reading number of transaction hashes requested")
	}

	// Read in all the hashes.
	hashList := []*BlockHash{}
	for ii := uint64(0); ii < numHashes; ii++ {
		newHash := BlockHash{}

		_, err = io.ReadFull(rr, newHash[:])
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutGetTransactions.FromBytes: Error reading Hash: ")
		}
		hashList = append(hashList, &newHash)
	}

	*msg = MsgBitCloutGetTransactions{
		HashList: hashList,
	}
	return nil
}

func (msg *MsgBitCloutGetTransactions) String() string {
	return fmt.Sprintf("Num hashes: %v, HashList: %v", len(msg.HashList), msg.HashList)
}

// ==================================================================
// TransactionBundle message
// ==================================================================

type MsgBitCloutTransactionBundle struct {
	Transactions []*MsgBitCloutTxn
}

func (msg *MsgBitCloutTransactionBundle) GetMsgType() MsgType {
	return MsgTypeTransactionBundle
}

func (msg *MsgBitCloutTransactionBundle) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Encode the number of transactions in the bundle.
	data = append(data, UintToBuf(uint64(len(msg.Transactions)))...)

	// Encode all the transactions.
	for _, transaction := range msg.Transactions {
		transactionBytes, err := transaction.ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "MsgBitCloutTransactionBundle.ToBytes: Problem encoding transaction")
		}
		data = append(data, transactionBytes...)
	}

	return data, nil
}

func (msg *MsgBitCloutTransactionBundle) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retBundle := NewMessage(MsgTypeTransactionBundle).(*MsgBitCloutTransactionBundle)

	// Read in the number of transactions in the bundle.
	numTransactions, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgBitCloutTransactionBundle.FromBytes: Problem decoding number of transaction")
	}

	// Read in all of the transactions.
	for ii := uint64(0); ii < numTransactions; ii++ {
		retTransaction, err := _readTransaction(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutTransaction.FromBytes: ")
		}

		retBundle.Transactions = append(retBundle.Transactions, retTransaction)
	}

	*msg = *retBundle
	return nil
}

func (msg *MsgBitCloutTransactionBundle) String() string {
	return fmt.Sprintf("Num txns: %v, Txns: %v", len(msg.Transactions), msg.Transactions)
}

// ==================================================================
// Mempool Messages
// ==================================================================

type MsgBitCloutMempool struct {
}

func (msg *MsgBitCloutMempool) GetMsgType() MsgType {
	return MsgTypeMempool
}

func (msg *MsgBitCloutMempool) ToBytes(preSignature bool) ([]byte, error) {
	// A mempool message is just empty.
	return []byte{}, nil
}

func (msg *MsgBitCloutMempool) FromBytes(data []byte) error {
	// A mempool message is just empty.
	return nil
}

func (msg *MsgBitCloutMempool) String() string {
	return fmt.Sprintf("%v", msg.GetMsgType())
}

// ==================================================================
// INV Messages
// ==================================================================

const (
	// MaxBlocksInFlight is the maximum number of blocks that can be requested
	// from a peer.
	MaxBlocksInFlight = 250
)

// InvType represents the allowed types of inventory vectors. See InvVect.
type InvType uint32

// These constants define the various supported inventory vector types.
const (
	InvTypeTx    InvType = 0
	InvTypeBlock InvType = 1
)

// Map of service flags back to their constant names for pretty printing.
var ivStrings = map[InvType]string{
	InvTypeTx:    "TX_INV",
	InvTypeBlock: "BLOCK_INV",
}

// String returns the InvType in human-readable form.
func (invtype InvType) String() string {
	if s, ok := ivStrings[invtype]; ok {
		return s
	}

	return fmt.Sprintf("Unknown InvType (%d)", uint32(invtype))
}

// InvVect defines an inventory vector which is used to describe data,
// as specified by the Type field, that a peer wants, has, or does not have to
// another peer.
type InvVect struct {
	Type InvType   // Type of data
	Hash BlockHash // Hash of the data
}

func (invVect *InvVect) String() string {
	return fmt.Sprintf("Type: %v, Hash: %v", invVect.Type, &(invVect.Hash))
}

type MsgBitCloutInv struct {
	InvList []*InvVect
	// IsSyncResponse indicates that the inv was sent in response to a sync message.
	// This indicates that the node shouldn't relay it to peers because they likely
	// already have it.
	IsSyncResponse bool
}

func (msg *MsgBitCloutInv) GetMsgType() MsgType {
	return MsgTypeInv
}

func _invListToBytes(invList []*InvVect) ([]byte, error) {
	data := []byte{}

	// Encode the number of inventory vectors.
	data = append(data, UintToBuf(uint64(len(invList)))...)

	// Encode each inventory vector subsequent.
	for _, invVect := range invList {
		data = append(data, UintToBuf(uint64(invVect.Type))...)
		data = append(data, invVect.Hash[:]...)
	}

	return data, nil
}

func _readInvList(rr io.Reader) ([]*InvVect, error) {
	invList := []*InvVect{}

	// Parse the number of inventory vectors in the message and make sure it doesn't
	// exceed the limit.
	numInvVects, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readInvList: Problem reading number of InvVects")
	}

	// Now parse each individual InvVect.
	for ii := uint64(0); ii < numInvVects; ii++ {
		// Parse the type field, which was encoded as a varint.
		typeUint, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readInvList: Problem parsing Type for InvVect")
		}
		if typeUint > math.MaxUint32 {
			return nil, fmt.Errorf("_readInvList: Type field exceeds maximum value sanity check (%f) vs (%f)", float64(typeUint), float64(math.MaxUint32))
		}

		// Read the Hash of the InvVect.
		invHash := BlockHash{}
		_, err = io.ReadFull(rr, invHash[:])
		if err != nil {
			return nil, errors.Wrapf(err, "_readInvList:: Error reading Hash for InvVect: ")
		}

		invVect := &InvVect{
			Type: InvType(typeUint),
			Hash: invHash,
		}

		invList = append(invList, invVect)
	}

	return invList, nil
}

func (msg *MsgBitCloutInv) ToBytes(preSignature bool) ([]byte, error) {
	data, err := _invListToBytes(msg.InvList)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgBitCloutGetInv: ")
	}
	data = append(data, BoolToByte(msg.IsSyncResponse))

	return data, nil
}

func (msg *MsgBitCloutInv) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	invList, err := _readInvList(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgBitCloutInv: ")
	}
	isSyncResponse := ReadBoolByte(rr)

	*msg = MsgBitCloutInv{
		InvList:        invList,
		IsSyncResponse: isSyncResponse,
	}
	return nil
}

func (msg *MsgBitCloutInv) String() string {
	return fmt.Sprintf("Num invs: %v, SyncResponse: %v, InvList: %v",
		len(msg.InvList), msg.IsSyncResponse, msg.InvList)
}

// ==================================================================
// PING and PONG Messages
// ==================================================================

type MsgBitCloutPing struct {
	Nonce uint64
}

func (msg *MsgBitCloutPing) GetMsgType() MsgType {
	return MsgTypePing
}

func (msg *MsgBitCloutPing) ToBytes(preSignature bool) ([]byte, error) {
	return UintToBuf(msg.Nonce), nil
}

func (msg *MsgBitCloutPing) FromBytes(data []byte) error {
	nonce, err := ReadUvarint(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("MsgBitCloutPing.FromBytes: %v", err)
	}
	*msg = MsgBitCloutPing{Nonce: nonce}
	return nil
}

type MsgBitCloutPong struct {
	Nonce uint64
}

func (msg *MsgBitCloutPong) GetMsgType() MsgType {
	return MsgTypePong
}

func (msg *MsgBitCloutPong) ToBytes(preSignature bool) ([]byte, error) {
	return UintToBuf(msg.Nonce), nil
}

func (msg *MsgBitCloutPong) FromBytes(data []byte) error {
	nonce, err := ReadUvarint(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("MsgBitCloutPong.FromBytes: %v", err)
	}
	*msg = MsgBitCloutPong{Nonce: nonce}
	return nil
}

// ==================================================================
// VERSION Message
// ==================================================================

type ServiceFlag uint64

const (
	// SFFullNode is a flag used to indicate a peer is a full node.
	SFFullNode ServiceFlag = 1 << iota
)

type MsgBitCloutVersion struct {
	// What is the current version we're on?
	Version uint64

	// What are the services offered by this node?
	Services ServiceFlag

	// The node's unix timestamp that we use to compute a
	// robust "network time" using NTP.
	TstampSecs int64

	// Used to detect when a node connects to itself, which
	// we generally want to prevent.
	Nonce uint64

	// Used as a "vanity plate" to identify different BitClout
	// clients. Mainly useful in analyzing the network at
	// a meta level, not in the protocol itself.
	UserAgent string

	// The height of the last block on the main chain for
	// this node.
	//
	// TODO: We need to update this to uint64
	StartBlockHeight uint32

	// MinFeeRateNanosPerKB is the minimum feerate that a peer will
	// accept from other peers when validating transactions.
	MinFeeRateNanosPerKB uint64
}

func (msg *MsgBitCloutVersion) ToBytes(preSignature bool) ([]byte, error) {
	retBytes := []byte{}

	// Version
	//
	// We give each one of these its own scope to avoid issues where
	// nn accidentally gets recycled.
	retBytes = append(retBytes, UintToBuf(msg.Version)...)

	// Services
	retBytes = append(retBytes, UintToBuf(uint64(msg.Services))...)

	// TstampSecs
	retBytes = append(retBytes, IntToBuf(msg.TstampSecs)...)

	// Nonce
	retBytes = append(retBytes, UintToBuf(msg.Nonce)...)

	// UserAgent
	//
	// Strings are encoded by putting their length first as uvarints
	// then their values afterward as bytes.
	retBytes = append(retBytes, UintToBuf(uint64(len(msg.UserAgent)))...)
	retBytes = append(retBytes, msg.UserAgent...)

	// StartBlockHeight
	retBytes = append(retBytes, UintToBuf(uint64(msg.StartBlockHeight))...)

	// MinFeeRateNanosPerKB
	retBytes = append(retBytes, UintToBuf(uint64(msg.MinFeeRateNanosPerKB))...)

	// JSONAPIPort - deprecated
	retBytes = append(retBytes, UintToBuf(uint64(0))...)

	return retBytes, nil
}

func (msg *MsgBitCloutVersion) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retVer := MsgBitCloutVersion{}

	// Version
	//
	// We give each one of these its own scope to avoid issues where
	// a value accidentally gets recycled.
	{
		ver, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutVersion.FromBytes: Problem converting msg.Version")
		}
		retVer.Version = ver
	}

	// Services
	{
		services, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutVersion.FromBytes: Problem converting msg.Services")
		}
		retVer.Services = ServiceFlag(services)
	}

	// TstampSecs
	{
		tstampSecs, err := ReadVarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutVersion.FromBytes: Problem converting msg.TstampSecs")
		}
		retVer.TstampSecs = tstampSecs
	}

	// Nonce
	{
		nonce, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutVersion.FromBytes: Problem converting msg.Nonce")
		}
		retVer.Nonce = nonce
	}

	// UserAgent
	//
	// Strings are encoded by putting their length first as uvarints
	// then their values afterward as bytes.
	{
		strLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutVersion.FromBytes: Problem reading length of msg.UserAgent")
		}
		if strLen > MaxMessagePayload {
			return fmt.Errorf("MsgBitCloutVersion.FromBytes: Length msg.UserAgent %d larger than max allowed %d", strLen, MaxMessagePayload)
		}
		userAgent := make([]byte, strLen)
		_, err = io.ReadFull(rr, userAgent)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutVersion.FromBytes: Error reading msg.UserAgent")
		}
		retVer.UserAgent = string(userAgent)
	}

	// StartBlockHeight
	{
		lastBlockHeight, err := ReadUvarint(rr)
		if err != nil || lastBlockHeight > math.MaxUint32 {
			return errors.Wrapf(err, "MsgBitCloutVersion.FromBytes: Problem converting msg.LatestBlockHeight")
		}
		retVer.StartBlockHeight = uint32(lastBlockHeight)
	}

	// MinFeeRateNanosPerKB
	{
		minFeeRateNanosPerKB, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutVersion.FromBytes: Problem converting msg.MinFeeRateNanosPerKB")
		}
		retVer.MinFeeRateNanosPerKB = minFeeRateNanosPerKB
	}

	// JSONAPIPort - deprecated
	{
		_, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutVersion.FromBytes: Problem converting msg.JSONAPIPort")
		}
	}

	*msg = retVer
	return nil
}

func (msg *MsgBitCloutVersion) GetMsgType() MsgType {
	return MsgTypeVersion
}

// ==================================================================
// ADDR Message
// ==================================================================

const (
	// MaxAddrsPerAddrMsg is the maximum number of addresses we allow in a single
	// addr message from a peer.
	MaxAddrsPerAddrMsg = 1000
	// AddrRelayIntervalSeconds is the amount of time we wait before relaying each
	// batch of addresses we've received recently.
	AddrRelayIntervalSeconds = 60

	// RebroadcastNodeAddrIntervalMinutes is how often we broadcast our own address
	// to our peers.
	RebroadcastNodeAddrIntervalMinutes = 24 * 60
)

// SingleAddr is similar to the wire.NetAddress definition from the btcd guys.
type SingleAddr struct {
	// Last time the address was seen. Encoded as number UNIX seconds on the wire.
	Timestamp time.Time

	// Bitfield which identifies the services supported by the address.
	Services ServiceFlag

	// IP address of the peer. Must be 4 or 16 bytes for IPV4 or IPV6 respectively.
	IP net.IP

	// Port the peer is using.
	Port uint16
}

func (addr *SingleAddr) StringWithPort(includePort bool) string {
	// Always include the port for localhost as it's useful for testing.
	if includePort || net.IP([]byte{127, 0, 0, 1}).Equal(addr.IP) {
		return fmt.Sprintf("%s:%d", addr.IP.String(), addr.Port)
	}

	return addr.IP.String()
}

func (addr *SingleAddr) String() string {
	return fmt.Sprintf("%s:%d", addr.IP.String(), addr.Port)
}

type MsgBitCloutAddr struct {
	// The definition of NetAddress as defined by the btcd guys works fine for
	// our purposes. The only difference is that for BitClout nodes, the Service
	// flag in the NetAddress is as we define it above in ServiceFlag.
	// Note that we also rewrite the serialization logic as well to avoid
	// relying on potentially crusty Bitcoin-related work-arounds going forward.
	AddrList []*SingleAddr
}

func (msg *MsgBitCloutAddr) ToBytes(preSignature bool) ([]byte, error) {
	retBytes := []byte{}

	// Encode the number of addresses as a uvarint.
	retBytes = append(retBytes, UintToBuf(uint64(len(msg.AddrList)))...)

	// Encode each address.
	for _, addr := range msg.AddrList {
		// Timestamp
		// Assume it's always positive.
		retBytes = append(retBytes, UintToBuf(uint64(addr.Timestamp.Unix()))...)

		// Services
		retBytes = append(retBytes, UintToBuf(uint64(addr.Services))...)

		// IP
		// Encode the length of the IP and then the actual bytes.
		retBytes = append(retBytes, UintToBuf(uint64(len(addr.IP[:])))...)
		retBytes = append(retBytes, addr.IP[:]...)

		// Port
		retBytes = append(retBytes, UintToBuf(uint64(addr.Port))...)
	}

	return retBytes, nil
}

func (msg *MsgBitCloutAddr) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retVer := MsgBitCloutAddr{}

	// Read the number of addresses encoded.
	numAddrs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgBitCloutAddr.FromBytes: Problem reading numAddrs: ")
	}
	for ii := uint64(0); ii < numAddrs; ii++ {
		// Read each addr and add it to the AddrList.
		currentAddr := &SingleAddr{}

		// Timestamp
		tstampSecs, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutAddr.FromBytes: Problem reading tstamp: ")
		}
		currentAddr.Timestamp = time.Unix(int64(tstampSecs), 0)

		// Services
		serviceUint, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutAddr.FromBytes: Problem reading services: ")
		}
		currentAddr.Services = ServiceFlag(serviceUint)

		// IP
		ipLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutAddr.FromBytes: Problem reading IP: ")
		}
		if ipLen != 4 && ipLen != 16 {
			return fmt.Errorf("MsgBitCloutAddr.FromBytes: IP length must be 4 or 16 bytes but was %d", ipLen)
		}
		currentAddr.IP = net.IP(make([]byte, ipLen))
		_, err = io.ReadFull(rr, currentAddr.IP)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutAddr.FromBytes: Error reading IP")
		}

		// Port
		port, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutAddr.FromBytes: Problem reading port: ")
		}
		if port > math.MaxUint16 {
			return fmt.Errorf("MsgBitCloutAddr.FromBytes: Port value %d exceeds max "+
				"allowed %d", port, math.MaxUint16)
		}
		currentAddr.Port = uint16(port)

		retVer.AddrList = append(retVer.AddrList, currentAddr)
	}

	*msg = retVer
	return nil
}

func (msg *MsgBitCloutAddr) GetMsgType() MsgType {
	return MsgTypeAddr
}

func (msg *MsgBitCloutAddr) String() string {
	return fmt.Sprintf("Num addrs: %v, AddrList: %v", len(msg.AddrList), msg.AddrList)
}

// ==================================================================
// GET_ADDR Message
// ==================================================================

type MsgBitCloutGetAddr struct {
}

func (msg *MsgBitCloutGetAddr) ToBytes(preSignature bool) ([]byte, error) {
	return []byte{}, nil
}

func (msg *MsgBitCloutGetAddr) FromBytes(data []byte) error {
	return nil
}

func (msg *MsgBitCloutGetAddr) GetMsgType() MsgType {
	return MsgTypeGetAddr
}

// ==================================================================
// VERACK Message
// ==================================================================

// VERACK messages have no payload.
type MsgBitCloutVerack struct {
	// A verack message must contain the nonce the peer received in the
	// initial version message. This ensures the peer that is communicating
	// with us actually controls the address she says she does similar to
	// "SYN Cookie" DDOS protection.
	Nonce uint64
}

func (msg *MsgBitCloutVerack) ToBytes(preSignature bool) ([]byte, error) {
	retBytes := []byte{}

	// Nonce
	retBytes = append(retBytes, UintToBuf(msg.Nonce)...)
	return retBytes, nil
}

func (msg *MsgBitCloutVerack) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retMsg := NewMessage(MsgTypeVerack).(*MsgBitCloutVerack)
	{
		nonce, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutVerack.FromBytes: Problem reading Nonce")
		}
		retMsg.Nonce = nonce
	}
	*msg = *retMsg
	return nil
}

func (msg *MsgBitCloutVerack) GetMsgType() MsgType {
	return MsgTypeVerack
}

// ==================================================================
// HEADER Message
// ==================================================================

// MsgBitCloutHeader definition.
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
type MsgBitCloutHeader struct {
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
	header := NewMessage(MsgTypeHeader)
	headerBytes, _ := header.ToBytes(false)
	return len(headerBytes)
}

func (msg *MsgBitCloutHeader) EncodeHeaderVersion0(preSignature bool) ([]byte, error) {
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

func (msg *MsgBitCloutHeader) EncodeHeaderVersion1(preSignature bool) ([]byte, error) {
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

func (msg *MsgBitCloutHeader) ToBytes(preSignature bool) ([]byte, error) {

	// Depending on the version, we decode the header differently.
	if msg.Version == HeaderVersion0 {
		return msg.EncodeHeaderVersion0(preSignature)
	} else if msg.Version == HeaderVersion1 {
		return msg.EncodeHeaderVersion1(preSignature)
	} else {
		// If we have an unrecognized version then we default to serializing with
		// version 0. This is necessary because there are places where we use a
		// MsgBitCloutHeader struct to store Bitcoin headers.
		return msg.EncodeHeaderVersion0(preSignature)
	}
}

func DecodeHeaderVersion0(rr io.Reader) (*MsgBitCloutHeader, error) {
	retHeader := NewMessage(MsgTypeHeader).(*MsgBitCloutHeader)

	// PrevBlockHash
	_, err := io.ReadFull(rr, retHeader.PrevBlockHash[:])
	if err != nil {
		return nil, errors.Wrapf(err, "MsgBitCloutHeader.FromBytes: Problem decoding PrevBlockHash")
	}

	// TransactionMerkleRoot
	_, err = io.ReadFull(rr, retHeader.TransactionMerkleRoot[:])
	if err != nil {
		return nil, errors.Wrapf(err, "MsgBitCloutHeader.FromBytes: Problem decoding TransactionMerkleRoot")
	}

	// TstampSecs
	{
		scratchBytes := [4]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgBitCloutHeader.FromBytes: Problem decoding TstampSecs")
		}
		retHeader.TstampSecs = uint64(binary.LittleEndian.Uint32(scratchBytes[:]))
	}

	// Height
	{
		scratchBytes := [4]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgBitCloutHeader.FromBytes: Problem decoding Height")
		}
		retHeader.Height = uint64(binary.LittleEndian.Uint32(scratchBytes[:]))
	}

	// Nonce
	{
		scratchBytes := [4]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgBitCloutHeader.FromBytes: Problem decoding Nonce")
		}
		retHeader.Nonce = uint64(binary.LittleEndian.Uint32(scratchBytes[:]))
	}

	return retHeader, nil
}

func DecodeHeaderVersion1(rr io.Reader) (*MsgBitCloutHeader, error) {
	retHeader := NewMessage(MsgTypeHeader).(*MsgBitCloutHeader)

	// PrevBlockHash
	_, err := io.ReadFull(rr, retHeader.PrevBlockHash[:])
	if err != nil {
		return nil, errors.Wrapf(err, "MsgBitCloutHeader.FromBytes: Problem decoding PrevBlockHash")
	}

	// TransactionMerkleRoot
	_, err = io.ReadFull(rr, retHeader.TransactionMerkleRoot[:])
	if err != nil {
		return nil, errors.Wrapf(err, "MsgBitCloutHeader.FromBytes: Problem decoding TransactionMerkleRoot")
	}

	// TstampSecs
	{
		scratchBytes := [8]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgBitCloutHeader.FromBytes: Problem decoding TstampSecs")
		}
		retHeader.TstampSecs = binary.BigEndian.Uint64(scratchBytes[:])
	}

	// Height
	{
		scratchBytes := [8]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgBitCloutHeader.FromBytes: Problem decoding Height")
		}
		retHeader.Height = binary.BigEndian.Uint64(scratchBytes[:])
	}

	// Nonce
	{
		scratchBytes := [8]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgBitCloutHeader.FromBytes: Problem decoding Nonce")
		}
		retHeader.Nonce = binary.BigEndian.Uint64(scratchBytes[:])
	}

	// ExtraNonce
	{
		scratchBytes := [8]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgBitCloutHeader.FromBytes: Problem decoding ExtraNonce")
		}
		retHeader.ExtraNonce = binary.BigEndian.Uint64(scratchBytes[:])
	}

	return retHeader, nil
}

func DecodeHeader(rr io.Reader) (*MsgBitCloutHeader, error) {
	// Read the version to determine
	scratchBytes := [4]byte{}
	_, err := io.ReadFull(rr, scratchBytes[:])
	if err != nil {
		return nil, errors.Wrapf(err, "MsgBitCloutHeader.FromBytes: Problem decoding Version")
	}
	headerVersion := binary.BigEndian.Uint32(scratchBytes[:])

	var ret *MsgBitCloutHeader
	if headerVersion == HeaderVersion0 {
		ret, err = DecodeHeaderVersion0(rr)
	} else if headerVersion == HeaderVersion1 {
		ret, err = DecodeHeaderVersion1(rr)
	} else {
		// If we have an unrecognized version then we default to de-serializing with
		// version 0. This is necessary because there are places where we use a
		// MsgBitCloutHeader struct to store Bitcoin headers.
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

func (msg *MsgBitCloutHeader) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retHeader, err := DecodeHeader(rr)
	if err != nil {
		return fmt.Errorf("MsgBitCloutHeader.FromBytes: %v", err)
	}

	*msg = *retHeader
	return nil
}

func (msg *MsgBitCloutHeader) GetMsgType() MsgType {
	return MsgTypeHeader
}

// Hash is a helper function to compute a hash of the header. Note that the header
// hash is special in that we always hash it using the ProofOfWorkHash rather than
// Sha256DoubleHash.
func (msg *MsgBitCloutHeader) Hash() (*BlockHash, error) {
	preSignature := false
	headerBytes, err := msg.ToBytes(preSignature)
	if err != nil {
		return nil, errors.Wrap(err, "MsgBitCloutHeader.Hash: ")
	}

	return ProofOfWorkHash(headerBytes, msg.Version), nil
}

func (msg *MsgBitCloutHeader) String() string {
	hash, _ := msg.Hash()
	return fmt.Sprintf("< %d, %s, %v >", msg.Height, hash, msg.Version)
}

// ==================================================================
// BLOCK Message
// ==================================================================

type BlockProducerInfo struct {
	PublicKey []byte
	Signature *btcec.Signature
}

func (bpi *BlockProducerInfo) Serialize() []byte {
	data := []byte{}
	data = append(data, UintToBuf(uint64(len(bpi.PublicKey)))...)
	data = append(data, bpi.PublicKey...)

	sigBytes := []byte{}
	if bpi.Signature != nil {
		sigBytes = bpi.Signature.Serialize()
	}
	data = append(data, UintToBuf(uint64(len(sigBytes)))...)
	data = append(data, sigBytes...)

	return data
}

func (bpi *BlockProducerInfo) Deserialize(data []byte) error {
	ret := &BlockProducerInfo{}
	rr := bytes.NewReader(data)

	// De-serialize the public key.
	{
		pkLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "BlockProducerInfo.Deserialize: Error reading public key len")
		}
		if pkLen > MaxMessagePayload {
			return errors.Wrapf(err, "BlockProducerInfo.Deserialize: pkLen too long: %v", pkLen)
		}
		pkBytes := make([]byte, pkLen)
		_, err = io.ReadFull(rr, pkBytes)
		if err != nil {
			return errors.Wrapf(err, "BlockProducerInfo.Deserialize: Error reading public key: ")
		}
		ret.PublicKey = pkBytes
	}

	// De-serialize the signature.
	{
		sigLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "BlockProducerInfo.Deserialize: Error reading signature len")
		}
		if sigLen > MaxMessagePayload {
			return errors.Wrapf(err, "BlockProducerInfo.Deserialize: signature len too long: %v", sigLen)
		}
		sigBytes := make([]byte, sigLen)
		_, err = io.ReadFull(rr, sigBytes)
		if err != nil {
			return errors.Wrapf(err, "BlockProducerInfo.Deserialize: Error reading signature: ")
		}
		ret.Signature = nil
		if sigLen > 0 {
			sig, err := btcec.ParseDERSignature(sigBytes, btcec.S256())
			if err != nil {
				return errors.Wrapf(err, "BlockProducerInfo.Deserialize: Error parsing signature bytes: ")
			}
			ret.Signature = sig
		}
	}

	*bpi = *ret
	return nil
}

func (bpi *BlockProducerInfo) String() string {
	if bpi == nil || len(bpi.PublicKey) == 0 {
		return "Signer Key: NONE"
	}
	return fmt.Sprintf("Signer Key: %v", PkToStringMainnet(bpi.PublicKey))
}

type MsgBitCloutBlock struct {
	Header *MsgBitCloutHeader
	Txns   []*MsgBitCloutTxn

	// This field is optional and provides the producer of the block the ability to sign it
	// with their private key. Doing this proves that this block was produced by a particular
	// entity, which can be useful for nodes that want to restrict who they accept blocks
	// from.
	BlockProducerInfo *BlockProducerInfo
}

func (msg *MsgBitCloutBlock) EncodeBlockCommmon(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Serialize the header.
	if msg.Header == nil {
		return nil, fmt.Errorf("MsgBitCloutBlock.ToBytes: Header should not be nil")
	}
	hdrBytes, err := msg.Header.ToBytes(preSignature)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgBitCloutBlock.ToBytes: Problem encoding header")
	}
	data = append(data, UintToBuf(uint64(len(hdrBytes)))...)
	data = append(data, hdrBytes...)

	// Serialize all the transactions.
	numTxns := uint64(len(msg.Txns))
	data = append(data, UintToBuf(numTxns)...)
	for ii := uint64(0); ii < numTxns; ii++ {
		currentTxnBytes, err := msg.Txns[ii].ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "MsgBitCloutBlock.ToBytes: Problem encoding txn")
		}
		data = append(data, UintToBuf(uint64(len(currentTxnBytes)))...)
		data = append(data, currentTxnBytes...)
	}

	return data, nil
}

func (msg *MsgBitCloutBlock) EncodeBlockVersion0(preSignature bool) ([]byte, error) {
	return msg.EncodeBlockCommmon(preSignature)
}

func (msg *MsgBitCloutBlock) EncodeBlockVersion1(preSignature bool) ([]byte, error) {
	data, err := msg.EncodeBlockCommmon(preSignature)
	if err != nil {
		return nil, err
	}

	// BlockProducerInfo
	blockProducerInfoBytes := []byte{}
	if msg.BlockProducerInfo != nil {
		blockProducerInfoBytes = msg.BlockProducerInfo.Serialize()
	}
	data = append(data, UintToBuf(uint64(len(blockProducerInfoBytes)))...)
	data = append(data, blockProducerInfoBytes...)

	return data, nil
}

func (msg *MsgBitCloutBlock) ToBytes(preSignature bool) ([]byte, error) {
	if msg.Header.Version == HeaderVersion0 {
		return msg.EncodeBlockVersion0(preSignature)
	} else if msg.Header.Version == HeaderVersion1 {
		return msg.EncodeBlockVersion1(preSignature)
	} else {
		return nil, fmt.Errorf("MsgBitCloutBlock.ToBytes: Error encoding version: %v", msg.Header.Version)
	}
}

func (msg *MsgBitCloutBlock) FromBytes(data []byte) error {
	ret := NewMessage(MsgTypeBlock).(*MsgBitCloutBlock)
	rr := bytes.NewReader(data)

	// De-serialize the header.
	hdrLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgBitCloutBlock.FromBytes: Problem decoding header length")
	}
	if hdrLen > MaxMessagePayload {
		return fmt.Errorf("MsgBitCloutBlock.FromBytes: Header length %d longer than max %d", hdrLen, MaxMessagePayload)
	}
	hdrBytes := make([]byte, hdrLen)
	_, err = io.ReadFull(rr, hdrBytes)
	if err != nil {
		return errors.Wrapf(err, "MsgBitCloutBlock.FromBytes: Problem reading header")
	}

	err = ret.Header.FromBytes(hdrBytes)
	if err != nil {
		return errors.Wrapf(err, "MsgBitCloutBlock.FromBytes: Problem converting header")
	}

	// De-serialize the transactions.
	numTxns, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgBitCloutBlock.FromBytes: Problem decoding num txns")
	}
	ret.Txns = make([]*MsgBitCloutTxn, 0)
	for ii := uint64(0); ii < numTxns; ii++ {
		txBytesLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutBlock.FromBytes: Problem decoding txn length")
		}
		if txBytesLen > MaxMessagePayload {
			return fmt.Errorf("MsgBitCloutBlock.FromBytes: Txn %d length %d longer than max %d", ii, hdrLen, MaxMessagePayload)
		}
		txBytes := make([]byte, txBytesLen)
		_, err = io.ReadFull(rr, txBytes)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutBlock.FromBytes: Problem reading tx bytes")
		}
		currentTxn := NewMessage(MsgTypeTxn).(*MsgBitCloutTxn)
		err = currentTxn.FromBytes(txBytes)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutBlock.FromBytes: Problem decoding txn")
		}
		ret.Txns = append(ret.Txns, currentTxn)
	}

	// Version 1 blocks have a BlockProducerInfo attached to them that
	// must be read. If this is not a Version 1 block, then the BlockProducerInfo
	// remains nil.
	if ret.Header.Version == HeaderVersion1 {
		blockProducerInfoLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgBitCloutBlock.FromBytes: Error decoding header length")
		}
		var blockProducerInfo *BlockProducerInfo
		if blockProducerInfoLen > 0 {
			if blockProducerInfoLen > MaxMessagePayload {
				return fmt.Errorf("MsgBitCloutBlock.FromBytes: Header length %d longer "+
					"than max %d", blockProducerInfoLen, MaxMessagePayload)
			}
			blockProducerInfoBytes := make([]byte, blockProducerInfoLen)
			_, err = io.ReadFull(rr, blockProducerInfoBytes)
			if err != nil {
				return errors.Wrapf(err, "MsgBitCloutBlock.FromBytes: Problem reading header")
			}
			blockProducerInfo = &BlockProducerInfo{}
			blockProducerInfo.Deserialize(blockProducerInfoBytes)
			ret.BlockProducerInfo = blockProducerInfo
		}
	}

	*msg = *ret
	return nil
}

func (msg *MsgBitCloutBlock) GetMsgType() MsgType {
	return MsgTypeBlock
}

func (msg *MsgBitCloutBlock) Hash() (*BlockHash, error) {
	if msg == nil || msg.Header == nil {
		return nil, fmt.Errorf("MsgBitCloutBLock.Hash: nil block or nil header")
	}
	return msg.Header.Hash()
}

func (msg *MsgBitCloutBlock) String() string {
	if msg == nil || msg.Header == nil {
		return "<nil block or header>"
	}
	return fmt.Sprintf("<Header: %v, %v>", msg.Header.String(), msg.BlockProducerInfo)
}

// ==================================================================
// TXN Message
// ==================================================================

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

const (
	// MaxBitCloutInputSizeBytes is the size required to encode an BitCloutInput.
	// 32 bytes for the TxID and 4 bytes for the Index = 36 bytes. Note
	// that because the index is encoded as a uvarint, this size represents
	// a maximum.
	MaxBitCloutInputSizeBytes = 32 + 4
	// MaxBitCloutOutputSizeBytes is the size required to encode an BitCloutOutput.
	// It is 33 bytes for the public key and 8 bytes for the amount
	// = 41 bytes. Note that because the amount is encoded as a uvarint,
	// this size represents a maximum.
	MaxBitCloutOutputSizeBytes = btcec.PubKeyBytesLenCompressed + 8
)

// BitCloutInput represents a single unspent output from a previous txn.
// For that reason it specifies the previous txn and the index in that txn where
// the output appears by simply aliasing UtxoKey.
type BitCloutInput UtxoKey

func (bitcloutInput *BitCloutInput) String() string {
	return (*UtxoKey)(bitcloutInput).String()
}

func NewBitCloutInput() *BitCloutInput {
	return &BitCloutInput{
		TxID: BlockHash{},
	}
}

type BitCloutOutput struct {
	// Outputs always compensate a specific public key.
	PublicKey []byte
	// The amount of BitClout to send to this public key.
	AmountNanos uint64
}

func (bitcloutOutput *BitCloutOutput) String() string {
	return fmt.Sprintf("< PublicKey: %#v, AmountNanos: %d >",
		PkToStringMainnet(bitcloutOutput.PublicKey), bitcloutOutput.AmountNanos)
}

type MsgBitCloutTxn struct {
	TxInputs  []*BitCloutInput
	TxOutputs []*BitCloutOutput

	// BitCloutTxnMetadata is an interface type that will give us information on how
	// we should handle the transaction, including what type of transaction this
	// is.
	TxnMeta BitCloutTxnMetadata

	// Transactions must generally explicitly include the key that is
	// spending the inputs to the transaction. The exception to this rule is that
	// BlockReward and BitcoinExchange transactions do not require the inclusion
	// of a public key since they have no inputs to spend.
	//
	// The public key should be a serialized compressed ECDSA public key on the
	// secp256k1 curve.
	PublicKey []byte

	// This is typically a JSON field that can be used to add extra information to
	// a transaction without causing a hard fork. It is useful in rare cases where we
	// realize that something needs to be added to a transaction but where we can't
	// afford a hard fork.
	ExtraData map[string][]byte

	// Transactions must generally be signed by the key that is spending the
	// inputs to the transaction. The exception to this rule is that
	// BLOCK_REWARD and CREATE_bitclout transactions do not require a signature
	// since they have no inputs.
	Signature []byte

	// (!!) **DO_NOT_USE** (!!)
	//
	// Use txn.TxnMeta.GetTxnType() instead.
	//
	// We need this for JSON encoding/decoding. It isn't used for anything
	// else and it isn't actually serialized or de-serialized when sent
	// across the network using ToBytes/FromBytes because we prefer that
	// any use of the MsgBitCloutTxn in Go code rely on TxnMeta.GetTxnType() rather
	// than checking this value, which, in Go context, is redundant and
	// therefore error-prone (e.g. someone might change TxnMeta while
	// forgetting to set it). We make it a uint64 explicitly to prevent
	// people from using it in Go code.
	TxnTypeJSON uint64
}

func (msg *MsgBitCloutTxn) String() string {
	pubKey := msg.PublicKey
	if msg.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
		pubKeyObj, err := ExtractBitcoinPublicKeyFromBitcoinTransactionInputs(
			msg.TxnMeta.(*BitcoinExchangeMetadata).BitcoinTransaction, BitCloutMainnetParams.BitcoinBtcdParams)
		if err != nil {
			pubKey = msg.PublicKey
		} else {
			pubKey = pubKeyObj.SerializeCompressed()
		}
	}
	return fmt.Sprintf("< TxHash: %v, TxnType: %v, PubKey: %v >",
		msg.Hash(), msg.TxnMeta.GetTxnType(), PkToStringMainnet(pubKey))
}

func (msg *MsgBitCloutTxn) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Serialize the inputs
	data = append(data, UintToBuf(uint64(len(msg.TxInputs)))...)
	for _, bitcloutInput := range msg.TxInputs {
		data = append(data, bitcloutInput.TxID[:]...)
		data = append(data, UintToBuf(uint64(bitcloutInput.Index))...)
	}

	// Serialize the outputs
	data = append(data, UintToBuf(uint64(len(msg.TxOutputs)))...)
	for _, bitcloutOutput := range msg.TxOutputs {
		// The public key is always 33 bytes.
		data = append(data, bitcloutOutput.PublicKey[:]...)
		data = append(data, UintToBuf(bitcloutOutput.AmountNanos)...)
	}

	// Serialize the metadata
	//
	// Encode the type as a uvarint.
	data = append(data, UintToBuf(uint64(msg.TxnMeta.GetTxnType()))...)
	// Encode the length and payload for the metadata.
	//
	// Note that we do *NOT* serialize the metadata using the preSignature
	// flag. This is the correct thing to do since by the time we're ready
	// to serialize the full transaction, all of the metadata should have
	// its signatures fully computed. As a result, the proper way to use
	// the preSignature flag when metadata is involved is as follows:
	// - Compute the bytes for the meta using preSignature=true
	// - Sign the bytes for the meta however that particular metadata
	//   requires.
	// - Compute the bytes for the full transaction using preSignature=true.
	//   This will fully-serialize the meta with its computed signature,
	//   which is correct.
	// - Sign the bytes for the full transaction from above.
	preSignatureForMeta := false
	metadataBuf, err := msg.TxnMeta.ToBytes(preSignatureForMeta)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgBitCloutTxn.ToBytes: Problem encoding meta of type %v: ",
			msg.TxnMeta.GetTxnType())
	}
	data = append(data, UintToBuf(uint64(len(metadataBuf)))...)
	data = append(data, metadataBuf...)

	// Serialize the public key if there is one. Encode the length in
	// case this field was left empty.
	data = append(data, UintToBuf(uint64(len(msg.PublicKey)))...)
	data = append(data, msg.PublicKey...)

	// ExtraData
	extraDataLength := uint64(len(msg.ExtraData))
	data = append(data, UintToBuf(extraDataLength)...)
	if extraDataLength > 0 {
		// Sort the keys of the map
		keys := make([]string, 0, len(msg.ExtraData))
		for key := range msg.ExtraData {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		// Encode the length of the key, the key itself
		// then the length of the value, then the value itself.
		for _, key := range keys {
			data = append(data, UintToBuf(uint64(len(key)))...)
			data = append(data, []byte(key)...)
			value := msg.ExtraData[key]
			data = append(data, UintToBuf(uint64(len(value)))...)
			data = append(data, value...)
		}
	}

	// Serialize the signature. Since this can be variable length, encode
	// the length first and then the signature. If there is no signature, then
	// a zero will be encoded for the length and no signature bytes will be added
	// beyond it.
	sigBytes := []byte{}
	if !preSignature && len(msg.Signature) != 0 {
		sigBytes = append([]byte{}, msg.Signature...)
	}
	// Note that even though we encode the length as a varint as opposed to a
	// fixed-width int, it should always take up just one byte since the length
	// of the signature will never exceed 127 bytes in length. This is important
	// to note for e.g. operations that try to compute a transaction's size
	// before a signature is present such as during transaction fee computations.
	data = append(data, UintToBuf(uint64(len(sigBytes)))...)
	data = append(data, sigBytes...)

	return data, nil
}

func _readTransaction(rr io.Reader) (*MsgBitCloutTxn, error) {
	ret := NewMessage(MsgTypeTxn).(*MsgBitCloutTxn)

	// De-serialize the inputs
	numInputs, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem converting len(msg.TxInputs)")
	}
	for ii := uint64(0); ii < numInputs; ii++ {
		currentInput := NewBitCloutInput()
		_, err = io.ReadFull(rr, currentInput.TxID[:])
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem converting input txid")
		}
		inputIndex, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem converting input index")
		}
		if inputIndex > uint64(^uint32(0)) {
			return nil, fmt.Errorf("_readTransaction: Input index (%d) must not exceed (%d)", inputIndex, ^uint32(0))
		}
		currentInput.Index = uint32(inputIndex)

		ret.TxInputs = append(ret.TxInputs, currentInput)
	}

	// De-serialize the outputs
	numOutputs, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem converting len(msg.TxOutputs)")
	}
	for ii := uint64(0); ii < numOutputs; ii++ {
		currentOutput := &BitCloutOutput{}
		currentOutput.PublicKey = make([]byte, btcec.PubKeyBytesLenCompressed)
		_, err = io.ReadFull(rr, currentOutput.PublicKey)
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem reading BitCloutOutput.PublicKey")
		}

		amountNanos, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem reading BitCloutOutput.AmountNanos")
		}
		currentOutput.AmountNanos = amountNanos

		ret.TxOutputs = append(ret.TxOutputs, currentOutput)
	}

	// De-serialize the metadata
	//
	// Encode the type as a uvarint.
	txnMetaType, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading MsgBitCloutTxn.TxnType")
	}
	ret.TxnMeta, err = NewTxnMetadata(TxnType(txnMetaType))
	if err != nil {
		return nil, fmt.Errorf("_readTransaction: Problem initializing metadata: %v", err)
	}
	if ret.TxnMeta == nil {
		return nil, fmt.Errorf("_readTransaction: Metadata was nil: %v", ret.TxnMeta)
	}
	metaLen, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading len(TxnMeta)")
	}
	if metaLen > MaxMessagePayload {
		return nil, fmt.Errorf("_readTransaction.FromBytes: metaLen length %d longer than max %d", metaLen, MaxMessagePayload)
	}
	metaBuf := make([]byte, metaLen)
	_, err = io.ReadFull(rr, metaBuf)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading TxnMeta")
	}
	err = ret.TxnMeta.FromBytes(metaBuf)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem decoding TxnMeta: ")
	}

	// De-serialize the public key if there is one
	pkLen, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading len(BitCloutTxn.PublicKey)")
	}
	if pkLen > MaxMessagePayload {
		return nil, fmt.Errorf("_readTransaction.FromBytes: pkLen length %d longer than max %d", pkLen, MaxMessagePayload)
	}
	ret.PublicKey = nil
	if pkLen != 0 {
		ret.PublicKey = make([]byte, pkLen)
		_, err = io.ReadFull(rr, ret.PublicKey)
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem reading BitCloutTxn.PublicKey")
		}
	}

	// De-serialize the ExtraData
	extraDataLen, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading len(BitCloutTxn.ExtraData)")
	}
	if extraDataLen > MaxMessagePayload {
		return nil, fmt.Errorf("_readTransaction.FromBytes: extraDataLen length %d longer than max %d", extraDataLen, MaxMessagePayload)
	}
	// Initialize an map of strings to byte slices of size extraDataLen -- extraDataLen is the number of keys.
	if extraDataLen != 0 {
		ret.ExtraData = make(map[string][]byte, extraDataLen)
		// Loop over each key
		for ii := uint64(0); ii < extraDataLen; ii++ {
			// De-serialize the length of the key
			var keyLen uint64
			keyLen, err = ReadUvarint(rr)
			if err != nil {
				return nil, fmt.Errorf("_readTransaction.FromBytes: Problem reading len(BitcloutTxn.ExtraData.Keys[#{ii}]")
			}
			// De-serialize the key
			keyBytes := make([]byte, keyLen)
			_, err = io.ReadFull(rr, keyBytes)
			if err != nil {
				return nil, fmt.Errorf("_readTransaction.FromBytes: Problem reading key #{ii}")
			}
			// Convert the key to a string and check if it already exists in the map.
			// If it already exists in the map, this is an error as a map cannot have duplicate keys.
			key := string(keyBytes)
			if _, keyExists := ret.ExtraData[key]; keyExists {
				return nil, fmt.Errorf("_readTransaction.FromBytes: Key [#{ii}] ({key}) already exists in ExtraData")
			}
			// De-serialize the length of the value
			var valueLen uint64
			valueLen, err = ReadUvarint(rr)
			if err != nil {
				return nil, fmt.Errorf("_readTransaction.FromBytes: Problem reading len(BitcloutTxn.ExtraData.Value[#{ii}]")
			}
			// De-serialize the value
			value := make([]byte, valueLen)
			_, err = io.ReadFull(rr, value)
			if err != nil {
				return nil, fmt.Errorf("_readTransaction.FromBytes: Problem read value #{ii}")
			}
			// Map the key to the value
			ret.ExtraData[key] = value
		}
	}

	// De-serialize the signature if there is one.
	sigLen, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading len(BitCloutTxn.Signature)")
	}
	if sigLen > MaxMessagePayload {
		return nil, fmt.Errorf("_readTransaction.FromBytes: sigLen length %d longer than max %d", sigLen, MaxMessagePayload)
	}

	if sigLen != 0 {
		sigBytes := make([]byte, sigLen)
		_, err = io.ReadFull(rr, sigBytes)
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem reading BitCloutTxn.Signature")
		}

		// Verify that the signature is valid.
		_, err := btcec.ParseDERSignature(sigBytes, btcec.S256())
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem parsing BitCloutTxn.Signature bytes")
		}
		// If everything worked, we set the ret signature to the original.
		ret.Signature = sigBytes
	}

	return ret, nil
}

func (msg *MsgBitCloutTxn) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	ret, err := _readTransaction(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgBitCloutTxn.FromBytes: Problem reading txn: ")
	}
	*msg = *ret
	return nil
}

func (msg *MsgBitCloutTxn) GetMsgType() MsgType {
	return MsgTypeTxn
}

// Hash is a helper function to compute a hash of the transaction aka a
// transaction ID.
func (msg *MsgBitCloutTxn) Hash() *BlockHash {
	// BitcoinExchange transactions are a special case whereby the hash
	// of the BitClout transaction is defined as the hash of the Bitcoin
	// transaction embedded within it. This allows us to use BitcoinExchange
	// transactions as inputs to subsequent transactions *before* the
	// merkle proof has actually been defined. Thus it allows us to support
	// the "instant BitClout buy" feature in the UI.
	if msg.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
		bitcoinTxHash := (BlockHash)(
			msg.TxnMeta.(*BitcoinExchangeMetadata).BitcoinTransaction.TxHash())
		return &bitcoinTxHash
	}

	preSignature := false
	txBytes, err := msg.ToBytes(preSignature)
	if err != nil {
		return nil
	}

	return Sha256DoubleHash(txBytes)
}

func (msg *MsgBitCloutTxn) Copy() (*MsgBitCloutTxn, error) {
	txnBytes, err := msg.ToBytes(false /*preSignature*/)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgBitCloutTxn.Copy: ")
	}
	newTxn := &MsgBitCloutTxn{}
	err = newTxn.FromBytes(txnBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgBitCloutTxn.Copy: ")
	}
	return newTxn, nil
}

func (msg *MsgBitCloutTxn) Sign(privKey *btcec.PrivateKey) (*btcec.Signature, error) {
	// Serialize the transaction without the signature portion.
	txnBytes, err := msg.ToBytes(true /*preSignature*/)
	if err != nil {
		return nil, err
	}
	// Compute a hash of the transaction bytes without the signature
	// portion and sign it with the passed private key.
	txnSignatureHash := Sha256DoubleHash(txnBytes)
	txnSignature, err := privKey.Sign(txnSignatureHash[:])
	if err != nil {
		return nil, err
	}
	return txnSignature, nil
}

// SignTransactionWithDerivedKey the signature contains solution iteration,
// which allows us to recover signer public key from the signature.
func SignTransactionWithDerivedKey(txnBytes []byte, privateKey *btcec.PrivateKey) ([]byte, error){
	// Compute a hash of the transaction bytes without the signature
	// portion and sign it with the passed private key.
	txnSignatureHash := Sha256DoubleHash(txnBytes)
	txnSignature, err := privateKey.Sign(txnSignatureHash[:])
	if err != nil {
		return nil, err
	}

	// If we're signing with a derived key, we will encode recovery byte into
	// the signature.
	txnSignatureBytes := txnSignature.Serialize()
	txnSignatureCompact, err := btcec.SignCompact(btcec.S256(), privateKey, txnSignatureHash[:], false)
	if err != nil {
		return nil, err
	}

	// Get the public key solution based on btcsuite/btcd RecoverCompact method.
	// Iteration is between 1-4.
	iteration := 1 + int((txnSignatureCompact[0] - CompactControlByte) & ^byte(4))

	// Encode the public key solution in the first byte of the signature.
	// Normally DER signatures start with 0x30 or 48 in base-10. We set
	// the first byte to 0x30 + 0x1-4 depending on the solution.
	txnSignatureBytes[0] = byte(DERControlByte + iteration)

	return txnSignatureBytes, nil
}

// MarshalJSON and UnmarshalJSON implement custom JSON marshaling/unmarshaling
// to support transaction metadata. The reason this needs to exist is because
// TxnMeta is an abstract interface and therefore
// when its decoded to JSON, the type information (i.e. which TxnType it is)
// cannot be inferred from the JSON unless we augment it a little bit.
// Note this format is not used to relay messages between nodes, only
// for replying to frontend/user-facing queries.
func (msg *MsgBitCloutTxn) MarshalJSON() ([]byte, error) {
	// Copy the txn so none of the fields get set on the passed-in txn.
	txnCopy := *msg
	// If there's no metadata then we have an error. Transactions should
	// always have a metadata field that indicates what type the transaction
	// is.
	if txnCopy.TxnMeta == nil {
		return nil, fmt.Errorf("MsgBitCloutTxn.MarshalJSON: Transaction is missing TxnMeta: %v", txnCopy)
	}
	// Set the txnType based on the metadata that is set.
	txnCopy.TxnTypeJSON = uint64(txnCopy.TxnMeta.GetTxnType())
	return json.Marshal(txnCopy)
}

// UnmarshalJSON is covered by the comment on MarshalJSON.
func (msg *MsgBitCloutTxn) UnmarshalJSON(data []byte) error {
	// Use the map-based JSON conversion to determine the type of the
	// TxnMeta and initialize it appropriately.
	var responseMap map[string]interface{}
	err := json.Unmarshal(data, &responseMap)
	if err != nil {
		return err
	}

	// Set the TxnMeta based on the TxnType that's set in the top level
	// of the transaction.
	txnType, txnTypeExists := responseMap["TxnTypeJSON"]
	if !txnTypeExists {
		// If there is not metadata that's an error.
		return fmt.Errorf("MsgBitCloutTxn.UnmarshalJSON: Field txnType is missing "+
			"from JSON decoded map: %v", responseMap)
	}
	txnMeta, err := NewTxnMetadata(TxnType(uint64(txnType.(float64))))
	if err != nil {
		return fmt.Errorf("MsgBitCloutTxn.UnmarshalJSON: Problem parsing TxnType: %v, %v", err, responseMap)
	}
	msg.TxnMeta = txnMeta

	// TODO: The code below is an ugly hack, but it achieves the goal of making
	// TxnMeta (and MsgBitCloutTxn by proxy) serializable to JSON without any extra overhead
	// needed on the caller side. This is particularly important when one considers
	// that transactions can be serialized to JSON as part of blocks,
	// and this makes it so that even in that case no special handling is
	// needed by the code serializing/deserializing, which is good. Still, would
	// be nice if, for example, the code below didn't break whenever we modify
	// MsgBitCloutTxn (which is admittedly very rare and a test can easily catch this
	// by erroring when the number of fields changes with a helpful message).
	anonymousTxn := struct {
		TxInputs  []*BitCloutInput
		TxOutputs []*BitCloutOutput
		TxnMeta   BitCloutTxnMetadata
		PublicKey []byte
		Signature []byte
		TxnType   uint64
	}{
		TxInputs:  msg.TxInputs,
		TxOutputs: msg.TxOutputs,
		TxnMeta:   msg.TxnMeta,
		PublicKey: msg.PublicKey,
		Signature: msg.Signature,
		TxnType:   msg.TxnTypeJSON,
	}
	json.Unmarshal(data, &anonymousTxn)

	msg.TxInputs = anonymousTxn.TxInputs
	msg.TxOutputs = anonymousTxn.TxOutputs
	msg.TxnMeta = anonymousTxn.TxnMeta
	msg.PublicKey = anonymousTxn.PublicKey
	msg.Signature = anonymousTxn.Signature
	// Don't set the TxnTypeJSON when unmarshaling. It should never be used in
	// Go code, only at the interface between Go and non-Go.
	msg.TxnTypeJSON = 0

	return nil
}

// ==================================================================
// BasicTransferMetadata
// ==================================================================

type BasicTransferMetadata struct {
	// Requires no extra information
}

func (txnData *BasicTransferMetadata) GetTxnType() TxnType {
	return TxnTypeBasicTransfer
}

func (txnData *BasicTransferMetadata) ToBytes(preSignature bool) ([]byte, error) {
	return []byte{}, nil
}

func (txnData *BasicTransferMetadata) FromBytes(data []byte) error {
	// Nothing to set
	return nil
}

func (txnData *BasicTransferMetadata) New() BitCloutTxnMetadata {
	return &BasicTransferMetadata{}
}

// ==================================================================
// BlockRewardMetadataa
// ==================================================================

type BlockRewardMetadataa struct {
	// A block reward txn has an ExtraData field that can be between
	// zero and 100 bytes long. It can theoretically contain anything
	// but in practice it's likely that miners will use this field to
	// update the merkle root of the block, which may make the block
	// easier to mine (namely by allowing the Nonce in the header to
	// be shorter).
	ExtraData []byte
}

func (txnData *BlockRewardMetadataa) GetTxnType() TxnType {
	return TxnTypeBlockReward
}

func (txnData *BlockRewardMetadataa) ToBytes(preSignature bool) ([]byte, error) {
	retBytes := []byte{}

	// ExtraData.
	numExtraDataBytes := len(txnData.ExtraData)
	if numExtraDataBytes > MaxBlockRewardDataSizeBytes {
		return nil, fmt.Errorf(
			"BLOCK_REWARD txn ExtraData length (%d) cannot be longer than "+
				"(%d) bytes", numExtraDataBytes, MaxBlockRewardDataSizeBytes)
	}
	retBytes = append(retBytes, UintToBuf(uint64(numExtraDataBytes))...)
	retBytes = append(retBytes, txnData.ExtraData...)

	return retBytes, nil
}

func (txnData *BlockRewardMetadataa) FromBytes(dataa []byte) error {
	ret := BlockRewardMetadataa{}
	rr := bytes.NewReader(dataa)

	// ExtraData
	numExtraDataBytes, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BlockRewardMetadataa.FromBytes: Problem reading NumExtraDataBytes")
	}

	if numExtraDataBytes > uint64(MaxBlockRewardDataSizeBytes) {
		return fmt.Errorf(
			"BLOCK_REWARD txn ExtraData length (%d) cannot be longer than "+
				"(%d) bytes", numExtraDataBytes, MaxBlockRewardDataSizeBytes)
	}
	ret.ExtraData = make([]byte, numExtraDataBytes)
	_, err = io.ReadFull(rr, ret.ExtraData[:])
	if err != nil {
		return errors.Wrapf(err, "BlockRewardMetadataa.FromBytes: Problem reading ExtraData")
	}

	*txnData = ret
	return nil
}

func (txnData *BlockRewardMetadataa) New() BitCloutTxnMetadata {
	return &BlockRewardMetadataa{}
}

func EncryptBytesWithPublicKey(bytesToEncrypt []byte, pubkey *ecdsa.PublicKey) ([]byte, error) {
	eciesPubkey := ecies.ImportECDSAPublic(pubkey)
	// Note we need to manually set the Params. Params is normally
	// set automatically in ImportECDSA based on what curve you're using.
	// However, because we use btcec.S256() rather than Ethereum's
	// implementation ethcrypto.S256(), which is just a wrapper around
	// secp256k1, the ecies library fails to fetch the proper parameters
	// for our curve even though it is functionally identical. So we just
	// set the params here and everything works.
	eciesPubkey.Params = ecies.ECIES_AES128_SHA256
	return ecies.Encrypt(rand.Reader, eciesPubkey, bytesToEncrypt, nil, nil)
}

func DecryptBytesWithPrivateKey(bytesToDecrypt []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
	eciesKeypair := ecies.ImportECDSA(privKey)
	// Note we need to manually set the Params. Params is normally
	// set automatically in ImportECDSA based on what curve you're using.
	// However, because we use btcec.S256() rather than Ethereum's
	// implementation ethcrypto.S256(), which is just a wrapper around
	// secp256k1, the ecies library fails to fetch the proper parameters
	// for our curve even though it is functionally identical. So we just
	// set the params here and everything works.
	eciesKeypair.Params = ecies.ECIES_AES128_SHA256
	return eciesKeypair.Decrypt(bytesToDecrypt, nil, nil)
}

// ==================================================================
// BitcoinExchangeMetadata
// ==================================================================

type BitcoinExchangeMetadata struct {
	// The Bitcoin transaction that sends Bitcoin to the designated burn address.
	BitcoinTransaction *wire.MsgTx
	// The hash of the Bitcoin block in which the Bitcoin transaction was mined.
	BitcoinBlockHash *BlockHash
	// The Bitcoin mekle root corresponding to the block in which the BitcoinTransaction
	// above was mined. Note that it is not strictly necessary to include this field
	// since we can look it up from the Bitcoin header if we know the BitcoinBlockHash.
	// However, having it here is convenient and allows us to do more validation prior
	// to looking up the header in the Bitcoin header chain.
	BitcoinMerkleRoot *BlockHash
	// This is a merkle proof that shows that the BitcoinTransaction above, with
	// hash equal to BitcoinTransactionHash, exists in the block with hash equal
	// to BitcoinBlockHash. This is effectively a path through a Merkle tree starting
	// from BitcoinTransactionHash as a leaf node and finishing with BitcoinMerkleRoot
	// as the root.
	BitcoinMerkleProof []*merkletree.ProofPart
}

func (txnData *BitcoinExchangeMetadata) GetTxnType() TxnType {
	return TxnTypeBitcoinExchange
}

func (txnData *BitcoinExchangeMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// BitcoinTransaction
	txnBytes := bytes.Buffer{}
	if err := txnData.BitcoinTransaction.Serialize(&txnBytes); err != nil {
		return nil, errors.Wrapf(err, "BitcoinExchangeMetadata.ToBytes: Problem "+
			"serializing BitcoinTransaction: ")
	}
	data = append(data, UintToBuf(uint64(len(txnBytes.Bytes())))...)
	data = append(data, txnBytes.Bytes()...)

	// BitcoinBlockHash
	data = append(data, txnData.BitcoinBlockHash[:]...)

	// BitcoinMerkleRoot
	data = append(data, txnData.BitcoinMerkleRoot[:]...)

	// BitcoinMerkleProof
	//
	// Encode the number of proof parts followed by all the proof parts.
	numProofParts := uint64(len(txnData.BitcoinMerkleProof))
	data = append(data, UintToBuf(numProofParts)...)
	for _, pf := range txnData.BitcoinMerkleProof {
		// ProofParts have a specific length so no need to encode the length.
		pfBytes, err := pf.Serialize()
		if err != nil {
			return nil, errors.Wrapf(err, "BitcoinExchangeMetadata.ToBytes")
		}

		data = append(data, pfBytes...)
	}

	return data, nil
}

func (txnData *BitcoinExchangeMetadata) FromBytes(data []byte) error {
	ret := BitcoinExchangeMetadata{}
	rr := bytes.NewReader(data)

	// BitcoinTransaction
	txnBytesLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem "+
			"decoding BitcoinTransaction length")
	}
	if txnBytesLen > MaxMessagePayload {
		return fmt.Errorf("BitcoinExchangeMetadata.FromBytes: txnBytesLen %d "+
			"exceeds max %d", txnBytesLen, MaxMessagePayload)
	}
	txnBytes := make([]byte, txnBytesLen)
	_, err = io.ReadFull(rr, txnBytes)
	if err != nil {
		return fmt.Errorf("BitcoinExchangeMetadata.FromBytes: Error reading txnBytes: %v", err)
	}
	ret.BitcoinTransaction = &wire.MsgTx{}
	err = ret.BitcoinTransaction.Deserialize(bytes.NewBuffer(txnBytes))
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem parsing txnBytes: ")
	}

	// BitcoinBlockHash
	ret.BitcoinBlockHash = &BlockHash{}
	_, err = io.ReadFull(rr, ret.BitcoinBlockHash[:])
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem reading BitcoinBlockHash: ")
	}

	// BitcoinMerkleRoot
	ret.BitcoinMerkleRoot = &BlockHash{}
	_, err = io.ReadFull(rr, ret.BitcoinMerkleRoot[:])
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem reading BitcoinMerkleRoot: ")
	}

	// BitcoinMerkleProof
	numProofParts, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem reading numProofParts: ")
	}
	for ii := uint64(0); ii < numProofParts; ii++ {
		pfBytes := make([]byte, merkletree.ProofPartSerializeSize)
		_, err = io.ReadFull(rr, pfBytes[:])
		if err != nil {
			return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem reading ProofPart %d: ", ii)
		}
		pf := &merkletree.ProofPart{}
		if err := pf.Deserialize(pfBytes); err != nil {
			return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem parsing ProofPart %d: ", ii)
		}

		ret.BitcoinMerkleProof = append(ret.BitcoinMerkleProof, pf)
	}

	*txnData = ret

	return nil
}

func (txnData *BitcoinExchangeMetadata) New() BitCloutTxnMetadata {
	return &BitcoinExchangeMetadata{}
}

// ==================================================================
// PrivateMessageMetadata
//
// A private message is a message from one user on the platform to
// another user on the platform. It is generally treated as a normal
// transaction would be except that the public key of the top-level
// MsgBitCloutTxn is assumed to be the sender of the message and the
// metadata contains a messange encrypted with the receiver's public
// key.
// ==================================================================

type PrivateMessageMetadata struct {
	// The sender of the message is assumed to be the originator of the
	// top-level transaction.

	// The public key of the recipient of the message.
	RecipientPublicKey []byte

	// The content of the message. It is encrypted with the recipient's
	// public key using ECIES.
	EncryptedText []byte

	// A timestamp used for ordering messages when displaying them to
	// users. The timestamp must be unique. Note that we use a nanosecond
	// timestamp because it makes it easier to deal with the uniqueness
	// constraint technically (e.g. If one second spacing is required
	// as would be the case with a standard Unix timestamp then any code
	// that generates these transactions will need to potentially wait
	// or else risk a timestamp collision. This complexity is avoided
	// by just using a nanosecond timestamp). Note that the timestamp is
	// an unsigned int as opposed to a signed int, which means times
	// before the zero time are not represented which doesn't matter
	// for our purposes. Restricting the timestamp in this way makes
	// lexicographic sorting based on bytes easier in our database which
	// is one of the reasons we do it.
	TimestampNanos uint64
}

func (txnData *PrivateMessageMetadata) GetTxnType() TxnType {
	return TxnTypePrivateMessage
}

func (txnData *PrivateMessageMetadata) ToBytes(preSignature bool) ([]byte, error) {
	// Validate the metadata before encoding it.
	//
	// Public key must be included and must have the expected length.
	if len(txnData.RecipientPublicKey) != btcec.PubKeyBytesLenCompressed {
		return nil, fmt.Errorf("PrivateMessageMetadata.ToBytes: RecipientPublicKey "+
			"has length %d != %d", len(txnData.RecipientPublicKey), btcec.PubKeyBytesLenCompressed)
	}

	data := []byte{}

	// RecipientPublicKey
	//
	// We know the public key is set and has the expected length so we don't need
	// to encode the length here.
	data = append(data, txnData.RecipientPublicKey...)

	// EncryptedText
	data = append(data, UintToBuf(uint64(len(txnData.EncryptedText)))...)
	data = append(data, txnData.EncryptedText...)

	// TimestampNanos
	data = append(data, UintToBuf(txnData.TimestampNanos)...)

	return data, nil
}

func (txnData *PrivateMessageMetadata) FromBytes(data []byte) error {
	ret := PrivateMessageMetadata{}
	rr := bytes.NewReader(data)

	// RecipientPublicKey
	ret.RecipientPublicKey = make([]byte, btcec.PubKeyBytesLenCompressed)
	_, err := io.ReadFull(rr, ret.RecipientPublicKey)
	if err != nil {
		return fmt.Errorf("PrivateMessageMetadata.FromBytes: Error reading RecipientPublicKey: %v", err)
	}

	// EncryptedText
	encryptedTextLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PrivateMessageMetadata.FromBytes: Problem "+
			"decoding EncryptedText length")
	}
	if encryptedTextLen > MaxMessagePayload {
		return fmt.Errorf("PrivateMessageMetadata.FromBytes: encryptedTextLen %d "+
			"exceeds max %d", encryptedTextLen, MaxMessagePayload)
	}
	ret.EncryptedText = make([]byte, encryptedTextLen)
	_, err = io.ReadFull(rr, ret.EncryptedText)
	if err != nil {
		return fmt.Errorf("PrivateMessageMetadata.FromBytes: Error reading EncryptedText: %v", err)
	}

	// TimestampNanos
	ret.TimestampNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("PrivateMessageMetadata.FromBytes: Error reading TimestampNanos: %v", err)
	}

	*txnData = ret

	return nil
}

func (txnData *PrivateMessageMetadata) New() BitCloutTxnMetadata {
	return &PrivateMessageMetadata{}
}

// ==================================================================
// LikeMetadata
//
// A like is an interaction where a user on the platform "likes" a post.
// ==================================================================

type LikeMetadata struct {
	// The user casting a "like" is assumed to be the originator of the
	// top-level transaction.

	// The post hash to like.
	LikedPostHash *BlockHash

	// Set to true when a user is requesting to unlike a post.
	IsUnlike bool
}

func (txnData *LikeMetadata) GetTxnType() TxnType {
	return TxnTypeLike
}

func (txnData *LikeMetadata) ToBytes(preSignature bool) ([]byte, error) {
	// Validate the metadata before encoding it.
	//
	// Post hash must be included and must have the expected length.
	if len(txnData.LikedPostHash) != HashSizeBytes {
		return nil, fmt.Errorf("LikeMetadata.ToBytes: LikedPostHash "+
			"has length %d != %d", len(txnData.LikedPostHash), HashSizeBytes)
	}

	data := []byte{}

	// Add LikedPostHash
	//
	// We know the post hash is set and has the expected length so we don't need
	// to encode the length here.
	data = append(data, txnData.LikedPostHash[:]...)

	// Add IsUnlike bool.
	data = append(data, BoolToByte(txnData.IsUnlike))

	return data, nil
}

func (txnData *LikeMetadata) FromBytes(data []byte) error {
	ret := LikeMetadata{}
	rr := bytes.NewReader(data)

	// LikedPostHash
	ret.LikedPostHash = &BlockHash{}
	_, err := io.ReadFull(rr, ret.LikedPostHash[:])
	if err != nil {
		return fmt.Errorf(
			"LikeMetadata.FromBytes: Error reading LikedPostHash: %v", err)
	}

	// IsUnlike
	ret.IsUnlike = ReadBoolByte(rr)

	*txnData = ret

	return nil
}

func (txnData *LikeMetadata) New() BitCloutTxnMetadata {
	return &LikeMetadata{}
}

// ==================================================================
// FollowMetadata
//
// A follow is an interaction where one user on the platform
// "follows" another user on the platform.  This is used as an
// indicator to UIs/Feeds that a user is interested in
// consuming the "followed" users content.
// ==================================================================

type FollowMetadata struct {
	// The follower is assumed to be the originator of the
	// top-level transaction.

	// The public key to follow.
	FollowedPublicKey []byte

	// Set to true when a user is requesting to unfollow.
	IsUnfollow bool
}

func (txnData *FollowMetadata) GetTxnType() TxnType {
	return TxnTypeFollow
}

func (txnData *FollowMetadata) ToBytes(preSignature bool) ([]byte, error) {
	// Validate the metadata before encoding it.
	//
	// Public key must be included and must have the expected length.
	if len(txnData.FollowedPublicKey) != btcec.PubKeyBytesLenCompressed {
		return nil, fmt.Errorf("FollowMetadata.ToBytes: FollowedPublicKey "+
			"has length %d != %d", len(txnData.FollowedPublicKey),
			btcec.PubKeyBytesLenCompressed)
	}

	data := []byte{}

	// RecipientPublicKey
	//
	// We know the public key is set and has the expected length so we don't need
	// to encode the length here.
	data = append(data, txnData.FollowedPublicKey...)

	// Add IsUnfollow bool.
	data = append(data, BoolToByte(txnData.IsUnfollow))

	return data, nil
}

func (txnData *FollowMetadata) FromBytes(data []byte) error {
	ret := FollowMetadata{}
	rr := bytes.NewReader(data)

	// FollowedPublicKey
	ret.FollowedPublicKey = make([]byte, btcec.PubKeyBytesLenCompressed)
	_, err := io.ReadFull(rr, ret.FollowedPublicKey)
	if err != nil {
		return fmt.Errorf(
			"FollowMetadata.FromBytes: Error reading FollowedPublicKey: %v", err)
	}

	// IsUnfollow
	ret.IsUnfollow = ReadBoolByte(rr)

	*txnData = ret

	return nil
}

func (txnData *FollowMetadata) New() BitCloutTxnMetadata {
	return &FollowMetadata{}
}

// = = = = = = = = = = = = = = = = = = = = = = =
// BitClout
// = = = = = = = = = = = = = = = = = = = = = = =

// ==================================================================
// SubmitPostMetadata
// ==================================================================

func ReadBoolByte(rr *bytes.Reader) bool {
	boolByte, err := rr.ReadByte()
	if err != nil {
		return false
	}
	if boolByte != 0 {
		return true
	}
	return false
}

func BoolToByte(val bool) byte {
	if val {
		return 1
	}
	return 0
}

type SubmitPostMetadata struct {
	// The creator of the post is assumed to be the originator of the
	// top-level transaction.

	// When set, this transaction is treated as modifying an existing
	// post rather than creating a new post.
	PostHashToModify []byte

	// When a ParentStakeID is set, the post is actually a comment on
	// another entity (either a post or a profile depending on the
	// type of StakeID provided).
	ParentStakeID []byte
	Body          []byte

	// The amount the creator of the post gets when someone stakes
	// to the post.
	CreatorBasisPoints uint64
	// The multiple of the payout when a user stakes to a post.
	// 2x multiple = 200% = 20,000bps
	StakeMultipleBasisPoints uint64

	// A timestamp used for ordering messages when displaying them to
	// users. The timestamp must be unique. Note that we use a nanosecond
	// timestamp because it makes it easier to deal with the uniqueness
	// constraint technically (e.g. If one second spacing is required
	// as would be the case with a standard Unix timestamp then any code
	// that generates these transactions will need to potentially wait
	// or else risk a timestamp collision. This complexity is avoided
	// by just using a nanosecond timestamp). Note that the timestamp is
	// an unsigned int as opposed to a signed int, which means times
	// before the zero time are not represented which doesn't matter
	// for our purposes. Restricting the timestamp in this way makes
	// lexicographic sorting based on bytes easier in our database which
	// is one of the reasons we do it.
	TimestampNanos uint64

	// When set to true, indicates that the post should be deleted. This
	// value is only considered when PostHashToModify is set to a valid
	// pre-existing post.
	IsHidden bool
}

func (txnData *SubmitPostMetadata) GetTxnType() TxnType {
	return TxnTypeSubmitPost
}

func (txnData *SubmitPostMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// PostHashToModify
	data = append(data, UintToBuf(uint64(len(txnData.PostHashToModify)))...)
	data = append(data, txnData.PostHashToModify...)

	// ParentPostHash
	data = append(data, UintToBuf(uint64(len(txnData.ParentStakeID)))...)
	data = append(data, txnData.ParentStakeID...)

	// Body
	data = append(data, UintToBuf(uint64(len(txnData.Body)))...)
	data = append(data, txnData.Body...)

	// CreatorBasisPoints
	data = append(data, UintToBuf(txnData.CreatorBasisPoints)...)

	// StakeMultipleBasisPoints
	data = append(data, UintToBuf(txnData.StakeMultipleBasisPoints)...)

	// TimestampNanos
	data = append(data, UintToBuf(txnData.TimestampNanos)...)

	// IsHidden
	data = append(data, BoolToByte(txnData.IsHidden))

	return data, nil
}

func ReadVarString(rr io.Reader) ([]byte, error) {
	StringLen, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "SubmitPostMetadata.FromBytes: Problem "+
			"decoding String length")
	}
	if StringLen > MaxMessagePayload {
		return nil, fmt.Errorf("SubmitPostMetadata.FromBytes: StringLen %d "+
			"exceeds max %d", StringLen, MaxMessagePayload)
	}
	ret := make([]byte, StringLen)
	_, err = io.ReadFull(rr, ret)
	if err != nil {
		return nil, fmt.Errorf("SubmitPostMetadata.FromBytes: Error reading StringText: %v", err)
	}

	return ret, nil
}

func (txnData *SubmitPostMetadata) FromBytes(data []byte) error {
	ret := SubmitPostMetadata{}
	rr := bytes.NewReader(data)

	// PostHashToModify
	var err error
	ret.PostHashToModify, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf("SubmitPostMetadata.FromBytes: Error reading PostHashToModify: %v", err)
	}

	// ParentStakeID
	ret.ParentStakeID, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf("SubmitPostMetadata.FromBytes: Error reading ParentStakeID: %v", err)
	}

	// Body
	ret.Body, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"SubmitPostMetadata.FromBytes: Error reading Body: %v", err)
	}

	// CreatorBasisPoints
	ret.CreatorBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("SubmitPostMetadata.FromBytes: Error reading CreatorBasisPoints: %v", err)
	}

	// StakeMultipleBasisPoints
	ret.StakeMultipleBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("SubmitPostMetadata.FromBytes: Error reading StakeMultipleBasisPoints: %v", err)
	}

	// TimestampNanos
	ret.TimestampNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("SubmitPostMetadata.FromBytes: Error reading TimestampNanos: %v", err)
	}

	// IsHidden
	ret.IsHidden = ReadBoolByte(rr)

	*txnData = ret

	return nil
}

func (txnData *SubmitPostMetadata) New() BitCloutTxnMetadata {
	return &SubmitPostMetadata{}
}

// ==================================================================
// UpdateProfileMetadata
// ==================================================================

type UpdateProfileMetadata struct {
	// The public key being updated is assumed to be the originator of the
	// top-level transaction.

	// The public key of the profile to update. When left unset, the public
	// key in the transaction is used.
	ProfilePublicKey []byte

	NewUsername    []byte
	NewDescription []byte
	NewProfilePic  []byte

	// This is the percentage of each "net buy" that a creator earns when
	// someone purchases her coin. For example, if this were set to 25%,
	// then every time their coin reaches a new high, they would get 25%
	// of the coins as they're being minted. More concretely, if someone
	// put in enough BitClout to buy 10 coins, the creator would get 2.5
	// and this person would get 7.5. However, if they sold 5 coins and
	// someone subsequently bought those same coins, the creator wouldn't
	// get any coins because no "net new" coins have been created.
	NewCreatorBasisPoints uint64

	// The multiple of the payout when a user stakes to this profile. If
	// unset, a sane default is set when the first person stakes to this
	// profile.
	// 2x multiple = 200% = 20,000bps
	//
	// TODO: This field is deprecated; delete it.
	NewStakeMultipleBasisPoints uint64

	// Profile is hidden from the UI when this field is true.
	// TODO: This field is deprecated; delete it.
	IsHidden bool
}

func (txnData *UpdateProfileMetadata) GetTxnType() TxnType {
	return TxnTypeUpdateProfile
}

func (txnData *UpdateProfileMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// ProfilePublicKey
	data = append(data, UintToBuf(uint64(len(txnData.ProfilePublicKey)))...)
	data = append(data, txnData.ProfilePublicKey...)

	// NewUsername
	data = append(data, UintToBuf(uint64(len(txnData.NewUsername)))...)
	data = append(data, txnData.NewUsername...)

	// NewDescription
	data = append(data, UintToBuf(uint64(len(txnData.NewDescription)))...)
	data = append(data, txnData.NewDescription...)

	// NewProfilePic
	data = append(data, UintToBuf(uint64(len(txnData.NewProfilePic)))...)
	data = append(data, txnData.NewProfilePic...)

	// NewCreatorBasisPoints
	data = append(data, UintToBuf(txnData.NewCreatorBasisPoints)...)

	// NewStakeMultipleBasisPoints
	data = append(data, UintToBuf(txnData.NewStakeMultipleBasisPoints)...)

	// IsHidden
	data = append(data, BoolToByte(txnData.IsHidden))

	return data, nil
}

func (txnData *UpdateProfileMetadata) FromBytes(data []byte) error {
	ret := UpdateProfileMetadata{}
	rr := bytes.NewReader(data)

	// ProfilePublicKey
	var err error
	ret.ProfilePublicKey, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"UpdateProfileMetadata.FromBytes: Error reading ProfilePublicKey: %v", err)
	}
	// Set the profile public key to nil if it's not set as a convenience.
	if len(ret.ProfilePublicKey) == 0 {
		ret.ProfilePublicKey = nil
	}

	// NewUsername
	ret.NewUsername, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"UpdateProfileMetadata.FromBytes: Error reading NewUsername: %v", err)
	}

	// NewDescription
	ret.NewDescription, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"UpdateProfileMetadata.FromBytes: Error reading NewDescription: %v", err)
	}

	// NewProfilePic
	ret.NewProfilePic, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"UpdateProfileMetadata.FromBytes: Error reading NewProfilePic: %v", err)
	}

	// NewCreatorBasisPoints
	ret.NewCreatorBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("UpdateProfileMetadata.FromBytes: Error reading NewCreatorBasisPoints: %v", err)
	}

	// NewStakeMultipleBasisPoints
	ret.NewStakeMultipleBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("UpdateProfileMetadata.FromBytes: Error reading NewStakeMultipleBasisPoints: %v", err)
	}

	// IsHidden
	ret.IsHidden = ReadBoolByte(rr)

	*txnData = ret

	return nil
}

func (txnData *UpdateProfileMetadata) New() BitCloutTxnMetadata {
	return &UpdateProfileMetadata{}
}

// ==================================================================
// UpdateGlobalParamsMetadata
// ==================================================================
type UpdateGlobalParamsMetadata struct {
	// The GlobalParamsMetadata struct is empty because all information is stored in the transaction's ExtraData
}

func (txnData *UpdateGlobalParamsMetadata) GetTxnType() TxnType {
	return TxnTypeUpdateGlobalParams
}

func (txnData *UpdateGlobalParamsMetadata) ToBytes(preSignature bool) ([]byte, error) {
	// All metadata is stored in extra for these transactions.
	retBytes := []byte{}
	return retBytes, nil
}

func (txnData *UpdateGlobalParamsMetadata) FromBytes(data []byte) error {
	ret := UpdateGlobalParamsMetadata{}
	// All metadata is stored in extra for these transactions.
	*txnData = ret
	return nil
}

func (txnData *UpdateGlobalParamsMetadata) New() BitCloutTxnMetadata {
	return &UpdateGlobalParamsMetadata{}
}

// ==================================================================
// UpdateBitcoinUSDExchangeRateMetadataa
// ==================================================================

type UpdateBitcoinUSDExchangeRateMetadataa struct {
	// The new exchange rate to set.
	USDCentsPerBitcoin uint64
}

func (txnData *UpdateBitcoinUSDExchangeRateMetadataa) GetTxnType() TxnType {
	return TxnTypeUpdateBitcoinUSDExchangeRate
}

func (txnData *UpdateBitcoinUSDExchangeRateMetadataa) ToBytes(preSignature bool) ([]byte, error) {
	retBytes := []byte{}

	retBytes = append(retBytes, UintToBuf(uint64(txnData.USDCentsPerBitcoin))...)

	return retBytes, nil
}

func (txnData *UpdateBitcoinUSDExchangeRateMetadataa) FromBytes(dataa []byte) error {
	ret := UpdateBitcoinUSDExchangeRateMetadataa{}
	rr := bytes.NewReader(dataa)

	// USDCentsPerBitcoin
	var err error
	ret.USDCentsPerBitcoin, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("UpdateBitcoinUSDExchangeRateMetadata.FromBytes: Error reading USDCentsPerBitcoin: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *UpdateBitcoinUSDExchangeRateMetadataa) New() BitCloutTxnMetadata {
	return &UpdateBitcoinUSDExchangeRateMetadataa{}
}

// ==================================================================
// CreatorCoinMetadataa
// ==================================================================

type CreatorCoinOperationType uint8

const (
	CreatorCoinOperationTypeBuy         CreatorCoinOperationType = 0
	CreatorCoinOperationTypeSell        CreatorCoinOperationType = 1
	CreatorCoinOperationTypeAddBitClout CreatorCoinOperationType = 2
)

type CreatorCoinMetadataa struct {
	// ProfilePublicKey is the public key of the profile that owns the
	// coin the person wants to operate on. Creator coins can only be
	// bought and sold if a valid profile exists.
	ProfilePublicKey []byte

	// OperationType specifies what the user wants to do with this
	// creator coin.
	OperationType CreatorCoinOperationType

	// Generally, only one of these will be used depending on the OperationType
	// set. In a Buy transaction, BitCloutToSellNanos will be converted into
	// creator coin on behalf of the user. In a Sell transaction,
	// CreatorCoinToSellNanos will be converted into BitClout. In an AddBitClout
	// operation, BitCloutToAddNanos will be aded for the user. This allows us to
	// support multiple transaction types with same meta field.
	BitCloutToSellNanos    uint64
	CreatorCoinToSellNanos uint64
	BitCloutToAddNanos     uint64

	// When a user converts BitClout into CreatorCoin, MinCreatorCoinExpectedNanos
	// specifies the minimum amount of creator coin that the user expects from their
	// transaction. And vice versa when a user is converting CreatorCoin for BitClout.
	// Specifying these fields prevents the front-running of users' buy/sell. Setting
	// them to zero turns off the check. Give it your best shot, Ivan.
	MinBitCloutExpectedNanos    uint64
	MinCreatorCoinExpectedNanos uint64
}

func (txnData *CreatorCoinMetadataa) GetTxnType() TxnType {
	return TxnTypeCreatorCoin
}

func (txnData *CreatorCoinMetadataa) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// ProfilePublicKey
	data = append(data, UintToBuf(uint64(len(txnData.ProfilePublicKey)))...)
	data = append(data, txnData.ProfilePublicKey...)

	// OperationType byte
	data = append(data, byte(txnData.OperationType))

	// BitCloutToSellNanos    uint64
	data = append(data, UintToBuf(uint64(txnData.BitCloutToSellNanos))...)

	// CreatorCoinToSellNanos uint64
	data = append(data, UintToBuf(uint64(txnData.CreatorCoinToSellNanos))...)
	// BitCloutToAddNanos     uint64
	data = append(data, UintToBuf(uint64(txnData.BitCloutToAddNanos))...)

	// MinBitCloutExpectedNanos    uint64
	data = append(data, UintToBuf(uint64(txnData.MinBitCloutExpectedNanos))...)
	// MinCreatorCoinExpectedNanos uint64
	data = append(data, UintToBuf(uint64(txnData.MinCreatorCoinExpectedNanos))...)

	return data, nil
}

func (txnData *CreatorCoinMetadataa) FromBytes(dataa []byte) error {
	ret := CreatorCoinMetadataa{}
	rr := bytes.NewReader(dataa)

	// ProfilePublicKey
	var err error
	ret.ProfilePublicKey, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"CreatorCoinMetadataa.FromBytes: Error reading ProfilePublicKey: %v", err)
	}

	// OperationType byte
	operationType, err := rr.ReadByte()
	if err != nil {
		return fmt.Errorf(
			"CreatorCoinMetadataa.FromBytes: Error reading OperationType: %v", err)
	}
	ret.OperationType = CreatorCoinOperationType(operationType)

	// BitCloutToSellNanos    uint64
	ret.BitCloutToSellNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreatorCoinMetadata.FromBytes: Error reading BitCloutToSellNanos: %v", err)
	}

	// CreatorCoinToSellNanos uint64
	ret.CreatorCoinToSellNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreatorCoinMetadata.FromBytes: Error reading CreatorCoinToSellNanos: %v", err)
	}

	// BitCloutToAddNanos     uint64
	ret.BitCloutToAddNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreatorCoinMetadata.FromBytes: Error reading BitCloutToAddNanos: %v", err)
	}

	// MinBitCloutExpectedNanos    uint64
	ret.MinBitCloutExpectedNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreatorCoinMetadata.FromBytes: Error reading MinBitCloutExpectedNanos: %v", err)
	}

	// MinCreatorCoinExpectedNanos uint64
	ret.MinCreatorCoinExpectedNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreatorCoinMetadata.FromBytes: Error reading MinCreatorCoinExpectedNanos: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *CreatorCoinMetadataa) New() BitCloutTxnMetadata {
	return &CreatorCoinMetadataa{}
}

// ==================================================================
// CreatorCoinTransferMetadataa
// ==================================================================

type CreatorCoinTransferMetadataa struct {
	// ProfilePublicKey is the public key of the profile that owns the
	// coin the person wants to transer. Creator coins can only be
	// transferred if a valid profile exists.
	ProfilePublicKey []byte

	CreatorCoinToTransferNanos uint64
	ReceiverPublicKey          []byte
}

func (txnData *CreatorCoinTransferMetadataa) GetTxnType() TxnType {
	return TxnTypeCreatorCoinTransfer
}

func (txnData *CreatorCoinTransferMetadataa) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// ProfilePublicKey
	data = append(data, UintToBuf(uint64(len(txnData.ProfilePublicKey)))...)
	data = append(data, txnData.ProfilePublicKey...)

	// CreatorCoinToTransferNanos uint64
	data = append(data, UintToBuf(uint64(txnData.CreatorCoinToTransferNanos))...)

	// RecipientPublicKey
	data = append(data, UintToBuf(uint64(len(txnData.ReceiverPublicKey)))...)
	data = append(data, txnData.ReceiverPublicKey...)

	return data, nil
}

func (txnData *CreatorCoinTransferMetadataa) FromBytes(dataa []byte) error {
	ret := CreatorCoinTransferMetadataa{}
	rr := bytes.NewReader(dataa)

	// ProfilePublicKey
	var err error
	ret.ProfilePublicKey, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"CreatorCoinTransferMetadataa.FromBytes: Error reading ProfilePublicKey: %v", err)
	}

	// CreatorCoinToTransferNanos uint64
	ret.CreatorCoinToTransferNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreatorCoinTransferMetadata.FromBytes: Error reading CreatorCoinToSellNanos: %v", err)
	}

	// ReceiverPublicKey
	ret.ReceiverPublicKey, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"CreatorCoinTransferMetadataa.FromBytes: Error reading ProfilePublicKey: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *CreatorCoinTransferMetadataa) New() BitCloutTxnMetadata {
	return &CreatorCoinTransferMetadataa{}
}

// ==================================================================
// CreateNFTMetadata
// ==================================================================

type CreateNFTMetadata struct {
	NFTPostHash                    *BlockHash
	NumCopies                      uint64
	HasUnlockable                  bool
	IsForSale                      bool
	MinBidAmountNanos              uint64
	NFTRoyaltyToCreatorBasisPoints uint64
	NFTRoyaltyToCoinBasisPoints    uint64
}

func (txnData *CreateNFTMetadata) GetTxnType() TxnType {
	return TxnTypeCreateNFT
}

func (txnData *CreateNFTMetadata) ToBytes(preSignature bool) ([]byte, error) {
	// Validate the metadata before encoding it.
	//
	// Post hash must be included and must have the expected length.
	if len(txnData.NFTPostHash) != HashSizeBytes {
		return nil, fmt.Errorf("CreateNFTMetadata.ToBytes: NFTPostHash "+
			"has length %d != %d", len(txnData.NFTPostHash), HashSizeBytes)
	}

	data := []byte{}

	// NFTPostHash
	data = append(data, txnData.NFTPostHash[:]...)

	// NumCopies uint64
	data = append(data, UintToBuf(txnData.NumCopies)...)

	// HasUnlockable
	data = append(data, BoolToByte(txnData.HasUnlockable))

	// IsForSale
	data = append(data, BoolToByte(txnData.IsForSale))

	// MinBidAmountNanos uint64
	data = append(data, UintToBuf(txnData.MinBidAmountNanos)...)

	// NFTRoyaltyToCreatorBasisPoints uint64
	data = append(data, UintToBuf(txnData.NFTRoyaltyToCreatorBasisPoints)...)

	// NFTRoyaltyToCoinBasisPoints uint64
	data = append(data, UintToBuf(txnData.NFTRoyaltyToCoinBasisPoints)...)

	return data, nil
}

func (txnData *CreateNFTMetadata) FromBytes(dataa []byte) error {
	ret := CreateNFTMetadata{}
	rr := bytes.NewReader(dataa)

	// NFTPostHash
	ret.NFTPostHash = &BlockHash{}
	_, err := io.ReadFull(rr, ret.NFTPostHash[:])
	if err != nil {
		return fmt.Errorf(
			"CreateNFTMetadata.FromBytes: Error reading NFTPostHash: %v", err)
	}

	// NumCopies uint64
	ret.NumCopies, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreateNFTMetadata.FromBytes: Error reading NumCopies: %v", err)
	}

	// HasUnlockable
	ret.HasUnlockable = ReadBoolByte(rr)

	// IsForSale
	ret.IsForSale = ReadBoolByte(rr)

	// MinBidAmountNanos uint64
	ret.MinBidAmountNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreateNFTMetadata.FromBytes: Error reading MinBidAmountNanos: %v", err)
	}

	// NFTRoyaltyToCreatorBasisPoints uint64
	ret.NFTRoyaltyToCreatorBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreateNFTMetadata.FromBytes: Error reading NFTRoyaltyToCreatorBasisPoints: %v", err)
	}

	// NFTRoyaltyToCoinBasisPoints uint64
	ret.NFTRoyaltyToCoinBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreateNFTMetadata.FromBytes: Error reading NFTRoyaltyToCoinBasisPoints: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *CreateNFTMetadata) New() BitCloutTxnMetadata {
	return &CreateNFTMetadata{}
}

// ==================================================================
// UpdateNFTMetadata
// ==================================================================

type UpdateNFTMetadata struct {
	NFTPostHash       *BlockHash
	SerialNumber      uint64
	IsForSale         bool
	MinBidAmountNanos uint64
}

func (txnData *UpdateNFTMetadata) GetTxnType() TxnType {
	return TxnTypeUpdateNFT
}

func (txnData *UpdateNFTMetadata) ToBytes(preSignature bool) ([]byte, error) {
	// Validate the metadata before encoding it.
	//
	// Post hash must be included and must have the expected length.
	if len(txnData.NFTPostHash) != HashSizeBytes {
		return nil, fmt.Errorf("UpdateNFTMetadata.ToBytes: NFTPostHash "+
			"has length %d != %d", len(txnData.NFTPostHash), HashSizeBytes)
	}

	data := []byte{}

	// NFTPostHash
	data = append(data, txnData.NFTPostHash[:]...)

	// SerialNumber uint64
	data = append(data, UintToBuf(txnData.SerialNumber)...)

	// IsForSale
	data = append(data, BoolToByte(txnData.IsForSale))

	// MinBidAmountNanos uint64
	data = append(data, UintToBuf(txnData.MinBidAmountNanos)...)

	return data, nil
}

func (txnData *UpdateNFTMetadata) FromBytes(dataa []byte) error {
	ret := UpdateNFTMetadata{}
	rr := bytes.NewReader(dataa)

	// NFTPostHash
	ret.NFTPostHash = &BlockHash{}
	_, err := io.ReadFull(rr, ret.NFTPostHash[:])
	if err != nil {
		return fmt.Errorf(
			"UpdateNFTMetadata.FromBytes: Error reading NFTPostHash: %v", err)
	}

	// SerialNumber uint64
	ret.SerialNumber, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("UpdateNFTMetadata.FromBytes: Error reading SerialNumber: %v", err)
	}

	// IsForSale
	ret.IsForSale = ReadBoolByte(rr)

	// SerialNumber uint64
	ret.MinBidAmountNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("UpdateNFTMetadata.FromBytes: Error reading MinBidAmountNanos: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *UpdateNFTMetadata) New() BitCloutTxnMetadata {
	return &UpdateNFTMetadata{}
}

// ==================================================================
// AcceptNFTBidMetadata
// ==================================================================

type AcceptNFTBidMetadata struct {
	NFTPostHash    *BlockHash
	SerialNumber   uint64
	BidderPKID     *PKID
	BidAmountNanos uint64
	UnlockableText []byte

	// When an NFT owner accepts a bid, they must specify the bidder's UTXO inputs they will lock up
	// as payment for the purchase. This prevents the transaction from accidentally using UTXOs
	// that are used by future transactions.
	BidderInputs []*BitCloutInput
}

func (txnData *AcceptNFTBidMetadata) GetTxnType() TxnType {
	return TxnTypeAcceptNFTBid
}

func (txnData *AcceptNFTBidMetadata) ToBytes(preSignature bool) ([]byte, error) {
	// Validate the metadata before encoding it.
	//
	// Post hash and pub key must be included and must have the expected length.
	if len(txnData.NFTPostHash) != HashSizeBytes {
		return nil, fmt.Errorf("AcceptNFTBidMetadata.ToBytes: NFTPostHash "+
			"has length %d != %d", len(txnData.NFTPostHash), HashSizeBytes)
	}
	if len(txnData.BidderPKID) != btcec.PubKeyBytesLenCompressed {
		return nil, fmt.Errorf("AcceptNFTBidMetadata.ToBytes: BidderPublicKey "+
			"has length %d != %d", len(txnData.BidderPKID), btcec.PubKeyBytesLenCompressed)
	}

	data := []byte{}

	// NFTPostHash
	data = append(data, txnData.NFTPostHash[:]...)

	// SerialNumber uint64
	data = append(data, UintToBuf(txnData.SerialNumber)...)

	// BidderPKID
	data = append(data, UintToBuf(uint64(len(txnData.BidderPKID)))...)
	data = append(data, txnData.BidderPKID[:]...)

	// BidAmountNanos uint64
	data = append(data, UintToBuf(txnData.BidAmountNanos)...)

	// UnlockableText
	data = append(data, UintToBuf(uint64(len(txnData.UnlockableText)))...)
	data = append(data, txnData.UnlockableText...)

	// Serialize the bidder inputs
	data = append(data, UintToBuf(uint64(len(txnData.BidderInputs)))...)
	for _, bitcloutInput := range txnData.BidderInputs {
		data = append(data, bitcloutInput.TxID[:]...)
		data = append(data, UintToBuf(uint64(bitcloutInput.Index))...)
	}

	return data, nil
}

func (txnData *AcceptNFTBidMetadata) FromBytes(dataa []byte) error {
	ret := AcceptNFTBidMetadata{}
	rr := bytes.NewReader(dataa)

	// NFTPostHash
	ret.NFTPostHash = &BlockHash{}
	_, err := io.ReadFull(rr, ret.NFTPostHash[:])
	if err != nil {
		return fmt.Errorf(
			"AcceptNFTBidMetadata.FromBytes: Error reading NFTPostHash: %v", err)
	}

	// SerialNumber uint64
	ret.SerialNumber, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("AcceptNFTBidMetadata.FromBytes: Error reading SerialNumber: %v", err)
	}

	// BidderPKID
	bidderPKIDBytes, err := ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"AcceptNFTBidMetadata.FromBytes: Error reading BidderPublicKey: %v", err)
	}
	ret.BidderPKID = PublicKeyToPKID(bidderPKIDBytes)

	// BidAmountNanos uint64
	ret.BidAmountNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("AcceptNFTBidMetadata.FromBytes: Error reading BidAmountNanos: %v", err)
	}

	// UnlockableText
	unlockableTextLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AcceptNFTBidMetadata.FromBytes: Problem "+
			"decoding UnlockableText length")
	}
	if unlockableTextLen > MaxMessagePayload {
		return fmt.Errorf("AcceptNFTBidMetadata.FromBytes: unlockableTextLen %d "+
			"exceeds max %d", unlockableTextLen, MaxMessagePayload)
	}
	ret.UnlockableText = make([]byte, unlockableTextLen)
	_, err = io.ReadFull(rr, ret.UnlockableText)
	if err != nil {
		return fmt.Errorf("PrivateMessageMetadata.FromBytes: Error reading EncryptedText: %v", err)
	}

	// De-serialize the inputs
	numInputs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AcceptNFTBidMetadata.FromBytes: Problem getting length of inputs")
	}
	for ii := uint64(0); ii < numInputs; ii++ {
		currentInput := NewBitCloutInput()
		_, err = io.ReadFull(rr, currentInput.TxID[:])
		if err != nil {
			return errors.Wrapf(err, "AcceptNFTBidMetadata.FromBytes: Problem converting input txid")
		}
		inputIndex, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "AcceptNFTBidMetadata.FromBytes: Problem converting input index")
		}
		if inputIndex > uint64(^uint32(0)) {
			return fmt.Errorf("AcceptNFTBidMetadata.FromBytes: Input index (%d) must not exceed (%d)", inputIndex, ^uint32(0))
		}
		currentInput.Index = uint32(inputIndex)

		ret.BidderInputs = append(ret.BidderInputs, currentInput)
	}

	*txnData = ret
	return nil
}

func (txnData *AcceptNFTBidMetadata) New() BitCloutTxnMetadata {
	return &AcceptNFTBidMetadata{}
}

// ==================================================================
// NFTBidMetadata
// ==================================================================

type NFTBidMetadata struct {
	NFTPostHash    *BlockHash
	SerialNumber   uint64
	BidAmountNanos uint64
}

func (txnData *NFTBidMetadata) GetTxnType() TxnType {
	return TxnTypeNFTBid
}

func (txnData *NFTBidMetadata) ToBytes(preSignature bool) ([]byte, error) {
	// Validate the metadata before encoding it.
	//
	// Post hash must be included and must have the expected length.
	if len(txnData.NFTPostHash) != HashSizeBytes {
		return nil, fmt.Errorf("NFTBidMetadata.ToBytes: NFTPostHash "+
			"has length %d != %d", len(txnData.NFTPostHash), HashSizeBytes)
	}

	data := []byte{}

	// NFTPostHash
	data = append(data, txnData.NFTPostHash[:]...)

	// SerialNumber uint64
	data = append(data, UintToBuf(txnData.SerialNumber)...)

	// BidAmountNanos uint64
	data = append(data, UintToBuf(txnData.BidAmountNanos)...)

	return data, nil
}

func (txnData *NFTBidMetadata) FromBytes(dataa []byte) error {
	ret := NFTBidMetadata{}
	rr := bytes.NewReader(dataa)

	// NFTPostHash
	ret.NFTPostHash = &BlockHash{}
	_, err := io.ReadFull(rr, ret.NFTPostHash[:])
	if err != nil {
		return fmt.Errorf(
			"NFTBidMetadata.FromBytes: Error reading NFTPostHash: %v", err)
	}

	// SerialNumber uint64
	ret.SerialNumber, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("NFTBidMetadata.FromBytes: Error reading SerialNumber: %v", err)
	}

	// BidAmountNanos uint64
	ret.BidAmountNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("NFTBidMetadata.FromBytes: Error reading BidAmountNanos: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *NFTBidMetadata) New() BitCloutTxnMetadata {
	return &NFTBidMetadata{}
}

// ==================================================================
// SwapIdentityMetadataa
// ==================================================================

type SwapIdentityOperationType uint8

type SwapIdentityMetadataa struct {
	// TODO: This is currently only accessible by ParamUpdater. This avoids the
	// possibility that a user will stomp over another user's profile, and
	// simplifies the logic. In the long run, though, we should eliminate all
	// dependencies on ParamUpdater.

	// The public key that we are swapping *from*. Doesn't matter which public
	// key is *from* and which public key is *to* because it's just a swap.
	FromPublicKey []byte

	// The public key that we are swapping *to*. Doesn't matter which public
	// key is *from* and which public key is *to* because it's just a swap.
	ToPublicKey []byte
}

func (txnData *SwapIdentityMetadataa) GetTxnType() TxnType {
	return TxnTypeSwapIdentity
}

func (txnData *SwapIdentityMetadataa) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// FromPublicKey
	data = append(data, UintToBuf(uint64(len(txnData.FromPublicKey)))...)
	data = append(data, txnData.FromPublicKey...)

	// ToPublicKey
	data = append(data, UintToBuf(uint64(len(txnData.ToPublicKey)))...)
	data = append(data, txnData.ToPublicKey...)

	return data, nil
}

func (txnData *SwapIdentityMetadataa) FromBytes(dataa []byte) error {
	ret := SwapIdentityMetadataa{}
	rr := bytes.NewReader(dataa)

	// FromPublicKey
	var err error
	ret.FromPublicKey, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"SwapIdentityMetadataa.FromBytes: Error reading FromPublicKey: %v", err)
	}

	// ToPublicKey
	ret.ToPublicKey, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"SwapIdentityMetadataa.FromBytes: Error reading ToPublicKey: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *SwapIdentityMetadataa) New() BitCloutTxnMetadata {
	return &SwapIdentityMetadataa{}
}

// ==================================================================
// AuthorizeDerivedKeyMetadata
// ==================================================================

type AuthorizeDerivedKeyOperationType uint8

const (
	AuthorizeDerivedKeyOperationNotValid AuthorizeDerivedKeyOperationType = 0
	AuthorizeDerivedKeyOperationValid    AuthorizeDerivedKeyOperationType = 1
)

type AuthorizeDerivedKeyMetadata struct {
	// DerivedPublicKey is the key that is authorized to sign transactions
	// on behalf of the public key owner
	DerivedPublicKey []byte

	// ExpirationBlock is the block at which this authorization becomes invalid
	ExpirationBlock uint64

	// OperationType determines if transaction validates or invalidates derived key
	OperationType AuthorizeDerivedKeyOperationType

	// AccessSignature is the signed hash of (derivedPublicKey + expirationBlock)
	// made with the ownerPublicKey. Signature is in the DER format.
	AccessSignature []byte
}

func (txnData *AuthorizeDerivedKeyMetadata) GetTxnType() TxnType {
	return TxnTypeAuthorizeDerivedKey
}

func (txnData *AuthorizeDerivedKeyMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// DerivedPublicKey
	data = append(data, UintToBuf(uint64(len(txnData.DerivedPublicKey)))...)
	data = append(data, txnData.DerivedPublicKey...)

	// ExpirationBlock uint64
	data = append(data, UintToBuf(uint64(txnData.ExpirationBlock))...)

	// OperationType byte
	data = append(data, byte(txnData.OperationType))

	// AccessSignature
	data = append(data, UintToBuf(uint64(len(txnData.AccessSignature)))...)
	data = append(data, txnData.AccessSignature...)

	return data, nil
}

func (txnData *AuthorizeDerivedKeyMetadata) FromBytes(data []byte) error {
	ret := AuthorizeDerivedKeyMetadata{}
	rr := bytes.NewReader(data)

	// DerivedPublicKey
	var err error
	ret.DerivedPublicKey, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"AuthorizeDerivedKeyMetadata.FromBytes: Error reading DerivedPublicKey: %v", err)
	}

	// ExpirationBlock uint64
	ret.ExpirationBlock, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf(
			"AuthorizeDerivedKeyMetadata.FromBytes: Error reading ExpirationBlock: %v", err)
	}

	// OperationType byte
	operationType, err := rr.ReadByte()
	if err != nil {
		return fmt.Errorf(
			"AuthorizeDerivedKeyMetadata.FromBytes: Error reading OperationType: %v", err)
	}
	ret.OperationType = AuthorizeDerivedKeyOperationType(operationType)

	// AccessSignature
	ret.AccessSignature, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"AuthorizeDerivedKeyMetadata.FromBytes: Error reading AccessSignature: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *AuthorizeDerivedKeyMetadata) New() BitCloutTxnMetadata {
	return &AuthorizeDerivedKeyMetadata{}
}