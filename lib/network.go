package lib

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/holiman/uint256"
	"io"
	"math"
	"net"
	"sort"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	merkletree "github.com/deso-protocol/go-merkle-tree"
	"github.com/ethereum/go-ethereum/crypto/ecies"

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

// DeSoMessage is the interface that a message we send on the wire must implement.
type DeSoMessage interface {
	// The following methods allow one to convert a message struct into
	// a byte slice and back. Example usage:
	//
	//   params := &DeSoTestnetParams
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
	TxnTypeNFTTransfer                  TxnType = 19
	TxnTypeAcceptNFTTransfer            TxnType = 20
	TxnTypeBurnNFT                      TxnType = 21
	TxnTypeAuthorizeDerivedKey          TxnType = 22
	TxnTypeMessagingGroup               TxnType = 23
	TxnTypeDAOCoin                      TxnType = 24
	TxnTypeDAOCoinTransfer              TxnType = 25

	// NEXT_ID = 26
)

type TxnString string

const (
	TxnStringUnset                        TxnString = "UNSET"
	TxnStringBlockReward                  TxnString = "BLOCK_REWARD"
	TxnStringBasicTransfer                TxnString = "BASIC_TRANSFER"
	TxnStringBitcoinExchange              TxnString = "BITCOIN_EXCHANGE"
	TxnStringPrivateMessage               TxnString = "PRIVATE_MESSAGE"
	TxnStringSubmitPost                   TxnString = "SUBMIT_POST"
	TxnStringUpdateProfile                TxnString = "UPDATE_PROFILE"
	TxnStringUpdateBitcoinUSDExchangeRate TxnString = "UPDATE_BITCOIN_USD_EXCHANGE_RATE"
	TxnStringFollow                       TxnString = "FOLLOW"
	TxnStringLike                         TxnString = "LIKE"
	TxnStringCreatorCoin                  TxnString = "CREATOR_COIN"
	TxnStringSwapIdentity                 TxnString = "SWAP_IDENTITY"
	TxnStringUpdateGlobalParams           TxnString = "UPDATE_GLOBAL_PARAMS"
	TxnStringCreatorCoinTransfer          TxnString = "CREATOR_COIN_TRANSFER"
	TxnStringCreateNFT                    TxnString = "CREATE_NFT"
	TxnStringUpdateNFT                    TxnString = "UPDATE_NFT"
	TxnStringAcceptNFTBid                 TxnString = "ACCEPT_NFT_BID"
	TxnStringNFTBid                       TxnString = "NFT_BID"
	TxnStringNFTTransfer                  TxnString = "NFT_TRANSFER"
	TxnStringAcceptNFTTransfer            TxnString = "ACCEPT_NFT_TRANSFER"
	TxnStringBurnNFT                      TxnString = "BURN_NFT"
	TxnStringAuthorizeDerivedKey          TxnString = "AUTHORIZE_DERIVED_KEY"
	TxnStringMessagingGroup               TxnString = "MESSAGING_GROUP"
	TxnStringDAOCoin                      TxnString = "DAO_COIN"
	TxnStringDAOCoinTransfer              TxnString = "DAO_COIN_TRANSFER"
	TxnStringUndefined                    TxnString = "TXN_UNDEFINED"
)

var (
	AllTxnTypes = []TxnType{
		TxnTypeUnset, TxnTypeBlockReward, TxnTypeBasicTransfer, TxnTypeBitcoinExchange, TxnTypePrivateMessage,
		TxnTypeSubmitPost, TxnTypeUpdateProfile, TxnTypeUpdateBitcoinUSDExchangeRate, TxnTypeFollow, TxnTypeLike,
		TxnTypeCreatorCoin, TxnTypeSwapIdentity, TxnTypeUpdateGlobalParams, TxnTypeCreatorCoinTransfer,
		TxnTypeCreateNFT, TxnTypeUpdateNFT, TxnTypeAcceptNFTBid, TxnTypeNFTBid, TxnTypeNFTTransfer,
		TxnTypeAcceptNFTTransfer, TxnTypeBurnNFT, TxnTypeAuthorizeDerivedKey, TxnTypeMessagingGroup,
		TxnTypeDAOCoin, TxnTypeDAOCoinTransfer,
	}
	AllTxnString = []TxnString{
		TxnStringUnset, TxnStringBlockReward, TxnStringBasicTransfer, TxnStringBitcoinExchange, TxnStringPrivateMessage,
		TxnStringSubmitPost, TxnStringUpdateProfile, TxnStringUpdateBitcoinUSDExchangeRate, TxnStringFollow, TxnStringLike,
		TxnStringCreatorCoin, TxnStringSwapIdentity, TxnStringUpdateGlobalParams, TxnStringCreatorCoinTransfer,
		TxnStringCreateNFT, TxnStringUpdateNFT, TxnStringAcceptNFTBid, TxnStringNFTBid, TxnStringNFTTransfer,
		TxnStringAcceptNFTTransfer, TxnStringBurnNFT, TxnStringAuthorizeDerivedKey, TxnStringMessagingGroup,
		TxnStringDAOCoin, TxnStringDAOCoinTransfer,
	}
)

func (txnType TxnType) String() string {
	txnString := txnType.GetTxnString()
	if txnString == TxnStringUndefined {
		return fmt.Sprintf("UNRECOGNIZED(%d) - make sure GetTxnString() is up to date", txnType)
	}
	return string(txnString)
}

func (txnType TxnType) GetTxnString() TxnString {
	switch txnType {
	case TxnTypeUnset:
		return TxnStringUnset
	case TxnTypeBlockReward:
		return TxnStringBlockReward
	case TxnTypeBasicTransfer:
		return TxnStringBasicTransfer
	case TxnTypeBitcoinExchange:
		return TxnStringBitcoinExchange
	case TxnTypePrivateMessage:
		return TxnStringPrivateMessage
	case TxnTypeSubmitPost:
		return TxnStringSubmitPost
	case TxnTypeUpdateProfile:
		return TxnStringUpdateProfile
	case TxnTypeUpdateBitcoinUSDExchangeRate:
		return TxnStringUpdateBitcoinUSDExchangeRate
	case TxnTypeFollow:
		return TxnStringFollow
	case TxnTypeLike:
		return TxnStringLike
	case TxnTypeCreatorCoin:
		return TxnStringCreatorCoin
	case TxnTypeCreatorCoinTransfer:
		return TxnStringCreatorCoinTransfer
	case TxnTypeSwapIdentity:
		return TxnStringSwapIdentity
	case TxnTypeUpdateGlobalParams:
		return TxnStringUpdateGlobalParams
	case TxnTypeCreateNFT:
		return TxnStringCreateNFT
	case TxnTypeUpdateNFT:
		return TxnStringUpdateNFT
	case TxnTypeAcceptNFTBid:
		return TxnStringAcceptNFTBid
	case TxnTypeNFTBid:
		return TxnStringNFTBid
	case TxnTypeNFTTransfer:
		return TxnStringNFTTransfer
	case TxnTypeAcceptNFTTransfer:
		return TxnStringAcceptNFTTransfer
	case TxnTypeBurnNFT:
		return TxnStringBurnNFT
	case TxnTypeAuthorizeDerivedKey:
		return TxnStringAuthorizeDerivedKey
	case TxnTypeMessagingGroup:
		return TxnStringMessagingGroup
	case TxnTypeDAOCoin:
		return TxnStringDAOCoin
	case TxnTypeDAOCoinTransfer:
		return TxnStringDAOCoinTransfer
	default:
		return TxnStringUndefined
	}
}

func GetTxnTypeFromString(txnString TxnString) TxnType {
	switch txnString {
	case TxnStringUnset:
		return TxnTypeUnset
	case TxnStringBlockReward:
		return TxnTypeBlockReward
	case TxnStringBasicTransfer:
		return TxnTypeBasicTransfer
	case TxnStringBitcoinExchange:
		return TxnTypeBitcoinExchange
	case TxnStringPrivateMessage:
		return TxnTypePrivateMessage
	case TxnStringSubmitPost:
		return TxnTypeSubmitPost
	case TxnStringUpdateProfile:
		return TxnTypeUpdateProfile
	case TxnStringUpdateBitcoinUSDExchangeRate:
		return TxnTypeUpdateBitcoinUSDExchangeRate
	case TxnStringFollow:
		return TxnTypeFollow
	case TxnStringLike:
		return TxnTypeLike
	case TxnStringCreatorCoin:
		return TxnTypeCreatorCoin
	case TxnStringCreatorCoinTransfer:
		return TxnTypeCreatorCoinTransfer
	case TxnStringSwapIdentity:
		return TxnTypeSwapIdentity
	case TxnStringUpdateGlobalParams:
		return TxnTypeUpdateGlobalParams
	case TxnStringCreateNFT:
		return TxnTypeCreateNFT
	case TxnStringUpdateNFT:
		return TxnTypeUpdateNFT
	case TxnStringAcceptNFTBid:
		return TxnTypeAcceptNFTBid
	case TxnStringNFTBid:
		return TxnTypeNFTBid
	case TxnStringNFTTransfer:
		return TxnTypeNFTTransfer
	case TxnStringAcceptNFTTransfer:
		return TxnTypeNFTTransfer
	case TxnStringBurnNFT:
		return TxnTypeBurnNFT
	case TxnStringAuthorizeDerivedKey:
		return TxnTypeAuthorizeDerivedKey
	case TxnStringMessagingGroup:
		return TxnTypeMessagingGroup
	case TxnStringDAOCoin:
		return TxnTypeDAOCoin
	case TxnStringDAOCoinTransfer:
		return TxnTypeDAOCoinTransfer
	default:
		// TxnTypeUnset means we couldn't find a matching txn type
		return TxnTypeUnset
	}
}

type DeSoTxnMetadata interface {
	ToBytes(preSignature bool) ([]byte, error)
	FromBytes(data []byte) error
	New() DeSoTxnMetadata
	GetTxnType() TxnType
}

func NewTxnMetadata(txType TxnType) (DeSoTxnMetadata, error) {
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
	case TxnTypeNFTTransfer:
		return (&NFTTransferMetadata{}).New(), nil
	case TxnTypeAcceptNFTTransfer:
		return (&AcceptNFTTransferMetadata{}).New(), nil
	case TxnTypeBurnNFT:
		return (&BurnNFTMetadata{}).New(), nil
	case TxnTypeAuthorizeDerivedKey:
		return (&AuthorizeDerivedKeyMetadata{}).New(), nil
	case TxnTypeMessagingGroup:
		return (&MessagingGroupMetadata{}).New(), nil
	case TxnTypeDAOCoin:
		return (&DAOCoinMetadata{}).New(), nil
	case TxnTypeDAOCoinTransfer:
		return (&DAOCoinTransferMetadata{}).New(), nil
	default:
		return nil, fmt.Errorf("NewTxnMetadata: Unrecognized TxnType: %v; make sure you add the new type of transaction to NewTxnMetadata", txType)
	}
}

// WriteMessage takes an io.Writer and serializes and writes the specified message
// to it. Returns an error if the message is malformed or invalid for any reason.
// Otherwise returns the payload that was written sans the header.
func WriteMessage(ww io.Writer, msg DeSoMessage, networkType NetworkType) ([]byte, error) {
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
func ReadMessage(rr io.Reader, networkType NetworkType) (DeSoMessage, []byte, error) {
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

func NewMessage(msgType MsgType) DeSoMessage {
	switch msgType {
	case MsgTypeVersion:
		{
			return &MsgDeSoVersion{}
		}
	case MsgTypeVerack:
		{
			return &MsgDeSoVerack{}
		}
	case MsgTypeHeader:
		{
			return &MsgDeSoHeader{
				PrevBlockHash:         &BlockHash{},
				TransactionMerkleRoot: &BlockHash{},
			}
		}
	case MsgTypeBlock:
		{
			return &MsgDeSoBlock{
				Header: NewMessage(MsgTypeHeader).(*MsgDeSoHeader),
			}
		}
	case MsgTypeTxn:
		{
			return &MsgDeSoTxn{}
		}
	case MsgTypePing:
		{
			return &MsgDeSoPing{}
		}
	case MsgTypePong:
		{
			return &MsgDeSoPong{}
		}
	case MsgTypeInv:
		{
			return &MsgDeSoInv{}
		}
	case MsgTypeGetBlocks:
		{
			return &MsgDeSoGetBlocks{}
		}
	case MsgTypeGetTransactions:
		{
			return &MsgDeSoGetTransactions{}
		}
	case MsgTypeTransactionBundle:
		{
			return &MsgDeSoTransactionBundle{}
		}
	case MsgTypeMempool:
		{
			return &MsgDeSoMempool{}
		}
	case MsgTypeGetHeaders:
		{
			return &MsgDeSoGetHeaders{}
		}
	case MsgTypeHeaderBundle:
		{
			return &MsgDeSoHeaderBundle{}
		}
	case MsgTypeAddr:
		{
			return &MsgDeSoAddr{}
		}
	case MsgTypeGetAddr:
		{
			return &MsgDeSoGetAddr{}
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

type MsgDeSoQuit struct {
}

func (msg *MsgDeSoQuit) GetMsgType() MsgType {
	return MsgTypeQuit
}

func (msg *MsgDeSoQuit) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgDeSoQuit.ToBytes not implemented")
}

func (msg *MsgDeSoQuit) FromBytes(data []byte) error {
	return fmt.Errorf("MsgDeSoQuit.FromBytes not implemented")
}

type MsgDeSoNewPeer struct {
}

func (msg *MsgDeSoNewPeer) GetMsgType() MsgType {
	return MsgTypeNewPeer
}

func (msg *MsgDeSoNewPeer) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgDeSoNewPeer.ToBytes: Not implemented")
}

func (msg *MsgDeSoNewPeer) FromBytes(data []byte) error {
	return fmt.Errorf("MsgDeSoNewPeer.FromBytes not implemented")
}

type MsgDeSoDonePeer struct {
}

func (msg *MsgDeSoDonePeer) GetMsgType() MsgType {
	return MsgTypeDonePeer
}

func (msg *MsgDeSoDonePeer) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgDeSoDonePeer.ToBytes: Not implemented")
}

func (msg *MsgDeSoDonePeer) FromBytes(data []byte) error {
	return fmt.Errorf("MsgDeSoDonePeer.FromBytes not implemented")
}

type MsgDeSoBitcoinManagerUpdate struct {
	// Keep it simple for now. A BitcoinManagerUpdate just signals that
	// the BitcoinManager has added at least one block or done a reorg.
	// No serialization because we don't want this sent on the wire ever.
	TransactionsFound []*MsgDeSoTxn
}

func (msg *MsgDeSoBitcoinManagerUpdate) GetMsgType() MsgType {
	return MsgTypeBitcoinManagerUpdate
}

func (msg *MsgDeSoBitcoinManagerUpdate) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgDeSoBitcoinManagerUpdate.ToBytes: Not implemented")
}

func (msg *MsgDeSoBitcoinManagerUpdate) FromBytes(data []byte) error {
	return fmt.Errorf("MsgDeSoBitcoinManagerUpdate.FromBytes not implemented")
}

// ==================================================================
// GET_HEADERS message
// ==================================================================

type MsgDeSoGetHeaders struct {
	StopHash     *BlockHash
	BlockLocator []*BlockHash
}

func (msg *MsgDeSoGetHeaders) GetMsgType() MsgType {
	return MsgTypeGetHeaders
}

func (msg *MsgDeSoGetHeaders) ToBytes(preSignature bool) ([]byte, error) {
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

func (msg *MsgDeSoGetHeaders) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retGetHeaders := NewMessage(MsgTypeGetHeaders).(*MsgDeSoGetHeaders)

	// StopHash
	stopHash := BlockHash{}
	_, err := io.ReadFull(rr, stopHash[:])
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoGetHeaders.FromBytes: Problem decoding StopHash")
	}
	retGetHeaders.StopHash = &stopHash

	// Number of hashes in block locator.
	numHeaders, err := ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("MsgDeSoGetHeaders.FromBytes: %v", err)
	}

	for ii := uint64(0); ii < numHeaders; ii++ {
		currentHeader := BlockHash{}
		_, err := io.ReadFull(rr, currentHeader[:])
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoGetHeaders.FromBytes: Problem decoding header hash")
		}

		retGetHeaders.BlockLocator = append(retGetHeaders.BlockLocator, &currentHeader)
	}

	*msg = *retGetHeaders
	return nil
}

func (msg *MsgDeSoGetHeaders) String() string {
	return fmt.Sprintf("StopHash: %v Locator: %v",
		msg.StopHash, msg.BlockLocator)
}

// ==================================================================
// HEADER_BUNDLE message
// ==================================================================

type MsgDeSoHeaderBundle struct {
	Headers   []*MsgDeSoHeader
	TipHash   *BlockHash
	TipHeight uint32
}

func (msg *MsgDeSoHeaderBundle) GetMsgType() MsgType {
	return MsgTypeHeaderBundle
}

func (msg *MsgDeSoHeaderBundle) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Encode the number of headers in the bundle.
	data = append(data, UintToBuf(uint64(len(msg.Headers)))...)

	// Encode all the headers.
	for _, header := range msg.Headers {
		headerBytes, err := header.ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "MsgDeSoHeaderBundle.ToBytes: Problem encoding header")
		}
		data = append(data, headerBytes...)
	}

	// Encode the tip hash.
	data = append(data, msg.TipHash[:]...)

	// Encode the tip height.
	data = append(data, UintToBuf(uint64(msg.TipHeight))...)

	return data, nil
}

func (msg *MsgDeSoHeaderBundle) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retBundle := NewMessage(MsgTypeHeaderBundle).(*MsgDeSoHeaderBundle)

	// Read in the number of headers in the bundle.
	numHeaders, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoHeaderBundle.FromBytes: Problem decoding number of header")
	}

	// Read in all of the headers.
	for ii := uint64(0); ii < numHeaders; ii++ {
		retHeader, err := DecodeHeader(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoHeader.FromBytes: ")
		}

		retBundle.Headers = append(retBundle.Headers, retHeader)
	}

	// Read in the tip hash.
	retBundle.TipHash = &BlockHash{}
	_, err = io.ReadFull(rr, retBundle.TipHash[:])
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoHeaderBundle.FromBytes:: Error reading TipHash: ")
	}

	// Read in the tip height.
	tipHeight, err := ReadUvarint(rr)
	if err != nil || tipHeight > math.MaxUint32 {
		return fmt.Errorf("MsgDeSoHeaderBundle.FromBytes: %v", err)
	}
	retBundle.TipHeight = uint32(tipHeight)

	*msg = *retBundle
	return nil
}

func (msg *MsgDeSoHeaderBundle) String() string {
	return fmt.Sprintf("Num Headers: %v, Tip Height: %v, Tip Hash: %v, Headers: %v", len(msg.Headers), msg.TipHeight, msg.TipHash, msg.Headers)
}

// ==================================================================
// GetBlocks Messages
// ==================================================================

type MsgDeSoGetBlocks struct {
	HashList []*BlockHash
}

func (msg *MsgDeSoGetBlocks) GetMsgType() MsgType {
	return MsgTypeGetBlocks
}

func (msg *MsgDeSoGetBlocks) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	if len(msg.HashList) > MaxBlocksInFlight {
		return nil, fmt.Errorf("MsgDeSoGetBlocks.ToBytes: Blocks requested %d "+
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

func (msg *MsgDeSoGetBlocks) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// Parse the nmber of block hashes.
	numHashes, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoGetBlocks.FromBytes: Problem "+
			"reading number of block hashes requested")
	}
	if numHashes > MaxBlocksInFlight {
		return fmt.Errorf("MsgDeSoGetBlocks.FromBytes: HashList length (%d) "+
			"exceeds maximum allowed (%d)", numHashes, MaxBlocksInFlight)
	}

	// Read in all the hashes.
	hashList := []*BlockHash{}
	for ii := uint64(0); ii < numHashes; ii++ {
		newHash := BlockHash{}

		_, err = io.ReadFull(rr, newHash[:])
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoGetBlocks.FromBytes:: Error reading Hash: ")
		}
		hashList = append(hashList, &newHash)
	}

	*msg = MsgDeSoGetBlocks{
		HashList: hashList,
	}
	return nil
}

func (msg *MsgDeSoGetBlocks) String() string {
	return fmt.Sprintf("%v", msg.HashList)
}

// DeSoBodySchema Within a post, the body typically has a particular
// schema defined below.
type DeSoBodySchema struct {
	Body      string   `json:",omitempty"`
	ImageURLs []string `json:",omitempty"`
	VideoURLs []string `json:",omitempty"`
}

// ==================================================================
// GetTransactions Messages
// ==================================================================

type MsgDeSoGetTransactions struct {
	HashList []*BlockHash
}

func (msg *MsgDeSoGetTransactions) GetMsgType() MsgType {
	return MsgTypeGetTransactions
}

func (msg *MsgDeSoGetTransactions) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Encode the number of hashes.
	data = append(data, UintToBuf(uint64(len(msg.HashList)))...)
	// Encode each hash.
	for _, hash := range msg.HashList {
		data = append(data, hash[:]...)
	}

	return data, nil
}

func (msg *MsgDeSoGetTransactions) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// Parse the nmber of block hashes.
	numHashes, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoGetTransactions.FromBytes: Problem "+
			"reading number of transaction hashes requested")
	}

	// Read in all the hashes.
	hashList := []*BlockHash{}
	for ii := uint64(0); ii < numHashes; ii++ {
		newHash := BlockHash{}

		_, err = io.ReadFull(rr, newHash[:])
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoGetTransactions.FromBytes: Error reading Hash: ")
		}
		hashList = append(hashList, &newHash)
	}

	*msg = MsgDeSoGetTransactions{
		HashList: hashList,
	}
	return nil
}

func (msg *MsgDeSoGetTransactions) String() string {
	return fmt.Sprintf("Num hashes: %v, HashList: %v", len(msg.HashList), msg.HashList)
}

// ==================================================================
// TransactionBundle message
// ==================================================================

type MsgDeSoTransactionBundle struct {
	Transactions []*MsgDeSoTxn
}

func (msg *MsgDeSoTransactionBundle) GetMsgType() MsgType {
	return MsgTypeTransactionBundle
}

func (msg *MsgDeSoTransactionBundle) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Encode the number of transactions in the bundle.
	data = append(data, UintToBuf(uint64(len(msg.Transactions)))...)

	// Encode all the transactions.
	for _, transaction := range msg.Transactions {
		transactionBytes, err := transaction.ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "MsgDeSoTransactionBundle.ToBytes: Problem encoding transaction")
		}
		data = append(data, transactionBytes...)
	}

	return data, nil
}

func (msg *MsgDeSoTransactionBundle) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retBundle := NewMessage(MsgTypeTransactionBundle).(*MsgDeSoTransactionBundle)

	// Read in the number of transactions in the bundle.
	numTransactions, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoTransactionBundle.FromBytes: Problem decoding number of transaction")
	}

	// Read in all of the transactions.
	for ii := uint64(0); ii < numTransactions; ii++ {
		retTransaction, err := _readTransaction(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoTransaction.FromBytes: ")
		}

		retBundle.Transactions = append(retBundle.Transactions, retTransaction)
	}

	*msg = *retBundle
	return nil
}

func (msg *MsgDeSoTransactionBundle) String() string {
	return fmt.Sprintf("Num txns: %v, Txns: %v", len(msg.Transactions), msg.Transactions)
}

// ==================================================================
// Mempool Messages
// ==================================================================

type MsgDeSoMempool struct {
}

func (msg *MsgDeSoMempool) GetMsgType() MsgType {
	return MsgTypeMempool
}

func (msg *MsgDeSoMempool) ToBytes(preSignature bool) ([]byte, error) {
	// A mempool message is just empty.
	return []byte{}, nil
}

func (msg *MsgDeSoMempool) FromBytes(data []byte) error {
	// A mempool message is just empty.
	return nil
}

func (msg *MsgDeSoMempool) String() string {
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

type MsgDeSoInv struct {
	InvList []*InvVect
	// IsSyncResponse indicates that the inv was sent in response to a sync message.
	// This indicates that the node shouldn't relay it to peers because they likely
	// already have it.
	IsSyncResponse bool
}

func (msg *MsgDeSoInv) GetMsgType() MsgType {
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

func (msg *MsgDeSoInv) ToBytes(preSignature bool) ([]byte, error) {
	data, err := _invListToBytes(msg.InvList)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoGetInv: ")
	}
	data = append(data, BoolToByte(msg.IsSyncResponse))

	return data, nil
}

func (msg *MsgDeSoInv) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	invList, err := _readInvList(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoInv: ")
	}
	isSyncResponse := ReadBoolByte(rr)

	*msg = MsgDeSoInv{
		InvList:        invList,
		IsSyncResponse: isSyncResponse,
	}
	return nil
}

func (msg *MsgDeSoInv) String() string {
	return fmt.Sprintf("Num invs: %v, SyncResponse: %v, InvList: %v",
		len(msg.InvList), msg.IsSyncResponse, msg.InvList)
}

// ==================================================================
// PING and PONG Messages
// ==================================================================

type MsgDeSoPing struct {
	Nonce uint64
}

func (msg *MsgDeSoPing) GetMsgType() MsgType {
	return MsgTypePing
}

func (msg *MsgDeSoPing) ToBytes(preSignature bool) ([]byte, error) {
	return UintToBuf(msg.Nonce), nil
}

func (msg *MsgDeSoPing) FromBytes(data []byte) error {
	nonce, err := ReadUvarint(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("MsgDeSoPing.FromBytes: %v", err)
	}
	*msg = MsgDeSoPing{Nonce: nonce}
	return nil
}

type MsgDeSoPong struct {
	Nonce uint64
}

func (msg *MsgDeSoPong) GetMsgType() MsgType {
	return MsgTypePong
}

func (msg *MsgDeSoPong) ToBytes(preSignature bool) ([]byte, error) {
	return UintToBuf(msg.Nonce), nil
}

func (msg *MsgDeSoPong) FromBytes(data []byte) error {
	nonce, err := ReadUvarint(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("MsgDeSoPong.FromBytes: %v", err)
	}
	*msg = MsgDeSoPong{Nonce: nonce}
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

type MsgDeSoVersion struct {
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

	// Used as a "vanity plate" to identify different DeSo
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

func (msg *MsgDeSoVersion) ToBytes(preSignature bool) ([]byte, error) {
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

func (msg *MsgDeSoVersion) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retVer := MsgDeSoVersion{}

	// Version
	//
	// We give each one of these its own scope to avoid issues where
	// a value accidentally gets recycled.
	{
		ver, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoVersion.FromBytes: Problem converting msg.Version")
		}
		retVer.Version = ver
	}

	// Services
	{
		services, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoVersion.FromBytes: Problem converting msg.Services")
		}
		retVer.Services = ServiceFlag(services)
	}

	// TstampSecs
	{
		tstampSecs, err := ReadVarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoVersion.FromBytes: Problem converting msg.TstampSecs")
		}
		retVer.TstampSecs = tstampSecs
	}

	// Nonce
	{
		nonce, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoVersion.FromBytes: Problem converting msg.Nonce")
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
			return errors.Wrapf(err, "MsgDeSoVersion.FromBytes: Problem reading length of msg.UserAgent")
		}
		if strLen > MaxMessagePayload {
			return fmt.Errorf("MsgDeSoVersion.FromBytes: Length msg.UserAgent %d larger than max allowed %d", strLen, MaxMessagePayload)
		}
		userAgent := make([]byte, strLen)
		_, err = io.ReadFull(rr, userAgent)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoVersion.FromBytes: Error reading msg.UserAgent")
		}
		retVer.UserAgent = string(userAgent)
	}

	// StartBlockHeight
	{
		lastBlockHeight, err := ReadUvarint(rr)
		if err != nil || lastBlockHeight > math.MaxUint32 {
			return errors.Wrapf(err, "MsgDeSoVersion.FromBytes: Problem converting msg.LatestBlockHeight")
		}
		retVer.StartBlockHeight = uint32(lastBlockHeight)
	}

	// MinFeeRateNanosPerKB
	{
		minFeeRateNanosPerKB, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoVersion.FromBytes: Problem converting msg.MinFeeRateNanosPerKB")
		}
		retVer.MinFeeRateNanosPerKB = minFeeRateNanosPerKB
	}

	// JSONAPIPort - deprecated
	{
		_, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoVersion.FromBytes: Problem converting msg.JSONAPIPort")
		}
	}

	*msg = retVer
	return nil
}

func (msg *MsgDeSoVersion) GetMsgType() MsgType {
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

type MsgDeSoAddr struct {
	// The definition of NetAddress as defined by the btcd guys works fine for
	// our purposes. The only difference is that for DeSo nodes, the Service
	// flag in the NetAddress is as we define it above in ServiceFlag.
	// Note that we also rewrite the serialization logic as well to avoid
	// relying on potentially crusty Bitcoin-related work-arounds going forward.
	AddrList []*SingleAddr
}

func (msg *MsgDeSoAddr) ToBytes(preSignature bool) ([]byte, error) {
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

func (msg *MsgDeSoAddr) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retVer := MsgDeSoAddr{}

	// Read the number of addresses encoded.
	numAddrs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoAddr.FromBytes: Problem reading numAddrs: ")
	}
	for ii := uint64(0); ii < numAddrs; ii++ {
		// Read each addr and add it to the AddrList.
		currentAddr := &SingleAddr{}

		// Timestamp
		tstampSecs, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoAddr.FromBytes: Problem reading tstamp: ")
		}
		currentAddr.Timestamp = time.Unix(int64(tstampSecs), 0)

		// Services
		serviceUint, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoAddr.FromBytes: Problem reading services: ")
		}
		currentAddr.Services = ServiceFlag(serviceUint)

		// IP
		ipLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoAddr.FromBytes: Problem reading IP: ")
		}
		if ipLen != 4 && ipLen != 16 {
			return fmt.Errorf("MsgDeSoAddr.FromBytes: IP length must be 4 or 16 bytes but was %d", ipLen)
		}
		currentAddr.IP = net.IP(make([]byte, ipLen))
		_, err = io.ReadFull(rr, currentAddr.IP)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoAddr.FromBytes: Error reading IP")
		}

		// Port
		port, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoAddr.FromBytes: Problem reading port: ")
		}
		if port > math.MaxUint16 {
			return fmt.Errorf("MsgDeSoAddr.FromBytes: Port value %d exceeds max "+
				"allowed %d", port, math.MaxUint16)
		}
		currentAddr.Port = uint16(port)

		retVer.AddrList = append(retVer.AddrList, currentAddr)
	}

	*msg = retVer
	return nil
}

func (msg *MsgDeSoAddr) GetMsgType() MsgType {
	return MsgTypeAddr
}

func (msg *MsgDeSoAddr) String() string {
	return fmt.Sprintf("Num addrs: %v, AddrList: %v", len(msg.AddrList), msg.AddrList)
}

// ==================================================================
// GET_ADDR Message
// ==================================================================

type MsgDeSoGetAddr struct {
}

func (msg *MsgDeSoGetAddr) ToBytes(preSignature bool) ([]byte, error) {
	return []byte{}, nil
}

func (msg *MsgDeSoGetAddr) FromBytes(data []byte) error {
	return nil
}

func (msg *MsgDeSoGetAddr) GetMsgType() MsgType {
	return MsgTypeGetAddr
}

// ==================================================================
// VERACK Message
// ==================================================================

// VERACK messages have no payload.
type MsgDeSoVerack struct {
	// A verack message must contain the nonce the peer received in the
	// initial version message. This ensures the peer that is communicating
	// with us actually controls the address she says she does similar to
	// "SYN Cookie" DDOS protection.
	Nonce uint64
}

func (msg *MsgDeSoVerack) ToBytes(preSignature bool) ([]byte, error) {
	retBytes := []byte{}

	// Nonce
	retBytes = append(retBytes, UintToBuf(msg.Nonce)...)
	return retBytes, nil
}

func (msg *MsgDeSoVerack) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retMsg := NewMessage(MsgTypeVerack).(*MsgDeSoVerack)
	{
		nonce, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoVerack.FromBytes: Problem reading Nonce")
		}
		retMsg.Nonce = nonce
	}
	*msg = *retMsg
	return nil
}

func (msg *MsgDeSoVerack) GetMsgType() MsgType {
	return MsgTypeVerack
}

// ==================================================================
// HEADER Message
// ==================================================================

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
	header := NewMessage(MsgTypeHeader)
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
	retHeader := NewMessage(MsgTypeHeader).(*MsgDeSoHeader)

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
	retHeader := NewMessage(MsgTypeHeader).(*MsgDeSoHeader)

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

func (msg *MsgDeSoHeader) GetMsgType() MsgType {
	return MsgTypeHeader
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

type MsgDeSoBlock struct {
	Header *MsgDeSoHeader
	Txns   []*MsgDeSoTxn

	// This field is optional and provides the producer of the block the ability to sign it
	// with their private key. Doing this proves that this block was produced by a particular
	// entity, which can be useful for nodes that want to restrict who they accept blocks
	// from.
	BlockProducerInfo *BlockProducerInfo
}

func (msg *MsgDeSoBlock) EncodeBlockCommmon(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Serialize the header.
	if msg.Header == nil {
		return nil, fmt.Errorf("MsgDeSoBlock.ToBytes: Header should not be nil")
	}
	hdrBytes, err := msg.Header.ToBytes(preSignature)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoBlock.ToBytes: Problem encoding header")
	}
	data = append(data, UintToBuf(uint64(len(hdrBytes)))...)
	data = append(data, hdrBytes...)

	// Serialize all the transactions.
	numTxns := uint64(len(msg.Txns))
	data = append(data, UintToBuf(numTxns)...)
	for ii := uint64(0); ii < numTxns; ii++ {
		currentTxnBytes, err := msg.Txns[ii].ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "MsgDeSoBlock.ToBytes: Problem encoding txn")
		}
		data = append(data, UintToBuf(uint64(len(currentTxnBytes)))...)
		data = append(data, currentTxnBytes...)
	}

	return data, nil
}

func (msg *MsgDeSoBlock) EncodeBlockVersion0(preSignature bool) ([]byte, error) {
	return msg.EncodeBlockCommmon(preSignature)
}

func (msg *MsgDeSoBlock) EncodeBlockVersion1(preSignature bool) ([]byte, error) {
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

func (msg *MsgDeSoBlock) ToBytes(preSignature bool) ([]byte, error) {
	if msg.Header.Version == HeaderVersion0 {
		return msg.EncodeBlockVersion0(preSignature)
	} else if msg.Header.Version == HeaderVersion1 {
		return msg.EncodeBlockVersion1(preSignature)
	} else {
		return nil, fmt.Errorf("MsgDeSoBlock.ToBytes: Error encoding version: %v", msg.Header.Version)
	}
}

func (msg *MsgDeSoBlock) FromBytes(data []byte) error {
	ret := NewMessage(MsgTypeBlock).(*MsgDeSoBlock)
	rr := bytes.NewReader(data)

	// De-serialize the header.
	hdrLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Problem decoding header length")
	}
	if hdrLen > MaxMessagePayload {
		return fmt.Errorf("MsgDeSoBlock.FromBytes: Header length %d longer than max %d", hdrLen, MaxMessagePayload)
	}
	hdrBytes := make([]byte, hdrLen)
	_, err = io.ReadFull(rr, hdrBytes)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Problem reading header")
	}

	err = ret.Header.FromBytes(hdrBytes)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Problem converting header")
	}

	// De-serialize the transactions.
	numTxns, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Problem decoding num txns")
	}
	ret.Txns = make([]*MsgDeSoTxn, 0)
	for ii := uint64(0); ii < numTxns; ii++ {
		txBytesLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Problem decoding txn length")
		}
		if txBytesLen > MaxMessagePayload {
			return fmt.Errorf("MsgDeSoBlock.FromBytes: Txn %d length %d longer than max %d", ii, hdrLen, MaxMessagePayload)
		}
		txBytes := make([]byte, txBytesLen)
		_, err = io.ReadFull(rr, txBytes)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Problem reading tx bytes")
		}
		currentTxn := NewMessage(MsgTypeTxn).(*MsgDeSoTxn)
		err = currentTxn.FromBytes(txBytes)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Problem decoding txn")
		}
		ret.Txns = append(ret.Txns, currentTxn)
	}

	// Version 1 blocks have a BlockProducerInfo attached to them that
	// must be read. If this is not a Version 1 block, then the BlockProducerInfo
	// remains nil.
	if ret.Header.Version == HeaderVersion1 {
		blockProducerInfoLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Error decoding header length")
		}
		var blockProducerInfo *BlockProducerInfo
		if blockProducerInfoLen > 0 {
			if blockProducerInfoLen > MaxMessagePayload {
				return fmt.Errorf("MsgDeSoBlock.FromBytes: Header length %d longer "+
					"than max %d", blockProducerInfoLen, MaxMessagePayload)
			}
			blockProducerInfoBytes := make([]byte, blockProducerInfoLen)
			_, err = io.ReadFull(rr, blockProducerInfoBytes)
			if err != nil {
				return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Problem reading header")
			}
			blockProducerInfo = &BlockProducerInfo{}
			blockProducerInfo.Deserialize(blockProducerInfoBytes)
			ret.BlockProducerInfo = blockProducerInfo
		}
	}

	*msg = *ret
	return nil
}

func (msg *MsgDeSoBlock) GetMsgType() MsgType {
	return MsgTypeBlock
}

func (msg *MsgDeSoBlock) Hash() (*BlockHash, error) {
	if msg == nil || msg.Header == nil {
		return nil, fmt.Errorf("MsgDeSoBLock.Hash: nil block or nil header")
	}
	return msg.Header.Hash()
}

func (msg *MsgDeSoBlock) String() string {
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
	// MaxDeSoInputSizeBytes is the size required to encode an DeSoInput.
	// 32 bytes for the TxID and 4 bytes for the Index = 36 bytes. Note
	// that because the index is encoded as a uvarint, this size represents
	// a maximum.
	MaxDeSoInputSizeBytes = 32 + 4
	// MaxDeSoOutputSizeBytes is the size required to encode an DeSoOutput.
	// It is 33 bytes for the public key and 8 bytes for the amount
	// = 41 bytes. Note that because the amount is encoded as a uvarint,
	// this size represents a maximum.
	MaxDeSoOutputSizeBytes = btcec.PubKeyBytesLenCompressed + 8
)

// DeSoInput represents a single unspent output from a previous txn.
// For that reason it specifies the previous txn and the index in that txn where
// the output appears by simply aliasing UtxoKey.
type DeSoInput UtxoKey

func (desoInput *DeSoInput) String() string {
	return (*UtxoKey)(desoInput).String()
}

func NewDeSoInput() *DeSoInput {
	return &DeSoInput{
		TxID: BlockHash{},
	}
}

type DeSoOutput struct {
	// Outputs always compensate a specific public key.
	PublicKey []byte
	// The amount of DeSo to send to this public key.
	AmountNanos uint64
}

func (desoOutput *DeSoOutput) String() string {
	return fmt.Sprintf("< PublicKey: %#v, AmountNanos: %d >",
		PkToStringMainnet(desoOutput.PublicKey), desoOutput.AmountNanos)
}

type MsgDeSoTxn struct {
	TxInputs  []*DeSoInput
	TxOutputs []*DeSoOutput

	// DeSoTxnMetadata is an interface type that will give us information on how
	// we should handle the transaction, including what type of transaction this
	// is.
	TxnMeta DeSoTxnMetadata

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
	// BLOCK_REWARD and CREATE_deso transactions do not require a signature
	// since they have no inputs.
	Signature *btcec.Signature

	// (!!) **DO_NOT_USE** (!!)
	//
	// Use txn.TxnMeta.GetTxnType() instead.
	//
	// We need this for JSON encoding/decoding. It isn't used for anything
	// else and it isn't actually serialized or de-serialized when sent
	// across the network using ToBytes/FromBytes because we prefer that
	// any use of the MsgDeSoTxn in Go code rely on TxnMeta.GetTxnType() rather
	// than checking this value, which, in Go context, is redundant and
	// therefore error-prone (e.g. someone might change TxnMeta while
	// forgetting to set it). We make it a uint64 explicitly to prevent
	// people from using it in Go code.
	TxnTypeJSON uint64
}

func (msg *MsgDeSoTxn) String() string {
	pubKey := msg.PublicKey
	if msg.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
		pubKeyObj, err := ExtractBitcoinPublicKeyFromBitcoinTransactionInputs(
			msg.TxnMeta.(*BitcoinExchangeMetadata).BitcoinTransaction, DeSoMainnetParams.BitcoinBtcdParams)
		if err != nil {
			pubKey = msg.PublicKey
		} else {
			pubKey = pubKeyObj.SerializeCompressed()
		}
	}
	return fmt.Sprintf("< TxHash: %v, TxnType: %v, PubKey: %v >",
		msg.Hash(), msg.TxnMeta.GetTxnType(), PkToStringMainnet(pubKey))
}

func (msg *MsgDeSoTxn) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Serialize the inputs
	data = append(data, UintToBuf(uint64(len(msg.TxInputs)))...)
	for _, desoInput := range msg.TxInputs {
		data = append(data, desoInput.TxID[:]...)
		data = append(data, UintToBuf(uint64(desoInput.Index))...)
	}

	// Serialize the outputs
	data = append(data, UintToBuf(uint64(len(msg.TxOutputs)))...)
	for _, desoOutput := range msg.TxOutputs {
		// The public key is always 33 bytes.
		data = append(data, desoOutput.PublicKey[:]...)
		data = append(data, UintToBuf(desoOutput.AmountNanos)...)
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
		return nil, errors.Wrapf(err, "MsgDeSoTxn.ToBytes: Problem encoding meta of type %v: ",
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
	if !preSignature && msg.Signature != nil {
		sigBytes = msg.Signature.Serialize()
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

func _readTransaction(rr io.Reader) (*MsgDeSoTxn, error) {
	ret := NewMessage(MsgTypeTxn).(*MsgDeSoTxn)

	// De-serialize the inputs
	numInputs, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem converting len(msg.TxInputs)")
	}
	for ii := uint64(0); ii < numInputs; ii++ {
		currentInput := NewDeSoInput()
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
		currentOutput := &DeSoOutput{}
		currentOutput.PublicKey = make([]byte, btcec.PubKeyBytesLenCompressed)
		_, err = io.ReadFull(rr, currentOutput.PublicKey)
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem reading DeSoOutput.PublicKey")
		}

		amountNanos, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem reading DeSoOutput.AmountNanos")
		}
		currentOutput.AmountNanos = amountNanos

		ret.TxOutputs = append(ret.TxOutputs, currentOutput)
	}

	// De-serialize the metadata
	//
	// Encode the type as a uvarint.
	txnMetaType, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading MsgDeSoTxn.TxnType")
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
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading len(DeSoTxn.PublicKey)")
	}
	if pkLen > MaxMessagePayload {
		return nil, fmt.Errorf("_readTransaction.FromBytes: pkLen length %d longer than max %d", pkLen, MaxMessagePayload)
	}
	ret.PublicKey = nil
	if pkLen != 0 {
		ret.PublicKey = make([]byte, pkLen)
		_, err = io.ReadFull(rr, ret.PublicKey)
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem reading DeSoTxn.PublicKey")
		}
	}

	// De-serialize the ExtraData
	extraDataLen, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading len(DeSoTxn.ExtraData)")
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
				return nil, fmt.Errorf("_readTransaction.FromBytes: Problem reading len(DeSoTxn.ExtraData.Keys[#{ii}]")
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
				return nil, fmt.Errorf("_readTransaction.FromBytes: Problem reading len(DeSoTxn.ExtraData.Value[#{ii}]")
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
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading len(DeSoTxn.Signature)")
	}
	if sigLen > MaxMessagePayload {
		return nil, fmt.Errorf("_readTransaction.FromBytes: sigLen length %d longer than max %d", sigLen, MaxMessagePayload)
	}

	ret.Signature = nil
	if sigLen != 0 {
		sigBytes := make([]byte, sigLen)
		_, err = io.ReadFull(rr, sigBytes)
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem reading DeSoTxn.Signature")
		}

		// Verify that the signature is valid.
		sig, err := btcec.ParseDERSignature(sigBytes, btcec.S256())
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem parsing DeSoTxn.Signature bytes")
		}
		// If everything worked, we set the ret signature to the original.
		ret.Signature = sig
	}

	return ret, nil
}

func (msg *MsgDeSoTxn) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	ret, err := _readTransaction(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoTxn.FromBytes: Problem reading txn: ")
	}
	*msg = *ret
	return nil
}

func (msg *MsgDeSoTxn) GetMsgType() MsgType {
	return MsgTypeTxn
}

// Hash is a helper function to compute a hash of the transaction aka a
// transaction ID.
func (msg *MsgDeSoTxn) Hash() *BlockHash {
	// BitcoinExchange transactions are a special case whereby the hash
	// of the DeSo transaction is defined as the hash of the Bitcoin
	// transaction embedded within it. This allows us to use BitcoinExchange
	// transactions as inputs to subsequent transactions *before* the
	// merkle proof has actually been defined. Thus it allows us to support
	// the "instant DeSo buy" feature in the UI.
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

func (msg *MsgDeSoTxn) Copy() (*MsgDeSoTxn, error) {
	txnBytes, err := msg.ToBytes(false /*preSignature*/)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoTxn.Copy: ")
	}
	newTxn := &MsgDeSoTxn{}
	err = newTxn.FromBytes(txnBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoTxn.Copy: ")
	}
	return newTxn, nil
}

func (msg *MsgDeSoTxn) Sign(privKey *btcec.PrivateKey) (*btcec.Signature, error) {
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
// Returns (new txn bytes, txn signature, error)
func SignTransactionWithDerivedKey(txnBytes []byte, privateKey *btcec.PrivateKey) ([]byte, []byte, error) {
	// As we're signing the transaction using a derived key, we
	// pass the key to extraData.
	rr := bytes.NewReader(txnBytes)
	txn, err := _readTransaction(rr)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "SignTransactionWithDerivedKey: Problem reading txn: ")
	}
	if txn.ExtraData == nil {
		txn.ExtraData = make(map[string][]byte)
	}
	txn.ExtraData[DerivedPublicKey] = privateKey.PubKey().SerializeCompressed()

	// Sign the transaction with the passed private key.
	txnSignature, err := txn.Sign(privateKey)
	if err != nil {
		return nil, nil, err
	}

	newTxnBytes, err := txn.ToBytes(true)
	if err != nil {
		return nil, nil, err
	}

	return newTxnBytes, txnSignature.Serialize(), nil
}

// MarshalJSON and UnmarshalJSON implement custom JSON marshaling/unmarshaling
// to support transaction metadata. The reason this needs to exist is because
// TxnMeta is an abstract interface and therefore
// when its decoded to JSON, the type information (i.e. which TxnType it is)
// cannot be inferred from the JSON unless we augment it a little bit.
// Note this format is not used to relay messages between nodes, only
// for replying to frontend/user-facing queries.
func (msg *MsgDeSoTxn) MarshalJSON() ([]byte, error) {
	// Copy the txn so none of the fields get set on the passed-in txn.
	txnCopy := *msg
	// If there's no metadata then we have an error. Transactions should
	// always have a metadata field that indicates what type the transaction
	// is.
	if txnCopy.TxnMeta == nil {
		return nil, fmt.Errorf("MsgDeSoTxn.MarshalJSON: Transaction is missing TxnMeta: %v", txnCopy)
	}
	// Set the txnType based on the metadata that is set.
	txnCopy.TxnTypeJSON = uint64(txnCopy.TxnMeta.GetTxnType())
	return json.Marshal(txnCopy)
}

// UnmarshalJSON is covered by the comment on MarshalJSON.
func (msg *MsgDeSoTxn) UnmarshalJSON(data []byte) error {
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
		return fmt.Errorf("MsgDeSoTxn.UnmarshalJSON: Field txnType is missing "+
			"from JSON decoded map: %v", responseMap)
	}
	txnMeta, err := NewTxnMetadata(TxnType(uint64(txnType.(float64))))
	if err != nil {
		return fmt.Errorf("MsgDeSoTxn.UnmarshalJSON: Problem parsing TxnType: %v, %v", err, responseMap)
	}
	msg.TxnMeta = txnMeta

	// TODO: The code below is an ugly hack, but it achieves the goal of making
	// TxnMeta (and MsgDeSoTxn by proxy) serializable to JSON without any extra overhead
	// needed on the caller side. This is particularly important when one considers
	// that transactions can be serialized to JSON as part of blocks,
	// and this makes it so that even in that case no special handling is
	// needed by the code serializing/deserializing, which is good. Still, would
	// be nice if, for example, the code below didn't break whenever we modify
	// MsgDeSoTxn (which is admittedly very rare and a test can easily catch this
	// by erroring when the number of fields changes with a helpful message).
	anonymousTxn := struct {
		TxInputs  []*DeSoInput
		TxOutputs []*DeSoOutput
		TxnMeta   DeSoTxnMetadata
		PublicKey []byte
		Signature *btcec.Signature
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

func (txnData *BasicTransferMetadata) New() DeSoTxnMetadata {
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

func (txnData *BlockRewardMetadataa) New() DeSoTxnMetadata {
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

func (txnData *BitcoinExchangeMetadata) New() DeSoTxnMetadata {
	return &BitcoinExchangeMetadata{}
}

// ==================================================================
// PrivateMessageMetadata
//
// A private message is a message from one user on the platform to
// another user on the platform. It is generally treated as a normal
// transaction would be except that the public key of the top-level
// MsgDeSoTxn is assumed to be the sender of the message and the
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

func (txnData *PrivateMessageMetadata) New() DeSoTxnMetadata {
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

func (txnData *LikeMetadata) New() DeSoTxnMetadata {
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

	// FollowedPublicKey
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

func (txnData *FollowMetadata) New() DeSoTxnMetadata {
	return &FollowMetadata{}
}

// = = = = = = = = = = = = = = = = = = = = = = =
// DeSo
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

func (txnData *SubmitPostMetadata) New() DeSoTxnMetadata {
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
	// put in enough DeSo to buy 10 coins, the creator would get 2.5
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

func (txnData *UpdateProfileMetadata) New() DeSoTxnMetadata {
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

func (txnData *UpdateGlobalParamsMetadata) New() DeSoTxnMetadata {
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

func (txnData *UpdateBitcoinUSDExchangeRateMetadataa) New() DeSoTxnMetadata {
	return &UpdateBitcoinUSDExchangeRateMetadataa{}
}

// ==================================================================
// CreatorCoinMetadataa
// ==================================================================

type CreatorCoinOperationType uint8

const (
	CreatorCoinOperationTypeBuy     CreatorCoinOperationType = 0
	CreatorCoinOperationTypeSell    CreatorCoinOperationType = 1
	CreatorCoinOperationTypeAddDeSo CreatorCoinOperationType = 2
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
	// set. In a Buy transaction, DeSoToSellNanos will be converted into
	// creator coin on behalf of the user. In a Sell transaction,
	// CreatorCoinToSellNanos will be converted into DeSo. In an AddDeSo
	// operation, DeSoToAddNanos will be aded for the user. This allows us to
	// support multiple transaction types with same meta field.
	DeSoToSellNanos        uint64
	CreatorCoinToSellNanos uint64
	DeSoToAddNanos         uint64

	// When a user converts DeSo into CreatorCoin, MinCreatorCoinExpectedNanos
	// specifies the minimum amount of creator coin that the user expects from their
	// transaction. And vice versa when a user is converting CreatorCoin for DeSo.
	// Specifying these fields prevents the front-running of users' buy/sell. Setting
	// them to zero turns off the check. Give it your best shot, Ivan.
	MinDeSoExpectedNanos        uint64
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

	// DeSoToSellNanos    uint64
	data = append(data, UintToBuf(uint64(txnData.DeSoToSellNanos))...)

	// CreatorCoinToSellNanos uint64
	data = append(data, UintToBuf(uint64(txnData.CreatorCoinToSellNanos))...)
	// DeSoToAddNanos     uint64
	data = append(data, UintToBuf(uint64(txnData.DeSoToAddNanos))...)

	// MinDeSoExpectedNanos    uint64
	data = append(data, UintToBuf(uint64(txnData.MinDeSoExpectedNanos))...)
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

	// DeSoToSellNanos    uint64
	ret.DeSoToSellNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreatorCoinMetadata.FromBytes: Error reading DeSoToSellNanos: %v", err)
	}

	// CreatorCoinToSellNanos uint64
	ret.CreatorCoinToSellNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreatorCoinMetadata.FromBytes: Error reading CreatorCoinToSellNanos: %v", err)
	}

	// DeSoToAddNanos     uint64
	ret.DeSoToAddNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreatorCoinMetadata.FromBytes: Error reading DeSoToAddNanos: %v", err)
	}

	// MinDeSoExpectedNanos    uint64
	ret.MinDeSoExpectedNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreatorCoinMetadata.FromBytes: Error reading MinDeSoExpectedNanos: %v", err)
	}

	// MinCreatorCoinExpectedNanos uint64
	ret.MinCreatorCoinExpectedNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("CreatorCoinMetadata.FromBytes: Error reading MinCreatorCoinExpectedNanos: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *CreatorCoinMetadataa) New() DeSoTxnMetadata {
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

	// ReceiverPublicKey
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
			"CreatorCoinTransferMetadataa.FromBytes: Error reading ReceiverPublicKey: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *CreatorCoinTransferMetadataa) New() DeSoTxnMetadata {
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

func (txnData *CreateNFTMetadata) New() DeSoTxnMetadata {
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

func (txnData *UpdateNFTMetadata) New() DeSoTxnMetadata {
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
	BidderInputs []*DeSoInput
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
	for _, desoInput := range txnData.BidderInputs {
		data = append(data, desoInput.TxID[:]...)
		data = append(data, UintToBuf(uint64(desoInput.Index))...)
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
		return fmt.Errorf("AcceptNFTBidMetadata.FromBytes: Error reading EncryptedText: %v", err)
	}

	// De-serialize the inputs
	numInputs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AcceptNFTBidMetadata.FromBytes: Problem getting length of inputs")
	}
	for ii := uint64(0); ii < numInputs; ii++ {
		currentInput := NewDeSoInput()
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

func (txnData *AcceptNFTBidMetadata) New() DeSoTxnMetadata {
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

func (txnData *NFTBidMetadata) New() DeSoTxnMetadata {
	return &NFTBidMetadata{}
}

// ==================================================================
// NFTTransferMetadata
// ==================================================================

type NFTTransferMetadata struct {
	NFTPostHash       *BlockHash
	SerialNumber      uint64
	ReceiverPublicKey []byte
	UnlockableText    []byte
}

func (txnData *NFTTransferMetadata) GetTxnType() TxnType {
	return TxnTypeNFTTransfer
}

func (txnData *NFTTransferMetadata) ToBytes(preSignature bool) ([]byte, error) {
	// Validate the metadata before encoding it.
	//
	// Post hash must be included and must have the expected length.
	if len(txnData.NFTPostHash) != HashSizeBytes {
		return nil, fmt.Errorf("NFTTransferMetadata.ToBytes: NFTPostHash "+
			"has length %d != %d", len(txnData.NFTPostHash), HashSizeBytes)
	}

	data := []byte{}

	// NFTPostHash
	data = append(data, txnData.NFTPostHash[:]...)

	// SerialNumber uint64
	data = append(data, UintToBuf(txnData.SerialNumber)...)

	// ReceiverPublicKey
	data = append(data, UintToBuf(uint64(len(txnData.ReceiverPublicKey)))...)
	data = append(data, txnData.ReceiverPublicKey...)

	// UnlockableText
	data = append(data, UintToBuf(uint64(len(txnData.UnlockableText)))...)
	data = append(data, txnData.UnlockableText...)

	return data, nil
}

func (txnData *NFTTransferMetadata) FromBytes(dataa []byte) error {
	ret := NFTTransferMetadata{}
	rr := bytes.NewReader(dataa)

	// NFTPostHash
	ret.NFTPostHash = &BlockHash{}
	_, err := io.ReadFull(rr, ret.NFTPostHash[:])
	if err != nil {
		return fmt.Errorf(
			"NFTTransferMetadata.FromBytes: Error reading NFTPostHash: %v", err)
	}

	// SerialNumber uint64
	ret.SerialNumber, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("NFTTransferMetadata.FromBytes: Error reading SerialNumber: %v", err)
	}

	// ReceiverPublicKey
	ret.ReceiverPublicKey, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"NFTTransferMetadataa.FromBytes: Error reading ReceiverPublicKey: %v", err)
	}

	// UnlockableText
	unlockableTextLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTTransferMetadata.FromBytes: Problem "+
			"decoding UnlockableText length")
	}
	if unlockableTextLen > MaxMessagePayload {
		return fmt.Errorf("NFTTransferMetadata.FromBytes: unlockableTextLen %d "+
			"exceeds max %d", unlockableTextLen, MaxMessagePayload)
	}
	ret.UnlockableText = make([]byte, unlockableTextLen)
	_, err = io.ReadFull(rr, ret.UnlockableText)
	if err != nil {
		return fmt.Errorf("NFTTransferMetadata.FromBytes: Error reading EncryptedText: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *NFTTransferMetadata) New() DeSoTxnMetadata {
	return &NFTTransferMetadata{}
}

// ==================================================================
// AcceptNFTTransferMetadata
// ==================================================================

type AcceptNFTTransferMetadata struct {
	NFTPostHash  *BlockHash
	SerialNumber uint64
}

func (txnData *AcceptNFTTransferMetadata) GetTxnType() TxnType {
	return TxnTypeAcceptNFTTransfer
}

func (txnData *AcceptNFTTransferMetadata) ToBytes(preSignature bool) ([]byte, error) {
	// Validate the metadata before encoding it.
	//
	// Post hash must be included and must have the expected length.
	if len(txnData.NFTPostHash) != HashSizeBytes {
		return nil, fmt.Errorf("AcceptNFTTransferMetadata.ToBytes: NFTPostHash "+
			"has length %d != %d", len(txnData.NFTPostHash), HashSizeBytes)
	}

	data := []byte{}

	// NFTPostHash
	data = append(data, txnData.NFTPostHash[:]...)

	// SerialNumber uint64
	data = append(data, UintToBuf(txnData.SerialNumber)...)

	return data, nil
}

func (txnData *AcceptNFTTransferMetadata) FromBytes(dataa []byte) error {
	ret := AcceptNFTTransferMetadata{}
	rr := bytes.NewReader(dataa)

	// NFTPostHash
	ret.NFTPostHash = &BlockHash{}
	_, err := io.ReadFull(rr, ret.NFTPostHash[:])
	if err != nil {
		return fmt.Errorf(
			"AcceptNFTTransferMetadata.FromBytes: Error reading NFTPostHash: %v", err)
	}

	// SerialNumber uint64
	ret.SerialNumber, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("AcceptNFTTransferMetadata.FromBytes: Error reading SerialNumber: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *AcceptNFTTransferMetadata) New() DeSoTxnMetadata {
	return &AcceptNFTTransferMetadata{}
}

// ==================================================================
// BurnNFTMetadata
// ==================================================================

type BurnNFTMetadata struct {
	NFTPostHash  *BlockHash
	SerialNumber uint64
}

func (txnData *BurnNFTMetadata) GetTxnType() TxnType {
	return TxnTypeBurnNFT
}

func (txnData *BurnNFTMetadata) ToBytes(preSignature bool) ([]byte, error) {
	// Validate the metadata before encoding it.
	//
	// Post hash must be included and must have the expected length.
	if len(txnData.NFTPostHash) != HashSizeBytes {
		return nil, fmt.Errorf("BurnNFTMetadata.ToBytes: NFTPostHash "+
			"has length %d != %d", len(txnData.NFTPostHash), HashSizeBytes)
	}

	data := []byte{}

	// NFTPostHash
	data = append(data, txnData.NFTPostHash[:]...)

	// SerialNumber uint64
	data = append(data, UintToBuf(txnData.SerialNumber)...)

	return data, nil
}

func (txnData *BurnNFTMetadata) FromBytes(dataa []byte) error {
	ret := BurnNFTMetadata{}
	rr := bytes.NewReader(dataa)

	// NFTPostHash
	ret.NFTPostHash = &BlockHash{}
	_, err := io.ReadFull(rr, ret.NFTPostHash[:])
	if err != nil {
		return fmt.Errorf(
			"BurnNFTMetadata.FromBytes: Error reading NFTPostHash: %v", err)
	}

	// SerialNumber uint64
	ret.SerialNumber, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("BurnNFTMetadata.FromBytes: Error reading SerialNumber: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *BurnNFTMetadata) New() DeSoTxnMetadata {
	return &BurnNFTMetadata{}
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

func (txnData *SwapIdentityMetadataa) New() DeSoTxnMetadata {
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
	// on behalf of the public key owner.
	DerivedPublicKey []byte

	// ExpirationBlock is the block at which this authorization becomes invalid.
	ExpirationBlock uint64

	// OperationType determines if transaction validates or invalidates derived key.
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

func (txnData *AuthorizeDerivedKeyMetadata) New() DeSoTxnMetadata {
	return &AuthorizeDerivedKeyMetadata{}
}

// ==================================================================
// DAOCoinMetadata
// ==================================================================

type DAOCoinOperationType uint8

const (
	DAOCoinOperationTypeMint                            DAOCoinOperationType = 0
	DAOCoinOperationTypeBurn                            DAOCoinOperationType = 1
	DAOCoinOperationTypeDisableMinting                  DAOCoinOperationType = 2
	DAOCoinOperationTypeUpdateTransferRestrictionStatus DAOCoinOperationType = 3
)

type DAOCoinMetadata struct {
	// ProfilePublicKey is the public key of the profile that owns the
	// coin the person wants to operate on.
	ProfilePublicKey []byte

	// OperationType specifies what the user wants to do with this
	// DAO coin.
	OperationType DAOCoinOperationType

	// TODO: Should we only have one field that tracks number of coins in operation to keep this struct small?
	// We will only ever need 1 of these fields.
	// Mint field
	CoinsToMintNanos uint256.Int

	// Burn Fields
	CoinsToBurnNanos uint256.Int

	// TransferRestrictionStatus to set if OperationType == DAOCoinOperatoinTypeUpdateTransferRestrictionStatus
	TransferRestrictionStatus
}

func (txnData *DAOCoinMetadata) GetTxnType() TxnType {
	return TxnTypeDAOCoin
}

func (txnData *DAOCoinMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// ProfilePublicKey
	data = append(data, UintToBuf(uint64(len(txnData.ProfilePublicKey)))...)
	data = append(data, txnData.ProfilePublicKey...)

	// OperationType byte
	data = append(data, byte(txnData.OperationType))

	// CoinsToMintNanos
	{
		coinsToMintBytes := txnData.CoinsToMintNanos.Bytes()
		data = append(data, UintToBuf(uint64(len(coinsToMintBytes)))...)
		data = append(data, coinsToMintBytes...)
	}

	// CoinsToBurnNanos
	{
		coinsToBurnBytes := txnData.CoinsToBurnNanos.Bytes()
		data = append(data, UintToBuf(uint64(len(coinsToBurnBytes)))...)
		data = append(data, coinsToBurnBytes...)
	}

	data = append(data, byte(txnData.TransferRestrictionStatus))

	return data, nil
}

func (txnData *DAOCoinMetadata) FromBytes(data []byte) error {
	ret := DAOCoinMetadata{}
	rr := bytes.NewReader(data)

	// ProfilePublicKey
	var err error
	ret.ProfilePublicKey, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"DAOCoinMetadata.FromBytes: Error reading ProfilePublicKey: %v", err)
	}

	// OperationType byte
	operationType, err := rr.ReadByte()
	if err != nil {
		return fmt.Errorf(
			"DAOCoinMetadata.FromBytes: Error reading OperationType: %v", err)
	}
	ret.OperationType = DAOCoinOperationType(operationType)

	// Set CoinsToMintNanos from the bytes
	maxUint256BytesLen := len(MaxUint256.Bytes())
	{
		intLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "DAOCoinMetadata.FromBytes: Problem "+
				"coinsToMint length")
		}
		if intLen > uint64(maxUint256BytesLen) {
			return fmt.Errorf("DAOCoinMetadata.FromBytes: coinsToMintLen %d "+
				"exceeds max %d", intLen, MaxMessagePayload)
		}
		coinsToMintBytes := make([]byte, intLen)
		_, err = io.ReadFull(rr, coinsToMintBytes)
		if err != nil {
			return fmt.Errorf("DAOCoinMetadata.FromBytes: Error reading coinsToMintBytes: %v", err)
		}
		ret.CoinsToMintNanos = *uint256.NewInt().SetBytes(coinsToMintBytes)
	}

	{
		intLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "DAOCoinMetadata.FromBytes: Problem "+
				"coinsToBurn length")
		}
		if intLen > uint64(maxUint256BytesLen) {
			return fmt.Errorf("DAOCoinMetadata.FromBytes: coinsToBurnLen %d "+
				"exceeds max %d", intLen, MaxMessagePayload)
		}
		coinsToBurnBytes := make([]byte, intLen)
		_, err = io.ReadFull(rr, coinsToBurnBytes)
		if err != nil {
			return fmt.Errorf("DAOCoinMetadata.FromBytes: Error reading coinsToBurnBytes: %v", err)
		}
		ret.CoinsToBurnNanos = *uint256.NewInt().SetBytes(coinsToBurnBytes)
	}

	transferRestrictionStatus, err := rr.ReadByte()
	if err != nil {
		return fmt.Errorf("DAOCoinMetadata.FromBytes: Error reading TransferRestrictionStatus: %v", err)
	}
	ret.TransferRestrictionStatus = TransferRestrictionStatus(transferRestrictionStatus)

	*txnData = ret
	return nil
}

func (txnData *DAOCoinMetadata) New() DeSoTxnMetadata {
	return &DAOCoinMetadata{}
}

// ==================================================================
// DAOCoinTransferMetadata
// ==================================================================

type DAOCoinTransferMetadata struct {
	// ProfilePublicKey is the public key of the profile that owns the
	// coin the person wants to transfer. DAO coins can only be
	// transferred if a valid profile exists.
	ProfilePublicKey []byte

	DAOCoinToTransferNanos uint256.Int
	ReceiverPublicKey      []byte
}

func (txnData *DAOCoinTransferMetadata) GetTxnType() TxnType {
	return TxnTypeDAOCoinTransfer
}

func (txnData *DAOCoinTransferMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// ProfilePublicKey
	data = append(data, UintToBuf(uint64(len(txnData.ProfilePublicKey)))...)
	data = append(data, txnData.ProfilePublicKey...)

	// DAOCoinToTransferNanos uint64
	{
		coinsToTransferBytes := txnData.DAOCoinToTransferNanos.Bytes()
		data = append(data, UintToBuf(uint64(len(coinsToTransferBytes)))...)
		data = append(data, coinsToTransferBytes...)
	}

	// ReceiverPublicKey
	data = append(data, UintToBuf(uint64(len(txnData.ReceiverPublicKey)))...)
	data = append(data, txnData.ReceiverPublicKey...)

	return data, nil
}

func (txnData *DAOCoinTransferMetadata) FromBytes(data []byte) error {
	ret := DAOCoinTransferMetadata{}
	rr := bytes.NewReader(data)

	// ProfilePublicKey
	var err error
	ret.ProfilePublicKey, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"DAOCoinTransferMetadata.FromBytes: Error reading ProfilePublicKey: %v", err)
	}

	// DAOCoinToTransferNanos uint256
	maxUint256BytesLen := len(MaxUint256.Bytes())
	{
		intLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "DAOCoinTransferMetadata.FromBytes: Problem "+
				"coinsToTransfer length")
		}
		if intLen > uint64(maxUint256BytesLen) {
			return fmt.Errorf("DAOCoinTransferMetadata.FromBytes: coinsToTransferLen %d "+
				"exceeds max %d", intLen, MaxMessagePayload)
		}
		coinsToTransferBytes := make([]byte, intLen)
		_, err = io.ReadFull(rr, coinsToTransferBytes)
		if err != nil {
			return fmt.Errorf("DAOCoinTransferMetadata.FromBytes: Error reading coinsToTransferBytes: %v", err)
		}
		ret.DAOCoinToTransferNanos = *uint256.NewInt().SetBytes(coinsToTransferBytes)
	}

	// ReceiverPublicKey
	ret.ReceiverPublicKey, err = ReadVarString(rr)
	if err != nil {
		return fmt.Errorf(
			"DAOCoinTransferMetadata.FromBytes: Error reading ReceiverPublicKey: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *DAOCoinTransferMetadata) New() DeSoTxnMetadata {
	return &DAOCoinTransferMetadata{}
}

func SerializePubKeyToUint64Map(mm map[PublicKey]uint64) ([]byte, error) {
	data := []byte{}
	// Encode the number of key/value pairs
	numKeys := uint64(len(mm))
	data = append(data, UintToBuf(numKeys)...)

	// For each kv pair, encode the public key and the length
	if numKeys > 0 {
		// Sort the keys of the map based on the mainnet public key encoding.
		// This ensures a deterministic sorting.
		keys := make([]string, 0, numKeys)
		for key := range mm {
			keys = append(keys, PkToStringMainnet(key[:]))
		}
		sort.Strings(keys)
		// Encode each (public key, uint64) pair
		for _, key := range keys {
			// Serialize the raw public key
			pkBytes, _, err := Base58CheckDecode(key)
			if err != nil {
				// This should never happen since we just enoded it above,
				// so panic if it does
				return nil, err
			}
			data = append(data, pkBytes...)

			// The value needs to be looked up using the raw public key
			val, exists := mm[*NewPublicKey(pkBytes)]
			if !exists {
				return nil, fmt.Errorf("Missing pubkey %v in SerializePubKeyToUint64Map %v",
					key, spew.Sdump(mm))
			}

			// Add the uint64 to the end of the map
			data = append(data, UintToBuf(val)...)
		}
	}

	return data, nil
}

func DeserializePubKeyToUint64Map(data []byte) (map[PublicKey]uint64, error) {
	rr := bytes.NewReader(data)

	numKeys, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializePubKeyToUint64Map.FromBytes: Problem "+
			"reading num keys")
	}
	mm := make(map[PublicKey]uint64, numKeys)
	for ii := uint64(0); ii < numKeys; ii++ {
		// Read in the public key bytes
		pkBytes := make([]byte, btcec.PubKeyBytesLenCompressed)
		_, err = io.ReadFull(rr, pkBytes)
		if err != nil {
			return nil, err
		}
		pk := *NewPublicKey(pkBytes)

		// Read in the uint
		val, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "DeserializePubKeyToUint64Map.FromBytes: Problem "+
				"reading value for key %v", PkToStringMainnet(pkBytes))
		}

		mm[pk] = val
	}

	return mm, nil
}

// ==================================================================
// MessagingGroupMetadata
// ==================================================================

type MessagingGroupMetadata struct {
	// This struct is very similar to the MessagingGroupEntry type.
	MessagingPublicKey    []byte
	MessagingGroupKeyName []byte
	// This value is the signature of the following using the private key
	// of the GroupOwnerPublicKey (aka txn.PublicKey):
	// - Sha256DoubleHash(MessagingPublicKey || MessagingGroupKeyName)
	//
	// This signature is only required when setting up a group where
	// - MessagingGroupKeyName = "default-key"
	// In this case, we want to make sure that people don't accidentally register
	// this group name with a derived key, and forcing this signature ensures that.
	// The reason is that if someone accidentally registers the default-key with
	// the wrong public key, then they won't be able to receive messages cross-device
	// anymore.
	//
	// This field is not critical and can be removed in the future.
	GroupOwnerSignature []byte

	MessagingGroupMembers []*MessagingGroupMember
}

func (txnData *MessagingGroupMetadata) GetTxnType() TxnType {
	return TxnTypeMessagingGroup
}

func (txnData *MessagingGroupMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	data = append(data, UintToBuf(uint64(len(txnData.MessagingPublicKey)))...)
	data = append(data, txnData.MessagingPublicKey...)

	data = append(data, UintToBuf(uint64(len(txnData.MessagingGroupKeyName)))...)
	data = append(data, txnData.MessagingGroupKeyName...)

	data = append(data, UintToBuf(uint64(len(txnData.GroupOwnerSignature)))...)
	data = append(data, txnData.GroupOwnerSignature...)

	data = append(data, UintToBuf(uint64(len(txnData.MessagingGroupMembers)))...)
	for _, recipient := range txnData.MessagingGroupMembers {
		data = append(data, recipient.Encode()...)
	}

	return data, nil
}

func (txnData *MessagingGroupMetadata) FromBytes(data []byte) error {
	ret := MessagingGroupMetadata{}
	rr := bytes.NewReader(data)

	var err error
	ret.MessagingPublicKey, err = ReadVarString(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupMetadata.FromBytes: "+
			"Problem reading MessagingPublicKey")
	}

	ret.MessagingGroupKeyName, err = ReadVarString(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupMetadata.FromBytes: "+
			"Problem reading MessagingGroupKey")
	}

	ret.GroupOwnerSignature, err = ReadVarString(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupMetadata.FromBytes: "+
			"Problem reading GroupOwnerSignature")
	}

	numRecipients, err := ReadUvarint(rr)
	for ; numRecipients > 0; numRecipients-- {
		recipient := MessagingGroupMember{}
		err = recipient.Decode(rr)
		if err != nil {
			return errors.Wrapf(err, "MessagingGroupMetadata.FromBytes: "+
				"error reading recipient")
		}
		ret.MessagingGroupMembers = append(ret.MessagingGroupMembers, &recipient)
	}

	*txnData = ret
	return nil
}

func (txnData *MessagingGroupMetadata) New() DeSoTxnMetadata {
	return &MessagingGroupMetadata{}
}
