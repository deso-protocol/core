package lib

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	decredEC "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/deso-protocol/core/bls"
	merkletree "github.com/deso-protocol/go-merkle-tree"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

// network.go defines all the basic data structures that get sent over the
// network and defines precisely how they are serialized and de-serialized.

// MaxMessagePayload is the maximum size alowed for a message payload.
const MaxMessagePayload = (1024 * 1024 * 1000) // 1GB

// MaxBlockRewardDataSizeBytes is the maximum size allowed for a BLOCK_REWARD's ExtraData field.
var MaxBlockRewardDataSizeBytes = 250

// MaxHeadersPerMsg is the maximum numbers allowed in a GetHeaders response.
var MaxHeadersPerMsg = uint32(2000)

// With PoS we can afford to download more headers in each batch.
//
// TODO: I set this number really high because it's easier to lower it than it is
// to increase it (increasing requires everyone to upgrade).
var MaxHeadersPerMsgPos = uint32(200000)

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
	MsgTypeBlockBundle     MsgType = 22
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

	// MsgTypeGetSnapshot is used to retrieve state from peers.
	MsgTypeGetSnapshot  MsgType = 17
	MsgTypeSnapshotData MsgType = 18
	// MsgTypeTransactionBundleV2 contains transactions after the balance model block height from a peer.
	MsgTypeTransactionBundleV2 MsgType = 19

	// Proof of stake vote and timeout messages
	MsgTypeValidatorVote    MsgType = 20
	MsgTypeValidatorTimeout MsgType = 21

	// NEXT_TAG = 23

	// Below are control messages used to signal to the Server from other parts of
	// the code but not actually sent among peers.
	//
	// TODO: Should probably split these out into a separate channel in the server to
	// make things more parallelized.

	MsgTypeQuit                  MsgType = ControlMessagesStart
	MsgTypeDisconnectedPeer      MsgType = ControlMessagesStart + 1
	MsgTypeBlockAccepted         MsgType = ControlMessagesStart + 2
	MsgTypeBitcoinManagerUpdate  MsgType = ControlMessagesStart + 3 // Deprecated
	MsgTypePeerHandshakeComplete MsgType = ControlMessagesStart + 4
	MsgTypeNewConnection         MsgType = ControlMessagesStart + 5

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
	case MsgTypeBlockBundle:
		return "BLOCK_BUNDLE"
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
	case MsgTypeTransactionBundleV2:
		return "TRANSACTION_BUNDLE_V2"
	case MsgTypeValidatorVote:
		return "VALIDATOR_VOTE"
	case MsgTypeValidatorTimeout:
		return "VALIDATOR_TIMEOUT"
	case MsgTypeMempool:
		return "MEMPOOL"
	case MsgTypeAddr:
		return "ADDR"
	case MsgTypeGetAddr:
		return "GET_ADDR"
	case MsgTypeQuit:
		return "QUIT"
	case MsgTypeDisconnectedPeer:
		return "DONE_PEER"
	case MsgTypeBlockAccepted:
		return "BLOCK_ACCEPTED"
	case MsgTypeBitcoinManagerUpdate:
		return "BITCOIN_MANAGER_UPDATE"
	case MsgTypePeerHandshakeComplete:
		return "PEER_HANDSHAKE_COMPLETE"
	case MsgTypeNewConnection:
		return "NEW_CONNECTION"
	case MsgTypeGetSnapshot:
		return "GET_SNAPSHOT"
	case MsgTypeSnapshotData:
		return "SNAPSHOT_DATA"
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
	TxnTypeDAOCoinLimitOrder            TxnType = 26
	TxnTypeCreateUserAssociation        TxnType = 27
	TxnTypeDeleteUserAssociation        TxnType = 28
	TxnTypeCreatePostAssociation        TxnType = 29
	TxnTypeDeletePostAssociation        TxnType = 30
	TxnTypeAccessGroup                  TxnType = 31
	TxnTypeAccessGroupMembers           TxnType = 32
	TxnTypeNewMessage                   TxnType = 33
	TxnTypeRegisterAsValidator          TxnType = 34
	TxnTypeUnregisterAsValidator        TxnType = 35
	TxnTypeStake                        TxnType = 36
	TxnTypeUnstake                      TxnType = 37
	TxnTypeUnlockStake                  TxnType = 38
	TxnTypeUnjailValidator              TxnType = 39
	TxnTypeCoinLockup                   TxnType = 40
	TxnTypeUpdateCoinLockupParams       TxnType = 41
	TxnTypeCoinLockupTransfer           TxnType = 42
	TxnTypeCoinUnlock                   TxnType = 43
	TxnTypeAtomicTxnsWrapper            TxnType = 44

	// NEXT_ID = 44
)

type TxnString string

const (
	TxnStringUndefined                    TxnString = "TXN_UNDEFINED"
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
	TxnStringDAOCoinLimitOrder            TxnString = "DAO_COIN_LIMIT_ORDER"
	TxnStringCreateUserAssociation        TxnString = "CREATE_USER_ASSOCIATION"
	TxnStringDeleteUserAssociation        TxnString = "DELETE_USER_ASSOCIATION"
	TxnStringCreatePostAssociation        TxnString = "CREATE_POST_ASSOCIATION"
	TxnStringDeletePostAssociation        TxnString = "DELETE_POST_ASSOCIATION"
	TxnStringAccessGroup                  TxnString = "ACCESS_GROUP"
	TxnStringAccessGroupMembers           TxnString = "ACCESS_GROUP_MEMBERS"
	TxnStringNewMessage                   TxnString = "NEW_MESSAGE"
	TxnStringRegisterAsValidator          TxnString = "REGISTER_AS_VALIDATOR"
	TxnStringUnregisterAsValidator        TxnString = "UNREGISTER_AS_VALIDATOR"
	TxnStringStake                        TxnString = "STAKE"
	TxnStringUnstake                      TxnString = "UNSTAKE"
	TxnStringUnlockStake                  TxnString = "UNLOCK_STAKE"
	TxnStringUnjailValidator              TxnString = "UNJAIL_VALIDATOR"
	TxnStringCoinLockup                   TxnString = "COIN_LOCKUP"
	TxnStringUpdateCoinLockupParams       TxnString = "UPDATE_COIN_LOCKUP_PARAMS"
	TxnStringCoinLockupTransfer           TxnString = "COIN_LOCKUP_TRANSFER"
	TxnStringCoinUnlock                   TxnString = "COIN_UNLOCK"
	TxnStringAtomicTxnsWrapper            TxnString = "ATOMIC_TXNS_WRAPPER"
)

var (
	AllTxnTypes = []TxnType{
		TxnTypeUnset, TxnTypeBlockReward, TxnTypeBasicTransfer, TxnTypeBitcoinExchange, TxnTypePrivateMessage,
		TxnTypeSubmitPost, TxnTypeUpdateProfile, TxnTypeUpdateBitcoinUSDExchangeRate, TxnTypeFollow, TxnTypeLike,
		TxnTypeCreatorCoin, TxnTypeSwapIdentity, TxnTypeUpdateGlobalParams, TxnTypeCreatorCoinTransfer,
		TxnTypeCreateNFT, TxnTypeUpdateNFT, TxnTypeAcceptNFTBid, TxnTypeNFTBid, TxnTypeNFTTransfer,
		TxnTypeAcceptNFTTransfer, TxnTypeBurnNFT, TxnTypeAuthorizeDerivedKey, TxnTypeMessagingGroup,
		TxnTypeDAOCoin, TxnTypeDAOCoinTransfer, TxnTypeDAOCoinLimitOrder, TxnTypeCreateUserAssociation,
		TxnTypeDeleteUserAssociation, TxnTypeCreatePostAssociation, TxnTypeDeletePostAssociation,
		TxnTypeAccessGroup, TxnTypeAccessGroupMembers, TxnTypeNewMessage, TxnTypeRegisterAsValidator,
		TxnTypeUnregisterAsValidator, TxnTypeStake, TxnTypeUnstake, TxnTypeUnlockStake, TxnTypeUnjailValidator,
		TxnTypeCoinLockup, TxnTypeUpdateCoinLockupParams, TxnTypeCoinLockupTransfer, TxnTypeCoinUnlock,
		TxnTypeAtomicTxnsWrapper,
	}
	AllTxnString = []TxnString{
		TxnStringUnset, TxnStringBlockReward, TxnStringBasicTransfer, TxnStringBitcoinExchange, TxnStringPrivateMessage,
		TxnStringSubmitPost, TxnStringUpdateProfile, TxnStringUpdateBitcoinUSDExchangeRate, TxnStringFollow, TxnStringLike,
		TxnStringCreatorCoin, TxnStringSwapIdentity, TxnStringUpdateGlobalParams, TxnStringCreatorCoinTransfer,
		TxnStringCreateNFT, TxnStringUpdateNFT, TxnStringAcceptNFTBid, TxnStringNFTBid, TxnStringNFTTransfer,
		TxnStringAcceptNFTTransfer, TxnStringBurnNFT, TxnStringAuthorizeDerivedKey, TxnStringMessagingGroup,
		TxnStringDAOCoin, TxnStringDAOCoinTransfer, TxnStringDAOCoinLimitOrder, TxnStringCreateUserAssociation,
		TxnStringDeleteUserAssociation, TxnStringCreatePostAssociation, TxnStringDeletePostAssociation,
		TxnStringAccessGroup, TxnStringAccessGroupMembers, TxnStringNewMessage, TxnStringRegisterAsValidator,
		TxnStringUnregisterAsValidator, TxnStringStake, TxnStringUnstake, TxnStringUnlockStake, TxnStringUnjailValidator,
		TxnStringCoinLockup, TxnStringUpdateCoinLockupParams, TxnStringCoinLockupTransfer, TxnStringCoinUnlock,
		TxnStringAtomicTxnsWrapper,
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
	case TxnTypeDAOCoinLimitOrder:
		return TxnStringDAOCoinLimitOrder
	case TxnTypeCreateUserAssociation:
		return TxnStringCreateUserAssociation
	case TxnTypeDeleteUserAssociation:
		return TxnStringDeleteUserAssociation
	case TxnTypeCreatePostAssociation:
		return TxnStringCreatePostAssociation
	case TxnTypeDeletePostAssociation:
		return TxnStringDeletePostAssociation
	case TxnTypeAccessGroup:
		return TxnStringAccessGroup
	case TxnTypeAccessGroupMembers:
		return TxnStringAccessGroupMembers
	case TxnTypeNewMessage:
		return TxnStringNewMessage
	case TxnTypeRegisterAsValidator:
		return TxnStringRegisterAsValidator
	case TxnTypeUnregisterAsValidator:
		return TxnStringUnregisterAsValidator
	case TxnTypeStake:
		return TxnStringStake
	case TxnTypeUnstake:
		return TxnStringUnstake
	case TxnTypeUnlockStake:
		return TxnStringUnlockStake
	case TxnTypeUnjailValidator:
		return TxnStringUnjailValidator
	case TxnTypeCoinLockup:
		return TxnStringCoinLockup
	case TxnTypeUpdateCoinLockupParams:
		return TxnStringUpdateCoinLockupParams
	case TxnTypeCoinLockupTransfer:
		return TxnStringCoinLockupTransfer
	case TxnTypeCoinUnlock:
		return TxnStringCoinUnlock
	case TxnTypeAtomicTxnsWrapper:
		return TxnStringAtomicTxnsWrapper
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
	case TxnStringDAOCoinLimitOrder:
		return TxnTypeDAOCoinLimitOrder
	case TxnStringCreateUserAssociation:
		return TxnTypeCreateUserAssociation
	case TxnStringDeleteUserAssociation:
		return TxnTypeDeleteUserAssociation
	case TxnStringCreatePostAssociation:
		return TxnTypeCreatePostAssociation
	case TxnStringDeletePostAssociation:
		return TxnTypeDeletePostAssociation
	case TxnStringAccessGroup:
		return TxnTypeAccessGroup
	case TxnStringAccessGroupMembers:
		return TxnTypeAccessGroupMembers
	case TxnStringNewMessage:
		return TxnTypeNewMessage
	case TxnStringRegisterAsValidator:
		return TxnTypeRegisterAsValidator
	case TxnStringUnregisterAsValidator:
		return TxnTypeUnregisterAsValidator
	case TxnStringStake:
		return TxnTypeStake
	case TxnStringUnstake:
		return TxnTypeUnstake
	case TxnStringUnlockStake:
		return TxnTypeUnlockStake
	case TxnStringUnjailValidator:
		return TxnTypeUnjailValidator
	case TxnStringCoinLockup:
		return TxnTypeCoinLockup
	case TxnStringUpdateCoinLockupParams:
		return TxnTypeUpdateCoinLockupParams
	case TxnStringCoinLockupTransfer:
		return TxnTypeCoinLockupTransfer
	case TxnStringCoinUnlock:
		return TxnTypeCoinUnlock
	case TxnStringAtomicTxnsWrapper:
		return TxnTypeAtomicTxnsWrapper
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
	case TxnTypeDAOCoinLimitOrder:
		return (&DAOCoinLimitOrderMetadata{}).New(), nil
	case TxnTypeCreateUserAssociation:
		return (&CreateUserAssociationMetadata{}).New(), nil
	case TxnTypeDeleteUserAssociation:
		return (&DeleteUserAssociationMetadata{}).New(), nil
	case TxnTypeCreatePostAssociation:
		return (&CreatePostAssociationMetadata{}).New(), nil
	case TxnTypeDeletePostAssociation:
		return (&DeletePostAssociationMetadata{}).New(), nil
	case TxnTypeAccessGroup:
		return (&AccessGroupMetadata{}).New(), nil
	case TxnTypeAccessGroupMembers:
		return (&AccessGroupMembersMetadata{}).New(), nil
	case TxnTypeNewMessage:
		return (&NewMessageMetadata{}).New(), nil
	case TxnTypeRegisterAsValidator:
		return (&RegisterAsValidatorMetadata{}).New(), nil
	case TxnTypeUnregisterAsValidator:
		return (&UnregisterAsValidatorMetadata{}).New(), nil
	case TxnTypeStake:
		return (&StakeMetadata{}).New(), nil
	case TxnTypeUnstake:
		return (&UnstakeMetadata{}).New(), nil
	case TxnTypeUnlockStake:
		return (&UnlockStakeMetadata{}).New(), nil
	case TxnTypeUnjailValidator:
		return (&UnjailValidatorMetadata{}).New(), nil
	case TxnTypeCoinLockup:
		return (&CoinLockupMetadata{}).New(), nil
	case TxnTypeUpdateCoinLockupParams:
		return (&UpdateCoinLockupParamsMetadata{}).New(), nil
	case TxnTypeCoinLockupTransfer:
		return (&CoinLockupTransferMetadata{}).New(), nil
	case TxnTypeCoinUnlock:
		return (&CoinUnlockMetadata{}).New(), nil
	case TxnTypeAtomicTxnsWrapper:
		return (&AtomicTxnsWrapperMetadata{}).New(), nil
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
	payload, err := SafeMakeSliceWithLength[byte](payloadLength)
	if err != nil {
		return nil, nil, fmt.Errorf("ReadMessage: PRoblem creating slice of length %v for payload", payloadLength)
	}
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
		return &MsgDeSoVersion{}
	case MsgTypeVerack:
		return &MsgDeSoVerack{}
	case MsgTypeHeader:
		return &MsgDeSoHeader{
			PrevBlockHash:         &BlockHash{},
			TransactionMerkleRoot: &BlockHash{},
		}
	case MsgTypeBlock:
		return &MsgDeSoBlock{
			Header: NewMessage(MsgTypeHeader).(*MsgDeSoHeader),
		}
	case MsgTypeTxn:
		return &MsgDeSoTxn{}
	case MsgTypePing:
		return &MsgDeSoPing{}
	case MsgTypePong:
		return &MsgDeSoPong{}
	case MsgTypeInv:
		return &MsgDeSoInv{}
	case MsgTypeGetBlocks:
		return &MsgDeSoGetBlocks{}
	case MsgTypeGetTransactions:
		return &MsgDeSoGetTransactions{}
	case MsgTypeTransactionBundle:
		return &MsgDeSoTransactionBundle{}
	case MsgTypeTransactionBundleV2:
		return &MsgDeSoTransactionBundleV2{}
	case MsgTypeValidatorVote:
		return &MsgDeSoValidatorVote{}
	case MsgTypeValidatorTimeout:
		return &MsgDeSoValidatorTimeout{}
	case MsgTypeMempool:
		return &MsgDeSoMempool{}
	case MsgTypeGetHeaders:
		return &MsgDeSoGetHeaders{}
	case MsgTypeHeaderBundle:
		return &MsgDeSoHeaderBundle{}
	case MsgTypeBlockBundle:
		return &MsgDeSoBlockBundle{}
	case MsgTypeAddr:
		return &MsgDeSoAddr{}
	case MsgTypeGetAddr:
		return &MsgDeSoGetAddr{}
	case MsgTypeGetSnapshot:
		return &MsgDeSoGetSnapshot{}
	case MsgTypeSnapshotData:
		return &MsgDeSoSnapshotData{}
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

type MsgDeSoDisconnectedPeer struct {
}

func (msg *MsgDeSoDisconnectedPeer) GetMsgType() MsgType {
	return MsgTypeDisconnectedPeer
}

func (msg *MsgDeSoDisconnectedPeer) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgDeSoDisconnectedPeer.ToBytes: Not implemented")
}

func (msg *MsgDeSoDisconnectedPeer) FromBytes(data []byte) error {
	return fmt.Errorf("MsgDeSoDisconnectedPeer.FromBytes not implemented")
}

type ConnectionType uint8

const (
	ConnectionTypeOutbound ConnectionType = iota
	ConnectionTypeInbound
)

type Connection interface {
	GetConnectionType() ConnectionType
	Close()
}

type MsgDeSoNewConnection struct {
	Connection Connection
}

func (msg *MsgDeSoNewConnection) GetMsgType() MsgType {
	return MsgTypeNewConnection
}

func (msg *MsgDeSoNewConnection) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgDeSoNewConnection.ToBytes: Not implemented")
}

func (msg *MsgDeSoNewConnection) FromBytes(data []byte) error {
	return fmt.Errorf("MsgDeSoNewConnection.FromBytes not implemented")
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
// BLOCK_BUNDLE message
// ==================================================================

type MsgDeSoBlockBundle struct {
	Version   uint8
	Blocks    []*MsgDeSoBlock
	TipHash   *BlockHash
	TipHeight uint64
}

func (msg *MsgDeSoBlockBundle) GetMsgType() MsgType {
	return MsgTypeBlockBundle
}

func (msg *MsgDeSoBlockBundle) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Encode the version of the bundle.
	data = append(data, msg.Version)

	// Encode the number of blocks in the bundle.
	data = append(data, UintToBuf(uint64(len(msg.Blocks)))...)

	// Encode all the blocks.
	for _, block := range msg.Blocks {
		blockBytes, err := block.ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "MsgDeSoBlockBundle.ToBytes: Problem encoding block")
		}
		data = append(data, EncodeByteArray(blockBytes)...)
	}

	// Encode the tip hash.
	data = append(data, msg.TipHash[:]...)

	// Encode the tip height.
	data = append(data, UintToBuf(uint64(msg.TipHeight))...)

	return data, nil
}

func (msg *MsgDeSoBlockBundle) FromBytes(data []byte) error {
	var err error

	rr := bytes.NewReader(data)
	retBundle := NewMessage(MsgTypeBlockBundle).(*MsgDeSoBlockBundle)

	// Read the version of the bundle.
	retBundle.Version, err = rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoBlockBundle.FromBytes: Problem decoding version")
	}

	// For now, only version is supported for the block bundle message type.
	if retBundle.Version != 0 {
		return fmt.Errorf("MsgDeSoBlockBundle.FromBytes: Unsupported version %d", retBundle.Version)
	}

	// Read in the number of block in the bundle.
	numBlocks, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoBlockBundle.FromBytes: Problem decoding number of block")
	}

	// Read in all of the blocks.
	for ii := uint64(0); ii < numBlocks; ii++ {
		blockBytes, err := DecodeByteArray(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoBlockBundle.FromBytes: Problem decoding block: ")
		}
		retBlock := &MsgDeSoBlock{}
		if err := retBlock.FromBytes(blockBytes); err != nil {
			return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: ")
		}

		retBundle.Blocks = append(retBundle.Blocks, retBlock)
	}

	// Read in the tip hash.
	retBundle.TipHash = &BlockHash{}
	_, err = io.ReadFull(rr, retBundle.TipHash[:])
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoBlockBundle.FromBytes:: Error reading TipHash: ")
	}

	// Read in the tip height.
	tipHeight, err := ReadUvarint(rr)
	if err != nil || tipHeight > math.MaxUint32 {
		return fmt.Errorf("MsgDeSoBlockBundle.FromBytes: %v", err)
	}
	retBundle.TipHeight = tipHeight

	*msg = *retBundle
	return nil
}

func (msg *MsgDeSoBlockBundle) String() string {
	return fmt.Sprintf("Num Blocks: %v, Tip Height: %v, Tip Hash: %v, Blocks: %v", len(msg.Blocks), msg.TipHeight, msg.TipHash, msg.Blocks)
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

	// We can safely increase this without breaking backwards-compatibility because old
	// nodes will never send us more hashes than this.
	if len(msg.HashList) > MaxBlocksInFlightPoS {
		return nil, fmt.Errorf("MsgDeSoGetBlocks.ToBytes: Blocks requested %d "+
			"exceeds MaxBlocksInFlightPoS %d", len(msg.HashList), MaxBlocksInFlightPoS)
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

	// Parse the number of block hashes.
	numHashes, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoGetBlocks.FromBytes: Problem "+
			"reading number of block hashes requested")
	}
	// We can safely increase this without breaking backwards-compatibility because old
	// nodes will never send us more hashes than this.
	if numHashes > MaxBlocksInFlightPoS {
		return fmt.Errorf("MsgDeSoGetBlocks.FromBytes: HashList length (%d) "+
			"exceeds maximum allowed (%d)", numHashes, MaxBlocksInFlightPoS)
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
// (DEPRECATED) TransactionBundle message
// 	- After the BalanceModelBlockHeight, nodes should rely on TransactionBundleV2.
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

	// Read in all the transactions.
	for ii := uint64(0); ii < numTransactions; ii++ {
		retTransaction := NewMessage(MsgTypeTxn).(*MsgDeSoTxn)

		if err := ReadTransactionV0Fields(rr, retTransaction); err != nil {
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
// TransactionBundleV2 message
//   - Note that the crucial difference between the original TransactionBundle and
//     TransactionBundleV2 is that TransactionBundleV2 includes the number of bytes per
//     transaction in the transaction serialization.
//   - This was needed when we switched
//     from UTXOs to a balance model because we had to add a field to the end of MsgDeSoTxn,
//     which meant we could no longer implicitly determine where one transaction ended and
//     another began within a bundle. Hence the need for a new v2 bundle type that encodes
//     the number of bytes per txn.
// ==================================================================

type MsgDeSoTransactionBundleV2 struct {
	Transactions []*MsgDeSoTxn
}

func (msg *MsgDeSoTransactionBundleV2) GetMsgType() MsgType {
	return MsgTypeTransactionBundleV2
}

func (msg *MsgDeSoTransactionBundleV2) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Encode the number of transactions in the bundle.
	data = append(data, UintToBuf(uint64(len(msg.Transactions)))...)

	// Encode all the transactions.
	for _, transaction := range msg.Transactions {
		transactionBytes, err := transaction.ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "MsgDeSoTransactionBundleV2.ToBytes: Problem encoding transaction")
		}
		// The number of bytes in each txn is the only difference between v2 bundles and v1 bundles.
		data = append(data, UintToBuf(uint64(len(transactionBytes)))...)
		// Encode the txn just like in v1 bundles.
		data = append(data, transactionBytes...)
	}

	return data, nil
}

func (msg *MsgDeSoTransactionBundleV2) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retBundle := NewMessage(MsgTypeTransactionBundleV2).(*MsgDeSoTransactionBundleV2)

	// Read in the number of transactions in the bundle.
	numTransactions, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoTransactionBundleV2.FromBytes: Problem decoding number of transaction")
	}

	retBundle.Transactions = make([]*MsgDeSoTxn, 0)
	for ii := uint64(0); ii < numTransactions; ii++ {
		txBytesLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Problem decoding txn length")
		}
		if txBytesLen > MaxMessagePayload {
			return fmt.Errorf(
				"MsgDeSoBlock.FromBytes: Txn %d length %d longer than max %d",
				ii, txBytesLen, MaxMessagePayload)
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
		retBundle.Transactions = append(retBundle.Transactions, currentTxn)
	}

	*msg = *retBundle
	return nil
}

func (msg *MsgDeSoTransactionBundleV2) String() string {
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
	// After PoS, we have blocks every second rather than every five minutes, and blocks
	// are smaller. As such, we can safely increase this limit.
	//
	// TODO: This is a pretty large value. Blocks were processing at ~80 blocks per second
	// when I last ran it. If we can't get the blocks per second to a higher value, then
	// we should probably decrease this value.
	MaxBlocksInFlightPoS = 25000
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
			return nil, errors.Wrapf(err, "_readInvList: Error reading Hash for InvVect: ")
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
	isSyncResponse, err := ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoInv: ")
	}

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
	// SFFullNodeDeprecated is deprecated, and set on all nodes by default now.
	SFFullNodeDeprecated ServiceFlag = 1 << 0
	// SFHyperSync is a flag used to indicate that the peer supports hyper sync.
	SFHyperSync ServiceFlag = 1 << 1
	// SFArchivalNode is a flag complementary to SFHyperSync. If node is a hypersync node then
	// it might not be able to support block sync anymore, unless it has archival mode turned on.
	SFArchivalNode ServiceFlag = 1 << 2
	// SFPosValidator is a flag used to indicate that the peer is running a PoS validator.
	SFPosValidator ServiceFlag = 1 << 3
)

func (sf ServiceFlag) HasService(serviceFlag ServiceFlag) bool {
	return sf&serviceFlag == serviceFlag
}

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
	LatestBlockHeight uint64

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

	// LatestBlockHeight
	retBytes = append(retBytes, UintToBuf(msg.LatestBlockHeight)...)

	// MinFeeRateNanosPerKB
	retBytes = append(retBytes, UintToBuf(msg.MinFeeRateNanosPerKB)...)

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
		userAgent, err := SafeMakeSliceWithLength[byte](strLen)
		if err != nil {
			return fmt.Errorf("MsgDeSoVersion.FromBytes: PRoblem creating slice of length %d for user agent", strLen)
		}
		_, err = io.ReadFull(rr, userAgent)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoVersion.FromBytes: Error reading msg.UserAgent")
		}
		retVer.UserAgent = string(userAgent)
	}

	// LatestBlockHeight
	{
		latestBlockHeight, err := ReadUvarint(rr)
		if err != nil || latestBlockHeight > math.MaxUint32 {
			return errors.Wrapf(err, "MsgDeSoVersion.FromBytes: Problem converting msg.LatestBlockHeight")
		}
		retVer.LatestBlockHeight = latestBlockHeight
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
		currentAddrIPSlice, err := SafeMakeSliceWithLength[byte](ipLen)
		if err != nil {
			return fmt.Errorf("MsgDeSoAddr.FromBytes: Problem making slice of length %d for currentAddr.IP", ipLen)
		}
		currentAddr.IP = net.IP(currentAddrIPSlice)
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

type VerackVersion uint64

func NewVerackVersion(version uint64) VerackVersion {
	return VerackVersion(version)
}

const (
	VerackVersion0 VerackVersion = 0
	VerackVersion1 VerackVersion = 1
)

func (vv VerackVersion) ToUint64() uint64 {
	return uint64(vv)
}

type MsgDeSoVerack struct {
	// The VerackVersion0 message contains only the NonceReceived field, which is the nonce the sender received in the
	// initial version message from the peer. This ensures the sender controls the network address, similarly to the
	// "SYN Cookie" DDOS protection. The Version field in the VerackVersion0 message is implied, based on the msg length.
	//
	// The VerackVersion1 message contains the tuple of <NonceReceived, NonceSent, TstampMicro> which correspond to the
	// received and sent nonces in the version message from the sender's perspective, as well as a recent timestamp.
	// The VerackVersion1 message is used in context of Proof of Stake, where validators register their BLS public keys
	// as part of their validator entry. The sender of this message must be a registered validator, and he must attach
	// their public key to the message, along with a BLS signature of the <NonceReceived, NonceSent, TstampMicro> tuple.
	Version VerackVersion

	NonceReceived uint64
	NonceSent     uint64
	TstampMicro   uint64

	PublicKey *bls.PublicKey
	Signature *bls.Signature
}

func (msg *MsgDeSoVerack) ToBytes(preSignature bool) ([]byte, error) {
	switch msg.Version {
	case VerackVersion0:
		return msg.EncodeVerackV0()
	case VerackVersion1:
		return msg.EncodeVerackV1()
	default:
		return nil, fmt.Errorf("MsgDeSoVerack.ToBytes: Unrecognized version: %v", msg.Version)
	}
}

func (msg *MsgDeSoVerack) EncodeVerackV0() ([]byte, error) {
	retBytes := []byte{}

	// Nonce
	retBytes = append(retBytes, UintToBuf(msg.NonceReceived)...)
	return retBytes, nil
}

func (msg *MsgDeSoVerack) EncodeVerackV1() ([]byte, error) {
	retBytes := []byte{}

	// Version
	retBytes = append(retBytes, UintToBuf(msg.Version.ToUint64())...)
	// Nonce Received
	retBytes = append(retBytes, UintToBuf(msg.NonceReceived)...)
	// Nonce Sent
	retBytes = append(retBytes, UintToBuf(msg.NonceSent)...)
	// Tstamp Micro
	retBytes = append(retBytes, UintToBuf(msg.TstampMicro)...)
	// PublicKey
	retBytes = append(retBytes, EncodeBLSPublicKey(msg.PublicKey)...)
	// Signature
	retBytes = append(retBytes, EncodeBLSSignature(msg.Signature)...)

	return retBytes, nil
}

func (msg *MsgDeSoVerack) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	// The V0 verack message is determined from the message length. The V0 message will only contain the NonceReceived field.
	if len(data) <= MaxVarintLen64 {
		return msg.FromBytesV0(data)
	}

	version, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoVerack.FromBytes: Problem reading Version")
	}
	msg.Version = NewVerackVersion(version)
	switch msg.Version {
	case VerackVersion0:
		return fmt.Errorf("MsgDeSoVerack.FromBytes: Outdated Version=0 used for new encoding")
	case VerackVersion1:
		return msg.FromBytesV1(data)
	default:
		return fmt.Errorf("MsgDeSoVerack.FromBytes: Unrecognized version: %v", msg.Version)
	}
}

func (msg *MsgDeSoVerack) FromBytesV0(data []byte) error {
	var err error
	rr := bytes.NewReader(data)
	msg.NonceReceived, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoVerack.FromBytes: Problem reading Nonce")
	}
	return nil
}

func (msg *MsgDeSoVerack) FromBytesV1(data []byte) error {
	var err error
	rr := bytes.NewReader(data)
	version, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoVerack.FromBytes: Problem reading Version")
	}
	msg.Version = NewVerackVersion(version)

	msg.NonceReceived, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoVerack.FromBytes: Problem reading Nonce Received")
	}

	msg.NonceSent, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoVerack.FromBytes: Problem reading Nonce Sent")
	}

	msg.TstampMicro, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoVerack.FromBytes: Problem reading Tstamp Micro")
	}

	msg.PublicKey, err = DecodeBLSPublicKey(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoVerack.FromBytes: Problem reading PublicKey")
	}

	msg.Signature, err = DecodeBLSSignature(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoVerack.FromBytes: Problem reading Signature")
	}
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

	// The original TstampSecs struct field is deprecated and replaced by the higher resolution
	// TstampNanoSecs field. The deprecation is backwards compatible for all existing header
	// versions and byte encodings. To read or write timestamps with the old 1-second resolution,
	// use the SetTstampSecs() and GetTstampSecs() public methods.

	// The unix timestamp (in nanoseconds) specifying when this block was produced.
	TstampNanoSecs int64

	// The height of the block this header corresponds to.
	Height uint64

	// Nonce is only used for Proof of Work blocks, with MsgDeSoHeader versions 0 and 1.
	// For all later versions, this field will default to a value of zero.
	//
	// The nonce that is used by miners in order to produce valid blocks.
	//
	// Note: Before the upgrade from HeaderVersion0 to HeaderVersion1, miners would make
	// use of ExtraData in the BlockRewardMetadata to get extra nonces. However, this is
	// no longer needed since HeaderVersion1 upgraded the nonce to 64 bits from 32 bits.
	Nonce uint64

	// ExtraNonce is only used for Proof of Work blocks, with MsgDeSoHeader versions 0 and 1.
	// For all later versions, this field will default to zero.
	//
	// An extra nonce that can be used to provide *even more* entropy for miners, in the
	// event that ASICs become powerful enough to have birthday problems in the future.
	ExtraNonce uint64

	// ProposerVotingPublicKey is only used for Proof of Stake blocks, starting with
	// MsgDeSoHeader version 2. For all earlier versions, this field will default to nil.
	//
	// The BLS public key of the validator who proposed this block.
	ProposerVotingPublicKey *bls.PublicKey

	// ProposerRandomSeedSignature is only used for Proof of Stake blocks, starting with
	// MsgDeSoHeader version 2. For all earlier versions, this field will default to nil.
	//
	// The current block's randomness seed provided by the block's proposer.
	ProposerRandomSeedSignature *bls.Signature

	// ProposedInView is only used for Proof of Stake blocks, starting with MsgDeSoHeader
	// version 2. For all earlier versions, this field will default to nil.
	//
	// The view in which this block was proposed.
	ProposedInView uint64

	// ValidatorsVoteQC is only used for Proof of Stake blocks, starting with MsgDeSoHeader
	// version 2. For all earlier versions, this field will default to nil.
	//
	// This is a QC containing votes from 2/3 of validators weighted by stake.
	ValidatorsVoteQC *QuorumCertificate

	// ValidatorsTimeoutAggregateQC is only used for Proof of Stake blocks, starting with
	// MsgDeSoHeader version 2. For all earlier versions, this field will default to nil.
	//
	// In the event of a timeout, this field will contain the aggregate QC constructed from
	// timeout messages from 2/3 of validators weighted by stake, and proves that they have
	// timed out. This value is set to nil in normal cases where a regular block vote has
	// taken place.
	ValidatorsTimeoutAggregateQC *TimeoutAggregateQuorumCertificate

	// ProposerVotePartialSignature is only used for Proof of Stake blocks, starting with
	// MsgDeSoHeader version 2. For all earlier versions, this field will default to nil.
	//
	// The block proposer's partial BLS signature of the (ProposedInView, BlockHash) pair
	// for the block. This signature proves that a particular validator proposed the block,
	// and also acts as the proposer's vote for the block.
	ProposerVotePartialSignature *bls.Signature
}

func (msg *MsgDeSoHeader) GetHeight() uint64 {
	return msg.Height
}

func HeaderSizeBytes() int {
	header := NewMessage(MsgTypeHeader)
	headerBytes, _ := header.ToBytes(false)
	return len(headerBytes)
}

func (msg *MsgDeSoHeader) SetTstampSecs(tstampSecs int64) {
	msg.TstampNanoSecs = SecondsToNanoSeconds(tstampSecs)
}

func (msg *MsgDeSoHeader) GetTstampSecs() int64 {
	return NanoSecondsToSeconds(msg.TstampNanoSecs)
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
		binary.LittleEndian.PutUint32(scratchBytes[:], uint32(msg.GetTstampSecs()))
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
		binary.BigEndian.PutUint64(scratchBytes[:], uint64(msg.GetTstampSecs()))
		retBytes = append(retBytes, scratchBytes[:]...)

		// TODO: Don't allow this field to exceed 32-bits for now. This will
		// adjust once other parts of the code are fixed to handle the wider
		// type.
		if msg.GetTstampSecs() > math.MaxUint32 {
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

func (msg *MsgDeSoHeader) EncodeHeaderVersion2(preSignature bool) ([]byte, error) {
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

	// TstampNanosSecs: this field can be encoded to take up to the full 64 bits now
	// that MsgDeSoHeader version 2 does not need to be backwards compatible.
	retBytes = append(retBytes, IntToBuf(msg.TstampNanoSecs)...)

	// Height: similar to the field above, this field can be encoded to take
	// up to the full 64 bits now that MsgDeSoHeader version 2 does not need to
	// be backwards compatible.
	retBytes = append(retBytes, UintToBuf(msg.Height)...)

	// The Nonce and ExtraNonce fields are unused in version 2. We skip them
	// during both encoding and decoding.

	// ProposerVotingPublicKey
	if msg.ProposerVotingPublicKey == nil {
		return nil, fmt.Errorf("EncodeHeaderVersion2: ProposerVotingPublicKey must be non-nil")
	}
	retBytes = append(retBytes, EncodeBLSPublicKey(msg.ProposerVotingPublicKey)...)

	// ProposerRandomSeedSignature
	if msg.ProposerRandomSeedSignature == nil {
		return nil, fmt.Errorf("EncodeHeaderVersion2: ProposerRandomSeedSignature must be non-nil")
	}
	retBytes = append(retBytes, EncodeOptionalBLSSignature(msg.ProposerRandomSeedSignature)...)

	// ProposedInView
	retBytes = append(retBytes, UintToBuf(msg.ProposedInView)...)

	// Only one of ValidatorsVoteQC or ValidatorsTimeoutAggregateQC must be defined.
	if (msg.ValidatorsVoteQC == nil) == (msg.ValidatorsTimeoutAggregateQC == nil) {
		return nil, fmt.Errorf(
			"EncodeHeaderVersion2: Exactly one of ValidatorsVoteQC or ValidatorsTimeoutAggregateQC must be non-nil",
		)
	}

	// ValidatorsVoteQC
	encodedValidatorsVoteQC, err := EncodeQuorumCertificate(msg.ValidatorsVoteQC)
	if err != nil {
		return nil, errors.Wrapf(err, "EncodeHeaderVersion2: error encoding ValidatorsVoteQC")
	}
	retBytes = append(retBytes, encodedValidatorsVoteQC...)

	// ValidatorsTimeoutAggregateQC
	encodedValidatorsTimeoutAggregateQC, err := EncodeTimeoutAggregateQuorumCertificate(msg.ValidatorsTimeoutAggregateQC)
	if err != nil {
		return nil, errors.Wrapf(err, "EncodeHeaderVersion2: error encoding ValidatorsTimeoutAggregateQC")
	}
	retBytes = append(retBytes, encodedValidatorsTimeoutAggregateQC...)

	// If preSignature=false, then the ProposerVotePartialSignature must be populated.
	if !preSignature && msg.ProposerVotePartialSignature == nil {
		return nil, fmt.Errorf("EncodeHeaderVersion2: ProposerVotePartialSignature must be non-nil when preSignature=false")
	}

	// ProposerVotePartialSignature: we encode the signature if it's present and the preSignature
	// flag is set to false. Otherwise, we encode an empty byte array as a placeholder. The placeholder
	// ensures that the DecodeHeaderVersion2 function can properly recognize encodings where the signature
	// isn't populated. It ensures that every possible output from EncodeHeaderVersion2 can be decoded by
	// DecodeHeaderVersion2.
	if preSignature {
		retBytes = append(retBytes, EncodeOptionalBLSSignature(nil)...)
	} else {
		retBytes = append(retBytes, EncodeOptionalBLSSignature(msg.ProposerVotePartialSignature)...)
	}

	return retBytes, nil
}

func (msg *MsgDeSoHeader) ToBytes(preSignature bool) ([]byte, error) {
	// Depending on the version, we decode the header differently.
	if msg.Version == HeaderVersion0 {
		return msg.EncodeHeaderVersion0(preSignature)
	} else if msg.Version == HeaderVersion1 {
		return msg.EncodeHeaderVersion1(preSignature)
	} else if msg.Version == HeaderVersion2 {
		return msg.EncodeHeaderVersion2(preSignature)
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
		retHeader.SetTstampSecs(int64(binary.LittleEndian.Uint32(scratchBytes[:])))
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
		retHeader.SetTstampSecs(int64(binary.BigEndian.Uint64(scratchBytes[:])))
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

func DecodeHeaderVersion2(rr io.Reader) (*MsgDeSoHeader, error) {
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

	// TstampNanoSecs
	retHeader.TstampNanoSecs, err = ReadVarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding TstampNanoSecs")
	}

	// Height
	retHeader.Height, err = ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding Height")
	}

	// The Nonce and ExtraNonce fields are unused in version 2. We skip them
	// during both encoding and decoding.
	retHeader.Nonce = 0
	retHeader.ExtraNonce = 0

	// ProposerVotingPublicKey
	retHeader.ProposerVotingPublicKey, err = DecodeBLSPublicKey(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding ProposerVotingPublicKey")
	}

	// ProposerRandomSeedSignature
	retHeader.ProposerRandomSeedSignature, err = DecodeOptionalBLSSignature(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding ProposerRandomSeedSignature")
	}

	// ProposedInView
	retHeader.ProposedInView, err = ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding ProposedInView")
	}

	// ValidatorsVoteQC
	retHeader.ValidatorsVoteQC, err = DecodeQuorumCertificate(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding ValidatorsVoteQC")
	}

	// ValidatorsTimeoutAggregateQC
	retHeader.ValidatorsTimeoutAggregateQC, err = DecodeTimeoutAggregateQuorumCertificate(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding ValidatorsTimeoutAggregateQC")
	}

	// ProposerVotePartialSignature: we decode the signature if it's present in the byte encoding.
	// If it's not present, then we set the signature to nil.
	retHeader.ProposerVotePartialSignature, err = DecodeOptionalBLSSignature(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgDeSoHeader.FromBytes: Problem decoding ProposerVotePartialSignature")
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
	} else if headerVersion == HeaderVersion2 {
		ret, err = DecodeHeaderVersion2(rr)
	} else {
		// If we have an unrecognized version then we return an error. The schema
		// differences between header versions 0, 1, 2, and beyond will be large
		// enough that no one decoder is a safe fallback.
		err = fmt.Errorf("DecodeHeader: Unrecognized header version: %v", headerVersion)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeHeader: Error parsing header:")
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

// Hash is a helper function to compute a hash of the header. For Proof of Work
// blocks headers, which have header version 0 or 1, this uses the specialized
// ProofOfWorkHash, which takes mining difficulty and hardware into consideration.
//
// For Proof of Stake block headers, which start header versions 2, it uses the
// simpler Sha256DoubleHash function.
func (msg *MsgDeSoHeader) Hash() (*BlockHash, error) {
	// The preSignature flag is unused during byte encoding in
	// in header versions 0 and 1. We set it to true to ensure that
	// it's forward compatible for versions 2 and beyond.
	headerBytes, err := msg.ToBytes(true)
	if err != nil {
		return nil, errors.Wrap(err, "MsgDeSoHeader.Hash: ")
	}

	// Compute the specialized PoW hash for header versions 0 and 1.
	if msg.Version == HeaderVersion0 || msg.Version == HeaderVersion1 {
		return ProofOfWorkHash(headerBytes, msg.Version), nil
	}

	// TODO: Do we need a new specialized hash function for Proof of Stake
	// block headers? A simple SHA256 hash seems like it would be sufficient.
	// The use of ASICS is no longer a consideration, so we should be able to
	// simplify the hash function used.
	return Sha256DoubleHash(headerBytes), nil
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
		pkBytes, err := SafeMakeSliceWithLength[byte](pkLen)
		if err != nil {
			return errors.Wrapf(err, "BlockProducerInfo.Deserialize: Problem making slice for pkBytes")
		}
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
		sigBytes, err := SafeMakeSliceWithLength[byte](sigLen)
		if err != nil {
			return errors.Wrapf(err, "BlockProducerInfo.Deserialize: Problem making slice for sigBytes")
		}
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
	switch msg.Header.Version {
	case HeaderVersion0:
		return msg.EncodeBlockVersion0(preSignature)
	case HeaderVersion1, HeaderVersion2:
		return msg.EncodeBlockVersion1(preSignature)
	default:
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
	hdrBytes, err := SafeMakeSliceWithLength[byte](hdrLen)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Problem creating slice for header")
	}
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
			return fmt.Errorf("MsgDeSoBlock.FromBytes: Txn %d length %d longer than max %d",
				ii, txBytesLen, MaxMessagePayload)
		}
		txBytes, err := SafeMakeSliceWithLength[byte](txBytesLen)
		if err != nil {
			return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Problem making slice for txBytes")
		}
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
			blockProducerInfoBytes, err := SafeMakeSliceWithLength[byte](blockProducerInfoLen)
			if err != nil {
				return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Problem creating slice for block producer info bytes")
			}
			_, err = io.ReadFull(rr, blockProducerInfoBytes)
			if err != nil {
				return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Problem reading header")
			}
			blockProducerInfo = &BlockProducerInfo{}
			if err = blockProducerInfo.Deserialize(blockProducerInfoBytes); err != nil {
				return errors.Wrapf(err, "MsgDeSoBlock.FromBytes: Error deserializing block producer info")
			}
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

func (msg *MsgDeSoBlock) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	blockBytes, err := msg.ToBytes(false /*preSignature*/)
	if err != nil {
		glog.Errorf("MsgDeSoBlock.RawEncodeWithoutMetadata: Problem encoding block: %v", err)
	}
	return EncodeByteArray(blockBytes)
}

func (msg *MsgDeSoBlock) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	blockBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoBlock.RawDecodeWithoutMetadata: Problem decoding block")
	}
	return msg.FromBytes(blockBytes)
}

func (msg *MsgDeSoBlock) GetVersionByte(blockHeight uint64) byte {
	return 0
}

// GetEncoderType should return the EncoderType corresponding to the DeSoEncoder.
func (msg *MsgDeSoBlock) GetEncoderType() EncoderType {
	return EncoderTypeBlock
}

// Append DeSo Encoder Metadata bytes to MsgDeSoBlock bytes.
func AddEncoderMetadataToMsgDeSoBlockBytes(blockBytes []byte, blockHeight uint64) []byte {
	var blockData []byte
	blockData = append(blockData, BoolToByte(true))
	blockData = append(blockData, UintToBuf(uint64((&MsgDeSoBlock{}).GetEncoderType()))...)
	blockData = append(blockData, UintToBuf(uint64((&MsgDeSoBlock{}).GetVersionByte(blockHeight)))...)
	blockData = append(blockData, EncodeByteArray(blockBytes)...)
	return blockData
}

// ==================================================================
// SNAPSHOT Message
// ==================================================================

type MsgDeSoGetSnapshot struct {
	// SnapshotStartKey is the db key from which we want to start fetching the data.
	SnapshotStartKey []byte
}

func (msg *MsgDeSoGetSnapshot) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}
	data = append(data, EncodeByteArray(msg.SnapshotStartKey)...)

	return data, nil
}

func (msg *MsgDeSoGetSnapshot) FromBytes(data []byte) error {
	var err error

	rr := bytes.NewReader(data)

	msg.SnapshotStartKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoGetSnapshot.FromBytes: Error reading snapshot start key")
	}
	if len(msg.SnapshotStartKey) == 0 {
		return fmt.Errorf("MsgDeSoGetSnapshot.FromBytes: Received an empty SnapshotStartKey")
	}
	return nil
}

func (msg *MsgDeSoGetSnapshot) GetMsgType() MsgType {
	return MsgTypeGetSnapshot
}

func (msg *MsgDeSoGetSnapshot) GetPrefix() []byte {
	return msg.SnapshotStartKey[:1]
}

type MsgDeSoSnapshotData struct {
	// SnapshotMetadata is the information about the current snapshot epoch.
	SnapshotMetadata *SnapshotEpochMetadata

	// SnapshotChunk is the snapshot state data chunk.
	SnapshotChunk []*DBEntry
	// SnapshotChunkFull indicates whether we've exhausted all entries for the given prefix.
	// If this is true, it means that there are more entries in node's db, and false means
	// we've fetched everything.
	SnapshotChunkFull bool

	// Prefix indicates the db prefix of the current snapshot chunk.
	Prefix []byte
}

func (msg *MsgDeSoSnapshotData) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Encode the snapshot metadata.
	data = append(data, msg.SnapshotMetadata.ToBytes()...)

	// Encode the snapshot chunk data.
	if len(msg.SnapshotChunk) == 0 {
		return nil, fmt.Errorf("MsgDeSoSnapshotData.ToBytes: Snapshot data should not be empty")
	}
	data = append(data, UintToBuf(uint64(len(msg.SnapshotChunk)))...)
	for _, vv := range msg.SnapshotChunk {
		data = append(data, vv.ToBytes()...)
	}
	data = append(data, BoolToByte(msg.SnapshotChunkFull))
	data = append(data, UintToBuf(uint64(len(msg.Prefix)))...)
	data = append(data, msg.Prefix...)

	return data, nil
}

func (msg *MsgDeSoSnapshotData) FromBytes(data []byte) error {
	var err error

	rr := bytes.NewReader(data)

	// Decode snapshot metadata.
	msg.SnapshotMetadata = &SnapshotEpochMetadata{}
	if err := msg.SnapshotMetadata.FromBytes(rr); err != nil {
		return errors.Wrapf(err, "MsgDeSoSnapshotData.FromBytes: Problem decoding snapshot metadata")
	}
	// Decode snapshot keys
	dataLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoSnapshotData.FromBytes: Problem decoding length of SnapshotChunk")
	}
	for ; dataLen > 0; dataLen-- {
		dbEntry := &DBEntry{}
		if err := dbEntry.FromBytes(rr); err != nil {
			return errors.Wrapf(err, "MsgDeSoSnapshotData.FromBytes: Problem decoding SnapshotChunk")
		}
		msg.SnapshotChunk = append(msg.SnapshotChunk, dbEntry)
	}
	msg.SnapshotChunkFull, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoSnapshotData.FromBytes: Problem decoding SnapshotChunkFull")
	}

	prefixLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoSnapshotData.FromBytes: Problem decoding length of prefix")
	}
	msg.Prefix, err = SafeMakeSliceWithLength[byte](prefixLen)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoSnapshotData.FromBytes: Problem creating slice for prefix")
	}
	_, err = io.ReadFull(rr, msg.Prefix)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoSnapshotData.FromBytes: Problem decoding prefix")
	}

	return nil
}

func (msg *MsgDeSoSnapshotData) GetMsgType() MsgType {
	return MsgTypeSnapshotData
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

func (utxoKey *UtxoKey) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, utxoKey.TxID.ToBytes()...)
	data = append(data, UintToBuf(uint64(utxoKey.Index))...)
	return data
}

func (utxoKey *UtxoKey) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	// Read TxIndex
	txIdBytes := make([]byte, HashSizeBytes)
	_, err := io.ReadFull(rr, txIdBytes)
	if err != nil {
		return errors.Wrapf(err, "UtxoKey.Decode: Problem reading TxID")
	}
	utxoKey.TxID = *NewBlockHash(txIdBytes)

	index, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UtxoKey.Decode: Problem reading Index")
	}
	utxoKey.Index = uint32(index)

	return nil
}

func (utxoKey *UtxoKey) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (utxoKey *UtxoKey) GetEncoderType() EncoderType {
	return EncoderTypeUtxoKey
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

func (desoOutput *DeSoOutput) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray(desoOutput.PublicKey)...)
	data = append(data, UintToBuf(desoOutput.AmountNanos)...)

	return data
}

func (desoOutput *DeSoOutput) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	desoOutput.PublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DesoOutput.Decode: Problem reading PublicKey")
	}

	desoOutput.AmountNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "DesoOutput.Decode: Problem reading AmountNanos")
	}
	return nil
}

func (desoOutput *DeSoOutput) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (desoOutput *DeSoOutput) GetEncoderType() EncoderType {
	return EncoderTypeDeSoOutput
}

const (
	// derSigMagicOffset is the first byte of the DER signature format. It's a hard-coded value defined as part of the
	// DER encoding standard.
	derSigMagicOffset = 0x30

	// derSigMagicMaxRecoveryOffset is the maximal value of the DeSo-DER signature format. We enable public key recovery
	// from ECDSA signatures. To facilitate this, we add the recovery id to the DER magic 0x30 first byte. The recovery id
	// is in the range of [0, 3] and corresponds to the compact signature header magic. Adding recovery id to signature
	// encoding is totally optional and leaving the first byte 0x30 is acceptable. Specifically, the DeSo-DER signatures
	// have the following format:
	// <0x30 + optionally (0x01 + recoveryId)> <length of whole message> <0x02> <length of R> <R> 0x2 <length of S> <S>.
	// At this point, a familiar reader might arrive at some malleability concerns. After all that's why bip-62 enforced
	// DER signatures. ECDSA malleability is prevented by allowing public key recovery iff it was produced with a derived key.
	// That is, signatures made with derived keys cannot start with 0x30, unless the underlying transaction has the
	// derived public key in ExtraData. And if it does, then the header must be 0x30.
	derSigMagicMaxRecoveryOffset = 0x34
)

// DeSoSignature is a wrapper around ECDSA signatures used primarily in the MsgDeSoTxn transaction type.
type DeSoSignature struct {
	// Sign stores the main ECDSA signature. We use the btcec crypto package for most of the heavy-lifting.
	Sign *btcec.Signature

	// RecoveryId is the public key recovery id. The RecoveryId is taken from the DeSo-DER signature header magic byte and
	// must be in the [0, 3] range.
	RecoveryId byte
	// IsRecoverable indicates if the original signature contained the public key recovery id.
	IsRecoverable bool
}

func (desoSign *DeSoSignature) SetSignature(sign *btcec.Signature) {
	desoSign.Sign = sign
}

// Verify is a wrapper around DeSoSignature.Sign.Verify.
func (desoSign *DeSoSignature) Verify(hash []byte, pubKey *btcec.PublicKey) bool {
	if desoSign.Sign == nil {
		return false
	}
	return desoSign.Sign.Verify(hash, pubKey)
}

// HasHighS returns true if the signature has a high S value, which is non-standard
func (desoSign *DeSoSignature) HasHighS() bool {
	if desoSign == nil || desoSign.Sign == nil {
		return false
	}
	// We reject high-S signatures as they lead to inconsistent public key recovery
	// https://github.com/indutny/elliptic/blob/master/lib/elliptic/ec/index.js#L147
	return desoSign.Sign.S.Cmp(big.NewInt(0).Rsh(secp256k1.Params().N, 1)) != -1
}

// ToBytes encodes the signature in accordance to the DeSo-DER ECDSA format.
// <0x30 + optionally (0x01 + recoveryId)> <length of whole message> <0x02> <length of R> <R> 0x2 <length of S> <S>.
func (desoSign *DeSoSignature) ToBytes() []byte {
	// Serialize the signature using the DER encoding.
	signatureBytes := desoSign.Sign.Serialize()

	// If the signature contains the recovery id, place it in the header magic in accordance with
	// the DeSo-DER format.
	if len(signatureBytes) > 0 && desoSign.IsRecoverable {
		signatureBytes[0] += 0x01 + desoSign.RecoveryId
	}
	return signatureBytes
}

// FromBytes parses the signature bytes encoded in accordance to the DeSo-DER ECDSA format.
func (desoSign *DeSoSignature) FromBytes(signatureBytes []byte) error {
	// Signature cannot be an empty byte array.
	if len(signatureBytes) == 0 {
		return fmt.Errorf("FromBytes: Signature cannot be empty")
	}

	// The first byte of the signature must be in the [0x30, 0x34] range.
	if signatureBytes[0] < derSigMagicOffset || signatureBytes[0] > derSigMagicMaxRecoveryOffset {
		return fmt.Errorf("FromBytes: DeSo-DER header magic expected in [%v, %v] range but got: %v",
			derSigMagicOffset, derSigMagicMaxRecoveryOffset, signatureBytes[0])
	}

	// Copy the signature bytes to make so that we can freely modify it.
	signatureBytesCopy, err := SafeMakeSliceWithLength[byte](uint64(len(signatureBytes)))
	if err != nil {
		return fmt.Errorf("FromBytes: Problem creating slice for signatureBytesCopy")
	}
	copy(signatureBytesCopy, signatureBytes)
	// If header magic contains the recovery Id, we will retrieve it.
	if signatureBytes[0] > derSigMagicOffset {
		// We subtract 1 because DeSo-DER header magic in this case is 0x30 + 0x01 + recoveryId
		desoSign.RecoveryId = signatureBytes[0] - derSigMagicOffset - 0x01
		desoSign.IsRecoverable = true
		// Now set the first byte as the standard DER header offset so that we can parse it with btcec.
		signatureBytesCopy[0] = derSigMagicOffset
	}
	// Parse the signature assuming it's encoded in the standard DER format.
	desoSign.Sign, err = btcec.ParseDERSignature(signatureBytesCopy, btcec.S256())
	if err != nil {
		return errors.Wrapf(err, "Problem parsing signatureBytes")
	}
	return nil
}

const (
	// See comment on _btcecSerializeCompact to better understand how these constants are used.

	// btcecCompactSigSize is the size of a btcec compact signature. It consists of a compact signature recovery code
	// byte followed by the R and S components serialized as 32-byte big-endian values. 1+32*2 = 65 for the R and S
	// components. 1+32+32=65.
	btcecCompactSigSize byte = 65

	// This is a magic offset that we need to implement the compact signature concept from btcec.
	//
	// btcecCompactSigMagicOffset is a value used when creating the compact signature recovery code inherited from Bitcoin and
	// has no meaning, but has been retained for compatibility. For historical purposes, it was originally picked to avoid
	// a binary representation that would allow compact signatures to be mistaken for other components.
	btcecCompactSigMagicOffset byte = 27

	// btcecCompactSigCompPubKey is a value used when creating the compact signature recovery code to indicate the original
	// public key was compressed.
	btcecCompactSigCompPubKey byte = 4
)

// The concept of a compact signature comes from btcec. It's a weird format that's different from standard DER
// encoding, but we use it because it allows us to leverage their RecoverCompact function. For some reason, btcec
// only implemented SignCompact() and RecoverCompact() but not SerializeCompact(). So, for our use-case, we
// implement the missing Serialize() function and then we call the following to recover the public key:
// - btcec.RecoverCompact(_btcecSerializeCompact(desoSignature)).
//
// _btcecSerializeCompact encodes the signature into the compact signature format:
// <1-byte compact sig recovery code><32-byte R><32-byte S>
//
// The compact sig recovery code is the value 27 + public key recovery ID + 4
// if the compact signature was created with a compressed public key.
// Public key recovery ID is in the range [0, 3].
func (desoSign *DeSoSignature) _btcecSerializeCompact() ([]byte, error) {
	// We will change from the btcec signature type to the dcrec signature type. To achieve this, we will create the
	// ecdsa (R, S) pair using the decred's package.
	// Reference: https://github.com/decred/dcrd/blob/1eff7/dcrec/secp256k1/modnscalar_test.go#L26
	rBytes := desoSign.Sign.R.Bytes()
	r := &secp256k1.ModNScalar{}
	r.SetByteSlice(rBytes)

	sBytes := desoSign.Sign.S.Bytes()
	s := &secp256k1.ModNScalar{}
	s.SetByteSlice(sBytes)

	// To make sure the signature has been correctly parsed, we verify DER encoding of both signatures matches.
	verifySignature := decredEC.NewSignature(r, s)
	if !bytes.Equal(verifySignature.Serialize(), desoSign.Sign.Serialize()) {
		return nil, fmt.Errorf("_btcecSerializeCompact: Problem sanity-checking signature")
	}

	// Encode the signature using compact format.
	// reference: https://github.com/decred/dcrd/blob/1eff7/dcrec/secp256k1/ecdsa/signature.go#L712
	compactSigRecoveryCode := btcecCompactSigMagicOffset + desoSign.RecoveryId + btcecCompactSigCompPubKey

	// Output <compactSigRecoveryCode><32-byte R><32-byte S>.
	var b [btcecCompactSigSize]byte
	b[0] = compactSigRecoveryCode
	r.PutBytesUnchecked(b[1:33])
	s.PutBytesUnchecked(b[33:65])
	return b[:], nil
}

// RecoverPublicKey attempts to retrieve the signer's public key from the DeSoSignature given the messageHash sha256x2 digest.
func (desoSign *DeSoSignature) RecoverPublicKey(messageHash []byte) (*btcec.PublicKey, error) {
	// Serialize signature into the compact encoding.
	signatureBytes, err := desoSign._btcecSerializeCompact()
	if err != nil {
		return nil, errors.Wrapf(err, "RecoverPublicKey: Problem serializing compact signature")
	}

	// Now recover the public key from the compact encoding.
	recoveredPublicKey, _, err := btcec.RecoverCompact(btcec.S256(), signatureBytes, messageHash)
	if err != nil {
		return nil, errors.Wrapf(err, "RecoverPublicKey: Problem recovering public key from the signature bytes")
	}

	return recoveredPublicKey, nil
}

// SignRecoverable computes a signature that adds a publicKeyRecoveryID to the first byte of a
// standard DER signature. We call the combination the DeSo-DER signature.
//
// Overall, it first computes a standard DER signature, and then it adds (0x01 + recoveryID) to
// the first byte. This makes it so that the first byte will be between [0x31, 0x34] inclusive,
// instead of being 0x30, which is the standard DER signature magic number.
func SignRecoverable(bb []byte, privateKey *btcec.PrivateKey) (*DeSoSignature, error) {
	signature, err := privateKey.Sign(bb)
	if err != nil {
		return nil, err
	}

	// We use SignCompact from the btcec library to get the recoverID. This results in a non-standard
	// encoding that we need to manipulate in order to get the recoveryID back out. See comment on
	// _btcecSerializeCompact for more information.
	signatureCompact, err := btcec.SignCompact(btcec.S256(), privateKey, bb, true)
	if err != nil {
		return nil, err
	}
	recoveryId := (signatureCompact[0] - btcecCompactSigMagicOffset) & ^byte(btcecCompactSigCompPubKey)

	return &DeSoSignature{
		Sign:          signature,
		RecoveryId:    recoveryId,
		IsRecoverable: true,
	}, nil
}

// DeSoNonce is a nonce that can be used to prevent replay attacks. It is used in the DeSo protocol
// to prevent replay attacks when a user is trying to create a transaction. The nonce comprises
// two uint64s: the expiration block height and the partial ID. The expiration block height is the
// block height at which the nonce expires. The partial ID is a random uint64 that is used to
// prevent nonce reuse. This scheme allows us to re-order transactions based on fees while
// optimizing developer UX. Nonce schemes used in other protocols require monotonically
// increasing nonces. In DeSo, this would cause issues if a user tried to create a transaction
// with a higher fee after creating a bunch of transactions with lower fees. For example,
// a user may perform a normal social transactions such as posts and follows with low fees
// and then wants to bid on an NFT and use a higher fee to ensure their bid is processed
// quickly. If the nonce scheme required monotonically increasing nonces, the user would
// have to wait for all of their low-fee transactions to be processed before they could
// create a transaction with a higher fee.
type DeSoNonce struct {
	ExpirationBlockHeight uint64
	PartialID             uint64
}

func (nonce *DeSoNonce) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte
	data = append(data, nonce.ToBytes()...)
	return data
}

func (nonce *DeSoNonce) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	return nonce.ReadDeSoNonce(rr)
}

func (nonce *DeSoNonce) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (nonce *DeSoNonce) GetEncoderType() EncoderType {
	return EncoderTypeDeSoNonce
}

func (nonce *DeSoNonce) ToBytes() []byte {
	data := []byte{}
	data = append(data, UintToBuf(nonce.ExpirationBlockHeight)...)
	data = append(data, UintToBuf(nonce.PartialID)...)
	return data
}

func (nonce *DeSoNonce) String() string {
	return fmt.Sprintf("DeSoNonce: ExpirationBlockHeight: %d, PartialID: %d",
		nonce.ExpirationBlockHeight, nonce.PartialID)
}

func (nonce *DeSoNonce) ReadDeSoNonce(rr io.Reader) error {
	var err error
	nonce.ExpirationBlockHeight, err = ReadUvarint(rr)
	if err != nil {
		return err
	}
	nonce.PartialID, err = ReadUvarint(rr)
	if err != nil {
		return err
	}
	return nil
}

type DeSoTxnVersion uint64

const (
	DeSoTxnVersion0 DeSoTxnVersion = 0
	DeSoTxnVersion1 DeSoTxnVersion = 1
)

type MsgDeSoTxn struct {
	// TxnVersion 0: UTXO model transactions.
	// TxnVersion 1: Balance model transactions, which include a nonce and fee nanos.
	TxnVersion DeSoTxnVersion

	TxInputs  []*DeSoInput
	TxOutputs []*DeSoOutput

	// In the UTXO model, a transaction's "fee" is simply the DESO input nanos that aren't
	// spent in the transaction outputs. Since the balance model does not use inputs, each
	// transaction must explicitly specify its fee nanos.
	TxnFeeNanos uint64
	// In the balance model, a unique nonce is required for each transaction that a single
	// public key makes. Without this field, it would be possible to rebroadcast a user's
	// transactions repeatedly, aka a "replay attack."
	TxnNonce *DeSoNonce

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
	Signature DeSoSignature

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
	data = append(data, EncodeExtraData(msg.ExtraData)...)

	// Serialize the signature. Since this can be variable length, encode
	// the length first and then the signature. If there is no signature, then
	// a zero will be encoded for the length and no signature bytes will be added
	// beyond it.
	sigBytes := []byte{}
	if !preSignature && msg.Signature.Sign != nil {
		sigBytes = msg.Signature.ToBytes()
	}
	// Note that even though we encode the length as a varint as opposed to a
	// fixed-width int, it should always take up just one byte since the length
	// of the signature will never exceed 127 bytes in length. This is important
	// to note for e.g. operations that try to compute a transaction's size
	// before a signature is present such as during transaction fee computations.
	data = append(data, UintToBuf(uint64(len(sigBytes)))...)
	data = append(data, sigBytes...)

	// If TxnVersion is non-zero, this is a post-UTXO model transaction, and we must encode the
	// version, fee, and the nonce.
	//
	// In an ideal world, the TxnVersion would appear at the beginning. However, because we
	// introduced TxnVersion later on, putting it at the end allowed for v2 transactions to
	// remain mostly backwards-compatible with v1 transactions, without needing to introduce
	// a MsgDeSoTxnV2. This was highly-advantageous because it meant that all of the old v1
	// transaction processing code could be left as-is, without needing to support two different
	// message types.
	if msg.TxnVersion != 0 {
		data = append(data, UintToBuf(uint64(msg.TxnVersion))...)
		data = append(data, UintToBuf(msg.TxnFeeNanos)...)
		data = append(data, msg.TxnNonce.ToBytes()...)
	}
	return data, nil
}

func (msg *MsgDeSoTxn) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	txnBytes, err := msg.ToBytes(false /*preSignature*/)
	if err != nil {
		glog.Errorf("MsgDeSoTxn.RawEncodeWithoutMetadata: Problem encoding transaction: %v", err)
	}
	return EncodeByteArray(txnBytes)
}

func (msg *MsgDeSoTxn) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	txnBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgDeSoBlock.RawDecodeWithoutMetadata: Problem decoding block")
	}
	return msg.FromBytes(txnBytes)
}

func (msg *MsgDeSoTxn) GetVersionByte(blockHeight uint64) byte {
	return 0
}

// GetEncoderType should return the EncoderType corresponding to the DeSoEncoder.
func (msg *MsgDeSoTxn) GetEncoderType() EncoderType {
	return EncoderTypeTxn
}

func ReadTransaction(rr io.Reader) (*MsgDeSoTxn, error) {
	ret := NewMessage(MsgTypeTxn).(*MsgDeSoTxn)
	// When the DeSo blockchain switched from UTXOs to a balance model, new fields had to be
	// added to the transaction struct (ie. TxnFeeNanos and TxnNonce). In order to maintain
	// backwards compatibility, these fields were added to the end of the serialized
	// transaction and we only attempt to read them if we have not reached EOF after reading
	// the original "basic" transaction fields. Thus, we split the _readTransaction
	// deserialization process into these two steps below.
	if err := ReadTransactionV0Fields(rr, ret); err != nil {
		return nil, errors.Wrapf(err, "ReadTransaction: Problem reading basic transaction fields")
	}
	if err := ReadTransactionV1Fields(rr, ret); err != nil {
		return nil, errors.Wrapf(err, "ReadTransaction: Problem reading extra transaction fields")
	}
	return ret, nil
}

// This function deserializes the original pre-Balance Model transaction fields from
// the passed buffer and then stops reading. It exists in order to maintain support
// for TransactionBundles, which expect transactions to only include these fields. After
// the balance model block height nodes will rely on the new TransactionBundleV2 struct,
// which will allow transactions to contain arbitrary fields.
func ReadTransactionV0Fields(rr io.Reader, ret *MsgDeSoTxn) error {
	// De-serialize the inputs
	numInputs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "ReadTransactionV0Fields: Problem converting len(msg.TxInputs)")
	}
	for ii := uint64(0); ii < numInputs; ii++ {
		currentInput := NewDeSoInput()
		_, err = io.ReadFull(rr, currentInput.TxID[:])
		if err != nil {
			return errors.Wrapf(err, "ReadTransactionV0Fields: Problem converting input txid")
		}
		inputIndex, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "ReadTransactionV0Fields: Problem converting input index")
		}
		if inputIndex > uint64(^uint32(0)) {
			return fmt.Errorf("ReadTransactionV0Fields: Input index (%d) must not exceed (%d)", inputIndex, ^uint32(0))
		}
		currentInput.Index = uint32(inputIndex)

		ret.TxInputs = append(ret.TxInputs, currentInput)
	}

	// De-serialize the outputs
	numOutputs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "ReadTransactionV0Fields: Problem converting len(msg.TxOutputs)")
	}
	for ii := uint64(0); ii < numOutputs; ii++ {
		currentOutput := &DeSoOutput{}
		currentOutput.PublicKey = make([]byte, btcec.PubKeyBytesLenCompressed)
		_, err = io.ReadFull(rr, currentOutput.PublicKey)
		if err != nil {
			return errors.Wrapf(err, "ReadTransactionV0Fields: Problem reading DeSoOutput.PublicKey")
		}

		amountNanos, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "ReadTransactionV0Fields: Problem reading DeSoOutput.AmountNanos")
		}
		currentOutput.AmountNanos = amountNanos

		ret.TxOutputs = append(ret.TxOutputs, currentOutput)
	}

	// De-serialize the metadata
	//
	// Encode the type as a uvarint.
	txnMetaType, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "ReadTransactionV0Fields: Problem reading MsgDeSoTxn.TxnType")
	}
	ret.TxnMeta, err = NewTxnMetadata(TxnType(txnMetaType))
	if err != nil {
		return fmt.Errorf("ReadTransactionV0Fields: Problem initializing metadata: %v", err)
	}
	if ret.TxnMeta == nil {
		return fmt.Errorf("ReadTransactionV0Fields: Metadata was nil: %v", ret.TxnMeta)
	}
	metaLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "ReadTransactionV0Fields: Problem reading len(TxnMeta)")
	}
	if metaLen > MaxMessagePayload {
		return fmt.Errorf("ReadTransactionV0Fields.FromBytes: metaLen length %d longer than max %d", metaLen, MaxMessagePayload)
	}
	metaBuf, err := SafeMakeSliceWithLength[byte](metaLen)
	if err != nil {
		return fmt.Errorf("ReadTransactionV0Fields.FromBytes: Problem creating slice for metaBuf")
	}
	_, err = io.ReadFull(rr, metaBuf)
	if err != nil {
		return errors.Wrapf(err, "ReadTransactionV0Fields: Problem reading TxnMeta")
	}
	err = ret.TxnMeta.FromBytes(metaBuf)
	if err != nil {
		return errors.Wrapf(err, "ReadTransactionV0Fields: Problem decoding TxnMeta: ")
	}

	// De-serialize the public key if there is one
	pkLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "ReadTransactionV0Fields: Problem reading len(DeSoTxn.PublicKey)")
	}
	if pkLen > MaxMessagePayload {
		return fmt.Errorf("ReadTransactionV0Fields.FromBytes: pkLen length %d longer than max %d", pkLen, MaxMessagePayload)
	}
	ret.PublicKey = nil
	if pkLen != 0 {
		ret.PublicKey, err = SafeMakeSliceWithLength[byte](pkLen)
		if err != nil {
			return fmt.Errorf("ReadTransactionV0Fields.FromBytes: Problem making slice for PublicKey")
		}
		_, err = io.ReadFull(rr, ret.PublicKey)
		if err != nil {
			return errors.Wrapf(err, "ReadTransactionV0Fields: Problem reading DeSoTxn.PublicKey")
		}
	}

	// De-serialize the ExtraData
	extraData, err := DecodeExtraData(rr)
	if err != nil {
		return fmt.Errorf("ReadTransactionV0Fields: Error decoding extra data: %v", err)
	}
	ret.ExtraData = extraData

	// De-serialize the signature if there is one.
	sigLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "ReadTransactionV0Fields: Problem reading len(DeSoTxn.Signature)")
	}
	if sigLen > MaxMessagePayload {
		return fmt.Errorf("ReadTransactionV0Fields.FromBytes: sigLen length %d longer than max %d", sigLen, MaxMessagePayload)
	}

	ret.Signature.SetSignature(nil)
	if sigLen != 0 {
		sigBytes, err := SafeMakeSliceWithLength[byte](sigLen)
		if err != nil {
			return fmt.Errorf("ReadTransactionV0Fields.FromBytes: Problem making slice for sigBytes")
		}
		_, err = io.ReadFull(rr, sigBytes)
		if err != nil {
			return errors.Wrapf(err, "ReadTransactionV0Fields: Problem reading DeSoTxn.Signature")
		}

		// Verify that the signature is valid.
		err = ret.Signature.FromBytes(sigBytes)
		if err != nil {
			return errors.Wrapf(err, "ReadTransactionV0Fields: Problem parsing DeSoTxn.Signature bytes")
		}
	}
	return nil
}

// This function takes an io.Reader and attempts to read the transaction fields that were
// added after the BalanceModelBlockHeight, if the reader has not reached EOF. See the comments
// in _readTransaction() and above ReadTransactionV0Fields() for more info.
func ReadTransactionV1Fields(rr io.Reader, ret *MsgDeSoTxn) error {
	txnVersion, err := ReadUvarint(rr)
	if err == io.EOF {
		return nil
	} else if err != nil {
		return errors.Wrapf(
			err, "ReadTransactionV1Fields: Problem parsing DeSoTxn.TxnVersion bytes")
	}
	ret.TxnVersion = DeSoTxnVersion(txnVersion)

	txnFeeNanos, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(
			err, "ReadTransactionV1Fields: Problem parsing DeSoTxn.TxnFeeNanos bytes")
	}
	ret.TxnFeeNanos = txnFeeNanos

	txnNonce := &DeSoNonce{}
	err = txnNonce.ReadDeSoNonce(rr)
	if err != nil {
		return errors.Wrapf(
			err, "ReadTransactionV1Fields: Problem parsing DeSoTxn.TxnNonce bytes")
	}
	ret.TxnNonce = txnNonce

	return nil
}

func (msg *MsgDeSoTxn) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	ret, err := ReadTransaction(rr)
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
func SignTransactionBytes(txnBytes []byte, privateKey *btcec.PrivateKey, isDerived bool) ([]byte, []byte, error) {
	// As we're signing the transaction using a derived key, we
	// pass the key to extraData.
	rr := bytes.NewReader(txnBytes)
	txn, err := ReadTransaction(rr)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "SignTransactionBytes: Problem reading txn: ")
	}
	if isDerived {
		if txn.ExtraData == nil {
			txn.ExtraData = make(map[string][]byte)
		}
		txn.ExtraData[DerivedPublicKey] = privateKey.PubKey().SerializeCompressed()
	}

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
		TxnVersion  DeSoTxnVersion
		TxInputs    []*DeSoInput
		TxOutputs   []*DeSoOutput
		TxnFeeNanos uint64
		TxnNonce    *DeSoNonce
		TxnMeta     DeSoTxnMetadata
		PublicKey   []byte
		ExtraData   map[string][]byte
		Signature   DeSoSignature
		TxnType     uint64
	}{
		TxnVersion:  msg.TxnVersion,
		TxInputs:    msg.TxInputs,
		TxOutputs:   msg.TxOutputs,
		TxnFeeNanos: msg.TxnFeeNanos,
		TxnNonce:    msg.TxnNonce,
		TxnMeta:     msg.TxnMeta,
		PublicKey:   msg.PublicKey,
		ExtraData:   msg.ExtraData,
		Signature:   msg.Signature,
		TxnType:     msg.TxnTypeJSON,
	}
	json.Unmarshal(data, &anonymousTxn)

	msg.TxnVersion = anonymousTxn.TxnVersion
	msg.TxInputs = anonymousTxn.TxInputs
	msg.TxOutputs = anonymousTxn.TxOutputs
	msg.TxnFeeNanos = anonymousTxn.TxnFeeNanos
	msg.TxnNonce = anonymousTxn.TxnNonce
	msg.TxnMeta = anonymousTxn.TxnMeta
	msg.PublicKey = anonymousTxn.PublicKey
	msg.ExtraData = anonymousTxn.ExtraData
	msg.Signature = anonymousTxn.Signature
	// Don't set the TxnTypeJSON when unmarshaling. It should never be used in
	// Go code, only at the interface between Go and non-Go.
	msg.TxnTypeJSON = 0

	return nil
}

// ComputeFeeRatePerKBNanos computes the fee rate per KB for a signed transaction. This function should not be used for
// unsigned transactions because the fee rate will not be accurate. However, we allow unsigned Atomic txn wrappers
// since there will never be a signature for the wrapper transactions.
func (txn *MsgDeSoTxn) ComputeFeeRatePerKBNanos() (uint64, error) {
	if txn.Signature.Sign == nil && txn.TxnMeta.GetTxnType() != TxnTypeAtomicTxnsWrapper {
		return 0, fmt.Errorf("ComputeFeeRatePerKBNanos: Cannot compute fee rate for unsigned txn")
	}

	var err error
	txBytes, err := txn.ToBytes(false)
	if err != nil {
		return 0, errors.Wrapf(err, "ComputeFeeRatePerKBNanos: Problem converting txn to bytes")
	}
	totalFees := txn.TxnFeeNanos
	if totalFees != ((totalFees * 1000) / 1000) {
		return 0, errors.Wrapf(RuleErrorOverflowDetectedInFeeRateCalculation,
			"ComputeFeeRatePerKBNanos: Overflow detected in fee rate calculation")
	}

	serializedLen := uint64(len(txBytes))
	if serializedLen == 0 {
		return 0, fmt.Errorf("ComputeFeeRatePerKBNanos: Txn has zero length")
	}

	return (totalFees * 1000) / serializedLen, nil
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
	ret.ExtraData, err = SafeMakeSliceWithLength[byte](numExtraDataBytes)
	if err != nil {
		return errors.Wrapf(err, "BlockRewardMetadataa.FromBytes: Problem creating slice for extradata")
	}
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
	txnBytes, err := SafeMakeSliceWithLength[byte](txnBytesLen)
	if err != nil {
		return fmt.Errorf("BitcoinExchangeMetadata.FromBytes: Problem making slice for txnBytes")
	}
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
	ret.EncryptedText, err = SafeMakeSliceWithLength[byte](encryptedTextLen)
	if err != nil {
		return errors.Wrapf(err, "PrivateMessageMetadata.FromBytes: Problem making slice for encrypted text")
	}
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
	ret.IsUnlike, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "LikeMetadata.FromBytes: Problem reading IsUnlike")
	}

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
	ret.IsUnfollow, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "FollowMetadata.FromBytes: Problem reading IsUnfollow")
	}

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

func ReadBoolByte(rr *bytes.Reader) (bool, error) {
	boolByte, err := rr.ReadByte()
	if err != nil {
		return false, err
	}
	if boolByte != 0 {
		return true, nil
	}
	return false, nil
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
		return nil, errors.Wrapf(err, "ReadVarString: Problem "+
			"decoding String length")
	}
	if StringLen > MaxMessagePayload {
		return nil, fmt.Errorf("ReadVarString: StringLen %d "+
			"exceeds max %d", StringLen, MaxMessagePayload)
	}
	ret, err := SafeMakeSliceWithLength[byte](StringLen)
	if err != nil {
		return nil, errors.Wrapf(err, "ReadVarString: Problem making slice for var string")
	}
	_, err = io.ReadFull(rr, ret)
	if err != nil {
		return nil, fmt.Errorf("ReadVarString: Error reading StringText: %v", err)
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
	ret.IsHidden, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "SubmitPostMetadata.FromBytes: Problem reading IsHidden")
	}

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
	ret.IsHidden, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateProfileMetadata.FromBytes: Problem reading IsHidden")
	}

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
	ret.HasUnlockable, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateNFTMetadata.FromBytes: Problem reading HasUnlockable")
	}

	// IsForSale
	ret.IsForSale, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateNFTMetadata.FromBytes: Problem reading IsForSale")
	}

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
	ret.IsForSale, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateNFTMetadata.FromBytes: Problem reading IsForSale")
	}

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
	ret.UnlockableText, err = SafeMakeSliceWithLength[byte](unlockableTextLen)
	if err != nil {
		return fmt.Errorf("AcceptNFTBidMetadata.FromBytes: Problem making slice for unlockable text")
	}
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
	ret.UnlockableText, err = SafeMakeSliceWithLength[byte](unlockableTextLen)
	if err != nil {
		return errors.Wrapf(err, "NFTTransferMetadata.FromBytes: Problem making slice for unlockable text")
	}
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

type TransactionSpendingLimit struct {
	// This is the total amount the derived key can spend.
	GlobalDESOLimit uint64

	// TransactionCount
	// If a transaction type is not specified in the map, it is not allowed.
	// If the transaction type is in the map, the derived key is allowed to
	// perform the transaction up to the value to which it is mapped.
	TransactionCountLimitMap map[TxnType]uint64

	// CreatorCoinOperationLimitMap is a map with keys composed of
	// creator PKID || CreatorCoinLimitOperation to number
	// of transactions
	CreatorCoinOperationLimitMap map[CreatorCoinOperationLimitKey]uint64

	// DAOCoinOperationLimitMap is a map with keys composed of
	// creator PKID || DAOCoinLimitOperation to number of
	// transactions
	DAOCoinOperationLimitMap map[DAOCoinOperationLimitKey]uint64

	// NFTOperationLimitMap is a map with keys composed of
	// PostHash || Serial Num || NFTLimitOperation to number
	// of transactions
	NFTOperationLimitMap map[NFTOperationLimitKey]uint64

	// DAOCoinLimitOrderLimitMap is a map with keys composed of
	// BuyingCreatorPKID || SellingCreatorPKID to number of
	// transactions
	DAOCoinLimitOrderLimitMap map[DAOCoinLimitOrderLimitKey]uint64

	// AccessGroupMap is a map with keys composed of
	// AccessGroupOwnerPublicKey || AccessGroupKeyName || AccessGroupOperationType
	// to number of transactions.
	AccessGroupMap map[AccessGroupLimitKey]uint64

	// AccessGroupMemberMap is a map with keys composed of
	// AccessGroupOwnerPublicKey || AccessGroupKeyName || AccessGroupMemberOperationType
	// to number of transactions.
	AccessGroupMemberMap map[AccessGroupMemberLimitKey]uint64

	// ===== ENCODER MIGRATION UnlimitedDerivedKeysMigration =====
	// IsUnlimited field determines whether this derived key has no spending limit.
	IsUnlimited bool

	// ===== ENCODER MIGRATION AssociationsMigration =====
	// AssociationClass || AssociationType || AppPKID || AppScopeType || AssociationOperation
	// to number of transactions
	//   - AssociationClass: one of { User, Post }
	//   - AssociationType: a byte slice to scope by AssociationType or an empty byte slice to signify Any
	//   - AppPKID: a PKID to scope by App, if AppScopeType == Any then AppPKID has to be the ZeroPKID
	//   - AppScopeType: one of { Any, Scoped }
	//   - AssociationOperation: one of { Any, Create, Delete }
	AssociationLimitMap map[AssociationLimitKey]uint64

	// ===== ENCODER MIGRATION ProofOfStake1StateSetupMigration =====
	// ProfilePKID || LockupLimitOperation || LockupLimitScopeType to number of transactions.
	//  - ProfilePKID: A PKID to scope transactions by.
	//                 If using the "Any" scope, then ProfilePKID has to be the ZeroPKID.
	//  - LockupLimitScopeType: One of {Any, Scoped}
	//                 If using the "Any" scope type, this limit applies to any possible DeSo token lockup.
	//                 If using the "Scoped" scope type, this limit applies to the ProfilePKID specified.
	//  - LockupLimitOperation: One of {Any, Lockup, UpdateCoinLockupYieldCurve, UpdateCoinLockupTransferRestrictions,
	//                                  CoinLockupTransfer, CoinLockupUnlock}
	//                 If using the "Any" operation type the limit applies to any coin lockup transaction type.
	//                 If using the "CoinLockup" operation type the limit applies strictly to coin lockups transactions.
	//                 If using the "UpdateCoinLockupYield" operation type the limit applies to any
	//                 UpdateCoinLockupParams transaction where the yield curve is updated.
	//                 If using the "UpdateCoinLockupTransferRestrictions" operation the limit applies to any
	//                 UpdateCoinLockupParams transaction where the lockup transfer restrictions are updated.
	//                 If using the "CoinLockupTransfer" operation type the limit applies to any
	//                 coin lockup transfer transactions.
	//                 If using the "CoinLockupUnlock" operation type the limit applies to
	//                 any locked coin unlock transactions.
	//
	// NOTE: Note that an UpdateCoinLockupParams transaction can decrement the transaction limits twice.
	//       This is because we consider updating the yield curve and updating transfer restrictions as
	//       separate for the purpose of derived key limits.
	LockupLimitMap map[LockupLimitKey]uint64
	// ValidatorPKID || StakerPKID to amount of stake-able $DESO.
	// Note that this is not a limit on the number of Stake txns that
	// this derived key can perform but instead a limit on the amount
	// of $DESO this derived key can stake.
	StakeLimitMap map[StakeLimitKey]*uint256.Int
	// ValidatorPKID || StakerPKID to amount of unstake-able DESO.
	// Note that this is not a limit on the number of Unstake txns that
	// this derived key can perform but instead a limit on the amount
	// of $DESO this derived key can unstake.
	UnstakeLimitMap map[StakeLimitKey]*uint256.Int
	// ValidatorPKID || StakerPKID to number of UnlockStake transactions.
	UnlockStakeLimitMap map[StakeLimitKey]uint64
}

// ToMetamaskString encodes the TransactionSpendingLimit into a Metamask-compatible string. The encoded string will
// be a part of Access Bytes Encoding 2.0 for derived keys, which creates a human-readable string that MM can sign.
// The idea behind this function is to create an injective mapping from the TransactionSpendingLimit -> string.
// This mapping is not intended to be invertible, rather we would also call this function while verifying access bytes.
// Basically, to verify signature on a derived key, we will call this function as well, instead of attempting to revert
// the metamask string.
func (tsl *TransactionSpendingLimit) ToMetamaskString(params *DeSoParams) string {
	var str string
	var indentationCounter int

	str += "Spending limits on the derived key:\n"
	indentationCounter++

	// GlobalDESOLimit
	if tsl.GlobalDESOLimit > 0 {
		str += _indt(indentationCounter) + "Total $DESO Limit: " + FormatScaledUint256AsDecimalString(
			BigIntFromUint64(tsl.GlobalDESOLimit), big.NewInt(int64(NanosPerUnit))) + " $DESO\n"
	}

	// Sort an array of strings and add them to the spending limit string str. This will come in handy below,
	// simplifying the construction of the metamask spending limit string.
	sortStringsAndAddToLimitStr := func(strList []string) {
		sort.Strings(strList)
		for _, limitStr := range strList {
			str += limitStr
		}
	}

	// TransactionCountLimitMap
	if len(tsl.TransactionCountLimitMap) > 0 {
		var txnCountStr []string
		str += _indt(indentationCounter) + "Transaction Count Limit: \n"
		indentationCounter++
		for txnType, limit := range tsl.TransactionCountLimitMap {
			txnCountStr = append(txnCountStr, _indt(indentationCounter)+txnType.String()+": "+
				strconv.FormatUint(limit, 10)+"\n")
		}
		// Ensure deterministic ordering of the transaction count limit strings by doing a lexicographical sort.
		sortStringsAndAddToLimitStr(txnCountStr)
		indentationCounter--
	}

	// CreatorCoinOperationLimitMap
	if len(tsl.CreatorCoinOperationLimitMap) > 0 {
		var creatorCoinLimitStr []string
		str += _indt(indentationCounter) + "Creator Coin Operation Limits:\n"
		indentationCounter++
		for limitKey, limit := range tsl.CreatorCoinOperationLimitMap {
			opString := _indt(indentationCounter) + "[\n"

			indentationCounter++
			opString += _indt(indentationCounter) + "Creator PKID: " +
				Base58CheckEncode(limitKey.CreatorPKID.ToBytes(), false, params) + "\n"
			opString += _indt(indentationCounter) + "Operation: " +
				limitKey.Operation.ToString() + "\n"
			opString += _indt(indentationCounter) + "Transaction Count: " +
				strconv.FormatUint(limit, 10) + "\n"
			indentationCounter--

			opString += _indt(indentationCounter) + "]\n"
			creatorCoinLimitStr = append(creatorCoinLimitStr, opString)
		}
		// Ensure deterministic ordering of the transaction count limit strings by doing a lexicographical sort.
		sortStringsAndAddToLimitStr(creatorCoinLimitStr)
		indentationCounter--
	}

	// DAOCoinOperationLimitMap
	if len(tsl.DAOCoinOperationLimitMap) > 0 {
		var daoCoinOperationLimitStr []string
		str += _indt(indentationCounter) + "DAO Coin Operation Limits:\n"
		indentationCounter++
		for limitKey, limit := range tsl.DAOCoinOperationLimitMap {
			opString := _indt(indentationCounter) + "[\n"

			indentationCounter++
			opString += _indt(indentationCounter) + "Creator PKID: " +
				Base58CheckEncode(limitKey.CreatorPKID.ToBytes(), false, params) + "\n"
			opString += _indt(indentationCounter) + "Operation: " +
				limitKey.Operation.ToString() + "\n"
			opString += _indt(indentationCounter) + "Transaction Count: " +
				strconv.FormatUint(limit, 10) + "\n"
			indentationCounter--

			opString += _indt(indentationCounter) + "]\n"
			daoCoinOperationLimitStr = append(daoCoinOperationLimitStr, opString)
		}
		// Ensure deterministic ordering of the transaction count limit strings by doing a lexicographical sort.
		sortStringsAndAddToLimitStr(daoCoinOperationLimitStr)
		indentationCounter--
	}

	// NFTOperationLimitMap
	if len(tsl.NFTOperationLimitMap) > 0 {
		var nftOperationLimitKey []string
		str += _indt(indentationCounter) + "NFT Operation Limits:\n"
		indentationCounter++
		for limitKey, limit := range tsl.NFTOperationLimitMap {
			opString := _indt(indentationCounter) + "[\n"

			indentationCounter++
			opString += _indt(indentationCounter) + "Block Hash: " + limitKey.BlockHash.String() + "\n"
			opString += _indt(indentationCounter) + "Serial Number: " +
				strconv.FormatUint(limitKey.SerialNumber, 10) + "\n"
			opString += _indt(indentationCounter) + "Operation: " +
				limitKey.Operation.ToString() + "\n"
			opString += _indt(indentationCounter) + "Transaction Count: " +
				strconv.FormatUint(limit, 10) + "\n"
			indentationCounter--

			opString += _indt(indentationCounter) + "]\n"
			nftOperationLimitKey = append(nftOperationLimitKey, opString)
		}
		// Ensure deterministic ordering of the transaction count limit strings by doing a lexicographical sort.
		sortStringsAndAddToLimitStr(nftOperationLimitKey)
		indentationCounter--
	}

	// DAOCoinLimitOrderLimitMap
	if len(tsl.DAOCoinLimitOrderLimitMap) > 0 {
		var daoCoinLimitOrderStr []string
		str += _indt(indentationCounter) + "DAO Coin Limit Order Restrictions:\n"
		indentationCounter++
		for limitKey, limit := range tsl.DAOCoinLimitOrderLimitMap {
			opString := _indt(indentationCounter) + "[\n"

			indentationCounter++
			opString += _indt(indentationCounter) + "Buying DAO Creator PKID: " +
				Base58CheckEncode(limitKey.BuyingDAOCoinCreatorPKID.ToBytes(), false, params) + "\n"
			opString += _indt(indentationCounter) + "Selling DAO Creator PKID: " +
				Base58CheckEncode(limitKey.SellingDAOCoinCreatorPKID.ToBytes(), false, params) + "\n"
			opString += _indt(indentationCounter) + "Transaction Count: " +
				strconv.FormatUint(limit, 10) + "\n"
			indentationCounter--

			opString += _indt(indentationCounter) + "]\n"
			daoCoinLimitOrderStr = append(daoCoinLimitOrderStr, opString)
		}
		// Ensure deterministic ordering of the transaction count limit strings by doing a lexicographical sort.
		sortStringsAndAddToLimitStr(daoCoinLimitOrderStr)
		indentationCounter--
	}

	// AssociationLimitMap
	if len(tsl.AssociationLimitMap) > 0 {
		var associationLimitStr []string
		str += _indt(indentationCounter) + "Association Restrictions:\n"
		indentationCounter++
		for limitKey, limit := range tsl.AssociationLimitMap {
			opString := _indt(indentationCounter) + "[\n"

			indentationCounter++
			opString += _indt(indentationCounter) + "Association Class: " +
				limitKey.AssociationClass.ToString() + "\n"
			associationType := strings.ToUpper(limitKey.AssociationType)
			if associationType == "" {
				associationType = "Any"
			}
			opString += _indt(indentationCounter) + "Association Type: " +
				associationType + "\n"
			appPublicKeyBase58Check := "Any"
			if limitKey.AppScopeType == AssociationAppScopeTypeScoped {
				appPublicKeyBase58Check = Base58CheckEncode(limitKey.AppPKID.ToBytes(), false, params)
			}
			opString += _indt(indentationCounter) + "App PKID: " +
				appPublicKeyBase58Check + "\n"
			opString += _indt(indentationCounter) + "Operation: " +
				limitKey.Operation.ToString() + "\n"
			opString += _indt(indentationCounter) + "Transaction Count: " +
				strconv.FormatUint(limit, 10) + "\n"
			indentationCounter--

			opString += _indt(indentationCounter) + "]\n"
			associationLimitStr = append(associationLimitStr, opString)
		}
		// Ensure deterministic ordering of the transaction count limit strings by doing a lexicographical sort.
		sortStringsAndAddToLimitStr(associationLimitStr)
		indentationCounter--
	}

	// AccessGroupMap
	if len(tsl.AccessGroupMap) > 0 {
		var accessGroupStr []string
		str += _indt(indentationCounter) + "Access Group Restrictions:\n"
		indentationCounter++
		for accessGroupKey, limit := range tsl.AccessGroupMap {
			opString := _indt(indentationCounter) + "[\n"

			indentationCounter++
			opString += _indt(indentationCounter) + "Access Group Owner Public Key: " +
				Base58CheckEncode(accessGroupKey.AccessGroupOwnerPublicKey.ToBytes(), false, params) + "\n"
			groupKeyName := string(AccessKeyNameDecode(&accessGroupKey.AccessGroupKeyName))
			if accessGroupKey.AccessGroupScopeType == AccessGroupScopeTypeAny {
				groupKeyName = "Any"
			}
			opString += _indt(indentationCounter) + "Access Group Key Name: " +
				groupKeyName + "\n"
			opString += _indt(indentationCounter) + "Access Group Operation: " +
				accessGroupKey.OperationType.ToString() + "\n"
			opString += _indt(indentationCounter) + "Transaction Count: " +
				strconv.FormatUint(limit, 10) + "\n"

			indentationCounter--
			opString += _indt(indentationCounter) + "]\n"
			accessGroupStr = append(accessGroupStr, opString)
		}
		// Ensure deterministic ordering of the transaction count limit strings by doing a lexicographical sort.
		sortStringsAndAddToLimitStr(accessGroupStr)
		indentationCounter--
	}

	// AccessGroupMemberMap
	if len(tsl.AccessGroupMemberMap) > 0 {
		var accessGroupMemberStr []string
		str += _indt(indentationCounter) + "Access Group Member Restrictions:\n"
		indentationCounter++
		for accessGroupMemberKey, limit := range tsl.AccessGroupMemberMap {
			opString := _indt(indentationCounter) + "[\n"

			indentationCounter++
			opString += _indt(indentationCounter) + "Access Group Owner Public Key: " +
				Base58CheckEncode(accessGroupMemberKey.AccessGroupOwnerPublicKey.ToBytes(), false, params) + "\n"
			groupKeyName := string(AccessKeyNameDecode(&accessGroupMemberKey.AccessGroupKeyName))
			if accessGroupMemberKey.AccessGroupScopeType == AccessGroupScopeTypeAny {
				groupKeyName = "Any"
			}
			opString += _indt(indentationCounter) + "Access Group Key Name: " +
				groupKeyName + "\n"
			opString += _indt(indentationCounter) + "Access Group Member Operation Type: " +
				accessGroupMemberKey.OperationType.ToString() + "\n"
			opString += _indt(indentationCounter) + "Transaction Count: " +
				strconv.FormatUint(limit, 10) + "\n"

			indentationCounter--
			opString += _indt(indentationCounter) + "]\n"
			accessGroupMemberStr = append(accessGroupMemberStr, opString)
		}
		// Ensure deterministic ordering of the transaction count limit strings by doing a lexicographical sort.
		sortStringsAndAddToLimitStr(accessGroupMemberStr)
		indentationCounter--
	}

	// LockupLimitMap
	if len(tsl.LockupLimitMap) > 0 {
		var lockupLimitStr []string
		str += _indt(indentationCounter) + "Lockup Restrictions:\n"
		indentationCounter++
		for limitKey, limit := range tsl.LockupLimitMap {
			opString := _indt(indentationCounter) + "[\n"

			indentationCounter++
			opString += _indt(indentationCounter) + "Lockup Profile PKID: " +
				Base58CheckEncode(limitKey.ProfilePKID.ToBytes(), false, params) + "\n"
			opString += _indt(indentationCounter) + "Lockup Scope: " +
				limitKey.ScopeType.ToString() + "\n"
			opString += _indt(indentationCounter) + "Lockup Operation: " +
				limitKey.Operation.ToString() + "\n"
			opString += _indt(indentationCounter) + "Transaction Count: " +
				strconv.FormatUint(limit, 10) + "\n"
			indentationCounter--

			opString += _indt(indentationCounter) + "]\n"
			lockupLimitStr = append(lockupLimitStr, opString)
		}
		// Ensure deterministic ordering of the transaction count limit strings by doing a lexicographical sort.
		sortStringsAndAddToLimitStr(lockupLimitStr)
		indentationCounter--
	}

	// StakeLimitMap
	if len(tsl.StakeLimitMap) > 0 {
		var stakeLimitStr []string
		str += _indt(indentationCounter) + "Staking Restrictions:\n"
		indentationCounter++
		for limitKey, limit := range tsl.StakeLimitMap {
			opString := _indt(indentationCounter) + "[\n"

			indentationCounter++
			// ValidatorPKID
			validatorPublicKeyBase58Check := "Any"
			if !limitKey.ValidatorPKID.Eq(&ZeroPKID) {
				validatorPublicKeyBase58Check = Base58CheckEncode(limitKey.ValidatorPKID.ToBytes(), false, params)
			}
			opString += _indt(indentationCounter) + "Validator PKID: " + validatorPublicKeyBase58Check + "\n"
			// StakeLimit
			stakeLimitDESO := NewFloat().Quo(
				NewFloat().SetInt(limit.ToBig()), NewFloat().SetUint64(NanosPerUnit),
			)
			opString += _indt(indentationCounter) + fmt.Sprintf("Staking Limit: %.2f $DESO\n", stakeLimitDESO)

			indentationCounter--
			opString += _indt(indentationCounter) + "]\n"
			stakeLimitStr = append(stakeLimitStr, opString)
		}
		// Ensure deterministic ordering of the transaction count limit strings by doing a lexicographical sort.
		sortStringsAndAddToLimitStr(stakeLimitStr)
		indentationCounter--
	}

	// UnstakeLimitMap
	if len(tsl.UnstakeLimitMap) > 0 {
		var unstakeLimitStr []string
		str += _indt(indentationCounter) + "Unstaking Restrictions:\n"
		indentationCounter++
		for limitKey, limit := range tsl.UnstakeLimitMap {
			opString := _indt(indentationCounter) + "[\n"

			indentationCounter++
			// ValidatorPKID
			validatorPublicKeyBase58Check := "Any"
			if !limitKey.ValidatorPKID.Eq(&ZeroPKID) {
				validatorPublicKeyBase58Check = Base58CheckEncode(limitKey.ValidatorPKID.ToBytes(), false, params)
			}
			opString += _indt(indentationCounter) + "Validator PKID: " + validatorPublicKeyBase58Check + "\n"
			// UnstakeLimit
			unstakeLimitDESO := NewFloat().Quo(
				NewFloat().SetInt(limit.ToBig()), NewFloat().SetUint64(NanosPerUnit),
			)
			opString += _indt(indentationCounter) + fmt.Sprintf("Unstaking Limit: %.2f $DESO\n", unstakeLimitDESO)

			indentationCounter--
			opString += _indt(indentationCounter) + "]\n"
			unstakeLimitStr = append(unstakeLimitStr, opString)
		}
		// Ensure deterministic ordering of the transaction count limit strings by doing a lexicographical sort.
		sortStringsAndAddToLimitStr(unstakeLimitStr)
		indentationCounter--
	}

	// UnlockStakeLimitMap
	if len(tsl.UnlockStakeLimitMap) > 0 {
		var unlockStakeLimitStr []string
		str += _indt(indentationCounter) + "Unlocking Stake Restrictions:\n"
		indentationCounter++
		for limitKey, limit := range tsl.UnlockStakeLimitMap {
			opString := _indt(indentationCounter) + "[\n"

			indentationCounter++
			// ValidatorPKID
			validatorPublicKeyBase58Check := "Any"
			if !limitKey.ValidatorPKID.Eq(&ZeroPKID) {
				validatorPublicKeyBase58Check = Base58CheckEncode(limitKey.ValidatorPKID.ToBytes(), false, params)
			}
			opString += _indt(indentationCounter) + "Validator PKID: " + validatorPublicKeyBase58Check + "\n"
			// UnlockStakeLimit
			opString += _indt(indentationCounter) + "Transaction Count: " + strconv.FormatUint(limit, 10) + "\n"

			indentationCounter--
			opString += _indt(indentationCounter) + "]\n"
			unlockStakeLimitStr = append(unlockStakeLimitStr, opString)
		}
		// Ensure deterministic ordering of the transaction count limit strings by doing a lexicographical sort.
		sortStringsAndAddToLimitStr(unlockStakeLimitStr)
		indentationCounter--
	}

	// IsUnlimited
	if tsl.IsUnlimited {
		str += "Unlimited"
	}

	return str
}

func _indt(counter int) string {
	var indentationString string
	for ; counter > 0; counter-- {
		indentationString += "\t"
	}
	return indentationString
}

func (tsl *TransactionSpendingLimit) ToBytes(blockHeight uint64) ([]byte, error) {
	data := []byte{}

	if tsl == nil {
		return data, nil
	}

	// GlobalDESOLimit
	data = append(data, UintToBuf(tsl.GlobalDESOLimit)...)

	// TransactionCountLimitMap
	transactionCountLimitMapLength := uint64(len(tsl.TransactionCountLimitMap))
	data = append(data, UintToBuf(transactionCountLimitMapLength)...)
	if transactionCountLimitMapLength > 0 {
		// Sort the keys
		keys, err := SafeMakeSliceWithLengthAndCapacity[TxnType](0, transactionCountLimitMapLength)
		if err != nil {
			return nil, err
		}
		for key := range tsl.TransactionCountLimitMap {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(ii, jj int) bool {
			return keys[ii] < keys[jj]
		})
		for _, key := range keys {
			data = append(data, UintToBuf(uint64(key))...)
			value := tsl.TransactionCountLimitMap[key]
			data = append(data, UintToBuf(value)...)
		}
	}

	// CreatorCoinOperationLimitMap
	ccOperationLimitMapLength := uint64(len(tsl.CreatorCoinOperationLimitMap))
	data = append(data, UintToBuf(ccOperationLimitMapLength)...)
	if ccOperationLimitMapLength > 0 {
		keys, err := SafeMakeSliceWithLengthAndCapacity[CreatorCoinOperationLimitKey](0, ccOperationLimitMapLength)
		if err != nil {
			return nil, err
		}
		for key := range tsl.CreatorCoinOperationLimitMap {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(ii, jj int) bool {
			return hex.EncodeToString(keys[ii].Encode()) < hex.EncodeToString(keys[jj].Encode())
		})
		for _, key := range keys {
			data = append(data, key.Encode()...)
			data = append(data, UintToBuf(tsl.CreatorCoinOperationLimitMap[key])...)
		}
	}

	// DAOCoinOperationLimitMap
	daoCoinOperationLimitMapLength := uint64(len(tsl.DAOCoinOperationLimitMap))
	data = append(data, UintToBuf(daoCoinOperationLimitMapLength)...)
	if daoCoinOperationLimitMapLength > 0 {
		keys, err := SafeMakeSliceWithLengthAndCapacity[DAOCoinOperationLimitKey](0, daoCoinOperationLimitMapLength)
		if err != nil {
			return nil, err
		}
		for key := range tsl.DAOCoinOperationLimitMap {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(ii, jj int) bool {
			return hex.EncodeToString(keys[ii].Encode()) < hex.EncodeToString(keys[jj].Encode())
		})
		for _, key := range keys {
			data = append(data, key.Encode()...)
			data = append(data, UintToBuf(tsl.DAOCoinOperationLimitMap[key])...)
		}
	}

	// NFTOperationLimitMap
	nftOperationLimitMapLength := uint64(len(tsl.NFTOperationLimitMap))
	data = append(data, UintToBuf(nftOperationLimitMapLength)...)
	if nftOperationLimitMapLength > 0 {
		keys, err := SafeMakeSliceWithLengthAndCapacity[NFTOperationLimitKey](0, nftOperationLimitMapLength)
		if err != nil {
			return nil, err
		}
		for key := range tsl.NFTOperationLimitMap {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(ii, jj int) bool {
			return hex.EncodeToString(keys[ii].Encode()) < hex.EncodeToString(keys[jj].Encode())
		})
		for _, key := range keys {
			data = append(data, key.Encode()...)
			data = append(data, UintToBuf(tsl.NFTOperationLimitMap[key])...)
		}
	}

	// DAOCoinLimitOrderLimitMap
	daoCoinLimitOrderLimitMapLength := uint64(len(tsl.DAOCoinLimitOrderLimitMap))
	data = append(data, UintToBuf(daoCoinLimitOrderLimitMapLength)...)
	if daoCoinLimitOrderLimitMapLength > 0 {
		keys, err := SafeMakeSliceWithLengthAndCapacity[DAOCoinLimitOrderLimitKey](0, daoCoinLimitOrderLimitMapLength)
		if err != nil {
			return nil, err
		}
		for key := range tsl.DAOCoinLimitOrderLimitMap {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(ii, jj int) bool {
			return hex.EncodeToString(keys[ii].Encode()) < hex.EncodeToString(keys[jj].Encode())
		})
		for _, key := range keys {
			data = append(data, key.Encode()...)
			data = append(data, UintToBuf(tsl.DAOCoinLimitOrderLimitMap[key])...)
		}
	}

	// IsUnlimited, gated by the encoder migration.
	if MigrationTriggered(blockHeight, UnlimitedDerivedKeysMigration) {
		data = append(data, BoolToByte(tsl.IsUnlimited))
	}

	// AssociationLimitMap, gated by the encoder migration
	if MigrationTriggered(blockHeight, AssociationsAndAccessGroupsMigration) {
		associationLimitMapLength := uint64(len(tsl.AssociationLimitMap))
		data = append(data, UintToBuf(associationLimitMapLength)...)
		if associationLimitMapLength > 0 {
			keys, err := SafeMakeSliceWithLengthAndCapacity[AssociationLimitKey](0, associationLimitMapLength)
			if err != nil {
				return nil, err
			}
			for key := range tsl.AssociationLimitMap {
				keys = append(keys, key)
			}
			sort.Slice(keys, func(ii, jj int) bool {
				return hex.EncodeToString(keys[ii].Encode()) < hex.EncodeToString(keys[jj].Encode())
			})
			for _, key := range keys {
				data = append(data, key.Encode()...)
				data = append(data, UintToBuf(tsl.AssociationLimitMap[key])...)
			}
		}
	}

	// There happened to be a bug in the encoding of access group spending limits before the balance model fork.
	// The problem was non-deterministic encoding of the tsl.AccessGroupMap. The bug was left for backwards-compatibility,
	// and can be found in the tsl.AccessGroupsToBytesLegacy method.
	//
	// As a result of this bug, checksum computation became non-deterministic, hindering node's ability to accurately
	// compute the checksum. To solve this problem, we patched the encoding in the BalanceModelMigration. Having a new
	// migration will force all nodes on the network to re-encode their checksum using the newest encoding.
	// In the new encoding, the map is encoded in a deterministic way. In addition, we add "safety bytes" after the
	// access group spending limit bytes to ensure there is never an overlap between the legacy and new encodings.
	// This prevents potential issues that could arise in the migration checksum computation.
	if MigrationTriggered(blockHeight, BalanceModelMigration) {

		accessGroupLimitMapLength := uint64(len(tsl.AccessGroupMap))
		data = append(data, UintToBuf(accessGroupLimitMapLength)...)
		if accessGroupLimitMapLength > 0 {
			keys, err := SafeMakeSliceWithLengthAndCapacity[AccessGroupLimitKey](0, accessGroupLimitMapLength)
			if err != nil {
				return nil, err
			}
			for key := range tsl.AccessGroupMap {
				keys = append(keys, key)
			}
			sort.Slice(keys, func(ii, jj int) bool {
				return hex.EncodeToString(keys[ii].Encode()) < hex.EncodeToString(keys[jj].Encode())
			})
			for _, key := range keys {
				data = append(data, key.Encode()...)
				data = append(data, UintToBuf(tsl.AccessGroupMap[key])...)
			}
		}

		accessGroupMemberLimitMapLength := uint64(len(tsl.AccessGroupMemberMap))
		data = append(data, UintToBuf(accessGroupMemberLimitMapLength)...)
		if accessGroupMemberLimitMapLength > 0 {
			keys, err := SafeMakeSliceWithLengthAndCapacity[AccessGroupMemberLimitKey](0, accessGroupMemberLimitMapLength)
			if err != nil {
				return nil, err
			}
			for key := range tsl.AccessGroupMemberMap {
				keys = append(keys, key)
			}
			sort.Slice(keys, func(ii, jj int) bool {
				return hex.EncodeToString(keys[ii].Encode()) < hex.EncodeToString(keys[jj].Encode())
			})
			for _, key := range keys {
				data = append(data, key.Encode()...)
				data = append(data, UintToBuf(tsl.AccessGroupMemberMap[key])...)
			}
		}

	} else if MigrationTriggered(blockHeight, AssociationsAndAccessGroupsMigration) {
		accessGroupsBytes, err := tsl.AccessGroupsToBytesLegacy(blockHeight)
		if err != nil {
			return nil, err
		}
		data = append(data, accessGroupsBytes...)
	}

	// StakeLimitMap, UnstakeLimitMap, and UnlockStakeLimitMap, gated by the encoder migration.
	if MigrationTriggered(blockHeight, ProofOfStake1StateSetupMigration) {
		// LockupLimitMap
		lockupLimitMapLength := uint64(len(tsl.LockupLimitMap))
		data = append(data, UintToBuf(lockupLimitMapLength)...)
		if lockupLimitMapLength > 0 {
			keys, err := SafeMakeSliceWithLengthAndCapacity[LockupLimitKey](0, lockupLimitMapLength)
			if err != nil {
				return nil, err
			}
			for key := range tsl.LockupLimitMap {
				keys = append(keys, key)
			}
			// Sort the keys to ensure deterministic ordering.
			sort.Slice(keys, func(ii, jj int) bool {
				return hex.EncodeToString(keys[ii].Encode()) < hex.EncodeToString(keys[jj].Encode())
			})
			for _, key := range keys {
				data = append(data, key.Encode()...)
				data = append(data, UintToBuf(tsl.LockupLimitMap[key])...)
			}
		}

		// StakeLimitMap
		stakeLimitMapLength := uint64(len(tsl.StakeLimitMap))
		data = append(data, UintToBuf(stakeLimitMapLength)...)
		if stakeLimitMapLength > 0 {
			keys, err := SafeMakeSliceWithLengthAndCapacity[StakeLimitKey](0, stakeLimitMapLength)
			if err != nil {
				return nil, err
			}
			for key := range tsl.StakeLimitMap {
				keys = append(keys, key)
			}
			// Sort the keys to ensure deterministic ordering.
			sort.Slice(keys, func(ii, jj int) bool {
				return hex.EncodeToString(keys[ii].Encode()) < hex.EncodeToString(keys[jj].Encode())
			})
			for _, key := range keys {
				data = append(data, key.Encode()...)
				data = append(data, VariableEncodeUint256(tsl.StakeLimitMap[key])...)
			}
		}

		// UnstakeLimitMap
		unstakeLimitMapLength := uint64(len(tsl.UnstakeLimitMap))
		data = append(data, UintToBuf(unstakeLimitMapLength)...)
		if unstakeLimitMapLength > 0 {
			keys, err := SafeMakeSliceWithLengthAndCapacity[StakeLimitKey](0, unstakeLimitMapLength)
			if err != nil {
				return nil, err
			}
			for key := range tsl.UnstakeLimitMap {
				keys = append(keys, key)
			}
			// Sort the keys to ensure deterministic ordering.
			sort.Slice(keys, func(ii, jj int) bool {
				return hex.EncodeToString(keys[ii].Encode()) < hex.EncodeToString(keys[jj].Encode())
			})
			for _, key := range keys {
				data = append(data, key.Encode()...)
				data = append(data, VariableEncodeUint256(tsl.UnstakeLimitMap[key])...)
			}
		}

		// UnlockStakeLimitMap
		unlockStakeLimitMapLength := uint64(len(tsl.UnlockStakeLimitMap))
		data = append(data, UintToBuf(unlockStakeLimitMapLength)...)
		if unlockStakeLimitMapLength > 0 {
			keys, err := SafeMakeSliceWithLengthAndCapacity[StakeLimitKey](0, unlockStakeLimitMapLength)
			if err != nil {
				return nil, err
			}
			for key := range tsl.UnlockStakeLimitMap {
				keys = append(keys, key)
			}
			// Sort the keys to ensure deterministic ordering.
			sort.Slice(keys, func(ii, jj int) bool {
				return hex.EncodeToString(keys[ii].Encode()) < hex.EncodeToString(keys[jj].Encode())
			})
			for _, key := range keys {
				data = append(data, key.Encode()...)
				data = append(data, UintToBuf(tsl.UnlockStakeLimitMap[key])...)
			}
		}
	}

	return data, nil
}

func (tsl *TransactionSpendingLimit) FromBytes(blockHeight uint64, rr *bytes.Reader) error {
	globalDESOLimit, err := ReadUvarint(rr)
	if err != nil {
		return err
	}
	tsl.GlobalDESOLimit = globalDESOLimit

	transactionSpendingLimitLen, err := ReadUvarint(rr)
	if err != nil {
		return err
	}
	tsl.TransactionCountLimitMap = make(map[TxnType]uint64)
	if transactionSpendingLimitLen > 0 {
		for ii := uint64(0); ii < transactionSpendingLimitLen; ii++ {
			key, err := ReadUvarint(rr)
			if err != nil {
				return err
			}
			val, err := ReadUvarint(rr)
			if err != nil {
				return err
			}
			// Make sure it doesn't already exist in the map
			if _, exists := tsl.TransactionCountLimitMap[TxnType(key)]; exists {
				return fmt.Errorf("Key already exists in map")
			}
			tsl.TransactionCountLimitMap[TxnType(key)] = val
		}
	}

	ccOperationLimitMapLen, err := ReadUvarint(rr)
	if err != nil {
		return err
	}
	tsl.CreatorCoinOperationLimitMap = make(map[CreatorCoinOperationLimitKey]uint64)
	if ccOperationLimitMapLen > 0 {
		for ii := uint64(0); ii < ccOperationLimitMapLen; ii++ {
			ccOperationLimitMapKey := &CreatorCoinOperationLimitKey{}
			if err = ccOperationLimitMapKey.Decode(rr); err != nil {
				return errors.Wrap(err, "Error decoding Creator Coin Operation Limit Key")
			}
			var operationCount uint64
			operationCount, err = ReadUvarint(rr)
			if err != nil {
				return err
			}
			if _, exists := tsl.CreatorCoinOperationLimitMap[*ccOperationLimitMapKey]; exists {
				return fmt.Errorf("Creator Coin Operation Limit Key already exists in map")
			}
			tsl.CreatorCoinOperationLimitMap[*ccOperationLimitMapKey] = operationCount
		}
	}

	daoCoinOperationLimitMapLen, err := ReadUvarint(rr)
	if err != nil {
		return err
	}
	tsl.DAOCoinOperationLimitMap = make(map[DAOCoinOperationLimitKey]uint64)
	if daoCoinOperationLimitMapLen > 0 {
		for ii := uint64(0); ii < daoCoinOperationLimitMapLen; ii++ {
			daoCoinOperationLimitMapKey := &DAOCoinOperationLimitKey{}
			if err = daoCoinOperationLimitMapKey.Decode(rr); err != nil {
				return errors.Wrap(err, "Error decoding DAO Coin Operation Limit Key")
			}
			var operationCount uint64
			operationCount, err = ReadUvarint(rr)
			if err != nil {
				return err
			}
			if _, exists := tsl.DAOCoinOperationLimitMap[*daoCoinOperationLimitMapKey]; exists {
				return fmt.Errorf("DAO Coin Operation Limit Key already exists in map")
			}
			tsl.DAOCoinOperationLimitMap[*daoCoinOperationLimitMapKey] = operationCount
		}
	}

	nftOperationLimitMapLen, err := ReadUvarint(rr)
	if err != nil {
		return err
	}
	tsl.NFTOperationLimitMap = make(map[NFTOperationLimitKey]uint64)
	if nftOperationLimitMapLen > 0 {
		for ii := uint64(0); ii < nftOperationLimitMapLen; ii++ {
			nftOperationLimitMapKey := &NFTOperationLimitKey{}
			if err = nftOperationLimitMapKey.Decode(rr); err != nil {
				return errors.Wrap(err, "Error decoding NFT Operation Limit Key")
			}
			var operationCount uint64
			operationCount, err = ReadUvarint(rr)
			if err != nil {
				return err
			}
			if _, exists := tsl.NFTOperationLimitMap[*nftOperationLimitMapKey]; exists {
				return fmt.Errorf("NFT Limit Operation Key already exists in map")
			}
			tsl.NFTOperationLimitMap[*nftOperationLimitMapKey] = operationCount
		}
	}

	daoCoinLimitOrderMapLen, err := ReadUvarint(rr)
	if err != nil {
		return err
	}
	tsl.DAOCoinLimitOrderLimitMap = make(map[DAOCoinLimitOrderLimitKey]uint64)
	if daoCoinLimitOrderMapLen > 0 {
		for ii := uint64(0); ii < daoCoinLimitOrderMapLen; ii++ {
			daoCoinLimitOrderLimitKey := &DAOCoinLimitOrderLimitKey{}
			if err = daoCoinLimitOrderLimitKey.Decode(rr); err != nil {
				return errors.Wrap(err, "Error decoding DAO Coin Limit Order Key")
			}
			var operationCount uint64
			operationCount, err = ReadUvarint(rr)
			if err != nil {
				return err
			}
			if _, exists := tsl.DAOCoinLimitOrderLimitMap[*daoCoinLimitOrderLimitKey]; exists {
				return fmt.Errorf("DAO Coin Limit Order Key already exists in map")
			}
			tsl.DAOCoinLimitOrderLimitMap[*daoCoinLimitOrderLimitKey] = operationCount
		}
	}

	if MigrationTriggered(blockHeight, UnlimitedDerivedKeysMigration) {
		tsl.IsUnlimited, err = ReadBoolByte(rr)
		if err != nil {
			return errors.Wrapf(err, "TransactionSpendingLimit.FromBytes: Problem reading IsUnlimited")
		}
	}

	if MigrationTriggered(blockHeight, AssociationsAndAccessGroupsMigration) {
		associationMapLen, err := ReadUvarint(rr)
		if err != nil {
			return err
		}
		tsl.AssociationLimitMap = make(map[AssociationLimitKey]uint64)
		if associationMapLen > 0 {
			for ii := uint64(0); ii < associationMapLen; ii++ {
				associationLimitKey := &AssociationLimitKey{}
				if err = associationLimitKey.Decode(rr); err != nil {
					return errors.Wrap(err, "Error decoding Association Key")
				}
				var operationCount uint64
				operationCount, err = ReadUvarint(rr)
				if err != nil {
					return err
				}
				if _, exists := tsl.AssociationLimitMap[*associationLimitKey]; exists {
					return errors.New("Association Key already exists in map")
				}
				tsl.AssociationLimitMap[*associationLimitKey] = operationCount
			}
		}
	}

	if MigrationTriggered(blockHeight, AssociationsAndAccessGroupsMigration) ||
		MigrationTriggered(blockHeight, BalanceModelMigration) {

		// Access Group Map
		accessGroupLimitMapLen, err := ReadUvarint(rr)
		if err != nil {
			return err
		}
		tsl.AccessGroupMap = make(map[AccessGroupLimitKey]uint64)
		if accessGroupLimitMapLen > 0 {
			for ii := uint64(0); ii < accessGroupLimitMapLen; ii++ {
				accessGroupLimitKey := &AccessGroupLimitKey{}
				if err = accessGroupLimitKey.Decode(rr); err != nil {
					return errors.Wrapf(err, "Error decoding access group limit key")
				}
				var operationCount uint64
				operationCount, err = ReadUvarint(rr)
				if err != nil {
					return err
				}
				if _, exists := tsl.AccessGroupMap[*accessGroupLimitKey]; exists {
					return fmt.Errorf("Access group limit key already exists")
				}
				tsl.AccessGroupMap[*accessGroupLimitKey] = operationCount
			}
		}

		// Access Group Member Map
		accessGroupMemberLimitMapLen, err := ReadUvarint(rr)
		if err != nil {
			return err
		}
		tsl.AccessGroupMemberMap = make(map[AccessGroupMemberLimitKey]uint64)
		if accessGroupMemberLimitMapLen > 0 {
			for ii := uint64(0); ii < accessGroupMemberLimitMapLen; ii++ {
				accessGroupMemberLimitKey := &AccessGroupMemberLimitKey{}
				if err = accessGroupMemberLimitKey.Decode(rr); err != nil {
					return errors.Wrapf(err, "Error decoding access group member limit key")
				}
				var operationCount uint64
				operationCount, err = ReadUvarint(rr)
				if err != nil {
					return err
				}
				if _, exists := tsl.AccessGroupMemberMap[*accessGroupMemberLimitKey]; exists {
					return fmt.Errorf("Access group member limit key already exists")
				}
				tsl.AccessGroupMemberMap[*accessGroupMemberLimitKey] = operationCount
			}
		}
	}

	// StakeLimitMap, UnstakeLimitMap, and UnlockStakeLimitMap, gated by the encoder migration.
	if MigrationTriggered(blockHeight, ProofOfStake1StateSetupMigration) {
		// LockupLimitMap
		lockupLimitMapLen, err := ReadUvarint(rr)
		if err != nil {
			return err
		}
		tsl.LockupLimitMap = make(map[LockupLimitKey]uint64)
		if lockupLimitMapLen > 0 {
			for ii := uint64(0); ii < lockupLimitMapLen; ii++ {
				lockupLimitKey := &LockupLimitKey{}
				if err = lockupLimitKey.Decode(rr); err != nil {
					return errors.Wrap(err, "Error decoding LockupLimitKey: ")
				}
				var operationCount uint64
				operationCount, err = ReadUvarint(rr)
				if err != nil {
					return errors.Wrap(err, "Error decoding OperationCount for LockupLimitKey: ")
				}
				if _, keyExists := tsl.LockupLimitMap[*lockupLimitKey]; keyExists {
					return errors.New("LockupLimitKey already exists")
				}
				tsl.LockupLimitMap[*lockupLimitKey] = operationCount
			}
		}

		// StakeLimitMap
		stakeLimitMapLen, err := ReadUvarint(rr)
		if err != nil {
			return err
		}
		tsl.StakeLimitMap = make(map[StakeLimitKey]*uint256.Int)
		if stakeLimitMapLen > 0 {
			for ii := uint64(0); ii < stakeLimitMapLen; ii++ {
				stakeLimitKey := &StakeLimitKey{}
				if err = stakeLimitKey.Decode(rr); err != nil {
					return errors.Wrap(err, "Error decoding StakeLimitKey: ")
				}
				var stakeLimitDESONanos *uint256.Int
				stakeLimitDESONanos, err = VariableDecodeUint256(rr)
				if err != nil {
					return err
				}
				if _, exists := tsl.StakeLimitMap[*stakeLimitKey]; exists {
					return errors.New("StakeLimitKey already exists in StakeLimitMap")
				}
				tsl.StakeLimitMap[*stakeLimitKey] = stakeLimitDESONanos
			}
		}

		// UnstakeLimitMap
		unstakeLimitMapLen, err := ReadUvarint(rr)
		if err != nil {
			return err
		}
		tsl.UnstakeLimitMap = make(map[StakeLimitKey]*uint256.Int)
		if unstakeLimitMapLen > 0 {
			for ii := uint64(0); ii < unstakeLimitMapLen; ii++ {
				stakeLimitKey := &StakeLimitKey{}
				if err = stakeLimitKey.Decode(rr); err != nil {
					return errors.Wrap(err, "Error decoding StakeLimitKey: ")
				}
				var unstakeLimitDESONanos *uint256.Int
				unstakeLimitDESONanos, err = VariableDecodeUint256(rr)
				if err != nil {
					return err
				}
				if _, exists := tsl.UnstakeLimitMap[*stakeLimitKey]; exists {
					return errors.New("StakeLimitKey already exists in UnstakeLimitMap")
				}
				tsl.UnstakeLimitMap[*stakeLimitKey] = unstakeLimitDESONanos
			}
		}

		// UnlockStakeLimitMap
		unlockStakeLimitMapLen, err := ReadUvarint(rr)
		if err != nil {
			return err
		}
		tsl.UnlockStakeLimitMap = make(map[StakeLimitKey]uint64)
		if unlockStakeLimitMapLen > 0 {
			for ii := uint64(0); ii < unlockStakeLimitMapLen; ii++ {
				stakeLimitKey := &StakeLimitKey{}
				if err = stakeLimitKey.Decode(rr); err != nil {
					return errors.Wrap(err, "Error decoding StakeLimitKey: ")
				}
				var operationCount uint64
				operationCount, err = ReadUvarint(rr)
				if err != nil {
					return err
				}
				if _, exists := tsl.UnlockStakeLimitMap[*stakeLimitKey]; exists {
					return errors.New("StakeLimitKey already exists in UnlockStakeLimitMap")
				}
				tsl.UnlockStakeLimitMap[*stakeLimitKey] = operationCount
			}
		}
	}

	return nil
}

func (tsl *TransactionSpendingLimit) AccessGroupsToBytesLegacy(blockHeight uint64) ([]byte, error) {
	data := []byte{}

	accessGroupLimitMapLength := uint64(len(tsl.AccessGroupMap))
	data = append(data, UintToBuf(accessGroupLimitMapLength)...)
	if accessGroupLimitMapLength > 0 {
		keys, err := SafeMakeSliceWithLengthAndCapacity[AccessGroupLimitKey](0, accessGroupLimitMapLength)
		if err != nil {
			return nil, err
		}
		for key := range tsl.AccessGroupMap {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(ii, jj int) bool {
			return hex.EncodeToString(keys[ii].Encode()) < hex.EncodeToString(keys[jj].Encode())
		})
		for key := range tsl.AccessGroupMap {
			data = append(data, key.Encode()...)
			data = append(data, UintToBuf(tsl.AccessGroupMap[key])...)
		}
	}

	accessGroupMemberLimitMapLength := uint64(len(tsl.AccessGroupMemberMap))
	data = append(data, UintToBuf(accessGroupMemberLimitMapLength)...)
	if accessGroupMemberLimitMapLength > 0 {
		keys, err := SafeMakeSliceWithLengthAndCapacity[AccessGroupMemberLimitKey](0, accessGroupMemberLimitMapLength)
		if err != nil {
			return nil, err
		}
		for key := range tsl.AccessGroupMemberMap {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(ii, jj int) bool {
			return hex.EncodeToString(keys[ii].Encode()) < hex.EncodeToString(keys[jj].Encode())
		})
		for _, key := range keys {
			data = append(data, key.Encode()...)
			data = append(data, UintToBuf(tsl.AccessGroupMemberMap[key])...)
		}
	}
	return data, nil
}

func (tsl *TransactionSpendingLimit) Copy() *TransactionSpendingLimit {
	copyTSL := &TransactionSpendingLimit{
		GlobalDESOLimit:              tsl.GlobalDESOLimit,
		TransactionCountLimitMap:     make(map[TxnType]uint64),
		CreatorCoinOperationLimitMap: make(map[CreatorCoinOperationLimitKey]uint64),
		DAOCoinOperationLimitMap:     make(map[DAOCoinOperationLimitKey]uint64),
		NFTOperationLimitMap:         make(map[NFTOperationLimitKey]uint64),
		DAOCoinLimitOrderLimitMap:    make(map[DAOCoinLimitOrderLimitKey]uint64),
		AccessGroupMap:               make(map[AccessGroupLimitKey]uint64),
		AccessGroupMemberMap:         make(map[AccessGroupMemberLimitKey]uint64),
		LockupLimitMap:               make(map[LockupLimitKey]uint64),
		StakeLimitMap:                make(map[StakeLimitKey]*uint256.Int),
		UnstakeLimitMap:              make(map[StakeLimitKey]*uint256.Int),
		UnlockStakeLimitMap:          make(map[StakeLimitKey]uint64),
		IsUnlimited:                  tsl.IsUnlimited,
	}

	for txnType, txnCount := range tsl.TransactionCountLimitMap {
		copyTSL.TransactionCountLimitMap[txnType] = txnCount
	}

	for ccOp, ccOpCount := range tsl.CreatorCoinOperationLimitMap {
		copyTSL.CreatorCoinOperationLimitMap[ccOp] = ccOpCount
	}

	for daoOp, daoOpCount := range tsl.DAOCoinOperationLimitMap {
		copyTSL.DAOCoinOperationLimitMap[daoOp] = daoOpCount
	}

	for nftOp, nftOpCount := range tsl.NFTOperationLimitMap {
		copyTSL.NFTOperationLimitMap[nftOp] = nftOpCount
	}

	for daoCoinLimitOrderLimitKey, daoCoinLimitOrderCount := range tsl.DAOCoinLimitOrderLimitMap {
		copyTSL.DAOCoinLimitOrderLimitMap[daoCoinLimitOrderLimitKey] = daoCoinLimitOrderCount
	}

	if tsl.AssociationLimitMap != nil {
		// Before the AssociationsAndAccessGroupsBlockHeight, this map will
		// be null. So we should ensure this is the case in the copy too.
		copyTSL.AssociationLimitMap = make(map[AssociationLimitKey]uint64)
		for associationLimitKey, associationCount := range tsl.AssociationLimitMap {
			copyTSL.AssociationLimitMap[associationLimitKey] = associationCount
		}
	}

	for accessGroupLimitKey, accessGroupCount := range tsl.AccessGroupMap {
		copyTSL.AccessGroupMap[accessGroupLimitKey] = accessGroupCount
	}

	for accessGroupMemberLimitKey, accessGroupMemberCount := range tsl.AccessGroupMemberMap {
		copyTSL.AccessGroupMemberMap[accessGroupMemberLimitKey] = accessGroupMemberCount
	}

	for lockupLimitKey, lockupLimit := range tsl.LockupLimitMap {
		copyTSL.LockupLimitMap[lockupLimitKey] = lockupLimit
	}

	for stakeLimitKey, stakeLimitDESONanos := range tsl.StakeLimitMap {
		copyTSL.StakeLimitMap[stakeLimitKey] = stakeLimitDESONanos.Clone()
	}

	for stakeLimitKey, unstakeLimitDESONanos := range tsl.UnstakeLimitMap {
		copyTSL.UnstakeLimitMap[stakeLimitKey] = unstakeLimitDESONanos.Clone()
	}

	for stakeLimitKey, unlockStakeOperationCount := range tsl.UnlockStakeLimitMap {
		copyTSL.UnlockStakeLimitMap[stakeLimitKey] = unlockStakeOperationCount
	}

	return copyTSL
}

func (bav *UtxoView) CheckIfValidUnlimitedSpendingLimit(tsl *TransactionSpendingLimit, blockHeight uint32) (_isUnlimited bool, _err error) {
	AssertDependencyStructFieldNumbers(&TransactionSpendingLimit{}, 14)

	if tsl.IsUnlimited && blockHeight < bav.Params.ForkHeights.DeSoUnlimitedDerivedKeysBlockHeight {
		return false, RuleErrorUnlimitedDerivedKeyBeforeBlockHeight
	}

	// Note: We don't need a blockheight here to gate access group nor access group member maps. They will always be
	// empty prior to the fork block height, and should be empty after the blockheight for the unlimited spending limit.
	if tsl.IsUnlimited && (tsl.GlobalDESOLimit > 0 ||
		len(tsl.TransactionCountLimitMap) > 0 ||
		len(tsl.CreatorCoinOperationLimitMap) > 0 ||
		len(tsl.DAOCoinOperationLimitMap) > 0 ||
		len(tsl.NFTOperationLimitMap) > 0 ||
		len(tsl.DAOCoinLimitOrderLimitMap) > 0 ||
		len(tsl.AssociationLimitMap) > 0 ||
		len(tsl.AccessGroupMap) > 0 ||
		len(tsl.AccessGroupMemberMap) > 0 ||
		len(tsl.LockupLimitMap) > 0 ||
		len(tsl.StakeLimitMap) > 0 ||
		len(tsl.UnstakeLimitMap) > 0 ||
		len(tsl.UnlockStakeLimitMap) > 0) {
		return tsl.IsUnlimited, RuleErrorUnlimitedDerivedKeyNonEmptySpendingLimits
	}

	return tsl.IsUnlimited, nil
}

type NFTLimitOperation uint8

const (
	AnyNFTOperation            NFTLimitOperation = 0
	UpdateNFTOperation         NFTLimitOperation = 1
	AcceptNFTBidOperation      NFTLimitOperation = 2
	NFTBidOperation            NFTLimitOperation = 3
	TransferNFTOperation       NFTLimitOperation = 4
	BurnNFTOperation           NFTLimitOperation = 5
	AcceptNFTTransferOperation NFTLimitOperation = 6
	UndefinedNFTOperation      NFTLimitOperation = 7
)

type NFTLimitOperationString string

const (
	AnyNFTOperationString            NFTLimitOperationString = "any"
	UpdateNFTOperationString         NFTLimitOperationString = "update"
	AcceptNFTBidOperationString      NFTLimitOperationString = "accept_nft_bid"
	NFTBidOperationString            NFTLimitOperationString = "nft_bid"
	TransferNFTOperationString       NFTLimitOperationString = "transfer"
	BurnNFTOperationString           NFTLimitOperationString = "burn"
	AcceptNFTTransferOperationString NFTLimitOperationString = "accept_nft_transfer"
	UndefinedNFTOperationString      NFTLimitOperationString = "undefined"
)

func (nftLimitOperation NFTLimitOperation) ToString() string {
	return string(nftLimitOperation.ToNFTLimitOperationString())
}

func (nftLimitOperation NFTLimitOperation) ToNFTLimitOperationString() NFTLimitOperationString {
	switch nftLimitOperation {
	case AnyNFTOperation:
		return AnyNFTOperationString
	case UpdateNFTOperation:
		return UpdateNFTOperationString
	case AcceptNFTBidOperation:
		return AcceptNFTBidOperationString
	case NFTBidOperation:
		return NFTBidOperationString
	case TransferNFTOperation:
		return TransferNFTOperationString
	case BurnNFTOperation:
		return BurnNFTOperationString
	case AcceptNFTTransferOperation:
		return AcceptNFTTransferOperationString
	default:
		return UndefinedNFTOperationString
	}
}

func (nftLimitOperationString NFTLimitOperationString) ToNFTLimitOperation() NFTLimitOperation {
	switch nftLimitOperationString {
	case AnyNFTOperationString:
		return AnyNFTOperation
	case UpdateNFTOperationString:
		return UpdateNFTOperation
	case AcceptNFTBidOperationString:
		return AcceptNFTBidOperation
	case NFTBidOperationString:
		return NFTBidOperation
	case TransferNFTOperationString:
		return TransferNFTOperation
	case BurnNFTOperationString:
		return BurnNFTOperation
	case AcceptNFTTransferOperationString:
		return AcceptNFTTransferOperation
	default:
		return UndefinedNFTOperation
	}
}

func (nftLimitOperation NFTLimitOperation) IsUndefined() bool {
	return nftLimitOperation == UndefinedNFTOperation
}

type NFTOperationLimitKey struct {
	BlockHash    BlockHash
	SerialNumber uint64
	Operation    NFTLimitOperation
}

func (nftOperationLimitKey NFTOperationLimitKey) Encode() []byte {
	var data []byte
	blockHash := nftOperationLimitKey.BlockHash.ToBytes()
	data = append(data, UintToBuf(uint64(len(blockHash)))...)
	data = append(data, blockHash...)
	data = append(data, UintToBuf(nftOperationLimitKey.SerialNumber)...)
	data = append(data, UintToBuf(uint64(nftOperationLimitKey.Operation))...)
	return data
}

func (nftOperationLimitKey *NFTOperationLimitKey) Decode(rr *bytes.Reader) error {
	blockHashLen, err := ReadUvarint(rr)
	if err != nil {
		return err
	}
	// De-serialize the key
	blockhashBytes, err := SafeMakeSliceWithLength[byte](blockHashLen)
	if err != nil {
		return err
	}
	if _, err = io.ReadFull(rr, blockhashBytes); err != nil {
		return err
	}
	blockHash := NewBlockHash(blockhashBytes)
	if blockHash == nil {
		return fmt.Errorf("Invalid block hash")
	}
	nftOperationLimitKey.BlockHash = *blockHash
	serialNum, err := ReadUvarint(rr)
	if err != nil {
		return err
	}
	nftOperationLimitKey.SerialNumber = serialNum
	operationKey, err := ReadUvarint(rr)
	if err != nil {
		return err
	}
	nftOperationLimitKey.Operation = NFTLimitOperation(operationKey)
	return nil
}

func MakeNFTOperationLimitKey(blockHash BlockHash, serialNumber uint64, operation NFTLimitOperation) NFTOperationLimitKey {
	return NFTOperationLimitKey{
		blockHash,
		serialNumber,
		operation,
	}
}

// The operations that are permitted to be performed by a derived key.
type CreatorCoinLimitOperation uint8

const (
	AnyCreatorCoinOperation       CreatorCoinLimitOperation = 0
	BuyCreatorCoinOperation       CreatorCoinLimitOperation = 1
	SellCreatorCoinOperation      CreatorCoinLimitOperation = 2
	TransferCreatorCoinOperation  CreatorCoinLimitOperation = 3
	UndefinedCreatorCoinOperation CreatorCoinLimitOperation = 4
)

type CreatorCoinLimitOperationString string

const (
	AnyCreatorCoinOperationString       CreatorCoinLimitOperationString = "any"
	BuyCreatorCoinOperationString       CreatorCoinLimitOperationString = "buy"
	SellCreatorCoinOperationString      CreatorCoinLimitOperationString = "sell"
	TransferCreatorCoinOperationString  CreatorCoinLimitOperationString = "transfer"
	UndefinedCreatorCoinOperationString CreatorCoinLimitOperationString = "undefined"
)

func (creatorCoinLimitOperation CreatorCoinLimitOperation) ToString() string {
	return string(creatorCoinLimitOperation.ToCreatorCoinLimitOperationString())
}

func (creatorCoinLimitOperation CreatorCoinLimitOperation) ToCreatorCoinLimitOperationString() CreatorCoinLimitOperationString {
	switch creatorCoinLimitOperation {
	case AnyCreatorCoinOperation:
		return AnyCreatorCoinOperationString
	case BuyCreatorCoinOperation:
		return BuyCreatorCoinOperationString
	case SellCreatorCoinOperation:
		return SellCreatorCoinOperationString
	case TransferCreatorCoinOperation:
		return TransferCreatorCoinOperationString
	default:
		return UndefinedCreatorCoinOperationString
	}
}

func (creatorCoinLimitOperationString CreatorCoinLimitOperationString) ToCreatorCoinLimitOperation() CreatorCoinLimitOperation {
	switch creatorCoinLimitOperationString {
	case AnyCreatorCoinOperationString:
		return AnyCreatorCoinOperation
	case BuyCreatorCoinOperationString:
		return BuyCreatorCoinOperation
	case SellCreatorCoinOperationString:
		return SellCreatorCoinOperation
	case TransferCreatorCoinOperationString:
		return TransferCreatorCoinOperation
	default:
		return UndefinedCreatorCoinOperation
	}
}

func (creatorCoinLimitOperation CreatorCoinLimitOperation) IsUndefined() bool {
	return creatorCoinLimitOperation == UndefinedCreatorCoinOperation
}

type CreatorCoinOperationLimitKey struct {
	CreatorPKID PKID
	Operation   CreatorCoinLimitOperation
}

func (creatorCoinOperationLimitKey CreatorCoinOperationLimitKey) Encode() []byte {
	var data []byte
	creatorPKIDBytes := creatorCoinOperationLimitKey.CreatorPKID.ToBytes()
	data = append(data, UintToBuf(uint64(len(creatorPKIDBytes)))...)
	data = append(data, creatorPKIDBytes...)
	data = append(data, UintToBuf(uint64(creatorCoinOperationLimitKey.Operation))...)
	return data
}

func (creatorCoinOperationLimitKey *CreatorCoinOperationLimitKey) Decode(rr *bytes.Reader) error {
	creatorPKIDBytesLen, err := ReadUvarint(rr)
	if err != nil {
		return err
	}
	// De-serialize the key
	creatorPKIDBytes, err := SafeMakeSliceWithLength[byte](creatorPKIDBytesLen)
	if err != nil {
		return err
	}
	if _, err = io.ReadFull(rr, creatorPKIDBytes); err != nil {
		return err
	}
	creatorPKID := NewPKID(creatorPKIDBytes)
	if creatorPKID == nil {
		return fmt.Errorf("Invalid PKID")
	}
	creatorCoinOperationLimitKey.CreatorPKID = *creatorPKID
	operationKey, err := ReadUvarint(rr)
	if err != nil {
		return err
	}
	creatorCoinOperationLimitKey.Operation = CreatorCoinLimitOperation(operationKey)
	return nil
}

func MakeCreatorCoinOperationLimitKey(creatorPKID PKID, operation CreatorCoinLimitOperation) CreatorCoinOperationLimitKey {
	return CreatorCoinOperationLimitKey{
		creatorPKID,
		operation,
	}
}

type DAOCoinLimitOperation uint8

const (
	AnyDAOCoinOperation                             DAOCoinLimitOperation = 0
	MintDAOCoinOperation                            DAOCoinLimitOperation = 1
	BurnDAOCoinOperation                            DAOCoinLimitOperation = 2
	DisableMintingDAOCoinOperation                  DAOCoinLimitOperation = 3
	UpdateTransferRestrictionStatusDAOCoinOperation DAOCoinLimitOperation = 4
	TransferDAOCoinOperation                        DAOCoinLimitOperation = 5
	UndefinedDAOCoinOperation                       DAOCoinLimitOperation = 6
)

type DAOCoinLimitOperationString string

const (
	AnyDAOCoinOperationString                             DAOCoinLimitOperationString = "any"
	MintDAOCoinOperationString                            DAOCoinLimitOperationString = "mint"
	BurnDAOCoinOperationString                            DAOCoinLimitOperationString = "burn"
	DisableMintingDAOCoinOperationString                  DAOCoinLimitOperationString = "disable_minting"
	UpdateTransferRestrictionStatusDAOCoinOperationString DAOCoinLimitOperationString = "update_transfer_restriction_status"
	TransferDAOCoinOperationString                        DAOCoinLimitOperationString = "transfer"
	UndefinedDAOCoinOperationString                       DAOCoinLimitOperationString = "undefined"
)

func (daoCoinLimitOperation DAOCoinLimitOperation) ToString() string {
	return string(daoCoinLimitOperation.ToDAOCoinLimitOperationString())
}

func (daoCoinLimitOperation DAOCoinLimitOperation) ToDAOCoinLimitOperationString() DAOCoinLimitOperationString {
	switch daoCoinLimitOperation {
	case AnyDAOCoinOperation:
		return AnyDAOCoinOperationString
	case MintDAOCoinOperation:
		return MintDAOCoinOperationString
	case BurnDAOCoinOperation:
		return BurnDAOCoinOperationString
	case DisableMintingDAOCoinOperation:
		return DisableMintingDAOCoinOperationString
	case UpdateTransferRestrictionStatusDAOCoinOperation:
		return UpdateTransferRestrictionStatusDAOCoinOperationString
	case TransferDAOCoinOperation:
		return TransferDAOCoinOperationString
	default:
		return UndefinedDAOCoinOperationString
	}
}

func (daoCoinLimitOperationString DAOCoinLimitOperationString) ToDAOCoinLimitOperation() DAOCoinLimitOperation {
	switch daoCoinLimitOperationString {
	case AnyDAOCoinOperationString:
		return AnyDAOCoinOperation
	case MintDAOCoinOperationString:
		return MintDAOCoinOperation
	case BurnDAOCoinOperationString:
		return BurnDAOCoinOperation
	case DisableMintingDAOCoinOperationString:
		return DisableMintingDAOCoinOperation
	case UpdateTransferRestrictionStatusDAOCoinOperationString:
		return UpdateTransferRestrictionStatusDAOCoinOperation
	case TransferDAOCoinOperationString:
		return TransferDAOCoinOperation
	default:
		return UndefinedDAOCoinOperation
	}
}

func (daoCoinLimitOperation DAOCoinLimitOperation) IsUndefined() bool {
	return daoCoinLimitOperation == UndefinedDAOCoinOperation
}

type DAOCoinOperationLimitKey struct {
	CreatorPKID PKID
	Operation   DAOCoinLimitOperation
}

func (daoCoinOperationLimitKey DAOCoinOperationLimitKey) Encode() []byte {
	var data []byte
	creatorPKIDBytes := daoCoinOperationLimitKey.CreatorPKID.ToBytes()
	data = append(data, UintToBuf(uint64(len(creatorPKIDBytes)))...)
	data = append(data, creatorPKIDBytes...)
	data = append(data, UintToBuf(uint64(daoCoinOperationLimitKey.Operation))...)
	return data
}

func (daoCoinOperationLimitKey *DAOCoinOperationLimitKey) Decode(rr *bytes.Reader) error {
	creatorPKIDBytesLen, err := ReadUvarint(rr)
	if err != nil {
		return err
	}
	// De-serialize the key
	creatorPKIDBytes, err := SafeMakeSliceWithLength[byte](creatorPKIDBytesLen)
	if err != nil {
		return err
	}
	if _, err = io.ReadFull(rr, creatorPKIDBytes); err != nil {
		return err
	}
	creatorPKID := NewPKID(creatorPKIDBytes)
	if creatorPKID == nil {
		return fmt.Errorf("Invalid PKID")
	}
	daoCoinOperationLimitKey.CreatorPKID = *creatorPKID
	operationKey, err := ReadUvarint(rr)
	if err != nil {
		return err
	}
	daoCoinOperationLimitKey.Operation = DAOCoinLimitOperation(operationKey)
	return nil
}

func MakeDAOCoinOperationLimitKey(creatorPKID PKID, operation DAOCoinLimitOperation) DAOCoinOperationLimitKey {
	return DAOCoinOperationLimitKey{
		creatorPKID,
		operation,
	}
}

type DAOCoinLimitOrderLimitKey struct {
	// The PKID of the coin that we're going to buy
	BuyingDAOCoinCreatorPKID PKID
	// The PKID of the coin that we're going to sell
	SellingDAOCoinCreatorPKID PKID
}

func (daoCoinLimitOrderLimitKey DAOCoinLimitOrderLimitKey) Encode() []byte {
	var data []byte
	data = append(data, daoCoinLimitOrderLimitKey.BuyingDAOCoinCreatorPKID.ToBytes()...)
	data = append(data, daoCoinLimitOrderLimitKey.SellingDAOCoinCreatorPKID.ToBytes()...)
	return data
}

func (daoCoinLimitOrderLimitKey *DAOCoinLimitOrderLimitKey) Decode(rr *bytes.Reader) error {
	buyingDAOCoinCreatorPKID := &PKID{}
	if err := buyingDAOCoinCreatorPKID.FromBytes(rr); err != nil {
		return err
	}
	daoCoinLimitOrderLimitKey.BuyingDAOCoinCreatorPKID = *buyingDAOCoinCreatorPKID

	sellingDAOCoinCreatorPKID := &PKID{}
	if err := sellingDAOCoinCreatorPKID.FromBytes(rr); err != nil {
		return err
	}
	daoCoinLimitOrderLimitKey.SellingDAOCoinCreatorPKID = *sellingDAOCoinCreatorPKID
	return nil
}

func MakeDAOCoinLimitOrderLimitKey(buyingDAOCoinCreatorPKID PKID, sellingDAOCoinCreatorPKID PKID) DAOCoinLimitOrderLimitKey {
	return DAOCoinLimitOrderLimitKey{
		BuyingDAOCoinCreatorPKID:  buyingDAOCoinCreatorPKID,
		SellingDAOCoinCreatorPKID: sellingDAOCoinCreatorPKID,
	}
}

type AssociationLimitKey struct {
	AssociationClass AssociationClass // User || Post
	AssociationType  string
	AppPKID          PKID
	AppScopeType     AssociationAppScopeType // Any || Scoped
	Operation        AssociationOperation    // Any || Create || Delete
}

type AssociationClass uint8
type AssociationClassString string
type AssociationAppScopeType uint8
type AssociationAppScopeTypeString string
type AssociationOperation uint8
type AssociationOperationString string

const (
	UndefinedAssociationClassString AssociationClassString = "Undefined"
	UserAssociationClassString      AssociationClassString = "User"
	PostAssociationClassString      AssociationClassString = "Post"
)

func (associationClass AssociationClass) ToString() string {
	return string(associationClass.ToAssociationClassString())
}

func (associationClass AssociationClass) ToAssociationClassString() AssociationClassString {
	switch associationClass {
	case AssociationClassUser:
		return UserAssociationClassString
	case AssociationClassPost:
		return PostAssociationClassString
	default:
		return UndefinedAssociationClassString
	}
}

func (associationClassString AssociationClassString) ToAssociationClass() AssociationClass {
	switch associationClassString {
	case UserAssociationClassString:
		return AssociationClassUser
	case PostAssociationClassString:
		return AssociationClassPost
	default:
		return AssociationClassUndefined
	}
}

const (
	UndefinedAssociationAppScopeTypeString AssociationAppScopeTypeString = "Undefined"
	AnyAssociationAppScopeTypeString       AssociationAppScopeTypeString = "Any"
	ScopedAssociationAppScopeTypeString    AssociationAppScopeTypeString = "Scoped"
)

func (associationAppScopeType AssociationAppScopeType) ToString() string {
	return string(associationAppScopeType.ToAssociationAppScopeTypeString())
}

func (associationAppScopeType AssociationAppScopeType) ToAssociationAppScopeTypeString() AssociationAppScopeTypeString {
	switch associationAppScopeType {
	case AssociationAppScopeTypeAny:
		return AnyAssociationAppScopeTypeString
	case AssociationAppScopeTypeScoped:
		return ScopedAssociationAppScopeTypeString
	default:
		return UndefinedAssociationAppScopeTypeString
	}
}

func (associationAppScopeTypeString AssociationAppScopeTypeString) ToAssociationAppScopeType() AssociationAppScopeType {
	switch associationAppScopeTypeString {
	case AnyAssociationAppScopeTypeString:
		return AssociationAppScopeTypeAny
	case ScopedAssociationAppScopeTypeString:
		return AssociationAppScopeTypeScoped
	default:
		return AssociationAppScopeTypeUndefined
	}
}

const (
	UndefinedAssociationOperation AssociationOperationString = "Undefined"
	AnyAssociationOperation       AssociationOperationString = "Any"
	CreateAssociationOperation    AssociationOperationString = "Create"
	DeleteAssociationOperation    AssociationOperationString = "Delete"
)

func (associationOperation AssociationOperation) ToString() string {
	return string(associationOperation.ToAssociationOperationString())
}

func (associationOperation AssociationOperation) ToAssociationOperationString() AssociationOperationString {
	switch associationOperation {
	case AssociationOperationAny:
		return AnyAssociationOperation
	case AssociationOperationCreate:
		return CreateAssociationOperation
	case AssociationOperationDelete:
		return DeleteAssociationOperation
	default:
		return UndefinedAssociationOperation
	}
}

func (associationOperationString AssociationOperationString) ToAssociationOperation() AssociationOperation {
	switch associationOperationString {
	case AnyAssociationOperation:
		return AssociationOperationAny
	case CreateAssociationOperation:
		return AssociationOperationCreate
	case DeleteAssociationOperation:
		return AssociationOperationDelete
	default:
		return AssociationOperationUndefined
	}
}

const (
	// AssociationClass: User || Post
	AssociationClassUndefined AssociationClass = 0
	AssociationClassUser      AssociationClass = 1
	AssociationClassPost      AssociationClass = 2
	// AssociationScope: Any || Scoped
	AssociationAppScopeTypeUndefined AssociationAppScopeType = 0
	AssociationAppScopeTypeAny       AssociationAppScopeType = 1
	AssociationAppScopeTypeScoped    AssociationAppScopeType = 2
	// AssociationOperation: Any || Create || Delete
	AssociationOperationUndefined AssociationOperation = 0
	AssociationOperationAny       AssociationOperation = 1
	AssociationOperationCreate    AssociationOperation = 2
	AssociationOperationDelete    AssociationOperation = 3
)

func (associationLimitKey AssociationLimitKey) Encode() []byte {
	var data []byte
	data = append(data, UintToBuf(uint64(associationLimitKey.AssociationClass))...)
	data = append(data, EncodeByteArray([]byte(associationLimitKey.AssociationType))...)
	data = append(data, associationLimitKey.AppPKID.ToBytes()...)
	data = append(data, UintToBuf(uint64(associationLimitKey.AppScopeType))...)
	data = append(data, UintToBuf(uint64(associationLimitKey.Operation))...)
	return data
}

func (associationLimitKey *AssociationLimitKey) Decode(rr *bytes.Reader) error {
	var err error
	// AssociationClass: User || Post
	associationClass, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AssociationLimitKey.Decode: Problem reading AssociationClass: ")
	}
	associationLimitKey.AssociationClass = AssociationClass(associationClass)
	// AssociationType
	associationType, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrap(err, "AssociationLimitKey.Decode: Problem reading AssociationType: ")
	}
	associationLimitKey.AssociationType = string(associationType)
	// AppPKID
	appPKID := &PKID{}
	if err = appPKID.FromBytes(rr); err != nil {
		return errors.Wrap(err, "AssociationLimitKey.Decode: Problem reading AppPKID: ")
	}
	associationLimitKey.AppPKID = *appPKID
	// AppScopeType: Any || Scoped
	appScopeType, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrap(err, "AssociationLimitKey.Decode: Problem reading AppScopeType: ")
	}
	associationLimitKey.AppScopeType = AssociationAppScopeType(appScopeType)
	// Operation: Any || Create || Delete
	operation, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AssociationLimitKey.Decode: Problem reading Operation: ")
	}
	associationLimitKey.Operation = AssociationOperation(operation)
	return nil
}

func MakeAssociationLimitKey(
	associationClass AssociationClass,
	associationType []byte,
	appPKID PKID,
	appScopeType AssociationAppScopeType,
	operation AssociationOperation,
) AssociationLimitKey {
	// Note: AssociationType is case-insensitive.
	return AssociationLimitKey{
		AssociationClass: associationClass,
		AssociationType:  string(bytes.ToLower(associationType)),
		AppPKID:          appPKID,
		AppScopeType:     appScopeType,
		Operation:        operation,
	}
}

type AccessGroupLimitKey struct {
	// AccessGroupOwnerPublicKey is the public key of the owner of the access group.
	AccessGroupOwnerPublicKey PublicKey

	// AccessGroupScopeType is the scope of the access group.
	AccessGroupScopeType AccessGroupScopeType

	// AccessGroupKeyName is the name of the access group.
	AccessGroupKeyName GroupKeyName

	// OperationType is the type of operation for which the spending limit count will apply
	OperationType AccessGroupOperationType
}

func (accessGroupLimitKey *AccessGroupLimitKey) Encode() []byte {
	var data []byte
	data = append(data, EncodeByteArray(accessGroupLimitKey.AccessGroupOwnerPublicKey.ToBytes())...)
	data = append(data, UintToBuf(uint64(accessGroupLimitKey.AccessGroupScopeType))...)
	data = append(data, EncodeByteArray(accessGroupLimitKey.AccessGroupKeyName.ToBytes())...)
	data = append(data, UintToBuf(uint64(accessGroupLimitKey.OperationType))...)
	return data
}

func (accessGroupLimitKey *AccessGroupLimitKey) Decode(rr *bytes.Reader) error {
	accessGroupOwnerPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupLimitKey.Decode: "+
			"Problem reading AccessGroupOwnerPublicKey")
	}
	accessGroupLimitKey.AccessGroupOwnerPublicKey = *NewPublicKey(accessGroupOwnerPublicKeyBytes)

	scopeType, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupLimitKey.Decode: Problem decoding AccessGroupScopeType")
	}
	accessGroupLimitKey.AccessGroupScopeType = AccessGroupScopeType(scopeType)

	accessGroupKeyNameBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupLimitKey.Decode: "+
			"Problem reading AccessGroupKeyName")
	}
	accessGroupLimitKey.AccessGroupKeyName = *NewGroupKeyName(accessGroupKeyNameBytes)

	operationType, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupLimitKey.Decode: Problem decoding OperationType")
	}
	accessGroupLimitKey.OperationType = AccessGroupOperationType(operationType)
	return nil
}

func MakeAccessGroupLimitKey(
	accessGroupOwnerPublicKey PublicKey,
	accessGroupScopeType AccessGroupScopeType,
	accessGroupKeyName GroupKeyName,
	operationType AccessGroupOperationType,
) AccessGroupLimitKey {
	return AccessGroupLimitKey{
		AccessGroupOwnerPublicKey: accessGroupOwnerPublicKey,
		AccessGroupScopeType:      accessGroupScopeType,
		AccessGroupKeyName:        accessGroupKeyName,
		OperationType:             operationType,
	}
}

type AccessGroupMemberLimitKey struct {
	// AccessGroupOwnerPublicKey is the public key of the owner of the access group.
	AccessGroupOwnerPublicKey PublicKey

	// AccessGroupScopeType is the scope of the access group member.
	AccessGroupScopeType AccessGroupScopeType

	// AccessGroupKeyName is the name of the access group.
	AccessGroupKeyName GroupKeyName

	// OperationType is the type of operation for which the spending limit count will apply to.
	OperationType AccessGroupMemberOperationType
}

func (accessGroupMemberLimitKey *AccessGroupMemberLimitKey) Encode() []byte {
	var data []byte
	data = append(data, EncodeByteArray(accessGroupMemberLimitKey.AccessGroupOwnerPublicKey.ToBytes())...)
	data = append(data, UintToBuf(uint64(accessGroupMemberLimitKey.AccessGroupScopeType))...)
	data = append(data, EncodeByteArray(accessGroupMemberLimitKey.AccessGroupKeyName.ToBytes())...)
	data = append(data, UintToBuf(uint64(accessGroupMemberLimitKey.OperationType))...)
	return data
}

func (accessGroupMemberLimitKey *AccessGroupMemberLimitKey) Decode(rr *bytes.Reader) error {
	accessGroupOwnerPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMemberLimitKey.Decode: "+
			"Problem reading AccessGroupOwnerPublicKey")
	}
	accessGroupMemberLimitKey.AccessGroupOwnerPublicKey = *NewPublicKey(accessGroupOwnerPublicKeyBytes)

	scopeType, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMemberLimitKey.Decode: Problem reading AccessGroupScopeType")
	}
	accessGroupMemberLimitKey.AccessGroupScopeType = AccessGroupScopeType(scopeType)

	accessGroupKeyNameBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMemberLimitKey.Decode: "+
			"Problem reading AccessGroupKeyName")
	}
	accessGroupMemberLimitKey.AccessGroupKeyName = *NewGroupKeyName(accessGroupKeyNameBytes)

	operationType, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMemberLimitKey.Decode: Problem reading operation type")
	}
	accessGroupMemberLimitKey.OperationType = AccessGroupMemberOperationType(operationType)
	return nil
}

func MakeAccessGroupMemberLimitKey(
	accessGroupOwnerPublicKey PublicKey,
	accessGroupScopeType AccessGroupScopeType,
	accessGroupKeyName GroupKeyName,
	operationType AccessGroupMemberOperationType,
) AccessGroupMemberLimitKey {
	return AccessGroupMemberLimitKey{
		AccessGroupOwnerPublicKey: accessGroupOwnerPublicKey,
		AccessGroupScopeType:      accessGroupScopeType,
		AccessGroupKeyName:        accessGroupKeyName,
		OperationType:             operationType,
	}
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

	// TransferRestrictionStatus to set if OperationType == DAOCoinOperationTypeUpdateTransferRestrictionStatus
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
		coinsToMintBytes, err := SafeMakeSliceWithLength[byte](intLen)
		if err != nil {
			return errors.Wrapf(err, "DAOCoinMetadata.FromBytes: Problem making slice for coinsToMintBytes")
		}
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
		coinsToBurnBytes, err := SafeMakeSliceWithLength[byte](intLen)
		if err != nil {
			return errors.Wrapf(err, "DAOCoinMetadata.FromBytes: Problem making slice for coinsToBurnBytes")
		}
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
		coinsToTransferBytes, err := SafeMakeSliceWithLength[byte](intLen)
		if err != nil {
			return errors.Wrapf(err,
				"DAOCoinTransferMetadata.FromBytes: Problem creating slice for coinsToTransfer")
		}
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

// ==================================================================
// DAOCoinLimitOrderMetadata
// ==================================================================

type DeSoInputsByTransactor struct {
	TransactorPublicKey *PublicKey
	Inputs              []*DeSoInput
}

type DAOCoinLimitOrderMetadata struct {
	BuyingDAOCoinCreatorPublicKey             *PublicKey
	SellingDAOCoinCreatorPublicKey            *PublicKey
	ScaledExchangeRateCoinsToSellPerCoinToBuy *uint256.Int
	QuantityToFillInBaseUnits                 *uint256.Int
	OperationType                             DAOCoinLimitOrderOperationType
	FillType                                  DAOCoinLimitOrderFillType

	// If set, we will find and delete the
	// order with the given OrderID.
	CancelOrderID *BlockHash

	// This is only populated when this order is selling a DAO coin for
	// $DESO, and is immediately matched with an existing bid-side order
	// at time of creation. This field contains the transactor and their
	// utxo inputs that can be used to immediately execute this trade.
	BidderInputs []*DeSoInputsByTransactor

	// DEPRECATED: This field was needed when we were on a UTXO model but
	// it is redundant now that we have switched to a balance model because
	// we embed the fee directly into the top level of the txn.
	//
	// Since a DAO Coin Limit Order may spend DESO or yield DESO to the
	// transactor, we specify FeeNanos in the transaction metadata in
	// order to ensure the transactor pays the standard fee rate for the size
	// of the transaction AND ensures the internal balance model of the
	// DAO Coin Limit Order transaction connection logic remains valid.
	FeeNanos uint64
}

func (txnData *DAOCoinLimitOrderMetadata) GetTxnType() TxnType {
	return TxnTypeDAOCoinLimitOrder
}

func (txnData *DAOCoinLimitOrderMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := append([]byte{}, EncodeOptionalPublicKey(txnData.BuyingDAOCoinCreatorPublicKey)...)
	data = append(data, EncodeOptionalPublicKey(txnData.SellingDAOCoinCreatorPublicKey)...)
	data = append(data, FixedWidthEncodeUint256(txnData.ScaledExchangeRateCoinsToSellPerCoinToBuy)...)
	data = append(data, FixedWidthEncodeUint256(txnData.QuantityToFillInBaseUnits)...)
	data = append(data, UintToBuf(uint64(txnData.OperationType))...)
	data = append(data, UintToBuf(uint64(txnData.FillType))...)
	data = append(data, EncodeOptionalBlockHash(txnData.CancelOrderID)...)
	data = append(data, UintToBuf(uint64(len(txnData.BidderInputs)))...)

	// we use a sorted copy internally, so we don't modify the original struct from underneath the caller
	for _, transactor := range txnData.BidderInputs {
		data = append(data, transactor.TransactorPublicKey[:]...)

		data = append(data, UintToBuf(uint64(len(transactor.Inputs)))...)
		for _, input := range transactor.Inputs {
			data = append(data, input.TxID[:]...)
			data = append(data, UintToBuf(uint64(input.Index))...)
		}
	}

	data = append(data, UintToBuf(txnData.FeeNanos)...)
	return data, nil
}

func (txnData *DAOCoinLimitOrderMetadata) FromBytes(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	ret := DAOCoinLimitOrderMetadata{}
	rr := bytes.NewReader(data)
	var err error

	// Parse BuyingDAOCoinCreatorPublicKey
	ret.BuyingDAOCoinCreatorPublicKey, err = ReadOptionalPublicKey(rr)
	if err != nil {
		return fmt.Errorf(
			"DAOCoinLimitOrderMetadata.FromBytes: Error "+
				"reading BuyingDAOCoinCreatorPublicKey: %v", err)
	}

	// Parse SellingDAOCoinCreatorPublicKey
	ret.SellingDAOCoinCreatorPublicKey, err = ReadOptionalPublicKey(rr)
	if err != nil {
		return fmt.Errorf(
			"DAOCoinLimitOrderMetadata.FromBytes: Error reading "+
				"SellingDAOCoinCreatorPKID: %v", err)
	}

	// Parse ScaledExchangeRateCoinsToSellPerCoinToBuy
	ret.ScaledExchangeRateCoinsToSellPerCoinToBuy, err = FixedWidthDecodeUint256(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderMetadata.FromBytes: Error reading ScaledPrice: %v", err)
	}

	// Parse QuantityToFillInBaseUnits
	ret.QuantityToFillInBaseUnits, err = FixedWidthDecodeUint256(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderMetadata.FromBytes: Error reading QuantityToFillInBaseUnits: %v", err)
	}

	// Parse OperationType
	operationType, err := ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderMetadata.FromBytes: Error reading OperationType: %v", err)
	}
	if operationType > math.MaxUint8 {
		return fmt.Errorf("DAOCoinLimitOrderMetadata.FromBytes: OperationType exceeds "+
			"uint8 max: %v vs %v", operationType, math.MaxUint8)
	}
	ret.OperationType = DAOCoinLimitOrderOperationType(operationType)

	// Parse FillType
	fillType, err := ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderMetadata.FromBytes: Error reading FillType: %v", err)
	}
	if fillType > math.MaxUint8 {
		return fmt.Errorf("DAOCoinLimitOrderMetadata.FromBytes: FillType exceeds "+
			"uint8 max: %v vs %v", fillType, math.MaxUint8)
	}
	ret.FillType = DAOCoinLimitOrderFillType(fillType)

	// Parse CancelOrderID
	ret.CancelOrderID, err = ReadOptionalBlockHash(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderMetadata.FromBytes: Error reading CancelOrderID: %v", err)
	}

	// Parse MatchingBidsTransactors
	matchingBidsTransactorsLength, err := ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf(
			"DAOCoinLimitOrderMetadata.FromBytes: Error reading length of matching bids input: %v", err)
	}

	for ii := uint64(0); ii < matchingBidsTransactorsLength; ii++ {
		pubKey, err := ReadPublicKey(rr)
		if err != nil {
			return fmt.Errorf(
				"DAOCoinLimitOrderMetadata.FromBytes: Error reading PKID at index %v: %v", ii, err)
		}
		var inputsLength uint64
		inputsLength, err = ReadUvarint(rr)
		if err != nil {
			return fmt.Errorf(
				"DAOCoinLimitOrderMetadata.FromBytes: Error reading inputs length at index %v: %v", ii, err)
		}
		inputs := []*DeSoInput{}
		for jj := uint64(0); jj < inputsLength; jj++ {
			currentInput := NewDeSoInput()
			_, err = io.ReadFull(rr, currentInput.TxID[:])
			if err != nil {
				return fmt.Errorf(
					"DAOCoinLimitOrderMetadata.FromBytes: Error reading input txId at ii %v, jj %v: %v",
					ii, jj, err)
			}
			var inputIndex uint64
			inputIndex, err = ReadUvarint(rr)
			if err != nil {
				return fmt.Errorf(
					"DAOCoinLimitOrderMetadata.FromBytes: Error reading input index at ii %v, jj %v: %v",
					ii, jj, err)
			}
			if inputIndex > uint64(math.MaxUint32) {
				return fmt.Errorf(
					"DAOCoinLimitOrderMetadata.FromBytes: Input index at ii %v, jj %v must not exceed %d",
					ii, jj, math.MaxUint32)
			}
			currentInput.Index = uint32(inputIndex)

			inputs = append(inputs, currentInput)
		}

		pubKeyCopy := *pubKey
		ret.BidderInputs = append(
			ret.BidderInputs,
			&DeSoInputsByTransactor{
				TransactorPublicKey: &pubKeyCopy,
				Inputs:              inputs,
			},
		)
	}

	// Parse FeeNanos
	ret.FeeNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderMetadata.FromBytes: Error reading FeeNanos: %v", err)
	}

	*txnData = ret
	return nil
}

func (txnData *DAOCoinLimitOrderMetadata) New() DeSoTxnMetadata {
	return &DAOCoinLimitOrderMetadata{}
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
		keys, err := SafeMakeSliceWithLengthAndCapacity[string](0, numKeys)
		if err != nil {
			return nil, err
		}
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
	mm, err := SafeMakeMapWithCapacity[PublicKey, uint64](numKeys)
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializePubKeyToUint64Map.FromBytes: Problem creating "+
			"map")
	}
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
	// of the AccessGroupOwnerPublicKey (aka txn.PublicKey):
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
		data = append(data, recipient.ToBytes()...)
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
		recipient := &MessagingGroupMember{}
		if err := recipient.FromBytes(rr); err != nil {
			return errors.Wrapf(err, "MessagingGroupMetadata.FromBytes: "+
				"error reading recipient")
		}
		ret.MessagingGroupMembers = append(ret.MessagingGroupMembers, recipient)
	}

	*txnData = ret
	return nil
}

func (txnData *MessagingGroupMetadata) New() DeSoTxnMetadata {
	return &MessagingGroupMetadata{}
}

// ==================================================================
// Associations Metadata
// ==================================================================

type CreateUserAssociationMetadata struct {
	TargetUserPublicKey *PublicKey
	AppPublicKey        *PublicKey
	AssociationType     []byte
	AssociationValue    []byte
}

type DeleteUserAssociationMetadata struct {
	AssociationID *BlockHash
}

type CreatePostAssociationMetadata struct {
	PostHash         *BlockHash
	AppPublicKey     *PublicKey
	AssociationType  []byte
	AssociationValue []byte
}

type DeletePostAssociationMetadata struct {
	AssociationID *BlockHash
}

func (txnData *CreateUserAssociationMetadata) GetTxnType() TxnType {
	return TxnTypeCreateUserAssociation
}

func (txnData *DeleteUserAssociationMetadata) GetTxnType() TxnType {
	return TxnTypeDeleteUserAssociation
}

func (txnData *CreatePostAssociationMetadata) GetTxnType() TxnType {
	return TxnTypeCreatePostAssociation
}

func (txnData *DeletePostAssociationMetadata) GetTxnType() TxnType {
	return TxnTypeDeletePostAssociation
}

func (txnData *CreateUserAssociationMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.TargetUserPublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.AppPublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.AssociationType)...)
	data = append(data, EncodeByteArray(txnData.AssociationValue)...)
	return data, nil
}

func (txnData *DeleteUserAssociationMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.AssociationID.ToBytes())...)
	return data, nil
}

func (txnData *CreatePostAssociationMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.PostHash.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.AppPublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.AssociationType)...)
	data = append(data, EncodeByteArray(txnData.AssociationValue)...)
	return data, nil
}

func (txnData *DeletePostAssociationMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte
	data = append(data, EncodeByteArray(txnData.AssociationID.ToBytes())...)
	return data, nil
}

func (txnData *CreateUserAssociationMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// TargetUserPublicKey
	targetUserPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateUserAssociationMetadata.FromBytes: Problem reading TargetUserPublicKey: ")
	}
	txnData.TargetUserPublicKey = NewPublicKey(targetUserPublicKeyBytes)

	// AppPublicKey
	appPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateUserAssociationMetadata.FromBytes: Problem reading AppPublicKey: ")
	}
	txnData.AppPublicKey = NewPublicKey(appPublicKeyBytes)

	// AssociationType
	txnData.AssociationType, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateUserAssociationMetadata.FromBytes: Problem reading AssociationType: ")
	}

	// AssociationValue
	txnData.AssociationValue, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateUserAssociationMetadata.FromBytes: Problem reading AssociationValue: ")
	}

	return nil
}

func (txnData *DeleteUserAssociationMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// AssociationID
	associationIDBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeleteUserAssociationMetadata.FromBytes: Problem reading AssociationID: ")
	}
	txnData.AssociationID = NewBlockHash(associationIDBytes)

	return nil
}

func (txnData *CreatePostAssociationMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// PostHash
	postHashBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatePostAssociationMetadata.FromBytes: Problem reading PostHash: ")
	}
	txnData.PostHash = NewBlockHash(postHashBytes)

	// AppPublicKey
	appPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatePostAssociationMetadata.FromBytes: Problem reading AppPublicKey: ")
	}
	txnData.AppPublicKey = NewPublicKey(appPublicKeyBytes)

	// AssociationType
	txnData.AssociationType, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatePostAssociationMetadata.FromBytes: Problem reading AssociationType: ")
	}

	// AssociationValue
	txnData.AssociationValue, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatePostAssociationMetadata.FromBytes: Problem reading AssociationValue: ")
	}

	return nil
}

func (txnData *DeletePostAssociationMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// AssociationID
	associationIDBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DeletePostAssociationMetadata.FromBytes: Problem reading AssociationID: ")
	}
	txnData.AssociationID = NewBlockHash(associationIDBytes)

	return nil
}

func (txnData *CreateUserAssociationMetadata) New() DeSoTxnMetadata {
	return &CreateUserAssociationMetadata{}
}

func (txnData *DeleteUserAssociationMetadata) New() DeSoTxnMetadata {
	return &DeleteUserAssociationMetadata{}
}

func (txnData *CreatePostAssociationMetadata) New() DeSoTxnMetadata {
	return &CreatePostAssociationMetadata{}
}

func (txnData *DeletePostAssociationMetadata) New() DeSoTxnMetadata {
	return &DeletePostAssociationMetadata{}
}

type UserAssociationQuery struct {
	TransactorPKID         *PKID
	TargetUserPKID         *PKID
	AppPKID                *PKID
	AssociationType        []byte
	AssociationTypePrefix  []byte
	AssociationValue       []byte
	AssociationValuePrefix []byte
	Limit                  int
	LastSeenAssociationID  *BlockHash
	SortDescending         bool
}

type PostAssociationQuery struct {
	TransactorPKID         *PKID
	PostHash               *BlockHash
	AppPKID                *PKID
	AssociationType        []byte
	AssociationTypePrefix  []byte
	AssociationValue       []byte
	AssociationValuePrefix []byte
	Limit                  int
	LastSeenAssociationID  *BlockHash
	SortDescending         bool
}

// =======================================================================================
// AccessGroupMetadata
// =======================================================================================

type AccessGroupScopeType uint8
type AccessGroupScopeString string

const (
	AccessGroupScopeTypeAny     AccessGroupScopeType = 0
	AccessGroupScopeTypeScoped  AccessGroupScopeType = 1
	AccessGroupScopeTypeUnknown AccessGroupScopeType = 2
)

const (
	AccessGroupScopeStringAny     AccessGroupScopeString = "Any"
	AccessGroupScopeStringScoped  AccessGroupScopeString = "Scoped"
	AccessGroupScopeStringUnknown AccessGroupScopeString = "Unknown"
)

func (scopeType AccessGroupScopeType) ToAccessGroupScopeString() AccessGroupScopeString {
	switch scopeType {
	case AccessGroupScopeTypeAny:
		return AccessGroupScopeStringAny
	case AccessGroupScopeTypeScoped:
		return AccessGroupScopeStringScoped
	default:
		return AccessGroupScopeStringUnknown
	}
}

func (scopeString AccessGroupScopeString) ToAccessGroupScopeType() AccessGroupScopeType {
	switch scopeString {
	case AccessGroupScopeStringAny:
		return AccessGroupScopeTypeAny
	case AccessGroupScopeStringScoped:
		return AccessGroupScopeTypeScoped
	default:
		return AccessGroupScopeTypeUnknown
	}
}

func (scopeType AccessGroupScopeType) ToString() string {
	switch scopeType {
	case AccessGroupScopeTypeAny:
		return "Any"
	case AccessGroupScopeTypeScoped:
		return "Scoped"
	default:
		return ""
	}
}

type AccessGroupOperationType uint8
type AccessGroupOperationString string

const (
	AccessGroupOperationTypeUnknown AccessGroupOperationType = 0
	AccessGroupOperationTypeAny     AccessGroupOperationType = 1
	AccessGroupOperationTypeCreate  AccessGroupOperationType = 2
	AccessGroupOperationTypeUpdate  AccessGroupOperationType = 3
)

const (
	AccessGroupOperationStringUnknown AccessGroupOperationString = "Unknown"
	AccessGroupOperationStringAny     AccessGroupOperationString = "Any"
	AccessGroupOperationStringCreate  AccessGroupOperationString = "Create"
	AccessGroupOperationStringUpdate  AccessGroupOperationString = "Update"
)

func (groupOp AccessGroupOperationType) ToAccessGroupOperationString() AccessGroupOperationString {
	switch groupOp {
	case AccessGroupOperationTypeAny:
		return AccessGroupOperationStringAny
	case AccessGroupOperationTypeCreate:
		return AccessGroupOperationStringCreate
	case AccessGroupOperationTypeUpdate:
		return AccessGroupOperationStringUpdate
	default:
		return AccessGroupOperationStringUnknown
	}
}

func (opString AccessGroupOperationString) ToAccessGroupOperationType() AccessGroupOperationType {
	switch opString {
	case AccessGroupOperationStringAny:
		return AccessGroupOperationTypeAny
	case AccessGroupOperationStringCreate:
		return AccessGroupOperationTypeCreate
	case AccessGroupOperationStringUpdate:
		return AccessGroupOperationTypeUpdate
	default:
		return AccessGroupOperationTypeUnknown
	}
}

func (groupOp AccessGroupOperationType) ToString() string {
	if groupOp == AccessGroupOperationTypeUnknown {
		return ""
	}
	return string(groupOp.ToAccessGroupOperationString())
}

type AccessGroupMetadata struct {
	AccessGroupOwnerPublicKey []byte
	AccessGroupPublicKey      []byte
	AccessGroupKeyName        []byte
	AccessGroupOperationType  AccessGroupOperationType
}

func (txnData *AccessGroupMetadata) GetTxnType() TxnType {
	return TxnTypeAccessGroup
}

func (txnData *AccessGroupMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte

	data = append(data, EncodeByteArray(txnData.AccessGroupOwnerPublicKey)...)
	data = append(data, EncodeByteArray(txnData.AccessGroupPublicKey)...)
	data = append(data, EncodeByteArray(txnData.AccessGroupKeyName)...)
	data = append(data, UintToBuf(uint64(txnData.AccessGroupOperationType))...)
	return data, nil
}

func (txnData *AccessGroupMetadata) FromBytes(data []byte) error {
	ret := AccessGroupMetadata{}
	rr := bytes.NewReader(data)

	var err error
	ret.AccessGroupOwnerPublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMetadata.FromBytes: "+
			"Problem reading AccessGroupOwnerPublicKey")
	}

	ret.AccessGroupPublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMetadata.FromBytes: "+
			"Problem reading AccessGroupPublicKey")
	}

	ret.AccessGroupKeyName, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMetadata.FromBytes: "+
			"Problem reading AccessGroupKeyName")
	}

	accessGroupOperationType, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMetadata.FromBytes: "+
			"Problem reading AccessGroupOperationType")
	}
	ret.AccessGroupOperationType = AccessGroupOperationType(accessGroupOperationType)

	*txnData = ret
	return nil
}

func (txnData *AccessGroupMetadata) New() DeSoTxnMetadata {
	return &AccessGroupMetadata{}
}

// =======================================================================================
// AccessGroupMembersMetadata
// =======================================================================================

type AccessGroupMemberOperationType uint8
type AccessGroupMemberOperationString string

const (
	AccessGroupMemberOperationTypeUnknown AccessGroupMemberOperationType = 0
	AccessGroupMemberOperationTypeAny     AccessGroupMemberOperationType = 1
	AccessGroupMemberOperationTypeAdd     AccessGroupMemberOperationType = 2
	AccessGroupMemberOperationTypeRemove  AccessGroupMemberOperationType = 3
	AccessGroupMemberOperationTypeUpdate  AccessGroupMemberOperationType = 4
)

const (
	AccessGroupMemberOperationStringUnknown AccessGroupMemberOperationString = "Unknown"
	AccessGroupMemberOperationStringAny     AccessGroupMemberOperationString = "Any"
	AccessGroupMemberOperationStringAdd     AccessGroupMemberOperationString = "Add"
	AccessGroupMemberOperationStringRemove  AccessGroupMemberOperationString = "Remove"
	AccessGroupMemberOperationStringUpdate  AccessGroupMemberOperationString = "Update"
)

func (groupOp AccessGroupMemberOperationType) ToAccessGroupMemberOperationString() AccessGroupMemberOperationString {
	switch groupOp {
	case AccessGroupMemberOperationTypeAny:
		return AccessGroupMemberOperationStringAny
	case AccessGroupMemberOperationTypeAdd:
		return AccessGroupMemberOperationStringAdd
	case AccessGroupMemberOperationTypeRemove:
		return AccessGroupMemberOperationStringRemove
	case AccessGroupMemberOperationTypeUpdate:
		return AccessGroupMemberOperationStringUpdate
	default:
		return AccessGroupMemberOperationStringUnknown
	}
}

func (opString AccessGroupMemberOperationString) ToAccessGroupMemberOperation() AccessGroupMemberOperationType {
	switch opString {
	case AccessGroupMemberOperationStringAny:
		return AccessGroupMemberOperationTypeAny
	case AccessGroupMemberOperationStringAdd:
		return AccessGroupMemberOperationTypeAdd
	case AccessGroupMemberOperationStringRemove:
		return AccessGroupMemberOperationTypeRemove
	case AccessGroupMemberOperationStringUpdate:
		return AccessGroupMemberOperationTypeUpdate
	default:
		return AccessGroupMemberOperationTypeUnknown
	}
}

func (groupOp AccessGroupMemberOperationType) ToString() string {
	if groupOp == AccessGroupMemberOperationTypeUnknown {
		return ""
	}
	return string(groupOp.ToAccessGroupMemberOperationString())
}

// AccessGroupMembersMetadata is the metadata for a transaction to update the members of an access group.
type AccessGroupMembersMetadata struct {
	AccessGroupOwnerPublicKey []byte
	AccessGroupKeyName        []byte
	// The list of members to add/remove from the access group.
	AccessGroupMembersList []*AccessGroupMember
	// The operation to perform on the members.
	AccessGroupMemberOperationType
}

type AccessGroupMember struct {
	// AccessGroupMemberPublicKey is the public key of the user in the access group
	AccessGroupMemberPublicKey []byte

	// AccessGroupMemberKeyName is the name of the user in the access group
	AccessGroupMemberKeyName []byte

	EncryptedKey []byte

	ExtraData map[string][]byte
}

func (txnData *AccessGroupMembersMetadata) GetTxnType() TxnType {
	return TxnTypeAccessGroupMembers
}

func (txnData *AccessGroupMembersMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte

	// AccessPublicKey
	data = append(data, EncodeByteArray(txnData.AccessGroupOwnerPublicKey)...)
	// AccessGroupKeyName
	data = append(data, EncodeByteArray(txnData.AccessGroupKeyName)...)
	// AccessGroupMembersList
	data = append(data, encodeAccessGroupMembersList(txnData.AccessGroupMembersList)...)
	// AccessGroupMemberOperationType
	data = append(data, UintToBuf(uint64(txnData.AccessGroupMemberOperationType))...)

	return data, nil
}

func (txnData *AccessGroupMembersMetadata) FromBytes(data []byte) error {
	var err error
	ret := AccessGroupMembersMetadata{}
	rr := bytes.NewReader(data)

	// AccessPublicKey
	ret.AccessGroupOwnerPublicKey, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMembersMetadata.FromBytes: "+
			"Problem reading AccessPublicKey")
	}

	// AccessGroupKeyName
	ret.AccessGroupKeyName, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMembersMetadata.FromBytes: "+
			"Problem reading AccessGroupKeyName")
	}

	// AccessGroupMembersList
	ret.AccessGroupMembersList, err = decodeAccessGroupMembersList(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMembersMetadata.FromBytes: "+
			"Problem reading AccessGroupMembersList")
	}

	// AccessGroupMemberOperationType
	accessGroupMemberOperationType, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMembersMetadata.FromBytes: "+
			"Problem reading AccessGroupMemberOperationType")
	}
	ret.AccessGroupMemberOperationType = AccessGroupMemberOperationType(accessGroupMemberOperationType)

	*txnData = ret
	return nil
}

func (txnData *AccessGroupMembersMetadata) New() DeSoTxnMetadata {
	return &AccessGroupMembersMetadata{}
}

func (member *AccessGroupMember) ToBytes() []byte {
	var data []byte

	data = append(data, EncodeByteArray(member.AccessGroupMemberPublicKey[:])...)
	data = append(data, EncodeByteArray(member.AccessGroupMemberKeyName[:])...)
	data = append(data, EncodeByteArray(member.EncryptedKey)...)
	data = append(data, EncodeExtraData(member.ExtraData)...)

	return data
}

func (member *AccessGroupMember) FromBytes(rr *bytes.Reader) error {

	accessGroupMemberPublicKey, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMember.FromBytes: Problem decoding AccessGroupMemberPublicKey")
	}

	accessGroupMemberKeyName, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMember.FromBytes: Problem decoding AccessGroupMemberKeyName")
	}

	encryptedKey, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMember.FromBytes: Problem decoding EncryptedKey")
	}

	extraData, err := DecodeExtraData(rr)
	if err != nil {
		return errors.Wrapf(err, "AccessGroupMember.FromBytes: Problem decoding ExtraData")
	}

	member.AccessGroupMemberPublicKey = accessGroupMemberPublicKey
	member.AccessGroupMemberKeyName = accessGroupMemberKeyName
	member.EncryptedKey = encryptedKey
	member.ExtraData = extraData

	return nil
}

func encodeAccessGroupMembersList(members []*AccessGroupMember) []byte {
	var data []byte

	data = append(data, UintToBuf(uint64(len(members)))...)
	for _, accessGroupMember := range members {
		data = append(data, accessGroupMember.ToBytes()...)
	}
	return data
}

func decodeAccessGroupMembersList(rr *bytes.Reader) ([]*AccessGroupMember, error) {
	var members []*AccessGroupMember

	numAccessGroupMembers, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "decodeAccessGroupMembersList: "+
			"Problem reading numAccessGroupMembers")
	}
	members = make([]*AccessGroupMember, numAccessGroupMembers)
	for ii := uint64(0); ii < numAccessGroupMembers; ii++ {
		members[ii] = &AccessGroupMember{}
		err = members[ii].FromBytes(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "decodeAccessGroupMembersList: "+
				"Problem reading AccessGroupMembersList[%d]", ii)
		}
	}

	return members, nil
}

// =======================================================================================
// NewMessageMetadata
// =======================================================================================

type NewMessageType byte
type NewMessageOperation byte

const (
	// Message Types
	NewMessageTypeDm        NewMessageType = 0
	NewMessageTypeGroupChat NewMessageType = 1

	// Message Operations
	NewMessageOperationCreate NewMessageOperation = 0
	NewMessageOperationUpdate NewMessageOperation = 1
)

type NewMessageMetadata struct {
	SenderAccessGroupOwnerPublicKey    PublicKey
	SenderAccessGroupKeyName           GroupKeyName
	SenderAccessGroupPublicKey         PublicKey
	RecipientAccessGroupOwnerPublicKey PublicKey
	RecipientAccessGroupKeyName        GroupKeyName
	RecipientAccessGroupPublicKey      PublicKey
	EncryptedText                      []byte
	TimestampNanos                     uint64
	// TODO: Add operation type create/update
	NewMessageType
	NewMessageOperation
}

func (txnData *NewMessageMetadata) GetTxnType() TxnType {
	return TxnTypeNewMessage
}

func (txnData *NewMessageMetadata) ToBytes(preSignature bool) ([]byte, error) {
	var data []byte

	data = append(data, EncodeByteArray(txnData.SenderAccessGroupOwnerPublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.SenderAccessGroupKeyName.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.SenderAccessGroupPublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.RecipientAccessGroupOwnerPublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.RecipientAccessGroupKeyName.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.RecipientAccessGroupPublicKey.ToBytes())...)
	data = append(data, EncodeByteArray(txnData.EncryptedText)...)
	data = append(data, UintToBuf(txnData.TimestampNanos)...)
	data = append(data, UintToBuf(uint64(txnData.NewMessageType))...)
	data = append(data, UintToBuf(uint64(txnData.NewMessageOperation))...)

	return data, nil
}

func (txnData *NewMessageMetadata) FromBytes(data []byte) error {
	var err error
	ret := NewMessageMetadata{}
	rr := bytes.NewReader(data)

	// MinorAccessGroupOwnerPublicKey
	senderAccessGroupOwnerPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Problem reading SenderAccessGroupOwnerPublicKey")
	}
	// SenderAccessGroupKeyName
	senderAccessGroupKeyName, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Problem reading SenderAccessGroupKeyName")
	}
	if err = ValidateAccessGroupPublicKeyAndName(senderAccessGroupOwnerPublicKeyBytes, senderAccessGroupKeyName); err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Invalid sender access group public key and name")
	}
	ret.SenderAccessGroupOwnerPublicKey = *NewPublicKey(senderAccessGroupOwnerPublicKeyBytes)
	ret.SenderAccessGroupKeyName = *NewGroupKeyName(senderAccessGroupKeyName)

	// SenderAccessGroupPublicKey
	senderAccessPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Problem reading SenderAccessGroupPublicKey")
	}
	if err = IsByteArrayValidPublicKey(senderAccessPublicKeyBytes); err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Invalid sender access public key")
	}
	ret.SenderAccessGroupPublicKey = *NewPublicKey(senderAccessPublicKeyBytes)

	// RecipientAccessGroupOwnerPublicKey
	recipientAccessGroupOwnerPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Problem reading RecipientAccessGroupOwnerPublicKey")
	}
	// RecipientAccessGroupKeyName
	recipientAccessGroupKeyName, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Problem reading RecipientAccessGroupKeyName")
	}
	if err = ValidateAccessGroupPublicKeyAndName(recipientAccessGroupOwnerPublicKeyBytes, recipientAccessGroupKeyName); err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Invalid recipient access group public key and name")
	}
	ret.RecipientAccessGroupOwnerPublicKey = *NewPublicKey(recipientAccessGroupOwnerPublicKeyBytes)
	ret.RecipientAccessGroupKeyName = *NewGroupKeyName(recipientAccessGroupKeyName)

	// RecipientAccessGroupPublicKey
	recipientAccessPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Problem reading RecipientAccessGroupPublicKey")
	}
	if err = IsByteArrayValidPublicKey(recipientAccessPublicKeyBytes); err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Invalid recipient access public key")
	}
	ret.RecipientAccessGroupPublicKey = *NewPublicKey(recipientAccessPublicKeyBytes)

	// EncryptedText
	ret.EncryptedText, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Problem reading EncryptedText")
	}

	// TimestampNanos
	ret.TimestampNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Problem reading TimestampNanos")
	}

	// NewMessageType
	messageType, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Problem reading NewMessageType")
	}
	ret.NewMessageType = NewMessageType(messageType)

	// NewMessageOperation
	messageOperation, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NewMessageMetadata.FromBytes: "+
			"Problem reading NewMessageOperation")
	}
	ret.NewMessageOperation = NewMessageOperation(messageOperation)
	*txnData = ret

	return nil
}

func (txnData *NewMessageMetadata) New() DeSoTxnMetadata {
	return &NewMessageMetadata{}
}
