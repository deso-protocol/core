package lib

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"io"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strings"
)

type UtxoType uint8

const (
	// UTXOs can come from different sources. We document all of those sources
	// in the UTXOEntry using these types.
	UtxoTypeOutput      UtxoType = 0
	UtxoTypeBlockReward UtxoType = 1
	UtxoTypeBitcoinBurn UtxoType = 2
	// TODO(DELETEME): Remove the StakeReward txn type
	UtxoTypeStakeReward              UtxoType = 3
	UtxoTypeCreatorCoinSale          UtxoType = 4
	UtxoTypeCreatorCoinFounderReward UtxoType = 5
	UtxoTypeNFTSeller                UtxoType = 6
	UtxoTypeNFTBidderChange          UtxoType = 7
	UtxoTypeNFTCreatorRoyalty        UtxoType = 8
	UtxoTypeNFTAdditionalDESORoyalty UtxoType = 9
	UtxoTypeDAOCoinLimitOrderPayout  UtxoType = 10

	// NEXT_TAG = 11
)

func (mm UtxoType) String() string {
	switch mm {
	case UtxoTypeOutput:
		return "UtxoTypeOutput"
	case UtxoTypeBlockReward:
		return "UtxoTypeBlockReward"
	case UtxoTypeBitcoinBurn:
		return "UtxoTypeBitcoinBurn"
	case UtxoTypeStakeReward:
		return "UtxoTypeStakeReward"
	case UtxoTypeCreatorCoinSale:
		return "UtxoTypeCreatorCoinSale"
	case UtxoTypeCreatorCoinFounderReward:
		return "UtxoTypeCreatorCoinFounderReward"
	case UtxoTypeNFTSeller:
		return "UtxoTypeNFTSeller"
	case UtxoTypeNFTBidderChange:
		return "UtxoTypeNFTBidderChange"
	case UtxoTypeNFTCreatorRoyalty:
		return "UtxoTypeNFTCreatorRoyalty"
	case UtxoTypeNFTAdditionalDESORoyalty:
		return "UtxoTypeNFTAdditionalDESORoyalty"
	default:
		return "UtxoTypeUnknown"
	}
}

// UtxoEntry identifies the data associated with a UTXO.
type UtxoEntry struct {
	AmountNanos uint64
	PublicKey   []byte
	BlockHeight uint32
	UtxoType    UtxoType

	// The fields below aren't serialized or hashed. They are only kept
	// around for in-memory bookkeeping purposes.

	// Whether or not the UTXO is spent. This is not used by the database,
	// (in fact it's not even stored in the db) it's used
	// only by the in-memory data structure. The database is simple: A UTXO
	// is unspent if and only if it exists in the db. However, for the view,
	// a UTXO is unspent if it (exists in memory and is unspent) OR (it does not
	// exist in memory at all but does exist in the database).
	//
	// Note that we are relying on the code that serializes the entry to the
	// db to ignore private fields, which is why this variable is lowerCamelCase
	// rather than UpperCamelCase. We are also relying on it defaulting to
	// false when newly-read from the database.
	isSpent bool

	// A back-reference to the utxo key associated with this entry.
	UtxoKey *UtxoKey
}

type OperationType uint

const (
	// Every operation has a type that we document here. This information is
	// used when rolling back a txn to determine what kind of operations need
	// to be performed. For example, rolling back a BitcoinExchange may require
	// rolling back an AddUtxo operation.
	OperationTypeAddUtxo                      OperationType = 0
	OperationTypeSpendUtxo                    OperationType = 1
	OperationTypeBitcoinExchange              OperationType = 2
	OperationTypePrivateMessage               OperationType = 3
	OperationTypeSubmitPost                   OperationType = 4
	OperationTypeUpdateProfile                OperationType = 5
	OperationTypeDeletePost                   OperationType = 7
	OperationTypeUpdateBitcoinUSDExchangeRate OperationType = 8
	OperationTypeFollow                       OperationType = 9
	OperationTypeLike                         OperationType = 10
	OperationTypeCreatorCoin                  OperationType = 11
	OperationTypeSwapIdentity                 OperationType = 12
	OperationTypeUpdateGlobalParams           OperationType = 13
	OperationTypeCreatorCoinTransfer          OperationType = 14
	OperationTypeCreateNFT                    OperationType = 15
	OperationTypeUpdateNFT                    OperationType = 16
	OperationTypeAcceptNFTBid                 OperationType = 17
	OperationTypeNFTBid                       OperationType = 18
	OperationTypeDeSoDiamond                  OperationType = 19
	OperationTypeNFTTransfer                  OperationType = 20
	OperationTypeAcceptNFTTransfer            OperationType = 21
	OperationTypeBurnNFT                      OperationType = 22
	OperationTypeAuthorizeDerivedKey          OperationType = 23
	OperationTypeMessagingKey                 OperationType = 24
	OperationTypeDAOCoin                      OperationType = 25
	OperationTypeDAOCoinTransfer              OperationType = 26
	OperationTypeSpendingLimitAccounting      OperationType = 27
	OperationTypeDAOCoinLimitOrder            OperationType = 28

	// NEXT_TAG = 29
)

func (op OperationType) String() string {
	switch op {
	case OperationTypeAddUtxo:
		{
			return "OperationTypeAddUtxo"
		}
	case OperationTypeSpendUtxo:
		{
			return "OperationTypeSpendUtxo"
		}
	case OperationTypeBitcoinExchange:
		{
			return "OperationTypeBitcoinExchange"
		}
	case OperationTypePrivateMessage:
		{
			return "OperationTypePrivateMessage"
		}
	case OperationTypeSubmitPost:
		{
			return "OperationTypeSubmitPost"
		}
	case OperationTypeUpdateProfile:
		{
			return "OperationTypeUpdateProfile"
		}
	case OperationTypeDeletePost:
		{
			return "OperationTypeDeletePost"
		}
	case OperationTypeUpdateBitcoinUSDExchangeRate:
		{
			return "OperationTypeUpdateBitcoinUSDExchangeRate"
		}
	case OperationTypeFollow:
		{
			return "OperationTypeFollow"
		}
	case OperationTypeLike:
		{
			return "OperationTypeLike"
		}
	case OperationTypeCreatorCoin:
		{
			return "OperationTypeCreatorCoin"
		}
	case OperationTypeSwapIdentity:
		{
			return "OperationTypeSwapIdentity"
		}
	case OperationTypeUpdateGlobalParams:
		{
			return "OperationTypeUpdateGlobalParams"
		}
	case OperationTypeCreatorCoinTransfer:
		{
			return "OperationTypeCreatorCoinTransfer"
		}
	case OperationTypeCreateNFT:
		{
			return "OperationTypeCreateNFT"
		}
	case OperationTypeUpdateNFT:
		{
			return "OperationTypeUpdateNFT"
		}
	case OperationTypeAcceptNFTBid:
		{
			return "OperationTypeAcceptNFTBid"
		}
	case OperationTypeNFTBid:
		{
			return "OperationTypeNFTBid"
		}
	case OperationTypeDeSoDiamond:
		{
			return "OperationTypeDeSoDiamond"
		}
	case OperationTypeNFTTransfer:
		{
			return "OperationTypeNFTTransfer"
		}
	case OperationTypeAcceptNFTTransfer:
		{
			return "OperationTypeAcceptNFTTransfer"
		}
	case OperationTypeBurnNFT:
		{
			return "OperationTypeBurnNFT"
		}
	case OperationTypeAuthorizeDerivedKey:
		{
			return "OperationTypeAuthorizeDerivedKey"
		}
	case OperationTypeMessagingKey:
		{
			return "OperationTypeMessagingKey"
		}
	case OperationTypeDAOCoin:
		{
			return "OperationTypeDAOCoin"
		}
	case OperationTypeDAOCoinTransfer:
		{
			return "OperationTypeDAOCoinTransfer"
		}
	case OperationTypeSpendingLimitAccounting:
		{
			return "OperationTypeSpendingLimitAccounting"
		}
	case OperationTypeDAOCoinLimitOrder:
		{
			return "OperationTypeDAOCoinLimitOrder"
		}
	}
	return "OperationTypeUNKNOWN"
}

type UtxoOperation struct {
	Type OperationType

	// Only set for OperationTypeSpendUtxo
	//
	// When we SPEND a UTXO entry we delete it from the utxo set but we still
	// store its info in case we want to reverse
	// it in the future. This information is not needed for ADD since
	// reversing an ADD just means deleting an entry from the end of our list.
	//
	// SPEND works by swapping the UTXO we want to spend with the UTXO at
	// the end of the list and then deleting from the end of the list. Obviously
	// this is more efficient than deleting the element in-place and then shifting
	// over everything after it. In order to be able to undo this operation,
	// however, we need to store the original index of the item we are
	// spending/deleting. Reversing the operation then amounts to adding a utxo entry
	// at the end of the list and swapping with this index. Given this, the entry
	// we store here has its position set to the position it was at right before the
	// SPEND operation was performed.
	Entry *UtxoEntry

	// Only set for OperationTypeSpendUtxo
	//
	// Store the UtxoKey as well. This isn't necessary but it helps
	// with error-checking during a roll-back so we just keep it.
	//
	// TODO: We can probably delete this at some point and save some space. UTXOs
	// are probably our biggest disk hog so getting rid of this should materially
	// improve disk usage.
	Key *UtxoKey

	// Used to revert BitcoinExchange transaction.
	PrevNanosPurchased uint64
	// Used to revert UpdateBitcoinUSDExchangeRate transaction.
	PrevUSDCentsPerBitcoin uint64

	// Save the previous post entry when making an update to a post.
	PrevPostEntry            *PostEntry
	PrevParentPostEntry      *PostEntry
	PrevGrandparentPostEntry *PostEntry
	PrevRepostedPostEntry    *PostEntry

	// Save the previous profile entry when making an update.
	PrevProfileEntry *ProfileEntry

	// Save the previous like entry and like count when making an update.
	PrevLikeEntry *LikeEntry
	PrevLikeCount uint64

	// For disconnecting diamonds.
	PrevDiamondEntry *DiamondEntry

	// For disconnecting NFTs.
	PrevNFTEntry              *NFTEntry
	PrevNFTBidEntry           *NFTBidEntry
	DeletedNFTBidEntries      []*NFTBidEntry
	NFTPaymentUtxoKeys        []*UtxoKey
	NFTSpentUtxoEntries       []*UtxoEntry
	PrevAcceptedNFTBidEntries *[]*NFTBidEntry

	// For disconnecting AuthorizeDerivedKey transactions.
	PrevDerivedKeyEntry *DerivedKeyEntry

	// For disconnecting MessagingGroupKey transactions.
	PrevMessagingKeyEntry *MessagingGroupEntry

	// Save the previous repost entry and repost count when making an update.
	PrevRepostEntry *RepostEntry
	PrevRepostCount uint64

	// Save the state of a creator coin prior to updating it due to a
	// buy/sell/add transaction.
	PrevCoinEntry *CoinEntry

	// Save the state of coin entries associated with a PKID prior to updating
	// it due to an additional coin royalty when an NFT is sold.
	PrevCoinRoyaltyCoinEntries map[PKID]CoinEntry

	// Save the creator coin balance of both the transactor and the creator.
	// We modify the transactor's balances when they buys/sell a creator coin
	// and we modify the creator's balance when we pay them a founder reward.
	PrevTransactorBalanceEntry *BalanceEntry
	PrevCreatorBalanceEntry    *BalanceEntry
	// We use this to revert founder's reward UTXOs created by creator coin buys.
	FounderRewardUtxoKey *UtxoKey

	// Save balance entries for the sender and receiver when creator coins are transferred.
	PrevSenderBalanceEntry   *BalanceEntry
	PrevReceiverBalanceEntry *BalanceEntry

	// Save the global params when making an update.
	PrevGlobalParamsEntry    *GlobalParamsEntry
	PrevForbiddenPubKeyEntry *ForbiddenPubKeyEntry

	// This value is used by Rosetta to adjust for a bug whereby a ParamUpdater
	// CoinEntry could get clobbered if updating a profile on someone else's
	// behalf. This is super confusing.
	ClobberedProfileBugDESOLockedNanos uint64

	// This value is used by Rosetta to return the amount of DESO that was added
	// or removed from a profile during a CreatorCoin transaction. It's needed
	// in order to avoid having to reconnect all transactions.
	CreatorCoinDESOLockedNanosDiff int64

	// This value is used by Rosetta to create a proper input/output when we
	// encounter a SwapIdentity txn. This makes it so that we don't have to
	// reconnect all txns in order to get these values.
	SwapIdentityFromDESOLockedNanos uint64
	SwapIdentityToDESOLockedNanos   uint64

	// These values are used by Rosetta in order to create input and output
	// operations. They make it so that we don't have to reconnect all txns
	// in order to get these values.
	AcceptNFTBidCreatorPublicKey        []byte
	AcceptNFTBidBidderPublicKey         []byte
	AcceptNFTBidCreatorRoyaltyNanos     uint64
	AcceptNFTBidCreatorDESORoyaltyNanos uint64
	AcceptNFTBidAdditionalCoinRoyalties []*PublicKeyRoyaltyPair
	AcceptNFTBidAdditionalDESORoyalties []*PublicKeyRoyaltyPair

	// These values are used by Rosetta in order to create input and output
	// operations. They make it so that we don't have to reconnect all txns
	// in order to get these values for NFT bid transactions on Buy Now NFTs.
	NFTBidCreatorPublicKey        []byte
	NFTBidBidderPublicKey         []byte
	NFTBidCreatorRoyaltyNanos     uint64
	NFTBidCreatorDESORoyaltyNanos uint64
	NFTBidAdditionalCoinRoyalties []*PublicKeyRoyaltyPair
	NFTBidAdditionalDESORoyalties []*PublicKeyRoyaltyPair

	// DAO coin limit order
	// PrevTransactorDAOCoinLimitOrderEntry is the previous version of the
	// transactor's DAO Coin Limit Order before this transaction was connected.
	// Note: This is only set if the transactor is cancelling an existing order.
	PrevTransactorDAOCoinLimitOrderEntry *DAOCoinLimitOrderEntry

	// PrevBalanceEntries is a map of User PKID, Creator PKID to DAO Coin Balance
	// Entry. When disconnecting a DAO Coin Limit Order, we will revert to these
	// BalanceEntries.
	PrevBalanceEntries map[PKID]map[PKID]*BalanceEntry

	// PrevMatchingOrder is a slice of DAOCoinLimitOrderEntries that were deleted
	// in the DAO Coin Limit Order Transaction. In order to revert the state in
	// the event of a disconnect, we restore all the deleted Order Entries
	PrevMatchingOrders []*DAOCoinLimitOrderEntry

	// FilledDAOCoinLimitOrder is a slice of FilledDAOCoinLimitOrder structs
	// that represent all orders fulfilled by the DAO Coin Limit Order transaction.
	// These are used to construct notifications for order fulfillment.
	FilledDAOCoinLimitOrders []*FilledDAOCoinLimitOrder
}

func (utxoEntry *UtxoEntry) String() string {
	return fmt.Sprintf("< OwnerPublicKey: %v, BlockHeight: %d, AmountNanos: %d, UtxoType: %v, "+
		"isSpent: %v, utxoKey: %v>", PkToStringMainnet(utxoEntry.PublicKey),
		utxoEntry.BlockHeight, utxoEntry.AmountNanos,
		utxoEntry.UtxoType, utxoEntry.isSpent, utxoEntry.UtxoKey)
}

// Have to define these because Go doesn't let you use raw byte slices as map keys.
// This needs to be in-sync with DeSoMainnetParams.MaxUsernameLengthBytes
type UsernameMapKey [MaxUsernameLengthBytes]byte

func MakeUsernameMapKey(nonLowercaseUsername []byte) UsernameMapKey {
	// Always lowercase the username when we use it as a key in our map. This allows
	// us to check uniqueness in a case-insensitive way.
	lowercaseUsername := []byte(strings.ToLower(string(nonLowercaseUsername)))
	usernameMapKey := UsernameMapKey{}
	copy(usernameMapKey[:], lowercaseUsername)
	return usernameMapKey
}

// DEPRECATED: Replace all instances with lib.PublicKey
type PkMapKey [btcec.PubKeyBytesLenCompressed]byte

func (mm PkMapKey) String() string {
	return PkToStringBoth(mm[:])
}

func MakePkMapKey(pk []byte) PkMapKey {
	pkMapKey := PkMapKey{}
	copy(pkMapKey[:], pk)
	return pkMapKey
}

func MakeMessageKey(pk []byte, tstampNanos uint64) MessageKey {
	return MessageKey{
		PublicKey:   *NewPublicKey(pk),
		TstampNanos: tstampNanos,
	}
}

type MessageKey struct {
	PublicKey   PublicKey
	BlockHeight uint32
	TstampNanos uint64
}

func (mm *MessageKey) String() string {
	return fmt.Sprintf("<Public Key: %s, TstampNanos: %d>",
		PkToStringMainnet(mm.PublicKey[:]), mm.TstampNanos)
}

// StringKey is useful for creating maps that need to be serialized to JSON.
func (mm *MessageKey) StringKey(params *DeSoParams) string {
	return PkToString(mm.PublicKey[:], params) + "_" + fmt.Sprint(mm.TstampNanos)
}

// MessageEntry stores the essential content of a message transaction.
type MessageEntry struct {
	SenderPublicKey    *PublicKey
	RecipientPublicKey *PublicKey
	EncryptedText      []byte
	// TODO: Right now a sender can fake the timestamp and make it appear to
	// the recipient that she sent messages much earlier than she actually did.
	// This isn't a big deal because there is generally not much to gain from
	// faking a timestamp, and it's still impossible for a user to impersonate
	// another user, which is the important thing. Moreover, it is easy to fix
	// the timestamp spoofing issue: You just need to make it so that the nodes
	// index messages based on block height in addition to on the tstamp. The
	// reason I didn't do it yet is because it adds some complexity around
	// detecting duplicates, particularly if a transaction is allowed to have
	// zero inputs/outputs, which is advantageous for various reasons.
	TstampNanos uint64

	isDeleted bool

	// Indicates message encryption method
	// Version = 3 : message encrypted using rotating keys and group chats.
	// Version = 2 : message encrypted using shared secrets
	// Version = 1 : message encrypted using public key
	Version uint8

	// DeSo V3 Messages fields

	// SenderMessagingPublicKey is the sender's messaging public key that was used
	// to encrypt the corresponding message.
	SenderMessagingPublicKey *PublicKey

	// SenderMessagingGroupKeyName is the sender's key name of SenderMessagingPublicKey
	SenderMessagingGroupKeyName *GroupKeyName

	// RecipientMessagingPublicKey is the recipient's messaging public key that was
	// used to encrypt the corresponding message.
	RecipientMessagingPublicKey *PublicKey

	// RecipientMessagingGroupKeyName is the recipient's key name of RecipientMessagingPublicKey
	RecipientMessagingGroupKeyName *GroupKeyName

	// Extra data
	ExtraData map[string][]byte
}

func (message *MessageEntry) Encode() []byte {
	var data []byte

	data = append(data, EncodeByteArray(message.SenderPublicKey[:])...)
	data = append(data, EncodeByteArray(message.RecipientPublicKey[:])...)
	data = append(data, EncodeByteArray(message.EncryptedText)...)
	data = append(data, UintToBuf(message.TstampNanos)...)
	data = append(data, UintToBuf(uint64(message.Version))...)
	data = append(data, EncodeByteArray(message.SenderMessagingPublicKey[:])...)
	data = append(data, EncodeByteArray(message.SenderMessagingGroupKeyName[:])...)
	data = append(data, EncodeByteArray(message.RecipientMessagingPublicKey[:])...)
	data = append(data, EncodeByteArray(message.RecipientMessagingGroupKeyName[:])...)
	data = append(data, EncodeExtraData(message.ExtraData)...)
	return data
}

func (message *MessageEntry) Decode(data []byte) error {
	rr := bytes.NewReader(data)

	senderPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding sender public key")
	}
	message.SenderPublicKey = NewPublicKey(senderPublicKeyBytes)

	recipientPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding recipient public key")
	}
	message.RecipientPublicKey = NewPublicKey(recipientPublicKeyBytes)

	message.EncryptedText, err = DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding encrypted bytes")
	}

	message.TstampNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding timestamp")
	}

	versionBytes, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding version")
	}
	message.Version = uint8(versionBytes)

	senderMessagingPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding sender messaging public key")
	}
	message.SenderMessagingPublicKey = NewPublicKey(senderMessagingPublicKeyBytes)

	senderMessagingKeyName, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding sender messaging key name")
	}
	message.SenderMessagingGroupKeyName = NewGroupKeyName(senderMessagingKeyName)

	recipientMessagingPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding recipient messaging public key")
	}
	message.RecipientMessagingPublicKey = NewPublicKey(recipientMessagingPublicKeyBytes)

	recipientMessagingKeyName, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessageEntry.Decode: problem decoding recipient messaging key name")
	}
	message.RecipientMessagingGroupKeyName = NewGroupKeyName(recipientMessagingKeyName)

	extraData, err := DecodeExtraData(rr)
	if err != nil && strings.Contains(err.Error(), "EOF") {
		// To preserve backwards-compatibility, we set an empty map and return if we
		// encounter an EOF error decoding ExtraData.
		glog.Warning(err, "MesssageEntry.Decode: problem decoding extra data. "+
			"Please resync your node to upgrade your datadir before the next hard fork.")
		return nil
	} else if err != nil {
		return errors.Wrapf(err, "MesssageEntry.Decode: problem decoding extra data")
	}
	message.ExtraData = extraData

	return nil
}

// GroupKeyName helps with handling key names in MessagingGroupKey
type GroupKeyName [MaxMessagingKeyNameCharacters]byte

func (name *GroupKeyName) ToBytes() []byte {
	return name[:]
}

// Encode message key from varying length to a MaxMessagingKeyNameCharacters.
// We fill the length of the messaging key to make sure there are no weird
// prefix overlaps in DB.
func NewGroupKeyName(groupKeyName []byte) *GroupKeyName {
	name := GroupKeyName{}

	// Fill with 0s to the MaxMessagingKeyNameCharacters.
	for {
		if len(groupKeyName) < MaxMessagingKeyNameCharacters {
			groupKeyName = append(groupKeyName, []byte{0}...)
		} else {
			copy(name[:], groupKeyName)
			return &name
		}
	}
}

// Decode filled message key of length MaxMessagingKeyNameCharacters array.
func MessagingKeyNameDecode(name *GroupKeyName) []byte {

	bytes := make([]byte, MaxMessagingKeyNameCharacters)
	copy(bytes, name[:])

	// Return empty byte array if we have a non-existent key.
	if reflect.DeepEqual(bytes, (*NewGroupKeyName([]byte{}))[:]) {
		return []byte{}
	}

	// Remove trailing 0s from the encoded message key.
	for {
		if len(bytes) > MinMessagingKeyNameCharacters && bytes[len(bytes)-1] == byte(0) {
			bytes = bytes[:len(bytes)-1]
		} else {
			return bytes
		}
	}
}

func EqualGroupKeyName(a, b *GroupKeyName) bool {
	return reflect.DeepEqual(a.ToBytes(), b.ToBytes())
}

func BaseGroupKeyName() *GroupKeyName {
	return NewGroupKeyName([]byte{})
}

func DefaultGroupKeyName() *GroupKeyName {
	return NewGroupKeyName([]byte("default-key"))
}

// MessagingGroupKey is similar to the MessageKey, and is used to index messaging keys for a user.
type MessagingGroupKey struct {
	OwnerPublicKey PublicKey
	GroupKeyName   GroupKeyName
}

func NewMessagingGroupKey(ownerPublicKey *PublicKey, groupKeyName []byte) *MessagingGroupKey {
	return &MessagingGroupKey{
		OwnerPublicKey: *ownerPublicKey,
		GroupKeyName:   *NewGroupKeyName(groupKeyName),
	}
}

func (key *MessagingGroupKey) String() string {
	return fmt.Sprintf("<OwnerPublicKey: %v, GroupKeyName: %v",
		key.OwnerPublicKey, key.GroupKeyName)
}

// MessagingGroupEntry is used to update messaging keys for a user, this was added in
// the DeSo V3 Messages protocol.
type MessagingGroupEntry struct {
	// GroupOwnerPublicKey represents the owner public key of the user who created
	// this group. This key is what is used to index the group metadata in the db.
	GroupOwnerPublicKey *PublicKey

	// MessagingPublicKey is the key others will use to encrypt messages. The
	// GroupOwnerPublicKey is used for indexing, but the MessagingPublicKey is the
	// actual key used to encrypt/decrypt messages.
	MessagingPublicKey *PublicKey

	// MessagingGroupKeyName is the name of the messaging key. This is used to identify
	// the message public key. You can pass any 8-32 character string (byte array).
	// The standard Messages V3 key is named "default-key"
	MessagingGroupKeyName *GroupKeyName

	// MessagingGroupMembers is a list of recipients in a group chat. Messaging keys can have
	// multiple recipients, where the encrypted private key of the messaging public key
	// is given to all group members.
	MessagingGroupMembers []*MessagingGroupMember

	// ExtraData is an arbitrary key value map
	ExtraData map[string][]byte

	// Whether this entry should be deleted when the view is flushed
	// to the db. This is initially set to false, but can become true if
	// we disconnect the messaging key from UtxoView
	isDeleted bool
}

func (entry *MessagingGroupEntry) String() string {
	return fmt.Sprintf("<MessagingGroupEntry: %v | MessagingPublicKey : %v | MessagingGroupKey : %v | isDeleted : %v >",
		entry.GroupOwnerPublicKey, entry.MessagingPublicKey, entry.MessagingGroupKeyName, entry.isDeleted)
}

func sortMessagingGroupMembers(membersArg []*MessagingGroupMember) []*MessagingGroupMember {
	// Make a deep copy of the members to avoid messing up the slice the caller
	// used. Not doing this could cause downstream effects, mainly in tests where
	// the same slice is re-used in txns and in expectations later on.
	members := make([]*MessagingGroupMember, len(membersArg))
	copy(members, membersArg)
	sort.Slice(members, func(ii, jj int) bool {
		iiStr := PkToStringMainnet(members[ii].GroupMemberPublicKey[:]) + string(members[ii].GroupMemberKeyName[:]) + string(members[ii].EncryptedKey)
		jjStr := PkToStringMainnet(members[jj].GroupMemberPublicKey[:]) + string(members[jj].GroupMemberKeyName[:]) + string(members[jj].EncryptedKey)
		return iiStr < jjStr
	})
	return members
}

func (entry *MessagingGroupEntry) Encode() []byte {
	var entryBytes []byte

	entryBytes = append(entryBytes, EncodeByteArray(entry.GroupOwnerPublicKey[:])...)
	entryBytes = append(entryBytes, EncodeByteArray(entry.MessagingPublicKey[:])...)
	entryBytes = append(entryBytes, EncodeByteArray(entry.MessagingGroupKeyName[:])...)
	entryBytes = append(entryBytes, UintToBuf(uint64(len(entry.MessagingGroupMembers)))...)
	// We sort the MessagingGroupMembers because they can be added while iterating over
	// a map, which could lead to inconsistent orderings across nodes when encoding.
	members := sortMessagingGroupMembers(entry.MessagingGroupMembers)
	for ii := 0; ii < len(members); ii++ {
		entryBytes = append(entryBytes, members[ii].Encode()...)
	}
	entryBytes = append(entryBytes, EncodeExtraData(entry.ExtraData)...)
	return entryBytes
}

func (entry *MessagingGroupEntry) Decode(data []byte) error {
	rr := bytes.NewReader(data)

	groupOwnerPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupEntry.Decode: Problem decoding groupOwnerPublicKeyBytes")
	}
	entry.GroupOwnerPublicKey = NewPublicKey(groupOwnerPublicKeyBytes)

	messagingPublicKeyBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupEntry.Decode: Problem decoding messagingPublicKey")
	}
	entry.MessagingPublicKey = NewPublicKey(messagingPublicKeyBytes)

	messagingKeyNameBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupEntry.Decode: Problem decoding messagingKeyName")
	}
	entry.MessagingGroupKeyName = NewGroupKeyName(messagingKeyNameBytes)

	recipientsLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupEntry.Decode: Problem decoding recipients length")
	}
	for ; recipientsLen > 0; recipientsLen-- {
		recipient := MessagingGroupMember{}
		err = recipient.Decode(rr)
		if err != nil {
			return errors.Wrapf(err, "MessagingGroupEntry.Decode: Problem decoding recipient")
		}

		entry.MessagingGroupMembers = append(entry.MessagingGroupMembers, &recipient)
	}

	extraData, err := DecodeExtraData(rr)
	if err != nil && strings.Contains(err.Error(), "EOF") {
		// To preserve backwards-compatibility, we set an empty map and return if we
		// encounter an EOF error decoding ExtraData.
		glog.Warning(err, "MessagingGroupEntry.Decode: problem decoding extra data. "+
			"Please resync your node to upgrade your datadir before the next hard fork.")
		return nil
	} else if err != nil {
		return errors.Wrapf(err, "MessagingGroupEntry.Decode: Problem decoding extra data")
	}
	entry.ExtraData = extraData

	return nil
}

// MessagingGroupMember is used to store information about a group chat member.
type MessagingGroupMember struct {
	// GroupMemberPublicKey is the main public key of the group chat member.
	// Importantly, it isn't a messaging public key.
	GroupMemberPublicKey *PublicKey

	// GroupMemberKeyName determines the key of the recipient that the
	// encrypted key is addressed to. We allow adding recipients by their
	// messaging keys. It suffices to specify the recipient's main public key
	// and recipient's messaging key name for the consensus to know how to
	// index the recipient. That's why we don't actually store the messaging
	// public key in the MessagingGroupMember entry.
	GroupMemberKeyName *GroupKeyName

	// EncryptedKey is the encrypted messaging public key, addressed to the recipient.
	EncryptedKey []byte
}

func (rec *MessagingGroupMember) Encode() []byte {
	data := []byte{}

	data = append(data, UintToBuf(uint64(len(rec.GroupMemberPublicKey)))...)
	data = append(data, rec.GroupMemberPublicKey[:]...)

	data = append(data, UintToBuf(uint64(len(rec.GroupMemberKeyName)))...)
	data = append(data, rec.GroupMemberKeyName[:]...)

	data = append(data, UintToBuf(uint64(len(rec.EncryptedKey)))...)
	data = append(data, rec.EncryptedKey...)

	return data
}

func (rec *MessagingGroupMember) Decode(rr io.Reader) error {

	recipientPublicKeyBytes, err := ReadVarString(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupMember.Decode: Problem reading "+
			"GroupMemberPublicKey")
	}
	recipientKeyName, err := ReadVarString(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupMember.Decode: Problem reading "+
			"GroupMemberKeyName")
	}
	err = ValidateGroupPublicKeyAndName(recipientPublicKeyBytes, recipientKeyName)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupMember.Decode: Problem reading "+
			"GroupMemberPublicKey and GroupMemberKeyName")
	}

	rec.GroupMemberPublicKey = NewPublicKey(recipientPublicKeyBytes)
	rec.GroupMemberKeyName = NewGroupKeyName(recipientKeyName)
	rec.EncryptedKey, err = ReadVarString(rr)
	if err != nil {
		return errors.Wrapf(err, "MessagingGroupMember.Decode: Problem reading "+
			"EncryptedKey")
	}
	return nil
}

// Entry for a public key forbidden from signing blocks.
type ForbiddenPubKeyEntry struct {
	PubKey []byte

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func MakeLikeKey(userPk []byte, LikedPostHash BlockHash) LikeKey {
	return LikeKey{
		LikerPubKey:   MakePkMapKey(userPk),
		LikedPostHash: LikedPostHash,
	}
}

type LikeKey struct {
	LikerPubKey   PkMapKey
	LikedPostHash BlockHash
}

// LikeEntry stores the content of a like transaction.
type LikeEntry struct {
	LikerPubKey   []byte
	LikedPostHash *BlockHash

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func MakeNFTKey(nftPostHash *BlockHash, serialNumber uint64) NFTKey {
	return NFTKey{
		NFTPostHash:  *nftPostHash,
		SerialNumber: serialNumber,
	}
}

type NFTKey struct {
	NFTPostHash  BlockHash
	SerialNumber uint64
}

// This struct defines an individual NFT owned by a PKID. An NFT entry  maps to a single
// postEntry, but a single postEntry can map to multiple NFT entries. Each NFT copy is
// defined by a serial number, which denotes it's place in the set (ie. #1 of 100).
type NFTEntry struct {
	LastOwnerPKID              *PKID // This is needed to decrypt unlockable text.
	OwnerPKID                  *PKID
	NFTPostHash                *BlockHash
	SerialNumber               uint64
	IsForSale                  bool
	MinBidAmountNanos          uint64
	UnlockableText             []byte
	LastAcceptedBidAmountNanos uint64

	// If this NFT was transferred to the current owner, it will be pending until accepted.
	IsPending bool

	// If an NFT does not have unlockable content, it can be sold instantly at BuyNowPriceNanos.
	IsBuyNow bool

	// If an NFT is a Buy Now NFT, it can be purchased for this price.
	BuyNowPriceNanos uint64

	ExtraData map[string][]byte

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func MakeNFTBidKey(bidderPKID *PKID, nftPostHash *BlockHash, serialNumber uint64) NFTBidKey {
	return NFTBidKey{
		BidderPKID:   *bidderPKID,
		NFTPostHash:  *nftPostHash,
		SerialNumber: serialNumber,
	}
}

type NFTBidKey struct {
	BidderPKID   PKID
	NFTPostHash  BlockHash
	SerialNumber uint64
}

// This struct defines a single bid on an NFT.
type NFTBidEntry struct {
	BidderPKID     *PKID
	NFTPostHash    *BlockHash
	SerialNumber   uint64
	BidAmountNanos uint64

	AcceptedBlockHeight *uint32

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func (nftBidEntry *NFTBidEntry) Copy() *NFTBidEntry {
	if nftBidEntry == nil {
		return nil
	}
	newEntry := *nftBidEntry
	newEntry.BidderPKID = nftBidEntry.BidderPKID.NewPKID()
	newEntry.NFTPostHash = nftBidEntry.NFTPostHash.NewBlockHash()
	if nftBidEntry.AcceptedBlockHeight != nil {
		*newEntry.AcceptedBlockHeight = *nftBidEntry.AcceptedBlockHeight
	}
	return &newEntry
}

type DerivedKeyEntry struct {
	// Owner public key
	OwnerPublicKey PublicKey

	// Derived public key
	DerivedPublicKey PublicKey

	// Expiration Block
	ExpirationBlock uint64

	// Operation type determines if the derived key is
	// authorized or de-authorized.
	OperationType AuthorizeDerivedKeyOperationType

	ExtraData map[string][]byte

	// Transaction Spending limit Tracker
	TransactionSpendingLimitTracker *TransactionSpendingLimit

	// Memo that tells you what this derived key is for. Should
	// include the name or domain of the app that asked for these
	// permissions so the user can manage it from a centralized UI.
	Memo []byte

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func (dk *DerivedKeyEntry) Copy() *DerivedKeyEntry {
	if dk == nil {
		return nil
	}
	newEntry := *dk
	if dk.TransactionSpendingLimitTracker != nil {
		newEntry.TransactionSpendingLimitTracker = dk.TransactionSpendingLimitTracker.Copy()
	}
	return &newEntry
}

type DerivedKeyMapKey struct {
	// Owner public key
	OwnerPublicKey PublicKey

	// Derived public key
	DerivedPublicKey PublicKey
}

func MakeDerivedKeyMapKey(ownerPublicKey PublicKey, derivedPublicKey PublicKey) DerivedKeyMapKey {
	return DerivedKeyMapKey{
		OwnerPublicKey:   ownerPublicKey,
		DerivedPublicKey: derivedPublicKey,
	}
}

func MakeFollowKey(followerPKID *PKID, followedPKID *PKID) FollowKey {
	return FollowKey{
		FollowerPKID: *followerPKID,
		FollowedPKID: *followedPKID,
	}
}

type FollowKey struct {
	FollowerPKID PKID
	FollowedPKID PKID
}

// FollowEntry stores the content of a follow transaction.
type FollowEntry struct {
	// Note: It's a little redundant to have these in the entry because they're
	// already used as the key in the DB but it doesn't hurt for now.
	FollowerPKID *PKID
	FollowedPKID *PKID

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

type DiamondKey struct {
	SenderPKID      PKID
	ReceiverPKID    PKID
	DiamondPostHash BlockHash
}

func MakeDiamondKey(senderPKID *PKID, receiverPKID *PKID, diamondPostHash *BlockHash) DiamondKey {
	return DiamondKey{
		SenderPKID:      *senderPKID,
		ReceiverPKID:    *receiverPKID,
		DiamondPostHash: *diamondPostHash,
	}
}

func (mm *DiamondKey) String() string {
	return fmt.Sprintf("<SenderPKID: %v, ReceiverPKID: %v, DiamondPostHash: %v>",
		PkToStringMainnet(mm.SenderPKID[:]), PkToStringMainnet(mm.ReceiverPKID[:]),
		hex.EncodeToString(mm.DiamondPostHash[:]))
}

// DiamondEntry stores the number of diamonds given by a sender to a post.
type DiamondEntry struct {
	SenderPKID      *PKID
	ReceiverPKID    *PKID
	DiamondPostHash *BlockHash
	DiamondLevel    int64

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func MakeRepostKey(userPk []byte, RepostedPostHash BlockHash) RepostKey {
	return RepostKey{
		ReposterPubKey:   MakePkMapKey(userPk),
		RepostedPostHash: RepostedPostHash,
	}
}

type RepostKey struct {
	ReposterPubKey PkMapKey
	// Post Hash of post that was reposted
	RepostedPostHash BlockHash
}

// RepostEntry stores the content of a Repost transaction.
type RepostEntry struct {
	ReposterPubKey []byte

	// BlockHash of the repost
	RepostPostHash *BlockHash

	// Post Hash of post that was reposted
	RepostedPostHash *BlockHash

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

type GlobalParamsEntry struct {
	// The new exchange rate to set.
	USDCentsPerBitcoin uint64

	// The new create profile fee
	CreateProfileFeeNanos uint64

	// The fee to create a single NFT (NFTs with n copies incur n of these fees).
	CreateNFTFeeNanos uint64

	// The maximum number of NFT copies that are allowed to be minted.
	MaxCopiesPerNFT uint64

	// The new minimum fee the network will accept
	MinimumNetworkFeeNanosPerKB uint64
}

// This struct holds info on a readers interactions (e.g. likes) with a post.
// It is added to a post entry response in the frontend server api.
type PostEntryReaderState struct {
	// This is true if the reader has liked the associated post.
	LikedByReader bool

	// The number of diamonds that the reader has given this post.
	DiamondLevelBestowed int64

	// This is true if the reader has reposted the associated post.
	RepostedByReader bool

	// This is the post hash hex of the repost
	RepostPostHashHex string
}

type PostEntry struct {
	// The hash of this post entry. Used as the ID for the entry.
	PostHash *BlockHash

	// The public key of the user who made the post.
	PosterPublicKey []byte

	// The parent post. This is used for comments.
	ParentStakeID []byte

	// The body of this post.
	Body []byte

	// The PostHash of the post this post reposts
	RepostedPostHash *BlockHash

	// Indicator if this PostEntry is a quoted repost or not
	IsQuotedRepost bool

	// The amount the creator of the post gets when someone stakes
	// to the post.
	CreatorBasisPoints uint64

	// The multiple of the payout when a user stakes to a post.
	// 2x multiple = 200% = 20,000bps
	StakeMultipleBasisPoints uint64

	// The block height when the post was confirmed.
	ConfirmationBlockHeight uint32

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

	// Users can "delete" posts, but right now we just implement this as
	// setting a flag on the post to hide it rather than actually deleting
	// it. This simplifies the implementation and makes it easier to "undelete"
	// posts in certain situations.
	IsHidden bool

	// Counter of users that have liked this post.
	LikeCount uint64

	// Counter of users that have reposted this post.
	RepostCount uint64

	// Counter of quote reposts for this post.
	QuoteRepostCount uint64

	// Counter of diamonds that the post has received.
	DiamondCount uint64

	// The private fields below aren't serialized or hashed. They are only kept
	// around for in-memory bookkeeping purposes.

	// Whether or not this entry is deleted in the view.
	isDeleted bool

	// How many comments this post has
	CommentCount uint64

	// Indicator if a post is pinned or not.
	IsPinned bool

	// NFT info.
	IsNFT                          bool
	NumNFTCopies                   uint64
	NumNFTCopiesForSale            uint64
	NumNFTCopiesBurned             uint64
	HasUnlockable                  bool
	NFTRoyaltyToCreatorBasisPoints uint64
	NFTRoyaltyToCoinBasisPoints    uint64

	// AdditionalNFTRoyaltiesToCreatorsBasisPoints is a map where keys are PKIDs and values are uint64s representing
	// basis points. The user with the PKID specified should receive the basis points specified by the value as a
	// royalty anytime this NFT is sold. This map must not contain the post creator.
	AdditionalNFTRoyaltiesToCreatorsBasisPoints map[PKID]uint64
	// AdditionalNFTRoyaltiesToCoinsBasisPoints is a map where keys are PKIDs and values are uint64s representing
	// basis points. The user with the PKID specified should have the basis points specified as by the value added to
	// the DESO locked in their profile anytime this NFT is sold. This map must not contain the post creator.
	AdditionalNFTRoyaltiesToCoinsBasisPoints map[PKID]uint64

	// ExtraData map to hold arbitrary attributes of a post. Holds non-consensus related information about a post.
	// TODO: Change to just ExtraData. Will be easy to do once we have hypersync
	// encoders/decoders, but for now doing so would mess up GOB encoding so we'll
	// wait.
	PostExtraData map[string][]byte
}

func (pe *PostEntry) IsDeleted() bool {
	return pe.isDeleted
}

func IsQuotedRepost(postEntry *PostEntry) bool {
	return postEntry.IsQuotedRepost && postEntry.RepostedPostHash != nil
}

func (pe *PostEntry) HasMedia() bool {
	bodyJSONObj := DeSoBodySchema{}
	err := json.Unmarshal(pe.Body, &bodyJSONObj)
	//Return true if body json can be parsed and ImageURLs or VideoURLs is not nil/non-empty or EmbedVideoUrl is not nil/non-empty
	if (err == nil && len(bodyJSONObj.ImageURLs) > 0 || len(bodyJSONObj.VideoURLs) > 0) || len(pe.PostExtraData["EmbedVideoURL"]) > 0 {
		return true
	}
	return false
}

// Return true if postEntry is a vanilla repost.  A vanilla repost is a post that reposts another post,
// but does not have a body.
func IsVanillaRepost(postEntry *PostEntry) bool {
	return !postEntry.IsQuotedRepost && postEntry.RepostedPostHash != nil
}

type BalanceEntryMapKey struct {
	HODLerPKID  PKID
	CreatorPKID PKID
}

func MakeBalanceEntryKey(hodlerPKID *PKID, creatorPKID *PKID) BalanceEntryMapKey {
	return BalanceEntryMapKey{
		HODLerPKID:  *hodlerPKID,
		CreatorPKID: *creatorPKID,
	}
}

func (mm BalanceEntryMapKey) String() string {
	return fmt.Sprintf("BalanceEntryMapKey: <HODLer Pub Key: %v, Creator Pub Key: %v>",
		PkToStringBoth(mm.HODLerPKID[:]), PkToStringBoth(mm.CreatorPKID[:]))
}

// This struct is mainly used to track a user's balance of a particular
// creator coin. In the database, we store it as the value in a mapping
// that looks as follows:
// <HodlerPKID, CreatorPKID> -> HODLerEntry
type BalanceEntry struct {
	// The PKID of the HODLer. This should never change after it's set initially.
	HODLerPKID *PKID
	// The PKID of the creator. This should never change after it's set initially.
	CreatorPKID *PKID

	// How much this HODLer owns of a particular creator coin.
	BalanceNanos uint256.Int

	// Has the hodler purchased any amount of this user's coin
	HasPurchased bool

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

func (entry *BalanceEntry) Copy() *BalanceEntry {
	return &BalanceEntry{
		HODLerPKID:   entry.HODLerPKID.NewPKID(),
		CreatorPKID:  entry.CreatorPKID.NewPKID(),
		BalanceNanos: *entry.BalanceNanos.Clone(),
		HasPurchased: entry.HasPurchased,
		isDeleted:    entry.isDeleted,
	}
}

type TransferRestrictionStatus uint8

const (
	TransferRestrictionStatusUnrestricted            TransferRestrictionStatus = 0
	TransferRestrictionStatusProfileOwnerOnly        TransferRestrictionStatus = 1
	TransferRestrictionStatusDAOMembersOnly          TransferRestrictionStatus = 2
	TransferRestrictionStatusPermanentlyUnrestricted TransferRestrictionStatus = 3
)

func (transferRestrictionStatus TransferRestrictionStatus) IsUnrestricted() bool {
	if transferRestrictionStatus == TransferRestrictionStatusUnrestricted ||
		transferRestrictionStatus == TransferRestrictionStatusPermanentlyUnrestricted {
		return true
	}
	return false
}

func (transferRestrictionStatus TransferRestrictionStatus) String() string {
	switch transferRestrictionStatus {
	case TransferRestrictionStatusUnrestricted:
		return "Unrestricted"
	case TransferRestrictionStatusProfileOwnerOnly:
		return "Profile Owner Only"
	case TransferRestrictionStatusDAOMembersOnly:
		return "DAO Members Only"
	case TransferRestrictionStatusPermanentlyUnrestricted:
		return "Permanently Unrestricted"
	default:
		return "INVALID TRANSFER RESTRICTION STATUS"
	}
}

// This struct contains all the information required to support coin
// buy/sell transactions on profiles.
type CoinEntry struct {
	// The amount the owner of this profile receives when there is a
	// "net new" purchase of their coin.
	CreatorBasisPoints uint64

	// The amount of DeSo backing the coin. Whenever a user buys a coin
	// from the protocol this amount increases, and whenever a user sells a
	// coin to the protocol this decreases.
	DeSoLockedNanos uint64

	// The number of public keys who have holdings in this creator coin.
	// Due to floating point truncation, it can be difficult to simultaneously
	// reset CoinsInCirculationNanos and DeSoLockedNanos to zero after
	// everyone has sold all their creator coins. Initially NumberOfHolders
	// is set to zero. Once it returns to zero after a series of buys & sells
	// we reset the DeSoLockedNanos and CoinsInCirculationNanos to prevent
	// abnormal bancor curve behavior.
	NumberOfHolders uint64

	// The number of coins currently in circulation. Whenever a user buys a
	// coin from the protocol this increases, and whenever a user sells a
	// coin to the protocol this decreases.
	//
	// It's OK to have a pointer here as long as we *NEVER* manipulate the
	// bigint in place. Instead, we must always do computations of the form:
	//
	// CoinsInCirculationNanos = uint256.NewInt(0).Add(CoinsInCirculationNanos, <other uint256>)
	//
	// This will guarantee that modifying a copy of this struct will not break
	// the original, which is needed for disconnects to work.
	CoinsInCirculationNanos uint256.Int

	// This field keeps track of the highest number of coins that has ever
	// been in circulation. It is used to determine when a creator should
	// receive a "founder reward." In particular, whenever the number of
	// coins being minted would push the number of coins in circulation
	// beyond the watermark, we allocate a percentage of the coins being
	// minted to the creator as a "founder reward."
	//
	// Note that this field doesn't need to be uint256 because it's only
	// relevant for CreatorCoins, which can't exceed math.MaxUint64 in total
	// supply.
	CoinWatermarkNanos uint64

	// If true, DAO coins can no longer be minted.
	MintingDisabled bool

	TransferRestrictionStatus TransferRestrictionStatus
}

type PublicKeyRoyaltyPair struct {
	PublicKey          []byte
	RoyaltyAmountNanos uint64
}

type PKIDEntry struct {
	PKID *PKID
	// We add the public key only so we can reuse this struct to store the reverse
	// mapping of pkid -> public key.
	PublicKey []byte

	isDeleted bool
}

func (pkid *PKIDEntry) String() string {
	return fmt.Sprintf("< PKID: %s, OwnerPublicKey: %s >", PkToStringMainnet(pkid.PKID[:]), PkToStringMainnet(pkid.PublicKey))
}

type ProfileEntry struct {
	// PublicKey is the key used by the user to sign for things and generally
	// verify her identity.
	PublicKey []byte

	// Username is a unique human-readable identifier associated with a profile.
	Username []byte

	// Some text describing the profile.
	Description []byte

	// The profile pic string encoded as a link e.g.
	// data:image/png;base64,<data in base64>
	ProfilePic []byte

	// Users can "delete" profiles, but right now we just implement this as
	// setting a flag on the post to hide it rather than actually deleting
	// it. This simplifies the implementation and makes it easier to "undelete"
	// profiles in certain situations.
	IsHidden bool

	// CreatorCoinEntry tracks the information required to buy/sell creator coins on a user's
	// profile. We "embed" it here for convenience so we can access the fields
	// directly on the ProfileEntry object. Embedding also makes it so that we
	// don't need to initialize it explicitly.
	CreatorCoinEntry CoinEntry

	// DAOCoinEntry tracks the information around the DAO coins issued on a user's profile.
	// Note: the following fields are basically ignored for the DAOCoinEntry
	// 1. CreatorBasisPoints
	// 2. DeSoLockedNanos
	// 3. CoinWaterMarkNanos
	DAOCoinEntry CoinEntry

	// ExtraData map to hold arbitrary attributes of a profile. Holds
	// non-consensus related information about a profile.
	ExtraData map[string][]byte

	// Whether or not this entry should be deleted when the view is flushed
	// to the db. This is initially set to false, but can become true if for
	// example we update a user entry and need to delete the data associated
	// with the old entry.
	isDeleted bool
}

func (pe *ProfileEntry) IsDeleted() bool {
	return pe.isDeleted
}

func EncodeByteArray(bytes []byte) []byte {
	data := []byte{}

	data = append(data, UintToBuf(uint64(len(bytes)))...)
	data = append(data, bytes...)

	return data
}

func DecodeByteArray(reader io.Reader) ([]byte, error) {
	pkLen, err := ReadUvarint(reader)
	if err != nil {
		return nil, errors.Wrapf(err, "DecodeByteArray: Problem when ReadUvarint")
	}

	if pkLen > 0 {
		result := make([]byte, pkLen)

		_, err = io.ReadFull(reader, result)
		if err != nil {
			return nil, errors.Wrapf(err, "DecodeByteArray: Problem when ReadFull")
		}

		return result, nil
	} else {
		return []byte{}, nil
	}
}

// -----------------------------------
// DAO coin limit order
// -----------------------------------

type DAOCoinLimitOrderEntry struct {
	// OrderID is the txn hash (unique identifier) for this order.
	OrderID *BlockHash
	// TransactorPKID is the PKID of the user who created this order.
	TransactorPKID *PKID
	// The PKID of the coin that we're going to buy
	BuyingDAOCoinCreatorPKID *PKID
	// The PKID of the coin that we're going to sell
	SellingDAOCoinCreatorPKID *PKID
	// ScaledExchangeRateCoinsToSellPerCoinToBuy specifies how many of the coins
	// associated with SellingDAOCoinCreatorPKID we need to convert in order
	// to get one BuyingDAOCoinCreatorPKID. For example, if this value was
	// 2, then we would need to convert 2 SellingDAOCoinCreatorPKID
	// coins to get 1 BuyingDAOCoinCreatorPKID. Note, however, that to represent
	// 2, we would actually have to set ScaledExchangeRateCoinsToSellPerCoinToBuy to
	// be equal to 2*1e38 because of the representation format we describe
	// below.
	//
	// The exchange rate is represented as a fixed-point value, which works
	// as follows:
	// - Whenever we reference an exchange rate, call it Y, we pass it
	//   around as a uint256 BUT we consider it to be implicitly divided
	//   by 1e38.
	// - For example, to represent a decimal number like 123456789.987654321,
	//   call it X, we would pass around Y = X*1e38 = 1234567899876543210000000000000000000000000000
	//   as a uint256.
	//   Then, to do operations with Y, we would make sure to always divide by
	//   1e38 before returning a final quantity.
	// - We will refer to Y as "scaled." The value of ScaledExchangeRateCoinsToSellPerCoinToBuy
	//   will always be scaled, meaning it is a uint256 that we implicitly
	//   assume represents a number that is divided by 1e38.
	//
	// This scheme is also referred to as "fixed point," and a similar scheme
	// is utilized by Uniswap. You can learn more about how this works here:
	// - https://en.wikipedia.org/wiki/Q_(number_format)
	// - https://ethereum.org/de/developers/tutorials/uniswap-v2-annotated-code/#FixedPoint
	// - https://uniswap.org/whitepaper.pdf
	ScaledExchangeRateCoinsToSellPerCoinToBuy *uint256.Int
	// QuantityBaseUnits expresses how many "base units" of the coin this order is
	// buying. Note that we could have called this QuantityToBuyNanos, and in the
	// case where we're buying DESO, the base unit is a "nano." However, we call it
	// "base unit" rather than nano because other DAO coins might decide to use a
	// different scheme than nanos for their base unit. In particular, we expect 1e18
	// base units to equal 1 DAO coin, rather than using nanos.
	QuantityToFillInBaseUnits *uint256.Int
	// This is one of ASK or BID. If the operation type is an ASK, then the quantity
	// column applies to the selling coin. I.e. the order is considered fulfilled
	// once the selling coin quantity to fill is zero. If the operation type is a BID,
	// then quantity column applies to the buying coin. I.e. the order is considered
	// fulfilled once the buying coin quantity to fill is zero.
	OperationType DAOCoinLimitOrderOperationType
	// This is the block height at which the order was placed. We use the block height
	// to break ties between orders. If there are two orders that could be filled, we
	// pick the one that was submitted earlier.
	BlockHeight uint32

	isDeleted bool
}

type DAOCoinLimitOrderOperationType uint64

const (
	// We intentionally skip zero as otherwise that would be the default value.
	DAOCoinLimitOrderOperationTypeASK DAOCoinLimitOrderOperationType = 1
	DAOCoinLimitOrderOperationTypeBID DAOCoinLimitOrderOperationType = 2
)

// FilledDAOCoinLimitOrder only exists to support understanding what orders were
// fulfilled when connecting a DAO Coin Limit Order Txn
type FilledDAOCoinLimitOrder struct {
	OrderID                       *BlockHash
	TransactorPKID                *PKID
	BuyingDAOCoinCreatorPKID      *PKID
	SellingDAOCoinCreatorPKID     *PKID
	CoinQuantityInBaseUnitsBought *uint256.Int
	CoinQuantityInBaseUnitsSold   *uint256.Int
	IsFulfilled                   bool
}

func (order *DAOCoinLimitOrderEntry) Copy() *DAOCoinLimitOrderEntry {
	return &DAOCoinLimitOrderEntry{
		OrderID:                   order.OrderID.NewBlockHash(),
		TransactorPKID:            order.TransactorPKID.NewPKID(),
		BuyingDAOCoinCreatorPKID:  order.BuyingDAOCoinCreatorPKID.NewPKID(),
		SellingDAOCoinCreatorPKID: order.SellingDAOCoinCreatorPKID.NewPKID(),
		ScaledExchangeRateCoinsToSellPerCoinToBuy: order.ScaledExchangeRateCoinsToSellPerCoinToBuy.Clone(),
		QuantityToFillInBaseUnits:                 order.QuantityToFillInBaseUnits.Clone(),
		OperationType:                             order.OperationType,
		BlockHeight:                               order.BlockHeight,
		isDeleted:                                 order.isDeleted,
	}
}

func (order *DAOCoinLimitOrderEntry) ToBytes() ([]byte, error) {
	data := append([]byte{}, order.OrderID.ToBytes()...)
	data = append(data, order.TransactorPKID.Encode()...)
	data = append(data, order.BuyingDAOCoinCreatorPKID.Encode()...)
	data = append(data, order.SellingDAOCoinCreatorPKID.Encode()...)
	data = append(data, EncodeUint256(order.ScaledExchangeRateCoinsToSellPerCoinToBuy)...)
	data = append(data, EncodeUint256(order.QuantityToFillInBaseUnits)...)
	data = append(data, UintToBuf(uint64(order.OperationType))...)
	data = append(data, UintToBuf(uint64(order.BlockHeight))...)
	return data, nil
}

func (order *DAOCoinLimitOrderEntry) FromBytes(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	ret := DAOCoinLimitOrderEntry{}
	rr := bytes.NewReader(data)
	var err error

	// Parse OrderID
	ret.OrderID, err = ReadBlockHash(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderEntry.FromBytes: Error reading OrderID: %v", err)
	}

	// Parse TransactorPKID
	ret.TransactorPKID, err = ReadPKID(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderEntry.FromBytes: Error reading TransactorPKID: %v", err)
	}

	// Parse BuyingDAOCoinCreatorPKID
	ret.BuyingDAOCoinCreatorPKID, err = ReadPKID(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderEntry.FromBytes: Error reading BuyingDAOCoinCreatorPKID: %v", err)
	}

	// Parse SellingDAOCoinCreatorPublicKey
	ret.SellingDAOCoinCreatorPKID, err = ReadPKID(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderEntry.FromBytes: Error reading SellingDAOCoinCreatorPKID: %v", err)
	}

	// Parse ScaledExchangeRateCoinsToSellPerCoinToBuy
	ret.ScaledExchangeRateCoinsToSellPerCoinToBuy, err = ReadUint256(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderEntry.FromBytes: Error reading ScaledPrice: %v", err)
	}

	// Parse QuantityToFillInBaseUnits
	ret.QuantityToFillInBaseUnits, err = ReadUint256(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderEntry.FromBytes: Error reading QuantityToFillInBaseUnits: %v", err)
	}

	// Parse OperationType
	operationType, err := ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderEntry.FromBytes: Error reading OperationType: %v", err)
	}
	ret.OperationType = DAOCoinLimitOrderOperationType(operationType)

	// Parse BlockHeight
	var blockHeight uint64
	blockHeight, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("DAOCoinLimitOrderEntry.FromBytes: Error reading BlockHeight: %v", err)
	}
	if blockHeight > uint64(math.MaxUint32) {
		return fmt.Errorf("DAOCoinLimitOrderEntry.FromBytes: Invalid block height %d: Greater than max uint32", blockHeight)
	}
	ret.BlockHeight = uint32(blockHeight)

	*order = ret
	return nil
}

func (order *DAOCoinLimitOrderEntry) IsBetterMatchingOrderThan(other *DAOCoinLimitOrderEntry) bool {
	// We prefer the order with the higher exchange rate. This would result
	// in more of their selling DAO coin being offered to the transactor
	// for each of the corresponding buying DAO coin.
	if !order.ScaledExchangeRateCoinsToSellPerCoinToBuy.Eq(
		other.ScaledExchangeRateCoinsToSellPerCoinToBuy) {

		// order.ScaledPrice > other.ScaledPrice
		return order.ScaledExchangeRateCoinsToSellPerCoinToBuy.Gt(
			other.ScaledExchangeRateCoinsToSellPerCoinToBuy)
	}

	// FIFO, prefer older orders first, i.e. lower block height.
	if order.BlockHeight != other.BlockHeight {
		return order.BlockHeight < other.BlockHeight
	}

	// To break a tie and guarantee idempotency in sorting,
	// prefer higher OrderIDs. This matches the BadgerDB
	// ordering where we SEEK descending.
	return bytes.Compare(order.OrderID.ToBytes(), other.OrderID.ToBytes()) > 0
}

func (order *DAOCoinLimitOrderEntry) BaseUnitsToBuyUint256() (*uint256.Int, error) {
	if order.OperationType == DAOCoinLimitOrderOperationTypeASK {
		// In this case, the quantity specified in the order is the amount to sell,
		// so needs to be converted.
		return ComputeBaseUnitsToBuyUint256(
			order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			order.QuantityToFillInBaseUnits)
	} else if order.OperationType == DAOCoinLimitOrderOperationTypeBID {
		// In this case, the quantity specified in the order is the amount to buy,
		// so can be returned as-is.
		return order.QuantityToFillInBaseUnits, nil
	} else {
		return nil, fmt.Errorf("Invalid OperationType %v", order.OperationType)
	}
}

func ComputeBaseUnitsToBuyUint256(
	scaledExchangeRateCoinsToSellPerCoinToBuy *uint256.Int,
	quantityToSellBaseUnits *uint256.Int) (*uint256.Int, error) {
	// Converts quantity to sell to quantity to buy according to the given exchange rate.
	// Quantity to buy
	//	 = Scaling factor * Quantity to sell / Scaled exchange rate coins to sell per coin to buy
	//	 = Scaling factor * Quantity to sell / (Scaling factor * Quantity to sell / Quantity to Buy)
	//	 = 1 / (1 / Quantity to buy)
	//	 = Quantity to buy

	// Perform a few validations.
	if scaledExchangeRateCoinsToSellPerCoinToBuy == nil ||
		scaledExchangeRateCoinsToSellPerCoinToBuy.IsZero() {
		// This should never happen.
		return nil, fmt.Errorf("ComputeBaseUnitsToBuyUint256: passed invalid exchange rate")
	}

	if quantityToSellBaseUnits == nil || quantityToSellBaseUnits.IsZero() {
		// This should never happen.
		return nil, fmt.Errorf("ComputeBaseUnitsToBuyUint256: passed invalid quantity to sell")
	}

	// Perform calculation.
	scaledQuantityToSellBigInt := big.NewInt(0).Mul(
		OneE38.ToBig(), quantityToSellBaseUnits.ToBig())

	quantityToBuyBigInt := big.NewInt(0).Div(
		scaledQuantityToSellBigInt, scaledExchangeRateCoinsToSellPerCoinToBuy.ToBig())

	// Check for overflow.
	if quantityToBuyBigInt.Cmp(MaxUint256.ToBig()) > 0 {
		return nil, errors.Wrapf(
			RuleErrorDAOCoinLimitOrderTotalCostOverflowsUint256,
			"ComputeBaseUnitsToBuyUint256: scaledExchangeRateCoinsToSellPerCoinToBuy: %v, "+
				"quantityToSellBaseUnits: %v",
			scaledExchangeRateCoinsToSellPerCoinToBuy.Hex(),
			quantityToSellBaseUnits.Hex())
	}

	// We don't trust the overflow checker in uint256. It's too risky because
	// it could cause a money printer bug if there's a problem with it. We
	// manually check for overflow above.
	quantityToBuyUint256, _ := uint256.FromBig(quantityToBuyBigInt)

	// Error if resulting quantity to buy is < 1 base unit.
	if quantityToBuyUint256.IsZero() {
		return nil, RuleErrorDAOCoinLimitOrderTotalCostIsLessThanOneNano
	}

	return quantityToBuyUint256, nil
}

func (order *DAOCoinLimitOrderEntry) BaseUnitsToSellUint256() (*uint256.Int, error) {
	if order.OperationType == DAOCoinLimitOrderOperationTypeBID {
		// In this case, the quantity specified in the order is the amount to buy,
		// so needs to be converted.
		return ComputeBaseUnitsToSellUint256(
			order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			order.QuantityToFillInBaseUnits)
	} else if order.OperationType == DAOCoinLimitOrderOperationTypeASK {
		// In this case, the quantity specified in the order is the amount to sell,
		// so can be returned as-is.
		return order.QuantityToFillInBaseUnits, nil
	} else {
		return nil, fmt.Errorf("Invalid OperationType %v", order.OperationType)
	}
}

func ComputeBaseUnitsToSellUint256(
	scaledExchangeRateCoinsToSellPerCoinToBuy *uint256.Int,
	quantityToBuyBaseUnits *uint256.Int) (*uint256.Int, error) {
	// Converts quantity to buy to quantity to sell according to the given exchange rate.
	// Quantity to sell
	//   = Scaled exchange rate coins to sell per coin to buy * Quantity to buy / Scaling factor
	//   = (Scaling factor * Quantity to sell / Quantity to buy) * Quantity to buy / Scaling factor
	//   = Quantity to sell

	// Perform a few validations.
	if scaledExchangeRateCoinsToSellPerCoinToBuy == nil ||
		scaledExchangeRateCoinsToSellPerCoinToBuy.IsZero() {
		// This should never happen.
		return nil, fmt.Errorf("ComputeBaseUnitsToBuyUint256: passed invalid exchange rate")
	}

	if quantityToBuyBaseUnits == nil || quantityToBuyBaseUnits.IsZero() {
		// This should never happen.
		return nil, fmt.Errorf("ComputeBaseUnitsToBuyUint256: passed invalid quantity to buy")
	}

	// Perform calculation.
	// Note that we account for overflow here. Not doing this could result
	// in a money printer bug. You need to check the following:
	// scaledExchangeRateCoinsToSellPerCoinToBuy * quantityToBuyBaseUnits < uint256max
	// -> scaledExchangeRateCoinsToSellPerCoinToBuy < uint256max / quantitybaseunits
	//
	// The division afterward is inherently safe so no need to check it.

	// Returns the total cost of the inputted price x quantity as a uint256.
	scaledQuantityToSellBigint := big.NewInt(0).Mul(
		scaledExchangeRateCoinsToSellPerCoinToBuy.ToBig(),
		quantityToBuyBaseUnits.ToBig())

	// Check for overflow.
	if scaledQuantityToSellBigint.Cmp(MaxUint256.ToBig()) > 0 {
		return nil, errors.Wrapf(
			RuleErrorDAOCoinLimitOrderTotalCostOverflowsUint256,
			"ComputeBaseUnitsToSellUint256: scaledExchangeRateCoinsToSellPerCoinToBuy: %v, "+
				"quantityToBuyBaseUnits: %v",
			scaledExchangeRateCoinsToSellPerCoinToBuy.Hex(),
			quantityToBuyBaseUnits.Hex())
	}

	// We don't trust the overflow checker in uint256. It's too risky because
	// it could cause a money printer bug if there's a problem with it. We
	// manually check for overflow above.
	scaledQuantityToSellUint256, _ := uint256.FromBig(scaledQuantityToSellBigint)
	quantityToSellUint256, err := SafeUint256().Div(scaledQuantityToSellUint256, OneE38)
	if err != nil {
		// This should never happen as we're dividing by a known constant.
		return nil, errors.Wrapf(err, "ComputeBaseUnitsToSellUint256: ")
	}

	// Error if resulting quantity to sell is < 1 base unit.
	if quantityToSellUint256.IsZero() {
		return nil, RuleErrorDAOCoinLimitOrderTotalCostIsLessThanOneNano
	}

	return quantityToSellUint256, nil
}

type DAOCoinLimitOrderMapKey struct {
	// An OrderID uniquely identifies an order
	OrderID BlockHash
}

func (order *DAOCoinLimitOrderEntry) ToMapKey() DAOCoinLimitOrderMapKey {
	return DAOCoinLimitOrderMapKey{
		OrderID: *order.OrderID.NewBlockHash(),
	}
}
