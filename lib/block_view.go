package lib

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/davecgh/go-spew/spew"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

// block_view.go is the main work-horse for validating transactions in blocks.
// It generally works by creating an "in-memory view" of the current tip and
// then applying a transaction's operations to the view to see if those operations
// are allowed and consistent with the blockchain's current state. Generally,
// every transaction we define has a corresponding connect() and disconnect()
// function defined here that specifies what operations that transaction applies
// to the view and ultimately to the database. If you want to know how any
// particular transaction impacts the database, you've found the right file. A
// good place to start in this file is ConnectTransaction and DisconnectTransaction.
// ConnectBlock is also good.

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

	// NEXT_TAG = 9
)

func (mm UtxoType) String() string {
	if mm == UtxoTypeOutput {
		return "UtxoTypeOutput"
	} else if mm == UtxoTypeBlockReward {
		return "UtxoTypeBlockReward"
	} else if mm == UtxoTypeBitcoinBurn {
		return "UtxoTypeBitcoinBurn"
	} else if mm == UtxoTypeStakeReward {
		return "UtxoTypeStakeReward"
	}

	return "UtxoTypeUnknown"
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

func (utxoEntry *UtxoEntry) String() string {
	return fmt.Sprintf("< PublicKey: %v, BlockHeight: %d, AmountNanos: %d, UtxoType: %v, "+
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
		PublicKey:   MakePkMapKey(pk),
		TstampNanos: tstampNanos,
	}
}

type MessageKey struct {
	PublicKey   PkMapKey
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
	SenderPublicKey    []byte
	RecipientPublicKey []byte
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
	// Version = 2 : message encrypted using shared secret
	// Version = 1 : message encrypted using public key
	Version uint8
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

	// Whether or not this entry is deleted in the view.
	isDeleted bool
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

	// Whether or not this entry is deleted in the view.
	isDeleted bool
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

// The blockchain used to store the USD to BTC exchange rate in bav.USDCentsPerBitcoin, which was set by a
// UPDATE_BITCOIN_USD_EXCHANGE_RATE txn, but has since moved to the GlobalParamsEntry, which is set by a
// UPDATE_GLOBAL_PARAMS txn.
func (bav *UtxoView) GetCurrentUSDCentsPerBitcoin() uint64 {
	usdCentsPerBitcoin := bav.USDCentsPerBitcoin
	if bav.GlobalParamsEntry.USDCentsPerBitcoin != 0 {
		usdCentsPerBitcoin = bav.GlobalParamsEntry.USDCentsPerBitcoin
	}
	return usdCentsPerBitcoin
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

func (bav *UtxoView) GetPostEntryReaderState(
	readerPK []byte, postEntry *PostEntry) *PostEntryReaderState {
	postEntryReaderState := &PostEntryReaderState{}

	// Get like state.
	postEntryReaderState.LikedByReader = bav.GetLikedByReader(readerPK, postEntry.PostHash)

	// Get repost state.
	postEntryReaderState.RepostPostHashHex, postEntryReaderState.RepostedByReader = bav.GetRepostPostEntryStateForReader(readerPK, postEntry.PostHash)

	// Get diamond state.
	senderPKID := bav.GetPKIDForPublicKey(readerPK)
	receiverPKID := bav.GetPKIDForPublicKey(postEntry.PosterPublicKey)
	if senderPKID == nil || receiverPKID == nil {
		glog.Debugf(
			"GetPostEntryReaderState: Could not find PKID for reader PK: %s or poster PK: %s",
			PkToString(readerPK, bav.Params), PkToString(postEntry.PosterPublicKey, bav.Params))
	} else {
		diamondKey := MakeDiamondKey(senderPKID.PKID, receiverPKID.PKID, postEntry.PostHash)
		diamondEntry := bav.GetDiamondEntryForDiamondKey(&diamondKey)
		if diamondEntry != nil {
			postEntryReaderState.DiamondLevelBestowed = diamondEntry.DiamondLevel
		}
	}

	return postEntryReaderState
}

func (bav *UtxoView) GetLikedByReader(readerPK []byte, postHash *BlockHash) bool {
	// Get like state.
	likeKey := MakeLikeKey(readerPK, *postHash)
	likeEntry := bav._getLikeEntryForLikeKey(&likeKey)
	return likeEntry != nil && !likeEntry.isDeleted
}

func (bav *UtxoView) GetRepostPostEntryStateForReader(readerPK []byte, postHash *BlockHash) (string, bool) {
	repostKey := MakeRepostKey(readerPK, *postHash)
	repostEntry := bav._getRepostEntryForRepostKey(&repostKey)
	if repostEntry == nil {
		return "", false
	}
	repostPostEntry := bav.GetPostEntryForPostHash(repostEntry.RepostPostHash)
	if repostPostEntry == nil {
		glog.Errorf("Could not find repost post entry from post hash: %v", repostEntry.RepostedPostHash)
		return "", false
	}
	// We include the PostHashHex of this user's post that reposts the current post to
	// handle undo-ing (AKA hiding) a repost.
	// If the user's repost of this post is hidden, we set RepostedByReader to false.
	return hex.EncodeToString(repostEntry.RepostPostHash[:]), !repostPostEntry.IsHidden
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

	// ExtraData map to hold arbitrary attributes of a post. Holds non-consensus related information about a post.
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

func MakeCreatorCoinBalanceKey(hodlerPKID *PKID, creatorPKID *PKID) BalanceEntryMapKey {
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
	BalanceNanos uint64

	// Has the hodler purchased any amount of this user's coin
	HasPurchased bool

	// Whether or not this entry is deleted in the view.
	isDeleted bool
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
	CoinsInCirculationNanos uint64

	// This field keeps track of the highest number of coins that has ever
	// been in circulation. It is used to determine when a creator should
	// receive a "founder reward." In particular, whenever the number of
	// coins being minted would push the number of coins in circulation
	// beyond the watermark, we allocate a percentage of the coins being
	// minted to the creator as a "founder reward."
	CoinWatermarkNanos uint64
}

type PKIDEntry struct {
	PKID *PKID
	// We add the public key only so we can reuse this struct to store the reverse
	// mapping of pkid -> public key.
	PublicKey []byte

	isDeleted bool
	isDirty   bool
}

func (pkid *PKIDEntry) String() string {
	return fmt.Sprintf("< PKID: %s, PublicKey: %s >", PkToStringMainnet(pkid.PKID[:]), PkToStringMainnet(pkid.PublicKey))
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

	// CoinEntry tracks the information required to buy/sell coins on a user's
	// profile. We "embed" it here for convenience so we can access the fields
	// directly on the ProfileEntry object. Embedding also makes it so that we
	// don't need to initialize it explicitly.
	CoinEntry

	// Whether or not this entry should be deleted when the view is flushed
	// to the db. This is initially set to false, but can become true if for
	// example we update a user entry and need to delete the data associated
	// with the old entry.
	isDeleted bool
}

func (pe *ProfileEntry) IsDeleted() bool {
	return pe.isDeleted
}

type UtxoView struct {
	// Utxo data
	NumUtxoEntries              uint64
	UtxoKeyToUtxoEntry          map[UtxoKey]*UtxoEntry
	PublicKeyToDeSoBalanceNanos map[PublicKey]uint64

	// BitcoinExchange data
	NanosPurchased     uint64
	USDCentsPerBitcoin uint64
	GlobalParamsEntry  *GlobalParamsEntry
	BitcoinBurnTxIDs   map[BlockHash]bool

	// Forbidden block signature pubkeys
	ForbiddenPubKeyToForbiddenPubKeyEntry map[PkMapKey]*ForbiddenPubKeyEntry

	// Messages data
	MessageKeyToMessageEntry map[MessageKey]*MessageEntry

	// Postgres stores message data slightly differently
	MessageMap map[BlockHash]*PGMessage

	// Follow data
	FollowKeyToFollowEntry map[FollowKey]*FollowEntry

	// NFT data
	NFTKeyToNFTEntry              map[NFTKey]*NFTEntry
	NFTBidKeyToNFTBidEntry        map[NFTBidKey]*NFTBidEntry
	NFTKeyToAcceptedNFTBidHistory map[NFTKey]*[]*NFTBidEntry

	// Diamond data
	DiamondKeyToDiamondEntry map[DiamondKey]*DiamondEntry

	// Like data
	LikeKeyToLikeEntry map[LikeKey]*LikeEntry

	// Repost data
	RepostKeyToRepostEntry map[RepostKey]*RepostEntry

	// Post data
	PostHashToPostEntry map[BlockHash]*PostEntry

	// Profile data
	PublicKeyToPKIDEntry map[PkMapKey]*PKIDEntry
	// The PKIDEntry is only used here to store the public key.
	PKIDToPublicKey               map[PKID]*PKIDEntry
	ProfilePKIDToProfileEntry     map[PKID]*ProfileEntry
	ProfileUsernameToProfileEntry map[UsernameMapKey]*ProfileEntry

	// Coin balance entries
	HODLerPKIDCreatorPKIDToBalanceEntry map[BalanceEntryMapKey]*BalanceEntry

	// Derived Key entries. Map key is a combination of owner and derived public keys.
	DerivedKeyToDerivedEntry map[DerivedKeyMapKey]*DerivedKeyEntry

	// The hash of the tip the view is currently referencing. Mainly used
	// for error-checking when doing a bulk operation on the view.
	TipHash *BlockHash

	Handle   *badger.DB
	Postgres *Postgres
	Params   *DeSoParams
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

	// NEXT_TAG = 24
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
	case OperationTypeCreatorCoin:
		{
			return "OperationTypeCreatorCoin"
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
	case OperationTypeAuthorizeDerivedKey:
		{
			return "OperationTypeAuthorizeDerivedKey"
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

	// Save the previous repost entry and repost count when making an update.
	PrevRepostEntry *RepostEntry
	PrevRepostCount uint64

	// Save the state of a creator coin prior to updating it due to a
	// buy/sell/add transaction.
	PrevCoinEntry *CoinEntry
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
	AcceptNFTBidCreatorPublicKey    []byte
	AcceptNFTBidBidderPublicKey     []byte
	AcceptNFTBidCreatorRoyaltyNanos uint64
}

// Assumes the db Handle is already set on the view, but otherwise the
// initialization is full.
func (bav *UtxoView) _ResetViewMappingsAfterFlush() {
	// Utxo data
	bav.UtxoKeyToUtxoEntry = make(map[UtxoKey]*UtxoEntry)
	// TODO: Deprecate this value
	bav.NumUtxoEntries = GetUtxoNumEntries(bav.Handle)
	bav.PublicKeyToDeSoBalanceNanos = make(map[PublicKey]uint64)

	// BitcoinExchange data
	bav.NanosPurchased = DbGetNanosPurchased(bav.Handle)
	bav.USDCentsPerBitcoin = DbGetUSDCentsPerBitcoinExchangeRate(bav.Handle)
	bav.GlobalParamsEntry = DbGetGlobalParamsEntry(bav.Handle)
	bav.BitcoinBurnTxIDs = make(map[BlockHash]bool)

	// Forbidden block signature pub key info.
	bav.ForbiddenPubKeyToForbiddenPubKeyEntry = make(map[PkMapKey]*ForbiddenPubKeyEntry)

	// Post and profile data
	bav.PostHashToPostEntry = make(map[BlockHash]*PostEntry)
	bav.PublicKeyToPKIDEntry = make(map[PkMapKey]*PKIDEntry)
	bav.PKIDToPublicKey = make(map[PKID]*PKIDEntry)
	bav.ProfilePKIDToProfileEntry = make(map[PKID]*ProfileEntry)
	bav.ProfileUsernameToProfileEntry = make(map[UsernameMapKey]*ProfileEntry)

	// Messages data
	bav.MessageKeyToMessageEntry = make(map[MessageKey]*MessageEntry)
	bav.MessageMap = make(map[BlockHash]*PGMessage)

	// Follow data
	bav.FollowKeyToFollowEntry = make(map[FollowKey]*FollowEntry)

	// NFT data
	bav.NFTKeyToNFTEntry = make(map[NFTKey]*NFTEntry)
	bav.NFTBidKeyToNFTBidEntry = make(map[NFTBidKey]*NFTBidEntry)
	bav.NFTKeyToAcceptedNFTBidHistory = make(map[NFTKey]*[]*NFTBidEntry)

	// Diamond data
	bav.DiamondKeyToDiamondEntry = make(map[DiamondKey]*DiamondEntry)

	// Like data
	bav.LikeKeyToLikeEntry = make(map[LikeKey]*LikeEntry)

	// Repost data
	bav.RepostKeyToRepostEntry = make(map[RepostKey]*RepostEntry)

	// Coin balance entries
	bav.HODLerPKIDCreatorPKIDToBalanceEntry = make(map[BalanceEntryMapKey]*BalanceEntry)

	// Derived Key entries
	bav.DerivedKeyToDerivedEntry = make(map[DerivedKeyMapKey]*DerivedKeyEntry)
}

func (bav *UtxoView) CopyUtxoView() (*UtxoView, error) {
	newView, err := NewUtxoView(bav.Handle, bav.Params, bav.Postgres)
	if err != nil {
		return nil, err
	}

	// Copy the UtxoEntry data
	// Note that using _setUtxoMappings is dangerous because the Pos within
	// the UtxoEntrys is off.
	newView.UtxoKeyToUtxoEntry = make(map[UtxoKey]*UtxoEntry, len(bav.UtxoKeyToUtxoEntry))
	for utxoKey, utxoEntry := range bav.UtxoKeyToUtxoEntry {
		newUtxoEntry := *utxoEntry
		newView.UtxoKeyToUtxoEntry[utxoKey] = &newUtxoEntry
	}
	newView.NumUtxoEntries = bav.NumUtxoEntries

	// Copy the public key to balance data
	newView.PublicKeyToDeSoBalanceNanos = make(map[PublicKey]uint64, len(bav.PublicKeyToDeSoBalanceNanos))
	for pkMapKey, desoBalance := range bav.PublicKeyToDeSoBalanceNanos {
		newView.PublicKeyToDeSoBalanceNanos[pkMapKey] = desoBalance
	}

	// Copy the BitcoinExchange data
	newView.BitcoinBurnTxIDs = make(map[BlockHash]bool, len(bav.BitcoinBurnTxIDs))
	for bh := range bav.BitcoinBurnTxIDs {
		newView.BitcoinBurnTxIDs[bh] = true
	}
	newView.NanosPurchased = bav.NanosPurchased
	newView.USDCentsPerBitcoin = bav.USDCentsPerBitcoin

	// Copy the GlobalParamsEntry
	newGlobalParamsEntry := *bav.GlobalParamsEntry
	newView.GlobalParamsEntry = &newGlobalParamsEntry

	// Copy the post data
	newView.PostHashToPostEntry = make(map[BlockHash]*PostEntry, len(bav.PostHashToPostEntry))
	for postHash, postEntry := range bav.PostHashToPostEntry {
		if postEntry == nil {
			continue
		}

		newPostEntry := *postEntry
		newView.PostHashToPostEntry[postHash] = &newPostEntry
	}

	// Copy the PKID data
	newView.PublicKeyToPKIDEntry = make(map[PkMapKey]*PKIDEntry, len(bav.PublicKeyToPKIDEntry))
	for pkMapKey, pkid := range bav.PublicKeyToPKIDEntry {
		newPKID := *pkid
		newView.PublicKeyToPKIDEntry[pkMapKey] = &newPKID
	}

	newView.PKIDToPublicKey = make(map[PKID]*PKIDEntry, len(bav.PKIDToPublicKey))
	for pkid, pkidEntry := range bav.PKIDToPublicKey {
		newPKIDEntry := *pkidEntry
		newView.PKIDToPublicKey[pkid] = &newPKIDEntry
	}

	// Copy the profile data
	newView.ProfilePKIDToProfileEntry = make(map[PKID]*ProfileEntry, len(bav.ProfilePKIDToProfileEntry))
	for profilePKID, profileEntry := range bav.ProfilePKIDToProfileEntry {
		if profileEntry == nil {
			continue
		}

		newProfileEntry := *profileEntry
		newView.ProfilePKIDToProfileEntry[profilePKID] = &newProfileEntry
	}
	newView.ProfileUsernameToProfileEntry = make(map[UsernameMapKey]*ProfileEntry, len(bav.ProfileUsernameToProfileEntry))
	for profilePKID, profileEntry := range bav.ProfileUsernameToProfileEntry {
		if profileEntry == nil {
			continue
		}

		newProfileEntry := *profileEntry
		newView.ProfileUsernameToProfileEntry[profilePKID] = &newProfileEntry
	}

	// Copy the message data
	newView.MessageKeyToMessageEntry = make(map[MessageKey]*MessageEntry, len(bav.MessageKeyToMessageEntry))
	for msgKey, msgEntry := range bav.MessageKeyToMessageEntry {
		newMsgEntry := *msgEntry
		newView.MessageKeyToMessageEntry[msgKey] = &newMsgEntry
	}

	newView.MessageMap = make(map[BlockHash]*PGMessage, len(bav.MessageMap))
	for txnHash, message := range bav.MessageMap {
		newMessage := *message
		newView.MessageMap[txnHash] = &newMessage
	}

	// Copy the follow data
	newView.FollowKeyToFollowEntry = make(map[FollowKey]*FollowEntry, len(bav.FollowKeyToFollowEntry))
	for followKey, followEntry := range bav.FollowKeyToFollowEntry {
		if followEntry == nil {
			continue
		}

		newFollowEntry := *followEntry
		newView.FollowKeyToFollowEntry[followKey] = &newFollowEntry
	}

	// Copy the like data
	newView.LikeKeyToLikeEntry = make(map[LikeKey]*LikeEntry, len(bav.LikeKeyToLikeEntry))
	for likeKey, likeEntry := range bav.LikeKeyToLikeEntry {
		if likeEntry == nil {
			continue
		}

		newLikeEntry := *likeEntry
		newView.LikeKeyToLikeEntry[likeKey] = &newLikeEntry
	}

	// Copy the repost data
	newView.RepostKeyToRepostEntry = make(map[RepostKey]*RepostEntry, len(bav.RepostKeyToRepostEntry))
	for repostKey, repostEntry := range bav.RepostKeyToRepostEntry {
		newRepostEntry := *repostEntry
		newView.RepostKeyToRepostEntry[repostKey] = &newRepostEntry
	}

	// Copy the balance entry data
	newView.HODLerPKIDCreatorPKIDToBalanceEntry = make(
		map[BalanceEntryMapKey]*BalanceEntry, len(bav.HODLerPKIDCreatorPKIDToBalanceEntry))
	for balanceEntryMapKey, balanceEntry := range bav.HODLerPKIDCreatorPKIDToBalanceEntry {
		if balanceEntry == nil {
			continue
		}

		newBalanceEntry := *balanceEntry
		newView.HODLerPKIDCreatorPKIDToBalanceEntry[balanceEntryMapKey] = &newBalanceEntry
	}

	// Copy the Diamond data
	newView.DiamondKeyToDiamondEntry = make(
		map[DiamondKey]*DiamondEntry, len(bav.DiamondKeyToDiamondEntry))
	for diamondKey, diamondEntry := range bav.DiamondKeyToDiamondEntry {
		newDiamondEntry := *diamondEntry
		newView.DiamondKeyToDiamondEntry[diamondKey] = &newDiamondEntry
	}

	// Copy the NFT data
	newView.NFTKeyToNFTEntry = make(map[NFTKey]*NFTEntry, len(bav.NFTKeyToNFTEntry))
	for nftKey, nftEntry := range bav.NFTKeyToNFTEntry {
		newNFTEntry := *nftEntry
		newView.NFTKeyToNFTEntry[nftKey] = &newNFTEntry
	}

	newView.NFTBidKeyToNFTBidEntry = make(map[NFTBidKey]*NFTBidEntry, len(bav.NFTBidKeyToNFTBidEntry))
	for nftBidKey, nftBidEntry := range bav.NFTBidKeyToNFTBidEntry {
		newNFTBidEntry := *nftBidEntry
		newView.NFTBidKeyToNFTBidEntry[nftBidKey] = &newNFTBidEntry
	}

	newView.NFTKeyToAcceptedNFTBidHistory = make(map[NFTKey]*[]*NFTBidEntry, len(bav.NFTKeyToAcceptedNFTBidHistory))
	for nftKey, nftBidEntries := range bav.NFTKeyToAcceptedNFTBidHistory {
		newNFTBidEntries := *nftBidEntries
		newView.NFTKeyToAcceptedNFTBidHistory[nftKey] = &newNFTBidEntries
	}

	// Copy the Derived Key data
	newView.DerivedKeyToDerivedEntry = make(map[DerivedKeyMapKey]*DerivedKeyEntry, len(bav.DerivedKeyToDerivedEntry))
	for entryKey, entry := range bav.DerivedKeyToDerivedEntry {
		newEntry := *entry
		newView.DerivedKeyToDerivedEntry[entryKey] = &newEntry
	}

	return newView, nil
}

func NewUtxoView(
	_handle *badger.DB,
	_params *DeSoParams,
	_postgres *Postgres,
) (*UtxoView, error) {

	view := UtxoView{
		Handle: _handle,
		Params: _params,
		// Note that the TipHash does not get reset as part of
		// _ResetViewMappingsAfterFlush because it is not something that is affected by a
		// flush operation. Moreover, its value is consistent with the view regardless of
		// whether or not the view is flushed or not. Additionally the utxo view does
		// not concern itself with the header chain (see comment on GetBestHash for more
		// info on that).
		TipHash: DbGetBestHash(_handle, ChainTypeDeSoBlock /* don't get the header chain */),

		Postgres: _postgres,
		// Set everything else in _ResetViewMappings()
	}

	// Note that the TipHash does not get reset as part of
	// _ResetViewMappingsAfterFlush because it is not something that is affected by a
	// flush operation. Moreover, its value is consistent with the view regardless of
	// whether or not the view is flushed or not. Additionally the utxo view does
	// not concern itself with the header chain (see comment on GetBestHash for more
	// info on that).
	if view.Postgres != nil {
		view.TipHash = view.Postgres.GetChain(MAIN_CHAIN).TipHash
	} else {
		view.TipHash = DbGetBestHash(view.Handle, ChainTypeDeSoBlock /* don't get the header chain */)
	}

	// This function is generally used to reset the view after a flush has been performed
	// but we can use it here to initialize the mappings.
	view._ResetViewMappingsAfterFlush()

	return &view, nil
}

func (bav *UtxoView) _deleteUtxoMappings(utxoEntry *UtxoEntry) error {
	if utxoEntry.UtxoKey == nil {
		return fmt.Errorf("_deleteUtxoMappings: utxoKey missing for utxoEntry %+v", utxoEntry)
	}

	// Deleting a utxo amounts to setting its mappings to point to an
	// entry that has (isSpent = true). So we create such an entry and set
	// the mappings to point to it.
	tombstoneEntry := *utxoEntry
	tombstoneEntry.isSpent = true

	// _setUtxoMappings will take this and use its fields to update the
	// mappings.
	// TODO: We're doing a double-copy here at the moment. We should make this more
	// efficient.
	return bav._setUtxoMappings(&tombstoneEntry)

	// Note at this point, the utxoEntry passed in is dangling and can
	// be re-used for another purpose if desired.
}

func (bav *UtxoView) _setUtxoMappings(utxoEntry *UtxoEntry) error {
	if utxoEntry.UtxoKey == nil {
		return fmt.Errorf("_setUtxoMappings: utxoKey missing for utxoEntry %+v", utxoEntry)
	}
	bav.UtxoKeyToUtxoEntry[*utxoEntry.UtxoKey] = utxoEntry

	return nil
}

func (bav *UtxoView) GetUtxoEntryForUtxoKey(utxoKey *UtxoKey) *UtxoEntry {
	utxoEntry, ok := bav.UtxoKeyToUtxoEntry[*utxoKey]
	// If the utxo entry isn't in our in-memory data structure, fetch it from the
	// db.
	if !ok {
		if bav.Postgres != nil {
			utxoEntry = bav.Postgres.GetUtxoEntryForUtxoKey(utxoKey)
		} else {
			utxoEntry = DbGetUtxoEntryForUtxoKey(bav.Handle, utxoKey)
		}
		if utxoEntry == nil {
			// This means the utxo is neither in our map nor in the db so
			// it doesn't exist. Return nil to signal that in this case.
			return nil
		}

		// At this point we have the utxo entry so load it
		// into our in-memory data structure for future reference. Note that
		// isSpent should be false by default. Also note that a back-reference
		// to the utxoKey should be set on the utxoEntry by this function.
		utxoEntry.UtxoKey = utxoKey
		if err := bav._setUtxoMappings(utxoEntry); err != nil {
			glog.Errorf("GetUtxoEntryForUtxoKey: Problem encountered setting utxo mapping %v", err)
			return nil
		}
	}

	return utxoEntry
}

func (bav *UtxoView) GetDeSoBalanceNanosForPublicKey(publicKey []byte) (uint64, error) {
	balanceNanos, hasBalance := bav.PublicKeyToDeSoBalanceNanos[*NewPublicKey(publicKey)]
	if hasBalance {
		return balanceNanos, nil
	}

	// If the utxo entry isn't in our in-memory data structure, fetch it from the db.
	if bav.Postgres != nil {
		balanceNanos = bav.Postgres.GetBalance(NewPublicKey(publicKey))
	} else {
		var err error
		balanceNanos, err = DbGetDeSoBalanceNanosForPublicKey(bav.Handle, publicKey)
		if err != nil {
			return uint64(0), errors.Wrap(err, "GetDeSoBalanceNanosForPublicKey: ")
		}
	}

	// Add the balance to memory for future references.
	bav.PublicKeyToDeSoBalanceNanos[*NewPublicKey(publicKey)] = balanceNanos

	return balanceNanos, nil
}

func (bav *UtxoView) _unSpendUtxo(utxoEntryy *UtxoEntry) error {
	// Operate on a copy of the entry in order to avoid bugs. Note that not
	// doing this could result in us maintaining a reference to the entry and
	// modifying it on subsequent calls to this function, which is bad.
	utxoEntryCopy := *utxoEntryy

	// If the utxoKey back-reference on the entry isn't set return an error.
	if utxoEntryCopy.UtxoKey == nil {
		return fmt.Errorf("_unSpendUtxo: utxoEntry must have utxoKey set")
	}
	// Make sure isSpent is set to false. It should be false by default if we
	// read this entry from the db but set it in case the caller derived the
	// entry via a different method.
	utxoEntryCopy.isSpent = false

	// Not setting this to a copy could cause issues down the road where we modify
	// the utxo passed-in on subsequent calls.
	if err := bav._setUtxoMappings(&utxoEntryCopy); err != nil {
		return err
	}

	// Since we re-added the utxo, bump the number of entries.
	bav.NumUtxoEntries++

	// Add the utxo back to the spender's balance.
	desoBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(utxoEntryy.PublicKey)
	if err != nil {
		return errors.Wrap(err, "_unSpendUtxo: ")
	}
	desoBalanceNanos += utxoEntryy.AmountNanos
	bav.PublicKeyToDeSoBalanceNanos[*NewPublicKey(utxoEntryy.PublicKey)] = desoBalanceNanos

	return nil
}

func (bav *UtxoView) _spendUtxo(utxoKey *UtxoKey) (*UtxoOperation, error) {
	// Swap this utxo's position with the utxo in the last position and delete it.

	// Get the entry for this utxo from the view if it's cached,
	// otherwise try and get it from the db.
	utxoEntry := bav.GetUtxoEntryForUtxoKey(utxoKey)
	if utxoEntry == nil {
		return nil, fmt.Errorf("_spendUtxo: Attempting to spend non-existent UTXO")
	}
	if utxoEntry.isSpent {
		return nil, fmt.Errorf("_spendUtxo: Attempting to spend an already-spent UTXO")
	}

	// Delete the entry by removing its mappings from our in-memory data
	// structures.
	if err := bav._deleteUtxoMappings(utxoEntry); err != nil {
		return nil, errors.Wrapf(err, "_spendUtxo: ")
	}

	// Decrement the number of entries by one since we marked one as spent in the
	// view.
	bav.NumUtxoEntries--

	// Deduct the utxo from the spender's balance.
	desoBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(utxoEntry.PublicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "_spendUtxo: ")
	}
	desoBalanceNanos -= utxoEntry.AmountNanos
	bav.PublicKeyToDeSoBalanceNanos[*NewPublicKey(utxoEntry.PublicKey)] = desoBalanceNanos

	// Record a UtxoOperation in case we want to roll this back in the
	// future. At this point, the UtxoEntry passed in still has all of its
	// fields set to what they were right before SPEND was called. This is
	// exactly what we want (see comment on OperationTypeSpendUtxo for more info).
	// Make a copy of the entry to avoid issues where we accidentally modify
	// the entry in the future.
	utxoEntryCopy := *utxoEntry
	return &UtxoOperation{
		Type:  OperationTypeSpendUtxo,
		Key:   utxoKey,
		Entry: &utxoEntryCopy,
	}, nil
}

func (bav *UtxoView) _unAddUtxo(utxoKey *UtxoKey) error {
	// Get the entry for this utxo from the view if it's cached,
	// otherwise try and get it from the db.
	utxoEntry := bav.GetUtxoEntryForUtxoKey(utxoKey)
	if utxoEntry == nil {
		return fmt.Errorf("_unAddUtxo: Attempting to remove non-existent UTXO")
	}
	if utxoEntry.isSpent {
		return fmt.Errorf("_unAddUtxo: Attempting to remove an already-spent UTXO")
	}

	// At this point we should have the entry sanity-checked. To remove
	// it from our data structure, it is sufficient to replace it with an
	// entry that is marked as spent. When the view is eventually flushed
	// to the database the output's status as spent will translate to it
	// getting deleted, which is what we want.
	if err := bav._deleteUtxoMappings(utxoEntry); err != nil {
		return err
	}

	// In addition to marking the output as spent, we update the number of
	// entries to reflect the output is no longer in our utxo list.
	bav.NumUtxoEntries--

	// Remove the utxo back from the spender's balance.
	desoBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(utxoEntry.PublicKey)
	if err != nil {
		return errors.Wrapf(err, "_unAddUtxo: ")
	}
	desoBalanceNanos -= utxoEntry.AmountNanos
	bav.PublicKeyToDeSoBalanceNanos[*NewPublicKey(utxoEntry.PublicKey)] = desoBalanceNanos

	return nil
}

// Note: We assume that the person passing in the utxo key and the utxo entry
// aren't going to modify them after.
func (bav *UtxoView) _addUtxo(utxoEntryy *UtxoEntry) (*UtxoOperation, error) {
	// Use a copy of the utxo passed in so we avoid keeping a reference to it
	// which could be modified in subsequent calls.
	utxoEntryCopy := *utxoEntryy

	// If the utxoKey back-reference on the entry isn't set then error.
	if utxoEntryCopy.UtxoKey == nil {
		return nil, fmt.Errorf("_addUtxo: utxoEntry must have utxoKey set")
	}
	// If the UtxoEntry passed in has isSpent set then error. The caller should only
	// pass in entries that are unspent.
	if utxoEntryCopy.isSpent {
		return nil, fmt.Errorf("_addUtxo: UtxoEntry being added has isSpent = true")
	}

	// Put the utxo at the end and update our in-memory data structures with
	// this change.
	//
	// Note this may over-write an existing entry but this is OK for a very subtle
	// reason. When we roll back a transaction, e.g. due to a
	// reorg, we mark the outputs of that transaction as "spent" but we don't delete them
	// from our view because doing so would cause us to neglect to actually delete them
	// when we flush the view to the db. What this means is that if we roll back a transaction
	// in a block but then add it later in a different block, that second add could
	// over-write the entry that is currently has isSpent=true with a similar (though
	// not identical because the block height may differ) entry that has isSpent=false.
	// This is OK however because the new entry we're over-writing the old entry with
	// has the same key and so flushing the view to the database will result in the
	// deletion of the old entry as intended when the new entry over-writes it. Put
	// simply, the over-write that could happen here is an over-write we also want to
	// happen when we flush and so it should be OK.
	if err := bav._setUtxoMappings(&utxoEntryCopy); err != nil {
		return nil, errors.Wrapf(err, "_addUtxo: ")
	}

	// Bump the number of entries since we just added this one at the end.
	bav.NumUtxoEntries++

	// Add the utxo back to the spender's balance.
	desoBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(utxoEntryy.PublicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "_addUtxo: ")
	}
	desoBalanceNanos += utxoEntryy.AmountNanos
	bav.PublicKeyToDeSoBalanceNanos[*NewPublicKey(utxoEntryy.PublicKey)] = desoBalanceNanos

	// Finally record a UtxoOperation in case we want to roll back this ADD
	// in the future. Note that Entry data isn't required for an ADD operation.
	return &UtxoOperation{
		Type: OperationTypeAddUtxo,
		// We don't technically need these in order to be able to roll back the
		// transaction but they're useful for callers of connectTransaction to
		// determine implicit outputs that were created like those that get created
		// in a Bitcoin burn transaction.
		Key:   utxoEntryCopy.UtxoKey,
		Entry: &utxoEntryCopy,
	}, nil
}

func (bav *UtxoView) _disconnectBasicTransfer(currentTxn *MsgDeSoTxn, txnHash *BlockHash, utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {
	// First we check to see if the last utxoOp was a diamond operation. If it was, we disconnect
	// the diamond-related changes and decrement the operation index to move past it.
	operationIndex := len(utxoOpsForTxn) - 1
	if len(utxoOpsForTxn) > 0 && utxoOpsForTxn[operationIndex].Type == OperationTypeDeSoDiamond {
		currentOperation := utxoOpsForTxn[operationIndex]

		diamondPostHashBytes, hasDiamondPostHash := currentTxn.ExtraData[DiamondPostHashKey]
		if !hasDiamondPostHash {
			return fmt.Errorf("_disconnectBasicTransfer: Found diamond op without diamondPostHash")
		}

		// Sanity check the post hash bytes before creating the post hash.
		diamondPostHash := &BlockHash{}
		if len(diamondPostHashBytes) != HashSizeBytes {
			return fmt.Errorf(
				"_disconnectBasicTransfer: DiamondPostHashBytes has incorrect length: %d",
				len(diamondPostHashBytes))
		}
		copy(diamondPostHash[:], diamondPostHashBytes[:])

		// Get the diamonded post entry and make sure it exists.
		diamondedPostEntry := bav.GetPostEntryForPostHash(diamondPostHash)
		if diamondedPostEntry == nil || diamondedPostEntry.isDeleted {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Could not find diamonded post entry: %s",
				diamondPostHash.String())
		}

		// Get the existing diamondEntry so we can delete it.
		senderPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
		receiverPKID := bav.GetPKIDForPublicKey(diamondedPostEntry.PosterPublicKey)
		diamondKey := MakeDiamondKey(senderPKID.PKID, receiverPKID.PKID, diamondPostHash)
		diamondEntry := bav.GetDiamondEntryForDiamondKey(&diamondKey)

		// Sanity check that the diamondEntry is not nil.
		if diamondEntry == nil {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Found nil diamond entry for diamondKey: %v", &diamondKey)
		}

		// Delete the diamond entry mapping and re-add it if the previous mapping is not nil.
		bav._deleteDiamondEntryMappings(diamondEntry)
		if currentOperation.PrevDiamondEntry != nil {
			bav._setDiamondEntryMappings(currentOperation.PrevDiamondEntry)
		}

		// Finally, revert the post entry mapping since we likely updated the DiamondCount.
		bav._setPostEntryMappings(currentOperation.PrevPostEntry)

		operationIndex--
	}

	// Loop through the transaction's outputs backwards and remove them
	// from the view. Since the outputs will have been added to the view
	// at the end of the utxo list, removing them from the view amounts to
	// removing the last element from the utxo list.
	//
	// Loop backwards over the utxo operations as we go along.
	for outputIndex := len(currentTxn.TxOutputs) - 1; outputIndex >= 0; outputIndex-- {
		currentOutput := currentTxn.TxOutputs[outputIndex]

		// Compute the utxo key for this output so we can reference it in our
		// data structures.
		outputKey := &UtxoKey{
			TxID:  *txnHash,
			Index: uint32(outputIndex),
		}

		// Verify that the utxo operation we're undoing is an add and advance
		// our index to the next operation.
		currentOperation := utxoOpsForTxn[operationIndex]
		operationIndex--
		if currentOperation.Type != OperationTypeAddUtxo {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v does not line up to an "+
					"ADD operation in the passed utxoOps", outputKey)
		}

		// The current output should be at the end of the utxo list so go
		// ahead and fetch it. Do some sanity checks to make sure the view
		// is in sync with the operations we're trying to perform.
		outputEntry := bav.GetUtxoEntryForUtxoKey(outputKey)
		if outputEntry == nil {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v is missing from "+
					"utxo view", outputKey)
		}
		if outputEntry.isSpent {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v was spent before "+
					"being removed from the utxo view. This should never "+
					"happen", outputKey)
		}
		if outputEntry.AmountNanos != currentOutput.AmountNanos {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v has amount (%d) "+
					"that differs from the amount for the output in the "+
					"view (%d)", outputKey, currentOutput.AmountNanos,
				outputEntry.AmountNanos)
		}
		if !reflect.DeepEqual(outputEntry.PublicKey, currentOutput.PublicKey) {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v has public key (%v) "+
					"that differs from the public key for the output in the "+
					"view (%v)", outputKey, currentOutput.PublicKey,
				outputEntry.PublicKey)
		}
		if outputEntry.BlockHeight != blockHeight {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v has block height (%d) "+
					"that differs from the block we're disconnecting (%d)",
				outputKey, outputEntry.BlockHeight, blockHeight)
		}
		if outputEntry.UtxoType == UtxoTypeBlockReward && (currentTxn.TxnMeta.GetTxnType() != TxnTypeBlockReward) {

			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v is a block reward txn according "+
					"to the view, yet is not the first transaction referenced in "+
					"the block", outputKey)
		}

		if err := bav._unAddUtxo(outputKey); err != nil {
			return errors.Wrapf(err, "_disconnectBasicTransfer: Problem unAdding utxo %v: ", outputKey)
		}
	}

	// At this point we should have rolled back all of the transaction's outputs
	// in the view. Now we roll back its inputs, similarly processing them in
	// backwards order.
	for inputIndex := len(currentTxn.TxInputs) - 1; inputIndex >= 0; inputIndex-- {
		currentInput := currentTxn.TxInputs[inputIndex]

		// Convert this input to a utxo key.
		inputKey := UtxoKey(*currentInput)

		// Get the output entry for this input from the utxoOps that were
		// passed in and check its type. For every input that we're restoring
		// we need a SPEND operation that lines up with it.
		currentOperation := utxoOpsForTxn[operationIndex]
		operationIndex--
		if currentOperation.Type != OperationTypeSpendUtxo {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Input with key %v does not line up with a "+
					"SPEND operation in the passed utxoOps", inputKey)
		}

		// Check that the input matches the key of the spend we're rolling
		// back.
		if inputKey != *currentOperation.Key {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Input with key %v does not match the key of the "+
					"corresponding SPEND operation in the passed utxoOps %v",
				inputKey, *currentOperation.Key)
		}

		// Unspend the entry using the information in the UtxoOperation. If the entry
		// was de-serialized from the db it will have its utxoKey unset so we need to
		// set it here in order to make it unspendable.
		currentOperation.Entry.UtxoKey = currentOperation.Key
		if err := bav._unSpendUtxo(currentOperation.Entry); err != nil {
			return errors.Wrapf(err, "_disconnectBasicTransfer: Problem unspending utxo %v: ", currentOperation.Key)
		}
	}

	return nil
}

func (bav *UtxoView) _disconnectBitcoinExchange(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Check that the last operation has the required OperationType
	operationIndex := len(utxoOpsForTxn) - 1
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectBitcoinExchange: Trying to revert "+
			"%v but utxoOperations are missing",
			OperationTypeBitcoinExchange)
	}
	if utxoOpsForTxn[operationIndex].Type != OperationTypeBitcoinExchange {
		return fmt.Errorf("_disconnectBitcoinExchange: Trying to revert "+
			"%v but found type %v",
			OperationTypeBitcoinExchange, utxoOpsForTxn[operationIndex].Type)
	}
	operationData := utxoOpsForTxn[operationIndex]

	// Get the transaction metadata from the transaction now that we know it has
	// OperationTypeBitcoinExchange.
	txMeta := currentTxn.TxnMeta.(*BitcoinExchangeMetadata)

	// Remove the BitcoinTransactionHash from our TxID mappings since we are
	// unspending it. This makes it so that this hash can be processed again in
	// the future in order to re-grant the public key the DeSo they are entitled
	// to (though possibly more or less than the amount of DeSo they had before
	// because they might execute at a different conversion price).
	bitcoinTxHash := (BlockHash)(txMeta.BitcoinTransaction.TxHash())
	bav._deleteBitcoinBurnTxIDMappings(&bitcoinTxHash)

	// Un-add the UTXO taht was created as a result of this transaction. It should
	// be the one at the end of our UTXO list at this point.
	//
	// The UtxoKey is simply the transaction hash with index zero.
	utxoKey := UtxoKey{
		TxID: *currentTxn.Hash(),
		// We give all UTXOs that are created as a result of BitcoinExchange transactions
		// an index of zero. There is generally only one UTXO created in a BitcoinExchange
		// transaction so this field doesn't really matter.
		Index: 0,
	}
	if err := bav._unAddUtxo(&utxoKey); err != nil {
		return errors.Wrapf(err, "_disconnectBitcoinExchange: Problem unAdding utxo %v: ", utxoKey)
	}

	// Reset NanosPurchased to the value it was before granting this DeSo to this user.
	// This previous value comes from the UtxoOperation data.
	prevNanosPurchased := operationData.PrevNanosPurchased
	bav.NanosPurchased = prevNanosPurchased

	// At this point the BitcoinExchange transaction should be fully reverted.
	return nil
}

func (bav *UtxoView) _disconnectUpdateBitcoinUSDExchangeRate(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Check that the last operation has the required OperationType
	operationIndex := len(utxoOpsForTxn) - 1
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectUpdateBitcoinUSDExchangeRate: Trying to revert "+
			"%v but utxoOperations are missing",
			OperationTypeUpdateBitcoinUSDExchangeRate)
	}
	if utxoOpsForTxn[operationIndex].Type != OperationTypeUpdateBitcoinUSDExchangeRate {
		return fmt.Errorf("_disconnectUpdateBitcoinUSDExchangeRate: Trying to revert "+
			"%v but found type %v",
			OperationTypeUpdateBitcoinUSDExchangeRate, utxoOpsForTxn[operationIndex].Type)
	}
	operationData := utxoOpsForTxn[operationIndex]

	// Get the transaction metadata from the transaction now that we know it has
	// OperationTypeUpdateBitcoinUSDExchangeRate.
	txMeta := currentTxn.TxnMeta.(*UpdateBitcoinUSDExchangeRateMetadataa)
	_ = txMeta

	// Reset exchange rate to the value it was before granting this DeSo to this user.
	// This previous value comes from the UtxoOperation data.
	prevUSDCentsPerBitcoin := operationData.PrevUSDCentsPerBitcoin
	bav.USDCentsPerBitcoin = prevUSDCentsPerBitcoin

	// Now revert the basic transfer with the remaining operations. Cut off
	// the UpdateBitcoinUSDExchangeRate operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) _disconnectUpdateGlobalParams(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {
	// Check that the last operation has the required OperationType
	operationIndex := len(utxoOpsForTxn) - 1
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectUpdateGlobalParams: Trying to revert "+
			"%v but utxoOperations are missing",
			OperationTypeUpdateGlobalParams)
	}
	if utxoOpsForTxn[operationIndex].Type != OperationTypeUpdateGlobalParams {
		return fmt.Errorf("_disconnectUpdateGlobalParams: Trying to revert "+
			"%v but found type %v",
			OperationTypeUpdateGlobalParams, utxoOpsForTxn[operationIndex].Type)
	}
	operationData := utxoOpsForTxn[operationIndex]

	// Reset the global params to their previous value.
	// This previous value comes from the UtxoOperation data.
	prevGlobalParamEntry := operationData.PrevGlobalParamsEntry
	if prevGlobalParamEntry == nil {
		prevGlobalParamEntry = &InitialGlobalParamsEntry
	}
	bav.GlobalParamsEntry = prevGlobalParamEntry

	// Reset any modified forbidden pub key entries if they exist.
	if operationData.PrevForbiddenPubKeyEntry != nil {
		pkMapKey := MakePkMapKey(operationData.PrevForbiddenPubKeyEntry.PubKey)
		bav.ForbiddenPubKeyToForbiddenPubKeyEntry[pkMapKey] = operationData.PrevForbiddenPubKeyEntry
	}

	// Now revert the basic transfer with the remaining operations. Cut off
	// the UpdateGlobalParams operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

// TODO: Update for postgres
func (bav *UtxoView) _disconnectPrivateMessage(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a PrivateMessage opration
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectPrivateMessage: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypePrivateMessage {
		return fmt.Errorf("_disconnectPrivateMessage: Trying to revert "+
			"OperationTypePrivateMessage but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}

	// Now we know the txMeta is PrivateMessage
	txMeta := currentTxn.TxnMeta.(*PrivateMessageMetadata)

	// Get the MessageEntry for the sender in the transaction. If we don't find
	// it or if it has isDeleted=true that's an error.
	senderMessageKey := MakeMessageKey(currentTxn.PublicKey, txMeta.TimestampNanos)
	messageEntry := bav._getMessageEntryForMessageKey(&senderMessageKey)
	if messageEntry == nil || messageEntry.isDeleted {
		return fmt.Errorf("_disconnectPrivateMessage: MessageEntry for "+
			"SenderMessageKey %v was found to be nil or deleted: %v",
			&senderMessageKey, messageEntry)
	}

	// Verify that the sender and recipient in the entry match the TxnMeta as
	// a sanity check.
	if !reflect.DeepEqual(messageEntry.SenderPublicKey, currentTxn.PublicKey) {
		return fmt.Errorf("_disconnectPrivateMessage: Sender public key on "+
			"MessageEntry was %s but the PublicKey on the txn was %s",
			PkToString(messageEntry.SenderPublicKey, bav.Params),
			PkToString(currentTxn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(messageEntry.RecipientPublicKey, txMeta.RecipientPublicKey) {
		return fmt.Errorf("_disconnectPrivateMessage: Recipient public key on "+
			"MessageEntry was %s but the PublicKey on the TxnMeta was %s",
			PkToString(messageEntry.RecipientPublicKey, bav.Params),
			PkToString(txMeta.RecipientPublicKey, bav.Params))
	}
	// Sanity-check that the MessageEntry TstampNanos matches the transaction.
	if messageEntry.TstampNanos != txMeta.TimestampNanos {
		return fmt.Errorf("_disconnectPrivateMessage: TimestampNanos in "+
			"MessageEntry was %d but in transaction it was %d",
			messageEntry.TstampNanos,
			txMeta.TimestampNanos)
	}
	// Sanity-check that the EncryptedText on the MessageEntry matches the transaction
	// just for good measure.
	if !reflect.DeepEqual(messageEntry.EncryptedText, txMeta.EncryptedText) {
		return fmt.Errorf("_disconnectPrivateMessage: EncryptedText in MessageEntry "+
			"did not match EncryptedText in transaction: (%s) != (%s)",
			hex.EncodeToString(messageEntry.EncryptedText),
			hex.EncodeToString(txMeta.EncryptedText))
	}

	// Now that we are confident the MessageEntry lines up with the transaction we're
	// rolling back, use the entry to delete the mappings for this message.
	bav._deleteMessageEntryMappings(messageEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the PrivateMessage operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) _disconnectLike(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a Like operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectLike: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeLike {
		return fmt.Errorf("_disconnectLike: Trying to revert "+
			"OperationTypeLike but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}

	// Now we know the txMeta is a Like
	txMeta := currentTxn.TxnMeta.(*LikeMetadata)

	// Before we do anything, let's get the post so we can adjust the like counter later.
	likedPostEntry := bav.GetPostEntryForPostHash(txMeta.LikedPostHash)
	if likedPostEntry == nil {
		return fmt.Errorf("_disconnectLike: Error getting post: %v", txMeta.LikedPostHash)
	}

	// Here we diverge and consider the like and unlike cases separately.
	if txMeta.IsUnlike {
		// If this is an "unlike," we just need to add back the previous like entry and like
		// like count. We do some sanity checks first though to be extra safe.

		prevLikeEntry := utxoOpsForTxn[operationIndex].PrevLikeEntry
		// Sanity check: verify that the user on the likeEntry matches the transaction sender.
		if !reflect.DeepEqual(prevLikeEntry.LikerPubKey, currentTxn.PublicKey) {
			return fmt.Errorf("_disconnectLike: User public key on "+
				"LikeEntry was %s but the PublicKey on the txn was %s",
				PkToStringBoth(prevLikeEntry.LikerPubKey),
				PkToStringBoth(currentTxn.PublicKey))
		}

		// Sanity check: verify that the post hash on the prevLikeEntry matches the transaction's.
		if !reflect.DeepEqual(prevLikeEntry.LikedPostHash, txMeta.LikedPostHash) {
			return fmt.Errorf("_disconnectLike: Liked post hash on "+
				"LikeEntry was %s but the LikedPostHash on the txn was %s",
				prevLikeEntry.LikedPostHash, txMeta.LikedPostHash)
		}

		// Set the like entry and like count to their previous state.
		bav._setLikeEntryMappings(prevLikeEntry)
		likedPostEntry.LikeCount = utxoOpsForTxn[operationIndex].PrevLikeCount
		bav._setPostEntryMappings(likedPostEntry)
	} else {
		// If this is a normal "like," we do some sanity checks and then delete the entry.

		// Get the LikeEntry. If we don't find it or isDeleted=true, that's an error.
		likeKey := MakeLikeKey(currentTxn.PublicKey, *txMeta.LikedPostHash)
		likeEntry := bav._getLikeEntryForLikeKey(&likeKey)
		if likeEntry == nil || likeEntry.isDeleted {
			return fmt.Errorf("_disconnectLike: LikeEntry for "+
				"likeKey %v was found to be nil or isDeleted not set appropriately: %v",
				&likeKey, likeEntry)
		}

		// Sanity check: verify that the user on the likeEntry matches the transaction sender.
		if !reflect.DeepEqual(likeEntry.LikerPubKey, currentTxn.PublicKey) {
			return fmt.Errorf("_disconnectLike: User public key on "+
				"LikeEntry was %s but the PublicKey on the txn was %s",
				PkToStringBoth(likeEntry.LikerPubKey),
				PkToStringBoth(currentTxn.PublicKey))
		}

		// Sanity check: verify that the post hash on the likeEntry matches the transaction's.
		if !reflect.DeepEqual(likeEntry.LikedPostHash, txMeta.LikedPostHash) {
			return fmt.Errorf("_disconnectLike: Liked post hash on "+
				"LikeEntry was %s but the LikedPostHash on the txn was %s",
				likeEntry.LikedPostHash, txMeta.LikedPostHash)
		}

		// Now that we're confident the FollowEntry lines up with the transaction we're
		// rolling back, delete the mappings and set the like counter to its previous value.
		bav._deleteLikeEntryMappings(likeEntry)
		likedPostEntry.LikeCount = utxoOpsForTxn[operationIndex].PrevLikeCount
		bav._setPostEntryMappings(likedPostEntry)
	}

	// Now revert the basic transfer with the remaining operations. Cut off
	// the Like operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) _disconnectFollow(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a Follow operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectFollow: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeFollow {
		return fmt.Errorf("_disconnectFollow: Trying to revert "+
			"OperationTypeFollow but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}

	// Now we know the txMeta is a Follow
	txMeta := currentTxn.TxnMeta.(*FollowMetadata)

	// Look up the PKIDs for the follower and the followed.
	// Get the PKIDs for the public keys associated with the follower and the followed.
	followerPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if followerPKID == nil || followerPKID.isDeleted {
		return fmt.Errorf("_disconnectFollow: followerPKID was nil or deleted; this should never happen")
	}
	followedPKID := bav.GetPKIDForPublicKey(txMeta.FollowedPublicKey)
	if followedPKID == nil || followerPKID.isDeleted {
		return fmt.Errorf("_disconnectFollow: followedPKID was nil or deleted; this should never happen")
	}

	// If the transaction is an unfollow, it removed the follow entry from the DB
	// so we have to add it back.  Then we can finish by reverting the basic transfer.
	if txMeta.IsUnfollow {
		followEntry := FollowEntry{
			FollowerPKID: followerPKID.PKID,
			FollowedPKID: followedPKID.PKID,
		}
		bav._setFollowEntryMappings(&followEntry)
		return bav._disconnectBasicTransfer(
			currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
	}

	// Get the FollowEntry. If we don't find it or idDeleted=true, that's an error.
	followKey := MakeFollowKey(followerPKID.PKID, followedPKID.PKID)
	followEntry := bav._getFollowEntryForFollowKey(&followKey)
	if followEntry == nil || followEntry.isDeleted {
		return fmt.Errorf("_disconnectFollow: FollowEntry for "+
			"followKey %v was found to be nil or isDeleted not set appropriately: %v",
			&followKey, followEntry)
	}

	// Verify that the sender and recipient in the entry match the TxnMeta as
	// a sanity check.
	if !reflect.DeepEqual(followEntry.FollowerPKID, followerPKID.PKID) {
		return fmt.Errorf("_disconnectFollow: Follower PKID on "+
			"FollowEntry was %s but the PKID looked up from the txn was %s",
			PkToString(followEntry.FollowerPKID[:], bav.Params),
			PkToString(followerPKID.PKID[:], bav.Params))
	}
	if !reflect.DeepEqual(followEntry.FollowedPKID, followedPKID.PKID) {
		return fmt.Errorf("_disconnectFollow: Followed PKID on "+
			"FollowEntry was %s but the FollowedPKID looked up from the txn was %s",
			PkToString(followEntry.FollowedPKID[:], bav.Params),
			PkToString(followedPKID.PKID[:], bav.Params))
	}

	// Now that we are confident the FollowEntry lines up with the transaction we're
	// rolling back, delete the mappings.
	bav._deleteFollowEntryMappings(followEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the FollowMessage operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) _disconnectSubmitPost(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a SubmitPost operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectSubmitPost: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	currentOperation := utxoOpsForTxn[operationIndex]
	if currentOperation.Type != OperationTypeSubmitPost {
		return fmt.Errorf("_disconnectSubmitPost: Trying to revert "+
			"OperationTypeSubmitPost but found type %v",
			currentOperation.Type)
	}

	// Now we know the txMeta is SubmitPost
	txMeta := currentTxn.TxnMeta.(*SubmitPostMetadata)

	// The post hash is either the transaction hash or the hash set
	// in the metadata.
	postHashModified := txnHash
	if len(txMeta.PostHashToModify) != 0 {
		postHashModified = &BlockHash{}
		copy(postHashModified[:], txMeta.PostHashToModify[:])
	}

	// Get the PostEntry. If we don't find
	// it or if it has isDeleted=true that's an error.
	postEntry := bav.GetPostEntryForPostHash(postHashModified)
	if postEntry == nil || postEntry.isDeleted {
		return fmt.Errorf("_disconnectSubmitPost: PostEntry for "+
			"Post Hash %v was found to be nil or deleted: %v",
			&txnHash, postEntry)
	}

	// Delete repost mappings if they exist. They will be added back later if there is a previous version of this
	// postEntry
	if IsVanillaRepost(postEntry) {
		repostKey := MakeRepostKey(postEntry.PosterPublicKey, *postEntry.RepostedPostHash)
		repostEntry := bav._getRepostEntryForRepostKey(&repostKey)
		if repostEntry == nil {
			return fmt.Errorf("_disconnectSubmitPost: RepostEntry for "+
				"Post Has %v could not be found: %v", &txnHash, postEntry)
		}
		bav._deleteRepostEntryMappings(repostEntry)
	}

	// Now that we are confident the PostEntry lines up with the transaction we're
	// rolling back, use the entry to delete the mappings for this post.
	//
	// Note: We don't need to delete the existing PostEntry mappings for parent and grandparent
	// before setting the prev mappings because the only thing that could have changed is the
	// comment count, which isn't indexed.
	bav._deletePostEntryMappings(postEntry)

	// If we have a non-nil previous post entry then set the mappings for
	// that.
	if currentOperation.PrevPostEntry != nil {
		bav._setPostEntryMappings(currentOperation.PrevPostEntry)
	}
	if currentOperation.PrevParentPostEntry != nil {
		bav._setPostEntryMappings(currentOperation.PrevParentPostEntry)
	}
	if currentOperation.PrevGrandparentPostEntry != nil {
		bav._setPostEntryMappings(currentOperation.PrevGrandparentPostEntry)
	}
	if currentOperation.PrevRepostedPostEntry != nil {
		bav._setPostEntryMappings(currentOperation.PrevRepostedPostEntry)
	}
	if currentOperation.PrevRepostEntry != nil {
		bav._setRepostEntryMappings(currentOperation.PrevRepostEntry)
	}

	// Now revert the basic transfer with the remaining operations. Cut off
	// the SubmitPost operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) _disconnectUpdateProfile(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is an UpdateProfile opration
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectUpdateProfile: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	currentOperation := utxoOpsForTxn[operationIndex]
	if currentOperation.Type != OperationTypeUpdateProfile {
		return fmt.Errorf("_disconnectUpdateProfile: Trying to revert "+
			"OperationTypeUpdateProfile but found type %v",
			currentOperation.Type)
	}

	// Now we know the txMeta is UpdateProfile
	txMeta := currentTxn.TxnMeta.(*UpdateProfileMetadata)

	// Extract the public key of the profile from the meta if necessary and run some
	// sanity checks.
	profilePublicKey := currentTxn.PublicKey
	if len(txMeta.ProfilePublicKey) != 0 {
		if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
			return fmt.Errorf("_disconnectUpdateProfile: %#v", txMeta.ProfilePublicKey)
		}
		_, err := btcec.ParsePubKey(txMeta.ProfilePublicKey, btcec.S256())
		if err != nil {
			return fmt.Errorf("_disconnectUpdateProfile: %v", err)
		}
		profilePublicKey = txMeta.ProfilePublicKey
	}

	// Get the ProfileEntry. If we don't find
	// it or if it has isDeleted=true that's an error.
	profileEntry := bav.GetProfileEntryForPublicKey(profilePublicKey)
	if profileEntry == nil || profileEntry.isDeleted {
		return fmt.Errorf("_disconnectUpdateProfile: ProfileEntry for "+
			"public key %v was found to be nil or deleted: %v",
			PkToString(profilePublicKey, bav.Params),
			profileEntry)
	}

	// Now that we are confident the ProfileEntry lines up with the transaction we're
	// rolling back, set the mappings to be equal to whatever we had previously.
	// We need to do this to prevent a fetch from a db later on.
	bav._deleteProfileEntryMappings(profileEntry)

	// If we had a previous ProfileEntry set then update the mappings to match
	// that. Otherwise leave it as deleted.
	if currentOperation.PrevProfileEntry != nil {
		bav._setProfileEntryMappings(currentOperation.PrevProfileEntry)
	}

	// Now revert the basic transfer with the remaining operations. Cut off
	// the UpdateProfile operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) _disconnectSwapIdentity(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is an SwapIdentity operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectSwapIdentity: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	currentOperation := utxoOpsForTxn[operationIndex]
	if currentOperation.Type != OperationTypeSwapIdentity {
		return fmt.Errorf("_disconnectSwapIdentity: Trying to revert "+
			"OperationTypeSwapIdentity but found type %v",
			currentOperation.Type)
	}

	// Now we know the txMeta is SwapIdentity
	txMeta := currentTxn.TxnMeta.(*SwapIdentityMetadataa)

	// Swap the public keys within the profiles back. Note that this *must* be done
	// before the swapping of the PKID mappings occurs. Not doing this would cause
	// the profiles to be fetched inconsistently from the DB.
	fromProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.FromPublicKey)
	if fromProfileEntry != nil && !fromProfileEntry.isDeleted {
		fromProfileEntry.PublicKey = txMeta.ToPublicKey
	}
	toProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ToPublicKey)
	if toProfileEntry != nil && !toProfileEntry.isDeleted {
		toProfileEntry.PublicKey = txMeta.FromPublicKey
	}

	// Get the PKIDEntries for the *from* and *to* public keys embedded in the txn
	oldFromPKIDEntry := bav.GetPKIDForPublicKey(txMeta.FromPublicKey)
	oldToPKIDEntry := bav.GetPKIDForPublicKey(txMeta.ToPublicKey)

	// Mark all the entries as dirty so they get flushed. This marks the new entries as dirty too.
	oldFromPKIDEntry.isDirty = true
	oldToPKIDEntry.isDirty = true

	// Create copies of the old entries with swapped PKIDs.
	newFromPKIDEntry := *oldFromPKIDEntry
	newFromPKIDEntry.PKID = oldToPKIDEntry.PKID

	newToPKIDEntry := *oldToPKIDEntry
	newToPKIDEntry.PKID = oldFromPKIDEntry.PKID

	// Delete the old mappings. This isn't strictly necessary since the sets
	// below will overwrite everything, but it keeps us be consistent with other code.
	bav._deletePKIDMappings(oldFromPKIDEntry)
	bav._deletePKIDMappings(oldToPKIDEntry)

	// Set the new mappings for the *from* and *to* PKID's.
	bav._setPKIDMappings(&newFromPKIDEntry)
	bav._setPKIDMappings(&newToPKIDEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the SwapIdentity operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) _disconnectCreatorCoin(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a CreatorCoin opration
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectCreatorCoin: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeCreatorCoin {
		return fmt.Errorf("_disconnectCreatorCoin: Trying to revert "+
			"OperationTypeCreatorCoin but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*CreatorCoinMetadataa)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// We sometimes have some extra AddUtxo operations we need to remove
	// These are "implicit" outputs that always occur at the end of the
	// list of UtxoOperations. The number of implicit outputs is equal to
	// the total number of "Add" operations minus the explicit outputs.
	numUtxoAdds := 0
	for _, utxoOp := range utxoOpsForTxn {
		if utxoOp.Type == OperationTypeAddUtxo {
			numUtxoAdds += 1
		}
	}
	operationIndex -= numUtxoAdds - len(currentTxn.TxOutputs)

	// Get the profile corresponding to the creator coin txn.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	// Sanity-check that it exists.
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return fmt.Errorf("_disconnectCreatorCoin: CreatorCoin profile for "+
			"public key %v doesn't exist; this should never happen",
			PkToStringBoth(txMeta.ProfilePublicKey))
	}
	// Get the BalanceEntry of the transactor. This should always exist.
	transactorBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		currentTxn.PublicKey, txMeta.ProfilePublicKey)
	// Sanity-check that the transactor BalanceEntry exists
	if transactorBalanceEntry == nil || transactorBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectCreatorCoin: Transactor BalanceEntry "+
			"pubkey %v and creator pubkey %v does not exist; this should "+
			"never happen",
			PkToStringBoth(currentTxn.PublicKey), PkToStringBoth(txMeta.ProfilePublicKey))
	}

	// Get the BalanceEntry of the creator. It could be nil if this is a sell
	// transaction or if the balance entry was deleted by a creator coin transfer.
	creatorBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txMeta.ProfilePublicKey, txMeta.ProfilePublicKey)
	if creatorBalanceEntry == nil || creatorBalanceEntry.isDeleted {
		creatorPKID := bav.GetPKIDForPublicKey(txMeta.ProfilePublicKey)
		creatorBalanceEntry = &BalanceEntry{
			HODLerPKID:   creatorPKID.PKID,
			CreatorPKID:  creatorPKID.PKID,
			BalanceNanos: uint64(0),
		}
	}

	if txMeta.OperationType == CreatorCoinOperationTypeBuy {
		// Set up some variables so that we can run some sanity-checks
		deltaBuyerNanos := transactorBalanceEntry.BalanceNanos - operationData.PrevTransactorBalanceEntry.BalanceNanos
		deltaCreatorNanos := creatorBalanceEntry.BalanceNanos - operationData.PrevCreatorBalanceEntry.BalanceNanos
		deltaCoinsInCirculation := existingProfileEntry.CoinsInCirculationNanos - operationData.PrevCoinEntry.CoinsInCirculationNanos

		// If the creator is distinct from the buyer, then reset their balance.
		// This check avoids double-updating in situations where a creator bought
		// their own coin.
		if !reflect.DeepEqual(currentTxn.PublicKey, txMeta.ProfilePublicKey) {

			// Sanity-check that the amount that we increased the CoinsInCirculation by
			// equals the total amount received by the buyer and the creator.
			if deltaBuyerNanos+deltaCreatorNanos != deltaCoinsInCirculation {
				return fmt.Errorf("_disconnectCreatorCoin: The creator coin nanos "+
					"the buyer and the creator received (%v, %v) does not equal the "+
					"creator coins added to the circulating supply %v",
					deltaBuyerNanos, deltaCreatorNanos, deltaCoinsInCirculation)
			}

			// Sanity-check that the watermark delta equates to what the creator received.
			deltaNanos := uint64(0)
			if blockHeight > DeSoFounderRewardBlockHeight {
				// Do nothing.  After the DeSoFounderRewardBlockHeight, creator coins are not
				// minted as a founder's reward, just DeSo (see utxo reverted later).
			} else if blockHeight > SalomonFixBlockHeight {
				// Following the SalomonFixBlockHeight block, we calculate a founders reward
				// on every buy, not just the ones that push a creator to a new all time high.
				deltaNanos = existingProfileEntry.CoinsInCirculationNanos - operationData.PrevCoinEntry.CoinsInCirculationNanos
			} else {
				// Prior to the SalomonFixBlockHeight block, we calculate the founders reward
				// only for new all time highs.
				deltaNanos = existingProfileEntry.CoinWatermarkNanos - operationData.PrevCoinEntry.CoinWatermarkNanos
			}
			founderRewardNanos := IntDiv(
				IntMul(
					big.NewInt(int64(deltaNanos)),
					big.NewInt(int64(existingProfileEntry.CreatorBasisPoints))),
				big.NewInt(100*100)).Uint64()
			if founderRewardNanos != deltaCreatorNanos {
				return fmt.Errorf("_disconnectCreatorCoin: The creator coin nanos "+
					"the creator received %v does not equal the founder reward %v; "+
					"this should never happen",
					deltaCreatorNanos, founderRewardNanos)
			}

			// Reset the creator's BalanceEntry to what it was previously.
			*creatorBalanceEntry = *operationData.PrevCreatorBalanceEntry
			bav._setBalanceEntryMappings(creatorBalanceEntry)
		} else {
			// We do a simliar sanity-check as above, but in this case we don't need to
			// reset the creator mappings.
			deltaBuyerNanos := transactorBalanceEntry.BalanceNanos - operationData.PrevTransactorBalanceEntry.BalanceNanos
			deltaCoinsInCirculation := existingProfileEntry.CoinsInCirculationNanos - operationData.PrevCoinEntry.CoinsInCirculationNanos
			if deltaBuyerNanos != deltaCoinsInCirculation {
				return fmt.Errorf("_disconnectCreatorCoin: The creator coin nanos "+
					"the buyer/creator received (%v) does not equal the "+
					"creator coins added to the circulating supply %v",
					deltaBuyerNanos, deltaCoinsInCirculation)
			}
		}

		// Reset the Buyer's BalanceEntry to what it was previously.
		*transactorBalanceEntry = *operationData.PrevTransactorBalanceEntry
		bav._setBalanceEntryMappings(transactorBalanceEntry)

		// If a DeSo founder reward was created, revert it.
		if operationData.FounderRewardUtxoKey != nil {
			if err := bav._unAddUtxo(operationData.FounderRewardUtxoKey); err != nil {
				return errors.Wrapf(err, "_disconnectBitcoinExchange: Problem unAdding utxo %v: ", operationData.FounderRewardUtxoKey)
			}
		}

		// The buyer will get the DeSo they locked up back when we revert the
		// basic transfer. This is OK because resetting the CoinEntry to the previous
		// value lowers the amount of DeSo locked in the profile by the same
		// amount the buyer will receive. Thus no DeSo is created in this
		// transaction.
	} else if txMeta.OperationType == CreatorCoinOperationTypeSell {
		// Set up some variables so that we can run some sanity-checks. The coins
		// the transactor has and the coins in circulation should both have gone
		// down as a result of the transaction, so both of these values should be
		// positive.
		deltaCoinNanos := operationData.PrevTransactorBalanceEntry.BalanceNanos - transactorBalanceEntry.BalanceNanos
		deltaCoinsInCirculation := operationData.PrevCoinEntry.CoinsInCirculationNanos - existingProfileEntry.CoinsInCirculationNanos

		// Sanity-check that the amount we decreased CoinsInCirculation by
		// equals the total amount put in by the seller.
		if deltaCoinNanos != deltaCoinsInCirculation {
			return fmt.Errorf("_disconnectCreatorCoin: The creator coin nanos "+
				"the seller put in (%v) does not equal the "+
				"creator coins removed from the circulating supply %v",
				deltaCoinNanos, deltaCoinsInCirculation)
		}

		// In the case of a sell we only need to revert the transactor's balance,
		// and we don't have to worry about the creator's balance.
		// Reset the transactor's BalanceEntry to what it was previously.
		*transactorBalanceEntry = *operationData.PrevTransactorBalanceEntry
		bav._setBalanceEntryMappings(transactorBalanceEntry)

		// Un-add the UTXO taht was created as a result of this transaction. It should
		// be the one at the end of our UTXO list at this point.
		//
		// The UtxoKey is simply the transaction hash with index set to the end of the
		// transaction list.
		utxoKey := UtxoKey{
			TxID: *currentTxn.Hash(),
			// We give all UTXOs that are created as a result of BitcoinExchange transactions
			// an index of zero. There is generally only one UTXO created in a BitcoinExchange
			// transaction so this field doesn't really matter.
			Index: uint32(len(currentTxn.TxOutputs)),
		}
		if err := bav._unAddUtxo(&utxoKey); err != nil {
			return errors.Wrapf(err, "_disconnectBitcoinExchange: Problem unAdding utxo %v: ", utxoKey)
		}
	} else if txMeta.OperationType == CreatorCoinOperationTypeAddDeSo {
		return fmt.Errorf("_disconnectCreatorCoin: Add DeSo operation txn not implemented")
	}

	// Reset the CoinEntry on the profile to what it was previously now that we
	// have reverted the individual users' balances.
	existingProfileEntry.CoinEntry = *operationData.PrevCoinEntry
	bav._setProfileEntryMappings(existingProfileEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the CreatorCoin operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectCreatorCoinTransfer(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a CreatorCoinTransfer operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeCreatorCoinTransfer {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: Trying to revert "+
			"OperationTypeCreatorCoinTransfer but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*CreatorCoinTransferMetadataa)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// Get the profile corresponding to the creator coin txn.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	// Sanity-check that it exists.
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: CreatorCoinTransfer profile for "+
			"public key %v doesn't exist; this should never happen",
			PkToStringBoth(txMeta.ProfilePublicKey))
	}

	// Get the current / previous balance for the sender for sanity checking.
	senderBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		currentTxn.PublicKey, txMeta.ProfilePublicKey)
	// Sanity-check that the sender had a previous BalanceEntry, it should always exist.
	if operationData.PrevSenderBalanceEntry == nil || operationData.PrevSenderBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: Previous sender BalanceEntry "+
			"pubkey %v and creator pubkey %v does not exist; this should "+
			"never happen",
			PkToStringBoth(currentTxn.PublicKey), PkToStringBoth(txMeta.ProfilePublicKey))
	}
	senderPrevBalanceNanos := operationData.PrevSenderBalanceEntry.BalanceNanos
	var senderCurrBalanceNanos uint64
	// Since the sender may have given away their whole balance, their BalanceEntry can be nil.
	if senderBalanceEntry != nil && !senderBalanceEntry.isDeleted {
		senderCurrBalanceNanos = senderBalanceEntry.BalanceNanos
	}

	// Get the current / previous balance for the receiver for sanity checking.
	receiverBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txMeta.ReceiverPublicKey, txMeta.ProfilePublicKey)
	// Sanity-check that the receiver BalanceEntry exists, it should always exist here.
	if receiverBalanceEntry == nil || receiverBalanceEntry.isDeleted {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: Receiver BalanceEntry "+
			"pubkey %v and creator pubkey %v does not exist; this should "+
			"never happen",
			PkToStringBoth(currentTxn.PublicKey), PkToStringBoth(txMeta.ProfilePublicKey))
	}
	receiverCurrBalanceNanos := receiverBalanceEntry.BalanceNanos
	var receiverPrevBalanceNanos uint64
	if operationData.PrevReceiverBalanceEntry != nil {
		receiverPrevBalanceNanos = operationData.PrevReceiverBalanceEntry.BalanceNanos
	}

	// Sanity check that the sender's current balance is less than their previous balance.
	if senderCurrBalanceNanos > senderPrevBalanceNanos {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: Sender's current balance %d is "+
			"greater than their previous balance %d.",
			senderCurrBalanceNanos, senderPrevBalanceNanos)
	}

	// Sanity check that the receiver's previous balance is less than their current balance.
	if receiverPrevBalanceNanos > receiverCurrBalanceNanos {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: Receiver's previous balance %d is "+
			"greater than their current balance %d.",
			receiverPrevBalanceNanos, receiverCurrBalanceNanos)
	}

	// Sanity check the sender's increase equals the receiver's decrease after disconnect.
	senderBalanceIncrease := senderPrevBalanceNanos - senderCurrBalanceNanos
	receiverBalanceDecrease := receiverCurrBalanceNanos - receiverPrevBalanceNanos
	if senderBalanceIncrease != receiverBalanceDecrease {
		return fmt.Errorf("_disconnectCreatorCoinTransfer: Sender's balance increase "+
			"of %d will not equal the receiver's balance decrease of  %v after disconnect.",
			senderBalanceIncrease, receiverBalanceDecrease)
	}

	// At this point we have sanity checked the current and previous state. Now we just
	// need to revert the mappings.

	// Delete the sender/receiver balance entries (they will be added back later if needed).
	bav._deleteBalanceEntryMappings(
		receiverBalanceEntry, txMeta.ReceiverPublicKey, txMeta.ProfilePublicKey)
	if senderBalanceEntry != nil {
		bav._deleteBalanceEntryMappings(
			senderBalanceEntry, currentTxn.PublicKey, txMeta.ProfilePublicKey)
	}

	// Set the balance entries appropriately.
	bav._setBalanceEntryMappings(operationData.PrevSenderBalanceEntry)
	if operationData.PrevReceiverBalanceEntry != nil && operationData.PrevReceiverBalanceEntry.BalanceNanos != 0 {
		bav._setBalanceEntryMappings(operationData.PrevReceiverBalanceEntry)
	}

	// Reset the CoinEntry on the profile to what it was previously now that we
	// have reverted the individual users' balances.
	existingProfileEntry.CoinEntry = *operationData.PrevCoinEntry
	bav._setProfileEntryMappings(existingProfileEntry)

	// If the transaction had diamonds, let's revert those too.
	diamondPostHashBytes, hasDiamondPostHash := currentTxn.ExtraData[DiamondPostHashKey]
	if hasDiamondPostHash {
		// Sanity check the post hash bytes before creating the post hash.
		diamondPostHash := &BlockHash{}
		if len(diamondPostHashBytes) != HashSizeBytes {
			return fmt.Errorf(
				"_disconnectCreatorCoin: DiamondPostHashBytes has incorrect length: %d",
				len(diamondPostHashBytes))
		}
		copy(diamondPostHash[:], diamondPostHashBytes[:])

		// Get the existing diamondEntry so we can delete it.
		senderPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
		receiverPKID := bav.GetPKIDForPublicKey(txMeta.ReceiverPublicKey)
		diamondKey := MakeDiamondKey(senderPKID.PKID, receiverPKID.PKID, diamondPostHash)
		diamondEntry := bav.GetDiamondEntryForDiamondKey(&diamondKey)

		// Sanity check that the diamondEntry is not nil.
		if diamondEntry == nil {
			return fmt.Errorf(
				"_disconnectCreatorCoin: Found nil diamond entry for diamondKey: %v", &diamondKey)
		}

		// Delete the diamond entry mapping and re-add it if the previous mapping is not nil.
		bav._deleteDiamondEntryMappings(diamondEntry)
		if operationData.PrevDiamondEntry != nil {
			bav._setDiamondEntryMappings(operationData.PrevDiamondEntry)
		}

		// Finally, revert the post entry mapping since we likely updated the DiamondCount.
		bav._setPostEntryMappings(operationData.PrevPostEntry)
	}

	// Now revert the basic transfer with the remaining operations. Cut off
	// the CreatorCoin operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectCreateNFT(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a CreateNFT operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectCreateNFT: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeCreateNFT {
		return fmt.Errorf("_disconnectCreateNFT: Trying to revert "+
			"OperationTypeCreateNFT but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*CreateNFTMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// Get the postEntry corresponding to this txn.
	existingPostEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	// Sanity-check that it exists.
	if existingPostEntry == nil || existingPostEntry.isDeleted {
		return fmt.Errorf("_disconnectCreateNFT: Post entry for "+
			"post hash %v doesn't exist; this should never happen",
			txMeta.NFTPostHash.String())
	}

	// Revert to the old post entry since we changed IsNFT, etc.
	bav._setPostEntryMappings(operationData.PrevPostEntry)

	// Delete the NFT entries.
	posterPKID := bav.GetPKIDForPublicKey(existingPostEntry.PosterPublicKey)
	if posterPKID == nil || posterPKID.isDeleted {
		return fmt.Errorf("_disconnectCreateNFT: PKID for poster public key %v doesn't exist; this should never happen", string(existingPostEntry.PosterPublicKey))
	}
	for ii := uint64(1); ii <= txMeta.NumCopies; ii++ {
		nftEntry := &NFTEntry{
			OwnerPKID:    posterPKID.PKID,
			NFTPostHash:  txMeta.NFTPostHash,
			SerialNumber: ii,
			IsForSale:    true,
		}
		bav._deleteNFTEntryMappings(nftEntry)
	}

	// Now revert the basic transfer with the remaining operations. Cut off
	// the CreatorCoin operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectUpdateNFT(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is an UpdateNFT operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectUpdateNFT: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeUpdateNFT {
		return fmt.Errorf("_disconnectUpdateNFT: Trying to revert "+
			"OperationTypeUpdateNFT but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*UpdateNFTMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// In order to disconnect an updated NFT, we need to do the following:
	// 	(1) Revert the NFT entry to the previous one.
	//  (2) Add back all of the bids that were deleted (if any).
	//  (3) Revert the post entry since we updated num NFT copies for sale.

	// Make sure that there is a prev NFT entry.
	if operationData.PrevNFTEntry == nil || operationData.PrevNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectUpdateNFT: prev NFT entry doesn't exist; " +
			"this should never happen")
	}

	// If the previous NFT entry was not for sale, it should not have had any bids to delete.
	if !operationData.PrevNFTEntry.IsForSale &&
		operationData.DeletedNFTBidEntries != nil &&
		len(operationData.DeletedNFTBidEntries) > 0 {

		return fmt.Errorf("_disconnectUpdateNFT: prev NFT entry was not for sale but found " +
			"deleted bids anyway; this should never happen")
	}

	// Set the old NFT entry.
	bav._setNFTEntryMappings(operationData.PrevNFTEntry)

	// Set the old bids.
	if operationData.DeletedNFTBidEntries != nil {
		for _, nftBid := range operationData.DeletedNFTBidEntries {
			bav._setNFTBidEntryMappings(nftBid)
		}
	}

	// Get the postEntry corresponding to this txn.
	existingPostEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	// Sanity-check that it exists.
	if existingPostEntry == nil || existingPostEntry.isDeleted {
		return fmt.Errorf("_disconnectUpdateNFT: Post entry for "+
			"post hash %v doesn't exist; this should never happen",
			txMeta.NFTPostHash.String())
	}

	// Revert to the old post entry since we changed NumNFTCopiesForSale.
	bav._setPostEntryMappings(operationData.PrevPostEntry)

	// Now revert the basic transfer with the remaining operations.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectAcceptNFTBid(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a CreatorCoinTransfer operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectAcceptNFTBid: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeAcceptNFTBid {
		return fmt.Errorf("_disconnectAcceptNFTBid: Trying to revert "+
			"OperationTypeAcceptNFTBid but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*AcceptNFTBidMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// We sometimes have some extra AddUtxo operations we need to remove
	// These are "implicit" outputs that always occur at the end of the
	// list of UtxoOperations. The number of implicit outputs is equal to
	// the total number of "Add" operations minus the explicit outputs.
	numUtxoAdds := 0
	for _, utxoOp := range utxoOpsForTxn {
		if utxoOp.Type == OperationTypeAddUtxo {
			numUtxoAdds += 1
		}
	}
	operationIndex -= numUtxoAdds - len(currentTxn.TxOutputs)

	// In order to disconnect an accepted bid, we need to do the following:
	// 	(1) Revert the NFT entry to the previous one with the previous owner.
	//  (2) Add back all of the bids that were deleted.
	//  (3) Disconnect payment UTXOs.
	//  (4) Unspend bidder UTXOs.
	//  (5) Revert profileEntry to undo royalties added to DeSoLockedNanos.
	//  (6) Revert the postEntry since NumNFTCopiesForSale was decremented.

	// (1) Set the old NFT entry.
	if operationData.PrevNFTEntry == nil || operationData.PrevNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectAcceptNFTBid: prev NFT entry doesn't exist; " +
			"this should never happen")
	}

	prevNFTEntry := operationData.PrevNFTEntry
	bav._setNFTEntryMappings(prevNFTEntry)

	// Revert the accepted NFT bid history mappings
	bav._setAcceptNFTBidHistoryMappings(MakeNFTKey(prevNFTEntry.NFTPostHash, prevNFTEntry.SerialNumber), operationData.PrevAcceptedNFTBidEntries)

	// (2) Set the old bids.
	if operationData.DeletedNFTBidEntries == nil || len(operationData.DeletedNFTBidEntries) == 0 {
		return fmt.Errorf("_disconnectAcceptNFTBid: DeletedNFTBidEntries doesn't exist; " +
			"this should never happen")
	}

	for _, nftBid := range operationData.DeletedNFTBidEntries {
		bav._setNFTBidEntryMappings(nftBid)
	}

	// (3) Revert payments made from accepting the NFT bids.
	if operationData.NFTPaymentUtxoKeys == nil || len(operationData.NFTPaymentUtxoKeys) == 0 {
		return fmt.Errorf("_disconnectAcceptNFTBid: NFTPaymentUtxoKeys was nil; " +
			"this should never happen")
	}
	// Note: these UTXOs need to be unadded in reverse order.
	for ii := len(operationData.NFTPaymentUtxoKeys) - 1; ii >= 0; ii-- {
		paymentUtxoKey := operationData.NFTPaymentUtxoKeys[ii]
		if err := bav._unAddUtxo(paymentUtxoKey); err != nil {
			return errors.Wrapf(err, "_disconnectAcceptNFTBid: Problem unAdding utxo %v: ", paymentUtxoKey)
		}
	}

	// (4) Revert spent bidder UTXOs.
	if operationData.NFTSpentUtxoEntries == nil || len(operationData.NFTSpentUtxoEntries) == 0 {
		return fmt.Errorf("_disconnectAcceptNFTBid: NFTSpentUtxoEntries was nil; " +
			"this should never happen")
	}
	// Note: these UTXOs need to be unspent in reverse order.
	for ii := len(operationData.NFTSpentUtxoEntries) - 1; ii >= 0; ii-- {
		spentUtxoEntry := operationData.NFTSpentUtxoEntries[ii]
		if err := bav._unSpendUtxo(spentUtxoEntry); err != nil {
			return errors.Wrapf(err, "_disconnectAcceptNFTBid: Problem unSpending utxo %v: ", spentUtxoEntry)
		}
	}

	// (5) Revert the creator's CoinEntry if a previous one exists.
	if operationData.PrevCoinEntry != nil {
		nftPostEntry := bav.GetPostEntryForPostHash(operationData.PrevNFTEntry.NFTPostHash)
		// We have to get the post entry first so that we have the poster's pub key.
		if nftPostEntry == nil || nftPostEntry.isDeleted {
			return fmt.Errorf("_disconnectAcceptNFTBid: nftPostEntry was nil; " +
				"this should never happen")
		}
		existingProfileEntry := bav.GetProfileEntryForPublicKey(nftPostEntry.PosterPublicKey)
		if existingProfileEntry == nil || existingProfileEntry.isDeleted {
			return fmt.Errorf("_disconnectAcceptNFTBid: existingProfileEntry was nil; " +
				"this should never happen")
		}
		existingProfileEntry.CoinEntry = *operationData.PrevCoinEntry
		bav._setProfileEntryMappings(existingProfileEntry)
	}

	// (6) Verify a postEntry exists and then revert it since NumNFTCopiesForSale was decremented.

	// Get the postEntry corresponding to this txn.
	existingPostEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	// Sanity-check that it exists.
	if existingPostEntry == nil || existingPostEntry.isDeleted {
		return fmt.Errorf("_disconnectAcceptNFTBid: Post entry for "+
			"post hash %v doesn't exist; this should never happen",
			txMeta.NFTPostHash.String())
	}

	// Revert to the old post entry since we changed NumNFTCopiesForSale.
	bav._setPostEntryMappings(operationData.PrevPostEntry)

	// Now revert the basic transfer with the remaining operations.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectNFTBid(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a CreatorCoinTransfer operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectNFTBid: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeNFTBid {
		return fmt.Errorf("_disconnectNFTBid: Trying to revert "+
			"OperationTypeNFTBid but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*NFTBidMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// Get the NFTBidEntry corresponding to this txn.
	bidderPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if bidderPKID == nil || bidderPKID.isDeleted {
		return fmt.Errorf("_disconnectNFTBid: PKID for bidder public key %v doesn't exist; this should never happen", string(currentTxn.PublicKey))
	}
	nftBidKey := MakeNFTBidKey(bidderPKID.PKID, txMeta.NFTPostHash, txMeta.SerialNumber)
	nftBidEntry := bav.GetNFTBidEntryForNFTBidKey(&nftBidKey)
	// Sanity-check that it exists.
	if nftBidEntry == nil || nftBidEntry.isDeleted {
		return fmt.Errorf("_disconnectNFTBid: Bid entry for "+
			"nftBidKey %v doesn't exist; this should never happen", nftBidKey)
	}

	// Delete the existing NFT bid entry.
	bav._deleteNFTBidEntryMappings(nftBidEntry)

	// If a previous entry exists, set it.
	if operationData.PrevNFTBidEntry != nil {
		bav._setNFTBidEntryMappings(operationData.PrevNFTBidEntry)
	}

	// Now revert the basic transfer with the remaining operations.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectNFTTransfer(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is an NFTTransfer operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectNFTTransfer: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeNFTTransfer {
		return fmt.Errorf("_disconnectNFTTransfer: Trying to revert "+
			"OperationTypeNFTTransfer but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*NFTTransferMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// Make sure that there is a prev NFT entry.
	if operationData.PrevNFTEntry == nil || operationData.PrevNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectNFTTransfer: prev NFT entry doesn't exist; " +
			"this should never happen.")
	}

	// Sanity check the old NFT entry PKID / PostHash / SerialNumber.
	updaterPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return fmt.Errorf("_disconnectNFTTransfer: non-existent updaterPKID: %s",
			PkToString(currentTxn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(operationData.PrevNFTEntry.OwnerPKID, updaterPKID.PKID) {
		return fmt.Errorf(
			"_disconnectNFTTransfer: updaterPKID does not match NFT owner: %s, %s",
			PkToString(updaterPKID.PKID[:], bav.Params),
			PkToString(operationData.PrevNFTEntry.OwnerPKID[:], bav.Params))
	}
	if !reflect.DeepEqual(txMeta.NFTPostHash, operationData.PrevNFTEntry.NFTPostHash) ||
		txMeta.SerialNumber != operationData.PrevNFTEntry.SerialNumber {
		return fmt.Errorf("_disconnectNFTTransfer: txMeta post hash and serial number do "+
			"not match previous NFT entry; this should never happen (%v, %v).",
			txMeta, operationData.PrevNFTEntry)
	}

	// Sanity check that the old NFT entry was not for sale.
	if operationData.PrevNFTEntry.IsForSale {
		return fmt.Errorf("_disconnecttNFTTransfer: prevNFT Entry was either not "+
			"pending or for sale (%v); this should never happen.", operationData.PrevNFTEntry)
	}

	// Get the current NFT entry so we can delete it.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	currNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if currNFTEntry == nil || currNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectNFTTransfer: currNFTEntry not found: %s, %d",
			txMeta.NFTPostHash.String(), txMeta.SerialNumber)
	}

	// Set the old NFT entry.
	bav._deleteNFTEntryMappings(currNFTEntry)
	bav._setNFTEntryMappings(operationData.PrevNFTEntry)

	// Now revert the basic transfer with the remaining operations.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectAcceptNFTTransfer(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is an AcceptNFTTransfer operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectAcceptNFTTransfer: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeAcceptNFTTransfer {
		return fmt.Errorf("_disconnectAcceptNFTTransfer: Trying to revert "+
			"OperationTypeAcceptNFTTransfer but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*AcceptNFTTransferMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// Make sure that there is a prev NFT entry.
	if operationData.PrevNFTEntry == nil || operationData.PrevNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectAcceptNFTTransfer: prev NFT entry doesn't exist; " +
			"this should never happen.")
	}

	// Sanity check the old NFT entry PKID / PostHash / SerialNumber.
	updaterPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return fmt.Errorf("_disconnectAcceptNFTTransfer: non-existent updaterPKID: %s",
			PkToString(currentTxn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(operationData.PrevNFTEntry.OwnerPKID, updaterPKID.PKID) {
		return fmt.Errorf(
			"_disconnectAcceptNFTTransfer: updaterPKID does not match NFT owner: %s, %s",
			PkToString(updaterPKID.PKID[:], bav.Params),
			PkToString(operationData.PrevNFTEntry.OwnerPKID[:], bav.Params))
	}
	if !reflect.DeepEqual(txMeta.NFTPostHash, operationData.PrevNFTEntry.NFTPostHash) ||
		txMeta.SerialNumber != operationData.PrevNFTEntry.SerialNumber {
		return fmt.Errorf("_disconnectAcceptNFTTransfer: txMeta post hash and serial number"+
			" do not match previous NFT entry; this should never happen (%v, %v).",
			txMeta, operationData.PrevNFTEntry)
	}

	// Sanity check that the old NFT entry was pending and not for sale.
	if !operationData.PrevNFTEntry.IsPending || operationData.PrevNFTEntry.IsForSale {
		return fmt.Errorf("_disconnectAcceptNFTTransfer: prevNFT Entry was either not "+
			"pending or for sale (%v); this should never happen.", operationData.PrevNFTEntry)
	}

	// Get the current NFT entry so we can delete it.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	currNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if currNFTEntry == nil || currNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectAcceptNFTTransfer: currNFTEntry not found: %s, %d",
			txMeta.NFTPostHash.String(), txMeta.SerialNumber)
	}

	// Delete the current NFT entry and set the old one.
	bav._deleteNFTEntryMappings(currNFTEntry)
	bav._setNFTEntryMappings(operationData.PrevNFTEntry)

	// Now revert the basic transfer with the remaining operations.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectBurnNFT(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is an BurnNFT operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectBurnNFT: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeBurnNFT {
		return fmt.Errorf("_disconnectBurnNFT: Trying to revert "+
			"OperationTypeBurnNFT but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*BurnNFTMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// Make sure that there is a prev NFT entry.
	if operationData.PrevNFTEntry == nil || operationData.PrevNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectBurnNFT: prev NFT entry doesn't exist; " +
			"this should never happen.")
	}

	// Make sure that there is a prev post entry.
	if operationData.PrevPostEntry == nil || operationData.PrevPostEntry.isDeleted {
		return fmt.Errorf("_disconnectBurnNFT: prev NFT entry doesn't exist; " +
			"this should never happen.")
	}

	// Sanity check the old NFT entry PKID / PostHash / SerialNumber.
	updaterPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return fmt.Errorf("_disconnectBurnNFT: non-existent updaterPKID: %s",
			PkToString(currentTxn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(operationData.PrevNFTEntry.OwnerPKID, updaterPKID.PKID) {
		return fmt.Errorf("_disconnectBurnNFT: updaterPKID does not match NFT owner: %s, %s",
			PkToString(updaterPKID.PKID[:], bav.Params),
			PkToString(operationData.PrevNFTEntry.OwnerPKID[:], bav.Params))
	}
	if !reflect.DeepEqual(txMeta.NFTPostHash, operationData.PrevNFTEntry.NFTPostHash) ||
		txMeta.SerialNumber != operationData.PrevNFTEntry.SerialNumber {
		return fmt.Errorf("_disconnectBurnNFT: txMeta post hash and serial number do "+
			"not match previous NFT entry; this should never happen (%v, %v).",
			txMeta, operationData.PrevNFTEntry)
	}

	// Sanity check that the old NFT entry was not for sale.
	if operationData.PrevNFTEntry.IsForSale {
		return fmt.Errorf("_disconnectBurnNFT: prevNFTEntry was for sale (%v); this should"+
			" never happen.", operationData.PrevNFTEntry)
	}

	// Get the postEntry for sanity checking / deletion later.
	currPostEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	if currPostEntry == nil || currPostEntry.isDeleted {
		return fmt.Errorf(
			"_disconnectBurnNFT: non-existent nftPostEntry for NFTPostHash: %s",
			txMeta.NFTPostHash.String())
	}

	// Sanity check that the previous num NFT copies burned makes sense.
	if operationData.PrevPostEntry.NumNFTCopiesBurned != currPostEntry.NumNFTCopiesBurned-1 {
		return fmt.Errorf(
			"_disconnectBurnNFT: prevPostEntry has the wrong num NFT copies burned %d != %d-1",
			operationData.PrevPostEntry.NumNFTCopiesBurned, currPostEntry.NumNFTCopiesBurned)
	}

	// Sanity check that there is no current NFT entry.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	currNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if currNFTEntry != nil && !currNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectBurnNFT: found currNFTEntry for burned NFT: %s, %d",
			txMeta.NFTPostHash.String(), txMeta.SerialNumber)
	}

	// Set the old NFT entry (no need to delete first since there is no current entry).
	bav._setNFTEntryMappings(operationData.PrevNFTEntry)

	// Delete the current post entry and set the old one.
	bav._deletePostEntryMappings(currPostEntry)
	bav._setPostEntryMappings(operationData.PrevPostEntry)

	// Now revert the basic transfer with the remaining operations.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectAuthorizeDerivedKey(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a AuthorizeDerivedKey operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeAuthorizeDerivedKey {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey: Trying to revert "+
			"OperationTypeAuthorizeDerivedKey but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}

	txMeta := currentTxn.TxnMeta.(*AuthorizeDerivedKeyMetadata)
	prevDerivedKeyEntry := utxoOpsForTxn[operationIndex].PrevDerivedKeyEntry

	// Sanity check that txn public key is valid. Assign this public key to ownerPublicKey.
	var ownerPublicKey []byte
	if len(currentTxn.PublicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey invalid public key: %v", currentTxn.PublicKey)
	}
	_, err := btcec.ParsePubKey(currentTxn.PublicKey, btcec.S256())
	if err != nil {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey invalid public key: %v", err)
	}
	ownerPublicKey = currentTxn.PublicKey

	// Sanity check that derived key is valid. Assign this key to derivedPublicKey.
	var derivedPublicKey []byte
	if len(txMeta.DerivedPublicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey invalid derived key: %v", txMeta.DerivedPublicKey)
	}
	_, err = btcec.ParsePubKey(txMeta.DerivedPublicKey, btcec.S256())
	if err != nil {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey invalid derived key: %v", err)
	}
	derivedPublicKey = txMeta.DerivedPublicKey

	// Get the derived key entry. If it's nil or is deleted then we have an error.
	derivedKeyEntry := bav._getDerivedKeyMappingForOwner(ownerPublicKey, derivedPublicKey)
	if derivedKeyEntry == nil || derivedKeyEntry.isDeleted {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey: DerivedKeyEntry for "+
			"public key %v, derived key %v was found to be nil or deleted: %v",
			PkToString(ownerPublicKey, bav.Params), PkToString(derivedPublicKey, bav.Params),
			derivedKeyEntry)
	}

	// If we had a previous derivedKeyEntry set then compare it with the current entry.
	if prevDerivedKeyEntry != nil {
		// Sanity check public keys. This should never fail.
		if !reflect.DeepEqual(ownerPublicKey, prevDerivedKeyEntry.OwnerPublicKey[:]) {
			return fmt.Errorf("_disconnectAuthorizeDerivedKey: Owner public key in txn "+
				"differs from that in previous derivedKeyEntry (%v %v)", prevDerivedKeyEntry.OwnerPublicKey, ownerPublicKey)
		}
		if !reflect.DeepEqual(derivedPublicKey, prevDerivedKeyEntry.DerivedPublicKey[:]) {
			return fmt.Errorf("_disconnectAuthorizeDerivedKey: Derived public key in txn "+
				"differs from that in existing derivedKeyEntry (%v %v)", prevDerivedKeyEntry.DerivedPublicKey, derivedPublicKey)
		}
	}

	// Now that we are confident the derivedKeyEntry lines up with the transaction we're
	// rolling back, delete the mapping from utxoView. We need to do this to prevent
	// a fetch from a db later on.
	bav._deleteDerivedKeyMapping(derivedKeyEntry)

	// Set the previous derivedKeyEntry.
	bav._setDerivedKeyMapping(prevDerivedKeyEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the authorizeDerivedKey operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) DisconnectTransaction(currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	if currentTxn.TxnMeta.GetTxnType() == TxnTypeBlockReward || currentTxn.TxnMeta.GetTxnType() == TxnTypeBasicTransfer {
		return bav._disconnectBasicTransfer(
			currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
		return bav._disconnectBitcoinExchange(
			OperationTypeBitcoinExchange, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypePrivateMessage {
		return bav._disconnectPrivateMessage(
			OperationTypePrivateMessage, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeSubmitPost {
		return bav._disconnectSubmitPost(
			OperationTypeSubmitPost, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeUpdateProfile {
		return bav._disconnectUpdateProfile(
			OperationTypeUpdateProfile, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeUpdateBitcoinUSDExchangeRate {
		return bav._disconnectUpdateBitcoinUSDExchangeRate(
			OperationTypeUpdateBitcoinUSDExchangeRate, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeUpdateGlobalParams {
		return bav._disconnectUpdateGlobalParams(
			OperationTypeUpdateGlobalParams, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeFollow {
		return bav._disconnectFollow(
			OperationTypeFollow, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeLike {
		return bav._disconnectLike(
			OperationTypeFollow, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeCreatorCoin {
		return bav._disconnectCreatorCoin(
			OperationTypeCreatorCoin, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeCreatorCoinTransfer {
		return bav._disconnectCreatorCoinTransfer(
			OperationTypeCreatorCoinTransfer, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeSwapIdentity {
		return bav._disconnectSwapIdentity(
			OperationTypeSwapIdentity, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeCreateNFT {
		return bav._disconnectCreateNFT(
			OperationTypeCreateNFT, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeUpdateNFT {
		return bav._disconnectUpdateNFT(
			OperationTypeUpdateNFT, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeAcceptNFTBid {
		return bav._disconnectAcceptNFTBid(
			OperationTypeAcceptNFTBid, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeNFTBid {
		return bav._disconnectNFTBid(
			OperationTypeNFTBid, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeNFTTransfer {
		return bav._disconnectNFTTransfer(
			OperationTypeNFTTransfer, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeAcceptNFTTransfer {
		return bav._disconnectAcceptNFTTransfer(
			OperationTypeAcceptNFTTransfer, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeBurnNFT {
		return bav._disconnectBurnNFT(
			OperationTypeBurnNFT, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeAuthorizeDerivedKey {
		return bav._disconnectAuthorizeDerivedKey(
			OperationTypeAuthorizeDerivedKey, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	}

	return fmt.Errorf("DisconnectBlock: Unimplemented txn type %v", currentTxn.TxnMeta.GetTxnType().String())
}

func (bav *UtxoView) DisconnectBlock(
	desoBlock *MsgDeSoBlock, txHashes []*BlockHash, utxoOps [][]*UtxoOperation) error {

	glog.Infof("DisconnectBlock: Disconnecting block %v", desoBlock)

	// Verify that the block being disconnected is the current tip. DisconnectBlock
	// can only be called on a block at the tip. We do this to keep the API simple.
	blockHash, err := desoBlock.Header.Hash()
	if err != nil {
		return fmt.Errorf("DisconnectBlock: Problem computing block hash")
	}
	if *bav.TipHash != *blockHash {
		return fmt.Errorf("DisconnectBlock: Block being disconnected does not match tip")
	}

	// Verify the number of ADD and SPEND operations in the utxOps list is equal
	// to the number of outputs and inputs in the block respectively.
	//
	// There is a special case, which is that BidderInputs count as inputs in a
	// txn and they result in SPEND operations being created.
	numInputs := 0
	numOutputs := 0
	for _, txn := range desoBlock.Txns {
		numInputs += len(txn.TxInputs)
		if txn.TxnMeta.GetTxnType() == TxnTypeAcceptNFTBid {
			numInputs += len(txn.TxnMeta.(*AcceptNFTBidMetadata).BidderInputs)
		}
		numOutputs += len(txn.TxOutputs)
	}
	numSpendOps := 0
	numAddOps := 0
	for _, utxoOpsForTxn := range utxoOps {
		for _, op := range utxoOpsForTxn {
			if op.Type == OperationTypeSpendUtxo {
				numSpendOps++
			} else if op.Type == OperationTypeAddUtxo {
				numAddOps++
			}
		}
	}
	if numInputs != numSpendOps {
		return fmt.Errorf(
			"DisconnectBlock: Number of inputs in passed block (%d) "+
				"not equal to number of SPEND operations in passed "+
				"utxoOps (%d)", numInputs, numSpendOps)
	}
	// Note that the number of add operations can be greater than the number of "explicit"
	// outputs in the block because transactions like BitcoinExchange
	// produce "implicit" outputs when the transaction is applied.
	if numOutputs > numAddOps {
		return fmt.Errorf(
			"DisconnectBlock: Number of outputs in passed block (%d) "+
				"not equal to number of ADD operations in passed "+
				"utxoOps (%d)", numOutputs, numAddOps)
	}

	// Loop through the txns backwards to process them.
	// Track the operation we're performing as we go.
	for txnIndex := len(desoBlock.Txns) - 1; txnIndex >= 0; txnIndex-- {
		currentTxn := desoBlock.Txns[txnIndex]
		txnHash := txHashes[txnIndex]
		utxoOpsForTxn := utxoOps[txnIndex]
		blockHeight := desoBlock.Header.Height

		err := bav.DisconnectTransaction(currentTxn, txnHash, utxoOpsForTxn, uint32(blockHeight))
		if err != nil {
			return errors.Wrapf(err, "DisconnectBlock: Problem disconnecting transaction: %v", currentTxn)
		}
	}

	// At this point, all of the transactions in the block should be fully
	// reversed and the view should therefore be in the state it was in before
	// this block was applied.

	// Update the tip to point to the parent of this block since we've managed
	// to successfully disconnect it.
	bav.TipHash = desoBlock.Header.PrevBlockHash

	return nil
}

func _isEntryImmatureBlockReward(utxoEntry *UtxoEntry, blockHeight uint32, params *DeSoParams) bool {
	if utxoEntry.UtxoType == UtxoTypeBlockReward {
		blocksPassed := blockHeight - utxoEntry.BlockHeight
		// Note multiplication is OK here and has no chance of overflowing because
		// block heights are computed by our code and are guaranteed to be sane values.
		timePassed := time.Duration(int64(params.TimeBetweenBlocks) * int64(blocksPassed))
		if timePassed < params.BlockRewardMaturity {
			// Mark the block as invalid and return error if an immature block reward
			// is being spent.
			return true
		}
	}
	return false
}

func (bav *UtxoView) _verifySignature(txn *MsgDeSoTxn, blockHeight uint32) error {
	// Compute a hash of the transaction.
	txBytes, err := txn.ToBytes(true /*preSignature*/)
	if err != nil {
		return errors.Wrapf(err, "_verifySignature: Problem serializing txn without signature: ")
	}
	txHash := Sha256DoubleHash(txBytes)

	// Look for the derived key in transaction ExtraData and validate it. For transactions
	// signed using a derived key, the derived public key is passed to ExtraData.
	var derivedPk *btcec.PublicKey
	var derivedPkBytes []byte
	if txn.ExtraData != nil {
		var isDerived bool
		derivedPkBytes, isDerived = txn.ExtraData[DerivedPublicKey]
		if isDerived {
			derivedPk, err = btcec.ParsePubKey(derivedPkBytes, btcec.S256())
			if err != nil {
				return RuleErrorDerivedKeyInvalidExtraData
			}
		}
	}

	// Get the owner public key and attempt turning it into *btcec.PublicKey.
	ownerPkBytes := txn.PublicKey
	ownerPk, err := btcec.ParsePubKey(ownerPkBytes, btcec.S256())
	if err != nil {
		return errors.Wrapf(err, "_verifySignature: Problem parsing owner public key: ")
	}

	// If no derived key is present in ExtraData, we check if transaction was signed by the owner.
	// If derived key is present in ExtraData, we check if transaction was signed by the derived key.
	if derivedPk == nil {
		// Verify that the transaction is signed by the specified key.
		if txn.Signature.Verify(txHash[:], ownerPk) {
			return nil
		}
	} else {
		// Look for a derived key entry in UtxoView and DB, check if it exists nor is deleted.
		derivedKeyEntry := bav._getDerivedKeyMappingForOwner(ownerPkBytes, derivedPkBytes)
		if derivedKeyEntry == nil || derivedKeyEntry.isDeleted {
			return RuleErrorDerivedKeyNotAuthorized
		}

		// Sanity-check that transaction public keys line up with looked-up derivedKeyEntry public keys.
		if !reflect.DeepEqual(ownerPkBytes, derivedKeyEntry.OwnerPublicKey[:]) ||
			!reflect.DeepEqual(derivedPkBytes, derivedKeyEntry.DerivedPublicKey[:]) {
			return RuleErrorDerivedKeyNotAuthorized
		}

		// At this point, we know the derivedKeyEntry that we have is matching.
		// We check if the derived key hasn't been de-authorized or hasn't expired.
		if derivedKeyEntry.OperationType != AuthorizeDerivedKeyOperationValid ||
			derivedKeyEntry.ExpirationBlock <= uint64(blockHeight) {
			return RuleErrorDerivedKeyNotAuthorized
		}

		// All checks passed so we try to verify the signature.
		if txn.Signature.Verify(txHash[:], derivedPk) {
			return nil
		}

		return RuleErrorDerivedKeyNotAuthorized
	}

	return RuleErrorInvalidTransactionSignature
}

func (bav *UtxoView) _connectBasicTransfer(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	var utxoOpsForTxn []*UtxoOperation

	// Loop through all the inputs and validate them.
	var totalInput uint64
	// Each input should have a UtxoEntry corresponding to it if the transaction
	// is legitimate. These should all have back-pointers to their UtxoKeys as well.
	utxoEntriesForInputs := []*UtxoEntry{}
	for _, desoInput := range txn.TxInputs {
		// Fetch the utxoEntry for this input from the view. Make a copy to
		// avoid having the iterator change under our feet.
		utxoKey := UtxoKey(*desoInput)
		utxoEntry := bav.GetUtxoEntryForUtxoKey(&utxoKey)
		// If the utxo doesn't exist mark the block as invalid and return an error.
		if utxoEntry == nil {
			return 0, 0, nil, RuleErrorInputSpendsNonexistentUtxo
		}
		// If the utxo exists but is already spent mark the block as invalid and
		// return an error.
		if utxoEntry.isSpent {
			return 0, 0, nil, RuleErrorInputSpendsPreviouslySpentOutput
		}
		// If the utxo is from a block reward txn, make sure enough time has passed to
		// make it spendable.
		if _isEntryImmatureBlockReward(utxoEntry, blockHeight, bav.Params) {
			glog.Debugf("utxoKey: %v, utxoEntry: %v, height: %d", &utxoKey, utxoEntry, blockHeight)
			return 0, 0, nil, RuleErrorInputSpendsImmatureBlockReward
		}

		// Verify that the input's public key is the same as the public key specified
		// in the transaction.
		//
		// TODO: Enforcing this rule isn't a clear-cut decision. On the one hand,
		// we save space and minimize complexity by enforcing this constraint. On
		// the other hand, we make certain things harder to implement in the
		// future. For example, implementing constant key rotation like Bitcoin
		// has is difficult to do with a scheme like this. As are things like
		// multi-sig (although that could probably be handled using transaction
		// metadata). Key rotation combined with the use of addresses also helps
		// a lot with quantum resistance. Nevertheless, if we assume the platform
		// is committed to "one identity = roughly one public key" for usability
		// reasons (e.g. reputation is way easier to manage without key rotation),
		// then I don't think this constraint should pose much of an issue.
		if !reflect.DeepEqual(utxoEntry.PublicKey, txn.PublicKey) {
			return 0, 0, nil, RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey
		}

		// Sanity check the amount of the input.
		if utxoEntry.AmountNanos > MaxNanos ||
			totalInput >= (math.MaxUint64-utxoEntry.AmountNanos) ||
			totalInput+utxoEntry.AmountNanos > MaxNanos {

			return 0, 0, nil, RuleErrorInputSpendsOutputWithInvalidAmount
		}
		// Add the amount of the utxo to the total input and add the UtxoEntry to
		// our list.
		totalInput += utxoEntry.AmountNanos
		utxoEntriesForInputs = append(utxoEntriesForInputs, utxoEntry)

		// At this point we know the utxo exists in the view and is unspent so actually
		// tell the view to spend the input. If the spend fails for any reason we return
		// an error. Don't mark the block as invalid though since this is not necessarily
		// a rule error and the block could benefit from reprocessing.
		newUtxoOp, err := bav._spendUtxo(&utxoKey)

		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectBasicTransfer: Problem spending input utxo")
		}

		utxoOpsForTxn = append(utxoOpsForTxn, newUtxoOp)
	}

	if len(txn.TxInputs) != len(utxoEntriesForInputs) {
		// Something went wrong if these lists differ in length.
		return 0, 0, nil, fmt.Errorf("_connectBasicTransfer: Length of list of " +
			"UtxoEntries does not match length of input list; this should never happen")
	}

	// Block rewards are a bit special in that we don't allow them to have any
	// inputs. Part of the reason for this stems from the fact that we explicitly
	// require that block reward transactions not be signed. If a block reward is
	// not allowed to have a signature then it should not be trying to spend any
	// inputs.
	if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward && len(txn.TxInputs) != 0 {
		return 0, 0, nil, RuleErrorBlockRewardTxnNotAllowedToHaveInputs
	}

	// At this point, all of the utxos corresponding to inputs of this txn
	// should be marked as spent in the view. Now we go through and process
	// the outputs.
	var totalOutput uint64
	amountsByPublicKey := make(map[PkMapKey]uint64)
	for outputIndex, desoOutput := range txn.TxOutputs {
		// Sanity check the amount of the output. Mark the block as invalid and
		// return an error if it isn't sane.
		if desoOutput.AmountNanos > MaxNanos ||
			totalOutput >= (math.MaxUint64-desoOutput.AmountNanos) ||
			totalOutput+desoOutput.AmountNanos > MaxNanos {

			return 0, 0, nil, RuleErrorTxnOutputWithInvalidAmount
		}

		// Since the amount is sane, add it to the total.
		totalOutput += desoOutput.AmountNanos

		// Create a map of total output by public key. This is used to check diamond
		// amounts below.
		//
		// Note that we don't need to check overflow here because overflow is checked
		// directly above when adding to totalOutput.
		currentAmount, _ := amountsByPublicKey[MakePkMapKey(desoOutput.PublicKey)]
		amountsByPublicKey[MakePkMapKey(desoOutput.PublicKey)] = currentAmount + desoOutput.AmountNanos

		// Create a new entry for this output and add it to the view. It should be
		// added at the end of the utxo list.
		outputKey := UtxoKey{
			TxID:  *txHash,
			Index: uint32(outputIndex),
		}
		utxoType := UtxoTypeOutput
		if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward {
			utxoType = UtxoTypeBlockReward
		}
		// A basic transfer cannot create any output other than a "normal" output
		// or a BlockReward. Outputs of other types must be created after processing
		// the "basic" outputs.

		utxoEntry := UtxoEntry{
			AmountNanos: desoOutput.AmountNanos,
			PublicKey:   desoOutput.PublicKey,
			BlockHeight: blockHeight,
			UtxoType:    utxoType,
			UtxoKey:     &outputKey,
			// We leave the position unset and isSpent to false by default.
			// The position will be set in the call to _addUtxo.
		}
		// If we have a problem adding this utxo return an error but don't
		// mark this block as invalid since it's not a rule error and the block
		// could therefore benefit from being processed in the future.
		newUtxoOp, err := bav._addUtxo(&utxoEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectBasicTransfer: Problem adding output utxo")
		}

		// Rosetta uses this UtxoOperation to provide INPUT amounts
		utxoOpsForTxn = append(utxoOpsForTxn, newUtxoOp)
	}

	// Now that we have computed the outputs, we can finish processing diamonds if need be.
	diamondPostHashBytes, hasDiamondPostHash := txn.ExtraData[DiamondPostHashKey]
	diamondPostHash := &BlockHash{}
	diamondLevelBytes, hasDiamondLevel := txn.ExtraData[DiamondLevelKey]
	var previousDiamondPostEntry *PostEntry
	var previousDiamondEntry *DiamondEntry
	if hasDiamondPostHash && blockHeight > DeSoDiamondsBlockHeight &&
		txn.TxnMeta.GetTxnType() == TxnTypeBasicTransfer {
		if !hasDiamondLevel {
			return 0, 0, nil, RuleErrorBasicTransferHasDiamondPostHashWithoutDiamondLevel
		}
		diamondLevel, bytesRead := Varint(diamondLevelBytes)
		// NOTE: Despite being an int, diamondLevel is required to be non-negative. This
		// is useful for sorting our dbkeys by diamondLevel.
		if bytesRead < 0 || diamondLevel < 0 {
			return 0, 0, nil, RuleErrorBasicTransferHasInvalidDiamondLevel
		}

		// Get the post that is being diamonded.
		if len(diamondPostHashBytes) != HashSizeBytes {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorBasicTransferDiamondInvalidLengthForPostHashBytes,
				"_connectBasicTransfer: DiamondPostHashBytes length: %d", len(diamondPostHashBytes))
		}
		copy(diamondPostHash[:], diamondPostHashBytes[:])

		previousDiamondPostEntry = bav.GetPostEntryForPostHash(diamondPostHash)
		if previousDiamondPostEntry == nil || previousDiamondPostEntry.isDeleted {
			return 0, 0, nil, RuleErrorBasicTransferDiamondPostEntryDoesNotExist
		}

		// Store the diamond recipient pub key so we can figure out how much they are paid.
		diamondRecipientPubKey := previousDiamondPostEntry.PosterPublicKey

		// Check that the diamond sender and receiver public keys are different.
		if reflect.DeepEqual(txn.PublicKey, diamondRecipientPubKey) {
			return 0, 0, nil, RuleErrorBasicTransferDiamondCannotTransferToSelf
		}

		expectedDeSoNanosToTransfer, netNewDiamonds, err := bav.ValidateDiamondsAndGetNumDeSoNanos(
			txn.PublicKey, diamondRecipientPubKey, diamondPostHash, diamondLevel, blockHeight)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectBasicTransfer: ")
		}
		diamondRecipientTotal, _ := amountsByPublicKey[MakePkMapKey(diamondRecipientPubKey)]

		if diamondRecipientTotal < expectedDeSoNanosToTransfer {
			return 0, 0, nil, RuleErrorBasicTransferInsufficientDeSoForDiamondLevel
		}

		// The diamondPostEntry needs to be updated with the number of new diamonds.
		// We make a copy to avoid issues with disconnecting.
		newDiamondPostEntry := &PostEntry{}
		*newDiamondPostEntry = *previousDiamondPostEntry
		newDiamondPostEntry.DiamondCount += uint64(netNewDiamonds)
		bav._setPostEntryMappings(newDiamondPostEntry)

		// Convert pub keys into PKIDs so we can make the DiamondEntry.
		senderPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
		receiverPKID := bav.GetPKIDForPublicKey(diamondRecipientPubKey)

		// Create a new DiamondEntry
		newDiamondEntry := &DiamondEntry{
			SenderPKID:      senderPKID.PKID,
			ReceiverPKID:    receiverPKID.PKID,
			DiamondPostHash: diamondPostHash,
			DiamondLevel:    diamondLevel,
		}

		// Save the old DiamondEntry
		diamondKey := MakeDiamondKey(senderPKID.PKID, receiverPKID.PKID, diamondPostHash)
		existingDiamondEntry := bav.GetDiamondEntryForDiamondKey(&diamondKey)
		// Save the existing DiamondEntry, if it exists, so we can disconnect
		if existingDiamondEntry != nil {
			dd := &DiamondEntry{}
			*dd = *existingDiamondEntry
			previousDiamondEntry = dd
		}

		// Now set the diamond entry mappings on the view so they are flushed to the DB.
		bav._setDiamondEntryMappings(newDiamondEntry)

		// Add an op to help us with the disconnect.
		utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
			Type:             OperationTypeDeSoDiamond,
			PrevPostEntry:    previousDiamondPostEntry,
			PrevDiamondEntry: previousDiamondEntry,
		})
	}

	// If signature verification is requested then do that as well.
	if verifySignatures {
		// When we looped through the inputs we verified that all of them belong
		// to the public key specified in the transaction. So, as long as the transaction
		// public key has signed the transaction as a whole, we can assume that
		// all of the inputs are authorized to be spent. One signature to rule them
		// all.
		//
		// UPDATE: Transaction can be signed by a different key, called a derived key.
		// The derived key must be authorized through an AuthorizeDerivedKey transaction,
		// and then passed along in ExtraData for evey transaction signed with it.
		//
		// We treat block rewards as a special case in that we actually require that they
		// not have a transaction-level public key and that they not be signed. Doing this
		// simplifies things operationally for miners because it means they can run their
		// mining operation without having any private key material on any of the mining
		// nodes. Block rewards are the only transactions that get a pass on this. They are
		// also not allowed to have any inputs because they by construction cannot authorize
		// the spending of any inputs.
		if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward {
			if len(txn.PublicKey) != 0 || txn.Signature != nil {
				return 0, 0, nil, RuleErrorBlockRewardTxnNotAllowedToHaveSignature
			}
		} else {
			if err := bav._verifySignature(txn, blockHeight); err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectBasicTransfer: Problem verifying txn signature: ")
			}
		}
	}

	// Now that we've processed the transaction, return all of the computed
	// data.
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _getMessageEntryForMessageKey(messageKey *MessageKey) *MessageEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.MessageKeyToMessageEntry[*messageKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory view mapping got later.
	dbMessageEntry := DbGetMessageEntry(bav.Handle, messageKey.PublicKey[:], messageKey.TstampNanos)
	if dbMessageEntry != nil {
		bav._setMessageEntryMappings(dbMessageEntry)
	}
	return dbMessageEntry
}

func (bav *UtxoView) _setMessageEntryMappings(messageEntry *MessageEntry) {
	// This function shouldn't be called with nil.
	if messageEntry == nil {
		glog.Errorf("_setMessageEntryMappings: Called with nil MessageEntry; " +
			"this should never happen.")
		return
	}

	// Add a mapping for the sender and the recipient.
	senderKey := MakeMessageKey(messageEntry.SenderPublicKey, messageEntry.TstampNanos)
	bav.MessageKeyToMessageEntry[senderKey] = messageEntry

	recipientKey := MakeMessageKey(messageEntry.RecipientPublicKey, messageEntry.TstampNanos)
	bav.MessageKeyToMessageEntry[recipientKey] = messageEntry
}

func (bav *UtxoView) _deleteMessageEntryMappings(messageEntry *MessageEntry) {

	// Create a tombstone entry.
	tombstoneMessageEntry := *messageEntry
	tombstoneMessageEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setMessageEntryMappings(&tombstoneMessageEntry)
}

//
// Postgres messages
//

func (bav *UtxoView) getMessage(messageHash *BlockHash) *PGMessage {
	mapValue, existsMapValue := bav.MessageMap[*messageHash]
	if existsMapValue {
		return mapValue
	}

	message := bav.Postgres.GetMessage(messageHash)
	if message != nil {
		bav.setMessageMappings(message)
	}
	return message
}

func (bav *UtxoView) setMessageMappings(message *PGMessage) {
	bav.MessageMap[*message.MessageHash] = message
}

func (bav *UtxoView) deleteMessageMappings(message *PGMessage) {
	deletedMessage := *message
	deletedMessage.isDeleted = true
	bav.setMessageMappings(&deletedMessage)
}

func (bav *UtxoView) _getLikeEntryForLikeKey(likeKey *LikeKey) *LikeEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.LikeKeyToLikeEntry[*likeKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory view mapping got later.
	likeExists := false
	if bav.Postgres != nil {
		likeExists = bav.Postgres.GetLike(likeKey.LikerPubKey[:], &likeKey.LikedPostHash) != nil
	} else {
		likeExists = DbGetLikerPubKeyToLikedPostHashMapping(bav.Handle, likeKey.LikerPubKey[:], likeKey.LikedPostHash) != nil
	}

	if likeExists {
		likeEntry := LikeEntry{
			LikerPubKey:   likeKey.LikerPubKey[:],
			LikedPostHash: &likeKey.LikedPostHash,
		}
		bav._setLikeEntryMappings(&likeEntry)
		return &likeEntry
	}

	return nil
}

func (bav *UtxoView) _getRepostEntryForRepostKey(repostKey *RepostKey) *RepostEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.RepostKeyToRepostEntry[*repostKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory view mapping got later.
	repostEntry := DbReposterPubKeyRepostedPostHashToRepostEntry(
		bav.Handle, repostKey.ReposterPubKey[:], repostKey.RepostedPostHash)
	if repostEntry != nil {
		bav._setRepostEntryMappings(repostEntry)
	}
	return repostEntry
}

func (bav *UtxoView) _setLikeEntryMappings(likeEntry *LikeEntry) {
	// This function shouldn't be called with nil.
	if likeEntry == nil {
		glog.Errorf("_setLikeEntryMappings: Called with nil LikeEntry; " +
			"this should never happen.")
		return
	}

	likeKey := MakeLikeKey(likeEntry.LikerPubKey, *likeEntry.LikedPostHash)
	bav.LikeKeyToLikeEntry[likeKey] = likeEntry
}

func (bav *UtxoView) _deleteLikeEntryMappings(likeEntry *LikeEntry) {

	// Create a tombstone entry.
	tombstoneLikeEntry := *likeEntry
	tombstoneLikeEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setLikeEntryMappings(&tombstoneLikeEntry)
}

func (bav *UtxoView) _setRepostEntryMappings(repostEntry *RepostEntry) {
	// This function shouldn't be called with nil.
	if repostEntry == nil {
		glog.Errorf("_setRepostEntryMappings: Called with nil RepostEntry; " +
			"this should never happen.")
		return
	}

	repostKey := MakeRepostKey(repostEntry.ReposterPubKey, *repostEntry.RepostedPostHash)
	bav.RepostKeyToRepostEntry[repostKey] = repostEntry
}

func (bav *UtxoView) _deleteRepostEntryMappings(repostEntry *RepostEntry) {

	if repostEntry == nil {
		glog.Errorf("_deleteRepostEntryMappings: called with nil RepostEntry; " +
			"this should never happen")
		return
	}
	// Create a tombstone entry.
	tombstoneRepostEntry := *repostEntry
	tombstoneRepostEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setRepostEntryMappings(&tombstoneRepostEntry)
}

func (bav *UtxoView) GetFollowEntryForFollowerPublicKeyCreatorPublicKey(followerPublicKey []byte, creatorPublicKey []byte) *FollowEntry {
	followerPKID := bav.GetPKIDForPublicKey(followerPublicKey)
	creatorPKID := bav.GetPKIDForPublicKey(creatorPublicKey)

	if followerPKID == nil || creatorPKID == nil {
		return nil
	}

	followKey := MakeFollowKey(followerPKID.PKID, creatorPKID.PKID)
	return bav._getFollowEntryForFollowKey(&followKey)
}

func (bav *UtxoView) _getFollowEntryForFollowKey(followKey *FollowKey) *FollowEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.FollowKeyToFollowEntry[*followKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory view mapping got later.
	followExists := false
	if bav.Postgres != nil {
		followExists = bav.Postgres.GetFollow(&followKey.FollowerPKID, &followKey.FollowedPKID) != nil
	} else {
		followExists = DbGetFollowerToFollowedMapping(bav.Handle, &followKey.FollowerPKID, &followKey.FollowedPKID) != nil
	}

	if followExists {
		followEntry := FollowEntry{
			FollowerPKID: &followKey.FollowerPKID,
			FollowedPKID: &followKey.FollowedPKID,
		}
		bav._setFollowEntryMappings(&followEntry)
		return &followEntry
	}

	return nil
}

// Make sure that follows are loaded into the view before calling this
func (bav *UtxoView) _followEntriesForPubKey(publicKey []byte, getEntriesFollowingPublicKey bool) (
	_followEntries []*FollowEntry) {

	// Return an empty list if no public key is provided
	if len(publicKey) == 0 {
		return []*FollowEntry{}
	}

	// Look up the PKID for the public key. This should always be set.
	pkidForPublicKey := bav.GetPKIDForPublicKey(publicKey)
	if pkidForPublicKey == nil || pkidForPublicKey.isDeleted {
		glog.Errorf("PKID for public key %v was nil or deleted on the view; this "+
			"should never happen", PkToString(publicKey, bav.Params))
		return nil
	}

	// Now that the view mappings are a complete picture, iterate through them
	// and set them on the map we're returning. Skip entries that don't match
	// our public key or that are deleted. Note that only considering mappings
	// where our public key is part of the key should ensure there are no
	// duplicates in the resulting list.
	followEntriesToReturn := []*FollowEntry{}
	for viewFollowKey, viewFollowEntry := range bav.FollowKeyToFollowEntry {
		if viewFollowEntry.isDeleted {
			continue
		}

		var followKey FollowKey
		if getEntriesFollowingPublicKey {
			// publicKey is the followed public key
			followKey = MakeFollowKey(viewFollowEntry.FollowerPKID, pkidForPublicKey.PKID)
		} else {
			// publicKey is the follower public key
			followKey = MakeFollowKey(pkidForPublicKey.PKID, viewFollowEntry.FollowedPKID)
		}

		// Skip the follow entries that don't involve our publicKey
		if viewFollowKey != followKey {
			continue
		}

		// At this point we are confident the map key is equal to the message
		// key containing the passed-in public key so add it to the mapping.
		followEntriesToReturn = append(followEntriesToReturn, viewFollowEntry)
	}

	return followEntriesToReturn
}

// getEntriesFollowingPublicKey == true => Returns FollowEntries for people that follow publicKey
// getEntriesFollowingPublicKey == false => Returns FollowEntries for people that publicKey follows
func (bav *UtxoView) GetFollowEntriesForPublicKey(publicKey []byte, getEntriesFollowingPublicKey bool) (
	_followEntries []*FollowEntry, _err error) {

	// If the public key is not set then there are no FollowEntrys to return.
	if len(publicKey) == 0 {
		return []*FollowEntry{}, nil
	}

	// Look up the PKID for the public key. This should always be set.
	pkidForPublicKey := bav.GetPKIDForPublicKey(publicKey)
	if pkidForPublicKey == nil || pkidForPublicKey.isDeleted {
		return nil, fmt.Errorf("GetFollowEntriesForPublicKey: PKID for public key %v was nil "+
			"or deleted on the view; this should never happen",
			PkToString(publicKey, bav.Params))
	}

	// Start by fetching all the follows we have in the db.
	if bav.Postgres != nil {
		var follows []*PGFollow
		if getEntriesFollowingPublicKey {
			follows = bav.Postgres.GetFollowers(pkidForPublicKey.PKID)
		} else {
			follows = bav.Postgres.GetFollowing(pkidForPublicKey.PKID)
		}

		for _, follow := range follows {
			bav._setFollowEntryMappings(follow.NewFollowEntry())
		}
	} else {
		var dbPKIDs []*PKID
		var err error
		if getEntriesFollowingPublicKey {
			dbPKIDs, err = DbGetPKIDsFollowingYou(bav.Handle, pkidForPublicKey.PKID)
		} else {
			dbPKIDs, err = DbGetPKIDsYouFollow(bav.Handle, pkidForPublicKey.PKID)
		}
		if err != nil {
			return nil, errors.Wrapf(err, "GetFollowsForUser: Problem fetching FollowEntrys from db: ")
		}

		// Iterate through the entries found in the db and force the view to load them.
		// This fills in any gaps in the view so that, after this, the view should contain
		// the union of what it had before plus what was in the db.
		for _, dbPKID := range dbPKIDs {
			var followKey FollowKey
			if getEntriesFollowingPublicKey {
				// publicKey is the followed public key
				followKey = MakeFollowKey(dbPKID, pkidForPublicKey.PKID)
			} else {
				// publicKey is the follower public key
				followKey = MakeFollowKey(pkidForPublicKey.PKID, dbPKID)
			}

			bav._getFollowEntryForFollowKey(&followKey)
		}
	}

	followEntriesToReturn := bav._followEntriesForPubKey(publicKey, getEntriesFollowingPublicKey)

	return followEntriesToReturn, nil
}

func (bav *UtxoView) _setFollowEntryMappings(followEntry *FollowEntry) {
	// This function shouldn't be called with nil.
	if followEntry == nil {
		glog.Errorf("_setFollowEntryMappings: Called with nil FollowEntry; " +
			"this should never happen.")
		return
	}

	followerKey := MakeFollowKey(followEntry.FollowerPKID, followEntry.FollowedPKID)
	bav.FollowKeyToFollowEntry[followerKey] = followEntry
}

func (bav *UtxoView) _deleteFollowEntryMappings(followEntry *FollowEntry) {

	// Create a tombstone entry.
	tombstoneFollowEntry := *followEntry
	tombstoneFollowEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setFollowEntryMappings(&tombstoneFollowEntry)
}

func (bav *UtxoView) _setNFTEntryMappings(nftEntry *NFTEntry) {
	// This function shouldn't be called with nil.
	if nftEntry == nil {
		glog.Errorf("_setNFTEntryMappings: Called with nil NFTEntry; " +
			"this should never happen.")
		return
	}

	nftKey := MakeNFTKey(nftEntry.NFTPostHash, nftEntry.SerialNumber)
	bav.NFTKeyToNFTEntry[nftKey] = nftEntry
}

func (bav *UtxoView) _deleteNFTEntryMappings(nftEntry *NFTEntry) {

	// Create a tombstone entry.
	tombstoneNFTEntry := *nftEntry
	tombstoneNFTEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setNFTEntryMappings(&tombstoneNFTEntry)
}

func (bav *UtxoView) GetNFTEntryForNFTKey(nftKey *NFTKey) *NFTEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.NFTKeyToNFTEntry[*nftKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	var nftEntry *NFTEntry
	if bav.Postgres != nil {
		nft := bav.Postgres.GetNFT(&nftKey.NFTPostHash, nftKey.SerialNumber)
		if nft != nil {
			nftEntry = nft.NewNFTEntry()
		}
	} else {
		nftEntry = DBGetNFTEntryByPostHashSerialNumber(bav.Handle, &nftKey.NFTPostHash, nftKey.SerialNumber)
	}

	if nftEntry != nil {
		bav._setNFTEntryMappings(nftEntry)
	}
	return nftEntry
}

func (bav *UtxoView) GetNFTEntriesForPostHash(nftPostHash *BlockHash) []*NFTEntry {
	// Get all the entries in the DB.
	var dbNFTEntries []*NFTEntry
	if bav.Postgres != nil {
		nfts := bav.Postgres.GetNFTsForPostHash(nftPostHash)
		for _, nft := range nfts {
			dbNFTEntries = append(dbNFTEntries, nft.NewNFTEntry())
		}
	} else {
		dbNFTEntries = DBGetNFTEntriesForPostHash(bav.Handle, nftPostHash)
	}

	// Make sure all of the DB entries are loaded in the view.
	for _, dbNFTEntry := range dbNFTEntries {
		nftKey := MakeNFTKey(dbNFTEntry.NFTPostHash, dbNFTEntry.SerialNumber)

		// If the NFT is not in the view, add it to the view.
		if _, ok := bav.NFTKeyToNFTEntry[nftKey]; !ok {
			bav._setNFTEntryMappings(dbNFTEntry)
		}
	}

	// Loop over the view and build the final set of NFTEntries to return.
	nftEntries := []*NFTEntry{}
	for _, nftEntry := range bav.NFTKeyToNFTEntry {
		if !nftEntry.isDeleted && reflect.DeepEqual(nftEntry.NFTPostHash, nftPostHash) {
			nftEntries = append(nftEntries, nftEntry)
		}
	}
	return nftEntries
}

func (bav *UtxoView) GetNFTEntriesForPKID(ownerPKID *PKID) []*NFTEntry {
	var dbNFTEntries []*NFTEntry
	if bav.Postgres != nil {
		nfts := bav.Postgres.GetNFTsForPKID(ownerPKID)
		for _, nft := range nfts {
			dbNFTEntries = append(dbNFTEntries, nft.NewNFTEntry())
		}
	} else {
		dbNFTEntries = DBGetNFTEntriesForPKID(bav.Handle, ownerPKID)
	}

	// Make sure all of the DB entries are loaded in the view.
	for _, dbNFTEntry := range dbNFTEntries {
		nftKey := MakeNFTKey(dbNFTEntry.NFTPostHash, dbNFTEntry.SerialNumber)

		// If the NFT is not in the view, add it to the view.
		if _, ok := bav.NFTKeyToNFTEntry[nftKey]; !ok {
			bav._setNFTEntryMappings(dbNFTEntry)
		}
	}

	// Loop over the view and build the final set of NFTEntries to return.
	nftEntries := []*NFTEntry{}
	for _, nftEntry := range bav.NFTKeyToNFTEntry {
		if !nftEntry.isDeleted && reflect.DeepEqual(nftEntry.OwnerPKID, ownerPKID) {
			nftEntries = append(nftEntries, nftEntry)
		}
	}
	return nftEntries
}

func (bav *UtxoView) GetNFTBidEntriesForPKID(bidderPKID *PKID) (_nftBidEntries []*NFTBidEntry) {
	var dbNFTBidEntries []*NFTBidEntry
	if bav.Postgres != nil {
		bids := bav.Postgres.GetNFTBidsForPKID(bidderPKID)
		for _, bid := range bids {
			dbNFTBidEntries = append(dbNFTBidEntries, bid.NewNFTBidEntry())
		}
	} else {
		dbNFTBidEntries = DBGetNFTBidEntriesForPKID(bav.Handle, bidderPKID)
	}

	// Make sure all of the DB entries are loaded in the view.
	for _, dbNFTBidEntry := range dbNFTBidEntries {
		nftBidKey := MakeNFTBidKey(bidderPKID, dbNFTBidEntry.NFTPostHash, dbNFTBidEntry.SerialNumber)

		// If the NFT is not in the view, add it to the view.
		if _, ok := bav.NFTBidKeyToNFTBidEntry[nftBidKey]; !ok {
			bav._setNFTBidEntryMappings(dbNFTBidEntry)
		}
	}

	// Loop over the view and build the final set of NFTEntries to return.
	nftBidEntries := []*NFTBidEntry{}
	for _, nftBidEntry := range bav.NFTBidKeyToNFTBidEntry {
		if !nftBidEntry.isDeleted && reflect.DeepEqual(nftBidEntry.BidderPKID, bidderPKID) {
			nftBidEntries = append(nftBidEntries, nftBidEntry)
		}
	}
	return nftBidEntries
}

// TODO: Postgres
func (bav *UtxoView) GetHighAndLowBidsForNFTCollection(
	nftHash *BlockHash,
) (_highBid uint64, _lowBid uint64) {
	highBid := uint64(0)
	lowBid := uint64(0)
	postEntry := bav.GetPostEntryForPostHash(nftHash)

	// First we get the highest and lowest bids from the db.
	for ii := uint64(1); ii <= postEntry.NumNFTCopies; ii++ {
		highBidForSerialNum, lowBidForSerialNum := bav.GetDBHighAndLowBidsForNFT(nftHash, ii)

		if highBidForSerialNum > highBid {
			highBid = highBidForSerialNum
		}

		if lowBidForSerialNum < lowBid {
			lowBid = lowBidForSerialNum
		}
	}

	// Then we loop over the view to for anything we missed.
	for _, nftBidEntry := range bav.NFTBidKeyToNFTBidEntry {
		if !nftBidEntry.isDeleted && reflect.DeepEqual(nftBidEntry.NFTPostHash, nftHash) {
			if nftBidEntry.BidAmountNanos > highBid {
				highBid = nftBidEntry.BidAmountNanos
			}

			if nftBidEntry.BidAmountNanos < lowBid {
				lowBid = nftBidEntry.BidAmountNanos
			}
		}
	}

	return highBid, lowBid
}

// TODO: Postgres
func (bav *UtxoView) GetHighAndLowBidsForNFTSerialNumber(nftHash *BlockHash, serialNumber uint64) (_highBid uint64, _lowBid uint64) {
	highBid := uint64(0)
	lowBid := uint64(0)

	highBidEntry, lowBidEntry := bav.GetDBHighAndLowBidEntriesForNFT(nftHash, serialNumber)

	if highBidEntry != nil {
		highBidKey := MakeNFTBidKey(highBidEntry.BidderPKID, highBidEntry.NFTPostHash, highBidEntry.SerialNumber)
		if _, exists := bav.NFTBidKeyToNFTBidEntry[highBidKey]; !exists {
			bav._setNFTBidEntryMappings(highBidEntry)
		}
		highBid = highBidEntry.BidAmountNanos
	}

	if lowBidEntry != nil {
		lowBidKey := MakeNFTBidKey(lowBidEntry.BidderPKID, lowBidEntry.NFTPostHash, lowBidEntry.SerialNumber)
		if _, exists := bav.NFTBidKeyToNFTBidEntry[lowBidKey]; !exists {
			bav._setNFTBidEntryMappings(lowBidEntry)
		}
		lowBid = lowBidEntry.BidAmountNanos
	}

	// Then we loop over the view to for anything we missed.
	for _, nftBidEntry := range bav.NFTBidKeyToNFTBidEntry {
		if !nftBidEntry.isDeleted && nftBidEntry.SerialNumber == serialNumber && reflect.DeepEqual(nftBidEntry.NFTPostHash, nftHash) {
			if nftBidEntry.BidAmountNanos > highBid {
				highBid = nftBidEntry.BidAmountNanos
			}

			if nftBidEntry.BidAmountNanos < lowBid {
				lowBid = nftBidEntry.BidAmountNanos
			}
		}
	}
	return highBid, lowBid
}

// TODO: Postgres
func (bav *UtxoView) GetDBHighAndLowBidsForNFT(nftHash *BlockHash, serialNumber uint64) (_highBid uint64, _lowBid uint64) {
	highBidAmount := uint64(0)
	lowBidAmount := uint64(0)
	highBidEntry, lowBidEntry := bav.GetDBHighAndLowBidEntriesForNFT(nftHash, serialNumber)
	if highBidEntry != nil {
		highBidAmount = highBidEntry.BidAmountNanos
	}
	if lowBidEntry != nil {
		lowBidAmount = lowBidEntry.BidAmountNanos
	}
	return highBidAmount, lowBidAmount
}

// This function gets the highest and lowest bids for a specific NFT that
// have not been deleted in the view.
// TODO: Postgres
func (bav *UtxoView) GetDBHighAndLowBidEntriesForNFT(
	nftHash *BlockHash, serialNumber uint64,
) (_highBidEntry *NFTBidEntry, _lowBidEntry *NFTBidEntry) {
	numPerDBFetch := 5
	var highestBidEntry *NFTBidEntry
	var lowestBidEntry *NFTBidEntry

	// Loop until we find the highest bid in the database that hasn't been deleted in the view.
	exitLoop := false
	highBidEntries := DBGetNFTBidEntriesPaginated(
		bav.Handle, nftHash, serialNumber, nil, numPerDBFetch, true)
	for _, bidEntry := range highBidEntries {
		bidEntryKey := MakeNFTBidKey(bidEntry.BidderPKID, bidEntry.NFTPostHash, bidEntry.SerialNumber)
		if _, exists := bav.NFTBidKeyToNFTBidEntry[bidEntryKey]; !exists {
			bav._setNFTBidEntryMappings(bidEntry)
		}
	}
	for {
		for _, highBidEntry := range highBidEntries {
			bidKey := &NFTBidKey{
				NFTPostHash:  *highBidEntry.NFTPostHash,
				SerialNumber: highBidEntry.SerialNumber,
				BidderPKID:   *highBidEntry.BidderPKID,
			}
			bidEntry := bav.NFTBidKeyToNFTBidEntry[*bidKey]
			if !bidEntry.isDeleted && !exitLoop {
				exitLoop = true
				highestBidEntry = bidEntry
			}
		}

		if len(highBidEntries) < numPerDBFetch {
			exitLoop = true
		}

		if exitLoop {
			break
		} else {
			nextStartEntry := highBidEntries[len(highBidEntries)-1]
			highBidEntries = DBGetNFTBidEntriesPaginated(
				bav.Handle, nftHash, serialNumber, nextStartEntry, numPerDBFetch, true,
			)
		}
	}

	// Loop until we find the lowest bid in the database that hasn't been deleted in the view.
	exitLoop = false
	lowBidEntries := DBGetNFTBidEntriesPaginated(
		bav.Handle, nftHash, serialNumber, nil, numPerDBFetch, false)
	for _, bidEntry := range lowBidEntries {
		bidEntryKey := MakeNFTBidKey(bidEntry.BidderPKID, bidEntry.NFTPostHash, bidEntry.SerialNumber)
		if _, exists := bav.NFTBidKeyToNFTBidEntry[bidEntryKey]; !exists {
			bav._setNFTBidEntryMappings(bidEntry)
		}
	}
	for {
		for _, lowBidEntry := range lowBidEntries {
			bidKey := &NFTBidKey{
				NFTPostHash:  *lowBidEntry.NFTPostHash,
				SerialNumber: lowBidEntry.SerialNumber,
				BidderPKID:   *lowBidEntry.BidderPKID,
			}
			bidEntry := bav.NFTBidKeyToNFTBidEntry[*bidKey]
			if !bidEntry.isDeleted && !exitLoop {
				exitLoop = true
				lowestBidEntry = bidEntry
			}
		}

		if len(lowBidEntries) < numPerDBFetch {
			exitLoop = true
		}

		if exitLoop {
			break
		} else {
			nextStartEntry := lowBidEntries[len(lowBidEntries)-1]
			lowBidEntries = DBGetNFTBidEntriesPaginated(
				bav.Handle, nftHash, serialNumber, nextStartEntry, numPerDBFetch, false,
			)
		}
	}

	return highestBidEntry, lowestBidEntry
}

func (bav *UtxoView) _setAcceptNFTBidHistoryMappings(nftKey NFTKey, nftBidEntries *[]*NFTBidEntry) {
	if nftBidEntries == nil {
		glog.Errorf("_setAcceptedNFTBidHistoryMappings: Called with nil nftBidEntries; " +
			"this should never happen.")
		return
	}

	bav.NFTKeyToAcceptedNFTBidHistory[nftKey] = nftBidEntries
}

func (bav *UtxoView) GetAcceptNFTBidHistoryForNFTKey(nftKey *NFTKey) *[]*NFTBidEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.

	mapValue, existsMapValue := bav.NFTKeyToAcceptedNFTBidHistory[*nftKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	dbNFTBidEntries := DBGetAcceptedNFTBidEntriesByPostHashSerialNumber(bav.Handle, &nftKey.NFTPostHash, nftKey.SerialNumber)
	if dbNFTBidEntries != nil {
		bav._setAcceptNFTBidHistoryMappings(*nftKey, dbNFTBidEntries)
		return dbNFTBidEntries
	}
	// We return an empty slice instead of nil
	return &[]*NFTBidEntry{}
}

func (bav *UtxoView) _setNFTBidEntryMappings(nftBidEntry *NFTBidEntry) {
	// This function shouldn't be called with nil.
	if nftBidEntry == nil {
		glog.Errorf("_setNFTBidEntryMappings: Called with nil nftBidEntry; " +
			"this should never happen.")
		return
	}

	nftBidKey := MakeNFTBidKey(nftBidEntry.BidderPKID, nftBidEntry.NFTPostHash, nftBidEntry.SerialNumber)
	bav.NFTBidKeyToNFTBidEntry[nftBidKey] = nftBidEntry
}

func (bav *UtxoView) _deleteNFTBidEntryMappings(nftBidEntry *NFTBidEntry) {

	// Create a tombstone entry.
	tombstoneNFTBidEntry := *nftBidEntry
	tombstoneNFTBidEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setNFTBidEntryMappings(&tombstoneNFTBidEntry)
}

func (bav *UtxoView) GetNFTBidEntryForNFTBidKey(nftBidKey *NFTBidKey) *NFTBidEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.NFTBidKeyToNFTBidEntry[*nftBidKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	var dbNFTBidEntry *NFTBidEntry
	if bav.Postgres != nil {
		bidEntry := bav.Postgres.GetNFTBid(&nftBidKey.NFTPostHash, &nftBidKey.BidderPKID, nftBidKey.SerialNumber)
		if bidEntry != nil {
			dbNFTBidEntry = bidEntry.NewNFTBidEntry()
		}
	} else {
		dbNFTBidEntry = DBGetNFTBidEntryForNFTBidKey(bav.Handle, nftBidKey)
	}

	if dbNFTBidEntry != nil {
		bav._setNFTBidEntryMappings(dbNFTBidEntry)
	}

	return dbNFTBidEntry
}

func (bav *UtxoView) GetAllNFTBidEntries(nftPostHash *BlockHash, serialNumber uint64) []*NFTBidEntry {
	// Get all the entries in the DB.
	var dbEntries []*NFTBidEntry
	if bav.Postgres != nil {
		bids := bav.Postgres.GetNFTBidsForSerial(nftPostHash, serialNumber)
		for _, bid := range bids {
			dbEntries = append(dbEntries, bid.NewNFTBidEntry())
		}
	} else {
		dbEntries = DBGetNFTBidEntries(bav.Handle, nftPostHash, serialNumber)
	}

	// Make sure all of the DB entries are loaded in the view.
	for _, dbEntry := range dbEntries {
		nftBidKey := MakeNFTBidKey(dbEntry.BidderPKID, dbEntry.NFTPostHash, dbEntry.SerialNumber)

		// If the bidEntry is not in the view, add it to the view.
		if _, ok := bav.NFTBidKeyToNFTBidEntry[nftBidKey]; !ok {
			bav._setNFTBidEntryMappings(dbEntry)
		}
	}

	// Loop over the view and build the final set of NFTBidEntries to return.
	nftBidEntries := []*NFTBidEntry{}
	for _, nftBidEntry := range bav.NFTBidKeyToNFTBidEntry {

		if nftBidEntry.SerialNumber == serialNumber && !nftBidEntry.isDeleted &&
			reflect.DeepEqual(nftBidEntry.NFTPostHash, nftPostHash) {

			nftBidEntries = append(nftBidEntries, nftBidEntry)
		}
	}
	return nftBidEntries
}

func (bav *UtxoView) _setDiamondEntryMappings(diamondEntry *DiamondEntry) {
	// This function shouldn't be called with nil.
	if diamondEntry == nil {
		glog.Errorf("_setDiamondEntryMappings: Called with nil DiamondEntry; " +
			"this should never happen.")
		return
	}

	diamondKey := MakeDiamondKey(
		diamondEntry.SenderPKID, diamondEntry.ReceiverPKID, diamondEntry.DiamondPostHash)
	bav.DiamondKeyToDiamondEntry[diamondKey] = diamondEntry
}

func (bav *UtxoView) _deleteDiamondEntryMappings(diamondEntry *DiamondEntry) {

	// Create a tombstone entry.
	tombstoneDiamondEntry := *diamondEntry
	tombstoneDiamondEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setDiamondEntryMappings(&tombstoneDiamondEntry)
}

func (bav *UtxoView) GetDiamondEntryForDiamondKey(diamondKey *DiamondKey) *DiamondEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	bavDiamondEntry, existsMapValue := bav.DiamondKeyToDiamondEntry[*diamondKey]
	if existsMapValue {
		return bavDiamondEntry
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	var diamondEntry *DiamondEntry
	if bav.Postgres != nil {
		diamond := bav.Postgres.GetDiamond(&diamondKey.SenderPKID, &diamondKey.ReceiverPKID, &diamondKey.DiamondPostHash)
		if diamond != nil {
			diamondEntry = &DiamondEntry{
				SenderPKID:      diamond.SenderPKID,
				ReceiverPKID:    diamond.ReceiverPKID,
				DiamondPostHash: diamond.DiamondPostHash,
				DiamondLevel:    int64(diamond.DiamondLevel),
			}
		}
	} else {
		diamondEntry = DbGetDiamondMappings(bav.Handle, &diamondKey.ReceiverPKID, &diamondKey.SenderPKID, &diamondKey.DiamondPostHash)
	}

	if diamondEntry != nil {
		bav._setDiamondEntryMappings(diamondEntry)
	}

	return diamondEntry
}

func (bav *UtxoView) GetPostEntryForPostHash(postHash *BlockHash) *PostEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.PostHashToPostEntry[*postHash]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	if bav.Postgres != nil {
		post := bav.Postgres.GetPost(postHash)
		if post != nil {
			return bav.setPostMappings(post)
		}
		return nil
	} else {
		dbPostEntry := DBGetPostEntryByPostHash(bav.Handle, postHash)
		if dbPostEntry != nil {
			bav._setPostEntryMappings(dbPostEntry)
		}
		return dbPostEntry
	}
}

func (bav *UtxoView) GetDiamondEntryMapForPublicKey(publicKey []byte, fetchYouDiamonded bool,
) (_pkidToDiamondsMap map[PKID][]*DiamondEntry, _err error) {
	pkidEntry := bav.GetPKIDForPublicKey(publicKey)

	dbPKIDToDiamondsMap, err := DbGetPKIDsThatDiamondedYouMap(bav.Handle, pkidEntry.PKID, fetchYouDiamonded)
	if err != nil {
		return nil, errors.Wrapf(err, "GetDiamondEntryMapForPublicKey: Error Getting "+
			"PKIDs that diamonded you map from the DB.")
	}

	// Load all of the diamondEntries into the view.
	for _, diamondEntryList := range dbPKIDToDiamondsMap {
		for _, diamondEntry := range diamondEntryList {
			diamondKey := &DiamondKey{
				SenderPKID:      *diamondEntry.SenderPKID,
				ReceiverPKID:    *diamondEntry.ReceiverPKID,
				DiamondPostHash: *diamondEntry.DiamondPostHash,
			}
			// If the diamond key is not in the view, add it to the view.
			if _, ok := bav.DiamondKeyToDiamondEntry[*diamondKey]; !ok {
				bav._setDiamondEntryMappings(diamondEntry)
			}
		}
	}

	// Iterate over all the diamondEntries in the view and build the final map.
	pkidToDiamondsMap := make(map[PKID][]*DiamondEntry)
	for _, diamondEntry := range bav.DiamondKeyToDiamondEntry {
		if diamondEntry.isDeleted {
			continue
		}
		// Make sure the diamondEntry we are looking at is for the correct receiver public key.
		if !fetchYouDiamonded && reflect.DeepEqual(diamondEntry.ReceiverPKID, pkidEntry.PKID) {
			pkidToDiamondsMap[*diamondEntry.SenderPKID] = append(
				pkidToDiamondsMap[*diamondEntry.SenderPKID], diamondEntry)
		}

		// Make sure the diamondEntry we are looking at is for the correct sender public key.
		if fetchYouDiamonded && reflect.DeepEqual(diamondEntry.SenderPKID, pkidEntry.PKID) {
			pkidToDiamondsMap[*diamondEntry.ReceiverPKID] = append(
				pkidToDiamondsMap[*diamondEntry.ReceiverPKID], diamondEntry)
		}
	}

	return pkidToDiamondsMap, nil
}

func (bav *UtxoView) GetDiamondEntriesForSenderToReceiver(receiverPublicKey []byte, senderPublicKey []byte,
) (_diamondEntries []*DiamondEntry, _err error) {

	receiverPKIDEntry := bav.GetPKIDForPublicKey(receiverPublicKey)
	senderPKIDEntry := bav.GetPKIDForPublicKey(senderPublicKey)
	dbDiamondEntries, err := DbGetDiamondEntriesForSenderToReceiver(bav.Handle, receiverPKIDEntry.PKID, senderPKIDEntry.PKID)
	if err != nil {
		return nil, errors.Wrapf(err, "GetDiamondEntriesForGiverToReceiver: Error getting diamond entries from DB.")
	}

	// Load all of the diamondEntries into the view
	for _, diamondEntry := range dbDiamondEntries {
		diamondKey := &DiamondKey{
			SenderPKID:      *diamondEntry.SenderPKID,
			ReceiverPKID:    *diamondEntry.ReceiverPKID,
			DiamondPostHash: *diamondEntry.DiamondPostHash,
		}
		// If the diamond key is not in the view, add it to the view.
		if _, ok := bav.DiamondKeyToDiamondEntry[*diamondKey]; !ok {
			bav._setDiamondEntryMappings(diamondEntry)
		}
	}

	var diamondEntries []*DiamondEntry
	for _, diamondEntry := range bav.DiamondKeyToDiamondEntry {
		if diamondEntry.isDeleted {
			continue
		}

		// Make sure the diamondEntry we are looking at is for the correct sender and receiver pair
		if reflect.DeepEqual(diamondEntry.ReceiverPKID, receiverPKIDEntry.PKID) &&
			reflect.DeepEqual(diamondEntry.SenderPKID, senderPKIDEntry.PKID) {
			diamondEntries = append(diamondEntries, diamondEntry)
		}
	}

	return diamondEntries, nil
}

func (bav *UtxoView) _setPostEntryMappings(postEntry *PostEntry) {
	// This function shouldn't be called with nil.
	if postEntry == nil {
		glog.Errorf("_setPostEntryMappings: Called with nil PostEntry; this should never happen.")
		return
	}

	// Add a mapping for the post.
	bav.PostHashToPostEntry[*postEntry.PostHash] = postEntry
}

func (bav *UtxoView) _deletePostEntryMappings(postEntry *PostEntry) {

	// Create a tombstone entry.
	tombstonePostEntry := *postEntry
	tombstonePostEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setPostEntryMappings(&tombstonePostEntry)
}

func (bav *UtxoView) setPostMappings(post *PGPost) *PostEntry {
	postEntry := post.NewPostEntry()

	// Add a mapping for the post.
	bav.PostHashToPostEntry[*post.PostHash] = postEntry

	return postEntry
}

func (bav *UtxoView) _getBalanceEntryForHODLerPKIDAndCreatorPKID(
	hodlerPKID *PKID, creatorPKID *PKID) *BalanceEntry {

	// If an entry exists in the in-memory map, return the value of that mapping.
	balanceEntryKey := MakeCreatorCoinBalanceKey(hodlerPKID, creatorPKID)
	mapValue, existsMapValue := bav.HODLerPKIDCreatorPKIDToBalanceEntry[balanceEntryKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	var balanceEntry *BalanceEntry
	if bav.Postgres != nil {
		balance := bav.Postgres.GetCreatorCoinBalance(hodlerPKID, creatorPKID)
		if balance != nil {
			balanceEntry = &BalanceEntry{
				HODLerPKID:   balance.HolderPKID,
				CreatorPKID:  balance.CreatorPKID,
				BalanceNanos: balance.BalanceNanos,
				HasPurchased: balance.HasPurchased,
			}
		}
	} else {
		balanceEntry = DBGetCreatorCoinBalanceEntryForHODLerAndCreatorPKIDs(bav.Handle, hodlerPKID, creatorPKID)
	}
	if balanceEntry != nil {
		bav._setBalanceEntryMappingsWithPKIDs(balanceEntry, hodlerPKID, creatorPKID)
	}
	return balanceEntry
}

func (bav *UtxoView) GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
	hodlerPubKey []byte, creatorPubKey []byte) (
	_balanceEntry *BalanceEntry, _hodlerPKID *PKID, _creatorPKID *PKID) {

	// These are guaranteed to be non-nil as long as the public keys are valid.
	hodlerPKID := bav.GetPKIDForPublicKey(hodlerPubKey)
	creatorPKID := bav.GetPKIDForPublicKey(creatorPubKey)

	return bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(hodlerPKID.PKID, creatorPKID.PKID), hodlerPKID.PKID, creatorPKID.PKID
}

func (bav *UtxoView) _setBalanceEntryMappingsWithPKIDs(
	balanceEntry *BalanceEntry, hodlerPKID *PKID, creatorPKID *PKID) {

	// This function shouldn't be called with nil.
	if balanceEntry == nil {
		glog.Errorf("_setBalanceEntryMappings: Called with nil BalanceEntry; " +
			"this should never happen.")
		return
	}

	// Add a mapping for the BalancEntry.
	balanceEntryKey := MakeCreatorCoinBalanceKey(hodlerPKID, creatorPKID)
	bav.HODLerPKIDCreatorPKIDToBalanceEntry[balanceEntryKey] = balanceEntry
}

func (bav *UtxoView) _setBalanceEntryMappings(
	balanceEntry *BalanceEntry) {

	bav._setBalanceEntryMappingsWithPKIDs(
		balanceEntry, balanceEntry.HODLerPKID, balanceEntry.CreatorPKID)
}

func (bav *UtxoView) _deleteBalanceEntryMappingsWithPKIDs(
	balanceEntry *BalanceEntry, hodlerPKID *PKID, creatorPKID *PKID) {

	// Create a tombstone entry.
	tombstoneBalanceEntry := *balanceEntry
	tombstoneBalanceEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setBalanceEntryMappingsWithPKIDs(&tombstoneBalanceEntry, hodlerPKID, creatorPKID)
}

func (bav *UtxoView) _deleteBalanceEntryMappings(
	balanceEntry *BalanceEntry, hodlerPublicKey []byte, creatorPublicKey []byte) {

	// These are guaranteed to be non-nil as long as the public keys are valid.
	hodlerPKID := bav.GetPKIDForPublicKey(hodlerPublicKey)
	creatorPKID := bav.GetPKIDForPublicKey(creatorPublicKey)

	// Set the mappings to point to the tombstone entry.
	bav._deleteBalanceEntryMappingsWithPKIDs(balanceEntry, hodlerPKID.PKID, creatorPKID.PKID)
}

func (bav *UtxoView) GetHoldings(pkid *PKID, fetchProfiles bool) ([]*BalanceEntry, []*ProfileEntry, error) {
	var entriesYouHold []*BalanceEntry
	if bav.Postgres != nil {
		balances := bav.Postgres.GetHoldings(pkid)
		for _, balance := range balances {
			entriesYouHold = append(entriesYouHold, balance.NewBalanceEntry())
		}
	} else {
		holdings, err := DbGetBalanceEntriesYouHold(bav.Handle, pkid, true)
		if err != nil {
			return nil, nil, err
		}
		entriesYouHold = holdings
	}

	holdingsMap := make(map[PKID]*BalanceEntry)
	for _, balanceEntry := range entriesYouHold {
		holdingsMap[*balanceEntry.CreatorPKID] = balanceEntry
	}

	for _, balanceEntry := range bav.HODLerPKIDCreatorPKIDToBalanceEntry {
		if reflect.DeepEqual(balanceEntry.HODLerPKID, pkid) {
			if _, ok := holdingsMap[*balanceEntry.CreatorPKID]; ok {
				// We found both a mempool and a db balanceEntry. Update the BalanceEntry using mempool data.
				holdingsMap[*balanceEntry.CreatorPKID].BalanceNanos = balanceEntry.BalanceNanos
			} else {
				// Add new entries to the list
				entriesYouHold = append(entriesYouHold, balanceEntry)
			}
		}
	}

	// Optionally fetch all the profile entries as well.
	var profilesYouHold []*ProfileEntry
	if fetchProfiles {
		for _, balanceEntry := range entriesYouHold {
			// In this case you're the hodler so the creator is the one whose profile we need to fetch.
			currentProfileEntry := bav.GetProfileEntryForPKID(balanceEntry.CreatorPKID)
			profilesYouHold = append(profilesYouHold, currentProfileEntry)
		}
	}

	return entriesYouHold, profilesYouHold, nil
}

func (bav *UtxoView) GetHolders(pkid *PKID, fetchProfiles bool) ([]*BalanceEntry, []*ProfileEntry, error) {
	var holderEntries []*BalanceEntry
	if bav.Postgres != nil {
		balances := bav.Postgres.GetHolders(pkid)
		for _, balance := range balances {
			holderEntries = append(holderEntries, balance.NewBalanceEntry())
		}
	} else {
		holders, err := DbGetBalanceEntriesHodlingYou(bav.Handle, pkid, true)
		if err != nil {
			return nil, nil, err
		}
		holderEntries = holders
	}

	holdersMap := make(map[PKID]*BalanceEntry)
	for _, balanceEntry := range holderEntries {
		holdersMap[*balanceEntry.HODLerPKID] = balanceEntry
	}

	for _, balanceEntry := range bav.HODLerPKIDCreatorPKIDToBalanceEntry {
		if reflect.DeepEqual(balanceEntry.HODLerPKID, pkid) {
			if _, ok := holdersMap[*balanceEntry.HODLerPKID]; ok {
				// We found both a mempool and a db balanceEntry. Update the BalanceEntry using mempool data.
				holdersMap[*balanceEntry.HODLerPKID].BalanceNanos = balanceEntry.BalanceNanos
			} else {
				// Add new entries to the list
				holderEntries = append(holderEntries, balanceEntry)
			}
		}
	}

	// Optionally fetch all the profile entries as well.
	var profilesYouHold []*ProfileEntry
	if fetchProfiles {
		for _, balanceEntry := range holderEntries {
			// In this case you're the hodler so the creator is the one whose profile we need to fetch.
			currentProfileEntry := bav.GetProfileEntryForPKID(balanceEntry.CreatorPKID)
			profilesYouHold = append(profilesYouHold, currentProfileEntry)
		}
	}

	return holderEntries, profilesYouHold, nil
}

func (bav *UtxoView) GetProfileEntryForUsername(nonLowercaseUsername []byte) *ProfileEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.

	// Note that the call to MakeUsernameMapKey will lowercase the username
	// and thus enforce a uniqueness check.
	mapKey := MakeUsernameMapKey(nonLowercaseUsername)
	mapValue, existsMapValue := bav.ProfileUsernameToProfileEntry[mapKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	// Note that the DB username lookup is case-insensitive.
	if bav.Postgres != nil {
		profile := bav.Postgres.GetProfileForUsername(string(nonLowercaseUsername))
		if profile == nil {
			bav.ProfileUsernameToProfileEntry[mapKey] = nil
			return nil
		}

		profileEntry, _ := bav.setProfileMappings(profile)
		return profileEntry
	} else {
		dbProfileEntry := DBGetProfileEntryForUsername(bav.Handle, nonLowercaseUsername)
		if dbProfileEntry != nil {
			bav._setProfileEntryMappings(dbProfileEntry)
		}
		return dbProfileEntry
	}
}

func (bav *UtxoView) GetPKIDForPublicKey(publicKey []byte) *PKIDEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.PublicKeyToPKIDEntry[MakePkMapKey(publicKey)]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	//
	// Note that we construct an entry from the DB return value in order to track
	// isDeleted on the view. If not for isDeleted, we wouldn't need the PKIDEntry
	// wrapper.
	if bav.Postgres != nil {
		profile := bav.Postgres.GetProfileForPublicKey(publicKey)
		if profile == nil {
			pkidEntry := &PKIDEntry{
				PKID:      PublicKeyToPKID(publicKey),
				PublicKey: publicKey,
			}
			bav._setPKIDMappings(pkidEntry)
			return pkidEntry
		}

		_, pkidEntry := bav.setProfileMappings(profile)
		return pkidEntry
	} else {
		pkidEntry := DBGetPKIDEntryForPublicKey(bav.Handle, publicKey)
		if pkidEntry == nil {
			pkidEntry = &PKIDEntry{
				PKID:      PublicKeyToPKID(publicKey),
				PublicKey: publicKey,
			}
		}

		bav._setPKIDMappings(pkidEntry)

		return pkidEntry
	}
}

func (bav *UtxoView) GetPublicKeyForPKID(pkid *PKID) []byte {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.PKIDToPublicKey[*pkid]
	if existsMapValue {
		return mapValue.PublicKey
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	//
	// Note that we construct an entry from the DB return value in order to track
	// isDeleted on the view. If not for isDeleted, we wouldn't need the PKIDEntry
	// wrapper.
	if bav.Postgres != nil {
		profile := bav.Postgres.GetProfile(*pkid)
		if profile == nil {
			pkidEntry := &PKIDEntry{
				PKID:      pkid,
				PublicKey: PKIDToPublicKey(pkid),
			}
			bav._setPKIDMappings(pkidEntry)
			return pkidEntry.PublicKey
		}

		_, pkidEntry := bav.setProfileMappings(profile)
		return pkidEntry.PublicKey
	} else {
		publicKey := DBGetPublicKeyForPKID(bav.Handle, pkid)
		if len(publicKey) == 0 {
			publicKey = pkid.ToBytes()
		}

		bav._setPKIDMappings(&PKIDEntry{
			PKID:      pkid,
			PublicKey: publicKey,
		})

		return publicKey
	}
}

func (bav *UtxoView) _setPKIDMappings(pkidEntry *PKIDEntry) {
	// This function shouldn't be called with nil.
	if pkidEntry == nil {
		glog.Errorf("_setPKIDMappings: Called with nil PKID; " +
			"this should never happen.")
		return
	}

	// Add a mapping for the profile and add the reverse mapping as well.
	bav.PublicKeyToPKIDEntry[MakePkMapKey(pkidEntry.PublicKey)] = pkidEntry
	bav.PKIDToPublicKey[*(pkidEntry.PKID)] = pkidEntry
}

func (bav *UtxoView) _deletePKIDMappings(pkid *PKIDEntry) {
	// Create a tombstone entry.
	tombstonePKIDEntry := *pkid
	tombstonePKIDEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setPKIDMappings(&tombstonePKIDEntry)
}

func (bav *UtxoView) GetProfileEntryForPublicKey(publicKey []byte) *ProfileEntry {
	// Get the PKID for the public key provided. This should never return nil if a
	// proper public key is provided.
	pkidEntry := bav.GetPKIDForPublicKey(publicKey)
	if pkidEntry == nil || pkidEntry.isDeleted {
		return nil
	}

	return bav.GetProfileEntryForPKID(pkidEntry.PKID)
}

func (bav *UtxoView) GetProfileEntryForPKID(pkid *PKID) *ProfileEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.ProfilePKIDToProfileEntry[*pkid]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	if bav.Postgres != nil {
		// Note: We should never get here but writing this code just in case
		profile := bav.Postgres.GetProfile(*pkid)
		if profile == nil {
			return nil
		}

		profileEntry, _ := bav.setProfileMappings(profile)
		return profileEntry
	} else {
		dbProfileEntry := DBGetProfileEntryForPKID(bav.Handle, pkid)
		if dbProfileEntry != nil {
			bav._setProfileEntryMappings(dbProfileEntry)
		}
		return dbProfileEntry
	}
}

func (bav *UtxoView) _setProfileEntryMappings(profileEntry *ProfileEntry) {
	// This function shouldn't be called with nil.
	if profileEntry == nil {
		glog.Errorf("_setProfileEntryMappings: Called with nil ProfileEntry; " +
			"this should never happen.")
		return
	}

	// Look up the current PKID for the profile. Never nil because we create the entry if it doesn't exist
	pkidEntry := bav.GetPKIDForPublicKey(profileEntry.PublicKey)

	// Add a mapping for the profile.
	bav.ProfilePKIDToProfileEntry[*pkidEntry.PKID] = profileEntry
	// Note the username will be lowercased when used as a map key.
	bav.ProfileUsernameToProfileEntry[MakeUsernameMapKey(profileEntry.Username)] = profileEntry
}

func (bav *UtxoView) _deleteProfileEntryMappings(profileEntry *ProfileEntry) {
	// Create a tombstone entry.
	tombstoneProfileEntry := *profileEntry
	tombstoneProfileEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setProfileEntryMappings(&tombstoneProfileEntry)
}

// _getDerivedKeyMappingForOwner fetches the derived key mapping from the utxoView
func (bav *UtxoView) _getDerivedKeyMappingForOwner(ownerPublicKey []byte, derivedPublicKey []byte) *DerivedKeyEntry {
	// Check if the entry exists in utxoView.
	ownerPk := NewPublicKey(ownerPublicKey)
	derivedPk := NewPublicKey(derivedPublicKey)
	derivedKeyMapKey := MakeDerivedKeyMapKey(*ownerPk, *derivedPk)
	entry, exists := bav.DerivedKeyToDerivedEntry[derivedKeyMapKey]
	if exists {
		return entry
	}

	// Check if the entry exists in the DB.
	if bav.Postgres != nil {
		if entryPG := bav.Postgres.GetDerivedKey(ownerPk, derivedPk); entryPG != nil {
			entry = entryPG.NewDerivedKeyEntry()
		} else {
			entry = nil
		}
	} else {
		entry = DBGetOwnerToDerivedKeyMapping(bav.Handle, *ownerPk, *derivedPk)
	}

	// If an entry exists, update the UtxoView map.
	if entry != nil {
		bav._setDerivedKeyMapping(entry)
		return entry
	}
	return nil
}

// GetAllDerivedKeyMappingsForOwner fetches all derived key mappings belonging to an owner.
func (bav *UtxoView) GetAllDerivedKeyMappingsForOwner(ownerPublicKey []byte) (
	map[PublicKey]*DerivedKeyEntry, error) {
	derivedKeyMappings := make(map[PublicKey]*DerivedKeyEntry)

	// Check for entries in UtxoView.
	for entryKey, entry := range bav.DerivedKeyToDerivedEntry {
		if reflect.DeepEqual(entryKey.OwnerPublicKey[:], ownerPublicKey) {
			derivedKeyMappings[entryKey.DerivedPublicKey] = entry
		}
	}

	// Check for entries in DB.
	var dbMappings []*DerivedKeyEntry
	ownerPk := NewPublicKey(ownerPublicKey)
	if bav.Postgres != nil {
		pgMappings := bav.Postgres.GetAllDerivedKeysForOwner(ownerPk)
		for _, entry := range pgMappings {
			dbMappings = append(dbMappings, entry.NewDerivedKeyEntry())
		}
	} else {
		var err error
		dbMappings, err = DBGetAllOwnerToDerivedKeyMappings(bav.Handle, *ownerPk)
		if err != nil {
			return nil, errors.Wrapf(err, "GetAllDerivedKeyMappingsForOwner: problem looking up"+
				"entries in the DB.")
		}
	}

	// Add entries from the DB that aren't already present.
	for _, entry := range dbMappings {
		mapKey := entry.DerivedPublicKey
		if _, ok := derivedKeyMappings[mapKey]; !ok {
			derivedKeyMappings[mapKey] = entry
		}
	}

	// Delete entries with isDeleted=true. We are deleting these entries
	// only now, because we wanted to skip corresponding keys in DB fetch.
	for entryKey, entry := range derivedKeyMappings {
		if entry.isDeleted {
			delete(derivedKeyMappings, entryKey)
		}
	}

	return derivedKeyMappings, nil
}

// _setDerivedKeyMapping sets a derived key mapping in the utxoView.
func (bav *UtxoView) _setDerivedKeyMapping(derivedKeyEntry *DerivedKeyEntry) {
	// If the derivedKeyEntry is nil then there's nothing to do.
	if derivedKeyEntry == nil {
		return
	}
	// Add a mapping for the derived key.
	derivedKeyMapKey := MakeDerivedKeyMapKey(derivedKeyEntry.OwnerPublicKey, derivedKeyEntry.DerivedPublicKey)
	bav.DerivedKeyToDerivedEntry[derivedKeyMapKey] = derivedKeyEntry
}

// _deleteDerivedKeyMapping deletes a derived key mapping from utxoView.
func (bav *UtxoView) _deleteDerivedKeyMapping(derivedKeyEntry *DerivedKeyEntry) {
	// If the derivedKeyEntry is nil then there's nothing to do.
	if derivedKeyEntry == nil {
		return
	}

	// Create a tombstone entry.
	tombstoneDerivedKeyEntry := *derivedKeyEntry
	tombstoneDerivedKeyEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setDerivedKeyMapping(&tombstoneDerivedKeyEntry)
}

// Takes a Postgres Profile, sets all the mappings on the view, returns the equivalent ProfileEntry and PKIDEntry
func (bav *UtxoView) setProfileMappings(profile *PGProfile) (*ProfileEntry, *PKIDEntry) {
	pkidEntry := &PKIDEntry{
		PKID:      profile.PKID,
		PublicKey: profile.PublicKey.ToBytes(),
	}
	bav._setPKIDMappings(pkidEntry)

	var profileEntry *ProfileEntry

	// Postgres stores profiles with empty usernames when a swap identity occurs.
	// Storing a nil value for the profile entry preserves badger behavior
	if profile.Empty() {
		bav.ProfilePKIDToProfileEntry[*pkidEntry.PKID] = nil
	} else {
		profileEntry = &ProfileEntry{
			PublicKey:   profile.PublicKey.ToBytes(),
			Username:    []byte(profile.Username),
			Description: []byte(profile.Description),
			ProfilePic:  profile.ProfilePic,
			CoinEntry: CoinEntry{
				CreatorBasisPoints:      profile.CreatorBasisPoints,
				DeSoLockedNanos:         profile.DeSoLockedNanos,
				NumberOfHolders:         profile.NumberOfHolders,
				CoinsInCirculationNanos: profile.CoinsInCirculationNanos,
				CoinWatermarkNanos:      profile.CoinWatermarkNanos,
			},
		}

		bav._setProfileEntryMappings(profileEntry)
	}

	return profileEntry, pkidEntry
}

func (bav *UtxoView) GetProfilesByCoinValue(startLockedNanos uint64, limit int) []*ProfileEntry {
	profiles := bav.Postgres.GetProfilesByCoinValue(startLockedNanos, limit)
	var profileEntrys []*ProfileEntry
	for _, profile := range profiles {
		profileEntry, _ := bav.setProfileMappings(profile)
		profileEntrys = append(profileEntrys, profileEntry)
	}
	return profileEntrys
}

func (bav *UtxoView) GetProfilesForUsernamePrefixByCoinValue(usernamePrefix string) []*ProfileEntry {
	profiles := bav.Postgres.GetProfilesForUsernamePrefixByCoinValue(usernamePrefix, 50)
	pubKeysMap := make(map[PkMapKey][]byte)

	// TODO: We are overwriting profiles here which is awful
	for _, profile := range profiles {
		bav.setProfileMappings(profile)
	}

	lowercaseUsernamePrefixString := strings.ToLower(usernamePrefix)
	var profileEntrys []*ProfileEntry
	for _, pk := range pubKeysMap {
		pkid := bav.GetPKIDForPublicKey(pk).PKID
		profile := bav.GetProfileEntryForPKID(pkid)
		// Double-check that a username matches the prefix.
		// If a user had the handle "elon" and then changed to "jeff" and that transaction hadn't mined yet,
		// we would return the profile for "jeff" when we search for "elon" which is incorrect.
		if profile != nil && strings.HasPrefix(strings.ToLower(string(profile.Username[:])), lowercaseUsernamePrefixString) {
			profileEntrys = append(profileEntrys, profile)
		}
	}

	// Username searches are always sorted by coin value.
	sort.Slice(profileEntrys, func(ii, jj int) bool {
		return profileEntrys[ii].CoinEntry.DeSoLockedNanos > profileEntrys[jj].CoinEntry.DeSoLockedNanos
	})

	return profileEntrys
}

func (bav *UtxoView) _existsBitcoinTxIDMapping(bitcoinBurnTxID *BlockHash) bool {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.BitcoinBurnTxIDs[*bitcoinBurnTxID]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return true. If not, return
	// false. Either way, save the value to the in-memory view mapping got later.
	dbHasMapping := DbExistsBitcoinBurnTxID(bav.Handle, bitcoinBurnTxID)
	bav.BitcoinBurnTxIDs[*bitcoinBurnTxID] = dbHasMapping
	return dbHasMapping
}

func (bav *UtxoView) _setBitcoinBurnTxIDMappings(bitcoinBurnTxID *BlockHash) {
	bav.BitcoinBurnTxIDs[*bitcoinBurnTxID] = true
}

func (bav *UtxoView) _deleteBitcoinBurnTxIDMappings(bitcoinBurnTxID *BlockHash) {
	bav.BitcoinBurnTxIDs[*bitcoinBurnTxID] = false
}

func ExtractBitcoinPublicKeyFromBitcoinTransactionInputs(
	bitcoinTransaction *wire.MsgTx, btcdParams *chaincfg.Params) (
	_publicKey *btcec.PublicKey, _err error) {

	for _, input := range bitcoinTransaction.TxIn {
		// P2PKH follows the form: <sig len> <sig> <pubKeyLen> <pubKey>
		if len(input.SignatureScript) == 0 {
			continue
		}
		sigLen := input.SignatureScript[0]
		pubKeyStart := sigLen + 2
		pubKeyBytes := input.SignatureScript[pubKeyStart:]
		addr, err := btcutil.NewAddressPubKey(pubKeyBytes, btcdParams)
		if err != nil {
			continue
		}

		// If we were able to successfully decode the bytes into a public key, return it.
		if addr.PubKey() != nil {
			return addr.PubKey(), nil
		}

		// If we get here it means we could not extract a public key from this
		// particular input. This is OK as long as we can find a public key in
		// one of the other inputs.
	}

	// If we get here it means we went through all the inputs and were not able to
	// successfully decode a public key from the inputs. Error in this case.
	return nil, fmt.Errorf("ExtractBitcoinPublicKeyFromBitcoinTransactionInputs: " +
		"No valid public key found after scanning all input signature scripts")
}

func _computeBitcoinBurnOutput(bitcoinTransaction *wire.MsgTx, bitcoinBurnAddress string,
	btcdParams *chaincfg.Params) (_burnedOutputSatoshis int64, _err error) {

	totalBurnedOutput := int64(0)
	for _, output := range bitcoinTransaction.TxOut {
		class, addresses, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, btcdParams)
		if err != nil {
			// If we hit an error processing an output just let it slide. We only honor
			// P2PKH transactions and even this we do on a best-effort basis.
			//
			// TODO: Run this over a few Bitcoin blocks to see what its errors look like
			// so we can catch them here.
			continue
		}
		// We only allow P2PK and P2PKH transactions to be counted as burns. Allowing
		// anything else would require making this logic more sophisticated. Additionally,
		// limiting the gamut of possible transactions protects us from weird attacks
		// whereby someone could make us think that some Bitcoin was burned when really
		// it's just some fancy script that fools us into thinking that.
		if !(class == txscript.PubKeyTy || class == txscript.PubKeyHashTy) {
			continue
		}
		// We only process outputs if they have a single address in them, which should
		// be the case anyway given the classes we're limiting ourselves to above.
		if len(addresses) != 1 {
			continue
		}

		// At this point we're confident that we're dealing with a nice vanilla
		// P2PK or P2PKH output that contains just one address that its making a
		// simple payment to.

		// Extract the address and add its output to the total if it happens to be
		// equal to the burn address.
		outputAddress := addresses[0]
		if outputAddress.EncodeAddress() == bitcoinBurnAddress {
			// Check for overflow just in case.
			if output.Value < 0 || totalBurnedOutput > math.MaxInt64-output.Value {
				return 0, fmt.Errorf("_computeBitcoinBurnOutput: output value %d would "+
					"overflow totalBurnedOutput %d; this should never happen",
					output.Value, totalBurnedOutput)
			}
			totalBurnedOutput += output.Value
		}
	}

	return totalBurnedOutput, nil
}

func (bav *UtxoView) _connectBitcoinExchange(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if bav.Params.DeflationBombBlockHeight != 0 &&
		uint64(blockHeight) >= bav.Params.DeflationBombBlockHeight {

		return 0, 0, nil, RuleErrorDeflationBombForbidsMintingAnyMoreDeSo
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeBitcoinExchange {
		return 0, 0, nil, fmt.Errorf("_connectBitcoinExchange: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMetaa := txn.TxnMeta.(*BitcoinExchangeMetadata)

	// Verify that the the transaction has:
	// - no inputs
	// - no outputs
	// - no public key
	// - no signature
	//
	// For BtcExchange transactions the only thing that should be set is the
	// BitcoinExchange metadata. This is because we derive all of the other
	// fields for this transaction from the underlying BitcoinTransaction in
	// the metadata. Not doing this would potentially open up avenues for people
	// to repackage Bitcoin burn transactions paying themselves rather than the person
	// who originally burned the Bitcoin.
	if len(txn.TxInputs) != 0 {
		return 0, 0, nil, RuleErrorBitcoinExchangeShouldNotHaveInputs
	}
	if len(txn.TxOutputs) != 0 {
		return 0, 0, nil, RuleErrorBitcoinExchangeShouldNotHaveOutputs
	}
	if len(txn.PublicKey) != 0 {
		return 0, 0, nil, RuleErrorBitcoinExchangeShouldNotHavePublicKey
	}
	if txn.Signature != nil {
		return 0, 0, nil, RuleErrorBitcoinExchangeShouldNotHaveSignature
	}

	// Check that the BitcoinTransactionHash has not been used in a BitcoinExchange
	// transaction in the past. This ensures that all the Bitcoin that is burned can
	// be converted to DeSo precisely one time. No need to worry about malleability
	// because we also verify that the transaction was mined into a valid Bitcoin block
	// with a lot of work on top of it, which means we can't be tricked by someone
	// twiddling the transaction to give it a different hash (unless the Bitcoin chain
	// is also tricked, in which case we have bigger problems).
	bitcoinTxHash := (BlockHash)(txMetaa.BitcoinTransaction.TxHash())
	if bav._existsBitcoinTxIDMapping(&bitcoinTxHash) {
		return 0, 0, nil, RuleErrorBitcoinExchangeDoubleSpendingBitcoinTransaction
	}

	if verifySignatures {
		// We don't check for signatures and we don't do any checks to verify that
		// the inputs of the BitcoinTransaction are actually entitled to spend their
		// outputs. We get away with this because we check that the transaction
		// was mined into a Bitcoin block with a lot of work on top of it, which
		// would presumably be near-impossible if the Bitcoin transaction were invalid.
	}

	// Extract a public key from the BitcoinTransaction's inputs. Note that we only
	// consider P2PKH inputs to be valid. If no P2PKH inputs are found then we consider
	// the transaction as a whole to be invalid since we don't know who to credit the
	// new DeSo to. If we find more than one P2PKH input, we consider the public key
	// corresponding to the first of these inputs to be the one that will receive the
	// DeSo that will be created.
	publicKey, err := ExtractBitcoinPublicKeyFromBitcoinTransactionInputs(
		txMetaa.BitcoinTransaction, bav.Params.BitcoinBtcdParams)
	if err != nil {
		return 0, 0, nil, RuleErrorBitcoinExchangeValidPublicKeyNotFoundInInputs
	}
	// At this point, we should have extracted a public key from the Bitcoin transaction
	// that we expect to credit the newly-created DeSo to.

	// The burn address cannot create this type of transaction.
	addrFromPubKey, err := btcutil.NewAddressPubKey(
		publicKey.SerializeCompressed(), bav.Params.BitcoinBtcdParams)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("_connectBitcoinExchange: Error "+
			"converting public key to Bitcoin address: %v", err)
	}
	if addrFromPubKey.AddressPubKeyHash().EncodeAddress() == bav.Params.BitcoinBurnAddress {
		return 0, 0, nil, RuleErrorBurnAddressCannotBurnBitcoin
	}

	// Go through the transaction's outputs and count up the satoshis that are being
	// allocated to the burn address. If no Bitcoin is being sent to the burn address
	// then we consider the transaction to be invalid. Watch out for overflow as we do
	// this.
	totalBurnOutput, err := _computeBitcoinBurnOutput(
		txMetaa.BitcoinTransaction, bav.Params.BitcoinBurnAddress,
		bav.Params.BitcoinBtcdParams)
	if err != nil {
		return 0, 0, nil, RuleErrorBitcoinExchangeProblemComputingBurnOutput
	}
	if totalBurnOutput <= 0 {
		return 0, 0, nil, RuleErrorBitcoinExchangeTotalOutputLessThanOrEqualZero
	}

	// At this point we know how many satoshis were burned and we know the public key
	// that should receive the DeSo we are going to create.
	usdCentsPerBitcoin := bav.GetCurrentUSDCentsPerBitcoin()
	// Compute the amount of DeSo that we should create as a result of this transaction.
	nanosToCreate := CalcNanosToCreate(bav.NanosPurchased, uint64(totalBurnOutput), usdCentsPerBitcoin)

	// Compute the amount of DeSo that the user will receive. Note
	// that we allocate a small fee to the miner to incentivize her to include the
	// transaction in a block. The fee for BitcoinExchange transactions is fixed because
	// if it weren't then a miner could theoretically repackage the BitcoinTransaction
	// into a new BitcoinExchange transaction that spends all of the newly-created DeSo as
	// a fee. This way of doing it is a bit annoying because it means that for small
	// BitcoinExchange transactions they might have to wait a long time and for large
	// BitcoinExchange transactions they are highly likely to be overpaying. But it has
	// the major benefit that all miners can autonomously scan the Bitcoin chain for
	// burn transactions that they can turn into BitcoinExchange transactions, effectively
	// making it so that the user doesn't have to manage the process of wrapping the
	// Bitcoin burn into a BitcoinExchange transaction herself.
	//
	// We use bigints because we're paranoid about overflow. Realistically, though,
	// it will never happen.
	nanosToCreateBigint := big.NewInt(int64(nanosToCreate))
	bitcoinExchangeFeeBigint := big.NewInt(
		int64(bav.Params.BitcoinExchangeFeeBasisPoints))
	// = nanosToCreate * bitcoinExchangeFeeBps
	nanosTimesFeeBps := big.NewInt(0).Mul(nanosToCreateBigint, bitcoinExchangeFeeBigint)
	// feeNanos = nanosToCreate * bitcoinExchangeFeeBps / 10000
	feeNanosBigint := big.NewInt(0).Div(nanosTimesFeeBps, big.NewInt(10000))
	if feeNanosBigint.Cmp(big.NewInt(math.MaxInt64)) > 0 ||
		nanosToCreate < uint64(feeNanosBigint.Int64()) {

		return 0, 0, nil, RuleErrorBitcoinExchangeFeeOverflow
	}
	feeNanos := feeNanosBigint.Uint64()
	userNanos := nanosToCreate - feeNanos

	// Now that we have all the information we need, save a UTXO allowing the user to
	// spend the DeSo she's purchased in the future.
	outputKey := UtxoKey{
		TxID: *txn.Hash(),
		// We give all UTXOs that are created as a result of BitcoinExchange transactions
		// an index of zero. There is generally only one UTXO created in a BitcoinExchange
		// transaction so this field doesn't really matter.
		Index: 0,
	}
	utxoEntry := UtxoEntry{
		AmountNanos: userNanos,
		PublicKey:   publicKey.SerializeCompressed(),
		BlockHeight: blockHeight,
		UtxoType:    UtxoTypeBitcoinBurn,
		UtxoKey:     &outputKey,
		// We leave the position unset and isSpent to false by default.
		// The position will be set in the call to _addUtxo.
	}
	// If we have a problem adding this utxo return an error but don't
	// mark this block as invalid since it's not a rule error and the block
	// could therefore benefit from being processed in the future.
	newUtxoOp, err := bav._addUtxo(&utxoEntry)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectBitcoinExchange: Problem adding output utxo")
	}

	// Rosetta uses this UtxoOperation to provide INPUT amounts
	var utxoOpsForTxn []*UtxoOperation
	utxoOpsForTxn = append(utxoOpsForTxn, newUtxoOp)

	// Increment NanosPurchased to reflect the total nanos we created with this
	// transaction, which includes the fee paid to the miner. Save the previous
	// value so it can be easily reverted.
	prevNanosPurchased := bav.NanosPurchased
	bav.NanosPurchased += nanosToCreate

	// Add the Bitcoin TxID to our unique mappings
	bav._setBitcoinBurnTxIDMappings(&bitcoinTxHash)

	// Save a UtxoOperation of type OperationTypeBitcoinExchange that will allow
	// us to easily revert NanosPurchased when we disconnect the transaction.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:               OperationTypeBitcoinExchange,
		PrevNanosPurchased: prevNanosPurchased,
	})

	// Note that the fee is implicitly equal to (nanosToCreate - userNanos)
	return nanosToCreate, userNanos, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectUpdateBitcoinUSDExchangeRate(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeUpdateBitcoinUSDExchangeRate {
		return 0, 0, nil, fmt.Errorf("_connectUpdateBitcoinUSDExchangeRate: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*UpdateBitcoinUSDExchangeRateMetadataa)

	// Validate that the exchange rate is not less than the floor as a sanity-check.
	if txMeta.USDCentsPerBitcoin < MinUSDCentsPerBitcoin {
		return 0, 0, nil, RuleErrorExchangeRateTooLow
	}
	if txMeta.USDCentsPerBitcoin > MaxUSDCentsPerBitcoin {
		return 0, 0, nil, RuleErrorExchangeRateTooHigh
	}

	// Validate the public key. Only a paramUpdater is allowed to trigger this.
	_, updaterIsParamUpdater := bav.Params.ParamUpdaterPublicKeys[MakePkMapKey(txn.PublicKey)]
	if !updaterIsParamUpdater {
		return 0, 0, nil, RuleErrorUserNotAuthorizedToUpdateExchangeRate
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUpdateBitcoinUSDExchangeRate: ")
	}

	// Output must be non-zero
	if totalOutput == 0 {
		return 0, 0, nil, RuleErrorUserOutputMustBeNonzero
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which is all we need.
	}

	// Update the exchange rate using the txn metadata. Save the previous value
	// so it can be easily reverted.
	prevUSDCentsPerBitcoin := bav.USDCentsPerBitcoin
	bav.USDCentsPerBitcoin = txMeta.USDCentsPerBitcoin

	// Save a UtxoOperation of type OperationTypeUpdateBitcoinUSDExchangeRate that will allow
	// us to easily revert  when we disconnect the transaction.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                   OperationTypeUpdateBitcoinUSDExchangeRate,
		PrevUSDCentsPerBitcoin: prevUSDCentsPerBitcoin,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectUpdateGlobalParams(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeUpdateGlobalParams {
		return 0, 0, nil, fmt.Errorf("_connectUpdateGlobalParams: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}

	// Initialize the new global params entry as a copy of the old global params entry and
	// only overwrite values provided in extra data.
	prevGlobalParamsEntry := bav.GlobalParamsEntry
	newGlobalParamsEntry := *prevGlobalParamsEntry
	extraData := txn.ExtraData
	// Validate the public key. Only a paramUpdater is allowed to trigger this.
	_, updaterIsParamUpdater := bav.Params.ParamUpdaterPublicKeys[MakePkMapKey(txn.PublicKey)]
	if !updaterIsParamUpdater {
		return 0, 0, nil, RuleErrorUserNotAuthorizedToUpdateGlobalParams
	}
	if len(extraData[USDCentsPerBitcoinKey]) > 0 {
		// Validate that the exchange rate is not less than the floor as a sanity-check.
		newUSDCentsPerBitcoin, usdCentsPerBitcoinBytesRead := Uvarint(extraData[USDCentsPerBitcoinKey])
		if usdCentsPerBitcoinBytesRead <= 0 {
			return 0, 0, nil, fmt.Errorf("_connectUpdateGlobalParams: unable to decode USDCentsPerBitcoin as uint64")
		}
		if newUSDCentsPerBitcoin < MinUSDCentsPerBitcoin {
			return 0, 0, nil, RuleErrorExchangeRateTooLow
		}
		if newUSDCentsPerBitcoin > MaxUSDCentsPerBitcoin {
			return 0, 0, nil, RuleErrorExchangeRateTooHigh
		}
		newGlobalParamsEntry.USDCentsPerBitcoin = newUSDCentsPerBitcoin
	}

	if len(extraData[MinNetworkFeeNanosPerKBKey]) > 0 {
		newMinNetworkFeeNanosPerKB, minNetworkFeeNanosPerKBBytesRead := Uvarint(extraData[MinNetworkFeeNanosPerKBKey])
		if minNetworkFeeNanosPerKBBytesRead <= 0 {
			return 0, 0, nil, fmt.Errorf("_connectUpdateGlobalParams: unable to decode MinNetworkFeeNanosPerKB as uint64")
		}
		if newMinNetworkFeeNanosPerKB < MinNetworkFeeNanosPerKBValue {
			return 0, 0, nil, RuleErrorMinNetworkFeeTooLow
		}
		if newMinNetworkFeeNanosPerKB > MaxNetworkFeeNanosPerKBValue {
			return 0, 0, nil, RuleErrorMinNetworkFeeTooHigh
		}
		newGlobalParamsEntry.MinimumNetworkFeeNanosPerKB = newMinNetworkFeeNanosPerKB
	}

	if len(extraData[CreateProfileFeeNanosKey]) > 0 {
		newCreateProfileFeeNanos, createProfileFeeNanosBytesRead := Uvarint(extraData[CreateProfileFeeNanosKey])
		if createProfileFeeNanosBytesRead <= 0 {
			return 0, 0, nil, fmt.Errorf("_connectUpdateGlobalParams: unable to decode CreateProfileFeeNanos as uint64")
		}
		if newCreateProfileFeeNanos < MinCreateProfileFeeNanos {
			return 0, 0, nil, RuleErrorCreateProfileFeeTooLow
		}
		if newCreateProfileFeeNanos > MaxCreateProfileFeeNanos {
			return 0, 0, nil, RuleErrorCreateProfileTooHigh
		}
		newGlobalParamsEntry.CreateProfileFeeNanos = newCreateProfileFeeNanos
	}

	if len(extraData[CreateNFTFeeNanosKey]) > 0 {
		newCreateNFTFeeNanos, createNFTFeeNanosBytesRead := Uvarint(extraData[CreateNFTFeeNanosKey])
		if createNFTFeeNanosBytesRead <= 0 {
			return 0, 0, nil, fmt.Errorf("_connectUpdateGlobalParams: unable to decode CreateNFTFeeNanos as uint64")
		}
		if newCreateNFTFeeNanos < MinCreateNFTFeeNanos {
			return 0, 0, nil, RuleErrorCreateNFTFeeTooLow
		}
		if newCreateNFTFeeNanos > MaxCreateNFTFeeNanos {
			return 0, 0, nil, RuleErrorCreateNFTFeeTooHigh
		}
		newGlobalParamsEntry.CreateNFTFeeNanos = newCreateNFTFeeNanos
	}

	if len(extraData[MaxCopiesPerNFTKey]) > 0 {
		newMaxCopiesPerNFT, maxCopiesPerNFTBytesRead := Uvarint(extraData[MaxCopiesPerNFTKey])
		if maxCopiesPerNFTBytesRead <= 0 {
			return 0, 0, nil, fmt.Errorf("_connectUpdateGlobalParams: unable to decode MaxCopiesPerNFT as uint64")
		}
		if newMaxCopiesPerNFT < MinMaxCopiesPerNFT {
			return 0, 0, nil, RuleErrorMaxCopiesPerNFTTooLow
		}
		if newMaxCopiesPerNFT > MaxMaxCopiesPerNFT {
			return 0, 0, nil, RuleErrorMaxCopiesPerNFTTooHigh
		}
		newGlobalParamsEntry.MaxCopiesPerNFT = newMaxCopiesPerNFT
	}

	var newForbiddenPubKeyEntry *ForbiddenPubKeyEntry
	var prevForbiddenPubKeyEntry *ForbiddenPubKeyEntry
	var forbiddenPubKey []byte
	if _, exists := extraData[ForbiddenBlockSignaturePubKeyKey]; exists {
		forbiddenPubKey = extraData[ForbiddenBlockSignaturePubKeyKey]

		if len(forbiddenPubKey) != btcec.PubKeyBytesLenCompressed {
			return 0, 0, nil, RuleErrorForbiddenPubKeyLength
		}

		// If there is already an entry on the view for this pub key, save it.
		if val, ok := bav.ForbiddenPubKeyToForbiddenPubKeyEntry[MakePkMapKey(forbiddenPubKey)]; ok {
			prevForbiddenPubKeyEntry = val
		}

		newForbiddenPubKeyEntry = &ForbiddenPubKeyEntry{
			PubKey: forbiddenPubKey,
		}
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUpdateGlobalParams: ")
	}

	// Output must be non-zero
	if totalOutput == 0 {
		return 0, 0, nil, RuleErrorUserOutputMustBeNonzero
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which is all we need.
	}

	// Update the GlobalParamsEntry using the txn's ExtraData. Save the previous value
	// so it can be easily reverted.
	bav.GlobalParamsEntry = &newGlobalParamsEntry

	// Update the forbidden pub key entry on the view, if we have one to update.
	if newForbiddenPubKeyEntry != nil {
		bav.ForbiddenPubKeyToForbiddenPubKeyEntry[MakePkMapKey(forbiddenPubKey)] = newForbiddenPubKeyEntry
	}

	// Save a UtxoOperation of type OperationTypeUpdateGlobalParams that will allow
	// us to easily revert when we disconnect the transaction.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                     OperationTypeUpdateGlobalParams,
		PrevGlobalParamsEntry:    prevGlobalParamsEntry,
		PrevForbiddenPubKeyEntry: prevForbiddenPubKeyEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectPrivateMessage(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypePrivateMessage {
		return 0, 0, nil, fmt.Errorf("_connectPrivateMessage: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*PrivateMessageMetadata)

	// Check the length of the EncryptedText
	if uint64(len(txMeta.EncryptedText)) > bav.Params.MaxPrivateMessageLengthBytes {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageEncryptedTextLengthExceedsMax, "_connectPrivateMessage: "+
				"EncryptedTextLen = %d; Max length = %d",
			len(txMeta.EncryptedText), bav.Params.MaxPrivateMessageLengthBytes)
	}

	// Check that a proper public key is provided in the message metadata
	if len(txMeta.RecipientPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageRecipientPubKeyLen, "_connectPrivateMessage: "+
				"RecipientPubKeyLen = %d; Expected length = %d",
			len(txMeta.RecipientPublicKey), btcec.PubKeyBytesLenCompressed)
	}
	_, err := btcec.ParsePubKey(txMeta.RecipientPublicKey, btcec.S256())
	if err != nil {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageParsePubKeyError, "_connectPrivateMessage: Parse error: %v", err)
	}

	// You can't send a message to yourself.
	if reflect.DeepEqual(txn.PublicKey, txMeta.RecipientPublicKey) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageSenderPublicKeyEqualsRecipientPublicKey,
			"_connectPrivateMessage: Parse error: %v", err)
	}

	// Check that the timestamp is greater than zero. Not doing this could make
	// the message not get returned when we call Seek() in our db. It's also just
	// a reasonable sanity check.
	if txMeta.TimestampNanos == 0 {
		return 0, 0, nil, RuleErrorPrivateMessageTstampIsZero
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectPrivateMessage: ")
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// If a message already exists and does not have isDeleted=true then return
	// an error. In general, messages must have unique (pubkey, tstamp) tuples.
	//
	// Postgres does not enforce these rule errors
	if bav.Postgres == nil {
		senderMessageKey := MakeMessageKey(txn.PublicKey, txMeta.TimestampNanos)
		senderMessage := bav._getMessageEntryForMessageKey(&senderMessageKey)
		if senderMessage != nil && !senderMessage.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageExistsWithSenderPublicKeyTstampTuple,
				"_connectPrivateMessage: Message key: %v", &senderMessageKey)
		}
		recipientMessageKey := MakeMessageKey(txMeta.RecipientPublicKey, txMeta.TimestampNanos)
		recipientMessage := bav._getMessageEntryForMessageKey(&recipientMessageKey)
		if recipientMessage != nil && !recipientMessage.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageExistsWithRecipientPublicKeyTstampTuple,
				"_connectPrivateMessage: Message key: %v", &recipientMessageKey)
		}
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// At this point we are confident that we are parsing a message with a unique
	// <PublicKey, TstampNanos> tuple. We also know that the sender and recipient
	// have different public keys.

	// Create a MessageEntry
	messageEntry := &MessageEntry{
		SenderPublicKey:    txn.PublicKey,
		RecipientPublicKey: txMeta.RecipientPublicKey,
		EncryptedText:      txMeta.EncryptedText,
		TstampNanos:        txMeta.TimestampNanos,
		Version:            1,
	}

	//Check if message is encrypted with shared secret
	extraV, hasExtraV := txn.ExtraData["V"]
	if hasExtraV {
		Version, _ := Uvarint(extraV)
		messageEntry.Version = uint8(Version)
	}

	if bav.Postgres != nil {
		message := &PGMessage{
			MessageHash:        txn.Hash(),
			SenderPublicKey:    txn.PublicKey,
			RecipientPublicKey: txMeta.RecipientPublicKey,
			EncryptedText:      txMeta.EncryptedText,
			TimestampNanos:     txMeta.TimestampNanos,
		}

		bav.setMessageMappings(message)
	} else {
		// Set the mappings in our in-memory map for the MessageEntry.
		bav._setMessageEntryMappings(messageEntry)
	}

	// Add an operation to the list at the end indicating we've added a message
	// to our data structure.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type: OperationTypePrivateMessage,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectLike(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeLike {
		return 0, 0, nil, fmt.Errorf("_connectLike: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*LikeMetadata)

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectLike: ")
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// At this point the inputs and outputs have been processed. Now we need to handle
	// the metadata.

	// There are two main checks that need to be done before allowing a like:
	//  - Check that the post exists
	//  - Check that the person hasn't already liked the post

	//	Check that the post to like actually exists.
	existingPostEntry := bav.GetPostEntryForPostHash(txMeta.LikedPostHash)
	if existingPostEntry == nil || existingPostEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorCannotLikeNonexistentPost,
			"_connectLike: Post hash: %v", txMeta.LikedPostHash)
	}

	// At this point the code diverges and considers the like / unlike flows differently
	// since the presence of an existing like entry has a different effect in either case.

	likeKey := MakeLikeKey(txn.PublicKey, *txMeta.LikedPostHash)
	existingLikeEntry := bav._getLikeEntryForLikeKey(&likeKey)
	// We don't need to make a copy of the post entry because all we're modifying is the like count,
	// which isn't stored in any of our mappings. But we make a copy here just because it's a little bit
	// more foolproof.
	updatedPostEntry := *existingPostEntry
	if txMeta.IsUnlike {
		// Ensure that there *is* an existing like entry to delete.
		if existingLikeEntry == nil || existingLikeEntry.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorCannotUnlikeWithoutAnExistingLike,
				"_connectLike: Like key: %v", &likeKey)
		}

		// Now that we know there is a like entry, we delete it and decrement the like count.
		bav._deleteLikeEntryMappings(existingLikeEntry)
		updatedPostEntry.LikeCount -= 1
	} else {
		// Ensure that there *is not* an existing like entry.
		if existingLikeEntry != nil && !existingLikeEntry.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorLikeEntryAlreadyExists,
				"_connectLike: Like key: %v", &likeKey)
		}

		// Now that we know there is no pre-existing like entry, we can create one and
		// increment the likes on the liked post.
		likeEntry := &LikeEntry{
			LikerPubKey:   txn.PublicKey,
			LikedPostHash: txMeta.LikedPostHash,
		}
		bav._setLikeEntryMappings(likeEntry)
		updatedPostEntry.LikeCount += 1
	}

	// Set the updated post entry so it has the new like count.
	bav._setPostEntryMappings(&updatedPostEntry)

	// Add an operation to the list at the end indicating we've added a follow.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:          OperationTypeLike,
		PrevLikeEntry: existingLikeEntry,
		PrevLikeCount: existingPostEntry.LikeCount,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectFollow(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeFollow {
		return 0, 0, nil, fmt.Errorf("_connectFollow: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*FollowMetadata)

	// Check that a proper public key is provided in the message metadata
	if len(txMeta.FollowedPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorFollowPubKeyLen, "_connectFollow: "+
				"FollowedPubKeyLen = %d; Expected length = %d",
			len(txMeta.FollowedPublicKey), btcec.PubKeyBytesLenCompressed)
	}

	// TODO: This check feels unnecessary and is expensive
	//_, err := btcec.ParsePubKey(txMeta.FollowedPublicKey, btcec.S256())
	//if err != nil {
	//	return 0, 0, nil, errors.Wrapf(
	//		RuleErrorFollowParsePubKeyError, "_connectFollow: Parse error: %v", err)
	//}

	// Check that the profile to follow actually exists.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.FollowedPublicKey)
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorFollowingNonexistentProfile,
			"_connectFollow: Profile pub key: %v",
			PkToStringBoth(txMeta.FollowedPublicKey))
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectFollow: ")
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// Get the PKIDs for the public keys associated with the follower and the followed.
	followerPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
	if followerPKID == nil || followerPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectFollow: followerPKID was nil or deleted; this should never happen")
	}
	followedPKID := bav.GetPKIDForPublicKey(txMeta.FollowedPublicKey)
	if followedPKID == nil || followerPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectFollow: followedPKID was nil or deleted; this should never happen")
	}

	// Here we consider existing followEntries.  It is handled differently in the follow
	// vs. unfollow case so the code splits those cases out.
	followKey := MakeFollowKey(followerPKID.PKID, followedPKID.PKID)
	existingFollowEntry := bav._getFollowEntryForFollowKey(&followKey)
	if txMeta.IsUnfollow {
		// If this is an unfollow, a FollowEntry *should* exist.
		if existingFollowEntry == nil || existingFollowEntry.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorCannotUnfollowNonexistentFollowEntry,
				"_connectFollow: Follow key: %v", &followKey)
		}

		// Now that we know that this is a valid unfollow entry, delete mapping.
		bav._deleteFollowEntryMappings(existingFollowEntry)
	} else {
		if existingFollowEntry != nil && !existingFollowEntry.isDeleted {
			// If this is a follow, a Follow entry *should not* exist.
			return 0, 0, nil, errors.Wrapf(
				RuleErrorFollowEntryAlreadyExists,
				"_connectFollow: Follow key: %v", &followKey)
		}

		// Now that we know that this is a valid follow, update the mapping.
		followEntry := &FollowEntry{
			FollowerPKID: followerPKID.PKID,
			FollowedPKID: followedPKID.PKID,
		}
		bav._setFollowEntryMappings(followEntry)
	}

	// Add an operation to the list at the end indicating we've added a follow.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type: OperationTypeFollow,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectSubmitPost(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32,
	verifySignatures bool, ignoreUtxos bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeSubmitPost {
		return 0, 0, nil, fmt.Errorf("_connectSubmitPost: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*SubmitPostMetadata)

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	//
	// The ignoreUtxos flag is used to connect "seed" transactions when initializing
	// the blockchain. It allows us to "seed" the database with posts and profiles
	// when we do a hard fork, without having the transactions rejected due to their
	// not being spendable.
	var totalInput, totalOutput uint64
	var utxoOpsForTxn = []*UtxoOperation{}
	var err error
	if !ignoreUtxos {
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectBasicTransfer(
			txn, txHash, blockHeight, verifySignatures)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectSubmitPost: ")
		}

		// Force the input to be non-zero so that we can prevent replay attacks.
		if totalInput == 0 {
			return 0, 0, nil, RuleErrorSubmitPostRequiresNonZeroInput
		}
	}

	// Transaction extra data contains both consensus-related, such as repost info, and additional information about a post,
	// whereas PostExtraData is an attribute of a PostEntry that contains only non-consensus related
	// information about a post, such as a link to a video that is embedded.
	extraData := make(map[string][]byte)
	for k, v := range txn.ExtraData {
		extraData[k] = v
	}
	// Set the IsQuotedRepost attribute of postEntry based on extra data
	isQuotedRepost := false
	if quotedRepost, hasQuotedRepost := extraData[IsQuotedRepostKey]; hasQuotedRepost {
		if reflect.DeepEqual(quotedRepost, QuotedRepostVal) {
			isQuotedRepost = true
		}
		// Delete key since it is not needed in the PostExtraData map as IsQuotedRepost is involved in consensus code.
		delete(extraData, IsQuotedRepostKey)
	}
	var repostedPostHash *BlockHash
	if repostedPostHashBytes, isRepost := extraData[RepostedPostHash]; isRepost {
		repostedPostHash = &BlockHash{}
		copy(repostedPostHash[:], repostedPostHashBytes)
		delete(extraData, RepostedPostHash)
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// If the metadata has a PostHashToModify then treat it as modifying an
	// existing post rather than creating a new post.
	var prevPostEntry *PostEntry
	var prevParentPostEntry *PostEntry
	var prevGrandparentPostEntry *PostEntry
	var prevRepostedPostEntry *PostEntry
	var prevRepostEntry *RepostEntry

	var newPostEntry *PostEntry
	var newParentPostEntry *PostEntry
	var newGrandparentPostEntry *PostEntry
	var newRepostedPostEntry *PostEntry
	var newRepostEntry *RepostEntry
	if len(txMeta.PostHashToModify) != 0 {
		// Make sure the post hash is valid
		if len(txMeta.PostHashToModify) != HashSizeBytes {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorSubmitPostInvalidPostHashToModify,
				"_connectSubmitPost: Bad post hash: %#v", txMeta.PostHashToModify)
		}

		// Get the existing post entry, which must exist and be undeleted.
		postHash := &BlockHash{}
		copy(postHash[:], txMeta.PostHashToModify[:])
		existingPostEntryy := bav.GetPostEntryForPostHash(postHash)
		if existingPostEntryy == nil || existingPostEntryy.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorSubmitPostModifyingNonexistentPost,
				"_connectSubmitPost: Post hash: %v", postHash)
		}

		// Post modification is only allowed by the original poster.
		if !reflect.DeepEqual(txn.PublicKey, existingPostEntryy.PosterPublicKey) {

			return 0, 0, nil, errors.Wrapf(
				RuleErrorSubmitPostPostModificationNotAuthorized,
				"_connectSubmitPost: Post hash: %v, poster public key: %v, "+
					"txn public key: %v, paramUpdater: %v", postHash,
				PkToStringBoth(existingPostEntryy.PosterPublicKey),
				PkToStringBoth(txn.PublicKey), spew.Sdump(bav.Params.ParamUpdaterPublicKeys))
		}

		// Modification of an NFT is not allowed.
		if existingPostEntryy.IsNFT {
			return 0, 0, nil, errors.Wrapf(RuleErrorSubmitPostCannotUpdateNFT, "_connectSubmitPost: ")
		}

		// It's an error if we are updating the value of RepostedPostHash. A post can only ever repost a single post.
		if !reflect.DeepEqual(repostedPostHash, existingPostEntryy.RepostedPostHash) {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorSubmitPostUpdateRepostHash,
				"_connectSubmitPost: cannot update reposted post hash when updating a post")
		}

		// It's an error if we are updating the value of IsQuotedRepost.
		if isQuotedRepost != existingPostEntryy.IsQuotedRepost {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorSubmitPostUpdateIsQuotedRepost,
				"_connectSubmitPost: cannot update isQuotedRepost attribute of post when updating a post")
		}

		// Save the data from the post. Note that we don't make a deep copy
		// because all the fields that we modify are non-pointer fields.
		prevPostEntry = &PostEntry{}
		*prevPostEntry = *existingPostEntryy

		// Set the newPostEntry pointer to the existing entry
		newPostEntry = existingPostEntryy

		// The field values should have already been validated so set
		// them.
		if len(txMeta.Body) != 0 {
			newPostEntry.Body = txMeta.Body
		}

		// Merge the remaining attributes of the transaction's ExtraData into the postEntry's PostExtraData map.
		if len(extraData) > 0 {
			newPostExtraData := make(map[string][]byte)
			for k, v := range existingPostEntryy.PostExtraData {
				newPostExtraData[k] = v
			}
			for k, v := range extraData {
				// If we're given a value with length greater than 0, add it to the map.
				if len(v) > 0 {
					newPostExtraData[k] = v
				} else {
					// If the value we're given has a length of 0, this indicates that we should delete it if it exists.
					delete(newPostExtraData, k)
				}
			}
			newPostEntry.PostExtraData = newPostExtraData
		}
		// TODO: Right now a post can be undeleted by the owner of the post,
		// which seems like undesired behavior if a paramUpdater is trying to reduce
		// spam
		newPostEntry.IsHidden = txMeta.IsHidden

		// Obtain the parent posts
		newParentPostEntry, newGrandparentPostEntry, err = bav._getParentAndGrandparentPostEntry(newPostEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectSubmitPost: error with _getParentAndGrandparentPostEntry: %v", postHash)
		}

		if newPostEntry.RepostedPostHash != nil {
			newRepostedPostEntry = bav.GetPostEntryForPostHash(newPostEntry.RepostedPostHash)
		}

		// Figure out how much we need to change the parent / grandparent's comment count by
		var commentCountUpdateAmount int
		repostCountUpdateAmount := 0
		quoteRepostCountUpdateAmount := 0
		hidingPostEntry := !prevPostEntry.IsHidden && newPostEntry.IsHidden
		if hidingPostEntry {
			// If we're hiding a post then we need to decrement the comment count of the parent
			// and grandparent posts.
			commentCountUpdateAmount = -1 * int(1+prevPostEntry.CommentCount)

			// If we're hiding a post that is a vanilla repost of another post, we decrement the repost count of the
			// post that was reposted.
			if IsVanillaRepost(newPostEntry) {
				repostCountUpdateAmount = -1
			} else if isQuotedRepost {
				quoteRepostCountUpdateAmount = -1
			}
		}

		unhidingPostEntry := prevPostEntry.IsHidden && !newPostEntry.IsHidden
		if unhidingPostEntry {
			// If we're unhiding a post then we need to increment the comment count of the parent
			// and grandparent posts.
			commentCountUpdateAmount = int(1 + prevPostEntry.CommentCount)
			// If we are unhiding a post that is a vanilla repost of another post, we increment the repost count of
			// the post that was reposted.
			if IsVanillaRepost(newPostEntry) {
				repostCountUpdateAmount = 1
			} else if isQuotedRepost {
				quoteRepostCountUpdateAmount = 1
			}
		}

		// Save the data from the parent post. Note that we don't make a deep copy
		// because all the fields that we modify are non-pointer fields.
		if newParentPostEntry != nil {
			prevParentPostEntry = &PostEntry{}
			*prevParentPostEntry = *newParentPostEntry
			bav._updateParentCommentCountForPost(newPostEntry, newParentPostEntry, commentCountUpdateAmount)
		}

		// Save the data from the grandparent post. Note that we don't make a deep copy
		// because all the fields that we modify are non-pointer fields.
		if newGrandparentPostEntry != nil {
			prevGrandparentPostEntry = &PostEntry{}
			*prevGrandparentPostEntry = *newGrandparentPostEntry
			bav._updateParentCommentCountForPost(newPostEntry, newGrandparentPostEntry, commentCountUpdateAmount)
		}
		if newRepostedPostEntry != nil {
			prevRepostedPostEntry = &PostEntry{}
			*prevRepostedPostEntry = *newRepostedPostEntry
			// If the previous post entry is a vanilla repost, we can set the prevRepostEntry.
			if IsVanillaRepost(prevPostEntry) {
				prevRepostKey := MakeRepostKey(prevPostEntry.PosterPublicKey, *prevPostEntry.RepostedPostHash)
				prevRepostEntry = bav._getRepostEntryForRepostKey(&prevRepostKey)
				if prevRepostEntry == nil {
					return 0, 0, nil, fmt.Errorf("prevRepostEntry not found for prevPostEntry")
				}
				// Generally prevRepostEntry is identical to newRepostEntry. Currently, we enforce a check that
				// the RepostedPostHash does not get modified when attempting to connect a submitPost transaction
				newRepostEntry = &RepostEntry{
					ReposterPubKey:   newPostEntry.PosterPublicKey,
					RepostedPostHash: newPostEntry.RepostedPostHash,
					RepostPostHash:   newPostEntry.PostHash,
				}

				// Update the repost count if it has changed.
				bav._updateRepostCount(newRepostedPostEntry, repostCountUpdateAmount)
			} else {
				// Update the quote repost count if it has changed.
				bav._updateQuoteRepostCount(newRepostedPostEntry, quoteRepostCountUpdateAmount)
			}
		}
	} else {
		// In this case we are creating a post from scratch so validate
		// all the fields.

		// StakeMultipleBasisPoints > 0 < max
		// Between 1x = 100% and 10x = 10,000%
		if txMeta.StakeMultipleBasisPoints < 100*100 ||
			txMeta.StakeMultipleBasisPoints > bav.Params.MaxStakeMultipleBasisPoints {

			return 0, 0, nil, errors.Wrapf(RuleErrorSubmitPostStakeMultipleSize,
				"_connectSubmitPost: Invalid StakeMultipleSize: %d",
				txMeta.StakeMultipleBasisPoints)
		}
		// CreatorBasisPoints > 0 < max
		if txMeta.CreatorBasisPoints < 0 ||
			txMeta.CreatorBasisPoints > bav.Params.MaxCreatorBasisPoints {

			return 0, 0, nil, errors.Wrapf(RuleErrorSubmitPostCreatorPercentageSize,
				"_connectSubmitPost: Invalid CreatorPercentageSize: %d",
				txMeta.CreatorBasisPoints)
		}
		// TstampNanos != 0
		if txMeta.TimestampNanos == 0 {
			return 0, 0, nil, errors.Wrapf(RuleErrorSubmitPostTimestampIsZero,
				"_connectSubmitPost: Invalid Timestamp: %d",
				txMeta.TimestampNanos)
		}
		// The parent stake id should be a block hash or profile public key if it's set.
		if len(txMeta.ParentStakeID) != 0 && len(txMeta.ParentStakeID) != HashSizeBytes &&
			len(txMeta.ParentStakeID) != btcec.PubKeyBytesLenCompressed {
			return 0, 0, nil, errors.Wrapf(RuleErrorSubmitPostInvalidParentStakeIDLength,
				"_connectSubmitPost: Parent stake ID length %v must be either 0 or %v or %v",
				len(txMeta.ParentStakeID), HashSizeBytes, btcec.PubKeyBytesLenCompressed)
		}

		// The PostHash is just the transaction hash.
		postHash := txHash
		existingPostEntry := bav.GetPostEntryForPostHash(postHash)
		if existingPostEntry != nil && !existingPostEntry.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPostAlreadyExists,
				"_connectSubmitPost: Post hash: %v", postHash)
		}

		if repostedPostHash != nil {
			newRepostedPostEntry = bav.GetPostEntryForPostHash(repostedPostHash)
			// It is an error if a post entry attempts to repost a post that does not exist.
			if newRepostedPostEntry == nil {
				return 0, 0, nil, RuleErrorSubmitPostRepostPostNotFound
			}
			// It is an error if a post is trying to repost a vanilla repost.
			if IsVanillaRepost(newRepostedPostEntry) {
				return 0, 0, nil, RuleErrorSubmitPostRepostOfRepost
			}
		}

		// Set the post entry pointer to a brand new post.
		newPostEntry = &PostEntry{
			PostHash:                 postHash,
			PosterPublicKey:          txn.PublicKey,
			ParentStakeID:            txMeta.ParentStakeID,
			Body:                     txMeta.Body,
			RepostedPostHash:         repostedPostHash,
			IsQuotedRepost:           isQuotedRepost,
			CreatorBasisPoints:       txMeta.CreatorBasisPoints,
			StakeMultipleBasisPoints: txMeta.StakeMultipleBasisPoints,
			TimestampNanos:           txMeta.TimestampNanos,
			ConfirmationBlockHeight:  blockHeight,
			PostExtraData:            extraData,
			// Don't set IsHidden on new posts.
		}

		// Obtain the parent posts
		newParentPostEntry, newGrandparentPostEntry, err = bav._getParentAndGrandparentPostEntry(newPostEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectSubmitPost: error with _getParentAndGrandparentPostEntry: %v", postHash)
		}

		// Save the data from the parent posts. Note that we don't make a deep copy
		// because all the fields that we modify are non-pointer fields.
		if newParentPostEntry != nil {
			prevParentPostEntry = &PostEntry{}
			*prevParentPostEntry = *newParentPostEntry
			bav._updateParentCommentCountForPost(newPostEntry, newParentPostEntry, 1 /*amountToChangeParentBy*/)
		}

		if newGrandparentPostEntry != nil {
			prevGrandparentPostEntry = &PostEntry{}
			*prevGrandparentPostEntry = *newGrandparentPostEntry
			bav._updateParentCommentCountForPost(newPostEntry, newGrandparentPostEntry, 1 /*amountToChangeParentBy*/)
		}

		// Save the data from the reposted post.
		if newRepostedPostEntry != nil {
			prevRepostedPostEntry = &PostEntry{}
			*prevRepostedPostEntry = *newRepostedPostEntry

			// We only set repost entry mappings and increment counts for vanilla reposts.
			if !isQuotedRepost {
				// Increment the repost count of the post that was reposted by 1 as we are creating a new
				// vanilla repost.
				bav._updateRepostCount(newRepostedPostEntry, 1)
				// Create the new repostEntry
				newRepostEntry = &RepostEntry{
					ReposterPubKey:   newPostEntry.PosterPublicKey,
					RepostedPostHash: newPostEntry.RepostedPostHash,
					RepostPostHash:   newPostEntry.PostHash,
				}
			} else {
				// If it is a quote repost, we need to increment the corresponding count.
				bav._updateQuoteRepostCount(newRepostedPostEntry, 1)
			}
		}
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the poster's
		// public key.
	}

	// Set the mappings for the entry regardless of whether we modified it or
	// created it from scratch.
	bav._setPostEntryMappings(newPostEntry)
	if newParentPostEntry != nil {
		bav._setPostEntryMappings(newParentPostEntry)
	}
	if newGrandparentPostEntry != nil {
		bav._setPostEntryMappings(newGrandparentPostEntry)
	}
	if newRepostedPostEntry != nil {
		bav._setPostEntryMappings(newRepostedPostEntry)
	}

	if newRepostEntry != nil {
		bav._setRepostEntryMappings(newRepostEntry)
	}

	// Add an operation to the list at the end indicating we've added a post.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		// PrevPostEntry should generally be nil when we created a new post from
		// scratch, but non-nil if we modified an existing post.
		PrevPostEntry:            prevPostEntry,
		PrevParentPostEntry:      prevParentPostEntry,
		PrevGrandparentPostEntry: prevGrandparentPostEntry,
		PrevRepostedPostEntry:    prevRepostedPostEntry,
		PrevRepostEntry:          prevRepostEntry,
		Type:                     OperationTypeSubmitPost,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _getParentAndGrandparentPostEntry(postEntry *PostEntry) (
	_parentPostEntry *PostEntry, _grandparentPostEntry *PostEntry, _err error) {
	var parentPostEntry *PostEntry
	var grandparentPostEntry *PostEntry

	// This length check ensures that the parent is a post (and not something else, like a profile)
	//
	// If we ever allow commenting on something else such that the parent is not a post, but where
	// ParentStakeID is also HashSizeBytes, then this logic would likely need to be changed.
	if len(postEntry.ParentStakeID) == HashSizeBytes {
		parentPostEntry = bav.GetPostEntryForPostHash(NewBlockHash(postEntry.ParentStakeID))
		if parentPostEntry == nil {
			return nil, nil, errors.Wrapf(
				RuleErrorSubmitPostParentNotFound,
				"_getParentAndGrandparentPostEntry: failed to find parent post for post hash: %v, parentStakeId: %v",
				postEntry.PostHash, hex.EncodeToString(postEntry.ParentStakeID),
			)
		}
	}

	if parentPostEntry != nil && len(parentPostEntry.ParentStakeID) == HashSizeBytes {
		grandparentPostEntry = bav.GetPostEntryForPostHash(NewBlockHash(parentPostEntry.ParentStakeID))
		if grandparentPostEntry == nil {
			return nil, nil, errors.Wrapf(
				RuleErrorSubmitPostParentNotFound,
				"_getParentAndGrandparentPostEntry: failed to find grandparent post for post hash: %v, parentStakeId: %v, grandparentStakeId: %v",
				postEntry.PostHash, postEntry.ParentStakeID, parentPostEntry.ParentStakeID,
			)
		}
	}

	return parentPostEntry, grandparentPostEntry, nil
}

// Adds amount to the repost count of the post at repostPostHash
func (bav *UtxoView) _updateRepostCount(repostedPost *PostEntry, amount int) {
	result := int(repostedPost.RepostCount) + amount

	// Repost count should never be below 0.
	if result < 0 {
		glog.Errorf("_updateRepostCountForPost: RepostCount < 0 for result %v, repost post hash: %v, amount : %v",
			result, repostedPost, amount)
		result = 0
	}
	repostedPost.RepostCount = uint64(result)

}

// Adds amount to the quote repost count of the post at repostPostHash
func (bav *UtxoView) _updateQuoteRepostCount(repostedPost *PostEntry, amount int) {
	result := int(repostedPost.QuoteRepostCount) + amount

	// Repost count should never be below 0.
	if result < 0 {
		glog.Errorf("_updateQuoteRepostCountForPost: QuoteRepostCount < 0 for result %v, repost post hash: %v, amount : %v",
			result, repostedPost, amount)
		result = 0
	}
	repostedPost.QuoteRepostCount = uint64(result)

}

func (bav *UtxoView) _updateParentCommentCountForPost(postEntry *PostEntry, parentPostEntry *PostEntry, amountToChangeParentBy int) {
	result := int(parentPostEntry.CommentCount) + amountToChangeParentBy
	if result < 0 {
		glog.Errorf("_updateParentCommentCountForPost: CommentCount < 0 for result %v, postEntry hash: %v, parentPostEntry hash: %v, amountToChangeParentBy: %v",
			result, postEntry.PostHash, parentPostEntry.PostHash, amountToChangeParentBy)
		result = 0
	}

	parentPostEntry.CommentCount = uint64(result)
}

func (bav *UtxoView) _connectUpdateProfile(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool,
	ignoreUtxos bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeUpdateProfile {
		return 0, 0, nil, fmt.Errorf("_connectUpdateProfile: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*UpdateProfileMetadata)

	// See comment on ForgivenProfileUsernameClaims. This fixes a bug in the blockchain
	// where users could claim usernames that weren't actually available.
	if forgivenUsername, exists := ForgivenProfileUsernameClaims[*txHash]; exists {
		// Make a copy of txMeta and assign it to the existing txMeta so we avoid
		// modifying the fields.
		newTxMeta := *txMeta
		newTxMeta.NewUsername = []byte(forgivenUsername)
		txMeta = &newTxMeta
	}

	// Validate the fields to make sure they don't exceed our limits.
	if uint64(len(txMeta.NewUsername)) > bav.Params.MaxUsernameLengthBytes {
		return 0, 0, nil, RuleErrorProfileUsernameTooLong
	}
	if uint64(len(txMeta.NewDescription)) > bav.Params.MaxUserDescriptionLengthBytes {
		return 0, 0, nil, RuleErrorProfileDescriptionTooLong
	}
	if uint64(len(txMeta.NewProfilePic)) > bav.Params.MaxProfilePicLengthBytes {
		return 0, 0, nil, RuleErrorMaxProfilePicSize
	}
	if txMeta.NewCreatorBasisPoints > bav.Params.MaxCreatorBasisPoints || txMeta.NewCreatorBasisPoints < 0 {
		return 0, 0, nil, RuleErrorProfileCreatorPercentageSize
	}
	if txMeta.NewStakeMultipleBasisPoints <= 100*100 ||
		txMeta.NewStakeMultipleBasisPoints > bav.Params.MaxStakeMultipleBasisPoints {

		return 0, 0, nil, RuleErrorProfileStakeMultipleSize
	}
	// If a username is set then it must adhere to a particular regex.
	if len(txMeta.NewUsername) != 0 && !UsernameRegex.Match(txMeta.NewUsername) {
		return 0, 0, nil, errors.Wrapf(RuleErrorInvalidUsername, "Username: %v", string(txMeta.NewUsername))
	}

	profilePublicKey := txn.PublicKey
	_, updaterIsParamUpdater := bav.Params.ParamUpdaterPublicKeys[MakePkMapKey(txn.PublicKey)]
	if len(txMeta.ProfilePublicKey) != 0 {
		if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
			return 0, 0, nil, errors.Wrapf(RuleErrorProfilePublicKeySize, "_connectUpdateProfile: %#v", txMeta.ProfilePublicKey)
		}
		_, err := btcec.ParsePubKey(txMeta.ProfilePublicKey, btcec.S256())
		if err != nil {
			return 0, 0, nil, errors.Wrapf(RuleErrorProfileBadPublicKey, "_connectUpdateProfile: %v", err)
		}
		profilePublicKey = txMeta.ProfilePublicKey

		if blockHeight > UpdateProfileFixBlockHeight {
			// Make sure that either (1) the profile pub key is the txn signer's  public key or
			// (2) the signer is a param updater
			if !reflect.DeepEqual(txn.PublicKey, txMeta.ProfilePublicKey) && !updaterIsParamUpdater {

				return 0, 0, nil, errors.Wrapf(
					RuleErrorProfilePubKeyNotAuthorized,
					"_connectUpdateProfile: Profile pub key: %v, signer public key: %v",
					PkToStringBoth(txn.PublicKey), PkToStringBoth(txMeta.ProfilePublicKey))
			}
		}
	}

	// If a profile with this username exists already AND if that profile
	// belongs to another public key then that's an error.
	if len(txMeta.NewUsername) != 0 {
		// Note that this check is case-insensitive
		existingProfileEntry := bav.GetProfileEntryForUsername(txMeta.NewUsername)
		if existingProfileEntry != nil && !existingProfileEntry.isDeleted &&
			!reflect.DeepEqual(existingProfileEntry.PublicKey, profilePublicKey) {

			return 0, 0, nil, errors.Wrapf(
				RuleErrorProfileUsernameExists, "Username: %v, TxHashHex: %v",
				string(txMeta.NewUsername), hex.EncodeToString(txHash[:]))
		}
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	//
	// The ignoreUtxos flag is used to connect "seed" transactions when initializing
	// the blockchain. It allows us to "seed" the database with posts and profiles
	// when we do a hard fork, without having the transactions rejected due to their
	// not being spendable.
	var totalInput, totalOutput uint64
	var utxoOpsForTxn = []*UtxoOperation{}
	var err error
	if !ignoreUtxos {
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectBasicTransfer(
			txn, txHash, blockHeight, verifySignatures)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectUpdateProfile: ")
		}

		// Force the input to be non-zero so that we can prevent replay attacks.
		if totalInput == 0 {
			return 0, 0, nil, RuleErrorProfileUpdateRequiresNonZeroInput
		}
	}

	// See if a profile already exists for this public key.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(profilePublicKey)
	// If we are creating a profile for the first time, assess the create profile fee.
	if existingProfileEntry == nil {
		createProfileFeeNanos := bav.GlobalParamsEntry.CreateProfileFeeNanos
		totalOutput += createProfileFeeNanos
		if totalInput < totalOutput {
			return 0, 0, nil, RuleErrorCreateProfileTxnOutputExceedsInput
		}
	}
	// Save a copy of the profile entry so so that we can safely modify it.
	var prevProfileEntry *ProfileEntry
	if existingProfileEntry != nil {
		// NOTE: The only pointer in here is the StakeEntry and CoinEntry pointer, but since
		// this is not modified below we don't need to make a copy of it.
		prevProfileEntry = &ProfileEntry{}
		*prevProfileEntry = *existingProfileEntry
	}

	// This is an adjustment factor that we track for Rosetta. It adjusts
	// the amount of DeSo to make up for a bug whereby a profile's DeSo locked
	// could get clobbered during a ParamUpdater txn.
	clobberedProfileBugDeSoAdjustment := uint64(0)

	// If a profile already exists then we only update fields that are set.
	var newProfileEntry ProfileEntry
	if existingProfileEntry != nil && !existingProfileEntry.isDeleted {
		newProfileEntry = *existingProfileEntry

		// Modifying a profile is only allowed if the transaction public key equals
		// the profile public key or if the public key belongs to a paramUpdater.
		_, updaterIsParamUpdater := bav.Params.ParamUpdaterPublicKeys[MakePkMapKey(txn.PublicKey)]
		if !reflect.DeepEqual(txn.PublicKey, existingProfileEntry.PublicKey) &&
			!updaterIsParamUpdater {

			return 0, 0, nil, errors.Wrapf(
				RuleErrorProfileModificationNotAuthorized,
				"_connectUpdateProfile: Profile: %v, profile public key: %v, "+
					"txn public key: %v, paramUpdater: %v", existingProfileEntry,
				PkToStringBoth(existingProfileEntry.PublicKey),
				PkToStringBoth(txn.PublicKey), spew.Sdump(bav.Params.ParamUpdaterPublicKeys))
		}

		// Only set the fields if they have non-zero length. Otherwise leave
		// them untouched.
		if len(txMeta.NewUsername) != 0 {
			newProfileEntry.Username = txMeta.NewUsername
		}
		if len(txMeta.NewDescription) != 0 {
			newProfileEntry.Description = txMeta.NewDescription
		}
		if len(txMeta.NewProfilePic) != 0 {
			newProfileEntry.ProfilePic = txMeta.NewProfilePic
		}
		// TODO: Right now a profile can be undeleted by the owner of the profile,
		// which seems like undesired behavior if a paramUpdater is trying to reduce
		// spam
		newProfileEntry.IsHidden = txMeta.IsHidden

		// Just always set the creator basis points and stake multiple.
		newProfileEntry.CreatorBasisPoints = txMeta.NewCreatorBasisPoints

		// The StakeEntry is always left unmodified here.

	} else {
		// When there's no pre-existing profile entry we need to do more
		// checks.
		if len(txMeta.NewUsername) == 0 {
			return 0, 0, nil, RuleErrorProfileUsernameTooShort
		}
		// We allow users to create profiles without a description or picture
		// in the consensus code. If desired, frontends can filter out profiles
		// that don't have these fields.
		//
		// Creator percentage and stake multiple are sufficiently checked above.

		// In this case we need to set all the fields using what was passed
		// into the transaction.

		// If below block height, use transaction public key.
		// If above block height, use ProfilePublicKey if available.
		profileEntryPublicKey := txn.PublicKey
		if blockHeight > ParamUpdaterProfileUpdateFixBlockHeight {
			profileEntryPublicKey = profilePublicKey
		} else if !reflect.DeepEqual(txn.PublicKey, txMeta.ProfilePublicKey) {
			// In this case a clobbering will occur if there was a pre-existing profile
			// associated with txn.PublicKey. In this case, we save the
			// DESO locked of the previous profile associated with the
			// txn.PublicKey. Sorry this is confusing...

			// Look up the profile of the txn.PublicKey
			clobberedProfileEntry := bav.GetProfileEntryForPublicKey(txn.PublicKey)
			// Save the amount of DESO locked in the profile since this is going to
			// be clobbered.
			if clobberedProfileEntry != nil && !clobberedProfileEntry.isDeleted {
				clobberedProfileBugDeSoAdjustment = clobberedProfileEntry.CoinEntry.DeSoLockedNanos
			}
		}

		newProfileEntry = ProfileEntry{
			PublicKey:   profileEntryPublicKey,
			Username:    txMeta.NewUsername,
			Description: txMeta.NewDescription,
			ProfilePic:  txMeta.NewProfilePic,

			CoinEntry: CoinEntry{
				CreatorBasisPoints: txMeta.NewCreatorBasisPoints,

				// The other coin fields are automatically set to zero, which is an
				// appropriate default value for all of them.
			},
		}

	}
	// At this point the newProfileEntry should be set to what we actually
	// want to store in the db.

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the poster's
		// public key.
	}

	// Delete the old profile mappings. Not doing this could cause a username
	// change to have outdated mappings, among other things.
	if prevProfileEntry != nil {
		bav._deleteProfileEntryMappings(prevProfileEntry)
	}

	// Save the profile entry now that we've updated it or created it from scratch.
	bav._setProfileEntryMappings(&newProfileEntry)

	// Add an operation to the list at the end indicating we've updated a profile.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                               OperationTypeUpdateProfile,
		PrevProfileEntry:                   prevProfileEntry,
		ClobberedProfileBugDESOLockedNanos: clobberedProfileBugDeSoAdjustment,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectCreateNFT(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {
	if bav.GlobalParamsEntry.MaxCopiesPerNFT == 0 {
		return 0, 0, nil, fmt.Errorf("_connectCreateNFT: called with zero MaxCopiesPerNFT")
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCreateNFT {
		return 0, 0, nil, fmt.Errorf("_connectCreateNFT: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*CreateNFTMetadata)

	// Validate the txMeta.
	if txMeta.NumCopies > bav.GlobalParamsEntry.MaxCopiesPerNFT {
		return 0, 0, nil, RuleErrorTooManyNFTCopies
	}
	if txMeta.NumCopies == 0 {
		return 0, 0, nil, RuleErrorNFTMustHaveNonZeroCopies
	}
	// Make sure we won't oveflow when we add the royalty basis points.
	if math.MaxUint64-txMeta.NFTRoyaltyToCreatorBasisPoints < txMeta.NFTRoyaltyToCoinBasisPoints {
		return 0, 0, nil, RuleErrorNFTRoyaltyOverflow
	}
	royaltyBasisPoints := txMeta.NFTRoyaltyToCreatorBasisPoints + txMeta.NFTRoyaltyToCoinBasisPoints
	if royaltyBasisPoints > bav.Params.MaxNFTRoyaltyBasisPoints {
		return 0, 0, nil, RuleErrorNFTRoyaltyHasTooManyBasisPoints
	}
	postEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	if postEntry == nil || postEntry.isDeleted {
		return 0, 0, nil, RuleErrorCreateNFTOnNonexistentPost
	}
	if IsVanillaRepost(postEntry) {
		return 0, 0, nil, RuleErrorCreateNFTOnVanillaRepost
	}
	if !reflect.DeepEqual(postEntry.PosterPublicKey, txn.PublicKey) {
		return 0, 0, nil, RuleErrorCreateNFTMustBeCalledByPoster
	}
	if postEntry.IsNFT {
		return 0, 0, nil, RuleErrorCreateNFTOnPostThatAlreadyIsNFT
	}
	profileEntry := bav.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
	if profileEntry == nil || profileEntry.isDeleted {
		return 0, 0, nil, RuleErrorCantCreateNFTWithoutProfileEntry
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectCreateNFT: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorCreateNFTRequiresNonZeroInput
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the poster's
		// public key.
	}

	// Since issuing N copies of an NFT multiplies the downstream processing overhead by N,
	// we charge a fee for each additional copy minted.
	// We do not need to check for overflow as these values are managed by the ParamUpdater.
	nftFee := txMeta.NumCopies * bav.GlobalParamsEntry.CreateNFTFeeNanos

	// Sanity check overflow and then ensure that the transaction covers the NFT fee.
	if math.MaxUint64-totalOutput < nftFee {
		return 0, 0, nil, fmt.Errorf("_connectCreateNFTFee: nft Fee overflow")
	}
	totalOutput += nftFee
	if totalInput < totalOutput {
		return 0, 0, nil, RuleErrorCreateNFTWithInsufficientFunds
	}

	// Save a copy of the post entry so that we can safely modify it.
	prevPostEntry := &PostEntry{}
	*prevPostEntry = *postEntry

	// Update and save the post entry.
	postEntry.IsNFT = true
	postEntry.NumNFTCopies = txMeta.NumCopies
	if txMeta.IsForSale {
		postEntry.NumNFTCopiesForSale = txMeta.NumCopies
	}
	postEntry.HasUnlockable = txMeta.HasUnlockable
	postEntry.NFTRoyaltyToCreatorBasisPoints = txMeta.NFTRoyaltyToCreatorBasisPoints
	postEntry.NFTRoyaltyToCoinBasisPoints = txMeta.NFTRoyaltyToCoinBasisPoints
	bav._setPostEntryMappings(postEntry)

	posterPKID := bav.GetPKIDForPublicKey(postEntry.PosterPublicKey)
	if posterPKID == nil || posterPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectCreateNFT: non-existent posterPKID: %s",
			PkToString(postEntry.PosterPublicKey, bav.Params))
	}

	// Add the appropriate NFT entries.
	for ii := uint64(1); ii <= txMeta.NumCopies; ii++ {
		nftEntry := &NFTEntry{
			OwnerPKID:         posterPKID.PKID,
			NFTPostHash:       txMeta.NFTPostHash,
			SerialNumber:      ii,
			IsForSale:         txMeta.IsForSale,
			MinBidAmountNanos: txMeta.MinBidAmountNanos,
		}
		bav._setNFTEntryMappings(nftEntry)
	}

	// Add an operation to the utxoOps list indicating we've created an NFT.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:          OperationTypeCreateNFT,
		PrevPostEntry: prevPostEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectUpdateNFT(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {
	if bav.GlobalParamsEntry.MaxCopiesPerNFT == 0 {
		return 0, 0, nil, fmt.Errorf("_connectUpdateNFT: called with zero MaxCopiesPerNFT")
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeUpdateNFT {
		return 0, 0, nil, fmt.Errorf("_connectUpdateNFT: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*UpdateNFTMetadata)

	// Verify the NFT entry exists.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	prevNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if prevNFTEntry == nil || prevNFTEntry.isDeleted {
		return 0, 0, nil, RuleErrorCannotUpdateNonExistentNFT
	}

	// Verify the NFT is not a pending transfer.
	if prevNFTEntry.IsPending {
		return 0, 0, nil, RuleErrorCannotUpdatePendingNFTTransfer
	}

	// Get the postEntry so we can update the number of NFT copies for sale.
	postEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	if postEntry == nil || postEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectUpdateNFT: non-existent postEntry for NFTPostHash: %s",
			txMeta.NFTPostHash.String())
	}

	// Verify that the updater is the owner of the NFT.
	updaterPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectUpdateNFT: non-existent updaterPKID: %s",
			PkToString(txn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(prevNFTEntry.OwnerPKID, updaterPKID.PKID) {
		return 0, 0, nil, RuleErrorUpdateNFTByNonOwner
	}

	// Sanity check that the NFT entry is correct.
	if !reflect.DeepEqual(prevNFTEntry.NFTPostHash, txMeta.NFTPostHash) ||
		!reflect.DeepEqual(prevNFTEntry.SerialNumber, txMeta.SerialNumber) {
		return 0, 0, nil, fmt.Errorf("_connectUpdateNFT: prevNFTEntry %v is inconsistent with txMeta %v;"+
			" this should never happen.", prevNFTEntry, txMeta)
	}

	// At the moment, updates can only be made if the 'IsForSale' status of the NFT is changing.
	// As a result, you cannot change the MinBidAmountNanos of an NFT while it is for sale.
	if prevNFTEntry.IsForSale == txMeta.IsForSale {
		return 0, 0, nil, RuleErrorNFTUpdateMustUpdateIsForSaleStatus
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUpdateNFT: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorUpdateNFTRequiresNonZeroInput
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the poster's
		// public key.
	}

	// Now we are ready to update the NFT. Three things must happen:
	// 	(1) Update the NFT entry.
	//  (2) If the NFT entry is being updated to "is not for sale", kill all the bids.
	//  (3) Update the number of NFT copies for sale on the post entry.

	// Create the updated NFTEntry.
	newNFTEntry := &NFTEntry{
		LastOwnerPKID:     prevNFTEntry.LastOwnerPKID,
		OwnerPKID:         updaterPKID.PKID,
		NFTPostHash:       txMeta.NFTPostHash,
		SerialNumber:      txMeta.SerialNumber,
		IsForSale:         txMeta.IsForSale,
		MinBidAmountNanos: txMeta.MinBidAmountNanos,
		UnlockableText:    prevNFTEntry.UnlockableText,
		// Keep the last accepted bid amount nanos from the previous entry since this
		// value is only updated when a new bid is accepted.
		LastAcceptedBidAmountNanos: prevNFTEntry.LastAcceptedBidAmountNanos,
	}
	bav._setNFTEntryMappings(newNFTEntry)

	// If we are going from ForSale->NotForSale, delete all the NFTBidEntries for this NFT.
	deletedBidEntries := []*NFTBidEntry{}
	if prevNFTEntry.IsForSale && !txMeta.IsForSale {
		bidEntries := bav.GetAllNFTBidEntries(txMeta.NFTPostHash, txMeta.SerialNumber)
		for _, bidEntry := range bidEntries {
			deletedBidEntries = append(deletedBidEntries, bidEntry)
			bav._deleteNFTBidEntryMappings(bidEntry)
		}
	}

	// Save a copy of the post entry so that we can safely modify it.
	prevPostEntry := &PostEntry{}
	*prevPostEntry = *postEntry

	// Update the number of NFT copies that are for sale.
	if prevNFTEntry.IsForSale && !txMeta.IsForSale {
		// For sale --> Not for sale.
		postEntry.NumNFTCopiesForSale--
	} else if !prevNFTEntry.IsForSale && txMeta.IsForSale {
		// Not for sale --> For sale.
		postEntry.NumNFTCopiesForSale++
	}

	// Set the new postEntry.
	bav._setPostEntryMappings(postEntry)

	// Add an operation to the list at the end indicating we've connected an NFT update.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                 OperationTypeUpdateNFT,
		PrevNFTEntry:         prevNFTEntry,
		PrevPostEntry:        prevPostEntry,
		DeletedNFTBidEntries: deletedBidEntries,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectAcceptNFTBid(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {
	if bav.GlobalParamsEntry.MaxCopiesPerNFT == 0 {
		return 0, 0, nil, fmt.Errorf("_connectAcceptNFTBid: called with zero MaxCopiesPerNFT")
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeAcceptNFTBid {
		return 0, 0, nil, fmt.Errorf("_connectAcceptNFTBid: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*AcceptNFTBidMetadata)

	// Verify the NFT entry that is being bid on exists and is on sale.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	prevNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if prevNFTEntry == nil || prevNFTEntry.isDeleted {
		// We wrap these errors in order to differentiate versus _connectNFTBid().
		return 0, 0, nil, errors.Wrapf(RuleErrorNFTBidOnNonExistentNFTEntry, "_connectAcceptNFTBid: ")
	}
	if !prevNFTEntry.IsForSale {
		return 0, 0, nil, errors.Wrapf(RuleErrorNFTBidOnNFTThatIsNotForSale, "_connectAcceptNFTBid: ")
	}

	// Verify the NFT is not a pending transfer.
	if prevNFTEntry.IsPending {
		return 0, 0, nil, RuleErrorCannotAcceptBidForPendingNFTTransfer
	}

	// Verify that the updater is the owner of the NFT.
	updaterPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectAcceptNFTBid: non-existent updaterPKID: %s",
			PkToString(txn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(prevNFTEntry.OwnerPKID, updaterPKID.PKID) {
		return 0, 0, nil, RuleErrorAcceptNFTBidByNonOwner
	}

	// Get the post entry, verify it exists.
	nftPostEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)

	// If this is an unlockable NFT, make sure that an unlockable string was provided.
	if nftPostEntry == nil || nftPostEntry.isDeleted {
		return 0, 0, nil, RuleErrorPostEntryNotFoundForAcceptedNFTBid
	}
	if nftPostEntry.HasUnlockable && len(txMeta.UnlockableText) == 0 {
		return 0, 0, nil, RuleErrorUnlockableNFTMustProvideUnlockableText
	}

	// Check the length of the UnlockableText.
	if uint64(len(txMeta.UnlockableText)) > bav.Params.MaxPrivateMessageLengthBytes {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorUnlockableTextLengthExceedsMax, "_connectAcceptNFTBid: "+
				"UnlockableTextLen = %d; Max length = %d",
			len(txMeta.UnlockableText), bav.Params.MaxPrivateMessageLengthBytes)
	}

	// Get the poster's profile.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(nftPostEntry.PosterPublicKey)
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: Profile missing for NFT pub key: %v %v",
			PkToStringMainnet(nftPostEntry.PosterPublicKey), PkToStringTestnet(nftPostEntry.PosterPublicKey))
	}
	// Save all the old values from the CoinEntry before we potentially
	// update them. Note that CoinEntry doesn't contain any pointers and so
	// a direct copy is OK.
	prevCoinEntry := existingProfileEntry.CoinEntry

	// Verify the NFT bid entry being accepted exists and has a bid consistent with the metadata.
	// If we did not require an AcceptNFTBid txn to have a bid amount, it would leave the door
	// open for an attack where someone replaces a high bid with a low bid after the owner accepts.
	nftBidKey := MakeNFTBidKey(txMeta.BidderPKID, txMeta.NFTPostHash, txMeta.SerialNumber)
	nftBidEntry := bav.GetNFTBidEntryForNFTBidKey(&nftBidKey)
	if nftBidEntry == nil || nftBidEntry.isDeleted {
		// NOTE: Users can submit a bid for SerialNumber zero as a blanket bid for any SerialNumber
		// in an NFT collection. Thus, we must check to see if a SerialNumber zero bid exists
		// for this bidder before we return an error.
		nftBidKey = MakeNFTBidKey(txMeta.BidderPKID, txMeta.NFTPostHash, uint64(0))
		nftBidEntry = bav.GetNFTBidEntryForNFTBidKey(&nftBidKey)
		if nftBidEntry == nil || nftBidEntry.isDeleted {
			return 0, 0, nil, RuleErrorCantAcceptNonExistentBid
		}
	}
	if nftBidEntry.BidAmountNanos != txMeta.BidAmountNanos {
		return 0, 0, nil, RuleErrorAcceptedNFTBidAmountDoesNotMatch
	}

	bidderPublicKey := bav.GetPublicKeyForPKID(txMeta.BidderPKID)

	//
	// Store starting balances of all the participants to check diff later.
	//
	// We assume the tip is right before the block in which this txn is about to be applied.
	tipHeight := uint32(0)
	if blockHeight > 0 {
		tipHeight = blockHeight - 1
	}
	sellerBalanceBefore, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(txn.PublicKey, tipHeight)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: Problem getting initial balance for seller pubkey: %v",
			PkToStringBoth(txn.PublicKey))
	}
	bidderBalanceBefore, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(
		bidderPublicKey, tipHeight)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: Problem getting initial balance for bidder pubkey: %v",
			PkToStringBoth(bidderPublicKey))
	}
	creatorBalanceBefore, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(
		nftPostEntry.PosterPublicKey, tipHeight)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: Problem getting initial balance for poster pubkey: %v",
			PkToStringBoth(nftPostEntry.PosterPublicKey))
	}

	//
	// Validate bidder UTXOs.
	//
	if len(txMeta.BidderInputs) == 0 {
		return 0, 0, nil, RuleErrorAcceptedNFTBidMustSpecifyBidderInputs
	}
	totalBidderInput := uint64(0)
	spentUtxoEntries := []*UtxoEntry{}
	utxoOpsForTxn := []*UtxoOperation{}
	for _, bidderInput := range txMeta.BidderInputs {
		bidderUtxoKey := UtxoKey(*bidderInput)
		bidderUtxoEntry := bav.GetUtxoEntryForUtxoKey(&bidderUtxoKey)
		if bidderUtxoEntry == nil || bidderUtxoEntry.isSpent {
			return 0, 0, nil, RuleErrorBidderInputForAcceptedNFTBidNoLongerExists
		}

		// Make sure that the utxo specified is actually from the bidder.
		if !reflect.DeepEqual(bidderUtxoEntry.PublicKey, bidderPublicKey) {
			return 0, 0, nil, RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey
		}

		// If the utxo is from a block reward txn, make sure enough time has passed to
		// make it spendable.
		if _isEntryImmatureBlockReward(bidderUtxoEntry, blockHeight, bav.Params) {
			return 0, 0, nil, RuleErrorInputSpendsImmatureBlockReward
		}
		totalBidderInput += bidderUtxoEntry.AmountNanos

		// Make sure we spend the utxo so that the bidder can't reuse it.
		utxoOp, err := bav._spendUtxo(&bidderUtxoKey)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAcceptNFTBid: Problem spending bidder utxo")
		}
		spentUtxoEntries = append(spentUtxoEntries, bidderUtxoEntry)

		// Track the UtxoOperations so we can rollback, and for Rosetta
		utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
	}

	if totalBidderInput < txMeta.BidAmountNanos {
		return 0, 0, nil, RuleErrorAcceptNFTBidderInputsInsufficientForBidAmount
	}

	// The bidder gets back any unspent nanos from the inputs specified.
	bidderChangeNanos := totalBidderInput - txMeta.BidAmountNanos
	// The amount of deso that should go to the original creator from this purchase.
	// Calculated as: (BidAmountNanos * NFTRoyaltyToCreatorBasisPoints) / (100 * 100)
	creatorRoyaltyNanos := IntDiv(
		IntMul(
			big.NewInt(int64(txMeta.BidAmountNanos)),
			big.NewInt(int64(nftPostEntry.NFTRoyaltyToCreatorBasisPoints))),
		big.NewInt(100*100)).Uint64()
	// The amount of deso that should go to the original creator's coin from this purchase.
	// Calculated as: (BidAmountNanos * NFTRoyaltyToCoinBasisPoints) / (100 * 100)
	creatorCoinRoyaltyNanos := IntDiv(
		IntMul(
			big.NewInt(int64(txMeta.BidAmountNanos)),
			big.NewInt(int64(nftPostEntry.NFTRoyaltyToCoinBasisPoints))),
		big.NewInt(100*100)).Uint64()
	//glog.Infof("Bid amount: %d, coin basis points: %d, coin royalty: %d",
	//	txMeta.BidAmountNanos, nftPostEntry.NFTRoyaltyToCoinBasisPoints, creatorCoinRoyaltyNanos)

	// Sanity check that the royalties are reasonable and won't cause underflow.
	if txMeta.BidAmountNanos < (creatorRoyaltyNanos + creatorCoinRoyaltyNanos) {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: sum of royalties (%d, %d) is less than bid amount (%d)",
			creatorRoyaltyNanos, creatorCoinRoyaltyNanos, txMeta.BidAmountNanos)
	}

	bidAmountMinusRoyalties := txMeta.BidAmountNanos - creatorRoyaltyNanos - creatorCoinRoyaltyNanos

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsFromBasicTransfer, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAcceptNFTBid: ")
	}
	// Append the basic transfer utxoOps to our list
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOpsFromBasicTransfer...)

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorAcceptNFTBidRequiresNonZeroInput
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the poster's
		// public key.
	}

	// Now we are ready to accept the bid. When we accept, the following must happen:
	// 	(1) Update the nft entry with the new owner and set it as "not for sale".
	//  (2) Delete all of the bids on this NFT since they are no longer relevant.
	//  (3) Pay the seller.
	//  (4) Pay royalties to the original creator.
	//  (5) Pay change to the bidder.
	//  (6) Add creator coin royalties to deso locked.
	//  (7) Decrement the nftPostEntry NumNFTCopiesForSale.

	// (1) Set an appropriate NFTEntry for the new owner.

	newNFTEntry := &NFTEntry{
		LastOwnerPKID:  updaterPKID.PKID,
		OwnerPKID:      txMeta.BidderPKID,
		NFTPostHash:    txMeta.NFTPostHash,
		SerialNumber:   txMeta.SerialNumber,
		IsForSale:      false,
		UnlockableText: txMeta.UnlockableText,

		LastAcceptedBidAmountNanos: txMeta.BidAmountNanos,
	}
	bav._setNFTEntryMappings(newNFTEntry)

	// append the accepted bid entry to the list of accepted bid entries
	prevAcceptedBidHistory := bav.GetAcceptNFTBidHistoryForNFTKey(&nftKey)
	newAcceptedBidHistory := append(*prevAcceptedBidHistory, nftBidEntry)
	bav._setAcceptNFTBidHistoryMappings(nftKey, &newAcceptedBidHistory)

	// (2) Iterate over all the NFTBidEntries for this NFT and delete them.
	bidEntries := bav.GetAllNFTBidEntries(txMeta.NFTPostHash, txMeta.SerialNumber)
	if len(bidEntries) == 0 && nftBidEntry.SerialNumber != 0 {
		// Quick sanity check to make sure that we found bid entries. There should be at least 1.
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: found zero bid entries to delete; this should never happen.")
	}
	deletedBidEntries := []*NFTBidEntry{}
	for _, bidEntry := range bidEntries {
		deletedBidEntries = append(deletedBidEntries, bidEntry)
		bav._deleteNFTBidEntryMappings(bidEntry)
	}
	// If this is a SerialNumber zero BidEntry, we must delete it specifically.
	if nftBidEntry.SerialNumber == uint64(0) {
		deletedBidEntries = append(deletedBidEntries, nftBidEntry)
		bav._deleteNFTBidEntryMappings(nftBidEntry)
	}

	// (3) Pay the seller by creating a new entry for this output and add it to the view.
	nftPaymentUtxoKeys := []*UtxoKey{}
	nextUtxoIndex := uint32(len(txn.TxOutputs))
	sellerOutputKey := &UtxoKey{
		TxID:  *txHash,
		Index: nextUtxoIndex,
	}

	utxoEntry := UtxoEntry{
		AmountNanos: bidAmountMinusRoyalties,
		PublicKey:   txn.PublicKey,
		BlockHeight: blockHeight,
		UtxoType:    UtxoTypeNFTSeller,
		UtxoKey:     sellerOutputKey,
		// We leave the position unset and isSpent to false by default.
		// The position will be set in the call to _addUtxo.
	}

	// Create a new scope to avoid name collisions
	{
		utxoOp, err := bav._addUtxo(&utxoEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(
				err, "_connectAcceptNFTBid: Problem adding output utxo")
		}
		nftPaymentUtxoKeys = append(nftPaymentUtxoKeys, sellerOutputKey)

		// Rosetta uses this UtxoOperation to provide INPUT amounts
		utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
	}

	// (4) Pay royalties to the original artist.
	if creatorRoyaltyNanos > 0 {
		nextUtxoIndex += 1
		royaltyOutputKey := &UtxoKey{
			TxID:  *txHash,
			Index: nextUtxoIndex,
		}

		utxoEntry := UtxoEntry{
			AmountNanos: creatorRoyaltyNanos,
			PublicKey:   nftPostEntry.PosterPublicKey,
			BlockHeight: blockHeight,
			UtxoType:    UtxoTypeNFTCreatorRoyalty,

			UtxoKey: royaltyOutputKey,
			// We leave the position unset and isSpent to false by default.
			// The position will be set in the call to _addUtxo.
		}

		utxoOp, err := bav._addUtxo(&utxoEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAcceptNFTBid: Problem adding output utxo")
		}
		nftPaymentUtxoKeys = append(nftPaymentUtxoKeys, royaltyOutputKey)

		// Rosetta uses this UtxoOperation to provide INPUT amounts
		utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
	}

	// (5) Give any change back to the bidder.
	if bidderChangeNanos > 0 {
		nextUtxoIndex += 1
		bidderChangeOutputKey := &UtxoKey{
			TxID:  *txHash,
			Index: nextUtxoIndex,
		}

		utxoEntry := UtxoEntry{
			AmountNanos: bidderChangeNanos,
			PublicKey:   bidderPublicKey,
			BlockHeight: blockHeight,
			UtxoType:    UtxoTypeNFTCreatorRoyalty,

			UtxoKey: bidderChangeOutputKey,
			// We leave the position unset and isSpent to false by default.
			// The position will be set in the call to _addUtxo.
		}

		utxoOp, err := bav._addUtxo(&utxoEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAcceptNFTBid: Problem adding output utxo")
		}
		nftPaymentUtxoKeys = append(nftPaymentUtxoKeys, bidderChangeOutputKey)

		// Rosetta uses this UtxoOperation to provide INPUT amounts
		utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
	}

	// We don't do a royalty if the number of coins in circulation is too low.
	if existingProfileEntry.CoinsInCirculationNanos < bav.Params.CreatorCoinAutoSellThresholdNanos {
		creatorCoinRoyaltyNanos = 0
	}

	// (6) Add creator coin royalties to deso locked. If the number of coins in circulation is
	// less than the "auto sell threshold" we burn the deso.
	newCoinEntry := prevCoinEntry
	if creatorCoinRoyaltyNanos > 0 {
		// Make a copy of the previous coin entry. It has no pointers, so a direct copy is ok.
		newCoinEntry.DeSoLockedNanos += creatorCoinRoyaltyNanos
		existingProfileEntry.CoinEntry = newCoinEntry
		bav._setProfileEntryMappings(existingProfileEntry)
	}

	// (7) Save a copy of the previous postEntry and then decrement NumNFTCopiesForSale.
	prevPostEntry := &PostEntry{}
	*prevPostEntry = *nftPostEntry
	nftPostEntry.NumNFTCopiesForSale--
	bav._setPostEntryMappings(nftPostEntry)

	// Add an operation to the list at the end indicating we've connected an NFT bid.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                      OperationTypeAcceptNFTBid,
		PrevNFTEntry:              prevNFTEntry,
		PrevPostEntry:             prevPostEntry,
		PrevCoinEntry:             &prevCoinEntry,
		DeletedNFTBidEntries:      deletedBidEntries,
		NFTPaymentUtxoKeys:        nftPaymentUtxoKeys,
		NFTSpentUtxoEntries:       spentUtxoEntries,
		PrevAcceptedNFTBidEntries: prevAcceptedBidHistory,

		// Rosetta fields.
		AcceptNFTBidCreatorPublicKey:    nftPostEntry.PosterPublicKey,
		AcceptNFTBidBidderPublicKey:     bidderPublicKey,
		AcceptNFTBidCreatorRoyaltyNanos: creatorCoinRoyaltyNanos,
	})

	// HARDCORE SANITY CHECK:
	//  - Before returning we do one more sanity check that money hasn't been printed.
	//
	// Seller balance diff:
	sellerBalanceAfter, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(txn.PublicKey, tipHeight)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: Problem getting final balance for seller pubkey: %v",
			PkToStringBoth(txn.PublicKey))
	}
	sellerDiff := int64(sellerBalanceAfter) - int64(sellerBalanceBefore)
	// Bidder balance diff (only relevant if bidder != seller):
	bidderDiff := int64(0)
	if !reflect.DeepEqual(bidderPublicKey, txn.PublicKey) {
		bidderBalanceAfter, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(bidderPublicKey, tipHeight)
		if err != nil {
			return 0, 0, nil, fmt.Errorf(
				"_connectAcceptNFTBid: Problem getting final balance for bidder pubkey: %v",
				PkToStringBoth(bidderPublicKey))
		}
		bidderDiff = int64(bidderBalanceAfter) - int64(bidderBalanceBefore)
	}
	// Creator balance diff (only relevant if creator != seller and creator != bidder):
	creatorDiff := int64(0)
	if !reflect.DeepEqual(nftPostEntry.PosterPublicKey, txn.PublicKey) &&
		!reflect.DeepEqual(nftPostEntry.PosterPublicKey, bidderPublicKey) {
		creatorBalanceAfter, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(nftPostEntry.PosterPublicKey, tipHeight)
		if err != nil {
			return 0, 0, nil, fmt.Errorf(
				"_connectAcceptNFTBid: Problem getting final balance for poster pubkey: %v",
				PkToStringBoth(nftPostEntry.PosterPublicKey))
		}
		creatorDiff = int64(creatorBalanceAfter) - int64(creatorBalanceBefore)
	}
	// Creator coin diff:
	coinDiff := int64(newCoinEntry.DeSoLockedNanos) - int64(prevCoinEntry.DeSoLockedNanos)
	// Now the actual check. Use bigints to avoid getting fooled by overflow.
	sellerPlusBidderDiff := big.NewInt(0).Add(big.NewInt(sellerDiff), big.NewInt(bidderDiff))
	creatorPlusCoinDiff := big.NewInt(0).Add(big.NewInt(creatorDiff), big.NewInt(coinDiff))
	totalDiff := big.NewInt(0).Add(sellerPlusBidderDiff, creatorPlusCoinDiff)
	if totalDiff.Cmp(big.NewInt(0)) > 0 {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: Sum of participant diffs is >0 (%d, %d, %d, %d)",
			sellerDiff, bidderDiff, creatorDiff, coinDiff)
	}

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectNFTBid(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {
	if bav.GlobalParamsEntry.MaxCopiesPerNFT == 0 {
		return 0, 0, nil, fmt.Errorf("_connectNFTBid: called with zero MaxCopiesPerNFT")
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeNFTBid {
		return 0, 0, nil, fmt.Errorf("_connectNFTBid: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*NFTBidMetadata)

	// Verify that the postEntry being bid on exists, is an NFT, and supports the given serial #.
	postEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	if postEntry == nil || postEntry.isDeleted {
		return 0, 0, nil, RuleErrorNFTBidOnNonExistentPost
	} else if !postEntry.IsNFT {
		return 0, 0, nil, RuleErrorNFTBidOnPostThatIsNotAnNFT
	} else if txMeta.SerialNumber > postEntry.NumNFTCopies {
		return 0, 0, nil, RuleErrorNFTBidOnInvalidSerialNumber
	}

	// Validate the nftEntry.  Note that there is a special case where a bidder can submit a bid
	// on SerialNumber zero.  This acts as a blanket bid on any serial number version of this NFT
	// As a result, the nftEntry will be nil and should not be validated.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	nftEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	bidderPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
	if bidderPKID == nil || bidderPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectNFTBid: PKID for bidder public key %v doesn't exist; this should never happen", string(txn.PublicKey))
	}

	// Save a copy of the bid entry so that we can use it in the disconnect.
	nftBidKey := MakeNFTBidKey(bidderPKID.PKID, txMeta.NFTPostHash, txMeta.SerialNumber)
	prevNFTBidEntry := bav.GetNFTBidEntryForNFTBidKey(&nftBidKey)

	if txMeta.SerialNumber != uint64(0) {
		// Verify the NFT entry that is being bid on exists.
		if nftEntry == nil || nftEntry.isDeleted {
			return 0, 0, nil, RuleErrorNFTBidOnNonExistentNFTEntry
		}

		// Verify the NFT entry being bid on is for sale.
		if !nftEntry.IsForSale {
			return 0, 0, nil, RuleErrorNFTBidOnNFTThatIsNotForSale
		}

		// Verify the NFT is not a pending transfer.
		if nftEntry.IsPending {
			return 0, 0, nil, RuleErrorCannotBidForPendingNFTTransfer
		}

		// Verify that the bidder is not the current owner of the NFT.
		if reflect.DeepEqual(nftEntry.OwnerPKID, bidderPKID.PKID) {
			return 0, 0, nil, RuleErrorNFTOwnerCannotBidOnOwnedNFT
		}

		// Verify that the bid amount is greater than the min bid amount for this NFT.
		// We allow BidAmountNanos to be 0 if there exists a previous bid entry. A value of 0 indicates that we should delete the entry.
		if txMeta.BidAmountNanos < nftEntry.MinBidAmountNanos && !(txMeta.BidAmountNanos == 0 && prevNFTBidEntry != nil) {
			return 0, 0, nil, RuleErrorNFTBidLessThanMinBidAmountNanos
		}
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectNFTBid: ")
	}

	// We assume the tip is right before the block in which this txn is about to be applied.
	tipHeight := uint32(0)
	if blockHeight > 0 {
		tipHeight = blockHeight - 1
	}
	// Verify that the transaction creator has sufficient deso to create the bid.
	spendableBalance, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(txn.PublicKey, tipHeight)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectNFTBid: Error getting bidder balance: ")

	} else if txMeta.BidAmountNanos > spendableBalance && blockHeight > BrokenNFTBidsFixBlockHeight {
		return 0, 0, nil, RuleErrorInsufficientFundsForNFTBid
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorNFTBidRequiresNonZeroInput
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the poster's
		// public key.
	}

	// If an old bid exists, delete it.
	if prevNFTBidEntry != nil {
		bav._deleteNFTBidEntryMappings(prevNFTBidEntry)
	}

	// If the new bid has a non-zero amount, set it.
	if txMeta.BidAmountNanos != 0 {
		// Zero bids are not allowed, submitting a zero bid effectively withdraws a prior bid.
		newBidEntry := &NFTBidEntry{
			BidderPKID:     bidderPKID.PKID,
			NFTPostHash:    txMeta.NFTPostHash,
			SerialNumber:   txMeta.SerialNumber,
			BidAmountNanos: txMeta.BidAmountNanos,
		}
		bav._setNFTBidEntryMappings(newBidEntry)
	}

	// Add an operation to the list at the end indicating we've connected an NFT bid.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:            OperationTypeNFTBid,
		PrevNFTBidEntry: prevNFTBidEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectNFTTransfer(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if blockHeight < NFTTransferOrBurnAndDerivedKeysBlockHeight {
		return 0, 0, nil, RuleErrorNFTTransferBeforeBlockHeight
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeNFTTransfer {
		return 0, 0, nil, fmt.Errorf("_connectNFTTransfer: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*NFTTransferMetadata)

	// Check that the specified receiver public key is valid.
	if len(txMeta.ReceiverPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorNFTTransferInvalidReceiverPubKeySize
	}

	// Check that the sender and receiver public keys are different.
	if reflect.DeepEqual(txn.PublicKey, txMeta.ReceiverPublicKey) {
		return 0, 0, nil, RuleErrorNFTTransferCannotTransferToSelf
	}

	// Verify the NFT entry exists.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	prevNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if prevNFTEntry == nil || prevNFTEntry.isDeleted {
		return 0, 0, nil, RuleErrorCannotTransferNonExistentNFT
	}

	// Verify that the updater is the owner of the NFT.
	updaterPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectNFTTransfer: non-existent updaterPKID: %s",
			PkToString(txn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(prevNFTEntry.OwnerPKID, updaterPKID.PKID) {
		return 0, 0, nil, RuleErrorNFTTransferByNonOwner
	}

	// Fetch the receiver's PKID and make sure it exists.
	receiverPKID := bav.GetPKIDForPublicKey(txMeta.ReceiverPublicKey)
	// Sanity check that we found a PKID entry for these pub keys (should never fail).
	if receiverPKID == nil || receiverPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf(
			"_connectNFTTransfer: Found nil or deleted PKID for receiver, this should never "+
				"happen. Receiver pubkey: %v", PkToStringMainnet(txMeta.ReceiverPublicKey))
	}

	// Make sure that the NFT entry is not for sale.
	if prevNFTEntry.IsForSale {
		return 0, 0, nil, RuleErrorCannotTransferForSaleNFT
	}

	// Sanity check that the NFT entry is correct.
	if !reflect.DeepEqual(prevNFTEntry.NFTPostHash, txMeta.NFTPostHash) ||
		!reflect.DeepEqual(prevNFTEntry.SerialNumber, txMeta.SerialNumber) {
		return 0, 0, nil, fmt.Errorf("_connectNFTTransfer: prevNFTEntry %v is inconsistent with txMeta %v;"+
			" this should never happen.", prevNFTEntry, txMeta)
	}

	// Get the postEntry so we can check for unlockable content.
	nftPostEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	if nftPostEntry == nil || nftPostEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectNFTTransfer: non-existent nftPostEntry for NFTPostHash: %s",
			txMeta.NFTPostHash.String())
	}

	// If the post entry requires the NFT to have unlockable text, make sure it is provided.
	if nftPostEntry.HasUnlockable && len(txMeta.UnlockableText) == 0 {
		return 0, 0, nil, RuleErrorCannotTransferUnlockableNFTWithoutUnlockable
	}

	// Check the length of the UnlockableText.
	if uint64(len(txMeta.UnlockableText)) > bav.Params.MaxPrivateMessageLengthBytes {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorUnlockableTextLengthExceedsMax, "_connectNFTTransfer: "+
				"UnlockableTextLen = %d; Max length = %d",
			len(txMeta.UnlockableText), bav.Params.MaxPrivateMessageLengthBytes)
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectNFTTransfer: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorNFTTransferRequiresNonZeroInput
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the NFT owner's
		// public key.
	}

	// Now we are ready to transfer the NFT.

	// Make a copy of the previous NFT
	newNFTEntry := *prevNFTEntry
	// Update the fields that were set during this transfer.
	newNFTEntry.LastOwnerPKID = prevNFTEntry.OwnerPKID
	newNFTEntry.OwnerPKID = receiverPKID.PKID
	newNFTEntry.UnlockableText = txMeta.UnlockableText
	newNFTEntry.IsPending = true

	// Set the new entry in the view.
	bav._deleteNFTEntryMappings(prevNFTEntry)
	bav._setNFTEntryMappings(&newNFTEntry)

	// Add an operation to the list at the end indicating we've connected an NFT update.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:         OperationTypeNFTTransfer,
		PrevNFTEntry: prevNFTEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectAcceptNFTTransfer(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if blockHeight < NFTTransferOrBurnAndDerivedKeysBlockHeight {
		return 0, 0, nil, RuleErrorAcceptNFTTransferBeforeBlockHeight
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeAcceptNFTTransfer {
		return 0, 0, nil, fmt.Errorf("_connectAcceptNFTTransfer: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*AcceptNFTTransferMetadata)

	// Verify the NFT entry exists.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	prevNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if prevNFTEntry == nil || prevNFTEntry.isDeleted {
		return 0, 0, nil, RuleErrorCannotAcceptTransferOfNonExistentNFT
	}

	// Verify that the updater is the owner of the NFT.
	updaterPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectAcceptNFTTransfer: non-existent updaterPKID: %s",
			PkToString(txn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(prevNFTEntry.OwnerPKID, updaterPKID.PKID) {
		return 0, 0, nil, RuleErrorAcceptNFTTransferByNonOwner
	}

	// Verify that the NFT is actually pending.
	if !prevNFTEntry.IsPending {
		return 0, 0, nil, RuleErrorAcceptNFTTransferForNonPendingNFT
	}

	// Sanity check that the NFT entry is not for sale.
	if prevNFTEntry.IsForSale {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTTransfer: attempted to accept NFT transfer of NFT that is for "+
				"sale. This should never happen; txMeta %v.", txMeta)
	}

	// Sanity check that the NFT entry is correct.
	if !reflect.DeepEqual(prevNFTEntry.NFTPostHash, txMeta.NFTPostHash) ||
		!reflect.DeepEqual(prevNFTEntry.SerialNumber, txMeta.SerialNumber) {
		return 0, 0, nil, fmt.Errorf("_connectAcceptNFTTransfer: prevNFTEntry %v is "+
			"inconsistent with txMeta %v; this should never happen.", prevNFTEntry, txMeta)
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAcceptNFTTransfer: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorAcceptNFTTransferRequiresNonZeroInput
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the NFT owner's
		// public key.
	}

	// Now we are ready to transfer the NFT.

	// Create the updated NFTEntry (everything the same except for IsPending) and set it.
	newNFTEntry := *prevNFTEntry
	newNFTEntry.IsPending = false
	bav._deleteNFTEntryMappings(prevNFTEntry)
	bav._setNFTEntryMappings(&newNFTEntry)

	// Add an operation for the accepted NFT transfer.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:         OperationTypeAcceptNFTTransfer,
		PrevNFTEntry: prevNFTEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectBurnNFT(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if blockHeight < NFTTransferOrBurnAndDerivedKeysBlockHeight {
		return 0, 0, nil, RuleErrorBurnNFTBeforeBlockHeight
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeBurnNFT {
		return 0, 0, nil, fmt.Errorf("_connectBurnNFT: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*BurnNFTMetadata)

	// Verify the NFT entry exists.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	nftEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if nftEntry == nil || nftEntry.isDeleted {
		return 0, 0, nil, RuleErrorCannotBurnNonExistentNFT
	}

	// Verify that the updater is the owner of the NFT.
	updaterPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectBurnNFT: non-existent updaterPKID: %s",
			PkToString(txn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(nftEntry.OwnerPKID, updaterPKID.PKID) {
		return 0, 0, nil, RuleErrorBurnNFTByNonOwner
	}

	// Verify that the NFT is not for sale.
	if nftEntry.IsForSale {
		return 0, 0, nil, RuleErrorCannotBurnNFTThatIsForSale
	}

	// Sanity check that the NFT entry is correct.
	if !reflect.DeepEqual(nftEntry.NFTPostHash, txMeta.NFTPostHash) ||
		!reflect.DeepEqual(nftEntry.SerialNumber, txMeta.SerialNumber) {
		return 0, 0, nil, fmt.Errorf("_connectBurnNFT: nftEntry %v is "+
			"inconsistent with txMeta %v; this should never happen.", nftEntry, txMeta)
	}

	// Get the postEntry so we can increment the burned copies count.
	nftPostEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	if nftPostEntry == nil || nftPostEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf(
			"_connectBurnNFT: non-existent nftPostEntry for NFTPostHash: %s",
			txMeta.NFTPostHash.String())
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectBurnNFT: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorBurnNFTRequiresNonZeroInput
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the NFT owner's
		// public key.
	}

	// Create a backup before we burn the NFT.
	prevNFTEntry := *nftEntry

	// Delete the NFT.
	bav._deleteNFTEntryMappings(nftEntry)

	// Save a copy of the previous postEntry and then increment NumNFTCopiesBurned.
	prevPostEntry := *nftPostEntry
	nftPostEntry.NumNFTCopiesBurned++
	bav._deletePostEntryMappings(&prevPostEntry)
	bav._setPostEntryMappings(nftPostEntry)

	// Add an operation for the burnt NFT.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:          OperationTypeBurnNFT,
		PrevNFTEntry:  &prevNFTEntry,
		PrevPostEntry: &prevPostEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectSwapIdentity(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeSwapIdentity {
		return 0, 0, nil, fmt.Errorf(
			"_connectSwapIdentity: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*SwapIdentityMetadataa)

	// The txn.PublicKey must be paramUpdater
	_, updaterIsParamUpdater := bav.Params.ParamUpdaterPublicKeys[MakePkMapKey(txn.PublicKey)]
	if !updaterIsParamUpdater {
		return 0, 0, nil, RuleErrorSwapIdentityIsParamUpdaterOnly
	}

	// call _connectBasicTransfer to verify signatures
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectSwapIdentity: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorProfileUpdateRequiresNonZeroInput
	}

	// The "from " public key must be set and valid.
	fromPublicKey := txMeta.FromPublicKey
	if len(fromPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorFromPublicKeyIsRequired
	}
	if _, err := btcec.ParsePubKey(fromPublicKey, btcec.S256()); err != nil {
		return 0, 0, nil, errors.Wrap(RuleErrorInvalidFromPublicKey, err.Error())
	}

	// The "to" public key must be set and valid.
	toPublicKey := txMeta.ToPublicKey
	if len(toPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorToPublicKeyIsRequired
	}
	if _, err := btcec.ParsePubKey(toPublicKey, btcec.S256()); err != nil {
		return 0, 0, nil, errors.Wrap(RuleErrorInvalidToPublicKey, err.Error())
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the poster's
		// public key.
	}

	// If a profile is associated with either of the public keys then change the public
	// key embedded in the profile. Note that we don't need to delete and re-add the
	// ProfileEntry mappings because everything other than the embedded public key stays
	// the same (basically the public key is the only thing that's de-normalized that we
	// need to manually adjust). Note that we must do this lookup *before* we swap the
	// PKID's or else we're get opposite profiles back.
	fromProfileEntry := bav.GetProfileEntryForPublicKey(fromPublicKey)
	if fromProfileEntry != nil && !fromProfileEntry.isDeleted {
		fromProfileEntry.PublicKey = toPublicKey
	}
	toProfileEntry := bav.GetProfileEntryForPublicKey(toPublicKey)
	if toProfileEntry != nil && !toProfileEntry.isDeleted {
		toProfileEntry.PublicKey = fromPublicKey
	}

	// Get the existing PKID mappings. These are guaranteed to be set (they default to
	// the existing public key if they are unset).
	oldFromPKIDEntry := bav.GetPKIDForPublicKey(fromPublicKey)
	if oldFromPKIDEntry == nil || oldFromPKIDEntry.isDeleted {
		// This should basically never happen since we never delete PKIDs.
		return 0, 0, nil, RuleErrorOldFromPublicKeyHasDeletedPKID
	}
	oldToPKIDEntry := bav.GetPKIDForPublicKey(toPublicKey)
	if oldToPKIDEntry == nil || oldToPKIDEntry.isDeleted {
		// This should basically never happen since we never delete PKIDs.
		return 0, 0, nil, RuleErrorOldToPublicKeyHasDeletedPKID
	}

	// At this point, we are certain that the *from* and the *to* public keys
	// have valid PKID's.

	// Mark all the entries as dirty so they get flushed. This marks the new entries as dirty too.
	oldFromPKIDEntry.isDirty = true
	oldToPKIDEntry.isDirty = true

	// Create copies of the old PKID's so we can safely update the mappings.
	newFromPKIDEntry := *oldFromPKIDEntry
	newToPKIDEntry := *oldToPKIDEntry

	// Swap the PKID's on the entry copies.
	newFromPKIDEntry.PKID = oldToPKIDEntry.PKID
	newToPKIDEntry.PKID = oldFromPKIDEntry.PKID

	// Delete the old mappings for the *from* and *to* PKID's. This isn't really needed
	// because the calls to _setPKIDMappings below will undo the deletions we just did,
	// but we do it to maintain consistency with other functions.
	bav._deletePKIDMappings(oldFromPKIDEntry)
	bav._deletePKIDMappings(oldToPKIDEntry)

	// Set the new mappings for the *from* and *to* PKID's.
	bav._setPKIDMappings(&newFromPKIDEntry)
	bav._setPKIDMappings(&newToPKIDEntry)

	// Postgres doesn't have a concept of PKID Mappings. Instead, we need to save an empty
	// profile with the correct PKID and public key
	if bav.Postgres != nil {
		if fromProfileEntry == nil {
			bav._setProfileEntryMappings(&ProfileEntry{
				PublicKey: toPublicKey,
			})
		}

		if toProfileEntry == nil {
			bav._setProfileEntryMappings(&ProfileEntry{
				PublicKey: fromPublicKey,
			})
		}
	}

	// Rosetta needs to know the current locked deso in each profile so it can model the swap of
	// the creator coins. Rosetta models a swap identity as two INPUTs and two OUTPUTs effectively
	// swapping the balances of total deso locked. If no profile exists, from/to is zero.
	fromNanos := uint64(0)
	if fromProfileEntry != nil {
		fromNanos = fromProfileEntry.CoinEntry.DeSoLockedNanos
	}
	toNanos := uint64(0)
	if toProfileEntry != nil {
		toNanos = toProfileEntry.CoinEntry.DeSoLockedNanos
	}

	// Add an operation to the list at the end indicating we've swapped identities.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type: OperationTypeSwapIdentity,
		// Rosetta fields
		SwapIdentityFromDESOLockedNanos: fromNanos,
		SwapIdentityToDESOLockedNanos:   toNanos,

		// Note that we don't need any metadata on this operation, since the swap is reversible
		// without it.
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

// _verifyAccessSignature verifies if the accessSignature is correct. Valid
// accessSignature is the signed hash of (derivedPublicKey + expirationBlock)
// in DER format, made with the ownerPublicKey.
func _verifyAccessSignature(ownerPublicKey []byte, derivedPublicKey []byte,
	expirationBlock uint64, accessSignature []byte) error {

	// Sanity-check and convert ownerPublicKey to *btcec.PublicKey.
	if len(ownerPublicKey) != btcec.PubKeyBytesLenCompressed {
		fmt.Errorf("_verifyAccessSignature: Problem parsing owner public key")
	}
	ownerPk, err := btcec.ParsePubKey(ownerPublicKey, btcec.S256())
	if err != nil {
		return errors.Wrapf(err, "_verifyAccessSignature: Problem parsing owner public key: ")
	}

	// Sanity-check and convert derivedPublicKey to *btcec.PublicKey.
	if len(derivedPublicKey) != btcec.PubKeyBytesLenCompressed {
		fmt.Errorf("_verifyAccessSignature: Problem parsing derived public key")
	}
	_, err = btcec.ParsePubKey(derivedPublicKey, btcec.S256())
	if err != nil {
		return errors.Wrapf(err, "_verifyAccessSignature: Problem parsing derived public key: ")
	}

	// Compute a hash of derivedPublicKey+expirationBlock.
	expirationBlockBytes := EncodeUint64(expirationBlock)
	accessBytes := append(derivedPublicKey, expirationBlockBytes[:]...)
	accessHash := Sha256DoubleHash(accessBytes)

	// Convert accessSignature to *btcec.Signature.
	signature, err := btcec.ParseDERSignature(accessSignature, btcec.S256())
	if err != nil {
		return errors.Wrapf(err, "_verifyAccessSignature: Problem parsing access signature: ")
	}

	// Verify signature.
	if !signature.Verify(accessHash[:], ownerPk) {
		return fmt.Errorf("_verifyAccessSignature: Invalid signature")
	}

	return nil
}

func (bav *UtxoView) _connectAuthorizeDerivedKey(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if blockHeight < NFTTransferOrBurnAndDerivedKeysBlockHeight {
		return 0, 0, nil, RuleErrorDerivedKeyBeforeBlockHeight
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeAuthorizeDerivedKey {
		return 0, 0, nil, fmt.Errorf("_connectAuthorizeDerivedKey: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}

	txMeta := txn.TxnMeta.(*AuthorizeDerivedKeyMetadata)

	// Validate the operation type.
	if txMeta.OperationType != AuthorizeDerivedKeyOperationValid &&
		txMeta.OperationType != AuthorizeDerivedKeyOperationNotValid {
		return 0, 0, nil, fmt.Errorf("_connectAuthorizeDerivedKey: called with bad OperationType %s",
			txn.TxnMeta.GetTxnType().String())
	}

	// Make sure transaction hasn't expired.
	if txMeta.ExpirationBlock <= uint64(blockHeight) {
		return 0, 0, nil, RuleErrorAuthorizeDerivedKeyExpiredDerivedPublicKey
	}

	// Validate the owner public key.
	ownerPublicKey := txn.PublicKey
	if len(ownerPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorAuthorizeDerivedKeyInvalidOwnerPublicKey
	}
	if _, err := btcec.ParsePubKey(ownerPublicKey, btcec.S256()); err != nil {
		return 0, 0, nil, errors.Wrap(RuleErrorAuthorizeDerivedKeyInvalidOwnerPublicKey, err.Error())
	}

	// Validate the derived public key.
	derivedPublicKey := txMeta.DerivedPublicKey
	if len(derivedPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorAuthorizeDerivedKeyInvalidDerivedPublicKey
	}
	if _, err := btcec.ParsePubKey(derivedPublicKey, btcec.S256()); err != nil {
		return 0, 0, nil, errors.Wrap(RuleErrorAuthorizeDerivedKeyInvalidDerivedPublicKey, err.Error())
	}

	// Verify that the access signature is valid. This means the derived key is authorized.
	err := _verifyAccessSignature(ownerPublicKey, derivedPublicKey,
		txMeta.ExpirationBlock, txMeta.AccessSignature)
	if err != nil {
		return 0, 0, nil, errors.Wrap(RuleErrorAuthorizeDerivedKeyAccessSignatureNotValid, err.Error())
	}

	// Get current (previous) derived key entry. We might revert to it later so we copy it.
	prevDerivedKeyEntry := bav._getDerivedKeyMappingForOwner(ownerPublicKey, derivedPublicKey)

	// Authorize transactions can be signed by both owner and derived keys. However, this
	// poses a risk in a situation where a malicious derived key, which has previously been
	// de-authorized by the owner, were to attempt to re-authorize itself.
	// To prevent this, the following check completely blocks a derived key once it has been
	// de-authorized. This makes the lifecycle of a derived key more controllable.
	if prevDerivedKeyEntry != nil && !prevDerivedKeyEntry.isDeleted {
		if prevDerivedKeyEntry.OperationType == AuthorizeDerivedKeyOperationNotValid {
			return 0, 0, nil, RuleErrorAuthorizeDerivedKeyDeletedDerivedPublicKey
		}
	}

	// At this point we've verified the access signature, which means the derived key is authorized
	// to sign on behalf of the owner. In particular, if this authorize transaction was signed
	// by the derived key, we would accept it. We accommodate this by adding a temporary derived
	// key entry to UtxoView, to support first-time derived keys (they don't exist in the DB yet).
	// As a result, and if the derived key is present in transaction's ExtraData, we will
	// pass signature verification in _connectBasicTransfer() -> _verifySignature().
	//
	// NOTE: Setting a mapping in UtxoView prior to fully validating a transaction shouldn't be
	// reproduced elsewhere. It's error-prone, controversial, some even call it "a dirty hack!"
	// All considered, this feature greatly simplifies the flow in identity - from the moment you
	// generate a derived key, you can use it to sign any transaction offline, including authorize
	// transactions. It also resolves issues in situations where the owner account has insufficient
	// balance to submit an authorize transaction.
	derivedKeyEntry := DerivedKeyEntry{
		OwnerPublicKey:   *NewPublicKey(ownerPublicKey),
		DerivedPublicKey: *NewPublicKey(derivedPublicKey),
		ExpirationBlock:  txMeta.ExpirationBlock,
		OperationType:    AuthorizeDerivedKeyOperationValid,
		isDeleted:        false,
	}
	bav._setDerivedKeyMapping(&derivedKeyEntry)

	// Call _connectBasicTransfer() to verify txn signature.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		// Since we've failed, we revert the UtxoView mapping to what it was previously.
		// We're doing this manually because we've set a temporary entry in UtxoView.
		bav._deleteDerivedKeyMapping(&derivedKeyEntry)
		bav._setDerivedKeyMapping(prevDerivedKeyEntry)
		return 0, 0, nil, errors.Wrapf(err, "_connectAuthorizeDerivedKey: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		// Since we've failed, we revert the UtxoView mapping to what it was previously.
		// We're doing this manually because we've set a temporary entry in UtxoView.
		bav._deleteDerivedKeyMapping(&derivedKeyEntry)
		bav._setDerivedKeyMapping(prevDerivedKeyEntry)
		return 0, 0, nil, RuleErrorAuthorizeDerivedKeyRequiresNonZeroInput
	}

	// Earlier we've set a temporary derived key entry that had OperationType set to Valid.
	// So if the txn metadata had OperationType set to NotValid, we update the entry here.
	bav._deleteDerivedKeyMapping(&derivedKeyEntry)
	derivedKeyEntry.OperationType = txMeta.OperationType
	bav._setDerivedKeyMapping(&derivedKeyEntry)

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the owner key or the derived key.
	}

	// Add an operation to the list at the end indicating we've authorized a derived key.
	// Also add the prevDerivedKeyEntry for disconnecting.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                OperationTypeAuthorizeDerivedKey,
		PrevDerivedKeyEntry: prevDerivedKeyEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func CalculateCreatorCoinToMintPolynomial(
	deltaDeSoNanos uint64, currentCreatorCoinSupplyNanos uint64, params *DeSoParams) uint64 {
	// The values our equations take are generally in whole units rather than
	// nanos, so the first step is to convert the nano amounts into floats
	// representing full coin units.
	bigNanosPerUnit := NewFloat().SetUint64(NanosPerUnit)
	bigDeltaDeSo := Div(NewFloat().SetUint64(deltaDeSoNanos), bigNanosPerUnit)
	bigCurrentCreatorCoinSupply :=
		Div(NewFloat().SetUint64(currentCreatorCoinSupplyNanos), bigNanosPerUnit)

	// These calculations are basically what you get when you integrate a
	// polynomial price curve. For more information, see the comment on
	// CreatorCoinSlope in constants.go and check out the Mathematica notebook
	// linked in that comment.
	//
	// This is the formula:
	// - (((dB + m*RR*s^(1/RR))/(m*RR)))^RR-s
	// - where:
	//     dB = bigDeltaDeSo,
	//     m = params.CreatorCoinSlope
	//     RR = params.CreatorCoinReserveRatio
	//     s = bigCurrentCreatorCoinSupply
	//
	// If you think it's hard to understand the code below, don't worry-- I hate
	// the Go float libary syntax too...
	bigRet := Sub(BigFloatPow((Div((Add(bigDeltaDeSo,
		Mul(params.CreatorCoinSlope, Mul(params.CreatorCoinReserveRatio,
			BigFloatPow(bigCurrentCreatorCoinSupply, (Div(bigOne,
				params.CreatorCoinReserveRatio))))))), Mul(params.CreatorCoinSlope,
		params.CreatorCoinReserveRatio))), params.CreatorCoinReserveRatio),
		bigCurrentCreatorCoinSupply)
	// The value we get is generally a number of whole creator coins, and so we
	// need to convert it to "nanos" as a last step.
	retNanos, _ := Mul(bigRet, bigNanosPerUnit).Uint64()
	return retNanos
}

func CalculateCreatorCoinToMintBancor(
	deltaDeSoNanos uint64, currentCreatorCoinSupplyNanos uint64,
	currentDeSoLockedNanos uint64, params *DeSoParams) uint64 {
	// The values our equations take are generally in whole units rather than
	// nanos, so the first step is to convert the nano amounts into floats
	// representing full coin units.
	bigNanosPerUnit := NewFloat().SetUint64(NanosPerUnit)
	bigDeltaDeSo := Div(NewFloat().SetUint64(deltaDeSoNanos), bigNanosPerUnit)
	bigCurrentCreatorCoinSupply := Div(NewFloat().SetUint64(currentCreatorCoinSupplyNanos), bigNanosPerUnit)
	bigCurrentDeSoLocked := Div(NewFloat().SetUint64(currentDeSoLockedNanos), bigNanosPerUnit)

	// These calculations are derived from the Bancor pricing formula, which
	// is proportional to a polynomial price curve (and equivalent to Uniswap
	// under certain assumptions). For more information, see the comment on
	// CreatorCoinSlope in constants.go and check out the Mathematica notebook
	// linked in that comment.
	//
	// This is the formula:
	// - S0 * ((1 + dB / B0) ^ (RR) - 1)
	// - where:
	//     dB = bigDeltaDeSo,
	//     B0 = bigCurrentDeSoLocked
	//     S0 = bigCurrentCreatorCoinSupply
	//     RR = params.CreatorCoinReserveRatio
	//
	// Sorry the code for the equation is so hard to read.
	bigRet := Mul(bigCurrentCreatorCoinSupply,
		Sub(BigFloatPow((Add(bigOne, Div(bigDeltaDeSo,
			bigCurrentDeSoLocked))),
			(params.CreatorCoinReserveRatio)), bigOne))
	// The value we get is generally a number of whole creator coins, and so we
	// need to convert it to "nanos" as a last step.
	retNanos, _ := Mul(bigRet, bigNanosPerUnit).Uint64()
	return retNanos
}

func CalculateDeSoToReturn(
	deltaCreatorCoinNanos uint64, currentCreatorCoinSupplyNanos uint64,
	currentDeSoLockedNanos uint64, params *DeSoParams) uint64 {
	// The values our equations take are generally in whole units rather than
	// nanos, so the first step is to convert the nano amounts into floats
	// representing full coin units.
	bigNanosPerUnit := NewFloat().SetUint64(NanosPerUnit)
	bigDeltaCreatorCoin := Div(NewFloat().SetUint64(deltaCreatorCoinNanos), bigNanosPerUnit)
	bigCurrentCreatorCoinSupply := Div(NewFloat().SetUint64(currentCreatorCoinSupplyNanos), bigNanosPerUnit)
	bigCurrentDeSoLocked := Div(NewFloat().SetUint64(currentDeSoLockedNanos), bigNanosPerUnit)

	// These calculations are derived from the Bancor pricing formula, which
	// is proportional to a polynomial price curve (and equivalent to Uniswap
	// under certain assumptions). For more information, see the comment on
	// CreatorCoinSlope in constants.go and check out the Mathematica notebook
	// linked in that comment.
	//
	// This is the formula:
	// - B0 * (1 - (1 - dS / S0)^(1/RR))
	// - where:
	//     dS = bigDeltaCreatorCoin,
	//     B0 = bigCurrentDeSoLocked
	//     S0 = bigCurrentCreatorCoinSupply
	//     RR = params.CreatorCoinReserveRatio
	//
	// Sorry the code for the equation is so hard to read.
	bigRet := Mul(bigCurrentDeSoLocked, (Sub(bigOne, BigFloatPow((Sub(bigOne,
		Div(bigDeltaCreatorCoin, bigCurrentCreatorCoinSupply))), (Div(bigOne,
		params.CreatorCoinReserveRatio))))))
	// The value we get is generally a number of whole creator coins, and so we
	// need to convert it to "nanos" as a last step.
	retNanos, _ := Mul(bigRet, bigNanosPerUnit).Uint64()
	return retNanos
}

func CalculateCreatorCoinToMint(
	desoToSellNanos uint64,
	coinsInCirculationNanos uint64, desoLockedNanos uint64,
	params *DeSoParams) uint64 {

	if desoLockedNanos == 0 {
		// In this case, there is no DeSo in the profile so we have to use
		// the polynomial equations to initialize the coin and determine how
		// much to mint.
		return CalculateCreatorCoinToMintPolynomial(
			desoToSellNanos, coinsInCirculationNanos,
			params)
	}

	// In this case, we have DeSo locked in the profile and so we use the
	// standard Bancor equations to determine how much creator coin to mint.
	return CalculateCreatorCoinToMintBancor(
		desoToSellNanos, coinsInCirculationNanos,
		desoLockedNanos, params)
}

// TODO: A lot of duplicate code between buy and sell. Consider factoring
// out the common code.
func (bav *UtxoView) HelpConnectCreatorCoinBuy(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _creatorCoinReturnedNanos uint64, _founderRewardNanos uint64,
	_utxoOps []*UtxoOperation, _err error) {

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, 0, 0, nil, errors.Wrapf(err, "_connectCreatorCoin: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks. If
	// we didn't do this then someone could replay your sell over and over again
	// to force-convert all your creator coin into DeSo. Think about it.
	if totalInput == 0 {
		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinRequiresNonZeroInput
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// Check that the specified profile public key is valid and that a profile
	// corresponding to that public key exists.
	txMeta := txn.TxnMeta.(*CreatorCoinMetadataa)
	if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinInvalidPubKeySize
	}

	// Dig up the profile. It must exist for the user to be able to
	// operate on its coin.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinOperationOnNonexistentProfile,
			"_connectCreatorCoin: Profile pub key: %v %v",
			PkToStringMainnet(txMeta.ProfilePublicKey), PkToStringTestnet(txMeta.ProfilePublicKey))
	}

	// At this point we are confident that we have a profile that
	// exists that corresponds to the profile public key the user
	// provided.

	// Check that the amount of DeSo being traded for creator coin is
	// non-zero.
	desoBeforeFeesNanos := txMeta.DeSoToSellNanos
	if desoBeforeFeesNanos == 0 {
		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustTradeNonZeroDeSo
	}
	// The amount of DeSo being traded counts as output being spent by
	// this transaction, so add it to the transaction output and check that
	// the resulting output does not exceed the total input.
	//
	// Check for overflow of the outputs before adding.
	if totalOutput > math.MaxUint64-desoBeforeFeesNanos {
		return 0, 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinTxnOutputWithInvalidBuyAmount,
			"_connectCreatorCoin: %v", desoBeforeFeesNanos)
	}
	totalOutput += desoBeforeFeesNanos
	// It's assumed the caller code will check that things like output <= input,
	// but we check it here just in case...
	if totalInput < totalOutput {
		return 0, 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinTxnOutputExceedsInput,
			"_connectCreatorCoin: Input: %v, Output: %v", totalInput, totalOutput)
	}
	// At this point we have verified that the output is sufficient to cover
	// the amount the user wants to use to buy the creator's coin.

	// Now we burn some DeSo before executing the creator coin buy. Doing
	// this guarantees that floating point errors in our subsequent calculations
	// will not result in a user being able to print infinite amounts of DeSo
	// through the protocol.
	//
	// TODO(performance): We use bigints to avoid overflow in the intermediate
	// stages of the calculation but this most likely isn't necessary. This
	// formula is equal to:
	// - desoAfterFeesNanos = desoBeforeFeesNanos * (CreatorCoinTradeFeeBasisPoints / (100*100))
	desoAfterFeesNanos := IntDiv(
		IntMul(
			big.NewInt(int64(desoBeforeFeesNanos)),
			big.NewInt(int64(100*100-bav.Params.CreatorCoinTradeFeeBasisPoints))),
		big.NewInt(100*100)).Uint64()

	// The amount of DeSo being convertend must be nonzero after fees as well.
	if desoAfterFeesNanos == 0 {
		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustTradeNonZeroDeSoAfterFees
	}

	// Figure out how much deso goes to the founder.
	// Note: If the user performing this transaction has the same public key as the
	// profile being bought, we do not cut a founder reward.
	desoRemainingNanos := uint64(0)
	desoFounderRewardNanos := uint64(0)
	if blockHeight > DeSoFounderRewardBlockHeight &&
		!reflect.DeepEqual(txn.PublicKey, existingProfileEntry.PublicKey) {

		// This formula is equal to:
		// desoFounderRewardNanos = desoAfterFeesNanos * creatorBasisPoints / (100*100)
		desoFounderRewardNanos = IntDiv(
			IntMul(
				big.NewInt(int64(desoAfterFeesNanos)),
				big.NewInt(int64(existingProfileEntry.CreatorBasisPoints))),
			big.NewInt(100*100)).Uint64()

		// Sanity check, just to be extra safe.
		if desoAfterFeesNanos < desoFounderRewardNanos {
			return 0, 0, 0, 0, nil, fmt.Errorf("HelpConnectCreatorCoinBuy: desoAfterFeesNanos"+
				" less than desoFounderRewardNanos: %v %v",
				desoAfterFeesNanos, desoFounderRewardNanos)
		}

		desoRemainingNanos = desoAfterFeesNanos - desoFounderRewardNanos
	} else {
		desoRemainingNanos = desoAfterFeesNanos
	}

	if desoRemainingNanos == 0 {
		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustTradeNonZeroDeSoAfterFounderReward
	}

	// If no DeSo is currently locked in the profile then we use the
	// polynomial equation to mint creator coins. We do this because the
	// Uniswap/Bancor equations don't work when zero coins have been minted,
	// and so we have to special case here. See this wolfram sheet for all
	// the equations with tests:
	// - https://pastebin.com/raw/1EmgeW56
	//
	// Note also that we use big floats with a custom math library in order
	// to guarantee that all nodes get the same result regardless of what
	// architecture they're running on. If we didn't do this, then some nodes
	// could round floats or use different levels of precision for intermediate
	// results and get different answers which would break consensus.
	creatorCoinToMintNanos := CalculateCreatorCoinToMint(
		desoRemainingNanos, existingProfileEntry.CoinsInCirculationNanos,
		existingProfileEntry.DeSoLockedNanos, bav.Params)

	// Check if the total amount minted satisfies CreatorCoinAutoSellThresholdNanos.
	// This makes it prohibitively expensive for a user to buy themself above the
	// CreatorCoinAutoSellThresholdNanos and then spam tiny nano DeSo creator
	// coin purchases causing the effective Bancor Creator Coin Reserve Ratio to drift.
	if blockHeight > SalomonFixBlockHeight {
		if creatorCoinToMintNanos < bav.Params.CreatorCoinAutoSellThresholdNanos {
			return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustSatisfyAutoSellThresholdNanos
		}
	}

	// At this point, we know how much creator coin we are going to mint.
	// Now it's just a matter of adjusting our bookkeeping and potentially
	// giving the creator a founder reward.

	// Save all the old values from the CoinEntry before we potentially
	// update them. Note that CoinEntry doesn't contain any pointers and so
	// a direct copy is OK.
	prevCoinEntry := existingProfileEntry.CoinEntry

	// Increment DeSoLockedNanos. Sanity-check that we're not going to
	// overflow.
	if existingProfileEntry.DeSoLockedNanos > math.MaxUint64-desoRemainingNanos {
		return 0, 0, 0, 0, nil, fmt.Errorf("_connectCreatorCoin: Overflow while summing"+
			"DeSoLockedNanos and desoAfterFounderRewardNanos: %v %v",
			existingProfileEntry.DeSoLockedNanos, desoRemainingNanos)
	}
	existingProfileEntry.DeSoLockedNanos += desoRemainingNanos

	// Increment CoinsInCirculation. Sanity-check that we're not going to
	// overflow.
	if existingProfileEntry.CoinsInCirculationNanos > math.MaxUint64-creatorCoinToMintNanos {
		return 0, 0, 0, 0, nil, fmt.Errorf("_connectCreatorCoin: Overflow while summing"+
			"CoinsInCirculationNanos and creatorCoinToMintNanos: %v %v",
			existingProfileEntry.CoinsInCirculationNanos, creatorCoinToMintNanos)
	}
	existingProfileEntry.CoinsInCirculationNanos += creatorCoinToMintNanos

	// Calculate the *Creator Coin nanos* to give as a founder reward.
	creatorCoinFounderRewardNanos := uint64(0)
	if blockHeight > DeSoFounderRewardBlockHeight {
		// Do nothing. The chain stopped minting creator coins as a founder reward for
		// creators at this blockheight.  It gives DeSo as a founder reward now instead.

	} else if blockHeight > SalomonFixBlockHeight {
		// Following the SalomonFixBlockHeight block, creator coin buys continuously mint
		// a founders reward based on the CreatorBasisPoints.

		creatorCoinFounderRewardNanos = IntDiv(
			IntMul(
				big.NewInt(int64(creatorCoinToMintNanos)),
				big.NewInt(int64(existingProfileEntry.CreatorBasisPoints))),
			big.NewInt(100*100)).Uint64()
	} else {
		// Up to and including the SalomonFixBlockHeight block, creator coin buys only minted
		// a founders reward if the creator reached a new all time high.

		if existingProfileEntry.CoinsInCirculationNanos > existingProfileEntry.CoinWatermarkNanos {
			// This value must be positive if we made it past the if condition above.
			watermarkDiff := existingProfileEntry.CoinsInCirculationNanos - existingProfileEntry.CoinWatermarkNanos
			// The founder reward is computed as a percentage of the "net coins created,"
			// which is equal to the watermarkDiff
			creatorCoinFounderRewardNanos = IntDiv(
				IntMul(
					big.NewInt(int64(watermarkDiff)),
					big.NewInt(int64(existingProfileEntry.CreatorBasisPoints))),
				big.NewInt(100*100)).Uint64()
		}
	}

	// CoinWatermarkNanos is no longer used, however it may be helpful for
	// future analytics or updates so we continue to update it here.
	if existingProfileEntry.CoinsInCirculationNanos > existingProfileEntry.CoinWatermarkNanos {
		existingProfileEntry.CoinWatermarkNanos = existingProfileEntry.CoinsInCirculationNanos
	}

	// At this point, founderRewardNanos will be non-zero if and only if we increased
	// the watermark *and* there was a non-zero CreatorBasisPoints set on the CoinEntry
	// *and* the blockHeight is less than DeSoFounderRewardBlockHeight.

	// The user gets whatever's left after we pay the founder their reward.
	coinsBuyerGetsNanos := creatorCoinToMintNanos - creatorCoinFounderRewardNanos

	// If the coins the buyer is getting is less than the minimum threshold that
	// they expected to get, then the transaction is invalid. This prevents
	// front-running attacks, but it also prevents the buyer from getting a
	// terrible price.
	//
	// Note that when the min is set to zero it means we should skip this check.
	if txMeta.MinCreatorCoinExpectedNanos != 0 &&
		coinsBuyerGetsNanos < txMeta.MinCreatorCoinExpectedNanos {
		return 0, 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinLessThanMinimumSetByUser,
			"_connectCreatorCoin: Amount that would be minted and given to user: "+
				"%v, amount that would be given to founder: %v, amount user needed: %v",
			coinsBuyerGetsNanos, creatorCoinFounderRewardNanos, txMeta.MinCreatorCoinExpectedNanos)
	}

	// If we get here, we are good to go. We will now update the balance of the
	// buyer and the creator (assuming we had a non-zero founderRewardNanos).

	// Look up a CreatorCoinBalanceEntry for the buyer and the creator. Create
	// an entry for each if one doesn't exist already.
	buyerBalanceEntry, hodlerPKID, creatorPKID :=
		bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			txn.PublicKey, existingProfileEntry.PublicKey)
	// If the user does not have a balance entry or the user's balance entry is deleted and we have passed the
	// BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight, we create a new balance entry.
	if buyerBalanceEntry == nil ||
		(buyerBalanceEntry.isDeleted && blockHeight > BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight) {
		// If there is no balance entry for this mapping yet then just create it.
		// In this case the balance will be zero.
		buyerBalanceEntry = &BalanceEntry{
			// The person who created the txn is they buyer/hodler
			HODLerPKID: hodlerPKID,
			// The creator is the owner of the profile that corresponds to the coin.
			CreatorPKID:  creatorPKID,
			BalanceNanos: uint64(0),
		}
	}

	// Get the balance entry for the creator. In this case the creator owns
	// their own coin and therefore the creator is also the HODLer. We need
	// this so we can pay the creator their founder reward. Note that we have
	// a special case when the creator is purchasing their own coin.
	var creatorBalanceEntry *BalanceEntry
	if reflect.DeepEqual(txn.PublicKey, existingProfileEntry.PublicKey) {
		// If the creator is buying their own coin, don't fetch/create a
		// duplicate entry. If we didn't do this, we might wind up with two
		// duplicate BalanceEntrys when a creator is buying their own coin.
		creatorBalanceEntry = buyerBalanceEntry
	} else {
		// In this case, the creator is distinct from the buyer, so fetch and
		// potentially create a new BalanceEntry for them rather than using the
		// existing one.
		creatorBalanceEntry, hodlerPKID, creatorPKID = bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			existingProfileEntry.PublicKey, existingProfileEntry.PublicKey)
		// If the creator does not have a balance entry or the creator's balance entry is deleted and we have passed the
		// BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight, we create a new balance entry.
		if creatorBalanceEntry == nil ||
			(creatorBalanceEntry.isDeleted && blockHeight > BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight) {
			// If there is no balance entry then it means the creator doesn't own
			// any of their coin yet. In this case we create a new entry for them
			// with a zero balance.
			creatorBalanceEntry = &BalanceEntry{
				HODLerPKID:   hodlerPKID,
				CreatorPKID:  creatorPKID,
				BalanceNanos: uint64(0),
			}
		}
	}
	// At this point we should have a BalanceEntry for the buyer and the creator.
	// These may be the same BalancEntry if the creator is buying their own coin,
	// but that is OK.

	// Save the previous balance entry before modifying it. If the creator is
	// buying their own coin, this will be the same BalanceEntry, which is fine.
	prevBuyerBalanceEntry := *buyerBalanceEntry
	prevCreatorBalanceEntry := *creatorBalanceEntry

	// Increase the buyer and the creator's balances by the amounts computed
	// previously. Always check for overflow.
	if buyerBalanceEntry.BalanceNanos > math.MaxUint64-coinsBuyerGetsNanos {
		return 0, 0, 0, 0, nil, fmt.Errorf("_connectCreatorCoin: Overflow while summing"+
			"buyerBalanceEntry.BalanceNanos and coinsBuyerGetsNanos %v %v",
			buyerBalanceEntry.BalanceNanos, coinsBuyerGetsNanos)
	}
	// Check that if the buyer is receiving nanos for the first time, it's enough
	// to push them above the CreatorCoinAutoSellThresholdNanos threshold. This helps
	// prevent tiny amounts of nanos from drifting the ratio of creator coins to DeSo locked.
	if blockHeight > SalomonFixBlockHeight {
		if buyerBalanceEntry.BalanceNanos == 0 && coinsBuyerGetsNanos != 0 &&
			coinsBuyerGetsNanos < bav.Params.CreatorCoinAutoSellThresholdNanos {
			return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustSatisfyAutoSellThresholdNanosForBuyer
		}
	}

	// Check if this is the buyers first buy or first buy after a complete sell.
	// If it is, we increment the NumberOfHolders to reflect this value.
	if buyerBalanceEntry.BalanceNanos == 0 && coinsBuyerGetsNanos != 0 {
		// Increment number of holders by one to reflect the buyer
		existingProfileEntry.NumberOfHolders += 1

		// Update the profile to reflect the new number of holders
		bav._setProfileEntryMappings(existingProfileEntry)
	}
	// Finally increment the buyerBalanceEntry.BalanceNanos to reflect
	// the purchased coinsBuyerGetsNanos. If coinsBuyerGetsNanos is greater than 0, we set HasPurchased to true.
	buyerBalanceEntry.BalanceNanos += coinsBuyerGetsNanos
	buyerBalanceEntry.HasPurchased = true

	// If the creator is buying their own coin, this will just be modifying
	// the same pointer as the buyerBalanceEntry, which is what we want.
	if creatorBalanceEntry.BalanceNanos > math.MaxUint64-creatorCoinFounderRewardNanos {
		return 0, 0, 0, 0, nil, fmt.Errorf("_connectCreatorCoin: Overflow while summing"+
			"creatorBalanceEntry.BalanceNanos and creatorCoinFounderRewardNanos %v %v",
			creatorBalanceEntry.BalanceNanos, creatorCoinFounderRewardNanos)
	}
	// Check that if the creator is receiving nanos for the first time, it's enough
	// to push them above the CreatorCoinAutoSellThresholdNanos threshold. This helps
	// prevent tiny amounts of nanos from drifting the effective creator coin reserve ratio drift.
	if creatorBalanceEntry.BalanceNanos == 0 &&
		creatorCoinFounderRewardNanos != 0 &&
		creatorCoinFounderRewardNanos < bav.Params.CreatorCoinAutoSellThresholdNanos &&
		blockHeight > SalomonFixBlockHeight {

		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustSatisfyAutoSellThresholdNanosForCreator
	}
	// Check if the creator's balance is going from zero to non-zero and increment the NumberOfHolders if so.
	if creatorBalanceEntry.BalanceNanos == 0 && creatorCoinFounderRewardNanos != 0 {
		// Increment number of holders by one to reflect the creator
		existingProfileEntry.NumberOfHolders += 1

		// Update the profile to reflect the new number of holders
		bav._setProfileEntryMappings(existingProfileEntry)
	}
	creatorBalanceEntry.BalanceNanos += creatorCoinFounderRewardNanos

	// At this point the balances for the buyer and the creator should be correct
	// so set the mappings in the view.
	bav._setBalanceEntryMappings(buyerBalanceEntry)
	// Avoid setting the same entry twice if the creator is buying their own coin.
	if buyerBalanceEntry != creatorBalanceEntry {
		bav._setBalanceEntryMappings(creatorBalanceEntry)
	}

	// Finally, if the creator is getting a deso founder reward, add a UTXO for it.
	var outputKey *UtxoKey
	if blockHeight > DeSoFounderRewardBlockHeight {
		if desoFounderRewardNanos > 0 {
			// Create a new entry for this output and add it to the view. It should be
			// added at the end of the utxo list.
			outputKey = &UtxoKey{
				TxID: *txHash,
				// The output is like an extra virtual output at the end of the transaction.
				Index: uint32(len(txn.TxOutputs)),
			}

			utxoEntry := UtxoEntry{
				AmountNanos: desoFounderRewardNanos,
				PublicKey:   existingProfileEntry.PublicKey,
				BlockHeight: blockHeight,
				UtxoType:    UtxoTypeCreatorCoinFounderReward,
				UtxoKey:     outputKey,
				// We leave the position unset and isSpent to false by default.
				// The position will be set in the call to _addUtxo.
			}

			utxoOp, err := bav._addUtxo(&utxoEntry)
			if err != nil {
				return 0, 0, 0, 0, nil, errors.Wrapf(err, "HelpConnectCreatorCoinBuy: Problem adding output utxo")
			}

			// Rosetta uses this UtxoOperation to provide INPUT amounts
			utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
		}
	}

	// Compute the change in DESO locked. This information is needed by Rosetta
	// and it's much more efficient to compute it here than it is to recompute
	// it later.
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, 0, 0, nil, errors.Wrapf(err, "HelpConnectCreatorCoinBuy: Error computing "+
			"desoLockedNanosDiff: Missing profile")
	}
	desoLockedNanosDiff := int64(existingProfileEntry.DeSoLockedNanos) - int64(prevCoinEntry.DeSoLockedNanos)

	// Add an operation to the list at the end indicating we've executed a
	// CreatorCoin txn. Save the previous state of the CoinEntry for easy
	// reversion during disconnect.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                           OperationTypeCreatorCoin,
		PrevCoinEntry:                  &prevCoinEntry,
		PrevTransactorBalanceEntry:     &prevBuyerBalanceEntry,
		PrevCreatorBalanceEntry:        &prevCreatorBalanceEntry,
		FounderRewardUtxoKey:           outputKey,
		CreatorCoinDESOLockedNanosDiff: desoLockedNanosDiff,
	})

	return totalInput, totalOutput, coinsBuyerGetsNanos, creatorCoinFounderRewardNanos, utxoOpsForTxn, nil
}

// TODO: A lot of duplicate code between buy and sell. Consider factoring
// out the common code.
func (bav *UtxoView) HelpConnectCreatorCoinSell(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _desoReturnedNanos uint64,
	_utxoOps []*UtxoOperation, _err error) {

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, 0, nil, errors.Wrapf(err, "_connectCreatorCoin: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks. If
	// we didn't do this then someone could replay your sell over and over again
	// to force-convert all your creator coin into DeSo. Think about it.
	if totalInput == 0 {
		return 0, 0, 0, nil, RuleErrorCreatorCoinRequiresNonZeroInput
	}

	// Verify that the output does not exceed the input. This check should also
	// be done by the caller, but we do it here as well.
	if totalInput < totalOutput {
		return 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinTxnOutputExceedsInput,
			"_connectCreatorCoin: Input: %v, Output: %v", totalInput, totalOutput)
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// Check that the specified profile public key is valid and that a profile
	// corresponding to that public key exists.
	txMeta := txn.TxnMeta.(*CreatorCoinMetadataa)
	if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, 0, nil, RuleErrorCreatorCoinInvalidPubKeySize
	}

	// Dig up the profile. It must exist for the user to be able to
	// operate on its coin.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinOperationOnNonexistentProfile,
			"_connectCreatorCoin: Profile pub key: %v %v",
			PkToStringMainnet(txMeta.ProfilePublicKey), PkToStringTestnet(txMeta.ProfilePublicKey))
	}

	// At this point we are confident that we have a profile that
	// exists that corresponds to the profile public key the user
	// provided.

	// Look up a BalanceEntry for the seller. If it doesn't exist then the seller
	// implicitly has a balance of zero coins, and so the sell transaction shouldn't be
	// allowed.
	sellerBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txn.PublicKey, existingProfileEntry.PublicKey)
	if sellerBalanceEntry == nil || sellerBalanceEntry.isDeleted {
		return 0, 0, 0, nil, RuleErrorCreatorCoinSellerBalanceEntryDoesNotExist
	}

	// Check that the amount of creator coin being sold is non-zero.
	creatorCoinToSellNanos := txMeta.CreatorCoinToSellNanos
	if creatorCoinToSellNanos == 0 {
		return 0, 0, 0, nil, RuleErrorCreatorCoinSellMustTradeNonZeroCreatorCoin
	}

	// Check that the amount of creator coin being sold does not exceed the user's
	// balance of this particular creator coin.
	if creatorCoinToSellNanos > sellerBalanceEntry.BalanceNanos {
		return 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinSellInsufficientCoins,
			"_connectCreatorCoin: CreatorCoin nanos being sold %v exceeds "+
				"user's creator coin balance %v",
			creatorCoinToSellNanos, sellerBalanceEntry.BalanceNanos)
	}

	// If the amount of DeSo locked in the profile is zero then selling is
	// not allowed.
	if existingProfileEntry.DeSoLockedNanos == 0 {
		return 0, 0, 0, nil, RuleErrorCreatorCoinSellNotAllowedWhenZeroDeSoLocked
	}

	desoBeforeFeesNanos := uint64(0)
	// Compute the amount of DeSo to return.
	if blockHeight > SalomonFixBlockHeight {
		// Following the SalomonFixBlockHeight block, if a user would be left with less than
		// bav.Params.CreatorCoinAutoSellThresholdNanos, we clear all their remaining holdings
		// to prevent 1 or 2 lingering creator coin nanos from staying in their wallet.
		// This also gives a method for cleanly and accurately reducing the numberOfHolders.

		// Note that we check that sellerBalanceEntry.BalanceNanos >= creatorCoinToSellNanos above.
		if sellerBalanceEntry.BalanceNanos-creatorCoinToSellNanos < bav.Params.CreatorCoinAutoSellThresholdNanos {
			// Setup to sell all the creator coins the seller has.
			creatorCoinToSellNanos = sellerBalanceEntry.BalanceNanos

			// Compute the amount of DeSo to return with the new creatorCoinToSellNanos.
			desoBeforeFeesNanos = CalculateDeSoToReturn(
				creatorCoinToSellNanos, existingProfileEntry.CoinsInCirculationNanos,
				existingProfileEntry.DeSoLockedNanos, bav.Params)

			// If the amount the formula is offering is more than what is locked in the
			// profile, then truncate it down. This addresses an edge case where our
			// equations may return *too much* DeSo due to rounding errors.
			if desoBeforeFeesNanos > existingProfileEntry.DeSoLockedNanos {
				desoBeforeFeesNanos = existingProfileEntry.DeSoLockedNanos
			}
		} else {
			// If we're above the CreatorCoinAutoSellThresholdNanos, we can safely compute
			// the amount to return based on the Bancor curve.
			desoBeforeFeesNanos = CalculateDeSoToReturn(
				creatorCoinToSellNanos, existingProfileEntry.CoinsInCirculationNanos,
				existingProfileEntry.DeSoLockedNanos, bav.Params)

			// If the amount the formula is offering is more than what is locked in the
			// profile, then truncate it down. This addresses an edge case where our
			// equations may return *too much* DeSo due to rounding errors.
			if desoBeforeFeesNanos > existingProfileEntry.DeSoLockedNanos {
				desoBeforeFeesNanos = existingProfileEntry.DeSoLockedNanos
			}
		}
	} else {
		// Prior to the SalomonFixBlockHeight block, coins would be minted based on floating point
		// arithmetic with the exception being if a creator was selling all remaining creator coins. This caused
		// a rare issue where a creator would be left with 1 creator coin nano in circulation
		// and 1 nano DeSo locked after completely selling. This in turn made the Bancor Curve unstable.

		if creatorCoinToSellNanos == existingProfileEntry.CoinsInCirculationNanos {
			desoBeforeFeesNanos = existingProfileEntry.DeSoLockedNanos
		} else {
			// Calculate the amount to return based on the Bancor Curve.
			desoBeforeFeesNanos = CalculateDeSoToReturn(
				creatorCoinToSellNanos, existingProfileEntry.CoinsInCirculationNanos,
				existingProfileEntry.DeSoLockedNanos, bav.Params)

			// If the amount the formula is offering is more than what is locked in the
			// profile, then truncate it down. This addresses an edge case where our
			// equations may return *too much* DeSo due to rounding errors.
			if desoBeforeFeesNanos > existingProfileEntry.DeSoLockedNanos {
				desoBeforeFeesNanos = existingProfileEntry.DeSoLockedNanos
			}
		}
	}

	// Save all the old values from the CoinEntry before we potentially
	// update them. Note that CoinEntry doesn't contain any pointers and so
	// a direct copy is OK.
	prevCoinEntry := existingProfileEntry.CoinEntry

	// Subtract the amount of DeSo the seller is getting from the amount of
	// DeSo locked in the profile. Sanity-check that it does not exceed the
	// total amount of DeSo locked.
	if desoBeforeFeesNanos > existingProfileEntry.DeSoLockedNanos {
		return 0, 0, 0, nil, fmt.Errorf("_connectCreatorCoin: DeSo nanos seller "+
			"would get %v exceeds DeSo nanos locked in profile %v",
			desoBeforeFeesNanos, existingProfileEntry.DeSoLockedNanos)
	}
	existingProfileEntry.DeSoLockedNanos -= desoBeforeFeesNanos

	// Subtract the number of coins the seller is selling from the number of coins
	// in circulation. Sanity-check that it does not exceed the number of coins
	// currently in circulation.
	if creatorCoinToSellNanos > existingProfileEntry.CoinsInCirculationNanos {
		return 0, 0, 0, nil, fmt.Errorf("_connectCreatorCoin: CreatorCoin nanos seller "+
			"is selling %v exceeds CreatorCoin nanos in circulation %v",
			creatorCoinToSellNanos, existingProfileEntry.CoinsInCirculationNanos)
	}
	existingProfileEntry.CoinsInCirculationNanos -= creatorCoinToSellNanos

	// Check if this is a complete sell of the seller's remaining creator coins
	if sellerBalanceEntry.BalanceNanos == creatorCoinToSellNanos {
		existingProfileEntry.NumberOfHolders -= 1
	}

	// If the number of holders has reached zero, we clear all the DeSoLockedNanos and
	// creatorCoinToSellNanos to ensure that the profile is reset to its normal initial state.
	// It's okay to modify these values because they are saved in the PrevCoinEntry.
	if existingProfileEntry.NumberOfHolders == 0 {
		existingProfileEntry.DeSoLockedNanos = 0
		existingProfileEntry.CoinsInCirculationNanos = 0
	}

	// Save the seller's balance before we modify it. We don't need to save the
	// creator's BalancEntry on a sell because the creator's balance will not
	// be modified.
	prevTransactorBalanceEntry := *sellerBalanceEntry

	// Subtract the number of coins the seller is selling from the number of coins
	// they HODL. Note that we already checked that this amount does not exceed the
	// seller's balance above. Note that this amount equals sellerBalanceEntry.BalanceNanos
	// in the event where the requested remaining creator coin balance dips
	// below CreatorCoinAutoSellThresholdNanos.
	sellerBalanceEntry.BalanceNanos -= creatorCoinToSellNanos

	// If the seller's balance will be zero after this transaction, set HasPurchased to false
	if sellerBalanceEntry.BalanceNanos == 0 {
		sellerBalanceEntry.HasPurchased = false
	}

	// Set the new BalanceEntry in our mappings for the seller and set the
	// ProfileEntry mappings as well since everything is up to date.
	bav._setBalanceEntryMappings(sellerBalanceEntry)
	bav._setProfileEntryMappings(existingProfileEntry)

	// Charge a fee on the DeSo the seller is getting to hedge against
	// floating point errors
	desoAfterFeesNanos := IntDiv(
		IntMul(
			big.NewInt(int64(desoBeforeFeesNanos)),
			big.NewInt(int64(100*100-bav.Params.CreatorCoinTradeFeeBasisPoints))),
		big.NewInt(100*100)).Uint64()

	// Check that the seller is getting back an amount of DeSo that is
	// greater than or equal to what they expect. Note that this check is
	// skipped if the min amount specified is zero.
	if txMeta.MinDeSoExpectedNanos != 0 &&
		desoAfterFeesNanos < txMeta.MinDeSoExpectedNanos {

		return 0, 0, 0, nil, errors.Wrapf(
			RuleErrorDeSoReceivedIsLessThanMinimumSetBySeller,
			"_connectCreatorCoin: DeSo nanos that would be given to seller: "+
				"%v, amount user needed: %v",
			desoAfterFeesNanos, txMeta.MinDeSoExpectedNanos)
	}

	// Now that we have all the information we need, save a UTXO allowing the user to
	// spend the DeSo from the sale in the future.
	outputKey := UtxoKey{
		TxID: *txn.Hash(),
		// The output is like an extra virtual output at the end of the transaction.
		Index: uint32(len(txn.TxOutputs)),
	}
	utxoEntry := UtxoEntry{
		AmountNanos: desoAfterFeesNanos,
		PublicKey:   txn.PublicKey,
		BlockHeight: blockHeight,
		UtxoType:    UtxoTypeCreatorCoinSale,
		UtxoKey:     &outputKey,
		// We leave the position unset and isSpent to false by default.
		// The position will be set in the call to _addUtxo.
	}
	// If we have a problem adding this utxo return an error but don't
	// mark this block as invalid since it's not a rule error and the block
	// could therefore benefit from being processed in the future.
	utxoOp, err := bav._addUtxo(&utxoEntry)
	if err != nil {
		return 0, 0, 0, nil, errors.Wrapf(
			err, "_connectBitcoinExchange: Problem adding output utxo")
	}

	// Rosetta uses this UtxoOperation to provide INPUT amounts
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)

	// Compute the change in DESO locked. This information is needed by Rosetta
	// and it's much more efficient to compute it here than it is to recompute
	// it later.
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, 0, nil, errors.Wrapf(
			err, "HelpConnectCreatorCoinSell: Error computing "+
				"desoLockedNanosDiff: Missing profile")
	}
	desoLockedNanosDiff := int64(existingProfileEntry.DeSoLockedNanos) - int64(prevCoinEntry.DeSoLockedNanos)

	// Add an operation to the list at the end indicating we've executed a
	// CreatorCoin txn. Save the previous state of the CoinEntry for easy
	// reversion during disconnect.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                           OperationTypeCreatorCoin,
		PrevCoinEntry:                  &prevCoinEntry,
		PrevTransactorBalanceEntry:     &prevTransactorBalanceEntry,
		PrevCreatorBalanceEntry:        nil,
		CreatorCoinDESOLockedNanosDiff: desoLockedNanosDiff,
	})

	// The DeSo that the user gets from selling their creator coin counts
	// as both input and output in the transaction.
	return totalInput + desoAfterFeesNanos,
		totalOutput + desoAfterFeesNanos,
		desoAfterFeesNanos, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectCreatorCoin(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCreatorCoin {
		return 0, 0, nil, fmt.Errorf("_connectCreatorCoin: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*CreatorCoinMetadataa)

	// We save the previous CoinEntry so that we can revert things easily during a
	// disconnect. If we didn't do this, it would be annoying to reset the coin
	// state when reverting a transaction.
	switch txMeta.OperationType {
	case CreatorCoinOperationTypeBuy:
		// We don't need the creatorCoinsReturned return value
		totalInput, totalOutput, _, _, utxoOps, err :=
			bav.HelpConnectCreatorCoinBuy(txn, txHash, blockHeight, verifySignatures)
		return totalInput, totalOutput, utxoOps, err

	case CreatorCoinOperationTypeSell:
		// We don't need the desoReturned return value
		totalInput, totalOutput, _, utxoOps, err :=
			bav.HelpConnectCreatorCoinSell(txn, txHash, blockHeight, verifySignatures)
		return totalInput, totalOutput, utxoOps, err

	case CreatorCoinOperationTypeAddDeSo:
		return 0, 0, nil, fmt.Errorf("_connectCreatorCoin: Add DeSo not implemented")
	}

	return 0, 0, nil, fmt.Errorf("_connectCreatorCoin: Unrecognized CreatorCoin "+
		"OperationType: %v", txMeta.OperationType)
}

func (bav *UtxoView) ValidateDiamondsAndGetNumCreatorCoinNanos(
	senderPublicKey []byte,
	receiverPublicKey []byte,
	diamondPostHash *BlockHash,
	diamondLevel int64,
	blockHeight uint32,
) (_numCreatorCoinNanos uint64, _netNewDiamonds int64, _err error) {

	// Check that the diamond level is reasonable
	diamondLevelMap := GetDeSoNanosDiamondLevelMapAtBlockHeight(int64(blockHeight))
	if _, isAllowedLevel := diamondLevelMap[diamondLevel]; !isAllowedLevel {
		return 0, 0, fmt.Errorf(
			"ValidateDiamondsAndGetNumCreatorCoinNanos: Diamond level %v not allowed",
			diamondLevel)
	}

	// Convert pub keys into PKIDs.
	senderPKID := bav.GetPKIDForPublicKey(senderPublicKey)
	receiverPKID := bav.GetPKIDForPublicKey(receiverPublicKey)

	// Look up if there is an existing diamond entry.
	diamondKey := MakeDiamondKey(senderPKID.PKID, receiverPKID.PKID, diamondPostHash)
	diamondEntry := bav.GetDiamondEntryForDiamondKey(&diamondKey)

	// Look up if there's an existing profile entry for the sender. There needs
	// to be in order to be able to give one's creator coin as a diamond.
	existingProfileEntry := bav.GetProfileEntryForPKID(senderPKID.PKID)
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, fmt.Errorf(
			"ValidateDiamondsAndGetNumCreatorCoinNanos: Cannot send CreatorCoin "+
				"with diamond because ProfileEntry for public key %v does not exist",
			senderPublicKey)
	}
	// If we get here, then we're sure the ProfileEntry for this user exists.

	currDiamondLevel := int64(0)
	if diamondEntry != nil {
		currDiamondLevel = diamondEntry.DiamondLevel
	}

	if currDiamondLevel >= diamondLevel {
		return 0, 0, RuleErrorCreatorCoinTransferPostAlreadyHasSufficientDiamonds
	}

	// Calculate the number of creator coin nanos needed vs. already added for previous diamonds.
	currCreatorCoinNanos := GetCreatorCoinNanosForDiamondLevelAtBlockHeight(
		existingProfileEntry.CoinsInCirculationNanos, existingProfileEntry.DeSoLockedNanos,
		currDiamondLevel, int64(blockHeight), bav.Params)
	neededCreatorCoinNanos := GetCreatorCoinNanosForDiamondLevelAtBlockHeight(
		existingProfileEntry.CoinsInCirculationNanos, existingProfileEntry.DeSoLockedNanos,
		diamondLevel, int64(blockHeight), bav.Params)

	// There is an edge case where, if the person's creator coin value goes down
	// by a large enough amount, then they can get a "free" diamond upgrade. This
	// seems fine for now.
	creatorCoinToTransferNanos := uint64(0)
	if neededCreatorCoinNanos > currCreatorCoinNanos {
		creatorCoinToTransferNanos = neededCreatorCoinNanos - currCreatorCoinNanos
	}

	netNewDiamonds := diamondLevel - currDiamondLevel

	return creatorCoinToTransferNanos, netNewDiamonds, nil
}

func (bav *UtxoView) ValidateDiamondsAndGetNumDeSoNanos(
	senderPublicKey []byte,
	receiverPublicKey []byte,
	diamondPostHash *BlockHash,
	diamondLevel int64,
	blockHeight uint32,
) (_numDeSoNanos uint64, _netNewDiamonds int64, _err error) {

	// Check that the diamond level is reasonable
	diamondLevelMap := GetDeSoNanosDiamondLevelMapAtBlockHeight(int64(blockHeight))
	if _, isAllowedLevel := diamondLevelMap[diamondLevel]; !isAllowedLevel {
		return 0, 0, fmt.Errorf(
			"ValidateDiamondsAndGetNumCreatorCoinNanos: Diamond level %v not allowed",
			diamondLevel)
	}

	// Convert pub keys into PKIDs.
	senderPKID := bav.GetPKIDForPublicKey(senderPublicKey)
	receiverPKID := bav.GetPKIDForPublicKey(receiverPublicKey)

	// Look up if there is an existing diamond entry.
	diamondKey := MakeDiamondKey(senderPKID.PKID, receiverPKID.PKID, diamondPostHash)
	diamondEntry := bav.GetDiamondEntryForDiamondKey(&diamondKey)

	currDiamondLevel := int64(0)
	if diamondEntry != nil {
		currDiamondLevel = diamondEntry.DiamondLevel
	}

	if currDiamondLevel >= diamondLevel {
		return 0, 0, RuleErrorCreatorCoinTransferPostAlreadyHasSufficientDiamonds
	}

	// Calculate the number of creator coin nanos needed vs. already added for previous diamonds.
	currDeSoNanos := GetDeSoNanosForDiamondLevelAtBlockHeight(currDiamondLevel, int64(blockHeight))
	neededDeSoNanos := GetDeSoNanosForDiamondLevelAtBlockHeight(diamondLevel, int64(blockHeight))

	// There is an edge case where, if the person's creator coin value goes down
	// by a large enough amount, then they can get a "free" diamond upgrade. This
	// seems fine for now.
	desoToTransferNanos := uint64(0)
	if neededDeSoNanos > currDeSoNanos {
		desoToTransferNanos = neededDeSoNanos - currDeSoNanos
	}

	netNewDiamonds := diamondLevel - currDiamondLevel

	return desoToTransferNanos, netNewDiamonds, nil
}

func (bav *UtxoView) _connectCreatorCoinTransfer(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCreatorCoinTransfer {
		return 0, 0, nil, fmt.Errorf("_connectCreatorCoinTransfer: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*CreatorCoinTransferMetadataa)

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectCreatorCoin: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks. If
	// we didn't do this then someone could replay your transfer over and over again
	// to force-convert all your creator coin into DeSo. Think about it.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorCreatorCoinTransferRequiresNonZeroInput
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// Check that the specified receiver public key is valid.
	if len(txMeta.ReceiverPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorCreatorCoinTransferInvalidReceiverPubKeySize
	}

	// Check that the sender and receiver public keys are different.
	if reflect.DeepEqual(txn.PublicKey, txMeta.ReceiverPublicKey) {
		return 0, 0, nil, RuleErrorCreatorCoinTransferCannotTransferToSelf
	}

	// Check that the specified profile public key is valid and that a profile
	// corresponding to that public key exists.
	if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorCreatorCoinTransferInvalidProfilePubKeySize
	}

	// Dig up the profile. It must exist for the user to be able to transfer its coin.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinTransferOnNonexistentProfile,
			"_connectCreatorCoin: Profile pub key: %v %v",
			PkToStringMainnet(txMeta.ProfilePublicKey), PkToStringTestnet(txMeta.ProfilePublicKey))
	}

	// At this point we are confident that we have a profile that
	// exists that corresponds to the profile public key the user provided.

	// Look up a BalanceEntry for the sender. If it doesn't exist then the sender implicitly
	// has a balance of zero coins, and so the transfer shouldn't be allowed.
	senderBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txn.PublicKey, existingProfileEntry.PublicKey)
	if senderBalanceEntry == nil || senderBalanceEntry.isDeleted {
		return 0, 0, nil, RuleErrorCreatorCoinTransferBalanceEntryDoesNotExist
	}

	// Check that the amount of creator coin being transferred is not less than the min threshold.
	if txMeta.CreatorCoinToTransferNanos < bav.Params.CreatorCoinAutoSellThresholdNanos {
		return 0, 0, nil, RuleErrorCreatorCoinTransferMustBeGreaterThanMinThreshold
	}

	// Check that the amount of creator coin being transferred does not exceed the user's
	// balance of this particular creator coin.
	if txMeta.CreatorCoinToTransferNanos > senderBalanceEntry.BalanceNanos {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinTransferInsufficientCoins,
			"_connectCreatorCoin: CreatorCoin nanos being transferred %v exceeds "+
				"user's creator coin balance %v",
			txMeta.CreatorCoinToTransferNanos, senderBalanceEntry.BalanceNanos)
	}

	// Now that we have validated this transaction, let's build the new BalanceEntry state.

	// Look up a BalanceEntry for the receiver.
	receiverBalanceEntry, _, _ := bav.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
		txMeta.ReceiverPublicKey, txMeta.ProfilePublicKey)

	// Save the receiver's balance if it is non-nil.
	var prevReceiverBalanceEntry *BalanceEntry
	if receiverBalanceEntry != nil {
		prevReceiverBalanceEntry = &BalanceEntry{}
		*prevReceiverBalanceEntry = *receiverBalanceEntry
	}

	// If the receiver's balance entry is nil, we need to make one.
	if receiverBalanceEntry == nil || receiverBalanceEntry.isDeleted {
		receiverPKID := bav.GetPKIDForPublicKey(txMeta.ReceiverPublicKey)
		creatorPKID := bav.GetPKIDForPublicKey(existingProfileEntry.PublicKey)
		// Sanity check that we found a PKID entry for these pub keys (should never fail).
		if receiverPKID == nil || receiverPKID.isDeleted || creatorPKID == nil || creatorPKID.isDeleted {
			return 0, 0, nil, fmt.Errorf(
				"_connectCreatorCoin: Found nil or deleted PKID for receiver or creator, this should never "+
					"happen. Receiver pubkey: %v, creator pubkey: %v",
				PkToStringMainnet(txMeta.ReceiverPublicKey),
				PkToStringMainnet(existingProfileEntry.PublicKey))
		}
		receiverBalanceEntry = &BalanceEntry{
			HODLerPKID:   receiverPKID.PKID,
			CreatorPKID:  creatorPKID.PKID,
			BalanceNanos: uint64(0),
		}
	}

	// Save the sender's balance before we modify it.
	prevSenderBalanceEntry := *senderBalanceEntry

	// Subtract the number of coins being given from the sender and add them to the receiver.
	// TODO: We should avoid editing the pointer returned by "bav._getX" directly before
	// deleting / setting. Since the pointer returned is the one held by the view, it
	// makes setting redundant.  An alternative would be to not call _set after modification.
	senderBalanceEntry.BalanceNanos -= txMeta.CreatorCoinToTransferNanos
	receiverBalanceEntry.BalanceNanos += txMeta.CreatorCoinToTransferNanos

	// We do not allow accounts to maintain tiny creator coin balances in order to avoid
	// Bancor curve price anomalies as famously demonstrated by @salomon.  Thus, if the
	// sender tries to make a transfer that will leave them below the threshold we give
	// their remaining balance to the receiver in order to zero them out.
	if senderBalanceEntry.BalanceNanos < bav.Params.CreatorCoinAutoSellThresholdNanos {
		receiverBalanceEntry.BalanceNanos += senderBalanceEntry.BalanceNanos
		senderBalanceEntry.BalanceNanos = 0
		senderBalanceEntry.HasPurchased = false
	}

	// Delete the sender's balance entry under the assumption that the sender gave away all
	// of their coins. We add it back later, if this is not the case.
	bav._deleteBalanceEntryMappings(senderBalanceEntry, txn.PublicKey, txMeta.ProfilePublicKey)
	// Delete the receiver's balance entry just to be safe. Added back immediately after.
	bav._deleteBalanceEntryMappings(
		receiverBalanceEntry, txMeta.ReceiverPublicKey, txMeta.ProfilePublicKey)

	bav._setBalanceEntryMappings(receiverBalanceEntry)
	if senderBalanceEntry.BalanceNanos > 0 {
		bav._setBalanceEntryMappings(senderBalanceEntry)
	}

	// Save all the old values from the CoinEntry before we potentially update them. Note
	// that CoinEntry doesn't contain any pointers and so a direct copy is OK.
	prevCoinEntry := existingProfileEntry.CoinEntry

	if prevReceiverBalanceEntry == nil || prevReceiverBalanceEntry.BalanceNanos == 0 {
		// The receiver did not have a BalanceEntry before. Increment num holders.
		existingProfileEntry.CoinEntry.NumberOfHolders++
	}

	if senderBalanceEntry.BalanceNanos == 0 {
		// The sender no longer holds any of this creator's coin, so we decrement num holders.
		existingProfileEntry.CoinEntry.NumberOfHolders--
	}

	// Update and set the new profile entry.
	bav._setProfileEntryMappings(existingProfileEntry)

	// If this creator coin transfer has diamonds, validate them and do the connection.
	diamondPostHashBytes, hasDiamondPostHash := txn.ExtraData[DiamondPostHashKey]
	diamondPostHash := &BlockHash{}
	diamondLevelBytes, hasDiamondLevel := txn.ExtraData[DiamondLevelKey]
	var previousDiamondPostEntry *PostEntry
	var previousDiamondEntry *DiamondEntry
	// After the DeSoDiamondsBlockHeight, we no longer accept creator coin diamonds.
	if hasDiamondPostHash && blockHeight > DeSoDiamondsBlockHeight {
		return 0, 0, nil, RuleErrorCreatorCoinTransferHasDiamondsAfterDeSoBlockHeight
	} else if hasDiamondPostHash {
		if !hasDiamondLevel {
			return 0, 0, nil, RuleErrorCreatorCoinTransferHasDiamondPostHashWithoutDiamondLevel
		}
		diamondLevel, bytesRead := Varint(diamondLevelBytes)
		// NOTE: Despite being an int, diamondLevel is required to be non-negative. This
		// is useful for sorting our dbkeys by diamondLevel.
		if bytesRead < 0 || diamondLevel < 0 {
			return 0, 0, nil, RuleErrorCreatorCoinTransferHasInvalidDiamondLevel
		}

		if !reflect.DeepEqual(txn.PublicKey, existingProfileEntry.PublicKey) {
			return 0, 0, nil, RuleErrorCreatorCoinTransferCantSendDiamondsForOtherProfiles
		}
		if reflect.DeepEqual(txMeta.ReceiverPublicKey, existingProfileEntry.PublicKey) {
			return 0, 0, nil, RuleErrorCreatorCoinTransferCantDiamondYourself
		}

		if len(diamondPostHashBytes) != HashSizeBytes {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorCreatorCoinTransferInvalidLengthForPostHashBytes,
				"_connectCreatorCoin: DiamondPostHashBytes length: %d", len(diamondPostHashBytes))
		}
		copy(diamondPostHash[:], diamondPostHashBytes[:])

		previousDiamondPostEntry = bav.GetPostEntryForPostHash(diamondPostHash)
		if previousDiamondPostEntry == nil || previousDiamondPostEntry.isDeleted {
			return 0, 0, nil, RuleErrorCreatorCoinTransferDiamondPostEntryDoesNotExist
		}

		expectedCreatorCoinNanosToTransfer, netNewDiamonds, err := bav.ValidateDiamondsAndGetNumCreatorCoinNanos(
			txn.PublicKey, txMeta.ReceiverPublicKey, diamondPostHash, diamondLevel, blockHeight)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectCreatorCoin: ")
		}

		if txMeta.CreatorCoinToTransferNanos < expectedCreatorCoinNanosToTransfer {
			return 0, 0, nil, RuleErrorCreatorCoinTransferInsufficientCreatorCoinsForDiamondLevel
		}

		// The diamondPostEntry needs to be updated with the number of new diamonds.
		// We make a copy to avoid issues with disconnecting.
		newDiamondPostEntry := &PostEntry{}
		*newDiamondPostEntry = *previousDiamondPostEntry
		newDiamondPostEntry.DiamondCount += uint64(netNewDiamonds)
		bav._setPostEntryMappings(newDiamondPostEntry)

		// Convert pub keys into PKIDs so we can make the DiamondEntry.
		senderPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
		receiverPKID := bav.GetPKIDForPublicKey(txMeta.ReceiverPublicKey)

		// Create a new DiamondEntry
		newDiamondEntry := &DiamondEntry{
			SenderPKID:      senderPKID.PKID,
			ReceiverPKID:    receiverPKID.PKID,
			DiamondPostHash: diamondPostHash,
			DiamondLevel:    diamondLevel,
		}

		// Save the old DiamondEntry
		diamondKey := MakeDiamondKey(senderPKID.PKID, receiverPKID.PKID, diamondPostHash)
		existingDiamondEntry := bav.GetDiamondEntryForDiamondKey(&diamondKey)
		// Save the existing DiamondEntry, if it exists, so we can disconnect
		if existingDiamondEntry != nil {
			dd := &DiamondEntry{}
			*dd = *existingDiamondEntry
			previousDiamondEntry = dd
		}

		// Now set the diamond entry mappings on the view so they are flushed to the DB.
		bav._setDiamondEntryMappings(newDiamondEntry)
	}

	// Add an operation to the list at the end indicating we've executed a
	// CreatorCoin txn. Save the previous state of the CoinEntry for easy
	// reversion during disconnect.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                     OperationTypeCreatorCoinTransfer,
		PrevSenderBalanceEntry:   &prevSenderBalanceEntry,
		PrevReceiverBalanceEntry: prevReceiverBalanceEntry,
		PrevCoinEntry:            &prevCoinEntry,
		PrevPostEntry:            previousDiamondPostEntry,
		PrevDiamondEntry:         previousDiamondEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) ConnectTransaction(txn *MsgDeSoTxn, txHash *BlockHash,
	txnSizeBytes int64,
	blockHeight uint32, verifySignatures bool, ignoreUtxos bool) (
	_utxoOps []*UtxoOperation, _totalInput uint64, _totalOutput uint64,
	_fees uint64, _err error) {

	return bav._connectTransaction(txn, txHash,
		txnSizeBytes,
		blockHeight, verifySignatures,
		ignoreUtxos)

}

func (bav *UtxoView) _connectTransaction(txn *MsgDeSoTxn, txHash *BlockHash,
	txnSizeBytes int64, blockHeight uint32, verifySignatures bool, ignoreUtxos bool) (
	_utxoOps []*UtxoOperation, _totalInput uint64, _totalOutput uint64,
	_fees uint64, _err error) {

	// Do a quick sanity check before trying to connect.
	if err := CheckTransactionSanity(txn); err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "_connectTransaction: ")
	}

	// Don't allow transactions that take up more than half of the block.
	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "CheckTransactionSanity: Problem serializing transaction: ")
	}
	if len(txnBytes) > int(bav.Params.MaxBlockSizeBytes/2) {
		return nil, 0, 0, 0, RuleErrorTxnTooBig
	}

	var totalInput, totalOutput uint64
	var utxoOpsForTxn []*UtxoOperation
	if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward || txn.TxnMeta.GetTxnType() == TxnTypeBasicTransfer {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectBasicTransfer(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectBitcoinExchange(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypePrivateMessage {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectPrivateMessage(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeSubmitPost {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectSubmitPost(
				txn, txHash, blockHeight, verifySignatures, ignoreUtxos)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateProfile {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectUpdateProfile(
				txn, txHash, blockHeight, verifySignatures, ignoreUtxos)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateBitcoinUSDExchangeRate {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectUpdateBitcoinUSDExchangeRate(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateGlobalParams {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectUpdateGlobalParams(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeFollow {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectFollow(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeLike {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectLike(txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoin {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectCreatorCoin(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoinTransfer {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectCreatorCoinTransfer(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeSwapIdentity {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectSwapIdentity(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeCreateNFT {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectCreateNFT(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateNFT {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectUpdateNFT(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeAcceptNFTBid {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectAcceptNFTBid(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeNFTBid {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectNFTBid(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeNFTTransfer {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectNFTTransfer(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeAcceptNFTTransfer {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectAcceptNFTTransfer(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeBurnNFT {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectBurnNFT(
				txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeAuthorizeDerivedKey {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectAuthorizeDerivedKey(
				txn, txHash, blockHeight, verifySignatures)

	} else {
		err = fmt.Errorf("ConnectTransaction: Unimplemented txn type %v", txn.TxnMeta.GetTxnType().String())
	}
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "ConnectTransaction: ")
	}

	// Do some extra processing for non-block-reward transactions. Block reward transactions
	// will return zero for their fees.
	fees := uint64(0)
	if txn.TxnMeta.GetTxnType() != TxnTypeBlockReward {
		// If this isn't a block reward transaction, make sure the total input does
		// not exceed the total output. If it does, mark the block as invalid and
		// return an error.
		if totalInput < totalOutput {
			return nil, 0, 0, 0, RuleErrorTxnOutputExceedsInput
		}
		fees = totalInput - totalOutput
	}

	// BitcoinExchange transactions have their own special fee that is computed as a function of how much
	// DeSo is being minted. They do not need to abide by the global minimum fee check, since if they had
	// enough fees to get mined into the Bitcoin blockchain itself then they're almost certainly not spam.
	// If the transaction size was set to 0, skip validating the fee is above the minimum.
	// If the current minimum network fee per kb is set to 0, that indicates we should not assess a minimum fee.
	if txn.TxnMeta.GetTxnType() != TxnTypeBitcoinExchange && txnSizeBytes != 0 && bav.GlobalParamsEntry.MinimumNetworkFeeNanosPerKB != 0 {
		// Make sure there isn't overflow in the fee.
		if fees != ((fees * 1000) / 1000) {
			return nil, 0, 0, 0, RuleErrorOverflowDetectedInFeeRateCalculation
		}
		// If the fee is less than the minimum network fee per KB, return an error.
		if (fees*1000)/uint64(txnSizeBytes) < bav.GlobalParamsEntry.MinimumNetworkFeeNanosPerKB {
			return nil, 0, 0, 0, RuleErrorTxnFeeBelowNetworkMinimum
		}
	}

	return utxoOpsForTxn, totalInput, totalOutput, fees, nil
}

func (bav *UtxoView) ConnectBlock(
	desoBlock *MsgDeSoBlock, txHashes []*BlockHash, verifySignatures bool, eventManager *EventManager) (
	[][]*UtxoOperation, error) {

	glog.Debugf("ConnectBlock: Connecting block %v", desoBlock)

	// Check that the block being connected references the current tip. ConnectBlock
	// can only add a block to the current tip. We do this to keep the API simple.
	if *desoBlock.Header.PrevBlockHash != *bav.TipHash {
		return nil, fmt.Errorf("ConnectBlock: Parent hash of block being connected does not match tip")
	}

	blockHeader := desoBlock.Header
	// Loop through all the transactions and validate them using the view. Also
	// keep track of the total fees throughout.
	var totalFees uint64
	utxoOps := [][]*UtxoOperation{}
	for txIndex, txn := range desoBlock.Txns {
		txHash := txHashes[txIndex]

		// ConnectTransaction validates all of the transactions in the block and
		// is responsible for verifying signatures.
		//
		// TODO: We currently don't check that the min transaction fee is satisfied when
		// connecting blocks. We skip this check because computing the transaction's size
		// would slow down block processing significantly. We should figure out a way to
		// enforce this check in the future, but for now the only attack vector is one in
		// which a miner is trying to spam the network, which should generally never happen.
		utxoOpsForTxn, totalInput, totalOutput, currentFees, err := bav.ConnectTransaction(
			txn, txHash, 0, uint32(blockHeader.Height), verifySignatures, false /*ignoreUtxos*/)
		_, _ = totalInput, totalOutput // A bit surprising we don't use these
		if err != nil {
			return nil, errors.Wrapf(err, "ConnectBlock: ")
		}

		// Add the fees from this txn to the total fees. If any overflow occurs
		// mark the block as invalid and return a rule error. Note that block reward
		// txns should count as having zero fees.
		if totalFees > (math.MaxUint64 - currentFees) {
			return nil, RuleErrorTxnOutputWithInvalidAmount
		}
		totalFees += currentFees

		// Add the utxo operations to our list for all the txns.
		utxoOps = append(utxoOps, utxoOpsForTxn)

		// TODO: This should really be called at the end of _connectTransaction but it's
		// really annoying to change all the call signatures right now and we don't really
		// need it just yet.
		//
		// Call the event manager
		if eventManager != nil {
			eventManager.transactionConnected(&TransactionEvent{
				Txn:      txn,
				TxnHash:  txHash,
				UtxoView: bav,
				UtxoOps:  utxoOpsForTxn,
			})
		}
	}

	// We should now have computed totalFees. Use this to check that
	// the block reward's outputs are correct.
	//
	// Compute the sum of the outputs in the block reward. If an overflow
	// occurs mark the block as invalid and return a rule error.
	var blockRewardOutput uint64
	for _, bro := range desoBlock.Txns[0].TxOutputs {
		if bro.AmountNanos > MaxNanos ||
			blockRewardOutput > (math.MaxUint64-bro.AmountNanos) {

			return nil, RuleErrorBlockRewardOutputWithInvalidAmount
		}
		blockRewardOutput += bro.AmountNanos
	}
	// Verify that the block reward does not overflow when added to
	// the block's fees.
	blockReward := CalcBlockRewardNanos(uint32(blockHeader.Height))
	if totalFees > MaxNanos ||
		blockReward > (math.MaxUint64-totalFees) {

		return nil, RuleErrorBlockRewardOverflow
	}
	maxBlockReward := blockReward + totalFees
	// If the outputs of the block reward txn exceed the max block reward
	// allowed then mark the block as invalid and return an error.
	if blockRewardOutput > maxBlockReward {
		glog.Errorf("ConnectBlock(RuleErrorBlockRewardExceedsMaxAllowed): "+
			"blockRewardOutput %d exceeds maxBlockReward %d", blockRewardOutput, maxBlockReward)
		return nil, RuleErrorBlockRewardExceedsMaxAllowed
	}

	// If we made it to the end and this block is valid, advance the tip
	// of the view to reflect that.
	blockHash, err := desoBlock.Header.Hash()
	if err != nil {
		return nil, fmt.Errorf("ConnectBlock: Problem computing block hash after validation")
	}
	bav.TipHash = blockHash

	return utxoOps, nil
}

// Preload tries to fetch all the relevant data needed to connect a block
// in batches from Postgres. It marks many objects as "nil" in the respective
// data structures and then fills in the objects it is able to retrieve from
// the database. It's much faster to fetch data in bulk and cache "nil" values
// then to query individual records when connecting every transaction. If something
// is not preloaded the view falls back to individual queries.
func (bav *UtxoView) Preload(desoBlock *MsgDeSoBlock) error {
	// We can only preload if we're using postgres
	if bav.Postgres == nil {
		return nil
	}

	// One iteration for all the PKIDs
	// NOTE: Work in progress. Testing with follows for now.
	var publicKeys []*PublicKey
	for _, txn := range desoBlock.Txns {
		if txn.TxnMeta.GetTxnType() == TxnTypeFollow {
			txnMeta := txn.TxnMeta.(*FollowMetadata)
			publicKeys = append(publicKeys, NewPublicKey(txn.PublicKey))
			publicKeys = append(publicKeys, NewPublicKey(txnMeta.FollowedPublicKey))
		} else if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoin {
			txnMeta := txn.TxnMeta.(*CreatorCoinMetadataa)
			publicKeys = append(publicKeys, NewPublicKey(txn.PublicKey))
			publicKeys = append(publicKeys, NewPublicKey(txnMeta.ProfilePublicKey))
		} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateProfile {
			publicKeys = append(publicKeys, NewPublicKey(txn.PublicKey))
		}
	}

	if len(publicKeys) > 0 {
		for _, publicKey := range publicKeys {
			publicKeyBytes := publicKey.ToBytes()
			pkidEntry := &PKIDEntry{
				PKID:      PublicKeyToPKID(publicKeyBytes),
				PublicKey: publicKeyBytes,
			}

			// Set pkid entries for all the public keys
			bav._setPKIDMappings(pkidEntry)

			// Set nil profile entries
			bav.ProfilePKIDToProfileEntry[*pkidEntry.PKID] = nil
		}

		// Set real entries for all the profiles that actually exist
		result := bav.Postgres.GetProfilesForPublicKeys(publicKeys)
		for _, profile := range result {
			bav.setProfileMappings(profile)
		}
	}

	// One iteration for everything else
	// TODO: For some reason just fetching follows from the DB causes consensus issues??
	var outputs []*PGTransactionOutput
	var follows []*PGFollow
	var balances []*PGCreatorCoinBalance
	var likes []*PGLike
	var posts []*PGPost
	var lowercaseUsernames []string

	for _, txn := range desoBlock.Txns {
		// Preload all the inputs
		for _, txInput := range txn.TxInputs {
			output := &PGTransactionOutput{
				OutputHash:  &txInput.TxID,
				OutputIndex: txInput.Index,
				Spent:       false,
			}
			outputs = append(outputs, output)
		}

		if txn.TxnMeta.GetTxnType() == TxnTypeFollow {
			txnMeta := txn.TxnMeta.(*FollowMetadata)
			follow := &PGFollow{
				FollowerPKID: bav.GetPKIDForPublicKey(txn.PublicKey).PKID.NewPKID(),
				FollowedPKID: bav.GetPKIDForPublicKey(txnMeta.FollowedPublicKey).PKID.NewPKID(),
			}
			follows = append(follows, follow)

			// We cache the follow as not present and then fill them in later
			followerKey := MakeFollowKey(follow.FollowerPKID, follow.FollowedPKID)
			bav.FollowKeyToFollowEntry[followerKey] = nil
		} else if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoin {
			txnMeta := txn.TxnMeta.(*CreatorCoinMetadataa)

			// Fetch the buyer's balance entry
			balance := &PGCreatorCoinBalance{
				HolderPKID:  bav.GetPKIDForPublicKey(txn.PublicKey).PKID.NewPKID(),
				CreatorPKID: bav.GetPKIDForPublicKey(txnMeta.ProfilePublicKey).PKID.NewPKID(),
			}
			balances = append(balances, balance)

			// We cache the balances as not present and then fill them in later
			balanceEntryKey := MakeCreatorCoinBalanceKey(balance.HolderPKID, balance.CreatorPKID)
			bav.HODLerPKIDCreatorPKIDToBalanceEntry[balanceEntryKey] = nil

			// Fetch the creator's balance entry if they're not buying their own coin
			if !reflect.DeepEqual(txn.PublicKey, txnMeta.ProfilePublicKey) {
				balance = &PGCreatorCoinBalance{
					HolderPKID:  bav.GetPKIDForPublicKey(txnMeta.ProfilePublicKey).PKID.NewPKID(),
					CreatorPKID: bav.GetPKIDForPublicKey(txnMeta.ProfilePublicKey).PKID.NewPKID(),
				}
				balances = append(balances, balance)

				// We cache the balances as not present and then fill them in later
				balanceEntryKey = MakeCreatorCoinBalanceKey(balance.HolderPKID, balance.CreatorPKID)
				bav.HODLerPKIDCreatorPKIDToBalanceEntry[balanceEntryKey] = nil
			}
		} else if txn.TxnMeta.GetTxnType() == TxnTypeLike {
			txnMeta := txn.TxnMeta.(*LikeMetadata)
			like := &PGLike{
				LikerPublicKey: txn.PublicKey,
				LikedPostHash:  txnMeta.LikedPostHash.NewBlockHash(),
			}
			likes = append(likes, like)

			// We cache the likes as not present and then fill them in later
			likeKey := MakeLikeKey(like.LikerPublicKey, *like.LikedPostHash)
			bav.LikeKeyToLikeEntry[likeKey] = nil

			post := &PGPost{
				PostHash: txnMeta.LikedPostHash.NewBlockHash(),
			}
			posts = append(posts, post)

			// We cache the posts as not present and then fill them in later
			bav.PostHashToPostEntry[*post.PostHash] = nil
		} else if txn.TxnMeta.GetTxnType() == TxnTypeSubmitPost {
			txnMeta := txn.TxnMeta.(*SubmitPostMetadata)

			var postHash *BlockHash
			if len(txnMeta.PostHashToModify) != 0 {
				postHash = NewBlockHash(txnMeta.PostHashToModify)
			} else {
				postHash = txn.Hash()
			}

			posts = append(posts, &PGPost{
				PostHash: postHash,
			})

			// We cache the posts as not present and then fill them in later
			bav.PostHashToPostEntry[*postHash] = nil

			// TODO: Preload parent, grandparent, and reposted posts
		} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateProfile {
			txnMeta := txn.TxnMeta.(*UpdateProfileMetadata)
			if len(txnMeta.NewUsername) == 0 {
				continue
			}

			lowercaseUsernames = append(lowercaseUsernames, strings.ToLower(string(txnMeta.NewUsername)))

			// We cache the profiles as not present and then fill them in later
			bav.ProfileUsernameToProfileEntry[MakeUsernameMapKey(txnMeta.NewUsername)] = nil
		}
	}

	if len(outputs) > 0 {
		//foundOutputs := bav.Postgres.GetOutputs(outputs)
		//for _, output := range foundOutputs {
		//	err := bav._setUtxoMappings(output.NewUtxoEntry())
		//	if err != nil {
		//		return err
		//	}
		//}
	}

	if len(follows) > 0 {
		foundFollows := bav.Postgres.GetFollows(follows)
		for _, follow := range foundFollows {
			followEntry := follow.NewFollowEntry()
			bav._setFollowEntryMappings(followEntry)
		}
	}

	if len(balances) > 0 {
		foundBalances := bav.Postgres.GetCreatorCoinBalances(balances)
		for _, balance := range foundBalances {
			balanceEntry := balance.NewBalanceEntry()
			bav._setBalanceEntryMappings(balanceEntry)
		}
	}

	if len(likes) > 0 {
		foundLikes := bav.Postgres.GetLikes(likes)
		for _, like := range foundLikes {
			likeEntry := like.NewLikeEntry()
			bav._setLikeEntryMappings(likeEntry)
		}
	}

	if len(posts) > 0 {
		foundPosts := bav.Postgres.GetPosts(posts)
		for _, post := range foundPosts {
			bav.setPostMappings(post)
		}
	}

	if len(lowercaseUsernames) > 0 {
		foundProfiles := bav.Postgres.GetProfilesForUsername(lowercaseUsernames)
		for _, profile := range foundProfiles {
			bav.setProfileMappings(profile)
		}
	}

	return nil
}

// TODO: Update for Postgres
func (bav *UtxoView) GetMessagesForUser(publicKey []byte) (
	_messageEntries []*MessageEntry, _err error) {

	// Start by fetching all the messages we have in the db.
	dbMessageEntries, err := DbGetMessageEntriesForPublicKey(bav.Handle, publicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "GetMessagesForUser: Problem fetching MessageEntrys from db: ")
	}

	// Iterate through the entries found in the db and force the view to load them.
	// This fills in any gaps in the view so that, after this, the view should contain
	// the union of what it had before plus what was in the db.
	for _, dbMessageEntry := range dbMessageEntries {
		messageKey := MakeMessageKey(publicKey, dbMessageEntry.TstampNanos)
		bav._getMessageEntryForMessageKey(&messageKey)
	}

	// Now that the view mappings are a complete picture, iterate through them
	// and set them on the map we're returning. Skip entries that don't match
	// our public key or that are deleted. Note that only considering mappings
	// where our public key is part of the key should ensure there are no
	// duplicates in the resulting list.
	messageEntriesToReturn := []*MessageEntry{}
	for viewMessageKey, viewMessageEntry := range bav.MessageKeyToMessageEntry {
		if viewMessageEntry.isDeleted {
			continue
		}
		messageKey := MakeMessageKey(publicKey, viewMessageEntry.TstampNanos)
		if viewMessageKey != messageKey {
			continue
		}

		// At this point we are confident the map key is equal to the message
		// key containing the passed-in public key so add it to the mapping.
		messageEntriesToReturn = append(messageEntriesToReturn, viewMessageEntry)
	}

	return messageEntriesToReturn, nil
}

// TODO: Update for Postgres
func (bav *UtxoView) GetLimitedMessagesForUser(publicKey []byte) (
	_messageEntries []*MessageEntry, _err error) {

	// Start by fetching all the messages we have in the db.
	dbMessageEntries, err := DbGetLimitedMessageEntriesForPublicKey(bav.Handle, publicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "GetMessagesForUser: Problem fetching MessageEntrys from db: ")
	}

	// Iterate through the entries found in the db and force the view to load them.
	// This fills in any gaps in the view so that, after this, the view should contain
	// the union of what it had before plus what was in the db.
	for _, dbMessageEntry := range dbMessageEntries {
		messageKey := MakeMessageKey(publicKey, dbMessageEntry.TstampNanos)
		bav._getMessageEntryForMessageKey(&messageKey)
	}

	// Now that the view mappings are a complete picture, iterate through them
	// and set them on the map we're returning. Skip entries that don't match
	// our public key or that are deleted. Note that only considering mappings
	// where our public key is part of the key should ensure there are no
	// duplicates in the resulting list.
	messageEntriesToReturn := []*MessageEntry{}
	for viewMessageKey, viewMessageEntry := range bav.MessageKeyToMessageEntry {
		if viewMessageEntry.isDeleted {
			continue
		}
		messageKey := MakeMessageKey(publicKey, viewMessageEntry.TstampNanos)
		if viewMessageKey != messageKey {
			continue
		}

		// At this point we are confident the map key is equal to the message
		// key containing the passed-in public key so add it to the mapping.
		messageEntriesToReturn = append(messageEntriesToReturn, viewMessageEntry)
	}

	return messageEntriesToReturn, nil
}

func (bav *UtxoView) GetCommentEntriesForParentStakeID(parentStakeID []byte) ([]*PostEntry, error) {
	if bav.Postgres != nil {
		posts := bav.Postgres.GetComments(NewBlockHash(parentStakeID))
		for _, post := range posts {
			bav.setPostMappings(post)
		}
	} else {
		_, dbCommentHashes, _, err := DBGetCommentPostHashesForParentStakeID(bav.Handle, parentStakeID, false)
		if err != nil {
			return nil, errors.Wrapf(err, "GetCommentEntriesForParentStakeID: Problem fetching comments: %v", err)
		}

		// Load comment hashes into the view.
		for _, commentHash := range dbCommentHashes {
			bav.GetPostEntryForPostHash(commentHash)
		}
	}

	commentEntries := []*PostEntry{}
	for _, postEntry := range bav.PostHashToPostEntry {
		// Ignore deleted or rolled-back posts.
		if postEntry.isDeleted {
			continue
		}

		if len(postEntry.ParentStakeID) == 0 || !reflect.DeepEqual(postEntry.ParentStakeID, parentStakeID) {
			continue // Skip posts that are not comments on the given parentStakeID.
		} else {
			// Add the comment to our map.
			commentEntries = append(commentEntries, postEntry)
		}
	}

	return commentEntries, nil
}

// Accepts a postEntry and returns as many parent posts as it can find up to maxDepth.
// This function never returns an error, only an empty list if it hits a non-post parentStakeID.
// If "rootFirst" is passed, the root of the tree will be returned first, not the 1st parent.
// _truncatedTree is a flag that is true when the root post was not reached before the maxDepth was hit.
func (bav *UtxoView) GetParentPostEntriesForPostEntry(postEntry *PostEntry, maxDepth uint32, rootFirst bool,
) (_parentPostEntries []*PostEntry, _truncatedTree bool) {

	parentStakeID := postEntry.ParentStakeID
	parentPostEntries := []*PostEntry{}

	// If the post passed has no parent or isn't a post, we return the empty list.
	if len(parentStakeID) != HashSizeBytes {
		return parentPostEntries, false
	}

	iterations := uint32(0)
	for len(parentStakeID) == HashSizeBytes && iterations < maxDepth {
		parentPostHash := &BlockHash{}
		copy(parentPostHash[:], parentStakeID)

		parentPostEntry := bav.GetPostEntryForPostHash(parentPostHash)
		if postEntry == nil {
			break
		}
		if rootFirst {
			parentPostEntries = append([]*PostEntry{parentPostEntry}, parentPostEntries...)
		} else {
			parentPostEntries = append(parentPostEntries, parentPostEntry)
		}

		// Set up the next iteration of the loop.
		parentStakeID = parentPostEntry.ParentStakeID
		iterations += 1
	}

	return parentPostEntries, iterations >= maxDepth
}

// Just fetch all the posts from the db and join them with all the posts
// in the mempool. Then sort them by their timestamp. This can be called
// on an empty view or a view that already has a lot of transactions
// applied to it.
func (bav *UtxoView) GetAllPosts() (_corePosts []*PostEntry, _commentsByPostHash map[BlockHash][]*PostEntry, _err error) {
	// Start by fetching all the posts we have in the db.
	//
	// TODO(performance): This currently fetches all posts. We should implement
	// some kind of pagination instead though.
	_, _, dbPostEntries, err := DBGetAllPostsByTstamp(bav.Handle, true /*fetchEntries*/)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GetAllPosts: Problem fetching PostEntry's from db: ")
	}

	// Iterate through the entries found in the db and force the view to load them.
	// This fills in any gaps in the view so that, after this, the view should contain
	// the union of what it had before plus what was in the db.
	for _, dbPostEntry := range dbPostEntries {
		bav.GetPostEntryForPostHash(dbPostEntry.PostHash)
	}

	// Do one more pass to load all the comments from the DB.
	for _, postEntry := range bav.PostHashToPostEntry {
		// Ignore deleted or rolled-back posts.
		if postEntry.isDeleted {
			continue
		}

		// If we have a post in the view and if that post is not a comment
		// then fetch its attached comments from the db. We need to do this
		// because the tstamp index above only fetches "core" posts not
		// comments.

		if len(postEntry.ParentStakeID) == 0 {
			_, dbCommentHashes, _, err := DBGetCommentPostHashesForParentStakeID(
				bav.Handle, postEntry.ParentStakeID, false /*fetchEntries*/)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "GetAllPosts: Problem fetching comment PostEntry's from db: ")
			}
			for _, commentHash := range dbCommentHashes {
				bav.GetPostEntryForPostHash(commentHash)
			}
		}
	}

	allCorePosts := []*PostEntry{}
	commentsByPostHash := make(map[BlockHash][]*PostEntry)
	for _, postEntry := range bav.PostHashToPostEntry {
		// Ignore deleted or rolled-back posts.
		if postEntry.isDeleted {
			continue
		}

		// Every post is either a core post or a comment. If it has a stake ID
		// its a comment, and if it doesn't then it's a core post.
		if len(postEntry.ParentStakeID) == 0 {
			allCorePosts = append(allCorePosts, postEntry)
		} else {
			// Add the comment to our map.
			commentsForPost := commentsByPostHash[*NewBlockHash(postEntry.ParentStakeID)]
			commentsForPost = append(commentsForPost, postEntry)
			commentsByPostHash[*NewBlockHash(postEntry.ParentStakeID)] = commentsForPost
		}
	}
	// Sort all the comment lists as well. Here we put the latest comment at the
	// end.
	for _, commentList := range commentsByPostHash {
		sort.Slice(commentList, func(ii, jj int) bool {
			return commentList[ii].TimestampNanos < commentList[jj].TimestampNanos
		})
	}

	return allCorePosts, commentsByPostHash, nil
}

func (bav *UtxoView) GetPostsPaginatedForPublicKeyOrderedByTimestamp(publicKey []byte, startPostHash *BlockHash, limit uint64, mediaRequired bool) (_posts []*PostEntry, _err error) {
	if bav.Postgres != nil {
		var startTime uint64 = math.MaxUint64
		if startPostHash != nil {
			startPostEntry := bav.GetPostEntryForPostHash(startPostHash)
			startTime = startPostEntry.TimestampNanos
		}
		posts := bav.Postgres.GetPostsForPublicKey(publicKey, startTime, limit)
		for _, post := range posts {
			// TODO: Normalize this field so we get the correct number of results from the DB
			if mediaRequired && !post.HasMedia() {
				continue
			}
			bav.setPostMappings(post)
		}
	} else {
		handle := bav.Handle
		dbPrefix := append([]byte{}, _PrefixPosterPublicKeyTimestampPostHash...)
		dbPrefix = append(dbPrefix, publicKey...)
		var prefix []byte
		if startPostHash != nil {
			startPostEntry := bav.GetPostEntryForPostHash(startPostHash)
			if startPostEntry == nil {
				return nil, fmt.Errorf("GetPostsPaginatedForPublicKeyOrderedByTimestamp: Invalid start post hash")
			}
			prefix = append(dbPrefix, EncodeUint64(startPostEntry.TimestampNanos)...)
			prefix = append(prefix, startPostEntry.PostHash[:]...)
		} else {
			maxBigEndianUint64Bytes := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
			prefix = append(dbPrefix, maxBigEndianUint64Bytes...)
		}
		timestampSizeBytes := 8
		var posts []*PostEntry
		err := handle.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions

			opts.PrefetchValues = false

			// Go in reverse order
			opts.Reverse = true

			it := txn.NewIterator(opts)
			defer it.Close()
			it.Seek(prefix)
			if startPostHash != nil {
				// Skip the first post if we have a startPostHash.
				it.Next()
			}
			for ; it.ValidForPrefix(dbPrefix) && uint64(len(posts)) < limit; it.Next() {
				rawKey := it.Item().Key()

				keyWithoutPrefix := rawKey[1:]
				//posterPublicKey := keyWithoutPrefix[:HashSizeBytes]
				publicKeySizeBytes := HashSizeBytes + 1
				//tstampNanos := DecodeUint64(keyWithoutPrefix[publicKeySizeBytes:(publicKeySizeBytes + timestampSizeBytes)])

				postHash := &BlockHash{}
				copy(postHash[:], keyWithoutPrefix[(publicKeySizeBytes+timestampSizeBytes):])
				postEntry := bav.GetPostEntryForPostHash(postHash)
				if postEntry == nil {
					return fmt.Errorf("Missing post entry")
				}
				if postEntry.isDeleted || postEntry.ParentStakeID != nil || postEntry.IsHidden {
					continue
				}

				// mediaRequired set to determine if we only want posts that include media and ignore posts without
				if mediaRequired && !postEntry.HasMedia() {
					continue
				}

				posts = append(posts, postEntry)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	var postEntries []*PostEntry
	// Iterate over the view. Put all posts authored by the public key into our mempool posts slice
	for _, postEntry := range bav.PostHashToPostEntry {
		// Ignore deleted or hidden posts and any comments.
		if postEntry.isDeleted || postEntry.IsHidden || len(postEntry.ParentStakeID) != 0 {
			continue
		}

		// mediaRequired set to determine if we only want posts that include media and ignore posts without
		if mediaRequired && !postEntry.HasMedia() {
			continue
		}

		if reflect.DeepEqual(postEntry.PosterPublicKey, publicKey) {
			postEntries = append(postEntries, postEntry)
		}
	}

	return postEntries, nil
}

func (bav *UtxoView) GetDiamondSendersForPostHash(postHash *BlockHash) (_pkidToDiamondLevel map[PKID]int64, _err error) {
	handle := bav.Handle
	dbPrefix := append([]byte{}, _PrefixDiamondedPostHashDiamonderPKIDDiamondLevel...)
	dbPrefix = append(dbPrefix, postHash[:]...)
	keysFound, _ := EnumerateKeysForPrefix(handle, dbPrefix)

	diamondPostEntry := bav.GetPostEntryForPostHash(postHash)
	receiverPKIDEntry := bav.GetPKIDForPublicKey(diamondPostEntry.PosterPublicKey)

	// Iterate over all the db keys & values and load them into the view.
	expectedKeyLength := 1 + HashSizeBytes + btcec.PubKeyBytesLenCompressed + 8
	for _, key := range keysFound {
		// Sanity check that this is a reasonable key.
		if len(key) != expectedKeyLength {
			return nil, fmt.Errorf("UtxoView.GetDiamondsForPostHash: Invalid key length found: %d", len(key))
		}

		senderPKID := &PKID{}
		copy(senderPKID[:], key[1+HashSizeBytes:])

		diamondKey := &DiamondKey{
			SenderPKID:      *senderPKID,
			ReceiverPKID:    *receiverPKIDEntry.PKID,
			DiamondPostHash: *postHash,
		}

		bav.GetDiamondEntryForDiamondKey(diamondKey)
	}

	// Iterate over the view and create the final map to return.
	pkidToDiamondLevel := make(map[PKID]int64)
	for _, diamondEntry := range bav.DiamondKeyToDiamondEntry {
		if !diamondEntry.isDeleted && reflect.DeepEqual(diamondEntry.DiamondPostHash[:], postHash[:]) {
			pkidToDiamondLevel[*diamondEntry.SenderPKID] = diamondEntry.DiamondLevel
		}
	}

	return pkidToDiamondLevel, nil
}

func (bav *UtxoView) GetLikesForPostHash(postHash *BlockHash) (_likerPubKeys [][]byte, _err error) {
	if bav.Postgres != nil {
		likes := bav.Postgres.GetLikesForPost(postHash)
		for _, like := range likes {
			bav._setLikeEntryMappings(like.NewLikeEntry())
		}
	} else {
		handle := bav.Handle
		dbPrefix := append([]byte{}, _PrefixLikedPostHashToLikerPubKey...)
		dbPrefix = append(dbPrefix, postHash[:]...)
		keysFound, _ := EnumerateKeysForPrefix(handle, dbPrefix)

		// Iterate over all the db keys & values and load them into the view.
		expectedKeyLength := 1 + HashSizeBytes + btcec.PubKeyBytesLenCompressed
		for _, key := range keysFound {
			// Sanity check that this is a reasonable key.
			if len(key) != expectedKeyLength {
				return nil, fmt.Errorf("UtxoView.GetLikesForPostHash: Invalid key length found: %d", len(key))
			}

			likerPubKey := key[1+HashSizeBytes:]

			likeKey := &LikeKey{
				LikerPubKey:   MakePkMapKey(likerPubKey),
				LikedPostHash: *postHash,
			}

			bav._getLikeEntryForLikeKey(likeKey)
		}
	}

	// Iterate over the view and create the final list to return.
	likerPubKeys := [][]byte{}
	for _, likeEntry := range bav.LikeKeyToLikeEntry {
		if !likeEntry.isDeleted && reflect.DeepEqual(likeEntry.LikedPostHash[:], postHash[:]) {
			likerPubKeys = append(likerPubKeys, likeEntry.LikerPubKey)
		}
	}

	return likerPubKeys, nil
}

func (bav *UtxoView) GetRepostsForPostHash(postHash *BlockHash) (_reposterPubKeys [][]byte, _err error) {
	handle := bav.Handle
	dbPrefix := append([]byte{}, _PrefixRepostedPostHashReposterPubKey...)
	dbPrefix = append(dbPrefix, postHash[:]...)
	keysFound, _ := EnumerateKeysForPrefix(handle, dbPrefix)

	// Iterate over all the db keys & values and load them into the view.
	expectedKeyLength := 1 + HashSizeBytes + btcec.PubKeyBytesLenCompressed
	for _, key := range keysFound {
		// Sanity check that this is a reasonable key.
		if len(key) != expectedKeyLength {
			return nil, fmt.Errorf("UtxoView.GetRepostersForPostHash: Invalid key length found: %d", len(key))
		}

		reposterPubKey := key[1+HashSizeBytes:]

		repostKey := &RepostKey{
			ReposterPubKey:   MakePkMapKey(reposterPubKey),
			RepostedPostHash: *postHash,
		}

		bav._getRepostEntryForRepostKey(repostKey)
	}

	// Iterate over the view and create the final list to return.
	reposterPubKeys := [][]byte{}
	for _, repostEntry := range bav.RepostKeyToRepostEntry {
		if !repostEntry.isDeleted && reflect.DeepEqual(repostEntry.RepostedPostHash[:], postHash[:]) {
			reposterPubKeys = append(reposterPubKeys, repostEntry.ReposterPubKey)
		}
	}

	return reposterPubKeys, nil
}

func (bav *UtxoView) GetQuoteRepostsForPostHash(postHash *BlockHash,
) (_quoteReposterPubKeys [][]byte, _quoteReposterPubKeyToPosts map[PkMapKey][]*PostEntry, _err error) {
	handle := bav.Handle
	dbPrefix := append([]byte{}, _PrefixRepostedPostHashReposterPubKeyRepostPostHash...)
	dbPrefix = append(dbPrefix, postHash[:]...)
	keysFound, _ := EnumerateKeysForPrefix(handle, dbPrefix)

	// Iterate over all the db keys & values and load them into the view.
	expectedKeyLength := 1 + HashSizeBytes + btcec.PubKeyBytesLenCompressed + HashSizeBytes

	repostPostHashIdx := 1 + HashSizeBytes + btcec.PubKeyBytesLenCompressed
	for _, key := range keysFound {
		// Sanity check that this is a reasonable key.
		if len(key) != expectedKeyLength {
			return nil, nil, fmt.Errorf("UtxoView.GetQuoteRepostsForPostHash: Invalid key length found: %d", len(key))
		}

		repostPostHash := &BlockHash{}
		copy(repostPostHash[:], key[repostPostHashIdx:])

		bav.GetPostEntryForPostHash(repostPostHash)
	}

	// Iterate over the view and create the final map to return.
	quoteReposterPubKeys := [][]byte{}
	quoteReposterPubKeyToPosts := make(map[PkMapKey][]*PostEntry)

	for _, postEntry := range bav.PostHashToPostEntry {
		if !postEntry.isDeleted && postEntry.IsQuotedRepost && reflect.DeepEqual(postEntry.RepostedPostHash[:], postHash[:]) {
			quoteReposterPubKeys = append(quoteReposterPubKeys, postEntry.PosterPublicKey)

			quoteRepostPosts, _ := quoteReposterPubKeyToPosts[MakePkMapKey(postEntry.PosterPublicKey)]
			quoteRepostPosts = append(quoteRepostPosts, postEntry)
			quoteReposterPubKeyToPosts[MakePkMapKey(postEntry.PosterPublicKey)] = quoteRepostPosts
		}
	}

	return quoteReposterPubKeys, quoteReposterPubKeyToPosts, nil
}

// Just fetch all the profiles from the db and join them with all the profiles
// in the mempool. Then sort them by their DeSo. This can be called
// on an empty view or a view that already has a lot of transactions
// applied to it.
func (bav *UtxoView) GetAllProfiles(readerPK []byte) (
	_profiles map[PkMapKey]*ProfileEntry,
	_corePostsByProfilePublicKey map[PkMapKey][]*PostEntry,
	_commentsByProfilePublicKey map[PkMapKey][]*PostEntry,
	_postEntryReaderStates map[BlockHash]*PostEntryReaderState, _err error) {
	// Start by fetching all the profiles we have in the db.
	//
	// TODO(performance): This currently fetches all profiles. We should implement
	// some kind of pagination instead though.
	_, _, dbProfileEntries, err := DBGetAllProfilesByCoinValue(bav.Handle, true /*fetchEntries*/)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrapf(
			err, "GetAllProfiles: Problem fetching ProfileEntrys from db: ")
	}

	// Iterate through the entries found in the db and force the view to load them.
	// This fills in any gaps in the view so that, after this, the view should contain
	// the union of what it had before plus what was in the db.
	for _, dbProfileEntry := range dbProfileEntries {
		bav.GetProfileEntryForPublicKey(dbProfileEntry.PublicKey)
	}

	// At this point, all the profiles should be loaded into the view.

	// Do one more pass to load all the comments associated with each
	// profile into the view.
	commentsByProfilePublicKey := make(map[PkMapKey][]*PostEntry)
	for _, profileEntry := range bav.ProfilePKIDToProfileEntry {
		// Ignore deleted or rolled-back posts.
		if profileEntry.isDeleted {
			continue
		}
		commentsByProfilePublicKey[MakePkMapKey(profileEntry.PublicKey)] = []*PostEntry{}
		_, dbCommentHashes, _, err := DBGetCommentPostHashesForParentStakeID(
			bav.Handle, profileEntry.PublicKey, false /*fetchEntries*/)
		if err != nil {
			return nil, nil, nil, nil, errors.Wrapf(err, "GetAllPosts: Problem fetching comment PostEntry's from db: ")
		}
		for _, commentHash := range dbCommentHashes {
			bav.GetPostEntryForPostHash(commentHash)
		}
	}
	// TODO(performance): Because we want to load all the posts the profile
	// has made, just go ahead and load *all* the posts into the view so that
	// they'll get returned in the mapping. Later, we should use the db index
	// to do this.
	_, _, dbPostEntries, err := DBGetAllPostsByTstamp(bav.Handle, true /*fetchEntries*/)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrapf(
			err, "GetAllPosts: Problem fetching PostEntry's from db: ")
	}
	for _, dbPostEntry := range dbPostEntries {
		bav.GetPostEntryForPostHash(dbPostEntry.PostHash)
	}

	// Iterate through all the posts loaded into the view and attach them
	// to the relevant profiles.  Also adds reader state if a reader pubkey is provided.
	corePostsByPublicKey := make(map[PkMapKey][]*PostEntry)
	postEntryReaderStates := make(map[BlockHash]*PostEntryReaderState)
	for _, postEntry := range bav.PostHashToPostEntry {
		// Ignore deleted or rolled-back posts.
		if postEntry.isDeleted {
			continue
		}

		// If the post has a stakeID that corresponds to a profile then add
		// it to our map.
		// Every post is either a core post or a comment. If it has a stake ID
		// its a comment, and if it doesn't then it's a core post.
		if len(postEntry.ParentStakeID) == 0 {
			// In this case we are dealing with a "core" post so add it to the
			// core post map.
			corePostsForProfile := corePostsByPublicKey[MakePkMapKey(postEntry.PosterPublicKey)]
			corePostsForProfile = append(corePostsForProfile, postEntry)
			corePostsByPublicKey[MakePkMapKey(postEntry.PosterPublicKey)] = corePostsForProfile
		} else {
			// Add the comment to our map.
			commentsForProfile := commentsByProfilePublicKey[MakePkMapKey(postEntry.ParentStakeID)]
			commentsForProfile = append(commentsForProfile, postEntry)
			commentsByProfilePublicKey[MakePkMapKey(postEntry.ParentStakeID)] = commentsForProfile
		}

		// Create reader state map. Ie, whether the reader has liked the post, etc.
		// If nil is passed in as the readerPK, this is skipped.
		if readerPK != nil {
			postEntryReaderState := bav.GetPostEntryReaderState(readerPK, postEntry)
			postEntryReaderStates[*postEntry.PostHash] = postEntryReaderState
		}
	}

	// Now that the view mappings are a complete picture, iterate through them
	// and set them on the map we're returning.
	profilesByPublicKey := make(map[PkMapKey]*ProfileEntry)
	for _, profileEntry := range bav.ProfilePKIDToProfileEntry {
		// Ignore deleted or rolled-back posts.
		if profileEntry.isDeleted {
			continue
		}
		profilesByPublicKey[MakePkMapKey(profileEntry.PublicKey)] = profileEntry
	}

	// Sort all the comment lists. Here we put the latest comment at the
	// end.
	for _, commentList := range commentsByProfilePublicKey {
		sort.Slice(commentList, func(ii, jj int) bool {
			return commentList[ii].TimestampNanos < commentList[jj].TimestampNanos
		})
	}

	return profilesByPublicKey, corePostsByPublicKey, commentsByProfilePublicKey, postEntryReaderStates, nil
}

func IsRestrictedPubKey(userGraylistState []byte, userBlacklistState []byte, moderationType string) bool {
	if moderationType == "unrestricted" {
		return false
	} else if reflect.DeepEqual(userBlacklistState, IsBlacklisted) {
		return true
	} else if moderationType == "leaderboard" && reflect.DeepEqual(userGraylistState, IsGraylisted) {
		return true
	} else {
		return false
	}
}

// GetUnspentUtxoEntrysForPublicKey returns the UtxoEntrys corresponding to the
// passed-in public key that are currently unspent. It does this while factoring
// in any transactions that have already been connected to it. This is useful,
// as an example, when one whats to see what UtxoEntrys are available for spending
// after factoring in (i.e. connecting) all of the transactions currently in the
// mempool that are related to this public key.
//
// At a high level, this function allows one to get the utxos that are the union of:
// - utxos in the db
// - utxos in the view from previously-connected transactions
func (bav *UtxoView) GetUnspentUtxoEntrysForPublicKey(pkBytes []byte) ([]*UtxoEntry, error) {
	// Fetch the relevant utxos for this public key from the db. We do this because
	// the db could contain utxos that are not currently loaded into the view.
	var utxoEntriesForPublicKey []*UtxoEntry
	var err error
	if bav.Postgres != nil {
		utxoEntriesForPublicKey = bav.Postgres.GetUtxoEntriesForPublicKey(pkBytes)
	} else {
		utxoEntriesForPublicKey, err = DbGetUtxosForPubKey(pkBytes, bav.Handle)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetUnspentUtxoEntrysForPublicKey: Problem fetching "+
			"utxos for public key %s", PkToString(pkBytes, bav.Params))
	}

	// Load all the utxos associated with this public key into
	// the view. This makes it so that the view can enumerate all of the utxoEntries
	// known for this public key. To put it another way, it allows the view to
	// contain the union of:
	// - utxos in the db
	// - utxos in the view from previously-connected transactions
	for _, utxoEntry := range utxoEntriesForPublicKey {
		bav.GetUtxoEntryForUtxoKey(utxoEntry.UtxoKey)
	}

	// Now that all of the utxos for this key have been loaded, filter the
	// ones for this public key and return them.
	utxoEntriesToReturn := []*UtxoEntry{}
	for utxoKeyTmp, utxoEntry := range bav.UtxoKeyToUtxoEntry {
		// Make a copy of the iterator since it might change from underneath us
		// if we take its pointer.
		utxoKey := utxoKeyTmp
		utxoEntry.UtxoKey = &utxoKey
		if !utxoEntry.isSpent && reflect.DeepEqual(utxoEntry.PublicKey, pkBytes) {
			utxoEntriesToReturn = append(utxoEntriesToReturn, utxoEntry)
		}
	}

	return utxoEntriesToReturn, nil
}

func (bav *UtxoView) GetSpendableDeSoBalanceNanosForPublicKey(pkBytes []byte,
	tipHeight uint32) (_spendableBalance uint64, _err error) {
	// In order to get the spendable balance, we need to account for any immature block rewards.
	// We get these by starting at the chain tip and iterating backwards until we have collected
	// all of the immature block rewards for this public key.
	nextBlockHash := bav.TipHash
	numImmatureBlocks := uint32(bav.Params.BlockRewardMaturity / bav.Params.TimeBetweenBlocks)
	immatureBlockRewards := uint64(0)

	if bav.Postgres != nil {
		// TODO: Filter out immature block rewards in postgres. UtxoType needs to be set correctly when importing blocks
		//outputs := bav.Postgres.GetBlockRewardsForPublicKey(NewPublicKey(pkBytes), tipHeight-numImmatureBlocks, tipHeight)
		//for _, output := range outputs {
		//	immatureBlockRewards += output.AmountNanos
		//}
	} else {
		for ii := uint64(1); ii < uint64(numImmatureBlocks); ii++ {
			// Don't look up the genesis block since it isn't in the DB.
			if GenesisBlockHashHex == nextBlockHash.String() {
				break
			}

			blockNode := GetHeightHashToNodeInfo(bav.Handle, tipHeight, nextBlockHash, false)
			if blockNode == nil {
				return uint64(0), fmt.Errorf(
					"GetSpendableDeSoBalanceNanosForPublicKey: Problem getting block for blockhash %s",
					nextBlockHash.String())
			}
			blockRewardForPK, err := DbGetBlockRewardForPublicKeyBlockHash(bav.Handle, pkBytes, nextBlockHash)
			if err != nil {
				return uint64(0), errors.Wrapf(
					err, "GetSpendableDeSoBalanceNanosForPublicKey: Problem getting block reward for "+
						"public key %s blockhash %s", PkToString(pkBytes, bav.Params), nextBlockHash.String())
			}
			immatureBlockRewards += blockRewardForPK
			if blockNode.Parent != nil {
				nextBlockHash = blockNode.Parent.Hash
			} else {
				nextBlockHash = GenesisBlockHash
			}
		}
	}

	balanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(pkBytes)
	if err != nil {
		return uint64(0), errors.Wrap(err, "GetSpendableUtxosForPublicKey: ")
	}
	// Sanity check that the balanceNanos >= immatureBlockRewards to prevent underflow.
	if balanceNanos < immatureBlockRewards {
		return uint64(0), fmt.Errorf(
			"GetSpendableUtxosForPublicKey: balance underflow (%d,%d)", balanceNanos, immatureBlockRewards)
	}
	return balanceNanos - immatureBlockRewards, nil
}

func (bav *UtxoView) _flushUtxosToDbWithTxn(txn *badger.Txn) error {
	glog.Debugf("_flushUtxosToDbWithTxn: flushing %d mappings", len(bav.UtxoKeyToUtxoEntry))

	numDeleted := 0
	numPut := 0

	for utxoKeyIter, utxoEntry := range bav.UtxoKeyToUtxoEntry {
		// Make a copy of the iterator since it might change from under us.
		utxoKey := utxoKeyIter

		// As a sanity-check, make sure the back-reference for each entry
		// points to its key.
		if utxoEntry.UtxoKey == nil || *utxoEntry.UtxoKey != utxoKey {
			return fmt.Errorf("_flushUtxosToDbWithTxn: Found utxoEntry %+v for "+
				"utxoKey %v has invalid back-refernce utxoKey %v",
				utxoEntry, utxoKey, utxoEntry.UtxoKey)
		}

		// Delete the entry if it was spent
		if utxoEntry.isSpent {
			numDeleted++

			if err := DeleteUnmodifiedMappingsForUtxoWithTxn(txn, &utxoKey); err != nil {
				return err
			}
		}
	}

	for utxoKeyIter, utxoEntry := range bav.UtxoKeyToUtxoEntry {
		// Make a copy of the iterator since it might change from under us.
		utxoKey := utxoKeyIter

		// If the entry is unspent, then we need to re-set its mappings in the db appropriately.
		if !utxoEntry.isSpent {
			numPut++
			if err := PutMappingsForUtxoWithTxn(txn, &utxoKey, utxoEntry); err != nil {
				return err
			}
		}
	}

	glog.Debugf("_flushUtxosToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)

	// Now update the number of entries in the db with confidence.
	if err := PutUtxoNumEntriesWithTxn(txn, bav.NumUtxoEntries); err != nil {
		return err
	}

	// At this point, the db's position index should be updated and the (key -> entry)
	// index should be updated to remove all spent utxos. The number of entries field
	// in the db should also be accurate.

	return nil
}

func (bav *UtxoView) _flushDeSoBalancesToDbWithTxn(txn *badger.Txn) error {
	glog.Debugf("_flushDeSoBalancesToDbWithTxn: flushing %d mappings",
		len(bav.PublicKeyToDeSoBalanceNanos))

	for pubKeyIter, balanceNanos := range bav.PublicKeyToDeSoBalanceNanos {
		// Make a copy of the iterator since it might change from under us.
		pubKey := pubKeyIter[:]

		if balanceNanos > 0 {
			if err := DbPutDeSoBalanceForPublicKeyWithTxn(txn, pubKey, balanceNanos); err != nil {
				return err
			}
		} else {
			if err := DbDeletePublicKeyToDeSoBalanceWithTxn(txn, pubKey); err != nil {
				return err
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushGlobalParamsEntryToDbWithTxn(txn *badger.Txn) error {
	globalParamsEntry := bav.GlobalParamsEntry
	if err := DbPutGlobalParamsEntryWithTxn(txn, *globalParamsEntry); err != nil {
		return errors.Wrapf(err, "_flushGlobalParamsEntryToDbWithTxn: Problem putting global params entry in DB")
	}
	return nil
}

func (bav *UtxoView) _flushForbiddenPubKeyEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through all the entries in the KeyTorepostEntry map.
	for _, forbiddenPubKeyEntry := range bav.ForbiddenPubKeyToForbiddenPubKeyEntry {
		// Delete the existing mappings in the db for this ForbiddenPubKeyEntry. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DbDeleteForbiddenBlockSignaturePubKeyWithTxn(
			txn, forbiddenPubKeyEntry.PubKey[:]); err != nil {

			return errors.Wrapf(
				err, "_flushForbiddenPubKeyEntriesToDbWithTxn: Problem deleting "+
					"forbidden public key: %v: ", &forbiddenPubKeyEntry.PubKey)
		}
	}

	for _, forbiddenPubKeyEntry := range bav.ForbiddenPubKeyToForbiddenPubKeyEntry {
		if forbiddenPubKeyEntry.isDeleted {
			// If the ForbiddenPubKeyEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If the ForbiddenPubKeyEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DbPutForbiddenBlockSignaturePubKeyWithTxn(txn, forbiddenPubKeyEntry.PubKey); err != nil {
				return err
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushBitcoinExchangeDataWithTxn(txn *badger.Txn) error {
	// Iterate through our in-memory map. If anything has a value of false it means
	// that particular mapping should be expunged from the db. If anything has a value
	// of true it means that mapping should be added to the db.
	for bitcoinBurnTxIDIter, mappingExists := range bav.BitcoinBurnTxIDs {
		// Be paranoid and copy the iterator in case anything takes a reference below.
		bitcoinBurnTxID := bitcoinBurnTxIDIter

		if mappingExists {
			// In this case we should add the mapping to the db.
			if err := DbPutBitcoinBurnTxIDWithTxn(txn, &bitcoinBurnTxID); err != nil {
				return errors.Wrapf(err, "UtxoView._flushBitcoinExchangeDataWithTxn: "+
					"Problem putting BitcoinBurnTxID %v to db", &bitcoinBurnTxID)
			}
		} else {
			// In this case we should delete the mapping from the db.
			if err := DbDeleteBitcoinBurnTxIDWithTxn(txn, &bitcoinBurnTxID); err != nil {
				return errors.Wrapf(err, "UtxoView._flushBitcoinExchangeDataWithTxn: "+
					"Problem deleting BitcoinBurnTxID %v to db", &bitcoinBurnTxID)
			}
		}
	}

	// Update NanosPurchased
	if err := DbPutNanosPurchasedWithTxn(txn, bav.NanosPurchased); err != nil {
		errors.Wrapf(err, "UtxoView._flushBitcoinExchangeDataWithTxn: "+
			"Problem putting NanosPurchased %d to db", bav.NanosPurchased)
	}

	// Update the BitcoinUSDExchangeRate in the db
	if err := DbPutUSDCentsPerBitcoinExchangeRateWithTxn(txn, bav.USDCentsPerBitcoin); err != nil {
		errors.Wrapf(err, "UtxoView.FlushToDBWithTxn: "+
			"Problem putting USDCentsPerBitcoin %d to db", bav.USDCentsPerBitcoin)
	}

	// DB should be fully up to date as far as BitcoinBurnTxIDs and NanosPurchased go.
	return nil
}

func (bav *UtxoView) _flushMessageEntriesToDbWithTxn(txn *badger.Txn) error {
	// Go through all the entries in the MessageKeyToMessageEntry map.
	for messageKeyIter, messageEntry := range bav.MessageKeyToMessageEntry {
		// Make a copy of the iterator since we take references to it below.
		messageKey := messageKeyIter

		// Sanity-check that one of the MessageKey computed from the MEssageEntry is
		// equal to the MessageKey that maps to that entry.
		senderMessageKeyInEntry := MakeMessageKey(messageEntry.SenderPublicKey, messageEntry.TstampNanos)
		recipientMessageKeyInEntry := MakeMessageKey(messageEntry.RecipientPublicKey, messageEntry.TstampNanos)
		if senderMessageKeyInEntry != messageKey && recipientMessageKeyInEntry != messageKey {
			return fmt.Errorf("_flushMessageEntriesToDbWithTxn: MessageEntry has "+
				"SenderMessageKey: %v and RecipientMessageKey %v, neither of which match "+
				"the MessageKeyToMessageEntry map key %v",
				&senderMessageKeyInEntry, &recipientMessageKeyInEntry, &messageKey)
		}

		if messageEntry.isDeleted {
			// Delete the existing mappings in the db for this MessageKey. They will be re-added
			// if the corresponding entry in memory has isDeleted=false.
			if err := DbDeleteMessageEntryMappingsWithTxn(txn, messageKey.PublicKey[:], messageKey.TstampNanos); err != nil {
				return errors.Wrapf(err, "_flushMessageEntriesToDbWithTxn: Problem deleting mappings "+
					"for MessageKey: %v: ", &messageKey)
			}
		} else {
			// If the MessageEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DbPutMessageEntryWithTxn(txn, messageEntry); err != nil {

				return err
			}
		}
	}

	// At this point all of the MessageEntry mappings in the db should be up-to-date.

	return nil
}

func (bav *UtxoView) _flushRepostEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through all the entries in the repostKeyTorepostEntry map.
	for repostKeyIter, repostEntry := range bav.RepostKeyToRepostEntry {
		// Make a copy of the iterator since we make references to it below.
		repostKey := repostKeyIter

		// Sanity-check that the RepostKey computed from the RepostEntry is equal to the RepostKey for that entry.
		repostKeyInEntry := MakeRepostKey(repostEntry.ReposterPubKey, *repostEntry.RepostedPostHash)
		if repostKeyInEntry != repostKey {
			return fmt.Errorf("_flushRepostEntriesToDbWithTxn: RepostEntry has "+
				"RepostKey: %v, which doesn't match the RepostKeyToRepostEntry map key %v",
				&repostKeyInEntry, &repostKey)
		}

		if repostEntry.isDeleted {
			// Delete the existing mappings in the db for this RepostKey.
			if err := DbDeleteRepostMappingsWithTxn(txn, repostKey.ReposterPubKey[:], repostKey.RepostedPostHash); err != nil {

				return errors.Wrapf(
					err, "_flushRepostEntriesToDbWithTxn: Problem deleting mappings "+
						"for RepostKey: %v: ", &repostKey)
			}
		} else {
			// If the RepostEntry has (isDeleted = false) then we put the corresponding mappings for it into the db.
			if err := DbPutRepostMappingsWithTxn(
				txn, repostEntry.ReposterPubKey, *repostEntry.RepostedPostHash, *repostEntry); err != nil {
				return err
			}
		}
	}

	// At this point all of the RepostEntry mappings in the db should be up-to-date.

	return nil
}

func (bav *UtxoView) _flushLikeEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through all the entries in the LikeKeyToLikeEntry map.
	for likeKeyIter, likeEntry := range bav.LikeKeyToLikeEntry {
		// Make a copy of the iterator since we make references to it below.
		likeKey := likeKeyIter

		// Sanity-check that the LikeKey computed from the LikeEntry is equal to the LikeKey for that entry.
		likeKeyInEntry := MakeLikeKey(likeEntry.LikerPubKey, *likeEntry.LikedPostHash)
		if likeKeyInEntry != likeKey {
			return fmt.Errorf("_flushLikeEntriesToDbWithTxn: LikeEntry has "+
				"LikeKey: %v, which doesn't match the LikeKeyToLikeEntry map key %v",
				&likeKeyInEntry, &likeKey)
		}

		if likeEntry.isDeleted {
			// Delete the existing mappings in the db for this LikeKey.
			if err := DbDeleteLikeMappingsWithTxn(txn, likeKey.LikerPubKey[:], likeKey.LikedPostHash); err != nil {
				return errors.Wrapf(
					err, "_flushLikeEntriesToDbWithTxn: Problem deleting mappings "+
						"for LikeKey: %v: ", &likeKey)
			}
		} else {
			// If the LikeEntry has (isDeleted = false) then we put the corresponding mappings for it into the db.
			if err := DbPutLikeMappingsWithTxn(txn, likeEntry.LikerPubKey, *likeEntry.LikedPostHash); err != nil {

				return err
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushFollowEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through all the entries in the FollowKeyToFollowEntry map.
	for followKeyIter, followEntry := range bav.FollowKeyToFollowEntry {
		// Make a copy of the iterator since we make references to it below.
		followKey := followKeyIter

		// Sanity-check that the FollowKey computed from the FollowEntry is equal to the FollowKey for that entry.
		followKeyInEntry := MakeFollowKey(followEntry.FollowerPKID, followEntry.FollowedPKID)
		if followKeyInEntry != followKey {
			return fmt.Errorf("_flushFollowEntriesToDbWithTxn: FollowEntry has "+
				"FollowKey: %v, which doesn't match the FollowKeyToFollowEntry map key %v",
				&followKeyInEntry, &followKey)
		}

		// Delete the existing mappings in the db for this FollowKey
		if followEntry.isDeleted {
			if err := DbDeleteFollowMappingsWithTxn(txn, followEntry.FollowerPKID, followEntry.FollowedPKID); err != nil {
				return errors.Wrapf(
					err, "_flushFollowEntriesToDbWithTxn: Problem deleting mappings "+
						"for FollowKey: %v: ", &followKey)
			}
		} else {
			// If the FollowEntry has (isDeleted = false) then we put the corresponding mappings for it into the db.
			if err := DbPutFollowMappingsWithTxn(txn, followEntry.FollowerPKID, followEntry.FollowedPKID); err != nil {
				return err
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushNFTEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through and delete all the entries so they can be added back fresh.
	for nftKeyIter, nftEntry := range bav.NFTKeyToNFTEntry {
		// Make a copy of the iterator since we make references to it below.
		nftKey := nftKeyIter

		// Sanity-check that the NFTKey computed from the NFTEntry is  equal to the NFTKey for that entry.
		nftKeyInEntry := MakeNFTKey(nftEntry.NFTPostHash, nftEntry.SerialNumber)
		if nftKeyInEntry != nftKey {
			return fmt.Errorf("_flushNFTEntriesToDbWithTxn: NFTEntry has "+
				"NFTKey: %v, which doesn't match the NFTKeyToNFTEntry map key %v",
				&nftKeyInEntry, &nftKey)
		}

		if nftEntry.isDeleted {
			// Delete the existing mappings in the db for this NFTKey.
			if err := DBDeleteNFTMappingsWithTxn(txn, nftEntry.NFTPostHash, nftEntry.SerialNumber); err != nil {
				return errors.Wrapf(
					err, "_flushNFTEntriesToDbWithTxn: Problem deleting mappings "+
						"for NFTKey: %v: ", &nftKey)
			}
		} else {
			// If the NFTEntry has (isDeleted = false) then we put the corresponding mappings for it into the db.
			if err := DBPutNFTEntryMappingsWithTxn(txn, nftEntry); err != nil {
				return err
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushAcceptedBidEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through and delete all the entries so they can be added back fresh.
	for nftKeyIter, acceptedNFTBidEntries := range bav.NFTKeyToAcceptedNFTBidHistory {
		// Make a copy of the iterator since we make references to it below.
		nftKey := nftKeyIter

		// We skip the standard sanity check.  Since it is possible to accept a bid on serial number 0, it is possible
		// that none of the accepted bids have the same serial number as the key.

		if acceptedNFTBidEntries == nil || len(*acceptedNFTBidEntries) == 0 {
			// If the acceptedNFTBidEntries is nil or has length 0 then we delete the entry.
			// Length 0 means that there are no accepted bids yet.
			if err := DBDeleteAcceptedNFTBidEntriesMappingsWithTxn(txn, &nftKey.NFTPostHash, nftKey.SerialNumber); err != nil {
				return errors.Wrapf(
					err, "_flushAcceptedBidEntriesToDbWithTxn: Problem deleting mappings "+
						"for NFTKey: %v: ", &nftKey)
			}
		} else {
			// If the NFTEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DBPutAcceptedNFTBidEntriesMappingWithTxn(txn, nftKey, acceptedNFTBidEntries); err != nil {
				return err
			}
		}

	}

	return nil
}

func (bav *UtxoView) _flushNFTBidEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through and delete all the entries so they can be added back fresh.
	for nftBidKeyIter, nftBidEntry := range bav.NFTBidKeyToNFTBidEntry {
		// Make a copy of the iterator since we make references to it below.
		nftBidKey := nftBidKeyIter

		// Sanity-check that the NFTBidKey computed from the NFTBidEntry is
		// equal to the NFTBidKey that maps to that entry.
		nftBidKeyInEntry := MakeNFTBidKey(nftBidEntry.BidderPKID, nftBidEntry.NFTPostHash, nftBidEntry.SerialNumber)
		if nftBidKeyInEntry != nftBidKey {
			return fmt.Errorf("_flushNFTBidEntriesToDbWithTxn: NFTBidEntry has "+
				"NFTBidKey: %v, which doesn't match the NFTBidKeyToNFTEntry map key %v",
				&nftBidKeyInEntry, &nftBidKey)
		}

		// Delete the existing mappings in the db for this NFTBidKey.
		// TODO: Why do we need to delete these even if isDeleted is false?
		if err := DBDeleteNFTBidMappingsWithTxn(txn, &nftBidKey); err != nil {
			return errors.Wrapf(
				err, "_flushNFTBidEntriesToDbWithTxn: Problem deleting mappings "+
					"for NFTBidKey: %v: ", &nftBidKey)
		}

		if !nftBidEntry.isDeleted {
			// If the NFTEntry has (isDeleted = false) then we put the corresponding mappings for it into the db.
			if err := DBPutNFTBidEntryMappingsWithTxn(txn, nftBidEntry); err != nil {
				return err
			}
		}

	}

	return nil
}

func (bav *UtxoView) _flushDiamondEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through and delete all the entries so they can be added back fresh.
	for diamondKeyIter, diamondEntry := range bav.DiamondKeyToDiamondEntry {
		// Make a copy of the iterator since we make references to it below.
		diamondKey := diamondKeyIter

		// Sanity-check that the DiamondKey computed from the DiamondEntry is
		// equal to the DiamondKey that maps to that entry.
		diamondKeyInEntry := MakeDiamondKey(
			diamondEntry.SenderPKID, diamondEntry.ReceiverPKID, diamondEntry.DiamondPostHash)
		if diamondKeyInEntry != diamondKey {
			return fmt.Errorf("_flushDiamondEntriesToDbWithTxn: DiamondEntry has "+
				"DiamondKey: %v, which doesn't match the DiamondKeyToDiamondEntry map key %v",
				&diamondKeyInEntry, &diamondKey)
		}

		if diamondEntry.isDeleted {
			// Delete the existing mappings in the db for this DiamondKey.
			if err := DbDeleteDiamondMappingsWithTxn(txn, diamondEntry); err != nil {
				return errors.Wrapf(
					err, "_flushDiamondEntriesToDbWithTxn: Problem deleting mappings "+
						"for DiamondKey: %v: ", &diamondKey)
			}
		} else {
			// If the DiamondEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DbPutDiamondMappingsWithTxn(txn, diamondEntry); err != nil {
				return err
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushPostEntriesToDbWithTxn(txn *badger.Txn) error {
	// Go through all the entries in the PostHashToPostEntry map.
	for postHashIter, postEntry := range bav.PostHashToPostEntry {
		// Make a copy of the iterator since we take references to it below.
		postHash := postHashIter

		// Sanity-check that the hash in the post is the same as the hash in the entry
		if postHash != *postEntry.PostHash {
			return fmt.Errorf("_flushPostEntriesToDbWithTxn: PostEntry has "+
				"PostHash: %v, neither of which match "+
				"the PostHashToPostEntry map key %v",
				postHash, postEntry.PostHash)
		}

		if postEntry.isDeleted {
			// Delete the existing mappings in the db for this PostHash.
			if err := DBDeletePostEntryMappingsWithTxn(txn, &postHash, bav.Params); err != nil {
				return errors.Wrapf(
					err, "_flushPostEntriesToDbWithTxn: Problem deleting mappings "+
						"for PostHash: %v: ", postHash)
			}
		} else {
			// If the PostEntry has (isDeleted = false) then we put the corresponding mappings for it into the db.
			if err := DBPutPostEntryMappingsWithTxn(txn, postEntry, bav.Params); err != nil {

				return err
			}
		}
	}

	return nil
}
func (bav *UtxoView) _flushPKIDEntriesToDbWithTxn(txn *badger.Txn) error {
	// Go through all the entries in the ProfilePublicKeyToProfileEntry map.
	for pubKeyIter, pkidEntry := range bav.PublicKeyToPKIDEntry {
		pubKeyCopy := make([]byte, btcec.PubKeyBytesLenCompressed)
		copy(pubKeyCopy, pubKeyIter[:])

		// Only flush dirty PKID entries
		if !pkidEntry.isDirty {
			continue
		}

		if pkidEntry.isDeleted {
			// Delete the existing mappings in the db for this PKID
			if err := DBDeletePKIDMappingsWithTxn(txn, pubKeyCopy, bav.Params); err != nil {
				return errors.Wrapf(
					err, "_flushPKIDEntriesToDbWithTxn: Problem deleting mappings "+
						"for pkid: %v, public key: %v: ", PkToString(pkidEntry.PKID[:], bav.Params),
					PkToString(pubKeyCopy, bav.Params))
			}
		} else {
			// Sanity-check that the public key in the entry matches the public key in
			// the mapping.
			if !reflect.DeepEqual(pubKeyCopy, pkidEntry.PublicKey) {
				return fmt.Errorf("_flushPKIDEntriesToDbWithTxn: Sanity-check failed. "+
					"Public key in entry %v does not match public key in mapping %v ",
					PkToString(pkidEntry.PublicKey[:], bav.Params),
					PkToString(pubKeyCopy, bav.Params))
			}
			// Sanity-check that the mapping in the public key map lines up with the mapping
			// in the PKID map.
			if _, pkidEntryExists := bav.PKIDToPublicKey[*pkidEntry.PKID]; !pkidEntryExists {
				return fmt.Errorf("_flushPKIDEntriesToDbWithTxn: Sanity-check failed. "+
					"PKID %v for public key %v does not exist in PKIDToPublicKey map.",
					PkToString(pkidEntry.PKID[:], bav.Params),
					PkToString(pubKeyCopy, bav.Params))
			}

			// If the ProfileEntry has (isDeleted = false) then we put the corresponding mappings for it into the db.
			if err := DBPutPKIDMappingsWithTxn(txn, pubKeyCopy, pkidEntry, bav.Params); err != nil {
				return err
			}
		}
	}

	// At this point all of the PKIDEntry mappings in the db should be up-to-date.
	return nil
}

func (bav *UtxoView) _flushProfileEntriesToDbWithTxn(txn *badger.Txn) error {
	glog.Debugf("_flushProfilesToDbWithTxn: flushing %d mappings", len(bav.ProfilePKIDToProfileEntry))

	// Go through all the entries in the ProfilePublicKeyToProfileEntry map.
	for profilePKIDIter, profileEntry := range bav.ProfilePKIDToProfileEntry {
		// Make a copy of the iterator since we take references to it below.
		profilePKID := profilePKIDIter

		// Delete the existing mappings in the db for this PKID. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DBDeleteProfileEntryMappingsWithTxn(txn, &profilePKID, bav.Params); err != nil {
			return errors.Wrapf(
				err, "_flushProfileEntriesToDbWithTxn: Problem deleting mappings "+
					"for pkid: %v, public key: %v: ", PkToString(profilePKID[:], bav.Params),
				PkToString(profileEntry.PublicKey, bav.Params))
		}
	}
	numDeleted := 0
	numPut := 0
	for profilePKIDIter, profileEntry := range bav.ProfilePKIDToProfileEntry {
		// Make a copy of the iterator since we take references to it below.
		profilePKID := profilePKIDIter

		if profileEntry.isDeleted {
			numDeleted++
			// If the ProfileEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			numPut++
			// Get the PKID according to another map in the view and
			// sanity-check that it lines up.
			viewPKIDEntry := bav.GetPKIDForPublicKey(profileEntry.PublicKey)
			if viewPKIDEntry == nil || viewPKIDEntry.isDeleted || *viewPKIDEntry.PKID != profilePKID {
				return fmt.Errorf("_flushProfileEntriesToDbWithTxn: Sanity-check failed: PKID %v does "+
					"not exist in view mapping for profile with public key %v",
					PkToString(profilePKID[:], bav.Params),
					PkToString(profileEntry.PublicKey, bav.Params))
			}

			// If the ProfileEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DBPutProfileEntryMappingsWithTxn(
				txn, profileEntry, &profilePKID, bav.Params); err != nil {

				return err
			}
		}
	}

	glog.Debugf("_flushProfilesToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)

	// At this point all of the PostEntry mappings in the db should be up-to-date.

	return nil
}

func (bav *UtxoView) _flushBalanceEntriesToDbWithTxn(txn *badger.Txn) error {
	glog.Debugf("_flushBalanceEntriesToDbWithTxn: flushing %d mappings", len(bav.HODLerPKIDCreatorPKIDToBalanceEntry))

	// Go through all the entries in the HODLerPubKeyCreatorPubKeyToBalanceEntry map.
	for balanceKeyIter, balanceEntry := range bav.HODLerPKIDCreatorPKIDToBalanceEntry {
		// Make a copy of the iterator since we take references to it below.
		balanceKey := balanceKeyIter

		// Sanity-check that the balance key in the map is the same
		// as the public key in the entry.
		computedBalanceKey := MakeCreatorCoinBalanceKey(
			balanceEntry.HODLerPKID, balanceEntry.CreatorPKID)
		if !reflect.DeepEqual(balanceKey, computedBalanceKey) {
			return fmt.Errorf("_flushBalanceEntriesToDbWithTxn: BalanceEntry has "+
				"map key: %v which does not match match "+
				"the HODLerPubKeyCreatorPubKeyToBalanceEntry map key %v",
				balanceKey, computedBalanceKey)
		}

		// Delete the existing mappings in the db for this balance key. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DBDeleteCreatorCoinBalanceEntryMappingsWithTxn(
			txn, &(balanceKey.HODLerPKID), &(balanceKey.CreatorPKID), bav.Params); err != nil {

			return errors.Wrapf(
				err, "_flushBalanceEntriesToDbWithTxn: Problem deleting mappings "+
					"for public key: %v: ", balanceKey)
		}
	}
	numDeleted := 0
	numPut := 0
	// Go through all the entries in the HODLerPubKeyCreatorPubKeyToBalanceEntry map.
	for _, balanceEntry := range bav.HODLerPKIDCreatorPKIDToBalanceEntry {
		// Make a copy of the iterator since we take references to it below.
		if balanceEntry.isDeleted {
			numDeleted++
			// If the ProfileEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			numPut++
			// If the ProfileEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DBPutCreatorCoinBalanceEntryMappingsWithTxn(
				txn, balanceEntry, bav.Params); err != nil {

				return err
			}
		}
	}

	glog.Debugf("_flushBalanceEntriesToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)

	// At this point all of the PostEntry mappings in the db should be up-to-date.

	return nil
}

func (bav *UtxoView) _flushDerivedKeyEntryToDbWithTxn(txn *badger.Txn) error {
	glog.Debugf("_flushDerivedKeyEntryToDbWithTxn: flushing %d mappings", len(bav.DerivedKeyToDerivedEntry))

	// Go through all entries in the DerivedKeyToDerivedEntry map and add them to the DB.
	for derivedKeyMapKey, derivedKeyEntry := range bav.DerivedKeyToDerivedEntry {
		// Delete the existing mapping in the DB for this map key, this will be re-added
		// later if isDeleted=false.
		if err := DBDeleteDerivedKeyMappingWithTxn(txn, derivedKeyMapKey.OwnerPublicKey,
			derivedKeyMapKey.DerivedPublicKey); err != nil {
			return errors.Wrapf(err, "UtxoView._flushDerivedKeyEntryToDbWithTxn: "+
				"Problem deleting DerivedKeyEntry %v from db", *derivedKeyEntry)
		}

		numDeleted := 0
		numPut := 0
		if derivedKeyEntry.isDeleted {
			// Since entry is deleted, there's nothing to do.
			numDeleted++
		} else {
			// In this case we add the mapping to the DB.
			if err := DBPutDerivedKeyMappingWithTxn(txn, derivedKeyMapKey.OwnerPublicKey,
				derivedKeyMapKey.DerivedPublicKey, derivedKeyEntry); err != nil {
				return errors.Wrapf(err, "UtxoView._flushDerivedKeyEntryToDbWithTxn: "+
					"Problem putting DerivedKeyEntry %v to db", *derivedKeyEntry)
			}
			numPut++
		}
		glog.Debugf("_flushDerivedKeyEntryToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)
	}

	return nil
}

func (bav *UtxoView) FlushToDbWithTxn(txn *badger.Txn) error {
	// Only flush to BadgerDB if Postgres is disabled
	if bav.Postgres == nil {
		if err := bav._flushUtxosToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushProfileEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushPKIDEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushPostEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushLikeEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushFollowEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushDiamondEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushMessageEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushBalanceEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushDeSoBalancesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushForbiddenPubKeyEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushNFTEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushNFTBidEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushDerivedKeyEntryToDbWithTxn(txn); err != nil {
			return err
		}
	}

	// Always flush to BadgerDB.
	if err := bav._flushBitcoinExchangeDataWithTxn(txn); err != nil {
		return err
	}
	if err := bav._flushGlobalParamsEntryToDbWithTxn(txn); err != nil {
		return err
	}
	if err := bav._flushAcceptedBidEntriesToDbWithTxn(txn); err != nil {
		return err
	}
	if err := bav._flushRepostEntriesToDbWithTxn(txn); err != nil {
		return err
	}

	return nil
}

func (bav *UtxoView) FlushToDb() error {
	// Make sure everything happens inside a single transaction.
	var err error
	if bav.Postgres != nil {
		err = bav.Postgres.FlushView(bav)
		if err != nil {
			return err
		}
	}

	err = bav.Handle.Update(func(txn *badger.Txn) error {
		return bav.FlushToDbWithTxn(txn)
	})
	if err != nil {
		return err
	}

	// After a successful flush, reset the in-memory mappings for the view
	// so that it can be re-used if desired.
	//
	// Note that the TipHash does not get reset as part of _ResetViewMappingsAfterFlush because
	// it is not something that is affected by a flush operation. Moreover, its value
	// is consistent with the view regardless of whether or not the view is flushed or
	// not.
	bav._ResetViewMappingsAfterFlush()

	return nil
}
