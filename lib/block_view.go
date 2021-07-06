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
	merkletree "github.com/laser/go-merkle-tree"
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

	// NEXT_TAG = 6
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
// This needs to be in-sync with BitCloutMainnetParams.MaxUsernameLengthBytes
type UsernameMapKey [MaxUsernameLengthBytes]byte

func MakeUsernameMapKey(nonLowercaseUsername []byte) UsernameMapKey {
	// Always lowercase the username when we use it as a key in our map. This allows
	// us to check uniqueness in a case-insensitive way.
	lowercaseUsername := []byte(strings.ToLower(string(nonLowercaseUsername)))
	usernameMapKey := UsernameMapKey{}
	copy(usernameMapKey[:], lowercaseUsername)
	return usernameMapKey
}

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
func (mm *MessageKey) StringKey(params *BitCloutParams) string {
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

func MakeRecloutKey(userPk []byte, RecloutedPostHash BlockHash) RecloutKey {
	return RecloutKey{
		ReclouterPubKey:   MakePkMapKey(userPk),
		RecloutedPostHash: RecloutedPostHash,
	}
}

type RecloutKey struct {
	ReclouterPubKey PkMapKey
	// Post Hash of post that was reclouted
	RecloutedPostHash BlockHash
}

// RecloutEntry stores the content of a Reclout transaction.
type RecloutEntry struct {
	ReclouterPubKey []byte

	// BlockHash of the reclout
	RecloutPostHash *BlockHash

	// Post Hash of post that was reclouted
	RecloutedPostHash *BlockHash

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

type GlobalParamsEntry struct {
	// The new exchange rate to set.
	USDCentsPerBitcoin uint64

	// The new create profile fee
	CreateProfileFeeNanos uint64

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

	// This is true if the reader has reclouted the associated post.
	RecloutedByReader bool

	// This is the post hash hex of the reclout
	RecloutPostHashHex string
}

func (bav *UtxoView) GetPostEntryReaderState(
	readerPK []byte, postEntry *PostEntry) *PostEntryReaderState {
	postEntryReaderState := &PostEntryReaderState{}

	// Get like state.
	postEntryReaderState.LikedByReader = bav.GetLikedByReader(readerPK, postEntry.PostHash)

	// Get reclout state.
	postEntryReaderState.RecloutPostHashHex, postEntryReaderState.RecloutedByReader = bav.GetRecloutPostEntryStateForReader(readerPK, postEntry.PostHash)

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

func (bav *UtxoView) GetRecloutPostEntryStateForReader(readerPK []byte, postHash *BlockHash) (string, bool) {
	recloutKey := MakeRecloutKey(readerPK, *postHash)
	recloutEntry := bav._getRecloutEntryForRecloutKey(&recloutKey)
	if recloutEntry == nil {
		return "", false
	}
	recloutPostEntry := bav.GetPostEntryForPostHash(recloutEntry.RecloutPostHash)
	if recloutPostEntry == nil {
		glog.Errorf("Could not find reclout post entry from post hash: %v", recloutEntry.RecloutedPostHash)
		return "", false
	}
	// We include the PostHashHex of this user's post that reclouts the current post to
	// handle undo-ing (AKA hiding) a reclout.
	// If the user's reclout of this post is hidden, we set RecloutedByReader to false.
	return hex.EncodeToString(recloutEntry.RecloutPostHash[:]), !recloutPostEntry.IsHidden
}

type SingleStake struct {
	// Just save the data from the initial stake for posterity.
	InitialStakeNanos               uint64
	BlockHeight                     uint64
	InitialStakeMultipleBasisPoints uint64
	// The amount distributed to previous users can be computed by
	// adding the creator percentage and the burn fee and then
	// subtracting that total percentage off of the InitialStakeNanos.
	// Example:
	// - InitialStakeNanos = 100
	// - CreatorPercentage = 15%
	// - BurnFeePercentage = 10%
	// - Amount to pay to previous users = 100 - 15 - 10 = 75
	InitialCreatorPercentageBasisPoints uint64

	// These fields are what we actually use to pay out the user who staked.
	//
	// The initial RemainingAmountOwedNanos is computed by simply multiplying
	// the InitialStakeNanos by the InitialStakeMultipleBasisPoints.
	RemainingStakeOwedNanos uint64
	PublicKey               []byte
}

type StakeEntry struct {
	StakeList []*SingleStake

	// Computed for profiles to cache how much has been staked to
	// their posts in total. When a post is staked to, this value
	// gets incremented on the profile. It gets reverted on the
	// profile when the post stake is reverted.
	TotalPostStake uint64
}

func NewStakeEntry() *StakeEntry {
	return &StakeEntry{
		StakeList: []*SingleStake{},
	}
}

func StakeEntryCopy(stakeEntry *StakeEntry) *StakeEntry {
	newStakeEntry := NewStakeEntry()
	for _, singleStake := range stakeEntry.StakeList {
		singleStakeCopy := *singleStake
		newStakeEntry.StakeList = append(newStakeEntry.StakeList, &singleStakeCopy)
	}
	newStakeEntry.TotalPostStake = stakeEntry.TotalPostStake

	return newStakeEntry
}

type StakeEntryStats struct {
	TotalStakeNanos           uint64
	TotalStakeOwedNanos       uint64
	TotalCreatorEarningsNanos uint64
	TotalFeesBurnedNanos      uint64
	TotalPostStakeNanos       uint64
}

func GetStakeEntryStats(stakeEntry *StakeEntry, params *BitCloutParams) *StakeEntryStats {
	stakeEntryStats := &StakeEntryStats{}

	for _, singleStake := range stakeEntry.StakeList {
		stakeEntryStats.TotalStakeNanos += singleStake.InitialStakeNanos
		stakeEntryStats.TotalStakeOwedNanos += singleStake.RemainingStakeOwedNanos
		// Be careful when computing these values in order to avoid overflow.
		stakeEntryStats.TotalCreatorEarningsNanos += big.NewInt(0).Div(
			big.NewInt(0).Mul(
				big.NewInt(int64(singleStake.InitialStakeNanos)),
				big.NewInt(int64(singleStake.InitialCreatorPercentageBasisPoints))),
			big.NewInt(100*100)).Uint64()
		stakeEntryStats.TotalFeesBurnedNanos += big.NewInt(0).Div(
			big.NewInt(0).Mul(
				big.NewInt(int64(singleStake.InitialStakeNanos)),
				big.NewInt(int64(params.StakeFeeBasisPoints))),
			big.NewInt(100*100)).Uint64()
	}
	stakeEntryStats.TotalPostStakeNanos = stakeEntry.TotalPostStake

	return stakeEntryStats
}

type StakeIDType uint8

const (
	StakeIDTypePost    StakeIDType = 0
	StakeIDTypeProfile StakeIDType = 1
)

func (ss StakeIDType) String() string {
	if ss == StakeIDTypePost {
		return "post"
	} else if ss == StakeIDTypeProfile {
		return "profile"
	} else {
		return "unknown"
	}
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

	// The PostHash of the post this post reclouts
	RecloutedPostHash *BlockHash

	// Indicator if this PostEntry is a quoted reclout or not
	IsQuotedReclout bool

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

	// Every post has a StakeEntry that keeps track of all the stakes that
	// have been applied to this post.
	StakeEntry *StakeEntry

	// Counter of users that have liked this post.
	LikeCount uint64

	// Counter of users that have reclouted this post.
	RecloutCount uint64

	// Counter of quote reclouts for this post.
	QuoteRecloutCount uint64

	// Counter of diamonds that the post has received.
	DiamondCount uint64

	// The private fields below aren't serialized or hashed. They are only kept
	// around for in-memory bookkeeping purposes.

	// Used to sort posts by their stake. Generally not set.
	stakeStats *StakeEntryStats

	// Whether or not this entry is deleted in the view.
	isDeleted bool

	// How many comments this post has
	CommentCount uint64

	// Indicator if a post is pinned or not.
	IsPinned bool

	// ExtraData map to hold arbitrary attributes of a post. Holds non-consensus related information about a post.
	PostExtraData map[string][]byte
}

func (pe *PostEntry) IsDeleted() bool {
	return pe.isDeleted
}

func IsQuotedReclout(postEntry *PostEntry) bool {
	return postEntry.IsQuotedReclout && postEntry.RecloutedPostHash != nil
}

func (pe *PostEntry) HasMedia() bool {
	bodyJSONObj := BitCloutBodySchema{}
	err := json.Unmarshal(pe.Body, &bodyJSONObj)
	//Return true if body json can be parsed and ImageUrls is not nil/non-empty or EmbedVideoUrl is not nil/non-empty
	if (err == nil && len(bodyJSONObj.ImageURLs) > 0) || len(pe.PostExtraData["EmbedVideoURL"]) > 0 {
		return true
	}
	return false
}

// Return true if postEntry is a vanilla reclout.  A vanilla reclout is a post that reclouts another post,
// but does not have a body.
func IsVanillaReclout(postEntry *PostEntry) bool {
	return !postEntry.IsQuotedReclout && postEntry.RecloutedPostHash != nil
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

	// The amount of BitClout backing the coin. Whenever a user buys a coin
	// from the protocol this amount increases, and whenever a user sells a
	// coin to the protocol this decreases.
	BitCloutLockedNanos uint64

	// The number of public keys who have holdings in this creator coin.
	// Due to floating point truncation, it can be difficult to simultaneously
	// reset CoinsInCirculationNanos and BitCloutLockedNanos to zero after
	// everyone has sold all their creator coins. Initially NumberOfHolders
	// is set to zero. Once it returns to zero after a series of buys & sells
	// we reset the BitCloutLockedNanos and CoinsInCirculationNanos to prevent
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

	// TODO(DELETEME): This field is deprecated. It was relevant back when
	// we wanted to allow people to stake to profiles, which isn't something
	// we want to support going forward.
	//
	// The multiple of the payout when a user stakes to this profile. If
	// unset, a sane default is set when the first person stakes to this
	// profile.
	// 2x multiple = 200% = 20,000bps
	StakeMultipleBasisPoints uint64

	// TODO(DELETEME): This field is deprecated. It was relevant back when
	// we wanted to allow people to stake to profiles, which isn't something
	// we want to support going forward.
	//
	// Every provile has a StakeEntry that keeps track of all the stakes that
	// have been applied to it.
	StakeEntry *StakeEntry

	// The private fields below aren't serialized or hashed. They are only kept
	// around for in-memory bookkeeping purposes.

	// TODO(DELETEME): This field is deprecated. It was relevant back when
	// we wanted to allow people to stake to profiles, which isn't something
	// we want to support going forward.
	//
	// Used to sort profiles by their stake. Generally not set.
	stakeStats *StakeEntryStats
}

func (pe *ProfileEntry) IsDeleted() bool {
	return pe.isDeleted
}

type UtxoView struct {
	// Utxo data
	NumUtxoEntries     uint64
	UtxoKeyToUtxoEntry map[UtxoKey]*UtxoEntry

	// BitcoinExchange data
	NanosPurchased     uint64
	USDCentsPerBitcoin uint64
	GlobalParamsEntry  *GlobalParamsEntry
	BitcoinBurnTxIDs   map[BlockHash]bool

	// Forbidden block signature pubkeys
	ForbiddenPubKeyToForbiddenPubKeyEntry map[PkMapKey]*ForbiddenPubKeyEntry

	// Messages data
	MessageKeyToMessageEntry map[MessageKey]*MessageEntry

	// Follow data
	FollowKeyToFollowEntry map[FollowKey]*FollowEntry

	// Diamond data
	DiamondKeyToDiamondEntry map[DiamondKey]*DiamondEntry

	// Like data
	LikeKeyToLikeEntry map[LikeKey]*LikeEntry

	// Reclout data
	RecloutKeyToRecloutEntry map[RecloutKey]*RecloutEntry

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

	// The hash of the tip the view is currently referencing. Mainly used
	// for error-checking when doing a bulk operation on the view.
	TipHash *BlockHash

	BitcoinManager *BitcoinManager
	Handle         *badger.DB
	Params         *BitCloutParams
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

	// NEXT_TAG = 15
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
	PrevRecloutedPostEntry   *PostEntry

	// Save the previous profile entry when making an update.
	PrevProfileEntry *ProfileEntry

	// Save the previous like entry and like count when making an update.
	PrevLikeEntry *LikeEntry
	PrevLikeCount uint64

	// For disconnecting diamonds.
	PrevDiamondEntry *DiamondEntry

	// Save the previous reclout entry and reclout count when making an update.
	PrevRecloutEntry *RecloutEntry
	PrevRecloutCount uint64

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
}

// Assumes the db Handle is already set on the view, but otherwise the
// initialization is full.
func (bav *UtxoView) _ResetViewMappingsAfterFlush() {
	// Utxo data
	bav.UtxoKeyToUtxoEntry = make(map[UtxoKey]*UtxoEntry)
	bav.NumUtxoEntries = GetUtxoNumEntries(bav.Handle)

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

	// Follow data
	bav.FollowKeyToFollowEntry = make(map[FollowKey]*FollowEntry)

	// Diamond data
	bav.DiamondKeyToDiamondEntry = make(map[DiamondKey]*DiamondEntry)

	// Like data
	bav.LikeKeyToLikeEntry = make(map[LikeKey]*LikeEntry)

	// Reclout data
	bav.RecloutKeyToRecloutEntry = make(map[RecloutKey]*RecloutEntry)

	// Coin balance entries
	bav.HODLerPKIDCreatorPKIDToBalanceEntry = make(map[BalanceEntryMapKey]*BalanceEntry)
}

func (bav *UtxoView) CopyUtxoView() (*UtxoView, error) {
	newView, err := NewUtxoView(bav.Handle, bav.Params, bav.BitcoinManager)
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
		newProfileEntry := *profileEntry
		newView.ProfilePKIDToProfileEntry[profilePKID] = &newProfileEntry
	}
	newView.ProfileUsernameToProfileEntry = make(map[UsernameMapKey]*ProfileEntry, len(bav.ProfileUsernameToProfileEntry))
	for profilePKID, profileEntry := range bav.ProfileUsernameToProfileEntry {
		newProfileEntry := *profileEntry
		newView.ProfileUsernameToProfileEntry[profilePKID] = &newProfileEntry
	}

	// Copy the message data
	newView.MessageKeyToMessageEntry = make(map[MessageKey]*MessageEntry, len(bav.MessageKeyToMessageEntry))
	for msgKey, msgEntry := range bav.MessageKeyToMessageEntry {
		newMsgEntry := *msgEntry
		newView.MessageKeyToMessageEntry[msgKey] = &newMsgEntry
	}

	// Copy the follow data
	newView.FollowKeyToFollowEntry = make(map[FollowKey]*FollowEntry, len(bav.FollowKeyToFollowEntry))
	for followKey, followEntry := range bav.FollowKeyToFollowEntry {
		newFollowEntry := *followEntry
		newView.FollowKeyToFollowEntry[followKey] = &newFollowEntry
	}

	// Copy the like data
	newView.LikeKeyToLikeEntry = make(map[LikeKey]*LikeEntry, len(bav.LikeKeyToLikeEntry))
	for likeKey, likeEntry := range bav.LikeKeyToLikeEntry {
		newLikeEntry := *likeEntry
		newView.LikeKeyToLikeEntry[likeKey] = &newLikeEntry
	}

	// Copy the reclout data
	newView.RecloutKeyToRecloutEntry = make(map[RecloutKey]*RecloutEntry, len(bav.RecloutKeyToRecloutEntry))
	for recloutKey, recloutEntry := range bav.RecloutKeyToRecloutEntry {
		newRecloutEntry := *recloutEntry
		newView.RecloutKeyToRecloutEntry[recloutKey] = &newRecloutEntry
	}

	// Copy the balance entry data
	newView.HODLerPKIDCreatorPKIDToBalanceEntry = make(
		map[BalanceEntryMapKey]*BalanceEntry, len(bav.HODLerPKIDCreatorPKIDToBalanceEntry))
	for balanceEntryMapKey, balanceEntry := range bav.HODLerPKIDCreatorPKIDToBalanceEntry {
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

	return newView, nil
}

func NewUtxoView(
	_handle *badger.DB, _params *BitCloutParams, _bitcoinManager *BitcoinManager) (*UtxoView, error) {

	view := UtxoView{
		Handle:         _handle,
		Params:         _params,
		BitcoinManager: _bitcoinManager,
		// Note that the TipHash does not get reset as part of
		// _ResetViewMappingsAfterFlush because it is not something that is affected by a
		// flush operation. Moreover, its value is consistent with the view regardless of
		// whether or not the view is flushed or not. Additionally the utxo view does
		// not concern itself with the header chain (see comment on GetBestHash for more
		// info on that).
		TipHash: DbGetBestHash(_handle, ChainTypeBitCloutBlock /* don't get the header chain */),

		// Set everything else in _ResetViewMappings()
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
		utxoEntry = DbGetUtxoEntryForUtxoKey(bav.Handle, utxoKey)
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

func (bav *UtxoView) _disconnectBasicTransfer(currentTxn *MsgBitCloutTxn, txnHash *BlockHash, utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Loop through the transaction's outputs backwards and remove them
	// from the view. Since the outputs will have been added to the view
	// at the end of the utxo list, removing them from the view amounts to
	// removing the last element from the utxo list.
	//
	// Loop backwards over the utxo operations as we go along.
	operationIndex := len(utxoOpsForTxn) - 1
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
	operationType OperationType, currentTxn *MsgBitCloutTxn, txnHash *BlockHash,
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
	// the future in order to re-grant the public key the BitClout they are entitled
	// to (though possibly more or less than the amount of BitClout they had before
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

	// Reset NanosPurchased to the value it was before granting this BitClout to this user.
	// This previous value comes from the UtxoOperation data.
	prevNanosPurchased := operationData.PrevNanosPurchased
	bav.NanosPurchased = prevNanosPurchased

	// At this point the BitcoinExchange transaction should be fully reverted.
	return nil
}

func (bav *UtxoView) _disconnectUpdateBitcoinUSDExchangeRate(
	operationType OperationType, currentTxn *MsgBitCloutTxn, txnHash *BlockHash,
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

	// Reset exchange rate to the value it was before granting this BitClout to this user.
	// This previous value comes from the UtxoOperation data.
	prevUSDCentsPerBitcoin := operationData.PrevUSDCentsPerBitcoin
	bav.USDCentsPerBitcoin = prevUSDCentsPerBitcoin

	// Now revert the basic transfer with the remaining operations. Cut off
	// the UpdateBitcoinUSDExchangeRate operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) _disconnectUpdateGlobalParams(
	operationType OperationType, currentTxn *MsgBitCloutTxn, txnHash *BlockHash,
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

func (bav *UtxoView) _disconnectPrivateMessage(
	operationType OperationType, currentTxn *MsgBitCloutTxn, txnHash *BlockHash,
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
	operationType OperationType, currentTxn *MsgBitCloutTxn, txnHash *BlockHash,
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
	operationType OperationType, currentTxn *MsgBitCloutTxn, txnHash *BlockHash,
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
	operationType OperationType, currentTxn *MsgBitCloutTxn, txnHash *BlockHash,
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

	// Delete reclout mappings if they exist. They will be added back later if there is a previous version of this
	// postEntry
	if IsVanillaReclout(postEntry) {
		recloutKey := MakeRecloutKey(postEntry.PosterPublicKey, *postEntry.RecloutedPostHash)
		recloutEntry := bav._getRecloutEntryForRecloutKey(&recloutKey)
		if recloutEntry == nil {
			return fmt.Errorf("_disconnectSubmitPost: RecloutEntry for "+
				"Post Has %v could not be found: %v", &txnHash, postEntry)
		}
		bav._deleteRecloutEntryMappings(recloutEntry)
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
	if currentOperation.PrevRecloutedPostEntry != nil {
		bav._setPostEntryMappings(currentOperation.PrevRecloutedPostEntry)
	}
	if currentOperation.PrevRecloutEntry != nil {
		bav._setRecloutEntryMappings(currentOperation.PrevRecloutEntry)
	}

	// Now revert the basic transfer with the remaining operations. Cut off
	// the SubmitPost operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) _disconnectUpdateProfile(
	operationType OperationType, currentTxn *MsgBitCloutTxn, txnHash *BlockHash,
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
	operationType OperationType, currentTxn *MsgBitCloutTxn, txnHash *BlockHash,
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
	operationType OperationType, currentTxn *MsgBitCloutTxn, txnHash *BlockHash,
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

	// Get the profile corresponding to the creator coin txn.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(txMeta.ProfilePublicKey)
	// Sanity-check that it exists.
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return fmt.Errorf("_disconnectCreatorCoin: CreatorCoin profile for "+
			"public key %v doesn't exist; this should never happen",
			PkToStringBoth(txMeta.ProfilePublicKey))
	}
	// Get the BalanceEntry of the transactor. This should always exist.
	transactorBalanceEntry, _, _ := bav._getBalanceEntryForHODLerPubKeyAndCreatorPubKey(
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
	creatorBalanceEntry, _, _ := bav._getBalanceEntryForHODLerPubKeyAndCreatorPubKey(
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
			if blockHeight > BitCloutFounderRewardBlockHeight {
				// Do nothing.  After the BitCloutFounderRewardBlockHeight, creator coins are not
				// minted as a founder's reward, just BitClout (see utxo reverted later).
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

		// If a BitClout founder reward was created, revert it.
		if operationData.FounderRewardUtxoKey != nil {
			if err := bav._unAddUtxo(operationData.FounderRewardUtxoKey); err != nil {
				return errors.Wrapf(err, "_disconnectBitcoinExchange: Problem unAdding utxo %v: ", operationData.FounderRewardUtxoKey)
			}
		}

		// The buyer will get the BitClout they locked up back when we revert the
		// basic transfer. This is OK because resetting the CoinEntry to the previous
		// value lowers the amount of BitClout locked in the profile by the same
		// amount the buyer will receive. Thus no BitClout is created in this
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
	} else if txMeta.OperationType == CreatorCoinOperationTypeAddBitClout {
		return fmt.Errorf("_disconnectCreatorCoin: Add BitClout operation txn not implemented")
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
	operationType OperationType, currentTxn *MsgBitCloutTxn, txnHash *BlockHash,
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
	senderBalanceEntry, _, _ := bav._getBalanceEntryForHODLerPubKeyAndCreatorPubKey(
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
	receiverBalanceEntry, _, _ := bav._getBalanceEntryForHODLerPubKeyAndCreatorPubKey(
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

func (bav *UtxoView) DisconnectTransaction(currentTxn *MsgBitCloutTxn, txnHash *BlockHash,
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

	}

	return fmt.Errorf("DisconnectBlock: Unimplemented txn type %v", currentTxn.TxnMeta.GetTxnType().String())
}

func (bav *UtxoView) DisconnectBlock(
	bitcloutBlock *MsgBitCloutBlock, txHashes []*BlockHash, utxoOps [][]*UtxoOperation) error {

	glog.Infof("DisconnectBlock: Disconnecting block %v", bitcloutBlock)

	// Verify that the block being disconnected is the current tip. DisconnectBlock
	// can only be called on a block at the tip. We do this to keep the API simple.
	blockHash, err := bitcloutBlock.Header.Hash()
	if err != nil {
		return fmt.Errorf("DisconnectBlock: Problem computing block hash")
	}
	if *bav.TipHash != *blockHash {
		return fmt.Errorf("DisconnectBlock: Block being disconnected does not match tip")
	}

	// Verify the number of ADD and SPEND operations in the utxOps list is equal
	// to the number of outputs and inputs in the block respectively.
	numInputs := 0
	numOutputs := 0
	for _, txn := range bitcloutBlock.Txns {
		numInputs += len(txn.TxInputs)
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
	for txnIndex := len(bitcloutBlock.Txns) - 1; txnIndex >= 0; txnIndex-- {
		currentTxn := bitcloutBlock.Txns[txnIndex]
		txnHash := txHashes[txnIndex]
		utxoOpsForTxn := utxoOps[txnIndex]
		blockHeight := bitcloutBlock.Header.Height

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
	bav.TipHash = bitcloutBlock.Header.PrevBlockHash

	return nil
}

func _isEntryImmatureBlockReward(utxoEntry *UtxoEntry, blockHeight uint32, params *BitCloutParams) bool {
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

func _verifySignature(txn *MsgBitCloutTxn) error {
	// Compute a hash of the transaction
	txBytes, err := txn.ToBytes(true /*preSignature*/)
	if err != nil {
		return errors.Wrapf(err, "_verifySignature: Problem serializing txn without signature: ")
	}
	txHash := Sha256DoubleHash(txBytes)
	// Convert the txn public key into a *btcec.PublicKey
	txnPk, err := btcec.ParsePubKey(txn.PublicKey, btcec.S256())
	if err != nil {
		return errors.Wrapf(err, "_verifySignature: Problem parsing public key: ")
	}
	// Verify that the transaction is signed by the specified key.
	if txn.Signature == nil || !txn.Signature.Verify(txHash[:], txnPk) {
		return RuleErrorInvalidTransactionSignature
	}

	return nil
}

func (bav *UtxoView) _connectBasicTransfer(
	txn *MsgBitCloutTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	var utxoOpsForTxn []*UtxoOperation

	// Loop through all the inputs and validate them.
	var totalInput uint64
	// Each input should have a UtxoEntry corresponding to it if the transaction
	// is legitimate. These should all have back-pointers to their UtxoKeys as well.
	utxoEntriesForInputs := []*UtxoEntry{}
	for _, bitcloutInput := range txn.TxInputs {
		// Fetch the utxoEntry for this input from the view. Make a copy to
		// avoid having the iterator change under our feet.
		utxoKey := UtxoKey(*bitcloutInput)
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
	for outputIndex, bitcloutOutput := range txn.TxOutputs {
		// Sanity check the amount of the output. Mark the block as invalid and
		// return an error if it isn't sane.
		if bitcloutOutput.AmountNanos > MaxNanos ||
			totalOutput >= (math.MaxUint64-bitcloutOutput.AmountNanos) ||
			totalOutput+bitcloutOutput.AmountNanos > MaxNanos {

			return 0, 0, nil, RuleErrorTxnOutputWithInvalidAmount
		}

		// Since the amount is sane, add it to the total.
		totalOutput += bitcloutOutput.AmountNanos

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
			AmountNanos: bitcloutOutput.AmountNanos,
			PublicKey:   bitcloutOutput.PublicKey,
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
		utxoOpsForTxn = append(utxoOpsForTxn, newUtxoOp)
	}

	// If signature verification is requested then do that as well.
	if verifySignatures {
		// When we looped through the inputs we verified that all of them belong
		// to the public key specified in the transaction. So, as long as the transaction
		// public key has signed the transaction as a whole, we can assume that
		// all of the inputs are authorized to be spent. One signature to rule them
		// all.
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
			if err := _verifySignature(txn); err != nil {
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

func (bav *UtxoView) _getLikeEntryForLikeKey(likeKey *LikeKey) *LikeEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.LikeKeyToLikeEntry[*likeKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory view mapping got later.
	if DbGetLikerPubKeyToLikedPostHashMapping(
		bav.Handle, likeKey.LikerPubKey[:], likeKey.LikedPostHash) != nil {
		likeEntry := LikeEntry{
			LikerPubKey:   likeKey.LikerPubKey[:],
			LikedPostHash: &likeKey.LikedPostHash,
		}
		bav._setLikeEntryMappings(&likeEntry)
		return &likeEntry
	}
	return nil
}

func (bav *UtxoView) _getRecloutEntryForRecloutKey(recloutKey *RecloutKey) *RecloutEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.RecloutKeyToRecloutEntry[*recloutKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory view mapping got later.
	recloutEntry := DbReclouterPubKeyRecloutedPostHashToRecloutEntry(
		bav.Handle, recloutKey.ReclouterPubKey[:], recloutKey.RecloutedPostHash)
	if recloutEntry != nil {
		bav._setRecloutEntryMappings(recloutEntry)
	}
	return recloutEntry
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

func (bav *UtxoView) _setRecloutEntryMappings(recloutEntry *RecloutEntry) {
	// This function shouldn't be called with nil.
	if recloutEntry == nil {
		glog.Errorf("_setRecloutEntryMappings: Called with nil RecloutEntry; " +
			"this should never happen.")
		return
	}

	recloutKey := MakeRecloutKey(recloutEntry.ReclouterPubKey, *recloutEntry.RecloutedPostHash)
	bav.RecloutKeyToRecloutEntry[recloutKey] = recloutEntry
}

func (bav *UtxoView) _deleteRecloutEntryMappings(recloutEntry *RecloutEntry) {

	if recloutEntry == nil {
		glog.Errorf("_deleteRecloutEntryMappings: called with nil RecloutEntry; " +
			"this should never happen")
		return
	}
	// Create a tombstone entry.
	tombstoneRecloutEntry := *recloutEntry
	tombstoneRecloutEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setRecloutEntryMappings(&tombstoneRecloutEntry)
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
	if DbGetFollowerToFollowedMapping(
		bav.Handle, &followKey.FollowerPKID, &followKey.FollowedPKID) != nil {
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
	dbDiamondEntry := DbGetDiamondMappings(
		bav.Handle, &diamondKey.ReceiverPKID, &diamondKey.SenderPKID, &diamondKey.DiamondPostHash)
	if dbDiamondEntry != nil {
		bav._setDiamondEntryMappings(dbDiamondEntry)
	}
	return dbDiamondEntry
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
	dbPostEntry := DBGetPostEntryByPostHash(bav.Handle, postHash)
	if dbPostEntry != nil {
		bav._setPostEntryMappings(dbPostEntry)
	}
	return dbPostEntry
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
		glog.Errorf("_setPostEntryMappings: Called with nil PostEntry; " +
			"this should never happen.")
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
	dbBalanceEntry := DBGetCreatorCoinBalanceEntryForHODLerAndCreatorPKIDs(
		bav.Handle, hodlerPKID, creatorPKID)
	if dbBalanceEntry != nil {
		bav._setBalanceEntryMappingsWithPKIDs(dbBalanceEntry, hodlerPKID, creatorPKID)
	}
	return dbBalanceEntry
}

func (bav *UtxoView) _getBalanceEntryForHODLerPubKeyAndCreatorPubKey(
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

func (bav *UtxoView) GetProfileEntryForUsername(nonLowercaseUsername []byte) *ProfileEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.

	// Note that the call to MakeUsernameMapKey will lowercase the username
	// and thus enforce a uniqueness check.
	mapValue, existsMapValue := bav.ProfileUsernameToProfileEntry[MakeUsernameMapKey(nonLowercaseUsername)]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	// Note that the DB username lookup is case-insensitive.
	dbProfileEntry := DBGetProfileEntryForUsername(bav.Handle, nonLowercaseUsername)
	if dbProfileEntry != nil {
		bav._setProfileEntryMappings(dbProfileEntry)
	}
	return dbProfileEntry
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
	dbPKIDEntry := DBGetPKIDEntryForPublicKey(bav.Handle, publicKey)
	if dbPKIDEntry != nil {
		bav._setPKIDMappings(dbPKIDEntry)
	}
	return dbPKIDEntry
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
	dbPublicKey := DBGetPublicKeyForPKID(bav.Handle, pkid)
	if len(dbPublicKey) != 0 {
		bav._setPKIDMappings(&PKIDEntry{
			PKID:      pkid,
			PublicKey: dbPublicKey,
		})
	}
	return dbPublicKey
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
	dbProfileEntry := DBGetProfileEntryForPKID(bav.Handle, pkid)
	if dbProfileEntry != nil {
		bav._setProfileEntryMappings(dbProfileEntry)
	}
	return dbProfileEntry
}

func (bav *UtxoView) _setProfileEntryMappings(profileEntry *ProfileEntry) {
	// This function shouldn't be called with nil.
	if profileEntry == nil {
		glog.Errorf("_setProfileEntryMappings: Called with nil ProfileEntry; " +
			"this should never happen.")
		return
	}

	// Look up the current PKID for the profile. It should never be nil, since
	// we create it if it doesn't exist.
	//
	// TODO: This seems like it could create a lot of unnecessary PKID mappings in the db.
	//
	// TODO: Is creating the PKID if it doesn't exist the right approach? Or should we
	// return nil and force the caller to create it before setting mappings?
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
	txn *MsgBitCloutTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool,
	checkMerkleProof bool, minBitcoinBurnWork int64) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if bav.Params.DeflationBombBlockHeight != 0 &&
		uint64(blockHeight) >= bav.Params.DeflationBombBlockHeight {

		return 0, 0, nil, RuleErrorDeflationBombForbidsMintingAnyMoreBitClout
	}

	if bav.BitcoinManager == nil ||
		!bav.BitcoinManager.IsCurrent(false /*considerCumWork*/) {

		return 0, 0, nil, fmt.Errorf("_connectBitcoinExchange: BitcoinManager "+
			"must be non-nil and time-current in order to connect "+
			"BitcoinExchange transactions: %v", bav.BitcoinManager.IsCurrent(false /*considerCumWork*/))
	}
	// At this point we are confident that we have a non-nil time-current
	// BitcoinManager we can refer to for validation purposes.

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
	// be converted to BitClout precisely one time. No need to worry about malleability
	// because we also verify that the transaction was mined into a valid Bitcoin block
	// with a lot of work on top of it, which means we can't be tricked by someone
	// twiddling the transaction to give it a different hash (unless the Bitcoin chain
	// is also tricked, in which case we have bigger problems).
	bitcoinTxHash := (BlockHash)(txMetaa.BitcoinTransaction.TxHash())
	if bav._existsBitcoinTxIDMapping(&bitcoinTxHash) {
		return 0, 0, nil, RuleErrorBitcoinExchangeDoubleSpendingBitcoinTransaction
	}

	// If this is a forgiven BitcoinExchange txn then skip all checks
	if IsForgivenBitcoinTransaction(txn) {
		checkMerkleProof = false
		minBitcoinBurnWork = 0
	}

	if checkMerkleProof {
		// Check that the BitcoinBlockHash exists in our main Bitcoin header chain.
		blockNodeForBlockHash := bav.BitcoinManager.GetBitcoinBlockNode(txMetaa.BitcoinBlockHash)
		if blockNodeForBlockHash == nil {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorBitcoinExchangeBlockHashNotFoundInMainBitcoinChain,
				"Bitcoin txn hash: %v",
				txMetaa.BitcoinTransaction.TxHash(),
			)
		}

		// Verify that the BitcoinMerkleRoot lines up with what is present in the Bitcoin
		// header.
		if *blockNodeForBlockHash.Header.TransactionMerkleRoot != *txMetaa.BitcoinMerkleRoot {
			return 0, 0, nil, RuleErrorBitcoinExchangeHasBadMerkleRoot
		}

		// Check that the BitcoinMerkleProof successfully proves that the
		// BitcoinTransaction was legitimately included in the mined Bitcoin block. Note
		// that we verified taht the BitcoinMerkleRoot is the same one that corresponds
		// to the provided BitcoinBlockHash.
		if !merkletree.VerifyProof(
			bitcoinTxHash[:], txMetaa.BitcoinMerkleProof, txMetaa.BitcoinMerkleRoot[:]) {

			return 0, 0, nil, RuleErrorBitcoinExchangeInvalidMerkleProof
		}
		// At this point we are sure that the BitcoinTransaction provided was mined into
		// a Bitcoin and that the BitcoinTransaction has not been used in a
		// BitcoinExchange transaction in the past.
	}

	if minBitcoinBurnWork != 0 {
		// Check that the BitcoinBlockHash exists in our main Bitcoin header chain.
		blockNodeForBlockHash := bav.BitcoinManager.GetBitcoinBlockNode(txMetaa.BitcoinBlockHash)
		if blockNodeForBlockHash == nil {
			return 0, 0, nil, RuleErrorBitcoinExchangeBlockHashNotFoundInMainBitcoinChain
		}

		// Check that the Bitcoin block has a sufficient amount of work built on top of it
		// for us to consider its contents. Note that the amount of work must be determined
		// based on the oldest time-current block that we have rather than the tip. Note also
		// that because we verified that the BitcoinManager is time-current that we must have
		// at least one time-current block in our main chain.
		bitcoinBurnWorkBlocks :=
			bav.BitcoinManager.GetBitcoinBurnWorkBlocks(blockNodeForBlockHash.Height)
		if bitcoinBurnWorkBlocks < minBitcoinBurnWork {

			// Note we opt against returning a RuleError here. This should prevent the block
			// from being marked as invalid so we can reconsider it if a fork favors it in the
			// long run which, although unlikely, could theoretically happen
			return 0, 0, nil, fmt.Errorf("_connectBitcoinExchange: Number of Bitcoin "+
				"burn work blocks mined on top of transaction %d is below MinBitcoinBurnWork %d",
				bitcoinBurnWorkBlocks, minBitcoinBurnWork)
		}

		// At this point we found a node on the main Bitcoin chain corresponding to the block hash
		// in the txMeta and have verified that this block has a sufficient amount of work built on
		// top of it to make us want to consider it. Its values should be set according to the
		// corresponding Bitcoin header.
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
	// new BitClout to. If we find more than one P2PKH input, we consider the public key
	// corresponding to the first of these inputs to be the one that will receive the
	// BitClout that will be created.
	publicKey, err := ExtractBitcoinPublicKeyFromBitcoinTransactionInputs(
		txMetaa.BitcoinTransaction, bav.Params.BitcoinBtcdParams)
	if err != nil {
		return 0, 0, nil, RuleErrorBitcoinExchangeValidPublicKeyNotFoundInInputs
	}
	// At this point, we should have extracted a public key from the Bitcoin transaction
	// that we expect to credit the newly-created BitClout to.

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
	// that should receive the BitClout we are going to create.
	usdCentsPerBitcoin := bav.GetCurrentUSDCentsPerBitcoin()
	// Compute the amount of BitClout that we should create as a result of this transaction.
	nanosToCreate := CalcNanosToCreate(
		bav.NanosPurchased, uint64(totalBurnOutput), usdCentsPerBitcoin)

	// Compute the amount of BitClout that the user will receive. Note
	// that we allocate a small fee to the miner to incentivize her to include the
	// transaction in a block. The fee for BitcoinExchange transactions is fixed because
	// if it weren't then a miner could theoretically repackage the BitcoinTransaction
	// into a new BitcoinExchange transaction that spends all of the newly-created BitClout as
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
	// spend the BitClout she's purchased in the future.
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
	// Save a UtxoOperation adding the UTXO so we can roll it back later if needed.
	//
	// TODO(DELETEME): I don't think this extra UTXOOperation is actually needed
	// or used in the disconnect function.
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
	txn *MsgBitCloutTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
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
	txn *MsgBitCloutTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
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
	if len(extraData[USDCentsPerBitcoin]) > 0 {
		// Validate that the exchange rate is not less than the floor as a sanity-check.
		newUSDCentsPerBitcoin, usdCentsPerBitcoinBytesRead := Uvarint(extraData[USDCentsPerBitcoin])
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

	if len(extraData[MinNetworkFeeNanosPerKB]) > 0 {
		newMinNetworkFeeNanosPerKB, minNetworkFeeNanosPerKBBytesRead := Uvarint(extraData[MinNetworkFeeNanosPerKB])
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

	if len(extraData[CreateProfileFeeNanos]) > 0 {
		newCreateProfileFeeNanos, createProfileFeeNanosBytesRead := Uvarint(extraData[CreateProfileFeeNanos])
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

	var newForbiddenPubKeyEntry *ForbiddenPubKeyEntry
	var prevForbiddenPubKeyEntry *ForbiddenPubKeyEntry
	var forbiddenPubKey []byte
	if _, exists := extraData[ForbiddenBlockSignaturePubKey]; exists {
		forbiddenPubKey := extraData[ForbiddenBlockSignaturePubKey]

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
	txn *MsgBitCloutTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
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
		Version,_ := Uvarint(extraV)
		messageEntry.Version = uint8(Version)
	}

	// Set the mappings in our in-memory map for the MessageEntry.
	bav._setMessageEntryMappings(messageEntry)

	// Add an operation to the list at the end indicating we've added a message
	// to our data structure.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type: OperationTypePrivateMessage,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectLike(
	txn *MsgBitCloutTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
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
	txn *MsgBitCloutTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
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
	_, err := btcec.ParsePubKey(txMeta.FollowedPublicKey, btcec.S256())
	if err != nil {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorFollowParsePubKeyError, "_connectFollow: Parse error: %v", err)
	}

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
	txn *MsgBitCloutTxn, txHash *BlockHash, blockHeight uint32,
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

	// Transaction extra data contains both consensus-related, such as reclout info, and additional information about a post,
	// whereas PostExtraData is an attribute of a PostEntry that contains only non-consensus related
	// information about a post, such as a link to a video that is embedded.
	extraData := make(map[string][]byte)
	for k, v := range txn.ExtraData {
		extraData[k] = v
	}
	// Set the IsQuotedReclout attribute of postEntry based on extra data
	isQuotedReclout := false
	if quotedReclout, hasQuotedReclout := extraData[IsQuotedRecloutKey]; hasQuotedReclout {
		if reflect.DeepEqual(quotedReclout, QuotedRecloutVal) {
			isQuotedReclout = true
		}
		// Delete key since it is not needed in the PostExtraData map as IsQuotedReclout is involved in consensus code.
		delete(extraData, IsQuotedRecloutKey)
	}
	var recloutedPostHash *BlockHash
	if recloutedPostHashBytes, isReclout := extraData[RecloutedPostHash]; isReclout {
		recloutedPostHash = &BlockHash{}
		copy(recloutedPostHash[:], recloutedPostHashBytes)
		delete(extraData, RecloutedPostHash)
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// If the metadata has a PostHashToModify then treat it as modifying an
	// existing post rather than creating a new post.
	var prevPostEntry *PostEntry
	var prevParentPostEntry *PostEntry
	var prevGrandparentPostEntry *PostEntry
	var prevRecloutedPostEntry *PostEntry
	var prevRecloutEntry *RecloutEntry

	var newPostEntry *PostEntry
	var newParentPostEntry *PostEntry
	var newGrandparentPostEntry *PostEntry
	var newRecloutedPostEntry *PostEntry
	var newRecloutEntry *RecloutEntry
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

		// Post modification is only allowed by the original poster or a
		// paramUpdater for now.
		_, posterIsParamUpdater := bav.Params.ParamUpdaterPublicKeys[MakePkMapKey(txn.PublicKey)]
		if !reflect.DeepEqual(txn.PublicKey, existingPostEntryy.PosterPublicKey) &&
			!posterIsParamUpdater {

			return 0, 0, nil, errors.Wrapf(
				RuleErrorSubmitPostPostModificationNotAuthorized,
				"_connectSubmitPost: Post hash: %v, poster public key: %v, "+
					"txn public key: %v, paramUpdater: %v", postHash,
				PkToStringBoth(existingPostEntryy.PosterPublicKey),
				PkToStringBoth(txn.PublicKey), spew.Sdump(bav.Params.ParamUpdaterPublicKeys))
		}

		// It's an error if we are updating the value of RecloutedPostHash. A post can only ever reclout a single post.
		if !reflect.DeepEqual(recloutedPostHash, existingPostEntryy.RecloutedPostHash) {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorSubmitPostUpdateRecloutHash,
				"_connectSubmitPost: cannot update reclouted post hash when updating a post")
		}

		// It's an error if we are updating the value of IsQuotedReclout.
		if isQuotedReclout != existingPostEntryy.IsQuotedReclout {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorSubmitPostUpdateIsQuotedReclout,
				"_connectSubmitPost: cannot update isQuotedReclout attribute of post when updating a post")
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

		if newPostEntry.RecloutedPostHash != nil {
			newRecloutedPostEntry = bav.GetPostEntryForPostHash(newPostEntry.RecloutedPostHash)
		}

		// Figure out how much we need to change the parent / grandparent's comment count by
		var commentCountUpdateAmount int
		recloutCountUpdateAmount := 0
		quoteRecloutCountUpdateAmount := 0
		hidingPostEntry := !prevPostEntry.IsHidden && newPostEntry.IsHidden
		if hidingPostEntry {
			// If we're hiding a post then we need to decrement the comment count of the parent
			// and grandparent posts.
			commentCountUpdateAmount = -1 * int(1+prevPostEntry.CommentCount)

			// If we're hiding a post that is a vanilla reclout of another post, we decrement the reclout count of the
			// post that was reclouted.
			if IsVanillaReclout(newPostEntry) {
				recloutCountUpdateAmount = -1
			} else if isQuotedReclout {
				quoteRecloutCountUpdateAmount = -1
			}
		}

		unhidingPostEntry := prevPostEntry.IsHidden && !newPostEntry.IsHidden
		if unhidingPostEntry {
			// If we're unhiding a post then we need to increment the comment count of the parent
			// and grandparent posts.
			commentCountUpdateAmount = int(1 + prevPostEntry.CommentCount)
			// If we are unhiding a post that is a vanilla reclout of another post, we increment the reclout count of
			// the post that was reclouted.
			if IsVanillaReclout(newPostEntry) {
				recloutCountUpdateAmount = 1
			} else if isQuotedReclout {
				quoteRecloutCountUpdateAmount = 1
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
		if newRecloutedPostEntry != nil {
			prevRecloutedPostEntry = &PostEntry{}
			*prevRecloutedPostEntry = *newRecloutedPostEntry
			// If the previous post entry is a vanilla reclout, we can set the prevRecloutEntry.
			if IsVanillaReclout(prevPostEntry) {
				prevRecloutKey := MakeRecloutKey(prevPostEntry.PosterPublicKey, *prevPostEntry.RecloutedPostHash)
				prevRecloutEntry = bav._getRecloutEntryForRecloutKey(&prevRecloutKey)
				if prevRecloutEntry == nil {
					return 0, 0, nil, fmt.Errorf("prevRecloutEntry not found for prevPostEntry")
				}
				// Generally prevRecloutEntry is identical to newRecloutEntry. Currently, we enforce a check that
				// the RecloutedPostHash does not get modified when attempting to connect a submitPost transaction
				newRecloutEntry = &RecloutEntry{
					ReclouterPubKey:   newPostEntry.PosterPublicKey,
					RecloutedPostHash: newPostEntry.RecloutedPostHash,
					RecloutPostHash:   newPostEntry.PostHash,
				}

				// Update the reclout count if it has changed.
				bav._updateRecloutCount(newRecloutedPostEntry, recloutCountUpdateAmount)
			} else {
				// Update the quote reclout count if it has changed.
				bav._updateQuoteRecloutCount(newRecloutedPostEntry, quoteRecloutCountUpdateAmount)
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

		if recloutedPostHash != nil {
			newRecloutedPostEntry = bav.GetPostEntryForPostHash(recloutedPostHash)
			// It is an error if a post entry attempts to reclout a post that does not exist.
			if newRecloutedPostEntry == nil {
				return 0, 0, nil, RuleErrorSubmitPostRecloutPostNotFound
			}
			// It is an error if a post is trying to reclout a vanilla reclout.
			if IsVanillaReclout(newRecloutedPostEntry) {
				return 0, 0, nil, RuleErrorSubmitPostRecloutOfReclout
			}
		}

		// Set the post entry pointer to a brand new post.
		newPostEntry = &PostEntry{
			PostHash:                 postHash,
			PosterPublicKey:          txn.PublicKey,
			ParentStakeID:            txMeta.ParentStakeID,
			Body:                     txMeta.Body,
			RecloutedPostHash:        recloutedPostHash,
			IsQuotedReclout:          isQuotedReclout,
			CreatorBasisPoints:       txMeta.CreatorBasisPoints,
			StakeMultipleBasisPoints: txMeta.StakeMultipleBasisPoints,
			TimestampNanos:           txMeta.TimestampNanos,
			ConfirmationBlockHeight:  blockHeight,
			StakeEntry:               NewStakeEntry(),
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

		// Save the data from the reclouted post.
		if newRecloutedPostEntry != nil {
			prevRecloutedPostEntry = &PostEntry{}
			*prevRecloutedPostEntry = *newRecloutedPostEntry

			// We only set reclout entry mappings and increment counts for vanilla reclouts.
			if !isQuotedReclout {
				// Increment the reclout count of the post that was reclouted by 1 as we are creating a new
				// vanilla reclout.
				bav._updateRecloutCount(newRecloutedPostEntry, 1)
				// Create the new recloutEntry
				newRecloutEntry = &RecloutEntry{
					ReclouterPubKey:   newPostEntry.PosterPublicKey,
					RecloutedPostHash: newPostEntry.RecloutedPostHash,
					RecloutPostHash:   newPostEntry.PostHash,
				}
			} else {
				// If it is a quote reclout, we need to increment the corresponding count.
				bav._updateQuoteRecloutCount(newRecloutedPostEntry, 1)
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
	if newRecloutedPostEntry != nil {
		bav._setPostEntryMappings(newRecloutedPostEntry)
	}

	if newRecloutEntry != nil {
		bav._setRecloutEntryMappings(newRecloutEntry)
	}

	// Add an operation to the list at the end indicating we've added a post.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		// PrevPostEntry should generally be nil when we created a new post from
		// scratch, but non-nil if we modified an existing post.
		PrevPostEntry:            prevPostEntry,
		PrevParentPostEntry:      prevParentPostEntry,
		PrevGrandparentPostEntry: prevGrandparentPostEntry,
		PrevRecloutedPostEntry:   prevRecloutedPostEntry,
		PrevRecloutEntry:         prevRecloutEntry,
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
		parentPostEntry = bav.GetPostEntryForPostHash(StakeIDToHash(postEntry.ParentStakeID))
		if parentPostEntry == nil {
			return nil, nil, errors.Wrapf(
				RuleErrorSubmitPostParentNotFound,
				"_getParentAndGrandparentPostEntry: failed to find parent post for post hash: %v, parentStakeId: %v",
				postEntry.PostHash, hex.EncodeToString(postEntry.ParentStakeID),
			)
		}
	}

	if parentPostEntry != nil && len(parentPostEntry.ParentStakeID) == HashSizeBytes {
		grandparentPostEntry = bav.GetPostEntryForPostHash(StakeIDToHash(parentPostEntry.ParentStakeID))
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

// Adds amount to the reclout count of the post at recloutPostHash
func (bav *UtxoView) _updateRecloutCount(recloutedPost *PostEntry, amount int) {
	result := int(recloutedPost.RecloutCount) + amount

	// Reclout count should never be below 0.
	if result < 0 {
		glog.Errorf("_updateRecloutCountForPost: RecloutCount < 0 for result %v, reclout post hash: %v, amount : %v",
			result, recloutedPost, amount)
		result = 0
	}
	recloutedPost.RecloutCount = uint64(result)

}

// Adds amount to the quote reclout count of the post at recloutPostHash
func (bav *UtxoView) _updateQuoteRecloutCount(recloutedPost *PostEntry, amount int) {
	result := int(recloutedPost.QuoteRecloutCount) + amount

	// Reclout count should never be below 0.
	if result < 0 {
		glog.Errorf("_updateQuoteRecloutCountForPost: QuoteRecloutCount < 0 for result %v, reclout post hash: %v, amount : %v",
			result, recloutedPost, amount)
		result = 0
	}
	recloutedPost.QuoteRecloutCount = uint64(result)

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
	txn *MsgBitCloutTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool,
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
	if len(txMeta.ProfilePublicKey) != 0 {
		if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
			return 0, 0, nil, errors.Wrapf(RuleErrorProfilePublicKeySize, "_connectUpdateProfile: %#v", txMeta.ProfilePublicKey)
		}
		_, err := btcec.ParsePubKey(txMeta.ProfilePublicKey, btcec.S256())
		if err != nil {
			return 0, 0, nil, errors.Wrapf(RuleErrorProfileBadPublicKey, "_connectUpdateProfile: %v", err)
		}
		profilePublicKey = txMeta.ProfilePublicKey
	}

	// If a profile with this username exists already AND if that profile
	// belongs to another public key then that's an error.
	{
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

		// TODO: This field is deprecated and should be deleted.
		newProfileEntry.StakeMultipleBasisPoints = txMeta.NewStakeMultipleBasisPoints

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

		// If below block height, user transaction public key.
		// If above block height, use ProfilePublicKey if available.
		profileEntryPublicKey := txn.PublicKey
		if blockHeight > ParamUpdaterProfileUpdateFixBlockHeight {
			profileEntryPublicKey = profilePublicKey
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

			// TODO(DELETEME): This field is deprecated and should be deleted because we're
			// not allowing staking to profiles.
			StakeMultipleBasisPoints: txMeta.NewStakeMultipleBasisPoints,
			// TODO(DELETEME): This field is deprecated and should be deleted because we're
			// not allowing staking to profiles.
			StakeEntry: NewStakeEntry(),
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
		Type:             OperationTypeUpdateProfile,
		PrevProfileEntry: prevProfileEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectSwapIdentity(
	txn *MsgBitCloutTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
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

	// Add an operation to the list at the end indicating we've swapped identities.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type: OperationTypeSwapIdentity,

		// Note that we don't need any metadata on this operation, since the swap is reversible
		// without it.
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func CalculateCreatorCoinToMintPolynomial(
	deltaBitCloutNanos uint64, currentCreatorCoinSupplyNanos uint64, params *BitCloutParams) uint64 {
	// The values our equations take are generally in whole units rather than
	// nanos, so the first step is to convert the nano amounts into floats
	// representing full coin units.
	bigNanosPerUnit := NewFloat().SetUint64(NanosPerUnit)
	bigDeltaBitClout := Div(NewFloat().SetUint64(deltaBitCloutNanos), bigNanosPerUnit)
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
	//     dB = bigDeltaBitClout,
	//     m = params.CreatorCoinSlope
	//     RR = params.CreatorCoinReserveRatio
	//     s = bigCurrentCreatorCoinSupply
	//
	// If you think it's hard to understand the code below, don't worry-- I hate
	// the Go float libary syntax too...
	bigRet := Sub(BigFloatPow((Div((Add(bigDeltaBitClout,
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
	deltaBitCloutNanos uint64, currentCreatorCoinSupplyNanos uint64,
	currentBitCloutLockedNanos uint64, params *BitCloutParams) uint64 {
	// The values our equations take are generally in whole units rather than
	// nanos, so the first step is to convert the nano amounts into floats
	// representing full coin units.
	bigNanosPerUnit := NewFloat().SetUint64(NanosPerUnit)
	bigDeltaBitClout := Div(NewFloat().SetUint64(deltaBitCloutNanos), bigNanosPerUnit)
	bigCurrentCreatorCoinSupply := Div(NewFloat().SetUint64(currentCreatorCoinSupplyNanos), bigNanosPerUnit)
	bigCurrentBitCloutLocked := Div(NewFloat().SetUint64(currentBitCloutLockedNanos), bigNanosPerUnit)

	// These calculations are derived from the Bancor pricing formula, which
	// is proportional to a polynomial price curve (and equivalent to Uniswap
	// under certain assumptions). For more information, see the comment on
	// CreatorCoinSlope in constants.go and check out the Mathematica notebook
	// linked in that comment.
	//
	// This is the formula:
	// - S0 * ((1 + dB / B0) ^ (RR) - 1)
	// - where:
	//     dB = bigDeltaBitClout,
	//     B0 = bigCurrentBitCloutLocked
	//     S0 = bigCurrentCreatorCoinSupply
	//     RR = params.CreatorCoinReserveRatio
	//
	// Sorry the code for the equation is so hard to read.
	bigRet := Mul(bigCurrentCreatorCoinSupply,
		Sub(BigFloatPow((Add(bigOne, Div(bigDeltaBitClout,
			bigCurrentBitCloutLocked))),
			(params.CreatorCoinReserveRatio)), bigOne))
	// The value we get is generally a number of whole creator coins, and so we
	// need to convert it to "nanos" as a last step.
	retNanos, _ := Mul(bigRet, bigNanosPerUnit).Uint64()
	return retNanos
}

func CalculateBitCloutToReturn(
	deltaCreatorCoinNanos uint64, currentCreatorCoinSupplyNanos uint64,
	currentBitCloutLockedNanos uint64, params *BitCloutParams) uint64 {
	// The values our equations take are generally in whole units rather than
	// nanos, so the first step is to convert the nano amounts into floats
	// representing full coin units.
	bigNanosPerUnit := NewFloat().SetUint64(NanosPerUnit)
	bigDeltaCreatorCoin := Div(NewFloat().SetUint64(deltaCreatorCoinNanos), bigNanosPerUnit)
	bigCurrentCreatorCoinSupply := Div(NewFloat().SetUint64(currentCreatorCoinSupplyNanos), bigNanosPerUnit)
	bigCurrentBitCloutLocked := Div(NewFloat().SetUint64(currentBitCloutLockedNanos), bigNanosPerUnit)

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
	//     B0 = bigCurrentBitCloutLocked
	//     S0 = bigCurrentCreatorCoinSupply
	//     RR = params.CreatorCoinReserveRatio
	//
	// Sorry the code for the equation is so hard to read.
	bigRet := Mul(bigCurrentBitCloutLocked, (Sub(bigOne, BigFloatPow((Sub(bigOne,
		Div(bigDeltaCreatorCoin, bigCurrentCreatorCoinSupply))), (Div(bigOne,
		params.CreatorCoinReserveRatio))))))
	// The value we get is generally a number of whole creator coins, and so we
	// need to convert it to "nanos" as a last step.
	retNanos, _ := Mul(bigRet, bigNanosPerUnit).Uint64()
	return retNanos
}

func CalculateCreatorCoinToMint(
	bitcloutToSellNanos uint64,
	coinsInCirculationNanos uint64, bitcloutLockedNanos uint64,
	params *BitCloutParams) uint64 {

	if bitcloutLockedNanos == 0 {
		// In this case, there is no BitClout in the profile so we have to use
		// the polynomial equations to initialize the coin and determine how
		// much to mint.
		return CalculateCreatorCoinToMintPolynomial(
			bitcloutToSellNanos, coinsInCirculationNanos,
			params)
	}

	// In this case, we have BitClout locked in the profile and so we use the
	// standard Bancor equations to determine how much creator coin to mint.
	return CalculateCreatorCoinToMintBancor(
		bitcloutToSellNanos, coinsInCirculationNanos,
		bitcloutLockedNanos, params)
}

// TODO: A lot of duplicate code between buy and sell. Consider factoring
// out the common code.
func (bav *UtxoView) HelpConnectCreatorCoinBuy(
	txn *MsgBitCloutTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
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
	// to force-convert all your creator coin into BitClout. Think about it.
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

	// Check that the amount of BitClout being traded for creator coin is
	// non-zero.
	bitCloutBeforeFeesNanos := txMeta.BitCloutToSellNanos
	if bitCloutBeforeFeesNanos == 0 {
		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustTradeNonZeroBitClout
	}
	// The amount of BitClout being traded counts as output being spent by
	// this transaction, so add it to the transaction output and check that
	// the resulting output does not exceed the total input.
	//
	// Check for overflow of the outputs before adding.
	if totalOutput > math.MaxUint64-bitCloutBeforeFeesNanos {
		return 0, 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinTxnOutputWithInvalidBuyAmount,
			"_connectCreatorCoin: %v", bitCloutBeforeFeesNanos)
	}
	totalOutput += bitCloutBeforeFeesNanos
	// It's assumed the caller code will check that things like output <= input,
	// but we check it here just in case...
	if totalInput < totalOutput {
		return 0, 0, 0, 0, nil, errors.Wrapf(
			RuleErrorCreatorCoinTxnOutputExceedsInput,
			"_connectCreatorCoin: Input: %v, Output: %v", totalInput, totalOutput)
	}
	// At this point we have verified that the output is sufficient to cover
	// the amount the user wants to use to buy the creator's coin.

	// Now we burn some BitClout before executing the creator coin buy. Doing
	// this guarantees that floating point errors in our subsequent calculations
	// will not result in a user being able to print infinite amounts of BitClout
	// through the protocol.
	//
	// TODO(performance): We use bigints to avoid overflow in the intermediate
	// stages of the calculation but this most likely isn't necessary. This
	// formula is equal to:
	// - bitCloutAfterFeesNanos = bitCloutBeforeFeesNanos * (CreatorCoinTradeFeeBasisPoints / (100*100))
	bitCloutAfterFeesNanos := IntDiv(
		IntMul(
			big.NewInt(int64(bitCloutBeforeFeesNanos)),
			big.NewInt(int64(100*100-bav.Params.CreatorCoinTradeFeeBasisPoints))),
		big.NewInt(100*100)).Uint64()

	// The amount of BitClout being convertend must be nonzero after fees as well.
	if bitCloutAfterFeesNanos == 0 {
		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustTradeNonZeroBitCloutAfterFees
	}

	// Figure out how much bitclout goes to the founder.
	// Note: If the user performing this transaction has the same public key as the
	// profile being bought, we do not cut a founder reward.
	bitcloutRemainingNanos := uint64(0)
	bitcloutFounderRewardNanos := uint64(0)
	if blockHeight > BitCloutFounderRewardBlockHeight &&
		!reflect.DeepEqual(txn.PublicKey, existingProfileEntry.PublicKey) {

		// This formula is equal to:
		// bitCloutFounderRewardNanos = bitcloutAfterFeesNanos * creatorBasisPoints / (100*100)
		bitcloutFounderRewardNanos = IntDiv(
			IntMul(
				big.NewInt(int64(bitCloutAfterFeesNanos)),
				big.NewInt(int64(existingProfileEntry.CreatorBasisPoints))),
			big.NewInt(100*100)).Uint64()

		// Sanity check, just to be extra safe.
		if bitCloutAfterFeesNanos < bitcloutFounderRewardNanos {
			return 0, 0, 0, 0, nil, fmt.Errorf("HelpConnectCreatorCoinBuy: bitCloutAfterFeesNanos"+
				" less than bitCloutFounderRewardNanos: %v %v",
				bitCloutAfterFeesNanos, bitcloutFounderRewardNanos)
		}

		bitcloutRemainingNanos = bitCloutAfterFeesNanos - bitcloutFounderRewardNanos
	} else {
		bitcloutRemainingNanos = bitCloutAfterFeesNanos
	}

	if bitcloutRemainingNanos == 0 {
		return 0, 0, 0, 0, nil, RuleErrorCreatorCoinBuyMustTradeNonZeroBitCloutAfterFounderReward
	}

	// If no BitClout is currently locked in the profile then we use the
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
		bitcloutRemainingNanos, existingProfileEntry.CoinsInCirculationNanos,
		existingProfileEntry.BitCloutLockedNanos, bav.Params)

	// Check if the total amount minted satisfies CreatorCoinAutoSellThresholdNanos.
	// This makes it prohibitively expensive for a user to buy themself above the
	// CreatorCoinAutoSellThresholdNanos and then spam tiny nano BitClout creator
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

	// Increment BitCloutLockedNanos. Sanity-check that we're not going to
	// overflow.
	if existingProfileEntry.BitCloutLockedNanos > math.MaxUint64-bitcloutRemainingNanos {
		return 0, 0, 0, 0, nil, fmt.Errorf("_connectCreatorCoin: Overflow while summing"+
			"BitCloutLockedNanos and bitCloutAfterFounderRewardNanos: %v %v",
			existingProfileEntry.BitCloutLockedNanos, bitcloutRemainingNanos)
	}
	existingProfileEntry.BitCloutLockedNanos += bitcloutRemainingNanos

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
	if blockHeight > BitCloutFounderRewardBlockHeight {
		// Do nothing. The chain stopped minting creator coins as a founder reward for
		// creators at this blockheight.  It gives BitClout as a founder reward now instead.

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
	// *and* the blockHeight is less than BitCloutFounderRewardBlockHeight.

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
		bav._getBalanceEntryForHODLerPubKeyAndCreatorPubKey(
			txn.PublicKey, existingProfileEntry.PublicKey)
	// If the user does not have a balance entry or the user's balance entry is deleted and we have passed the
	// BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight, we create a new balance entry.
	if buyerBalanceEntry == nil ||
			(buyerBalanceEntry.isDeleted && blockHeight > BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight){
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
		creatorBalanceEntry, hodlerPKID, creatorPKID = bav._getBalanceEntryForHODLerPubKeyAndCreatorPubKey(
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
	// prevent tiny amounts of nanos from drifting the ratio of creator coins to BitClout locked.
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

	// Finally, if the creator is getting a bitclout founder reward, add a UTXO for it.
	var outputKey *UtxoKey
	if blockHeight > BitCloutFounderRewardBlockHeight {
		if bitcloutFounderRewardNanos > 0 {
			// Create a new entry for this output and add it to the view. It should be
			// added at the end of the utxo list.
			outputKey = &UtxoKey{
				TxID: *txHash,
				// The output is like an extra virtual output at the end of the transaction.
				Index: uint32(len(txn.TxOutputs)),
			}

			utxoEntry := UtxoEntry{
				AmountNanos: bitcloutFounderRewardNanos,
				PublicKey:   existingProfileEntry.PublicKey,
				BlockHeight: blockHeight,
				UtxoType:    UtxoTypeCreatorCoinFounderReward,
				UtxoKey:     outputKey,
				// We leave the position unset and isSpent to false by default.
				// The position will be set in the call to _addUtxo.
			}

			_, err = bav._addUtxo(&utxoEntry)
			if err != nil {
				return 0, 0, 0, 0, nil, errors.Wrapf(err, "HelpConnectCreatorCoinBuy: Problem adding output utxo")
			}
		}
	}

	// Add an operation to the list at the end indicating we've executed a
	// CreatorCoin txn. Save the previous state of the CoinEntry for easy
	// reversion during disconnect.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                       OperationTypeCreatorCoin,
		PrevCoinEntry:              &prevCoinEntry,
		PrevTransactorBalanceEntry: &prevBuyerBalanceEntry,
		PrevCreatorBalanceEntry:    &prevCreatorBalanceEntry,
		FounderRewardUtxoKey:       outputKey,
	})

	return totalInput, totalOutput, coinsBuyerGetsNanos, creatorCoinFounderRewardNanos, utxoOpsForTxn, nil
}

// TODO: A lot of duplicate code between buy and sell. Consider factoring
// out the common code.
func (bav *UtxoView) HelpConnectCreatorCoinSell(
	txn *MsgBitCloutTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _bitCloutReturnedNanos uint64,
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
	// to force-convert all your creator coin into BitClout. Think about it.
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
	sellerBalanceEntry, _, _ := bav._getBalanceEntryForHODLerPubKeyAndCreatorPubKey(
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

	// If the amount of BitClout locked in the profile is zero then selling is
	// not allowed.
	if existingProfileEntry.BitCloutLockedNanos == 0 {
		return 0, 0, 0, nil, RuleErrorCreatorCoinSellNotAllowedWhenZeroBitCloutLocked
	}

	bitCloutBeforeFeesNanos := uint64(0)
	// Compute the amount of BitClout to return.
	if blockHeight > SalomonFixBlockHeight {
		// Following the SalomonFixBlockHeight block, if a user would be left with less than
		// bav.Params.CreatorCoinAutoSellThresholdNanos, we clear all their remaining holdings
		// to prevent 1 or 2 lingering creator coin nanos from staying in their wallet.
		// This also gives a method for cleanly and accurately reducing the numberOfHolders.

		// Note that we check that sellerBalanceEntry.BalanceNanos >= creatorCoinToSellNanos above.
		if sellerBalanceEntry.BalanceNanos-creatorCoinToSellNanos < bav.Params.CreatorCoinAutoSellThresholdNanos {
			// Setup to sell all the creator coins the seller has.
			creatorCoinToSellNanos = sellerBalanceEntry.BalanceNanos

			// Compute the amount of BitClout to return with the new creatorCoinToSellNanos.
			bitCloutBeforeFeesNanos = CalculateBitCloutToReturn(
				creatorCoinToSellNanos, existingProfileEntry.CoinsInCirculationNanos,
				existingProfileEntry.BitCloutLockedNanos, bav.Params)

			// If the amount the formula is offering is more than what is locked in the
			// profile, then truncate it down. This addresses an edge case where our
			// equations may return *too much* BitClout due to rounding errors.
			if bitCloutBeforeFeesNanos > existingProfileEntry.BitCloutLockedNanos {
				bitCloutBeforeFeesNanos = existingProfileEntry.BitCloutLockedNanos
			}
		} else {
			// If we're above the CreatorCoinAutoSellThresholdNanos, we can safely compute
			// the amount to return based on the Bancor curve.
			bitCloutBeforeFeesNanos = CalculateBitCloutToReturn(
				creatorCoinToSellNanos, existingProfileEntry.CoinsInCirculationNanos,
				existingProfileEntry.BitCloutLockedNanos, bav.Params)

			// If the amount the formula is offering is more than what is locked in the
			// profile, then truncate it down. This addresses an edge case where our
			// equations may return *too much* BitClout due to rounding errors.
			if bitCloutBeforeFeesNanos > existingProfileEntry.BitCloutLockedNanos {
				bitCloutBeforeFeesNanos = existingProfileEntry.BitCloutLockedNanos
			}
		}
	} else {
		// Prior to the SalomonFixBlockHeight block, coins would be minted based on floating point
		// arithmetic with the exception being if a creator was selling all remaining creator coins. This caused
		// a rare issue where a creator would be left with 1 creator coin nano in circulation
		// and 1 nano BitClout locked after completely selling. This in turn made the Bancor Curve unstable.

		if creatorCoinToSellNanos == existingProfileEntry.CoinsInCirculationNanos {
			bitCloutBeforeFeesNanos = existingProfileEntry.BitCloutLockedNanos
		} else {
			// Calculate the amount to return based on the Bancor Curve.
			bitCloutBeforeFeesNanos = CalculateBitCloutToReturn(
				creatorCoinToSellNanos, existingProfileEntry.CoinsInCirculationNanos,
				existingProfileEntry.BitCloutLockedNanos, bav.Params)

			// If the amount the formula is offering is more than what is locked in the
			// profile, then truncate it down. This addresses an edge case where our
			// equations may return *too much* BitClout due to rounding errors.
			if bitCloutBeforeFeesNanos > existingProfileEntry.BitCloutLockedNanos {
				bitCloutBeforeFeesNanos = existingProfileEntry.BitCloutLockedNanos
			}
		}
	}

	// Save all the old values from the CoinEntry before we potentially
	// update them. Note that CoinEntry doesn't contain any pointers and so
	// a direct copy is OK.
	prevCoinEntry := existingProfileEntry.CoinEntry

	// Subtract the amount of BitClout the seller is getting from the amount of
	// BitClout locked in the profile. Sanity-check that it does not exceed the
	// total amount of BitClout locked.
	if bitCloutBeforeFeesNanos > existingProfileEntry.BitCloutLockedNanos {
		return 0, 0, 0, nil, fmt.Errorf("_connectCreatorCoin: BitClout nanos seller "+
			"would get %v exceeds BitClout nanos locked in profile %v",
			bitCloutBeforeFeesNanos, existingProfileEntry.BitCloutLockedNanos)
	}
	existingProfileEntry.BitCloutLockedNanos -= bitCloutBeforeFeesNanos

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

	// If the number of holders has reached zero, we clear all the BitCloutLockedNanos and
	// creatorCoinToSellNanos to ensure that the profile is reset to its normal initial state.
	// It's okay to modify these values because they are saved in the PrevCoinEntry.
	if existingProfileEntry.NumberOfHolders == 0 {
		existingProfileEntry.BitCloutLockedNanos = 0
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

	// Charge a fee on the BitClout the seller is getting to hedge against
	// floating point errors
	bitCloutAfterFeesNanos := IntDiv(
		IntMul(
			big.NewInt(int64(bitCloutBeforeFeesNanos)),
			big.NewInt(int64(100*100-bav.Params.CreatorCoinTradeFeeBasisPoints))),
		big.NewInt(100*100)).Uint64()

	// Check that the seller is getting back an amount of BitClout that is
	// greater than or equal to what they expect. Note that this check is
	// skipped if the min amount specified is zero.
	if txMeta.MinBitCloutExpectedNanos != 0 &&
		bitCloutAfterFeesNanos < txMeta.MinBitCloutExpectedNanos {

		return 0, 0, 0, nil, errors.Wrapf(
			RuleErrorBitCloutReceivedIsLessThanMinimumSetBySeller,
			"_connectCreatorCoin: BitClout nanos that would be given to seller: "+
				"%v, amount user needed: %v",
			bitCloutAfterFeesNanos, txMeta.MinBitCloutExpectedNanos)
	}

	// Now that we have all the information we need, save a UTXO allowing the user to
	// spend the BitClout from the sale in the future.
	outputKey := UtxoKey{
		TxID: *txn.Hash(),
		// The output is like an extra virtual output at the end of the transaction.
		Index: uint32(len(txn.TxOutputs)),
	}
	utxoEntry := UtxoEntry{
		AmountNanos: bitCloutAfterFeesNanos,
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
	_, err = bav._addUtxo(&utxoEntry)
	if err != nil {
		return 0, 0, 0, nil, errors.Wrapf(
			err, "_connectBitcoinExchange: Problem adding output utxo")
	}
	// Note that we don't need to save a UTXOOperation for the added UTXO
	// because no extra information is needed in order to roll it back.

	// Add an operation to the list at the end indicating we've executed a
	// CreatorCoin txn. Save the previous state of the CoinEntry for easy
	// reversion during disconnect.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                       OperationTypeCreatorCoin,
		PrevCoinEntry:              &prevCoinEntry,
		PrevTransactorBalanceEntry: &prevTransactorBalanceEntry,
		PrevCreatorBalanceEntry:    nil,
	})

	// The BitClout that the user gets from selling their creator coin counts
	// as both input and output in the transaction.
	return totalInput + bitCloutAfterFeesNanos,
		totalOutput + bitCloutAfterFeesNanos,
		bitCloutAfterFeesNanos, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectCreatorCoin(
	txn *MsgBitCloutTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
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
		// We don't need the bitCloutReturned return value
		totalInput, totalOutput, _, utxoOps, err :=
			bav.HelpConnectCreatorCoinSell(txn, txHash, blockHeight, verifySignatures)
		return totalInput, totalOutput, utxoOps, err

	case CreatorCoinOperationTypeAddBitClout:
		return 0, 0, nil, fmt.Errorf("_connectCreatorCoin: Add BitClout not implemented")
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
	diamondLevelMap := GetBitCloutNanosDiamondLevelMapAtBlockHeight(int64(blockHeight))
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
		existingProfileEntry.CoinsInCirculationNanos, existingProfileEntry.BitCloutLockedNanos,
		currDiamondLevel, int64(blockHeight), bav.Params)
	neededCreatorCoinNanos := GetCreatorCoinNanosForDiamondLevelAtBlockHeight(
		existingProfileEntry.CoinsInCirculationNanos, existingProfileEntry.BitCloutLockedNanos,
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

func (bav *UtxoView) _connectCreatorCoinTransfer(
	txn *MsgBitCloutTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
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
	// to force-convert all your creator coin into BitClout. Think about it.
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
	senderBalanceEntry, _, _ := bav._getBalanceEntryForHODLerPubKeyAndCreatorPubKey(
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
	receiverBalanceEntry, _, _ := bav._getBalanceEntryForHODLerPubKeyAndCreatorPubKey(
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
	if hasDiamondPostHash {
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

func (bav *UtxoView) ConnectTransaction(txn *MsgBitCloutTxn, txHash *BlockHash,
	txnSizeBytes int64,
	blockHeight uint32, verifySignatures bool, ignoreUtxos bool) (
	_utxoOps []*UtxoOperation, _totalInput uint64, _totalOutput uint64,
	_fees uint64, _err error) {

	return bav._connectTransaction(txn, txHash,
		txnSizeBytes,
		blockHeight, verifySignatures,
		true, /*checkMerkleProof*/
		bav.Params.BitcoinMinBurnWorkBlockss,
		ignoreUtxos)

}

func (bav *UtxoView) _connectTransaction(txn *MsgBitCloutTxn, txHash *BlockHash,
	txnSizeBytes int64,
	blockHeight uint32, verifySignatures bool,
	checkMerkleProof bool,
	minBitcoinBurnWorkBlocks int64, ignoreUtxos bool) (
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
				txn, txHash, blockHeight, verifySignatures,
				checkMerkleProof, minBitcoinBurnWorkBlocks)

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
	// BitClout is being minted. They do not need to abide by the global minimum fee check, since if they had
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
	bitcloutBlock *MsgBitCloutBlock, txHashes []*BlockHash, verifySignatures bool) (
	[][]*UtxoOperation, error) {

	glog.Debugf("ConnectBlock: Connecting block %v", bitcloutBlock)

	// Check that the block being connected references the current tip. ConnectBlock
	// can only add a block to the current tip. We do this to keep the API simple.
	if *bitcloutBlock.Header.PrevBlockHash != *bav.TipHash {
		return nil, fmt.Errorf(
			"ConnectBlock: Parent hash of block being connected does not match tip")
	}

	blockHeader := bitcloutBlock.Header
	// Loop through all the transactions and validate them using the view. Also
	// keep track of the total fees throughout.
	var totalFees uint64
	utxoOps := [][]*UtxoOperation{}
	for txIndex, txn := range bitcloutBlock.Txns {
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
	}

	// We should now have computed totalFees. Use this to check that
	// the block reward's outputs are correct.
	//
	// Compute the sum of the outputs in the block reward. If an overflow
	// occurs mark the block as invalid and return a rule error.
	var blockRewardOutput uint64
	for _, bro := range bitcloutBlock.Txns[0].TxOutputs {
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
	blockHash, err := bitcloutBlock.Header.Hash()
	if err != nil {
		return nil, fmt.Errorf("ConnectBlock: Problem computing block hash after validation")
	}
	bav.TipHash = blockHash

	return utxoOps, nil
}

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

func (bav *UtxoView) GetCommentEntriesForParentStakeID(parentStakeID []byte,
) (_commentEntries []*PostEntry, _err error) {

	// Get the comment hashes from the DB.
	_, dbCommentHashes, _, err := DBGetCommentPostHashesForParentStakeID(
		bav.Handle, parentStakeID, false /*fetchEntries*/)
	if err != nil {
		return nil, errors.Wrapf(
			err, "GetCommentEntriesForParentStakeID: Problem fetching comment PostEntry's from db: ")
	}

	// Load comment hashes into the view.
	for _, commentHash := range dbCommentHashes {
		bav.GetPostEntryForPostHash(commentHash)
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
			commentsForPost := commentsByPostHash[*StakeIDToHash(postEntry.ParentStakeID)]
			commentsForPost = append(commentsForPost, postEntry)
			commentsByPostHash[*StakeIDToHash(postEntry.ParentStakeID)] = commentsForPost
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

	// Iterate over the view and create the final list to return.
	likerPubKeys := [][]byte{}
	for _, likeEntry := range bav.LikeKeyToLikeEntry {
		if !likeEntry.isDeleted && reflect.DeepEqual(likeEntry.LikedPostHash[:], postHash[:]) {
			likerPubKeys = append(likerPubKeys, likeEntry.LikerPubKey)
		}
	}

	return likerPubKeys, nil
}

func (bav *UtxoView) GetRecloutsForPostHash(postHash *BlockHash) (_reclouterPubKeys [][]byte, _err error) {
	handle := bav.Handle
	dbPrefix := append([]byte{}, _PrefixRecloutedPostHashReclouterPubKey...)
	dbPrefix = append(dbPrefix, postHash[:]...)
	keysFound, _ := EnumerateKeysForPrefix(handle, dbPrefix)

	// Iterate over all the db keys & values and load them into the view.
	expectedKeyLength := 1 + HashSizeBytes + btcec.PubKeyBytesLenCompressed
	for _, key := range keysFound {
		// Sanity check that this is a reasonable key.
		if len(key) != expectedKeyLength {
			return nil, fmt.Errorf("UtxoView.GetRecloutersForPostHash: Invalid key length found: %d", len(key))
		}

		reclouterPubKey := key[1+HashSizeBytes:]

		recloutKey := &RecloutKey{
			ReclouterPubKey:   MakePkMapKey(reclouterPubKey),
			RecloutedPostHash: *postHash,
		}

		bav._getRecloutEntryForRecloutKey(recloutKey)
	}

	// Iterate over the view and create the final list to return.
	reclouterPubKeys := [][]byte{}
	for _, recloutEntry := range bav.RecloutKeyToRecloutEntry {
		if !recloutEntry.isDeleted && reflect.DeepEqual(recloutEntry.RecloutedPostHash[:], postHash[:]) {
			reclouterPubKeys = append(reclouterPubKeys, recloutEntry.ReclouterPubKey)
		}
	}

	return reclouterPubKeys, nil
}

func (bav *UtxoView) GetQuoteRecloutsForPostHash(postHash *BlockHash,
) (_quoteReclouterPubKeys [][]byte, _quoteReclouterPubKeyToPosts map[PkMapKey][]*PostEntry, _err error) {
	handle := bav.Handle
	dbPrefix := append([]byte{}, _PrefixRecloutedPostHashReclouterPubKeyRecloutPostHash...)
	dbPrefix = append(dbPrefix, postHash[:]...)
	keysFound, _ := EnumerateKeysForPrefix(handle, dbPrefix)

	// Iterate over all the db keys & values and load them into the view.
	expectedKeyLength := 1 + HashSizeBytes + btcec.PubKeyBytesLenCompressed + HashSizeBytes

	recloutPostHashIdx := 1 + HashSizeBytes + btcec.PubKeyBytesLenCompressed
	for _, key := range keysFound {
		// Sanity check that this is a reasonable key.
		if len(key) != expectedKeyLength {
			return nil, nil, fmt.Errorf("UtxoView.GetQuoteRecloutsForPostHash: Invalid key length found: %d", len(key))
		}

		recloutPostHash := &BlockHash{}
		copy(recloutPostHash[:], key[recloutPostHashIdx:])

		bav.GetPostEntryForPostHash(recloutPostHash)
	}

	// Iterate over the view and create the final map to return.
	quoteReclouterPubKeys := [][]byte{}
	quoteReclouterPubKeyToPosts := make(map[PkMapKey][]*PostEntry)

	for _, postEntry := range bav.PostHashToPostEntry {
		if !postEntry.isDeleted && postEntry.IsQuotedReclout && reflect.DeepEqual(postEntry.RecloutedPostHash[:], postHash[:]) {
			quoteReclouterPubKeys = append(quoteReclouterPubKeys, postEntry.PosterPublicKey)

			quoteRecloutPosts, _ := quoteReclouterPubKeyToPosts[MakePkMapKey(postEntry.PosterPublicKey)]
			quoteRecloutPosts = append(quoteRecloutPosts, postEntry)
			quoteReclouterPubKeyToPosts[MakePkMapKey(postEntry.PosterPublicKey)] = quoteRecloutPosts
		}
	}

	return quoteReclouterPubKeys, quoteReclouterPubKeyToPosts, nil
}

// Just fetch all the profiles from the db and join them with all the profiles
// in the mempool. Then sort them by their BitClout. This can be called
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
			postEntry.stakeStats = GetStakeEntryStats(postEntry.StakeEntry, bav.Params)
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
		profileEntry.stakeStats = GetStakeEntryStats(profileEntry.StakeEntry, bav.Params)
		profilesByPublicKey[MakePkMapKey(profileEntry.PublicKey)] = profileEntry
	}

	// Sort the posts for each profile by when their stake.
	for _, postsForProfile := range corePostsByPublicKey {
		sort.Slice(postsForProfile, func(ii, jj int) bool {
			return postsForProfile[ii].stakeStats.TotalStakeNanos > postsForProfile[jj].stakeStats.TotalStakeNanos
		})
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
	utxoEntriesForPublicKey, err := DbGetUtxosForPubKey(pkBytes, bav.Handle)
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

func (bav *UtxoView) _flushUtxosToDbWithTxn(txn *badger.Txn) error {
	glog.Debugf("_flushUtxosToDbWithTxn: flushing %d mappings", len(bav.UtxoKeyToUtxoEntry))

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

		// Start by deleting the pre-existing mappings in the db for this key if they
		// have not yet been modified.
		if err := DeleteUnmodifiedMappingsForUtxoWithTxn(txn, &utxoKey); err != nil {
			return err
		}
	}
	numDeleted := 0
	numPut := 0
	for utxoKeyIter, utxoEntry := range bav.UtxoKeyToUtxoEntry {
		// Make a copy of the iterator since it might change from under us.
		utxoKey := utxoKeyIter

		if utxoEntry.isSpent {
			numDeleted++
			// If an entry is spent then there's nothing to do, since the mappings in
			// the db have already been deleted.
		} else {
			numPut++
			// If the entry is unspent, then we need to re-set its mappings in the db
			// appropriately.
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

func (bav *UtxoView) _flushGlobalParamsEntryToDbWithTxn(txn *badger.Txn) error {
	globalParamsEntry := bav.GlobalParamsEntry
	if err := DbPutGlobalParamsEntryWithTxn(txn, *globalParamsEntry); err != nil {
		return errors.Wrapf(err, "_flushGlobalParamsEntryToDbWithTxn: Problem putting global params entry in DB")
	}
	return nil
}

func (bav *UtxoView) _flushForbiddenPubKeyEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through all the entries in the KeyTorecloutEntry map.
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
		senderMessageKeyInEntry := MakeMessageKey(
			messageEntry.SenderPublicKey, messageEntry.TstampNanos)
		recipientMessageKeyInEntry := MakeMessageKey(
			messageEntry.RecipientPublicKey, messageEntry.TstampNanos)
		if senderMessageKeyInEntry != messageKey && recipientMessageKeyInEntry != messageKey {
			return fmt.Errorf("_flushMessageEntriesToDbWithTxn: MessageEntry has "+
				"SenderMessageKey: %v and RecipientMessageKey %v, neither of which match "+
				"the MessageKeyToMessageEntry map key %v",
				&senderMessageKeyInEntry, &recipientMessageKeyInEntry, &messageKey)
		}

		// Delete the existing mappings in the db for this MessageKey. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DbDeleteMessageEntryMappingsWithTxn(
			txn, messageKey.PublicKey[:], messageKey.TstampNanos); err != nil {

			return errors.Wrapf(
				err, "_flushMessageEntriesToDbWithTxn: Problem deleting mappings "+
					"for MessageKey: %v: ", &messageKey)
		}
	}
	// Go through all the entries in the MessageKeyToMessageEntry map.
	for _, messageEntry := range bav.MessageKeyToMessageEntry {
		if messageEntry.isDeleted {
			// If the MessageEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
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

func (bav *UtxoView) _flushRecloutEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through all the entries in the recloutKeyTorecloutEntry map.
	for recloutKeyIter, recloutEntry := range bav.RecloutKeyToRecloutEntry {
		// Make a copy of the iterator since we make references to it below.
		recloutKey := recloutKeyIter

		// Sanity-check that the RecloutKey computed from the RecloutEntry is
		// equal to the RecloutKey that maps to that entry.
		recloutKeyInEntry := MakeRecloutKey(recloutEntry.ReclouterPubKey, *recloutEntry.RecloutedPostHash)
		if recloutKeyInEntry != recloutKey {
			return fmt.Errorf("_flushRecloutEntriesToDbWithTxn: RecloutEntry has "+
				"RecloutKey: %v, which doesn't match the RecloutKeyToRecloutEntry map key %v",
				&recloutKeyInEntry, &recloutKey)
		}

		// Delete the existing mappings in the db for this RecloutKey. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DbDeleteRecloutMappingsWithTxn(
			txn, recloutKey.ReclouterPubKey[:], recloutKey.RecloutedPostHash); err != nil {

			return errors.Wrapf(
				err, "_flushRecloutEntriesToDbWithTxn: Problem deleting mappings "+
					"for RecloutKey: %v: ", &recloutKey)
		}
	}
	for _, recloutEntry := range bav.RecloutKeyToRecloutEntry {
		if recloutEntry.isDeleted {
			// If the RecloutedEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If the RecloutEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DbPutRecloutMappingsWithTxn(
				txn, recloutEntry.ReclouterPubKey, *recloutEntry.RecloutedPostHash, *recloutEntry); err != nil {
				return err
			}
		}
	}

	// At this point all of the RecloutEntry mappings in the db should be up-to-date.
	return nil
}

func (bav *UtxoView) _flushLikeEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through all the entries in the LikeKeyToLikeEntry map.
	for likeKeyIter, likeEntry := range bav.LikeKeyToLikeEntry {
		// Make a copy of the iterator since we make references to it below.
		likeKey := likeKeyIter

		// Sanity-check that the LikeKey computed from the LikeEntry is
		// equal to the LikeKey that maps to that entry.
		likeKeyInEntry := MakeLikeKey(likeEntry.LikerPubKey, *likeEntry.LikedPostHash)
		if likeKeyInEntry != likeKey {
			return fmt.Errorf("_flushLikeEntriesToDbWithTxn: LikeEntry has "+
				"LikeKey: %v, which doesn't match the LikeKeyToLikeEntry map key %v",
				&likeKeyInEntry, &likeKey)
		}

		// Delete the existing mappings in the db for this LikeKey. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DbDeleteLikeMappingsWithTxn(
			txn, likeKey.LikerPubKey[:], likeKey.LikedPostHash); err != nil {

			return errors.Wrapf(
				err, "_flushLikeEntriesToDbWithTxn: Problem deleting mappings "+
					"for LikeKey: %v: ", &likeKey)
		}
	}

	// Go through all the entries in the LikeKeyToLikeEntry map.
	for _, likeEntry := range bav.LikeKeyToLikeEntry {

		if likeEntry.isDeleted {
			// If the LikeEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If the LikeEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DbPutLikeMappingsWithTxn(
				txn, likeEntry.LikerPubKey, *likeEntry.LikedPostHash); err != nil {

				return err
			}
		}
	}

	// At this point all of the MessageEntry mappings in the db should be up-to-date.

	return nil
}

func (bav *UtxoView) _flushFollowEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through all the entries in the FollowKeyToFollowEntry map.
	for followKeyIter, followEntry := range bav.FollowKeyToFollowEntry {
		// Make a copy of the iterator since we make references to it below.
		followKey := followKeyIter

		// Sanity-check that the FollowKey computed from the FollowEntry is
		// equal to the FollowKey that maps to that entry.
		followKeyInEntry := MakeFollowKey(
			followEntry.FollowerPKID, followEntry.FollowedPKID)
		if followKeyInEntry != followKey {
			return fmt.Errorf("_flushFollowEntriesToDbWithTxn: FollowEntry has "+
				"FollowKey: %v, which doesn't match the FollowKeyToFollowEntry map key %v",
				&followKeyInEntry, &followKey)
		}

		// Delete the existing mappings in the db for this FollowKey. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DbDeleteFollowMappingsWithTxn(
			txn, followEntry.FollowerPKID, followEntry.FollowedPKID); err != nil {

			return errors.Wrapf(
				err, "_flushFollowEntriesToDbWithTxn: Problem deleting mappings "+
					"for FollowKey: %v: ", &followKey)
		}
	}

	// Go through all the entries in the FollowKeyToFollowEntry map.
	for _, followEntry := range bav.FollowKeyToFollowEntry {
		if followEntry.isDeleted {
			// If the FollowEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If the FollowEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DbPutFollowMappingsWithTxn(
				txn, followEntry.FollowerPKID, followEntry.FollowedPKID); err != nil {

				return err
			}
		}
	}

	// At this point all of the MessageEntry mappings in the db should be up-to-date.

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

		// Delete the existing mappings in the db for this DiamondKey. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DbDeleteDiamondMappingsWithTxn(txn, diamondEntry); err != nil {

			return errors.Wrapf(
				err, "_flushDiamondEntriesToDbWithTxn: Problem deleting mappings "+
					"for DiamondKey: %v: ", &diamondKey)
		}
	}

	// Add back all of the entries that aren't deleted.
	for _, diamondEntry := range bav.DiamondKeyToDiamondEntry {
		if diamondEntry.isDeleted {
			// If the DiamondEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If the DiamondEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DbPutDiamondMappingsWithTxn(
				txn,
				diamondEntry); err != nil {
				return err
			}
		}
	}

	// At this point all of the MessageEntry mappings in the db should be up-to-date.

	return nil
}

func (bav *UtxoView) _flushPostEntriesToDbWithTxn(txn *badger.Txn) error {
	// TODO(DELETEME): Remove flush logging after debugging MarkBlockInvalid bug.
	glog.Debugf("_flushPostEntriesToDbWithTxn: flushing %d mappings", len(bav.PostHashToPostEntry))

	// Go through all the entries in the PostHashToPostEntry map.
	for postHashIter, postEntry := range bav.PostHashToPostEntry {
		// Make a copy of the iterator since we take references to it below.
		postHash := postHashIter

		// Sanity-check that the hash in the post is the same as the hash in the
		// entry
		if postHash != *postEntry.PostHash {
			return fmt.Errorf("_flushPostEntriesToDbWithTxn: PostEntry has "+
				"PostHash: %v, neither of which match "+
				"the PostHashToPostEntry map key %v",
				postHash, postEntry.PostHash)
		}

		// Delete the existing mappings in the db for this PostHash. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DBDeletePostEntryMappingsWithTxn(txn, &postHash, bav.Params); err != nil {
			return errors.Wrapf(
				err, "_flushPostEntriesToDbWithTxn: Problem deleting mappings "+
					"for PostHash: %v: ", postHash)
		}
	}
	numDeleted := 0
	numPut := 0
	for _, postEntry := range bav.PostHashToPostEntry {
		if postEntry.isDeleted {
			numDeleted++
			// If the PostEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			numPut++
			// If the PostEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DBPutPostEntryMappingsWithTxn(txn, postEntry, bav.Params); err != nil {

				return err
			}
		}
	}

	// TODO(DELETEME): Remove flush logging after debugging MarkBlockInvalid bug.
	glog.Debugf("_flushPostEntriesToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)

	// At this point all of the PostEntry mappings in the db should be up-to-date.

	return nil
}
func (bav *UtxoView) _flushPKIDEntriesToDbWithTxn(txn *badger.Txn) error {
	for pubKeyIter, pkidEntry := range bav.PublicKeyToPKIDEntry {
		pubKeyCopy := make([]byte, btcec.PubKeyBytesLenCompressed)
		copy(pubKeyCopy, pubKeyIter[:])

		// Delete the existing mappings in the db for this PKID. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DBDeletePKIDMappingsWithTxn(txn, pubKeyCopy, bav.Params); err != nil {
			return errors.Wrapf(
				err, "_flushPKIDEntriesToDbWithTxn: Problem deleting mappings "+
					"for pkid: %v, public key: %v: ", PkToString(pkidEntry.PKID[:], bav.Params),
				PkToString(pubKeyCopy, bav.Params))
		}
	}

	// Go through all the entries in the ProfilePublicKeyToProfileEntry map.
	for pubKeyIter, pkidEntry := range bav.PublicKeyToPKIDEntry {
		pubKeyCopy := make([]byte, btcec.PubKeyBytesLenCompressed)
		copy(pubKeyCopy, pubKeyIter[:])

		if pkidEntry.isDeleted {
			// If the ProfileEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
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

			// If the ProfileEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
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

func (bav *UtxoView) FlushToDbWithTxn(txn *badger.Txn) error {
	// Flush the utxos to the db.
	if err := bav._flushUtxosToDbWithTxn(txn); err != nil {
		return err
	}

	if err := bav._flushBitcoinExchangeDataWithTxn(txn); err != nil {
		return err
	}

	if err := bav._flushGlobalParamsEntryToDbWithTxn(txn); err != nil {
		return err
	}

	if err := bav._flushForbiddenPubKeyEntriesToDbWithTxn(txn); err != nil {
		return err
	}

	if err := bav._flushMessageEntriesToDbWithTxn(txn); err != nil {
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

	if err := bav._flushRecloutEntriesToDbWithTxn(txn); err != nil {
		return err
	}

	if err := bav._flushPostEntriesToDbWithTxn(txn); err != nil {
		return err
	}
	if err := bav._flushProfileEntriesToDbWithTxn(txn); err != nil {
		return err
	}
	if err := bav._flushBalanceEntriesToDbWithTxn(txn); err != nil {
		return err
	}
	if err := bav._flushPKIDEntriesToDbWithTxn(txn); err != nil {
		return err
	}

	return nil
}

func (bav *UtxoView) FlushToDb() error {
	// Make sure everything happens inside a single transaction.
	err := bav.Handle.Update(func(txn *badger.Txn) error {
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
