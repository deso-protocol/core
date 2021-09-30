package lib

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/go-pg/pg/v10/orm"
	"github.com/golang/glog"
	"github.com/uptrace/bun"
	"reflect"
	"strings"
)

type Postgres struct {
	db  *bun.DB
	ctx context.Context
}

func NewPostgres(db *bun.DB) *Postgres {
	// Uncomment to print all queries.
	//db.AddQueryHook(pgdebug.DebugHook{
	//	Verbose: true,
	//})

	return &Postgres{
		db:  db,
		ctx: context.Background(),
	}
}

// LogSelect is a helpful utility when developing or debugging queries. Simply call
// LogSelect(query) instead of query.Select() to get a log of the raw query.
func LogSelect(query *orm.Query) error {
	selectQuery := orm.NewSelectQuery(query)
	fmter := orm.NewFormatter().WithModel(selectQuery)
	queryStr, _ := selectQuery.AppendQuery(fmter, nil)
	glog.Info(string(queryStr))
	return query.Select()
}

func LogError(err error) {
	glog.Info(reflect.TypeOf(err))
}

const (
	MAIN_CHAIN = "main"
)

//
// Tables
//
// The current schema is the sum of all the migrations in the migrate folder. Eventually we should
// export the current schema as new instances of the chain shouldn't be running every single migration.
//
// For information about the `bun:"..."` annotations, see: https://pg.uptrace.dev/models/
//
// Common annotations include:
// - Don't store 0 or false as NULL:
//
// The primary key for every table must be an auto incrementing big integer lest you desire to
// suffer the wrath of poor InnoDB insert performance
//
// Table names are defined so the relation is obvious even though go-pg can create them for us automatically.
//
// Column names are automatically created by go-pg. For example, a field named TipHash maps to tip_hash.
//

type PGChain struct {
	bun.BaseModel `bun:"pg_chains"`
	ID            uint64

	Name    string
	TipHash *BlockHash `bun:",type:binary"`
}

// PGBlock represents BlockNode and MsgDeSoHeader
type PGBlock struct {
	bun.BaseModel `bun:"pg_blocks"`
	ID            uint64

	// BlockNode and MsgDeSoHeader
	Hash       *BlockHash `bun:",type:binary"`
	ParentHash *BlockHash `bun:",type:binary"`
	Height     uint64

	// BlockNode
	DifficultyTarget *BlockHash  `bun:",type:binary"`
	CumWork          *BlockHash  `bun:",type:binary"`
	Status           BlockStatus // TODO: Refactor

	// MsgDeSoHeader
	TxMerkleRoot *BlockHash `bun:",type:binary"`
	Version      uint32
	Timestamp    uint64
	Nonce        uint64
	ExtraNonce   uint64

	// Notifications
	Notified bool
}

// PGTransaction represents MsgDeSoTxn
type PGTransaction struct {
	bun.BaseModel `bun:"pg_transactions"`
	ID            uint64

	Hash      *BlockHash `bun:"type:binary"`
	BlockHash *BlockHash `bun:",type:binary"`
	Type      TxnType
	PublicKey []byte `bun:",type:binary"`
	ExtraData map[string][]byte
	R         *BlockHash `bun:",type:binary"`
	S         *BlockHash `bun:",type:binary"`

	// Relationships
	Outputs                     []*PGTransactionOutput         `bun:"rel:has-many,join:hash=output_hash"`
	MetadataBlockReward         *PGMetadataBlockReward         `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataBitcoinExchange     *PGMetadataBitcoinExchange     `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataPrivateMessage      *PGMetadataPrivateMessage      `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataSubmitPost          *PGMetadataSubmitPost          `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataUpdateExchangeRate  *PGMetadataUpdateExchangeRate  `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataUpdateProfile       *PGMetadataUpdateProfile       `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataFollow              *PGMetadataFollow              `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataLike                *PGMetadataLike                `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataCreatorCoin         *PGMetadataCreatorCoin         `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataCreatorCoinTransfer *PGMetadataCreatorCoinTransfer `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataSwapIdentity        *PGMetadataSwapIdentity        `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataCreateNFT           *PGMetadataCreateNFT           `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataUpdateNFT           *PGMetadataUpdateNFT           `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataAcceptNFTBid        *PGMetadataAcceptNFTBid        `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataNFTBid              *PGMetadataNFTBid              `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataNFTTransfer         *PGMetadataNFTTransfer         `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataAcceptNFTTransfer   *PGMetadataAcceptNFTTransfer   `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataBurnNFT             *PGMetadataBurnNFT             `bun:"rel:has-one,join:hash=transaction_hash"`
	MetadataDerivedKey          *PGMetadataDerivedKey          `bun:"rel:has-one,join:hash=transaction_hash"`
}

// PGTransactionOutput represents DeSoOutput, DeSoInput, and UtxoEntry
type PGTransactionOutput struct {
	bun.BaseModel `bun:"pg_transaction_outputs"`
	ID            uint64

	OutputHash  *BlockHash `bun:",allowzero"`
	OutputIndex uint32     `bun:",allowzero"`
	OutputType  UtxoType
	Height      uint32
	PublicKey   []byte
	AmountNanos uint64
	Spent       bool
	InputHash   *BlockHash `bun:",nullzero"`
	InputIndex  uint32
}

func (utxo *PGTransactionOutput) NewUtxoEntry() *UtxoEntry {

	return &UtxoEntry{
		PublicKey:   utxo.PublicKey,
		AmountNanos: utxo.AmountNanos,
		BlockHeight: utxo.Height,
		UtxoType:    utxo.OutputType,
		isSpent:     utxo.Spent,
		UtxoKey: &UtxoKey{
			TxID:  *utxo.OutputHash,
			Index: utxo.OutputIndex,
		},
	}
}

// PGMetadataBlockReward represents BlockRewardMetadataa
type PGMetadataBlockReward struct {
	bun.BaseModel `bun:"pg_metadata_block_rewards"`
	ID            uint64

	TransactionHash *BlockHash `bun:"type:binary"`
	ExtraData       []byte     `bun:",type:binary"`
}

// PGMetadataBitcoinExchange represents BitcoinExchangeMetadata
type PGMetadataBitcoinExchange struct {
	bun.BaseModel `bun:"pg_metadata_bitcoin_exchanges"`
	ID            uint64

	TransactionHash   *BlockHash `bun:"type:binary"`
	BitcoinBlockHash  *BlockHash `bun:",type:binary"`
	BitcoinMerkleRoot *BlockHash `bun:",type:binary"`
	// Not storing BitcoinTransaction *wire.MsgTx
	// Not storing BitcoinMerkleProof []*merkletree.ProofPart
}

// PGMetadataPrivateMessage represents PrivateMessageMetadata
type PGMetadataPrivateMessage struct {
	bun.BaseModel `bun:"pg_metadata_private_messages"`
	ID            uint64

	TransactionHash    *BlockHash `bun:"type:binary"`
	RecipientPublicKey []byte     `bun:",type:binary"`
	EncryptedText      []byte     `bun:",type:binary"`
	TimestampNanos     uint64
}

// PGMetadataSubmitPost represents SubmitPostMetadata
type PGMetadataSubmitPost struct {
	bun.BaseModel `bun:"pg_metadata_submit_posts"`
	ID            uint64

	TransactionHash  *BlockHash `bun:"type:binary"`
	PostHashToModify *BlockHash `bun:",type:binary"`
	ParentStakeID    *BlockHash `bun:",type:binary"`
	Body             string
	TimestampNanos   uint64
	IsHidden         bool
}

// PGMetadataUpdateExchangeRate represents UpdateBitcoinUSDExchangeRateMetadataa
type PGMetadataUpdateExchangeRate struct {
	bun.BaseModel `bun:"pg_metadata_update_exchange_rates"`
	ID            uint64

	TransactionHash    *BlockHash `bun:"type:binary"`
	USDCentsPerBitcoin uint64
}

// PGMetadataUpdateProfile represents UpdateProfileMetadata
type PGMetadataUpdateProfile struct {
	bun.BaseModel `bun:"pg_metadata_update_profiles"`
	ID            uint64

	TransactionHash       *BlockHash `bun:"type:binary"`
	ProfilePublicKey      []byte     `bun:",type:binary"`
	NewUsername           []byte     `bun:",type:binary"`
	NewDescription        []byte     `bun:",type:binary"`
	NewProfilePic         []byte     `bun:",type:binary"`
	NewCreatorBasisPoints uint64
}

// PGMetadataFollow represents FollowMetadata
type PGMetadataFollow struct {
	bun.BaseModel `bun:"pg_metadata_follows"`
	ID            uint64

	TransactionHash   *BlockHash `bun:"type:binary"`
	FollowedPublicKey []byte     `bun:",type:binary"`
	IsUnfollow        bool
}

// PGMetadataLike represents LikeMetadata
type PGMetadataLike struct {
	bun.BaseModel `bun:"pg_metadata_likes"`
	ID            uint64

	TransactionHash *BlockHash `bun:"type:binary"`
	LikedPostHash   *BlockHash `bun:",type:binary"`
	IsUnlike        bool
}

// PGMetadataCreatorCoin represents CreatorCoinMetadataa
type PGMetadataCreatorCoin struct {
	bun.BaseModel `bun:"pg_metadata_creator_coins"`
	ID            uint64

	TransactionHash             *BlockHash `bun:"type:binary"`
	ProfilePublicKey            []byte     `bun:",type:binary"`
	OperationType               CreatorCoinOperationType
	DESOToSellNanos             uint64
	CreatorCoinToSellNanos      uint64
	DESOToAddNanos              uint64
	MinDESOExpectedNanos        uint64
	MinCreatorCoinExpectedNanos uint64
}

// PGMetadataCreatorCoinTransfer represents CreatorCoinTransferMetadataa
type PGMetadataCreatorCoinTransfer struct {
	bun.BaseModel `bun:"pg_metadata_creator_coin_transfers"`
	ID            uint64

	TransactionHash            *BlockHash `bun:"type:binary"`
	ProfilePublicKey           []byte     `bun:",type:binary"`
	CreatorCoinToTransferNanos uint64
	ReceiverPublicKey          []byte `bun:",type:binary"`
}

// PGMetadataSwapIdentity represents SwapIdentityMetadataa
type PGMetadataSwapIdentity struct {
	bun.BaseModel `bun:"pg_metadata_swap_identities"`
	ID            uint64

	TransactionHash *BlockHash `bun:"type:binary"`
	FromPublicKey   []byte     `bun:",type:binary"`
	ToPublicKey     []byte     `bun:",type:binary"`
}

// PGMetadataCreateNFT represents CreateNFTMetadata
type PGMetadataCreateNFT struct {
	bun.BaseModel `bun:"pg_metadata_create_nfts"`
	ID            uint64

	TransactionHash           *BlockHash `bun:"type:binary"`
	NFTPostHash               *BlockHash `bun:",type:binary"`
	NumCopies                 uint64
	HasUnlockable             bool
	IsForSale                 bool
	MinBidAmountNanos         uint64
	CreatorRoyaltyBasisPoints uint64
	CoinRoyaltyBasisPoints    uint64
}

// PGMetadataUpdateNFT represents UpdateNFTMetadata
type PGMetadataUpdateNFT struct {
	bun.BaseModel `bun:"pg_metadata_update_nfts"`
	ID            uint64

	TransactionHash   *BlockHash `bun:"type:binary"`
	NFTPostHash       *BlockHash `bun:",type:binary"`
	SerialNumber      uint64
	IsForSale         bool
	MinBidAmountNanos uint64
}

// PGMetadataAcceptNFTBid represents AcceptNFTBidMetadata
type PGMetadataAcceptNFTBid struct {
	bun.BaseModel `bun:"pg_metadata_accept_nft_bids"`
	ID            uint64

	TransactionHash *BlockHash `bun:"type:binary"`
	NFTPostHash     *BlockHash `bun:",type:binary"`
	SerialNumber    uint64
	BidderPKID      *PKID `bun:",type:binary"`
	BidAmountNanos  uint64
	UnlockableText  []byte                `bun:",type:binary"`
	BidderInputs    []*PGMetadataBidInput `bun:"rel:has-many,join:id=transaction_hash"`
}

type PGMetadataBidInput struct {
	bun.BaseModel `bun:"pg_metadata_bid_inputs"`
	ID            uint64

	TransactionHash *BlockHash `bun:"type:binary"`
	InputHash       *BlockHash `bun:"type:binary"`
	InputIndex      uint32     `bun:",pk"`
}

// PGMetadataNFTBid represents NFTBidMetadata
type PGMetadataNFTBid struct {
	bun.BaseModel `bun:"pg_metadata_nft_bids"`
	ID            uint64

	TransactionHash *BlockHash `bun:"type:binary"`
	NFTPostHash     *BlockHash `bun:",type:binary"`
	SerialNumber    uint64
	BidAmountNanos  uint64
}

// PGMetadataNFTTransfer represents NFTTransferMetadata
type PGMetadataNFTTransfer struct {
	bun.BaseModel `bun:"pg_metadata_nft_transfer"`
	ID            uint64

	TransactionHash   *BlockHash `bun:"type:binary"`
	NFTPostHash       *BlockHash `bun:"type:binary"`
	SerialNumber      uint64
	ReceiverPublicKey []byte `bun:"type:binary"`
	UnlockableText    []byte `bun:",type:binary"`
}

// PGMetadataAcceptNFTTransfer represents AcceptNFTTransferMetadata
type PGMetadataAcceptNFTTransfer struct {
	bun.BaseModel `bun:"pg_metadata_accept_nft_transfer"`
	ID            uint64

	TransactionHash *BlockHash `bun:"type:binary"`
	NFTPostHash     *BlockHash `bun:"type:binary"`
	SerialNumber    uint64
}

// PGMetadataBurnNFT represents BurnNFTMetadata
type PGMetadataBurnNFT struct {
	bun.BaseModel `bun:"pg_metadata_burn_nft"`
	ID            uint64

	TransactionHash *BlockHash `bun:"type:binary"`
	NFTPostHash     *BlockHash `bun:"type:binary"`
	SerialNumber    uint64
}

// PGMetadataDerivedKey represents AuthorizeDerivedKeyMetadata
type PGMetadataDerivedKey struct {
	bun.BaseModel `bun:"pg_metadata_derived_keys"`
	ID            uint64

	TransactionHash  *BlockHash `bun:"type:binary"`
	DerivedPublicKey PublicKey  `bun:",type:binary"`
	ExpirationBlock  uint64
	OperationType    AuthorizeDerivedKeyOperationType
	AccessSignature  []byte `bun:",type:binary"`
}

type PGNotification struct {
	bun.BaseModel `bun:"pg_notifications"`
	ID            uint64

	TransactionHash *BlockHash `bun:"type:binary"`
	Mined           bool
	ToUser          []byte `bun:",type:binary"`
	FromUser        []byte `bun:",type:binary"`
	OtherUser       []byte `bun:",type:binary"`
	Type            NotificationType
	Amount          uint64
	PostHash        *BlockHash `bun:",type:binary"`
	Timestamp       uint64
}

type NotificationType uint8

const (
	NotificationUnknown NotificationType = iota
	NotificationSendDESO
	NotificationLike
	NotificationFollow
	NotificationCoinPurchase
	NotificationCoinTransfer
	NotificationCoinDiamond
	NotificationPostMention
	NotificationPostReply
	NotificationPostRepost
	NotificationDESODiamond
)

type PGProfile struct {
	bun.BaseModel `bun:"pg_profiles"`
	ID            uint64

	PKID                    *PKID      `bun:"type:binary"`
	PublicKey               *PublicKey `bun:",type:binary"`
	Username                string
	Description             string
	ProfilePic              []byte
	CreatorBasisPoints      uint64
	DESOLockedNanos         uint64
	NumberOfHolders         uint64
	CoinsInCirculationNanos uint64
	CoinWatermarkNanos      uint64
}

func (profile *PGProfile) Empty() bool {
	return profile.Username == ""
}

type PGPost struct {
	bun.BaseModel `bun:"pg_posts"`
	ID            uint64

	PostHash                  *BlockHash `bun:"type:binary"`
	PosterPublicKey           []byte
	ParentPostHash            *BlockHash `bun:",type:binary"`
	Body                      string
	RepostedPostHash          *BlockHash `bun:",type:binary"`
	QuotedRepost              bool
	Timestamp                 uint64
	Hidden                    bool
	LikeCount                 uint64
	RepostCount               uint64
	QuoteRepostCount          uint64
	DiamondCount              uint64
	CommentCount              uint64
	Pinned                    bool
	NFT                       bool
	NumNFTCopies              uint64
	NumNFTCopiesForSale       uint64
	NumNFTCopiesBurned        uint64
	Unlockable                bool
	CreatorRoyaltyBasisPoints uint64
	CoinRoyaltyBasisPoints    uint64
	ExtraData                 map[string][]byte
}

func (post *PGPost) NewPostEntry() *PostEntry {
	postEntry := &PostEntry{
		ID:                             post.ID,
		PostHash:                       post.PostHash,
		PosterPublicKey:                post.PosterPublicKey,
		Body:                           []byte(post.Body),
		RepostedPostHash:               post.RepostedPostHash,
		IsQuotedRepost:                 post.QuotedRepost,
		TimestampNanos:                 post.Timestamp,
		IsHidden:                       post.Hidden,
		LikeCount:                      post.LikeCount,
		RepostCount:                    post.RepostCount,
		QuoteRepostCount:               post.QuoteRepostCount,
		DiamondCount:                   post.DiamondCount,
		CommentCount:                   post.CommentCount,
		IsPinned:                       post.Pinned,
		IsNFT:                          post.NFT,
		NumNFTCopies:                   post.NumNFTCopies,
		NumNFTCopiesForSale:            post.NumNFTCopiesForSale,
		NumNFTCopiesBurned:             post.NumNFTCopiesBurned,
		HasUnlockable:                  post.Unlockable,
		NFTRoyaltyToCoinBasisPoints:    post.CoinRoyaltyBasisPoints,
		NFTRoyaltyToCreatorBasisPoints: post.CreatorRoyaltyBasisPoints,
		PostExtraData:                  post.ExtraData,
	}

	if post.ParentPostHash != nil {
		postEntry.ParentStakeID = post.ParentPostHash.ToBytes()
	}

	return postEntry
}

// HasMedia is inefficient and needs to be moved to a column in the Posts table
func (post *PGPost) HasMedia() bool {
	bodyJSONObj := DeSoBodySchema{}
	err := json.Unmarshal([]byte(post.Body), &bodyJSONObj)
	// Return true if body json can be parsed and ImageUrls or VideoURLs is not nil/non-empty or EmbedVideoUrl is not nil/non-empty
	return (err == nil && len(bodyJSONObj.ImageURLs) > 0 || len(bodyJSONObj.VideoURLs) > 0) || len(post.ExtraData["EmbedVideoURL"]) > 0
}

type PGLike struct {
	bun.BaseModel `bun:"pg_likes"`
	ID            uint64

	LikerPublicKey []byte     `bun:"type:binary"`
	LikedPostHash  *BlockHash `bun:"type:binary"`
}

func (like *PGLike) NewLikeEntry() *LikeEntry {
	return &LikeEntry{
		ID:            like.ID,
		LikerPubKey:   like.LikerPublicKey,
		LikedPostHash: like.LikedPostHash,
	}
}

type PGFollow struct {
	bun.BaseModel `bun:"pg_follows"`
	ID            uint64

	FollowerPKID *PKID `bun:"type:binary"`
	FollowedPKID *PKID `bun:"type:binary"`
}

func (follow *PGFollow) NewFollowEntry() *FollowEntry {
	return &FollowEntry{
		ID:           follow.ID,
		FollowerPKID: follow.FollowerPKID,
		FollowedPKID: follow.FollowedPKID,
	}
}

type PGDiamond struct {
	bun.BaseModel `bun:"pg_diamonds"`
	ID            uint64

	SenderPKID      *PKID      `bun:"type:binary"`
	ReceiverPKID    *PKID      `bun:"type:binary"`
	DiamondPostHash *BlockHash `bun:"type:binary"`
	DiamondLevel    uint8
}

// TODO: This doesn't need to be a table. Just add sender to PGMetadataPrivateMessage?
// The only reason we might not want to do this is if we end up pruning Metadata tables.
type PGMessage struct {
	bun.BaseModel `bun:"pg_messages"`
	ID            uint64

	MessageHash        *BlockHash `bun:"type:binary"`
	SenderPublicKey    []byte
	RecipientPublicKey []byte
	EncryptedText      []byte
	TimestampNanos     uint64
	// TODO: Version

	// Used to track deletions in the UtxoView
	isDeleted bool
}

type PGCreatorCoinBalance struct {
	bun.BaseModel `bun:"pg_creator_coin_balances"`
	ID            uint64

	HolderPKID   *PKID `bun:"type:binary"`
	CreatorPKID  *PKID `bun:"type:binary"`
	BalanceNanos uint64
	HasPurchased bool
}

func (balance *PGCreatorCoinBalance) NewBalanceEntry() *BalanceEntry {
	return &BalanceEntry{
		ID:           balance.ID,
		HODLerPKID:   balance.HolderPKID,
		CreatorPKID:  balance.CreatorPKID,
		BalanceNanos: balance.BalanceNanos,
		HasPurchased: balance.HasPurchased,
	}
}

// PGBalance represents PublicKeyToDeSoBalanceNanos
type PGBalance struct {
	bun.BaseModel `bun:"pg_balances"`
	ID            uint64

	PublicKey    *PublicKey `bun:"type:binary"`
	BalanceNanos uint64
}

// PGGlobalParams represents GlobalParamsEntry
type PGGlobalParams struct {
	bun.BaseModel `bun:"pg_global_params"`
	ID            uint64

	USDCentsPerBitcoin      uint64
	CreateProfileFeeNanos   uint64
	CreateNFTFeeNanos       uint64
	MaxCopiesPerNFT         uint64
	MinNetworkFeeNanosPerKB uint64
}

type PGRepost struct {
	bun.BaseModel `bun:"pg_reposts"`
	ID            uint64

	ReposterPublickey *PublicKey `bun:"type:binary"`
	RepostedPostHash  *BlockHash `bun:"type:binary"`
	RepostPostHash    *BlockHash `bun:",type:binary"`

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

// PGForbiddenKey represents ForbiddenPubKeyEntry
type PGForbiddenKey struct {
	bun.BaseModel `bun:"pg_forbidden_keys"`
	ID            uint64

	PublicKey *PublicKey `bun:"type:binary"`
}

// PGNFT represents NFTEntry
type PGNFT struct {
	bun.BaseModel `bun:"pg_nfts"`
	ID            uint64

	NFTPostHash  *BlockHash `bun:"type:binary"`
	SerialNumber uint64     `bun:",pk"`

	// This is needed to decrypt unlockable text.
	LastOwnerPKID              *PKID `bun:",type:binary"`
	OwnerPKID                  *PKID `bun:",type:binary"`
	ForSale                    bool
	MinBidAmountNanos          uint64
	UnlockableText             string
	LastAcceptedBidAmountNanos uint64
	IsPending                  bool
}

func (nft *PGNFT) NewNFTEntry() *NFTEntry {
	return &NFTEntry{
		ID:                         nft.ID,
		LastOwnerPKID:              nft.LastOwnerPKID,
		OwnerPKID:                  nft.OwnerPKID,
		NFTPostHash:                nft.NFTPostHash,
		SerialNumber:               nft.SerialNumber,
		IsForSale:                  nft.ForSale,
		MinBidAmountNanos:          nft.MinBidAmountNanos,
		UnlockableText:             []byte(nft.UnlockableText),
		LastAcceptedBidAmountNanos: nft.LastAcceptedBidAmountNanos,
		IsPending:                  nft.IsPending,
	}
}

// PGNFTBid represents NFTBidEntry
type PGNFTBid struct {
	bun.BaseModel `bun:"pg_nft_bids"`
	ID            uint64

	BidderPKID     *PKID      `bun:"type:binary"`
	NFTPostHash    *BlockHash `bun:"type:binary"`
	SerialNumber   uint64     `bun:",pk"`
	BidAmountNanos uint64
	Accepted       bool
}

func (bid *PGNFTBid) NewNFTBidEntry() *NFTBidEntry {
	return &NFTBidEntry{
		ID:             bid.ID,
		BidderPKID:     bid.BidderPKID,
		NFTPostHash:    bid.NFTPostHash,
		SerialNumber:   bid.SerialNumber,
		BidAmountNanos: bid.BidAmountNanos,
	}
}

// PGDerivedKey represents DerivedKeyEntry
type PGDerivedKey struct {
	bun.BaseModel `bun:"pg_derived_keys"`
	ID            uint64

	OwnerPublicKey   PublicKey `bun:"type:binary"`
	DerivedPublicKey PublicKey `bun:"type:binary"`
	ExpirationBlock  uint64
	OperationType    AuthorizeDerivedKeyOperationType
}

func (key *PGDerivedKey) NewDerivedKeyEntry() *DerivedKeyEntry {
	return &DerivedKeyEntry{
		ID:               key.ID,
		OwnerPublicKey:   key.OwnerPublicKey,
		DerivedPublicKey: key.DerivedPublicKey,
		ExpirationBlock:  key.ExpirationBlock,
		OperationType:    key.OperationType,
	}
}

//
// Blockchain and Transactions
//

func (postgres *Postgres) UpsertBlock(blockNode *BlockNode) error {
	return postgres.db.RunInTx(postgres.ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		return postgres.UpsertBlockTx(tx, blockNode)
	})
}

func (postgres *Postgres) UpsertBlockTx(tx bun.Tx, blockNode *BlockNode) error {
	block := &PGBlock{
		Hash:   blockNode.Hash,
		Height: blockNode.Header.Height,

		DifficultyTarget: blockNode.DifficultyTarget,
		CumWork:          BigintToHash(blockNode.CumWork),
		Status:           blockNode.Status,

		TxMerkleRoot: blockNode.Header.TransactionMerkleRoot,
		Version:      blockNode.Header.Version,
		Timestamp:    blockNode.Header.TstampSecs,
		Nonce:        blockNode.Header.Nonce,
		ExtraNonce:   blockNode.Header.ExtraNonce,
	}

	// The genesis block has a nil parent
	if blockNode.Parent != nil {
		block.ParentHash = blockNode.Parent.Hash
	}

	_, err := tx.NewInsert().Model(block).On("DUPLICATE KEY UPDATE").Exec(postgres.ctx)
	return err
}

// GetBlockIndex gets all the PGBlocks and creates a map of BlockHash to BlockNode as needed by blockchain.go
func (postgres *Postgres) GetBlockIndex() (map[BlockHash]*BlockNode, error) {
	var blocks []PGBlock
	err := postgres.db.NewSelect().Model(&blocks).Scan(postgres.ctx)
	if err != nil {
		return nil, err
	}

	blockMap := make(map[BlockHash]*BlockNode)
	for _, block := range blocks {
		blockMap[*block.Hash] = &BlockNode{
			Hash:             block.Hash,
			Height:           uint32(block.Height),
			DifficultyTarget: block.DifficultyTarget,
			CumWork:          HashToBigint(block.CumWork),
			Header: &MsgDeSoHeader{
				Version:               block.Version,
				PrevBlockHash:         block.ParentHash,
				TransactionMerkleRoot: block.TxMerkleRoot,
				TstampSecs:            block.Timestamp,
				Height:                block.Height,
				Nonce:                 block.Nonce,
				ExtraNonce:            block.ExtraNonce,
			},
			Status: block.Status,
		}
	}

	// Setup parent pointers
	for _, blockNode := range blockMap {
		// Genesis block has nil parent
		parentHash := blockNode.Header.PrevBlockHash
		if parentHash != nil {
			blockNode.Parent = blockMap[*parentHash]
		}
	}

	return blockMap, nil
}

// GetChain returns the current chain by name. Postgres only supports MAIN_CHAIN for now but will eventually
// support multiple chains. A chain is defined by its Name and TipHash.
func (postgres *Postgres) GetChain(name string) *PGChain {
	chain := &PGChain{
		Name: name,
	}

	err := postgres.db.NewSelect().Model(chain).Limit(1).Scan(postgres.ctx)
	if err != nil {
		return nil
	}

	return chain
}

func (postgres *Postgres) UpsertChain(name string, tipHash *BlockHash) error {
	return postgres.db.RunInTx(postgres.ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		return postgres.UpsertChainTx(tx, name, tipHash)
	})
}

func (postgres *Postgres) UpsertChainTx(tx bun.Tx, name string, tipHash *BlockHash) error {
	bestChain := &PGChain{
		TipHash: tipHash,
		Name:    name,
	}

	_, err := tx.NewInsert().Model(bestChain).On("DUPLICATE KEY UPDATE").Exec(postgres.ctx)
	return err
}

// InsertTransactionsTx inserts all the transactions from a block in a bulk query
func (postgres *Postgres) InsertTransactionsTx(tx bun.Tx, desoTxns []*MsgDeSoTxn, blockNode *BlockNode) error {
	var transactions []*PGTransaction
	var transactionOutputs []*PGTransactionOutput
	var transactionInputs []*PGTransactionOutput

	var metadataBlockRewards []*PGMetadataBlockReward
	var metadataBitcoinExchanges []*PGMetadataBitcoinExchange
	var metadataPrivateMessages []*PGMetadataPrivateMessage
	var metadataSubmitPosts []*PGMetadataSubmitPost
	var metadataUpdateProfiles []*PGMetadataUpdateProfile
	var metadataExchangeRates []*PGMetadataUpdateExchangeRate
	var metadataFollows []*PGMetadataFollow
	var metadataLikes []*PGMetadataLike
	var metadataCreatorCoins []*PGMetadataCreatorCoin
	var metadataSwapIdentities []*PGMetadataSwapIdentity
	var metadataCreatorCoinTransfers []*PGMetadataCreatorCoinTransfer
	var metadataCreateNFTs []*PGMetadataCreateNFT
	var metadataUpdateNFTs []*PGMetadataUpdateNFT
	var metadataAcceptNFTBids []*PGMetadataAcceptNFTBid
	var metadataBidInputs []*PGMetadataBidInput
	var metadataNFTBids []*PGMetadataNFTBid
	var metadataNFTTransfer []*PGMetadataNFTTransfer
	var metadataAcceptNFTTransfer []*PGMetadataAcceptNFTTransfer
	var metadataBurnNFT []*PGMetadataBurnNFT
	var metadataDerivedKey []*PGMetadataDerivedKey

	blockHash := blockNode.Hash

	// Iterate over all the transactions and build the arrays of data to insert
	for _, txn := range desoTxns {
		txnHash := txn.Hash()
		transaction := &PGTransaction{
			Hash:      txnHash,
			BlockHash: blockHash,
			Type:      txn.TxnMeta.GetTxnType(),
			PublicKey: txn.PublicKey,
			ExtraData: txn.ExtraData,
		}

		if txn.Signature != nil {
			transaction.R = BigintToHash(txn.Signature.R)
			transaction.S = BigintToHash(txn.Signature.S)
		}

		transactions = append(transactions, transaction)

		for ii, input := range txn.TxInputs {
			transactionInputs = append(transactionInputs, &PGTransactionOutput{
				OutputHash:  &input.TxID,
				OutputIndex: input.Index,
				Height:      blockNode.Height,
				InputHash:   txnHash,
				InputIndex:  uint32(ii),
				Spent:       true,
			})
		}

		for ii, output := range txn.TxOutputs {
			transactionOutputs = append(transactionOutputs, &PGTransactionOutput{
				OutputHash:  txnHash,
				OutputIndex: uint32(ii),
				OutputType:  0, // TODO
				PublicKey:   output.PublicKey,
				AmountNanos: output.AmountNanos,
			})
		}

		if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward {
			txMeta := txn.TxnMeta.(*BlockRewardMetadataa)
			metadataBlockRewards = append(metadataBlockRewards, &PGMetadataBlockReward{
				TransactionHash: txnHash,
				ExtraData:       txMeta.ExtraData,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeBasicTransfer {
			// No extra metadata needed
		} else if txn.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
			txMeta := txn.TxnMeta.(*BitcoinExchangeMetadata)
			metadataBitcoinExchanges = append(metadataBitcoinExchanges, &PGMetadataBitcoinExchange{
				TransactionHash:   txnHash,
				BitcoinBlockHash:  txMeta.BitcoinBlockHash,
				BitcoinMerkleRoot: txMeta.BitcoinMerkleRoot,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypePrivateMessage {
			txMeta := txn.TxnMeta.(*PrivateMessageMetadata)
			metadataPrivateMessages = append(metadataPrivateMessages, &PGMetadataPrivateMessage{
				TransactionHash:    txnHash,
				RecipientPublicKey: txMeta.RecipientPublicKey,
				EncryptedText:      txMeta.EncryptedText,
				TimestampNanos:     txMeta.TimestampNanos,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeSubmitPost {
			txMeta := txn.TxnMeta.(*SubmitPostMetadata)

			postHashToModify := &BlockHash{}
			parentStakeId := &BlockHash{}
			copy(postHashToModify[:], txMeta.PostHashToModify)
			copy(parentStakeId[:], txMeta.ParentStakeID)

			metadataSubmitPosts = append(metadataSubmitPosts, &PGMetadataSubmitPost{
				TransactionHash:  txnHash,
				PostHashToModify: postHashToModify,
				ParentStakeID:    parentStakeId,
				Body:             string(txMeta.Body),
				TimestampNanos:   txMeta.TimestampNanos,
				IsHidden:         txMeta.IsHidden,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateProfile {
			txMeta := txn.TxnMeta.(*UpdateProfileMetadata)
			metadataUpdateProfiles = append(metadataUpdateProfiles, &PGMetadataUpdateProfile{
				TransactionHash:  txnHash,
				ProfilePublicKey: txMeta.ProfilePublicKey,
				NewUsername:      txMeta.NewUsername,
				//NewProfilePic:         txMeta.NewProfilePic,
				NewCreatorBasisPoints: txMeta.NewCreatorBasisPoints,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateBitcoinUSDExchangeRate {
			txMeta := txn.TxnMeta.(*UpdateBitcoinUSDExchangeRateMetadataa)
			metadataExchangeRates = append(metadataExchangeRates, &PGMetadataUpdateExchangeRate{
				TransactionHash:    txnHash,
				USDCentsPerBitcoin: txMeta.USDCentsPerBitcoin,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeFollow {
			txMeta := txn.TxnMeta.(*FollowMetadata)
			metadataFollows = append(metadataFollows, &PGMetadataFollow{
				TransactionHash:   txnHash,
				FollowedPublicKey: txMeta.FollowedPublicKey,
				IsUnfollow:        txMeta.IsUnfollow,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeLike {
			txMeta := txn.TxnMeta.(*LikeMetadata)
			metadataLikes = append(metadataLikes, &PGMetadataLike{
				TransactionHash: txnHash,
				LikedPostHash:   txMeta.LikedPostHash,
				IsUnlike:        txMeta.IsUnlike,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoin {
			txMeta := txn.TxnMeta.(*CreatorCoinMetadataa)
			metadataCreatorCoins = append(metadataCreatorCoins, &PGMetadataCreatorCoin{
				TransactionHash:             txnHash,
				ProfilePublicKey:            txMeta.ProfilePublicKey,
				OperationType:               txMeta.OperationType,
				DESOToSellNanos:             txMeta.DeSoToSellNanos,
				CreatorCoinToSellNanos:      txMeta.CreatorCoinToSellNanos,
				DESOToAddNanos:              txMeta.DeSoToAddNanos,
				MinDESOExpectedNanos:        txMeta.MinDeSoExpectedNanos,
				MinCreatorCoinExpectedNanos: txMeta.MinCreatorCoinExpectedNanos,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeSwapIdentity {
			txMeta := txn.TxnMeta.(*SwapIdentityMetadataa)
			metadataSwapIdentities = append(metadataSwapIdentities, &PGMetadataSwapIdentity{
				TransactionHash: txnHash,
				FromPublicKey:   txMeta.FromPublicKey,
				ToPublicKey:     txMeta.ToPublicKey,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateGlobalParams {
			// No extra metadata needed, it's all in ExtraData
		} else if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoinTransfer {
			txMeta := txn.TxnMeta.(*CreatorCoinTransferMetadataa)
			metadataCreatorCoinTransfers = append(metadataCreatorCoinTransfers, &PGMetadataCreatorCoinTransfer{
				TransactionHash:            txnHash,
				ProfilePublicKey:           txMeta.ProfilePublicKey,
				CreatorCoinToTransferNanos: txMeta.CreatorCoinToTransferNanos,
				ReceiverPublicKey:          txMeta.ReceiverPublicKey,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeCreateNFT {
			txMeta := txn.TxnMeta.(*CreateNFTMetadata)
			metadataCreateNFTs = append(metadataCreateNFTs, &PGMetadataCreateNFT{
				TransactionHash:           txnHash,
				NFTPostHash:               txMeta.NFTPostHash,
				NumCopies:                 txMeta.NumCopies,
				HasUnlockable:             txMeta.HasUnlockable,
				IsForSale:                 txMeta.IsForSale,
				MinBidAmountNanos:         txMeta.MinBidAmountNanos,
				CreatorRoyaltyBasisPoints: txMeta.NFTRoyaltyToCreatorBasisPoints,
				CoinRoyaltyBasisPoints:    txMeta.NFTRoyaltyToCoinBasisPoints,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateNFT {
			txMeta := txn.TxnMeta.(*UpdateNFTMetadata)
			metadataUpdateNFTs = append(metadataUpdateNFTs, &PGMetadataUpdateNFT{
				TransactionHash:   txnHash,
				NFTPostHash:       txMeta.NFTPostHash,
				SerialNumber:      txMeta.SerialNumber,
				IsForSale:         txMeta.IsForSale,
				MinBidAmountNanos: txMeta.MinBidAmountNanos,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeAcceptNFTBid {
			txMeta := txn.TxnMeta.(*AcceptNFTBidMetadata)
			metadataAcceptNFTBids = append(metadataAcceptNFTBids, &PGMetadataAcceptNFTBid{
				TransactionHash: txnHash,
				NFTPostHash:     txMeta.NFTPostHash,
				SerialNumber:    txMeta.SerialNumber,
				BidderPKID:      txMeta.BidderPKID,
				BidAmountNanos:  txMeta.BidAmountNanos,
				UnlockableText:  txMeta.UnlockableText,
			})

			for _, input := range txMeta.BidderInputs {
				metadataBidInputs = append(metadataBidInputs, &PGMetadataBidInput{
					TransactionHash: txnHash,
					InputHash:       input.TxID.NewBlockHash(),
					InputIndex:      input.Index,
				})
			}
		} else if txn.TxnMeta.GetTxnType() == TxnTypeNFTBid {
			txMeta := txn.TxnMeta.(*NFTBidMetadata)
			metadataNFTBids = append(metadataNFTBids, &PGMetadataNFTBid{
				TransactionHash: txnHash,
				NFTPostHash:     txMeta.NFTPostHash,
				SerialNumber:    txMeta.SerialNumber,
				BidAmountNanos:  txMeta.BidAmountNanos,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeNFTTransfer {
			txMeta := txn.TxnMeta.(*NFTTransferMetadata)
			metadataNFTTransfer = append(metadataNFTTransfer, &PGMetadataNFTTransfer{
				TransactionHash:   txnHash,
				NFTPostHash:       txMeta.NFTPostHash,
				SerialNumber:      txMeta.SerialNumber,
				ReceiverPublicKey: txMeta.ReceiverPublicKey,
				UnlockableText:    txMeta.UnlockableText,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeAcceptNFTTransfer {
			txMeta := txn.TxnMeta.(*AcceptNFTTransferMetadata)
			metadataAcceptNFTTransfer = append(metadataAcceptNFTTransfer, &PGMetadataAcceptNFTTransfer{
				TransactionHash: txnHash,
				NFTPostHash:     txMeta.NFTPostHash,
				SerialNumber:    txMeta.SerialNumber,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeBurnNFT {
			txMeta := txn.TxnMeta.(*BurnNFTMetadata)
			metadataBurnNFT = append(metadataBurnNFT, &PGMetadataBurnNFT{
				TransactionHash: txnHash,
				NFTPostHash:     txMeta.NFTPostHash,
				SerialNumber:    txMeta.SerialNumber,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeAuthorizeDerivedKey {
			txMeta := txn.TxnMeta.(*AuthorizeDerivedKeyMetadata)
			metadataDerivedKey = append(metadataDerivedKey, &PGMetadataDerivedKey{
				TransactionHash:  txnHash,
				DerivedPublicKey: *NewPublicKey(txMeta.DerivedPublicKey),
				ExpirationBlock:  txMeta.ExpirationBlock,
				OperationType:    txMeta.OperationType,
				AccessSignature:  txMeta.AccessSignature,
			})
		} else {
			return fmt.Errorf("InsertTransactionTx: Unimplemented txn type %v", txn.TxnMeta.GetTxnType().String())
		}
	}

	// Insert the block and all of its data in bulk

	if len(transactions) > 0 {
		if _, err := tx.NewInsert().Model(&transactions).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(transactionOutputs) > 0 {
		if _, err := tx.NewInsert().Model(&transactionOutputs).Returning("NULL").On("DUPLICATE KEY UPDATE").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(transactionInputs) > 0 {
		if _, err := tx.NewUpdate().Model(&transactionInputs).Column("input_hash", "input_index", "spent").Bulk().Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataBlockRewards) > 0 {
		if _, err := tx.NewInsert().Model(&metadataBlockRewards).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataBitcoinExchanges) > 0 {
		if _, err := tx.NewInsert().Model(&metadataBitcoinExchanges).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataPrivateMessages) > 0 {
		if _, err := tx.NewInsert().Model(&metadataPrivateMessages).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataSubmitPosts) > 0 {
		if _, err := tx.NewInsert().Model(&metadataSubmitPosts).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataUpdateProfiles) > 0 {
		if _, err := tx.NewInsert().Model(&metadataUpdateProfiles).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataExchangeRates) > 0 {
		if _, err := tx.NewInsert().Model(&metadataExchangeRates).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataFollows) > 0 {
		if _, err := tx.NewInsert().Model(&metadataFollows).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataLikes) > 0 {
		if _, err := tx.NewInsert().Model(&metadataLikes).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataCreatorCoins) > 0 {
		if _, err := tx.NewInsert().Model(&metadataCreatorCoins).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataSwapIdentities) > 0 {
		if _, err := tx.NewInsert().Model(&metadataSwapIdentities).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataCreatorCoinTransfers) > 0 {
		if _, err := tx.NewInsert().Model(&metadataCreatorCoinTransfers).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataCreateNFTs) > 0 {
		if _, err := tx.NewInsert().Model(&metadataCreateNFTs).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataUpdateNFTs) > 0 {
		if _, err := tx.NewInsert().Model(&metadataUpdateNFTs).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataAcceptNFTBids) > 0 {
		if _, err := tx.NewInsert().Model(&metadataAcceptNFTBids).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataBidInputs) > 0 {
		if _, err := tx.NewInsert().Model(&metadataBidInputs).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataNFTBids) > 0 {
		if _, err := tx.NewInsert().Model(&metadataNFTBids).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataNFTTransfer) > 0 {
		if _, err := tx.NewInsert().Model(&metadataNFTTransfer).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataAcceptNFTTransfer) > 0 {
		if _, err := tx.NewInsert().Model(&metadataAcceptNFTTransfer).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataBurnNFT) > 0 {
		if _, err := tx.NewInsert().Model(&metadataBurnNFT).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	if len(metadataDerivedKey) > 0 {
		if _, err := tx.NewInsert().Model(&metadataDerivedKey).Returning("NULL").Exec(postgres.ctx); err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) UpsertBlockAndTransactions(blockNode *BlockNode, desoBlock *MsgDeSoBlock) error {
	return postgres.db.RunInTx(postgres.ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		err := postgres.UpsertBlockTx(tx, blockNode)
		if err != nil {
			return err
		}

		blockHash := blockNode.Hash
		err = postgres.UpsertChainTx(tx, MAIN_CHAIN, blockHash)
		if err != nil {
			return err
		}

		err = postgres.InsertTransactionsTx(tx, desoBlock.Txns, blockNode)
		if err != nil {
			return err
		}

		return nil
	})
}

//
// BlockView Flushing
//

func (postgres *Postgres) FlushView(view *UtxoView) error {
	return postgres.db.RunInTx(postgres.ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if err := postgres.flushUtxos(tx, view); err != nil {
			return err
		}
		if err := postgres.flushProfiles(tx, view); err != nil {
			return err
		}
		if err := postgres.flushPosts(tx, view); err != nil {
			return err
		}
		if err := postgres.flushLikes(tx, view); err != nil {
			return err
		}
		if err := postgres.flushFollows(tx, view); err != nil {
			return err
		}
		if err := postgres.flushDiamonds(tx, view); err != nil {
			return err
		}
		if err := postgres.flushMessages(tx, view); err != nil {
			return err
		}
		if err := postgres.flushCreatorCoinBalances(tx, view); err != nil {
			return err
		}
		if err := postgres.flushBalances(tx, view); err != nil {
			return err
		}
		if err := postgres.flushForbiddenKeys(tx, view); err != nil {
			return err
		}
		if err := postgres.flushNFTs(tx, view); err != nil {
			return err
		}
		if err := postgres.flushNFTBids(tx, view); err != nil {
			return err
		}
		if err := postgres.flushDerivedKeys(tx, view); err != nil {
			return err
		}

		return nil
	})
}

func (postgres *Postgres) flushUtxos(tx bun.Tx, view *UtxoView) error {
	var outputs []*PGTransactionOutput
	for utxoKeyIter, utxoEntry := range view.UtxoKeyToUtxoEntry {
		// Making a copy of the iterator is required
		utxoKey := utxoKeyIter
		outputs = append(outputs, &PGTransactionOutput{
			OutputHash:  &utxoKey.TxID,
			OutputIndex: utxoKey.Index,
			OutputType:  utxoEntry.UtxoType,
			PublicKey:   utxoEntry.PublicKey,
			AmountNanos: utxoEntry.AmountNanos,
			Spent:       utxoEntry.isSpent,
		})
	}

	_, err := tx.NewInsert().Model(&outputs).On("DUPLICATE KEY UPDATE").Exec(postgres.ctx)
	if err != nil {
		return err
	}

	return nil
}

func (postgres *Postgres) flushProfiles(tx bun.Tx, view *UtxoView) error {
	var insertProfiles []*PGProfile
	var deleteProfiles []*PKID
	for _, pkidEntry := range view.PublicKeyToPKIDEntry {
		pkid := pkidEntry.PKID

		profile := &PGProfile{
			PKID:      pkid,
			PublicKey: NewPublicKey(pkidEntry.PublicKey),
		}

		profileEntry := view.ProfilePKIDToProfileEntry[*pkid]
		if profileEntry != nil {
			profile.Username = string(profileEntry.Username)
			profile.Description = string(profileEntry.Description)
			//profile.ProfilePic = profileEntry.ProfilePic
			profile.CreatorBasisPoints = profileEntry.CreatorBasisPoints
			profile.DESOLockedNanos = profileEntry.DeSoLockedNanos
			profile.NumberOfHolders = profileEntry.NumberOfHolders
			profile.CoinsInCirculationNanos = profileEntry.CoinsInCirculationNanos
			profile.CoinWatermarkNanos = profileEntry.CoinWatermarkNanos
		}

		if pkidEntry.isDeleted {
			deleteProfiles = append(deleteProfiles, profile.PKID)
		} else {
			insertProfiles = append(insertProfiles, profile)
		}
	}

	if len(insertProfiles) > 0 {
		_, err := tx.NewInsert().Model(&insertProfiles).On("DUPLICATE KEY UPDATE").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	if len(deleteProfiles) > 0 {
		_, err := tx.NewDelete().Model((*PGProfile)(nil)).Where("pkid IN (?)", bun.In(deleteProfiles)).Returning("NULL").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushPosts(tx bun.Tx, view *UtxoView) error {
	var insertPosts []*PGPost
	var deletePosts []*PGPost
	for _, postEntry := range view.PostHashToPostEntry {
		if postEntry == nil {
			continue
		}

		post := &PGPost{
			ID:                        postEntry.ID,
			PostHash:                  postEntry.PostHash,
			PosterPublicKey:           postEntry.PosterPublicKey,
			Body:                      string(postEntry.Body),
			RepostedPostHash:          postEntry.RepostedPostHash,
			QuotedRepost:              postEntry.IsQuotedRepost,
			Timestamp:                 postEntry.TimestampNanos,
			Hidden:                    postEntry.IsHidden,
			LikeCount:                 postEntry.LikeCount,
			RepostCount:               postEntry.RepostCount,
			QuoteRepostCount:          postEntry.QuoteRepostCount,
			DiamondCount:              postEntry.DiamondCount,
			CommentCount:              postEntry.CommentCount,
			Pinned:                    postEntry.IsPinned,
			NFT:                       postEntry.IsNFT,
			NumNFTCopies:              postEntry.NumNFTCopies,
			NumNFTCopiesForSale:       postEntry.NumNFTCopiesForSale,
			NumNFTCopiesBurned:        postEntry.NumNFTCopiesBurned,
			Unlockable:                postEntry.HasUnlockable,
			CreatorRoyaltyBasisPoints: postEntry.NFTRoyaltyToCreatorBasisPoints,
			CoinRoyaltyBasisPoints:    postEntry.NFTRoyaltyToCoinBasisPoints,
			ExtraData:                 postEntry.PostExtraData,
		}

		if len(postEntry.ParentStakeID) > 0 {
			post.ParentPostHash = NewBlockHash(postEntry.ParentStakeID)
		}

		if postEntry.isDeleted {
			deletePosts = append(deletePosts, post)
		} else {
			insertPosts = append(insertPosts, post)
		}
	}

	if len(insertPosts) > 0 {
		_, err := tx.NewInsert().Model(&insertPosts).On("DUPLICATE KEY UPDATE").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	if len(deletePosts) > 0 {
		_, err := tx.NewDelete().Model(&deletePosts).WherePK().Returning("NULL").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushLikes(tx bun.Tx, view *UtxoView) error {
	var insertLikes []*PGLike
	var deleteLikes []*PGLike
	for _, likeEntry := range view.LikeKeyToLikeEntry {
		if likeEntry == nil {
			continue
		}

		like := &PGLike{
			ID:             likeEntry.ID,
			LikerPublicKey: likeEntry.LikerPubKey,
			LikedPostHash:  likeEntry.LikedPostHash,
		}

		if likeEntry.isDeleted {
			deleteLikes = append(deleteLikes, like)
		} else {
			insertLikes = append(insertLikes, like)
		}
	}

	if len(insertLikes) > 0 {
		// No-op update
		_, err := tx.NewInsert().Model(&insertLikes).On("DUPLICATE KEY UPDATE liker_public_key=liker_public_key").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	if len(deleteLikes) > 0 {
		_, err := tx.NewDelete().Model(&deleteLikes).WherePK().Returning("NULL").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushFollows(tx bun.Tx, view *UtxoView) error {
	var insertFollows []*PGFollow
	var deleteFollows []*PGFollow
	for _, followEntry := range view.FollowKeyToFollowEntry {
		if followEntry == nil {
			continue
		}

		follow := &PGFollow{
			ID:           followEntry.ID,
			FollowerPKID: followEntry.FollowerPKID,
			FollowedPKID: followEntry.FollowedPKID,
		}

		if followEntry.isDeleted {
			deleteFollows = append(deleteFollows, follow)
		} else {
			insertFollows = append(insertFollows, follow)
		}
	}

	if len(insertFollows) > 0 {
		// No-op update on duplicate key
		_, err := tx.NewInsert().Model(&insertFollows).Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	if len(deleteFollows) > 0 {
		_, err := tx.NewDelete().Model(&deleteFollows).WherePK().Returning("NULL").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushDiamonds(tx bun.Tx, view *UtxoView) error {
	var insertDiamonds []*PGDiamond
	var deleteDiamonds []*PGDiamond
	for _, diamondEntry := range view.DiamondKeyToDiamondEntry {
		diamond := &PGDiamond{
			ID:              diamondEntry.ID,
			SenderPKID:      diamondEntry.SenderPKID,
			ReceiverPKID:    diamondEntry.ReceiverPKID,
			DiamondPostHash: diamondEntry.DiamondPostHash,
			DiamondLevel:    uint8(diamondEntry.DiamondLevel),
		}

		if diamondEntry.isDeleted {
			deleteDiamonds = append(deleteDiamonds, diamond)
		} else {
			insertDiamonds = append(insertDiamonds, diamond)
		}
	}

	if len(insertDiamonds) > 0 {
		_, err := tx.NewInsert().Model(&insertDiamonds).On("DUPLICATE KEY UPDATE").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	if len(deleteDiamonds) > 0 {
		_, err := tx.NewDelete().Model(&deleteDiamonds).WherePK().Returning("NULL").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushMessages(tx bun.Tx, view *UtxoView) error {
	var insertMessages []*PGMessage
	var deleteMessages []*PGMessage
	for _, message := range view.MessageMap {
		if message.isDeleted {
			deleteMessages = append(deleteMessages, message)
		} else {
			insertMessages = append(insertMessages, message)
		}
	}

	if len(insertMessages) > 0 {
		// TODO: There should never be a conflict here. Should we raise an error?
		_, err := tx.NewInsert().Model(&insertMessages).On("DUPLICATE KEY UPDATE").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	if len(deleteMessages) > 0 {
		_, err := tx.NewDelete().Model(&deleteMessages).WherePK().Returning("NULL").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushCreatorCoinBalances(tx bun.Tx, view *UtxoView) error {
	var insertBalances []*PGCreatorCoinBalance
	var deleteBalances []*PGCreatorCoinBalance
	for _, balanceEntry := range view.HODLerPKIDCreatorPKIDToBalanceEntry {
		if balanceEntry == nil {
			continue
		}

		balance := &PGCreatorCoinBalance{
			ID:           balanceEntry.ID,
			HolderPKID:   balanceEntry.HODLerPKID,
			CreatorPKID:  balanceEntry.CreatorPKID,
			BalanceNanos: balanceEntry.BalanceNanos,
			HasPurchased: balanceEntry.HasPurchased,
		}

		if balanceEntry.isDeleted {
			deleteBalances = append(deleteBalances, balance)
		} else {
			insertBalances = append(insertBalances, balance)
		}
	}

	if len(insertBalances) > 0 {
		_, err := tx.NewInsert().Model(&insertBalances).On("DUPLICATE KEY UPDATE").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	if len(deleteBalances) > 0 {
		_, err := tx.NewDelete().Model(&deleteBalances).WherePK().Returning("NULL").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushBalances(tx bun.Tx, view *UtxoView) error {
	var balances []*PGBalance
	for pubKeyIter, balanceNanos := range view.PublicKeyToDeSoBalanceNanos {
		// Make a copy of the iterator since it might change from under us.
		pubKey := pubKeyIter[:]

		balance := &PGBalance{
			PublicKey:    NewPublicKey(pubKey),
			BalanceNanos: balanceNanos,
		}

		balances = append(balances, balance)
	}

	if len(balances) > 0 {
		_, err := tx.NewInsert().Model(&balances).On("DUPLICATE KEY UPDATE").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushForbiddenKeys(tx bun.Tx, view *UtxoView) error {
	var insertKeys []*PGForbiddenKey
	var deleteKeys []*PGForbiddenKey
	for _, keyEntry := range view.ForbiddenPubKeyToForbiddenPubKeyEntry {
		balance := &PGForbiddenKey{
			ID:        keyEntry.ID,
			PublicKey: NewPublicKey(keyEntry.PubKey),
		}

		if keyEntry.isDeleted {
			deleteKeys = append(deleteKeys, balance)
		} else {
			insertKeys = append(insertKeys, balance)
		}
	}

	if len(insertKeys) > 0 {
		_, err := tx.NewInsert().Model(&insertKeys).On("DUPLICATE KEY UPDATE").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	if len(deleteKeys) > 0 {
		_, err := tx.NewDelete().Model(&deleteKeys).WherePK().Returning("NULL").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushNFTs(tx bun.Tx, view *UtxoView) error {
	var insertNFTs []*PGNFT
	var deleteNFTs []*PGNFT
	for _, nftEntry := range view.NFTKeyToNFTEntry {
		nft := &PGNFT{
			ID:                         nftEntry.ID,
			NFTPostHash:                nftEntry.NFTPostHash,
			SerialNumber:               nftEntry.SerialNumber,
			LastOwnerPKID:              nftEntry.LastOwnerPKID,
			OwnerPKID:                  nftEntry.OwnerPKID,
			ForSale:                    nftEntry.IsForSale,
			MinBidAmountNanos:          nftEntry.MinBidAmountNanos,
			UnlockableText:             string(nftEntry.UnlockableText),
			LastAcceptedBidAmountNanos: nftEntry.LastAcceptedBidAmountNanos,
			IsPending:                  nftEntry.IsPending,
		}

		if nftEntry.isDeleted {
			deleteNFTs = append(deleteNFTs, nft)
		} else {
			insertNFTs = append(insertNFTs, nft)
		}
	}

	if len(insertNFTs) > 0 {
		_, err := tx.NewInsert().Model(&insertNFTs).On("DUPLICATE KEY UPDATE").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	if len(deleteNFTs) > 0 {
		_, err := tx.NewDelete().Model(&deleteNFTs).WherePK().Returning("NULL").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushNFTBids(tx bun.Tx, view *UtxoView) error {
	var insertBids []*PGNFTBid
	var deleteBids []*PGNFTBid
	for _, bidEntry := range view.NFTBidKeyToNFTBidEntry {
		nft := &PGNFTBid{
			ID:             bidEntry.ID,
			BidderPKID:     bidEntry.BidderPKID,
			NFTPostHash:    bidEntry.NFTPostHash,
			SerialNumber:   bidEntry.SerialNumber,
			BidAmountNanos: bidEntry.BidAmountNanos,
			// TODO: Change how accepted bid logic works in consensus
			Accepted: false,
		}

		if bidEntry.isDeleted {
			deleteBids = append(deleteBids, nft)
		} else {
			insertBids = append(insertBids, nft)
		}
	}

	if len(insertBids) > 0 {
		_, err := tx.NewInsert().Model(&insertBids).On("DUPLICATE KEY UPDATE").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	if len(deleteBids) > 0 {
		_, err := tx.NewDelete().Model(&deleteBids).WherePK().Returning("NULL").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushDerivedKeys(tx bun.Tx, view *UtxoView) error {
	var insertKeys []*PGDerivedKey
	var deleteKeys []*PGDerivedKey
	for _, keyEntry := range view.DerivedKeyToDerivedEntry {
		key := &PGDerivedKey{
			ID:               keyEntry.ID,
			OwnerPublicKey:   keyEntry.OwnerPublicKey,
			DerivedPublicKey: keyEntry.DerivedPublicKey,
			ExpirationBlock:  keyEntry.ExpirationBlock,
			OperationType:    keyEntry.OperationType,
		}

		if keyEntry.isDeleted {
			deleteKeys = append(deleteKeys, key)
		} else {
			insertKeys = append(insertKeys, key)
		}
	}

	if len(insertKeys) > 0 {
		_, err := tx.NewInsert().Model(&insertKeys).On("DUPLICATE KEY UPDATE").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	if len(deleteKeys) > 0 {
		_, err := tx.NewDelete().Model(&deleteKeys).WherePK().Returning("NULL").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

//
// UTXOS
//

func (postgres *Postgres) GetUtxoEntryForUtxoKey(utxoKey *UtxoKey) *UtxoEntry {
	utxo := &PGTransactionOutput{}

	err := postgres.db.NewSelect().Model(utxo).Where("output_hash = ?", &utxoKey.TxID).
		Where("output_index = ?", utxoKey.Index).Where("spent = ?", false).Scan(postgres.ctx)
	if err != nil {
		return nil
	}

	return utxo.NewUtxoEntry()
}

func (postgres *Postgres) GetUtxoEntriesForPublicKey(publicKey []byte) []*UtxoEntry {
	var transactionOutputs []*PGTransactionOutput
	err := postgres.db.NewSelect().Model(&transactionOutputs).Where("public_key = ?", publicKey).Scan(postgres.ctx)
	if err != nil {
		return nil
	}

	var utxoEntries []*UtxoEntry
	for _, utxo := range transactionOutputs {
		utxoEntries = append(utxoEntries, utxo.NewUtxoEntry())
	}

	return utxoEntries
}

func (postgres *Postgres) GetOutputs(outputs []*PGTransactionOutput) []*PGTransactionOutput {
	err := postgres.db.NewSelect().Model(&outputs).Where(postgres.whereColumns(outputs, "OutputHash", "OutputIndex", "Spent")).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return outputs
}

func (postgres *Postgres) whereColumns(slice interface{}, columns ...string) string {
	query := []byte("(")

	vals := reflect.ValueOf(slice)
	numVals := vals.Len()

	numColumns := len(columns)
	for ii, column := range columns {
		query = append(query, Underscore(column)...)

		if ii != numColumns-1 {
			query = append(query, ',')
		}
	}

	query = append(query, ") IN ("...)

	for ii := 0; ii < numVals; ii++ {
		query = append(query, '(')

		for jj, column := range columns {
			val := vals.Index(ii).Elem().FieldByName(column)
			query = postgres.db.Formatter().AppendValue(query, val)
			if jj != numColumns-1 {
				query = append(query, ',')
			}
		}

		query = append(query, ')')

		if ii != numVals-1 {
			query = append(query, ',')
		}
	}

	query = append(query, ')')

	//glog.Info(string(query))

	return string(query)
}

func Underscore(s string) string {
	r := make([]byte, 0, len(s)+5)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if IsUpper(c) {
			if i > 0 && i+1 < len(s) && (IsLower(s[i-1]) || IsLower(s[i+1])) {
				r = append(r, '_', ToLower(c))
			} else {
				r = append(r, ToLower(c))
			}
		} else {
			r = append(r, c)
		}
	}
	return string(r)
}

func IsUpper(c byte) bool {
	return c >= 'A' && c <= 'Z'
}

func IsLower(c byte) bool {
	return c >= 'a' && c <= 'z'
}

func ToLower(c byte) byte {
	return c + 32
}
func (postgres *Postgres) GetBlockRewardsForPublicKey(publicKey *PublicKey, startHeight uint32, endHeight uint32) []*PGTransactionOutput {
	var transactionOutputs []*PGTransactionOutput
	err := postgres.db.NewSelect().Model(&transactionOutputs).Where("public_key = ?", publicKey).
		Where("height >= ?", startHeight).Where("height <= ?", endHeight).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return transactionOutputs
}

//
// Profiles
//

func (postgres *Postgres) GetProfileForUsername(nonLowercaseUsername string) *PGProfile {
	var profile PGProfile
	err := postgres.db.NewSelect().Model(&profile).
		Where("LOWER(username) = ?", strings.ToLower(nonLowercaseUsername)).Limit(1).Scan(postgres.ctx)
	if err != nil {
		LogError(err)
		return nil
	}
	return &profile
}

func (postgres *Postgres) GetProfileForPublicKey(publicKey []byte) *PGProfile {
	var profile PGProfile
	err := postgres.db.NewSelect().Model(&profile).Where("public_key = ?", publicKey).Limit(1).Scan(postgres.ctx)
	if err != nil {
		LogError(err)
		return nil
	}
	return &profile
}

func (postgres *Postgres) GetProfile(pkid *PKID) *PGProfile {
	var profile PGProfile
	err := postgres.db.NewSelect().Model(&profile).Where("pkid = ?", pkid).Limit(1).Scan(postgres.ctx)
	if err != nil {
		LogError(err)
		return nil
	}
	return &profile
}

func (postgres *Postgres) GetProfilesForPublicKeys(publicKeys []*PublicKey) []*PGProfile {
	var profiles []*PGProfile
	err := postgres.db.NewSelect().Model(&profiles).Where("public_key IN (?)", bun.In(publicKeys)).Scan(postgres.ctx)
	if err != nil {
		LogError(err)
		return nil
	}
	return profiles
}

func (postgres *Postgres) GetProfilesByCoinValue(startLockedNanos uint64, limit int) []*PGProfile {
	var profiles []*PGProfile
	err := postgres.db.NewSelect().Model(&profiles).Where("deso_locked_nanos < ?", startLockedNanos).
		OrderExpr("deso_locked_nanos DESC").Limit(limit).Scan(postgres.ctx)
	if err != nil {
		LogError(err)
		return nil
	}
	return profiles
}

func (postgres *Postgres) GetProfilesForUsernamePrefixByCoinValue(usernamePrefix string, limit int) []*PGProfile {
	var profiles []*PGProfile
	err := postgres.db.NewSelect().Model(&profiles).Where("username ILIKE ?", fmt.Sprintf("%s%%", usernamePrefix)).
		Where("deso_locked_nanos >= 0").OrderExpr("deso_locked_nanos DESC").Limit(limit).Scan(postgres.ctx)
	if err != nil {
		LogError(err)
		return nil
	}
	return profiles
}

func (postgres *Postgres) GetProfilesForUsername(usernames []string) []*PGProfile {
	var profiles []*PGProfile
	err := postgres.db.NewSelect().Model(&profiles).Where("LOWER(username) IN (?)", bun.In(usernames)).Scan(postgres.ctx)
	if err != nil {
		LogError(err)
		return nil
	}
	return profiles
}

//
// Posts
//

func (postgres *Postgres) GetPost(postHash *BlockHash) *PGPost {
	var post PGPost
	err := postgres.db.NewSelect().Model(&post).Where("post_hash = ?", postHash).Limit(1).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return &post
}

func (postgres *Postgres) GetPosts(posts []*PGPost) []*PGPost {
	err := postgres.db.NewSelect().Model(&posts).Where(postgres.whereColumns(posts, "PostHash")).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return posts
}

func (postgres *Postgres) GetPostsForPublicKey(publicKey []byte, startTime uint64, limit uint64) []*PGPost {
	var posts []*PGPost
	err := postgres.db.NewSelect().Model(&posts).
		Where("poster_public_key = ?", publicKey).Where("timestamp < ?", startTime).
		Where("hidden IS NULL").Where("parent_post_hash IS NULL").
		OrderExpr("timestamp DESC").Limit(int(limit)).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return posts
}

//
// Comments
//

// TODO: Pagination
func (postgres *Postgres) GetComments(parentPostHash *BlockHash) []*PGPost {
	var posts []*PGPost
	err := postgres.db.NewSelect().Model(&posts).Where("parent_post_hash = ?", parentPostHash).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return posts
}

func (postgres *Postgres) GetMessage(messageHash *BlockHash) *PGMessage {
	var message PGMessage
	err := postgres.db.NewSelect().Model(&message).Where("message_hash = ?", messageHash).Limit(1).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return &message
}

//
// LIKES
//

func (postgres *Postgres) GetLike(likerPublicKey []byte, likedPostHash *BlockHash) *PGLike {
	like := PGLike{}
	err := postgres.db.NewSelect().Model(&like).Where("liker_public_key = ?", likerPublicKey).
		Where("liked_post_hash = ?", likedPostHash).Limit(1).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return &like
}

func (postgres *Postgres) GetLikes(likes []*PGLike) []*PGLike {
	err := postgres.db.NewSelect().Model(&likes).Where(postgres.whereColumns(likes, "LikerPublicKey", "LikedPostHash")).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return likes
}

func (postgres *Postgres) GetLikesForPost(postHash *BlockHash) []*PGLike {
	var likes []*PGLike
	err := postgres.db.NewSelect().Model(&likes).Where("liked_post_hash = ?", postHash).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return likes
}

//
// Follows
//

func (postgres *Postgres) GetFollow(followerPkid *PKID, followedPkid *PKID) *PGFollow {
	follow := PGFollow{}
	err := postgres.db.NewSelect().Model(&follow).Where("follower_pkid = ?", followerPkid).
		Where("followed_pkid = ?", followedPkid).Limit(1).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return &follow
}

func (postgres *Postgres) GetFollows(follows []*PGFollow) []*PGFollow {
	err := postgres.db.NewSelect().Model(&follows).Where(postgres.whereColumns(follows, "FollowerPKID", "FollowedPKID")).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return follows
}

func (postgres *Postgres) GetFollowing(pkid *PKID) []*PGFollow {
	var follows []*PGFollow
	err := postgres.db.NewSelect().Model(&follows).Where("follower_pkid = ?", pkid).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return follows
}

func (postgres *Postgres) GetFollowers(pkid *PKID) []*PGFollow {
	var follows []*PGFollow
	err := postgres.db.NewSelect().Model(&follows).Where("followed_pkid = ?", pkid).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return follows
}

func (postgres *Postgres) GetDiamond(senderPkid *PKID, receiverPkid *PKID, postHash *BlockHash) *PGDiamond {
	diamond := PGDiamond{}
	err := postgres.db.NewSelect().Model(&diamond).Where("sender_pkid = ?", senderPkid).
		Where("receiver_pkid = ?", receiverPkid).Where("diamond_post_hash = ?", postHash).Limit(1).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return &diamond
}

//
// Creator Coins
//

func (postgres *Postgres) GetCreatorCoinBalances(balances []*PGCreatorCoinBalance) []*PGCreatorCoinBalance {
	err := postgres.db.NewSelect().Model(&balances).Where(postgres.whereColumns(balances, "HolderPKID", "CreatorPKID")).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return balances
}

func (postgres *Postgres) GetCreatorCoinBalance(holderPkid *PKID, creatorPkid *PKID) *PGCreatorCoinBalance {
	balance := PGCreatorCoinBalance{}
	err := postgres.db.NewSelect().Model(&balance).Where("holder_pkid = ?", holderPkid).
		Where("creator_pkid = ?", creatorPkid).Limit(1).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return &balance
}

func (postgres *Postgres) GetHoldings(pkid *PKID) []*PGCreatorCoinBalance {
	var holdings []*PGCreatorCoinBalance
	err := postgres.db.NewSelect().Model(&holdings).Where("holder_pkid = ?", pkid).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return holdings
}

func (postgres *Postgres) GetHolders(pkid *PKID) []*PGCreatorCoinBalance {
	var holdings []*PGCreatorCoinBalance
	err := postgres.db.NewSelect().Model(&holdings).Where("creator_pkid = ?", pkid).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return holdings
}

//
// NFTS
//

func (postgres *Postgres) GetNFT(nftPostHash *BlockHash, serialNumber uint64) *PGNFT {
	nft := PGNFT{}
	err := postgres.db.NewSelect().Model(&nft).Where("nft_post_hash = ?", nftPostHash).
		Where("serial_number = ?", serialNumber).Limit(1).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return &nft
}

func (postgres *Postgres) GetNFTsForPostHash(nftPostHash *BlockHash) []*PGNFT {
	var nfts []*PGNFT
	err := postgres.db.NewSelect().Model(&nfts).Where("nft_post_hash = ?", nftPostHash).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return nfts
}

func (postgres *Postgres) GetNFTsForPKID(pkid *PKID) []*PGNFT {
	var nfts []*PGNFT
	err := postgres.db.NewSelect().Model(&nfts).Where("owner_pkid = ?", pkid).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return nfts
}

func (postgres *Postgres) GetNFTBidsForPKID(pkid *PKID) []*PGNFTBid {
	var nftBids []*PGNFTBid
	err := postgres.db.NewSelect().Model(&nftBids).Where("bidder_pkid = ?", pkid).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return nftBids
}

func (postgres *Postgres) GetNFTBidsForSerial(nftPostHash *BlockHash, serialNumber uint64) []*PGNFTBid {
	var nftBids []*PGNFTBid
	err := postgres.db.NewSelect().Model(&nftBids).Where("nft_post_hash = ?", nftPostHash).
		Where("serial_number = ?", serialNumber).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return nftBids
}

func (postgres *Postgres) GetNFTBid(nftPostHash *BlockHash, bidderPKID *PKID, serialNumber uint64) *PGNFTBid {
	bid := PGNFTBid{}
	err := postgres.db.NewSelect().Model(&bid).Where("nft_post_hash = ?", nftPostHash).Where("bidder_pkid = ?", bidderPKID).
		Where("serial_number = ?", serialNumber).Limit(1).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return &bid
}

//
// Derived Keys
//

func (postgres *Postgres) GetDerivedKey(ownerPublicKey *PublicKey, derivedPublicKey *PublicKey) *PGDerivedKey {
	key := PGDerivedKey{}
	err := postgres.db.NewSelect().Model(&key).Where("owner_public_key = ?", ownerPublicKey).
		Where("derived_public_key = ?", derivedPublicKey).Limit(1).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return &key
}

func (postgres *Postgres) GetAllDerivedKeysForOwner(ownerPublicKey *PublicKey) []*PGDerivedKey {
	var keys []*PGDerivedKey
	err := postgres.db.NewSelect().Model(&keys).Where("owner_public_key = ?", *ownerPublicKey).Scan(postgres.ctx)
	if err != nil {
		return nil
	}
	return keys
}

//
// Balances
//

func (postgres *Postgres) GetBalance(publicKey *PublicKey) uint64 {
	balance := PGBalance{}
	err := postgres.db.NewSelect().Model(&balance).Where("public_key = ?", publicKey).Limit(1).Scan(postgres.ctx)
	if err != nil {
		return 0
	}
	return balance.BalanceNanos
}

//
// PGChain Init
//

func (postgres *Postgres) InitGenesisBlock(params *DeSoParams, db *badger.DB) error {
	// Construct a node for the genesis block. Its height is zero and it has no parents. Its difficulty should be
	// set to the initial difficulty specified in the parameters and it should be assumed to be
	// valid and stored by the end of this function.
	genesisBlock := params.GenesisBlock
	diffTarget := MustDecodeHexBlockHash(params.MinDifficultyTargetHex)
	blockHash := MustDecodeHexBlockHash(params.GenesisBlockHashHex)
	genesisNode := NewBlockNode(
		nil,
		blockHash,
		0,
		diffTarget,
		BytesToBigint(ExpectedWorkForBlockHash(diffTarget)[:]),
		genesisBlock.Header,
		StatusHeaderValidated|StatusBlockProcessed|StatusBlockStored|StatusBlockValidated,
	)

	// Create the chain
	err := postgres.UpsertChain("main", blockHash)
	if err != nil {
		return fmt.Errorf("InitGenesisBlock: Error upserting chain: %v", err)
	}

	// Set the fields in the db to reflect the current state of our chain.
	//
	// Set the best hash to the genesis block in the db since its the only node
	// we're currently aware of. Set it for both the header chain and the block
	// chain.
	err = postgres.UpsertBlock(genesisNode)
	if err != nil {
		return fmt.Errorf("InitGenesisBlock: Error upserting block: %v", err)
	}

	for index, txOutput := range params.SeedBalances {
		_, err := postgres.db.NewInsert().Model(&PGTransactionOutput{
			OutputHash:  &BlockHash{},
			OutputIndex: uint32(index),
			OutputType:  UtxoTypeOutput,
			AmountNanos: txOutput.AmountNanos,
			PublicKey:   txOutput.PublicKey,
		}).Returning("NULL").Exec(postgres.ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

//
// API
//

func (postgres *Postgres) GetNotifications(publicKey string) ([]*PGNotification, error) {
	keyBytes, _, _ := Base58CheckDecode(publicKey)

	var notifications []*PGNotification
	err := postgres.db.NewSelect().Model(&notifications).Where("to_user = ?", keyBytes).
		Order("timestamp desc").Limit(100).Scan(postgres.ctx)
	if err != nil {
		return nil, err
	}

	return notifications, nil
}
