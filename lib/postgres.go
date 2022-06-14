package lib

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"net/url"
	"regexp"
	"strings"
)

type Postgres struct {
	db *pg.DB
}

func NewPostgres(db *pg.DB) *Postgres {
	// Uncomment to print all queries.
	//db.AddQueryHook(pgdebug.DebugHook{
	//	Verbose: true,
	//})

	return &Postgres{
		db: db,
	}
}

func ParsePostgresURI(pgURI string) *pg.Options {
	// Parse postgres options from a postgres URI string.
	parsedURI, err := url.Parse(pgURI)
	if err != nil {
		return nil
	}

	pgPassword, _ := parsedURI.User.Password()

	return &pg.Options{
		Addr:     parsedURI.Host,
		User:     parsedURI.User.Username(),
		Database: parsedURI.Path[1:], // Skip one char to avoid the starting slash (/).
		Password: pgPassword,
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

const (
	MAIN_CHAIN = "main"
)

//
// Tables
//
// The current schema is the sum of all the migrations in the migrate folder. Eventually we should
// export the current schema as new instances of the chain shouldn't be running every single migration.
//
// For information about the `pg:"..."` annotations, see: https://pg.uptrace.dev/models/
//
// Common annotations include:
// - Custom primary key: `pg:",pk"`
// - Don't store 0 or false as NULL: `pg:",use_zero"`
//
// When we can, we use unique fields (or combinations of unique fields) as the primary keys on the models.
// This lets us use the WherePK() query while also minimizing columns and indicies on disk.
//
// Table names are defined so the relation is obvious even though go-pg can create them for us automatically.
//
// Column names are automatically created by go-pg. For example, a field named TipHash maps to tip_hash.
//

type PGChain struct {
	tableName struct{} `pg:"pg_chains"`

	Name    string     `pg:",pk"`
	TipHash *BlockHash `pg:",type:bytea"`
}

// PGBlock represents BlockNode and MsgDeSoHeader
type PGBlock struct {
	tableName struct{} `pg:"pg_blocks"`

	// BlockNode and MsgDeSoHeader
	Hash       *BlockHash `pg:",pk,type:bytea"`
	ParentHash *BlockHash `pg:",type:bytea"`
	Height     uint64     `pg:",use_zero"`

	// BlockNode
	DifficultyTarget *BlockHash  `pg:",type:bytea"`
	CumWork          *BlockHash  `pg:",type:bytea"`
	Status           BlockStatus `pg:",use_zero"` // TODO: Refactor

	// MsgDeSoHeader
	TxMerkleRoot *BlockHash `pg:",type:bytea"`
	Version      uint32     `pg:",use_zero"`
	Timestamp    uint64     `pg:",use_zero"`
	Nonce        uint64     `pg:",use_zero"`
	ExtraNonce   uint64     `pg:",use_zero"`

	// Notifications
	Notified bool `pg:",use_zero"`
}

// PGTransaction represents MsgDeSoTxn
type PGTransaction struct {
	tableName struct{} `pg:"pg_transactions"`

	Hash      *BlockHash `pg:",pk,type:bytea"`
	BlockHash *BlockHash `pg:",type:bytea"`
	Type      TxnType    `pg:",use_zero"`
	PublicKey []byte     `pg:",type:bytea"`
	ExtraData map[string][]byte
	R         *BlockHash `pg:",type:bytea"`
	S         *BlockHash `pg:",type:bytea"`

	// Relationships
	Outputs                     []*PGTransactionOutput         `pg:"rel:has-many,join_fk:output_hash"`
	MetadataBlockReward         *PGMetadataBlockReward         `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataBitcoinExchange     *PGMetadataBitcoinExchange     `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataPrivateMessage      *PGMetadataPrivateMessage      `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataSubmitPost          *PGMetadataSubmitPost          `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataUpdateExchangeRate  *PGMetadataUpdateExchangeRate  `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataUpdateProfile       *PGMetadataUpdateProfile       `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataFollow              *PGMetadataFollow              `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataLike                *PGMetadataLike                `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataCreatorCoin         *PGMetadataCreatorCoin         `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataCreatorCoinTransfer *PGMetadataCreatorCoinTransfer `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataSwapIdentity        *PGMetadataSwapIdentity        `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataCreateNFT           *PGMetadataCreateNFT           `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataUpdateNFT           *PGMetadataUpdateNFT           `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataAcceptNFTBid        *PGMetadataAcceptNFTBid        `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataNFTBid              *PGMetadataNFTBid              `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataNFTTransfer         *PGMetadataNFTTransfer         `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataAcceptNFTTransfer   *PGMetadataAcceptNFTTransfer   `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataBurnNFT             *PGMetadataBurnNFT             `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataDerivedKey          *PGMetadataDerivedKey          `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataDAOCoin             *PGMetadataDAOCoin             `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataDAOCoinTransfer     *PGMetadataDAOCoinTransfer     `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataDAOCoinLimitOrder   *PGMetadataDAOCoinLimitOrder   `pg:"rel:belongs-to,join_fk:transaction_hash"`
}

// PGTransactionOutput represents DeSoOutput, DeSoInput, and UtxoEntry
type PGTransactionOutput struct {
	tableName struct{} `pg:"pg_transaction_outputs"`

	OutputHash  *BlockHash `pg:",pk"`
	OutputIndex uint32     `pg:",pk,use_zero"`
	OutputType  UtxoType   `pg:",use_zero"`
	Height      uint32     `pg:",use_zero"`
	PublicKey   []byte
	AmountNanos uint64 `pg:",use_zero"`
	Spent       bool   `pg:",use_zero"`
	InputHash   *BlockHash
	InputIndex  uint32 `pg:",pk,use_zero"`
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
	tableName struct{} `pg:"pg_metadata_block_rewards"`

	TransactionHash *BlockHash `pg:",pk,type:bytea"`
	ExtraData       []byte     `pg:",type:bytea"`
}

// PGMetadataBitcoinExchange represents BitcoinExchangeMetadata
type PGMetadataBitcoinExchange struct {
	tableName struct{} `pg:"pg_metadata_bitcoin_exchanges"`

	TransactionHash   *BlockHash `pg:",pk,type:bytea"`
	BitcoinBlockHash  *BlockHash `pg:",type:bytea"`
	BitcoinMerkleRoot *BlockHash `pg:",type:bytea"`
	// Not storing BitcoinTransaction *wire.MsgTx
	// Not storing BitcoinMerkleProof []*merkletree.ProofPart
}

// PGMetadataPrivateMessage represents PrivateMessageMetadata
type PGMetadataPrivateMessage struct {
	tableName struct{} `pg:"pg_metadata_private_messages"`

	TransactionHash    *BlockHash `pg:",pk,type:bytea"`
	RecipientPublicKey []byte     `pg:",type:bytea"`
	EncryptedText      []byte     `pg:",type:bytea"`
	TimestampNanos     uint64
}

// PGMetadataSubmitPost represents SubmitPostMetadata
type PGMetadataSubmitPost struct {
	tableName struct{} `pg:"pg_metadata_submit_posts"`

	TransactionHash  *BlockHash `pg:",pk,type:bytea"`
	PostHashToModify *BlockHash `pg:",type:bytea"`
	ParentStakeID    *BlockHash `pg:",type:bytea"`
	Body             []byte     `pg:",type:bytea"`
	TimestampNanos   uint64
	IsHidden         bool `pg:",use_zero"`
}

// PGMetadataUpdateExchangeRate represents UpdateBitcoinUSDExchangeRateMetadataa
type PGMetadataUpdateExchangeRate struct {
	tableName struct{} `pg:"pg_metadata_update_exchange_rates"`

	TransactionHash    *BlockHash `pg:",pk,type:bytea"`
	USDCentsPerBitcoin uint64     `pg:",use_zero"`
}

// PGMetadataUpdateProfile represents UpdateProfileMetadata
type PGMetadataUpdateProfile struct {
	tableName struct{} `pg:"pg_metadata_update_profiles"`

	TransactionHash       *BlockHash `pg:",pk,type:bytea"`
	ProfilePublicKey      []byte     `pg:",type:bytea"`
	NewUsername           []byte     `pg:",type:bytea"`
	NewDescription        []byte     `pg:",type:bytea"`
	NewProfilePic         []byte     `pg:",type:bytea"`
	NewCreatorBasisPoints uint64     `pg:",use_zero"`
}

// PGMetadataFollow represents FollowMetadata
type PGMetadataFollow struct {
	tableName struct{} `pg:"pg_metadata_follows"`

	TransactionHash   *BlockHash `pg:",pk,type:bytea"`
	FollowedPublicKey []byte     `pg:",type:bytea"`
	IsUnfollow        bool       `pg:",use_zero"`
}

// PGMetadataLike represents LikeMetadata
type PGMetadataLike struct {
	tableName struct{} `pg:"pg_metadata_likes"`

	TransactionHash *BlockHash `pg:",pk,type:bytea"`
	LikedPostHash   *BlockHash `pg:",type:bytea"`
	IsUnlike        bool       `pg:",use_zero"`
}

// PGMetadataCreatorCoin represents CreatorCoinMetadataa
type PGMetadataCreatorCoin struct {
	tableName struct{} `pg:"pg_metadata_creator_coins"`

	TransactionHash             *BlockHash               `pg:",pk,type:bytea"`
	ProfilePublicKey            []byte                   `pg:",type:bytea"`
	OperationType               CreatorCoinOperationType `pg:",use_zero"`
	DeSoToSellNanos             uint64                   `pg:",use_zero"`
	CreatorCoinToSellNanos      uint64                   `pg:",use_zero"`
	DeSoToAddNanos              uint64                   `pg:",use_zero"`
	MinDeSoExpectedNanos        uint64                   `pg:",use_zero"`
	MinCreatorCoinExpectedNanos uint64                   `pg:",use_zero"`
}

// PGMetadataCreatorCoinTransfer represents CreatorCoinTransferMetadataa
type PGMetadataCreatorCoinTransfer struct {
	tableName struct{} `pg:"pg_metadata_creator_coin_transfers"`

	TransactionHash            *BlockHash `pg:",pk,type:bytea"`
	ProfilePublicKey           []byte     `pg:",type:bytea"`
	CreatorCoinToTransferNanos uint64     `pg:",use_zero"`
	ReceiverPublicKey          []byte     `pg:",type:bytea"`
}

// PGMetadataDAOCoin represents DAOCoinMetadata
type PGMetadataDAOCoin struct {
	tableName struct{} `pg:"pg_metadata_dao_coins"`

	TransactionHash           *BlockHash           `pg:",pk,type:bytea"`
	ProfilePublicKey          []byte               `pg:",type:bytea"`
	OperationType             DAOCoinOperationType `pg:",use_zero"`
	CoinsToMintNanos          string
	CoinsToBurnNanos          string
	TransferRestrictionStatus `pg:",use_zero"`
}

// PGMetadataDAOCoinTransfer represents DAOCoinTransferMetadata
type PGMetadataDAOCoinTransfer struct {
	tableName struct{} `pg:"pg_metadata_dao_coin_transfers"`

	TransactionHash        *BlockHash `pg:",pk,type:bytea"`
	ProfilePublicKey       []byte     `pg:",type:bytea"`
	DAOCoinToTransferNanos string     `pg:"dao_coin_to_transfer_nanos,use_zero"`
	ReceiverPublicKey      []byte     `pg:",type:bytea"`
}

// PGMetadataSwapIdentity represents SwapIdentityMetadataa
type PGMetadataSwapIdentity struct {
	tableName struct{} `pg:"pg_metadata_swap_identities"`

	TransactionHash *BlockHash `pg:",pk,type:bytea"`
	FromPublicKey   []byte     `pg:",type:bytea"`
	ToPublicKey     []byte     `pg:",type:bytea"`
}

// PGMetadataCreateNFT represents CreateNFTMetadata
type PGMetadataCreateNFT struct {
	tableName struct{} `pg:"pg_metadata_create_nfts"`

	TransactionHash           *BlockHash `pg:",pk,type:bytea"`
	NFTPostHash               *BlockHash `pg:",type:bytea"`
	NumCopies                 uint64     `pg:",use_zero"`
	HasUnlockable             bool       `pg:",use_zero"`
	IsForSale                 bool       `pg:",use_zero"`
	MinBidAmountNanos         uint64     `pg:",use_zero"`
	CreatorRoyaltyBasisPoints uint64     `pg:",use_zero"`
	CoinRoyaltyBasisPoints    uint64     `pg:",use_zero"`
}

// PGMetadataUpdateNFT represents UpdateNFTMetadata
type PGMetadataUpdateNFT struct {
	tableName struct{} `pg:"pg_metadata_update_nfts"`

	TransactionHash   *BlockHash `pg:",pk,type:bytea"`
	NFTPostHash       *BlockHash `pg:",type:bytea"`
	SerialNumber      uint64     `pg:",use_zero"`
	IsForSale         bool       `pg:",use_zero"`
	MinBidAmountNanos uint64     `pg:",use_zero"`
}

// PGMetadataAcceptNFTBid represents AcceptNFTBidMetadata
type PGMetadataAcceptNFTBid struct {
	tableName struct{} `pg:"pg_metadata_accept_nft_bids"`

	TransactionHash *BlockHash            `pg:",pk,type:bytea"`
	NFTPostHash     *BlockHash            `pg:",type:bytea"`
	SerialNumber    uint64                `pg:",use_zero"`
	BidderPKID      *PKID                 `pg:",type:bytea"`
	BidAmountNanos  uint64                `pg:",use_zero"`
	UnlockableText  []byte                `pg:",type:bytea"`
	BidderInputs    []*PGMetadataBidInput `pg:"rel:has-many,join_fk:transaction_hash"`
}

type PGMetadataBidInput struct {
	tableName struct{} `pg:"pg_metadata_bid_inputs"`

	TransactionHash *BlockHash `pg:",pk,type:bytea"`
	InputHash       *BlockHash `pg:",pk,type:bytea"`
	InputIndex      uint32     `pg:",pk,use_zero"`
}

// PGMetadataNFTBid represents NFTBidMetadata
type PGMetadataNFTBid struct {
	tableName struct{} `pg:"pg_metadata_nft_bids"`

	TransactionHash *BlockHash `pg:",pk,type:bytea"`
	NFTPostHash     *BlockHash `pg:",type:bytea"`
	SerialNumber    uint64     `pg:",use_zero"`
	BidAmountNanos  uint64     `pg:",use_zero"`
}

// PGMetadataNFTTransfer represents NFTTransferMetadata
type PGMetadataNFTTransfer struct {
	tableName struct{} `pg:"pg_metadata_nft_transfer"`

	TransactionHash   *BlockHash `pg:",pk,type:bytea"`
	NFTPostHash       *BlockHash `pg:",pk,type:bytea"`
	SerialNumber      uint64     `pg:",use_zero"`
	ReceiverPublicKey []byte     `pg:",pk,type:bytea"`
	UnlockableText    []byte     `pg:",type:bytea"`
}

// PGMetadataAcceptNFTTransfer represents AcceptNFTTransferMetadata
type PGMetadataAcceptNFTTransfer struct {
	tableName struct{} `pg:"pg_metadata_accept_nft_transfer"`

	TransactionHash *BlockHash `pg:",pk,type:bytea"`
	NFTPostHash     *BlockHash `pg:",pk,type:bytea"`
	SerialNumber    uint64     `pg:",use_zero"`
}

// PGMetadataBurnNFT represents BurnNFTMetadata
type PGMetadataBurnNFT struct {
	tableName struct{} `pg:"pg_metadata_burn_nft"`

	TransactionHash *BlockHash `pg:",pk,type:bytea"`
	NFTPostHash     *BlockHash `pg:",pk,type:bytea"`
	SerialNumber    uint64     `pg:",use_zero"`
}

// PGMetadataDerivedKey represents AuthorizeDerivedKeyMetadata
type PGMetadataDerivedKey struct {
	tableName struct{} `pg:"pg_metadata_derived_keys"`

	TransactionHash  *BlockHash                       `pg:",pk,type:bytea"`
	DerivedPublicKey PublicKey                        `pg:",type:bytea"`
	ExpirationBlock  uint64                           `pg:",use_zero"`
	OperationType    AuthorizeDerivedKeyOperationType `pg:",use_zero"`
	AccessSignature  []byte                           `pg:",type:bytea"`
}

// PGMetadataDAOCoinLimitOrder represents DAOCoinLimitOrderMetadata
type PGMetadataDAOCoinLimitOrder struct {
	tableName struct{} `pg:"pg_metadata_dao_coin_limit_orders"`

	TransactionHash                           *BlockHash                                 `pg:",pk,type:bytea"`
	BuyingDAOCoinCreatorPublicKey             *PublicKey                                 `pg:"buying_dao_coin_creator_public_key,type:bytea"`
	SellingDAOCoinCreatorPublicKey            *PublicKey                                 `pg:"selling_dao_coin_creator_public_key,type:bytea"`
	ScaledExchangeRateCoinsToSellPerCoinToBuy string                                     `pg:",use_zero"`
	QuantityToFillInBaseUnits                 string                                     `pg:",use_zero"`
	OperationType                             uint8                                      `pg:",use_zero"`
	FillType                                  uint8                                      `pg:",use_zero"`
	CancelOrderID                             *BlockHash                                 `pg:",type:bytea"`
	FeeNanos                                  uint64                                     `pg:",use_zero"`
	BidderInputs                              []*PGMetadataDAOCoinLimitOrderBidderInputs `pg:"rel:has-many,join_fk:transaction_hash"`
}

type PGMetadataDAOCoinLimitOrderBidderInputs struct {
	tableName struct{} `pg:"pg_metadata_dao_coin_limit_order_bidder_inputs"`

	TransactionHash *BlockHash `pg:",pk,type:bytea"`
	InputHash       *BlockHash `pg:",pk,type:bytea"`
	InputIndex      uint32     `pg:",pk,use_zero"`
}

type PGNotification struct {
	tableName struct{} `pg:"pg_notifications"`

	TransactionHash *BlockHash       `pg:",pk,type:bytea"`
	Mined           bool             `pg:",use_zero"`
	ToUser          []byte           `pg:",type:bytea"`
	FromUser        []byte           `pg:",type:bytea"`
	OtherUser       []byte           `pg:",type:bytea"`
	Type            NotificationType `pg:",use_zero"`
	Amount          uint64           `pg:",use_zero"`
	PostHash        *BlockHash       `pg:",type:bytea"`
	Timestamp       uint64           `pg:",use_zero"`
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
	tableName struct{} `pg:"pg_profiles"`

	PKID               *PKID      `pg:",pk,type:bytea"`
	PublicKey          *PublicKey `pg:",type:bytea"`
	Username           string
	Description        string
	ProfilePic         []byte
	CreatorBasisPoints uint64
	DeSoLockedNanos    uint64
	NumberOfHolders    uint64
	// FIXME: Postgres will break when values exceed uint64
	// We don't use Postgres right now so going to plow ahead and set this as-is
	// to fix compile errors. CoinsInCirculationNanos will never exceed uint64
	CoinsInCirculationNanos          uint64
	CoinWatermarkNanos               uint64
	MintingDisabled                  bool
	DAOCoinNumberOfHolders           uint64                    `pg:"dao_coin_number_of_holders"`
	DAOCoinCoinsInCirculationNanos   string                    `pg:"dao_coin_coins_in_circulation_nanos"`
	DAOCoinMintingDisabled           bool                      `pg:"dao_coin_minting_disabled"`
	DAOCoinTransferRestrictionStatus TransferRestrictionStatus `pg:"dao_coin_transfer_restriction_status"`
	ExtraData                        map[string][]byte
}

func (profile *PGProfile) Empty() bool {
	return profile.Username == ""
}

type PGPost struct {
	tableName struct{} `pg:"pg_posts"`

	PostHash                                    *BlockHash `pg:",pk,type:bytea"`
	PosterPublicKey                             []byte
	ParentPostHash                              *BlockHash `pg:",type:bytea"`
	Body                                        string
	RepostedPostHash                            *BlockHash        `pg:",type:bytea"`
	QuotedRepost                                bool              `pg:",use_zero"`
	Timestamp                                   uint64            `pg:",use_zero"`
	Hidden                                      bool              `pg:",use_zero"`
	LikeCount                                   uint64            `pg:",use_zero"`
	RepostCount                                 uint64            `pg:",use_zero"`
	QuoteRepostCount                            uint64            `pg:",use_zero"`
	DiamondCount                                uint64            `pg:",use_zero"`
	CommentCount                                uint64            `pg:",use_zero"`
	Pinned                                      bool              `pg:",use_zero"`
	NFT                                         bool              `pg:",use_zero"`
	NumNFTCopies                                uint64            `pg:",use_zero"`
	NumNFTCopiesForSale                         uint64            `pg:",use_zero"`
	NumNFTCopiesBurned                          uint64            `pg:",use_zero"`
	Unlockable                                  bool              `pg:",use_zero"`
	CreatorRoyaltyBasisPoints                   uint64            `pg:",use_zero"`
	CoinRoyaltyBasisPoints                      uint64            `pg:",use_zero"`
	AdditionalNFTRoyaltiesToCoinsBasisPoints    map[string]uint64 `pg:"additional_nft_royalties_to_coins_basis_points"`
	AdditionalNFTRoyaltiesToCreatorsBasisPoints map[string]uint64 `pg:"additional_nft_royalties_to_creators_basis_points"`
	ExtraData                                   map[string][]byte
}

func (post *PGPost) NewPostEntry() *PostEntry {
	postEntry := &PostEntry{
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

	if len(post.AdditionalNFTRoyaltiesToCoinsBasisPoints) > 0 {
		postEntry.AdditionalNFTRoyaltiesToCoinsBasisPoints = make(map[PKID]uint64)
		for pkidStr, bp := range post.AdditionalNFTRoyaltiesToCoinsBasisPoints {
			pkidBytes, err := hex.DecodeString(pkidStr)
			if err != nil {
				panic(err)
			}
			postEntry.AdditionalNFTRoyaltiesToCoinsBasisPoints[*NewPKID(pkidBytes)] = bp
		}
	}

	if len(post.AdditionalNFTRoyaltiesToCreatorsBasisPoints) > 0 {
		postEntry.AdditionalNFTRoyaltiesToCreatorsBasisPoints = make(map[PKID]uint64)
		for pkidStr, bp := range post.AdditionalNFTRoyaltiesToCreatorsBasisPoints {
			pkidBytes, err := hex.DecodeString(pkidStr)
			if err != nil {
				panic(err)
			}
			postEntry.AdditionalNFTRoyaltiesToCreatorsBasisPoints[*NewPKID(pkidBytes)] = bp
		}
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
	tableName struct{} `pg:"pg_likes"`

	LikerPublicKey []byte     `pg:",pk,type:bytea"`
	LikedPostHash  *BlockHash `pg:",pk,type:bytea"`
}

func (like *PGLike) NewLikeEntry() *LikeEntry {
	return &LikeEntry{
		LikerPubKey:   like.LikerPublicKey,
		LikedPostHash: like.LikedPostHash,
	}
}

type PGFollow struct {
	tableName struct{} `pg:"pg_follows"`

	FollowerPKID *PKID `pg:",pk,type:bytea"`
	FollowedPKID *PKID `pg:",pk,type:bytea"`
}

func (follow *PGFollow) NewFollowEntry() *FollowEntry {
	return &FollowEntry{
		FollowerPKID: follow.FollowerPKID,
		FollowedPKID: follow.FollowedPKID,
	}
}

type PGDiamond struct {
	tableName struct{} `pg:"pg_diamonds"`

	SenderPKID      *PKID      `pg:",pk,type:bytea"`
	ReceiverPKID    *PKID      `pg:",pk,type:bytea"`
	DiamondPostHash *BlockHash `pg:",pk,type:bytea"`
	DiamondLevel    uint8
}

// TODO: This doesn't need to be a table. Just add sender to PGMetadataPrivateMessage?
// The only reason we might not want to do this is if we end up pruning Metadata tables.
type PGMessage struct {
	tableName struct{} `pg:"pg_messages"`

	MessageHash        *BlockHash `pg:",pk,type:bytea"`
	SenderPublicKey    []byte
	RecipientPublicKey []byte
	EncryptedText      []byte
	TimestampNanos     uint64
	// TODO: Version

	ExtraData map[string][]byte

	// Used to track deletions in the UtxoView
	isDeleted bool
}

type PGMessagingGroup struct {
	tableName struct{} `pg:"pg_messaging_group"`

	GroupOwnerPublicKey   *PublicKey    `pg:",type:bytea"`
	MessagingPublicKey    *PublicKey    `pg:",type:bytea"`
	MessagingGroupKeyName *GroupKeyName `pg:",type:bytea"`
	MessagingGroupMembers []byte        `pg:",type:bytea"`

	ExtraData map[string][]byte
}

type PGCreatorCoinBalance struct {
	tableName struct{} `pg:"pg_creator_coin_balances"`

	HolderPKID   *PKID `pg:",pk,type:bytea"`
	CreatorPKID  *PKID `pg:",pk,type:bytea"`
	BalanceNanos uint64
	HasPurchased bool
}

func (balance *PGCreatorCoinBalance) NewBalanceEntry() *BalanceEntry {
	if balance == nil {
		return nil
	}

	return &BalanceEntry{
		HODLerPKID:  balance.HolderPKID,
		CreatorPKID: balance.CreatorPKID,
		// FIXME: This will break if the value exceeds uint256
		BalanceNanos: *uint256.NewInt().SetUint64(balance.BalanceNanos),
		HasPurchased: balance.HasPurchased,
	}
}

type PGDAOCoinBalance struct {
	tableName struct{} `pg:"pg_dao_coin_balances"`

	HolderPKID   *PKID `pg:",pk,type:bytea"`
	CreatorPKID  *PKID `pg:",pk,type:bytea"`
	BalanceNanos string
	HasPurchased bool
}

func (balance *PGDAOCoinBalance) NewBalanceEntry() *BalanceEntry {
	if balance == nil {
		return nil
	}

	return &BalanceEntry{
		HODLerPKID:   balance.HolderPKID,
		CreatorPKID:  balance.CreatorPKID,
		BalanceNanos: *HexToUint256(balance.BalanceNanos),
		HasPurchased: balance.HasPurchased,
	}
}

// PGDAOCoinLimitOrder represents DAOCoinLimitOrderEntry
type PGDAOCoinLimitOrder struct {
	tableName struct{} `pg:"pg_dao_coin_limit_orders"`

	OrderID                                   *BlockHash `pg:",pk,type:bytea"`
	TransactorPKID                            *PKID      `pg:",type:bytea"`
	BuyingDAOCoinCreatorPKID                  *PKID      `pg:"buying_dao_coin_creator_pkid,type:bytea"`
	SellingDAOCoinCreatorPKID                 *PKID      `pg:"selling_dao_coin_creator_pkid,type:bytea"`
	ScaledExchangeRateCoinsToSellPerCoinToBuy string     `pg:",use_zero"`
	QuantityToFillInBaseUnits                 string     `pg:",use_zero"`
	OperationType                             uint8      `pg:",use_zero"`
	FillType                                  uint8      `pg:",use_zero"`
	BlockHeight                               uint32     `pg:",use_zero"`
}

func (order *PGDAOCoinLimitOrder) FromDAOCoinLimitOrderEntry(orderEntry *DAOCoinLimitOrderEntry) {
	order.OrderID = orderEntry.OrderID
	order.TransactorPKID = orderEntry.TransactorPKID
	order.BuyingDAOCoinCreatorPKID = orderEntry.BuyingDAOCoinCreatorPKID
	order.SellingDAOCoinCreatorPKID = orderEntry.SellingDAOCoinCreatorPKID
	order.ScaledExchangeRateCoinsToSellPerCoinToBuy = Uint256ToLeftPaddedHex(orderEntry.ScaledExchangeRateCoinsToSellPerCoinToBuy)
	order.QuantityToFillInBaseUnits = Uint256ToLeftPaddedHex(orderEntry.QuantityToFillInBaseUnits)
	order.OperationType = uint8(orderEntry.OperationType)
	order.FillType = uint8(orderEntry.FillType)
	order.BlockHeight = orderEntry.BlockHeight
}

func (order *PGDAOCoinLimitOrder) ToDAOCoinLimitOrderEntry() *DAOCoinLimitOrderEntry {
	return &DAOCoinLimitOrderEntry{
		OrderID:                   order.OrderID,
		TransactorPKID:            order.TransactorPKID,
		BuyingDAOCoinCreatorPKID:  order.BuyingDAOCoinCreatorPKID,
		SellingDAOCoinCreatorPKID: order.SellingDAOCoinCreatorPKID,
		ScaledExchangeRateCoinsToSellPerCoinToBuy: LeftPaddedHexToUint256(order.ScaledExchangeRateCoinsToSellPerCoinToBuy),
		QuantityToFillInBaseUnits:                 LeftPaddedHexToUint256(order.QuantityToFillInBaseUnits),
		OperationType:                             DAOCoinLimitOrderOperationType(order.OperationType),
		FillType:                                  DAOCoinLimitOrderFillType(order.FillType),
		BlockHeight:                               order.BlockHeight,
	}
}

func HexToUint256(input string) *uint256.Int {
	output := uint256.NewInt()

	if input != "" {
		var err error
		output, err = uint256.FromHex(input)

		if err != nil {
			output = uint256.NewInt()
		}
	}

	return output
}

func Uint256ToLeftPaddedHex(input *uint256.Int) string {
	// Chop off the starting "0x" prefix.
	output := input.Hex()[2:]

	if len(output) < 32 {
		output = fmt.Sprintf("%032s", output)
	}

	// Add back the starting "0x" prefix.
	return "0x" + output
}

func LeftPaddedHexToUint256(input string) *uint256.Int {
	// Chop off the starting "0x" prefix and any leading zeroes.
	hexPrefixRegex := regexp.MustCompile("^0x0{0,31}")
	// Replace with "0x".
	output := hexPrefixRegex.ReplaceAllString(input, "0x")
	// Convert to uint256.
	return HexToUint256(output)
}

// PGBalance represents PublicKeyToDeSoBalanceNanos
type PGBalance struct {
	tableName struct{} `pg:"pg_balances"`

	PublicKey    *PublicKey `pg:",pk,type:bytea"`
	BalanceNanos uint64     `pg:",use_zero"`
}

// PGGlobalParams represents GlobalParamsEntry
type PGGlobalParams struct {
	tableName struct{} `pg:"pg_global_params"`

	ID uint64

	USDCentsPerBitcoin      uint64 `pg:",use_zero"`
	CreateProfileFeeNanos   uint64 `pg:",use_zero"`
	CreateNFTFeeNanos       uint64 `pg:",use_zero"`
	MaxCopiesPerNFT         uint64 `pg:",use_zero"`
	MinNetworkFeeNanosPerKB uint64 `pg:",use_zero"`
}

type PGRepost struct {
	tableName struct{} `pg:"pg_reposts"`

	ReposterPublickey *PublicKey `pg:",pk,type:bytea"`
	RepostedPostHash  *BlockHash `pg:",pk,type:bytea"`
	RepostPostHash    *BlockHash `pg:",type:bytea"`

	// Whether or not this entry is deleted in the view.
	isDeleted bool
}

// PGForbiddenKey represents ForbiddenPubKeyEntry
type PGForbiddenKey struct {
	tableName struct{} `pg:"pg_forbidden_keys"`

	PublicKey *PublicKey `pg:",pk,type:bytea"`
}

// PGNFT represents NFTEntry
type PGNFT struct {
	tableName struct{} `pg:"pg_nfts"`

	NFTPostHash  *BlockHash `pg:",pk,type:bytea"`
	SerialNumber uint64     `pg:",pk"`

	// This is needed to decrypt unlockable text.
	LastOwnerPKID              *PKID  `pg:",type:bytea"`
	OwnerPKID                  *PKID  `pg:",type:bytea"`
	ForSale                    bool   `pg:",use_zero"`
	MinBidAmountNanos          uint64 `pg:",use_zero"`
	UnlockableText             string
	LastAcceptedBidAmountNanos uint64 `pg:",use_zero"`
	IsPending                  bool   `pg:",use_zero"`
	IsBuyNow                   bool   `pg:",use_zero"`
	BuyNowPriceNanos           uint64 `pg:",use_zero"`

	ExtraData map[string][]byte
}

func (nft *PGNFT) NewNFTEntry() *NFTEntry {
	return &NFTEntry{
		LastOwnerPKID:              nft.LastOwnerPKID,
		OwnerPKID:                  nft.OwnerPKID,
		NFTPostHash:                nft.NFTPostHash,
		SerialNumber:               nft.SerialNumber,
		IsForSale:                  nft.ForSale,
		MinBidAmountNanos:          nft.MinBidAmountNanos,
		UnlockableText:             []byte(nft.UnlockableText),
		LastAcceptedBidAmountNanos: nft.LastAcceptedBidAmountNanos,
		IsPending:                  nft.IsPending,
		IsBuyNow:                   nft.IsBuyNow,
		BuyNowPriceNanos:           nft.BuyNowPriceNanos,
		ExtraData:                  nft.ExtraData,
	}
}

// PGNFTBid represents NFTBidEntry
type PGNFTBid struct {
	tableName struct{} `pg:"pg_nft_bids"`

	BidderPKID          *PKID      `pg:",pk,type:bytea"`
	NFTPostHash         *BlockHash `pg:",pk,type:bytea"`
	SerialNumber        uint64     `pg:",pk,use_zero"`
	BidAmountNanos      uint64     `pg:",use_zero"`
	Accepted            bool       `pg:",use_zero"`
	AcceptedBlockHeight *uint32    `pg:",use_zero"`
}

func (bid *PGNFTBid) NewNFTBidEntry() *NFTBidEntry {
	return &NFTBidEntry{
		BidderPKID:          bid.BidderPKID,
		NFTPostHash:         bid.NFTPostHash,
		SerialNumber:        bid.SerialNumber,
		BidAmountNanos:      bid.BidAmountNanos,
		AcceptedBlockHeight: bid.AcceptedBlockHeight,
	}
}

// PGDerivedKey represents DerivedKeyEntry
type PGDerivedKey struct {
	tableName struct{} `pg:"pg_derived_keys"`

	OwnerPublicKey   PublicKey                        `pg:",pk,type:bytea"`
	DerivedPublicKey PublicKey                        `pg:",pk,type:bytea"`
	ExpirationBlock  uint64                           `pg:",use_zero"`
	OperationType    AuthorizeDerivedKeyOperationType `pg:",use_zero"`

	ExtraData map[string][]byte

	// TransactionSpendingLimit fields
	TransactionSpendingLimitTracker []byte `pg:",type:bytea"`
	Memo                            []byte `pg:",type:bytea"`
}

func (key *PGDerivedKey) NewDerivedKeyEntry() *DerivedKeyEntry {
	var tsl *TransactionSpendingLimit
	if len(key.TransactionSpendingLimitTracker) > 0 {
		tsl = &TransactionSpendingLimit{}
		if err := tsl.FromBytes(bytes.NewReader(key.TransactionSpendingLimitTracker)); err != nil {
			glog.Errorf("Error converting Derived Key's TransactionLimitTracker bytes back into a TransactionSpendingLimit: %v", err)
			return nil
		}
	}
	return &DerivedKeyEntry{
		OwnerPublicKey:                  key.OwnerPublicKey,
		DerivedPublicKey:                key.DerivedPublicKey,
		ExpirationBlock:                 key.ExpirationBlock,
		OperationType:                   key.OperationType,
		ExtraData:                       key.ExtraData,
		TransactionSpendingLimitTracker: tsl,
		Memo:                            key.Memo,
	}
}

//
// Blockchain and Transactions
//

func (postgres *Postgres) UpsertBlock(blockNode *BlockNode) error {
	return postgres.db.RunInTransaction(postgres.db.Context(), func(tx *pg.Tx) error {
		return postgres.UpsertBlockTx(tx, blockNode)
	})
}

func (postgres *Postgres) UpsertBlockTx(tx *pg.Tx, blockNode *BlockNode) error {
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

	_, err := tx.Model(block).WherePK().OnConflict("(hash) DO UPDATE").Insert()
	return err
}

// GetBlockIndex gets all the PGBlocks and creates a map of BlockHash to BlockNode as needed by blockchain.go
func (postgres *Postgres) GetBlockIndex() (map[BlockHash]*BlockNode, error) {
	var blocks []PGBlock
	err := postgres.db.Model(&blocks).Select()
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

	err := postgres.db.Model(chain).First()
	if err != nil {
		return nil
	}

	return chain
}

func (postgres *Postgres) UpsertChain(name string, tipHash *BlockHash) error {
	return postgres.db.RunInTransaction(postgres.db.Context(), func(tx *pg.Tx) error {
		return postgres.UpsertChainTx(tx, name, tipHash)
	})
}

func (postgres *Postgres) UpsertChainTx(tx *pg.Tx, name string, tipHash *BlockHash) error {
	bestChain := &PGChain{
		TipHash: tipHash,
		Name:    name,
	}

	_, err := tx.Model(bestChain).WherePK().OnConflict("(name) DO UPDATE").Insert()
	return err
}

// InsertTransactionsTx inserts all the transactions from a block in a bulk query
func (postgres *Postgres) InsertTransactionsTx(tx *pg.Tx, desoTxns []*MsgDeSoTxn, blockNode *BlockNode) error {
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
	var metadataDAOCoin []*PGMetadataDAOCoin
	var metadataDAOCoinTransfer []*PGMetadataDAOCoinTransfer
	var metadataDAOCoinLimitOrder []*PGMetadataDAOCoinLimitOrder
	var metadataDAOCoinLimitOrderBidderInputs []*PGMetadataDAOCoinLimitOrderBidderInputs

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
				Body:             txMeta.Body,
				TimestampNanos:   txMeta.TimestampNanos,
				IsHidden:         txMeta.IsHidden,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateProfile {
			txMeta := txn.TxnMeta.(*UpdateProfileMetadata)
			metadataUpdateProfiles = append(metadataUpdateProfiles, &PGMetadataUpdateProfile{
				TransactionHash:       txnHash,
				ProfilePublicKey:      txMeta.ProfilePublicKey,
				NewUsername:           txMeta.NewUsername,
				NewProfilePic:         txMeta.NewProfilePic,
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
				DeSoToSellNanos:             txMeta.DeSoToSellNanos,
				CreatorCoinToSellNanos:      txMeta.CreatorCoinToSellNanos,
				DeSoToAddNanos:              txMeta.DeSoToAddNanos,
				MinDeSoExpectedNanos:        txMeta.MinDeSoExpectedNanos,
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

			//get related NFT
			pgBidNft := postgres.GetNFT(txMeta.NFTPostHash, txMeta.SerialNumber)

			//check if is buy now and BidAmountNanos > then BuyNowPriceNanos
			if pgBidNft != nil && pgBidNft.IsBuyNow && txMeta.BidAmountNanos >= pgBidNft.BuyNowPriceNanos {

				// Initialize bidderPKID with naive NewPKID from txn.PublicKey
				bidderPKID := NewPKID(txn.PublicKey)
				//get related profile
				pgBidProfile := postgres.GetProfileForPublicKey(txn.PublicKey)
				// If profile is non-nil, update bidderPKID to value from pgBidProfile
				if pgBidProfile != nil {
					bidderPKID = pgBidProfile.PKID
				}

				//add to accept bids as well
				metadataAcceptNFTBids = append(metadataAcceptNFTBids, &PGMetadataAcceptNFTBid{
					TransactionHash: txnHash,
					NFTPostHash:     txMeta.NFTPostHash,
					SerialNumber:    txMeta.SerialNumber,
					BidderPKID:      bidderPKID,
					BidAmountNanos:  txMeta.BidAmountNanos,
					UnlockableText:  []byte{},
				})
			}

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
		} else if txn.TxnMeta.GetTxnType() == TxnTypeDAOCoin {
			txMeta := txn.TxnMeta.(*DAOCoinMetadata)
			metadataDAOCoin = append(metadataDAOCoin, &PGMetadataDAOCoin{
				TransactionHash:           txnHash,
				ProfilePublicKey:          txMeta.ProfilePublicKey,
				OperationType:             txMeta.OperationType,
				CoinsToMintNanos:          txMeta.CoinsToMintNanos.Hex(),
				CoinsToBurnNanos:          txMeta.CoinsToBurnNanos.Hex(),
				TransferRestrictionStatus: txMeta.TransferRestrictionStatus,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeDAOCoinTransfer {
			txMeta := txn.TxnMeta.(*DAOCoinTransferMetadata)
			metadataDAOCoinTransfer = append(metadataDAOCoinTransfer, &PGMetadataDAOCoinTransfer{
				TransactionHash:        txnHash,
				ProfilePublicKey:       txMeta.ProfilePublicKey,
				DAOCoinToTransferNanos: txMeta.DAOCoinToTransferNanos.Hex(),
				ReceiverPublicKey:      txMeta.ReceiverPublicKey,
			})

		} else if txn.TxnMeta.GetTxnType() == TxnTypeDAOCoinLimitOrder {
			txMeta := txn.TxnMeta.(*DAOCoinLimitOrderMetadata)

			if txMeta.CancelOrderID != nil {
				// Transactor is cancelling an existing order.
				metadataDAOCoinLimitOrder = append(metadataDAOCoinLimitOrder, &PGMetadataDAOCoinLimitOrder{
					TransactionHash: txnHash,
					CancelOrderID:   txMeta.CancelOrderID,
					FeeNanos:        txMeta.FeeNanos,
				})

				break
			}

			// Transactor is submitting a new order.
			metadataDAOCoinLimitOrder = append(metadataDAOCoinLimitOrder, &PGMetadataDAOCoinLimitOrder{
				TransactionHash:                           txnHash,
				BuyingDAOCoinCreatorPublicKey:             txMeta.BuyingDAOCoinCreatorPublicKey,
				SellingDAOCoinCreatorPublicKey:            txMeta.SellingDAOCoinCreatorPublicKey,
				ScaledExchangeRateCoinsToSellPerCoinToBuy: txMeta.ScaledExchangeRateCoinsToSellPerCoinToBuy.Hex(),
				QuantityToFillInBaseUnits:                 txMeta.QuantityToFillInBaseUnits.Hex(),
				OperationType:                             uint8(txMeta.OperationType),
				FillType:                                  uint8(txMeta.FillType),
				FeeNanos:                                  txMeta.FeeNanos,
			})

			for _, inputsByTransactor := range txMeta.BidderInputs {
				for _, input := range inputsByTransactor.Inputs {
					metadataDAOCoinLimitOrderBidderInputs = append(metadataDAOCoinLimitOrderBidderInputs,
						&PGMetadataDAOCoinLimitOrderBidderInputs{
							TransactionHash: txnHash,
							InputHash:       input.TxID.NewBlockHash(),
							InputIndex:      input.Index,
						})
				}
			}

		} else if txn.TxnMeta.GetTxnType() == TxnTypeMessagingGroup {

			// FIXME: Skip PGMetadataMessagingGroup for now since it's not used downstream

		} else {
			return fmt.Errorf("InsertTransactionTx: Unimplemented txn type %v", txn.TxnMeta.GetTxnType().String())
		}
	}

	// Insert the block and all of its data in bulk

	if len(transactions) > 0 {
		if _, err := tx.Model(&transactions).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(transactionOutputs) > 0 {
		if _, err := tx.Model(&transactionOutputs).Returning("NULL").OnConflict("(output_hash, output_index) DO UPDATE").Insert(); err != nil {
			return err
		}
	}

	if len(transactionInputs) > 0 {
		if _, err := tx.Model(&transactionInputs).WherePK().Column("input_hash", "input_index", "spent").Update(); err != nil {
			return err
		}
	}

	if len(metadataBlockRewards) > 0 {
		if _, err := tx.Model(&metadataBlockRewards).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataBitcoinExchanges) > 0 {
		if _, err := tx.Model(&metadataBitcoinExchanges).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataPrivateMessages) > 0 {
		if _, err := tx.Model(&metadataPrivateMessages).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataSubmitPosts) > 0 {
		if _, err := tx.Model(&metadataSubmitPosts).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataUpdateProfiles) > 0 {
		if _, err := tx.Model(&metadataUpdateProfiles).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataExchangeRates) > 0 {
		if _, err := tx.Model(&metadataExchangeRates).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataFollows) > 0 {
		if _, err := tx.Model(&metadataFollows).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataLikes) > 0 {
		if _, err := tx.Model(&metadataLikes).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataCreatorCoins) > 0 {
		if _, err := tx.Model(&metadataCreatorCoins).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataSwapIdentities) > 0 {
		if _, err := tx.Model(&metadataSwapIdentities).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataCreatorCoinTransfers) > 0 {
		if _, err := tx.Model(&metadataCreatorCoinTransfers).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataCreateNFTs) > 0 {
		if _, err := tx.Model(&metadataCreateNFTs).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataUpdateNFTs) > 0 {
		if _, err := tx.Model(&metadataUpdateNFTs).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataAcceptNFTBids) > 0 {
		if _, err := tx.Model(&metadataAcceptNFTBids).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataBidInputs) > 0 {
		if _, err := tx.Model(&metadataBidInputs).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataNFTBids) > 0 {
		if _, err := tx.Model(&metadataNFTBids).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataNFTTransfer) > 0 {
		if _, err := tx.Model(&metadataNFTTransfer).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataAcceptNFTTransfer) > 0 {
		if _, err := tx.Model(&metadataAcceptNFTTransfer).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataBurnNFT) > 0 {
		if _, err := tx.Model(&metadataBurnNFT).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataDerivedKey) > 0 {
		if _, err := tx.Model(&metadataDerivedKey).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataDAOCoin) > 0 {
		if _, err := tx.Model(&metadataDAOCoin).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataDAOCoinTransfer) > 0 {
		if _, err := tx.Model(&metadataDAOCoinTransfer).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataDAOCoinLimitOrder) > 0 {
		if _, err := tx.Model(&metadataDAOCoinLimitOrder).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataDAOCoinLimitOrderBidderInputs) > 0 {
		if _, err := tx.Model(&metadataDAOCoinLimitOrderBidderInputs).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) UpsertBlockAndTransactions(blockNode *BlockNode, desoBlock *MsgDeSoBlock) error {
	return postgres.db.RunInTransaction(postgres.db.Context(), func(tx *pg.Tx) error {
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
	return postgres.db.RunInTransaction(postgres.db.Context(), func(tx *pg.Tx) error {
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
		if err := postgres.flushDAOCoinBalances(tx, view); err != nil {
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
		// Temporarily write limit orders to badger
		//if err := postgres.flushDAOCoinLimitOrders(tx, view); err != nil {
		//	return err
		//}

		return nil
	})
}

func (postgres *Postgres) flushUtxos(tx *pg.Tx, view *UtxoView) error {
	var outputs []*PGTransactionOutput
	for utxoKeyIter, utxoEntry := range view.UtxoKeyToUtxoEntry {
		// Making a copy of the iterator is required
		utxoKey := utxoKeyIter
		outputs = append(outputs, &PGTransactionOutput{
			OutputHash:  &utxoKey.TxID,
			OutputIndex: utxoKey.Index,
			OutputType:  utxoEntry.UtxoType,
			Height:      utxoEntry.BlockHeight,
			PublicKey:   utxoEntry.PublicKey,
			AmountNanos: utxoEntry.AmountNanos,
			Spent:       utxoEntry.isSpent,
		})
	}

	_, err := tx.Model(&outputs).WherePK().OnConflict("(output_hash, output_index) DO UPDATE").Insert()
	if err != nil {
		return fmt.Errorf("flushUtxos: insert: %v", err)
	}

	return nil
}

func (postgres *Postgres) flushProfiles(tx *pg.Tx, view *UtxoView) error {
	var insertProfiles []*PGProfile
	var deleteProfiles []*PGProfile
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
			profile.ProfilePic = profileEntry.ProfilePic
			profile.CreatorBasisPoints = profileEntry.CreatorCoinEntry.CreatorBasisPoints
			profile.DeSoLockedNanos = profileEntry.CreatorCoinEntry.DeSoLockedNanos
			profile.NumberOfHolders = profileEntry.CreatorCoinEntry.NumberOfHolders
			profile.CoinsInCirculationNanos = profileEntry.CreatorCoinEntry.CoinsInCirculationNanos.Uint64()
			profile.CoinWatermarkNanos = profileEntry.CreatorCoinEntry.CoinWatermarkNanos
			profile.DAOCoinCoinsInCirculationNanos = profileEntry.DAOCoinEntry.CoinsInCirculationNanos.Hex()
			profile.DAOCoinMintingDisabled = profileEntry.DAOCoinEntry.MintingDisabled
			profile.DAOCoinNumberOfHolders = profileEntry.DAOCoinEntry.NumberOfHolders
			profile.DAOCoinTransferRestrictionStatus = profileEntry.DAOCoinEntry.TransferRestrictionStatus
			profile.ExtraData = profileEntry.ExtraData
		}

		if pkidEntry.isDeleted {
			deleteProfiles = append(deleteProfiles, profile)
		} else {
			insertProfiles = append(insertProfiles, profile)
		}
	}

	if len(insertProfiles) > 0 {
		_, err := tx.Model(&insertProfiles).WherePK().OnConflict("(pkid) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return fmt.Errorf("flushProfiles: insert: %v", err)
		}
	}

	if len(deleteProfiles) > 0 {
		_, err := tx.Model(&deleteProfiles).Returning("NULL").Delete()
		if err != nil {
			return fmt.Errorf("flushProfiles: delete: %v", err)
		}
	}

	return nil
}

func (postgres *Postgres) flushPosts(tx *pg.Tx, view *UtxoView) error {
	var insertPosts []*PGPost
	var deletePosts []*PGPost
	for _, postEntry := range view.PostHashToPostEntry {
		if postEntry == nil {
			continue
		}

		post := &PGPost{
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

		if len(postEntry.AdditionalNFTRoyaltiesToCoinsBasisPoints) > 0 {
			post.AdditionalNFTRoyaltiesToCoinsBasisPoints = make(map[string]uint64)
			for pkid, bps := range postEntry.AdditionalNFTRoyaltiesToCoinsBasisPoints {
				pkidHexString := hex.EncodeToString(pkid[:])
				post.AdditionalNFTRoyaltiesToCoinsBasisPoints[pkidHexString] = bps
			}
		}

		if len(postEntry.AdditionalNFTRoyaltiesToCreatorsBasisPoints) > 0 {
			post.AdditionalNFTRoyaltiesToCreatorsBasisPoints = make(map[string]uint64)
			for pkid, bps := range postEntry.AdditionalNFTRoyaltiesToCreatorsBasisPoints {
				pkidHexString := hex.EncodeToString(pkid[:])
				post.AdditionalNFTRoyaltiesToCreatorsBasisPoints[pkidHexString] = bps
			}
		}

		if postEntry.isDeleted {
			deletePosts = append(deletePosts, post)
		} else {
			insertPosts = append(insertPosts, post)
		}
	}

	if len(insertPosts) > 0 {
		_, err := tx.Model(&insertPosts).WherePK().OnConflict("(post_hash) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return fmt.Errorf("flushPosts: insert: %v", err)
		}
	}

	if len(deletePosts) > 0 {
		_, err := tx.Model(&deletePosts).Returning("NULL").Delete()
		if err != nil {
			return fmt.Errorf("flushPosts: delete: %v", err)
		}
	}

	return nil
}

func (postgres *Postgres) flushLikes(tx *pg.Tx, view *UtxoView) error {
	var insertLikes []*PGLike
	var deleteLikes []*PGLike
	for _, likeEntry := range view.LikeKeyToLikeEntry {
		if likeEntry == nil {
			continue
		}

		like := &PGLike{
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
		_, err := tx.Model(&insertLikes).WherePK().OnConflict("DO NOTHING").Returning("NULL").Insert()
		if err != nil {
			return fmt.Errorf("flushLikes: insert: %v", err)
		}
	}

	if len(deleteLikes) > 0 {
		_, err := tx.Model(&deleteLikes).Returning("NULL").Delete()
		if err != nil {
			return fmt.Errorf("flushLikes: delete: %v", err)
		}
	}

	return nil
}

func (postgres *Postgres) flushFollows(tx *pg.Tx, view *UtxoView) error {
	var insertFollows []*PGFollow
	var deleteFollows []*PGFollow
	for _, followEntry := range view.FollowKeyToFollowEntry {
		if followEntry == nil {
			continue
		}

		follow := &PGFollow{
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
		_, err := tx.Model(&insertFollows).WherePK().OnConflict("DO NOTHING").Returning("NULL").Insert()
		if err != nil {
			return fmt.Errorf("flushFollows: insert: %v", err)
		}
	}

	if len(deleteFollows) > 0 {
		_, err := tx.Model(&deleteFollows).Returning("NULL").Delete()
		if err != nil {
			return fmt.Errorf("flushFollows: delete: %v", err)
		}
	}

	return nil
}

func (postgres *Postgres) flushDiamonds(tx *pg.Tx, view *UtxoView) error {
	var insertDiamonds []*PGDiamond
	var deleteDiamonds []*PGDiamond
	for _, diamondEntry := range view.DiamondKeyToDiamondEntry {
		diamond := &PGDiamond{
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
		_, err := tx.Model(&insertDiamonds).WherePK().OnConflict("(sender_pkid, receiver_pkid, diamond_post_hash) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return fmt.Errorf("flushDiamonds: insert: %v", err)
		}
	}

	if len(deleteDiamonds) > 0 {
		_, err := tx.Model(&deleteDiamonds).Returning("NULL").Delete()
		if err != nil {
			return fmt.Errorf("flushDiamonds: delete: %v", err)
		}
	}

	return nil
}

func (postgres *Postgres) flushMessages(tx *pg.Tx, view *UtxoView) error {
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
		_, err := tx.Model(&insertMessages).WherePK().OnConflict("(message_hash) DO NOTHING").Returning("NULL").Insert()
		if err != nil {
			return fmt.Errorf("flushMessages: insert: %v", err)
		}
	}

	if len(deleteMessages) > 0 {
		_, err := tx.Model(&deleteMessages).Returning("NULL").Delete()
		if err != nil {
			return fmt.Errorf("flushMessages: delete: %v", err)
		}
	}

	return nil
}

func (postgres *Postgres) flushMessagingGroups(tx *pg.Tx, view *UtxoView) error {
	var insertMessages []*PGMessagingGroup
	var deleteMessages []*PGMessagingGroup
	for _, groupEntry := range view.MessagingGroupKeyToMessagingGroupEntry {
		messagingGroupMembersBytes := bytes.NewBuffer([]byte{})
		if err := gob.NewEncoder(messagingGroupMembersBytes).Encode(groupEntry.MessagingGroupMembers); err != nil {
			return err
		}
		pgGroupEntry := &PGMessagingGroup{
			GroupOwnerPublicKey:   groupEntry.GroupOwnerPublicKey,
			MessagingPublicKey:    groupEntry.MessagingPublicKey,
			MessagingGroupKeyName: groupEntry.MessagingGroupKeyName,
			MessagingGroupMembers: messagingGroupMembersBytes.Bytes(),
			ExtraData:             groupEntry.ExtraData,
		}
		if groupEntry.isDeleted {
			deleteMessages = append(deleteMessages, pgGroupEntry)
		} else {
			insertMessages = append(insertMessages, pgGroupEntry)
		}
	}

	if len(insertMessages) > 0 {
		// TODO: There should never be a conflict here. Should we raise an error?
		_, err := tx.Model(&insertMessages).WherePK().OnConflict(
			"(group_owner_public_key, messaging_group_key_name) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return fmt.Errorf("flushMessagingGroups: insert: %v", err)
		}
	}

	if len(deleteMessages) > 0 {
		_, err := tx.Model(&deleteMessages).Returning("NULL").Delete()
		if err != nil {
			return fmt.Errorf("flushMessagingGroups: delete: %v", err)
		}
	}

	return nil
}

func (postgres *Postgres) flushCreatorCoinBalances(tx *pg.Tx, view *UtxoView) error {
	var insertBalances []*PGCreatorCoinBalance
	var deleteBalances []*PGCreatorCoinBalance
	for _, balanceEntry := range view.HODLerPKIDCreatorPKIDToBalanceEntry {
		if balanceEntry == nil {
			continue
		}

		balance := &PGCreatorCoinBalance{
			HolderPKID:  balanceEntry.HODLerPKID,
			CreatorPKID: balanceEntry.CreatorPKID,
			// FIXME: This will break if the value exceeds uint256
			BalanceNanos: balanceEntry.BalanceNanos.Uint64(),
			HasPurchased: balanceEntry.HasPurchased,
		}

		if balanceEntry.isDeleted {
			deleteBalances = append(deleteBalances, balance)
		} else {
			insertBalances = append(insertBalances, balance)
		}
	}

	if len(insertBalances) > 0 {
		_, err := tx.Model(&insertBalances).WherePK().OnConflict("(holder_pkid, creator_pkid) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return fmt.Errorf("flushCreatorCoinBalances: insert: %v", err)
		}
	}

	if len(deleteBalances) > 0 {
		_, err := tx.Model(&deleteBalances).Returning("NULL").Delete()
		if err != nil {
			return fmt.Errorf("flushCreatorCoinBalances: delete: %v", err)
		}
	}

	return nil
}

func (postgres *Postgres) flushDAOCoinBalances(tx *pg.Tx, view *UtxoView) error {
	var insertBalances []*PGDAOCoinBalance
	var deleteBalances []*PGDAOCoinBalance
	for _, balanceEntry := range view.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry {
		if balanceEntry == nil {
			continue
		}

		balance := &PGDAOCoinBalance{
			HolderPKID:   balanceEntry.HODLerPKID,
			CreatorPKID:  balanceEntry.CreatorPKID,
			BalanceNanos: balanceEntry.BalanceNanos.Hex(),
			HasPurchased: balanceEntry.HasPurchased,
		}

		if balanceEntry.isDeleted {
			deleteBalances = append(deleteBalances, balance)
		} else {
			insertBalances = append(insertBalances, balance)
		}
	}

	if len(insertBalances) > 0 {
		_, err := tx.Model(&insertBalances).WherePK().OnConflict("(holder_pkid, creator_pkid) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return fmt.Errorf("flushDAOCoinBalances: insert: %v", err)
		}
	}

	if len(deleteBalances) > 0 {
		_, err := tx.Model(&deleteBalances).Returning("NULL").Delete()
		if err != nil {
			return fmt.Errorf("flushDAOCoinBalances: delete: %v", err)
		}
	}

	return nil
}

func (postgres *Postgres) flushBalances(tx *pg.Tx, view *UtxoView) error {
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
		_, err := tx.Model(&balances).WherePK().OnConflict("(public_key) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return fmt.Errorf("flushBalances: %v", err)
		}
	}

	return nil
}

func (postgres *Postgres) flushForbiddenKeys(tx *pg.Tx, view *UtxoView) error {
	var insertKeys []*PGForbiddenKey
	var deleteKeys []*PGForbiddenKey
	for _, keyEntry := range view.ForbiddenPubKeyToForbiddenPubKeyEntry {
		balance := &PGForbiddenKey{
			PublicKey: NewPublicKey(keyEntry.PubKey),
		}

		if keyEntry.isDeleted {
			deleteKeys = append(deleteKeys, balance)
		} else {
			insertKeys = append(insertKeys, balance)
		}
	}

	if len(insertKeys) > 0 {
		_, err := tx.Model(&insertKeys).WherePK().OnConflict("(public_key) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return fmt.Errorf("flushForbiddenKeys: insert: %v", err)
		}
	}

	if len(deleteKeys) > 0 {
		_, err := tx.Model(&deleteKeys).Returning("NULL").Delete()
		if err != nil {
			return fmt.Errorf("flushForbiddenKeys: delete: %v", err)
		}
	}

	return nil
}

func (postgres *Postgres) flushNFTs(tx *pg.Tx, view *UtxoView) error {
	var insertNFTs []*PGNFT
	var deleteNFTs []*PGNFT
	for _, nftEntry := range view.NFTKeyToNFTEntry {
		nft := &PGNFT{
			NFTPostHash:                nftEntry.NFTPostHash,
			SerialNumber:               nftEntry.SerialNumber,
			LastOwnerPKID:              nftEntry.LastOwnerPKID,
			OwnerPKID:                  nftEntry.OwnerPKID,
			ForSale:                    nftEntry.IsForSale,
			MinBidAmountNanos:          nftEntry.MinBidAmountNanos,
			UnlockableText:             string(nftEntry.UnlockableText),
			LastAcceptedBidAmountNanos: nftEntry.LastAcceptedBidAmountNanos,
			IsPending:                  nftEntry.IsPending,
			IsBuyNow:                   nftEntry.IsBuyNow,
			BuyNowPriceNanos:           nftEntry.BuyNowPriceNanos,
		}

		if nftEntry.isDeleted {
			deleteNFTs = append(deleteNFTs, nft)
		} else {
			insertNFTs = append(insertNFTs, nft)
		}
	}

	if len(insertNFTs) > 0 {
		_, err := tx.Model(&insertNFTs).WherePK().OnConflict("(nft_post_hash, serial_number) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return fmt.Errorf("flushNFTs: insert: %v", err)
		}
	}

	if len(deleteNFTs) > 0 {
		_, err := tx.Model(&deleteNFTs).Returning("NULL").Delete()
		if err != nil {
			return fmt.Errorf("flushNFTs: delete: %v", err)
		}
	}

	return nil
}

func (postgres *Postgres) flushNFTBids(tx *pg.Tx, view *UtxoView) error {
	var insertBids []*PGNFTBid
	var deleteBids []*PGNFTBid
	for _, bidEntry := range view.NFTBidKeyToNFTBidEntry {
		nft := &PGNFTBid{
			BidderPKID:          bidEntry.BidderPKID,
			NFTPostHash:         bidEntry.NFTPostHash,
			SerialNumber:        bidEntry.SerialNumber,
			BidAmountNanos:      bidEntry.BidAmountNanos,
			Accepted:            bidEntry.AcceptedBlockHeight != nil,
			AcceptedBlockHeight: bidEntry.AcceptedBlockHeight,
		}

		if bidEntry.isDeleted {
			deleteBids = append(deleteBids, nft)
		} else {
			insertBids = append(insertBids, nft)
		}
	}

	if len(insertBids) > 0 {
		_, err := tx.Model(&insertBids).WherePK().OnConflict("(nft_post_hash, bidder_pkid, serial_number) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return fmt.Errorf("flushNFTBids: insert: %v", err)
		}
	}

	if len(deleteBids) > 0 {
		_, err := tx.Model(&deleteBids).Returning("NULL").Delete()
		if err != nil {
			return fmt.Errorf("flushNFTBids: delete: %v", err)
		}
	}

	return nil
}

func (postgres *Postgres) flushDerivedKeys(tx *pg.Tx, view *UtxoView) error {
	var insertKeys []*PGDerivedKey
	var deleteKeys []*PGDerivedKey
	for _, keyEntry := range view.DerivedKeyToDerivedEntry {
		tslBytes, err := keyEntry.TransactionSpendingLimitTracker.ToBytes()
		if err != nil {
			return err
		}
		key := &PGDerivedKey{
			OwnerPublicKey:                  keyEntry.OwnerPublicKey,
			DerivedPublicKey:                keyEntry.DerivedPublicKey,
			ExpirationBlock:                 keyEntry.ExpirationBlock,
			OperationType:                   keyEntry.OperationType,
			TransactionSpendingLimitTracker: tslBytes,
			Memo:                            keyEntry.Memo,
		}

		if keyEntry.isDeleted {
			deleteKeys = append(deleteKeys, key)
		} else {
			insertKeys = append(insertKeys, key)
		}
	}

	if len(insertKeys) > 0 {
		_, err := tx.Model(&insertKeys).WherePK().OnConflict("(owner_public_key, derived_public_key) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return fmt.Errorf("flushDerivedKeys: insert: %v", err)
		}
	}

	if len(deleteKeys) > 0 {
		_, err := tx.Model(&deleteKeys).Returning("NULL").Delete()
		if err != nil {
			return fmt.Errorf("flushDerivedKeys: delete: %v", err)
		}
	}

	return nil
}

func (postgres *Postgres) flushDAOCoinLimitOrders(tx *pg.Tx, view *UtxoView) error {
	var insertOrders []*PGDAOCoinLimitOrder
	var deleteOrders []*PGDAOCoinLimitOrder

	for _, orderEntry := range view.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry {
		if orderEntry == nil {
			continue
		}

		order := &PGDAOCoinLimitOrder{}
		order.FromDAOCoinLimitOrderEntry(orderEntry)

		if orderEntry.isDeleted {
			deleteOrders = append(deleteOrders, order)
		} else {
			insertOrders = append(insertOrders, order)
		}
	}

	if len(insertOrders) > 0 {
		_, err := tx.Model(&insertOrders).
			WherePK().
			OnConflict("(order_id) DO UPDATE").
			Returning("NULL").
			Insert()

		if err != nil {
			return fmt.Errorf("flushDAOCoinLimitOrders: insert: %v", err)
		}
	}

	if len(deleteOrders) > 0 {
		_, err := tx.Model(&deleteOrders).Returning("NULL").Delete()
		if err != nil {
			return fmt.Errorf("flushDAOCoinLimitOrders: delete: %v", err)
		}
	}

	return nil
}

//
// UTXOS
//

func (postgres *Postgres) GetUtxoEntryForUtxoKey(utxoKey *UtxoKey) *UtxoEntry {
	utxo := &PGTransactionOutput{
		OutputHash:  &utxoKey.TxID,
		OutputIndex: utxoKey.Index,
		Spent:       false,
	}

	err := postgres.db.Model(utxo).WherePK().Select()
	if err != nil {
		return nil
	}

	return utxo.NewUtxoEntry()
}

func (postgres *Postgres) GetUtxoEntriesForPublicKey(publicKey []byte) []*UtxoEntry {
	var transactionOutputs []*PGTransactionOutput
	err := postgres.db.Model(&transactionOutputs).Where("public_key = ?", publicKey).Select()
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
	err := postgres.db.Model(&outputs).WherePK().Select()
	if err != nil {
		return nil
	}
	return outputs
}

func (postgres *Postgres) GetBlockRewardsForPublicKey(publicKey *PublicKey, startHeight uint32, endHeight uint32) []*PGTransactionOutput {
	var transactionOutputs []*PGTransactionOutput
	err := postgres.db.Model(&transactionOutputs).
		ColumnExpr("pg_transaction_output.*").
		Join("JOIN pg_transactions as pgt").
		JoinOn("pg_transaction_output.output_hash = pgt.hash").
		Where("pg_transaction_output.public_key = ?", publicKey).
		Where("pgt.Type = ?", TxnTypeBlockReward).
		Where("pg_transaction_output.height > ?", startHeight).
		Where("pg_transaction_output.height < ?", endHeight).Select()
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
	err := postgres.db.Model(&profile).Where("LOWER(username) = ?", strings.ToLower(nonLowercaseUsername)).First()
	if err != nil {
		return nil
	}
	return &profile
}

func (postgres *Postgres) GetProfileForPublicKey(publicKey []byte) *PGProfile {
	var profile PGProfile
	err := postgres.db.Model(&profile).Where("public_key = ?", publicKey).First()
	if err != nil {
		return nil
	}
	return &profile
}

func (postgres *Postgres) GetProfile(pkid PKID) *PGProfile {
	var profile PGProfile
	err := postgres.db.Model(&profile).Where("pkid = ?", pkid).First()
	if err != nil {
		return nil
	}
	return &profile
}

func (postgres *Postgres) GetProfilesForPublicKeys(publicKeys []*PublicKey) []*PGProfile {
	var profiles []*PGProfile
	err := postgres.db.Model(&profiles).WhereIn("public_key IN (?)", publicKeys).Select()
	if err != nil {
		return nil
	}
	return profiles
}

func (postgres *Postgres) GetProfilesByCoinValue(startLockedNanos uint64, limit int) []*PGProfile {
	var profiles []*PGProfile
	err := postgres.db.Model(&profiles).Where("deso_locked_nanos < ?", startLockedNanos).
		OrderExpr("deso_locked_nanos DESC").Limit(limit).Select()
	if err != nil {
		return nil
	}
	return profiles
}

func (postgres *Postgres) GetProfilesForUsernamePrefixByCoinValue(usernamePrefix string, limit int) []*PGProfile {
	var profiles []*PGProfile
	err := postgres.db.Model(&profiles).Where("username ILIKE ?", fmt.Sprintf("%s%%", usernamePrefix)).
		Where("deso_locked_nanos >= 0").OrderExpr("deso_locked_nanos DESC").Limit(limit).Select()
	if err != nil {
		return nil
	}
	return profiles
}

func (postgres *Postgres) GetProfilesForUsername(usernames []string) []*PGProfile {
	var profiles []*PGProfile
	err := postgres.db.Model(&profiles).Where("LOWER(username) IN (?)", usernames).Select()
	if err != nil {
		return nil
	}
	return profiles
}

//
// Posts
//

func (postgres *Postgres) GetPost(postHash *BlockHash) *PGPost {
	var post PGPost
	err := postgres.db.Model(&post).Where("post_hash = ?", postHash).First()
	if err != nil {
		return nil
	}
	return &post
}

func (postgres *Postgres) GetPosts(posts []*PGPost) []*PGPost {
	err := postgres.db.Model(&posts).WherePK().Select()
	if err != nil {
		return nil
	}
	return posts
}

func (postgres *Postgres) GetPostsForPublicKey(publicKey []byte, startTime uint64, limit uint64) []*PGPost {
	var posts []*PGPost
	err := postgres.db.Model(&posts).
		Where("poster_public_key = ?", publicKey).Where("timestamp < ?", startTime).
		Where("hidden IS NULL").Where("parent_post_hash IS NULL").
		OrderExpr("timestamp DESC").Limit(int(limit)).Select()
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
	err := postgres.db.Model(&posts).Where("parent_post_hash = ?", parentPostHash).Select()
	if err != nil {
		return nil
	}
	return posts
}

func (postgres *Postgres) GetMessage(messageHash *BlockHash) *PGMessage {
	var message PGMessage
	err := postgres.db.Model(&message).Where("message_hash = ?", messageHash).First()
	if err != nil {
		return nil
	}
	return &message
}

//
// LIKES
//

func (postgres *Postgres) GetLike(likerPublicKey []byte, likedPostHash *BlockHash) *PGLike {
	like := PGLike{
		LikerPublicKey: likerPublicKey,
		LikedPostHash:  likedPostHash,
	}
	err := postgres.db.Model(&like).WherePK().First()
	if err != nil {
		return nil
	}
	return &like
}

func (postgres *Postgres) GetLikes(likes []*PGLike) []*PGLike {
	err := postgres.db.Model(&likes).WherePK().Select()
	if err != nil {
		return nil
	}
	return likes
}

func (postgres *Postgres) GetLikesForPost(postHash *BlockHash) []*PGLike {
	var likes []*PGLike
	err := postgres.db.Model(&likes).Where("liked_post_hash = ?", postHash).Select()
	if err != nil {
		return nil
	}
	return likes
}

//
// Follows
//

func (postgres *Postgres) GetFollow(followerPkid *PKID, followedPkid *PKID) *PGFollow {
	follow := PGFollow{
		FollowerPKID: followerPkid,
		FollowedPKID: followedPkid,
	}
	err := postgres.db.Model(&follow).WherePK().First()
	if err != nil {
		return nil
	}
	return &follow
}

func (postgres *Postgres) GetFollows(follows []*PGFollow) []*PGFollow {
	err := postgres.db.Model(&follows).WherePK().Select()
	if err != nil {
		return nil
	}
	return follows
}

func (postgres *Postgres) GetFollowing(pkid *PKID) []*PGFollow {
	var follows []*PGFollow
	err := postgres.db.Model(&follows).Where("follower_pkid = ?", pkid).Select()
	if err != nil {
		return nil
	}
	return follows
}

func (postgres *Postgres) GetFollowers(pkid *PKID) []*PGFollow {
	var follows []*PGFollow
	err := postgres.db.Model(&follows).Where("followed_pkid = ?", pkid).Select()
	if err != nil {
		return nil
	}
	return follows
}

func (postgres *Postgres) GetDiamond(senderPkid *PKID, receiverPkid *PKID, postHash *BlockHash) *PGDiamond {
	diamond := PGDiamond{
		SenderPKID:      senderPkid,
		ReceiverPKID:    receiverPkid,
		DiamondPostHash: postHash,
	}
	err := postgres.db.Model(&diamond).WherePK().First()
	if err != nil {
		return nil
	}
	return &diamond
}

//
// Creator Coins
//

func (postgres *Postgres) GetCreatorCoinBalances(balances []*PGCreatorCoinBalance) []*PGCreatorCoinBalance {
	err := postgres.db.Model(&balances).WherePK().Select()
	if err != nil {
		return nil
	}
	return balances
}

func (postgres *Postgres) GetCreatorCoinBalance(holderPkid *PKID, creatorPkid *PKID) *PGCreatorCoinBalance {
	balance := PGCreatorCoinBalance{
		HolderPKID:  holderPkid,
		CreatorPKID: creatorPkid,
	}
	err := postgres.db.Model(&balance).WherePK().First()
	if err != nil {
		return &PGCreatorCoinBalance{
			CreatorPKID:  creatorPkid,
			HolderPKID:   holderPkid,
			BalanceNanos: 0,
		}
	}
	return &balance
}

func (postgres *Postgres) GetCreatorCoinHoldings(pkid *PKID) []*PGCreatorCoinBalance {
	var holdings []*PGCreatorCoinBalance
	err := postgres.db.Model(&holdings).Where("holder_pkid = ?", pkid).Select()
	if err != nil {
		return nil
	}
	return holdings
}

func (postgres *Postgres) GetCreatorCoinHolders(pkid *PKID) []*PGCreatorCoinBalance {
	var holdings []*PGCreatorCoinBalance
	err := postgres.db.Model(&holdings).Where("creator_pkid = ?", pkid).Select()
	if err != nil {
		return nil
	}
	return holdings
}

//
// DAO Coins
//

func (postgres *Postgres) GetDAOCoinBalances(balances []*PGDAOCoinBalance) []*PGDAOCoinBalance {
	err := postgres.db.Model(&balances).WherePK().Select()
	if err != nil {
		return nil
	}
	return balances
}

func (postgres *Postgres) GetDAOCoinBalance(holderPkid *PKID, creatorPkid *PKID) *PGDAOCoinBalance {
	balance := PGDAOCoinBalance{
		HolderPKID:  holderPkid,
		CreatorPKID: creatorPkid,
	}
	err := postgres.db.Model(&balance).WherePK().First()
	if err != nil {
		return &PGDAOCoinBalance{
			CreatorPKID:  creatorPkid,
			HolderPKID:   holderPkid,
			BalanceNanos: "0x0",
		}
	}
	return &balance
}

func (postgres *Postgres) GetDAOCoinHoldings(pkid *PKID) []*PGDAOCoinBalance {
	var holdings []*PGDAOCoinBalance
	err := postgres.db.Model(&holdings).Where("holder_pkid = ?", pkid).Select()
	if err != nil {
		return nil
	}
	return holdings
}

func (postgres *Postgres) GetDAOCoinHolders(pkid *PKID) []*PGDAOCoinBalance {
	var holdings []*PGDAOCoinBalance
	err := postgres.db.Model(&holdings).Where("creator_pkid = ?", pkid).Select()
	if err != nil {
		return nil
	}
	return holdings
}

//
// DAO Coin Limit Orders
//

func (postgres *Postgres) GetDAOCoinLimitOrder(orderID *BlockHash) (*DAOCoinLimitOrderEntry, error) {
	order := PGDAOCoinLimitOrder{OrderID: orderID}
	err := postgres.db.Model(&order).WherePK().First()

	if err != nil {
		// If we don't find anything, don't error. Just return nil.
		if err.Error() == "pg: no rows in result set" {
			return nil, nil
		}

		return nil, err
	}

	return order.ToDAOCoinLimitOrderEntry(), nil
}

func (postgres *Postgres) GetAllDAOCoinLimitOrders() ([]*DAOCoinLimitOrderEntry, error) {
	// This function is currently used for testing purposes only.
	var orders []*PGDAOCoinLimitOrder

	// Order in the same way as BadgerDB keys.
	err := postgres.db.Model(&orders).
		Order("buying_dao_coin_creator_pkid ASC").
		Order("selling_dao_coin_creator_pkid ASC").
		Order("scaled_exchange_rate_coins_to_sell_per_coin_to_buy ASC").
		Order("block_height DESC").
		Order("order_id ASC").
		Select()

	if err != nil {
		return nil, err
	}

	var outputOrders []*DAOCoinLimitOrderEntry

	for _, order := range orders {
		outputOrders = append(outputOrders, order.ToDAOCoinLimitOrderEntry())
	}

	return outputOrders, nil
}

func (postgres *Postgres) GetAllDAOCoinLimitOrdersForThisDAOCoinPair(
	buyingDAOCoinCreatorPKID *PKID,
	sellingDAOCoinCreatorPKID *PKID) ([]*DAOCoinLimitOrderEntry, error) {

	var orders []*PGDAOCoinLimitOrder

	// Order in the same way as BadgerDB keys.
	err := postgres.db.Model(&orders).
		Where("buying_dao_coin_creator_pkid = ?", buyingDAOCoinCreatorPKID).
		Where("selling_dao_coin_creator_pkid = ?", sellingDAOCoinCreatorPKID).
		Order("scaled_exchange_rate_coins_to_sell_per_coin_to_buy ASC").
		Order("block_height DESC").
		Order("order_id ASC").
		Select()

	if err != nil {
		return nil, err
	}

	var outputOrders []*DAOCoinLimitOrderEntry

	for _, order := range orders {
		outputOrders = append(outputOrders, order.ToDAOCoinLimitOrderEntry())
	}

	return outputOrders, nil
}

func (postgres *Postgres) GetAllDAOCoinLimitOrdersForThisTransactor(transactorPKID *PKID) ([]*DAOCoinLimitOrderEntry, error) {
	var orders []*PGDAOCoinLimitOrder

	// Order in the same way as BadgerDB keys.
	err := postgres.db.Model(&orders).
		Where("transactor_pkid = ?", transactorPKID).
		Order("buying_dao_coin_creator_pkid ASC").
		Order("selling_dao_coin_creator_pkid ASC").
		Order("order_id ASC").
		Select()

	if err != nil {
		return nil, err
	}

	var outputOrders []*DAOCoinLimitOrderEntry

	for _, order := range orders {
		outputOrders = append(outputOrders, order.ToDAOCoinLimitOrderEntry())
	}

	return outputOrders, nil
}

func (postgres *Postgres) GetMatchingDAOCoinLimitOrders(inputOrder *DAOCoinLimitOrderEntry, lastSeenOrder *DAOCoinLimitOrderEntry, orderEntriesInView map[DAOCoinLimitOrderMapKey]bool) ([]*DAOCoinLimitOrderEntry, error) {
	// We do need to make sure we sort by price descending so that
	// the transactor is reviewing the best-priced orders first.

	// If last seen order is not nil, this means that the transactor
	// still has quantity to fulfill and is requesting more orders.
	lastSeenOrderPassed := false
	if lastSeenOrder == nil {
		lastSeenOrderPassed = true
	}

	var matchingOrders []*PGDAOCoinLimitOrder

	// Switch BuyingDAOCoinCreatorPKID and SellingDAOCoinCreatorPKID.
	err := postgres.db.Model(&matchingOrders).
		Where("buying_dao_coin_creator_pkid = ?", inputOrder.SellingDAOCoinCreatorPKID).
		Where("selling_dao_coin_creator_pkid = ?", inputOrder.BuyingDAOCoinCreatorPKID).
		Order("scaled_exchange_rate_coins_to_sell_per_coin_to_buy DESC"). // Best-priced first
		Order("block_height ASC").                                        // Then oldest first (FIFO)
		Order("order_id DESC").                                           // Then match BadgerDB ordering
		Select()

	if err != nil {
		return nil, err
	}

	var outputOrders []*DAOCoinLimitOrderEntry

	totalQuantity := inputOrder.QuantityToFillInBaseUnits
	for ii := 0; ii < len(matchingOrders) && totalQuantity.GtUint64(0); ii++ {
		matchingOrder := matchingOrders[ii]
		matchingOrderEntry := matchingOrder.ToDAOCoinLimitOrderEntry()
		// If we haven't seen the lastSeenOrder yet, check if the current matchingOrder we're looking at
		// is the lastSeenOrder by comparing OrderIDs.
		if !lastSeenOrderPassed {
			if bytes.Equal(matchingOrderEntry.OrderID.ToBytes(), lastSeenOrder.OrderID.ToBytes()) {
				lastSeenOrderPassed = true
			}
			continue
		}
		// Skip if order is already in the view.
		if _, exists := orderEntriesInView[matchingOrderEntry.ToMapKey()]; exists {
			continue
		}
		outputOrders = append(outputOrders, matchingOrderEntry)
		totalQuantity, _, _, _, err = _calculateDAOCoinsTransferredInLimitOrderMatch(
			matchingOrderEntry, inputOrder.OperationType, totalQuantity)
		if err != nil {
			return nil, err
		}
	}

	return outputOrders, nil
}

//
// NFTS
//

func (postgres *Postgres) GetNFT(nftPostHash *BlockHash, serialNumber uint64) *PGNFT {
	nft := PGNFT{
		NFTPostHash:  nftPostHash,
		SerialNumber: serialNumber,
	}
	err := postgres.db.Model(&nft).WherePK().First()
	if err != nil {
		return nil
	}
	return &nft
}

func (postgres *Postgres) GetNFTsForPostHash(nftPostHash *BlockHash) []*PGNFT {
	var nfts []*PGNFT
	err := postgres.db.Model(&nfts).Where("nft_post_hash = ?", nftPostHash).Select()
	if err != nil {
		return nil
	}
	return nfts
}

func (postgres *Postgres) GetNFTsForPKID(pkid *PKID) []*PGNFT {
	var nfts []*PGNFT
	err := postgres.db.Model(&nfts).Where("owner_pkid = ?", pkid).Select()
	if err != nil {
		return nil
	}
	return nfts
}

func (postgres *Postgres) GetNFTBidsForPKID(pkid *PKID) []*PGNFTBid {
	var nftBids []*PGNFTBid
	err := postgres.db.Model(&nftBids).Where("bidder_pkid = ?", pkid).Select()
	if err != nil {
		return nil
	}
	return nftBids
}

func (postgres *Postgres) GetNFTBidsForSerial(nftPostHash *BlockHash, serialNumber uint64) []*PGNFTBid {
	var nftBids []*PGNFTBid
	err := postgres.db.Model(&nftBids).Where("nft_post_hash = ?", nftPostHash).
		Where("serial_number = ?", serialNumber).Select()
	if err != nil {
		return nil
	}
	return nftBids
}

func (postgres *Postgres) GetNFTBid(nftPostHash *BlockHash, bidderPKID *PKID, serialNumber uint64) *PGNFTBid {
	bid := PGNFTBid{
		NFTPostHash:  nftPostHash,
		BidderPKID:   bidderPKID,
		SerialNumber: serialNumber,
	}
	err := postgres.db.Model(&bid).WherePK().First()
	if err != nil {
		return nil
	}
	return &bid
}

//
// Derived Keys
//

func (postgres *Postgres) GetDerivedKey(ownerPublicKey *PublicKey, derivedPublicKey *PublicKey) *PGDerivedKey {
	key := PGDerivedKey{
		OwnerPublicKey:   *ownerPublicKey,
		DerivedPublicKey: *derivedPublicKey,
	}
	err := postgres.db.Model(&key).WherePK().First()
	if err != nil {
		return nil
	}
	return &key
}

func (postgres *Postgres) GetAllDerivedKeysForOwner(ownerPublicKey *PublicKey) []*PGDerivedKey {
	var keys []*PGDerivedKey
	err := postgres.db.Model(&keys).Where("owner_public_key = ?", *ownerPublicKey).Select()
	if err != nil {
		return nil
	}
	return keys
}

//
// Balances
//

func (postgres *Postgres) GetBalance(publicKey *PublicKey) uint64 {
	balance := PGBalance{
		PublicKey: publicKey,
	}
	err := postgres.db.Model(&balance).WherePK().First()
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
		_, err := postgres.db.Model(&PGTransactionOutput{
			OutputHash:  &BlockHash{},
			OutputIndex: uint32(index),
			OutputType:  UtxoTypeOutput,
			AmountNanos: txOutput.AmountNanos,
			PublicKey:   txOutput.PublicKey,
		}).Returning("NULL").Insert()
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
	err := postgres.db.Model(&notifications).Where("to_user = ?", keyBytes).Order("timestamp desc").Limit(100).Select()
	if err != nil {
		return nil, err
	}

	return notifications, nil
}
